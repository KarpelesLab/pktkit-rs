//! DNS resolver.
//!
//! [`wire`] holds the pure RFC 1035 query builder and response parser (no
//! I/O — easy to unit test). [`Resolver`] runs those over a real
//! [`UdpSocket`], querying each configured server in turn until one answers.
//!
//! In the Go upstream, vclient routes DNS through the *virtual* network so
//! lookups traverse the tunnel. That path is also available here once a
//! `Client` is wired to a UDP transport; the standalone `Resolver` uses the
//! host's real sockets and is handy for tests and for resolving the tunnel
//! endpoints themselves.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

/// DNS record type we know how to ask for.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecordType {
    /// IPv4 address (`A`, type 1).
    A,
    /// IPv6 address (`AAAA`, type 28).
    Aaaa,
}

impl RecordType {
    fn qtype(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::Aaaa => 28,
        }
    }
}

/// Pure RFC 1035 codec — no sockets, no allocFree of side effects.
pub mod wire {
    use super::RecordType;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Build a DNS query for `name`/`rtype` with transaction id `id`.
    /// Returns `None` if any label exceeds 63 bytes (RFC 1035 §2.3.4).
    pub fn build_query(id: u16, name: &str, rtype: RecordType) -> Option<Vec<u8>> {
        let qname = encode_name(name)?;
        let mut pkt = Vec::with_capacity(12 + qname.len() + 4);
        pkt.extend_from_slice(&id.to_be_bytes());
        pkt.push(0x01); // flags hi: RD (recursion desired)
        pkt.push(0x00); // flags lo
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        pkt.extend_from_slice(&qname);
        pkt.extend_from_slice(&rtype.qtype().to_be_bytes()); // QTYPE
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        Some(pkt)
    }

    /// Encode a domain name in wire format. `None` if a label is too long.
    pub fn encode_name(name: &str) -> Option<Vec<u8>> {
        let name = name.strip_suffix('.').unwrap_or(name);
        let mut buf = Vec::with_capacity(name.len() + 2);
        if !name.is_empty() {
            for part in name.split('.') {
                if part.len() > 63 {
                    return None;
                }
                buf.push(part.len() as u8);
                buf.extend_from_slice(part.as_bytes());
            }
        }
        buf.push(0); // root label
        Some(buf)
    }

    /// Parse a DNS response, returning the A/AAAA addresses it carries.
    /// Verifies the transaction id, the QR bit, and the RCODE.
    pub fn parse_response(data: &[u8], expected_id: u16) -> Result<Vec<IpAddr>, &'static str> {
        if data.len() < 12 {
            return Err("response too short");
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        if id != expected_id {
            return Err("transaction ID mismatch");
        }
        let flags = u16::from_be_bytes([data[2], data[3]]);
        if flags & 0x8000 == 0 {
            return Err("not a response");
        }
        if flags & 0x000F != 0 {
            return Err("DNS error rcode");
        }
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);

        let mut off = 12;
        for _ in 0..qdcount {
            off = skip_name(data, off).ok_or("malformed question")?;
            if off + 4 > data.len() {
                return Err("truncated question");
            }
            off += 4; // QTYPE + QCLASS
        }

        let mut out = Vec::new();
        for _ in 0..ancount {
            off = match skip_name(data, off) {
                Some(o) => o,
                None => break,
            };
            if off + 10 > data.len() {
                break;
            }
            let rtype = u16::from_be_bytes([data[off], data[off + 1]]);
            let rdlength = u16::from_be_bytes([data[off + 8], data[off + 9]]) as usize;
            off += 10;
            if off + rdlength > data.len() {
                break;
            }
            match (rtype, rdlength) {
                (1, 4) => {
                    out.push(IpAddr::V4(Ipv4Addr::new(
                        data[off],
                        data[off + 1],
                        data[off + 2],
                        data[off + 3],
                    )));
                }
                (28, 16) => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&data[off..off + 16]);
                    out.push(IpAddr::V6(Ipv6Addr::from(b)));
                }
                _ => {}
            }
            off += rdlength;
        }
        Ok(out)
    }

    /// Skip a (possibly compressed) name, returning the offset just past it.
    pub fn skip_name(data: &[u8], mut off: usize) -> Option<usize> {
        loop {
            if off >= data.len() {
                return None;
            }
            let l = data[off] as usize;
            if l == 0 {
                return Some(off + 1);
            }
            if l & 0xC0 == 0xC0 {
                return Some(off + 2); // compression pointer
            }
            off += 1 + l;
        }
    }
}

/// Configure a [`Resolver`].
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// DNS servers to query, in priority order. Defaults to UDP/53.
    pub servers: Vec<SocketAddr>,
    /// Per-server query timeout.
    pub timeout: Duration,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        ResolverConfig {
            servers: Vec::new(),
            timeout: Duration::from_secs(5),
        }
    }
}

/// A DNS resolver over real UDP sockets.
#[derive(Debug, Clone)]
pub struct Resolver {
    cfg: ResolverConfig,
}

impl Resolver {
    /// New resolver with explicit config.
    pub fn new(cfg: ResolverConfig) -> Resolver {
        Resolver { cfg }
    }

    /// Convenience constructor from a list of server IPs (UDP/53).
    pub fn from_servers(servers: impl IntoIterator<Item = IpAddr>) -> Resolver {
        Resolver {
            cfg: ResolverConfig {
                servers: servers.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect(),
                timeout: Duration::from_secs(5),
            },
        }
    }

    /// Resolve `name` to a list of addresses (A then AAAA). If `name` is
    /// already an IP literal, it is returned directly.
    pub fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = name.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let mut all = self.query(name, RecordType::A)?;
        // Best-effort AAAA; ignore errors so an A-only host still resolves.
        if let Ok(v6) = self.query(name, RecordType::Aaaa) {
            all.extend(v6);
        }
        if all.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no addresses found for {name}"),
            ));
        }
        Ok(all)
    }

    /// Query a single record type across the configured servers.
    pub fn query(&self, name: &str, rtype: RecordType) -> io::Result<Vec<IpAddr>> {
        if self.cfg.servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no DNS servers configured",
            ));
        }
        let mut last_err = io::Error::new(io::ErrorKind::Other, "no servers tried");
        for server in &self.cfg.servers {
            match self.query_one(*server, name, rtype) {
                Ok(addrs) => return Ok(addrs),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn query_one(
        &self,
        server: SocketAddr,
        name: &str,
        rtype: RecordType,
    ) -> io::Result<Vec<IpAddr>> {
        let id = crate::rand::u32() as u16;
        let query = wire::build_query(id, name, rtype)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "label too long"))?;

        let bind = if server.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let sock = UdpSocket::bind(bind)?;
        sock.set_read_timeout(Some(self.cfg.timeout))?;
        sock.send_to(&query, server)?;

        let mut buf = [0u8; 1500];
        loop {
            let (n, _from) = sock.recv_from(&mut buf)?;
            match wire::parse_response(&buf[..n], id) {
                Ok(addrs) => return Ok(addrs),
                Err(_) => continue, // wrong id / parse error: keep waiting (until timeout)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn encode_name_basic() {
        let e = wire::encode_name("example.com").unwrap();
        assert_eq!(e, b"\x07example\x03com\x00");
        // trailing dot tolerated
        assert_eq!(wire::encode_name("example.com."), Some(e));
    }

    #[test]
    fn encode_name_rejects_long_label() {
        let long = "a".repeat(64);
        assert!(wire::encode_name(&long).is_none());
    }

    #[test]
    fn build_query_shape() {
        let q = wire::build_query(0x1234, "a.com", RecordType::A).unwrap();
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(q[2], 0x01); // RD
        assert_eq!(&q[4..6], &[0, 1]); // QDCOUNT
        // ends with QTYPE=1, QCLASS=1
        assert_eq!(&q[q.len() - 4..], &[0, 1, 0, 1]);
    }

    #[test]
    fn parse_a_record_response() {
        // Build a synthetic response for "a.com" -> 1.2.3.4
        let id: u16 = 0xBEEF;
        let mut r = Vec::new();
        r.extend_from_slice(&id.to_be_bytes());
        r.extend_from_slice(&0x8180u16.to_be_bytes()); // response, RD+RA, rcode 0
        r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        r.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        r.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        r.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Question
        r.extend_from_slice(&wire::encode_name("a.com").unwrap());
        r.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        r.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        // Answer: compressed name pointer to offset 12
        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        r.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        r.extend_from_slice(&300u32.to_be_bytes()); // TTL
        r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        r.extend_from_slice(&[1, 2, 3, 4]); // RDATA

        let ips = wire::parse_response(&r, id).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn parse_rejects_wrong_id() {
        let r = vec![0u8; 12];
        assert!(wire::parse_response(&r, 0x1234).is_err());
    }

    #[test]
    fn resolve_ip_literal_is_passthrough() {
        let r = Resolver::from_servers([]);
        assert_eq!(
            r.resolve("8.8.8.8").unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]
        );
    }

    #[test]
    fn resolve_loopback_server_roundtrip() {
        // Spin up a tiny UDP "DNS server" on loopback that answers A queries
        // for any name with 127.0.0.1.
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            // Echo question back with one A answer.
            let mut resp = Vec::new();
            resp.extend_from_slice(&id.to_be_bytes());
            resp.extend_from_slice(&0x8180u16.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes()); // QD
            resp.extend_from_slice(&1u16.to_be_bytes()); // AN
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            // copy question section (from offset 12 to end of received query)
            resp.extend_from_slice(&buf[12..n]);
            // answer
            resp.extend_from_slice(&[0xC0, 0x0C]);
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&60u32.to_be_bytes());
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.extend_from_slice(&[127, 0, 0, 1]);
            server.send_to(&resp, from).unwrap();
        });

        let r = Resolver::new(ResolverConfig {
            servers: vec![server_addr],
            timeout: Duration::from_secs(2),
        });
        let ips = r.query("anything.test", RecordType::A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
    }
}
