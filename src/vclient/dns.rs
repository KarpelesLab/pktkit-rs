//! DNS resolver.
//!
//! [`wire`] holds the pure RFC 1035 query builder and response parser (no
//! I/O — easy to unit test). [`Resolver`] runs those over a real
//! [`UdpSocket`], querying each configured server in turn until one answers,
//! and asks again over TCP when the answer comes back truncated.
//!
//! In the Go upstream, vclient routes DNS through the *virtual* network so
//! lookups traverse the tunnel. That path is also available here once a
//! `Client` is wired to a UDP transport; the standalone `Resolver` uses the
//! host's real sockets and is handy for tests and for resolving the tunnel
//! endpoints themselves.

// The resolver needs host UDP sockets, which wasm does not have. The codec
// still builds there (the fuzz targets use it), with nothing to call it.
#![cfg_attr(target_family = "wasm", allow(dead_code))]

#[cfg(not(target_family = "wasm"))]
use crate::time::Instant;
#[cfg(not(target_family = "wasm"))]
use std::io;
#[cfg(not(target_family = "wasm"))]
use std::net::{IpAddr, SocketAddr, UdpSocket};
#[cfg(not(target_family = "wasm"))]
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

    /// Whether `response` answers the question asked in `query` (both whole
    /// messages): one question, same name, type and class. The name is
    /// compared without regard to ASCII case (RFC 4343), since servers and
    /// resolvers may echo it in another case.
    pub fn question_matches(response: &[u8], query: &[u8]) -> bool {
        if response.len() < 12 || query.len() < 12 || response[4..6] != [0, 1] {
            return false;
        }
        let Some(name_end) = skip_name(query, 12) else {
            return false;
        };
        let q = &query[12..];
        let (name_len, len) = (name_end - 12, q.len());
        let Some(r) = response.get(12..12 + len) else {
            return false;
        };
        r[..name_len].eq_ignore_ascii_case(&q[..name_len]) && r[name_len..] == q[name_len..]
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
#[cfg(not(target_family = "wasm"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResolverConfig {
    /// DNS servers to query, in priority order. Defaults to UDP/53.
    pub servers: Vec<SocketAddr>,
    /// How long to wait for each server's answer.
    pub timeout: Duration,
}

#[cfg(not(target_family = "wasm"))]
setters! {
    ResolverConfig {
        set servers: Vec<SocketAddr>;
        set timeout: Duration;
    }
}

#[cfg(not(target_family = "wasm"))]
impl Default for ResolverConfig {
    fn default() -> Self {
        ResolverConfig {
            servers: Vec::new(),
            timeout: Duration::from_secs(5),
        }
    }
}

/// A transaction ID an off-path host cannot predict.
///
/// `crate::rand` is seeded from the clock, which is guessable. std's
/// `RandomState` is keyed from the OS's random source, so SipHash under it
/// gives unpredictable output with no extra dependency.
#[cfg(not(target_family = "wasm"))]
fn query_id() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u32(crate::rand::u32());
    h.finish() as u16
}

/// A DNS resolver over real UDP sockets.
#[cfg(not(target_family = "wasm"))]
#[derive(Debug, Clone)]
pub struct Resolver {
    cfg: ResolverConfig,
}

#[cfg(not(target_family = "wasm"))]
impl Resolver {
    /// New resolver with explicit config.
    pub fn new(cfg: ResolverConfig) -> Resolver {
        Resolver { cfg }
    }

    /// Convenience constructor from a list of server IPs (UDP/53).
    pub fn from_servers(servers: impl IntoIterator<Item = IpAddr>) -> Resolver {
        Resolver {
            cfg: ResolverConfig {
                servers: servers
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, 53))
                    .collect(),
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
        let mut last_err = io::Error::other("no servers tried");
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
        let id = query_id();
        let query = wire::build_query(id, name, rtype)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "label too long"))?;

        let bind = if server.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        // A fresh socket on an OS-chosen port, connected so that the kernel
        // drops datagrams from anyone but the server: an off-path forger then
        // has to guess the port as well as the ID. Connecting also surfaces
        // a port-unreachable reply at once, rather than as a timeout.
        let sock = UdpSocket::bind(bind)?;
        sock.connect(server)?;
        sock.send(&query)?;

        // One deadline for the whole exchange: stray datagrams must not
        // extend it.
        let deadline = Instant::now() + self.cfg.timeout;
        let mut buf = [0u8; 1500];
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out"))?;
            sock.set_read_timeout(Some(left))?;
            let n = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "DNS query timed out",
                    ));
                }
                Err(e) => return Err(e),
            };
            let resp = &buf[..n];
            // Anything that is not a response to exactly this query is
            // ignored: wrong ID, not a response, another question.
            if resp.len() < 12
                || resp[..2] != id.to_be_bytes()
                || resp[2] & 0x80 == 0
                || !wire::question_matches(resp, &query)
            {
                continue;
            }
            if resp[2] & 0x02 != 0 {
                // TC: the answer did not fit in a datagram, and what came
                // is not all of it. Ask again over TCP (RFC 7766 §5).
                return self.query_tcp(server, &query, id, deadline);
            }
            return wire::parse_response(resp, id)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        }
    }

    /// Send `query` to `server` over TCP, each message behind its two-byte
    /// length (RFC 1035 §4.2.2), by `deadline`: the same one as the UDP
    /// query this retries, so one server never costs more than the timeout.
    fn query_tcp(
        &self,
        server: SocketAddr,
        query: &[u8],
        id: u16,
        deadline: Instant,
    ) -> io::Result<Vec<IpAddr>> {
        use std::io::{Read, Write};

        let left = || {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out"))
        };
        let mut s = std::net::TcpStream::connect_timeout(&server, left()?)?;
        s.set_write_timeout(Some(left()?))?;
        let mut msg = Vec::with_capacity(2 + query.len());
        msg.extend_from_slice(&(query.len() as u16).to_be_bytes());
        msg.extend_from_slice(query);
        s.write_all(&msg)?;
        // A read timeout bounds each recv, not read_exact as a whole: a
        // server trickling one byte per timeout would hold the query for as
        // many timeouts as the length it announced. So read in a loop, and
        // give each read only what is left of the deadline.
        let mut read = |mut buf: &mut [u8]| -> io::Result<()> {
            while !buf.is_empty() {
                s.set_read_timeout(Some(left()?))?;
                match s.read(buf) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "DNS server closed the connection",
                        ));
                    }
                    Ok(n) => buf = &mut buf[n..],
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "DNS query timed out",
                        ));
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        };
        let mut len = [0u8; 2];
        read(&mut len)?;
        let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
        read(&mut resp)?;
        // Only the server can speak on this connection, but it must still
        // be answering this question.
        if !wire::question_matches(&resp, query) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS answer to another question",
            ));
        }
        wire::parse_response(&resp, id).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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
    fn question_match_is_case_insensitive_on_the_name_only() {
        let q = wire::build_query(1, "Example.test", RecordType::A).unwrap();
        let mut r = q.clone();
        r[13] = b'E';
        assert!(wire::question_matches(&r, &q));
        let mut r = q.clone();
        r[13] = b'e';
        assert!(wire::question_matches(&r, &q));
        let aaaa = wire::build_query(1, "Example.test", RecordType::Aaaa).unwrap();
        assert!(!wire::question_matches(&aaaa, &q));
        assert!(!wire::question_matches(&q[..q.len() - 1], &q));
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

    /// A response to `query` (as received) carrying one A record.
    fn answer(query: &[u8], ip: [u8; 4]) -> Vec<u8> {
        let mut resp = query.to_vec();
        resp[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        resp[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&60u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&ip);
        resp
    }

    #[test]
    fn replies_from_elsewhere_are_ignored() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            // An off-path host races the real server with a forged answer.
            let forger = UdpSocket::bind("127.0.0.1:0").unwrap();
            forger
                .send_to(&answer(&buf[..n], [6, 6, 6, 6]), from)
                .unwrap();
            std::thread::sleep(Duration::from_millis(50));
            server
                .send_to(&answer(&buf[..n], [1, 2, 3, 4]), from)
                .unwrap();
        });
        let r = Resolver::new(
            ResolverConfig::default()
                .servers(vec![server_addr])
                .timeout(Duration::from_secs(2)),
        );
        let ips = r.query("example.test", RecordType::A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn answer_to_another_question_is_ignored() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            // Same ID, but for a different name.
            let other = wire::build_query(0, "evil.test", RecordType::A).unwrap();
            let mut forged = answer(&other, [6, 6, 6, 6]);
            forged[..2].copy_from_slice(&buf[..2]);
            server.send_to(&forged, from).unwrap();
            // The name echoed in another letter case is still ours.
            let mut real = answer(&buf[..n], [1, 2, 3, 4]);
            real[13] = real[13].to_ascii_uppercase();
            server.send_to(&real, from).unwrap();
        });
        let r = Resolver::new(
            ResolverConfig::default()
                .servers(vec![server_addr])
                .timeout(Duration::from_secs(2)),
        );
        let ips = r.query("example.test", RecordType::A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn truncated_answer_is_retried_over_tcp() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        // UDP and TCP on the same port, as a DNS server listens.
        let (udp, tcp) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()) {
                break (udp, tcp);
            }
        };
        let server_addr = udp.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, from) = udp.recv_from(&mut buf).unwrap();
            // Too big for UDP: the header and question, with TC set.
            let mut tc = buf[..n].to_vec();
            tc[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
            udp.send_to(&tc, from).unwrap();

            let (mut s, _) = tcp.accept().unwrap();
            let mut len = [0u8; 2];
            s.read_exact(&mut len).unwrap();
            let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut q).unwrap();
            let resp = answer(&q, [1, 2, 3, 4]);
            s.write_all(&(resp.len() as u16).to_be_bytes()).unwrap();
            s.write_all(&resp).unwrap();
        });
        let r = Resolver::new(
            ResolverConfig::default()
                .servers(vec![server_addr])
                .timeout(Duration::from_secs(2)),
        );
        let ips = r.query("big.test", RecordType::A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    /// A TCP server that trickles its answer a byte at a time, each just
    /// inside the read timeout, still cannot hold the query past its
    /// deadline.
    #[test]
    fn a_trickling_tcp_answer_does_not_extend_the_timeout() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let (udp, tcp) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()) {
                break (udp, tcp);
            }
        };
        let server_addr = udp.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, from) = udp.recv_from(&mut buf).unwrap();
            let mut tc = buf[..n].to_vec();
            tc[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
            udp.send_to(&tc, from).unwrap();
            let (mut s, _) = tcp.accept().unwrap();
            let mut len = [0u8; 2];
            let _ = s.read_exact(&mut len);
            let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
            let _ = s.read_exact(&mut q);
            // Announce the largest answer, then send it one byte at a time.
            let _ = s.write_all(&u16::MAX.to_be_bytes());
            for _ in 0..200 {
                if s.write_all(&[0]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let r = Resolver::new(
            ResolverConfig::default()
                .servers(vec![server_addr])
                .timeout(Duration::from_millis(400)),
        );
        let start = std::time::Instant::now();
        assert!(r.query("slow.test", RecordType::A).is_err());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn junk_does_not_extend_the_timeout() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (_, from) = server.recv_from(&mut buf).unwrap();
            for _ in 0..100 {
                let _ = server.send_to(b"junk", from);
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let r = Resolver::new(
            ResolverConfig::default()
                .servers(vec![server_addr])
                .timeout(Duration::from_millis(300)),
        );
        let start = std::time::Instant::now();
        assert!(r.query("example.test", RecordType::A).is_err());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "took {:?}",
            start.elapsed()
        );
    }
}
