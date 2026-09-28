//! DNS resolver.
//!
//! [`wire`] holds the pure RFC 1035 query builder and response parser (no
//! I/O — easy to unit test). [`Resolver`] runs those over a real
//! [`UdpSocket`], querying each configured server in turn until one answers,
//! and asks again over TCP when the answer comes back truncated.
//!
//! Lookups do not traverse the virtual network: the `Resolver`, and
//! [`Client::resolve`](super::Client::resolve) and the HTTP client built on
//! it, send their queries from the host's real sockets, so they see the
//! host's routes and the servers must be reachable from the host. A server
//! only reachable inside the virtual network needs a query of the caller's
//! own, sent over a [`UdpConn`](super::UdpConn).

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
    /// Returns `None` if the name cannot be encoded (see [`encode_name`]).
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

    /// Encode a domain name in wire format. `None` if it has an empty
    /// label, a label over 63 octets, or is over 255 octets encoded
    /// (RFC 1035 §2.3.4, §3.1). One trailing dot, marking the name as
    /// absolute, is allowed.
    pub fn encode_name(name: &str) -> Option<Vec<u8>> {
        let name = name.strip_suffix('.').unwrap_or(name);
        let mut buf = Vec::with_capacity(name.len() + 2);
        if !name.is_empty() {
            for part in name.split('.') {
                // A zero length is the root label, which ends a name: one
                // in the middle would cut the name short on the wire.
                if part.is_empty() || part.len() > 63 {
                    return None;
                }
                buf.push(part.len() as u8);
                buf.extend_from_slice(part.as_bytes());
            }
        }
        buf.push(0); // root label
        (buf.len() <= 255).then_some(buf)
    }

    const TYPE_CNAME: u16 = 5;
    const CLASS_IN: u16 = 1;

    /// Most CNAMEs followed from the question's name. Real chains are a
    /// few links long; this only has to stop a looping one.
    const MAX_CNAME_HOPS: usize = 16;

    /// Most compression pointers followed reading one name (see
    /// [`read_name`]).
    pub(crate) const MAX_POINTER_HOPS: usize = 128;

    /// Parse the response `data` to `query` (the whole message sent),
    /// returning the addresses it gives for the name asked about.
    ///
    /// The response must carry the query's ID, be a response, and repeat
    /// its question -- all checked before its RCODE is believed, so an
    /// error answer is held to the same test as a positive one -- and have
    /// RCODE 0. Of the answers, only CLASS IN records of the
    /// type asked for count, and only those owned by the name asked about
    /// or one it leads to through CNAMEs in the same answer (RFC 1034
    /// §3.6.2, §5.3.3): anything else in the answer section is not an
    /// answer to this question, and taking it would let a server, or a
    /// forger, slip in addresses for a name nobody asked about.
    pub fn parse_response(data: &[u8], query: &[u8]) -> Result<Vec<IpAddr>, &'static str> {
        if data.len() < 12 {
            return Err("response too short");
        }
        if query.len() < 12 || data[..2] != query[..2] {
            return Err("transaction ID mismatch");
        }
        let flags = u16::from_be_bytes([data[2], data[3]]);
        if flags & 0x8000 == 0 {
            return Err("not a response");
        }
        if !question_matches(data, query) {
            return Err("answer to another question");
        }
        if flags & 0x000F != 0 {
            return Err("DNS error rcode");
        }
        let (qname, qend) = read_name(query, 12).ok_or("malformed query")?;
        let qtype = query.get(qend..qend + 2).ok_or("malformed query")?;
        let qtype = u16::from_be_bytes([qtype[0], qtype[1]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);

        // The question matched the query's, so it ends where the query's
        // does.
        let mut off = qend + 4;
        // Owner, type, and RDATA range of each CLASS IN answer.
        let mut records = Vec::new();
        for _ in 0..ancount {
            let (owner, o) = read_name(data, off).ok_or("malformed answer")?;
            let rr = data.get(o..o + 10).ok_or("truncated answer")?;
            let rtype = u16::from_be_bytes([rr[0], rr[1]]);
            let class = u16::from_be_bytes([rr[2], rr[3]]);
            let rdlength = u16::from_be_bytes([rr[8], rr[9]]) as usize;
            let rdata = o + 10..o + 10 + rdlength;
            if rdata.end > data.len() {
                return Err("truncated answer");
            }
            off = rdata.end;
            if class == CLASS_IN {
                records.push((owner, rtype, rdata));
            }
        }

        // The names the answer is for: the question's, and each one a CNAME
        // leads to from it, in turn.
        let mut names = vec![qname];
        while names.len() <= MAX_CNAME_HOPS {
            let last = names.last().expect("never empty");
            let Some((_, _, rdata)) = records
                .iter()
                .find(|(owner, t, _)| *t == TYPE_CNAME && owner == last)
            else {
                break;
            };
            let (target, end) = read_name(data, rdata.start).ok_or("malformed CNAME")?;
            if end != rdata.end {
                return Err("malformed CNAME");
            }
            if names.contains(&target) {
                break; // a loop: nothing further down it
            }
            names.push(target);
        }

        let mut out = Vec::new();
        for (owner, rtype, rdata) in &records {
            if *rtype != qtype || !names.contains(owner) {
                continue;
            }
            let rdata = &data[rdata.clone()];
            match (*rtype, rdata.len()) {
                (1, 4) => out.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                ))),
                (28, 16) => {
                    let b: [u8; 16] = rdata.try_into().expect("length checked");
                    out.push(IpAddr::V6(Ipv6Addr::from(b)));
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// Read the (possibly compressed) name at `off` in the message `data`.
    /// Returns it in wire form with its labels lowercased, so names compare
    /// without regard to ASCII case (RFC 4343) by plain equality, and the
    /// offset just past it where it sits.
    ///
    /// Each compression pointer must point before the one followed last
    /// (or, the first, before the name itself), as any a compressor writes
    /// do, to an earlier occurrence (RFC 1035 §4.1.4): so the walk cannot
    /// loop. The name must fit the 255-octet limit (§3.1), and label types
    /// other than plain labels and pointers are refused (RFC 6891 §5).
    ///
    /// Backwards-only pointers still let a chain of bare pointers run the
    /// length of the message, and every record's name is read through it:
    /// a crafted 64 KiB answer over TCP would cost tens of thousands of hops
    /// per record. A name has at most 127 labels, so it never needs more
    /// than [`MAX_POINTER_HOPS`] pointers; past that the name is refused.
    pub fn read_name(data: &[u8], mut off: usize) -> Option<(Vec<u8>, usize)> {
        let mut name = Vec::new();
        let mut end = None;
        let mut limit = off;
        let mut hops = 0;
        loop {
            let l = *data.get(off)? as usize;
            match l & 0xC0 {
                0 if l == 0 => {
                    name.push(0);
                    return Some((name, end.unwrap_or(off + 1)));
                }
                0 => {
                    let label = data.get(off + 1..off + 1 + l)?;
                    // With the root label still to come.
                    if name.len() + 1 + l + 1 > 255 {
                        return None;
                    }
                    name.push(l as u8);
                    name.extend(label.iter().map(u8::to_ascii_lowercase));
                    off += 1 + l;
                }
                0xC0 => {
                    let target = (l & 0x3F) << 8 | *data.get(off + 1)? as usize;
                    hops += 1;
                    if target >= limit || hops > MAX_POINTER_HOPS {
                        return None;
                    }
                    end.get_or_insert(off + 2);
                    limit = target;
                    off = target;
                }
                _ => return None,
            }
        }
    }

    /// Whether `response` answers the question asked in `query` (both whole
    /// messages): one question, same name, type and class. The name is
    /// compared without regard to ASCII case (RFC 4343), since servers and
    /// resolvers may echo it in another case.
    pub fn question_matches(response: &[u8], query: &[u8]) -> bool {
        if response.len() < 12 || query.len() < 12 || response[4..6] != [0, 1] {
            return false;
        }
        let Some((_, name_end)) = read_name(query, 12) else {
            return false;
        };
        let q = &query[12..];
        let (name_len, len) = (name_end - 12, q.len());
        let Some(r) = response.get(12..12 + len) else {
            return false;
        };
        r[..name_len].eq_ignore_ascii_case(&q[..name_len]) && r[name_len..] == q[name_len..]
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
    /// Send the name in a random mix of upper and lower case, and take
    /// over UDP only an answer whose question repeats it letter for letter
    /// (DNS 0x20, draft-vixie-dnsext-dns0x20). Default on.
    ///
    /// Names compare without regard to case, so the server answers the
    /// same question; a forger racing it has to guess the case of every
    /// letter as well as the ID and port. Servers copy the question into
    /// the answer as sent (RFC 1035 §4.1.1), and nearly all keep its case;
    /// one that does not is never answered in time, and needs this off.
    pub randomize_case: bool,
}

#[cfg(not(target_family = "wasm"))]
setters! {
    ResolverConfig {
        set servers: Vec<SocketAddr>;
        set timeout: Duration;
        set randomize_case: bool;
    }
}

#[cfg(not(target_family = "wasm"))]
impl Default for ResolverConfig {
    fn default() -> Self {
        ResolverConfig {
            servers: Vec::new(),
            timeout: Duration::from_secs(5),
            randomize_case: true,
        }
    }
}

/// A transaction ID an off-path host cannot predict. `crate::rand::u32`
/// is seeded from the clock, which is guessable.
#[cfg(not(target_family = "wasm"))]
fn query_id() -> u16 {
    crate::rand::unpredictable_u64() as u16
}

/// Flip the letters of the question name in `query` (a whole message)
/// to random case, for DNS 0x20 (see [`ResolverConfig::randomize_case`]).
/// The bits come from the same keyed source as the ID, since a forger
/// able to predict them gains nothing from the exercise.
#[cfg(not(target_family = "wasm"))]
fn randomize_case(query: &mut [u8]) {
    let mut bits = 0u64;
    let mut left = 0;
    let mut off = 12;
    while let Some(&len) = query.get(off) {
        // Built by build_query: plain labels, ending in the root.
        if len == 0 || len & 0xC0 != 0 {
            break;
        }
        let end = (off + 1 + len as usize).min(query.len());
        for b in &mut query[off + 1..end] {
            if !b.is_ascii_alphabetic() {
                continue;
            }
            if left == 0 {
                bits = crate::rand::unpredictable_u64();
                left = 64;
            }
            if bits & 1 == 1 {
                *b ^= 0x20;
            }
            bits >>= 1;
            left -= 1;
        }
        off = end;
    }
}

#[cfg(not(target_family = "wasm"))]
fn time_left(deadline: Option<Instant>) -> io::Result<Option<Duration>> {
    super::time_left(deadline, "DNS query timed out")
}

/// A DNS resolver over the host's real sockets (UDP, then TCP for a
/// truncated answer); its queries do not cross the virtual network.
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
            cfg: ResolverConfig::default().servers(
                servers
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, 53))
                    .collect(),
            ),
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
        let mut query = wire::build_query(id, name, rtype)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid domain name"))?;
        if self.cfg.randomize_case {
            randomize_case(&mut query);
        }

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
        // extend it. A timeout past what an Instant can hold is none.
        let deadline = Instant::now().checked_add(self.cfg.timeout);
        let mut buf = [0u8; 1500];
        loop {
            sock.set_read_timeout(time_left(deadline)?)?;
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
            // ignored: wrong ID, not a response, another question, or --
            // with 0x20 -- the question in other letter case than sent,
            // which is what an off-path forger's would be. An error answer
            // (SERVFAIL, NXDOMAIN) has to pass the same checks before it
            // ends the query, so a forged one is no easier than a forged
            // address.
            if resp.len() < 12
                || resp[..2] != id.to_be_bytes()
                || resp[2] & 0x80 == 0
                || !wire::question_matches(resp, &query)
                || (self.cfg.randomize_case && resp.get(12..query.len()) != query.get(12..))
            {
                continue;
            }
            if resp[2] & 0x02 != 0 {
                // TC: the answer did not fit in a datagram, and what came
                // is not all of it. Ask again over TCP (RFC 7766 §5).
                return self.query_tcp(server, &query, deadline);
            }
            return wire::parse_response(resp, &query)
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
        deadline: Option<Instant>,
    ) -> io::Result<Vec<IpAddr>> {
        use std::io::{Read, Write};

        let left = || time_left(deadline);
        let mut s = match left()? {
            Some(t) => std::net::TcpStream::connect_timeout(&server, t)?,
            None => std::net::TcpStream::connect(server)?,
        };
        s.set_write_timeout(left()?)?;
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
                s.set_read_timeout(left()?)?;
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
        // be answering this question, which the parser checks.
        wire::parse_response(&resp, query)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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
    fn encode_name_rejects_empty_labels_and_long_names() {
        for bad in ["a..com", ".com", "..", "a.com.."] {
            assert!(wire::encode_name(bad).is_none(), "{bad:?}");
        }
        // The root, with or without its dot.
        assert_eq!(wire::encode_name(".").unwrap(), b"\x00");
        assert_eq!(wire::encode_name("").unwrap(), b"\x00");

        // 4 labels of 63 octets and one of 1: 4 * 64 + 2 + 1 = 259 octets.
        let label = "a".repeat(63);
        let long = format!("{label}.{label}.{label}.{label}.b");
        assert!(wire::encode_name(&long).is_none());
        // 3 labels of 63 and one of 61: 3 * 64 + 62 + 1 = 255, the most.
        let max = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        assert_eq!(wire::encode_name(&max).unwrap().len(), 255);
        assert!(wire::encode_name(&format!("{max}.")).is_some());
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

        let q = wire::build_query(id, "a.com", RecordType::A).unwrap();
        let ips = wire::parse_response(&r, &q).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    /// Append a resource record owned by `owner` (wire form, pointers
    /// allowed) to `msg` and count it as an answer.
    fn push_rr(msg: &mut Vec<u8>, owner: &[u8], rtype: u16, class: u16, rdata: &[u8]) {
        msg.extend_from_slice(owner);
        msg.extend_from_slice(&rtype.to_be_bytes());
        msg.extend_from_slice(&class.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(rdata);
        let an = u16::from_be_bytes([msg[6], msg[7]]) + 1;
        msg[6..8].copy_from_slice(&an.to_be_bytes());
    }

    /// `query` turned into a response with no answers yet.
    fn response_to(query: &[u8]) -> Vec<u8> {
        let mut r = query.to_vec();
        r[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        r
    }

    #[test]
    fn only_answers_to_the_question_count() {
        let q = wire::build_query(7, "www.example.test", RecordType::A).unwrap();
        let name = |s| wire::encode_name(s).unwrap();
        let v4 = |ip: [u8; 4]| IpAddr::V4(ip.into());

        let mut r = response_to(&q);
        // Owned by another name, of another class, of another type: none
        // of these answers the question.
        push_rr(&mut r, &name("evil.test"), 1, 1, &[6, 6, 6, 6]);
        push_rr(&mut r, &[0xC0, 12], 1, 3, &[6, 6, 6, 7]);
        push_rr(&mut r, &[0xC0, 12], 28, 1, &[6; 16]);
        // The question's name, in another case, and through a pointer.
        push_rr(&mut r, &name("WWW.Example.TEST"), 1, 1, &[1, 1, 1, 1]);
        push_rr(&mut r, &[0xC0, 12], 1, 1, &[1, 1, 1, 2]);
        assert_eq!(
            wire::parse_response(&r, &q).unwrap(),
            [v4([1, 1, 1, 1]), v4([1, 1, 1, 2])]
        );

        // Through a CNAME chain, in any order, and nothing off it.
        let mut r = response_to(&q);
        let b_at = r.len() + 12; // where the first CNAME's target sits
        push_rr(&mut r, &[0xC0, 12], 5, 1, &name("b.test"));
        push_rr(&mut r, &name("c.test"), 1, 1, &[3, 3, 3, 3]);
        push_rr(&mut r, &name("other.test"), 1, 1, &[6, 6, 6, 6]);
        push_rr(
            &mut r,
            &[0xC0, b_at as u8],
            5,
            1,
            &[1, b'c', 0xC0, b_at as u8 + 2],
        );
        push_rr(&mut r, &name("other.test"), 5, 1, &name("c.test"));
        assert_eq!(wire::parse_response(&r, &q).unwrap(), [v4([3, 3, 3, 3])]);

        // A CNAME loop ends the chain rather than the parse.
        let mut r = response_to(&q);
        push_rr(&mut r, &[0xC0, 12], 5, 1, &name("x.test"));
        push_rr(&mut r, &name("x.test"), 5, 1, &name("www.example.test"));
        push_rr(&mut r, &name("x.test"), 1, 1, &[4, 4, 4, 4]);
        assert_eq!(wire::parse_response(&r, &q).unwrap(), [v4([4, 4, 4, 4])]);

        // A response to another question, or with another ID, is refused.
        let other = wire::build_query(7, "evil.test", RecordType::A).unwrap();
        assert!(wire::parse_response(&response_to(&other), &q).is_err());
        let mut r = response_to(&q);
        r[1] ^= 1;
        assert!(wire::parse_response(&r, &q).is_err());
    }

    #[test]
    fn compression_pointers_cannot_loop_or_point_ahead() {
        let q = wire::build_query(7, "a.test", RecordType::A).unwrap();
        for owner in [
            &[0xC0, 12][..],     // fine: the question's name
            &[0xC0, 0xFF],       // ahead of itself
            &[1, b'x', 0xC0, 2], // at the flags: not a label
        ] {
            let mut r = response_to(&q);
            let at = r.len();
            push_rr(&mut r, owner, 1, 1, &[1, 2, 3, 4]);
            let ok = owner == [0xC0, 12];
            assert_eq!(wire::parse_response(&r, &q).is_ok(), ok, "{owner:?}");
            // A pointer to itself.
            r[at..at + 2].copy_from_slice(&[0xC0 | (at >> 8) as u8, at as u8]);
            assert!(wire::read_name(&r, at).is_none());
        }
        // Two names pointing at each other.
        let msg = [0u8, 0, 0xC0, 4, 0xC0, 2];
        assert!(wire::read_name(&msg, 2).is_none());
        assert!(wire::read_name(&msg, 4).is_none());
        // Past 255 octets through pointers: each name is a 63-octet label
        // in front of the one before it.
        let mut msg = vec![63];
        msg.extend_from_slice(&[b'a'; 63]);
        msg.push(0);
        let mut starts = vec![0];
        for _ in 0..4 {
            let prev = *starts.last().unwrap();
            starts.push(msg.len());
            msg.push(63);
            msg.extend_from_slice(&[b'a'; 63]);
            msg.extend_from_slice(&[0xC0 | (prev >> 8) as u8, prev as u8]);
        }
        // 3 labels: 193 octets; 4: 257.
        assert_eq!(wire::read_name(&msg, starts[2]).unwrap().0.len(), 193);
        assert!(wire::read_name(&msg, starts[3]).is_none());
    }

    /// A chain of bare pointers, each to the one before, adds nothing to
    /// the name, so the 255-octet limit never stops it: the hop count does.
    #[test]
    fn pointer_chains_are_capped_in_hops() {
        let mut msg = vec![0u8]; // the root name, at 0
        let mut last = 0;
        for _ in 0..1000 {
            let at = msg.len();
            msg.extend_from_slice(&[0xC0 | (last >> 8) as u8, last as u8]);
            last = at;
        }
        // The pointer MAX_POINTER_HOPS links from the root still reads.
        let within = 1 + 2 * (wire::MAX_POINTER_HOPS - 1);
        assert_eq!(wire::read_name(&msg, within).unwrap().0, [0]);
        assert!(wire::read_name(&msg, within + 2).is_none());
        assert!(wire::read_name(&msg, last).is_none());
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
        let q = wire::build_query(0x1234, "a.com", RecordType::A).unwrap();
        let mut r = q.clone();
        r[..2].copy_from_slice(&[0, 0]);
        r[2] = 0x81;
        assert!(wire::parse_response(&r, &q).is_err());
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

        // A timeout too long for an Instant to reach is no deadline.
        let r = Resolver::new(
            ResolverConfig::default()
                .servers(vec![server_addr])
                .timeout(Duration::MAX),
        );
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
    fn records_for_other_names_are_not_answers() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            let mut resp = answer(&buf[..n], [1, 2, 3, 4]);
            push_rr(
                &mut resp,
                &wire::encode_name("evil.test").unwrap(),
                1,
                1,
                &[6, 6, 6, 6],
            );
            server.send_to(&resp, from).unwrap();
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
            let real = answer(&buf[..n], [1, 2, 3, 4]);
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
            start.elapsed() < Duration::from_secs(4),
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
            start.elapsed() < Duration::from_secs(4),
            "took {:?}",
            start.elapsed()
        );
    }

    /// The query's name, lowercased: what a forger who cannot see the
    /// query would echo.
    fn lowercased(query: &[u8]) -> Vec<u8> {
        let mut q = query.to_vec();
        q[12..].make_ascii_lowercase();
        q
    }

    #[test]
    fn a_forged_error_in_the_wrong_case_does_not_end_the_query() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            // A SERVFAIL with the right ID and port, from a forger who
            // could not see the query's letter case.
            let mut forged = lowercased(&buf[..n]);
            forged[2..4].copy_from_slice(&0x8182u16.to_be_bytes());
            server.send_to(&forged, from).unwrap();
            server
                .send_to(&answer(&buf[..n], [1, 2, 3, 4]), from)
                .unwrap();
        });
        let r = Resolver::new(
            ResolverConfig::default()
                .servers(vec![server_addr])
                .timeout(Duration::from_secs(2)),
        );
        let name = "abcdefghijklmnopqrstuvwxyz.example.test";
        let ips = r.query(name, RecordType::A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn query_names_go_out_in_random_case() {
        let name = "abcdefghijklmnopqrstuvwxyz.example.test";
        let plain = wire::build_query(1, name, RecordType::A).unwrap();
        let mut q = plain.clone();
        randomize_case(&mut q);
        assert!(wire::question_matches(&q, &plain), "not the same name");
        assert_ne!(q, plain, "35 letters, and not one flipped");
        let mut again = plain.clone();
        randomize_case(&mut again);
        assert_ne!(q, again, "the same case twice");
        // Only letters change; lengths and the rest stay.
        assert_eq!(lowercased(&q), plain);
    }

    #[test]
    fn case_randomization_can_be_turned_off_for_servers_that_fold_case() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            let mut resp = answer(&buf[..n], [1, 2, 3, 4]);
            let end = n;
            resp[12..end].make_ascii_uppercase();
            server.send_to(&resp, from).unwrap();
        });
        let r = Resolver::new(
            ResolverConfig::default()
                .servers(vec![server_addr])
                .timeout(Duration::from_secs(2))
                .randomize_case(false),
        );
        let ips = r.query("example.test", RecordType::A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }
}
