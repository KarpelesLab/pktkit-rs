//! H.323 (Q.931/H.225) Application Layer Gateway.
//!
//! H.323 signalling is ASN.1 PER encoded, which is expensive to parse fully.
//! Like the Go upstream, this is a heuristic ALG: it scans the TCP payload for
//! 6-byte transport addresses (4-byte IPv4 + 2-byte port) and bare 4-byte IPv4
//! addresses matching the inside (outbound) or outside (inbound) address, and
//! rewrites them. Transport addresses with a dynamic port (>= 1024) trigger
//! H.245/RTP expectations.
//!
//! Port of `alg_h323.go`.

use crate::nat::helper::{Expectation, Helper, NatMapping, PacketHelper, PROTO_TCP, PROTO_UDP};
use crate::nat::nat::Nat;
use crate::{checksum, combine_checksums, pseudo_header_checksum, Protocol};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

const H323_PORT: u16 = 1720;
const H323_RTP_TIMEOUT: Duration = Duration::from_secs(120);
/// H.245 dynamic port range lower bound; ports below this are not treated as
/// signalled transport ports.
const H245_PORT_MIN: u16 = 1024;

#[derive(Debug, Default)]
pub struct H323Helper;

impl H323Helper {
    pub fn new() -> H323Helper {
        H323Helper
    }
}

impl Helper for H323Helper {
    fn name(&self) -> &str {
        "h323"
    }
}

impl PacketHelper for H323Helper {
    fn match_outbound(&self, proto: u8, dst_port: u16) -> bool {
        proto == PROTO_TCP && dst_port == H323_PORT
    }

    fn process_outbound(&self, nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
        let (payload_off, payload) = match payload(&pkt) {
            Some(v) => v,
            None => return pkt,
        };
        let inside_ip = match m.inside_ip {
            IpAddr::V4(a) => a,
            _ => return pkt,
        };
        let outside_ip = match nat.outside_addr() {
            Some(a) => a,
            None => return pkt,
        };
        let inside = inside_ip.octets();
        let outside = outside_ip.octets();

        let mut new_payload = payload.to_vec();
        let mut modified = false;
        let mut i = 0usize;
        while i + 6 <= new_payload.len() {
            if new_payload[i..i + 4] == inside {
                let port = u16::from_be_bytes([new_payload[i + 4], new_payload[i + 5]]);
                if port >= H245_PORT_MIN {
                    // Transport address: allocate a mapping (TCP for H.245, with
                    // a UDP fallback for RTP) and register expectations.
                    let mut outside_port = nat.create_mapping(PROTO_TCP, inside_ip, port);
                    if outside_port.is_none() {
                        outside_port = nat.create_mapping(PROTO_UDP, inside_ip, port);
                    }
                    nat.add_expectation(Expectation {
                        proto: PROTO_TCP,
                        remote_ip: Ipv4Addr::UNSPECIFIED,
                        remote_port: 0,
                        inside_ip,
                        inside_port: port,
                        expires: Instant::now() + H323_RTP_TIMEOUT,
                    });
                    nat.add_expectation(Expectation {
                        proto: PROTO_UDP,
                        remote_ip: Ipv4Addr::UNSPECIFIED,
                        remote_port: 0,
                        inside_ip,
                        inside_port: port,
                        expires: Instant::now() + H323_RTP_TIMEOUT,
                    });
                    if port % 2 == 0 {
                        nat.add_expectation(Expectation {
                            proto: PROTO_UDP,
                            remote_ip: Ipv4Addr::UNSPECIFIED,
                            remote_port: 0,
                            inside_ip,
                            inside_port: port + 1,
                            expires: Instant::now() + H323_RTP_TIMEOUT,
                        });
                    }
                    new_payload[i..i + 4].copy_from_slice(&outside);
                    if let Some(op) = outside_port {
                        new_payload[i + 4..i + 6].copy_from_slice(&op.to_be_bytes());
                    }
                    modified = true;
                    i += 6;
                    continue;
                }
                // Bare IP — rewrite the address only.
                new_payload[i..i + 4].copy_from_slice(&outside);
                modified = true;
                i += 4;
            } else {
                i += 1;
            }
        }

        if !modified {
            return pkt;
        }
        h323_rebuild_packet(&pkt, payload_off, &new_payload)
    }

    fn process_inbound(&self, nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
        let (payload_off, payload) = match payload(&pkt) {
            Some(v) => v,
            None => return pkt,
        };
        let inside_ip = match m.inside_ip {
            IpAddr::V4(a) => a,
            _ => return pkt,
        };
        let outside_ip = match nat.outside_addr() {
            Some(a) => a,
            None => return pkt,
        };
        let inside = inside_ip.octets();
        let outside = outside_ip.octets();

        let mut new_payload = payload.to_vec();
        let mut modified = false;
        let mut i = 0usize;
        while i + 6 <= new_payload.len() {
            if new_payload[i..i + 4] == outside {
                let port = u16::from_be_bytes([new_payload[i + 4], new_payload[i + 5]]);
                if port >= H245_PORT_MIN {
                    new_payload[i..i + 4].copy_from_slice(&inside);
                    if port == m.outside_port {
                        new_payload[i + 4..i + 6].copy_from_slice(&m.inside_port.to_be_bytes());
                    }
                    modified = true;
                    i += 6;
                    continue;
                }
                new_payload[i..i + 4].copy_from_slice(&inside);
                modified = true;
                i += 4;
            } else {
                i += 1;
            }
        }

        if !modified {
            return pkt;
        }
        h323_rebuild_packet(&pkt, payload_off, &new_payload)
    }
}

/// Returns `(payload_offset, payload)` for a TCP packet, or `None` if malformed
/// or too short to contain an address.
fn payload(pkt: &[u8]) -> Option<(usize, &[u8])> {
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 20 {
        return None;
    }
    let tcp_hdr_len = (pkt[ihl + 12] >> 4) as usize * 4;
    let off = ihl + tcp_hdr_len;
    if off >= pkt.len() {
        return None;
    }
    let p = &pkt[off..];
    if p.len() < 4 {
        return None;
    }
    Some((off, p))
}

/// Rebuild the packet with the same-length payload, recomputing IP + TCP
/// checksums.
fn h323_rebuild_packet(orig: &[u8], payload_off: usize, new_payload: &[u8]) -> Vec<u8> {
    let ihl = (orig[0] & 0x0F) as usize * 4;
    let mut out = orig.to_vec();
    out[payload_off..].copy_from_slice(new_payload);

    // Total length is unchanged (address rewrite is same-length).
    out[10..12].copy_from_slice(&[0, 0]);
    let ip_csum = checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    if out.len() >= ihl + 18 {
        let tcp_len = (out.len() - ihl) as u16;
        let src = Ipv4Addr::new(out[12], out[13], out[14], out[15]);
        let dst = Ipv4Addr::new(out[16], out[17], out[18], out[19]);
        out[ihl + 16..ihl + 18].copy_from_slice(&[0, 0]);
        let ph = pseudo_header_checksum(Protocol::TCP, IpAddr::V4(src), IpAddr::V4(dst), tcp_len);
        let seg = checksum(&out[ihl..]);
        let cs = combine_checksums(ph, seg);
        out[ihl + 16..ihl + 18].copy_from_slice(&cs.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::nat::Nat;
    use crate::{IpPrefix, L3Device, Packet};
    use std::sync::{Arc, Mutex as StdMutex};

    fn pfx(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    fn build_h323(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let ic = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ic.to_be_bytes());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[32] = 0x50; // data offset 5
        p[33] = 0x18; // PSH|ACK
        p[40..].copy_from_slice(payload);
        let ph = pseudo_header_checksum(
            Protocol::TCP,
            IpAddr::V4(src),
            IpAddr::V4(dst),
            (20 + payload.len()) as u16,
        );
        let seg = checksum(&p[20..]);
        let cs = combine_checksums(ph, seg);
        p[36..38].copy_from_slice(&cs.to_be_bytes());
        p
    }

    fn payload_of(pkt: &[u8]) -> &[u8] {
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        let off = (pkt[ihl + 12] >> 4) as usize * 4;
        &pkt[ihl + off..]
    }

    #[test]
    fn h323_rewrites_transport_address_and_expectation() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_packet_helper(Arc::new(H323Helper::new()));

        let captured = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = captured.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        // Payload embeds a transport address: 10.0.0.5 : 4660 (0x1234).
        let inside = Ipv4Addr::new(10, 0, 0, 5);
        let mut body = vec![0xAA, 0xBB];
        body.extend_from_slice(&inside.octets());
        body.extend_from_slice(&0x1234u16.to_be_bytes());
        body.extend_from_slice(&[0xCC, 0xDD]);
        let pkt = build_h323(inside, 40000, Ipv4Addr::new(198, 51, 100, 9), H323_PORT, &body);
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();

        let out = captured.lock().unwrap();
        assert_eq!(out.len(), 1);
        let p = payload_of(&out[0]);
        // IP at offset 2 rewritten to outside.
        assert_eq!(&p[2..6], &[203, 0, 113, 1]);
        // Port at offset 6 rewritten to a NAT-range mapped port.
        let mapped = u16::from_be_bytes([p[6], p[7]]);
        assert!(mapped >= 10000, "expected mapped port, got {}", mapped);

        // The expectation should let an inbound RTP/UDP packet reach the inside.
        drop(out);
        let inbound = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let i = inbound.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            i.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        // UDP inbound to the mapped TCP port won't match (different proto); use
        // the TCP expectation: an inbound TCP to mapped port reaches inside.
        let reply = {
            let total = 20 + 20;
            let mut q = vec![0u8; total];
            q[0] = 0x45;
            q[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            q[8] = 64;
            q[9] = PROTO_TCP;
            q[12..16].copy_from_slice(&[198, 51, 100, 9]);
            q[16..20].copy_from_slice(&[203, 0, 113, 1]);
            let ic = checksum(&q[..20]);
            q[10..12].copy_from_slice(&ic.to_be_bytes());
            q[20..22].copy_from_slice(&50000u16.to_be_bytes());
            q[22..24].copy_from_slice(&mapped.to_be_bytes());
            q[32] = 0x50;
            q[33] = 0x02; // SYN
            q
        };
        nat.outside().send(Packet::from_slice(&reply)).unwrap();
        let inbound = inbound.lock().unwrap();
        assert_eq!(inbound.len(), 1, "H.245/RTP channel should reach inside");
        assert_eq!(&inbound[0][16..20], &[10, 0, 0, 5]);
    }

    #[test]
    fn h323_rewrites_bare_ip() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = H323Helper::new();
        let inside = Ipv4Addr::new(10, 0, 0, 5);
        // Bare IP followed by a low port (<1024) — treated as bare IP rewrite.
        let mut body = vec![0x01];
        body.extend_from_slice(&inside.octets());
        body.extend_from_slice(&[0x00, 0x50]); // port 80, below H245_PORT_MIN
        let m = NatMapping {
            proto: PROTO_TCP,
            inside_ip: IpAddr::V4(inside),
            inside_port: 40000,
            outside_port: 20000,
        };
        let pkt = build_h323(inside, 40000, Ipv4Addr::new(198, 51, 100, 9), H323_PORT, &body);
        let out = h.process_outbound(&nat, pkt, &m);
        let p = payload_of(&out);
        assert_eq!(&p[1..5], &[203, 0, 113, 1]);
        // Port preserved (bare-IP path does not touch the port).
        assert_eq!(&p[5..7], &[0x00, 0x50]);
    }

    #[test]
    fn h323_inbound_rewrites_outside_to_inside() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = H323Helper::new();
        let inside = Ipv4Addr::new(10, 0, 0, 5);
        let outside = Ipv4Addr::new(203, 0, 113, 1);
        // Inbound payload contains the outside address as a bare IP.
        let mut body = vec![0x09];
        body.extend_from_slice(&outside.octets());
        body.extend_from_slice(&[0x00, 0x01]); // low port -> bare IP path
        let m = NatMapping {
            proto: PROTO_TCP,
            inside_ip: IpAddr::V4(inside),
            inside_port: 1720,
            outside_port: 25000,
        };
        let pkt = build_h323(outside, 1720, outside, 1720, &body);
        let out = h.process_inbound(&nat, pkt, &m);
        let p = payload_of(&out);
        assert_eq!(&p[1..5], &[10, 0, 0, 5]);
    }
}
