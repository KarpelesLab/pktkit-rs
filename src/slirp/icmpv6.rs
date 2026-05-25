//! IPv6 ICMP handling: echo replies.
//!
//! Mirrors `slirp/icmpv6.go`. Router/Neighbor Discovery is intentionally
//! ignored — slirp operates above L2.

use crate::slirp::checksum::ipv6_pseudo_checksum;
use std::net::Ipv6Addr;

pub(crate) const ICMPV6_ECHO_REQUEST: u8 = 128;
pub(crate) const ICMPV6_ECHO_REPLY: u8 = 129;

/// Process an ICMPv6 packet. Returns a reply packet if appropriate, or
/// `None` for messages we ignore (RS/RA/NS/NA, unknown types).
pub(crate) fn build_icmpv6_echo_reply(
    packet: &[u8],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    transport_off: usize,
) -> Option<Vec<u8>> {
    if packet.len() < transport_off + 8 {
        return None;
    }
    let icmp = &packet[transport_off..];
    if icmp.len() < 8 {
        return None;
    }
    if icmp[0] != ICMPV6_ECHO_REQUEST {
        return None;
    }

    let mut reply_icmp = icmp.to_vec();
    reply_icmp[0] = ICMPV6_ECHO_REPLY;
    reply_icmp[1] = 0;
    reply_icmp[2..4].copy_from_slice(&0u16.to_be_bytes());

    let cs = ipv6_pseudo_checksum(dst_ip, src_ip, 58, reply_icmp.len() as u32, &reply_icmp);
    reply_icmp[2..4].copy_from_slice(&cs.to_be_bytes());

    let mut pkt = vec![0u8; 40 + reply_icmp.len()];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(reply_icmp.len() as u16).to_be_bytes());
    pkt[6] = 58;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&dst_ip.octets());
    pkt[24..40].copy_from_slice(&src_ip.octets());
    pkt[40..].copy_from_slice(&reply_icmp);
    Some(pkt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_echo_request6(src: Ipv6Addr, dst: Ipv6Addr, body: &[u8]) -> Vec<u8> {
        let icmp_len = 8 + body.len();
        let mut p = vec![0u8; 40 + icmp_len];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
        p[6] = 58;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p[40] = ICMPV6_ECHO_REQUEST;
        p[40 + 4] = 0xab; // id
        p[40 + 5] = 0xcd;
        p[40 + 6] = 0x00; // seq
        p[40 + 7] = 0x01;
        p[40 + 8..40 + 8 + body.len()].copy_from_slice(body);
        let cs = ipv6_pseudo_checksum(src, dst, 58, icmp_len as u32, &p[40..]);
        p[40 + 2..40 + 4].copy_from_slice(&cs.to_be_bytes());
        p
    }

    #[test]
    fn echo_reply_basic() {
        let src: Ipv6Addr = "fe80::5".parse().unwrap();
        let dst: Ipv6Addr = "fe80::1".parse().unwrap();
        let req = build_echo_request6(src, dst, b"ping");
        let reply = build_icmpv6_echo_reply(&req, src, dst, 40).unwrap();
        assert_eq!(reply[40], ICMPV6_ECHO_REPLY);
        // Source/dest swapped.
        assert_eq!(&reply[8..24], &dst.octets());
        assert_eq!(&reply[24..40], &src.octets());
    }

    #[test]
    fn unknown_type_ignored() {
        let src: Ipv6Addr = "fe80::5".parse().unwrap();
        let dst: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut req = build_echo_request6(src, dst, b"x");
        req[40] = 1; // Destination Unreachable
        assert!(build_icmpv6_echo_reply(&req, src, dst, 40).is_none());
    }
}
