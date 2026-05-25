//! IPv4 ICMP handling: answers Echo Requests addressed to the stack.
//!
//! Mirrors `slirp/icmpv4.go`. Anything that isn't a ping for our own
//! interface is dropped silently.

use crate::slirp::checksum::{internet_checksum, ipv4_header_checksum};
use std::net::{IpAddr, Ipv4Addr};

/// Build an ICMP echo reply for `ip` (the full IPv4 packet). Returns `None`
/// if the packet isn't a ping for us.
pub(crate) fn build_icmpv4_echo_reply(
    ip: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ihl: usize,
    our_ip: Option<IpAddr>,
) -> Option<Vec<u8>> {
    if ip.len() < ihl + 8 {
        return None;
    }
    let icmp = &ip[ihl..];
    if icmp.len() < 8 {
        return None;
    }
    // Only echo requests (type 8, code 0).
    if icmp[0] != 8 || icmp[1] != 0 {
        return None;
    }
    match our_ip {
        Some(IpAddr::V4(a)) if a == dst_ip => {}
        _ => return None,
    }

    let mut reply = ip.to_vec();
    reply[12..16].copy_from_slice(&dst_ip.octets());
    reply[16..20].copy_from_slice(&src_ip.octets());
    reply[8] = 64; // TTL

    {
        let icmp_reply = &mut reply[ihl..];
        icmp_reply[0] = 0; // echo reply
        icmp_reply[1] = 0;
        icmp_reply[2..4].copy_from_slice(&0u16.to_be_bytes());
        let cs = internet_checksum(icmp_reply);
        icmp_reply[2..4].copy_from_slice(&cs.to_be_bytes());
    }

    reply[10..12].copy_from_slice(&0u16.to_be_bytes());
    let hcs = ipv4_header_checksum(&reply[..ihl]);
    reply[10..12].copy_from_slice(&hcs.to_be_bytes());

    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_echo_request(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let ihl = 20usize;
        let total = ihl + 8 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 1; // ICMP
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let hcs = ipv4_header_checksum(&p[..ihl]);
        p[10..12].copy_from_slice(&hcs.to_be_bytes());

        // ICMP echo request
        p[ihl] = 8;
        p[ihl + 1] = 0;
        p[ihl + 4] = 0x12; // id
        p[ihl + 5] = 0x34;
        p[ihl + 6] = 0x00; // seq
        p[ihl + 7] = 0x01;
        p[ihl + 8..ihl + 8 + payload.len()].copy_from_slice(payload);
        let cs = internet_checksum(&p[ihl..]);
        p[ihl + 2..ihl + 4].copy_from_slice(&cs.to_be_bytes());
        p
    }

    #[test]
    fn echo_reply_swaps_addresses() {
        let src = Ipv4Addr::new(10, 0, 0, 5);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let req = build_echo_request(src, dst, b"ping");
        let reply = build_icmpv4_echo_reply(&req, src, dst, 20, Some(IpAddr::V4(dst))).unwrap();
        // Swapped.
        assert_eq!(&reply[12..16], &dst.octets());
        assert_eq!(&reply[16..20], &src.octets());
        // Type changed to 0.
        assert_eq!(reply[20], 0);
        assert_eq!(reply[21], 0);
        // Both checksums verify.
        assert_eq!(ipv4_header_checksum(&reply[..20]), 0);
        assert_eq!(internet_checksum(&reply[20..]), 0);
    }

    #[test]
    fn ignores_non_echo() {
        let src = Ipv4Addr::new(10, 0, 0, 5);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let mut req = build_echo_request(src, dst, b"x");
        req[20] = 3; // Destination Unreachable
        assert!(build_icmpv4_echo_reply(&req, src, dst, 20, Some(IpAddr::V4(dst))).is_none());
    }

    #[test]
    fn ignores_other_destination() {
        let src = Ipv4Addr::new(10, 0, 0, 5);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let req = build_echo_request(src, dst, b"x");
        // dst is not ours.
        let other = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(build_icmpv4_echo_reply(&req, src, dst, 20, Some(other)).is_none());
    }
}
