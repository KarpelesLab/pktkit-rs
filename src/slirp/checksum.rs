//! Internet checksum helpers used throughout the slirp stack.
//!
//! These duplicate the crate-level helpers but operate over the raw byte
//! buffers slirp manipulates directly. Keeping them local avoids the
//! `IpAddr` enum dispatch on hot paths.

use crate::Protocol;
use crate::checksum::raw_transport_sum;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[inline]
fn fold(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// RFC 1071 Internet checksum.
pub(crate) fn ipv4_header_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        i += 2;
    }
    if hdr.len() & 1 != 0 {
        sum += (hdr[hdr.len() - 1] as u32) << 8;
    }
    fold(sum)
}

/// Same as [`ipv4_header_checksum`]; named separately for callers that want
/// to express intent (e.g. inner ICMP body checksum).
#[inline]
pub(crate) fn internet_checksum(data: &[u8]) -> u16 {
    ipv4_header_checksum(data)
}

/// TCP checksum over the IPv4 pseudo-header + TCP segment (header+payload).
/// `tcp` must include the TCP header (with the checksum field zeroed) and
/// any payload concatenated.
pub(crate) fn tcp_v4_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let s = src.octets();
    let d = dst.octets();
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;
    sum += 6u32;
    sum += tcp.len() as u32;

    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
        i += 2;
    }
    if tcp.len() & 1 != 0 {
        sum += (tcp[tcp.len() - 1] as u32) << 8;
    }
    fold(sum)
}

/// UDP checksum over the IPv4 pseudo-header. `udp` is the UDP header
/// (8 bytes, with the checksum field zeroed); `payload` is concatenated.
pub(crate) fn udp_v4_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8], payload: &[u8]) -> u16 {
    let s = src.octets();
    let d = dst.octets();
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;
    sum += 17u32;
    sum += (udp.len() + payload.len()) as u32;

    let mut i = 0;
    while i + 1 < udp.len() {
        sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        i += 2;
    }
    if udp.len() & 1 != 0 {
        sum += (udp[udp.len() - 1] as u32) << 8;
    }
    i = 0;
    while i + 1 < payload.len() {
        sum += u16::from_be_bytes([payload[i], payload[i + 1]]) as u32;
        i += 2;
    }
    if payload.len() & 1 != 0 {
        sum += (payload[payload.len() - 1] as u32) << 8;
    }
    fold(sum)
}

/// IPv6 pseudo-header checksum (RFC 2460 §8.1) covering an upper-layer
/// packet of `len` bytes (header + payload) carried in `data`.
pub(crate) fn ipv6_pseudo_checksum(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    proto: u8,
    upper_len: u32,
    data: &[u8],
) -> u16 {
    let s = src.octets();
    let d = dst.octets();
    let mut sum: u32 = 0;

    let mut i = 0;
    while i < 16 {
        sum += u16::from_be_bytes([s[i], s[i + 1]]) as u32;
        i += 2;
    }
    let mut i = 0;
    while i < 16 {
        sum += u16::from_be_bytes([d[i], d[i + 1]]) as u32;
        i += 2;
    }
    sum += upper_len >> 16;
    sum += upper_len & 0xFFFF;
    sum += proto as u32;

    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if data.len() & 1 != 0 {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    fold(sum)
}

/// Whether a TCP segment from the guest (header and payload, checksum
/// included) checks out against its pseudo-header. RFC 9293 §3.1 makes
/// the check a MUST; a corrupt segment must not reach the engine, whose
/// ACKs and RSTs it could otherwise drive.
pub(crate) fn tcp_ok(src: IpAddr, dst: IpAddr, tcp: &[u8]) -> bool {
    raw_transport_sum(Protocol::TCP, src, dst, tcp) == 0xFFFF
}

/// Whether a UDP datagram from the guest (exactly its UDP length, header
/// included) checks out. Over IPv4 a checksum of 0 means the sender
/// computed none (RFC 768). Over IPv6 it is not allowed (RFC 8200 §8.1):
/// the zero-checksum exception of RFC 6935/6936 is for tunnel protocols
/// that opt in per port, which no destination here has, so it is dropped.
pub(crate) fn udp_ok(src: IpAddr, dst: IpAddr, udp: &[u8]) -> bool {
    if udp.len() < 8 {
        return false;
    }
    if udp[6..8] == [0, 0] {
        return src.is_ipv4();
    }
    raw_transport_sum(Protocol::UDP, src, dst, udp) == 0xFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_checks_accept_good_and_refuse_bad_sums() {
        let (s4, d4) = (Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(1, 1, 1, 1));
        let (s6, d6): (Ipv6Addr, Ipv6Addr) =
            ("fd00::5".parse().unwrap(), "2001:db8::1".parse().unwrap());
        let mut udp = vec![0x9c, 0x40, 0, 53, 0, 11, 0, 0, b'a', b'b', b'c'];
        // No checksum: fine over IPv4, invalid over IPv6.
        assert!(udp_ok(s4.into(), d4.into(), &udp));
        assert!(!udp_ok(s6.into(), d6.into(), &udp));
        let cs = udp_v4_checksum(s4, d4, &udp[..8], &udp[8..]);
        udp[6..8].copy_from_slice(&cs.to_be_bytes());
        assert!(udp_ok(s4.into(), d4.into(), &udp));
        udp[9] ^= 1;
        assert!(!udp_ok(s4.into(), d4.into(), &udp));
        udp[9] ^= 1;
        udp[6..8].copy_from_slice(&[0, 0]);
        let cs = ipv6_pseudo_checksum(s6, d6, 17, udp.len() as u32, &udp);
        udp[6..8].copy_from_slice(&cs.to_be_bytes());
        assert!(udp_ok(s6.into(), d6.into(), &udp));
        assert!(!udp_ok(s6.into(), "2001:db8::2".parse().unwrap(), &udp));

        let mut tcp = vec![0u8; 24];
        tcp[12] = 5 << 4;
        tcp[20..].copy_from_slice(b"data");
        let cs = tcp_v4_checksum(s4, d4, &tcp);
        tcp[16..18].copy_from_slice(&cs.to_be_bytes());
        assert!(tcp_ok(s4.into(), d4.into(), &tcp));
        tcp[23] ^= 0x80;
        assert!(!tcp_ok(s4.into(), d4.into(), &tcp));
    }

    #[test]
    fn fold_then_recheck_ipv4_header() {
        // A minimal IPv4 header.
        let mut hdr = [0u8; 20];
        hdr[0] = 0x45;
        hdr[2..4].copy_from_slice(&20u16.to_be_bytes());
        hdr[8] = 64;
        hdr[9] = 17;
        hdr[12..16].copy_from_slice(&[10, 0, 0, 1]);
        hdr[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let cs = ipv4_header_checksum(&hdr);
        hdr[10..12].copy_from_slice(&cs.to_be_bytes());
        // After writing the checksum back, re-summing yields 0.
        assert_eq!(ipv4_header_checksum(&hdr), 0);
    }

    #[test]
    fn udp_v4_checksum_matches_pseudo_then_fold() {
        let s = Ipv4Addr::new(1, 2, 3, 4);
        let d = Ipv4Addr::new(5, 6, 7, 8);
        let udp = [0u8; 8];
        let payload = [0u8; 4];
        let cs = udp_v4_checksum(s, d, &udp, &payload);
        // Doesn't panic and is non-zero for nontrivial inputs.
        assert_ne!(cs, 0);
    }
}
