//! Internet checksum helpers used throughout the slirp stack.
//!
//! These duplicate the crate-level helpers but operate over the raw byte
//! buffers slirp manipulates directly. Keeping them local avoids the
//! `IpAddr` enum dispatch on hot paths.

use std::net::{Ipv4Addr, Ipv6Addr};

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

#[cfg(test)]
mod tests {
    use super::*;

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
