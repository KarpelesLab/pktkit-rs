//! Packet-building helpers for the slirp stack.
//!
//! These mirror Go's `buildPacket4` / `buildPacket6` — they wrap a raw
//! transport-layer segment (TCP) in an IP header with checksums filled in.

use crate::slirp::checksum::{ipv4_header_checksum, ipv6_pseudo_checksum, tcp_v4_checksum};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Wrap a TCP segment in an IPv4 header (no Ethernet). Computes the IP and
/// TCP checksums in-place. Returns the full packet bytes.
pub(crate) fn build_packet4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_seg: &[u8]) -> Vec<u8> {
    let ihl = 20usize;
    let total_len = ihl + tcp_seg.len();

    let mut pkt = vec![0u8; total_len];
    let (ip, tcp_dst) = pkt.split_at_mut(ihl);
    tcp_dst.copy_from_slice(tcp_seg);

    ip[0] = (4 << 4) | 5;
    ip[1] = 0;
    ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&0u16.to_be_bytes());
    ip[6..8].copy_from_slice(&0u16.to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = 6; // TCP
    ip[10..12].copy_from_slice(&0u16.to_be_bytes());
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());
    let csum = ipv4_header_checksum(&ip[..ihl]);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());

    // Zero the TCP checksum, then compute over pseudo-header + segment.
    if tcp_dst.len() >= 18 {
        tcp_dst[16..18].copy_from_slice(&0u16.to_be_bytes());
        let cs = tcp_v4_checksum(src_ip, dst_ip, tcp_dst);
        tcp_dst[16..18].copy_from_slice(&cs.to_be_bytes());
    }

    pkt
}

/// Wrap a TCP segment in an IPv6 header.
pub(crate) fn build_packet6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, tcp_seg: &[u8]) -> Vec<u8> {
    let total_len = 40 + tcp_seg.len();
    let mut pkt = vec![0u8; total_len];
    let (ip, tcp_dst) = pkt.split_at_mut(40);
    tcp_dst.copy_from_slice(tcp_seg);

    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(tcp_seg.len() as u16).to_be_bytes());
    ip[6] = 6; // TCP
    ip[7] = 64; // Hop Limit
    ip[8..24].copy_from_slice(&src_ip.octets());
    ip[24..40].copy_from_slice(&dst_ip.octets());

    if tcp_dst.len() >= 18 {
        tcp_dst[16..18].copy_from_slice(&0u16.to_be_bytes());
        let cs = ipv6_pseudo_checksum(src_ip, dst_ip, 6, tcp_dst.len() as u32, tcp_dst);
        tcp_dst[16..18].copy_from_slice(&cs.to_be_bytes());
    }

    pkt
}

/// Build an IPv4+UDP packet from the response payload.
pub(crate) fn build_udp_packet4(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ihl = 20usize;
    let uh = 8usize;
    let total_len = ihl + uh + payload.len();

    let mut pkt = vec![0u8; total_len];
    {
        let (ip, rest) = pkt.split_at_mut(ihl);
        ip[0] = (4 << 4) | 5;
        ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&src_ip.octets());
        ip[16..20].copy_from_slice(&dst_ip.octets());
        ip[10..12].copy_from_slice(&0u16.to_be_bytes());
        let cs = ipv4_header_checksum(&ip[..ihl]);
        ip[10..12].copy_from_slice(&cs.to_be_bytes());

        let (udp, data) = rest.split_at_mut(uh);
        udp[0..2].copy_from_slice(&src_port.to_be_bytes());
        udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        udp[4..6].copy_from_slice(&((uh + payload.len()) as u16).to_be_bytes());
        udp[6..8].copy_from_slice(&0u16.to_be_bytes());
        data.copy_from_slice(payload);

        // Compute UDP checksum over pseudo-header + (udp + payload).
        let cs = crate::slirp::checksum::udp_v4_checksum(src_ip, dst_ip, udp, payload);
        udp[6..8].copy_from_slice(&cs.to_be_bytes());
    }
    pkt
}

/// Build an IPv6+UDP packet from the response payload.
pub(crate) fn build_udp_packet6(
    src_ip: Ipv6Addr,
    src_port: u16,
    dst_ip: Ipv6Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let uh = 8usize;
    let payload_len = uh + payload.len();
    let total_len = 40 + payload_len;

    let mut pkt = vec![0u8; total_len];
    let (ip, rest) = pkt.split_at_mut(40);
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    ip[6] = 17;
    ip[7] = 64;
    ip[8..24].copy_from_slice(&src_ip.octets());
    ip[24..40].copy_from_slice(&dst_ip.octets());

    let (udp, data) = rest.split_at_mut(uh);
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    udp[6..8].copy_from_slice(&0u16.to_be_bytes());
    data.copy_from_slice(payload);

    // The IPv6 checksum is over pseudo-header + full UDP datagram.
    let mut udp_full = Vec::with_capacity(payload_len);
    udp_full.extend_from_slice(udp);
    udp_full.extend_from_slice(payload);
    let cs = ipv6_pseudo_checksum(src_ip, dst_ip, 17, payload_len as u32, &udp_full);
    udp[6..8].copy_from_slice(&cs.to_be_bytes());

    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_v4_tcp_packet_layout() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        // Minimal TCP header: data offset = 5, no flags.
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&80u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&12345u16.to_be_bytes());
        tcp[12] = 5 << 4;
        let pkt = build_packet4(src, dst, &tcp);
        assert_eq!(pkt.len(), 40);
        assert_eq!(pkt[0], 0x45);
        assert_eq!(&pkt[12..16], &src.octets());
        assert_eq!(&pkt[16..20], &dst.octets());
        // IP header checksum should verify to zero when re-summed.
        assert_eq!(ipv4_header_checksum(&pkt[..20]), 0);
    }

    #[test]
    fn build_v4_udp_packet_layout() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let pkt = build_udp_packet4(src, 5353, dst, 33333, b"hello");
        assert_eq!(pkt.len(), 20 + 8 + 5);
        assert_eq!(pkt[9], 17);
        // total len
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 33);
        // src/dst port at start of UDP
        assert_eq!(u16::from_be_bytes([pkt[20], pkt[21]]), 5353);
        assert_eq!(u16::from_be_bytes([pkt[22], pkt[23]]), 33333);
    }

    #[test]
    fn build_v6_udp_packet_layout() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "fe80::2".parse().unwrap();
        let pkt = build_udp_packet6(src, 100, dst, 200, b"x");
        assert_eq!(pkt.len(), 40 + 8 + 1);
        assert_eq!(pkt[0], 0x60);
        assert_eq!(pkt[6], 17);
        assert_eq!(&pkt[8..24], &src.octets());
        assert_eq!(&pkt[24..40], &dst.octets());
    }
}
