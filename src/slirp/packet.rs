//! Packet-building helpers for the slirp stack.
//!
//! These mirror Go's `buildPacket4` / `buildPacket6` — they wrap a raw
//! transport-layer segment (TCP) in an IP header with checksums filled in.

use crate::Packet;
use crate::fragment::{Fragmentation, fragment_ipv4};
use crate::slirp::checksum::{ipv4_header_checksum, ipv6_pseudo_checksum, tcp_v4_checksum};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};

/// MTU of the virtual link, which the TCP MSS (1460 / 1440) also assumes.
/// Datagrams the stack originates are fragmented to fit it.
pub(crate) const LINK_MTU: usize = 1500;

/// Identification for the datagrams the stack originates. Fragments of one
/// datagram share it, so it must differ between datagrams in flight.
static NEXT_IP_ID: AtomicU32 = AtomicU32::new(1);

pub(crate) fn next_ip_id() -> u32 {
    NEXT_IP_ID.fetch_add(1, Ordering::Relaxed)
}

/// Split a packet the stack built into pieces that fit [`LINK_MTU`].
///
/// IPv4 is fragmented as a router would; for IPv6 the stack is the source
/// host, which is the one node RFC 8200 lets fragment.
pub(crate) fn fit_link(pkt: Vec<u8>) -> Vec<Vec<u8>> {
    if pkt.len() <= LINK_MTU {
        return vec![pkt];
    }
    match pkt[0] >> 4 {
        4 => {
            // The fragments need an ID of their own: an echo reply carries
            // its request's, which may be anything (0 after reassembly), and
            // its DF flag, which would forbid the split the stack is making.
            let mut pkt = pkt;
            let ihl = (pkt[0] & 0x0F) as usize * 4;
            pkt[4..6].copy_from_slice(&(next_ip_id() as u16).to_be_bytes());
            pkt[6..8].copy_from_slice(&[0, 0]);
            pkt[10..12].copy_from_slice(&[0, 0]);
            let cs = ipv4_header_checksum(&pkt[..ihl]);
            pkt[10..12].copy_from_slice(&cs.to_be_bytes());
            match fragment_ipv4(Packet::from_slice(&pkt), LINK_MTU) {
                Fragmentation::Fragments(f) => f,
                _ => vec![pkt],
            }
        }
        6 => fragment_ipv6(&pkt, LINK_MTU),
        _ => vec![pkt],
    }
}

/// Fragment an IPv6 packet whose only unfragmentable part is the fixed
/// header (which is all the stack builds).
fn fragment_ipv6(pkt: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    let id = next_ip_id();
    let next = pkt[6];
    let body = &pkt[40..];
    // Every fragment but the last carries a multiple of 8 bytes.
    let chunk = (mtu - 48) & !7;
    let mut out = Vec::with_capacity(body.len().div_ceil(chunk));
    for (i, part) in body.chunks(chunk).enumerate() {
        let offset = i * chunk;
        let more = offset + part.len() < body.len();
        let mut f = Vec::with_capacity(48 + part.len());
        f.extend_from_slice(&pkt[..40]);
        f[4..6].copy_from_slice(&((8 + part.len()) as u16).to_be_bytes());
        f[6] = 44; // Fragment
        f.extend_from_slice(&[next, 0]);
        f.extend_from_slice(&((offset as u16) | more as u16).to_be_bytes());
        f.extend_from_slice(&id.to_be_bytes());
        f.extend_from_slice(part);
        out.push(f);
    }
    out
}

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
    // DF stays clear (the stack does no path-MTU discovery, so a narrower
    // hop downstream must be free to fragment), which makes the datagram
    // non-atomic: RFC 6864 §4.1 requires a distinct ID, or reassembly at the
    // guest could splice fragments of two segments together.
    ip[4..6].copy_from_slice(&(next_ip_id() as u16).to_be_bytes());
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

/// A computed UDP checksum of zero goes on the wire as 0xFFFF (RFC 768):
/// zero means "no checksum" over IPv4, and is invalid over IPv6 (RFC 8200),
/// where the receiver drops the datagram.
#[inline]
fn nonzero_udp_checksum(cs: u16) -> u16 {
    if cs == 0 { 0xFFFF } else { cs }
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
        // Needed should the datagram be fragmented for the link.
        ip[4..6].copy_from_slice(&(next_ip_id() as u16).to_be_bytes());
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
        udp[6..8].copy_from_slice(&nonzero_udp_checksum(cs).to_be_bytes());
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
    udp[6..8].copy_from_slice(&nonzero_udp_checksum(cs).to_be_bytes());

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

    /// A path narrower than the link fragments the stack's segments (DF is
    /// clear). Were two segments to share an ID, a reassembler seeing their
    /// fragments interleaved would splice one's head onto the other's tail.
    #[test]
    fn v4_tcp_segments_reassemble_when_fragmented_and_reordered() {
        use crate::fragment::{Fragmentation, fragment_ipv4};
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let seg = |fill: u8| {
            let mut tcp = vec![fill; 1480];
            tcp[12] = 5 << 4;
            tcp
        };
        let a = build_packet4(src, dst, &seg(0xAA));
        let b = build_packet4(src, dst, &seg(0xBB));
        let frags = |p: &[u8]| match fragment_ipv4(Packet::from_slice(p), 576) {
            Fragmentation::Fragments(f) => f,
            _ => panic!("segment was not fragmented"),
        };
        let (fa, fb) = (frags(&a), frags(&b));
        // Heads of both first, then the tails in swapped order.
        let order = [&fa[..1], &fb[..1], &fb[1..], &fa[1..]]
            .into_iter()
            .flat_map(|s| s.iter())
            .collect::<Vec<_>>();
        let mut r = crate::defrag::Reassembler::default();
        let now = crate::time::Instant::now();
        let mut whole = Vec::new();
        for f in order {
            whole.extend(r.push_v4(now, 0, f, 20));
        }
        assert_eq!(whole.len(), 2, "segments lost in reassembly");
        for w in &whole {
            assert!(w == &a || w == &b, "fragments of different segments merged");
        }
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
    fn large_v6_datagram_is_fragmented_to_the_link() {
        let src: Ipv6Addr = "fd00::1".parse().unwrap();
        let dst: Ipv6Addr = "fd00::5".parse().unwrap();
        let body: Vec<u8> = (0..4000u32).map(|i| i as u8).collect();
        let pkt = build_udp_packet6(src, 53, dst, 4000, &body);
        let frags = fit_link(pkt.clone());
        assert_eq!(frags.len(), 3);
        let mut r = crate::defrag::Reassembler::default();
        let mut whole = None;
        for f in &frags {
            assert!(f.len() <= LINK_MTU);
            whole = r.push_v6(crate::time::Instant::now(), 0, f, 40);
        }
        assert_eq!(whole.unwrap(), pkt);
    }

    #[test]
    fn large_v4_datagram_is_fragmented_to_the_link() {
        let body = vec![7u8; 3000];
        let pkt = build_udp_packet4(
            Ipv4Addr::new(1, 1, 1, 1),
            53,
            Ipv4Addr::new(10, 0, 0, 5),
            9,
            &body,
        );
        let frags = fit_link(pkt);
        assert_eq!(frags.len(), 3);
        assert!(frags.iter().all(|f| f.len() <= LINK_MTU));
    }

    #[test]
    fn zero_udp_checksum_is_sent_as_all_ones() {
        // Choose the payload so the checksum computes to zero: a word equal
        // to the checksum of the same datagram with that word zeroed.
        let (s4, d4) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 5));
        let probe = build_udp_packet4(s4, 53, d4, 4000, &[0, 0]);
        let word = [probe[26], probe[27]];
        let pkt = build_udp_packet4(s4, 53, d4, 4000, &word);
        assert_eq!(&pkt[26..28], &[0xFF, 0xFF]);

        let (s6, d6): (Ipv6Addr, Ipv6Addr) =
            ("fd00::1".parse().unwrap(), "fd00::5".parse().unwrap());
        let probe = build_udp_packet6(s6, 53, d6, 4000, &[0, 0]);
        let word = [probe[46], probe[47]];
        let pkt = build_udp_packet6(s6, 53, d6, 4000, &word);
        assert_eq!(&pkt[46..48], &[0xFF, 0xFF]);
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
