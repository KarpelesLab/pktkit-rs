//! Constructors for well-formed packets.
//!
//! The accessor types ([`Frame`], [`Packet`](crate::Packet), the
//! [`l4`](crate::l4) views) read and mutate buffers that already exist. These
//! functions produce the buffers in the first place, with lengths and checksums
//! filled in, so tests and protocol code do not have to assemble headers by
//! hand.
//!
//! Everything returns an owned `Vec<u8>`; borrow it as a typed view to inspect
//! it. Layers compose outward — build the transport PDU, then wrap it in an IP
//! header, then in a frame:
//!
//! ```
//! # use pktkit::build::{build_ipv4, build_udp};
//! # use pktkit::{build_frame, EtherType, Frame, MacAddr, Packet, Protocol};
//! # use std::net::Ipv4Addr;
//! let (src, dst) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
//!
//! let udp = build_udp(src.into(), dst.into(), 5000, 53, b"hello");
//! let ip = build_ipv4(src, dst, Protocol::UDP, 64, &udp);
//! let eth = build_frame(MacAddr::broadcast(), MacAddr::zero(), EtherType::IPV4, &ip);
//!
//! let pkt = Packet::from_slice(Frame::from_slice(&eth).payload());
//! assert!(pkt.verify_ipv4_checksum());
//! assert_eq!(pkt.verify_transport_checksum(), Some(true));
//! assert_eq!(pkt.udp().unwrap().payload(), b"hello");
//! ```

use crate::checksum::{checksum, transport_checksum};
use crate::l4::TcpFlags;
use crate::{EtherType, Frame, Protocol};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Build an IPv4 packet around `payload`.
///
/// Total length and header checksum are computed; the identification field is
/// zero and no options are emitted. Set [`Packet::set_ipv4_id`] afterwards if
/// the datagram may be fragmented, since fragments of one datagram are matched
/// on that field.
///
/// [`Packet::set_ipv4_id`]: crate::Packet::set_ipv4_id
pub fn build_ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: Protocol,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut v = Vec::with_capacity(total);
    v.push(0x45); // version 4, IHL 5
    v.push(0); // DSCP / ECN
    v.extend_from_slice(&(total.min(u16::MAX as usize) as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]); // identification
    v.extend_from_slice(&[0, 0]); // flags / fragment offset
    v.push(ttl);
    v.push(proto.as_u8());
    v.extend_from_slice(&[0, 0]); // checksum placeholder
    v.extend_from_slice(&src.octets());
    v.extend_from_slice(&dst.octets());
    let sum = checksum(&v[..20]);
    v[10..12].copy_from_slice(&sum.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Build an IPv6 packet around `payload`.
///
/// `next_header` names whatever `payload` starts with — a transport protocol,
/// or the first extension header if you are assembling a chain yourself.
pub fn build_ipv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: Protocol,
    hop_limit: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(40 + payload.len());
    v.extend_from_slice(&[0x60, 0, 0, 0]); // version 6, no traffic class or flow label
    v.extend_from_slice(&(payload.len().min(u16::MAX as usize) as u16).to_be_bytes());
    v.push(next_header.as_u8());
    v.push(hop_limit);
    v.extend_from_slice(&src.octets());
    v.extend_from_slice(&dst.octets());
    v.extend_from_slice(payload);
    v
}

/// Build an IP packet of whichever version the addresses are, or `None` if the
/// two addresses are from different families.
pub fn build_ip(
    src: IpAddr,
    dst: IpAddr,
    proto: Protocol,
    hop_limit: u8,
    payload: &[u8],
) -> Option<Vec<u8>> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => Some(build_ipv4(s, d, proto, hop_limit, payload)),
        (IpAddr::V6(s), IpAddr::V6(d)) => Some(build_ipv6(s, d, proto, hop_limit, payload)),
        _ => None,
    }
}

/// Build a UDP datagram with its checksum computed over the pseudo-header
/// formed from `src` and `dst`.
///
/// The addresses are needed only for the checksum; they are not part of the
/// returned bytes. Wrap the result with [`build_ipv4`] or [`build_ipv6`] using
/// the same pair.
pub fn build_udp(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut v = Vec::with_capacity(len);
    v.extend_from_slice(&src_port.to_be_bytes());
    v.extend_from_slice(&dst_port.to_be_bytes());
    v.extend_from_slice(&(len.min(u16::MAX as usize) as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]); // checksum placeholder
    v.extend_from_slice(payload);
    let sum = transport_checksum(Protocol::UDP, src, dst, &v);
    // RFC 768: a computed checksum of zero is transmitted as all ones, since
    // zero means "no checksum" on the wire.
    let sum = if sum == 0 { 0xFFFF } else { sum };
    v[6..8].copy_from_slice(&sum.to_be_bytes());
    v
}

/// Build a TCP segment with its checksum computed.
///
/// No options are emitted, so the data offset is 5 words. As with
/// [`build_udp`], the addresses are used for the pseudo-header only.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(20 + payload.len());
    v.extend_from_slice(&src_port.to_be_bytes());
    v.extend_from_slice(&dst_port.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&ack.to_be_bytes());
    v.push(5 << 4); // data offset 5 words, no reserved bits
    v.push(flags.bits());
    v.extend_from_slice(&window.to_be_bytes());
    v.extend_from_slice(&[0, 0]); // checksum placeholder
    v.extend_from_slice(&[0, 0]); // urgent pointer
    v.extend_from_slice(payload);
    let sum = transport_checksum(Protocol::TCP, src, dst, &v);
    v[16..18].copy_from_slice(&sum.to_be_bytes());
    v
}

/// Build an ICMPv4 message. The checksum covers the message only — ICMPv4 has
/// no pseudo-header, so no addresses are needed.
pub fn build_icmpv4(
    message_type: u8,
    code: u8,
    rest_of_header: [u8; 4],
    payload: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.push(message_type);
    v.push(code);
    v.extend_from_slice(&[0, 0]); // checksum placeholder
    v.extend_from_slice(&rest_of_header);
    v.extend_from_slice(payload);
    let sum = checksum(&v);
    v[2..4].copy_from_slice(&sum.to_be_bytes());
    v
}

/// Build an ICMPv6 message. Unlike ICMPv4, the checksum covers an IPv6
/// pseudo-header, so the addresses of the enclosing packet are required.
pub fn build_icmpv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    message_type: u8,
    code: u8,
    rest_of_header: [u8; 4],
    payload: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.push(message_type);
    v.push(code);
    v.extend_from_slice(&[0, 0]); // checksum placeholder
    v.extend_from_slice(&rest_of_header);
    v.extend_from_slice(payload);
    let sum = transport_checksum(Protocol::ICMPV6, src.into(), dst.into(), &v);
    v[2..4].copy_from_slice(&sum.to_be_bytes());
    v
}

/// Insert an 802.1Q VLAN tag into a frame, returning the tagged copy.
///
/// `vid` is the 12-bit VLAN identifier and `pcp` the 3-bit priority. A frame
/// that already carries a tag is returned unchanged — this pushes one tag, it
/// does not stack them.
pub fn push_vlan(frame: &Frame, vid: u16, pcp: u8) -> Vec<u8> {
    let bytes = frame.as_bytes();
    if bytes.len() < 14 || frame.has_vlan() {
        return bytes.to_vec();
    }
    let tci = ((pcp as u16 & 0x07) << 13) | (vid & 0x0FFF);
    let mut v = Vec::with_capacity(bytes.len() + 4);
    v.extend_from_slice(&bytes[0..12]); // dst + src MAC
    v.extend_from_slice(&EtherType::VLAN.as_u16().to_be_bytes());
    v.extend_from_slice(&tci.to_be_bytes());
    v.extend_from_slice(&bytes[12..]); // original ethertype + payload
    v
}

/// Remove an 802.1Q VLAN tag from a frame, returning the untagged copy. An
/// untagged frame is returned unchanged.
pub fn pop_vlan(frame: &Frame) -> Vec<u8> {
    let bytes = frame.as_bytes();
    if !frame.has_vlan() {
        return bytes.to_vec();
    }
    let mut v = Vec::with_capacity(bytes.len() - 4);
    v.extend_from_slice(&bytes[0..12]);
    v.extend_from_slice(&bytes[16..]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_frame, MacAddr, Packet};

    const V4_A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const V4_B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    fn v6_a() -> Ipv6Addr {
        "2001:db8::1".parse().unwrap()
    }

    fn v6_b() -> Ipv6Addr {
        "2001:db8::2".parse().unwrap()
    }

    #[test]
    fn ipv4_udp_roundtrip() {
        let udp = build_udp(V4_A.into(), V4_B.into(), 5000, 53, b"hello");
        let buf = build_ipv4(V4_A, V4_B, Protocol::UDP, 64, &udp);
        let p = Packet::from_slice(&buf);

        assert_eq!(p.version(), 4);
        assert_eq!(p.ipv4_total_len() as usize, buf.len());
        assert!(p.verify_ipv4_checksum());
        assert_eq!(p.verify_transport_checksum(), Some(true));

        let dg = p.udp().unwrap();
        assert_eq!(dg.src_port(), 5000);
        assert_eq!(dg.dst_port(), 53);
        assert_eq!(dg.payload(), b"hello");
    }

    #[test]
    fn ipv6_udp_roundtrip() {
        let udp = build_udp(v6_a().into(), v6_b().into(), 1, 2, b"x");
        let buf = build_ipv6(v6_a(), v6_b(), Protocol::UDP, 64, &udp);
        let p = Packet::from_slice(&buf);

        assert_eq!(p.version(), 6);
        assert_eq!(p.transport_protocol(), Protocol::UDP);
        assert_eq!(p.verify_transport_checksum(), Some(true));
        assert_eq!(p.udp().unwrap().payload(), b"x");
    }

    #[test]
    fn ipv4_tcp_roundtrip() {
        let tcp = build_tcp(
            V4_A.into(),
            V4_B.into(),
            1234,
            80,
            1000,
            2000,
            TcpFlags::SYN | TcpFlags::ACK,
            65535,
            b"body",
        );
        let buf = build_ipv4(V4_A, V4_B, Protocol::TCP, 64, &tcp);
        let p = Packet::from_slice(&buf);

        assert_eq!(p.verify_transport_checksum(), Some(true));
        let seg = p.tcp().unwrap();
        assert_eq!(seg.src_port(), 1234);
        assert_eq!(seg.seq(), 1000);
        assert_eq!(seg.ack(), 2000);
        assert!(seg.flags().contains(TcpFlags::SYN | TcpFlags::ACK));
        assert_eq!(seg.payload(), b"body");
    }

    #[test]
    fn icmpv4_checksum_is_self_verifying() {
        let msg = build_icmpv4(8, 0, [0, 1, 0, 2], b"ping");
        let buf = build_ipv4(V4_A, V4_B, Protocol::ICMP, 64, &msg);
        let p = Packet::from_slice(&buf);
        let icmp = p.icmp().unwrap();
        assert!(icmp.verify_icmpv4_checksum());
        assert_eq!(icmp.echo_id(), 1);
        assert_eq!(icmp.echo_seq(), 2);
        assert_eq!(p.verify_transport_checksum(), Some(true));
    }

    #[test]
    fn icmpv6_checksum_covers_pseudo_header() {
        let msg = build_icmpv6(v6_a(), v6_b(), 128, 0, [0, 1, 0, 1], b"ping");
        let buf = build_ipv6(v6_a(), v6_b(), Protocol::ICMPV6, 64, &msg);
        let p = Packet::from_slice(&buf);
        assert_eq!(p.verify_transport_checksum(), Some(true));

        // The same message under different addresses must not verify.
        let other = build_ipv6(
            v6_a(),
            "2001:db8::99".parse().unwrap(),
            Protocol::ICMPV6,
            64,
            &msg,
        );
        assert_eq!(
            Packet::from_slice(&other).verify_transport_checksum(),
            Some(false)
        );
    }

    #[test]
    fn build_ip_rejects_mixed_families() {
        assert!(build_ip(V4_A.into(), v6_b().into(), Protocol::UDP, 64, &[]).is_none());
        assert!(build_ip(V4_A.into(), V4_B.into(), Protocol::UDP, 64, &[]).is_some());
    }

    #[test]
    fn udp_zero_checksum_becomes_all_ones() {
        // Search for a payload whose checksum lands on zero; the builder must
        // never emit 0, which would mean "no checksum" to the receiver.
        for i in 0..2000u16 {
            let udp = build_udp(
                V4_A.into(),
                V4_B.into(),
                i,
                i.wrapping_mul(7),
                &i.to_be_bytes(),
            );
            assert_ne!(&udp[6..8], &[0, 0]);
        }
    }

    #[test]
    fn recompute_after_rewrite_matches_builder() {
        let udp = build_udp(V4_A.into(), V4_B.into(), 5000, 53, b"hello");
        let mut buf = build_ipv4(V4_A, V4_B, Protocol::UDP, 64, &udp);

        let new_src = Ipv4Addr::new(192, 168, 0, 7);
        let p = Packet::from_mut(&mut buf);
        p.set_ipv4_src_addr(new_src);
        p.recompute_checksums();
        assert!(p.verify_ipv4_checksum());
        assert_eq!(p.verify_transport_checksum(), Some(true));

        // Byte-identical to building it that way from the start.
        let expect_udp = build_udp(new_src.into(), V4_B.into(), 5000, 53, b"hello");
        let expect = build_ipv4(new_src, V4_B, Protocol::UDP, 64, &expect_udp);
        assert_eq!(buf, expect);
    }

    #[test]
    fn vlan_push_and_pop() {
        let payload = [1u8, 2, 3, 4];
        let eth = build_frame(
            MacAddr::broadcast(),
            MacAddr::zero(),
            EtherType::IPV4,
            &payload,
        );
        let f = Frame::from_slice(&eth);
        assert!(!f.has_vlan());

        let tagged = push_vlan(f, 42, 3);
        let tf = Frame::from_slice(&tagged);
        assert!(tf.has_vlan());
        assert_eq!(tf.vlan_id(), 42);
        assert_eq!(tf.vlan_pcp(), 3);
        assert_eq!(tf.ether_type(), EtherType::IPV4);
        assert_eq!(tf.payload(), &payload);
        assert_eq!(tf.dst_mac(), f.dst_mac());

        // Pushing again is a no-op; popping restores the original bytes.
        assert_eq!(push_vlan(tf, 7, 0), tagged);
        assert_eq!(pop_vlan(tf), eth);
        assert_eq!(pop_vlan(f), eth);
    }
}
