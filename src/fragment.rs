//! IPv4 fragmentation on the send path.
//!
//! The `nat` feature's defragmenter puts fragments back together; this splits
//! a datagram that is too large for the next hop. A forwarder needs both:
//! reassemble to inspect, re-fragment to send on.
//!
//! IPv6 is deliberately not fragmented here. RFC 8200 moved that
//! responsibility to the source host, so a forwarder's only correct response to
//! an oversize IPv6 packet is [`crate::icmp::packet_too_big`] — which is what
//! [`fragment`] reports back with [`Fragmentation::NotFragmentable`].
//!
//! ```
//! # use pktkit::fragment::{fragment, Fragmentation};
//! # use pktkit::{Packet, Protocol};
//! # use pktkit::build::{build_ipv4, build_udp};
//! # use std::net::Ipv4Addr;
//! # let (src, dst) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
//! # let udp = build_udp(src.into(), dst.into(), 1, 2, &vec![0u8; 2000]);
//! # let buf = build_ipv4(src, dst, Protocol::UDP, 64, &udp);
//! match fragment(Packet::from_slice(&buf), 1500) {
//!     Fragmentation::Fits => { /* send as-is */ }
//!     Fragmentation::Fragments(parts) => assert_eq!(parts.len(), 2),
//!     Fragmentation::DontFragment => { /* reply frag-needed */ }
//!     Fragmentation::NotFragmentable => { /* reply packet-too-big */ }
//! }
//! ```

use crate::Packet;

/// The smallest MTU every IPv4 host must accept (RFC 791). Fragmenting to
/// anything below this is not useful.
pub const MIN_IPV4_MTU: usize = 68;

/// What [`fragment`] decided to do with a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fragmentation {
    /// The packet already fits the MTU; send it unchanged.
    Fits,
    /// The packet was split. Fragments are in offset order and each is a
    /// complete IPv4 packet with its header checksum computed.
    Fragments(Vec<Vec<u8>>),
    /// The packet is too big and has the Don't Fragment bit set. The caller
    /// should drop it and reply with
    /// [`icmp::packet_too_big`](crate::icmp::packet_too_big).
    DontFragment,
    /// The packet cannot be fragmented by an intermediate node: it is IPv6, it
    /// is malformed, or the MTU is too small to hold a header plus data. Reply
    /// with [`icmp::packet_too_big`](crate::icmp::packet_too_big).
    NotFragmentable,
}

/// Split `pkt` to fit `mtu`, dispatching on IP version.
///
/// `mtu` is the largest IP packet the next hop accepts — the link MTU, not
/// counting any Ethernet header.
pub fn fragment(pkt: &Packet, mtu: usize) -> Fragmentation {
    match pkt.version() {
        4 => fragment_ipv4(pkt, mtu),
        // A router must not fragment IPv6; only the source may.
        6 => {
            if pkt.len() <= mtu {
                Fragmentation::Fits
            } else {
                Fragmentation::NotFragmentable
            }
        }
        _ => Fragmentation::NotFragmentable,
    }
}

/// Split an IPv4 packet to fit `mtu`.
///
/// Already-fragmented input is handled: the incoming fragment offset is added
/// to each output offset and the More Fragments bit is preserved on the last
/// piece, so re-fragmenting a fragment stays consistent.
///
/// IPv4 options are copied into the first fragment verbatim; later fragments
/// keep only the options whose copy bit is set, as RFC 791 requires.
pub fn fragment_ipv4(pkt: &Packet, mtu: usize) -> Fragmentation {
    let buf = pkt.as_bytes();
    let hl = pkt.ipv4_header_len();
    let total = pkt.ipv4_total_len() as usize;

    if pkt.version() != 4 || hl < 20 || total < hl || buf.len() < total {
        return Fragmentation::NotFragmentable;
    }
    if total <= mtu {
        return Fragmentation::Fits;
    }
    if pkt.ipv4_dont_fragment() {
        return Fragmentation::DontFragment;
    }

    // Later fragments carry a possibly-shorter header, so both sizes matter.
    let later_header = copied_options_header(&buf[..hl]);
    let later_hl = later_header.len();
    if mtu < MIN_IPV4_MTU || mtu <= hl || mtu <= later_hl {
        return Fragmentation::NotFragmentable;
    }

    // Every fragment but the last must carry a multiple of 8 payload bytes.
    let first_room = ((mtu - hl) / 8) * 8;
    let later_room = ((mtu - later_hl) / 8) * 8;
    if first_room == 0 || later_room == 0 {
        return Fragmentation::NotFragmentable;
    }

    let data = &buf[hl..total];
    let base_offset = pkt.ipv4_fragment_offset();
    let last_has_more = pkt.ipv4_more_fragments();

    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let first = pos == 0;
        let room = if first { first_room } else { later_room };
        let take = room.min(data.len() - pos);
        let header: &[u8] = if first { &buf[..hl] } else { &later_header };

        let mut frag = Vec::with_capacity(header.len() + take);
        frag.extend_from_slice(header);
        frag.extend_from_slice(&data[pos..pos + take]);

        let more = pos + take < data.len() || last_has_more;
        {
            let p = Packet::from_mut(&mut frag);
            // Later fragments may have a shorter header than the original.
            if !first {
                let ihl = (later_hl / 4) as u8;
                p.as_bytes_mut()[0] = 0x40 | ihl;
            }
            p.set_ipv4_total_len((header.len() + take) as u16);
            p.set_ipv4_fragment_offset(base_offset + pos);
            p.set_ipv4_more_fragments(more);
            p.set_ipv4_dont_fragment(false);
            p.recompute_ipv4_checksum();
        }
        out.push(frag);
        pos += take;
    }

    Fragmentation::Fragments(out)
}

/// Build the header later fragments carry: the fixed 20 bytes plus only those
/// options whose copy bit (0x80) is set, padded out to a 4-byte multiple.
fn copied_options_header(header: &[u8]) -> Vec<u8> {
    if header.len() <= 20 {
        return header.to_vec();
    }
    let mut out = Vec::with_capacity(header.len());
    out.extend_from_slice(&header[..20]);

    let opts = &header[20..];
    let mut i = 0;
    while i < opts.len() {
        let kind = opts[i];
        // End of option list.
        if kind == 0 {
            break;
        }
        // NOP is a single byte and is never worth copying on its own.
        if kind == 1 {
            i += 1;
            continue;
        }
        if i + 1 >= opts.len() {
            break;
        }
        let len = opts[i + 1] as usize;
        if len < 2 || i + len > opts.len() {
            break;
        }
        if kind & 0x80 != 0 {
            out.extend_from_slice(&opts[i..i + len]);
        }
        i += len;
    }
    // The header length field counts 4-byte words.
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Protocol;
    use crate::build::{build_ipv4, build_udp};
    use std::net::Ipv4Addr;

    const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    fn packet_with_payload(n: usize) -> Vec<u8> {
        let body: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let udp = build_udp(A.into(), B.into(), 1234, 53, &body);
        build_ipv4(A, B, Protocol::UDP, 64, &udp)
    }

    /// Glue fragments back together and compare against the original payload.
    fn reassemble(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in parts {
            let p = Packet::from_slice(part);
            let hl = p.ipv4_header_len();
            let tl = p.ipv4_total_len() as usize;
            let off = p.ipv4_fragment_offset();
            if out.len() < off + (tl - hl) {
                out.resize(off + (tl - hl), 0);
            }
            out[off..off + (tl - hl)].copy_from_slice(&part[hl..tl]);
        }
        out
    }

    #[test]
    fn small_packet_fits() {
        let buf = packet_with_payload(100);
        assert_eq!(
            fragment(Packet::from_slice(&buf), 1500),
            Fragmentation::Fits
        );
    }

    #[test]
    fn splits_and_reassembles_losslessly() {
        let buf = packet_with_payload(4000);
        let parts = match fragment(Packet::from_slice(&buf), 1500) {
            Fragmentation::Fragments(p) => p,
            other => panic!("expected fragments, got {:?}", other),
        };
        assert!(parts.len() >= 3);

        for (i, part) in parts.iter().enumerate() {
            let p = Packet::from_slice(part);
            assert!(part.len() <= 1500, "fragment {} exceeds the MTU", i);
            assert!(p.verify_ipv4_checksum(), "fragment {} checksum", i);
            assert_eq!(p.ipv4_src_addr(), Some(A));
            assert_eq!(p.ipv4_dst_addr(), Some(B));
            assert_eq!(p.ipv4_protocol(), Protocol::UDP);
            assert!(!p.ipv4_dont_fragment());
            let last = i + 1 == parts.len();
            assert_eq!(p.ipv4_more_fragments(), !last, "MF on fragment {}", i);
            if !last {
                // All but the last must be a multiple of 8 payload bytes.
                assert_eq!((p.ipv4_total_len() as usize - p.ipv4_header_len()) % 8, 0);
            }
        }

        let original = Packet::from_slice(&buf);
        assert_eq!(reassemble(&parts), original.ipv4_payload());
    }

    #[test]
    fn dont_fragment_is_reported() {
        let mut buf = packet_with_payload(4000);
        let p = Packet::from_mut(&mut buf);
        p.set_ipv4_dont_fragment(true);
        p.recompute_ipv4_checksum();
        assert_eq!(fragment(p, 1500), Fragmentation::DontFragment);
    }

    #[test]
    fn refragmenting_a_fragment_keeps_offsets() {
        let buf = packet_with_payload(4000);
        let parts = match fragment(Packet::from_slice(&buf), 1500) {
            Fragmentation::Fragments(p) => p,
            other => panic!("{:?}", other),
        };
        // Re-fragment the middle piece to a smaller MTU.
        let mid = &parts[1];
        let mid_off = Packet::from_slice(mid).ipv4_fragment_offset();
        let sub = match fragment(Packet::from_slice(mid), 600) {
            Fragmentation::Fragments(p) => p,
            other => panic!("{:?}", other),
        };
        assert!(sub.len() >= 2);
        assert_eq!(Packet::from_slice(&sub[0]).ipv4_fragment_offset(), mid_off);
        for part in &sub {
            let p = Packet::from_slice(part);
            assert!(p.ipv4_more_fragments(), "a middle fragment always has MF");
            assert!(p.ipv4_fragment_offset() >= mid_off);
        }

        // Splicing the sub-fragments in place of the middle one still
        // reassembles to the original payload.
        let mut all = vec![parts[0].clone()];
        all.extend(sub);
        all.extend_from_slice(&parts[2..]);
        assert_eq!(
            reassemble(&all),
            Packet::from_slice(&buf).ipv4_payload(),
            "re-fragmented pieces must still reassemble"
        );
    }

    #[test]
    fn ipv6_is_never_fragmented() {
        let a = "2001:db8::1".parse().unwrap();
        let b = "2001:db8::2".parse().unwrap();
        let udp = build_udp(
            std::net::IpAddr::V6(a),
            std::net::IpAddr::V6(b),
            1,
            2,
            &vec![0u8; 3000],
        );
        let buf = crate::build::build_ipv6(a, b, Protocol::UDP, 64, &udp);
        assert_eq!(
            fragment(Packet::from_slice(&buf), 1500),
            Fragmentation::NotFragmentable
        );
        // But one that fits is fine.
        assert_eq!(
            fragment(Packet::from_slice(&buf), 9000),
            Fragmentation::Fits
        );
    }

    #[test]
    fn absurd_mtu_is_rejected() {
        let buf = packet_with_payload(4000);
        let p = Packet::from_slice(&buf);
        assert_eq!(fragment(p, 20), Fragmentation::NotFragmentable);
        assert_eq!(fragment(p, 0), Fragmentation::NotFragmentable);
        // Exactly the minimum IPv4 MTU still works.
        assert!(matches!(
            fragment(p, MIN_IPV4_MTU),
            Fragmentation::Fragments(_)
        ));
    }

    #[test]
    fn options_are_copied_per_rfc791() {
        // Build a header with two options: one copied (0x83, loose source
        // route), one not (0x07, record route).
        let mut buf = packet_with_payload(2000);
        let mut with_opts = buf[..20].to_vec();
        with_opts.extend_from_slice(&[0x83, 4, 0, 0]); // copied
        with_opts.extend_from_slice(&[0x07, 4, 0, 0]); // not copied
        let payload = buf.split_off(20);
        with_opts.extend_from_slice(&payload);
        buf = with_opts;

        let p = Packet::from_mut(&mut buf);
        p.as_bytes_mut()[0] = 0x47; // IHL = 7 words = 28 bytes
        let total = p.len() as u16;
        p.set_ipv4_total_len(total);
        p.recompute_ipv4_checksum();

        let parts = match fragment(p, 600) {
            Fragmentation::Fragments(p) => p,
            other => panic!("{:?}", other),
        };
        assert!(parts.len() >= 2);

        let first = Packet::from_slice(&parts[0]);
        assert_eq!(first.ipv4_header_len(), 28, "first keeps every option");
        assert_eq!(&first.ipv4_options()[..4], &[0x83, 4, 0, 0]);

        let later = Packet::from_slice(&parts[1]);
        assert_eq!(later.ipv4_header_len(), 24, "later drops the un-copied one");
        assert_eq!(later.ipv4_options(), &[0x83, 4, 0, 0]);
        assert!(later.verify_ipv4_checksum());
    }

    #[test]
    fn truncated_packet_is_not_fragmentable() {
        let buf = packet_with_payload(2000);
        // Claim more bytes than the buffer holds.
        let short = &buf[..100];
        assert_eq!(
            fragment(Packet::from_slice(short), 500),
            Fragmentation::NotFragmentable
        );
    }
}
