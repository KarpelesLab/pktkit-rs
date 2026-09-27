//! Transport-layer checksum and payload plumbing shared by the NAT, NAT64 and
//! the ALGs.

use crate::checksum::raw_transport_sum;
use crate::nat::helper::{PROTO_TCP, PROTO_UDP};
use crate::{Protocol, checksum, transport_checksum};
use std::net::{IpAddr, Ipv4Addr};

/// Offset of the checksum field inside a TCP or UDP header.
pub(crate) fn csum_field(proto: u8) -> Option<usize> {
    match proto {
        PROTO_TCP => Some(16),
        PROTO_UDP => Some(6),
        _ => None,
    }
}

/// True if the TCP/UDP checksum of the IPv4 packet `pkt` verifies. A UDP
/// datagram sent without a checksum (field zero, RFC 768) has nothing to
/// verify and counts as valid.
pub(crate) fn v4_l4_checksum_ok(pkt: &[u8], ihl: usize) -> bool {
    let proto = pkt[9];
    let Some(field) = csum_field(proto) else {
        return false;
    };
    if pkt.len() < ihl + field + 2 {
        return false;
    }
    let l4 = &pkt[ihl..];
    if proto == PROTO_UDP && l4[6] == 0 && l4[7] == 0 {
        return true;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    raw_transport_sum(Protocol(proto), IpAddr::V4(src), IpAddr::V4(dst), l4) == 0xFFFF
}

/// Replace the application payload of the IPv4 TCP/UDP packet `orig` (whose
/// L4 header is `l4_hdr_len` bytes) with `new_payload`, fixing the IP total
/// length, the UDP length and both checksums.
///
/// The L4 checksum is recomputed from scratch, which would launder a packet
/// that was corrupted in flight into one that verifies. So a packet whose
/// checksum does not verify on the way in is returned unchanged, and the end
/// host drops it as it would have without the NAT.
pub(crate) fn replace_payload(
    orig: &[u8],
    ihl: usize,
    l4_hdr_len: usize,
    new_payload: &[u8],
) -> Vec<u8> {
    let proto = orig[9];
    let Some(field) = csum_field(proto) else {
        return orig.to_vec();
    };
    if orig.len() < ihl + l4_hdr_len || l4_hdr_len < field + 2 || !v4_l4_checksum_ok(orig, ihl) {
        return orig.to_vec();
    }
    let total = ihl + l4_hdr_len + new_payload.len();
    if total > u16::MAX as usize {
        return orig.to_vec();
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&orig[..ihl + l4_hdr_len]);
    out.extend_from_slice(new_payload);

    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[10..12].copy_from_slice(&[0, 0]);
    let ip_csum = checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    let l4_len = total - ihl;
    if proto == PROTO_UDP {
        out[ihl + 4..ihl + 6].copy_from_slice(&(l4_len as u16).to_be_bytes());
    }
    fill_v4_l4_checksum(&mut out, ihl);
    out
}

/// Compute and store the TCP/UDP checksum of an IPv4 packet from scratch.
pub(crate) fn fill_v4_l4_checksum(pkt: &mut [u8], ihl: usize) {
    let proto = pkt[9];
    let Some(field) = csum_field(proto) else {
        return;
    };
    if pkt.len() < ihl + field + 2 {
        return;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    pkt[ihl + field..ihl + field + 2].copy_from_slice(&[0, 0]);
    let mut cs = transport_checksum(
        Protocol(proto),
        IpAddr::V4(src),
        IpAddr::V4(dst),
        &pkt[ihl..],
    );
    // A computed zero goes on the wire as all-ones: zero means "no checksum"
    // in UDP (RFC 768), and is the same one's-complement value for TCP.
    if cs == 0 {
        cs = 0xFFFF;
    }
    pkt[ihl + field..ihl + field + 2].copy_from_slice(&cs.to_be_bytes());
}

/// Patch a stored Internet checksum for 16-bit words that left the summed
/// data (`old`) and words that entered it (`new`): RFC 1624 equation 3,
/// generalised to regions of different sizes, as when a pseudo-header
/// changes address family. Every slice must have an even length.
pub(crate) fn csum_replace(csum: u16, old: &[&[u8]], new: &[&[u8]]) -> u16 {
    fn words(b: &[u8]) -> impl Iterator<Item = u16> + '_ {
        debug_assert!(
            b.len().is_multiple_of(2),
            "checksum patch needs whole words"
        );
        b.as_chunks::<2>().0.iter().map(|w| u16::from_be_bytes(*w))
    }
    let mut sum = (!csum) as u32;
    for w in old.iter().flat_map(|b| words(b)) {
        sum += (!w) as u32;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    for w in new.iter().flat_map(|b| words(b)) {
        sum += w as u32;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn csum_replace_matches_a_recompute_across_families() {
        let src4 = Ipv4Addr::new(198, 51, 100, 1);
        let dst4 = Ipv4Addr::new(192, 0, 2, 33);
        let src6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst6: Ipv6Addr = "64:ff9b::c000:221".parse().unwrap();
        let mut seg = vec![0x30, 0x39, 0, 53, 0, 13, 0, 0, b'h', b'e', b'l', b'l', b'o'];
        let v6 = transport_checksum(Protocol::UDP, IpAddr::V6(src6), IpAddr::V6(dst6), &seg);
        // Same datagram with a new source port, under the IPv4 pseudo-header.
        seg[0..2].copy_from_slice(&10000u16.to_be_bytes());
        let v4 = transport_checksum(Protocol::UDP, IpAddr::V4(src4), IpAddr::V4(dst4), &seg);
        let patched = csum_replace(
            v6,
            &[&src6.octets(), &dst6.octets(), &12345u16.to_be_bytes()],
            &[&src4.octets(), &dst4.octets(), &10000u16.to_be_bytes()],
        );
        // Equal as one's-complement values (0 and 0xFFFF are the same).
        assert_eq!(patched % 0xFFFF, v4 % 0xFFFF);
    }
}
