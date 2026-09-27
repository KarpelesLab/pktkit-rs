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
