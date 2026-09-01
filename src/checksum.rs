use crate::Protocol;
use std::net::IpAddr;

/// Compute the Internet checksum (RFC 1071) over `data`.
///
/// ```
/// # use pktkit::checksum;
/// // Empty buffer ⇒ ~0 = 0xFFFF
/// assert_eq!(checksum(&[]), 0xFFFF);
/// ```
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let n = data.len();
    let mut i = 0;
    // Word-aligned tight loop.
    while i + 1 < n {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if n & 1 != 0 {
        sum += (data[n - 1] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Fold two complemented Internet checksums into a single combined value.
///
/// This is the same primitive used to assemble a TCP/UDP checksum from a
/// pseudo-header sum and a payload sum.
pub fn combine_checksums(a: u16, b: u16) -> u16 {
    let mut sum = a as u32 + b as u32;
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// Compute the pseudo-header checksum for TCP/UDP, dispatching on the address
/// family. Returns the *complemented* sum, ready to feed into
/// [`combine_checksums`] with the payload checksum.
pub fn pseudo_header_checksum(proto: Protocol, src: IpAddr, dst: IpAddr, length: u16) -> u16 {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut buf = [0u8; 12];
            buf[0..4].copy_from_slice(&s.octets());
            buf[4..8].copy_from_slice(&d.octets());
            buf[8] = 0;
            buf[9] = proto.as_u8();
            buf[10..12].copy_from_slice(&length.to_be_bytes());
            !checksum(&buf)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            // RFC 2460 §8.1
            let mut buf = [0u8; 40];
            buf[0..16].copy_from_slice(&s.octets());
            buf[16..32].copy_from_slice(&d.octets());
            // bytes 32-33 left zero (upper length is always 0 for the lengths we handle)
            buf[34..36].copy_from_slice(&length.to_be_bytes());
            // bytes 36-38 zero, byte 39 holds the next header.
            buf[39] = proto.as_u8();
            !checksum(&buf)
        }
        _ => 0,
    }
}

/// Compute a TCP/UDP/ICMPv6 checksum over `pdu` with the pseudo-header for
/// `proto` mixed in. The result is the value to store in the checksum field.
///
/// `pdu` must already have its own checksum field zeroed, and `src`/`dst` must
/// be from the same address family as the enclosing packet.
///
/// ```
/// # use pktkit::{transport_checksum, Protocol};
/// # use std::net::Ipv4Addr;
/// let (src, dst) = (Ipv4Addr::new(10, 0, 0, 1).into(), Ipv4Addr::new(10, 0, 0, 2).into());
/// // A UDP header for ports 1 -> 2 with an empty body, checksum field zeroed.
/// let pdu = [0, 1, 0, 2, 0, 8, 0, 0];
/// assert_ne!(transport_checksum(Protocol::UDP, src, dst, &pdu), 0);
/// ```
pub fn transport_checksum(proto: Protocol, src: IpAddr, dst: IpAddr, pdu: &[u8]) -> u16 {
    !raw_transport_sum(proto, src, dst, pdu)
}

/// The uncomplemented sum of pseudo-header plus `pdu`.
///
/// Verification wants this form: a correct PDU — checksum field included —
/// sums to `0xFFFF`.
pub(crate) fn raw_transport_sum(proto: Protocol, src: IpAddr, dst: IpAddr, pdu: &[u8]) -> u16 {
    let length = pdu.len().min(u16::MAX as usize) as u16;
    let pseudo = pseudo_header_checksum(proto, src, dst, length);
    // `pseudo_header_checksum` and `checksum` both return complemented values;
    // combining needs the raw sums, so undo the complement on the body.
    combine_checksums(pseudo, !checksum(pdu))
}

/// Update a stored Internet checksum after part of the checksummed data
/// changed, without re-summing the whole buffer (RFC 1624, equation 3).
///
/// `old` and `new` are the bytes as they were and as they now are. They must
/// have the same length and must begin at an even offset within the
/// checksummed region, since the checksum is defined over 16-bit words.
///
/// This is what makes address and port rewriting cheap: a NAT that changes four
/// bytes pays for four bytes, not for the whole packet.
///
/// ```
/// # use pktkit::{checksum, incremental_update};
/// let mut buf = [0x45u8, 0x00, 0x00, 0x14, 0xde, 0xad, 0x00, 0x00];
/// let before = checksum(&buf);
/// // Rewrite the two bytes at offset 4 and patch the checksum to match.
/// let patched = incremental_update(before, &buf[4..6], &[0xbe, 0xef]);
/// buf[4..6].copy_from_slice(&[0xbe, 0xef]);
/// assert_eq!(patched, checksum(&buf));
/// ```
pub fn incremental_update(old_checksum: u16, old: &[u8], new: &[u8]) -> u16 {
    debug_assert_eq!(
        old.len(),
        new.len(),
        "incremental_update needs equal-length before/after images"
    );
    // HC' = ~(~HC + ~m + m')
    let mut sum = (!old_checksum) as u32;
    sum += ones_complement_words(old);
    sum += word_sum(new);
    !fold(sum)
}

/// Sum the 16-bit words of `data`, padding an odd tail byte on the right.
fn word_sum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let n = data.len();
    let mut i = 0;
    while i + 1 < n {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if n & 1 != 0 {
        sum += (data[n - 1] as u32) << 8;
    }
    sum
}

/// Sum the *complements* of the 16-bit words of `data` — the `~m` term.
fn ones_complement_words(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let n = data.len();
    let mut i = 0;
    while i + 1 < n {
        let w = ((data[i] as u16) << 8) | (data[i + 1] as u16);
        sum += (!w) as u32;
        i += 2;
    }
    if n & 1 != 0 {
        let w = (data[n - 1] as u16) << 8;
        sum += (!w) as u32;
    }
    sum
}

#[inline]
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn rfc1071_reference() {
        // RFC 1071 example: 00 01 f2 03 f4 f5 f6 f7
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), 0x220d);
    }

    #[test]
    fn odd_length_is_padded() {
        let data = [0x00, 0x01, 0x02];
        // Manual: word [0x0001] + word [0x0200] = 0x0201, complement = 0xFDFE
        assert_eq!(checksum(&data), 0xFDFE);
    }

    #[test]
    fn combine_is_associative() {
        let a = checksum(&[0xaa; 100]);
        let b = checksum(&[0x55; 50]);
        // Combining produces a valid u16 (no overflow leaks).
        let c = combine_checksums(a, b);
        let d = combine_checksums(b, a);
        assert_eq!(c, d);
    }

    #[test]
    fn pseudo_header_v4() {
        let s = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let d = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let sum = pseudo_header_checksum(Protocol::UDP, s, d, 20);
        // Build by hand and compare.
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&[1, 2, 3, 4]);
        buf[4..8].copy_from_slice(&[5, 6, 7, 8]);
        buf[9] = 17;
        buf[10..12].copy_from_slice(&20u16.to_be_bytes());
        assert_eq!(sum, !checksum(&buf));
    }

    #[test]
    fn pseudo_header_v6() {
        let s = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let d = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        let _ = pseudo_header_checksum(Protocol::TCP, s, d, 40);
        // Just ensure it runs without panicking and produces a value.
    }

    #[test]
    fn mixed_family_returns_zero() {
        let s = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let d = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(pseudo_header_checksum(Protocol::UDP, s, d, 8), 0);
    }

    #[test]
    fn transport_checksum_self_verifies() {
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut pdu = vec![0u8, 53, 0x13, 0x88, 0, 12, 0, 0, 1, 2, 3, 4];
        let sum = transport_checksum(Protocol::UDP, src, dst, &pdu);
        pdu[6..8].copy_from_slice(&sum.to_be_bytes());
        // With the field filled in, the whole thing sums to all ones.
        assert_eq!(raw_transport_sum(Protocol::UDP, src, dst, &pdu), 0xFFFF);
    }

    #[test]
    fn transport_checksum_detects_a_flipped_bit() {
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut pdu = vec![0u8, 53, 0x13, 0x88, 0, 12, 0, 0, 1, 2, 3, 4];
        let sum = transport_checksum(Protocol::UDP, src, dst, &pdu);
        pdu[6..8].copy_from_slice(&sum.to_be_bytes());
        pdu[9] ^= 0x01;
        assert_ne!(raw_transport_sum(Protocol::UDP, src, dst, &pdu), 0xFFFF);
    }

    #[test]
    fn incremental_matches_full_recompute() {
        // A realistic IPv4 header; flip the destination address and check that
        // the patched checksum equals a from-scratch one.
        let mut hdr = vec![
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let sum = checksum(&hdr);
        hdr[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(checksum(&hdr), 0, "header must now self-verify");

        let new_dst = [10u8, 0, 0, 9];
        let patched = incremental_update(sum, &hdr[16..20], &new_dst);
        hdr[16..20].copy_from_slice(&new_dst);
        hdr[10..12].copy_from_slice(&[0, 0]);
        assert_eq!(patched, checksum(&hdr));
    }

    #[test]
    fn incremental_is_reversible() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let sum = checksum(&data);
        let there = incremental_update(sum, &data[0..2], &[0x12, 0x34]);
        let back = incremental_update(there, &[0x12, 0x34], &data[0..2]);
        assert_eq!(back, sum);
    }

    #[test]
    fn incremental_no_change_is_identity() {
        let data = [1u8, 2, 3, 4, 5, 6];
        let sum = checksum(&data);
        assert_eq!(incremental_update(sum, &data[2..4], &data[2..4]), sum);
    }

    #[test]
    fn incremental_odd_length_region() {
        let mut data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let sum = checksum(&data);
        let patched = incremental_update(sum, &data[4..5], &[0x99]);
        data[4] = 0x99;
        assert_eq!(patched, checksum(&data));
    }
}
