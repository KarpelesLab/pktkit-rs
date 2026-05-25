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
}
