//! TCP segment codec.

use crate::Result;
use std::io;

use super::options::{self, TcpOption};

/// TCP header flag bits, for [`Segment::flags`] and [`Segment::has_flag`].
pub mod flags {
    /// No more data from the sender.
    pub const FIN: u8 = 0x01;
    /// Synchronize sequence numbers.
    pub const SYN: u8 = 0x02;
    /// Reset the connection.
    pub const RST: u8 = 0x04;
    /// Push.
    pub const PSH: u8 = 0x08;
    /// The acknowledgment field is significant.
    pub const ACK: u8 = 0x10;
    /// The urgent pointer is significant.
    pub const URG: u8 = 0x20;
    /// ECN-Echo (RFC 3168): on a SYN, a request for ECN; on a SYN-ACK,
    /// its acceptance; after the handshake, a congestion signal. With
    /// AccECN (RFC 9768) the lowest bit of the ACE counter.
    pub const ECE: u8 = 0x40;
    /// Congestion Window Reduced (RFC 3168): the sender has answered an
    /// ECN-Echo. With AccECN the middle bit of the ACE counter.
    pub const CWR: u8 = 0x80;
}

/// A parsed TCP segment (header + options + payload).
///
/// The checksum field is preserved on parse but left at zero when marshalled —
/// the caller fills it in using the IP pseudo-header (it needs L3 information
/// the segment alone does not have).
#[derive(Debug, Clone, Default)]
pub struct Segment {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgment number.
    pub ack: u32,
    /// Flag bits; see [`flags`].
    pub flags: u8,
    /// The AE flag (RFC 9768), once the reserved bit before CWR: the top
    /// bit of AccECN's ACE counter, and part of its SYN's request.
    pub ae: bool,
    /// Advertised window, unscaled as on the wire.
    pub window: u16,
    /// Checksum as parsed; ignored by [`marshal`](Self::marshal).
    pub checksum: u16,
    /// Urgent pointer.
    pub urgent: u16,
    /// Options, in wire order.
    pub options: Vec<TcpOption>,
    /// Payload bytes.
    pub payload: Vec<u8>,
}

impl Segment {
    /// Parse a raw TCP segment (no IP header).
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "segment too short",
            ));
        }
        let data_off = (raw[12] >> 4) as usize * 4;
        if data_off < 20 || data_off > raw.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid data offset",
            ));
        }
        let mut s = Segment {
            src_port: u16::from_be_bytes([raw[0], raw[1]]),
            dst_port: u16::from_be_bytes([raw[2], raw[3]]),
            seq: u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
            ack: u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]),
            flags: raw[13],
            ae: raw[12] & 1 != 0,
            window: u16::from_be_bytes([raw[14], raw[15]]),
            checksum: u16::from_be_bytes([raw[16], raw[17]]),
            urgent: u16::from_be_bytes([raw[18], raw[19]]),
            options: Vec::new(),
            payload: Vec::new(),
        };
        if data_off > 20 {
            s.options = options::parse_options(&raw[20..data_off]);
        }
        if data_off < raw.len() {
            s.payload = raw[data_off..].to_vec();
        }
        Ok(s)
    }

    /// Serialize the segment to wire format. The checksum field is zero;
    /// callers must compute the TCP checksum over IP pseudo-header + segment
    /// and patch bytes 16..18 of the result before transmission.
    pub fn marshal(&self) -> Vec<u8> {
        let hdr_len = 20 + options::options_len(&self.options);
        let mut out = vec![0u8; hdr_len + self.payload.len()];
        out[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        out[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        out[4..8].copy_from_slice(&self.seq.to_be_bytes());
        out[8..12].copy_from_slice(&self.ack.to_be_bytes());
        out[12] = (((hdr_len / 4) as u8) << 4) | u8::from(self.ae);
        out[13] = self.flags;
        out[14..16].copy_from_slice(&self.window.to_be_bytes());
        // checksum left at 0
        out[18..20].copy_from_slice(&self.urgent.to_be_bytes());
        // Straight into place: an intermediate buffer per segment cost
        // more than the rest of the header together.
        options::write_options(&self.options, &mut out[20..hdr_len]);
        if !self.payload.is_empty() {
            out[hdr_len..].copy_from_slice(&self.payload);
        }
        out
    }

    /// Payload byte count.
    #[inline]
    pub fn data_len(&self) -> u32 {
        self.payload.len() as u32
    }

    /// "Segment length" in sequence space: payload + 1 per SYN + 1 per FIN.
    pub fn seg_len(&self) -> u32 {
        let mut n = self.payload.len() as u32;
        if self.flags & flags::SYN != 0 {
            n += 1;
        }
        if self.flags & flags::FIN != 0 {
            n += 1;
        }
        n
    }

    /// True if any of the bits in `flag` (see [`flags`]) is set.
    #[inline]
    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

#[cfg(test)]
mod tests {
    use super::options::{get_mss, mss_option};
    use super::*;

    #[test]
    fn parse_minimal() {
        let mut raw = vec![0u8; 20];
        raw[0..2].copy_from_slice(&12345u16.to_be_bytes());
        raw[2..4].copy_from_slice(&80u16.to_be_bytes());
        raw[4..8].copy_from_slice(&1000u32.to_be_bytes());
        raw[8..12].copy_from_slice(&2000u32.to_be_bytes());
        raw[12] = 5 << 4;
        raw[13] = flags::SYN | flags::ACK;
        raw[14..16].copy_from_slice(&65535u16.to_be_bytes());
        let s = Segment::parse(&raw).unwrap();
        assert_eq!(s.src_port, 12345);
        assert_eq!(s.dst_port, 80);
        assert_eq!(s.seq, 1000);
        assert_eq!(s.ack, 2000);
        assert_eq!(s.flags, flags::SYN | flags::ACK);
        assert_eq!(s.window, 65535);
        assert!(s.options.is_empty());
        assert!(s.payload.is_empty());
    }

    #[test]
    fn parse_with_payload_and_opts() {
        let s = Segment {
            src_port: 1,
            dst_port: 2,
            seq: 100,
            ack: 200,
            flags: flags::PSH | flags::ACK,
            window: 1024,
            options: vec![mss_option(1460)],
            payload: b"hello".to_vec(),
            ..Default::default()
        };
        let raw = s.marshal();
        let p = Segment::parse(&raw).unwrap();
        assert_eq!(p.payload, b"hello");
        assert_eq!(get_mss(&p.options), 1460);
    }

    #[test]
    fn ae_flag_round_trips() {
        let s = Segment {
            flags: flags::SYN | flags::ECE | flags::CWR,
            ae: true,
            ..Default::default()
        };
        let raw = s.marshal();
        assert_eq!(raw[12], (5 << 4) | 1);
        let p = Segment::parse(&raw).unwrap();
        assert!(p.ae);
        assert_eq!(p.flags, flags::SYN | flags::ECE | flags::CWR);
        assert!(!Segment::parse(&Segment::default().marshal()).unwrap().ae);
    }

    #[test]
    fn too_short_is_error() {
        assert!(Segment::parse(&[0u8; 5]).is_err());
    }

    #[test]
    fn bad_offset_is_error() {
        let mut raw = vec![0u8; 20];
        raw[12] = 15 << 4; // declares 60-byte header
        assert!(Segment::parse(&raw).is_err());
    }

    #[test]
    fn seg_len_counts_syn_and_fin() {
        let mut s = Segment {
            payload: b"hello".to_vec(),
            ..Default::default()
        };
        assert_eq!(s.seg_len(), 5);
        s.flags = flags::SYN;
        assert_eq!(s.seg_len(), 6);
        s.flags = flags::FIN;
        assert_eq!(s.seg_len(), 6);
        s.flags = flags::SYN | flags::FIN;
        assert_eq!(s.seg_len(), 7);
    }
}
