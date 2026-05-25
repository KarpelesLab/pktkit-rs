use crate::Protocol;
use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A raw IP packet (no Ethernet header).
///
/// `Packet` is a `#[repr(transparent)]` newtype around `[u8]`, exactly mirroring
/// Go's `type Packet []byte`. Accessors are version-aware: pick the IP version
/// from the first nibble, then read header fields without copying.
///
/// ```
/// # use pktkit::Packet;
/// // Minimal IPv4 header with src=10.0.0.1, dst=10.0.0.2, proto=UDP.
/// let mut buf = vec![
///     0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
///     0x40, 0x11, 0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2,
///     // payload (8B for total len = 28)
///     0, 0, 0, 0, 0, 0, 0, 0,
/// ];
/// let p = Packet::from_slice(&buf);
/// assert!(p.is_valid());
/// assert_eq!(p.version(), 4);
/// assert_eq!(p.ipv4_protocol(), pktkit::Protocol::UDP);
/// ```
#[repr(transparent)]
pub struct Packet(pub [u8]);

impl Packet {
    /// Wrap an existing byte slice as a `&Packet`.
    #[inline]
    pub fn from_slice(b: &[u8]) -> &Packet {
        // SAFETY: `#[repr(transparent)]` over `[u8]`.
        unsafe { &*(b as *const [u8] as *const Packet) }
    }

    /// Wrap an existing mutable byte slice as a `&mut Packet`.
    #[inline]
    pub fn from_mut(b: &mut [u8]) -> &mut Packet {
        // SAFETY: see `from_slice`.
        unsafe { &mut *(b as *mut [u8] as *mut Packet) }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True if the packet is long enough to host its declared header.
    pub fn is_valid(&self) -> bool {
        match self.version() {
            4 => self.0.len() >= 20,
            6 => self.0.len() >= 40,
            _ => false,
        }
    }

    /// IP version (4 or 6). Returns 0 if the packet is empty.
    #[inline]
    pub fn version(&self) -> u8 {
        if self.0.is_empty() {
            0
        } else {
            self.0[0] >> 4
        }
    }

    // --- IPv4 accessors ----------------------------------------------------

    /// IPv4 IHL converted to bytes (IHL * 4).
    pub fn ipv4_header_len(&self) -> usize {
        if self.0.is_empty() {
            0
        } else {
            (self.0[0] & 0x0F) as usize * 4
        }
    }

    /// IPv4 Total Length field.
    pub fn ipv4_total_len(&self) -> u16 {
        if self.0.len() < 4 {
            0
        } else {
            u16::from_be_bytes([self.0[2], self.0[3]])
        }
    }

    /// IPv4 TTL field.
    pub fn ipv4_ttl(&self) -> u8 {
        if self.0.len() < 9 {
            0
        } else {
            self.0[8]
        }
    }

    /// IPv4 Protocol field.
    pub fn ipv4_protocol(&self) -> Protocol {
        if self.0.len() < 10 {
            Protocol(0)
        } else {
            Protocol(self.0[9])
        }
    }

    pub fn ipv4_src_addr(&self) -> Option<Ipv4Addr> {
        if self.0.len() < 16 {
            None
        } else {
            let mut b = [0u8; 4];
            b.copy_from_slice(&self.0[12..16]);
            Some(Ipv4Addr::from(b))
        }
    }

    pub fn ipv4_dst_addr(&self) -> Option<Ipv4Addr> {
        if self.0.len() < 20 {
            None
        } else {
            let mut b = [0u8; 4];
            b.copy_from_slice(&self.0[16..20]);
            Some(Ipv4Addr::from(b))
        }
    }

    /// IPv4 payload: bytes between the header and Total Length. Empty if
    /// the packet is shorter than declared.
    pub fn ipv4_payload(&self) -> &[u8] {
        let hl = self.ipv4_header_len();
        let tl = self.ipv4_total_len() as usize;
        if hl == 0 || tl < hl || self.0.len() < tl {
            return &[];
        }
        &self.0[hl..tl]
    }

    pub fn set_ipv4_src_addr(&mut self, addr: Ipv4Addr) {
        if self.0.len() < 16 {
            return;
        }
        self.0[12..16].copy_from_slice(&addr.octets());
    }

    pub fn set_ipv4_dst_addr(&mut self, addr: Ipv4Addr) {
        if self.0.len() < 20 {
            return;
        }
        self.0[16..20].copy_from_slice(&addr.octets());
    }

    // --- IPv6 accessors ----------------------------------------------------

    pub fn ipv6_payload_len(&self) -> u16 {
        if self.0.len() < 6 {
            0
        } else {
            u16::from_be_bytes([self.0[4], self.0[5]])
        }
    }

    /// IPv6 Next Header field (equivalent to IPv4 Protocol).
    pub fn ipv6_next_header(&self) -> Protocol {
        if self.0.len() < 7 {
            Protocol(0)
        } else {
            Protocol(self.0[6])
        }
    }

    pub fn ipv6_hop_limit(&self) -> u8 {
        if self.0.len() < 8 {
            0
        } else {
            self.0[7]
        }
    }

    pub fn ipv6_src_addr(&self) -> Option<Ipv6Addr> {
        if self.0.len() < 24 {
            None
        } else {
            let mut b = [0u8; 16];
            b.copy_from_slice(&self.0[8..24]);
            Some(Ipv6Addr::from(b))
        }
    }

    pub fn ipv6_dst_addr(&self) -> Option<Ipv6Addr> {
        if self.0.len() < 40 {
            None
        } else {
            let mut b = [0u8; 16];
            b.copy_from_slice(&self.0[24..40]);
            Some(Ipv6Addr::from(b))
        }
    }

    /// IPv6 payload (data after the fixed 40-byte header).
    pub fn ipv6_payload(&self) -> &[u8] {
        if self.0.len() < 40 {
            return &[];
        }
        let pl = self.ipv6_payload_len() as usize;
        let end = 40 + pl;
        if end > self.0.len() {
            return &[];
        }
        &self.0[40..end]
    }

    pub fn set_ipv6_src_addr(&mut self, addr: Ipv6Addr) {
        if self.0.len() < 24 {
            return;
        }
        self.0[8..24].copy_from_slice(&addr.octets());
    }

    pub fn set_ipv6_dst_addr(&mut self, addr: Ipv6Addr) {
        if self.0.len() < 40 {
            return;
        }
        self.0[24..40].copy_from_slice(&addr.octets());
    }

    // --- Version-independent accessors ------------------------------------

    /// Source address dispatched on version.
    pub fn src_addr(&self) -> Option<IpAddr> {
        match self.version() {
            4 => self.ipv4_src_addr().map(IpAddr::V4),
            6 => self.ipv6_src_addr().map(IpAddr::V6),
            _ => None,
        }
    }

    /// Destination address dispatched on version.
    pub fn dst_addr(&self) -> Option<IpAddr> {
        match self.version() {
            4 => self.ipv4_dst_addr().map(IpAddr::V4),
            6 => self.ipv6_dst_addr().map(IpAddr::V6),
            _ => None,
        }
    }

    /// Upper-layer protocol number dispatched on version.
    pub fn ip_protocol(&self) -> Protocol {
        match self.version() {
            4 => self.ipv4_protocol(),
            6 => self.ipv6_next_header(),
            _ => Protocol(0),
        }
    }

    /// Upper-layer payload dispatched on version.
    pub fn payload(&self) -> &[u8] {
        match self.version() {
            4 => self.ipv4_payload(),
            6 => self.ipv6_payload(),
            _ => &[],
        }
    }

    /// True for the IPv4 limited broadcast `255.255.255.255`.
    /// IPv6 has no broadcast; use [`is_multicast`](Self::is_multicast).
    pub fn is_broadcast(&self) -> bool {
        if self.version() != 4 || self.0.len() < 20 {
            return false;
        }
        self.0[16..20] == [0xff; 4]
    }

    /// True for IPv4 `224.0.0.0/4` or IPv6 `ff00::/8`.
    pub fn is_multicast(&self) -> bool {
        match self.version() {
            4 => self.0.len() >= 20 && self.0[16] & 0xF0 == 0xE0,
            6 => self.0.len() >= 40 && self.0[24] == 0xFF,
            _ => false,
        }
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("len", &self.len())
            .field("version", &self.version())
            .field("src", &self.src_addr())
            .field("dst", &self.dst_addr())
            .field("proto", &self.ip_protocol())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_min() -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // v4, IHL=5
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p[8] = 64; // TTL
        p[9] = Protocol::TCP.0;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p
    }

    fn v6_min() -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60; // v6
        p[4..6].copy_from_slice(&0u16.to_be_bytes());
        p[6] = Protocol::UDP.0;
        p[7] = 64;
        p
    }

    #[test]
    fn ipv4_accessors() {
        let buf = v4_min();
        let p = Packet::from_slice(&buf);
        assert!(p.is_valid());
        assert_eq!(p.version(), 4);
        assert_eq!(p.ipv4_header_len(), 20);
        assert_eq!(p.ipv4_total_len(), 20);
        assert_eq!(p.ipv4_ttl(), 64);
        assert_eq!(p.ipv4_protocol(), Protocol::TCP);
        assert_eq!(p.ipv4_src_addr(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(p.ipv4_dst_addr(), Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(p.src_addr(), Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(p.ip_protocol(), Protocol::TCP);
        assert!(!p.is_broadcast());
        assert!(!p.is_multicast());
    }

    #[test]
    fn ipv6_accessors() {
        let buf = v6_min();
        let p = Packet::from_slice(&buf);
        assert!(p.is_valid());
        assert_eq!(p.version(), 6);
        assert_eq!(p.ipv6_payload_len(), 0);
        assert_eq!(p.ipv6_next_header(), Protocol::UDP);
        assert_eq!(p.ipv6_hop_limit(), 64);
        assert_eq!(p.ip_protocol(), Protocol::UDP);
        assert_eq!(p.payload(), &[] as &[u8]);
    }

    #[test]
    fn broadcast_and_multicast() {
        let mut buf = v4_min();
        buf[16..20].copy_from_slice(&[0xff; 4]);
        assert!(Packet::from_slice(&buf).is_broadcast());

        buf[16..20].copy_from_slice(&[224, 0, 0, 1]);
        assert!(Packet::from_slice(&buf).is_multicast());

        let mut buf6 = v6_min();
        buf6[24] = 0xff;
        assert!(Packet::from_slice(&buf6).is_multicast());
    }

    #[test]
    fn unknown_version() {
        let buf = vec![0u8; 5];
        let p = Packet::from_slice(&buf);
        assert!(!p.is_valid());
        assert_eq!(p.version(), 0);
        assert_eq!(p.payload(), &[] as &[u8]);
    }

    #[test]
    fn setters_roundtrip() {
        let mut buf = v4_min();
        let p = Packet::from_mut(&mut buf);
        p.set_ipv4_src_addr(Ipv4Addr::new(192, 168, 1, 2));
        p.set_ipv4_dst_addr(Ipv4Addr::new(192, 168, 1, 3));
        assert_eq!(p.ipv4_src_addr(), Some(Ipv4Addr::new(192, 168, 1, 2)));
        assert_eq!(p.ipv4_dst_addr(), Some(Ipv4Addr::new(192, 168, 1, 3)));
    }
}
