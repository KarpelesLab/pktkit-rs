use crate::{EtherType, MacAddr};
use core::fmt;

/// A raw Ethernet frame.
///
/// `Frame` is a `#[repr(transparent)]` newtype around `[u8]`, exactly mirroring
/// Go's `type Frame []byte`. `&Frame` is `#[repr(transparent)]` around `&[u8]`,
/// so the typed accessors never copy or allocate.
///
/// Owned construction goes through [`build_frame`], which returns a `Vec<u8>`
/// that you can then borrow as `&Frame` via [`Frame::from_slice`].
///
/// ```
/// # use pktkit::{Frame, MacAddr, EtherType, build_frame};
/// let a: MacAddr = "00:11:22:33:44:55".parse().unwrap();
/// let b: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
/// let buf = build_frame(a, b, EtherType::IPV4, &[0u8; 20]);
/// let f = Frame::from_slice(&buf);
/// assert!(f.is_valid());
/// assert_eq!(f.dst_mac(), Some(a));
/// assert_eq!(f.src_mac(), Some(b));
/// assert_eq!(f.ether_type(), EtherType::IPV4);
/// ```
#[repr(transparent)]
pub struct Frame(pub [u8]);

impl Frame {
    /// Wrap an existing byte slice as a `&Frame`. No allocation, no copy.
    #[inline]
    pub fn from_slice(b: &[u8]) -> &Frame {
        // SAFETY: Frame is `#[repr(transparent)]` over `[u8]`, so the layouts
        // of `&[u8]` and `&Frame` are identical.
        unsafe { &*(b as *const [u8] as *const Frame) }
    }

    /// Wrap an existing mutable byte slice as a `&mut Frame`.
    #[inline]
    pub fn from_mut(b: &mut [u8]) -> &mut Frame {
        // SAFETY: see `from_slice`.
        unsafe { &mut *(b as *mut [u8] as *mut Frame) }
    }

    /// Borrow the underlying bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Borrow the underlying bytes mutably.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Total frame length in bytes (header + payload).
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True if the frame is at least 14 bytes (one Ethernet header).
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.0.len() >= 14
    }

    /// Destination MAC, or `None` if the frame is too short.
    pub fn dst_mac(&self) -> Option<MacAddr> {
        if self.0.len() < 14 {
            return None;
        }
        let mut o = [0u8; 6];
        o.copy_from_slice(&self.0[0..6]);
        Some(MacAddr(o))
    }

    /// Source MAC, or `None` if the frame is too short.
    pub fn src_mac(&self) -> Option<MacAddr> {
        if self.0.len() < 14 {
            return None;
        }
        let mut o = [0u8; 6];
        o.copy_from_slice(&self.0[6..12]);
        Some(MacAddr(o))
    }

    /// True if the frame carries an 802.1Q VLAN tag.
    #[inline]
    pub fn has_vlan(&self) -> bool {
        self.0.len() >= 18 && raw_ether_type(&self.0) == EtherType::VLAN.as_u16()
    }

    /// VLAN identifier (12 bits). Returns 0 when [`has_vlan`](Self::has_vlan) is false.
    pub fn vlan_id(&self) -> u16 {
        if !self.has_vlan() {
            return 0;
        }
        u16::from_be_bytes([self.0[14], self.0[15]]) & 0x0FFF
    }

    /// Protocol type of the payload, transparently handling a VLAN tag.
    pub fn ether_type(&self) -> EtherType {
        if self.0.len() < 14 {
            return EtherType(0);
        }
        let et = raw_ether_type(&self.0);
        if et == EtherType::VLAN.as_u16() && self.0.len() >= 18 {
            return EtherType(u16::from_be_bytes([self.0[16], self.0[17]]));
        }
        EtherType(et)
    }

    /// Number of header bytes (14 normally, 18 with a VLAN tag).
    pub fn header_len(&self) -> usize {
        if self.has_vlan() {
            18
        } else {
            14
        }
    }

    /// Frame payload (everything after the Ethernet header). Empty if the
    /// frame is shorter than the header.
    pub fn payload(&self) -> &[u8] {
        let hl = self.header_len();
        if self.0.len() < hl {
            return &[];
        }
        &self.0[hl..]
    }

    /// Mutable view of the payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let hl = self.header_len();
        if self.0.len() < hl {
            return &mut [];
        }
        &mut self.0[hl..]
    }

    /// True if the destination is the all-ones broadcast.
    pub fn is_broadcast(&self) -> bool {
        self.0.len() >= 6 && self.0[..6] == [0xff; 6]
    }

    /// True if the destination has the IG bit set (broadcast is multicast).
    pub fn is_multicast(&self) -> bool {
        !self.0.is_empty() && self.0[0] & 1 != 0
    }

    /// Write a new destination MAC in place.
    pub fn set_dst_mac(&mut self, mac: MacAddr) {
        if self.0.len() < 14 {
            return;
        }
        self.0[0..6].copy_from_slice(&mac.octets());
    }

    /// Write a new source MAC in place.
    pub fn set_src_mac(&mut self, mac: MacAddr) {
        if self.0.len() < 14 {
            return;
        }
        self.0[6..12].copy_from_slice(&mac.octets());
    }
}

#[inline]
fn raw_ether_type(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[12], b[13]])
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("len", &self.len())
            .field("dst", &self.dst_mac())
            .field("src", &self.src_mac())
            .field("ether_type", &self.ether_type())
            .finish()
    }
}

/// Allocate and return a new Ethernet frame with the given header fields and
/// payload. The result is a `Vec<u8>`; borrow it as `&Frame` via
/// [`Frame::from_slice`].
pub fn build_frame(dst: MacAddr, src: MacAddr, ether_type: EtherType, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(14 + payload.len());
    v.extend_from_slice(&dst.octets());
    v.extend_from_slice(&src.octets());
    v.extend_from_slice(&ether_type.as_u16().to_be_bytes());
    v.extend_from_slice(payload);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_inspect() {
        let dst: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        let src: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        let payload = [1, 2, 3, 4, 5];
        let buf = build_frame(dst, src, EtherType::IPV4, &payload);
        let f = Frame::from_slice(&buf);

        assert!(f.is_valid());
        assert_eq!(f.dst_mac(), Some(dst));
        assert_eq!(f.src_mac(), Some(src));
        assert_eq!(f.ether_type(), EtherType::IPV4);
        assert!(!f.has_vlan());
        assert_eq!(f.header_len(), 14);
        assert_eq!(f.payload(), &payload);
        assert!(!f.is_broadcast());
        assert!(!f.is_multicast());
    }

    #[test]
    fn vlan_passthrough() {
        // dst | src | 0x8100 | TCI(0x0001) | 0x0800 | ...
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xff; 6]); // dst broadcast
        buf.extend_from_slice(&[0u8; 6]);
        buf.extend_from_slice(&[0x81, 0x00]); // VLAN
        buf.extend_from_slice(&[0x00, 0x01]); // VID=1
        buf.extend_from_slice(&[0x08, 0x00]); // IPv4
        buf.extend_from_slice(&[0xaa, 0xbb]); // payload

        let f = Frame::from_slice(&buf);
        assert!(f.is_valid());
        assert!(f.has_vlan());
        assert_eq!(f.vlan_id(), 1);
        assert_eq!(f.ether_type(), EtherType::IPV4);
        assert_eq!(f.header_len(), 18);
        assert_eq!(f.payload(), &[0xaa, 0xbb]);
        assert!(f.is_broadcast());
        assert!(f.is_multicast());
    }

    #[test]
    fn short_frame_is_invalid() {
        let buf = [0u8; 5];
        let f = Frame::from_slice(&buf);
        assert!(!f.is_valid());
        assert_eq!(f.dst_mac(), None);
        assert_eq!(f.src_mac(), None);
        assert_eq!(f.ether_type(), EtherType(0));
        assert_eq!(f.payload(), &[] as &[u8]);
    }

    #[test]
    fn mutable_setters() {
        let buf = build_frame(MacAddr::zero(), MacAddr::zero(), EtherType::IPV4, &[]);
        let mut owned = buf;
        let f = Frame::from_mut(&mut owned);

        let m: MacAddr = "12:34:56:78:9a:bc".parse().unwrap();
        f.set_dst_mac(m);
        f.set_src_mac(m);
        assert_eq!(f.dst_mac(), Some(m));
        assert_eq!(f.src_mac(), Some(m));
    }
}
