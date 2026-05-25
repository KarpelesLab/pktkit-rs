use core::fmt;

/// A 48-bit Ethernet MAC address.
///
/// Stored as a fixed-size byte array — `Copy`, no allocation. Equivalent to
/// Go's `net.HardwareAddr` constrained to length 6.
///
/// ```
/// # use pktkit::MacAddr;
/// let m: MacAddr = "DE:AD:BE:EF:00:01".parse().unwrap();
/// assert_eq!(m.octets(), [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
/// assert!(!m.is_broadcast());
/// assert!(m.is_unicast());
/// ```
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

/// The all-ones broadcast MAC, `ff:ff:ff:ff:ff:ff`.
pub const BROADCAST_MAC: MacAddr = MacAddr([0xff; 6]);

impl MacAddr {
    /// Create a MAC from its six octets in transmission order.
    #[inline]
    pub const fn new(octets: [u8; 6]) -> MacAddr {
        MacAddr(octets)
    }

    /// All-zero MAC, `00:00:00:00:00:00`.
    #[inline]
    pub const fn zero() -> MacAddr {
        MacAddr([0; 6])
    }

    /// The all-ones broadcast MAC.
    #[inline]
    pub const fn broadcast() -> MacAddr {
        BROADCAST_MAC
    }

    /// Return the six octets.
    #[inline]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Borrow the octets as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Try to copy from a 6-byte slice. Returns `None` if the length is wrong.
    pub fn from_slice(b: &[u8]) -> Option<MacAddr> {
        if b.len() != 6 {
            return None;
        }
        let mut o = [0u8; 6];
        o.copy_from_slice(b);
        Some(MacAddr(o))
    }

    /// True if every octet is `0xff`.
    #[inline]
    pub fn is_broadcast(self) -> bool {
        self.0 == [0xff; 6]
    }

    /// True if the IG bit (LSB of the first octet) is set.
    /// Broadcast is also multicast.
    #[inline]
    pub fn is_multicast(self) -> bool {
        self.0[0] & 1 != 0
    }

    /// True if the IG bit is clear.
    #[inline]
    pub fn is_unicast(self) -> bool {
        !self.is_multicast()
    }

    /// True if the LU bit (second LSB of the first octet) is set, indicating
    /// a locally-administered address.
    #[inline]
    pub fn is_local(self) -> bool {
        self.0[0] & 2 != 0
    }

    /// Generate a random locally-administered unicast MAC using the OS RNG.
    /// The first octet has the IG bit cleared and the LU bit set.
    #[cfg(feature = "l2adapter")]
    pub fn random_local_unicast() -> MacAddr {
        let mut o = [0u8; 6];
        crate::rand::fill(&mut o);
        // Clear IG bit (unicast), set LU bit (locally administered).
        o[0] = (o[0] & 0xFC) | 0x02;
        MacAddr(o)
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

/// Parse `aa:bb:cc:dd:ee:ff` (`:` or `-` separated, hex octets, case-insensitive).
impl core::str::FromStr for MacAddr {
    type Err = ParseMacError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 6];
        let mut i = 0;
        for part in s.split(|c| c == ':' || c == '-') {
            if i >= 6 {
                return Err(ParseMacError(()));
            }
            if part.len() != 2 {
                return Err(ParseMacError(()));
            }
            octets[i] = u8::from_str_radix(part, 16).map_err(|_| ParseMacError(()))?;
            i += 1;
        }
        if i != 6 {
            return Err(ParseMacError(()));
        }
        Ok(MacAddr(octets))
    }
}

/// Returned by [`MacAddr::from_str`] on a malformed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseMacError(());

impl fmt::Display for ParseMacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid MAC address syntax")
    }
}

impl std::error::Error for ParseMacError {}

impl From<[u8; 6]> for MacAddr {
    #[inline]
    fn from(o: [u8; 6]) -> MacAddr {
        MacAddr(o)
    }
}

impl From<MacAddr> for [u8; 6] {
    #[inline]
    fn from(m: MacAddr) -> [u8; 6] {
        m.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display_roundtrip() {
        let m: MacAddr = "01:23:45:67:89:ab".parse().unwrap();
        assert_eq!(m.octets(), [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
        assert_eq!(format!("{}", m), "01:23:45:67:89:ab");

        // Dash separator also works.
        let n: MacAddr = "01-23-45-67-89-AB".parse().unwrap();
        assert_eq!(n, m);
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!("xx:yy:zz:00:00:00".parse::<MacAddr>().is_err());
        assert!("01:02:03:04:05".parse::<MacAddr>().is_err());
        assert!("01:02:03:04:05:06:07".parse::<MacAddr>().is_err());
        assert!("0:1:2:3:4:5".parse::<MacAddr>().is_err()); // octets must be 2 chars
    }

    #[test]
    fn classify() {
        assert!(BROADCAST_MAC.is_broadcast());
        assert!(BROADCAST_MAC.is_multicast());
        assert!(!MacAddr::zero().is_broadcast());
        assert!(!MacAddr::zero().is_multicast());

        let m: MacAddr = "01:00:5e:00:00:01".parse().unwrap(); // IPv4 multicast
        assert!(m.is_multicast());
        assert!(!m.is_unicast());
    }
}
