use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IP address with a CIDR prefix length.
///
/// Equivalent to Go's `netip.Prefix` — an [`IpAddr`] plus a prefix length in
/// bits (0–32 for v4, 0–128 for v6).
///
/// ```
/// # use std::net::Ipv4Addr;
/// # use pktkit::IpPrefix;
/// let p = IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1).into(), 24);
/// assert!(p.contains(Ipv4Addr::new(10, 0, 0, 99).into()));
/// assert!(!p.contains(Ipv4Addr::new(10, 0, 1, 1).into()));
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    addr: IpAddr,
    bits: u8,
}

impl IpPrefix {
    /// Construct a prefix. `bits` is clamped silently to the protocol max:
    /// at most 32 for v4 and 128 for v6.
    pub fn new(addr: IpAddr, bits: u8) -> IpPrefix {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        IpPrefix {
            addr,
            bits: bits.min(max),
        }
    }

    /// The address part. May or may not have the host bits zeroed; this matches
    /// Go's semantics so that `10.0.0.5/24` round-trips with the host bits.
    #[inline]
    pub fn addr(self) -> IpAddr {
        self.addr
    }

    /// The prefix length in bits.
    #[inline]
    pub fn bits(self) -> u8 {
        self.bits
    }

    /// True if `other` falls within this prefix (host bits ignored).
    pub fn contains(self, other: IpAddr) -> bool {
        match (self.addr, other) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => v4_contains(net, self.bits, ip),
            (IpAddr::V6(net), IpAddr::V6(ip)) => v6_contains(net, self.bits, ip),
            _ => false,
        }
    }

    /// Return a prefix with host bits zeroed (the canonical network address).
    pub fn masked(self) -> IpPrefix {
        match self.addr {
            IpAddr::V4(a) => IpPrefix {
                addr: IpAddr::V4(Ipv4Addr::from(u32::from(a) & v4_mask(self.bits))),
                bits: self.bits,
            },
            IpAddr::V6(a) => IpPrefix {
                addr: IpAddr::V6(Ipv6Addr::from(u128::from(a) & v6_mask(self.bits))),
                bits: self.bits,
            },
        }
    }

    /// Is this an IPv4 prefix?
    #[inline]
    pub fn is_v4(self) -> bool {
        matches!(self.addr, IpAddr::V4(_))
    }

    /// Is this an IPv6 prefix?
    #[inline]
    pub fn is_v6(self) -> bool {
        matches!(self.addr, IpAddr::V6(_))
    }

    /// True if this prefix has zero bits set on the address (an empty/unspecified).
    pub fn is_valid(self) -> bool {
        match self.addr {
            IpAddr::V4(a) => a != Ipv4Addr::UNSPECIFIED || self.bits != 0,
            IpAddr::V6(a) => a != Ipv6Addr::UNSPECIFIED || self.bits != 0,
        }
    }
}

impl Default for IpPrefix {
    fn default() -> IpPrefix {
        IpPrefix {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bits: 0,
        }
    }
}

impl fmt::Debug for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

/// Parse `addr/bits`, e.g. `10.0.0.0/24` or `fe80::/10`.
impl core::str::FromStr for IpPrefix {
    type Err = ParsePrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (a, b) = s.split_once('/').ok_or(ParsePrefixError(()))?;
        let addr: IpAddr = a.parse().map_err(|_| ParsePrefixError(()))?;
        let bits: u8 = b.parse().map_err(|_| ParsePrefixError(()))?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if bits > max {
            return Err(ParsePrefixError(()));
        }
        Ok(IpPrefix { addr, bits })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsePrefixError(());

impl fmt::Display for ParsePrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid IP prefix syntax")
    }
}

impl std::error::Error for ParsePrefixError {}

// --- helpers ----------------------------------------------------------------

fn v4_mask(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX.checked_shl(32 - bits as u32).unwrap_or(0)
    }
}

fn v6_mask(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX.checked_shl(128 - bits as u32).unwrap_or(0)
    }
}

fn v4_contains(net: Ipv4Addr, bits: u8, ip: Ipv4Addr) -> bool {
    let m = v4_mask(bits);
    u32::from(net) & m == u32::from(ip) & m
}

fn v6_contains(net: Ipv6Addr, bits: u8, ip: Ipv6Addr) -> bool {
    let m = v6_mask(bits);
    u128::from(net) & m == u128::from(ip) & m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v4() {
        let p: IpPrefix = "10.0.0.5/24".parse().unwrap();
        assert_eq!(p.bits(), 24);
        assert!(p.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200))));
        assert!(!p.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))));
        assert_eq!(p.masked().addr(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
    }

    #[test]
    fn parse_v6() {
        let p: IpPrefix = "2001:db8::1/64".parse().unwrap();
        assert!(p.is_v6());
        assert!(p.contains("2001:db8::ff".parse::<IpAddr>().unwrap()));
        assert!(!p.contains("2001:db8:1::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parse_rejects() {
        assert!("not-an-ip/24".parse::<IpPrefix>().is_err());
        assert!("10.0.0.0/33".parse::<IpPrefix>().is_err());
        assert!("::/129".parse::<IpPrefix>().is_err());
        assert!("10.0.0.0".parse::<IpPrefix>().is_err());
    }

    #[test]
    fn zero_bits_contains_all() {
        let p: IpPrefix = "0.0.0.0/0".parse().unwrap();
        assert!(p.contains(Ipv4Addr::new(1, 2, 3, 4).into()));
        let p6: IpPrefix = "::/0".parse().unwrap();
        assert!(p6.contains("dead::beef".parse::<IpAddr>().unwrap()));
    }
}
