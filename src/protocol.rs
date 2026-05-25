use core::fmt;

/// Protocol identifies the IP protocol number carried in an IP packet.
///
/// ```
/// # use pktkit::Protocol;
/// assert_eq!(Protocol::TCP.as_u8(), 6);
/// assert_eq!(format!("{}", Protocol::ICMPV6), "ICMPv6");
/// ```
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct Protocol(pub u8);

impl Protocol {
    pub const ICMP: Protocol = Protocol(1);
    pub const TCP: Protocol = Protocol(6);
    pub const UDP: Protocol = Protocol(17);
    pub const ICMPV6: Protocol = Protocol(58);

    // A handful of others worth naming because the L3 layer often peeks at them.
    pub const IGMP: Protocol = Protocol(2);
    pub const IPV4: Protocol = Protocol(4); // IP-in-IP
    pub const GRE: Protocol = Protocol(47);
    pub const ESP: Protocol = Protocol(50);
    pub const AH: Protocol = Protocol(51);

    #[inline]
    pub const fn new(v: u8) -> Protocol {
        Protocol(v)
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for Protocol {
    #[inline]
    fn from(v: u8) -> Protocol {
        Protocol(v)
    }
}

impl From<Protocol> for u8 {
    #[inline]
    fn from(p: Protocol) -> u8 {
        p.0
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Protocol::ICMP => f.write_str("ICMP"),
            Protocol::TCP => f.write_str("TCP"),
            Protocol::UDP => f.write_str("UDP"),
            Protocol::ICMPV6 => f.write_str("ICMPv6"),
            Protocol::IGMP => f.write_str("IGMP"),
            Protocol::IPV4 => f.write_str("IPv4"),
            Protocol::GRE => f.write_str("GRE"),
            Protocol::ESP => f.write_str("ESP"),
            Protocol::AH => f.write_str("AH"),
            Protocol(v) => write!(f, "proto({})", v),
        }
    }
}
