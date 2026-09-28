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
    /// Internet Control Message Protocol (RFC 792).
    pub const ICMP: Protocol = Protocol(1);
    /// Transmission Control Protocol.
    pub const TCP: Protocol = Protocol(6);
    /// User Datagram Protocol.
    pub const UDP: Protocol = Protocol(17);
    /// ICMP for IPv6 (RFC 4443).
    pub const ICMPV6: Protocol = Protocol(58);

    // A handful of others worth naming because the L3 layer often peeks at them.
    /// Internet Group Management Protocol.
    pub const IGMP: Protocol = Protocol(2);
    /// IPv4 encapsulated in IP (IP-in-IP, RFC 2003).
    pub const IPV4: Protocol = Protocol(4);
    /// Generic Routing Encapsulation.
    pub const GRE: Protocol = Protocol(47);
    /// IPsec Encapsulating Security Payload.
    pub const ESP: Protocol = Protocol(50);
    /// IPsec Authentication Header.
    pub const AH: Protocol = Protocol(51);

    /// The protocol with number `v`.
    #[inline]
    pub const fn new(v: u8) -> Protocol {
        Protocol(v)
    }

    /// The raw protocol number.
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
