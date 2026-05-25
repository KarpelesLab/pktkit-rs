use core::fmt;

/// EtherType identifies the protocol encapsulated in an Ethernet frame payload.
///
/// Construct from a raw `u16` via [`From`] or with [`EtherType::new`]. The
/// well-known values are exposed as `pub const` so they remain usable in
/// `match` arms:
///
/// ```
/// # use pktkit::EtherType;
/// match EtherType::from(0x0800_u16) {
///     EtherType::IPV4 => println!("v4"),
///     EtherType::ARP  => println!("arp"),
///     _ => {}
/// }
/// ```
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct EtherType(pub u16);

impl EtherType {
    pub const IPV4: EtherType = EtherType(0x0800);
    pub const ARP: EtherType = EtherType(0x0806);
    pub const VLAN: EtherType = EtherType(0x8100);
    pub const IPV6: EtherType = EtherType(0x86DD);

    #[inline]
    pub const fn new(v: u16) -> EtherType {
        EtherType(v)
    }

    #[inline]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl From<u16> for EtherType {
    #[inline]
    fn from(v: u16) -> EtherType {
        EtherType(v)
    }
}

impl From<EtherType> for u16 {
    #[inline]
    fn from(v: EtherType) -> u16 {
        v.0
    }
}

impl fmt::Debug for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            EtherType::IPV4 => f.write_str("IPv4"),
            EtherType::ARP => f.write_str("ARP"),
            EtherType::VLAN => f.write_str("802.1Q"),
            EtherType::IPV6 => f.write_str("IPv6"),
            EtherType(v) => write!(f, "0x{:04x}", v),
        }
    }
}
