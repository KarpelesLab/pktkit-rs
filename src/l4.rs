//! Typed, zero-copy views of the transport layer.
//!
//! These mirror [`Frame`](crate::Frame) and [`Packet`](crate::Packet) one layer
//! up: `#[repr(transparent)]` newtypes over `[u8]` with accessors that read
//! wire fields in place. Get one from a packet with [`Packet::tcp`],
//! [`Packet::udp`] or [`Packet::icmp`], or wrap a slice directly with
//! `from_slice`.
//!
//! ```
//! # use pktkit::{Packet, Protocol};
//! # use pktkit::build::{build_ipv4, build_udp};
//! # use std::net::Ipv4Addr;
//! let (src, dst) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
//! let udp = build_udp(src.into(), dst.into(), 1234, 53, b"query");
//! let buf = build_ipv4(src, dst, Protocol::UDP, 64, &udp);
//!
//! let pkt = Packet::from_slice(&buf);
//! let dg = pkt.udp().expect("a UDP datagram");
//! assert_eq!(dg.src_port(), 1234);
//! assert_eq!(dg.dst_port(), 53);
//! assert_eq!(dg.payload(), b"query");
//! ```
//!
//! [`Packet::tcp`]: crate::Packet::tcp
//! [`Packet::udp`]: crate::Packet::udp
//! [`Packet::icmp`]: crate::Packet::icmp

use crate::Protocol;
use core::fmt;
use core::ops::Deref;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

/// The TCP control bits, as a set.
///
/// ```
/// # use pktkit::l4::TcpFlags;
/// let f = TcpFlags::SYN | TcpFlags::ACK;
/// assert!(f.contains(TcpFlags::SYN));
/// assert!(!f.contains(TcpFlags::FIN));
/// assert_eq!(f.to_string(), "SYN|ACK");
/// ```
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: TcpFlags = TcpFlags(0x01);
    pub const SYN: TcpFlags = TcpFlags(0x02);
    pub const RST: TcpFlags = TcpFlags(0x04);
    pub const PSH: TcpFlags = TcpFlags(0x08);
    pub const ACK: TcpFlags = TcpFlags(0x10);
    pub const URG: TcpFlags = TcpFlags(0x20);
    pub const ECE: TcpFlags = TcpFlags(0x40);
    pub const CWR: TcpFlags = TcpFlags(0x80);

    #[inline]
    pub const fn new(bits: u8) -> TcpFlags {
        TcpFlags(bits)
    }

    #[inline]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// True if every flag in `other` is set here.
    #[inline]
    pub const fn contains(self, other: TcpFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// True if any flag in `other` is set here.
    #[inline]
    pub const fn intersects(self, other: TcpFlags) -> bool {
        self.0 & other.0 != 0
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for TcpFlags {
    type Output = TcpFlags;
    #[inline]
    fn bitor(self, rhs: TcpFlags) -> TcpFlags {
        TcpFlags(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for TcpFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: TcpFlags) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitAnd for TcpFlags {
    type Output = TcpFlags;
    #[inline]
    fn bitand(self, rhs: TcpFlags) -> TcpFlags {
        TcpFlags(self.0 & rhs.0)
    }
}

impl fmt::Debug for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [(u8, &str); 8] = [
            (0x01, "FIN"),
            (0x02, "SYN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x10, "ACK"),
            (0x20, "URG"),
            (0x40, "ECE"),
            (0x80, "CWR"),
        ];
        if self.0 == 0 {
            return f.write_str("none");
        }
        let mut first = true;
        for (bit, name) in NAMES {
            if self.0 & bit != 0 {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}

/// A TCP segment: header plus payload.
///
/// Every accessor returns a zero value rather than panicking when the buffer is
/// too short, so an untrusted segment can be inspected before
/// [`is_valid`](Self::is_valid) is consulted.
#[repr(transparent)]
pub struct TcpSegment(pub [u8]);

impl TcpSegment {
    /// Minimum TCP header size, with no options.
    pub const MIN_HEADER_LEN: usize = 20;

    #[inline]
    pub fn from_slice(b: &[u8]) -> &TcpSegment {
        // SAFETY: `#[repr(transparent)]` over `[u8]`.
        unsafe { &*(b as *const [u8] as *const TcpSegment) }
    }

    #[inline]
    pub fn from_mut(b: &mut [u8]) -> &mut TcpSegment {
        // SAFETY: see `from_slice`.
        unsafe { &mut *(b as *mut [u8] as *mut TcpSegment) }
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

    /// True if the buffer holds a complete TCP header, options included.
    pub fn is_valid(&self) -> bool {
        self.0.len() >= Self::MIN_HEADER_LEN && self.header_len() <= self.0.len()
    }

    #[inline]
    pub fn src_port(&self) -> u16 {
        read_u16(&self.0, 0)
    }

    #[inline]
    pub fn dst_port(&self) -> u16 {
        read_u16(&self.0, 2)
    }

    #[inline]
    pub fn seq(&self) -> u32 {
        read_u32(&self.0, 4)
    }

    #[inline]
    pub fn ack(&self) -> u32 {
        read_u32(&self.0, 8)
    }

    /// Header length in bytes, derived from the data-offset nibble. Clamped to
    /// at least [`MIN_HEADER_LEN`](Self::MIN_HEADER_LEN) so a nonsense
    /// data-offset of 0 cannot produce a header shorter than the fixed fields.
    pub fn header_len(&self) -> usize {
        if self.0.len() < 13 {
            return Self::MIN_HEADER_LEN;
        }
        ((self.0[12] >> 4) as usize * 4).max(Self::MIN_HEADER_LEN)
    }

    #[inline]
    pub fn flags(&self) -> TcpFlags {
        if self.0.len() < 14 {
            TcpFlags(0)
        } else {
            TcpFlags(self.0[13])
        }
    }

    #[inline]
    pub fn window(&self) -> u16 {
        read_u16(&self.0, 14)
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        read_u16(&self.0, 16)
    }

    #[inline]
    pub fn urgent_ptr(&self) -> u16 {
        read_u16(&self.0, 18)
    }

    /// The TCP options blob, between the fixed header and the data offset.
    pub fn options(&self) -> &[u8] {
        let hl = self.header_len();
        if hl <= Self::MIN_HEADER_LEN || self.0.len() < hl {
            return &[];
        }
        &self.0[Self::MIN_HEADER_LEN..hl]
    }

    /// Segment payload — the bytes past the header.
    pub fn payload(&self) -> &[u8] {
        let hl = self.header_len();
        if self.0.len() < hl {
            return &[];
        }
        &self.0[hl..]
    }

    /// Mutable view of [`payload`](Self::payload).
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let hl = self.header_len();
        if self.0.len() < hl {
            return &mut [];
        }
        &mut self.0[hl..]
    }

    pub fn set_src_port(&mut self, port: u16) {
        write_u16(&mut self.0, 0, port);
    }

    pub fn set_dst_port(&mut self, port: u16) {
        write_u16(&mut self.0, 2, port);
    }

    pub fn set_seq(&mut self, seq: u32) {
        write_u32(&mut self.0, 4, seq);
    }

    pub fn set_ack(&mut self, ack: u32) {
        write_u32(&mut self.0, 8, ack);
    }

    pub fn set_flags(&mut self, flags: TcpFlags) {
        if self.0.len() >= 14 {
            self.0[13] = flags.bits();
        }
    }

    pub fn set_window(&mut self, window: u16) {
        write_u16(&mut self.0, 14, window);
    }

    pub fn set_checksum(&mut self, sum: u16) {
        write_u16(&mut self.0, 16, sum);
    }

    /// Iterate the TCP options as `(kind, value)` pairs.
    ///
    /// End-of-options (0) terminates the iteration and NOP (1) is skipped; a
    /// truncated option ends it. Values exclude the kind and length bytes.
    pub fn option_iter(&self) -> TcpOptions<'_> {
        TcpOptions {
            buf: self.options(),
            pos: 0,
        }
    }
}

/// Iterator over TCP options — see [`TcpSegment::option_iter`].
#[derive(Debug)]
pub struct TcpOptions<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for TcpOptions<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        loop {
            let kind = *self.buf.get(self.pos)?;
            match kind {
                // End of option list.
                0 => return None,
                // No-op padding.
                1 => self.pos += 1,
                _ => {
                    let len = *self.buf.get(self.pos + 1)? as usize;
                    // A length below 2 would not advance; treat it as corrupt.
                    if len < 2 || self.pos + len > self.buf.len() {
                        return None;
                    }
                    let value = &self.buf[self.pos + 2..self.pos + len];
                    self.pos += len;
                    return Some((kind, value));
                }
            }
        }
    }
}

impl fmt::Debug for TcpSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpSegment")
            .field("src_port", &self.src_port())
            .field("dst_port", &self.dst_port())
            .field("seq", &self.seq())
            .field("ack", &self.ack())
            .field("flags", &self.flags())
            .field("window", &self.window())
            .field("payload_len", &self.payload().len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

/// A UDP datagram: 8-byte header plus payload.
#[repr(transparent)]
pub struct UdpDatagram(pub [u8]);

impl UdpDatagram {
    pub const HEADER_LEN: usize = 8;

    #[inline]
    pub fn from_slice(b: &[u8]) -> &UdpDatagram {
        // SAFETY: `#[repr(transparent)]` over `[u8]`.
        unsafe { &*(b as *const [u8] as *const UdpDatagram) }
    }

    #[inline]
    pub fn from_mut(b: &mut [u8]) -> &mut UdpDatagram {
        // SAFETY: see `from_slice`.
        unsafe { &mut *(b as *mut [u8] as *mut UdpDatagram) }
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

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.0.len() >= Self::HEADER_LEN
    }

    #[inline]
    pub fn src_port(&self) -> u16 {
        read_u16(&self.0, 0)
    }

    #[inline]
    pub fn dst_port(&self) -> u16 {
        read_u16(&self.0, 2)
    }

    /// The Length field: header plus payload, as declared on the wire.
    #[inline]
    pub fn length(&self) -> u16 {
        read_u16(&self.0, 4)
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        read_u16(&self.0, 6)
    }

    /// Datagram payload, bounded by the declared Length when that is shorter
    /// than the buffer (trailing bytes are Ethernet padding, not data).
    pub fn payload(&self) -> &[u8] {
        if self.0.len() < Self::HEADER_LEN {
            return &[];
        }
        let declared = self.length() as usize;
        let end = if declared >= Self::HEADER_LEN && declared <= self.0.len() {
            declared
        } else {
            self.0.len()
        };
        &self.0[Self::HEADER_LEN..end]
    }

    /// Mutable view of [`payload`](Self::payload).
    pub fn payload_mut(&mut self) -> &mut [u8] {
        if self.0.len() < Self::HEADER_LEN {
            return &mut [];
        }
        let declared = self.length() as usize;
        let end = if declared >= Self::HEADER_LEN && declared <= self.0.len() {
            declared
        } else {
            self.0.len()
        };
        &mut self.0[Self::HEADER_LEN..end]
    }

    pub fn set_src_port(&mut self, port: u16) {
        write_u16(&mut self.0, 0, port);
    }

    pub fn set_dst_port(&mut self, port: u16) {
        write_u16(&mut self.0, 2, port);
    }

    pub fn set_length(&mut self, len: u16) {
        write_u16(&mut self.0, 4, len);
    }

    pub fn set_checksum(&mut self, sum: u16) {
        write_u16(&mut self.0, 6, sum);
    }
}

impl fmt::Debug for UdpDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpDatagram")
            .field("src_port", &self.src_port())
            .field("dst_port", &self.dst_port())
            .field("length", &self.length())
            .field("payload_len", &self.payload().len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ICMP
// ---------------------------------------------------------------------------

/// ICMPv4 message types this crate names.
pub mod icmpv4 {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACHABLE: u8 = 3;
    pub const REDIRECT: u8 = 5;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const PARAMETER_PROBLEM: u8 = 12;

    /// Codes for [`DEST_UNREACHABLE`].
    pub const CODE_NET_UNREACHABLE: u8 = 0;
    pub const CODE_HOST_UNREACHABLE: u8 = 1;
    pub const CODE_PROTOCOL_UNREACHABLE: u8 = 2;
    pub const CODE_PORT_UNREACHABLE: u8 = 3;
    /// Fragmentation needed but DF set — carries the next-hop MTU.
    pub const CODE_FRAG_NEEDED: u8 = 4;
    pub const CODE_NET_ADMIN_PROHIBITED: u8 = 9;
    pub const CODE_HOST_ADMIN_PROHIBITED: u8 = 10;
    pub const CODE_ADMIN_PROHIBITED: u8 = 13;

    /// Codes for [`TIME_EXCEEDED`].
    pub const CODE_TTL_EXCEEDED: u8 = 0;
    pub const CODE_REASSEMBLY_TIMEOUT: u8 = 1;
}

/// ICMPv6 message types this crate names.
pub mod icmpv6 {
    pub const DEST_UNREACHABLE: u8 = 1;
    pub const PACKET_TOO_BIG: u8 = 2;
    pub const TIME_EXCEEDED: u8 = 3;
    pub const PARAMETER_PROBLEM: u8 = 4;
    pub const ECHO_REQUEST: u8 = 128;
    pub const ECHO_REPLY: u8 = 129;
    pub const ROUTER_SOLICITATION: u8 = 133;
    pub const ROUTER_ADVERTISEMENT: u8 = 134;
    pub const NEIGHBOR_SOLICITATION: u8 = 135;
    pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;

    /// Codes for [`DEST_UNREACHABLE`].
    pub const CODE_NO_ROUTE: u8 = 0;
    pub const CODE_ADMIN_PROHIBITED: u8 = 1;
    pub const CODE_ADDR_UNREACHABLE: u8 = 3;
    pub const CODE_PORT_UNREACHABLE: u8 = 4;

    /// Codes for [`TIME_EXCEEDED`].
    pub const CODE_HOP_LIMIT_EXCEEDED: u8 = 0;
    pub const CODE_REASSEMBLY_TIMEOUT: u8 = 1;
}

/// An ICMP or ICMPv6 message.
///
/// The two protocols share a header shape — type, code, checksum, four bytes of
/// per-type data — so one view serves both. The type and code numbers differ;
/// see the [`icmpv4`] and [`icmpv6`] constant modules.
#[repr(transparent)]
pub struct IcmpMessage(pub [u8]);

impl IcmpMessage {
    pub const HEADER_LEN: usize = 8;

    #[inline]
    pub fn from_slice(b: &[u8]) -> &IcmpMessage {
        // SAFETY: `#[repr(transparent)]` over `[u8]`.
        unsafe { &*(b as *const [u8] as *const IcmpMessage) }
    }

    #[inline]
    pub fn from_mut(b: &mut [u8]) -> &mut IcmpMessage {
        // SAFETY: see `from_slice`.
        unsafe { &mut *(b as *mut [u8] as *mut IcmpMessage) }
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

    /// True if the type, code and checksum fields are present. Note that the
    /// full 8-byte header is only guaranteed once
    /// [`len`](Self::len) >= [`HEADER_LEN`](Self::HEADER_LEN).
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.0.len() >= 4
    }

    #[inline]
    pub fn message_type(&self) -> u8 {
        if self.0.is_empty() {
            0
        } else {
            self.0[0]
        }
    }

    #[inline]
    pub fn code(&self) -> u8 {
        if self.0.len() < 2 {
            0
        } else {
            self.0[1]
        }
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        read_u16(&self.0, 2)
    }

    /// The four type-specific bytes after the checksum (identifier/sequence for
    /// echo, next-hop MTU for Packet Too Big, and so on).
    pub fn rest_of_header(&self) -> [u8; 4] {
        let mut out = [0u8; 4];
        if self.0.len() >= Self::HEADER_LEN {
            out.copy_from_slice(&self.0[4..8]);
        }
        out
    }

    /// Everything after the 8-byte header. For an error message this is the
    /// quoted original packet.
    pub fn payload(&self) -> &[u8] {
        if self.0.len() < Self::HEADER_LEN {
            return &[];
        }
        &self.0[Self::HEADER_LEN..]
    }

    /// Echo identifier — meaningful only for echo request/reply.
    #[inline]
    pub fn echo_id(&self) -> u16 {
        read_u16(&self.0, 4)
    }

    /// Echo sequence number — meaningful only for echo request/reply.
    #[inline]
    pub fn echo_seq(&self) -> u16 {
        read_u16(&self.0, 6)
    }

    /// Next-hop MTU carried by ICMPv4 Fragmentation Needed and ICMPv6 Packet
    /// Too Big.
    pub fn mtu(&self) -> u32 {
        match self.message_type() {
            // ICMPv4 frag-needed puts the MTU in the low half of the rest.
            icmpv4::DEST_UNREACHABLE => read_u16(&self.0, 6) as u32,
            _ => read_u32(&self.0, 4),
        }
    }

    pub fn set_message_type(&mut self, t: u8) {
        if !self.0.is_empty() {
            self.0[0] = t;
        }
    }

    pub fn set_code(&mut self, c: u8) {
        if self.0.len() >= 2 {
            self.0[1] = c;
        }
    }

    pub fn set_checksum(&mut self, sum: u16) {
        write_u16(&mut self.0, 2, sum);
    }

    /// True if this is an ICMPv4 error message rather than a query.
    ///
    /// Errors must never be generated in response to other errors; that check
    /// lives in [`crate::icmp`].
    pub fn is_icmpv4_error(&self) -> bool {
        matches!(self.message_type(), 3 | 4 | 5 | 11 | 12)
    }

    /// True if this is an ICMPv6 error message (types 0-127) rather than an
    /// informational message (128-255).
    pub fn is_icmpv6_error(&self) -> bool {
        self.message_type() < 128
    }

    /// Verify an **ICMPv4** checksum, which covers the message only.
    ///
    /// ICMPv6 mixes in an IPv6 pseudo-header, so it must be checked with
    /// [`Packet::verify_transport_checksum`](crate::Packet::verify_transport_checksum)
    /// instead, where the addresses are available.
    pub fn verify_icmpv4_checksum(&self) -> bool {
        self.0.len() >= 4 && crate::checksum::checksum(&self.0) == 0
    }
}

impl fmt::Debug for IcmpMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IcmpMessage")
            .field("type", &self.message_type())
            .field("code", &self.code())
            .field("len", &self.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// FiveTuple
// ---------------------------------------------------------------------------

/// The 5-tuple that identifies a transport flow.
///
/// Ports are zero for protocols that have none (ICMP, GRE, ESP, …) and for
/// fragments, whose transport header is not present.
///
/// ```
/// # use pktkit::l4::FiveTuple;
/// # use pktkit::Protocol;
/// # use std::net::Ipv4Addr;
/// let t = FiveTuple {
///     src: Ipv4Addr::new(10, 0, 0, 1).into(),
///     dst: Ipv4Addr::new(10, 0, 0, 2).into(),
///     src_port: 1234,
///     dst_port: 80,
///     protocol: Protocol::TCP,
/// };
/// assert_eq!(t.to_string(), "TCP 10.0.0.1:1234 -> 10.0.0.2:80");
/// assert_eq!(t.reversed().src_port, 80);
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl FiveTuple {
    /// The same flow seen from the other end: source and destination swapped.
    ///
    /// Connection-tracking tables key on this to find the reverse direction.
    pub fn reversed(self) -> FiveTuple {
        FiveTuple {
            src: self.dst,
            dst: self.src,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }

    /// A direction-independent form: the endpoint that sorts lower is placed
    /// first. Two tuples describing opposite directions of one connection
    /// normalize to the same value, which makes this a usable table key when
    /// direction should not matter.
    pub fn normalized(self) -> FiveTuple {
        if (self.src, self.src_port) <= (self.dst, self.dst_port) {
            self
        } else {
            self.reversed()
        }
    }

    /// True if both endpoints are IPv4.
    pub fn is_v4(&self) -> bool {
        self.src.is_ipv4() && self.dst.is_ipv4()
    }
}

impl fmt::Debug for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fmt_ep = |f: &mut fmt::Formatter<'_>, ip: IpAddr, port: u16| match ip {
            IpAddr::V6(a) if port != 0 => write!(f, "[{}]:{}", a, port),
            _ if port != 0 => write!(f, "{}:{}", ip, port),
            _ => write!(f, "{}", ip),
        };
        write!(f, "{} ", self.protocol)?;
        fmt_ep(f, self.src, self.src_port)?;
        f.write_str(" -> ")?;
        fmt_ep(f, self.dst, self.dst_port)
    }
}

// ---------------------------------------------------------------------------
// Shared helpers and trait impls
// ---------------------------------------------------------------------------

#[inline]
fn read_u16(b: &[u8], at: usize) -> u16 {
    if b.len() < at + 2 {
        0
    } else {
        u16::from_be_bytes([b[at], b[at + 1]])
    }
}

#[inline]
fn read_u32(b: &[u8], at: usize) -> u32 {
    if b.len() < at + 4 {
        0
    } else {
        u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
    }
}

#[inline]
fn write_u16(b: &mut [u8], at: usize, v: u16) {
    if b.len() >= at + 2 {
        b[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }
}

#[inline]
fn write_u32(b: &mut [u8], at: usize, v: u32) {
    if b.len() >= at + 4 {
        b[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }
}

macro_rules! byte_view_traits {
    ($t:ty) => {
        impl Deref for $t {
            type Target = [u8];
            #[inline]
            fn deref(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $t {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl PartialEq for $t {
            #[inline]
            fn eq(&self, other: &$t) -> bool {
                self.0 == other.0
            }
        }

        impl Eq for $t {}
    };
}

byte_view_traits!(TcpSegment);
byte_view_traits!(UdpDatagram);
byte_view_traits!(IcmpMessage);

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn tcp_syn() -> Vec<u8> {
        let mut b = vec![0u8; 24];
        b[0..2].copy_from_slice(&1234u16.to_be_bytes());
        b[2..4].copy_from_slice(&80u16.to_be_bytes());
        b[4..8].copy_from_slice(&0x1000_0000u32.to_be_bytes());
        b[8..12].copy_from_slice(&0u32.to_be_bytes());
        b[12] = 6 << 4; // data offset 6 words = 24 bytes
        b[13] = (TcpFlags::SYN | TcpFlags::ACK).bits();
        b[14..16].copy_from_slice(&65535u16.to_be_bytes());
        // Options: MSS (kind 2, len 4, 1460).
        b[20] = 2;
        b[21] = 4;
        b[22..24].copy_from_slice(&1460u16.to_be_bytes());
        b
    }

    #[test]
    fn tcp_accessors() {
        let buf = tcp_syn();
        let s = TcpSegment::from_slice(&buf);
        assert!(s.is_valid());
        assert_eq!(s.src_port(), 1234);
        assert_eq!(s.dst_port(), 80);
        assert_eq!(s.seq(), 0x1000_0000);
        assert_eq!(s.header_len(), 24);
        assert!(s.flags().contains(TcpFlags::SYN));
        assert!(s.flags().contains(TcpFlags::ACK));
        assert!(!s.flags().contains(TcpFlags::FIN));
        assert_eq!(s.window(), 65535);
        assert_eq!(s.options(), &[2, 4, 0x05, 0xB4]);
        assert_eq!(s.payload(), &[] as &[u8]);
    }

    #[test]
    fn tcp_option_iteration() {
        let mut buf = tcp_syn();
        // Extend to 32 bytes of header: MSS, NOP, window scale, EOL.
        buf.resize(32, 0);
        buf[12] = 8 << 4;
        buf[24] = 1; // NOP
        buf[25] = 3; // window scale
        buf[26] = 3;
        buf[27] = 7;
        buf[28] = 0; // EOL
        let s = TcpSegment::from_slice(&buf);
        let opts: Vec<_> = s.option_iter().collect();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].0, 2);
        assert_eq!(opts[0].1, &[0x05, 0xB4]);
        assert_eq!(opts[1].0, 3);
        assert_eq!(opts[1].1, &[7]);
    }

    #[test]
    fn tcp_malformed_option_length_terminates() {
        let mut buf = tcp_syn();
        buf[21] = 1; // length below the 2-byte minimum
        let s = TcpSegment::from_slice(&buf);
        assert_eq!(s.option_iter().count(), 0);
    }

    #[test]
    fn tcp_short_buffer_is_inert() {
        let buf = [0u8; 4];
        let s = TcpSegment::from_slice(&buf);
        assert!(!s.is_valid());
        assert_eq!(s.src_port(), 0);
        assert_eq!(s.seq(), 0);
        assert_eq!(s.flags(), TcpFlags(0));
        assert_eq!(s.payload(), &[] as &[u8]);
        assert_eq!(s.option_iter().count(), 0);
    }

    #[test]
    fn tcp_zero_data_offset_clamps() {
        let mut buf = tcp_syn();
        buf[12] = 0; // data offset 0 — would imply a header shorter than 20
        let s = TcpSegment::from_slice(&buf);
        assert_eq!(s.header_len(), 20);
        assert_eq!(s.payload().len(), 4);
    }

    #[test]
    fn tcp_setters() {
        let mut buf = tcp_syn();
        let s = TcpSegment::from_mut(&mut buf);
        s.set_src_port(9999);
        s.set_dst_port(443);
        s.set_seq(42);
        s.set_ack(43);
        s.set_flags(TcpFlags::RST);
        s.set_window(1024);
        assert_eq!(s.src_port(), 9999);
        assert_eq!(s.dst_port(), 443);
        assert_eq!(s.seq(), 42);
        assert_eq!(s.ack(), 43);
        assert_eq!(s.flags(), TcpFlags::RST);
        assert_eq!(s.window(), 1024);
    }

    #[test]
    fn udp_accessors() {
        let mut buf = vec![0u8; 12];
        buf[0..2].copy_from_slice(&53u16.to_be_bytes());
        buf[2..4].copy_from_slice(&1234u16.to_be_bytes());
        buf[4..6].copy_from_slice(&12u16.to_be_bytes());
        buf[8..12].copy_from_slice(&[1, 2, 3, 4]);
        let d = UdpDatagram::from_slice(&buf);
        assert!(d.is_valid());
        assert_eq!(d.src_port(), 53);
        assert_eq!(d.dst_port(), 1234);
        assert_eq!(d.length(), 12);
        assert_eq!(d.payload(), &[1, 2, 3, 4]);
    }

    #[test]
    fn udp_payload_respects_declared_length() {
        // Buffer carries 4 bytes of Ethernet padding past the declared length.
        let mut buf = vec![0u8; 16];
        buf[4..6].copy_from_slice(&12u16.to_be_bytes());
        buf[8..12].copy_from_slice(&[9, 9, 9, 9]);
        let d = UdpDatagram::from_slice(&buf);
        assert_eq!(d.payload(), &[9, 9, 9, 9], "padding must not leak in");
    }

    #[test]
    fn udp_bogus_length_falls_back_to_buffer() {
        let mut buf = vec![0u8; 12];
        buf[4..6].copy_from_slice(&60000u16.to_be_bytes());
        let d = UdpDatagram::from_slice(&buf);
        assert_eq!(d.payload().len(), 4);
    }

    #[test]
    fn icmp_accessors() {
        let mut buf = vec![0u8; 12];
        buf[0] = icmpv4::ECHO_REQUEST;
        buf[4..6].copy_from_slice(&7u16.to_be_bytes());
        buf[6..8].copy_from_slice(&9u16.to_be_bytes());
        let m = IcmpMessage::from_slice(&buf);
        assert!(m.is_valid());
        assert_eq!(m.message_type(), 8);
        assert_eq!(m.echo_id(), 7);
        assert_eq!(m.echo_seq(), 9);
        assert_eq!(m.payload().len(), 4);
        assert!(!m.is_icmpv4_error());

        buf[0] = icmpv4::DEST_UNREACHABLE;
        buf[1] = icmpv4::CODE_FRAG_NEEDED;
        buf[6..8].copy_from_slice(&1400u16.to_be_bytes());
        let m = IcmpMessage::from_slice(&buf);
        assert!(m.is_icmpv4_error());
        assert_eq!(m.mtu(), 1400);
    }

    #[test]
    fn five_tuple_reverse_and_normalize() {
        let a = FiveTuple {
            src: Ipv4Addr::new(10, 0, 0, 1).into(),
            dst: Ipv4Addr::new(10, 0, 0, 2).into(),
            src_port: 1234,
            dst_port: 80,
            protocol: Protocol::TCP,
        };
        let b = a.reversed();
        assert_eq!(b.src, a.dst);
        assert_eq!(b.src_port, a.dst_port);
        assert_eq!(a.reversed().reversed(), a);
        assert_eq!(
            a.normalized(),
            b.normalized(),
            "both directions must key the same"
        );
        assert!(a.is_v4());
    }

    #[test]
    fn tcp_flags_display() {
        assert_eq!(TcpFlags(0).to_string(), "none");
        assert_eq!((TcpFlags::SYN | TcpFlags::ACK).to_string(), "SYN|ACK");
        assert_eq!(TcpFlags::FIN.to_string(), "FIN");
        assert!(TcpFlags::SYN.intersects(TcpFlags::SYN | TcpFlags::FIN));
    }
}
