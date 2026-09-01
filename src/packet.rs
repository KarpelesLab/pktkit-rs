use crate::checksum::{checksum, raw_transport_sum, transport_checksum};
use crate::l4::{FiveTuple, IcmpMessage, TcpSegment, UdpDatagram};
use crate::Protocol;
use core::fmt;
use core::ops::Deref;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IPv6 extension header numbers this crate knows how to skip.
///
/// These share the number space with [`Protocol`], which is why an IPv6 "next
/// header" field cannot be treated as a transport protocol without walking the
/// chain first. See [`Packet::transport_protocol`].
mod ext {
    pub const HOPOPT: u8 = 0;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const ESP: u8 = 50;
    pub const AH: u8 = 51;
    pub const NO_NEXT: u8 = 59;
    pub const DEST_OPTS: u8 = 60;
    pub const MOBILITY: u8 = 135;
    pub const HIP: u8 = 139;
    pub const SHIM6: u8 = 140;
}

/// Walk the IPv6 extension header chain.
///
/// Starting from `next_header` at byte `offset`, follow the chain until a
/// header that is not an extension header is reached. Returns that protocol
/// number and the offset at which it begins.
///
/// A truncated or nonsensical chain terminates the walk rather than panicking:
/// the last decodable `(protocol, offset)` pair is returned. The walk is also
/// bounded to [`MAX_EXT_HEADERS`] links so a crafted packet whose chain loops
/// back on itself cannot spin here.
///
/// The chain stops at a Fragment header whose offset is non-zero (a non-first
/// fragment carries no transport header) and at ESP (the rest is encrypted).
pub(crate) fn skip_ipv6_ext(buf: &[u8], mut next_header: u8, mut offset: usize) -> (u8, usize) {
    for _ in 0..MAX_EXT_HEADERS {
        match next_header {
            // Type-Length-Option headers: length is in 8-octet units, not
            // counting the first 8 octets.
            ext::HOPOPT | ext::ROUTING | ext::DEST_OPTS | ext::MOBILITY | ext::HIP | ext::SHIM6 => {
                if offset + 2 > buf.len() {
                    return (next_header, offset);
                }
                let nh = buf[offset];
                let hdr_len = (buf[offset + 1] as usize + 1) * 8;
                next_header = nh;
                offset += hdr_len;
            }
            // Fragment header is a fixed 8 bytes. Only the first fragment
            // (offset 0) is followed through to the transport header; later
            // fragments have none, so the walk stops and reports Fragment.
            ext::FRAGMENT => {
                if offset + 8 > buf.len() {
                    return (next_header, offset);
                }
                let frag_off = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) & 0xFFF8;
                if frag_off != 0 {
                    return (ext::FRAGMENT, offset);
                }
                next_header = buf[offset];
                offset += 8;
            }
            // Authentication Header: length is in 4-octet units, minus 2.
            ext::AH => {
                if offset + 2 > buf.len() {
                    return (next_header, offset);
                }
                let nh = buf[offset];
                let hdr_len = (buf[offset + 1] as usize + 2) * 4;
                next_header = nh;
                offset += hdr_len;
            }
            // ESP hides everything past this point; NO_NEXT means there is
            // nothing past it at all. Both terminate the walk, as does any
            // number that is not an extension header — a transport protocol.
            ext::ESP | ext::NO_NEXT => return (next_header, offset),
            _ => return (next_header, offset),
        }
        if offset > buf.len() {
            // The chain claimed to extend past the buffer. Report the header
            // we were about to enter, clamped to the buffer end.
            return (next_header, buf.len());
        }
    }
    (next_header, offset.min(buf.len()))
}

/// Upper bound on how many IPv6 extension headers [`Packet`] will walk before
/// giving up. Real traffic uses at most a handful; the cap exists so a crafted
/// chain cannot make the walk unbounded.
pub const MAX_EXT_HEADERS: usize = 16;

/// A raw IP packet (no Ethernet header).
///
/// `Packet` is a `#[repr(transparent)]` newtype around `[u8]`. Accessors are
/// version-aware: pick the IP version from the first nibble, then read header
/// fields without copying.
///
/// Accessors come in three families:
///
/// - `ipv4_*` / `ipv6_*` read one version's header fields literally, and
///   return a zero value if the packet is the wrong version or too short.
/// - Version-independent accessors ([`src_addr`](Self::src_addr),
///   [`hop_limit`](Self::hop_limit), [`transport_protocol`](Self::transport_protocol),
///   …) dispatch on the version for you.
/// - [`tcp`](Self::tcp), [`udp`](Self::udp) and [`icmp`](Self::icmp) hand back
///   a typed L4 view of the payload.
///
/// ```
/// # use pktkit::Packet;
/// // Minimal IPv4 header with src=10.0.0.1, dst=10.0.0.2, proto=UDP.
/// let buf = vec![
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

    /// Copy the packet into an owned buffer.
    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
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

    /// IPv4 DSCP — the upper six bits of the TOS byte (RFC 2474).
    pub fn ipv4_dscp(&self) -> u8 {
        if self.0.len() < 2 {
            0
        } else {
            self.0[1] >> 2
        }
    }

    /// IPv4 ECN — the low two bits of the TOS byte (RFC 3168).
    pub fn ipv4_ecn(&self) -> u8 {
        if self.0.len() < 2 {
            0
        } else {
            self.0[1] & 0x03
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

    /// IPv4 Identification field, used to group fragments of one datagram.
    pub fn ipv4_id(&self) -> u16 {
        if self.0.len() < 6 {
            0
        } else {
            u16::from_be_bytes([self.0[4], self.0[5]])
        }
    }

    /// IPv4 flags — the top three bits of byte 6 (reserved, DF, MF).
    pub fn ipv4_flags(&self) -> u8 {
        if self.0.len() < 7 {
            0
        } else {
            self.0[6] >> 5
        }
    }

    /// True if the Don't Fragment bit is set.
    pub fn ipv4_dont_fragment(&self) -> bool {
        self.0.len() >= 7 && self.0[6] & 0x40 != 0
    }

    /// True if the More Fragments bit is set.
    pub fn ipv4_more_fragments(&self) -> bool {
        self.0.len() >= 7 && self.0[6] & 0x20 != 0
    }

    /// Offset of this fragment's payload within the reassembled datagram, **in
    /// bytes**. The wire field counts 8-octet units; this accessor multiplies
    /// it out so it can be used as a buffer index directly.
    pub fn ipv4_fragment_offset(&self) -> usize {
        if self.0.len() < 8 {
            0
        } else {
            (u16::from_be_bytes([self.0[6], self.0[7]]) & 0x1FFF) as usize * 8
        }
    }

    /// True if this packet is one fragment of a larger datagram — either it
    /// has more fragments following, or it starts partway in.
    pub fn ipv4_is_fragment(&self) -> bool {
        self.ipv4_more_fragments() || self.ipv4_fragment_offset() != 0
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

    /// IPv4 header checksum as it appears on the wire.
    pub fn ipv4_checksum(&self) -> u16 {
        if self.0.len() < 12 {
            0
        } else {
            u16::from_be_bytes([self.0[10], self.0[11]])
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

    /// IPv4 header options: the bytes between the fixed 20-byte header and the
    /// end of the header as declared by IHL. Empty when IHL is 5.
    pub fn ipv4_options(&self) -> &[u8] {
        let hl = self.ipv4_header_len();
        if self.version() != 4 || hl <= 20 || self.0.len() < hl {
            return &[];
        }
        &self.0[20..hl]
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

    pub fn set_ipv4_dscp(&mut self, dscp: u8) {
        if self.0.len() < 2 {
            return;
        }
        self.0[1] = (dscp << 2) | (self.0[1] & 0x03);
    }

    pub fn set_ipv4_ecn(&mut self, ecn: u8) {
        if self.0.len() < 2 {
            return;
        }
        self.0[1] = (self.0[1] & 0xFC) | (ecn & 0x03);
    }

    pub fn set_ipv4_total_len(&mut self, len: u16) {
        if self.0.len() < 4 {
            return;
        }
        self.0[2..4].copy_from_slice(&len.to_be_bytes());
    }

    pub fn set_ipv4_id(&mut self, id: u16) {
        if self.0.len() < 6 {
            return;
        }
        self.0[4..6].copy_from_slice(&id.to_be_bytes());
    }

    pub fn set_ipv4_dont_fragment(&mut self, on: bool) {
        if self.0.len() < 7 {
            return;
        }
        if on {
            self.0[6] |= 0x40;
        } else {
            self.0[6] &= !0x40;
        }
    }

    pub fn set_ipv4_more_fragments(&mut self, on: bool) {
        if self.0.len() < 7 {
            return;
        }
        if on {
            self.0[6] |= 0x20;
        } else {
            self.0[6] &= !0x20;
        }
    }

    /// Set the fragment offset, given **in bytes**; it is rounded down to the
    /// 8-octet granularity the wire format uses.
    pub fn set_ipv4_fragment_offset(&mut self, bytes: usize) {
        if self.0.len() < 8 {
            return;
        }
        let units = ((bytes / 8) as u16) & 0x1FFF;
        let flags = u16::from_be_bytes([self.0[6], self.0[7]]) & 0xE000;
        self.0[6..8].copy_from_slice(&(flags | units).to_be_bytes());
    }

    pub fn set_ipv4_ttl(&mut self, ttl: u8) {
        if self.0.len() < 9 {
            return;
        }
        self.0[8] = ttl;
    }

    pub fn set_ipv4_protocol(&mut self, proto: Protocol) {
        if self.0.len() < 10 {
            return;
        }
        self.0[9] = proto.as_u8();
    }

    pub fn set_ipv4_checksum(&mut self, sum: u16) {
        if self.0.len() < 12 {
            return;
        }
        self.0[10..12].copy_from_slice(&sum.to_be_bytes());
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

    /// IPv6 Traffic Class — the 8 bits spanning the first two header bytes.
    pub fn ipv6_traffic_class(&self) -> u8 {
        if self.0.len() < 2 {
            0
        } else {
            ((self.0[0] & 0x0F) << 4) | (self.0[1] >> 4)
        }
    }

    /// IPv6 DSCP — the upper six bits of the traffic class.
    pub fn ipv6_dscp(&self) -> u8 {
        self.ipv6_traffic_class() >> 2
    }

    /// IPv6 ECN — the low two bits of the traffic class.
    pub fn ipv6_ecn(&self) -> u8 {
        self.ipv6_traffic_class() & 0x03
    }

    /// IPv6 Flow Label (20 bits).
    pub fn ipv6_flow_label(&self) -> u32 {
        if self.0.len() < 4 {
            0
        } else {
            ((self.0[1] as u32 & 0x0F) << 16) | ((self.0[2] as u32) << 8) | self.0[3] as u32
        }
    }

    pub fn ipv6_payload_len(&self) -> u16 {
        if self.0.len() < 6 {
            0
        } else {
            u16::from_be_bytes([self.0[4], self.0[5]])
        }
    }

    /// IPv6 Next Header field, exactly as it appears in the fixed header.
    ///
    /// This is *not* necessarily a transport protocol: it may name an
    /// extension header (hop-by-hop, routing, fragment, …). Use
    /// [`transport_protocol`](Self::transport_protocol) to walk the chain to
    /// the real upper-layer protocol.
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

    /// Everything after the fixed 40-byte IPv6 header — extension headers
    /// included.
    ///
    /// This is the literal wire payload. For the bytes of the upper-layer
    /// protocol with the extension chain already skipped, use
    /// [`transport_payload`](Self::transport_payload) or the version-independent
    /// [`payload`](Self::payload).
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

    /// Walk the extension header chain and return the upper-layer protocol
    /// together with the offset at which it begins.
    ///
    /// For a non-first fragment the walk stops at the Fragment header and
    /// reports `Protocol(44)` — there is no transport header to point at.
    pub fn ipv6_transport(&self) -> (Protocol, usize) {
        if self.version() != 6 || self.0.len() < 40 {
            return (Protocol(0), 0);
        }
        let (proto, off) = skip_ipv6_ext(&self.0, self.0[6], 40);
        (Protocol(proto), off)
    }

    /// True if this IPv6 packet carries a Fragment extension header.
    pub fn ipv6_is_fragment(&self) -> bool {
        if self.version() != 6 || self.0.len() < 40 {
            return false;
        }
        // Walk manually: the chain walker stops early on a non-first fragment,
        // so we look for the header rather than relying on the terminal value.
        let mut nh = self.0[6];
        let mut off = 40usize;
        for _ in 0..MAX_EXT_HEADERS {
            match nh {
                ext::FRAGMENT => return true,
                ext::HOPOPT
                | ext::ROUTING
                | ext::DEST_OPTS
                | ext::MOBILITY
                | ext::HIP
                | ext::SHIM6 => {
                    if off + 2 > self.0.len() {
                        return false;
                    }
                    nh = self.0[off];
                    off += (self.0[off + 1] as usize + 1) * 8;
                }
                ext::AH => {
                    if off + 2 > self.0.len() {
                        return false;
                    }
                    nh = self.0[off];
                    off += (self.0[off + 1] as usize + 2) * 4;
                }
                _ => return false,
            }
            if off > self.0.len() {
                return false;
            }
        }
        false
    }

    pub fn set_ipv6_traffic_class(&mut self, tc: u8) {
        if self.0.len() < 2 {
            return;
        }
        self.0[0] = (self.0[0] & 0xF0) | (tc >> 4);
        self.0[1] = ((tc & 0x0F) << 4) | (self.0[1] & 0x0F);
    }

    pub fn set_ipv6_flow_label(&mut self, label: u32) {
        if self.0.len() < 4 {
            return;
        }
        self.0[1] = (self.0[1] & 0xF0) | ((label >> 16) as u8 & 0x0F);
        self.0[2] = (label >> 8) as u8;
        self.0[3] = label as u8;
    }

    pub fn set_ipv6_payload_len(&mut self, len: u16) {
        if self.0.len() < 6 {
            return;
        }
        self.0[4..6].copy_from_slice(&len.to_be_bytes());
    }

    pub fn set_ipv6_next_header(&mut self, proto: Protocol) {
        if self.0.len() < 7 {
            return;
        }
        self.0[6] = proto.as_u8();
    }

    pub fn set_ipv6_hop_limit(&mut self, hop_limit: u8) {
        if self.0.len() < 8 {
            return;
        }
        self.0[7] = hop_limit;
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

    /// Write the source address, dispatching on version. A mismatched family
    /// (writing a v6 address into a v4 packet) is ignored.
    pub fn set_src_addr(&mut self, addr: IpAddr) {
        match (self.version(), addr) {
            (4, IpAddr::V4(a)) => self.set_ipv4_src_addr(a),
            (6, IpAddr::V6(a)) => self.set_ipv6_src_addr(a),
            _ => {}
        }
    }

    /// Write the destination address, dispatching on version.
    pub fn set_dst_addr(&mut self, addr: IpAddr) {
        match (self.version(), addr) {
            (4, IpAddr::V4(a)) => self.set_ipv4_dst_addr(a),
            (6, IpAddr::V6(a)) => self.set_ipv6_dst_addr(a),
            _ => {}
        }
    }

    /// Length of the IP header, extension headers included. This is the offset
    /// at which the upper-layer protocol begins — see
    /// [`transport_offset`](Self::transport_offset), which it is an alias for.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.transport_offset()
    }

    /// Total length of the packet as declared by its header, which may be less
    /// than [`len`](Self::len) if the buffer has trailing padding.
    pub fn total_len(&self) -> usize {
        match self.version() {
            4 => self.ipv4_total_len() as usize,
            6 => 40 + self.ipv6_payload_len() as usize,
            _ => 0,
        }
    }

    /// The upper-layer protocol number.
    ///
    /// For IPv4 this is the Protocol field. For IPv6 the extension header
    /// chain is walked first, so hop-by-hop options and routing headers do not
    /// masquerade as transport protocols.
    pub fn transport_protocol(&self) -> Protocol {
        match self.version() {
            4 => self.ipv4_protocol(),
            6 => self.ipv6_transport().0,
            _ => Protocol(0),
        }
    }

    /// Alias for [`transport_protocol`](Self::transport_protocol).
    #[inline]
    pub fn ip_protocol(&self) -> Protocol {
        self.transport_protocol()
    }

    /// Offset at which the upper-layer protocol header begins.
    pub fn transport_offset(&self) -> usize {
        match self.version() {
            4 => self.ipv4_header_len().min(self.0.len()),
            6 => self.ipv6_transport().1,
            _ => 0,
        }
    }

    /// Upper-layer payload: the bytes of the transport header and everything
    /// after it, with IPv6 extension headers already skipped.
    pub fn transport_payload(&self) -> &[u8] {
        match self.version() {
            4 => self.ipv4_payload(),
            6 => {
                let (_, off) = self.ipv6_transport();
                let end = (40 + self.ipv6_payload_len() as usize).min(self.0.len());
                if off >= end {
                    return &[];
                }
                &self.0[off..end]
            }
            _ => &[],
        }
    }

    /// Mutable view of [`transport_payload`](Self::transport_payload).
    pub fn transport_payload_mut(&mut self) -> &mut [u8] {
        match self.version() {
            4 => {
                let hl = self.ipv4_header_len();
                let tl = self.ipv4_total_len() as usize;
                if hl == 0 || tl < hl || self.0.len() < tl {
                    return &mut [];
                }
                &mut self.0[hl..tl]
            }
            6 => {
                let (_, off) = self.ipv6_transport();
                let end = (40 + self.ipv6_payload_len() as usize).min(self.0.len());
                if off >= end {
                    return &mut [];
                }
                &mut self.0[off..end]
            }
            _ => &mut [],
        }
    }

    /// Alias for [`transport_payload`](Self::transport_payload).
    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.transport_payload()
    }

    /// True if this packet is a fragment of a larger datagram, in either
    /// address family.
    pub fn is_fragment(&self) -> bool {
        match self.version() {
            4 => self.ipv4_is_fragment(),
            6 => self.ipv6_is_fragment(),
            _ => false,
        }
    }

    /// TTL (v4) or Hop Limit (v6) — the same field under two names.
    pub fn hop_limit(&self) -> u8 {
        match self.version() {
            4 => self.ipv4_ttl(),
            6 => self.ipv6_hop_limit(),
            _ => 0,
        }
    }

    /// Set the TTL / Hop Limit. For IPv4 the header checksum is updated
    /// incrementally so the packet stays well-formed.
    pub fn set_hop_limit(&mut self, value: u8) {
        match self.version() {
            4 => {
                let old = self.ipv4_ttl();
                if old == value {
                    return;
                }
                self.set_ipv4_ttl(value);
                // The TTL is the high byte of the 16-bit word at offset 8.
                let sum = crate::checksum::incremental_update(
                    self.ipv4_checksum(),
                    &[old, self.0[9]],
                    &[value, self.0[9]],
                );
                self.set_ipv4_checksum(sum);
            }
            6 => self.set_ipv6_hop_limit(value),
            _ => {}
        }
    }

    /// Decrement the TTL / Hop Limit for forwarding, updating the IPv4 header
    /// checksum incrementally.
    ///
    /// Returns `true` if the packet may still be forwarded. Returns `false`
    /// when the field was already 0 or 1 — the packet has expired and the
    /// caller should generate an ICMP Time Exceeded (see
    /// [`crate::icmp::time_exceeded`]) rather than forward it. The field is
    /// left untouched in that case.
    pub fn decrement_hop_limit(&mut self) -> bool {
        let cur = self.hop_limit();
        if cur <= 1 {
            return false;
        }
        self.set_hop_limit(cur - 1);
        true
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

    // --- Checksums ---------------------------------------------------------

    /// Verify the IPv4 header checksum. Always true for IPv6, which has no
    /// header checksum.
    pub fn verify_ipv4_checksum(&self) -> bool {
        match self.version() {
            4 => {
                let hl = self.ipv4_header_len();
                if hl < 20 || self.0.len() < hl {
                    return false;
                }
                // A correct header sums to zero with the checksum field in place.
                checksum(&self.0[..hl]) == 0
            }
            6 => true,
            _ => false,
        }
    }

    /// Recompute and store the IPv4 header checksum. No-op for IPv6.
    pub fn recompute_ipv4_checksum(&mut self) {
        if self.version() != 4 {
            return;
        }
        let hl = self.ipv4_header_len();
        if hl < 20 || self.0.len() < hl {
            return;
        }
        self.set_ipv4_checksum(0);
        let sum = checksum(&self.0[..hl]);
        self.set_ipv4_checksum(sum);
    }

    /// Verify the transport checksum (TCP, UDP, or ICMPv6).
    ///
    /// Returns `None` when there is nothing to check: an unsupported protocol,
    /// a fragment (the transport header is incomplete), a truncated packet, or
    /// an IPv4 UDP datagram carrying checksum 0, which RFC 768 defines as
    /// "not computed".
    pub fn verify_transport_checksum(&self) -> Option<bool> {
        let proto = self.transport_protocol();
        let (src, dst) = (self.src_addr()?, self.dst_addr()?);
        if self.is_fragment() {
            return None;
        }
        let payload = self.transport_payload();
        match proto {
            Protocol::TCP if payload.len() >= 20 => {}
            Protocol::UDP if payload.len() >= 8 => {
                if payload[6..8] == [0, 0] && self.version() == 4 {
                    return None;
                }
            }
            Protocol::ICMPV6 if payload.len() >= 4 => {}
            // ICMPv4's checksum covers no pseudo-header, so it is handled by
            // IcmpMessage::verify_checksum instead.
            Protocol::ICMP if payload.len() >= 4 => return Some(checksum(payload) == 0),
            _ => return None,
        }
        Some(raw_transport_sum(proto, src, dst, payload) == 0xFFFF)
    }

    /// Recompute the transport checksum (TCP, UDP, ICMPv4 or ICMPv6) in place.
    ///
    /// Returns `true` if a checksum was written. Call this after rewriting
    /// addresses or ports when an incremental update is not convenient.
    pub fn recompute_transport_checksum(&mut self) -> bool {
        let proto = self.transport_protocol();
        let (src, dst) = match (self.src_addr(), self.dst_addr()) {
            (Some(s), Some(d)) => (s, d),
            _ => return false,
        };
        if self.is_fragment() {
            return false;
        }
        // Offset of the checksum field within the transport header.
        let field = match proto {
            Protocol::TCP => 16,
            Protocol::UDP => 6,
            Protocol::ICMP | Protocol::ICMPV6 => 2,
            _ => return false,
        };
        let payload = self.transport_payload_mut();
        if payload.len() < field + 2 {
            return false;
        }
        payload[field] = 0;
        payload[field + 1] = 0;
        let sum = if proto == Protocol::ICMP {
            // ICMPv4 has no pseudo-header.
            checksum(payload)
        } else {
            transport_checksum(proto, src, dst, payload)
        };
        let payload = self.transport_payload_mut();
        payload[field..field + 2].copy_from_slice(&sum.to_be_bytes());
        true
    }

    /// Recompute every checksum the packet owns: the IPv4 header checksum and
    /// the transport checksum.
    pub fn recompute_checksums(&mut self) {
        self.recompute_ipv4_checksum();
        self.recompute_transport_checksum();
    }

    // --- Typed L4 views ----------------------------------------------------

    /// A typed view of the TCP segment this packet carries, or `None` if it is
    /// not TCP, is a fragment, or is too short for a TCP header.
    pub fn tcp(&self) -> Option<&TcpSegment> {
        if self.transport_protocol() != Protocol::TCP || self.is_fragment() {
            return None;
        }
        let seg = TcpSegment::from_slice(self.transport_payload());
        seg.is_valid().then_some(seg)
    }

    /// Mutable counterpart of [`tcp`](Self::tcp).
    pub fn tcp_mut(&mut self) -> Option<&mut TcpSegment> {
        if self.transport_protocol() != Protocol::TCP || self.is_fragment() {
            return None;
        }
        let seg = TcpSegment::from_mut(self.transport_payload_mut());
        seg.is_valid().then_some(seg)
    }

    /// A typed view of the UDP datagram this packet carries.
    pub fn udp(&self) -> Option<&UdpDatagram> {
        if self.transport_protocol() != Protocol::UDP || self.is_fragment() {
            return None;
        }
        let dg = UdpDatagram::from_slice(self.transport_payload());
        dg.is_valid().then_some(dg)
    }

    /// Mutable counterpart of [`udp`](Self::udp).
    pub fn udp_mut(&mut self) -> Option<&mut UdpDatagram> {
        if self.transport_protocol() != Protocol::UDP || self.is_fragment() {
            return None;
        }
        let dg = UdpDatagram::from_mut(self.transport_payload_mut());
        dg.is_valid().then_some(dg)
    }

    /// A typed view of the ICMP (v4) or ICMPv6 message this packet carries.
    pub fn icmp(&self) -> Option<&IcmpMessage> {
        let proto = self.transport_protocol();
        if (proto != Protocol::ICMP && proto != Protocol::ICMPV6) || self.is_fragment() {
            return None;
        }
        let msg = IcmpMessage::from_slice(self.transport_payload());
        msg.is_valid().then_some(msg)
    }

    /// Mutable counterpart of [`icmp`](Self::icmp).
    pub fn icmp_mut(&mut self) -> Option<&mut IcmpMessage> {
        let proto = self.transport_protocol();
        if (proto != Protocol::ICMP && proto != Protocol::ICMPV6) || self.is_fragment() {
            return None;
        }
        let msg = IcmpMessage::from_mut(self.transport_payload_mut());
        msg.is_valid().then_some(msg)
    }

    /// The connection 5-tuple this packet belongs to.
    ///
    /// Ports are zero for protocols that have none. Returns `None` if the
    /// addresses cannot be read.
    pub fn five_tuple(&self) -> Option<FiveTuple> {
        let src = self.src_addr()?;
        let dst = self.dst_addr()?;
        let proto = self.transport_protocol();
        let (src_port, dst_port) = if self.is_fragment() {
            (0, 0)
        } else {
            let p = self.transport_payload();
            match proto {
                Protocol::TCP | Protocol::UDP if p.len() >= 4 => (
                    u16::from_be_bytes([p[0], p[1]]),
                    u16::from_be_bytes([p[2], p[3]]),
                ),
                _ => (0, 0),
            }
        };
        Some(FiveTuple {
            src,
            dst,
            src_port,
            dst_port,
            protocol: proto,
        })
    }
}

impl Deref for Packet {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Packet {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for Packet {
    #[inline]
    fn eq(&self, other: &Packet) -> bool {
        self.0 == other.0
    }
}

impl Eq for Packet {}

impl core::hash::Hash for Packet {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("len", &self.len())
            .field("version", &self.version())
            .field("src", &self.src_addr())
            .field("dst", &self.dst_addr())
            .field("proto", &self.transport_protocol())
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
        assert_eq!(p.transport_offset(), 0);
        assert_eq!(p.total_len(), 0);
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

    #[test]
    fn ipv4_header_fields_roundtrip() {
        let mut buf = v4_min();
        let p = Packet::from_mut(&mut buf);

        p.set_ipv4_dscp(46); // EF
        p.set_ipv4_ecn(3);
        assert_eq!(p.ipv4_dscp(), 46);
        assert_eq!(p.ipv4_ecn(), 3);

        p.set_ipv4_id(0xbeef);
        assert_eq!(p.ipv4_id(), 0xbeef);

        p.set_ipv4_dont_fragment(true);
        assert!(p.ipv4_dont_fragment());
        assert!(!p.ipv4_more_fragments());
        p.set_ipv4_more_fragments(true);
        assert!(p.ipv4_more_fragments());
        assert!(p.ipv4_dont_fragment());
        p.set_ipv4_dont_fragment(false);
        assert!(!p.ipv4_dont_fragment());
        assert!(p.ipv4_more_fragments());

        p.set_ipv4_fragment_offset(1480);
        assert_eq!(p.ipv4_fragment_offset(), 1480);
        // Flags survived the offset write.
        assert!(p.ipv4_more_fragments());
        assert!(p.ipv4_is_fragment());

        p.set_ipv4_protocol(Protocol::UDP);
        assert_eq!(p.ipv4_protocol(), Protocol::UDP);
        p.set_ipv4_total_len(1500);
        assert_eq!(p.ipv4_total_len(), 1500);
    }

    #[test]
    fn ipv6_header_fields_roundtrip() {
        let mut buf = v6_min();
        let p = Packet::from_mut(&mut buf);

        p.set_ipv6_traffic_class(0xA5);
        assert_eq!(p.ipv6_traffic_class(), 0xA5);
        assert_eq!(p.ipv6_dscp(), 0xA5 >> 2);
        assert_eq!(p.ipv6_ecn(), 0xA5 & 3);
        // The version nibble must survive a traffic-class write.
        assert_eq!(p.version(), 6);

        p.set_ipv6_flow_label(0xABCDE);
        assert_eq!(p.ipv6_flow_label(), 0xABCDE);
        assert_eq!(p.ipv6_traffic_class(), 0xA5);
        assert_eq!(p.version(), 6);

        p.set_ipv6_hop_limit(32);
        assert_eq!(p.ipv6_hop_limit(), 32);
        p.set_ipv6_next_header(Protocol::TCP);
        assert_eq!(p.ipv6_next_header(), Protocol::TCP);
        p.set_ipv6_payload_len(120);
        assert_eq!(p.ipv6_payload_len(), 120);
    }

    #[test]
    fn ipv4_checksum_verify_and_recompute() {
        let mut buf = v4_min();
        let p = Packet::from_mut(&mut buf);
        assert!(
            !p.verify_ipv4_checksum(),
            "zeroed checksum should not verify"
        );
        p.recompute_ipv4_checksum();
        assert!(p.verify_ipv4_checksum());
        assert_ne!(p.ipv4_checksum(), 0);

        // Mutating an address invalidates it; recomputing restores it.
        p.set_ipv4_dst_addr(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!p.verify_ipv4_checksum());
        p.recompute_ipv4_checksum();
        assert!(p.verify_ipv4_checksum());
    }

    #[test]
    fn hop_limit_decrement_keeps_checksum_valid() {
        let mut buf = v4_min();
        let p = Packet::from_mut(&mut buf);
        p.recompute_ipv4_checksum();

        assert!(p.decrement_hop_limit());
        assert_eq!(p.hop_limit(), 63);
        assert!(
            p.verify_ipv4_checksum(),
            "incremental update must keep the header checksum correct"
        );

        // Walk it down to expiry.
        p.set_hop_limit(1);
        assert!(p.verify_ipv4_checksum());
        assert!(!p.decrement_hop_limit());
        assert_eq!(p.hop_limit(), 1, "an expired packet is left untouched");
    }

    #[test]
    fn hop_limit_v6() {
        let mut buf = v6_min();
        let p = Packet::from_mut(&mut buf);
        assert_eq!(p.hop_limit(), 64);
        assert!(p.decrement_hop_limit());
        assert_eq!(p.ipv6_hop_limit(), 63);
        p.set_hop_limit(0);
        assert!(!p.decrement_hop_limit());
    }

    // --- IPv6 extension headers -------------------------------------------

    /// Build an IPv6 packet whose next-header chain is `chain`, each entry
    /// being (header type, body bytes to place after the 2-byte prologue).
    fn v6_with_ext(chain: &[(u8, Vec<u8>)], final_proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        for (i, (_, body)) in chain.iter().enumerate() {
            // Each extension header starts with (next header, len) then body.
            let next = if i + 1 < chain.len() {
                chain[i + 1].0
            } else {
                final_proto
            };
            ext.push(next);
            // Hdr Ext Len counts 8-octet units past the first 8.
            let total = 2 + body.len();
            ext.push(((total / 8) - 1) as u8);
            ext.extend_from_slice(body);
        }
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = if chain.is_empty() {
            final_proto
        } else {
            chain[0].0
        };
        p[7] = 64;
        p.extend_from_slice(&ext);
        p.extend_from_slice(payload);
        let plen = (ext.len() + payload.len()) as u16;
        p[4..6].copy_from_slice(&plen.to_be_bytes());
        p
    }

    #[test]
    fn ipv6_hop_by_hop_is_skipped() {
        // Hop-by-hop (0) then UDP. Body is 6 bytes so the header is 8 total.
        let buf = v6_with_ext(&[(0, vec![0u8; 6])], 17, &[0xde, 0xad, 0xbe, 0xef]);
        let p = Packet::from_slice(&buf);

        // The raw field still reports the extension header...
        assert_eq!(p.ipv6_next_header(), Protocol(0));
        // ...but the transport accessors see through it.
        assert_eq!(p.transport_protocol(), Protocol::UDP);
        assert_eq!(p.ip_protocol(), Protocol::UDP);
        assert_eq!(p.transport_offset(), 48);
        assert_eq!(p.payload(), &[0xde, 0xad, 0xbe, 0xef]);
        // The literal accessor still returns everything after byte 40.
        assert_eq!(p.ipv6_payload().len(), 12);
        assert!(!p.is_fragment());
    }

    #[test]
    fn ipv6_chained_extension_headers() {
        // Hop-by-hop -> routing -> destination options -> TCP.
        let buf = v6_with_ext(
            &[(0, vec![0u8; 6]), (43, vec![0u8; 14]), (60, vec![0u8; 6])],
            6,
            &[1, 2, 3, 4],
        );
        let p = Packet::from_slice(&buf);
        assert_eq!(p.transport_protocol(), Protocol::TCP);
        assert_eq!(p.transport_offset(), 40 + 8 + 16 + 8);
        assert_eq!(p.payload(), &[1, 2, 3, 4]);
    }

    #[test]
    fn ipv6_first_fragment_walks_through() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = 44; // fragment header
        p[7] = 64;
        // Fragment header: next=UDP, reserved, offset 0 + M flag, id.
        let mut frag = vec![17u8, 0, 0x00, 0x01, 0, 0, 0, 1];
        frag.extend_from_slice(&[9, 9, 9, 9]);
        p.extend_from_slice(&frag);
        let plen = frag.len() as u16;
        p[4..6].copy_from_slice(&plen.to_be_bytes());

        let pkt = Packet::from_slice(&p);
        assert!(pkt.ipv6_is_fragment());
        assert!(pkt.is_fragment());
        // First fragment: the transport header is present and reachable.
        assert_eq!(pkt.transport_protocol(), Protocol::UDP);
        assert_eq!(pkt.transport_offset(), 48);
        // Fragments never yield a typed L4 view, first or not.
        assert!(pkt.udp().is_none());
    }

    #[test]
    fn ipv6_later_fragment_stops_at_fragment_header() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = 44;
        p[7] = 64;
        // Fragment offset 185*8 = 1480 bytes in, so no transport header here.
        let off: u16 = (1480 / 8) << 3;
        let mut frag = vec![17u8, 0];
        frag.extend_from_slice(&off.to_be_bytes());
        frag.extend_from_slice(&[0, 0, 0, 1]);
        frag.extend_from_slice(&[7; 16]);
        p.extend_from_slice(&frag);
        let plen = frag.len() as u16;
        p[4..6].copy_from_slice(&plen.to_be_bytes());

        let pkt = Packet::from_slice(&p);
        assert!(pkt.ipv6_is_fragment());
        assert_eq!(
            pkt.transport_protocol(),
            Protocol(44),
            "a later fragment has no transport header to report"
        );
        assert!(pkt.udp().is_none());
        assert!(pkt.five_tuple().unwrap().src_port == 0);
    }

    #[test]
    fn ipv6_truncated_chain_does_not_panic() {
        // Declares a hop-by-hop header that runs off the end of the buffer.
        let mut p = vec![0u8; 42];
        p[0] = 0x60;
        p[6] = 0;
        p[40] = 17;
        p[41] = 200; // claims (200+1)*8 bytes
        let pkt = Packet::from_slice(&p);
        let (_, off) = pkt.ipv6_transport();
        assert!(off <= p.len());
        assert_eq!(pkt.payload(), &[] as &[u8]);
    }

    #[test]
    fn ipv6_chain_cycle_terminates() {
        // A hop-by-hop header whose next header points at itself, repeated.
        // The walk must stop after MAX_EXT_HEADERS rather than spin.
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = 0;
        p[7] = 64;
        for _ in 0..64 {
            p.extend_from_slice(&[0u8, 0, 0, 0, 0, 0, 0, 0]);
        }
        let plen = (p.len() - 40) as u16;
        p[4..6].copy_from_slice(&plen.to_be_bytes());
        // Terminates (the test would hang otherwise).
        let (proto, off) = Packet::from_slice(&p).ipv6_transport();
        assert_eq!(proto, Protocol(0));
        assert!(off <= p.len());
    }

    #[test]
    fn ipv6_esp_stops_the_walk() {
        let buf = v6_with_ext(&[(0, vec![0u8; 6])], 50, &[0; 16]);
        let p = Packet::from_slice(&buf);
        assert_eq!(p.transport_protocol(), Protocol::ESP);
        assert!(p.tcp().is_none());
    }
}
