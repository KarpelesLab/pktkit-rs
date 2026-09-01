//! Generating ICMP and ICMPv6 error messages.
//!
//! A device that drops a packet usually owes the sender an explanation. Path
//! MTU discovery, `traceroute` and prompt connection failures all depend on
//! these messages actually being sent, so anything that routes, filters or
//! forwards should reach for this module rather than dropping silently.
//!
//! Every constructor returns a complete IP packet — header included — addressed
//! from `from` back to the offending packet's source, or `None` when the RFC
//! forbids a reply. Those rules ([`may_reply`]) are what stop an error storm:
//! never answer an error with an error, never answer a fragment other than the
//! first, and never answer anything that was broadcast or multicast.
//!
//! ```
//! # use pktkit::{icmp, Packet, Protocol};
//! # use pktkit::build::{build_ipv4, build_udp};
//! # use std::net::Ipv4Addr;
//! # let (src, dst) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
//! # let udp = build_udp(src.into(), dst.into(), 5000, 53, b"hi");
//! # let buf = build_ipv4(src, dst, Protocol::UDP, 1, &udp);
//! let expired = Packet::from_slice(&buf);
//! let router = Ipv4Addr::new(10, 0, 0, 254).into();
//!
//! let reply = icmp::time_exceeded(expired, router).unwrap();
//! let reply = Packet::from_slice(&reply);
//! assert_eq!(reply.dst_addr(), Some(src.into()));   // back to the sender
//! assert_eq!(reply.ip_protocol(), Protocol::ICMP);
//! ```

use crate::build::{build_icmpv4, build_icmpv6, build_ipv4, build_ipv6};
use crate::l4::{IcmpMessage, icmpv4, icmpv6};
use crate::{Packet, Protocol};
use std::net::IpAddr;

/// TTL / hop limit given to generated error messages.
const ERROR_TTL: u8 = 64;

/// RFC 1812 §4.3.2.3: an ICMPv4 error should not push the datagram past the
/// minimum IPv4 reassembly buffer size.
const MAX_V4_ERROR: usize = 576;

/// RFC 4443 §2.4: an ICMPv6 error must fit in the minimum IPv6 MTU.
const MAX_V6_ERROR: usize = 1280;

/// Which error to report. The codes are protocol-specific; use the constants in
/// [`crate::l4::icmpv4`] and [`crate::l4::icmpv6`], or the named constructors
/// below, which pick the right code for each family.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IcmpError {
    /// Destination Unreachable, with a family-specific code.
    DestUnreachable(u8),
    /// Time Exceeded — TTL / hop limit hit zero in transit.
    TimeExceeded(u8),
    /// The packet is larger than the next-hop MTU. Emitted as ICMPv4
    /// Fragmentation Needed or ICMPv6 Packet Too Big.
    PacketTooBig(u32),
    /// Parameter Problem, with a code and the offending byte offset.
    ParameterProblem(u8, u32),
}

/// True if an ICMP error may be generated in response to `orig`.
///
/// Replying is forbidden when the original is itself an ICMP error, is a
/// fragment other than the first, was sent to a broadcast or multicast address,
/// or came *from* an address that cannot be a unique host. Sending anyway is
/// how a pair of misconfigured routers turns one bad packet into a loop.
pub fn may_reply(orig: &Packet) -> bool {
    if !orig.is_valid() {
        return false;
    }
    // Only the first fragment carries the headers a reply must quote.
    if is_later_fragment(orig) {
        return false;
    }
    if orig.is_multicast() || orig.is_broadcast() {
        return false;
    }
    let src = match orig.src_addr() {
        Some(s) => s,
        None => return false,
    };
    if src.is_unspecified() || src.is_multicast() {
        return false;
    }
    if let IpAddr::V4(v4) = src
        && v4.is_broadcast()
    {
        return false;
    }
    // Never answer an error with an error.
    let proto = orig.transport_protocol();
    if proto == Protocol::ICMP || proto == Protocol::ICMPV6 {
        let payload = orig.transport_payload();
        if payload.len() >= 4 {
            let msg = IcmpMessage::from_slice(payload);
            let is_error = if proto == Protocol::ICMP {
                msg.is_icmpv4_error()
            } else {
                msg.is_icmpv6_error()
            };
            if is_error {
                return false;
            }
        } else {
            // Too short to classify — assume the worst and stay quiet.
            return false;
        }
    }
    true
}

/// True if this is a fragment other than the first — one that carries payload
/// but none of the headers a quoted error is supposed to include.
fn is_later_fragment(p: &Packet) -> bool {
    match p.version() {
        4 => p.ipv4_fragment_offset() != 0,
        // The extension walker reports Protocol(44) only when it stopped at a
        // fragment header with a non-zero offset, which is precisely this case.
        6 => p.transport_protocol() == Protocol(44),
        _ => false,
    }
}

/// Build an ICMP error for `orig`, sent from `from`.
///
/// Returns `None` if [`may_reply`] forbids it, if `from` is from a different
/// address family than the packet, or if the packet is malformed.
pub fn error(orig: &Packet, from: IpAddr, err: IcmpError) -> Option<Vec<u8>> {
    if !may_reply(orig) {
        return None;
    }
    let dst = orig.src_addr()?;
    match (orig.version(), from, dst) {
        (4, IpAddr::V4(from), IpAddr::V4(dst)) => {
            let (t, code, rest) = match err {
                IcmpError::DestUnreachable(c) => (icmpv4::DEST_UNREACHABLE, c, [0u8; 4]),
                IcmpError::TimeExceeded(c) => (icmpv4::TIME_EXCEEDED, c, [0u8; 4]),
                IcmpError::PacketTooBig(mtu) => {
                    // The MTU lives in the low half of the unused word.
                    let mtu = mtu.min(u16::MAX as u32) as u16;
                    let [hi, lo] = mtu.to_be_bytes();
                    (
                        icmpv4::DEST_UNREACHABLE,
                        icmpv4::CODE_FRAG_NEEDED,
                        [0, 0, hi, lo],
                    )
                }
                IcmpError::ParameterProblem(c, ptr) => {
                    (icmpv4::PARAMETER_PROBLEM, c, [ptr.min(255) as u8, 0, 0, 0])
                }
            };
            // Quote as much of the original as fits, keeping the whole reply
            // within the minimum reassembly buffer.
            let room = MAX_V4_ERROR.saturating_sub(20 + 8);
            let quote = quoted(orig, room.max(orig.ipv4_header_len() + 8));
            let msg = build_icmpv4(t, code, rest, quote);
            Some(build_ipv4(from, dst, Protocol::ICMP, ERROR_TTL, &msg))
        }
        (6, IpAddr::V6(from), IpAddr::V6(dst)) => {
            let (t, code, rest) = match err {
                IcmpError::DestUnreachable(c) => (icmpv6::DEST_UNREACHABLE, c, [0u8; 4]),
                IcmpError::TimeExceeded(c) => (icmpv6::TIME_EXCEEDED, c, [0u8; 4]),
                IcmpError::PacketTooBig(mtu) => (icmpv6::PACKET_TOO_BIG, 0, mtu.to_be_bytes()),
                IcmpError::ParameterProblem(c, ptr) => {
                    (icmpv6::PARAMETER_PROBLEM, c, ptr.to_be_bytes())
                }
            };
            let room = MAX_V6_ERROR.saturating_sub(40 + 8 + 40);
            let quote = quoted(orig, room);
            let msg = build_icmpv6(from, dst, t, code, rest, quote);
            Some(build_ipv6(from, dst, Protocol::ICMPV6, ERROR_TTL, &msg))
        }
        _ => None,
    }
}

/// As much of the original packet as may be quoted back, capped at `room`
/// bytes and at whatever the buffer actually holds.
fn quoted(orig: &Packet, room: usize) -> &[u8] {
    let declared = orig.total_len();
    let have = orig.len();
    let end = if declared > 0 && declared <= have {
        declared
    } else {
        have
    };
    &orig.as_bytes()[..end.min(room)]
}

/// Destination Unreachable with a family-appropriate "port unreachable" code —
/// the reply a host owes to a UDP datagram for a port nobody is listening on.
pub fn port_unreachable(orig: &Packet, from: IpAddr) -> Option<Vec<u8>> {
    let code = match orig.version() {
        4 => icmpv4::CODE_PORT_UNREACHABLE,
        6 => icmpv6::CODE_PORT_UNREACHABLE,
        _ => return None,
    };
    error(orig, from, IcmpError::DestUnreachable(code))
}

/// Destination Unreachable / No route to host.
pub fn no_route(orig: &Packet, from: IpAddr) -> Option<Vec<u8>> {
    let code = match orig.version() {
        4 => icmpv4::CODE_HOST_UNREACHABLE,
        6 => icmpv6::CODE_NO_ROUTE,
        _ => return None,
    };
    error(orig, from, IcmpError::DestUnreachable(code))
}

/// Destination Unreachable / administratively prohibited — the honest reply
/// from a filter that dropped the packet on purpose.
pub fn admin_prohibited(orig: &Packet, from: IpAddr) -> Option<Vec<u8>> {
    let code = match orig.version() {
        4 => icmpv4::CODE_ADMIN_PROHIBITED,
        6 => icmpv6::CODE_ADMIN_PROHIBITED,
        _ => return None,
    };
    error(orig, from, IcmpError::DestUnreachable(code))
}

/// Time Exceeded — send this when [`Packet::decrement_hop_limit`] returns
/// false. Without it, `traceroute` sees nothing but timeouts.
///
/// [`Packet::decrement_hop_limit`]: crate::Packet::decrement_hop_limit
pub fn time_exceeded(orig: &Packet, from: IpAddr) -> Option<Vec<u8>> {
    let code = match orig.version() {
        4 => icmpv4::CODE_TTL_EXCEEDED,
        6 => icmpv6::CODE_HOP_LIMIT_EXCEEDED,
        _ => return None,
    };
    error(orig, from, IcmpError::TimeExceeded(code))
}

/// The packet is too big for the next hop and may not be fragmented.
///
/// This is the message path MTU discovery runs on: dropping an oversize packet
/// without it produces a black hole that looks like a hung connection.
pub fn packet_too_big(orig: &Packet, from: IpAddr, mtu: u32) -> Option<Vec<u8>> {
    error(orig, from, IcmpError::PacketTooBig(mtu))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::{build_ipv4, build_ipv6, build_udp};
    use crate::l4::IcmpMessage;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const ROUTER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 254);

    fn v4_udp() -> Vec<u8> {
        let udp = build_udp(HOST.into(), PEER.into(), 5000, 53, b"payload");
        build_ipv4(HOST, PEER, Protocol::UDP, 64, &udp)
    }

    fn v6_udp() -> Vec<u8> {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let udp = build_udp(a.into(), b.into(), 5000, 53, b"payload");
        build_ipv6(a, b, Protocol::UDP, 64, &udp)
    }

    #[test]
    fn time_exceeded_v4_is_well_formed() {
        let buf = v4_udp();
        let orig = Packet::from_slice(&buf);
        let reply = time_exceeded(orig, ROUTER.into()).unwrap();
        let p = Packet::from_slice(&reply);

        assert_eq!(p.version(), 4);
        assert_eq!(p.src_addr(), Some(ROUTER.into()));
        assert_eq!(
            p.dst_addr(),
            Some(HOST.into()),
            "errors go back to the sender"
        );
        assert_eq!(p.ip_protocol(), Protocol::ICMP);
        assert!(p.verify_ipv4_checksum());

        let msg = p.icmp().unwrap();
        assert_eq!(msg.message_type(), icmpv4::TIME_EXCEEDED);
        assert_eq!(msg.code(), icmpv4::CODE_TTL_EXCEEDED);
        assert!(msg.verify_icmpv4_checksum());
        // The quote begins with the original header.
        assert_eq!(&msg.payload()[..20], &buf[..20]);
    }

    #[test]
    fn port_unreachable_v6_is_well_formed() {
        let buf = v6_udp();
        let orig = Packet::from_slice(&buf);
        let from: Ipv6Addr = "2001:db8::ffff".parse().unwrap();
        let reply = port_unreachable(orig, from.into()).unwrap();
        let p = Packet::from_slice(&reply);

        assert_eq!(p.version(), 6);
        assert_eq!(p.ip_protocol(), Protocol::ICMPV6);
        assert_eq!(
            p.verify_transport_checksum(),
            Some(true),
            "ICMPv6 checksum must cover the pseudo-header"
        );
        let msg = p.icmp().unwrap();
        assert_eq!(msg.message_type(), icmpv6::DEST_UNREACHABLE);
        assert_eq!(msg.code(), icmpv6::CODE_PORT_UNREACHABLE);
    }

    #[test]
    fn frag_needed_carries_the_mtu() {
        let buf = v4_udp();
        let reply = packet_too_big(Packet::from_slice(&buf), ROUTER.into(), 1400).unwrap();
        let p = Packet::from_slice(&reply);
        let msg = p.icmp().unwrap();
        assert_eq!(msg.message_type(), icmpv4::DEST_UNREACHABLE);
        assert_eq!(msg.code(), icmpv4::CODE_FRAG_NEEDED);
        assert_eq!(msg.mtu(), 1400);
    }

    #[test]
    fn packet_too_big_v6_carries_the_mtu() {
        let buf = v6_udp();
        let from: Ipv6Addr = "2001:db8::ffff".parse().unwrap();
        let reply = packet_too_big(Packet::from_slice(&buf), from.into(), 1280).unwrap();
        let p = Packet::from_slice(&reply);
        let msg = p.icmp().unwrap();
        assert_eq!(msg.message_type(), icmpv6::PACKET_TOO_BIG);
        assert_eq!(msg.mtu(), 1280);
    }

    #[test]
    fn never_reply_to_an_icmp_error() {
        let buf = v4_udp();
        let err = time_exceeded(Packet::from_slice(&buf), ROUTER.into()).unwrap();
        let err_pkt = Packet::from_slice(&err);
        assert!(!may_reply(err_pkt));
        assert!(time_exceeded(err_pkt, ROUTER.into()).is_none());
    }

    #[test]
    fn do_reply_to_an_icmp_query() {
        // Echo requests are queries, not errors — those may be answered.
        let msg = crate::build::build_icmpv4(icmpv4::ECHO_REQUEST, 0, [0; 4], b"ping");
        let buf = build_ipv4(HOST, PEER, Protocol::ICMP, 64, &msg);
        assert!(may_reply(Packet::from_slice(&buf)));
    }

    #[test]
    fn never_reply_to_broadcast_or_multicast() {
        let udp = build_udp(HOST.into(), PEER.into(), 1, 2, b"x");
        let mut buf = build_ipv4(HOST, Ipv4Addr::BROADCAST, Protocol::UDP, 64, &udp);
        assert!(!may_reply(Packet::from_slice(&buf)));

        let p = Packet::from_mut(&mut buf);
        p.set_ipv4_dst_addr(Ipv4Addr::new(224, 0, 0, 1));
        assert!(!may_reply(p));
    }

    #[test]
    fn never_reply_to_a_later_fragment() {
        let mut buf = v4_udp();
        let p = Packet::from_mut(&mut buf);
        p.set_ipv4_fragment_offset(1480);
        p.recompute_ipv4_checksum();
        assert!(!may_reply(p));

        // The first fragment of the same datagram is fair game.
        p.set_ipv4_fragment_offset(0);
        p.set_ipv4_more_fragments(true);
        assert!(may_reply(p));
    }

    #[test]
    fn never_reply_to_a_bogus_source() {
        let udp = build_udp(HOST.into(), PEER.into(), 1, 2, b"x");
        let buf = build_ipv4(Ipv4Addr::UNSPECIFIED, PEER, Protocol::UDP, 64, &udp);
        assert!(!may_reply(Packet::from_slice(&buf)));

        let buf = build_ipv4(Ipv4Addr::new(224, 0, 0, 5), PEER, Protocol::UDP, 64, &udp);
        assert!(!may_reply(Packet::from_slice(&buf)));
    }

    #[test]
    fn mismatched_family_yields_nothing() {
        let buf = v4_udp();
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(time_exceeded(Packet::from_slice(&buf), v6.into()).is_none());
    }

    #[test]
    fn quote_is_bounded() {
        // A large original must not produce an oversize error message.
        let udp = build_udp(HOST.into(), PEER.into(), 1, 2, &vec![0u8; 4000]);
        let buf = build_ipv4(HOST, PEER, Protocol::UDP, 64, &udp);
        let reply = time_exceeded(Packet::from_slice(&buf), ROUTER.into()).unwrap();
        assert!(reply.len() <= MAX_V4_ERROR, "got {} bytes", reply.len());

        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let udp = build_udp(a.into(), b.into(), 1, 2, &vec![0u8; 4000]);
        let buf = build_ipv6(a, b, Protocol::UDP, 64, &udp);
        let reply =
            time_exceeded(Packet::from_slice(&buf), "2001:db8::f".parse().unwrap()).unwrap();
        assert!(reply.len() <= MAX_V6_ERROR, "got {} bytes", reply.len());
    }

    #[test]
    fn short_quote_survives_a_truncated_original() {
        // Declared total length larger than the buffer: quoting must clamp to
        // what is actually there rather than panic.
        let mut buf = v4_udp();
        let p = Packet::from_mut(&mut buf);
        p.set_ipv4_total_len(9000);
        let reply = time_exceeded(p, ROUTER.into()).unwrap();
        let p = Packet::from_slice(&reply);
        let msg = IcmpMessage::from_slice(p.transport_payload());
        assert_eq!(msg.payload().len(), buf.len());
    }
}
