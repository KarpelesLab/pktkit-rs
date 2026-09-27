//! NAT64 (RFC 6146): IPv6-to-IPv4 translation. IPv4 hosts appear on the
//! IPv6 side as IPv4-embedded addresses under the NAT64 prefix (RFC 6052),
//! e.g. `64:ff9b::192.0.2.33` for the Well-Known Prefix.
//!
//! Inside faces IPv6; outside faces IPv4. TCP, UDP and ICMP echo sessions
//! are translated, and so are ICMP errors about them in both directions:
//! ICMPv4 to ICMPv6 per RFC 7915 §4.2, ICMPv6 to ICMPv4 per §5.2.

use crate::nat::frag::FragTable;
use crate::nat::helper::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use crate::nat::l4::csum_replace;
use crate::nat::nat::frag_info;
use crate::nat::track::Peers;
use crate::time::Instant;
use crate::{
    IpPrefix, L3Device, L3Handler, Packet, Protocol, Result, checksum, transport_checksum,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, Weak};

const IPV6_HEADER_LEN: usize = 40;
const IPV4_MIN_HEADER: usize = 20;

const NAT_PORT_MIN: u16 = 10000;
const NAT_PORT_MAX: u16 = 65535;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Nat64Key {
    proto: u8,
    ip: Ipv6Addr,
    port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Nat64RevKey {
    proto: u8,
    port: u16,
}

#[derive(Debug)]
struct Mapping {
    #[allow(dead_code)] // kept for symmetry with `Nat` and possible introspection
    key: Nat64Key,
    outside_port: u16,
    last_active: Instant,
    peers: Peers,
}

/// NAT64 between an inside IPv6 network and an outside IPv4 network.
pub struct Nat64 {
    inside: Arc<Nat64Side>,
    outside: Arc<Nat64Side>,

    inner: Mutex<Nat64Inner>,
    self_ref: Mutex<Weak<Nat64>>,
    /// IPv4 Identification for packets translated from unfragmented IPv6.
    next_id: AtomicU16,
    /// Inbound fragmented datagrams: the inside host each one's first
    /// fragment went to, by source, IP ID and protocol.
    frags: Mutex<FragTable<(Ipv4Addr, u16, u8), Ipv6Addr>>,
}

struct Nat64Inner {
    mappings: HashMap<Nat64Key, Mapping>,
    reverse: HashMap<Nat64RevKey, Nat64Key>,
    next_port: u16,
}

impl std::fmt::Debug for Nat64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nat64")
            .field("inside", &self.inside.addr())
            .field("outside", &self.outside.addr())
            .finish()
    }
}

impl Nat64 {
    /// Construct a NAT64. `inside_addr` is the NAT64 prefix (Pref64::/n) IPv4
    /// hosts are mapped into, of length 32, 40, 48, 56, 64 or 96 (RFC 6052
    /// §2.2), such as the Well-Known Prefix `64:ff9b::/96`; with any other
    /// prefix nothing is translated. `outside_addr` is the IPv4 address the
    /// translated traffic uses.
    pub fn new(inside_addr: IpPrefix, outside_addr: IpPrefix) -> Arc<Nat64> {
        let inside = Arc::new(Nat64Side::new(true, inside_addr));
        let outside = Arc::new(Nat64Side::new(false, outside_addr));
        let nat = Arc::new(Nat64 {
            inside: inside.clone(),
            outside: outside.clone(),
            inner: Mutex::new(Nat64Inner {
                mappings: HashMap::new(),
                reverse: HashMap::new(),
                next_port: NAT_PORT_MIN,
            }),
            self_ref: Mutex::new(Weak::new()),
            next_id: AtomicU16::new(crate::rand::u32() as u16),
            frags: Mutex::new(FragTable::default()),
        });
        *nat.self_ref.lock().unwrap() = Arc::downgrade(&nat);
        inside.set_parent(Arc::downgrade(&nat));
        outside.set_parent(Arc::downgrade(&nat));
        nat
    }

    pub fn inside(&self) -> Arc<dyn L3Device> {
        self.inside.clone()
    }
    pub fn outside(&self) -> Arc<dyn L3Device> {
        self.outside.clone()
    }

    fn pref64(&self) -> Option<Pref64> {
        Pref64::new(self.inside.addr())
    }

    fn outside_ipv4(&self) -> Option<Ipv4Addr> {
        match self.outside.addr().addr() {
            IpAddr::V4(a) => Some(a),
            _ => None,
        }
    }

    /// Sweep expired connections — called by the user on a timer.
    pub fn sweep(&self) {
        self.sweep_at(Instant::now());
    }

    fn sweep_at(&self, now: Instant) {
        self.frags.lock().unwrap().expire(now);
        let mut inner = self.inner.lock().unwrap();
        let inner = &mut *inner;
        inner.mappings.retain(|k, m| {
            if m.peers.expire(k.proto, m.last_active, now) {
                inner.reverse.remove(&Nat64RevKey {
                    proto: k.proto,
                    port: m.outside_port,
                });
                false
            } else {
                true
            }
        });
    }

    /// Send a translated IPv4 packet on the outside, unless it is addressed
    /// to the NAT64's own IPv4 address: sent there, it would reach only the
    /// upstream, with the NAT64's address on both ends. It is another inside
    /// host's session, reached through the NAT64 (hairpinning, RFC 6146
    /// §3.8), and turns around as if it had arrived from outside.
    fn send_v4(&self, out: &[u8]) {
        if self
            .outside_ipv4()
            .is_some_and(|a| out[16..20] == a.octets())
        {
            self.handle_inbound(out);
            return;
        }
        self.outside.deliver(Packet::from_slice(out));
    }

    // ---------- Outbound (IPv6 -> IPv4) ----------

    fn handle_outbound(&self, pkt: &[u8]) {
        if pkt.len() < IPV6_HEADER_LEN || pkt[0] >> 4 != 6 {
            return;
        }
        let dst_v6 = read_v6(&pkt[24..40]);
        let Some(dst_v4) = self.pref64().and_then(|p| p.extract(dst_v6)) else {
            return;
        };
        let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
        let src_v6 = read_v6(&pkt[8..24]);

        if pkt.len() < IPV6_HEADER_LEN + payload_len {
            return;
        }
        // Link padding past the payload is not part of the packet.
        let pkt = &pkt[..IPV6_HEADER_LEN + payload_len];
        // The translator is a router (RFC 7915 §5.1): it spends one hop, and
        // owes the sender a Hop Limit Exceeded when none is left. It answers
        // from its own IPv4 address as seen through the prefix.
        let hop = pkt[7];
        if hop <= 1 {
            if let Some(me) = self.outside_ipv4().and_then(|ip| self.pref64()?.embed(ip))
                && let Some(err) =
                    crate::icmp::time_exceeded(Packet::from_slice(pkt), IpAddr::V6(me))
            {
                self.inside.deliver(Packet::from_slice(&err));
            }
            return;
        }
        // RFC 7915 §5.1: the Traffic Class becomes the TOS, DSCP and ECN
        // alike.
        let hop = (hop - 1, (pkt[0] << 4) | (pkt[1] >> 4));

        // Walk the extension headers (RFC 7915 §5.1), noting a Fragment
        // Header: its fields carry over to the IPv4 header.
        let mut next_header = pkt[6];
        let mut off = IPV6_HEADER_LEN;
        let mut frag: Option<V6Frag> = None;
        loop {
            match next_header {
                0 | 43 | 60 => {
                    if off + 8 > pkt.len() {
                        return;
                    }
                    // A routing header still naming hops to visit must not
                    // be translated: IPv4 has no way to honour it.
                    if next_header == 43 && pkt[off + 3] != 0 {
                        return;
                    }
                    next_header = pkt[off];
                    off += (pkt[off + 1] as usize + 1) * 8;
                }
                44 => {
                    if off + 8 > pkt.len() || frag.is_some() {
                        return;
                    }
                    let fo = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
                    frag = Some(V6Frag {
                        offset: (fo & 0xFFF8) as usize,
                        more: fo & 1 != 0,
                        id: u32::from_be_bytes([
                            pkt[off + 4],
                            pkt[off + 5],
                            pkt[off + 6],
                            pkt[off + 7],
                        ]),
                    });
                    next_header = pkt[off];
                    off += 8;
                }
                _ => break,
            }
        }
        if off > pkt.len() {
            return;
        }
        let data = &pkt[off..];
        let Some(outside_ip) = self.outside_ipv4() else {
            return;
        };
        // An IPv6 payload may reach 65535 bytes, an IPv4 packet with its
        // header may not: the Total Length would wrap. IPv4 cannot carry it,
        // so, as for any path MTU too small for a packet (RFC 7915 §5.1), the
        // sender is told the largest IPv6 packet that would translate to a
        // full-size IPv4 one.
        if IPV4_MIN_HEADER + data.len() > usize::from(u16::MAX) {
            let mtu = (usize::from(u16::MAX) - IPV4_MIN_HEADER + off) as u32;
            if let Some(me) = self.pref64().and_then(|p| p.embed(outside_ip))
                && let Some(err) =
                    crate::icmp::packet_too_big(Packet::from_slice(pkt), IpAddr::V6(me), mtu)
            {
                self.inside.deliver(Packet::from_slice(&err));
            }
            return;
        }

        // Likewise for a fragment of a datagram that would come out larger
        // than IPv4 allows: the pieces would translate, but the receiver
        // could never reassemble them into one datagram.
        if frag.is_some_and(|f| IPV4_MIN_HEADER + f.offset + data.len() > usize::from(u16::MAX)) {
            return;
        }

        match (next_header, frag) {
            // A non-first fragment carries no ports and needs no mapping:
            // only its IP header is translated (RFC 7915 §5.1.1).
            (PROTO_TCP | PROTO_UDP, Some(f)) if f.offset != 0 => {
                let flags = (f.offset / 8) as u16 | if f.more { 0x2000 } else { 0 };
                let mut out = v4_header(
                    outside_ip,
                    dst_v4,
                    next_header,
                    hop,
                    data.len(),
                    f.id as u16,
                    flags,
                );
                out.extend_from_slice(data);
                self.send_v4(&out);
            }
            (PROTO_TCP | PROTO_UDP, _) => self.outbound_tcpudp(
                data,
                next_header,
                (src_v6, dst_v6),
                (outside_ip, dst_v4),
                hop,
                frag,
            ),
            // The ICMPv6 checksum covers a pseudo-header holding the whole
            // message's length, which a first fragment does not know, so
            // fragmented ICMP is not translated.
            (PROTO_ICMPV6, None) => {
                self.outbound_icmpv6(data, src_v6, dst_v6, (outside_ip, dst_v4), hop)
            }
            _ => {}
        }
    }

    /// Translate a TCP/UDP packet, or the first fragment of one, to IPv4.
    fn outbound_tcpudp(
        &self,
        transport: &[u8],
        proto: u8,
        (src_v6, dst_v6): (Ipv6Addr, Ipv6Addr),
        (outside_ip, dst_v4): (Ipv4Addr, Ipv4Addr),
        hop: Hop,
        frag: Option<V6Frag>,
    ) {
        let field = if proto == PROTO_TCP { 16 } else { 6 };
        if transport.len() < field + 2 {
            return;
        }
        // IPv6 has no checksum-less UDP; such a datagram is invalid.
        if proto == PROTO_UDP && transport[6..8] == [0, 0] {
            return;
        }
        let src_port = u16::from_be_bytes([transport[0], transport[1]]);
        let k = Nat64Key {
            proto,
            ip: src_v6,
            port: src_port,
        };
        let (outside_port, _) = match self.get_or_create_mapping(k) {
            Some(v) => v,
            None => return,
        };

        let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
        self.note_peer(
            k,
            SocketAddrV4::new(dst_v4, dst_port),
            true,
            tcp_flags(transport, proto),
        );

        let mut l4 = transport.to_vec();
        l4[0..2].copy_from_slice(&outside_port.to_be_bytes());
        // Patched rather than recomputed: the checksum covers the whole
        // datagram, of which a first fragment holds only part, and a
        // recompute would also hide corruption from the receiver.
        let cs = u16::from_be_bytes([l4[field], l4[field + 1]]);
        let mut cs = csum_replace(
            cs,
            &[&src_v6.octets(), &dst_v6.octets(), &src_port.to_be_bytes()],
            &[
                &outside_ip.octets(),
                &dst_v4.octets(),
                &outside_port.to_be_bytes(),
            ],
        );
        if proto == PROTO_UDP && cs == 0 {
            cs = 0xFFFF;
        }
        l4[field..field + 2].copy_from_slice(&cs.to_be_bytes());

        let (id, flags) = match frag {
            Some(f) => (f.id as u16, if f.more { 0x2000 } else { 0 }),
            None => self.unfragmented_v4_id(IPV4_MIN_HEADER + l4.len()),
        };
        let mut out = v4_header(outside_ip, dst_v4, proto, hop, l4.len(), id, flags);
        out.extend_from_slice(&l4);
        self.send_v4(&out);
    }

    /// Identification and flags for an IPv4 packet translated from an
    /// unfragmented IPv6 one of `total` bytes (RFC 7915 §5.1): DF is set
    /// once the packet exceeds 1260 bytes, beyond which IPv6's 1280-byte
    /// minimum MTU no longer guarantees it fits; below that it may be
    /// fragmented and needs an ID unique enough to reassemble (RFC 6864).
    fn unfragmented_v4_id(&self, total: usize) -> (u16, u16) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        (id, if total > 1260 { 0x4000 } else { 0 })
    }

    fn outbound_icmpv6(
        &self,
        icmp: &[u8],
        src_v6: Ipv6Addr,
        dst_v6: Ipv6Addr,
        (outside_ip, dst_v4): (Ipv4Addr, Ipv4Addr),
        hop: Hop,
    ) {
        if icmp.len() < 8 {
            return;
        }
        // Echo Request, and the errors RFC 7915 §5.2 has ICMPv4 types for.
        if !matches!(icmp[0], 1..=4 | 128) {
            return;
        }
        // The ICMPv4 checksum is computed afresh; check the original first,
        // so a corrupted message is not laundered into a valid one.
        let sum = crate::checksum::raw_transport_sum(
            Protocol::ICMPV6,
            IpAddr::V6(src_v6),
            IpAddr::V6(dst_v6),
            icmp,
        );
        if sum != 0xFFFF {
            return;
        }
        if icmp[0] != 128 {
            return self.outbound_icmpv6_error(icmp, dst_v6, (outside_ip, dst_v4), hop);
        }
        // An echo request to the NAT64's own address: no inside host owns
        // it for ICMP (an echo names no port to hairpin by), so the NAT64
        // answers, as any host must (RFC 4443 §4.1).
        if dst_v4 == outside_ip {
            let mut out = v6_header(dst_v6, src_v6, PROTO_ICMPV6, (64, 0), icmp.len());
            out.extend_from_slice(icmp);
            let at = IPV6_HEADER_LEN;
            out[at] = 129;
            out[at + 2..at + 4].copy_from_slice(&[0, 0]);
            let cs = compute_icmpv6_checksum(dst_v6, src_v6, &out[at..]);
            out[at + 2..at + 4].copy_from_slice(&cs.to_be_bytes());
            self.inside.deliver(Packet::from_slice(&out));
            return;
        }
        let id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let k = Nat64Key {
            proto: PROTO_ICMP,
            ip: src_v6,
            port: id,
        };
        let (outside_port, _) = match self.get_or_create_mapping(k) {
            Some(v) => v,
            None => return,
        };
        self.note_peer(k, SocketAddrV4::new(dst_v4, 0), true, None);

        let mut msg = icmp.to_vec();
        msg[0] = 8; // ICMPv4 Echo Request
        msg[1] = 0;
        msg[4..6].copy_from_slice(&outside_port.to_be_bytes());
        msg[2..4].copy_from_slice(&[0, 0]);
        let cs = checksum(&msg);
        msg[2..4].copy_from_slice(&cs.to_be_bytes());

        let (ip_id, flags) = self.unfragmented_v4_id(IPV4_MIN_HEADER + msg.len());
        let mut out = v4_header(outside_ip, dst_v4, PROTO_ICMP, hop, msg.len(), ip_id, flags);
        out.extend_from_slice(&msg);
        self.send_v4(&out);
    }

    /// Translate an ICMPv6 error the inside sends about a packet that came
    /// in through this NAT64 into ICMPv4 (RFC 7915 §5.2 and §5.3): type and
    /// code from the RFC's tables, and the quoted IPv6 packet turned back
    /// into the IPv4 one it was translated from.
    fn outbound_icmpv6_error(
        &self,
        icmp: &[u8],
        dst_v6: Ipv6Addr,
        (outside_ip, dst_v4): (Ipv4Addr, Ipv4Addr),
        hop: Hop,
    ) {
        let rest = [icmp[4], icmp[5], icmp[6], icmp[7]];
        // Packet Too Big's MTU is filled in once the quote is parsed.
        let (v4_type, v4_code, mut word) = match (icmp[0], icmp[1]) {
            (1, 0 | 2 | 3) => (3, 1, [0; 4]),
            (1, 1) => (3, 10, [0; 4]),
            (1, 4) => (3, 3, [0; 4]),
            (2, _) => (3, 4, [0; 4]),
            (3, c @ (0 | 1)) => (11, c, [0; 4]),
            (4, 0) => match v6_pointer_to_v4(u32::from_be_bytes(rest)) {
                Some(p) => (12, 0, [p, 0, 0, 0]),
                None => return,
            },
            // Unrecognized Next Header: the IPv4 host named a protocol the
            // IPv6 one does not speak.
            (4, 1) => (3, 2, [0; 4]),
            _ => return,
        };

        // The quote: an IPv6 header, a Fragment Header if the packet was
        // translated from the first fragment of an IPv4 datagram, then the
        // transport header whose ports identify the session.
        let emb = &icmp[8..];
        if emb.len() < IPV6_HEADER_LEN || emb[0] >> 4 != 6 {
            return;
        }
        let mut nh = emb[6];
        let mut off = IPV6_HEADER_LEN;
        let mut frag = None;
        if nh == 44 {
            if emb.len() < off + 8 {
                return;
            }
            let fo = u16::from_be_bytes([emb[off + 2], emb[off + 3]]);
            // A later fragment carries no ports to find the session by.
            if fo & 0xFFF8 != 0 {
                return;
            }
            frag = Some((
                u16::from_be_bytes([emb[off + 6], emb[off + 7]]),
                fo & 1 != 0,
            ));
            nh = emb[off];
            off += 8;
        }
        if (nh != PROTO_TCP && nh != PROTO_UDP) || emb.len() < off + 8 {
            return;
        }
        let l4 = &emb[off..];
        let (emb_src_v6, emb_dst_v6) = (read_v6(&emb[8..24]), read_v6(&emb[24..40]));
        // An error goes back to whoever sent the packet it quotes.
        if emb_src_v6 != dst_v6 {
            return;
        }
        let remote = SocketAddrV4::new(dst_v4, u16::from_be_bytes([l4[0], l4[1]]));
        let inside_port = u16::from_be_bytes([l4[2], l4[3]]);
        let k = Nat64Key {
            proto: nh,
            ip: emb_dst_v6,
            port: inside_port,
        };
        // Only for a live mapping, about traffic it carried from that
        // remote: an inside host must not be able to forge errors against
        // sessions it is not part of.
        let outside_port = {
            let inner = self.inner.lock().unwrap();
            match inner.mappings.get(&k) {
                Some(m) if m.peers.contains(&remote) => m.outside_port,
                _ => return,
            }
        };
        if v4_type == 3 && v4_code == 4 {
            // The IPv4 packet was 20 bytes smaller than the IPv6 one, or 28
            // when the translation added a Fragment Header (RFC 7915 §5.2).
            let shrink = if frag.is_some() { 28 } else { 20 };
            let mtu = u32::from_be_bytes(rest).saturating_sub(shrink).min(0xFFFF) as u16;
            word[2..4].copy_from_slice(&mtu.to_be_bytes());
        }

        let payload_len = usize::from(u16::from_be_bytes([emb[4], emb[5]]));
        let v4_payload = payload_len.saturating_sub(off - IPV6_HEADER_LEN);
        let (id, flags) = frag.map_or((0, 0), |(id, more)| (id, if more { 0x2000 } else { 0 }));
        let quoted_hop = (emb[7], (emb[0] << 4) | (emb[1] >> 4));
        let mut quote = v4_header(dst_v4, outside_ip, nh, quoted_hop, v4_payload, id, flags);

        // An ICMPv4 error stays within 576 bytes (RFC 1812 §4.3.2.3).
        let room = 576 - 2 * IPV4_MIN_HEADER - 8;
        let l4_off = quote.len();
        quote.extend_from_slice(&l4[..l4.len().min(room)]);
        let q = &mut quote[l4_off..];
        let new_port = outside_port.to_be_bytes();
        q[2..4].copy_from_slice(&new_port);
        let field = if nh == PROTO_TCP { 16 } else { 6 };
        if q.len() >= field + 2 && !(nh == PROTO_UDP && q[6..8] == [0, 0]) {
            let cs = u16::from_be_bytes([q[field], q[field + 1]]);
            let mut cs = csum_replace(
                cs,
                &[
                    &emb_src_v6.octets(),
                    &emb_dst_v6.octets(),
                    &inside_port.to_be_bytes(),
                ],
                &[&dst_v4.octets(), &outside_ip.octets(), &new_port],
            );
            if nh == PROTO_UDP && cs == 0 {
                cs = 0xFFFF;
            }
            q[field..field + 2].copy_from_slice(&cs.to_be_bytes());
        }

        let mut msg = vec![v4_type, v4_code, 0, 0];
        msg.extend_from_slice(&word);
        msg.extend_from_slice(&quote);
        let cs = checksum(&msg);
        msg[2..4].copy_from_slice(&cs.to_be_bytes());
        let (ip_id, flags) = self.unfragmented_v4_id(IPV4_MIN_HEADER + msg.len());
        let mut out = v4_header(outside_ip, dst_v4, PROTO_ICMP, hop, msg.len(), ip_id, flags);
        out.extend_from_slice(&msg);
        self.send_v4(&out);
    }

    // ---------- Inbound (IPv4 -> IPv6) ----------

    fn handle_inbound(&self, pkt: &[u8]) {
        if pkt.len() < IPV4_MIN_HEADER || pkt[0] >> 4 != 4 {
            return;
        }
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        if ihl < IPV4_MIN_HEADER || pkt.len() < ihl {
            return;
        }
        let proto = pkt[9];
        let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if total < ihl || pkt.len() < total {
            return;
        }
        let pkt = &pkt[..total];
        // Mappings are found by port alone, so only traffic addressed to
        // the NAT64 itself may use them.
        if self
            .outside_ipv4()
            .is_none_or(|a| pkt[16..20] != a.octets())
        {
            return;
        }
        // The translator is a router (RFC 7915 §4.1): it spends one hop, and
        // owes the sender a Time Exceeded when none is left.
        // Options are dropped in translation (RFC 7915 §4.1), but a source
        // route still naming hops to visit cannot be honoured, so the packet
        // is refused and the sender told why.
        if unexpired_source_route(&pkt[IPV4_MIN_HEADER..ihl]) {
            if let Some(ip) = self.outside_ipv4()
                && let Some(err) = crate::icmp::error(
                    Packet::from_slice(pkt),
                    IpAddr::V4(ip),
                    crate::icmp::IcmpError::DestUnreachable(5),
                )
            {
                self.send_v4(&err);
            }
            return;
        }
        let ttl = pkt[8];
        if ttl <= 1 {
            if let Some(ip) = self.outside_ipv4()
                && let Some(err) =
                    crate::icmp::time_exceeded(Packet::from_slice(pkt), IpAddr::V4(ip))
            {
                self.send_v4(&err);
            }
            return;
        }
        // RFC 7915 §4.1: the TOS becomes the Traffic Class, DSCP and ECN
        // alike.
        let hop = (ttl - 1, pkt[1]);
        let src_v4 = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let transport = &pkt[ihl..];

        // Fragments are translated one by one (RFC 7915 §4.1): only the first
        // can be matched to a mapping, and the rest follow it to the same
        // inside host.
        let (more, offset) = frag_info(pkt);
        let key = (src_v4, u16::from_be_bytes([pkt[4], pkt[5]]), proto);
        if offset != 0 {
            let target = self.frags.lock().unwrap().later(key, pkt, Instant::now());
            if let Some(dst_v6) = target {
                self.inbound_later_fragment(pkt, dst_v6);
            }
            return;
        }
        let frag_id = more.then_some(key.1);

        match proto {
            PROTO_TCP | PROTO_UDP => {
                let Some(dst_v6) = self.inbound_tcpudp(transport, proto, src_v4, hop, frag_id)
                else {
                    return;
                };
                if frag_id.is_some() {
                    let held = self
                        .frags
                        .lock()
                        .unwrap()
                        .resolve(key, dst_v6, Instant::now());
                    for f in held {
                        self.inbound_later_fragment(&f, dst_v6);
                    }
                }
            }
            // See outbound: fragmented ICMP is not translated.
            PROTO_ICMP if frag_id.is_none() => self.inbound_icmp(transport, src_v4, hop),
            _ => {}
        }
    }

    /// A non-first IPv4 fragment, sent as an IPv6 fragment to the host its
    /// first fragment went to.
    fn inbound_later_fragment(&self, pkt: &[u8], dst_v6: Ipv6Addr) {
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        let src_v4 = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let Some(src_v6) = self.pref64().and_then(|p| p.embed(src_v4)) else {
            return;
        };
        let (more, offset) = frag_info(pkt);
        let id = u16::from_be_bytes([pkt[4], pkt[5]]);
        let data = &pkt[ihl..];
        let hop = (pkt[8].saturating_sub(1), pkt[1]);
        let mut out = v6_header(src_v6, dst_v6, 44, hop, 8 + data.len());
        out.extend_from_slice(&v6_frag_header(pkt[9], offset, more, id));
        out.extend_from_slice(data);
        self.inside.deliver(Packet::from_slice(&out));
    }

    /// Translate an inbound TCP/UDP packet, or the first fragment of one
    /// (IPv4 ID `frag_id`), to IPv6. Returns the inside host it went to.
    fn inbound_tcpudp(
        &self,
        transport: &[u8],
        proto: u8,
        src_v4: Ipv4Addr,
        hop: Hop,
        frag_id: Option<u16>,
    ) -> Option<Ipv6Addr> {
        let field = if proto == PROTO_TCP { 16 } else { 6 };
        if transport.len() < field + 2 {
            return None;
        }
        let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
        let rk = Nat64RevKey {
            proto,
            port: dst_port,
        };
        let mapping_key = {
            let mut inner = self.inner.lock().unwrap();
            let k = inner.reverse.get(&rk).copied()?;
            if let Some(m) = inner.mappings.get_mut(&k) {
                m.last_active = Instant::now();
                let src_port = u16::from_be_bytes([transport[0], transport[1]]);
                let peer = SocketAddrV4::new(src_v4, src_port);
                m.peers
                    .note(peer, false, tcp_flags(transport, proto), m.last_active);
            }
            k
        };

        let src_v6 = self.pref64().and_then(|p| p.embed(src_v4))?;
        let dst_v6 = mapping_key.ip;
        let outside_ip = self.outside_ipv4()?;

        let mut l4 = transport.to_vec();
        l4[2..4].copy_from_slice(&mapping_key.port.to_be_bytes());
        if proto == PROTO_UDP && transport[6..8] == [0, 0] {
            // IPv4 UDP may omit its checksum, IPv6 UDP may not: compute one
            // (RFC 7915 §4.5), which takes the whole datagram.
            if frag_id.is_some() {
                return None;
            }
            fill_v6_checksum(&mut l4, field, proto, src_v6, dst_v6);
        } else {
            let cs = u16::from_be_bytes([l4[field], l4[field + 1]]);
            let mut cs = csum_replace(
                cs,
                &[
                    &src_v4.octets(),
                    &outside_ip.octets(),
                    &dst_port.to_be_bytes(),
                ],
                &[
                    &src_v6.octets(),
                    &dst_v6.octets(),
                    &mapping_key.port.to_be_bytes(),
                ],
            );
            if proto == PROTO_UDP && cs == 0 {
                cs = 0xFFFF;
            }
            l4[field..field + 2].copy_from_slice(&cs.to_be_bytes());
        }

        let out = match frag_id {
            Some(id) => {
                let mut out = v6_header(src_v6, dst_v6, 44, hop, 8 + l4.len());
                out.extend_from_slice(&v6_frag_header(proto, 0, true, id));
                out.extend_from_slice(&l4);
                out
            }
            None => {
                let mut out = v6_header(src_v6, dst_v6, proto, hop, l4.len());
                out.extend_from_slice(&l4);
                out
            }
        };
        self.inside.deliver(Packet::from_slice(&out));
        Some(dst_v6)
    }

    fn inbound_icmp(&self, icmp: &[u8], src_v4: Ipv4Addr, hop: Hop) {
        // Every ICMP message is rebuilt with a fresh checksum below, so a
        // corrupted one must be caught here rather than laundered.
        if icmp.len() < 8 || checksum(icmp) != 0 {
            return;
        }
        let rest = [icmp[4], icmp[5], icmp[6], icmp[7]];
        // RFC 7915 §4.2: the ICMPv6 type, code and 32-bit field for each
        // ICMPv4 message; anything without a counterpart is dropped.
        let (v6_type, v6_code, word) = match (icmp[0], icmp[1]) {
            (0, 0) => return self.inbound_echo_reply(icmp, src_v4, hop),
            (3, 0 | 1 | 5 | 6 | 7 | 8 | 11 | 12) => (1, 0, 0),
            (3, 9 | 10 | 13 | 15) => (1, 1, 0),
            (3, 3) => (1, 4, 0),
            // Protocol unreachable: a parameter problem at Next Header.
            (3, 2) => (4, 1, 6),
            (3, 4) => {
                let emb_total = icmp
                    .get(10..12)
                    .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
                (
                    2,
                    0,
                    packet_too_big_mtu(u16::from_be_bytes([rest[2], rest[3]]), emb_total),
                )
            }
            (11, 0 | 1) => (3, icmp[1], 0),
            (12, 0 | 2) => match v4_pointer_to_v6(rest[0]) {
                Some(p) => (4, 0, p as u32),
                None => return,
            },
            _ => return,
        };
        self.inbound_icmp_error(icmp, src_v4, hop, v6_type, v6_code, word);
    }

    fn inbound_echo_reply(&self, icmp: &[u8], src_v4: Ipv4Addr, hop: Hop) {
        let id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let rk = Nat64RevKey {
            proto: PROTO_ICMP,
            port: id,
        };
        let mapping_key = {
            let mut inner = self.inner.lock().unwrap();
            let k = match inner.reverse.get(&rk).copied() {
                Some(k) => k,
                None => return,
            };
            if let Some(m) = inner.mappings.get_mut(&k) {
                m.last_active = Instant::now();
                let peer = SocketAddrV4::new(src_v4, 0);
                m.peers.note(peer, false, None, m.last_active);
            }
            k
        };
        let Some(src_v6) = self.pref64().and_then(|p| p.embed(src_v4)) else {
            return;
        };
        let dst_v6 = mapping_key.ip;
        let mut out = v6_header(src_v6, dst_v6, PROTO_ICMPV6, hop, icmp.len());
        out.extend_from_slice(icmp);
        let icmp_off = IPV6_HEADER_LEN;
        out[icmp_off] = 129; // ICMPv6 Echo Reply
        out[icmp_off + 1] = 0;
        out[icmp_off + 4..icmp_off + 6].copy_from_slice(&mapping_key.port.to_be_bytes());
        out[icmp_off + 2..icmp_off + 4].copy_from_slice(&[0, 0]);
        let cs = compute_icmpv6_checksum(src_v6, dst_v6, &out[icmp_off..]);
        out[icmp_off + 2..icmp_off + 4].copy_from_slice(&cs.to_be_bytes());
        self.inside.deliver(Packet::from_slice(&out));
    }

    /// Translate an ICMPv4 error about a packet this NAT64 sent out into the
    /// ICMPv6 error `v6_type`/`v6_code` (with `word` in its second 32-bit
    /// word) about the IPv6 packet it came from (RFC 7915 §4.2 and §4.3).
    fn inbound_icmp_error(
        &self,
        icmp: &[u8],
        src_v4: Ipv4Addr,
        hop: Hop,
        v6_type: u8,
        v6_code: u8,
        word: u32,
    ) {
        let emb = &icmp[8..];
        if emb.len() < IPV4_MIN_HEADER {
            return;
        }
        let emb_ihl = (emb[0] & 0x0F) as usize * 4;
        if emb[0] >> 4 != 4 || emb_ihl < IPV4_MIN_HEADER || emb.len() < emb_ihl + 8 {
            return;
        }
        let emb_proto = emb[9];
        let l4 = &emb[emb_ihl..];
        let emb_dst_v4 = Ipv4Addr::new(emb[16], emb[17], emb[18], emb[19]);
        let (emb_port, remote) = match emb_proto {
            PROTO_TCP | PROTO_UDP => (
                u16::from_be_bytes([l4[0], l4[1]]),
                SocketAddrV4::new(emb_dst_v4, u16::from_be_bytes([l4[2], l4[3]])),
            ),
            PROTO_ICMP if l4[0] == 8 => (
                u16::from_be_bytes([l4[4], l4[5]]),
                SocketAddrV4::new(emb_dst_v4, 0),
            ),
            _ => return,
        };
        if Some(Ipv4Addr::new(emb[12], emb[13], emb[14], emb[15])) != self.outside_ipv4() {
            return;
        }
        let rk = Nat64RevKey {
            proto: emb_proto,
            port: emb_port,
        };
        let mapping_key = {
            let inner = self.inner.lock().unwrap();
            let k = match inner.reverse.get(&rk).copied() {
                Some(k) => k,
                None => return,
            };
            // Only errors about traffic the mapping really sent: anyone could
            // otherwise forge them against an inside host's sessions.
            match inner.mappings.get(&k) {
                Some(m) if m.peers.contains(&remote) => {}
                _ => return,
            }
            k
        };

        let pref = self.pref64();
        let (Some(src_v6), Some(emb_dst_v6)) = (
            pref.and_then(|p| p.embed(src_v4)),
            pref.and_then(|p| p.embed(emb_dst_v4)),
        ) else {
            return;
        };
        let dst_v6 = mapping_key.ip;
        let emb_src_v6 = mapping_key.ip;

        // The quoted IPv6 packet: header rebuilt from the quoted IPv4 one, then
        // as much of the transport data as was quoted, within the 1280-byte
        // IPv6 minimum MTU the whole error must fit (RFC 7915 §4.2).
        let emb_total = u16::from_be_bytes([emb[2], emb[3]]) as usize;
        let emb_nh = if emb_proto == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            emb_proto
        };
        let room = 1280 - 2 * IPV6_HEADER_LEN - 8;
        let quoted_l4 = &l4[..l4.len().min(room)];
        let emb_payload_len = emb_total.saturating_sub(emb_ihl);
        let quoted_hop = (emb[8], emb[1]);
        let mut quote = v6_header(emb_src_v6, emb_dst_v6, emb_nh, quoted_hop, emb_payload_len);
        let l4_off = quote.len();
        quote.extend_from_slice(quoted_l4);
        let q = &mut quote[l4_off..];
        let (s4, d4) = (&emb[12..16], &emb[16..20]);
        let (s6, d6) = (emb_src_v6.octets(), emb_dst_v6.octets());
        let new_port = mapping_key.port.to_be_bytes();
        match emb_proto {
            PROTO_TCP | PROTO_UDP => {
                q[0..2].copy_from_slice(&new_port);
                let field = if emb_proto == PROTO_TCP { 16 } else { 6 };
                if q.len() >= field + 2 && !(emb_proto == PROTO_UDP && q[6..8] == [0, 0]) {
                    let cs = u16::from_be_bytes([q[field], q[field + 1]]);
                    let cs = csum_replace(
                        cs,
                        &[s4, d4, &emb_port.to_be_bytes()],
                        &[&s6, &d6, &new_port],
                    );
                    q[field..field + 2].copy_from_slice(&cs.to_be_bytes());
                }
            }
            _ => {
                // An echo request: ICMPv6 type 128, and the ICMPv6 checksum
                // covers a pseudo-header the ICMPv4 one did not have.
                let old_type = [q[0], q[1]];
                q[0] = 128;
                q[4..6].copy_from_slice(&new_port);
                let len = (emb_payload_len as u32).to_be_bytes();
                let cs = u16::from_be_bytes([q[2], q[3]]);
                let cs = csum_replace(
                    cs,
                    &[&old_type, &emb_port.to_be_bytes()],
                    &[
                        &[q[0], q[1]],
                        &new_port,
                        &s6,
                        &d6,
                        &len,
                        &[0, 0, 0, PROTO_ICMPV6],
                    ],
                );
                q[2..4].copy_from_slice(&cs.to_be_bytes());
            }
        }

        let mut msg = vec![v6_type, v6_code, 0, 0];
        msg.extend_from_slice(&word.to_be_bytes());
        msg.extend_from_slice(&quote);
        let cs = compute_icmpv6_checksum(src_v6, dst_v6, &msg);
        msg[2..4].copy_from_slice(&cs.to_be_bytes());
        let mut out = v6_header(src_v6, dst_v6, PROTO_ICMPV6, hop, msg.len());
        out.extend_from_slice(&msg);
        self.inside.deliver(Packet::from_slice(&out));
    }

    // ---------- Mapping plumbing ----------

    fn get_or_create_mapping(&self, k: Nat64Key) -> Option<(u16, bool)> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(m) = inner.mappings.get_mut(&k) {
            m.last_active = Instant::now();
            return Some((m.outside_port, false));
        }
        let port = Self::alloc_port_locked(&mut inner)?;
        let m = Mapping {
            key: k,
            outside_port: port,
            last_active: Instant::now(),
            peers: Peers::default(),
        };
        inner.reverse.insert(
            Nat64RevKey {
                proto: k.proto,
                port,
            },
            k,
        );
        inner.mappings.insert(k, m);
        Some((port, true))
    }

    fn note_peer(&self, k: Nat64Key, peer: SocketAddrV4, outbound: bool, flags: Option<u8>) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(m) = inner.mappings.get_mut(&k) {
            m.peers.note(peer, outbound, flags, m.last_active);
        }
    }

    fn alloc_port_locked(inner: &mut Nat64Inner) -> Option<u16> {
        let start = inner.next_port;
        loop {
            let p = inner.next_port;
            inner.next_port = if inner.next_port == NAT_PORT_MAX {
                NAT_PORT_MIN
            } else {
                inner.next_port + 1
            };
            let in_use = [PROTO_TCP, PROTO_UDP, PROTO_ICMP]
                .iter()
                .any(|&proto| inner.reverse.contains_key(&Nat64RevKey { proto, port: p }));
            if !in_use {
                return Some(p);
            }
            if inner.next_port == start {
                return None;
            }
        }
    }
}

// ===== nat64Side =====

pub(crate) struct Nat64Side {
    is_inside: bool,
    handler: Mutex<Option<L3Handler>>,
    addr: Mutex<IpPrefix>,
    parent: Mutex<Weak<Nat64>>,
}

impl Nat64Side {
    fn new(is_inside: bool, addr: IpPrefix) -> Nat64Side {
        Nat64Side {
            is_inside,
            handler: Mutex::new(None),
            addr: Mutex::new(addr),
            parent: Mutex::new(Weak::new()),
        }
    }
    fn set_parent(&self, w: Weak<Nat64>) {
        *self.parent.lock().unwrap() = w;
    }
    fn deliver(&self, p: &Packet) {
        let h = self.handler.lock().unwrap().clone();
        if let Some(h) = h {
            let _ = h(p);
        }
    }
}

impl L3Device for Nat64Side {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }
    fn send(&self, packet: &Packet) -> Result<()> {
        let bytes = packet.as_bytes();
        if let Some(nat) = self.parent.lock().unwrap().upgrade() {
            if self.is_inside {
                if bytes.len() >= IPV6_HEADER_LEN && bytes[0] >> 4 == 6 {
                    nat.handle_outbound(bytes);
                }
            } else if bytes.len() >= IPV4_MIN_HEADER && bytes[0] >> 4 == 4 {
                nat.handle_inbound(bytes);
            }
        }
        Ok(())
    }
    fn addr(&self) -> IpPrefix {
        *self.addr.lock().unwrap()
    }
    fn set_addr(&self, p: IpPrefix) -> Result<()> {
        *self.addr.lock().unwrap() = p;
        Ok(())
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}

// ===== Helpers =====

/// The TCP flags byte of a TCP header, `None` for other protocols.
fn tcp_flags(transport: &[u8], proto: u8) -> Option<u8> {
    (proto == PROTO_TCP)
        .then(|| transport.get(13).copied())
        .flatten()
}

/// Whether IPv4 options `opts` hold a Loose or Strict Source Route (RFC 791)
/// whose pointer has not yet run past its last address.
fn unexpired_source_route(opts: &[u8]) -> bool {
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let Some(&len) = opts.get(i + 1) else { break };
                let len = len as usize;
                if len < 2 || i + len > opts.len() {
                    break;
                }
                // The pointer counts from the option's first byte, and is
                // past the route once it exceeds the length.
                if (kind == 131 || kind == 137) && len >= 3 && usize::from(opts[i + 2]) <= len {
                    return true;
                }
                i += len;
            }
        }
    }
    false
}

fn read_v6(b: &[u8]) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[..16]);
    Ipv6Addr::from(a)
}

/// A NAT64 prefix and the RFC 6052 §2.2 layout that goes with its length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pref64 {
    prefix: [u8; 16],
    /// Where the four IPv4 octets sit in the IPv6 address. Octet 8 (bits
    /// 64..71, the "u" octet) is skipped for compatibility with interface
    /// identifiers, which splits the address for prefixes shorter than 64.
    at: [usize; 4],
    bits: u8,
}

/// The Well-Known Prefix, `64:ff9b::/96` (RFC 6052 §2.1).
const WKP: [u8; 12] = [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

impl Pref64 {
    fn new(p: IpPrefix) -> Option<Pref64> {
        let IpAddr::V6(a) = p.addr() else {
            return None;
        };
        let at = match p.bits() {
            32 => [4, 5, 6, 7],
            40 => [5, 6, 7, 9],
            48 => [6, 7, 9, 10],
            56 => [7, 9, 10, 11],
            64 => [9, 10, 11, 12],
            96 => [12, 13, 14, 15],
            _ => return None,
        };
        let mut prefix = [0u8; 16];
        let n = p.bits() as usize / 8;
        prefix[..n].copy_from_slice(&a.octets()[..n]);
        Some(Pref64 {
            prefix,
            at,
            bits: p.bits(),
        })
    }

    fn is_wkp(&self) -> bool {
        self.bits == 96 && self.prefix[..12] == WKP
    }

    /// The IPv6 address standing for `v4`, with the u octet and the suffix
    /// zero. `None` if the prefix cannot represent it: RFC 6052 §3.1 forbids
    /// the Well-Known Prefix for non-global IPv4 addresses.
    fn embed(&self, v4: Ipv4Addr) -> Option<Ipv6Addr> {
        if self.is_wkp() && !is_global_v4(v4) {
            return None;
        }
        let mut o = self.prefix;
        for (i, b) in self.at.iter().zip(v4.octets()) {
            o[*i] = b;
        }
        Some(Ipv6Addr::from(o))
    }

    /// The IPv4 address embedded in `v6`, if it lies under this prefix.
    fn extract(&self, v6: Ipv6Addr) -> Option<Ipv4Addr> {
        let o = v6.octets();
        let n = self.bits as usize / 8;
        if o[..n] != self.prefix[..n] {
            return None;
        }
        let v4 = Ipv4Addr::new(o[self.at[0]], o[self.at[1]], o[self.at[2]], o[self.at[3]]);
        (!self.is_wkp() || is_global_v4(v4)).then_some(v4)
    }
}

/// Close enough to "global" for RFC 6052 §3.1: not private (RFC 1918),
/// shared (RFC 6598), loopback, link-local or otherwise special-use.
fn is_global_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    let shared = o[0] == 100 && (o[1] & 0xC0) == 64;
    !(a.is_private()
        || shared
        || a.is_loopback()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || o[0] == 0
        || o[0] >= 240)
}

fn compute_icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, data: &[u8]) -> u16 {
    transport_checksum(Protocol::ICMPV6, IpAddr::V6(src), IpAddr::V6(dst), data)
}

/// The Fragment Header fields of an IPv6 packet.
#[derive(Clone, Copy, Debug)]
struct V6Frag {
    /// In bytes.
    offset: usize,
    more: bool,
    id: u32,
}

/// The hop count (TTL or Hop Limit) and traffic class (TOS or Traffic
/// Class) of a translated header. RFC 7915 §4.1 and §5.1 copy the traffic
/// class across by default: DSCP keeps the packet's service class, and ECN
/// its congestion marks, which endpoints would otherwise never see.
type Hop = (u8, u8);

/// An IPv4 header (payload to follow) with the given fields and its
/// checksum; `flags` holds the flags and fragment offset word.
fn v4_header(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    (ttl, tos): Hop,
    payload_len: usize,
    id: u16,
    flags: u16,
) -> Vec<u8> {
    let mut h = vec![0u8; IPV4_MIN_HEADER];
    h[0] = 0x45;
    h[1] = tos;
    h[2..4].copy_from_slice(&((IPV4_MIN_HEADER + payload_len) as u16).to_be_bytes());
    h[4..6].copy_from_slice(&id.to_be_bytes());
    h[6..8].copy_from_slice(&flags.to_be_bytes());
    h[8] = ttl;
    h[9] = proto;
    h[12..16].copy_from_slice(&src.octets());
    h[16..20].copy_from_slice(&dst.octets());
    let cs = checksum(&h);
    h[10..12].copy_from_slice(&cs.to_be_bytes());
    h
}

/// An IPv6 Fragment Header for a translated IPv4 fragment (RFC 7915 §4.1.1):
/// the IPv4 ID becomes the low half of the 32-bit identification.
fn v6_frag_header(next: u8, offset: usize, more: bool, id: u16) -> [u8; 8] {
    let fo = (offset as u16 & 0xFFF8) | u16::from(more);
    let mut h = [0u8; 8];
    h[0] = next;
    h[2..4].copy_from_slice(&fo.to_be_bytes());
    h[4..8].copy_from_slice(&u32::from(id).to_be_bytes());
    h
}

/// Compute the checksum at `field` of a whole TCP/UDP segment under an
/// IPv6 pseudo-header.
fn fill_v6_checksum(l4: &mut [u8], field: usize, proto: u8, src: Ipv6Addr, dst: Ipv6Addr) {
    l4[field..field + 2].copy_from_slice(&[0, 0]);
    let mut cs = transport_checksum(Protocol(proto), IpAddr::V6(src), IpAddr::V6(dst), l4);
    if cs == 0 {
        cs = 0xFFFF;
    }
    l4[field..field + 2].copy_from_slice(&cs.to_be_bytes());
}

/// An IPv6 header (payload to follow) with the given fields and a zero
/// flow label.
fn v6_header(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next: u8,
    (hop, tc): Hop,
    payload_len: usize,
) -> Vec<u8> {
    let mut h = vec![0u8; IPV6_HEADER_LEN];
    h[0] = 0x60 | (tc >> 4);
    h[1] = tc << 4;
    h[4..6].copy_from_slice(&(payload_len.min(u16::MAX as usize) as u16).to_be_bytes());
    h[6] = next;
    h[7] = hop;
    h[8..24].copy_from_slice(&src.octets());
    h[24..40].copy_from_slice(&dst.octets());
    h
}

/// The MTU for an ICMPv6 Packet Too Big translated from an ICMPv4
/// Fragmentation Needed advertising `mtu` about a packet of `total_len`
/// bytes (RFC 7915 §4.2): 20 more, for the larger IPv6 header. A router that
/// predates RFC 1191 advertises zero; the likely path MTU is then the largest
/// RFC 1191 plateau below the packet's length.
fn packet_too_big_mtu(mtu: u16, total_len: u16) -> u32 {
    const PLATEAUS: [u16; 11] = [
        65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68,
    ];
    let mtu = if mtu == 0 {
        PLATEAUS.into_iter().find(|&p| p < total_len).unwrap_or(68)
    } else {
        mtu
    };
    mtu as u32 + 20
}

/// RFC 7915 figure 3: where an ICMPv4 Parameter Problem pointer into the
/// IPv4 header lands in the IPv6 header. Fields with no counterpart (ID,
/// flags, fragment offset, header checksum) give `None`.
fn v4_pointer_to_v6(p: u8) -> Option<u8> {
    match p {
        0 => Some(0),
        1 => Some(1),
        2 | 3 => Some(4),
        8 => Some(7),
        9 => Some(6),
        12..=15 => Some(8),
        16..=19 => Some(24),
        _ => None,
    }
}

/// RFC 7915 figure 6: where an ICMPv6 Parameter Problem pointer into the
/// IPv6 header lands in the IPv4 header. The Flow Label, and anything past
/// the header, has no counterpart.
fn v6_pointer_to_v4(p: u32) -> Option<u8> {
    match p {
        0 => Some(0),
        1 => Some(1),
        4 | 5 => Some(2),
        6 => Some(9),
        7 => Some(8),
        8..=23 => Some(12),
        24..=39 => Some(16),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IpPrefix, L3Device, Packet};
    use std::sync::Mutex as StdMutex;

    fn pfx(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    /// Map an IPv4 address into the Well-Known Prefix, as the tests' NAT64
    /// is configured.
    fn wkp(v4: Ipv4Addr) -> Ipv6Addr {
        Pref64::new(pfx("64:ff9b::/96")).unwrap().embed(v4).unwrap()
    }

    #[test]
    fn rfc6052_examples() {
        // RFC 6052 §2.4, with 192.0.2.33.
        let v4 = Ipv4Addr::new(192, 0, 2, 33);
        for (prefix, addr) in [
            ("2001:db8::/32", "2001:db8:c000:221::"),
            ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
            ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100:0"),
            ("2001:db8:122:344::/96", "2001:db8:122:344::192.0.2.33"),
            ("64:ff9b::/96", "64:ff9b::192.0.2.33"),
        ] {
            let p = Pref64::new(pfx(prefix)).unwrap();
            let v6: Ipv6Addr = addr.parse().unwrap();
            assert_eq!(p.embed(v4), Some(v6), "{prefix}");
            assert_eq!(p.extract(v6), Some(v4), "{prefix}");
        }
    }

    #[test]
    fn pref64_rejects_foreign_and_non_global_addresses() {
        let p = Pref64::new(pfx("64:ff9b::/96")).unwrap();
        assert_eq!(p.extract("2001:db8::1".parse().unwrap()), None);
        // IPv4-mapped addresses must never appear on the wire (RFC 4291
        // §2.5.5.2), and are not under the prefix.
        assert_eq!(p.extract("::ffff:8.8.8.8".parse().unwrap()), None);
        // The WKP cannot stand for private IPv4 space (RFC 6052 §3.1).
        assert_eq!(p.embed(Ipv4Addr::new(10, 1, 2, 3)), None);
        assert_eq!(p.extract("64:ff9b::10.1.2.3".parse().unwrap()), None);
        // A network-specific prefix can.
        let nsp = Pref64::new(pfx("2001:db8:64::/96")).unwrap();
        assert!(nsp.embed(Ipv4Addr::new(10, 1, 2, 3)).is_some());
        assert!(Pref64::new(pfx("2001:db8::/60")).is_none());
    }

    #[test]
    fn translates_under_a_network_specific_prefix() {
        let nat = Nat64::new(pfx("2001:db8:122::/48"), pfx("198.51.100.1/24"));
        let captured = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = captured.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let client: Ipv6Addr = "2001:db8:1::100".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8:122:c000:2:2100::".parse().unwrap();
        let pkt = build_v6_udp(client, 5555, dst, 53, b"hello");
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();
        let out = captured.lock().unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0][16..20], &[192, 0, 2, 33]);
    }

    #[test]
    fn ipv4_mapped_destination_is_not_translated() {
        let nat = Nat64::new(pfx("64:ff9b::/96"), pfx("198.51.100.1/24"));
        let captured = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = captured.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let client: Ipv6Addr = "2001:db8::100".parse().unwrap();
        let pkt = build_v6_udp(client, 5555, "::ffff:8.8.8.8".parse().unwrap(), 53, b"x");
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();
        assert!(captured.lock().unwrap().is_empty());
    }

    fn build_v6_udp(
        src: Ipv6Addr,
        sport: u16,
        dst: Ipv6Addr,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total = IPV6_HEADER_LEN + udp_len;
        let mut p = vec![0u8; total];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        p[6] = PROTO_UDP;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p[IPV6_HEADER_LEN..IPV6_HEADER_LEN + 2].copy_from_slice(&sport.to_be_bytes());
        p[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&dport.to_be_bytes());
        p[IPV6_HEADER_LEN + 4..IPV6_HEADER_LEN + 6]
            .copy_from_slice(&(udp_len as u16).to_be_bytes());
        p[IPV6_HEADER_LEN + 8..].copy_from_slice(payload);
        // Compute UDP checksum.
        let mut cs = transport_checksum(
            Protocol::UDP,
            IpAddr::V6(src),
            IpAddr::V6(dst),
            &p[IPV6_HEADER_LEN..],
        );
        if cs == 0 {
            cs = 0xFFFF;
        }
        p[IPV6_HEADER_LEN + 6..IPV6_HEADER_LEN + 8].copy_from_slice(&cs.to_be_bytes());
        p
    }

    #[test]
    fn outbound_udp_v6_to_v4() {
        let nat = Nat64::new(pfx("64:ff9b::/96"), pfx("198.51.100.1/24"));
        let captured = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = captured.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        let client: Ipv6Addr = "2001:db8::100".parse().unwrap();
        let dst = wkp(Ipv4Addr::new(8, 8, 8, 8));
        let pkt = build_v6_udp(client, 5555, dst, 53, b"hello");
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();

        let out = captured.lock().unwrap();
        assert_eq!(out.len(), 1);
        let p = &out[0];
        assert_eq!(p[0] >> 4, 4);
        assert_eq!(&p[12..16], &[198, 51, 100, 1]);
        assert_eq!(&p[16..20], &[8, 8, 8, 8]);
        let mapped_port = u16::from_be_bytes([p[20], p[21]]);
        assert!(mapped_port >= NAT_PORT_MIN);
        let dport = u16::from_be_bytes([p[22], p[23]]);
        assert_eq!(dport, 53);
        assert!(
            crate::nat::l4::v4_l4_checksum_ok(p, 20),
            "translated UDP must carry a valid IPv4 checksum"
        );
    }

    #[test]
    fn round_trip_udp_v4_response_to_v6() {
        let nat = Nat64::new(pfx("64:ff9b::/96"), pfx("198.51.100.1/24"));
        let inbound = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let outbound = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        {
            let c = inbound.clone();
            nat.inside().set_handler(Arc::new(move |p| {
                c.lock().unwrap().push(p.as_bytes().to_vec());
                Ok(())
            }));
        }
        {
            let c = outbound.clone();
            nat.outside().set_handler(Arc::new(move |p| {
                c.lock().unwrap().push(p.as_bytes().to_vec());
                Ok(())
            }));
        }

        let client: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let pkt = build_v6_udp(client, 44000, wkp(Ipv4Addr::new(1, 1, 1, 1)), 53, b"q");
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();
        let outbound_pkts = outbound.lock().unwrap();
        let mapped_port = u16::from_be_bytes([outbound_pkts[0][20], outbound_pkts[0][21]]);
        drop(outbound_pkts);

        // Build IPv4 UDP reply.
        let udp_len = 8 + 4;
        let total = 20 + udp_len;
        let mut reply = vec![0u8; total];
        reply[0] = 0x45;
        reply[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        reply[8] = 64;
        reply[9] = PROTO_UDP;
        reply[12..16].copy_from_slice(&[1, 1, 1, 1]);
        reply[16..20].copy_from_slice(&[198, 51, 100, 1]);
        let ic = checksum(&reply[..20]);
        reply[10..12].copy_from_slice(&ic.to_be_bytes());
        reply[20..22].copy_from_slice(&53u16.to_be_bytes());
        reply[22..24].copy_from_slice(&mapped_port.to_be_bytes());
        reply[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        reply[28..32].copy_from_slice(b"resp");
        // UDP cksum left zero (optional in IPv4).
        nat.outside().send(Packet::from_slice(&reply)).unwrap();

        let inbound_pkts = inbound.lock().unwrap();
        assert_eq!(inbound_pkts.len(), 1);
        let r = &inbound_pkts[0];
        assert_eq!(r[0] >> 4, 6);
        // Destination = original client IPv6.
        assert_eq!(&r[24..40], &client.octets());
        let dport = u16::from_be_bytes([r[IPV6_HEADER_LEN + 2], r[IPV6_HEADER_LEN + 3]]);
        assert_eq!(dport, 44000);
        assert!(
            v6_sum_ok(r),
            "translated UDP must carry a valid IPv6 checksum"
        );
    }

    /// True if the upper-layer checksum of an IPv6 packet without extension
    /// headers verifies.
    fn v6_sum_ok(p: &[u8]) -> bool {
        crate::checksum::raw_transport_sum(
            Protocol(p[6]),
            IpAddr::V6(read_v6(&p[8..24])),
            IpAddr::V6(read_v6(&p[24..40])),
            &p[IPV6_HEADER_LEN..],
        ) == 0xFFFF
    }

    #[test]
    fn echo_round_trip_has_valid_checksums() {
        let nat = Nat64::new(pfx("64:ff9b::/96"), pfx("198.51.100.1/24"));
        let inbound = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let outbound = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = inbound.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let c = outbound.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        let client: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let dst = wkp(Ipv4Addr::new(1, 1, 1, 1));
        let mut req = vec![0u8; IPV6_HEADER_LEN + 12];
        req[0] = 0x60;
        req[4..6].copy_from_slice(&12u16.to_be_bytes());
        req[6] = PROTO_ICMPV6;
        req[7] = 64;
        req[8..24].copy_from_slice(&client.octets());
        req[24..40].copy_from_slice(&dst.octets());
        req[40] = 128;
        req[44..46].copy_from_slice(&0x1234u16.to_be_bytes());
        req[46..48].copy_from_slice(&1u16.to_be_bytes());
        req[48..52].copy_from_slice(b"ping");
        let cs = crate::transport_checksum(
            Protocol::ICMPV6,
            IpAddr::V6(client),
            IpAddr::V6(dst),
            &req[40..],
        );
        req[42..44].copy_from_slice(&cs.to_be_bytes());
        nat.inside().send(Packet::from_slice(&req)).unwrap();

        let out = outbound.lock().unwrap()[0].clone();
        assert_eq!(checksum(&out[20..]), 0, "ICMPv4 echo must verify");
        let id = u16::from_be_bytes([out[24], out[25]]);

        // Echo reply back from 1.1.1.1.
        let mut rep = vec![0u8; 20 + 12];
        rep[0] = 0x45;
        rep[2..4].copy_from_slice(&32u16.to_be_bytes());
        rep[8] = 64;
        rep[9] = PROTO_ICMP;
        rep[12..16].copy_from_slice(&[1, 1, 1, 1]);
        rep[16..20].copy_from_slice(&[198, 51, 100, 1]);
        let ic = checksum(&rep[..20]);
        rep[10..12].copy_from_slice(&ic.to_be_bytes());
        rep[24..26].copy_from_slice(&id.to_be_bytes());
        rep[26..28].copy_from_slice(&1u16.to_be_bytes());
        rep[28..32].copy_from_slice(b"ping");
        let cs = checksum(&rep[20..]);
        rep[22..24].copy_from_slice(&cs.to_be_bytes());
        nat.outside().send(Packet::from_slice(&rep)).unwrap();

        let got = inbound.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0][40], 129);
        assert!(v6_sum_ok(&got[0]), "ICMPv6 echo reply must verify");
    }

    type Captured = Arc<StdMutex<Vec<Vec<u8>>>>;

    fn wired() -> (Arc<Nat64>, Captured, Captured) {
        let nat = Nat64::new(pfx("64:ff9b::/96"), pfx("198.51.100.1/24"));
        let inside: Captured = Arc::default();
        let outside: Captured = Arc::default();
        let c = inside.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let c = outside.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        (nat, inside, outside)
    }

    const CLIENT: &str = "2001:db8::5";
    const SERVER: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
    const ROUTER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

    /// Send one UDP datagram out through the NAT64 and return what left.
    fn send_udp(nat: &Nat64, outside: &Captured) -> Vec<u8> {
        let pkt = build_v6_udp(CLIENT.parse().unwrap(), 5555, wkp(SERVER), 53, b"query");
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();
        outside.lock().unwrap().last().unwrap().clone()
    }

    /// An ICMPv4 error from `from` with the given type, code and second word,
    /// quoting `quoted` whole.
    fn icmp4_error(from: Ipv4Addr, t: u8, code: u8, word: [u8; 4], quoted: &[u8]) -> Vec<u8> {
        let mut msg = vec![t, code, 0, 0];
        msg.extend_from_slice(&word);
        msg.extend_from_slice(quoted);
        let cs = checksum(&msg);
        msg[2..4].copy_from_slice(&cs.to_be_bytes());
        let total = 20 + msg.len();
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_ICMP;
        p[12..16].copy_from_slice(&from.octets());
        p[16..20].copy_from_slice(&[198, 51, 100, 1]);
        let ic = checksum(&p);
        p[10..12].copy_from_slice(&ic.to_be_bytes());
        p.extend_from_slice(&msg);
        p
    }

    /// Translate one ICMPv4 error about an outbound datagram; returns what
    /// reached the inside, if anything.
    fn translate_error(t: u8, code: u8, word: [u8; 4]) -> Option<Vec<u8>> {
        let (nat, inside, outside) = wired();
        let sent = send_udp(&nat, &outside);
        let err = icmp4_error(ROUTER, t, code, word, &sent);
        nat.outside().send(Packet::from_slice(&err)).unwrap();
        inside.lock().unwrap().pop()
    }

    #[test]
    fn fragmentation_needed_becomes_packet_too_big() {
        let (nat, inside, outside) = wired();
        let sent = send_udp(&nat, &outside);
        let err = icmp4_error(ROUTER, 3, 4, [0, 0, 0x05, 0x78], &sent); // MTU 1400
        nat.outside().send(Packet::from_slice(&err)).unwrap();
        let got = inside
            .lock()
            .unwrap()
            .pop()
            .expect("PTB must reach the client");
        assert_eq!(&got[8..24], &wkp(ROUTER).octets());
        assert_eq!(&got[24..40], &CLIENT.parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!((got[40], got[41]), (2, 0));
        assert_eq!(
            u32::from_be_bytes([got[44], got[45], got[46], got[47]]),
            1420
        );
        assert!(v6_sum_ok(&got), "ICMPv6 checksum");

        // The quote is the client's own packet, checksum included.
        let quote = &got[48..];
        assert_eq!(quote[0] >> 4, 6);
        assert_eq!(&quote[8..24], &CLIENT.parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(&quote[24..40], &wkp(SERVER).octets());
        assert_eq!(u16::from_be_bytes([quote[40], quote[41]]), 5555);
        assert!(v6_sum_ok(quote), "quoted UDP checksum");
    }

    #[test]
    fn fragmentation_needed_without_mtu_uses_a_plateau() {
        assert_eq!(packet_too_big_mtu(0, 1500), 1492 + 20);
        assert_eq!(packet_too_big_mtu(1400, 1500), 1420);
    }

    #[test]
    fn destination_unreachable_codes_follow_rfc7915() {
        for (code, want) in [
            (0, Some((1, 0))),
            (1, Some((1, 0))),
            (3, Some((1, 4))),
            (5, Some((1, 0))),
            (9, Some((1, 1))),
            (11, Some((1, 0))),
            (12, Some((1, 0))),
            (13, Some((1, 1))),
            (15, Some((1, 1))),
            (14, None),
        ] {
            let got = translate_error(3, code, [0; 4]);
            assert_eq!(got.map(|g| (g[40], g[41])), want, "code {code}");
        }
        // Protocol unreachable is a parameter problem at Next Header.
        let got = translate_error(3, 2, [0; 4]).unwrap();
        assert_eq!((got[40], got[41]), (4, 1));
        assert_eq!(u32::from_be_bytes([got[44], got[45], got[46], got[47]]), 6);
    }

    #[test]
    fn parameter_problem_pointer_is_translated() {
        // Pointer 9 (Protocol) is the IPv6 Next Header, at 6.
        let got = translate_error(12, 0, [9, 0, 0, 0]).unwrap();
        assert_eq!((got[40], got[41]), (4, 0));
        assert_eq!(u32::from_be_bytes([got[44], got[45], got[46], got[47]]), 6);
        assert!(v6_sum_ok(&got));
        // The IPv4 identification field has no IPv6 counterpart.
        assert!(translate_error(12, 0, [4, 0, 0, 0]).is_none());
    }

    #[test]
    fn time_exceeded_is_translated() {
        let got = translate_error(11, 0, [0; 4]).unwrap();
        assert_eq!((got[40], got[41]), (3, 0));
    }

    #[test]
    fn forged_error_is_dropped() {
        let (nat, inside, outside) = wired();
        let mut sent = send_udp(&nat, &outside);
        // Claim the datagram went somewhere the mapping never sent to.
        sent[16..20].copy_from_slice(&[9, 9, 9, 9]);
        let err = icmp4_error(ROUTER, 3, 4, [0, 0, 5, 0x78], &sent);
        nat.outside().send(Packet::from_slice(&err)).unwrap();
        assert!(inside.lock().unwrap().is_empty());
    }

    #[test]
    fn hop_limit_and_ttl_are_decremented() {
        let (nat, inside, outside) = wired();
        let sent = send_udp(&nat, &outside);
        assert_eq!(sent[8], 63);
        let port = u16::from_be_bytes([sent[20], sent[21]]);
        let mut reply = vec![0u8; 28];
        reply[0] = 0x45;
        reply[2..4].copy_from_slice(&28u16.to_be_bytes());
        reply[8] = 64;
        reply[9] = PROTO_UDP;
        reply[12..16].copy_from_slice(&SERVER.octets());
        reply[16..20].copy_from_slice(&[198, 51, 100, 1]);
        let ic = checksum(&reply[..20]);
        reply[10..12].copy_from_slice(&ic.to_be_bytes());
        reply[20..22].copy_from_slice(&53u16.to_be_bytes());
        reply[22..24].copy_from_slice(&port.to_be_bytes());
        reply[24..26].copy_from_slice(&8u16.to_be_bytes());
        nat.outside().send(Packet::from_slice(&reply)).unwrap();
        assert_eq!(inside.lock().unwrap()[0][7], 63);
    }

    /// A UDP reply from `server`:53 to the NAT64's public `port`, with its
    /// checksum.
    fn v4_reply(server: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut r = vec![0u8; 32];
        r[0] = 0x45;
        r[2..4].copy_from_slice(&32u16.to_be_bytes());
        r[8] = 64;
        r[9] = PROTO_UDP;
        r[12..16].copy_from_slice(&server.octets());
        r[16..20].copy_from_slice(&[198, 51, 100, 1]);
        let ic = checksum(&r[..20]);
        r[10..12].copy_from_slice(&ic.to_be_bytes());
        r[20..22].copy_from_slice(&53u16.to_be_bytes());
        r[22..24].copy_from_slice(&port.to_be_bytes());
        r[24..26].copy_from_slice(&12u16.to_be_bytes());
        r[28..32].copy_from_slice(b"resp");
        crate::nat::l4::fill_v4_l4_checksum(&mut r, 20);
        r
    }

    /// An ICMPv6 error from the client to `to` quoting `quoted`.
    fn icmp6_error(to: Ipv6Addr, t: u8, code: u8, word: [u8; 4], quoted: &[u8]) -> Vec<u8> {
        let client: Ipv6Addr = CLIENT.parse().unwrap();
        let mut msg = vec![t, code, 0, 0];
        msg.extend_from_slice(&word);
        msg.extend_from_slice(quoted);
        let cs = compute_icmpv6_checksum(client, to, &msg);
        msg[2..4].copy_from_slice(&cs.to_be_bytes());
        let mut p = v6_header(client, to, PROTO_ICMPV6, (64, 0), msg.len());
        p.extend_from_slice(&msg);
        p
    }

    /// Have the client answer a server's reply with an ICMPv6 error;
    /// returns what left the outside, if anything, and the reply.
    fn client_error(t: u8, code: u8, word: [u8; 4]) -> (Option<Vec<u8>>, Vec<u8>) {
        let (nat, inside, outside) = wired();
        let sent = send_udp(&nat, &outside);
        outside.lock().unwrap().clear();
        let reply = v4_reply(SERVER, u16::from_be_bytes([sent[20], sent[21]]));
        nat.outside().send(Packet::from_slice(&reply)).unwrap();
        let delivered = inside.lock().unwrap().pop().unwrap();
        let err = icmp6_error(wkp(SERVER), t, code, word, &delivered);
        nat.inside().send(Packet::from_slice(&err)).unwrap();
        let got = outside.lock().unwrap().pop();
        (got, reply)
    }

    #[test]
    fn icmpv6_error_from_the_inside_becomes_icmpv4() {
        let (got, reply) = client_error(1, 4, [0; 4]);
        let e = got.expect("port unreachable must reach the server");
        assert_eq!(&e[12..16], &[198, 51, 100, 1]);
        assert_eq!(&e[16..20], &SERVER.octets());
        assert_eq!(checksum(&e[..20]), 0, "outer IP checksum");
        assert_eq!((e[20], e[21]), (3, 3));
        assert_eq!(checksum(&e[20..]), 0, "ICMPv4 checksum");
        // The quote is the server's own datagram again.
        let q = &e[28..];
        assert_eq!(q[0], 0x45);
        assert_eq!(checksum(&q[..20]), 0, "quoted IP checksum");
        assert_eq!(&q[2..4], &reply[2..4], "quoted total length");
        assert_eq!(q[9], PROTO_UDP);
        assert_eq!(&q[12..20], &reply[12..20]);
        assert_eq!(&q[20..], &reply[20..], "quoted UDP, ports and checksum");
    }

    #[test]
    fn icmpv6_error_types_follow_rfc7915() {
        for ((t, code, word), want) in [
            ((1, 0, [0; 4]), Some((3, 1, [0; 4]))),
            ((1, 1, [0; 4]), Some((3, 10, [0; 4]))),
            ((1, 2, [0; 4]), Some((3, 1, [0; 4]))),
            ((1, 3, [0; 4]), Some((3, 1, [0; 4]))),
            ((1, 5, [0; 4]), None),
            // Packet Too Big: 20 bytes less for the smaller header.
            ((2, 0, [0, 0, 0x05, 0x78]), Some((3, 4, [0, 0, 0x05, 0x64]))),
            ((3, 1, [0; 4]), Some((11, 1, [0; 4]))),
            // Pointer at Next Header (6) is at Protocol (9) in IPv4.
            ((4, 0, [0, 0, 0, 6]), Some((12, 0, [9, 0, 0, 0]))),
            // A Flow Label has nowhere to point in IPv4.
            ((4, 0, [0, 0, 0, 2]), None),
            ((4, 1, [0; 4]), Some((3, 2, [0; 4]))),
            ((4, 2, [0; 4]), None),
        ] {
            let (got, _) = client_error(t, code, word);
            let got = got.map(|e| (e[20], e[21], [e[24], e[25], e[26], e[27]]));
            assert_eq!(got, want, "ICMPv6 {t}/{code}");
        }
    }

    #[test]
    fn packet_too_big_about_a_fragment_allows_for_the_fragment_header() {
        let (nat, inside, outside) = wired();
        let sent = send_udp(&nat, &outside);
        outside.lock().unwrap().clear();
        // The first fragment of the reply: just the UDP header.
        let mut f = v4_reply(SERVER, u16::from_be_bytes([sent[20], sent[21]]));
        f.truncate(28);
        f[2..4].copy_from_slice(&28u16.to_be_bytes());
        f[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        f[6] = 0x20;
        f[10..12].copy_from_slice(&[0, 0]);
        let ic = checksum(&f[..20]);
        f[10..12].copy_from_slice(&ic.to_be_bytes());
        nat.outside().send(Packet::from_slice(&f)).unwrap();
        let delivered = inside.lock().unwrap().pop().unwrap();
        assert_eq!(delivered[6], 44, "translated with a Fragment Header");

        let err = icmp6_error(wkp(SERVER), 2, 0, [0, 0, 0x05, 0x00], &delivered);
        nat.inside().send(Packet::from_slice(&err)).unwrap();
        let e = outside.lock().unwrap().pop().expect("frag needed");
        assert_eq!((e[20], e[21]), (3, 4));
        assert_eq!(u16::from_be_bytes([e[26], e[27]]), 1280 - 28);
        assert_eq!(checksum(&e[20..]), 0);
        // The quoted header is the fragment's again.
        let q = &e[28..];
        assert_eq!(&q[4..8], &f[4..8], "ID, MF and offset");
        assert_eq!(&q[2..4], &f[2..4], "total length");
        assert_eq!(checksum(&q[..20]), 0);
        assert_eq!(&q[20..28], &f[20..28]);
    }

    #[test]
    fn inside_cannot_forge_icmpv6_errors() {
        let (nat, _inside, outside) = wired();
        send_udp(&nat, &outside);
        outside.lock().unwrap().clear();
        // A reply from a server the mapping never exchanged traffic with.
        let other = Ipv4Addr::new(9, 9, 9, 9);
        let src = wkp(other);
        let client: Ipv6Addr = CLIENT.parse().unwrap();
        let mut q = v6_header(src, client, PROTO_UDP, (60, 0), 12);
        let mut udp = [53u16, 5555, 12, 0].map(u16::to_be_bytes).concat();
        udp.extend_from_slice(b"resp");
        fill_v6_checksum(&mut udp, 6, PROTO_UDP, src, client);
        q.extend_from_slice(&udp);
        let err = icmp6_error(src, 1, 4, [0; 4], &q);
        nat.inside().send(Packet::from_slice(&err)).unwrap();
        assert!(outside.lock().unwrap().is_empty());
    }

    #[test]
    fn expiring_hop_limit_is_answered_not_forwarded() {
        let (nat, inside, outside) = wired();
        let mut pkt = build_v6_udp(CLIENT.parse().unwrap(), 5555, wkp(SERVER), 53, b"q");
        pkt[7] = 1;
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();
        assert!(outside.lock().unwrap().is_empty());
        let got = inside.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!((got[0][40], got[0][41]), (3, 0));
    }

    /// Split an IPv6 packet without extension headers into two fragments
    /// (Fragment Header, identification `id`), the first carrying `first`
    /// bytes of its payload.
    fn split_v6(pkt: &[u8], first: usize, id: u32) -> (Vec<u8>, Vec<u8>) {
        let mk = |data: &[u8], off: usize, more: bool| {
            let mut p = pkt[..IPV6_HEADER_LEN].to_vec();
            let len = (8 + data.len()) as u16;
            p[4..6].copy_from_slice(&len.to_be_bytes());
            p[6] = 44;
            let fo = off as u16 | u16::from(more);
            let mut fh = [0u8; 8];
            fh[0] = pkt[6];
            fh[2..4].copy_from_slice(&fo.to_be_bytes());
            fh[4..8].copy_from_slice(&id.to_be_bytes());
            p.extend_from_slice(&fh);
            p.extend_from_slice(data);
            p
        };
        let payload = &pkt[IPV6_HEADER_LEN..];
        (
            mk(&payload[..first], 0, true),
            mk(&payload[first..], first, false),
        )
    }

    fn v4_flags(p: &[u8]) -> (bool, usize) {
        crate::nat::nat::frag_info(p)
    }

    #[test]
    fn outbound_fragments_are_translated_per_rfc7915() {
        let (nat, _inside, outside) = wired();
        let mut data = vec![0x11; 8];
        // Looks like a UDP header to anything that would misread it.
        data.extend_from_slice(&[0x15, 0xB3, 0x00, 0x35, 0, 16, 0, 0]);
        let pkt = build_v6_udp(CLIENT.parse().unwrap(), 5555, wkp(SERVER), 53, &data);
        let (f1, f2) = split_v6(&pkt, 16, 0xDEAD_BEEF);
        nat.inside().send(Packet::from_slice(&f1)).unwrap();
        nat.inside().send(Packet::from_slice(&f2)).unwrap();

        let out = outside.lock().unwrap();
        assert_eq!(out.len(), 2);
        let (a, b) = (&out[0], &out[1]);
        for p in [a, b] {
            assert_eq!(
                u16::from_be_bytes([p[4], p[5]]),
                0xBEEF,
                "ID from the Fragment Header"
            );
            assert_eq!(p[9], PROTO_UDP);
            assert_eq!(checksum(&p[..20]), 0);
        }
        assert_eq!(v4_flags(a), (true, 0));
        assert_eq!(v4_flags(b), (false, 16));
        assert_eq!(&b[20..], &f2[48..], "later fragment data untouched");
        // Reassembled, the datagram's checksum holds.
        let mut whole = a.clone();
        whole.extend_from_slice(&b[20..]);
        let total = whole.len() as u16;
        whole[2..4].copy_from_slice(&total.to_be_bytes());
        whole[6..8].copy_from_slice(&[0, 0]);
        assert!(crate::nat::l4::v4_l4_checksum_ok(&whole, 20));
    }

    /// A fragment reaching past what an IPv4 datagram can hold is dropped:
    /// no receiver could reassemble it.
    #[test]
    fn a_fragment_past_the_ipv4_size_limit_is_dropped() {
        let (nat, _inside, outside) = wired();
        let pkt = build_v6_udp(CLIENT.parse().unwrap(), 5555, wkp(SERVER), 53, &[0x22; 24]);
        let (_, mut far) = split_v6(&pkt, 16, 7);
        let fo = 65_520u16; // + 16 bytes of data + 20 of IPv4 header > 65535
        far[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&fo.to_be_bytes());
        nat.inside().send(Packet::from_slice(&far)).unwrap();
        assert!(outside.lock().unwrap().is_empty());

        let (_, near) = split_v6(&pkt, 16, 8);
        nat.inside().send(Packet::from_slice(&near)).unwrap();
        assert_eq!(
            outside.lock().unwrap().len(),
            1,
            "an ordinary fragment still goes"
        );
    }

    #[test]
    fn outbound_later_fragment_creates_no_mapping() {
        let (nat, _inside, _outside) = wired();
        let pkt = build_v6_udp(CLIENT.parse().unwrap(), 5555, wkp(SERVER), 53, &[0x22; 24]);
        let (_, f2) = split_v6(&pkt, 16, 7);
        nat.inside().send(Packet::from_slice(&f2)).unwrap();
        assert!(nat.inner.lock().unwrap().mappings.is_empty());
    }

    #[test]
    fn inbound_fragments_reach_the_client_in_any_order() {
        let (nat, inside, outside) = wired();
        let sent = send_udp(&nat, &outside);
        let port = u16::from_be_bytes([sent[20], sent[21]]);

        // A 24-byte reply datagram, fragmented 16 + 16.
        let payload = [0x33u8; 24];
        let udp_len = 8 + payload.len();
        let mut d = vec![0u8; 20 + udp_len];
        d[0] = 0x45;
        d[2..4].copy_from_slice(&((20 + udp_len) as u16).to_be_bytes());
        d[8] = 64;
        d[9] = PROTO_UDP;
        d[12..16].copy_from_slice(&SERVER.octets());
        d[16..20].copy_from_slice(&[198, 51, 100, 1]);
        d[20..22].copy_from_slice(&53u16.to_be_bytes());
        d[22..24].copy_from_slice(&port.to_be_bytes());
        d[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        d[28..].copy_from_slice(&payload);
        crate::nat::l4::fill_v4_l4_checksum(&mut d, 20);
        let frag = |data: &[u8], off: usize, more: bool| {
            let mut p = d[..20].to_vec();
            p.extend_from_slice(data);
            let total = p.len() as u16;
            p[2..4].copy_from_slice(&total.to_be_bytes());
            p[4..6].copy_from_slice(&0x7777u16.to_be_bytes());
            let fo = (off / 8) as u16 | if more { 0x2000 } else { 0 };
            p[6..8].copy_from_slice(&fo.to_be_bytes());
            p[10..12].copy_from_slice(&[0, 0]);
            let ic = checksum(&p[..20]);
            p[10..12].copy_from_slice(&ic.to_be_bytes());
            p
        };
        let r1 = frag(&d[20..36], 0, true);
        let r2 = frag(&d[36..], 16, false);
        nat.outside().send(Packet::from_slice(&r2)).unwrap();
        assert!(inside.lock().unwrap().is_empty());
        nat.outside().send(Packet::from_slice(&r1)).unwrap();

        let got = inside.lock().unwrap();
        assert_eq!(got.len(), 2);
        let client: Ipv6Addr = CLIENT.parse().unwrap();
        let mut whole: Vec<u8> = Vec::new();
        let mut firsts = got.iter().filter(|p| p[42..44] == [0, 1]);
        let first = firsts.next().expect("first fragment");
        let last = got
            .iter()
            .find(|p| p[42..44] == [0, 16])
            .expect("last fragment");
        for p in [first, last] {
            assert_eq!(p[6], 44, "Fragment Header");
            assert_eq!(p[40], PROTO_UDP);
            assert_eq!(&p[44..48], &[0, 0, 0x77, 0x77]);
            assert_eq!(&p[24..40], &client.octets());
        }
        // Reassembled, the IPv6 datagram's checksum holds.
        whole.extend_from_slice(&first[..IPV6_HEADER_LEN]);
        whole.extend_from_slice(&first[48..]);
        whole.extend_from_slice(&last[48..]);
        whole[6] = PROTO_UDP;
        let len = (whole.len() - IPV6_HEADER_LEN) as u16;
        whole[4..6].copy_from_slice(&len.to_be_bytes());
        assert_eq!(u16::from_be_bytes([whole[42], whole[43]]), 5555);
        assert!(v6_sum_ok(&whole));
    }

    #[test]
    fn large_unfragmented_packets_get_df() {
        let (nat, _inside, outside) = wired();
        let small = build_v6_udp(CLIENT.parse().unwrap(), 1, wkp(SERVER), 53, &[0; 100]);
        let big = build_v6_udp(CLIENT.parse().unwrap(), 1, wkp(SERVER), 53, &[0; 1300]);
        nat.inside().send(Packet::from_slice(&small)).unwrap();
        nat.inside().send(Packet::from_slice(&big)).unwrap();
        let out = outside.lock().unwrap();
        assert_eq!(out[0][6] & 0x40, 0);
        assert_eq!(out[1][6] & 0x40, 0x40);
    }

    /// Set an IPv6 packet's Traffic Class (no checksum covers it).
    fn set_tc(p: &mut [u8], tc: u8) {
        p[0] = 0x60 | (tc >> 4);
        p[1] = (tc << 4) | (p[1] & 0x0F);
    }

    fn tc_of(p: &[u8]) -> u8 {
        (p[0] << 4) | (p[1] >> 4)
    }

    /// Set an IPv4 packet's TOS, keeping its header checksum.
    fn set_tos(p: &mut [u8], tos: u8) {
        p[1] = tos;
        p[10..12].copy_from_slice(&[0, 0]);
        let ic = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ic.to_be_bytes());
    }

    #[test]
    fn traffic_class_and_tos_carry_dscp_and_ecn() {
        let (nat, inside, outside) = wired();
        // DSCP EF with ECT(1) out; CE marked by a router on the way back.
        let mut pkt = build_v6_udp(CLIENT.parse().unwrap(), 5555, wkp(SERVER), 53, b"q");
        set_tc(&mut pkt, 0xB9);
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();
        let sent = outside.lock().unwrap()[0].clone();
        assert_eq!(sent[1], 0xB9);
        assert_eq!(checksum(&sent[..20]), 0);

        let mut r = v4_reply(SERVER, u16::from_be_bytes([sent[20], sent[21]]));
        set_tos(&mut r, 0xBB);
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        assert_eq!(tc_of(&inside.lock().unwrap()[0]), 0xBB);
    }

    #[test]
    fn inbound_traffic_must_be_addressed_to_the_nat64() {
        let (nat, inside, outside) = wired();
        let sent = send_udp(&nat, &outside);
        let port = u16::from_be_bytes([sent[20], sent[21]]);
        let mut r = v4_reply(SERVER, port);
        r[16..20].copy_from_slice(&[198, 51, 100, 99]);
        r[10..12].copy_from_slice(&[0, 0]);
        let ic = checksum(&r[..20]);
        r[10..12].copy_from_slice(&ic.to_be_bytes());
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        assert!(inside.lock().unwrap().is_empty());
        nat.outside()
            .send(Packet::from_slice(&v4_reply(SERVER, port)))
            .unwrap();
        assert_eq!(inside.lock().unwrap().len(), 1);
    }

    /// `pkt` (a 20-byte-header IPv4 packet) with IP options `opts`, padded
    /// to a 4-byte boundary.
    fn with_options(pkt: &[u8], opts: &[u8]) -> Vec<u8> {
        let mut o = opts.to_vec();
        o.resize(opts.len().div_ceil(4) * 4, 0);
        let mut p = pkt[..20].to_vec();
        p.extend_from_slice(&o);
        p.extend_from_slice(&pkt[20..]);
        p[0] = 0x40 | ((20 + o.len()) / 4) as u8;
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[10..12].copy_from_slice(&[0, 0]);
        let ic = checksum(&p[..20 + o.len()]);
        p[10..12].copy_from_slice(&ic.to_be_bytes());
        p
    }

    #[test]
    fn unexpired_source_route_is_refused() {
        let (nat, inside, outside) = wired();
        let sent = send_udp(&nat, &outside);
        outside.lock().unwrap().clear();
        let port = u16::from_be_bytes([sent[20], sent[21]]);
        let reply = v4_reply(SERVER, port);
        // Loose and strict source routes with a hop still to visit: NOP,
        // then type, length 7, pointer 4, one address.
        for kind in [131, 137] {
            let r = with_options(&reply, &[1, kind, 7, 4, 192, 0, 2, 1]);
            nat.outside().send(Packet::from_slice(&r)).unwrap();
            assert!(inside.lock().unwrap().is_empty(), "option {kind}");
            let err = outside.lock().unwrap().pop().expect("an ICMP error");
            assert_eq!(&err[16..20], &SERVER.octets());
            assert_eq!((err[9], err[20], err[21]), (PROTO_ICMP, 3, 5));
        }
        // A route already followed to its end is just ignored, like any
        // other option.
        let r = with_options(&reply, &[131, 7, 8, 192, 0, 2, 1]);
        nat.outside().send(Packet::from_slice(&r)).unwrap();
        assert_eq!(inside.lock().unwrap().len(), 1);
        assert!(outside.lock().unwrap().is_empty());
    }

    #[test]
    fn packet_too_large_for_ipv4_gets_packet_too_big() {
        let (nat, inside, outside) = wired();
        // The largest IPv6 payload, which no IPv4 header can describe.
        let big = build_v6_udp(CLIENT.parse().unwrap(), 1, wkp(SERVER), 53, &[0; 65527]);
        nat.inside().send(Packet::from_slice(&big)).unwrap();
        assert!(
            outside.lock().unwrap().is_empty(),
            "sent a malformed packet"
        );
        {
            let got = inside.lock().unwrap();
            assert_eq!(got.len(), 1);
            assert_eq!(got[0][40], 2, "Packet Too Big");
            let mtu = u32::from_be_bytes([got[0][44], got[0][45], got[0][46], got[0][47]]);
            assert_eq!(mtu, 65535 + 20);
            assert!(v6_sum_ok(&got[0]));
        }

        // The largest that does fit goes through.
        let fits = build_v6_udp(CLIENT.parse().unwrap(), 1, wkp(SERVER), 53, &[0; 65507]);
        nat.inside().send(Packet::from_slice(&fits)).unwrap();
        let out = outside.lock().unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(u16::from_be_bytes([out[0][2], out[0][3]]), 65535);
    }

    #[test]
    fn traffic_to_the_nat64s_own_address_does_not_leave() {
        let (nat, inside, outside) = wired();
        let me = wkp(Ipv4Addr::new(198, 51, 100, 1));
        let a: Ipv6Addr = CLIENT.parse().unwrap();
        let b: Ipv6Addr = "2001:db8::6".parse().unwrap();

        // A ping is answered by the NAT64.
        let mut req = vec![0u8; IPV6_HEADER_LEN + 12];
        req[0] = 0x60;
        req[4..6].copy_from_slice(&12u16.to_be_bytes());
        req[6] = PROTO_ICMPV6;
        req[7] = 64;
        req[8..24].copy_from_slice(&a.octets());
        req[24..40].copy_from_slice(&me.octets());
        req[40] = 128;
        req[44..48].copy_from_slice(&[0x12, 0x34, 0, 1]);
        req[48..52].copy_from_slice(b"ping");
        let cs = compute_icmpv6_checksum(a, me, &req[40..]);
        req[42..44].copy_from_slice(&cs.to_be_bytes());
        nat.inside().send(Packet::from_slice(&req)).unwrap();
        assert!(outside.lock().unwrap().is_empty(), "ping sent upstream");
        {
            let got = inside.lock().unwrap();
            assert_eq!(got.len(), 1);
            assert_eq!(read_v6(&got[0][8..24]), me);
            assert_eq!(read_v6(&got[0][24..40]), a);
            assert_eq!(got[0][40], 129);
            assert_eq!(&got[0][44..], &req[44..]);
            assert!(v6_sum_ok(&got[0]));
        }
        inside.lock().unwrap().clear();

        // B's session through the NAT64 gives it a public port; A reaches
        // it there, hairpinned, and B sees A's public endpoint.
        let pkt = build_v6_udp(b, 7000, wkp(SERVER), 53, b"q");
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();
        let b_port = u16::from_be_bytes({
            let o = outside.lock().unwrap();
            [o[0][20], o[0][21]]
        });
        outside.lock().unwrap().clear();
        let pkt = build_v6_udp(a, 5555, me, b_port, b"hi");
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();
        assert!(outside.lock().unwrap().is_empty(), "hairpin sent upstream");
        let got = inside.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(read_v6(&got[0][8..24]), me);
        assert_eq!(read_v6(&got[0][24..40]), b);
        assert_eq!(u16::from_be_bytes([got[0][42], got[0][43]]), 7000);
        assert!(v6_sum_ok(&got[0]));
    }
}
