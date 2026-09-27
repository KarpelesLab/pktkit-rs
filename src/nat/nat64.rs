//! NAT64 (RFC 6146): IPv6-to-IPv4 translation. IPv4 hosts appear on the
//! IPv6 side as IPv4-embedded addresses under the NAT64 prefix (RFC 6052),
//! e.g. `64:ff9b::192.0.2.33` for the Well-Known Prefix.
//!
//! Inside faces IPv6; outside faces IPv4. Only the happy paths for TCP, UDP
//! and ICMP echo are implemented; ICMP error translation covers Destination
//! Unreachable and Time Exceeded (mapping ICMPv4 → ICMPv6 codes per
//! RFC 6145 §4.2). Fragment and extension-header handling is best-effort.

use crate::nat::helper::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use crate::nat::track::Peers;
use crate::time::Instant;
use crate::{
    IpPrefix, L3Device, L3Handler, Packet, Protocol, Result, checksum, transport_checksum,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};
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

    // ---------- Outbound (IPv6 -> IPv4) ----------

    fn handle_outbound(&self, pkt: &[u8]) {
        if pkt.len() < IPV6_HEADER_LEN || pkt[0] >> 4 != 6 {
            return;
        }
        let dst_v6 = read_v6(&pkt[24..40]);
        let Some(dst_v4) = self.pref64().and_then(|p| p.extract(dst_v6)) else {
            return;
        };
        let hop = pkt[7];
        let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
        let src_v6 = read_v6(&pkt[8..24]);

        if pkt.len() < IPV6_HEADER_LEN + payload_len {
            return;
        }

        // Walk extension headers.
        let mut next_header = pkt[6];
        let mut transport_off = IPV6_HEADER_LEN;
        loop {
            match next_header {
                0 | 43 | 60 => {
                    if transport_off + 2 > pkt.len() {
                        return;
                    }
                    let ext_len = (pkt[transport_off + 1] as usize + 1) * 8;
                    next_header = pkt[transport_off];
                    transport_off += ext_len;
                    continue;
                }
                44 => {
                    if transport_off + 8 > pkt.len() {
                        return;
                    }
                    next_header = pkt[transport_off];
                    transport_off += 8;
                    continue;
                }
                _ => break,
            }
        }
        if transport_off > pkt.len() {
            return;
        }
        let transport = &pkt[transport_off..];

        match next_header {
            PROTO_TCP | PROTO_UDP => {
                self.outbound_tcpudp(transport, next_header, src_v6, dst_v4, hop)
            }
            PROTO_ICMPV6 => self.outbound_icmpv6(transport, src_v6, dst_v4, hop),
            _ => {}
        }
    }

    fn outbound_tcpudp(
        &self,
        transport: &[u8],
        proto: u8,
        src_v6: Ipv6Addr,
        dst_v4: Ipv4Addr,
        hop_limit: u8,
    ) {
        if transport.len() < 4 {
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

        let outside_ip = match self.outside_ipv4() {
            Some(a) => a,
            None => return,
        };

        let total_len = IPV4_MIN_HEADER + transport.len();
        let mut out = vec![0u8; total_len];
        out[0] = 0x45;
        out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        out[8] = hop_limit;
        out[9] = proto;
        out[12..16].copy_from_slice(&outside_ip.octets());
        out[16..20].copy_from_slice(&dst_v4.octets());
        out[IPV4_MIN_HEADER..].copy_from_slice(transport);

        // Rewrite source port to mapped port.
        out[IPV4_MIN_HEADER..IPV4_MIN_HEADER + 2].copy_from_slice(&outside_port.to_be_bytes());

        let tslice_len = out.len() - IPV4_MIN_HEADER;
        if proto == PROTO_TCP && tslice_len >= 18 {
            let off = IPV4_MIN_HEADER + 16;
            out[off..off + 2].copy_from_slice(&[0, 0]);
            let cs = compute_transport_checksum(
                Protocol(proto),
                IpAddr::V4(outside_ip),
                IpAddr::V4(dst_v4),
                &out[IPV4_MIN_HEADER..],
            );
            out[off..off + 2].copy_from_slice(&cs.to_be_bytes());
        } else if proto == PROTO_UDP && tslice_len >= 8 {
            let off = IPV4_MIN_HEADER + 6;
            out[off..off + 2].copy_from_slice(&[0, 0]);
            let mut cs = compute_transport_checksum(
                Protocol(proto),
                IpAddr::V4(outside_ip),
                IpAddr::V4(dst_v4),
                &out[IPV4_MIN_HEADER..],
            );
            if cs == 0 {
                cs = 0xFFFF;
            }
            out[off..off + 2].copy_from_slice(&cs.to_be_bytes());
        }

        out[10..12].copy_from_slice(&[0, 0]);
        let ic = checksum(&out[..IPV4_MIN_HEADER]);
        out[10..12].copy_from_slice(&ic.to_be_bytes());

        self.outside.deliver(Packet::from_slice(&out));
    }

    fn outbound_icmpv6(&self, icmp: &[u8], src_v6: Ipv6Addr, dst_v4: Ipv4Addr, hop: u8) {
        if icmp.len() < 8 {
            return;
        }
        if icmp[0] != 128 {
            // Only Echo Request → Echo Request is translated outbound.
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

        let outside_ip = match self.outside_ipv4() {
            Some(a) => a,
            None => return,
        };
        let total = IPV4_MIN_HEADER + icmp.len();
        let mut out = vec![0u8; total];
        out[0] = 0x45;
        out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        out[8] = hop;
        out[9] = PROTO_ICMP;
        out[12..16].copy_from_slice(&outside_ip.octets());
        out[16..20].copy_from_slice(&dst_v4.octets());
        out[IPV4_MIN_HEADER..].copy_from_slice(icmp);
        let icmp_off = IPV4_MIN_HEADER;
        out[icmp_off] = 8; // ICMPv4 Echo Request
        out[icmp_off + 1] = 0;
        out[icmp_off + 4..icmp_off + 6].copy_from_slice(&outside_port.to_be_bytes());
        out[icmp_off + 2..icmp_off + 4].copy_from_slice(&[0, 0]);
        let cs = checksum(&out[icmp_off..]);
        out[icmp_off + 2..icmp_off + 4].copy_from_slice(&cs.to_be_bytes());

        out[10..12].copy_from_slice(&[0, 0]);
        let ic = checksum(&out[..IPV4_MIN_HEADER]);
        out[10..12].copy_from_slice(&ic.to_be_bytes());
        self.outside.deliver(Packet::from_slice(&out));
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
        let transport = &pkt[ihl..total];
        let ttl = pkt[8];
        let src_v4 = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);

        match proto {
            PROTO_TCP | PROTO_UDP => self.inbound_tcpudp(transport, proto, src_v4, ttl),
            PROTO_ICMP => self.inbound_icmp(transport, src_v4, ttl),
            _ => {}
        }
    }

    fn inbound_tcpudp(&self, transport: &[u8], proto: u8, src_v4: Ipv4Addr, ttl: u8) {
        if transport.len() < 4 {
            return;
        }
        let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
        let rk = Nat64RevKey {
            proto,
            port: dst_port,
        };
        let mapping_key = {
            let mut inner = self.inner.lock().unwrap();
            let k = match inner.reverse.get(&rk).copied() {
                Some(k) => k,
                None => return,
            };
            if let Some(m) = inner.mappings.get_mut(&k) {
                m.last_active = Instant::now();
                let src_port = u16::from_be_bytes([transport[0], transport[1]]);
                let peer = SocketAddrV4::new(src_v4, src_port);
                m.peers
                    .note(peer, false, tcp_flags(transport, proto), m.last_active);
            }
            k
        };

        let Some(src_v6) = self.pref64().and_then(|p| p.embed(src_v4)) else {
            return;
        };
        let dst_v6 = mapping_key.ip;
        let out_len = IPV6_HEADER_LEN + transport.len();
        let mut out = vec![0u8; out_len];
        out[0] = 0x60;
        out[4..6].copy_from_slice(&(transport.len() as u16).to_be_bytes());
        out[6] = proto;
        out[7] = ttl;
        out[8..24].copy_from_slice(&src_v6.octets());
        out[24..40].copy_from_slice(&dst_v6.octets());
        out[IPV6_HEADER_LEN..].copy_from_slice(transport);

        // Restore original destination port.
        out[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4]
            .copy_from_slice(&mapping_key.port.to_be_bytes());

        let tslice_len = out.len() - IPV6_HEADER_LEN;
        if proto == PROTO_TCP && tslice_len >= 18 {
            let off = IPV6_HEADER_LEN + 16;
            out[off..off + 2].copy_from_slice(&[0, 0]);
            let cs = compute_transport_checksum(
                Protocol(proto),
                IpAddr::V6(src_v6),
                IpAddr::V6(dst_v6),
                &out[IPV6_HEADER_LEN..],
            );
            out[off..off + 2].copy_from_slice(&cs.to_be_bytes());
        } else if proto == PROTO_UDP && tslice_len >= 8 {
            let off = IPV6_HEADER_LEN + 6;
            out[off..off + 2].copy_from_slice(&[0, 0]);
            let mut cs = compute_transport_checksum(
                Protocol(proto),
                IpAddr::V6(src_v6),
                IpAddr::V6(dst_v6),
                &out[IPV6_HEADER_LEN..],
            );
            if cs == 0 {
                cs = 0xFFFF;
            }
            out[off..off + 2].copy_from_slice(&cs.to_be_bytes());
        }

        self.inside.deliver(Packet::from_slice(&out));
    }

    fn inbound_icmp(&self, icmp: &[u8], src_v4: Ipv4Addr, ttl: u8) {
        if icmp.len() < 8 {
            return;
        }
        match icmp[0] {
            0 => self.inbound_echo_reply(icmp, src_v4, ttl),
            3 => {
                let (v6t, v6c) = icmpv4_to_v6_dest_unreach(icmp[1]);
                if v6t != 0 {
                    self.inbound_icmp_error(icmp, src_v4, ttl, v6t, v6c);
                }
            }
            11 => self.inbound_icmp_error(icmp, src_v4, ttl, 3, icmp[1]),
            _ => {}
        }
    }

    fn inbound_echo_reply(&self, icmp: &[u8], src_v4: Ipv4Addr, ttl: u8) {
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
        let out_len = IPV6_HEADER_LEN + icmp.len();
        let mut out = vec![0u8; out_len];
        out[0] = 0x60;
        out[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
        out[6] = PROTO_ICMPV6;
        out[7] = ttl;
        out[8..24].copy_from_slice(&src_v6.octets());
        out[24..40].copy_from_slice(&dst_v6.octets());
        out[IPV6_HEADER_LEN..].copy_from_slice(icmp);
        let icmp_off = IPV6_HEADER_LEN;
        out[icmp_off] = 129; // ICMPv6 Echo Reply
        out[icmp_off + 1] = 0;
        out[icmp_off + 4..icmp_off + 6].copy_from_slice(&mapping_key.port.to_be_bytes());
        out[icmp_off + 2..icmp_off + 4].copy_from_slice(&[0, 0]);
        let cs = compute_icmpv6_checksum(src_v6, dst_v6, &out[icmp_off..]);
        out[icmp_off + 2..icmp_off + 4].copy_from_slice(&cs.to_be_bytes());
        self.inside.deliver(Packet::from_slice(&out));
    }

    fn inbound_icmp_error(&self, icmp: &[u8], src_v4: Ipv4Addr, ttl: u8, v6_type: u8, v6_code: u8) {
        if icmp.len() < 8 + IPV4_MIN_HEADER {
            return;
        }
        let emb_off = 8;
        let emb_ihl = (icmp[emb_off] & 0x0F) as usize * 4;
        if emb_ihl < IPV4_MIN_HEADER || icmp.len() < emb_off + emb_ihl + 4 {
            return;
        }
        let emb_proto_raw = icmp[emb_off + 9];
        let (emb_proto_lookup, emb_port) = match emb_proto_raw {
            PROTO_TCP | PROTO_UDP => (
                emb_proto_raw,
                u16::from_be_bytes([icmp[emb_off + emb_ihl], icmp[emb_off + emb_ihl + 1]]),
            ),
            PROTO_ICMP => {
                if icmp.len() < emb_off + emb_ihl + 6 {
                    return;
                }
                (
                    PROTO_ICMP,
                    u16::from_be_bytes([icmp[emb_off + emb_ihl + 4], icmp[emb_off + emb_ihl + 5]]),
                )
            }
            _ => return,
        };
        let rk = Nat64RevKey {
            proto: emb_proto_lookup,
            port: emb_port,
        };
        let mapping_key = {
            let mut inner = self.inner.lock().unwrap();
            let k = match inner.reverse.get(&rk).copied() {
                Some(k) => k,
                None => return,
            };
            if let Some(m) = inner.mappings.get_mut(&k) {
                m.last_active = Instant::now();
            }
            k
        };

        let Some(src_v6) = self.pref64().and_then(|p| p.embed(src_v4)) else {
            return;
        };
        let dst_v6 = mapping_key.ip;
        let emb_transport_len = icmp.len().saturating_sub(emb_off + emb_ihl);
        let emb_ipv6_len = IPV6_HEADER_LEN + emb_transport_len;
        let icmpv6_len = 8 + emb_ipv6_len;
        let out_len = IPV6_HEADER_LEN + icmpv6_len;

        let mut out = vec![0u8; out_len];
        out[0] = 0x60;
        out[4..6].copy_from_slice(&(icmpv6_len as u16).to_be_bytes());
        out[6] = PROTO_ICMPV6;
        out[7] = ttl;
        out[8..24].copy_from_slice(&src_v6.octets());
        out[24..40].copy_from_slice(&dst_v6.octets());

        let icmp_off = IPV6_HEADER_LEN;
        out[icmp_off] = v6_type;
        out[icmp_off + 1] = v6_code;
        // bytes 2..4 = checksum, 4..8 = zero

        let emb_off_out = icmp_off + 8;
        out[emb_off_out] = 0x60;
        out[emb_off_out + 4..emb_off_out + 6]
            .copy_from_slice(&(emb_transport_len as u16).to_be_bytes());
        let emb_nh = if emb_proto_raw == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            emb_proto_raw
        };
        out[emb_off_out + 6] = emb_nh;
        out[emb_off_out + 7] = icmp[emb_off + 8]; // original TTL

        // Embedded source IPv6 = original inside client (mapping key).
        out[emb_off_out + 8..emb_off_out + 24].copy_from_slice(&dst_v6.octets());
        // Embedded destination = original dst IPv4, IPv4-mapped.
        let emb_dst_v4 = Ipv4Addr::new(
            icmp[emb_off + 16],
            icmp[emb_off + 17],
            icmp[emb_off + 18],
            icmp[emb_off + 19],
        );
        let Some(emb_dst_v6) = self.pref64().and_then(|p| p.embed(emb_dst_v4)) else {
            return;
        };
        out[emb_off_out + 24..emb_off_out + 40].copy_from_slice(&emb_dst_v6.octets());

        if emb_transport_len > 0 {
            let emb_ip6_off = emb_off_out + IPV6_HEADER_LEN;
            let copy_from = emb_off + emb_ihl;
            out[emb_ip6_off..emb_ip6_off + emb_transport_len]
                .copy_from_slice(&icmp[copy_from..copy_from + emb_transport_len]);
            let emb_transport_off = emb_ip6_off;
            match emb_proto_raw {
                PROTO_TCP | PROTO_UDP if emb_transport_len >= 2 => {
                    out[emb_transport_off..emb_transport_off + 2]
                        .copy_from_slice(&mapping_key.port.to_be_bytes());
                }
                PROTO_ICMP if emb_transport_len >= 6 => {
                    out[emb_transport_off] = 128;
                    out[emb_transport_off + 4..emb_transport_off + 6]
                        .copy_from_slice(&mapping_key.port.to_be_bytes());
                }
                _ => {}
            }
        }

        out[icmp_off + 2..icmp_off + 4].copy_from_slice(&[0, 0]);
        let cs = compute_icmpv6_checksum(src_v6, dst_v6, &out[icmp_off..]);
        out[icmp_off + 2..icmp_off + 4].copy_from_slice(&cs.to_be_bytes());

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

fn compute_transport_checksum(proto: Protocol, src: IpAddr, dst: IpAddr, segment: &[u8]) -> u16 {
    transport_checksum(proto, src, dst, segment)
}

fn compute_icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, data: &[u8]) -> u16 {
    transport_checksum(Protocol::ICMPV6, IpAddr::V6(src), IpAddr::V6(dst), data)
}

fn icmpv4_to_v6_dest_unreach(code: u8) -> (u8, u8) {
    match code {
        0 => (1, 0),
        1 => (1, 0),
        2 => (4, 1),
        3 => (1, 4),
        4 => (0, 0), // Packet Too Big — handled separately, drop here.
        5 => (1, 5),
        6 | 7 => (1, 0),
        9 | 10 => (1, 1),
        13 => (1, 1),
        _ => (0, 0),
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
        let mut cs = compute_transport_checksum(
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
}
