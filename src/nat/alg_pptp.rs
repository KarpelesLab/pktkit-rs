//! PPTP Application Layer Gateway.
//!
//! Tracks PPTP control-channel messages (TCP/1723) to learn each Call-ID of
//! the associated GRE (IP protocol 47) tunnel.
//!
//! Note: actual GRE data forwarding requires NAT-core support for protocol 47
//! (including rewriting the Call-ID in the enhanced-GRE key field). The NAT
//! core here handles only TCP/UDP/ICMP, so this helper only records the calls
//! for a future GRE-aware core. It registers no NAT expectations: nothing
//! could ever match one, and each would sit in the table until it expired.
//!
//! Port of `alg_pptp.go`.

use crate::nat::helper::{Helper, NatMapping, PROTO_TCP, PacketHelper};
use crate::nat::nat::Nat;
use crate::time::Instant;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::Duration;

const PPTP_PORT: u16 = 1723;
const PPTP_MAGIC_COOKIE: u32 = 0x1A2B_3C4D;
const PPTP_GRE_TIMEOUT: Duration = Duration::from_secs(120);
/// How often the call table is swept of stale calls. A sweep walks the
/// whole table (up to 65536 calls, one per ID), so not on every message.
const PPTP_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

// PPTP control message types.
const PPTP_OUTGOING_CALL_REQ: u16 = 7;
const PPTP_OUTGOING_CALL_REPLY: u16 = 8;

/// Per-call state learned from the control channel.
#[derive(Debug, Clone, Copy)]
struct PptpCallInfo {
    #[allow(dead_code)]
    inside_call_id: u16,
    #[allow(dead_code)]
    outside_call_id: u16,
    peer_call_id: u16,
    #[allow(dead_code)]
    inside_ip: Ipv4Addr,
    created: Instant,
}

/// PPTP ALG: tracks the calls on the TCP 1723 control channel. The NAT does
/// not translate GRE, so this only records them (see the module notes in
/// `alg_pptp.rs`). Construct with [`new`](Self::new) and
/// register with
/// [`Nat::add_packet_helper`](crate::nat::Nat::add_packet_helper).
#[derive(Debug)]
pub struct PptpHelper {
    calls: Mutex<Calls>,
}

/// The calls, indexed by call ID, and when they are next swept.
#[derive(Debug)]
struct Calls {
    by_id: HashMap<u16, PptpCallInfo>,
    next_cleanup: Instant,
}

impl Calls {
    /// Record `info` under `call_id`, first sweeping stale calls if
    /// [`PPTP_CLEANUP_INTERVAL`] has passed: a stale call lingers a while
    /// longer, but no message pays for a walk of the table.
    fn insert(&mut self, call_id: u16, info: PptpCallInfo) {
        let now = info.created;
        if now >= self.next_cleanup {
            self.next_cleanup = now + PPTP_CLEANUP_INTERVAL;
            self.by_id
                .retain(|_, c| now.saturating_duration_since(c.created) <= PPTP_GRE_TIMEOUT);
        }
        self.by_id.insert(call_id, info);
    }
}

impl Default for PptpHelper {
    fn default() -> Self {
        PptpHelper::new()
    }
}

impl PptpHelper {
    /// A new PPTP helper.
    pub fn new() -> PptpHelper {
        PptpHelper {
            calls: Mutex::new(Calls {
                by_id: HashMap::new(),
                next_cleanup: Instant::now() + PPTP_CLEANUP_INTERVAL,
            }),
        }
    }
}

impl Helper for PptpHelper {
    fn name(&self) -> &str {
        "pptp"
    }
}

impl PacketHelper for PptpHelper {
    fn match_outbound(&self, proto: u8, dst_port: u16) -> bool {
        proto == PROTO_TCP && dst_port == PPTP_PORT
    }

    fn process_outbound(&self, _nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
        let payload = match payload(&pkt) {
            Some(p) => p,
            None => return pkt,
        };
        let (msg_type, ctrl_type) = match pptp_parse_header(payload) {
            Some(v) => v,
            None => return pkt,
        };
        if msg_type != 1 {
            return pkt;
        }
        let inside_ip = match m.inside_ip {
            IpAddr::V4(a) => a,
            _ => return pkt,
        };

        match ctrl_type {
            PPTP_OUTGOING_CALL_REQ => {
                // Outgoing-Call-Request: Call-ID at bytes 12-13.
                if payload.len() < 14 {
                    return pkt;
                }
                let call_id = u16::from_be_bytes([payload[12], payload[13]]);
                if call_id == 0 {
                    return pkt;
                }
                {
                    let mut calls = self.calls.lock().unwrap();
                    calls.insert(
                        call_id,
                        PptpCallInfo {
                            inside_call_id: call_id,
                            outside_call_id: call_id,
                            peer_call_id: 0,
                            inside_ip,
                            created: Instant::now(),
                        },
                    );
                }
            }
            PPTP_OUTGOING_CALL_REPLY => {
                // Outgoing-Call-Reply: Call-ID 12-13, Peer-Call-ID 14-15.
                if payload.len() < 16 {
                    return pkt;
                }
                let call_id = u16::from_be_bytes([payload[12], payload[13]]);
                let peer_call_id = u16::from_be_bytes([payload[14], payload[15]]);
                {
                    let mut calls = self.calls.lock().unwrap();
                    calls.insert(
                        call_id,
                        PptpCallInfo {
                            inside_call_id: call_id,
                            outside_call_id: call_id,
                            peer_call_id,
                            inside_ip,
                            created: Instant::now(),
                        },
                    );
                }
            }
            _ => {}
        }
        pkt
    }

    fn process_inbound(&self, _nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
        let payload = match payload(&pkt) {
            Some(p) => p,
            None => return pkt,
        };
        let (msg_type, ctrl_type) = match pptp_parse_header(payload) {
            Some(v) => v,
            None => return pkt,
        };
        if msg_type != 1 {
            return pkt;
        }
        let inside_ip = match m.inside_ip {
            IpAddr::V4(a) => a,
            _ => return pkt,
        };

        match ctrl_type {
            PPTP_OUTGOING_CALL_REPLY => {
                // Server reply: Call-ID 12-13 is the server's, Peer-Call-ID
                // 14-15 is our (client's) call ID.
                if payload.len() < 16 {
                    return pkt;
                }
                let server_call_id = u16::from_be_bytes([payload[12], payload[13]]);
                let peer_call_id = u16::from_be_bytes([payload[14], payload[15]]);
                // Only a live call of the host the reply reached: sweeps
                // are lazy, so a lapsed call, or one whose ID another host
                // has since reused, may still be listed.
                let now = Instant::now();
                let mut calls = self.calls.lock().unwrap();
                if let Some(info) = calls.by_id.get_mut(&peer_call_id) {
                    if now.saturating_duration_since(info.created) > PPTP_GRE_TIMEOUT {
                        calls.by_id.remove(&peer_call_id);
                    } else if info.inside_ip == inside_ip {
                        info.peer_call_id = server_call_id;
                    }
                }
            }
            PPTP_OUTGOING_CALL_REQ => {
                if payload.len() < 14 {
                    return pkt;
                }
                let call_id = u16::from_be_bytes([payload[12], payload[13]]);
                let mut calls = self.calls.lock().unwrap();
                calls.insert(
                    call_id,
                    PptpCallInfo {
                        inside_call_id: call_id,
                        outside_call_id: call_id,
                        peer_call_id: 0,
                        inside_ip,
                        created: Instant::now(),
                    },
                );
            }
            _ => {}
        }
        pkt
    }
}

/// Returns the TCP payload, or `None` if malformed/too short.
fn payload(pkt: &[u8]) -> Option<&[u8]> {
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 20 {
        return None;
    }
    let tcp_hdr_len = (pkt[ihl + 12] >> 4) as usize * 4;
    let off = ihl + tcp_hdr_len;
    if off >= pkt.len() {
        return None;
    }
    Some(&pkt[off..])
}

/// Validate and parse a PPTP control message header.
///
/// Layout: `[0..2]` length, `[2..4]` message type (1 = control), `[4..8]` magic
/// cookie `0x1A2B3C4D`, `[8..10]` control message type. Returns
/// `(msg_type, ctrl_type)` on success.
fn pptp_parse_header(payload: &[u8]) -> Option<(u16, u16)> {
    if payload.len() < 10 {
        return None;
    }
    let length = u16::from_be_bytes([payload[0], payload[1]]);
    if length as usize > payload.len() || length < 10 {
        return None;
    }
    let msg_type = u16::from_be_bytes([payload[2], payload[3]]);
    let magic = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if magic != PPTP_MAGIC_COOKIE {
        return None;
    }
    let ctrl_type = u16::from_be_bytes([payload[8], payload[9]]);
    Some((msg_type, ctrl_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::nat::Nat;
    use crate::{IpPrefix, checksum};

    fn pfx(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    /// Build a PPTP control message payload of the given control type with the
    /// supplied call-id fields (placed at offsets 12-13 and 14-15).
    fn pptp_payload(ctrl_type: u16, call_id: u16, peer_call_id: u16) -> Vec<u8> {
        let mut p = vec![0u8; 16];
        p[0..2].copy_from_slice(&16u16.to_be_bytes()); // length
        p[2..4].copy_from_slice(&1u16.to_be_bytes()); // control message
        p[4..8].copy_from_slice(&PPTP_MAGIC_COOKIE.to_be_bytes());
        p[8..10].copy_from_slice(&ctrl_type.to_be_bytes());
        p[12..14].copy_from_slice(&call_id.to_be_bytes());
        p[14..16].copy_from_slice(&peer_call_id.to_be_bytes());
        p
    }

    fn build_pptp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let ic = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ic.to_be_bytes());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[32] = 0x50;
        p[33] = 0x18;
        p[40..].copy_from_slice(payload);
        crate::nat::l4::fill_v4_l4_checksum(&mut p, 20);
        p
    }

    fn mapping(inside: Ipv4Addr) -> NatMapping {
        NatMapping::new(PROTO_TCP, IpAddr::V4(inside), 60000, 20000)
    }

    #[test]
    fn pptp_header_parse_validates_magic() {
        let good = pptp_payload(PPTP_OUTGOING_CALL_REQ, 0x1111, 0);
        assert_eq!(pptp_parse_header(&good), Some((1, PPTP_OUTGOING_CALL_REQ)));

        let mut bad = good.clone();
        bad[4] = 0; // corrupt magic
        assert_eq!(pptp_parse_header(&bad), None);

        assert_eq!(pptp_parse_header(&[0u8; 4]), None);
    }

    #[test]
    fn pptp_outgoing_call_req_tracks_call() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = PptpHelper::new();
        let inside = Ipv4Addr::new(10, 0, 0, 5);

        let pkt = build_pptp(
            inside,
            60000,
            Ipv4Addr::new(198, 51, 100, 9),
            PPTP_PORT,
            &pptp_payload(PPTP_OUTGOING_CALL_REQ, 0x2222, 0),
        );
        let out = h.process_outbound(&nat, pkt.clone(), &mapping(inside));
        // Control payload is passed through unchanged.
        assert_eq!(out, pkt);

        // Call-ID 0x2222 is now tracked.
        assert!(h.calls.lock().unwrap().by_id.contains_key(&0x2222));

        // No expectation the NAT core could never match is left behind.
        assert!(
            nat.take_expectation(crate::Protocol::GRE.as_u8(), inside, 0x2222)
                .is_none()
        );
    }

    #[test]
    fn pptp_inbound_reply_updates_peer_call_id() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = PptpHelper::new();
        let inside = Ipv4Addr::new(10, 0, 0, 5);

        // Client sends Outgoing-Call-Request with call ID 0x3333.
        let req = build_pptp(
            inside,
            60000,
            Ipv4Addr::new(198, 51, 100, 9),
            PPTP_PORT,
            &pptp_payload(PPTP_OUTGOING_CALL_REQ, 0x3333, 0),
        );
        h.process_outbound(&nat, req, &mapping(inside));

        // Server replies: its call ID 0x9999, peer (our) call ID 0x3333.
        let reply = build_pptp(
            Ipv4Addr::new(198, 51, 100, 9),
            PPTP_PORT,
            Ipv4Addr::new(203, 0, 113, 1),
            20000,
            &pptp_payload(PPTP_OUTGOING_CALL_REPLY, 0x9999, 0x3333),
        );
        h.process_inbound(&nat, reply, &mapping(inside));

        let calls = h.calls.lock().unwrap();
        let info = calls
            .by_id
            .get(&0x3333)
            .expect("call should still be tracked");
        assert_eq!(info.peer_call_id, 0x9999);
    }

    #[test]
    fn a_reply_matches_only_a_live_call_of_its_host() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = PptpHelper::new();
        let inside = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(198, 51, 100, 9);
        for (id, host) in [(0x3333, inside), (0x4444, Ipv4Addr::new(10, 0, 0, 6))] {
            let req = build_pptp(
                host,
                60000,
                server,
                PPTP_PORT,
                &pptp_payload(PPTP_OUTGOING_CALL_REQ, id, 0),
            );
            h.process_outbound(&nat, req, &mapping(host));
        }
        // The first call lapsed, unswept.
        let old = Instant::now() - PPTP_GRE_TIMEOUT - Duration::from_secs(1);
        h.calls
            .lock()
            .unwrap()
            .by_id
            .get_mut(&0x3333)
            .unwrap()
            .created = old;
        let reply = |peer: u16| {
            let pkt = build_pptp(
                server,
                PPTP_PORT,
                Ipv4Addr::new(203, 0, 113, 1),
                20000,
                &pptp_payload(PPTP_OUTGOING_CALL_REPLY, 0x9999, peer),
            );
            h.process_inbound(&nat, pkt, &mapping(inside));
        };
        reply(0x3333);
        reply(0x4444);
        let calls = h.calls.lock().unwrap();
        assert!(!calls.by_id.contains_key(&0x3333), "stale call kept");
        assert_eq!(calls.by_id[&0x4444].peer_call_id, 0, "another host's call");
    }

    #[test]
    fn requests_do_not_each_walk_the_call_table() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = PptpHelper::new();
        let inside = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(198, 51, 100, 9);
        let send = |call_id: u16, outbound: bool| {
            let payload = pptp_payload(PPTP_OUTGOING_CALL_REQ, call_id, 0);
            if outbound {
                let pkt = build_pptp(inside, 60000, server, PPTP_PORT, &payload);
                h.process_outbound(&nat, pkt, &mapping(inside));
            } else {
                let pkt = build_pptp(server, PPTP_PORT, inside, 60000, &payload);
                h.process_inbound(&nat, pkt, &mapping(inside));
            }
        };
        // A table nearly full of calls, then a stream of requests: each
        // used to sweep the whole table. The bound is loose enough for a
        // slow debug build on a loaded machine; the sweeps would take 5000
        // requests well past it.
        for id in 1..=60000 {
            send(id, false);
        }
        let start = std::time::Instant::now();
        for id in 60001..=65000 {
            send(id, true);
        }
        let took = start.elapsed();
        assert!(took < Duration::from_secs(2), "{took:?}");

        // Stale calls still go, once the interval has passed.
        let old = Instant::now() - PPTP_GRE_TIMEOUT - Duration::from_secs(1);
        {
            let mut calls = h.calls.lock().unwrap();
            calls.by_id.values_mut().for_each(|c| c.created = old);
            calls.next_cleanup = Instant::now();
        }
        send(1, true);
        assert_eq!(h.calls.lock().unwrap().by_id.len(), 1);
    }
}
