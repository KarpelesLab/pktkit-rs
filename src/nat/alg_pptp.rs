//! PPTP Application Layer Gateway.
//!
//! Tracks PPTP control-channel messages (TCP/1723) to learn each Call-ID and
//! registers expectations for the associated GRE (IP protocol 47) tunnel.
//!
//! Note: actual GRE data forwarding requires NAT-core support for protocol 47
//! (including rewriting the Call-ID in the enhanced-GRE key field). The NAT
//! core here handles only TCP/UDP/ICMP, so the GRE expectations registered by
//! this helper act as markers for a future GRE-aware core — they will not be
//! matched by the current `match_expectation` path. This mirrors the Go
//! upstream's documented scope.
//!
//! Port of `alg_pptp.go`.

use crate::nat::helper::{Expectation, Helper, NatMapping, PacketHelper, PROTO_TCP};
use crate::nat::nat::Nat;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PPTP_PORT: u16 = 1723;
const PPTP_MAGIC_COOKIE: u32 = 0x1A2B_3C4D;
const PPTP_GRE_TIMEOUT: Duration = Duration::from_secs(120);

// PPTP control message types.
const PPTP_OUTGOING_CALL_REQ: u16 = 7;
const PPTP_OUTGOING_CALL_REPLY: u16 = 8;

/// GRE protocol number. See module note: tracked only, not yet forwarded.
pub(crate) const PROTO_GRE: u8 = 47;

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

#[derive(Debug)]
pub struct PptpHelper {
    /// Indexed by call ID.
    calls: Mutex<HashMap<u16, PptpCallInfo>>,
}

impl Default for PptpHelper {
    fn default() -> Self {
        PptpHelper::new()
    }
}

impl PptpHelper {
    pub fn new() -> PptpHelper {
        PptpHelper {
            calls: Mutex::new(HashMap::new()),
        }
    }

    /// Remove stale call entries. Caller holds the lock.
    fn cleanup_calls(calls: &mut HashMap<u16, PptpCallInfo>) {
        let now = Instant::now();
        calls.retain(|_, info| now.duration_since(info.created) <= PPTP_GRE_TIMEOUT);
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

    fn process_outbound(&self, nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
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
                    Self::cleanup_calls(&mut calls);
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
                add_gre_expectation(nat, inside_ip, call_id);
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
                add_gre_expectation(nat, inside_ip, call_id);
            }
            _ => {}
        }
        pkt
    }

    fn process_inbound(&self, nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
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
                {
                    let mut calls = self.calls.lock().unwrap();
                    if let Some(info) = calls.get_mut(&peer_call_id) {
                        info.peer_call_id = server_call_id;
                    }
                }
                add_gre_expectation(nat, inside_ip, peer_call_id);
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

fn add_gre_expectation(nat: &Nat, inside_ip: Ipv4Addr, call_id: u16) {
    // GRE has no ports; the Call-ID stands in for the inside port so a future
    // GRE-aware NAT core can key on it.
    nat.add_expectation(Expectation {
        proto: PROTO_GRE,
        remote_ip: Ipv4Addr::UNSPECIFIED,
        remote_port: 0,
        inside_ip,
        inside_port: call_id,
        expires: Instant::now() + PPTP_GRE_TIMEOUT,
    });
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
    use crate::{checksum, combine_checksums, pseudo_header_checksum, IpPrefix, Protocol};

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
        let ph = pseudo_header_checksum(
            Protocol::TCP,
            IpAddr::V4(src),
            IpAddr::V4(dst),
            (20 + payload.len()) as u16,
        );
        let seg = checksum(&p[20..]);
        let cs = combine_checksums(ph, seg);
        p[36..38].copy_from_slice(&cs.to_be_bytes());
        p
    }

    fn mapping(inside: Ipv4Addr) -> NatMapping {
        NatMapping {
            proto: PROTO_TCP,
            inside_ip: IpAddr::V4(inside),
            inside_port: 60000,
            outside_port: 20000,
        }
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
    fn pptp_outgoing_call_req_tracks_call_and_gre_expectation() {
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
        assert!(h.calls.lock().unwrap().contains_key(&0x2222));

        // A GRE expectation keyed on the call ID was registered.
        let e = nat
            .take_expectation(PROTO_GRE, inside, 0x2222)
            .expect("GRE expectation should be registered");
        assert_eq!(e.proto, PROTO_GRE);
        assert_eq!(e.inside_ip, inside);
        assert_eq!(e.inside_port, 0x2222);
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
        let info = calls.get(&0x3333).expect("call should still be tracked");
        assert_eq!(info.peer_call_id, 0x9999);
    }
}
