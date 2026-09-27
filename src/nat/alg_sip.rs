//! SIP (RFC 3261) Application Layer Gateway.
//!
//! Rewrites embedded IP addresses and ports in SIP `Via`/`Contact` headers and
//! SDP `c=`/`m=` lines so VoIP signalling and the resulting RTP/RTCP media
//! streams traverse the NAT. Outbound (inside -> outside) maps the inside
//! address to the public address; inbound performs the inverse. For each SDP
//! media line an even outside port is allocated for RTP and the next one for
//! RTCP (RFC 3550 §11), an `a=rtcp:` attribute (RFC 3605) is honoured and
//! rewritten, and expectations are registered for both.
//!
//! Port of `alg_sip.go`.

use crate::nat::helper::{Expectation, Helper, NatMapping, PROTO_TCP, PROTO_UDP, PacketHelper};
use crate::nat::l4::replace_payload;
use crate::nat::nat::Nat;
use crate::time::Instant;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const SIP_PORT: u16 = 5060;
const SIP_RTP_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Default)]
pub struct SipHelper;

impl SipHelper {
    pub fn new() -> SipHelper {
        SipHelper
    }
}

impl Helper for SipHelper {
    fn name(&self) -> &str {
        "sip"
    }
}

impl PacketHelper for SipHelper {
    fn match_outbound(&self, proto: u8, dst_port: u16) -> bool {
        dst_port == SIP_PORT && (proto == PROTO_TCP || proto == PROTO_UDP)
    }

    fn process_outbound(&self, nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
        self.rewrite(nat, pkt, m, true)
    }

    fn process_inbound(&self, nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
        self.rewrite(nat, pkt, m, false)
    }
}

impl SipHelper {
    fn rewrite(&self, nat: &Nat, pkt: Vec<u8>, m: &NatMapping, outbound: bool) -> Vec<u8> {
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        let proto = pkt[9];
        if ihl < 20 || pkt.len() < ihl {
            return pkt;
        }
        let hdr_len = if proto == PROTO_TCP {
            if pkt.len() < ihl + 20 {
                return pkt;
            }
            (pkt[ihl + 12] >> 4) as usize * 4
        } else {
            8
        };
        let payload_off = ihl + hdr_len;
        if payload_off >= pkt.len() {
            return pkt;
        }
        let payload = &pkt[payload_off..];
        if payload.is_empty() {
            return pkt;
        }

        let inside_ip = match m.inside_ip {
            IpAddr::V4(a) => a,
            _ => return pkt,
        };
        let outside_ip = match nat.outside_addr() {
            Some(a) => a,
            None => return pkt,
        };

        let inside_addr = inside_ip.to_string();
        let outside_addr = outside_ip.to_string();
        let inside_hp = format!("{}:{}", inside_addr, m.inside_port);
        let outside_hp = format!("{}:{}", outside_addr, m.outside_port);

        // (from, to) substitutions depending on direction.
        let (hp_from, hp_to, addr_from, addr_to) = if outbound {
            (&inside_hp, &outside_hp, &inside_addr, &outside_addr)
        } else {
            (&outside_hp, &inside_hp, &outside_addr, &inside_addr)
        };

        let mut new_payload = payload.to_vec();
        // Headers carrying IP:port (more specific) first, then bare IP.
        for prefix in [
            b"Via:".as_slice(),
            b"v:".as_slice(),
            b"Contact:".as_slice(),
            b"m:".as_slice(),
        ] {
            new_payload =
                sip_rewrite_header(&new_payload, prefix, hp_from.as_bytes(), hp_to.as_bytes());
        }
        for prefix in [
            b"Via:".as_slice(),
            b"v:".as_slice(),
            b"Contact:".as_slice(),
            b"m:".as_slice(),
        ] {
            new_payload = sip_rewrite_header(
                &new_payload,
                prefix,
                addr_from.as_bytes(),
                addr_to.as_bytes(),
            );
        }

        // SDP body, separated from headers by a blank line.
        if let Some(sdp_start) = find_subslice(&new_payload, b"\r\n\r\n") {
            let header_part = &new_payload[..sdp_start];
            let lower = header_part.to_ascii_lowercase();
            if find_subslice(&lower, b"content-type: application/sdp").is_some()
                || find_subslice(&lower, b"c: application/sdp").is_some()
            {
                let sdp_body = new_payload[sdp_start + 4..].to_vec();
                let new_sdp = if outbound {
                    rewrite_sdp_outbound(nat, m.namespace, &sdp_body, &outside_addr, inside_ip)
                } else {
                    sip_rewrite_sdp_addr(&sdp_body, &outside_addr, &inside_addr)
                };
                if new_sdp != sdp_body {
                    let mut headers = new_payload[..sdp_start + 4].to_vec();
                    new_payload = sip_update_content_length(&mut headers, &new_sdp);
                }
            }
        }

        if new_payload == payload {
            return pkt;
        }
        replace_payload(&pkt, ihl, hdr_len, &new_payload)
    }
}

/// Rewrite SDP `c=` connection lines, `m=` media lines and `a=rtcp:`
/// attributes outbound, swapping the inside address for the outside address
/// and mapping each media stream's RTP and RTCP ports.
fn rewrite_sdp_outbound(
    nat: &Nat,
    ns: u64,
    sdp: &[u8],
    outside_addr: &str,
    inside_ip: Ipv4Addr,
) -> Vec<u8> {
    let inside_addr = inside_ip.to_string();
    let mut remote_ip = Ipv4Addr::UNSPECIFIED;
    let lines = split_subslice(sdp, b"\r\n");
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(lines.len() + 1);
    // The outside RTCP port of the media section being rewritten.
    let mut rtcp_out: Option<u16> = None;
    for (i, raw) in lines.iter().enumerate() {
        let mut line = raw.clone();
        if line.starts_with(b"c=IN IP4 ") {
            let rest = &line[b"c=IN IP4 ".len()..];
            let addr = String::from_utf8_lossy(rest).trim().to_string();
            if addr != inside_addr
                && let Ok(a) = addr.parse::<Ipv4Addr>()
            {
                remote_ip = a;
            }
            line = format!("c=IN IP4 {}", outside_addr).into_bytes();
        } else if line.starts_with(b"m=") {
            rtcp_out = None;
            // An a=rtcp attribute moves RTCP off RTP + 1 (RFC 3605); it is
            // media-level, so it belongs to the lines up to the next m=.
            let explicit = lines[i + 1..]
                .iter()
                .take_while(|l| !l.starts_with(b"m="))
                .find_map(|l| rtcp_attr(l).map(|(port, _)| port));
            if let Some((new_line, rtp, rtcp)) =
                sip_parse_media_line(&line, nat, ns, remote_ip, inside_ip, explicit)
            {
                out.push(new_line);
                rtcp_out = rtcp;
                // Without an a=rtcp line the peer sends RTCP to RTP + 1; if
                // the pair could not be allocated that way, say where it is.
                if explicit.is_none()
                    && let Some(rtcp) = rtcp.filter(|&p| Some(p) != rtp.checked_add(1))
                {
                    out.push(format!("a=rtcp:{}", rtcp).into_bytes());
                }
                continue;
            }
        } else if let (Some((_, rest)), Some(port)) = (rtcp_attr(&line), rtcp_out) {
            let mut new_line = format!("a=rtcp:{}", port).into_bytes();
            new_line.extend_from_slice(&replace_addr(
                rest,
                inside_addr.as_bytes(),
                outside_addr.as_bytes(),
            ));
            line = new_line;
        }
        out.push(line);
    }
    join_subslice(&out, b"\r\n")
}

/// The port of an `a=rtcp:<port> [<nettype> <addrtype> <address>]`
/// attribute (RFC 3605), and what follows it.
fn rtcp_attr(line: &[u8]) -> Option<(u16, &[u8])> {
    let rest = line.strip_prefix(b"a=rtcp:")?;
    let n = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    let port = std::str::from_utf8(&rest[..n]).ok()?.parse().ok()?;
    Some((port, &rest[n..]))
}

/// Replace inside addresses in `c=` lines (used inbound).
fn sip_rewrite_sdp_addr(sdp: &[u8], old_addr: &str, new_addr: &str) -> Vec<u8> {
    let old = format!("c=IN IP4 {}", old_addr).into_bytes();
    let new = format!("c=IN IP4 {}", new_addr).into_bytes();
    replace_addr(sdp, &old, &new)
}

/// Parse an SDP `m=` media line, map its RTP port and the RTCP port that
/// goes with it (`explicit` if an a=rtcp attribute names one, else RTP + 1),
/// register expectations for both, and return the rewritten line with the
/// outside RTP and RTCP ports. Returns `None` if the line could not be
/// processed (left unchanged by the caller).
fn sip_parse_media_line(
    line: &[u8],
    nat: &Nat,
    ns: u64,
    remote_ip: Ipv4Addr,
    inside_ip: Ipv4Addr,
    explicit: Option<u16>,
) -> Option<(Vec<u8>, u16, Option<u16>)> {
    let mut parts: Vec<Vec<u8>> = line
        .split(|b| b.is_ascii_whitespace())
        .filter(|f| !f.is_empty())
        .map(|f| f.to_vec())
        .collect();
    if parts.len() < 3 {
        return None;
    }
    let inside_port: u16 = std::str::from_utf8(&parts[1]).ok()?.parse().ok()?;
    if inside_port == 0 {
        return None;
    }
    let rtcp_inside = explicit.or(inside_port.checked_add(1));

    // RTP on an even port and RTCP on the next (RFC 3550 §11), allocated
    // together so the peer's default of RTP + 1 lands on the RTCP mapping.
    // RTCP multiplexed onto the RTP port (RFC 5761) needs just the one.
    let (rtp_out, rtcp_out) = match rtcp_inside {
        Some(rtcp) if rtcp != inside_port => {
            match nat.create_mapping_pair_in(ns, PROTO_UDP, inside_ip, (inside_port, rtcp)) {
                Some(p) => (p, Some(p + 1)),
                None => (
                    nat.create_mapping_in(ns, PROTO_UDP, inside_ip, inside_port)?,
                    nat.create_mapping_in(ns, PROTO_UDP, inside_ip, rtcp),
                ),
            }
        }
        Some(_) => {
            let p = nat.create_mapping_in(ns, PROTO_UDP, inside_ip, inside_port)?;
            (p, Some(p))
        }
        None => (
            nat.create_mapping_in(ns, PROTO_UDP, inside_ip, inside_port)?,
            None,
        ),
    };

    // The remote media ports are not known yet.
    let expires = Instant::now() + SIP_RTP_TIMEOUT;
    let streams = [
        (inside_port, Some(rtp_out)),
        (rtcp_inside.unwrap_or(0), rtcp_out),
    ];
    for (inside, outside) in streams {
        if let Some(outside) = outside {
            nat.add_expectation(
                Expectation::new(PROTO_UDP, inside_ip, inside, outside, expires)
                    .remote_ip(remote_ip)
                    .namespace(ns),
            );
        }
    }

    parts[1] = rtp_out.to_string().into_bytes();
    Some((join_subslice(&parts, b" "), rtp_out, rtcp_out))
}

/// Replace `old_val` with `new_val` only within lines whose start matches
/// `prefix` (case-insensitive on the prefix).
fn sip_rewrite_header(payload: &[u8], prefix: &[u8], old_val: &[u8], new_val: &[u8]) -> Vec<u8> {
    if old_val == new_val {
        return payload.to_vec();
    }
    let mut lines = split_subslice(payload, b"\r\n");
    let mut changed = false;
    for line in lines.iter_mut() {
        if line.len() < prefix.len() {
            continue;
        }
        if !line[..prefix.len()].eq_ignore_ascii_case(prefix) {
            continue;
        }
        let new_line = replace_addr(line, old_val, new_val);
        if new_line != *line {
            *line = new_line;
            changed = true;
        }
    }
    if !changed {
        return payload.to_vec();
    }
    join_subslice(&lines, b"\r\n")
}

/// Rebuild the SIP message with a corrected `Content-Length` header for the
/// given SDP body. `headers` ends with the `\r\n\r\n` separator.
fn sip_update_content_length(headers: &mut Vec<u8>, sdp_body: &[u8]) -> Vec<u8> {
    let new_cl = sdp_body.len().to_string().into_bytes();
    let lower = headers.to_ascii_lowercase();
    let mut cl_idx = find_subslice(&lower, b"content-length:");
    if cl_idx.is_none() {
        // SIP compact form "l:" at the start of a line.
        let mut off = 0;
        while off < lower.len() {
            if let Some(idx) = find_subslice(&lower[off..], b"l:") {
                let abs = off + idx;
                if abs == 0 || (abs >= 2 && lower[abs - 2] == b'\r' && lower[abs - 1] == b'\n') {
                    cl_idx = Some(abs);
                    break;
                }
                off = abs + 2;
            } else {
                break;
            }
        }
    }

    if let Some(cl) = cl_idx
        && let Some(line_end) = find_subslice(&headers[cl..], b"\r\n")
        && let Some(colon) = headers[cl..cl + line_end].iter().position(|&b| b == b':')
    {
        let before = headers[..cl + colon + 1].to_vec();
        let after = headers[cl + line_end..].to_vec();
        let mut rebuilt = before;
        rebuilt.push(b' ');
        rebuilt.extend_from_slice(&new_cl);
        rebuilt.extend_from_slice(&after);
        *headers = rebuilt;
    }

    let mut result = Vec::with_capacity(headers.len() + sdp_body.len());
    result.extend_from_slice(headers);
    result.extend_from_slice(sdp_body);
    result
}

// ---- small byte-slice helpers (std-only) ----

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn split_subslice(data: &[u8], sep: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + sep.len() <= data.len() {
        if &data[i..i + sep.len()] == sep {
            out.push(data[start..i].to_vec());
            i += sep.len();
            start = i;
        } else {
            i += 1;
        }
    }
    out.push(data[start..].to_vec());
    out
}

fn join_subslice(parts: &[Vec<u8>], sep: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(sep);
        }
        out.extend_from_slice(p);
    }
    out
}

/// Replace every occurrence of the address (or `address:port`) `old` that
/// stands on its own. A plain substring match would also hit `10.0.0.50`,
/// `110.0.0.5` or `10.0.0.5:50600` when rewriting `10.0.0.5` / `10.0.0.5:5060`,
/// corrupting another host's address, so the bytes either side of a match must
/// not continue the number.
fn replace_addr(data: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    if old.is_empty() {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let end = i + old.len();
        if end <= data.len()
            && &data[i..end] == old
            && (i == 0 || !(data[i - 1].is_ascii_digit() || data[i - 1] == b'.'))
            && data.get(end).is_none_or(|b| !b.is_ascii_digit())
        {
            out.extend_from_slice(new);
            i += old.len();
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;
    use crate::nat::nat::Nat;
    use crate::{IpPrefix, L3Device, Packet};
    use std::sync::{Arc, Mutex as StdMutex};

    fn pfx(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    fn build_sip_udp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, body: &[u8]) -> Vec<u8> {
        let udp_len = 8 + body.len();
        let total = 20 + udp_len;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let ic = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ic.to_be_bytes());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        p[28..].copy_from_slice(body);
        p
    }

    fn payload_of(pkt: &[u8]) -> &[u8] {
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        let proto = pkt[9];
        let hdr = if proto == PROTO_TCP {
            (pkt[ihl + 12] >> 4) as usize * 4
        } else {
            8
        };
        &pkt[ihl + hdr..]
    }

    #[test]
    fn sip_rewrites_via_contact_headers() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_packet_helper(Arc::new(SipHelper::new()));

        let captured = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = captured.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        let inside = Ipv4Addr::new(10, 0, 0, 5);
        let body = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK\r\n\
Contact: <sip:alice@10.0.0.5:5060>\r\n\
Content-Length: 0\r\n\r\n";
        let pkt = build_sip_udp(inside, 5060, Ipv4Addr::new(198, 51, 100, 9), 5060, body);
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();

        let out = captured.lock().unwrap();
        assert_eq!(out.len(), 1);
        let s = String::from_utf8_lossy(payload_of(&out[0])).to_string();
        assert!(s.contains("203.0.113.1"), "expected outside addr in: {}", s);
        assert!(!s.contains("10.0.0.5"), "inside addr should be gone: {}", s);
        assert!(
            crate::nat::l4::v4_l4_checksum_ok(&out[0], 20),
            "rewritten SIP datagram must carry a valid UDP checksum"
        );
    }

    #[test]
    fn sip_sdp_rewrite_and_rtp_expectation() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_packet_helper(Arc::new(SipHelper::new()));

        let captured = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = captured.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        let inside = Ipv4Addr::new(10, 0, 0, 5);
        let sdp =
            "v=0\r\no=- 0 0 IN IP4 10.0.0.5\r\nc=IN IP4 10.0.0.5\r\nm=audio 8000 RTP/AVP 0\r\n";
        let body = format!(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.5:5060\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{}",
            sdp.len(),
            sdp
        );
        let pkt = build_sip_udp(
            inside,
            5060,
            Ipv4Addr::new(198, 51, 100, 9),
            5060,
            body.as_bytes(),
        );
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();

        let out = captured.lock().unwrap();
        assert_eq!(out.len(), 1);
        let s = String::from_utf8_lossy(payload_of(&out[0])).to_string();
        // c= line rewritten to the outside address.
        assert!(s.contains("c=IN IP4 203.0.113.1"), "got: {}", s);
        // Media port rewritten away from the original 8000 to a mapped port.
        assert!(s.contains("m=audio "), "got: {}", s);
        let m_line = s.lines().find(|l| l.starts_with("m=audio")).unwrap();
        let port: u16 = m_line.split_whitespace().nth(1).unwrap().parse().unwrap();
        assert_ne!(port, 8000, "media port should be remapped: {}", m_line);
        assert!(port >= 10000, "remapped port in NAT range: {}", port);

        // An RTP expectation should now allow an inbound UDP packet to reach the
        // inside client. Send a UDP packet from the remote to the mapped port.
        drop(out);
        let inbound = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let i = inbound.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            i.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let reply = build_sip_udp(
            Ipv4Addr::new(198, 51, 100, 9),
            40000,
            Ipv4Addr::new(203, 0, 113, 1),
            port,
            b"\x80\x00rtp-media",
        );
        nat.outside().send(Packet::from_slice(&reply)).unwrap();
        let inbound = inbound.lock().unwrap();
        assert_eq!(
            inbound.len(),
            1,
            "RTP packet should reach inside via expectation"
        );
        assert_eq!(&inbound[0][16..20], &[10, 0, 0, 5]);
    }

    /// Send an INVITE carrying `sdp` from 10.0.0.5; returns the SDP that
    /// left the NAT and a capture of what reaches the inside.
    fn invite_with_sdp(
        sdp: &str,
        before: impl FnOnce(&Nat),
    ) -> (Arc<Nat>, String, Arc<StdMutex<Vec<Vec<u8>>>>) {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_packet_helper(Arc::new(SipHelper::new()));
        let captured = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = captured.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let inbound = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let i = inbound.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            i.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        before(&nat);
        let body = format!(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.5:5060\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{}",
            sdp.len(),
            sdp
        );
        let pkt = build_sip_udp(
            Ipv4Addr::new(10, 0, 0, 5),
            5060,
            Ipv4Addr::new(198, 51, 100, 9),
            5060,
            body.as_bytes(),
        );
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();
        let out = captured.lock().unwrap();
        assert_eq!(out.len(), 1);
        let s = String::from_utf8_lossy(payload_of(&out[0])).to_string();
        let sdp_out = s.split("\r\n\r\n").nth(1).unwrap().to_string();
        (nat, sdp_out, inbound)
    }

    /// The port number right after `prefix` on the SDP line starting with it.
    fn port_after(sdp: &str, prefix: &str) -> u16 {
        let line = sdp.lines().find(|l| l.starts_with(prefix)).unwrap();
        line[prefix.len()..]
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }

    /// Send a datagram from the remote to public `port`; returns the inside
    /// port it was delivered to, if any.
    fn reaches(nat: &Nat, inbound: &StdMutex<Vec<Vec<u8>>>, port: u16) -> Option<u16> {
        inbound.lock().unwrap().clear();
        let pkt = build_sip_udp(
            Ipv4Addr::new(198, 51, 100, 9),
            40001,
            Ipv4Addr::new(203, 0, 113, 1),
            port,
            b"media",
        );
        nat.outside().send(Packet::from_slice(&pkt)).unwrap();
        let got = inbound.lock().unwrap();
        got.first().map(|p| u16::from_be_bytes([p[22], p[23]]))
    }

    #[test]
    fn rtp_gets_an_even_port_with_rtcp_on_the_next() {
        let sdp = "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 8000 RTP/AVP 0\r\n";
        let (nat, out, inbound) = invite_with_sdp(sdp, |_| {});
        let rtp = port_after(&out, "m=audio ");
        assert_eq!(rtp % 2, 0, "RTP port must be even (RFC 3550): {}", out);
        assert_eq!(reaches(&nat, &inbound, rtp), Some(8000));
        assert_eq!(reaches(&nat, &inbound, rtp + 1), Some(8001));
    }

    #[test]
    fn explicit_rtcp_attribute_is_mapped_and_rewritten() {
        let sdp = "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 8000 RTP/AVP 0\r\n\
a=rtcp:9001 IN IP4 10.0.0.5\r\na=sendrecv\r\n";
        let (nat, out, inbound) = invite_with_sdp(sdp, |_| {});
        let rtp = port_after(&out, "m=audio ");
        let rtcp = port_after(&out, "a=rtcp:");
        assert!(
            out.contains(&format!("a=rtcp:{} IN IP4 203.0.113.1\r\n", rtcp)),
            "{}",
            out
        );
        assert_eq!(rtcp, rtp + 1);
        assert_eq!(reaches(&nat, &inbound, rtp), Some(8000));
        assert_eq!(reaches(&nat, &inbound, rtcp), Some(9001));
    }

    #[test]
    fn rtcp_off_the_next_port_is_announced() {
        // The RTP endpoint already holds a port of its own, so the pair
        // cannot be laid out as RTP + 1; the peer must be told.
        let sdp = "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 8000 RTP/AVP 0\r\n";
        let (nat, out, inbound) = invite_with_sdp(sdp, |nat| {
            nat.create_mapping(PROTO_UDP, Ipv4Addr::new(10, 0, 0, 5), 8000)
                .unwrap();
        });
        let rtp = port_after(&out, "m=audio ");
        let rtcp = port_after(&out, "a=rtcp:");
        assert_ne!(rtcp, rtp + 1, "{}", out);
        assert_eq!(reaches(&nat, &inbound, rtp), Some(8000));
        assert_eq!(reaches(&nat, &inbound, rtcp), Some(8001));
    }

    #[test]
    fn sip_leaves_addresses_that_merely_contain_the_inside_one() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = SipHelper::new();
        let body = b"REGISTER sip:reg SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.50:5060\r\n\
Contact: <sip:a@110.0.0.5>\r\n\
Content-Length: 0\r\n\r\n";
        let pkt = build_sip_udp(
            Ipv4Addr::new(10, 0, 0, 5),
            5060,
            Ipv4Addr::new(198, 51, 100, 9),
            5060,
            body,
        );
        let m = NatMapping::new(
            PROTO_UDP,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            5060,
            20000,
        );
        let out = h.process_outbound(&nat, pkt.clone(), &m);
        assert_eq!(out, pkt);
    }

    #[test]
    fn sip_no_match_passes_through() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let h = SipHelper::new();
        // A SIP message with no inside addresses present is unchanged.
        let body = b"REGISTER sip:reg SIP/2.0\r\nVia: SIP/2.0/UDP 9.9.9.9:5060\r\nContent-Length: 0\r\n\r\n";
        let pkt = build_sip_udp(
            Ipv4Addr::new(10, 0, 0, 5),
            5060,
            Ipv4Addr::new(198, 51, 100, 9),
            5060,
            body,
        );
        let m = NatMapping::new(
            PROTO_UDP,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            5060,
            20000,
        );
        let out = h.process_outbound(&nat, pkt.clone(), &m);
        assert_eq!(out, pkt);
    }
}
