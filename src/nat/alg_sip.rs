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

        let rewrite_message = |msg: &[u8]| -> Vec<u8> {
            let mut new_payload = msg.to_vec();
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
            if let Some(sdp_start) = find_subslice(&new_payload, b"\r\n\r\n")
                && is_sdp(&new_payload[..sdp_start])
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
            new_payload
        };

        let new_payload = if proto == PROTO_TCP {
            // A TCP segment may carry several messages, or part of one:
            // each ends where its Content-Length says (RFC 3261 §18.3), and
            // is rewritten on its own, so one's body is never taken for
            // another's headers, nor its Content-Length set over both.
            let messages = sip_messages(payload);
            let mut out = Vec::with_capacity(payload.len());
            let mut at = 0;
            for r in messages {
                out.extend_from_slice(&payload[at..r.start]);
                out.extend_from_slice(&rewrite_message(&payload[r.clone()]));
                at = r.end;
            }
            // What is left is a message continued in the next segment, or
            // the tail of one begun in an earlier one. Its addresses may be
            // split between segments, and its body length is not known, so
            // it goes on untouched: better unrewritten than corrupted.
            out.extend_from_slice(&payload[at..]);
            out
        } else {
            // A datagram holds one message; its body runs to the end of it.
            rewrite_message(payload)
        };

        if new_payload == payload {
            return pkt;
        }
        replace_payload(&pkt, ihl, hdr_len, &new_payload)
    }
}

/// Rewrite SDP `c=` connection lines, `m=` media lines and `a=rtcp:`
/// attributes outbound, swapping the inside address for the outside address
/// and mapping each media stream's RTP and RTCP ports.
///
/// Only what the inside host itself receives on is translated: a `c=` line
/// naming it, and the media sections whose connection address is it. Any
/// other address is left alone: `0.0.0.0` puts a stream on hold (RFC 3264
/// §8.4), and a relay or multicast group receives the media itself, so
/// rewriting it to the public address, or mapping ports for it, would send
/// the media to the wrong place.
fn rewrite_sdp_outbound(
    nat: &Nat,
    ns: u64,
    sdp: &[u8],
    outside_addr: &str,
    inside_ip: Ipv4Addr,
) -> Vec<u8> {
    let inside_addr = inside_ip.to_string();
    let lines = split_subslice(sdp, b"\r\n");
    // The session-level connection address: a c= line before the first m=.
    let session_c = lines
        .iter()
        .take_while(|l| !l.starts_with(b"m="))
        .find_map(|l| connection_addr(l));
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(lines.len() + 1);
    // The outside RTCP port of the media section being rewritten.
    let mut rtcp_out: Option<u16> = None;
    for (i, raw) in lines.iter().enumerate() {
        let mut line = raw.clone();
        if let Some(addr) = connection_addr(&line) {
            if addr == inside_addr.as_bytes() {
                line = format!("c=IN IP4 {}", outside_addr).into_bytes();
            }
        } else if line.starts_with(b"m=") {
            rtcp_out = None;
            // Media-level attributes are the lines up to the next m=.
            let section = || lines[i + 1..].iter().take_while(|l| !l.starts_with(b"m="));
            // A media-level c= overrides the session-level one for this
            // stream (RFC 4566 §5.7).
            let conn = section().find_map(|l| connection_addr(l)).or(session_c);
            // An a=rtcp attribute moves RTCP off RTP + 1 (RFC 3605).
            let explicit = section().find_map(|l| rtcp_attr(l).map(|(port, _)| port));
            if conn == Some(inside_addr.as_bytes())
                && let Some((new_line, rtp, rtcp)) =
                    sip_parse_media_line(&line, nat, ns, inside_ip, explicit)
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

/// The address of an SDP `c=IN IP4 <address>` line (RFC 4566 §5.7), with
/// any multicast `/ttl` suffix still on it.
fn connection_addr(line: &[u8]) -> Option<&[u8]> {
    Some(line.strip_prefix(b"c=IN IP4 ")?.trim_ascii())
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

    // Neither the remote's media address nor its ports are known yet: the
    // offer carries only this side's.
    let expires = Instant::now() + SIP_RTP_TIMEOUT;
    let streams = [
        (inside_port, Some(rtp_out)),
        (rtcp_inside.unwrap_or(0), rtcp_out),
    ];
    for (inside, outside) in streams {
        if let Some(outside) = outside {
            nat.add_expectation(
                Expectation::new(PROTO_UDP, inside_ip, inside, outside, expires).namespace(ns),
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
/// given SDP body. `headers` ends with the `\r\n\r\n` separator. Only the
/// header's value changes, on the line [`content_length`] reads it from.
fn sip_update_content_length(headers: &mut Vec<u8>, sdp_body: &[u8]) -> Vec<u8> {
    if let Some(value) = header_value(headers, CONTENT_LENGTH) {
        headers.splice(value, sdp_body.len().to_string().into_bytes());
    }
    let mut result = Vec::with_capacity(headers.len() + sdp_body.len());
    result.extend_from_slice(headers);
    result.extend_from_slice(sdp_body);
    result
}

/// `Content-Length` and its compact form (RFC 3261 §7.3.3, §20.14).
const CONTENT_LENGTH: [&[u8]; 2] = [b"content-length", b"l"];
/// `Content-Type` and its compact form (RFC 3261 §7.3.3, §20.15).
const CONTENT_TYPE: [&[u8]; 2] = [b"content-type", b"c"];

/// Where the value of the first header called one of `names` (lower case)
/// lies in `head`, a message head: its start line, then header lines, each
/// `name HCOLON value` where HCOLON allows whitespace on either side of
/// the colon (RFC 3261 §25.1). A name is matched whole and case-blind, so
/// `X-Content-Length` is not `Content-Length`. The range excludes the
/// surrounding whitespace.
fn header_value(head: &[u8], names: [&[u8]; 2]) -> Option<std::ops::Range<usize>> {
    let mut at = 0;
    let mut first = true;
    while at < head.len() {
        let end = find_subslice(&head[at..], b"\r\n").map_or(head.len(), |e| at + e);
        let line = &head[at..end];
        if !first && let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = line[..colon].trim_ascii();
            if names.iter().any(|n| name.eq_ignore_ascii_case(n)) {
                let value = &line[colon + 1..];
                let lead = value.len() - value.trim_ascii_start().len();
                let len = value.trim_ascii().len();
                let start = at + colon + 1 + lead;
                return Some(start..start + len);
            }
        }
        first = false;
        at = end + 2;
    }
    None
}

/// Where the complete SIP messages at the start of a TCP segment's payload
/// lie. A message counts only if it starts the payload (or follows a
/// complete one, keep-alives aside), its headers end within it, and so does
/// the body its Content-Length gives, which a stream transport requires
/// (RFC 3261 §18.3, §20.14).
fn sip_messages(payload: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        // CRLFs between messages are keep-alives (RFC 5626 §3.5.1).
        while payload[at..].starts_with(b"\r\n") {
            at += 2;
        }
        let msg = &payload[at..];
        // A segment picking up in the middle of a message does not start
        // with a request or status line.
        let first = &msg[..find_subslice(msg, b"\r\n").unwrap_or(msg.len())];
        if !(first.starts_with(b"SIP/2.0 ") || first.ends_with(b" SIP/2.0")) {
            return out;
        }
        let Some(hdr_end) = find_subslice(msg, b"\r\n\r\n") else {
            return out;
        };
        let Some(len) = content_length(&msg[..hdr_end]) else {
            return out;
        };
        let end = match (hdr_end + 4).checked_add(len) {
            Some(end) if end <= msg.len() => end,
            _ => return out,
        };
        out.push(at..at + end);
        at += end;
    }
}

/// The value of the `Content-Length` (compact form `l`) header among
/// `headers`, the message head without its terminating blank line.
fn content_length(headers: &[u8]) -> Option<usize> {
    let value = header_value(headers, CONTENT_LENGTH)?;
    std::str::from_utf8(&headers[value]).ok()?.parse().ok()
}

/// Whether the message head `headers` declares an SDP body.
fn is_sdp(headers: &[u8]) -> bool {
    header_value(headers, CONTENT_TYPE).is_some_and(|v| {
        let media = headers[v].split(|&b| b == b';').next().unwrap_or(&[]);
        media.trim_ascii().eq_ignore_ascii_case(b"application/sdp")
    })
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
        // The RTP endpoint already holds a port of its own, and another
        // host the one after it, so the pair cannot be laid out as RTP + 1;
        // the peer must be told.
        let sdp = "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 8000 RTP/AVP 0\r\n";
        let (nat, out, inbound) = invite_with_sdp(sdp, |nat| {
            nat.create_mapping(PROTO_UDP, Ipv4Addr::new(10, 0, 0, 5), 8000)
                .unwrap();
            nat.create_mapping(PROTO_UDP, Ipv4Addr::new(10, 0, 0, 6), 8001)
                .unwrap();
        });
        let rtp = port_after(&out, "m=audio ");
        let rtcp = port_after(&out, "a=rtcp:");
        assert_ne!(rtcp, rtp + 1, "{}", out);
        assert_eq!(reaches(&nat, &inbound, rtp), Some(8000));
        assert_eq!(reaches(&nat, &inbound, rtcp), Some(8001));
    }

    #[test]
    fn hold_relay_and_multicast_connection_addresses_are_left_alone() {
        // On hold (RFC 3264 §8.4): nothing to map, nothing to rewrite.
        let sdp = "v=0\r\nc=IN IP4 0.0.0.0\r\nm=audio 8000 RTP/AVP 0\r\n";
        let (nat, out, _) = invite_with_sdp(sdp, |_| {});
        assert_eq!(out, sdp);
        assert!(
            nat.take_expectation(PROTO_UDP, Ipv4Addr::new(10, 0, 0, 5), 8000)
                .is_none()
        );

        // A multicast group receives the media itself.
        let sdp = "v=0\r\nc=IN IP4 233.252.0.1/127\r\nm=audio 8000 RTP/AVP 0\r\n";
        let (_, out, _) = invite_with_sdp(sdp, |_| {});
        assert_eq!(out, sdp);

        // The session-level address is the host's, but the video stream's
        // own c= names a relay: only the audio stream is translated.
        let sdp = "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 8000 RTP/AVP 0\r\n\
m=video 9000 RTP/AVP 96\r\nc=IN IP4 192.0.2.77\r\n";
        let (_, out, _) = invite_with_sdp(sdp, |_| {});
        assert!(
            out.starts_with("v=0\r\nc=IN IP4 203.0.113.1\r\n"),
            "{}",
            out
        );
        assert_ne!(port_after(&out, "m=audio "), 8000, "{}", out);
        assert!(
            out.ends_with("m=video 9000 RTP/AVP 96\r\nc=IN IP4 192.0.2.77\r\n"),
            "{}",
            out
        );

        // And the other way round: held at session level, one stream on the
        // host itself.
        let sdp = "v=0\r\nc=IN IP4 0.0.0.0\r\nm=audio 8000 RTP/AVP 0\r\n\
m=video 9000 RTP/AVP 96\r\nc=IN IP4 10.0.0.5\r\n";
        let (_, out, _) = invite_with_sdp(sdp, |_| {});
        assert!(out.contains("c=IN IP4 0.0.0.0\r\nm=audio 8000 "), "{}", out);
        assert_ne!(port_after(&out, "m=video "), 9000, "{}", out);
        assert!(out.ends_with("\r\nc=IN IP4 203.0.113.1\r\n"), "{}", out);
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

    /// Run `body` from 10.0.0.5:5060 through the ALG as one TCP segment and
    /// return the payload that comes out.
    fn tcp_through_alg(body: &[u8]) -> Vec<u8> {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((40 + body.len()) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&[10, 0, 0, 5]);
        p[16..20].copy_from_slice(&[198, 51, 100, 9]);
        let ic = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ic.to_be_bytes());
        p[20..22].copy_from_slice(&5060u16.to_be_bytes());
        p[22..24].copy_from_slice(&5060u16.to_be_bytes());
        p[32] = 0x50;
        p[33] = 0x18;
        p.extend_from_slice(body);
        crate::nat::l4::fill_v4_l4_checksum(&mut p, 20);
        let m = NatMapping::new(
            PROTO_TCP,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            5060,
            20000,
        );
        let out = SipHelper::new().process_outbound(&nat, p, &m);
        assert!(crate::nat::l4::v4_l4_checksum_ok(&out, 20));
        payload_of(&out).to_vec()
    }

    fn invite(sdp: &str) -> String {
        format!(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 10.0.0.5:5060\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{}",
            sdp.len(),
            sdp
        )
    }

    #[test]
    fn each_sip_message_in_a_tcp_segment_is_rewritten_on_its_own() {
        let sdp = "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 8000 RTP/AVP 0\r\n";
        let second = "OPTIONS sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 10.0.0.5:5060\r\n\
Content-Type: text/plain\r\n\
Content-Length: 21\r\n\r\nc=IN IP4 10.0.0.5\r\nxy";
        let body = format!("{}\r\n\r\n{}", invite(sdp), second);
        let out = String::from_utf8(tcp_through_alg(body.as_bytes())).unwrap();

        let at = out.find("OPTIONS ").unwrap();
        let (first, rest) = out.split_at(at);
        let first = first.strip_suffix("\r\n\r\n").expect("keep-alive kept");
        // The INVITE: its SDP translated, its Content-Length its own.
        let (head, first_body) = first.split_once("\r\n\r\n").unwrap();
        assert!(first_body.starts_with("v=0\r\nc=IN IP4 203.0.113.1\r\nm=audio "));
        assert!(first_body.ends_with(" RTP/AVP 0\r\n"), "{first_body}");
        assert!(
            head.ends_with(&format!("\r\nContent-Length: {}", first_body.len())),
            "{head}"
        );
        // The second message: its headers translated, its body its own.
        assert_eq!(
            rest,
            second.replace("TCP 10.0.0.5:5060", "TCP 203.0.113.1:20000")
        );
    }

    #[test]
    fn sip_message_split_across_tcp_segments_is_left_alone() {
        let sdp = "v=0\r\nc=IN IP4 10.0.0.5\r\nm=audio 8000 RTP/AVP 0\r\n";
        let whole = invite(sdp);
        // Headers and the start of the body; the rest comes next segment.
        let part = &whole[..whole.len() - 20];
        assert_eq!(tcp_through_alg(part.as_bytes()), part.as_bytes());
        // The next segment, the body's tail, is no message to rewrite.
        let tail = &whole[whole.len() - 20..];
        assert_eq!(tcp_through_alg(tail.as_bytes()), tail.as_bytes());
        // A complete message before a partial one is still translated.
        let both = format!("{}{}", whole, part);
        let out = tcp_through_alg(both.as_bytes());
        assert!(out.ends_with(part.as_bytes()));
        assert!(String::from_utf8_lossy(&out).starts_with(
            "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP 203.0.113.1:20000\r\n"
        ));
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

    #[test]
    fn content_length_is_found_by_header_name() {
        let body = b"0123456789";
        for (head, want) in [
            // Another header merely ending in the name comes first.
            (
                &b"INVITE sip:a@b SIP/2.0\r\nX-Orig-Content-Length: 5\r\nContent-Length: 3\r\n\r\n"[..],
                &b"INVITE sip:a@b SIP/2.0\r\nX-Orig-Content-Length: 5\r\nContent-Length: 10\r\n\r\n"[..],
            ),
            // Whitespace before the colon (RFC 3261 HCOLON).
            (
                b"INVITE sip:a@b SIP/2.0\r\nContent-Length : 3\r\n\r\n",
                b"INVITE sip:a@b SIP/2.0\r\nContent-Length : 10\r\n\r\n",
            ),
            // The compact form, with a header ending in "l" before it.
            (
                b"INVITE sip:a@b SIP/2.0\r\nX-Url: x\r\nl:3\r\n\r\n",
                b"INVITE sip:a@b SIP/2.0\r\nX-Url: x\r\nl:10\r\n\r\n",
            ),
            (
                b"INVITE sip:a@b SIP/2.0\r\ncontent-LENGTH:\t3 \r\n\r\n",
                b"INVITE sip:a@b SIP/2.0\r\ncontent-LENGTH:\t10 \r\n\r\n",
            ),
        ] {
            let out = sip_update_content_length(&mut head.to_vec(), body);
            let (h, b) = out.split_at(want.len());
            assert_eq!(
                String::from_utf8_lossy(h),
                String::from_utf8_lossy(want),
                "from {}",
                String::from_utf8_lossy(head)
            );
            assert_eq!(b, body);
            // What is written is what is read.
            assert_eq!(content_length(&h[..h.len() - 4]), Some(body.len()));
        }
    }

    #[test]
    fn sdp_is_recognised_by_the_content_type_header_only() {
        assert!(is_sdp(b"INVITE x SIP/2.0\r\nContent-Type: application/sdp"));
        assert!(is_sdp(b"INVITE x SIP/2.0\r\nc :Application/SDP; charset=x"));
        assert!(!is_sdp(
            b"INVITE x SIP/2.0\r\nX-Content-Type: application/sdp"
        ));
        assert!(!is_sdp(
            b"INVITE x SIP/2.0\r\nContent-Type: text/plain\r\nX-Rc: application/sdp"
        ));
    }
}
