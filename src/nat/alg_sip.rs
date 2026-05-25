//! SIP (RFC 3261) Application Layer Gateway.
//!
//! Rewrites embedded IP addresses and ports in SIP `Via`/`Contact` headers and
//! SDP `c=`/`m=` lines so VoIP signalling and the resulting RTP/RTCP media
//! streams traverse the NAT. Outbound (inside -> outside) maps the inside
//! address to the public address; inbound performs the inverse. For each SDP
//! media line an outside port is allocated and two expectations (RTP + RTCP)
//! are registered.
//!
//! Port of `alg_sip.go`.

use crate::nat::helper::{Expectation, Helper, NatMapping, PacketHelper, PROTO_TCP, PROTO_UDP};
use crate::nat::nat::Nat;
use crate::{checksum, combine_checksums, pseudo_header_checksum, Protocol};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

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
                    rewrite_sdp_outbound(nat, &sdp_body, &outside_addr, inside_ip)
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
        sip_rebuild_packet(&pkt, ihl, proto, &new_payload)
    }
}

/// Rewrite SDP `c=` connection lines and `m=` media lines outbound, swapping
/// the inside address for the outside address and registering RTP/RTCP
/// expectations for each media stream.
fn rewrite_sdp_outbound(nat: &Nat, sdp: &[u8], outside_addr: &str, inside_ip: Ipv4Addr) -> Vec<u8> {
    let inside_addr = inside_ip.to_string();
    let mut remote_ip = Ipv4Addr::UNSPECIFIED;
    let mut out: Vec<Vec<u8>> = Vec::new();
    for raw in split_subslice(sdp, b"\r\n") {
        let mut line = raw.to_vec();
        if line.starts_with(b"c=IN IP4 ") {
            let rest = &line[b"c=IN IP4 ".len()..];
            let addr = String::from_utf8_lossy(rest).trim().to_string();
            if addr != inside_addr {
                if let Ok(a) = addr.parse::<Ipv4Addr>() {
                    remote_ip = a;
                }
            }
            line = format!("c=IN IP4 {}", outside_addr).into_bytes();
        } else if line.starts_with(b"m=") {
            if let Some(new_line) = sip_parse_media_line(&line, nat, remote_ip, inside_ip) {
                line = new_line;
            }
        }
        out.push(line);
    }
    join_subslice(&out, b"\r\n")
}

/// Replace inside addresses in `c=` lines (used inbound).
fn sip_rewrite_sdp_addr(sdp: &[u8], old_addr: &str, new_addr: &str) -> Vec<u8> {
    let old = format!("c=IN IP4 {}", old_addr).into_bytes();
    let new = format!("c=IN IP4 {}", new_addr).into_bytes();
    replace_all(sdp, &old, &new)
}

/// Parse an SDP `m=` media line, allocate an outside port, register RTP and
/// RTCP expectations, and return the rewritten line. Returns `None` if the line
/// could not be processed (left unchanged by the caller).
fn sip_parse_media_line(
    line: &[u8],
    nat: &Nat,
    remote_ip: Ipv4Addr,
    inside_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
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

    // Allocate an outside port for the RTP stream. The Go upstream additionally
    // prefers an even port (RFC 3550 convention); our allocator is a plain
    // counter, so we accept whatever it returns and use it for the rewrite.
    let rtp_out_port = nat.create_mapping(PROTO_UDP, inside_ip, inside_port)?;

    nat.add_expectation(Expectation {
        proto: PROTO_UDP,
        remote_ip,
        remote_port: 0, // remote RTP port not yet known
        inside_ip,
        inside_port,
        expires: Instant::now() + SIP_RTP_TIMEOUT,
    });

    // RTCP is conventionally RTP port + 1.
    let rtcp_inside = inside_port.wrapping_add(1);
    nat.create_mapping(PROTO_UDP, inside_ip, rtcp_inside);
    nat.add_expectation(Expectation {
        proto: PROTO_UDP,
        remote_ip,
        remote_port: 0,
        inside_ip,
        inside_port: rtcp_inside,
        expires: Instant::now() + SIP_RTP_TIMEOUT,
    });

    parts[1] = rtp_out_port.to_string().into_bytes();
    Some(join_subslice(&parts, b" "))
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
        let new_line = replace_all(line, old_val, new_val);
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

    if let Some(cl) = cl_idx {
        if let Some(line_end) = find_subslice(&headers[cl..], b"\r\n") {
            if let Some(colon) = headers[cl..cl + line_end].iter().position(|&b| b == b':') {
                let before = headers[..cl + colon + 1].to_vec();
                let after = headers[cl + line_end..].to_vec();
                let mut rebuilt = before;
                rebuilt.push(b' ');
                rebuilt.extend_from_slice(&new_cl);
                rebuilt.extend_from_slice(&after);
                *headers = rebuilt;
            }
        }
    }

    let mut result = Vec::with_capacity(headers.len() + sdp_body.len());
    result.extend_from_slice(headers);
    result.extend_from_slice(sdp_body);
    result
}

/// Reconstruct the IP packet with a new payload, fixing lengths and checksums.
fn sip_rebuild_packet(orig: &[u8], ihl: usize, proto: u8, new_payload: &[u8]) -> Vec<u8> {
    let l4_hdr_len = if proto == PROTO_TCP {
        if orig.len() < ihl + 20 {
            return orig.to_vec();
        }
        (orig[ihl + 12] >> 4) as usize * 4
    } else {
        8
    };

    let total = ihl + l4_hdr_len + new_payload.len();
    let mut out = vec![0u8; total];
    out[..ihl].copy_from_slice(&orig[..ihl]);
    if orig.len() >= ihl + l4_hdr_len {
        out[ihl..ihl + l4_hdr_len].copy_from_slice(&orig[ihl..ihl + l4_hdr_len]);
    }
    out[ihl + l4_hdr_len..].copy_from_slice(new_payload);

    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[10..12].copy_from_slice(&[0, 0]);
    let ip_csum = checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    if proto == PROTO_TCP {
        recalc_tcp_checksum(&mut out, ihl);
    } else if proto == PROTO_UDP {
        recalc_udp_checksum(&mut out, ihl);
    }
    out
}

fn recalc_tcp_checksum(pkt: &mut [u8], ihl: usize) {
    if pkt.len() < ihl + 18 {
        return;
    }
    let tcp_len = (pkt.len() - ihl) as u16;
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    pkt[ihl + 16..ihl + 18].copy_from_slice(&[0, 0]);
    let ph = pseudo_header_checksum(Protocol::TCP, IpAddr::V4(src), IpAddr::V4(dst), tcp_len);
    let seg = checksum(&pkt[ihl..]);
    let cs = combine_checksums(ph, seg);
    pkt[ihl + 16..ihl + 18].copy_from_slice(&cs.to_be_bytes());
}

fn recalc_udp_checksum(pkt: &mut [u8], ihl: usize) {
    if pkt.len() < ihl + 8 {
        return;
    }
    let udp_len = (pkt.len() - ihl) as u16;
    pkt[ihl + 4..ihl + 6].copy_from_slice(&udp_len.to_be_bytes());
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    pkt[ihl + 6..ihl + 8].copy_from_slice(&[0, 0]);
    let ph = pseudo_header_checksum(Protocol::UDP, IpAddr::V4(src), IpAddr::V4(dst), udp_len);
    let seg = checksum(&pkt[ihl..]);
    let mut cs = combine_checksums(ph, seg);
    if cs == 0 {
        cs = 0xFFFF; // a UDP checksum of zero is transmitted as all-ones
    }
    pkt[ihl + 6..ihl + 8].copy_from_slice(&cs.to_be_bytes());
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

fn replace_all(data: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    if old.is_empty() {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if i + old.len() <= data.len() && &data[i..i + old.len()] == old {
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
        let m = NatMapping {
            proto: PROTO_UDP,
            inside_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            inside_port: 5060,
            outside_port: 20000,
        };
        let out = h.process_outbound(&nat, pkt.clone(), &m);
        assert_eq!(out, pkt);
    }
}
