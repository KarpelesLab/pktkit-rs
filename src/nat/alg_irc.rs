//! IRC DCC Application Layer Gateway.
//!
//! Rewrites the IP (as a 32-bit decimal) and port in `\x01DCC SEND ...\x01`
//! and `\x01DCC CHAT ...\x01` payloads and registers an expectation so the
//! incoming DCC connection is forwarded to the inside client.

use crate::nat::helper::{Expectation, Helper, NatMapping, PacketHelper, PROTO_TCP};
use crate::nat::nat::Nat;
use crate::{checksum, combine_checksums, pseudo_header_checksum, Protocol};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

const IRC_EXPECT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct IrcHelper {
    ports: HashSet<u16>,
}

impl IrcHelper {
    /// Construct with the standard IRC port (6667) if `ports` is empty.
    pub fn new(ports: &[u16]) -> IrcHelper {
        let set: HashSet<u16> = if ports.is_empty() {
            [6667].into_iter().collect()
        } else {
            ports.iter().copied().collect()
        };
        IrcHelper { ports: set }
    }
}

impl Helper for IrcHelper {
    fn name(&self) -> &str {
        "irc"
    }
}

impl PacketHelper for IrcHelper {
    fn match_outbound(&self, proto: u8, dst_port: u16) -> bool {
        proto == PROTO_TCP && self.ports.contains(&dst_port)
    }

    fn process_outbound(&self, nat: &Nat, pkt: Vec<u8>, _m: &NatMapping) -> Vec<u8> {
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        if pkt.len() < ihl + 20 {
            return pkt;
        }
        let data_off = (pkt[ihl + 12] >> 4) as usize * 4;
        if data_off < 20 || pkt[ihl..].len() < data_off {
            return pkt;
        }
        let payload = &pkt[ihl + data_off..];
        if payload.is_empty() {
            return pkt;
        }
        let dcc_start = match find_subslice(payload, b"\x01DCC ") {
            Some(p) => p,
            None => return pkt,
        };
        let dcc_end_rel = match payload[dcc_start + 1..].iter().position(|&b| b == 0x01) {
            Some(p) => p,
            None => return pkt,
        };
        let dcc_end = dcc_start + 1 + dcc_end_rel;
        let body = &payload[dcc_start + 1..dcc_end];
        let fields: Vec<&[u8]> = body.split(|b| b.is_ascii_whitespace()).filter(|f| !f.is_empty()).collect();
        if fields.len() < 4 {
            return pkt;
        }
        let cmd = match std::str::from_utf8(fields[1]) {
            Ok(s) => s,
            Err(_) => return pkt,
        };
        if cmd != "SEND" && cmd != "CHAT" {
            return pkt;
        }
        // SEND: DCC SEND file ip port [size]  → ip idx 3, port idx 4
        // CHAT: DCC CHAT chat ip port         → ip idx 2, port idx 3 (using len-2/len-1)
        let (ip_idx, port_idx) = if cmd == "SEND" && fields.len() >= 5 {
            (3, 4)
        } else {
            (fields.len() - 2, fields.len() - 1)
        };
        let ip_val: u32 = match std::str::from_utf8(fields[ip_idx]).ok().and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => return pkt,
        };
        let port_val: u16 = match std::str::from_utf8(fields[port_idx]).ok().and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => return pkt,
        };
        let inside_ip = Ipv4Addr::from(ip_val);
        let outside_port = match nat.create_mapping(PROTO_TCP, inside_ip, port_val) {
            Some(p) => p,
            None => return pkt,
        };
        nat.add_expectation(Expectation {
            proto: PROTO_TCP,
            remote_ip: Ipv4Addr::UNSPECIFIED,
            remote_port: 0,
            inside_ip,
            inside_port: port_val,
            expires: Instant::now() + IRC_EXPECT_TIMEOUT,
        });

        let outside_octets = match nat.outside_addr() {
            Some(a) => a.octets(),
            None => return pkt,
        };
        let outside_u32 = u32::from_be_bytes(outside_octets);

        let mut new_dcc = Vec::with_capacity(body.len() + 8);
        new_dcc.push(0x01);
        for (i, f) in fields.iter().enumerate() {
            if i > 0 {
                new_dcc.push(b' ');
            }
            if i == ip_idx {
                new_dcc.extend_from_slice(outside_u32.to_string().as_bytes());
            } else if i == port_idx {
                new_dcc.extend_from_slice(outside_port.to_string().as_bytes());
            } else {
                new_dcc.extend_from_slice(f);
            }
        }
        new_dcc.push(0x01);

        let mut new_payload = Vec::with_capacity(payload.len() + 16);
        new_payload.extend_from_slice(&payload[..dcc_start]);
        new_payload.extend_from_slice(&new_dcc);
        new_payload.extend_from_slice(&payload[dcc_end + 1..]);

        rebuild_tcp_packet(&pkt, ihl, data_off, &new_payload)
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rebuild_tcp_packet(pkt: &[u8], ihl: usize, tcp_data_off: usize, new_payload: &[u8]) -> Vec<u8> {
    let total_len = ihl + tcp_data_off + new_payload.len();
    let mut out = vec![0u8; total_len];
    out[..ihl].copy_from_slice(&pkt[..ihl]);
    out[ihl..ihl + tcp_data_off].copy_from_slice(&pkt[ihl..ihl + tcp_data_off]);
    out[ihl + tcp_data_off..].copy_from_slice(new_payload);

    out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    out[10..12].copy_from_slice(&[0, 0]);
    let ip_csum = checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    let tcp_len = (total_len - ihl) as u16;
    let src = Ipv4Addr::new(out[12], out[13], out[14], out[15]);
    let dst = Ipv4Addr::new(out[16], out[17], out[18], out[19]);
    out[ihl + 16..ihl + 18].copy_from_slice(&[0, 0]);
    let ph = pseudo_header_checksum(Protocol::TCP, IpAddr::V4(src), IpAddr::V4(dst), tcp_len);
    let seg = checksum(&out[ihl..]);
    let tcsum = combine_checksums(ph, seg);
    out[ihl + 16..ihl + 18].copy_from_slice(&tcsum.to_be_bytes());
    out
}
