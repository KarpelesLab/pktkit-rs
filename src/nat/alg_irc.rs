//! IRC DCC Application Layer Gateway.
//!
//! Rewrites the IP (as a 32-bit decimal) and port in `\x01DCC SEND ...\x01`
//! and `\x01DCC CHAT ...\x01` payloads and registers an expectation so the
//! incoming DCC connection is forwarded to the inside client.

use crate::nat::alg_ftp::is_own_endpoint;
use crate::nat::helper::{Expectation, Helper, NatMapping, PROTO_TCP, PacketHelper};
use crate::nat::l4::replace_payload;
use crate::nat::nat::Nat;
use crate::time::Instant;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;

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

    fn process_outbound(&self, nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
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
        let fields: Vec<&[u8]> = body
            .split(|b| b.is_ascii_whitespace())
            .filter(|f| !f.is_empty())
            .collect();
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
        let ip_val: u32 = match std::str::from_utf8(fields[ip_idx])
            .ok()
            .and_then(|s| s.parse().ok())
        {
            Some(v) => v,
            None => return pkt,
        };
        let port_val: u16 = match std::str::from_utf8(fields[port_idx])
            .ok()
            .and_then(|s| s.parse().ok())
        {
            Some(v) => v,
            None => return pkt,
        };
        let inside_ip = Ipv4Addr::from(ip_val);
        if !is_own_endpoint(m, inside_ip, port_val) {
            return pkt;
        }
        let outside_port = match nat.create_mapping_in(m.namespace, PROTO_TCP, inside_ip, port_val)
        {
            Some(p) => p,
            None => return pkt,
        };
        // The DCC peer is not known yet: any remote may connect, but only to
        // the port advertised in the rewritten message.
        nat.add_expectation(
            Expectation::new(
                PROTO_TCP,
                inside_ip,
                port_val,
                outside_port,
                Instant::now() + IRC_EXPECT_TIMEOUT,
            )
            .namespace(m.namespace),
        );

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

        replace_payload(&pkt, ihl, data_off, &new_payload)
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;
    use crate::nat::l4::{fill_v4_l4_checksum, v4_l4_checksum_ok};
    use crate::{IpPrefix, L3Device, Packet};
    use std::sync::{Arc, Mutex as StdMutex};

    fn pfx(s: &str) -> IpPrefix {
        s.parse().unwrap()
    }

    fn build_irc(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
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
        fill_v4_l4_checksum(&mut p, 20);
        p
    }

    fn setup() -> (Arc<Nat>, Arc<StdMutex<Vec<Vec<u8>>>>) {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_packet_helper(Arc::new(IrcHelper::new(&[])));
        let captured = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = captured.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        (nat, captured)
    }

    #[test]
    fn dcc_send_is_rewritten_with_a_valid_checksum() {
        let (nat, captured) = setup();
        let inside = Ipv4Addr::new(10, 0, 0, 5);
        let msg = format!(
            "PRIVMSG bob :\x01DCC SEND file.txt {} 5000 1234\x01\r\n",
            u32::from(inside)
        );
        let pkt = build_irc(
            inside,
            40000,
            Ipv4Addr::new(198, 51, 100, 9),
            6667,
            msg.as_bytes(),
        );
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();

        let out = captured.lock().unwrap();
        assert_eq!(out.len(), 1);
        let s = String::from_utf8_lossy(&out[0][40..]).to_string();
        let outside = u32::from(Ipv4Addr::new(203, 0, 113, 1));
        assert!(
            s.contains(&format!("DCC SEND file.txt {} ", outside)),
            "got {}",
            s
        );
        assert!(
            v4_l4_checksum_ok(&out[0], 20),
            "rewritten DCC segment must verify"
        );
    }

    #[test]
    fn dcc_naming_another_host_is_left_alone() {
        let (nat, captured) = setup();
        let victim = Ipv4Addr::new(10, 0, 0, 7);
        let msg = format!(
            "PRIVMSG bob :\x01DCC SEND f {} 22 1\x01\r\n",
            u32::from(victim)
        );
        let pkt = build_irc(
            Ipv4Addr::new(10, 0, 0, 5),
            40000,
            Ipv4Addr::new(198, 51, 100, 9),
            6667,
            msg.as_bytes(),
        );
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();
        let out = captured.lock().unwrap();
        assert_eq!(&out[0][40..], msg.as_bytes());
        assert!(nat.take_expectation(PROTO_TCP, victim, 22).is_none());
    }
}
