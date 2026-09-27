//! FTP Application Layer Gateway (RFC 959).
//!
//! Rewrites `PORT`/`EPRT` commands outbound so active-mode data connections
//! work through the NAT. Passive mode (`227`/`229` replies) needs nothing: the
//! inside client opens the data connection itself, and the ordinary outbound
//! path maps it.

use crate::nat::helper::{Expectation, Helper, NatMapping, PROTO_TCP, PacketHelper};
use crate::nat::l4::replace_payload;
use crate::nat::nat::Nat;
use crate::time::Instant;
use std::net::Ipv4Addr;
use std::time::Duration;

const FTP_EXPECT_TIMEOUT: Duration = Duration::from_secs(60);

/// FTP ALG helper. Construct with [`new`](Self::new) and register via
/// [`Nat::add_packet_helper`](crate::nat::Nat::add_packet_helper).
#[derive(Debug, Default)]
pub struct FtpHelper;

impl FtpHelper {
    pub fn new() -> FtpHelper {
        FtpHelper
    }
}

impl Helper for FtpHelper {
    fn name(&self) -> &str {
        "ftp"
    }
}

impl PacketHelper for FtpHelper {
    fn match_outbound(&self, proto: u8, dst_port: u16) -> bool {
        proto == PROTO_TCP && dst_port == 21
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
        let upper: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
        if upper.starts_with(b"PORT ") {
            return rewrite_port(nat, &pkt, ihl, data_off, m);
        }
        if upper.starts_with(b"EPRT ") {
            return rewrite_eprt(nat, &pkt, ihl, data_off, m);
        }
        pkt
    }
}

fn rewrite_port(nat: &Nat, pkt: &[u8], ihl: usize, data_off: usize, m: &NatMapping) -> Vec<u8> {
    let payload = &pkt[ihl + data_off..];
    let end = match find_crlf(payload) {
        Some(p) => p,
        None => return pkt.to_vec(),
    };
    let args = &payload[5..end];
    let parts: Vec<&[u8]> = args.split(|&b| b == b',').collect();
    if parts.len() != 6 {
        return pkt.to_vec();
    }
    let mut ip = [0u8; 4];
    for i in 0..4 {
        let v: u16 = match std::str::from_utf8(parts[i])
            .ok()
            .and_then(|s| s.parse().ok())
        {
            Some(v) if v <= 255 => v,
            _ => return pkt.to_vec(),
        };
        ip[i] = v as u8;
    }
    let p1: u16 = match std::str::from_utf8(parts[4])
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(v) if v <= 255 => v,
        _ => return pkt.to_vec(),
    };
    let p2: u16 = match std::str::from_utf8(parts[5])
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(v) if v <= 255 => v,
        _ => return pkt.to_vec(),
    };
    let inside_port = p1 * 256 + p2;
    let inside_ip = Ipv4Addr::from(ip);
    if !is_own_endpoint(m, inside_ip, inside_port) {
        return pkt.to_vec();
    }

    let outside_data_port =
        match nat.create_mapping_in(m.namespace, PROTO_TCP, inside_ip, inside_port) {
            Some(p) => p,
            None => return pkt.to_vec(),
        };

    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    nat.add_expectation(
        Expectation::new(
            PROTO_TCP,
            inside_ip,
            inside_port,
            outside_data_port,
            Instant::now() + FTP_EXPECT_TIMEOUT,
        )
        .remote_ip(dst_ip)
        .namespace(m.namespace),
    );

    let outside_ip = match nat.outside_addr() {
        Some(a) => a.octets(),
        None => return pkt.to_vec(),
    };

    let mut new_payload = format!(
        "PORT {},{},{},{},{},{}\r\n",
        outside_ip[0],
        outside_ip[1],
        outside_ip[2],
        outside_ip[3],
        outside_data_port / 256,
        outside_data_port % 256,
    )
    .into_bytes();
    new_payload.extend_from_slice(&payload[end + 2..]);

    replace_payload(pkt, ihl, data_off, &new_payload)
}

fn rewrite_eprt(nat: &Nat, pkt: &[u8], ihl: usize, data_off: usize, m: &NatMapping) -> Vec<u8> {
    let payload = &pkt[ihl + data_off..];
    let end = match find_crlf(payload) {
        Some(p) => p,
        None => return pkt.to_vec(),
    };
    let args = &payload[5..end];
    if args.len() < 7 || args[0] != b'|' {
        return pkt.to_vec();
    }
    let fields: Vec<&[u8]> = args[1..].split(|&b| b == b'|').collect();
    if fields.len() < 3 {
        return pkt.to_vec();
    }
    if fields[0] != b"1" {
        return pkt.to_vec();
    }
    let ip_str = match std::str::from_utf8(fields[1]) {
        Ok(s) => s,
        Err(_) => return pkt.to_vec(),
    };
    let inside_ip: Ipv4Addr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => return pkt.to_vec(),
    };
    let inside_port: u16 = match std::str::from_utf8(fields[2])
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(p) => p,
        None => return pkt.to_vec(),
    };
    if !is_own_endpoint(m, inside_ip, inside_port) {
        return pkt.to_vec();
    }

    let outside_data_port =
        match nat.create_mapping_in(m.namespace, PROTO_TCP, inside_ip, inside_port) {
            Some(p) => p,
            None => return pkt.to_vec(),
        };
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    nat.add_expectation(
        Expectation::new(
            PROTO_TCP,
            inside_ip,
            inside_port,
            outside_data_port,
            Instant::now() + FTP_EXPECT_TIMEOUT,
        )
        .remote_ip(dst_ip)
        .namespace(m.namespace),
    );

    let outside_ip = match nat.outside_addr() {
        Some(a) => a,
        None => return pkt.to_vec(),
    };
    let mut new_payload = format!("EPRT |1|{}|{}|\r\n", outside_ip, outside_data_port).into_bytes();
    new_payload.extend_from_slice(&payload[end + 2..]);
    replace_payload(pkt, ihl, data_off, &new_payload)
}

/// Only an address belonging to the host that sent the command is opened
/// up. The payload is the client's to write: honouring any address in it
/// would let one inside host expose another host's port to the Internet
/// (`PORT 10,0,0,7,0,22` sent by 10.0.0.5).
pub(crate) fn is_own_endpoint(m: &NatMapping, ip: Ipv4Addr, port: u16) -> bool {
    port != 0 && m.inside_ip == std::net::IpAddr::V4(ip)
}

fn find_crlf(b: &[u8]) -> Option<usize> {
    b.windows(2).position(|w| w == b"\r\n")
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

    fn build_ftp_port_pkt(
        src: Ipv4Addr,
        sport: u16,
        dst: Ipv4Addr,
        dport: u16,
        command: &[u8],
    ) -> Vec<u8> {
        // IP(20) + TCP(20) + payload
        let total = 20 + 20 + command.len();
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
        p[32] = 0x50; // data offset = 5
        p[33] = 0x18; // PSH | ACK
        p[40..].copy_from_slice(command);
        crate::nat::l4::fill_v4_l4_checksum(&mut p, 20);
        p
    }

    #[test]
    fn ftp_port_rewrites_address_and_creates_expectation() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_packet_helper(Arc::new(FtpHelper::new()));

        let captured = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = captured.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        // PORT 10,0,0,5,4,210 → port 4*256+210=1234, ip 10.0.0.5
        let inside_client = Ipv4Addr::new(10, 0, 0, 5);
        let pkt = build_ftp_port_pkt(
            inside_client,
            45000,
            Ipv4Addr::new(198, 51, 100, 9),
            21,
            b"PORT 10,0,0,5,4,210\r\n",
        );
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();

        let outbound = captured.lock().unwrap();
        assert_eq!(outbound.len(), 1);
        let out = &outbound[0];
        // Payload should now mention outside address 203,0,113,1
        let ihl = (out[0] & 0x0F) as usize * 4;
        let data_off = (out[ihl + 12] >> 4) as usize * 4;
        let payload = &out[ihl + data_off..];
        let s = std::str::from_utf8(payload).unwrap();
        assert!(s.starts_with("PORT 203,0,113,1,"), "got {}", s);
        assert!(
            crate::nat::l4::v4_l4_checksum_ok(out, ihl),
            "rewritten PORT segment must carry a valid TCP checksum"
        );
    }

    #[test]
    fn port_naming_another_host_is_left_alone() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_packet_helper(Arc::new(FtpHelper::new()));
        let captured = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = captured.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let server = Ipv4Addr::new(198, 51, 100, 9);
        let victim = Ipv4Addr::new(10, 0, 0, 7);
        for cmd in [&b"PORT 10,0,0,7,0,22\r\n"[..], b"EPRT |1|10.0.0.7|22|\r\n"] {
            let pkt = build_ftp_port_pkt(Ipv4Addr::new(10, 0, 0, 5), 45000, server, 21, cmd);
            nat.inside().send(Packet::from_slice(&pkt)).unwrap();
            let out = captured.lock().unwrap().pop().unwrap();
            assert_eq!(&out[40..], cmd, "payload must pass unchanged");
            assert!(nat.take_expectation(PROTO_TCP, victim, 22).is_none());
        }
    }

    #[test]
    fn hostile_227_reply_is_harmless() {
        let nat = Nat::new(pfx("10.0.0.1/24"), pfx("203.0.113.1/24"));
        nat.add_packet_helper(Arc::new(FtpHelper::new()));
        let outside = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = outside.clone();
        nat.outside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));
        let inside = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
        let c = inside.clone();
        nat.inside().set_handler(Arc::new(move |p| {
            c.lock().unwrap().push(p.as_bytes().to_vec());
            Ok(())
        }));

        let client = Ipv4Addr::new(10, 0, 0, 5);
        let server = Ipv4Addr::new(198, 51, 100, 9);
        let pkt = build_ftp_port_pkt(client, 45000, server, 21, b"PASV\r\n");
        nat.inside().send(Packet::from_slice(&pkt)).unwrap();
        let mapped = {
            let o = outside.lock().unwrap();
            u16::from_be_bytes([o[0][20], o[0][21]])
        };

        // Port numbers out of range must not overflow the port arithmetic.
        let reply = build_ftp_port_pkt(
            server,
            21,
            Ipv4Addr::new(203, 0, 113, 1),
            mapped,
            b"227 Entering Passive Mode (1,2,3,4,65535,0)\r\n",
        );
        nat.outside().send(Packet::from_slice(&reply)).unwrap();
        assert_eq!(inside.lock().unwrap().len(), 1);
        // The passive data connection is opened by the inside client, so the
        // reply must not have opened anything towards the inside.
        assert!(nat.take_expectation(PROTO_TCP, client, 0).is_none());
    }
}
