//! FTP Application Layer Gateway (RFC 959).
//!
//! Rewrites `PORT`/`EPRT` commands outbound and `227`/`229` responses inbound
//! so active and passive mode data connections work through the NAT.

use crate::nat::helper::{Expectation, Helper, NatMapping, PacketHelper, PROTO_TCP};
use crate::nat::nat::Nat;
use crate::{checksum, combine_checksums, pseudo_header_checksum, Protocol};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

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

    fn process_inbound(&self, nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
        let ihl = (pkt[0] & 0x0F) as usize * 4;
        if pkt.len() < ihl + 20 {
            return pkt;
        }
        let data_off = (pkt[ihl + 12] >> 4) as usize * 4;
        if data_off < 20 || pkt[ihl..].len() < data_off {
            return pkt;
        }
        let payload = &pkt[ihl + data_off..];
        if payload.starts_with(b"227 ") {
            register_227(nat, &pkt, ihl, data_off, m);
            // We don't rewrite addresses in 227 — passive mode is initiated by
            // the inside client outbound, so the normal NAT path handles it.
        } else if payload.starts_with(b"229 ") {
            register_229(nat, &pkt, ihl, data_off, m);
        }
        pkt
    }
}

fn rewrite_port(nat: &Nat, pkt: &[u8], ihl: usize, data_off: usize, _m: &NatMapping) -> Vec<u8> {
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

    let outside_data_port = match nat.create_mapping(PROTO_TCP, inside_ip, inside_port) {
        Some(p) => p,
        None => return pkt.to_vec(),
    };

    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    nat.add_expectation(Expectation {
        proto: PROTO_TCP,
        remote_ip: dst_ip,
        remote_port: 0,
        inside_ip,
        inside_port,
        expires: Instant::now() + FTP_EXPECT_TIMEOUT,
    });

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

    rebuild_tcp_packet(pkt, ihl, data_off, &new_payload)
}

fn rewrite_eprt(nat: &Nat, pkt: &[u8], ihl: usize, data_off: usize, _m: &NatMapping) -> Vec<u8> {
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

    let outside_data_port = match nat.create_mapping(PROTO_TCP, inside_ip, inside_port) {
        Some(p) => p,
        None => return pkt.to_vec(),
    };
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    nat.add_expectation(Expectation {
        proto: PROTO_TCP,
        remote_ip: dst_ip,
        remote_port: 0,
        inside_ip,
        inside_port,
        expires: Instant::now() + FTP_EXPECT_TIMEOUT,
    });

    let outside_ip = match nat.outside_addr() {
        Some(a) => a,
        None => return pkt.to_vec(),
    };
    let mut new_payload = format!("EPRT |1|{}|{}|\r\n", outside_ip, outside_data_port).into_bytes();
    new_payload.extend_from_slice(&payload[end + 2..]);
    rebuild_tcp_packet(pkt, ihl, data_off, &new_payload)
}

fn register_227(nat: &Nat, pkt: &[u8], ihl: usize, data_off: usize, m: &NatMapping) {
    let payload = &pkt[ihl + data_off..];
    let end = match find_crlf(payload) {
        Some(p) => p,
        None => return,
    };
    let line = &payload[..end];
    let lp = match line.iter().position(|&b| b == b'(') {
        Some(p) => p,
        None => return,
    };
    let rp = match line.iter().position(|&b| b == b')') {
        Some(p) => p,
        None => return,
    };
    if rp <= lp {
        return;
    }
    let inner = &line[lp + 1..rp];
    let parts: Vec<&[u8]> = inner.split(|&b| b == b',').collect();
    if parts.len() != 6 {
        return;
    }
    let mut ip = [0u8; 4];
    for i in 0..4 {
        ip[i] = match std::str::from_utf8(parts[i])
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
        {
            Some(v) if v <= 255 => v as u8,
            _ => return,
        };
    }
    let p1: u16 = match std::str::from_utf8(parts[4])
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(v) => v,
        None => return,
    };
    let p2: u16 = match std::str::from_utf8(parts[5])
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(v) => v,
        None => return,
    };
    let server_port = p1 * 256 + p2;
    let server_ip = Ipv4Addr::from(ip);
    let inside_ip = match m.inside_ip {
        IpAddr::V4(a) => a,
        _ => return,
    };
    nat.add_expectation(Expectation {
        proto: PROTO_TCP,
        remote_ip: server_ip,
        remote_port: server_port,
        inside_ip,
        inside_port: 0,
        expires: Instant::now() + FTP_EXPECT_TIMEOUT,
    });
}

fn register_229(nat: &Nat, pkt: &[u8], ihl: usize, data_off: usize, m: &NatMapping) {
    let payload = &pkt[ihl + data_off..];
    let end = match find_crlf(payload) {
        Some(p) => p,
        None => return,
    };
    let line = &payload[..end];
    let lp = match line.iter().position(|&b| b == b'(') {
        Some(p) => p,
        None => return,
    };
    let rp = match line.iter().position(|&b| b == b')') {
        Some(p) => p,
        None => return,
    };
    if rp <= lp {
        return;
    }
    let inner = &line[lp + 1..rp];
    if !inner.starts_with(b"|||") || !inner.ends_with(b"|") {
        return;
    }
    let port_str = &inner[3..inner.len() - 1];
    let port: u16 = match std::str::from_utf8(port_str)
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(p) => p,
        None => return,
    };
    // Server IP = source of the inbound packet.
    let server_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let inside_ip = match m.inside_ip {
        IpAddr::V4(a) => a,
        _ => return,
    };
    nat.add_expectation(Expectation {
        proto: PROTO_TCP,
        remote_ip: server_ip,
        remote_port: port,
        inside_ip,
        inside_port: 0,
        expires: Instant::now() + FTP_EXPECT_TIMEOUT,
    });
}

fn find_crlf(b: &[u8]) -> Option<usize> {
    b.windows(2).position(|w| w == b"\r\n")
}

/// Replace the TCP payload and recalculate IP and TCP checksums from scratch.
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

#[cfg(test)]
mod tests {
    use super::*;
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
        // TCP checksum
        let ph = pseudo_header_checksum(
            Protocol::TCP,
            IpAddr::V4(src),
            IpAddr::V4(dst),
            20 + command.len() as u16,
        );
        let seg = checksum(&p[20..]);
        let cs = combine_checksums(ph, seg);
        p[36..38].copy_from_slice(&cs.to_be_bytes());
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
    }
}
