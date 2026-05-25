//! NDP (RFC 4861): neighbor cache + Neighbor Solicitation/Advertisement codec
//! for IPv6.

use crate::MacAddr;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const NS_TYPE: u8 = 135;
pub const NA_TYPE: u8 = 136;
pub const RS_TYPE: u8 = 133;
pub const RA_TYPE: u8 = 134;

pub const OPT_SOURCE_LINK_ADDR: u8 = 1;
pub const OPT_TARGET_LINK_ADDR: u8 = 2;

pub const DEFAULT_TTL: Duration = Duration::from_secs(5 * 60);
pub const MAX_ENTRIES: usize = 4096;

#[derive(Copy, Clone, Debug)]
struct Entry {
    mac: MacAddr,
    expires: Instant,
}

/// IPv6 neighbor cache.
#[derive(Default, Debug)]
pub struct Table {
    inner: Mutex<HashMap<Ipv6Addr, Entry>>,
}

impl Table {
    pub fn new() -> Table {
        Table::default()
    }

    pub fn lookup(&self, ip: Ipv6Addr) -> Option<MacAddr> {
        let mut t = self.inner.lock().unwrap();
        match t.get(&ip).copied() {
            Some(e) if e.expires > Instant::now() => Some(e.mac),
            Some(_) => {
                t.remove(&ip);
                None
            }
            None => None,
        }
    }

    pub fn set(&self, ip: Ipv6Addr, mac: MacAddr, ttl: Duration) {
        let mut t = self.inner.lock().unwrap();
        if !t.contains_key(&ip) && t.len() >= MAX_ENTRIES {
            let now = Instant::now();
            t.retain(|_, e| e.expires > now);
            if t.len() >= MAX_ENTRIES {
                return;
            }
        }
        t.insert(
            ip,
            Entry {
                mac,
                expires: Instant::now() + ttl,
            },
        );
    }
}

/// Derive a link-local IPv6 address from a MAC using EUI-64 (RFC 4291 §2.5.1).
pub fn link_local_from_mac(mac: MacAddr) -> Ipv6Addr {
    let m = mac.octets();
    Ipv6Addr::from([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0,
        m[0] ^ 0x02, m[1], m[2], 0xff,
        0xfe, m[3], m[4], m[5],
    ])
}

/// Return the solicited-node multicast address for `addr`
/// (`ff02::1:ffXX:XXXX`, taking the low 3 bytes of `addr`).
pub fn solicited_node_multicast(addr: Ipv6Addr) -> Ipv6Addr {
    let a = addr.octets();
    Ipv6Addr::from([
        0xff, 0x02, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0x01, 0xff, a[13], a[14], a[15],
    ])
}

/// Multicast MAC corresponding to a solicited-node multicast IPv6 address.
pub fn solicited_node_mac(addr: Ipv6Addr) -> MacAddr {
    let a = addr.octets();
    MacAddr([0x33, 0x33, 0xff, a[13], a[14], a[15]])
}

/// ICMPv6 checksum over the IPv6 pseudo-header + `icmp_data`.
pub fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmp_data: &[u8]) -> u16 {
    let s = src.octets();
    let d = dst.octets();
    let length = icmp_data.len();

    let mut sum: u32 = 0;
    for i in (0..16).step_by(2) {
        sum += ((s[i] as u32) << 8) | (s[i + 1] as u32);
    }
    for i in (0..16).step_by(2) {
        sum += ((d[i] as u32) << 8) | (d[i + 1] as u32);
    }
    sum += length as u32;
    sum += 58; // ICMPv6 next header

    let mut i = 0;
    while i + 1 < length {
        sum += ((icmp_data[i] as u32) << 8) | (icmp_data[i + 1] as u32);
        i += 2;
    }
    if length & 1 != 0 {
        sum += (icmp_data[length - 1] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Build a Neighbor Solicitation ICMPv6 payload. Returns 32 bytes.
pub fn build_ns(src_mac: MacAddr, target: Ipv6Addr) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = NS_TYPE;
    let t = target.octets();
    b[8..24].copy_from_slice(&t);
    b[24] = OPT_SOURCE_LINK_ADDR;
    b[25] = 1; // length in 8-byte units
    b[26..32].copy_from_slice(&src_mac.octets());
    b
}

/// Build a Neighbor Advertisement ICMPv6 payload. Returns 32 bytes.
///
/// `solicited` controls the S flag (set on unicast responses, cleared on
/// DAD responses to all-nodes multicast). The O (override) flag is always set.
pub fn build_na(src_mac: MacAddr, target: Ipv6Addr, solicited: bool) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = NA_TYPE;
    let mut flags = 0u8;
    if solicited {
        flags |= 0x40;
    }
    flags |= 0x20; // override
    b[4] = flags;
    let t = target.octets();
    b[8..24].copy_from_slice(&t);
    b[24] = OPT_TARGET_LINK_ADDR;
    b[25] = 1;
    b[26..32].copy_from_slice(&src_mac.octets());
    b
}

/// Wrap an ICMPv6 payload in an IPv6 header (hop limit 255 per RFC 4861).
///
/// The ICMPv6 checksum is computed and written into `icmp_payload` (offset 2..4)
/// before encapsulation.
pub fn wrap_icmpv6(src: Ipv6Addr, dst: Ipv6Addr, icmp_payload: &mut [u8]) -> Vec<u8> {
    icmp_payload[2] = 0;
    icmp_payload[3] = 0;
    let cs = icmpv6_checksum(src, dst, icmp_payload);
    icmp_payload[2..4].copy_from_slice(&cs.to_be_bytes());

    let mut ip = vec![0u8; 40 + icmp_payload.len()];
    ip[0] = 0x60; // version 6
    ip[4..6].copy_from_slice(&(icmp_payload.len() as u16).to_be_bytes());
    ip[6] = 58;
    ip[7] = 255;
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    ip[40..].copy_from_slice(icmp_payload);
    ip
}

/// Scan an NDP option list for `opt_type` and return the 6-byte link-layer
/// address it carries, if any.
pub fn parse_option(mut opts: &[u8], opt_type: u8) -> Option<MacAddr> {
    while opts.len() >= 8 {
        let t = opts[0];
        let l = opts[1] as usize * 8;
        if l == 0 || l > opts.len() {
            return None;
        }
        if t == opt_type && l >= 8 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&opts[2..8]);
            return Some(MacAddr(mac));
        }
        opts = &opts[l..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_eui64() {
        let m: MacAddr = "00:1c:42:00:00:09".parse().unwrap();
        let ll = link_local_from_mac(m);
        // EUI-64 flips the U/L bit: 0x00 ^ 0x02 = 0x02
        assert_eq!(ll.octets()[8], 0x02);
        assert_eq!(ll.octets()[9], 0x1c);
        assert_eq!(ll.octets()[11], 0xff);
        assert_eq!(ll.octets()[12], 0xfe);
    }

    #[test]
    fn solicited_node_address() {
        let ip: Ipv6Addr = "2001:db8::1:2:3".parse().unwrap();
        let sol = solicited_node_multicast(ip);
        let so = sol.octets();
        assert_eq!(so[0..3], [0xff, 0x02, 0]);
        assert_eq!(so[11], 0x01);
        assert_eq!(so[12], 0xff);
    }

    #[test]
    fn ns_then_parse_option() {
        let m: MacAddr = "02:11:22:33:44:55".parse().unwrap();
        let target: Ipv6Addr = "fe80::1".parse().unwrap();
        let ns = build_ns(m, target);
        assert_eq!(ns[0], NS_TYPE);
        let mac = parse_option(&ns[24..], OPT_SOURCE_LINK_ADDR).unwrap();
        assert_eq!(mac, m);
    }
}
