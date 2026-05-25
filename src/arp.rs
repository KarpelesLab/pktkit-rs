//! ARP (RFC 826) for IPv4 over Ethernet.
//!
//! - [`Table`] is the resolver cache: lookups, learning, capped at 4096 entries,
//!   entries age out after 5 minutes.
//! - [`Pending`] buffers packets awaiting resolution, up to 16 per target, and
//!   discards stale queues after 3 seconds.
//! - [`build_packet`] / [`parse`] encode and decode the 28-byte ARP body.

use crate::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const OP_REQUEST: u16 = 1;
pub const OP_REPLY: u16 = 2;

pub const DEFAULT_TTL: Duration = Duration::from_secs(5 * 60);
pub const PENDING_TIMEOUT: Duration = Duration::from_secs(3);
pub const PENDING_MAX_PKTS: usize = 16;
pub const MAX_ENTRIES: usize = 4096;

#[derive(Copy, Clone, Debug)]
struct Entry {
    mac: MacAddr,
    expires: Instant,
}

/// Thread-safe ARP cache.
#[derive(Default, Debug)]
pub struct Table {
    inner: Mutex<HashMap<Ipv4Addr, Entry>>,
}

impl Table {
    pub fn new() -> Table {
        Table::default()
    }

    /// Look up `ip`, returning its MAC if a non-expired entry exists.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
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

    /// Install or refresh an entry.
    pub fn set(&self, ip: Ipv4Addr, mac: MacAddr, ttl: Duration) {
        let mut t = self.inner.lock().unwrap();
        if !t.contains_key(&ip) && t.len() >= MAX_ENTRIES {
            // Prune expired entries before giving up.
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

/// Buffers packets waiting for ARP/NDP resolution and drops stale queues
/// every second via a background thread.
pub struct Pending {
    inner: Arc<Mutex<HashMap<Ipv4Addr, PendingEntry>>>,
    stop: Arc<Mutex<bool>>,
}

#[derive(Default)]
struct PendingEntry {
    packets: Vec<Vec<u8>>,
    created: Option<Instant>,
}

impl core::fmt::Debug for Pending {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let n = self.inner.lock().map(|m| m.len()).unwrap_or(0);
        f.debug_struct("arp::Pending").field("queues", &n).finish()
    }
}

impl Default for Pending {
    fn default() -> Self {
        Self::new()
    }
}

impl Pending {
    /// Build a new pending-queue, spawning a background cleanup thread.
    pub fn new() -> Pending {
        let inner = Arc::new(Mutex::new(HashMap::<Ipv4Addr, PendingEntry>::new()));
        let stop = Arc::new(Mutex::new(false));

        let inner_bg = inner.clone();
        let stop_bg = stop.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            if *stop_bg.lock().unwrap() {
                return;
            }
            let now = Instant::now();
            let mut map = inner_bg.lock().unwrap();
            map.retain(|_, e| {
                e.created
                    .map(|c| now.duration_since(c) <= PENDING_TIMEOUT)
                    .unwrap_or(true)
            });
        });

        Pending { inner, stop }
    }

    /// Buffer `pkt` for `ip`. Returns `true` when this is the first packet
    /// queued for `ip` — i.e. the caller should send an ARP solicitation now.
    pub fn enqueue(&self, ip: Ipv4Addr, pkt: &[u8]) -> bool {
        let mut map = self.inner.lock().unwrap();
        let entry = map.entry(ip).or_default();
        let first = entry.created.is_none();
        if first {
            entry.created = Some(Instant::now());
        }
        if entry.packets.len() < PENDING_MAX_PKTS {
            entry.packets.push(pkt.to_vec());
        }
        first
    }

    /// Remove and return every packet waiting for `ip`.
    pub fn drain(&self, ip: Ipv4Addr) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .unwrap()
            .remove(&ip)
            .map(|e| e.packets)
            .unwrap_or_default()
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        *self.stop.lock().unwrap() = true;
    }
}

/// Build the 28-byte ARP body for IPv4-over-Ethernet.
pub fn build_packet(
    op: u16,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0..2].copy_from_slice(&1u16.to_be_bytes()); // hardware: Ethernet
    b[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // protocol: IPv4
    b[4] = 6; // hardware addr len
    b[5] = 4; // protocol addr len
    b[6..8].copy_from_slice(&op.to_be_bytes());
    b[8..14].copy_from_slice(&sender_mac.octets());
    b[14..18].copy_from_slice(&sender_ip.octets());
    b[18..24].copy_from_slice(&target_mac.octets());
    b[24..28].copy_from_slice(&target_ip.octets());
    b
}

/// Parse a 28-byte ARP body. Returns `None` for malformed packets or for
/// hardware/protocol types other than Ethernet/IPv4.
pub fn parse(payload: &[u8]) -> Option<(u16, MacAddr, Ipv4Addr, MacAddr, Ipv4Addr)> {
    if payload.len() < 28 {
        return None;
    }
    if u16::from_be_bytes([payload[0], payload[1]]) != 1
        || u16::from_be_bytes([payload[2], payload[3]]) != 0x0800
    {
        return None;
    }
    if payload[4] != 6 || payload[5] != 4 {
        return None;
    }
    let op = u16::from_be_bytes([payload[6], payload[7]]);
    let mut sm = [0u8; 6];
    sm.copy_from_slice(&payload[8..14]);
    let si = Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]);
    let mut tm = [0u8; 6];
    tm.copy_from_slice(&payload[18..24]);
    let ti = Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]);
    Some((op, MacAddr(sm), si, MacAddr(tm), ti))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_parse_roundtrip() {
        let s = MacAddr([1, 2, 3, 4, 5, 6]);
        let t = MacAddr([7, 8, 9, 10, 11, 12]);
        let b = build_packet(OP_REQUEST, s, Ipv4Addr::new(10, 0, 0, 1), t, Ipv4Addr::new(10, 0, 0, 2));
        let (op, sm, si, tm, ti) = parse(&b).unwrap();
        assert_eq!(op, OP_REQUEST);
        assert_eq!(sm, s);
        assert_eq!(si, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(tm, t);
        assert_eq!(ti, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn parse_rejects_short() {
        assert!(parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn table_lookup_after_set() {
        let t = Table::new();
        let m = MacAddr([0xaa; 6]);
        t.set(Ipv4Addr::new(10, 0, 0, 1), m, Duration::from_secs(60));
        assert_eq!(t.lookup(Ipv4Addr::new(10, 0, 0, 1)), Some(m));
        assert_eq!(t.lookup(Ipv4Addr::new(10, 0, 0, 2)), None);
    }

    #[test]
    fn pending_first_then_more() {
        let p = Pending::new();
        assert!(p.enqueue(Ipv4Addr::new(10, 0, 0, 1), &[1, 2, 3]));
        assert!(!p.enqueue(Ipv4Addr::new(10, 0, 0, 1), &[4, 5, 6]));
        let drained = p.drain(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(drained.len(), 2);
    }
}
