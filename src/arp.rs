//! ARP (RFC 826) for IPv4 over Ethernet.
//!
//! - [`Table`] is the resolver cache: lookups, learning, capped at 4096 entries
//!   (a full cache evicts the entry closest to expiry),
//!   entries age out after 5 minutes.
//! - [`Pending`] buffers packets awaiting resolution, up to 16 per target, and
//!   discards stale queues after 3 seconds.
//! - [`build_packet`] / [`parse`] encode and decode the 28-byte ARP body.

use crate::MacAddr;
use crate::time::Instant;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

    /// Forget every entry, as when the network they were learnt on is left.
    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    /// Install or refresh an entry.
    pub fn set(&self, ip: Ipv4Addr, mac: MacAddr, ttl: Duration) {
        let mut t = self.inner.lock().unwrap();
        if !t.contains_key(&ip) && t.len() >= MAX_ENTRIES {
            make_room(&mut t);
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

/// Free a slot in a full cache. Expired entries go first; failing that, the
/// one closest to expiring -- the least recently confirmed. Refusing the new
/// entry instead would let anyone who fills the cache with made-up senders
/// keep every real neighbour out of it for good.
fn make_room(t: &mut HashMap<Ipv4Addr, Entry>) {
    let now = Instant::now();
    t.retain(|_, e| e.expires > now);
    if t.len() >= MAX_ENTRIES
        && let Some(oldest) = t.iter().min_by_key(|(_, e)| e.expires).map(|(k, _)| *k)
    {
        t.remove(&oldest);
    }
}

/// Buffers packets waiting for ARP/NDP resolution, keyed by the address
/// being resolved (`Ipv4Addr` for ARP, `Ipv6Addr` for NDP). A queue older
/// than [`PENDING_TIMEOUT`] is dropped, so the next packet for that target
/// solicits again.
///
/// Stale queues are pruned whenever a packet is queued; where threads are
/// available a background thread also sweeps every second, so memory held for
/// targets that never answer is released even when traffic stops.
pub struct Pending<K = Ipv4Addr> {
    inner: Arc<Mutex<HashMap<K, PendingEntry>>>,
    stop: Arc<Mutex<bool>>,
}

#[derive(Default)]
struct PendingEntry {
    packets: Vec<Vec<u8>>,
    created: Option<Instant>,
}

impl<K> core::fmt::Debug for Pending<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let n = self.inner.lock().map(|m| m.len()).unwrap_or(0);
        f.debug_struct("arp::Pending").field("queues", &n).finish()
    }
}

impl<K: Eq + Hash + Copy + Send + 'static> Default for Pending<K> {
    fn default() -> Self {
        Self::new()
    }
}

fn prune<K>(map: &mut HashMap<K, PendingEntry>, now: Instant) {
    map.retain(|_, e| {
        e.created
            .map(|c| now.duration_since(c) <= PENDING_TIMEOUT)
            .unwrap_or(true)
    });
}

impl<K: Eq + Hash + Copy + Send + 'static> Pending<K> {
    /// Build a new pending-queue, spawning a background cleanup thread where
    /// the target has threads.
    pub fn new() -> Pending<K> {
        let inner = Arc::new(Mutex::new(HashMap::<K, PendingEntry>::new()));
        let stop = Arc::new(Mutex::new(false));

        #[cfg(not(target_family = "wasm"))]
        {
            let inner_bg = inner.clone();
            let stop_bg = stop.clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    if *stop_bg.lock().unwrap() {
                        return;
                    }
                    prune(&mut inner_bg.lock().unwrap(), Instant::now());
                }
            });
        }

        Pending { inner, stop }
    }

    /// Buffer `pkt` for `ip`. Returns `true` when this is the first packet
    /// queued for `ip` — i.e. the caller should send an ARP solicitation now.
    pub fn enqueue(&self, ip: K, pkt: &[u8]) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap();
        prune(&mut map, now);
        let entry = map.entry(ip).or_default();
        let first = entry.created.is_none();
        if first {
            entry.created = Some(now);
        }
        if entry.packets.len() < PENDING_MAX_PKTS {
            entry.packets.push(pkt.to_vec());
        }
        first
    }

    /// True while packets are waiting for `ip`: a resolution is under way.
    pub fn contains(&self, ip: K) -> bool {
        let map = self.inner.lock().unwrap();
        map.get(&ip).is_some_and(|e| {
            e.created
                .is_some_and(|c| Instant::now().duration_since(c) <= PENDING_TIMEOUT)
        })
    }

    /// Drop every queue, and the packets in them.
    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    /// Remove and return every packet waiting for `ip`.
    pub fn drain(&self, ip: K) -> Vec<Vec<u8>> {
        self.inner
            .lock()
            .unwrap()
            .remove(&ip)
            .map(|e| e.packets)
            .unwrap_or_default()
    }
}

impl<K> Drop for Pending<K> {
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
    fn stale_pending_queue_solicits_again() {
        let p = Pending::new();
        let ip = Ipv4Addr::new(10, 0, 0, 9);
        assert!(p.enqueue(ip, b"one"));
        assert!(!p.enqueue(ip, b"two"), "still waiting on the first request");

        // Age the queue past the timeout without sleeping. Without threads
        // nothing sweeps it, so enqueue itself must notice.
        let old = Instant::now() - PENDING_TIMEOUT - Duration::from_millis(1);
        p.inner.lock().unwrap().get_mut(&ip).unwrap().created = Some(old);
        assert!(
            p.enqueue(ip, b"three"),
            "a stale queue must be re-solicited"
        );
        assert_eq!(p.drain(ip), vec![b"three".to_vec()]);
    }

    #[test]
    fn build_parse_roundtrip() {
        let s = MacAddr([1, 2, 3, 4, 5, 6]);
        let t = MacAddr([7, 8, 9, 10, 11, 12]);
        let b = build_packet(
            OP_REQUEST,
            s,
            Ipv4Addr::new(10, 0, 0, 1),
            t,
            Ipv4Addr::new(10, 0, 0, 2),
        );
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
    fn full_table_evicts_the_entry_closest_to_expiry() {
        let t = Table::new();
        let m = MacAddr([0xaa; 6]);
        let old = Ipv4Addr::new(10, 1, 0, 0);
        t.set(old, m, Duration::from_secs(1));
        for i in 1..MAX_ENTRIES as u32 {
            t.set(Ipv4Addr::from(0x0a01_0000 + i), m, Duration::from_secs(60));
        }
        let new = Ipv4Addr::new(10, 2, 0, 1);
        t.set(new, m, DEFAULT_TTL);
        assert_eq!(t.lookup(new), Some(m), "a full cache refused a neighbour");
        assert_eq!(t.lookup(old), None);
        assert_eq!(t.inner.lock().unwrap().len(), MAX_ENTRIES);
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
