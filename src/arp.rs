//! ARP (RFC 826) for IPv4 over Ethernet.
//!
//! - [`Table`] is the resolver cache: lookups, learning, capped at 4096 entries
//!   (a full cache evicts the entry closest to expiry),
//!   entries age out after 5 minutes.
//! - [`Pending`] buffers packets awaiting resolution, the newest 16 per target and
//!   256 targets, and times the solicitations: three, a second apart, before
//!   resolution fails and the packets are handed back to be reported.
//! - [`build_packet`] / [`parse`] encode and decode the 28-byte ARP body.

use crate::MacAddr;
use crate::time::Instant;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Duration;

pub const OP_REQUEST: u16 = 1;
pub const OP_REPLY: u16 = 2;

pub const DEFAULT_TTL: Duration = Duration::from_secs(5 * 60);
/// Wait between solicitations of an address being resolved (RFC 4861 §10
/// RETRANS_TIMER; RFC 1122 §2.3.2.1 asks the same of ARP: no more than one
/// request a second per destination).
pub const RETRANS_TIMER: Duration = Duration::from_secs(1);
/// Solicitations sent before resolution fails (RFC 4861 §10).
pub const MAX_MULTICAST_SOLICIT: u32 = 3;
/// How long resolution is tried before it fails: [`MAX_MULTICAST_SOLICIT`]
/// solicitations, [`RETRANS_TIMER`] apart, and as long again after the last.
pub const PENDING_TIMEOUT: Duration = Duration::from_secs(3);
pub const PENDING_MAX_PKTS: usize = 16;
/// Most destinations that may be awaiting resolution at once.
pub const PENDING_MAX_TARGETS: usize = 256;
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
    /// An empty cache.
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
/// being resolved (`Ipv4Addr` for ARP, `Ipv6Addr` for NDP), and times the
/// solicitations for each (RFC 4861 §7.2.2, RFC 1122 §2.3.2.1).
///
/// Nothing here runs by itself: [`poll`](Self::poll) says when to solicit
/// again and which resolutions have failed, and must be called regularly --
/// the [`L2Adapter`](crate::L2Adapter) does it from its timer. A target
/// solicited [`MAX_MULTICAST_SOLICIT`] times, [`RETRANS_TIMER`] apart, with
/// no answer [`RETRANS_TIMER`] after the last has failed, and its packets
/// are handed back so the sender can be told (ICMP destination
/// unreachable).
pub struct Pending<K = Ipv4Addr> {
    inner: Mutex<HashMap<K, PendingEntry>>,
}

struct PendingEntry {
    packets: Vec<Vec<u8>>,
    /// Solicitations sent so far.
    sent: u32,
    /// When the next is due, or the resolution fails.
    next: Instant,
}

impl PendingEntry {
    /// Whether the resolution has run its course and is only waiting for
    /// [`Pending::poll`] to report the failure.
    fn failed(&self, now: Instant) -> bool {
        self.sent >= MAX_MULTICAST_SOLICIT && self.next <= now
    }
}

/// What [`Pending::poll`] found due.
#[derive(Debug, PartialEq, Eq)]
pub enum PendingEvent<K> {
    /// Still unanswered: send another solicitation for this target.
    Resolicit(K),
    /// Resolution failed. Nothing more is queued for the target, and these
    /// are the packets that were, oldest first, for the caller to report
    /// as undeliverable (RFC 4861 §7.2.2).
    Failed(K, Vec<Vec<u8>>),
}

impl<K> core::fmt::Debug for Pending<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let n = self.inner.lock().map(|m| m.len()).unwrap_or(0);
        f.debug_struct("arp::Pending").field("queues", &n).finish()
    }
}

impl<K: Eq + Hash + Copy> Default for Pending<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Eq + Hash + Copy> Pending<K> {
    /// An empty set of queues.
    pub fn new() -> Pending<K> {
        Pending {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Buffer `pkt` for `ip`. Returns `true` when this is the first packet
    /// queued for `ip` — i.e. the caller should send an ARP solicitation now.
    /// A queue already holding [`PENDING_MAX_PKTS`] drops its oldest packet.
    ///
    /// Once [`PENDING_MAX_TARGETS`] destinations are waiting, a packet for
    /// yet another one is dropped and `false` returned, so nothing is
    /// solicited: someone sweeping a large subnet would otherwise have us
    /// hold a queue, and broadcast a request, for every address in it
    /// (RFC 6583 §4).
    pub fn enqueue(&self, ip: K, pkt: &[u8]) -> bool {
        self.enqueue_at(ip, pkt, Instant::now())
    }

    pub(crate) fn enqueue_at(&self, ip: K, pkt: &[u8], now: Instant) -> bool {
        let mut map = self.inner.lock().unwrap();
        // A resolution that failed but was never polled: with nobody
        // driving the timers, start over rather than hold the target, and
        // its full queue, forever. Its old packets go unreported.
        if map.get(&ip).is_some_and(|e| e.failed(now)) {
            map.remove(&ip);
        }
        if !map.contains_key(&ip) {
            if map.len() >= PENDING_MAX_TARGETS {
                map.retain(|_, e| !e.failed(now));
                if map.len() >= PENDING_MAX_TARGETS {
                    return false;
                }
            }
            map.insert(
                ip,
                PendingEntry {
                    packets: Vec::new(),
                    sent: 1,
                    next: now + RETRANS_TIMER,
                },
            );
            let entry = map.get_mut(&ip).unwrap();
            entry.packets.push(pkt.to_vec());
            return true;
        }
        let entry = map.get_mut(&ip).unwrap();
        // RFC 4861 §7.2.2: a full queue makes room by dropping its oldest
        // packet. The newest is the one a sender still cares about -- a
        // retransmission supersedes what it retransmits.
        if entry.packets.len() >= PENDING_MAX_PKTS {
            entry.packets.remove(0);
        }
        entry.packets.push(pkt.to_vec());
        false
    }

    /// Run the retransmission timers: what is due by `now` -- a target to
    /// solicit again, or one whose resolution has failed.
    pub fn poll(&self, now: Instant) -> Vec<PendingEvent<K>> {
        let mut map = self.inner.lock().unwrap();
        let mut due = Vec::new();
        map.retain(|ip, e| {
            if e.next > now {
                return true;
            }
            if e.sent < MAX_MULTICAST_SOLICIT {
                e.sent += 1;
                e.next = now + RETRANS_TIMER;
                due.push(PendingEvent::Resolicit(*ip));
                return true;
            }
            due.push(PendingEvent::Failed(*ip, std::mem::take(&mut e.packets)));
            false
        });
        due
    }

    /// True while packets are waiting for `ip`: a resolution is under way.
    pub fn contains(&self, ip: K) -> bool {
        self.contains_at(ip, Instant::now())
    }

    pub(crate) fn contains_at(&self, ip: K, now: Instant) -> bool {
        let map = self.inner.lock().unwrap();
        map.get(&ip).is_some_and(|e| !e.failed(now))
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
    fn unanswered_resolution_is_retried_then_fails_with_its_packets() {
        let p = Pending::new();
        let ip = Ipv4Addr::new(10, 0, 0, 9);
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        assert!(p.enqueue_at(ip, b"one", t0));
        assert!(!p.enqueue_at(ip, b"two", at(10)), "still waiting");

        assert!(p.poll(at(900)).is_empty());
        assert_eq!(p.poll(at(1000)), [PendingEvent::Resolicit(ip)]);
        assert!(p.poll(at(1500)).is_empty());
        assert_eq!(p.poll(at(2000)), [PendingEvent::Resolicit(ip)]);
        assert!(p.contains_at(ip, at(2999)));
        // RETRANS_TIMER after the third solicitation, it has failed.
        assert_eq!(
            p.poll(at(3000)),
            [PendingEvent::Failed(
                ip,
                vec![b"one".to_vec(), b"two".to_vec()]
            )]
        );
        assert!(!p.contains_at(ip, at(3000)));
        assert!(p.enqueue_at(ip, b"three", at(3100)), "solicits afresh");
    }

    #[test]
    fn an_unpolled_failed_queue_solicits_again() {
        let p = Pending::new();
        let ip = Ipv4Addr::new(10, 0, 0, 9);
        let t0 = Instant::now();
        assert!(p.enqueue_at(ip, b"one", t0));
        // Nobody drives the timers, as on wasm without tick(). Without a
        // fresh start the target would never be solicited again.
        let late = t0 + PENDING_TIMEOUT + Duration::from_millis(1);
        p.inner.lock().unwrap().get_mut(&ip).unwrap().sent = MAX_MULTICAST_SOLICIT;
        assert!(
            p.enqueue_at(ip, b"two", late),
            "a stale queue is re-solicited"
        );
        assert_eq!(p.drain(ip), vec![b"two".to_vec()]);
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
    fn pending_destinations_are_capped() {
        let p = Pending::new();
        for i in 0..PENDING_MAX_TARGETS as u32 {
            assert!(p.enqueue(Ipv4Addr::from(0x0a00_0000 + i), b"x"));
        }
        let extra = Ipv4Addr::new(10, 1, 0, 0);
        assert!(!p.enqueue(extra, b"x"), "solicited past the cap");
        assert!(!p.contains(extra));
        assert!(p.drain(extra).is_empty());
        // Destinations already waiting still take packets.
        assert!(!p.enqueue(Ipv4Addr::from(0x0a00_0000), b"y"));
        assert_eq!(p.drain(Ipv4Addr::from(0x0a00_0000)).len(), 2);
        assert_eq!(p.inner.lock().unwrap().len(), PENDING_MAX_TARGETS - 1);
    }

    #[test]
    fn full_queue_drops_its_oldest_packet() {
        let p = Pending::new();
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        for i in 0..=PENDING_MAX_PKTS as u8 {
            p.enqueue(ip, &[i]);
        }
        let q = p.drain(ip);
        assert_eq!(q.len(), PENDING_MAX_PKTS);
        assert_eq!(q[0], [1], "the oldest was kept");
        assert_eq!(q[PENDING_MAX_PKTS - 1], [PENDING_MAX_PKTS as u8]);
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
