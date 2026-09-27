//! ARP (RFC 826) for IPv4 over Ethernet.
//!
//! - [`Table`] is the neighbour cache, shared with NDP: lookups, learning,
//!   and Neighbour Unreachability Detection (RFC 4861 §7.3), so a neighbour
//!   that stops answering -- or moves to another MAC -- is found out within
//!   seconds of being used. Capped at 4096 entries: a full cache is cut back
//!   by an eighth, entries learnt unasked and closest to expiry first, and
//!   never the [pinned](Table::pin) router; entries unused for 5 minutes age
//!   out.
//! - [`Pending`] buffers packets awaiting resolution, the newest 16 per target,
//!   256 targets and 1 MiB in all (the [pinned](Pending::pin) router always
//!   admitted), and times the solicitations: three, a second apart, before
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
/// Most bytes that may be waiting for resolution, all destinations
/// together. The other two caps alone allow 256 x 16 packets, up to 64 KiB
/// each: a quarter of a gigabyte held for a subnet sweep.
pub const PENDING_MAX_BYTES: usize = 1 << 20;
pub const MAX_ENTRIES: usize = 4096;
/// What a full cache is cut back to. Evicting a batch, rather than one entry
/// per insert, pays for the scan that picks the victims once per
/// `MAX_ENTRIES - LOW_WATER` new neighbours: a flood of made-up senders
/// would otherwise have every one of its packets scan the whole cache,
/// under the lock every send takes.
const LOW_WATER: usize = MAX_ENTRIES - MAX_ENTRIES / 8;

/// How long a neighbour stays REACHABLE after a confirmation (RFC 4861 §10
/// REACHABLE_TIME).
pub const REACHABLE_TIME: Duration = Duration::from_secs(30);
/// How long a STALE entry, once used, waits for the upper layers' traffic to
/// confirm it before probing (RFC 4861 §10 DELAY_FIRST_PROBE_TIME).
pub const DELAY_FIRST_PROBE_TIME: Duration = Duration::from_secs(5);
/// Unicast probes sent, [`RETRANS_TIMER`] apart, before a neighbour that
/// stopped answering is forgotten (RFC 4861 §10).
pub const MAX_UNICAST_SOLICIT: u32 = 3;

/// Neighbour Unreachability Detection state (RFC 4861 §7.3.2). INCOMPLETE
/// is not here: an address being resolved is in [`Pending`], not the cache.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Nud {
    /// Confirmed reachable, until then.
    Reachable(Instant),
    /// Not confirmed lately. Nothing is done until it is used.
    Stale,
    /// Used while stale; probe from then unless confirmed first.
    Delay(Instant),
    /// Unicast probes sent so far, and when the next is due.
    Probe { sent: u32, next: Instant },
}

#[derive(Copy, Clone, Debug)]
struct Entry {
    mac: MacAddr,
    state: Nud,
    /// When an entry left STALE is forgotten, [`DEFAULT_TTL`] after it was
    /// last heard from. An entry in use never gets there: it is probed and
    /// either confirmed or dropped first.
    expires: Instant,
    /// Ever confirmed by an answer to our own solicitation (or installed
    /// with [`Table::set`]), rather than only learnt from what a neighbour
    /// chose to send. Anyone can mint entries of the second kind, so a
    /// full cache evicts those first.
    resolved: bool,
}

impl Entry {
    /// As good as gone: stale and past its time, or probed and never
    /// answered.
    fn gone(&self, now: Instant) -> bool {
        match self.state {
            Nud::Stale => self.expires <= now,
            Nud::Reachable(until) => until <= now && self.expires <= now,
            Nud::Delay(_) => false,
            // Also once the time for every probe left has passed, sent or
            // not: with nothing driving the timers between two sends (no
            // tick() on wasm), the next send must not find a neighbour
            // that ignored its probe long ago still trusted.
            Nud::Probe { sent, next } => {
                let left = MAX_UNICAST_SOLICIT.saturating_sub(sent);
                now >= next + RETRANS_TIMER * left
            }
        }
    }
}

/// What [`Table::resolve`] says about sending to an address.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Resolved {
    /// Send to this MAC.
    Hit(MacAddr),
    /// Send to this MAC, and also a unicast probe to it now: the neighbour
    /// has not been confirmed reachable lately.
    Probe(MacAddr),
    /// Unknown, or known no longer: resolve it afresh (multicast).
    Miss,
}

/// Thread-safe neighbour cache, keyed by `Ipv4Addr` for ARP or `Ipv6Addr`
/// for NDP ([`ndp::Table`](crate::ndp::Table)), with the Neighbour
/// Unreachability Detection of RFC 4861 §7.3 for both.
///
/// An entry confirmed by a solicited answer is REACHABLE for
/// [`REACHABLE_TIME`], then STALE. Used while STALE it waits
/// [`DELAY_FIRST_PROBE_TIME`], then is probed by unicast
/// ([`MAX_UNICAST_SOLICIT`] times, [`RETRANS_TIMER`] apart); a neighbour
/// that never answers is dropped, so the next packet resolves it afresh
/// rather than going to a MAC that is no longer there. The probes are sent
/// by the caller: [`resolve`](Self::resolve) and [`poll`](Self::poll) say
/// when.
#[derive(Debug)]
pub struct Table<K = Ipv4Addr> {
    inner: Mutex<Cache<K>>,
}

#[derive(Debug)]
struct Cache<K> {
    map: HashMap<K, Entry>,
    /// Never evicted to make room.
    pinned: Option<K>,
}

impl<K: Eq + Hash + Copy> Default for Table<K> {
    fn default() -> Self {
        Table {
            inner: Mutex::new(Cache {
                map: HashMap::new(),
                pinned: None,
            }),
        }
    }
}

impl<K: Eq + Hash + Copy> Table<K> {
    /// An empty cache.
    pub fn new() -> Table<K> {
        Table::default()
    }

    /// Never evict `ip` to make room in a full cache: the default router,
    /// through which all off-link traffic goes. Anyone on the link can fill
    /// the cache with made-up neighbours, and losing the router's entry to
    /// them would stall everything until it is resolved again. `None`
    /// unpins. Only room-making is affected: the entry still ages out, and
    /// NUD still drops it if the router stops answering.
    pub fn pin(&self, ip: Option<K>) {
        self.inner.lock().unwrap().pinned = ip;
    }

    /// Look up `ip`, returning its MAC if an entry exists. This only looks:
    /// it neither counts as using the entry nor moves its state on.
    pub fn lookup(&self, ip: K) -> Option<MacAddr> {
        let now = Instant::now();
        let t = &mut self.inner.lock().unwrap().map;
        match t.get(&ip).copied() {
            Some(e) if !e.gone(now) => Some(e.mac),
            Some(_) => {
                t.remove(&ip);
                None
            }
            None => None,
        }
    }

    /// The MAC to send a packet for `ip` to, as of now, and whether to
    /// probe it (RFC 4861 §7.3.3).
    pub fn resolve(&self, ip: K) -> Resolved {
        self.resolve_at(ip, Instant::now())
    }

    pub(crate) fn resolve_at(&self, ip: K, now: Instant) -> Resolved {
        let t = &mut self.inner.lock().unwrap().map;
        let Some(e) = t.get_mut(&ip) else {
            return Resolved::Miss;
        };
        if e.gone(now) {
            t.remove(&ip);
            return Resolved::Miss;
        }
        match e.state {
            Nud::Reachable(until) if until > now => Resolved::Hit(e.mac),
            // Used while stale: give the traffic a chance to be confirmed
            // by the upper layers' answers before probing.
            Nud::Reachable(_) | Nud::Stale => {
                e.state = Nud::Delay(now + DELAY_FIRST_PROBE_TIME);
                Resolved::Hit(e.mac)
            }
            Nud::Delay(until) if until > now => Resolved::Hit(e.mac),
            Nud::Delay(_) => {
                e.state = Nud::Probe {
                    sent: 1,
                    next: now + RETRANS_TIMER,
                };
                Resolved::Probe(e.mac)
            }
            Nud::Probe { next, .. } if next > now => Resolved::Hit(e.mac),
            // Not gone, so a probe is left to send.
            Nud::Probe { sent, .. } => {
                e.state = Nud::Probe {
                    sent: sent + 1,
                    next: now + RETRANS_TIMER,
                };
                Resolved::Probe(e.mac)
            }
        }
    }

    /// Run the NUD timers: return each neighbour to probe now, with the MAC
    /// to send the unicast probe to. Neighbours that have not answered
    /// their last probe are forgotten, as are entries long stale.
    pub fn poll(&self, now: Instant) -> Vec<(K, MacAddr)> {
        let mut probes = Vec::new();
        self.inner.lock().unwrap().map.retain(|ip, e| {
            match e.state {
                Nud::Delay(until) if until <= now => {
                    e.state = Nud::Probe {
                        sent: 1,
                        next: now + RETRANS_TIMER,
                    };
                    probes.push((*ip, e.mac));
                }
                _ if e.gone(now) => return false,
                Nud::Probe { sent, next } if next <= now => {
                    e.state = Nud::Probe {
                        sent: sent + 1,
                        next: now + RETRANS_TIMER,
                    };
                    probes.push((*ip, e.mac));
                }
                _ => {}
            }
            !e.gone(now)
        });
        probes
    }

    /// Forget every entry, as when the network they were learnt on is left.
    pub fn clear(&self) {
        self.inner.lock().unwrap().map.clear();
    }

    /// Install or refresh an entry, confirmed reachable (for `ttl` or
    /// [`REACHABLE_TIME`], whichever is shorter) and kept for `ttl`.
    pub fn set(&self, ip: K, mac: MacAddr, ttl: Duration) {
        let now = Instant::now();
        let mut t = self.inner.lock().unwrap();
        if !t.map.contains_key(&ip) && t.map.len() >= MAX_ENTRIES {
            t.make_room(now);
        }
        t.map.insert(
            ip,
            Entry {
                mac,
                state: Nud::Reachable(now + ttl.min(REACHABLE_TIME)),
                expires: now + ttl,
                resolved: true,
            },
        );
    }

    /// Record that `ip` is at `mac`, as some message from the neighbour
    /// says (RFC 4861 §7.2.5, with ARP's merge rule of RFC 826 read the same
    /// way). `solicited` is set for an answer to our own solicitation or
    /// probe, which confirms the neighbour reachable. Without `override_`,
    /// a MAC other than the cached one does not replace it, and only makes
    /// a REACHABLE entry STALE, to be checked. Otherwise a changed MAC is
    /// taken, and the entry is STALE until confirmed. A new entry is
    /// REACHABLE if `solicited`, else STALE.
    pub fn update(&self, ip: K, mac: MacAddr, solicited: bool, override_: bool) {
        self.update_at(ip, mac, solicited, override_, Instant::now());
    }

    pub(crate) fn update_at(
        &self,
        ip: K,
        mac: MacAddr,
        solicited: bool,
        override_: bool,
        now: Instant,
    ) {
        let mut t = self.inner.lock().unwrap();
        let state = if solicited {
            Nud::Reachable(now + REACHABLE_TIME)
        } else {
            Nud::Stale
        };
        let expires = now + DEFAULT_TTL;
        match t.map.get_mut(&ip) {
            Some(e) if !e.gone(now) => {
                if e.mac != mac && !override_ {
                    if matches!(e.state, Nud::Reachable(until) if until > now) {
                        e.state = Nud::Stale;
                    }
                    return;
                }
                if solicited || e.mac != mac {
                    e.state = state;
                }
                e.mac = mac;
                e.expires = expires;
                e.resolved |= solicited;
            }
            _ => {
                if !t.map.contains_key(&ip) && t.map.len() >= MAX_ENTRIES {
                    t.make_room(now);
                }
                t.map.insert(
                    ip,
                    Entry {
                        mac,
                        state,
                        expires,
                        resolved: solicited,
                    },
                );
            }
        }
    }
}

impl<K: Eq + Hash + Copy> Cache<K> {
    /// Cut a full cache back to [`LOW_WATER`]. Entries gone stale go first;
    /// then those learnt unasked before those we resolved ourselves, the
    /// closest to expiring -- the least recently heard from -- first; the
    /// pinned router never. Refusing the new entry instead would let anyone
    /// who fills the cache with made-up senders keep every real neighbour
    /// out of it for good.
    fn make_room(&mut self, now: Instant) {
        self.map.retain(|_, e| !e.gone(now));
        let Some(excess) = self.map.len().checked_sub(LOW_WATER).filter(|&n| n > 0) else {
            return;
        };
        let pinned = self.pinned;
        let mut victims: Vec<_> = self
            .map
            .iter()
            .filter(|(k, _)| Some(**k) != pinned)
            .map(|(k, e)| (e.resolved, e.expires, *k))
            .collect();
        let n = excess.min(victims.len());
        if n == 0 {
            return;
        }
        // Linear, not a sort: only which ones go matters, not their order.
        victims.select_nth_unstable_by_key(n - 1, |v| (v.0, v.1));
        for (_, _, k) in &victims[..n] {
            self.map.remove(k);
        }
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
    inner: Mutex<Queues<K>>,
}

struct Queues<K> {
    map: HashMap<K, PendingEntry>,
    /// What every queue holds together, in bytes.
    bytes: usize,
    /// Always admitted, whatever the caps.
    pinned: Option<K>,
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

    fn size(&self) -> usize {
        self.packets.iter().map(Vec::len).sum()
    }
}

impl<K: Eq + Hash + Copy> Queues<K> {
    fn remove(&mut self, ip: &K) -> Option<PendingEntry> {
        let e = self.map.remove(ip)?;
        self.bytes -= e.size();
        Some(e)
    }

    /// Drop the oldest packet of some queue other than `keep`'s, and the
    /// queue with it if that was its last. False if there is none.
    fn shed_other(&mut self, keep: K) -> bool {
        let Some((k, e)) = self
            .map
            .iter_mut()
            .find(|(k, e)| **k != keep && !e.packets.is_empty())
        else {
            return false;
        };
        self.bytes -= e.packets.remove(0).len();
        if e.packets.is_empty() {
            let k = *k;
            self.map.remove(&k);
        }
        true
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
        let n = self.inner.lock().map(|q| q.map.len()).unwrap_or(0);
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
            inner: Mutex::new(Queues {
                map: HashMap::new(),
                bytes: 0,
                pinned: None,
            }),
        }
    }

    /// Always admit `ip` -- the default router -- however full the queues
    /// are, making room by dropping what waits for other destinations.
    /// Someone sweeping the subnet fills the caps with targets that never
    /// answer, and would otherwise keep every off-link packet from being
    /// sent until they give up. `None` unpins.
    pub fn pin(&self, ip: Option<K>) {
        self.inner.lock().unwrap().pinned = ip;
    }

    /// Buffer `pkt` for `ip`. Returns `true` when the caller should send a
    /// solicitation now: this is the first packet queued for `ip`, or a
    /// retransmission has come due that [`poll`](Self::poll) has not sent.
    /// A queue already holding [`PENDING_MAX_PKTS`] drops its oldest packet.
    ///
    /// Once [`PENDING_MAX_TARGETS`] destinations are waiting, a packet for
    /// yet another one is dropped and `false` returned, so nothing is
    /// solicited: someone sweeping a large subnet would otherwise have us
    /// hold a queue, and broadcast a request, for every address in it
    /// (RFC 6583 §4). Likewise once the queues hold [`PENDING_MAX_BYTES`]
    /// together: a queue then makes room by dropping its own oldest packets,
    /// and a new destination is refused. The [pinned](Self::pin) router is
    /// the exception to both, and takes its room from the others.
    pub fn enqueue(&self, ip: K, pkt: &[u8]) -> bool {
        self.enqueue_at(ip, pkt, Instant::now())
    }

    pub(crate) fn enqueue_at(&self, ip: K, pkt: &[u8], now: Instant) -> bool {
        let q = &mut *self.inner.lock().unwrap();
        if pkt.len() > PENDING_MAX_BYTES {
            return false;
        }
        let pinned = q.pinned == Some(ip);
        // A resolution that failed but was never polled: with nobody
        // driving the timers, start over rather than hold the target, and
        // its full queue, forever. Its old packets go unreported.
        if q.map.get(&ip).is_some_and(|e| e.failed(now)) {
            q.remove(&ip);
        }
        let fresh = !q.map.contains_key(&ip);
        if fresh {
            if q.map.len() >= PENDING_MAX_TARGETS {
                let mut freed = 0;
                q.map.retain(|_, e| {
                    let keep = !e.failed(now);
                    if !keep {
                        freed += e.size();
                    }
                    keep
                });
                q.bytes -= freed;
            }
            if q.map.len() >= PENDING_MAX_TARGETS {
                if !pinned {
                    return false;
                }
                // Give up on the destination nearest to failing anyway.
                let victim = q
                    .map
                    .iter()
                    .min_by_key(|(_, e)| (core::cmp::Reverse(e.sent), e.next))
                    .map(|(k, _)| *k);
                if let Some(v) = victim {
                    q.remove(&v);
                }
            }
            q.map.insert(
                ip,
                PendingEntry {
                    packets: Vec::new(),
                    sent: 1,
                    next: now + RETRANS_TIMER,
                },
            );
        }
        // RFC 4861 §7.2.2: a full queue makes room by dropping its oldest
        // packet. The newest is the one a sender still cares about -- a
        // retransmission supersedes what it retransmits.
        let e = q.map.get_mut(&ip).unwrap();
        if e.packets.len() >= PENDING_MAX_PKTS {
            q.bytes -= e.packets.remove(0).len();
        }
        while q.bytes + pkt.len() > PENDING_MAX_BYTES {
            if pinned && q.shed_other(ip) {
                continue;
            }
            let e = q.map.get_mut(&ip).unwrap();
            if e.packets.is_empty() {
                if fresh {
                    q.map.remove(&ip);
                }
                return false;
            }
            q.bytes -= e.packets.remove(0).len();
        }
        let e = q.map.get_mut(&ip).unwrap();
        e.packets.push(pkt.to_vec());
        q.bytes += pkt.len();
        if fresh {
            return true;
        }
        // A retransmission due that no timer has sent yet: traffic still
        // flowing gets it out, even with nothing calling poll.
        if e.next <= now {
            e.sent += 1;
            e.next = now + RETRANS_TIMER;
            return true;
        }
        false
    }

    /// Run the retransmission timers: what is due by `now` -- a target to
    /// solicit again, or one whose resolution has failed.
    pub fn poll(&self, now: Instant) -> Vec<PendingEvent<K>> {
        let q = &mut *self.inner.lock().unwrap();
        let mut due = Vec::new();
        let mut freed = 0;
        q.map.retain(|ip, e| {
            if e.next > now {
                return true;
            }
            if e.sent < MAX_MULTICAST_SOLICIT {
                e.sent += 1;
                e.next = now + RETRANS_TIMER;
                due.push(PendingEvent::Resolicit(*ip));
                return true;
            }
            freed += e.size();
            due.push(PendingEvent::Failed(*ip, std::mem::take(&mut e.packets)));
            false
        });
        q.bytes -= freed;
        due
    }

    /// True while packets are waiting for `ip`: a resolution is under way.
    pub fn contains(&self, ip: K) -> bool {
        self.contains_at(ip, Instant::now())
    }

    pub(crate) fn contains_at(&self, ip: K, now: Instant) -> bool {
        let q = self.inner.lock().unwrap();
        q.map.get(&ip).is_some_and(|e| !e.failed(now))
    }

    /// Drop every queue, and the packets in them.
    pub fn clear(&self) {
        let mut q = self.inner.lock().unwrap();
        q.map.clear();
        q.bytes = 0;
    }

    /// Keep only the queued packets `keep` accepts; a queue left empty is
    /// dropped, and its resolution with it.
    pub fn retain_packets(&self, mut keep: impl FnMut(&[u8]) -> bool) {
        let q = &mut *self.inner.lock().unwrap();
        q.map.retain(|_, e| {
            e.packets.retain(|p| keep(p));
            !e.packets.is_empty()
        });
        q.bytes = q.map.values().map(PendingEntry::size).sum();
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
        p.inner.lock().unwrap().map.get_mut(&ip).unwrap().sent = MAX_MULTICAST_SOLICIT;
        assert!(
            p.enqueue_at(ip, b"two", late),
            "a stale queue is re-solicited"
        );
        assert_eq!(p.drain(ip), vec![b"two".to_vec()]);
    }

    #[test]
    fn neighbour_unreachability_detection() {
        let t = Table::new();
        let ip = Ipv4Addr::new(10, 0, 0, 7);
        let m = MacAddr([2, 0, 0, 0, 0, 7]);
        let t0 = Instant::now();
        let at = |s: u64, ms: u64| t0 + Duration::from_secs(s) + Duration::from_millis(ms);

        // Confirmed: used freely for REACHABLE_TIME.
        t.update_at(ip, m, true, true, t0);
        assert_eq!(t.resolve_at(ip, at(29, 0)), Resolved::Hit(m));
        assert!(t.poll(at(29, 0)).is_empty());
        // Then STALE: still used, but DELAY, then probed by unicast.
        assert_eq!(t.resolve_at(ip, at(31, 0)), Resolved::Hit(m));
        assert!(t.poll(at(35, 0)).is_empty(), "probed before DELAY ran out");
        assert_eq!(t.poll(at(36, 0)), [(ip, m)]);
        assert_eq!(t.resolve_at(ip, at(36, 500)), Resolved::Hit(m));
        assert_eq!(t.poll(at(37, 0)), [(ip, m)]);
        // A probe can be due from a send before the timer gets to it.
        assert_eq!(t.resolve_at(ip, at(38, 0)), Resolved::Probe(m));
        assert!(t.poll(at(38, 500)).is_empty());
        // MAX_UNICAST_SOLICIT unanswered: forgotten, to be resolved afresh.
        assert!(t.poll(at(39, 0)).is_empty());
        assert_eq!(t.lookup(ip), None);
        assert_eq!(t.resolve_at(ip, at(39, 0)), Resolved::Miss);

        // An answer to a probe makes it REACHABLE again.
        t.update_at(ip, m, false, true, t0);
        assert_eq!(
            t.resolve_at(ip, at(1, 0)),
            Resolved::Hit(m),
            "STALE is used"
        );
        assert_eq!(t.poll(at(6, 0)), [(ip, m)]);
        t.update_at(ip, m, true, true, at(6, 100));
        assert!(t.poll(at(8, 0)).is_empty());
        assert_eq!(t.resolve_at(ip, at(30, 0)), Resolved::Hit(m));
    }

    #[test]
    fn traffic_drives_the_timers_when_nothing_polls() {
        // Resolution: a packet sent once a retransmission is due solicits.
        let p = Pending::new();
        let ip = Ipv4Addr::new(10, 0, 0, 9);
        let t0 = Instant::now();
        assert!(p.enqueue_at(ip, b"a", t0));
        assert!(!p.enqueue_at(ip, b"b", t0 + Duration::from_millis(900)));
        assert!(
            p.enqueue_at(ip, b"c", t0 + RETRANS_TIMER),
            "not solicited again"
        );
        assert!(!p.enqueue_at(ip, b"d", t0 + Duration::from_millis(1500)));
        assert!(
            p.poll(t0 + Duration::from_millis(1900)).is_empty(),
            "sent twice"
        );

        // NUD: a neighbour that ignored its probe is not trusted when the
        // next packet comes long after, though no timer sent the rest.
        let t = Table::new();
        let m = MacAddr([2, 0, 0, 0, 0, 7]);
        t.update_at(ip, m, false, true, t0);
        assert_eq!(t.resolve_at(ip, t0), Resolved::Hit(m));
        let probed = t0 + DELAY_FIRST_PROBE_TIME;
        assert_eq!(t.resolve_at(ip, probed), Resolved::Probe(m));
        assert_eq!(
            t.resolve_at(ip, probed + Duration::from_secs(2)),
            Resolved::Probe(m)
        );
        let t = Table::new();
        t.update_at(ip, m, false, true, t0);
        t.resolve_at(ip, t0);
        assert_eq!(t.resolve_at(ip, probed), Resolved::Probe(m));
        assert_eq!(
            t.resolve_at(ip, probed + Duration::from_secs(30)),
            Resolved::Miss
        );
    }

    #[test]
    fn a_changed_mac_is_checked_before_it_is_trusted() {
        let t = Table::new();
        let ip = Ipv4Addr::new(10, 0, 0, 7);
        let (m, n) = (MacAddr([2, 0, 0, 0, 0, 7]), MacAddr([2, 0, 0, 0, 0, 8]));
        let t0 = Instant::now();
        t.update_at(ip, m, true, true, t0);
        // RFC 4861 §7.2.5: without Override, a REACHABLE entry keeps its
        // MAC but goes STALE; with it, the new MAC is taken, STALE.
        t.update_at(ip, n, false, false, t0);
        assert_eq!(t.lookup(ip), Some(m));
        assert_eq!(t.resolve_at(ip, t0), Resolved::Hit(m));
        assert_eq!(t.poll(t0 + DELAY_FIRST_PROBE_TIME), [(ip, m)]);
        t.update_at(ip, n, false, true, t0);
        assert_eq!(t.lookup(ip), Some(n));
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
    }

    #[test]
    fn a_full_cache_is_cut_back_in_one_batch() {
        let t = Table::new();
        let m = MacAddr([0xaa; 6]);
        for i in 0..MAX_ENTRIES as u32 {
            t.update(Ipv4Addr::from(0x0a01_0000 + i), m, false, true);
        }
        t.update(Ipv4Addr::new(10, 2, 0, 1), m, false, true);
        // The next MAX_ENTRIES - LOW_WATER - 1 new neighbours find room
        // without scanning the cache again.
        assert_eq!(t.inner.lock().unwrap().map.len(), LOW_WATER + 1);
    }

    #[test]
    fn a_flood_evicts_neither_the_router_nor_neighbours_we_resolved() {
        let t = Table::new();
        let m = MacAddr([0xaa; 6]);
        let t0 = Instant::now();
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let peer = Ipv4Addr::new(10, 0, 0, 2);
        t.pin(Some(gw));
        // Learnt first, so closest to expiry of all.
        t.update_at(gw, m, false, true, t0);
        t.update_at(peer, m, true, true, t0);
        // Unasked-for neighbours, every one newer, many times the cache.
        for i in 0..3 * MAX_ENTRIES as u32 {
            let at = t0 + Duration::from_millis(1 + i as u64 / 64);
            t.update_at(Ipv4Addr::from(0x0a10_0000 + i), m, false, true, at);
        }
        assert_eq!(t.lookup(gw), Some(m), "the router was evicted");
        assert_eq!(t.lookup(peer), Some(m), "a resolved neighbour was evicted");
        assert!(t.inner.lock().unwrap().map.len() <= MAX_ENTRIES);

        // Unpinned, the router goes like anyone else.
        let t = Table::new();
        t.update_at(gw, m, false, true, t0);
        for i in 0..MAX_ENTRIES as u32 {
            let at = t0 + Duration::from_millis(1);
            t.update_at(Ipv4Addr::from(0x0a10_0000 + i), m, false, true, at);
        }
        assert_eq!(t.lookup(gw), None);
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
        assert_eq!(p.inner.lock().unwrap().map.len(), PENDING_MAX_TARGETS - 1);
    }

    #[test]
    fn pending_bytes_are_capped() {
        let p = Pending::new();
        let big = vec![0u8; 65535];
        for i in 0..PENDING_MAX_TARGETS as u32 {
            for _ in 0..PENDING_MAX_PKTS {
                p.enqueue(Ipv4Addr::from(0x0a00_0000 + i), &big);
            }
        }
        let q = p.inner.lock().unwrap();
        let held: usize = q.map.values().map(PendingEntry::size).sum();
        assert_eq!(held, q.bytes);
        // Not the ~256 MiB the other caps allow.
        assert!(held <= 1 << 20, "{held} bytes queued");
    }

    #[test]
    fn the_router_is_admitted_however_full_the_queues() {
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let big = vec![0u8; 65535];
        // Full of destinations.
        let p = Pending::new();
        p.pin(Some(gw));
        for i in 0..PENDING_MAX_TARGETS as u32 {
            assert!(p.enqueue(Ipv4Addr::from(0x0a01_0000 + i), b"x"));
        }
        assert!(p.enqueue(gw, b"to the router"), "router not solicited");
        assert!(p.contains(gw));
        assert_eq!(p.inner.lock().unwrap().map.len(), PENDING_MAX_TARGETS);

        // Full of bytes.
        let p = Pending::new();
        p.pin(Some(gw));
        for i in 0..16 {
            for _ in 0..PENDING_MAX_PKTS {
                p.enqueue(Ipv4Addr::from(0x0a01_0000 + i), &big);
            }
        }
        assert!(!p.enqueue(Ipv4Addr::new(10, 2, 0, 1), &big), "over the cap");
        for _ in 0..PENDING_MAX_PKTS {
            p.enqueue(gw, &big);
        }
        assert_eq!(p.drain(gw).len(), PENDING_MAX_PKTS, "router starved");
        assert!(p.inner.lock().unwrap().bytes <= PENDING_MAX_BYTES);
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
