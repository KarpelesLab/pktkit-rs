//! Per-mapping session tracking shared by [`Nat`](super::Nat) and
//! [`Nat64`](super::Nat64): which remote endpoints a mapping talks to, the TCP
//! life cycle of each, and the idle timeouts that follow from it.

use crate::nat::helper::{PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use crate::time::Instant;
use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// RFC 5382 REQ-5: an established TCP connection must not be dropped for
/// being idle less than 2 hours 4 minutes.
pub(crate) const TCP_ESTABLISHED_TIMEOUT: Duration = Duration::from_secs(2 * 3600 + 4 * 60);
/// RFC 5382 REQ-5: a partially open or closing TCP connection may go after
/// 4 minutes idle (and no sooner).
pub(crate) const TCP_TRANSITORY_TIMEOUT: Duration = Duration::from_secs(4 * 60);
/// RFC 4787 REQ-5: a UDP mapping must not expire in less than 2 minutes;
/// 5 minutes is recommended.
pub(crate) const UDP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// RFC 5508 REQ-1: an ICMP query mapping must not expire in less than 60 s.
pub(crate) const ICMP_TIMEOUT: Duration = Duration::from_secs(60);

/// Cap on remotes tracked per mapping. A forwarded server can have many
/// clients; past the cap, new remotes still get through but are not tracked,
/// and the mapping's own idle timer covers them. With no record to hold a
/// sequence adjustment, ALGs may not change the length of their TCP payloads.
/// [`NatLimits`] caps them across mappings too.
const MAX_PEERS: usize = 1024;

/// Default for [`NatLimits::max_mappings_per_host`].
const DEFAULT_MAX_MAPPINGS_PER_HOST: usize = 16384;
/// Default for [`NatLimits::max_peers_per_host`].
const DEFAULT_MAX_PEERS_PER_HOST: usize = 65536;
/// Default for [`NatLimits::max_peers`].
const DEFAULT_MAX_PEERS: usize = 262_144;
/// Default for [`NatLimits::max_expectations_per_host`].
const DEFAULT_MAX_EXPECTATIONS_PER_HOST: usize = 128;
/// Default for [`NatLimits::host_prefix_v6`]: a /64, the subnet size
/// SLAAC hosts pick their addresses in (RFC 4291 §2.5.1).
const DEFAULT_HOST_PREFIX_V6: u8 = 64;

/// Caps on the state a [`Nat`](super::Nat) or [`Nat64`](super::Nat64)
/// keeps, so that no inside host, nor the remotes it talks to, can grow it
/// without bound or take what the other hosts need (RFC 6888 REQ-3 and
/// REQ-4). 0 means unlimited.
///
/// Past a cap on remotes, traffic still flows, but the new remote is not
/// tracked: it does not keep the mapping alive, ICMP errors about it are
/// not passed on, and ALGs may not resize its TCP payloads. Past the cap
/// on mappings, a host's new flows are dropped until old ones idle out.
///
/// The defaults allow one host 16384 mappings (under a third of the port
/// pool) and 65536 tracked remotes, and 262144 remotes in all, some 20 MB.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NatLimits {
    /// Most mappings, each holding an outside port, one inside host may
    /// have. Those made for port forwards and ALG expectations count, but
    /// are never refused. Default: 16384.
    pub max_mappings_per_host: usize,
    /// Most remotes tracked for one inside host, over all its mappings.
    /// Default: 65536.
    pub max_peers_per_host: usize,
    /// Most remotes tracked in all. Default: 262144.
    pub max_peers: usize,
    /// Most pending ALG expectations one inside host may have (NAT44
    /// only); past it, a new one replaces that host's closest to lapsing.
    /// The table holds 1024 in all. Default: 128.
    pub max_expectations_per_host: usize,
    /// Length of the IPv6 prefix that counts as one inside host for the
    /// per-host caps (NAT64 only). An IPv6 host picks addresses from its
    /// whole /64 at will (temporary addresses, RFC 8981), so capping each
    /// address alone caps nothing: one host could hold the whole pool by
    /// sending from a new one per flow. Lengthen it only where each host
    /// really has a longer prefix (DHCPv6 /128s on a shared link, say).
    /// Past 128 counts as 128; a change applies to mappings made after it.
    /// Default: 64.
    pub host_prefix_v6: u8,
}

setters! {
    NatLimits {
        set max_mappings_per_host: usize;
        set max_peers_per_host: usize;
        set max_peers: usize;
        set max_expectations_per_host: usize;
        set host_prefix_v6: u8;
    }
}

impl Default for NatLimits {
    fn default() -> Self {
        NatLimits {
            max_mappings_per_host: DEFAULT_MAX_MAPPINGS_PER_HOST,
            max_peers_per_host: DEFAULT_MAX_PEERS_PER_HOST,
            max_peers: DEFAULT_MAX_PEERS,
            max_expectations_per_host: DEFAULT_MAX_EXPECTATIONS_PER_HOST,
            host_prefix_v6: DEFAULT_HOST_PREFIX_V6,
        }
    }
}

/// A count of something held against a cap (0 = none), shared by the
/// records that hold it so that each gives its share back when dropped.
/// Only ever changed under the owning NAT's lock; the atomics just make it
/// shareable.
#[derive(Debug, Default)]
pub(crate) struct Quota {
    used: AtomicUsize,
    max: AtomicUsize,
}

impl Quota {
    pub(crate) fn new(max: usize) -> Quota {
        Quota {
            used: AtomicUsize::new(0),
            max: AtomicUsize::new(max),
        }
    }

    pub(crate) fn set_max(&self, max: usize) {
        self.max.store(max, Ordering::Relaxed);
    }

    /// Take one, if that stays within the cap.
    pub(crate) fn take(&self) -> bool {
        let max = self.max.load(Ordering::Relaxed);
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            if max != 0 && used >= max {
                return false;
            }
            match self.used.compare_exchange_weak(
                used,
                used + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(now) => used = now,
            }
        }
    }

    /// Take one whatever the cap.
    pub(crate) fn force(&self) {
        self.used.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn give(&self, n: usize) {
        self.used.fetch_sub(n, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }
}

/// What one inside host holds.
#[derive(Debug, Default)]
pub(crate) struct HostQuota {
    pub(crate) mappings: Quota,
    pub(crate) peers: Quota,
}

impl HostQuota {
    pub(crate) fn new(limits: &NatLimits) -> HostQuota {
        HostQuota {
            mappings: Quota::new(limits.max_mappings_per_host),
            peers: Quota::new(limits.max_peers_per_host),
        }
    }

    pub(crate) fn set_limits(&self, limits: &NatLimits) {
        self.mappings.set_max(limits.max_mappings_per_host);
        self.peers.set_max(limits.max_peers_per_host);
    }
}

/// One mapping's hold on its inside host's quota: counts it as a mapping
/// for as long as it lives.
#[derive(Debug)]
pub(crate) struct MappingHold(Arc<HostQuota>);

impl MappingHold {
    /// Count a new mapping for `host`, refused past its cap unless
    /// `force`.
    pub(crate) fn take(host: &Arc<HostQuota>, force: bool) -> Option<MappingHold> {
        if force {
            host.mappings.force();
        } else if !host.mappings.take() {
            return None;
        }
        Some(MappingHold(host.clone()))
    }
}

impl Drop for MappingHold {
    fn drop(&mut self) {
        self.0.mappings.give(1);
    }
}

/// The quotas a mapping's remotes count against: its inside host's and the
/// NAT's.
#[derive(Debug, Clone)]
pub(crate) struct PeerQuotas {
    pub(crate) global: Arc<Quota>,
    pub(crate) host: Arc<HostQuota>,
}

impl PeerQuotas {
    fn take(&self) -> bool {
        if !self.host.peers.take() {
            return false;
        }
        if !self.global.take() {
            self.host.peers.give(1);
            return false;
        }
        true
    }

    fn give(&self, n: usize) {
        if n > 0 {
            self.host.peers.give(n);
            self.global.give(n);
        }
    }
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

// Peer state bits.
const SEEN_OUT: u8 = 1 << 0;
const SEEN_IN: u8 = 1 << 1;
const FIN_OUT: u8 = 1 << 2;
const FIN_IN: u8 = 1 << 3;
const RESET: u8 = 1 << 4;

/// One remote endpoint a mapping exchanges traffic with.
#[derive(Debug)]
pub(crate) struct Peer {
    last: Instant,
    state: u8,
    /// Sequence corrections for `[outbound, inbound]` once an ALG has
    /// resized a TCP payload on this connection.
    seqadj: Option<Box<[SeqAdj; 2]>>,
}

/// The sequence-number shift one direction of a TCP connection has taken
/// since an ALG changed the length of its payload (the scheme of Linux's
/// `nf_ct_seqadj`). Bytes up to `pos` in the sender's numbering moved by
/// `before`, bytes after it by `after`.
///
/// Only the latest resize point is remembered, so a segment from before it
/// that is retransmitted after a later resize gets the older shift; ALG
/// commands are rare enough on one connection that this does not arise in
/// practice.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SeqAdj {
    pos: u32,
    before: i32,
    after: i32,
}

/// `a` comes after `b` in sequence space (RFC 793 modular comparison).
fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

impl SeqAdj {
    fn record(&mut self, seq: u32, delta: i32) {
        // A retransmission of the segment already accounted for is resized
        // again by the ALG, but must not shift the stream a second time.
        if self.before == self.after || seq_after(seq, self.pos) {
            self.pos = seq;
            self.before = self.after;
            self.after = self.after.wrapping_add(delta);
        }
    }

    /// Translate a sequence number sent in this direction.
    pub(crate) fn seq(&self, seq: u32) -> u32 {
        let off = if seq_after(seq, self.pos) {
            self.after
        } else {
            self.before
        };
        seq.wrapping_add(off as u32)
    }

    /// Translate an acknowledgement (or SACK edge) of this direction's data,
    /// sent by the other side in shifted numbering, back to the sender's.
    pub(crate) fn ack(&self, ack: u32) -> u32 {
        let off = if seq_after(ack.wrapping_sub(self.before as u32), self.pos) {
            self.after
        } else {
            self.before
        };
        ack.wrapping_sub(off as u32)
    }
}

impl Peer {
    fn closing(&self) -> bool {
        self.state & RESET != 0 || self.state & (FIN_OUT | FIN_IN) == FIN_OUT | FIN_IN
    }

    fn timeout(&self, proto: u8) -> Duration {
        match proto {
            PROTO_TCP => {
                let both_ways = self.state & (SEEN_OUT | SEEN_IN) == SEEN_OUT | SEEN_IN;
                // A half-closed connection still carries data the other way,
                // so only FINs in both directions (or a reset) end it.
                if both_ways && !self.closing() {
                    TCP_ESTABLISHED_TIMEOUT
                } else {
                    TCP_TRANSITORY_TIMEOUT
                }
            }
            PROTO_ICMP => ICMP_TIMEOUT,
            _ => UDP_TIMEOUT,
        }
    }
}

/// The remotes of one mapping.
#[derive(Debug, Default)]
pub(crate) struct Peers {
    map: HashMap<SocketAddrV4, Peer>,
    /// What each tracked remote counts against; none in unit tests.
    quotas: Option<PeerQuotas>,
}

impl Drop for Peers {
    fn drop(&mut self) {
        if let Some(q) = &self.quotas {
            q.give(self.map.len());
        }
    }
}

impl Peers {
    pub(crate) fn new(quotas: PeerQuotas) -> Peers {
        Peers {
            map: HashMap::new(),
            quotas: Some(quotas),
        }
    }

    /// Record a packet between the mapping and `peer`. `outbound` is true for
    /// a packet from the inside host; `tcp_flags` carries the TCP flags byte
    /// for TCP.
    pub(crate) fn note(
        &mut self,
        peer: SocketAddrV4,
        outbound: bool,
        tcp_flags: Option<u8>,
        now: Instant,
    ) {
        let flags = tcp_flags.unwrap_or(0);
        if !self.map.contains_key(&peer) {
            // A reset from a remote this mapping never talked to proves
            // nothing and must not end anyone's session; the inside host
            // judges it by its sequence number.
            if (!outbound && flags & TCP_RST != 0) || self.map.len() >= MAX_PEERS {
                return;
            }
            if self.quotas.as_ref().is_some_and(|q| !q.take()) {
                return;
            }
            self.map.insert(
                peer,
                Peer {
                    last: now,
                    state: 0,
                    seqadj: None,
                },
            );
        }
        let p = self.map.get_mut(&peer).expect("inserted above");
        p.last = now;
        if tcp_flags.is_none() {
            return;
        }
        // A fresh SYN on a finished connection is a new connection reusing
        // the same endpoints (RFC 793 TIME-WAIT reuse): forget the old one.
        if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 && p.closing() {
            p.state = 0;
            p.seqadj = None;
        }
        p.state |= if outbound { SEEN_OUT } else { SEEN_IN };
        if flags & TCP_FIN != 0 {
            p.state |= if outbound { FIN_OUT } else { FIN_IN };
        }
        if flags & TCP_RST != 0 {
            p.state |= RESET;
        }
    }

    /// Note that an ALG changed the payload length of the TCP segment with
    /// sequence number `seq` sent in direction `outbound` by `delta` bytes.
    pub(crate) fn record_resize(
        &mut self,
        peer: &SocketAddrV4,
        outbound: bool,
        seq: u32,
        delta: i32,
    ) {
        if let Some(p) = self.map.get_mut(peer) {
            let adj = p.seqadj.get_or_insert_with(Default::default);
            adj[usize::from(!outbound)].record(seq, delta);
        }
    }

    /// The corrections for a TCP segment sent in direction `outbound`: its
    /// own direction's (for its sequence number) and the other one's (for
    /// its acknowledgement and SACK blocks). `None` if no ALG has resized
    /// anything on this connection.
    pub(crate) fn seq_adjust(
        &self,
        peer: &SocketAddrV4,
        outbound: bool,
    ) -> Option<(SeqAdj, SeqAdj)> {
        let adj = self.map.get(peer)?.seqadj.as_ref()?;
        let this = usize::from(!outbound);
        Some((adj[this], adj[1 - this]))
    }

    /// True if the mapping has exchanged traffic with `peer`.
    pub(crate) fn contains(&self, peer: &SocketAddrV4) -> bool {
        self.map.contains_key(peer)
    }

    /// Make every remote look idle for `by` longer.
    #[cfg(test)]
    pub(crate) fn backdate(&mut self, by: Duration) {
        for p in self.map.values_mut() {
            p.last -= by;
        }
    }

    /// Forget remotes idle past their timeout, and report whether the whole
    /// mapping (last active at `last_active`) is now idle and may go.
    pub(crate) fn expire(&mut self, proto: u8, last_active: Instant, now: Instant) -> bool {
        let before = self.map.len();
        self.map
            .retain(|_, p| now.saturating_duration_since(p.last) <= p.timeout(proto));
        if let Some(q) = &self.quotas {
            q.give(before - self.map.len());
        }
        if !self.map.is_empty() {
            return false;
        }
        let base = match proto {
            PROTO_TCP => TCP_TRANSITORY_TIMEOUT,
            PROTO_UDP => UDP_TIMEOUT,
            PROTO_ICMP => ICMP_TIMEOUT,
            _ => UDP_TIMEOUT,
        };
        now.saturating_duration_since(last_active) > base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn peer(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 9), port)
    }

    #[test]
    fn established_tcp_outlives_two_hours() {
        let now = Instant::now();
        let mut p = Peers::default();
        p.note(peer(80), true, Some(TCP_SYN), now);
        p.note(peer(80), false, Some(TCP_SYN | TCP_ACK), now);
        assert!(!p.expire(PROTO_TCP, now, now + Duration::from_secs(2 * 3600)));
        assert!(p.expire(
            PROTO_TCP,
            now,
            now + TCP_ESTABLISHED_TIMEOUT + Duration::from_secs(1)
        ));
    }

    #[test]
    fn half_close_is_still_established() {
        let now = Instant::now();
        let mut p = Peers::default();
        p.note(peer(80), true, Some(TCP_SYN), now);
        p.note(peer(80), false, Some(TCP_SYN | TCP_ACK), now);
        p.note(peer(80), true, Some(TCP_FIN | TCP_ACK), now);
        assert!(!p.expire(PROTO_TCP, now, now + Duration::from_secs(3600)));
    }

    #[test]
    fn full_close_is_transitory() {
        let now = Instant::now();
        let mut p = Peers::default();
        p.note(peer(80), true, Some(TCP_SYN), now);
        p.note(peer(80), false, Some(TCP_SYN | TCP_ACK), now);
        p.note(peer(80), true, Some(TCP_FIN | TCP_ACK), now);
        p.note(peer(80), false, Some(TCP_FIN | TCP_ACK), now);
        assert!(!p.expire(PROTO_TCP, now, now + Duration::from_secs(200)));
        assert!(p.expire(
            PROTO_TCP,
            now,
            now + TCP_TRANSITORY_TIMEOUT + Duration::from_secs(1)
        ));
    }

    #[test]
    fn reset_from_a_stranger_is_ignored() {
        let now = Instant::now();
        let mut p = Peers::default();
        p.note(peer(80), true, Some(TCP_SYN), now);
        p.note(peer(80), false, Some(TCP_SYN | TCP_ACK), now);
        p.note(peer(81), false, Some(TCP_RST), now);
        assert!(!p.contains(&peer(81)));
        assert!(!p.expire(PROTO_TCP, now, now + Duration::from_secs(3600)));
    }

    #[test]
    fn new_syn_reopens_a_closed_connection() {
        let now = Instant::now();
        let mut p = Peers::default();
        p.note(peer(80), true, Some(TCP_SYN), now);
        p.note(peer(80), false, Some(TCP_SYN | TCP_ACK), now);
        p.note(peer(80), true, Some(TCP_RST), now);
        p.note(peer(80), true, Some(TCP_SYN), now);
        p.note(peer(80), false, Some(TCP_SYN | TCP_ACK), now);
        assert!(!p.expire(PROTO_TCP, now, now + Duration::from_secs(3600)));
    }

    #[test]
    fn seqadj_shifts_later_data_only() {
        let mut a = SeqAdj::default();
        // A 21-byte command at 1000 became 24 bytes.
        a.record(1000, 3);
        assert_eq!(a.seq(1000), 1000);
        assert_eq!(a.seq(1021), 1024);
        // The peer acknowledging the rewritten command.
        assert_eq!(a.ack(1024), 1021);
        assert_eq!(a.ack(1000), 1000);
        // A retransmission is not counted twice.
        a.record(1000, 3);
        assert_eq!(a.seq(1021), 1024);
        // A second resize later on accumulates.
        a.record(2000, -2);
        assert_eq!(a.seq(2000), 2003);
        assert_eq!(a.seq(2100), 2101);
        assert_eq!(a.ack(2101), 2100);
    }

    #[test]
    fn seqadj_handles_wraparound() {
        let mut a = SeqAdj::default();
        a.record(u32::MAX - 5, 10);
        assert_eq!(a.seq(4), 14);
        assert_eq!(a.ack(14), 4);
    }

    #[test]
    fn remotes_count_against_host_and_global_quotas() {
        let now = Instant::now();
        let global = Arc::new(Quota::new(5));
        let host = Arc::new(HostQuota::new(&NatLimits::default().max_peers_per_host(3)));
        let q = PeerQuotas {
            global: global.clone(),
            host: host.clone(),
        };
        let mut a = Peers::new(q.clone());
        for port in 1..=4 {
            a.note(peer(port), true, None, now);
        }
        // The host's cap stops the fourth.
        assert!(a.contains(&peer(3)) && !a.contains(&peer(4)));
        assert_eq!((host.peers.used(), global.used()), (3, 3));

        let other = Arc::new(HostQuota::new(&NatLimits::default()));
        let mut b = Peers::new(PeerQuotas {
            global: global.clone(),
            host: other.clone(),
        });
        for port in 1..=4 {
            b.note(peer(port), true, None, now);
        }
        // The global cap stops the third, and gives back what the host
        // took for it.
        assert!(b.contains(&peer(2)) && !b.contains(&peer(3)));
        assert_eq!((other.peers.used(), global.used()), (2, 5));

        // Expiry and dropping give the counts back.
        assert!(a.expire(PROTO_UDP, now, now + UDP_TIMEOUT * 2));
        assert_eq!((host.peers.used(), global.used()), (0, 2));
        drop(b);
        assert_eq!((other.peers.used(), global.used()), (0, 0));
    }

    #[test]
    fn udp_lasts_the_recommended_five_minutes() {
        let now = Instant::now();
        let mut p = Peers::default();
        p.note(peer(53), true, None, now);
        assert!(!p.expire(PROTO_UDP, now, now + Duration::from_secs(299)));
        assert!(p.expire(PROTO_UDP, now, now + Duration::from_secs(301)));
    }
}
