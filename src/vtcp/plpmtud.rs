//! Packetization Layer Path MTU Discovery (RFC 4821) for TCP.
//!
//! ICMP-based discovery (RFC 1191, RFC 8201) breaks where the ICMP messages
//! do not come back: a firewall that drops them, or a tunnel that never
//! sends them, turns a narrower hop into a black hole for full-sized
//! segments while small ones, the handshake's and the ACKs', get through.
//! PLPMTUD finds the path MTU from what TCP itself sees delivered: a probe
//! is an ordinary data segment larger than the current MSS, a success when
//! it is acknowledged and a failure when it is lost while the segments
//! after it arrive.
//!
//! This follows Linux's `tcp_mtu_probing`: a search for the MTU between
//! `search_low`, known to work, and `search_high`, not yet known to fail,
//! by bisection (RFC 4821 §7.5, RFC 8899 §5.3's search); a black hole
//! detected after repeated timeouts drops the MSS to a base that nearly
//! every path carries (RFC 4821 §7.2 suggests 1024 bytes), from where
//! probing climbs back; and once the search has converged, the whole range
//! is searched again every ten minutes (Linux's `tcp_probe_interval`), as
//! the path may have changed.

use std::time::Duration;

use crate::time::Instant;

/// Whether, and when, the connection searches for the path MTU itself
/// (RFC 4821), on top of what ICMP reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum MtuProbing {
    /// Never: only ICMP Fragmentation Needed / Packet Too Big messages
    /// lower the path MTU. Where they are filtered, a narrower hop leaves
    /// the connection stuck retransmitting segments that never get through
    /// until it gives up.
    Off,
    /// Once full-sized segments keep timing out (a black hole), drop the
    /// MSS to a base of 1024 bytes (IPv6: 1220, its minimum MTU's worth),
    /// then probe back up to what the path carries. As Linux's default,
    /// `tcp_mtu_probing = 1`. The default: it costs nothing until a black
    /// hole shows.
    #[default]
    OnBlackHole,
    /// Probe from the start: send with the base MSS until probes show more
    /// gets through, never sending a segment the path has not been seen to
    /// carry. As Linux's `tcp_mtu_probing = 2`. For paths known to have
    /// black holes; elsewhere it costs the first round trips' segment size.
    Always,
}

/// Linux's `tcp_base_mss`: the MSS a black hole drops the connection to,
/// and where [`MtuProbing::Always`] starts.
pub(crate) const BASE_MSS: u32 = 1024;
/// Linux's `tcp_probe_threshold`: the search stops once the range left is
/// narrower than this, in bytes.
const PROBE_THRESHOLD: u32 = 8;
/// Linux's `tcp_probe_interval`: how long a converged search rests before
/// the path is searched again.
pub(crate) const PROBE_INTERVAL: Duration = Duration::from_secs(600);
/// RFC 8899 §5.1.2's MAX_PROBES: probes of one size that must fail before
/// the size is taken as too large. A single loss may be congestion, not
/// the size, and would otherwise hold the MTU down for the ten minutes
/// until the next search.
const MAX_PROBES: u32 = 3;
/// Consecutive retransmission timeouts that make a black hole suspected.
/// Linux waits for `tcp_retries1`'s worth of time (three timeouts at the
/// minimum RTO); two is enough to tell a black hole, where the first
/// timeout's retransmission, full-sized again, is lost as well, from a
/// lost segment, whose retransmission gets through. A false alarm costs
/// little: probing climbs back within a few round trips.
pub(crate) const BLACK_HOLE_RTOS: u32 = 2;

/// The search, in MTUs (IP and TCP headers included, TCP options too).
#[derive(Debug, Clone)]
pub(crate) struct Search {
    mode: MtuProbing,
    /// The search is under way: a black hole was seen, or `Always`.
    enabled: bool,
    /// Largest MTU known to work.
    low: u32,
    /// Largest MTU not known to fail.
    high: u32,
    /// The largest the path could carry: the peer's MSS and ours, and
    /// what ICMP has reported, with headers.
    max: u32,
    /// The smallest MTU a black hole takes the connection down to.
    floor: u32,
    /// The base MTU: [`BASE_MSS`] with headers, at least `floor`.
    base: u32,
    /// Failed probes of the size last probed.
    fails: u32,
    last_size: u32,
    /// When the search last moved, for the next one.
    stamp: Instant,
}

impl Search {
    /// A search for a connection of `mode`, whose headers are `overhead`
    /// bytes and whose smallest path MTU is `floor`.
    pub fn new(mode: MtuProbing, overhead: u32, floor: u32, now: Instant) -> Self {
        let base = (BASE_MSS + overhead).max(floor);
        Self {
            mode,
            enabled: mode == MtuProbing::Always,
            low: base,
            high: base,
            max: base,
            floor,
            base,
            fails: 0,
            last_size: 0,
            stamp: now,
        }
    }

    /// The handshake has set the most the path could carry: `max`.
    pub fn set_max(&mut self, max: u32) {
        self.max = max.max(self.floor);
        self.high = self.max;
        self.low = self.base.min(self.max);
    }

    /// The path MTU is at most `mtu`, as ICMP reported.
    pub fn clamp(&mut self, mtu: u32) {
        let mtu = mtu.max(self.floor);
        self.max = self.max.min(mtu);
        self.high = self.high.min(mtu);
        self.low = self.low.min(mtu);
    }

    /// The most the connection may send with, as an MTU, if the search
    /// caps it: what the search has shown to work.
    #[inline]
    pub fn cap(&self) -> Option<u32> {
        self.enabled.then_some(self.low)
    }

    /// Where a black hole that swallows packets of `size` bytes takes the
    /// connection: the base, or half of `size` if that is no smaller, down
    /// to the floor. `None` if the search may not run, or `size` is at the
    /// floor already, where no path is narrower.
    pub fn black_hole_target(&self, size: u32) -> Option<u32> {
        if self.mode == MtuProbing::Off {
            return None;
        }
        let base = self.base.min(self.max);
        let t = if base < size {
            base
        } else {
            (size / 2).max(self.floor)
        };
        (t < size).then_some(t)
    }

    /// Full-sized segments keep timing out: a black hole is suspected. The
    /// search starts, if it was not under way, from `low`, a
    /// [`black_hole_target`](Self::black_hole_target), taken as what works.
    pub fn on_black_hole(&mut self, low: u32, now: Instant) {
        self.enabled = true;
        self.low = low.min(self.max);
        self.high = self.high.max(self.low);
        self.fails = 0;
        self.stamp = now;
    }

    /// The MTU to probe with now, if a probe is due: halfway between what
    /// works and what may, once the range is worth searching. Once it is
    /// not, the search rests for [`PROBE_INTERVAL`], then starts again from
    /// what works up to the most the path could carry.
    pub fn next_probe(&mut self, now: Instant) -> Option<u32> {
        if !self.enabled {
            return None;
        }
        if self.high.saturating_sub(self.low) < PROBE_THRESHOLD {
            if now.saturating_duration_since(self.stamp) < PROBE_INTERVAL {
                return None;
            }
            self.high = self.max;
            self.stamp = now;
            self.fails = 0;
            if self.high.saturating_sub(self.low) < PROBE_THRESHOLD {
                return None;
            }
        }
        Some(self.low + (self.high - self.low).div_ceil(2))
    }

    /// A probe of `mtu` bytes was delivered.
    pub fn on_success(&mut self, mtu: u32, now: Instant) {
        self.low = self.low.max(mtu.min(self.max));
        self.high = self.high.max(self.low);
        self.fails = 0;
        self.stamp = now;
    }

    /// A probe of `mtu` bytes was lost while what was sent around it was
    /// not: after [`MAX_PROBES`] such, the size is taken as too large.
    pub fn on_failure(&mut self, mtu: u32, now: Instant) {
        if mtu != self.last_size {
            self.last_size = mtu;
            self.fails = 0;
        }
        self.fails += 1;
        if self.fails >= MAX_PROBES {
            self.high = (mtu - 1).max(self.low);
            self.fails = 0;
        }
        self.stamp = now;
    }

    #[cfg(test)]
    pub fn range(&self) -> (u32, u32) {
        (self.low, self.high)
    }
}

/// A probe in flight: `[start, end)` went out as one segment of `mtu`
/// bytes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Probe {
    pub start: u32,
    pub end: u32,
    pub mtu: u32,
    /// Something sent before it has been retransmitted since: a loss of
    /// the probe then may well be congestion's, not its size's.
    pub others_lost: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn search(mode: MtuProbing) -> Search {
        let mut s = Search::new(mode, 40, 552, Instant::now());
        s.set_max(1500);
        s
    }

    /// Probe against a path of `path` bytes until the search rests, and
    /// return where it ends and how many probes it took.
    fn converge(s: &mut Search, path: u32) -> (u32, u32) {
        let now = Instant::now();
        let mut probes = 0;
        while let Some(p) = s.next_probe(now) {
            probes += 1;
            assert!(probes < 100, "no convergence");
            if p <= path {
                s.on_success(p, now);
            } else {
                s.on_failure(p, now);
            }
        }
        (s.cap().unwrap(), probes)
    }

    #[test]
    fn off_and_on_black_hole_do_not_search_until_told() {
        for mode in [MtuProbing::Off, MtuProbing::OnBlackHole] {
            let mut s = search(mode);
            assert_eq!(s.cap(), None);
            assert_eq!(s.next_probe(Instant::now()), None);
        }
        let off = search(MtuProbing::Off);
        assert_eq!(off.black_hole_target(1500), None);
    }

    #[test]
    fn always_starts_from_the_base_and_climbs() {
        let mut s = search(MtuProbing::Always);
        assert_eq!(s.cap(), Some(1064));
        let (mtu, _) = converge(&mut s, 1500);
        assert!(mtu > 1492, "{mtu}");
    }

    #[test]
    fn a_black_hole_converges_just_below_the_path() {
        for path in [1100, 1280, 1400, 1492] {
            let mut s = search(MtuProbing::OnBlackHole);
            assert_eq!(s.black_hole_target(1500), Some(1064));
            s.on_black_hole(1064, Instant::now());
            assert_eq!(s.cap(), Some(1064));
            let (mtu, probes) = converge(&mut s, path);
            assert!(mtu <= path && mtu + PROBE_THRESHOLD > path, "{path}: {mtu}");
            assert!(probes < 40, "{path}: {probes} probes");
        }
    }

    #[test]
    fn repeated_black_holes_halve_down_to_the_floor() {
        let mut s = search(MtuProbing::OnBlackHole);
        let now = Instant::now();
        assert_eq!(s.black_hole_target(1064), Some(552));
        assert_eq!(s.black_hole_target(900), Some(552));
        assert_eq!(s.black_hole_target(552), None);
        s.on_black_hole(552, now);
        assert_eq!(s.cap(), Some(552));
        // From there a path of 700 is found.
        let (mtu, _) = converge(&mut s, 700);
        assert!(mtu <= 700 && mtu > 690, "{mtu}");
    }

    #[test]
    fn one_lost_probe_does_not_condemn_its_size() {
        let mut s = search(MtuProbing::Always);
        let now = Instant::now();
        let p = s.next_probe(now).unwrap();
        s.on_failure(p, now);
        assert_eq!(s.next_probe(now), Some(p));
        s.on_failure(p, now);
        s.on_failure(p, now);
        assert_eq!(s.range().1, p - 1);
    }

    #[test]
    fn a_converged_search_starts_again_after_the_interval() {
        let mut s = search(MtuProbing::OnBlackHole);
        s.on_black_hole(1064, Instant::now());
        converge(&mut s, 1300);
        let later = Instant::now() + PROBE_INTERVAL;
        let p = s.next_probe(later).unwrap();
        assert!(p > 1300, "{p}");
        // The path widened meanwhile.
        s.on_success(p, later);
        assert_eq!(s.cap(), Some(p));
    }

    #[test]
    fn icmp_clamps_the_search() {
        let mut s = search(MtuProbing::Always);
        s.clamp(1200);
        let (mtu, _) = converge(&mut s, 1500);
        assert!(mtu <= 1200 && mtu > 1190, "{mtu}");
        s.clamp(100);
        assert_eq!(s.cap(), Some(552));
    }
}
