//! Process-wide bound on buffer auto-tuning.
//!
//! Each connection grows its send and receive buffers past their initial
//! sizes as the path calls for (see [`ConnConfig::autotune`]), which with
//! enough connections could add up to more memory than the host has. Like
//! Linux's `tcp_mem`, one counter tracks what all connections have grown by
//! together; once it reaches the budget, buffers stay where they are until
//! other connections give some back. Running short only caps throughput:
//! nothing fails.
//!
//! [`ConnConfig::autotune`]: super::ConnConfig::autotune

use crate::time::Instant;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::seqspace::seq_before;

/// What all connections together may grow their buffers by: room for 16
/// connections at the default maximum, both directions grown in full, or
/// many more that need less.
pub(crate) const AUTOTUNE_BUDGET: usize = 256 << 20;

/// Bytes of buffer growth handed out, against a cap.
#[derive(Debug)]
pub(crate) struct Budget {
    used: AtomicUsize,
    cap: usize,
}

/// The budget every connection draws on, unless a test gives it its own.
pub(crate) static GLOBAL: Budget = Budget::new(AUTOTUNE_BUDGET);

impl Budget {
    pub(crate) const fn new(cap: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            cap,
        }
    }

    /// Take up to `want` bytes, as much as is left. Returns what was taken,
    /// which may be less, or nothing.
    pub(crate) fn reserve(&self, want: usize) -> usize {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let got = want.min(self.cap.saturating_sub(cur));
            if got == 0 {
                return 0;
            }
            match self.used.compare_exchange_weak(
                cur,
                cur + got,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return got,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Give back `n` bytes taken by [`reserve`](Self::reserve).
    pub(crate) fn release(&self, n: usize) {
        if n > 0 {
            self.used.fetch_sub(n, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }
}

/// Receive-side dynamic right-sizing (Linux's `tcp_rcv_space_adjust`,
/// after Fisk and Feng's DRS): once per round trip, see how much the
/// application read in it. A window only as large as that holds the
/// sender to the rate the application already reached; twice as much
/// lets it double, as slow start does, and more still if it doubled last
/// time too.
#[derive(Debug)]
pub(crate) struct RcvSpace {
    /// Bytes the application has read, in all.
    copied: u64,
    /// `copied` and the time when the current measurement began.
    mark: u64,
    time: Instant,
    /// The most read in one measurement so far.
    space: usize,
    /// The receiver's own round-trip estimate (Linux's `rcv_rtt_est`), for a
    /// connection that may send nothing to time: the least time a window's
    /// worth of data took to arrive, or smoothed timestamp echoes.
    rtt: Option<Duration>,
    /// While timing a window: the sequence number that ends it, and when it
    /// began.
    rtt_mark: Option<(u32, Instant)>,
}

impl RcvSpace {
    /// `space` is what a round trip is assumed to carry before any has
    /// been measured: the peer's initial window.
    pub(crate) fn new(space: usize) -> Self {
        Self {
            copied: 0,
            mark: 0,
            time: Instant::now(),
            space: space.max(1),
            rtt: None,
            rtt_mark: None,
        }
    }

    /// Move the start of the current measurement `by` into the past, as if
    /// that much time had gone by since.
    #[cfg(test)]
    pub(crate) fn backdate(&mut self, by: Duration) {
        self.time = self.time.checked_sub(by).unwrap_or(self.time);
    }

    /// The application read `n` bytes.
    #[inline]
    pub(crate) fn on_read(&mut self, n: usize) {
        self.copied += n as u64;
    }

    /// In-order data advanced RCV.NXT to `rcv_nxt`, with `edge` the right
    /// edge of the window last advertised (Linux's `tcp_rcv_rtt_measure`).
    /// Filling a window takes at least a round trip, more when the sender is
    /// held back by something else, so the smallest of these is the
    /// estimate.
    pub(crate) fn measure_window(&mut self, rcv_nxt: u32, edge: u32, now: Instant) {
        if let Some((end, start)) = self.rtt_mark {
            if seq_before(rcv_nxt, end) {
                return;
            }
            let sample = now.saturating_duration_since(start);
            if !sample.is_zero() {
                self.rtt = Some(self.rtt.map_or(sample, |r| r.min(sample)));
            }
        }
        self.rtt_mark = Some((edge, now));
    }

    /// A round-trip sample from a timestamp echo on a full-sized segment
    /// (Linux's `tcp_rcv_rtt_measure_ts`), smoothed as RFC 6298 does SRTT.
    pub(crate) fn measure_ts(&mut self, sample: Duration) {
        if sample.is_zero() {
            return;
        }
        self.rtt = Some(self.rtt.map_or(sample, |r| (r * 7 + sample) / 8));
    }

    /// The receiver's round-trip estimate, and the most read in a round
    /// trip so far, for `TcpInfo`.
    pub(crate) fn snapshot(&self) -> (Option<Duration>, usize) {
        (self.rtt, self.space)
    }

    /// The round trip that paces the measurement: the receiver's own
    /// estimate, or `srtt` from our sending if smaller (or the only one).
    fn rtt(&self, srtt: Option<Duration>) -> Option<Duration> {
        match (self.rtt, srtt) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Called after a read: once a round trip has passed since the last
    /// measurement, the buffer size wanted for what the application read
    /// in it, if that is more than ever before. `mss` is the largest
    /// segment we accept.
    pub(crate) fn adjust(
        &mut self,
        now: Instant,
        srtt: Option<Duration>,
        mss: usize,
    ) -> Option<usize> {
        let rtt = self.rtt(srtt)?;
        if now.saturating_duration_since(self.time) < rtt {
            return None;
        }
        let copied = usize::try_from(self.copied - self.mark).unwrap_or(usize::MAX);
        self.mark = self.copied;
        self.time = now;
        if copied <= self.space {
            return None;
        }
        // Linux's arithmetic: twice what was read, room for reordering and
        // SACKed data on top, and twice the growth over the last round
        // trip besides, since a sender in slow start keeps doubling.
        let mut want = copied
            .saturating_mul(2)
            .saturating_add(mss.saturating_mul(16));
        let grow = (want as u128 * (copied - self.space) as u128 / self.space as u128)
            .min(usize::MAX as u128) as usize;
        want = want.saturating_add(grow.saturating_mul(2));
        self.space = copied;
        Some(want)
    }
}

/// The send buffer wanted for a congestion window of `cwnd` bytes (Linux's
/// `tcp_sndbuf_expand`): the window in flight and as much again queued
/// behind it, so the application can refill what each ACK frees before
/// the window needs it, and so a window that grows by half or doubles in
/// the next round trip finds the data already there.
pub(crate) fn sndbuf_target(cwnd: u32, mss: u32) -> usize {
    // Never below the initial window, as Linux counts at least
    // TCP_INIT_CWND segments.
    (cwnd.max(mss.saturating_mul(10)) as usize).saturating_mul(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_hands_out_what_is_left() {
        let b = Budget::new(1000);
        assert_eq!(b.reserve(600), 600);
        assert_eq!(b.reserve(600), 400);
        assert_eq!(b.reserve(1), 0);
        b.release(500);
        assert_eq!(b.used(), 500);
        assert_eq!(b.reserve(100), 100);
    }

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn waits_a_round_trip_and_grows_past_twice_the_rate() {
        let t0 = Instant::now();
        let mut r = RcvSpace::new(14600);
        r.time = t0;
        // No round trip known: nothing to pace by.
        r.on_read(100_000);
        assert_eq!(r.adjust(t0 + 100 * MS, None, 1460), None);
        // Known, but not yet elapsed.
        let srtt = Some(100 * MS);
        assert_eq!(r.adjust(t0 + 50 * MS, srtt, 1460), None);
        let want = r.adjust(t0 + 100 * MS, srtt, 1460).unwrap();
        assert!(want >= 2 * 100_000, "{want}");
        // The same rate again asks for nothing more.
        r.on_read(100_000);
        assert_eq!(r.adjust(t0 + 200 * MS, srtt, 1460), None);
        // Doubling it asks for well over twice as much.
        r.on_read(200_000);
        let more = r.adjust(t0 + 300 * MS, srtt, 1460).unwrap();
        assert!(more >= 4 * 200_000, "{more}");
    }

    #[test]
    fn window_timing_keeps_the_fastest_fill() {
        let t0 = Instant::now();
        let mut r = RcvSpace::new(14600);
        r.measure_window(0, 1000, t0);
        r.measure_window(500, 1000, t0 + 10 * MS); // not yet at the edge
        assert_eq!(r.rtt, None);
        r.measure_window(1000, 5000, t0 + 80 * MS);
        assert_eq!(r.rtt, Some(80 * MS));
        r.measure_window(5000, 9000, t0 + 200 * MS);
        assert_eq!(r.rtt, Some(80 * MS));
        r.measure_window(9000, 9500, t0 + 250 * MS);
        assert_eq!(r.rtt, Some(50 * MS));
        // A smaller SRTT from our own sending wins.
        assert_eq!(r.rtt(Some(20 * MS)), Some(20 * MS));
        assert_eq!(r.rtt(None), Some(50 * MS));
    }

    #[test]
    fn send_target_is_twice_the_window() {
        assert_eq!(sndbuf_target(1 << 20, 1460), 2 << 20);
        assert_eq!(sndbuf_target(1460, 1460), 2 * 14600);
    }
}
