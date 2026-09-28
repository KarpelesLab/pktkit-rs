//! RTO calculation (RFC 6298) with Karn's algorithm, and RFC 7323's
//! per-ACK samples when timestamps are on.
//!
//! The constants are Linux's: RFC 6298 asks for a 1 s floor (a SHOULD),
//! which every major stack lowers to 200 ms. Linux also floors the
//! variance term rather than the sum, RTO = SRTT + max(4*RTTVAR, 200 ms),
//! which is RFC 6298's `max(G, K*RTTVAR)` with a coarse G: on a path of
//! steady delay RTTVAR decays towards zero, and an RTO that close to the
//! round trip fires on any jitter (a delayed ACK alone adds 40 ms). The cap
//! stays at 60 s, the least RFC 6298 §2.5 allows (Linux uses 120 s): with
//! [`MAX_RETRIES`](super::conn::MAX_RETRIES) backoffs it bounds how long a
//! connection keeps trying.

use crate::time::Instant;
use std::time::Duration;

use super::seqspace::seq_after;

/// Default initial retransmission timeout (RFC 6298 §2.1).
pub const DEFAULT_RTO: Duration = Duration::from_secs(1);
/// Floor for the RTO, and for its variance term (Linux's `TCP_RTO_MIN`).
pub const MIN_RTO: Duration = Duration::from_millis(200);
/// RTO once data transfer begins after a lost SYN (RFC 6298 §5.7).
const SYN_LOSS_RTO: Duration = Duration::from_secs(3);
/// Cap on the RTO, backoff included: the least RFC 6298 §2.5 allows.
pub const MAX_RTO: Duration = Duration::from_secs(60);

/// Computes the retransmission timeout per RFC 6298.
///
/// Maintains SRTT and RTTVAR, exponential backoff on timeouts, and Karn's
/// algorithm to avoid sampling retransmitted segments.
#[derive(Debug)]
pub struct RtoState {
    srtt: Duration,
    rttvar: Duration,
    rto: Duration,
    measured: bool,

    timing: bool,
    time_sent: Instant,
    time_seq: u32,
}

impl RtoState {
    /// No sample yet: the RTO is [`DEFAULT_RTO`] (RFC 6298 §2.1).
    pub fn new(now: Instant) -> Self {
        Self {
            srtt: Duration::ZERO,
            rttvar: Duration::ZERO,
            rto: DEFAULT_RTO,
            measured: false,
            timing: false,
            time_sent: now,
            time_seq: 0,
        }
    }

    /// Feed a fresh RTT sample and recompute SRTT / RTTVAR / RTO.
    pub fn sample(&mut self, rtt: Duration) {
        self.sample_of(rtt, 1);
    }

    /// Feed one of about `per_window` samples taken this round trip.
    ///
    /// With timestamps every ACK that advances SND.UNA gives a sample (RFC
    /// 7323 §4.2), and weighing each as RFC 6298 weighs one per round trip
    /// would have SRTT and RTTVAR forget a round trip's history in a
    /// fraction of it. RFC 7323 Appendix G divides the gains by the
    /// samples expected per window instead, alpha' = alpha / n and
    /// beta' = beta / n, which keeps their memory a few round trips long.
    pub fn sample_of(&mut self, rtt: Duration, per_window: u32) {
        let n = per_window.max(1);
        if !self.measured {
            self.srtt = rtt;
            self.rttvar = rtt / 2;
            self.measured = true;
        } else {
            // RTTVAR must be updated before SRTT (RFC 6298 §2.3):
            // RTTVAR += beta' * (|SRTT - R| - RTTVAR), beta' = 1/(4n), and
            // SRTT += alpha' * (R - SRTT), alpha' = 1/(8n).
            let diff = self.srtt.abs_diff(rtt);
            self.rttvar = (self.rttvar * (4 * n - 1) + diff) / (4 * n);
            self.srtt = (self.srtt * (8 * n - 1) + rtt) / (8 * n);
        }
        self.rto = self.srtt + (self.rttvar * 4).max(MIN_RTO);
        self.clamp();
    }

    /// Exponential backoff on timeout.
    pub fn backoff(&mut self) {
        self.rto = self.rto.saturating_mul(2);
        self.clamp();
    }

    /// The SYN timed out, and data transfer is about to begin: RFC 6298
    /// §5.7 re-initializes an RTO below 3 s to 3 s, since the handshake
    /// gave no RTT sample and 1 s has proven too short for this path.
    pub fn reset_after_syn_loss(&mut self) {
        if !self.measured {
            self.rto = SYN_LOSS_RTO;
        }
    }

    /// The current retransmission timeout.
    #[inline]
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// The smoothed round-trip time; zero before the first sample.
    #[inline]
    pub fn srtt(&self) -> Duration {
        self.srtt
    }

    /// The RTTVAR estimate.
    #[inline]
    pub fn rttvar(&self) -> Duration {
        self.rttvar
    }

    /// A timeout turned out spurious, and a round trip taken since from
    /// data sent after it was `sample`: RFC 4015 step (11) makes the timer
    /// no less conservative than it was before, `srtt_prev` and
    /// `rttvar_prev` being SRTT (plus two clock ticks) and RTTVAR then.
    pub fn after_spurious_timeout(
        &mut self,
        srtt_prev: Duration,
        rttvar_prev: Duration,
        sample: Duration,
    ) {
        self.srtt = srtt_prev.max(sample);
        self.rttvar = rttvar_prev.max(sample / 2);
        self.measured = true;
        self.rto = self.srtt + (self.rttvar * 4).max(MIN_RTO);
        self.clamp();
    }

    /// Mark a segment sent at `now` as in-flight for RTT measurement.
    pub fn start_timing(&mut self, seq: u32, now: Instant) {
        if self.timing {
            return;
        }
        self.timing = true;
        self.time_sent = now;
        self.time_seq = seq;
    }

    /// If the ACK, arriving at `now`, covers the timed segment, record the
    /// sample. Returns true when a sample was taken.
    pub fn ack_received(&mut self, ack: u32, now: Instant) -> bool {
        match self.timed_rtt(ack, now) {
            Some(rtt) => {
                self.sample(rtt);
                true
            }
            None => false,
        }
    }

    /// If the ACK, arriving at `now`, covers the timed segment, the round
    /// trip it took, for the caller to [sample](Self::sample_of); timing
    /// stops either way.
    pub fn timed_rtt(&mut self, ack: u32, now: Instant) -> Option<Duration> {
        if !self.timing || !seq_after(ack, self.time_seq) {
            return None;
        }
        self.timing = false;
        Some(now.saturating_duration_since(self.time_sent))
    }

    /// Karn's algorithm: drop the current sample on retransmit.
    pub fn invalidate_timing(&mut self) {
        self.timing = false;
    }

    fn clamp(&mut self) {
        if self.rto < MIN_RTO {
            self.rto = MIN_RTO;
        }
        if self.rto > MAX_RTO {
            self.rto = MAX_RTO;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_sets_srtt_and_rto() {
        let mut r = RtoState::new(Instant::now());
        r.sample(Duration::from_millis(100));
        assert_eq!(r.srtt(), Duration::from_millis(100));
        // RTO = SRTT + 4*RTTVAR = 100 + 4*50 = 300ms
        assert_eq!(r.rto(), Duration::from_millis(300));
    }

    #[test]
    fn backoff_doubles_rto() {
        let mut r = RtoState::new(Instant::now());
        let before = r.rto();
        r.backoff();
        assert_eq!(r.rto(), before * 2);
    }

    #[test]
    fn rto_floor_is_min_rto() {
        let mut r = RtoState::new(Instant::now());
        r.sample(Duration::from_micros(1));
        assert!(r.rto() >= MIN_RTO);
    }

    /// The variance term has a floor of its own, as Linux's: a steady
    /// round trip must not bring the RTO down to it.
    #[test]
    fn rto_stays_clear_of_a_steady_rtt() {
        let mut r = RtoState::new(Instant::now());
        for _ in 0..100 {
            r.sample(Duration::from_millis(300));
        }
        assert_eq!(r.srtt(), Duration::from_millis(300));
        assert!(r.rto() >= Duration::from_millis(500), "{:?}", r.rto());
    }

    /// Before any sample the RTO is RFC 6298's 1 s; a backoff doubles it,
    /// up to the cap.
    #[test]
    fn initial_rto_and_cap() {
        let mut r = RtoState::new(Instant::now());
        assert_eq!(r.rto(), Duration::from_secs(1));
        for _ in 0..10 {
            r.backoff();
        }
        assert_eq!(r.rto(), MAX_RTO);
    }

    /// Many samples a window move SRTT about as far in a round trip as one
    /// sample a window does (RFC 7323 Appendix G).
    #[test]
    fn per_ack_samples_are_weighed_by_the_window() {
        let (mut once, mut each) = (RtoState::new(Instant::now()), RtoState::new(Instant::now()));
        once.sample(Duration::from_millis(100));
        each.sample(Duration::from_millis(100));
        once.sample(Duration::from_millis(200));
        for _ in 0..10 {
            each.sample_of(Duration::from_millis(200), 10);
        }
        let diff = once.srtt().abs_diff(each.srtt());
        assert!(diff < Duration::from_millis(2), "{once:?} / {each:?}");
    }

    #[test]
    fn karns_invalidation() {
        let mut r = RtoState::new(Instant::now());
        r.start_timing(100, Instant::now());
        r.invalidate_timing();
        // ACK after invalidation must not record a sample.
        assert!(!r.ack_received(200, Instant::now()));
    }

    #[test]
    fn ack_records_sample() {
        let mut r = RtoState::new(Instant::now());
        let t0 = Instant::now();
        r.start_timing(100, t0);
        assert!(r.ack_received(101, t0 + Duration::from_millis(5)));
        assert!(r.srtt() > Duration::ZERO);
    }
}
