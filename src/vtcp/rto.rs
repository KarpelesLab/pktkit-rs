//! RTO calculation (RFC 6298) with Karn's algorithm.

use std::time::{Duration, Instant};

use super::seqspace::seq_after;

/// Default initial retransmission timeout (RFC 6298 §2.1).
pub const DEFAULT_RTO: Duration = Duration::from_secs(1);
/// Floor for the RTO (RFC 6298 §2.4 — most implementations).
pub const MIN_RTO: Duration = Duration::from_millis(200);
/// Hard upper bound (RFC 6298 allows up to 60s).
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

impl Default for RtoState {
    fn default() -> Self {
        Self::new()
    }
}

impl RtoState {
    pub fn new() -> Self {
        Self {
            srtt: Duration::ZERO,
            rttvar: Duration::ZERO,
            rto: DEFAULT_RTO,
            measured: false,
            timing: false,
            time_sent: Instant::now(),
            time_seq: 0,
        }
    }

    /// Feed a fresh RTT sample and recompute SRTT / RTTVAR / RTO.
    pub fn sample(&mut self, rtt: Duration) {
        if !self.measured {
            self.srtt = rtt;
            self.rttvar = rtt / 2;
            self.measured = true;
        } else {
            // RTTVAR must be updated before SRTT (RFC 6298 §2.3).
            let diff = if self.srtt > rtt {
                self.srtt - rtt
            } else {
                rtt - self.srtt
            };
            self.rttvar = (self.rttvar * 3 + diff) / 4;
            self.srtt = (self.srtt * 7 + rtt) / 8;
        }
        self.rto = self.srtt + self.rttvar * 4;
        self.clamp();
    }

    /// Exponential backoff on timeout.
    pub fn backoff(&mut self) {
        self.rto = self.rto.saturating_mul(2);
        self.clamp();
    }

    #[inline]
    pub fn rto(&self) -> Duration {
        self.rto
    }

    #[inline]
    pub fn srtt(&self) -> Duration {
        self.srtt
    }

    /// Mark a segment as in-flight for RTT measurement.
    pub fn start_timing(&mut self, seq: u32) {
        if self.timing {
            return;
        }
        self.timing = true;
        self.time_sent = Instant::now();
        self.time_seq = seq;
    }

    /// If the ACK covers the timed segment, record the sample. Returns true
    /// when a sample was taken.
    pub fn ack_received(&mut self, ack: u32) -> bool {
        if !self.timing {
            return false;
        }
        if seq_after(ack, self.time_seq) {
            let elapsed = self.time_sent.elapsed();
            self.sample(elapsed);
            self.timing = false;
            return true;
        }
        false
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
    use std::thread::sleep;

    #[test]
    fn first_sample_sets_srtt_and_rto() {
        let mut r = RtoState::new();
        r.sample(Duration::from_millis(100));
        assert_eq!(r.srtt(), Duration::from_millis(100));
        // RTO = SRTT + 4*RTTVAR = 100 + 4*50 = 300ms
        assert_eq!(r.rto(), Duration::from_millis(300));
    }

    #[test]
    fn backoff_doubles_rto() {
        let mut r = RtoState::new();
        let before = r.rto();
        r.backoff();
        assert_eq!(r.rto(), before * 2);
    }

    #[test]
    fn rto_floor_is_min_rto() {
        let mut r = RtoState::new();
        r.sample(Duration::from_micros(1));
        assert!(r.rto() >= MIN_RTO);
    }

    #[test]
    fn karns_invalidation() {
        let mut r = RtoState::new();
        r.start_timing(100);
        r.invalidate_timing();
        // ACK after invalidation must not record a sample.
        assert!(!r.ack_received(200));
    }

    #[test]
    fn ack_records_sample() {
        let mut r = RtoState::new();
        r.start_timing(100);
        sleep(Duration::from_millis(5));
        assert!(r.ack_received(101));
        assert!(r.srtt() > Duration::ZERO);
    }
}
