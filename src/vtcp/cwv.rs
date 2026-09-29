//! Congestion window validation (RFC 7661): the pipeACK estimate of what
//! the path has recently carried, against which cwnd is validated.
//!
//! A window the sender has not been filling says nothing about the path
//! now. RFC 7661 keeps it for up to the non-validated period (NVP), so an
//! application that pauses can resume at its old rate, but does not let it
//! grow (the connection's `cwnd_limited` rule), bases the response to a loss
//! on what was really in use, and halves it once the NVP runs out.

use crate::time::Instant;
use std::time::Duration;

/// The non-validated period (RFC 7661 §4.4, §5): five minutes.
pub(crate) const NVP: Duration = Duration::from_secs(300);
/// Measurement periods the sampling period is split into (RFC 7661
/// §4.5.1's example).
const BUCKETS: usize = 5;

/// The pipeACK variable (RFC 7661 §4.2): the most data acknowledged within
/// a round trip over the last pipeACK Sampling Period, max(3·RTT, 1 s).
#[derive(Debug)]
pub(crate) struct PipeAck {
    /// False until a sample has been taken, and again after loss recovery,
    /// which keeps the connection in the validated phase.
    defined: bool,
    /// The sample being taken: when it began, and HighACK then.
    cur: Option<(Instant, u32)>,
    /// Each measurement period's start and largest sample, oldest first.
    buckets: [(Instant, u32); BUCKETS],
    len: usize,
}

impl PipeAck {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            defined: false,
            cur: None,
            buckets: [(now, 0); BUCKETS],
            len: 0,
        }
    }

    /// The sampling period for a round trip of `rtt`.
    fn period(rtt: Duration) -> Duration {
        (3 * rtt).max(Duration::from_secs(1))
    }

    /// An ACK took HighACK to `high_ack`, outside loss recovery (RFC 7661
    /// §4.2: no samples are taken during it). `rtt` is the smoothed round
    /// trip. A sample is what was acknowledged over one round trip.
    pub(crate) fn on_ack(&mut self, now: Instant, high_ack: u32, rtt: Duration) {
        let rtt = rtt.max(Duration::from_micros(1));
        let Some((start, from)) = self.cur else {
            self.cur = Some((now, high_ack));
            return;
        };
        let took = now.saturating_duration_since(start);
        if took < rtt {
            return;
        }
        // A sample that spans an idle spell measured the spell, not the
        // path's rate: it starts afresh instead. One that ran past a round
        // trip, the ACKs being sparse, counts one round trip's worth of
        // it (§4.2): whole, a sample of nearly two would read up to twice
        // what the path carries per round trip.
        if took <= 2 * rtt {
            let acked = u128::from(high_ack.wrapping_sub(from));
            let sample = acked * rtt.as_nanos() / took.as_nanos();
            self.push(now, sample as u32, rtt);
        }
        self.cur = Some((now, high_ack));
    }

    fn push(&mut self, now: Instant, sample: u32, rtt: Duration) {
        self.defined = true;
        let span = Self::period(rtt) / BUCKETS as u32;
        if self.len > 0 {
            let last = &mut self.buckets[self.len - 1];
            if now.saturating_duration_since(last.0) < span {
                last.1 = last.1.max(sample);
                return;
            }
        }
        if self.len == BUCKETS {
            self.buckets.copy_within(1.., 0);
            self.len -= 1;
        }
        self.buckets[self.len] = (now, sample);
        self.len += 1;
    }

    /// pipeACK, in bytes: `None` while undefined. Samples older than the
    /// sampling period count for nothing, so a sender idle for longer has
    /// a pipeACK of zero (RFC 7661 §4.5.1).
    pub(crate) fn value(&self, now: Instant, rtt: Duration) -> Option<u32> {
        if !self.defined {
            return None;
        }
        let period = Self::period(rtt);
        Some(
            self.buckets[..self.len]
                .iter()
                .filter(|b| now.saturating_duration_since(b.0) < period)
                .map(|b| b.1)
                .max()
                .unwrap_or(0),
        )
    }

    /// Back to undefined: after loss recovery (RFC 7661 §4.4.1), or a
    /// timeout, or a restart after idle.
    pub(crate) fn reset(&mut self) {
        self.defined = false;
        self.cur = None;
        self.len = 0;
    }
}

/// Whether a pipeACK of `pipe_ack` leaves a window of `cwnd` non-validated
/// (RFC 7661 §4.3): the sender has used less than half of it.
#[inline]
pub(crate) fn non_validated(pipe_ack: Option<u32>, cwnd: u32) -> bool {
    pipe_ack.is_some_and(|p| p < cwnd / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTT: Duration = Duration::from_millis(100);

    #[test]
    fn undefined_until_sampled() {
        let t0 = Instant::now();
        let mut p = PipeAck::new(t0);
        assert_eq!(p.value(t0, RTT), None);
        p.on_ack(t0, 0, RTT);
        p.on_ack(t0 + RTT / 2, 5000, RTT);
        assert_eq!(p.value(t0, RTT), None, "less than a round trip");
        p.on_ack(t0 + RTT, 10_000, RTT);
        assert_eq!(p.value(t0 + RTT, RTT), Some(10_000));
        p.reset();
        assert_eq!(p.value(t0 + RTT, RTT), None);
    }

    /// The largest sample of the sampling period, which then ages out.
    #[test]
    fn largest_recent_sample() {
        let t0 = Instant::now();
        let mut p = PipeAck::new(t0);
        let mut high = 0u32;
        p.on_ack(t0, high, RTT);
        // Three round trips at 50 kB, then a trickle of 5 kB each.
        let mut now = t0;
        for i in 0..40 {
            now += RTT;
            high += if i < 3 { 50_000 } else { 5_000 };
            p.on_ack(now, high, RTT);
            let v = p.value(now, RTT).unwrap();
            if i < 10 {
                assert_eq!(v, 50_000, "round {i}");
            }
        }
        assert_eq!(p.value(now, RTT), Some(5_000));
        // Idle: nothing within the period.
        assert_eq!(p.value(now + Duration::from_secs(2), RTT), Some(0));
        assert!(non_validated(Some(0), 10_000));
        assert!(!non_validated(None, 10_000));
        assert!(!non_validated(Some(5_000), 10_000));
    }

    /// A sample that took longer than a round trip counts what one round
    /// trip of it carried.
    #[test]
    fn sample_covers_one_round_trip() {
        let t0 = Instant::now();
        let mut p = PipeAck::new(t0);
        p.on_ack(t0, 0, RTT);
        // 10 kB per round trip, the ACK after one coming 1.9 RTTs in.
        let now = t0 + RTT * 19 / 10;
        p.on_ack(now, 19_000, RTT);
        assert_eq!(p.value(now, RTT), Some(10_000));
    }

    /// A sample across an idle spell is not taken.
    #[test]
    fn idle_spell_is_not_a_sample() {
        let t0 = Instant::now();
        let mut p = PipeAck::new(t0);
        p.on_ack(t0, 0, RTT);
        p.on_ack(t0 + Duration::from_secs(10), 1_000_000, RTT);
        assert_eq!(p.value(t0 + Duration::from_secs(10), RTT), None);
    }
}
