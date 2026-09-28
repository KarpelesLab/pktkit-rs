//! Congestion control. NewReno (RFC 5681) and HighSpeed TCP (RFC 3649).
//!
//! Both count bytes, not ACKs (RFC 3465): a receiver that delays its ACKs
//! acknowledges two segments with each, and counting ACKs would halve the
//! window's growth, in slow start and in congestion avoidance alike. Slow
//! start takes up to L = 2*SMSS per ACK (RFC 3465 §2.2), enough to double
//! the window per round trip against a delayed-ACK receiver without
//! letting one stretch ACK burst the window open.

/// Pluggable congestion control: the window, and how it grows and shrinks.
///
/// Loss recovery is the connection's: it detects losses (RACK, or
/// duplicate ACKs without SACK), decides when a recovery episode starts
/// and ends, paces the window down to ssthresh during it (RFC 6937), and
/// undoes a response found spurious. The controller only says how much to
/// cut and how fast to grow back.
pub trait CongestionController: Send {
    /// A cumulative ACK outside fast recovery: `bytes_acked` bytes were
    /// newly delivered, with `flight_size` bytes outstanding before it. A
    /// flight well short of the window means the sender was limited by
    /// the application or the receiver, not by cwnd, and growing cwnd then
    /// would validate nothing (RFC 7661 §4.3, RFC 5681 §3.1).
    fn on_ack(&mut self, bytes_acked: u32, flight_size: u32);
    /// A loss was detected with `flight_size` bytes outstanding: set
    /// ssthresh. The connection then brings cwnd down to it.
    fn on_loss(&mut self, flight_size: u32);
    /// The retransmission timer fired with `flight_size` bytes outstanding:
    /// set ssthresh, and cwnd to the loss window. `repeated` is set when
    /// the segment had already been retransmitted by the timer, in which
    /// case RFC 5681 §3.1 holds ssthresh where the first timeout put it.
    fn on_retransmit_timeout(&mut self, flight_size: u32, repeated: bool);
    /// The SYN or SYN-ACK was lost and resent; the handshake has just
    /// completed. RFC 5681 §3.1 has data start from the loss window (one
    /// segment) with ssthresh untouched. The default does that as a
    /// repeated timeout, which the built-in controllers take the same way.
    fn on_handshake_loss(&mut self) {
        self.on_retransmit_timeout(0, true);
    }
    /// The connection now sends segments of `mss` bytes: the path MTU
    /// turned out smaller than the handshake's MSS allowed. Not a loss
    /// signal, so the window stays; only the per-segment steps change. The
    /// default ignores it.
    fn set_mss(&mut self, mss: u32) {
        let _ = mss;
    }
    /// Set cwnd: fast recovery reduces it an ACK at a time, and sets it to
    /// ssthresh when done.
    fn set_cwnd(&mut self, cwnd: u32);
    /// A loss response turned out spurious: go back to `cwnd` and
    /// `ssthresh`, forgetting any growth state tied to the cut.
    fn undo(&mut self, cwnd: u32, ssthresh: u32);
    /// The congestion window, in bytes.
    fn cwnd(&self) -> u32;
    /// The slow-start threshold, in bytes; `u32::MAX` until the first loss.
    fn ssthresh(&self) -> u32;
}

/// RFC 6928's initial window, `min(10*MSS, max(2*MSS, 14600))`.
pub fn initial_window(mss: u32) -> u32 {
    (10 * mss).min((2 * mss).max(14600))
}

/// RFC 5681 NewReno: slow start, congestion avoidance, fast retransmit & recovery.
#[derive(Debug)]
pub struct NewReno {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    /// Bytes acknowledged in congestion avoidance towards the next
    /// segment of growth (RFC 3465 §2.1's `bytes_acked`).
    ca_acked: u32,
}

impl NewReno {
    /// A controller for segments of `mss` bytes, starting from RFC 6928's
    /// initial window.
    pub fn new(mss: u32) -> Self {
        Self {
            cwnd: initial_window(mss),
            ssthresh: u32::MAX,
            mss,
            ca_acked: 0,
        }
    }
}

/// Slow start's growth for an ACK of `bytes_acked` (RFC 3465 §2.2, L = 2).
fn slow_start_inc(bytes_acked: u32, mss: u32) -> u32 {
    bytes_acked.min(mss.saturating_mul(2))
}

impl CongestionController for NewReno {
    fn set_mss(&mut self, mss: u32) {
        self.mss = mss.max(1);
    }

    fn on_ack(&mut self, bytes_acked: u32, flight_size: u32) {
        if !cwnd_limited(self.cwnd, self.ssthresh, self.mss, flight_size) {
            return;
        }
        if self.cwnd < self.ssthresh {
            self.cwnd = self
                .cwnd
                .saturating_add(slow_start_inc(bytes_acked, self.mss));
        } else {
            // A segment per window's worth of bytes acknowledged (RFC 3465
            // §2.1), however many ACKs that took.
            self.ca_acked = self.ca_acked.saturating_add(bytes_acked);
            if self.ca_acked >= self.cwnd {
                self.ca_acked -= self.cwnd;
                self.cwnd = self.cwnd.saturating_add(self.mss);
            }
        }
    }

    fn on_loss(&mut self, flight_size: u32) {
        // RFC 5681 eq. (4): half the flight, not of cwnd, which may never
        // have been filled.
        self.ssthresh = (flight_size / 2).max(2 * self.mss);
        self.ca_acked = 0;
    }

    fn on_retransmit_timeout(&mut self, flight_size: u32, repeated: bool) {
        if !repeated {
            self.on_loss(flight_size);
        }
        self.cwnd = self.mss;
        self.ca_acked = 0;
    }

    fn set_cwnd(&mut self, cwnd: u32) {
        self.cwnd = cwnd.max(self.mss);
    }

    fn undo(&mut self, cwnd: u32, ssthresh: u32) {
        self.cwnd = cwnd.max(self.mss);
        self.ssthresh = ssthresh;
        self.ca_acked = 0;
    }

    fn cwnd(&self) -> u32 {
        self.cwnd
    }

    fn ssthresh(&self) -> u32 {
        self.ssthresh
    }
}

/// Whether an ACK arriving with `flight` bytes outstanding may grow cwnd:
/// only when the window was in use (RFC 7661 §4.3). In slow start, where
/// cwnd doubles each round trip, a flight of over half of it counts, as in
/// Linux's `tcp_is_cwnd_limited`; beyond that, less than a segment of room
/// must have been left.
fn cwnd_limited(cwnd: u32, ssthresh: u32, mss: u32, flight: u32) -> bool {
    if cwnd < ssthresh {
        cwnd < flight.saturating_mul(2)
    } else {
        flight.saturating_add(mss) > cwnd
    }
}

// --- HighSpeed TCP (RFC 3649) ----------------------------------------------

const HS_LOW_WINDOW: u32 = 38; // segments
const HS_HIGH_WINDOW: f64 = 83000.0; // segments
const HS_HIGH_DECREASE: f64 = 0.1;

/// HighSpeed TCP — RFC 3649. Identical to NewReno below `Low_Window`, more
/// aggressive increase / less aggressive decrease above it.
#[derive(Debug)]
pub struct HighSpeed {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    /// Growth earned in congestion avoidance and not yet applied, in
    /// bytes: a(w) segments per window of bytes acknowledged, a fraction
    /// of a byte at a time.
    ca_credit: f64,
}

impl HighSpeed {
    /// A controller for segments of `mss` bytes, starting from RFC 6928's
    /// initial window.
    pub fn new(mss: u32) -> Self {
        Self {
            cwnd: initial_window(mss),
            ssthresh: u32::MAX,
            mss,
            ca_credit: 0.0,
        }
    }

    fn b(w: u32) -> f64 {
        if w <= HS_LOW_WINDOW {
            return 0.5;
        }
        let log_w = (w as f64).ln();
        let log_low = (HS_LOW_WINDOW as f64).ln();
        let log_high = HS_HIGH_WINDOW.ln();
        // RFC 3649 §5 interpolates between Low_Window and High_Window;
        // past High_Window the extrapolation would fall below High_Decrease
        // and, far enough out, go negative, growing cwnd on a loss.
        let b = (HS_HIGH_DECREASE - 0.5) * (log_w - log_low) / (log_high - log_low) + 0.5;
        b.clamp(HS_HIGH_DECREASE, 0.5)
    }

    /// ssthresh after a loss: RFC 3649's `(1 - b(w)) * w`, with b taken at
    /// the current cwnd, applied to the flight rather than to a cwnd that
    /// may not have been in use (as RFC 5681 does for NewReno).
    fn decreased(&self, flight_size: u32) -> u32 {
        let b = Self::b(self.cwnd / self.mss);
        ((flight_size as f64 * (1.0 - b)) as u32).max(2 * self.mss)
    }

    fn a(w: u32) -> f64 {
        if w <= HS_LOW_WINDOW {
            return 1.0;
        }
        let bw = Self::b(w);
        let p = 0.078 / (w as f64).powf(1.2);
        let wf = w as f64;
        wf * wf * p * 2.0 * bw / (2.0 - bw)
    }
}

impl CongestionController for HighSpeed {
    fn set_mss(&mut self, mss: u32) {
        self.mss = mss.max(1);
    }

    fn on_ack(&mut self, bytes_acked: u32, flight_size: u32) {
        if !cwnd_limited(self.cwnd, self.ssthresh, self.mss, flight_size) {
            return;
        }
        if self.cwnd < self.ssthresh {
            self.cwnd = self
                .cwnd
                .saturating_add(slow_start_inc(bytes_acked, self.mss));
        } else {
            // a(w) segments per window of bytes acknowledged (RFC 3649 §5,
            // counted in bytes as RFC 3465 §2.1 does).
            let a = Self::a(self.cwnd / self.mss);
            self.ca_credit +=
                a * self.mss as f64 * f64::from(bytes_acked) / f64::from(self.cwnd.max(1));
            let inc = self.ca_credit.floor();
            self.ca_credit -= inc;
            self.cwnd = self
                .cwnd
                .saturating_add(inc.min(f64::from(u32::MAX)) as u32);
        }
    }

    fn on_loss(&mut self, flight_size: u32) {
        self.ssthresh = self.decreased(flight_size);
        self.ca_credit = 0.0;
    }

    fn on_retransmit_timeout(&mut self, flight_size: u32, repeated: bool) {
        if !repeated {
            self.on_loss(flight_size);
        }
        self.cwnd = self.mss;
        self.ca_credit = 0.0;
    }

    fn set_cwnd(&mut self, cwnd: u32) {
        self.cwnd = cwnd.max(self.mss);
    }

    fn undo(&mut self, cwnd: u32, ssthresh: u32) {
        self.cwnd = cwnd.max(self.mss);
        self.ssthresh = ssthresh;
        self.ca_credit = 0.0;
    }

    fn cwnd(&self) -> u32 {
        self.cwnd
    }

    fn ssthresh(&self) -> u32 {
        self.ssthresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn both(mss: u32) -> [Box<dyn CongestionController>; 2] {
        [Box::new(NewReno::new(mss)), Box::new(HighSpeed::new(mss))]
    }

    #[test]
    fn slow_start_grows_per_ack() {
        let mut nr = NewReno::new(1460);
        let initial = nr.cwnd();
        nr.on_ack(1460, u32::MAX);
        assert!(nr.cwnd() > initial);
    }

    #[test]
    fn timeout_collapses_cwnd_to_one_mss() {
        for mut cc in both(1460) {
            cc.on_retransmit_timeout(30_000, false);
            assert_eq!(cc.cwnd(), 1460);
            assert_eq!(cc.ssthresh(), 15_000);
        }
    }

    #[test]
    fn loss_sets_ssthresh_and_undo_restores() {
        for mut cc in both(1000) {
            cc.set_cwnd(30_000);
            cc.on_loss(30_000);
            assert_eq!(cc.ssthresh(), 15_000);
            assert_eq!(cc.cwnd(), 30_000, "cwnd is the connection's to bring down");
            cc.set_cwnd(cc.ssthresh());
            cc.undo(25_000, u32::MAX);
            assert_eq!((cc.cwnd(), cc.ssthresh()), (25_000, u32::MAX));
        }
    }

    #[test]
    fn highspeed_decrease_is_clamped_past_high_window() {
        assert_eq!(HighSpeed::b(83_000), HS_HIGH_DECREASE);
        assert_eq!(HighSpeed::b(1_000_000), HS_HIGH_DECREASE);
        let mss = 1000;
        let mut hs = HighSpeed::new(mss);
        hs.cwnd = 4_000_000_000;
        hs.on_loss(hs.cwnd);
        assert_eq!(hs.ssthresh(), 3_600_000_000);
    }

    // RFC 5681 eq. (4): ssthresh is half the flight, not half of cwnd.
    #[test]
    fn loss_halves_the_flight_not_cwnd() {
        let mss = 1000;
        let mut nr = NewReno::new(mss);
        nr.cwnd = 100 * mss;
        nr.on_retransmit_timeout(20 * mss, false);
        assert_eq!(nr.ssthresh(), 10 * mss);
        // A second timeout of the same segment keeps it.
        nr.on_retransmit_timeout(20 * mss, true);
        assert_eq!(nr.ssthresh(), 10 * mss);

        let mut hs = HighSpeed::new(mss);
        hs.cwnd = 30 * mss;
        hs.on_loss(20 * mss);
        assert_eq!(hs.ssthresh(), 10 * mss);
        let mut hs = HighSpeed::new(mss);
        hs.cwnd = 30 * mss;
        hs.on_retransmit_timeout(20 * mss, false);
        assert_eq!(hs.ssthresh(), 10 * mss);
    }

    // An application-limited flow does not grow cwnd (RFC 7661).
    #[test]
    fn cwnd_grows_only_when_in_use() {
        let mss = 1000;
        for mut cc in both(mss) {
            let initial = cc.cwnd();
            for _ in 0..100 {
                cc.on_ack(mss, 2 * mss);
            }
            assert_eq!(cc.cwnd(), initial);
            cc.on_ack(mss, initial);
            assert_eq!(cc.cwnd(), initial + mss);
        }
    }

    /// Against a receiver that ACKs every other segment, slow start still
    /// doubles the window per round trip, and congestion avoidance still
    /// adds a segment per round trip (RFC 3465).
    #[test]
    fn byte_counting_keeps_growth_with_delayed_acks() {
        let mss = 1000;
        for mut cc in both(mss) {
            let w = cc.cwnd();
            for _ in 0..w / (2 * mss) {
                cc.on_ack(2 * mss, w);
            }
            assert_eq!(cc.cwnd(), 2 * w);
            // A stretch ACK counts for two segments at most.
            cc.on_ack(10 * mss, u32::MAX);
            assert_eq!(cc.cwnd(), 2 * w + 2 * mss);
        }

        let mut nr = NewReno::new(mss);
        nr.on_loss(40 * mss);
        nr.set_cwnd(nr.ssthresh());
        let w = nr.cwnd();
        assert_eq!(w, 20 * mss);
        for _ in 0..w / (2 * mss) {
            nr.on_ack(2 * mss, w);
        }
        assert_eq!(nr.cwnd(), w + mss);
    }

    #[test]
    fn highspeed_matches_newreno_below_low_window() {
        let mss = 1460;
        let mut nr = NewReno::new(mss);
        let mut hs = HighSpeed::new(mss);
        for _ in 0..5 {
            nr.on_ack(mss, u32::MAX);
            hs.on_ack(mss, u32::MAX);
        }
        assert_eq!(nr.cwnd(), hs.cwnd());
    }
}
