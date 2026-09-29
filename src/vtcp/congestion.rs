//! Congestion control: CUBIC (RFC 9438, in [`super::cubic`]), NewReno (RFC
//! 5681), HighSpeed TCP (RFC 3649) and BBR (draft-ietf-ccwg-bbr, in
//! [`super::bbr`]).
//!
//! All count bytes, not ACKs (RFC 3465): a receiver that delays its ACKs
//! acknowledges two segments with each, and counting ACKs would halve the
//! window's growth, in slow start and in congestion avoidance alike. Slow
//! start takes up to L = 2*SMSS per ACK (RFC 3465 §2.2), enough to double
//! the window per round trip against a delayed-ACK receiver without
//! letting one stretch ACK burst the window open; CUBIC's HyStart++ takes
//! RFC 9406's L = 8, or no limit when paced.

use super::info::HyStartPhase;
use super::rate::{RateSample, TxState};
use crate::time::Instant;
use std::time::Duration;

/// What a cumulative ACK outside fast recovery tells the controller.
#[derive(Debug, Clone, Copy)]
pub struct Ack {
    /// When it arrived.
    pub now: Instant,
    /// Bytes newly delivered.
    pub bytes_acked: u32,
    /// Bytes outstanding before it, or the most the current window of
    /// data had out if more, or cwnd if cwnd held data back in it (as
    /// Linux's tcp_is_cwnd_limited judges): how much of cwnd is in use. A
    /// flight well short of the window means the sender was limited by the
    /// application or the receiver, not by cwnd, and growing cwnd then
    /// would validate nothing (RFC 7661 §4.4, RFC 5681 §3.1).
    pub flight: u32,
    /// The round trip it measured, if it measured one.
    pub rtt: Option<Duration>,
    /// The cumulative ACK, and SND.NXT as it arrived: a round of slow
    /// start (RFC 9406 §4.2) ends once what was sent by its start is
    /// acknowledged.
    pub ack: u32,
    pub snd_nxt: u32,
    /// Its delivery rate sample, if it delivered anything.
    pub rs: Option<RateSample>,
    /// Bytes it delivered, cumulatively or selectively (RFC 6937's
    /// DeliveredData, the BBR draft's RS.newly_acked).
    pub newly_acked: u32,
    /// Bytes marked lost while processing it.
    pub newly_lost: u32,
    /// Bytes in flight once it was processed.
    pub inflight: u32,
    /// Bytes delivered over the connection's life (C.delivered).
    pub delivered: u64,
    /// The round trip of the most recently sent segment it delivered.
    pub newest_rtt: Option<Duration>,
    /// Since the last ACK, cwnd held back data that was ready to go.
    pub cwnd_limited: bool,
    /// The peer SACKs: losses show up several per round trip.
    pub sack: bool,
    /// ECN feedback is in use (RFC 3168 or RFC 9768).
    pub ecn: bool,
    /// ECN feedback on it reports CE marks: congestion, without loss.
    pub ce: bool,
    /// Bytes delivered CE-marked over the connection's life
    /// (C.delivered_ce).
    pub delivered_ce: u64,
}

/// A segment just marked lost: what it was sent with, its size, and the
/// connection's totals at the time (for BBR's HandleLostPacket).
#[derive(Debug, Clone, Copy)]
pub struct Lost {
    pub tx: TxState,
    pub len: u32,
    /// Bytes marked lost over the connection's life, this one included.
    pub total_lost: u64,
    /// Bytes delivered over the connection's life.
    pub delivered: u64,
}

impl Ack {
    /// An ACK of `bytes_acked` bytes with `flight` outstanding, at `now`,
    /// that measured no round trip.
    #[cfg(test)]
    pub fn of(now: Instant, bytes_acked: u32, flight: u32) -> Self {
        Self {
            now,
            bytes_acked,
            flight,
            rtt: None,
            ack: 0,
            snd_nxt: 0,
            rs: None,
            newly_acked: bytes_acked,
            newly_lost: 0,
            inflight: flight.saturating_sub(bytes_acked),
            delivered: 0,
            newest_rtt: None,
            cwnd_limited: false,
            sack: true,
            ecn: false,
            ce: false,
            delivered_ce: 0,
        }
    }
}

/// Pluggable congestion control: the window, and how it grows and shrinks.
///
/// Loss recovery is the connection's: it detects losses (RACK, or
/// duplicate ACKs without SACK), decides when a recovery episode starts
/// and ends, paces the window down to ssthresh during it (RFC 6937), and
/// undoes a response found spurious. The controller only says how much to
/// cut and how fast to grow back.
///
/// A [model-based](Self::model_based) controller (BBR) instead sets cwnd
/// and the pacing rate itself on every ACK, recovery included, from its
/// model of the path: the connection then leaves PRR and ssthresh out.
pub trait CongestionController: Send {
    /// A cumulative ACK outside fast recovery; for a model-based
    /// controller, every ACK.
    fn on_ack(&mut self, ack: &Ack);
    /// Whether the controller runs on every ACK and sets cwnd itself in
    /// and out of recovery, and paces at a rate of its own (BBR).
    fn model_based(&self) -> bool {
        false
    }
    /// A segment was marked lost. Only a model-based controller is told.
    fn on_lost(&mut self, lost: &Lost) {
        let _ = lost;
    }
    /// A recovery episode (fast recovery or after a timeout) is over, all
    /// its losses repaired. Only a model-based controller is told; for the
    /// others the connection sets cwnd to ssthresh.
    fn on_recovery_exit(&mut self) {}
    /// About to send with nothing in flight after the application ran dry
    /// (`idle`), or otherwise. Only a model-based controller is told.
    fn on_transmit(&mut self, now: Instant, idle: bool) {
        let _ = (now, idle);
    }
    /// The controller wants the samples until what is in flight is
    /// delivered marked application-limited (BBR's ProbeRTT). Taken once.
    fn take_app_limited(&mut self) -> bool {
        false
    }
    /// The rate to pace at, in bytes per second, if the controller sets
    /// one; otherwise the connection derives it from cwnd and SRTT.
    fn pacing_rate(&self) -> Option<u64> {
        None
    }
    /// Sending is paced: slow start need not limit the growth per ACK
    /// against bursts (RFC 9406 §4.3's L).
    fn set_paced(&mut self, paced: bool) {
        let _ = paced;
    }
    /// The controller as BBR, for tests to look inside.
    #[cfg(test)]
    fn as_bbr(&self) -> Option<&super::bbr::Bbr> {
        None
    }
    /// A loss was detected with `flight_size` bytes outstanding: set
    /// ssthresh. The connection then brings cwnd down to it.
    fn on_loss(&mut self, flight_size: u32);
    /// ECN feedback reported CE marks with `flight_size` bytes
    /// outstanding: set ssthresh, as for a loss (RFC 3168 §6.1.2) unless
    /// the controller answers marks otherwise. Only a controller that is
    /// not model-based is told.
    fn on_ecn(&mut self, flight_size: u32) {
        self.on_loss(flight_size);
    }
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
    /// A loss episode begins that may later be found spurious: keep what
    /// [`undo`](Self::undo) would put back of the growth state. The
    /// default keeps nothing.
    fn save_undo(&mut self) {}
    /// A loss response turned out spurious: go back to `cwnd` and
    /// `ssthresh`, and to the growth state before the episode where the
    /// controller keeps one.
    fn undo(&mut self, cwnd: u32, ssthresh: u32);
    /// The window was cut for disuse, not congestion: after an idle spell
    /// (RFC 5681 §4.1) or a long application-limited one (RFC 7661
    /// §4.4.3). Growth starts afresh from `cwnd`.
    fn restart(&mut self, cwnd: u32, ssthresh: u32);
    /// The congestion window, in bytes.
    fn cwnd(&self) -> u32;
    /// The slow-start threshold, in bytes; `u32::MAX` until the first loss.
    fn ssthresh(&self) -> u32;
    /// The controller's name, as Linux's `tcp_congestion_ops` has it.
    fn name(&self) -> &'static str;
    /// Where HyStart++ stands, and how many times it has entered
    /// Conservative Slow Start, for a controller that runs it.
    fn hystart(&self) -> Option<(HyStartPhase, u32)> {
        None
    }
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
pub(crate) fn slow_start_inc(bytes_acked: u32, mss: u32) -> u32 {
    bytes_acked.min(mss.saturating_mul(2))
}

impl CongestionController for NewReno {
    fn name(&self) -> &'static str {
        "reno"
    }

    fn set_mss(&mut self, mss: u32) {
        self.mss = mss.max(1);
    }

    fn on_ack(&mut self, a: &Ack) {
        let bytes_acked = a.bytes_acked;
        if !cwnd_limited(self.cwnd, self.ssthresh, self.mss, a.flight) {
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

    /// RFC 8511 (ABE): marks in congestion avoidance cut to 0.8 of the
    /// flight, not half; in slow start, half.
    fn on_ecn(&mut self, flight_size: u32) {
        if self.cwnd < self.ssthresh {
            return self.on_loss(flight_size);
        }
        self.ssthresh = ((u64::from(flight_size) * 4 / 5) as u32).max(2 * self.mss);
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

    fn restart(&mut self, cwnd: u32, ssthresh: u32) {
        self.undo(cwnd, ssthresh);
    }

    fn cwnd(&self) -> u32 {
        self.cwnd
    }

    fn ssthresh(&self) -> u32 {
        self.ssthresh
    }
}

/// Whether an ACK arriving with `flight` bytes outstanding may grow cwnd:
/// only when the window was in use (RFC 7661 §4.4). In slow start, where
/// cwnd doubles each round trip, a flight of over half of it counts, as in
/// Linux's `tcp_is_cwnd_limited`; beyond that, less than a segment of room
/// must have been left.
pub(crate) fn cwnd_limited(cwnd: u32, ssthresh: u32, mss: u32, flight: u32) -> bool {
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
    fn name(&self) -> &'static str {
        "highspeed"
    }

    fn set_mss(&mut self, mss: u32) {
        self.mss = mss.max(1);
    }

    fn on_ack(&mut self, ack: &Ack) {
        let bytes_acked = ack.bytes_acked;
        if !cwnd_limited(self.cwnd, self.ssthresh, self.mss, ack.flight) {
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

    fn restart(&mut self, cwnd: u32, ssthresh: u32) {
        self.undo(cwnd, ssthresh);
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
        nr.on_ack(&Ack::of(Instant::now(), 1460, u32::MAX));
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
                cc.on_ack(&Ack::of(Instant::now(), mss, 2 * mss));
            }
            assert_eq!(cc.cwnd(), initial);
            cc.on_ack(&Ack::of(Instant::now(), mss, initial));
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
                cc.on_ack(&Ack::of(Instant::now(), 2 * mss, w));
            }
            assert_eq!(cc.cwnd(), 2 * w);
            // A stretch ACK counts for two segments at most.
            cc.on_ack(&Ack::of(Instant::now(), 10 * mss, u32::MAX));
            assert_eq!(cc.cwnd(), 2 * w + 2 * mss);
        }

        let mut nr = NewReno::new(mss);
        nr.on_loss(40 * mss);
        nr.set_cwnd(nr.ssthresh());
        let w = nr.cwnd();
        assert_eq!(w, 20 * mss);
        for _ in 0..w / (2 * mss) {
            nr.on_ack(&Ack::of(Instant::now(), 2 * mss, w));
        }
        assert_eq!(nr.cwnd(), w + mss);
    }

    #[test]
    fn highspeed_matches_newreno_below_low_window() {
        let mss = 1460;
        let mut nr = NewReno::new(mss);
        let mut hs = HighSpeed::new(mss);
        for _ in 0..5 {
            nr.on_ack(&Ack::of(Instant::now(), mss, u32::MAX));
            hs.on_ack(&Ack::of(Instant::now(), mss, u32::MAX));
        }
        assert_eq!(nr.cwnd(), hs.cwnd());
    }
}
