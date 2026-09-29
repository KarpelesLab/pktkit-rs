//! CUBIC (RFC 9438), with HyStart++ (RFC 9406) for its first slow start.
//!
//! After a loss CUBIC grows the window along a cubic curve of the time
//! since the cut rather than a segment per round trip: fast while far
//! below the window where the loss happened (W_max), flat around it, then
//! faster again as it probes past it. Growth so measured in time does not
//! slow with the round trip, which is what lets it fill a long, fat pipe
//! that Reno takes minutes to regrow, while the Reno-friendly region keeps
//! it no slower than Reno where Reno does well (short round trips, small
//! windows).
//!
//! Where the RFC leaves a choice Linux's `tcp_cubic.c` is followed: the
//! curve is read one minimum RTT ahead (its `delay_min`, where RFC 9438
//! §4.2 has SRTT, which queueing inflates), fast convergence is on, and
//! the time the sender spends application-limited is left out of the
//! curve's clock (RFC 9438 §5.8; Linux shifts the epoch after an idle
//! spell, this does so for any ACK that finds the window not in use).
//!
//! Windows are kept in bytes: C is in segments per second cubed, so the
//! curve scales by the MSS.

use super::congestion::{Ack, CongestionController, cwnd_limited, initial_window};
use super::info::HyStartPhase;
use super::seqspace::seq_after_eq;
use crate::time::Instant;
use std::time::Duration;

/// C, in segments per second cubed (RFC 9438 §5).
const C: f64 = 0.4;
/// β_cubic (RFC 9438 §4.6).
const BETA: f64 = 0.7;
/// β_ecn (RFC 8511, ABE): the cut for ECN marks in congestion avoidance.
/// A queue that marks early is short, and a cut by β_cubic from its
/// threshold would leave the link idle for seconds; RFC 8511 found 0.85
/// best for CUBIC. FreeBSD offers it; Linux cuts by β_cubic.
const BETA_ECN: f64 = 0.85;
/// α_cubic = 3(1 − β)/(1 + β) (RFC 9438 §4.3): the Reno-friendly
/// estimate's additive increase, for the same average window as Reno's
/// AIMD(1, 0.5).
const ALPHA: f64 = 3.0 * (1.0 - BETA) / (1.0 + BETA);
/// Fast convergence (RFC 9438 §4.7). The RFC would have it off for a flow
/// alone on its path, which a sender cannot know; Linux has it on.
const FAST_CONVERGENCE: bool = true;
/// Slow start's L (RFC 9406 §4.3), for a sender that does not pace. One
/// that does has none: pacing, not the ACK, spreads out what cwnd lets go.
const SS_LIMIT: u32 = 8;

// HyStart++'s constants (RFC 9406 §4.3).
const MIN_RTT_THRESH: Duration = Duration::from_millis(4);
const MAX_RTT_THRESH: Duration = Duration::from_millis(16);
const MIN_RTT_DIVISOR: u32 = 8;
const N_RTT_SAMPLE: u32 = 8;
const CSS_GROWTH_DIVISOR: u32 = 4;
const CSS_ROUNDS: u32 = 5;

/// A congestion avoidance stage: the curve it follows.
#[derive(Debug, Clone, Copy)]
struct Epoch {
    /// t_epoch, moved on by the time spent application-limited.
    start: Instant,
    /// K, in seconds.
    k: f64,
    /// The curve's plateau, in bytes: W_max, or cwnd_epoch when W_max is
    /// undefined or below it.
    origin: f64,
    /// W_est, the window Reno would have (RFC 9438 §4.3), in bytes.
    w_est: f64,
}

/// What undoing a spurious loss response puts back (RFC 9438 §4.9.2).
#[derive(Debug, Clone, Copy)]
struct Saved {
    w_max: Option<f64>,
    cwnd_prior: f64,
    epoch: Option<Epoch>,
    hystart: HyStart,
}

/// CUBIC congestion control (RFC 9438).
#[derive(Debug)]
pub struct Cubic {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    /// W_max in bytes; `None` until the first congestion event, and again
    /// after a timeout (RFC 9438 §4.8, §4.10).
    w_max: Option<f64>,
    /// cwnd_prior, in bytes: cwnd when ssthresh was last set.
    cwnd_prior: f64,
    epoch: Option<Epoch>,
    /// Growth earned and not yet applied, in bytes.
    credit: f64,
    /// The least round trip seen, which the curve is read ahead by.
    delay_min: Option<Duration>,
    /// When the last ACK came, for leaving application-limited time out of
    /// the curve's clock.
    last_ack: Option<Instant>,
    hystart: HyStart,
    saved: Option<Saved>,
    /// Sending is paced (see [`SS_LIMIT`]).
    paced: bool,
    /// Times HyStart++ entered Conservative Slow Start, for `TcpInfo`.
    css_entries: u32,
}

impl Cubic {
    /// A controller for segments of `mss` bytes, starting from RFC 6928's
    /// initial window.
    pub fn new(mss: u32) -> Self {
        Self {
            cwnd: initial_window(mss),
            ssthresh: u32::MAX,
            mss: mss.max(1),
            w_max: None,
            cwnd_prior: 0.0,
            epoch: None,
            credit: 0.0,
            delay_min: None,
            last_ack: None,
            hystart: HyStart::new(),
            saved: None,
            paced: false,
            css_entries: 0,
        }
    }

    /// C, scaled to bytes per second cubed.
    fn c(&self) -> f64 {
        C * f64::from(self.mss)
    }

    /// W_cubic(t), in bytes (RFC 9438 Figure 1).
    fn w_cubic(&self, e: &Epoch, t: f64) -> f64 {
        let d = t - e.k;
        self.c() * d * d * d + e.origin
    }

    /// Start a congestion avoidance stage (RFC 9438 §4.2, and §4.8 and
    /// §4.10 for an undefined W_max).
    fn begin_epoch(&mut self, now: Instant) -> Epoch {
        let w = f64::from(self.cwnd);
        let (k, origin) = match self.w_max {
            Some(w_max) if w_max > w => (((w_max - w) / self.c()).cbrt(), w_max),
            Some(_) => (0.0, w),
            None => {
                self.w_max = Some(w);
                self.cwnd_prior = w;
                (0.0, w)
            }
        };
        Epoch {
            start: now,
            k,
            origin,
            w_est: w,
        }
    }

    /// Congestion avoidance's growth for an ACK (RFC 9438 §4.2 to §4.5).
    fn avoid_congestion(&mut self, a: &Ack) {
        let now = a.now;
        let mut e = match self.epoch {
            Some(e) => e,
            None => self.begin_epoch(now),
        };
        let w = f64::from(self.cwnd);
        let acked = f64::from(a.bytes_acked);
        let t = now.saturating_duration_since(e.start).as_secs_f64();
        let rtt = self.delay_min.unwrap_or_default().as_secs_f64();

        // W_est grows by α_cubic segments per window acknowledged, and as
        // Reno's once past the window before the cut (§4.3).
        let alpha = if e.w_est >= self.cwnd_prior {
            1.0
        } else {
            ALPHA
        };
        e.w_est += alpha * f64::from(self.mss) * acked / w;
        self.epoch = Some(e);

        if self.w_cubic(&e, t) < e.w_est {
            // The Reno-friendly region.
            self.credit += (e.w_est - w).max(0.0);
        } else {
            // Concave or convex: (target − cwnd)/cwnd per segment
            // acknowledged, target never more than 1.5 cwnd (§4.4, §4.5).
            let target = self.w_cubic(&e, t + rtt).clamp(w, 1.5 * w);
            self.credit += (target - w) * acked / w;
        }
        if self.credit >= 1.0 {
            let inc = self.credit.floor();
            self.credit -= inc;
            self.cwnd = self
                .cwnd
                .saturating_add(inc.min(f64::from(u32::MAX)) as u32);
        }
    }

    /// The multiplicative decrease's ssthresh for a flight of `flight`
    /// bytes (RFC 9438 Figure 5).
    fn decreased(&self, flight: u32) -> u32 {
        self.decreased_by(flight, BETA)
    }

    fn decreased_by(&self, flight: u32, beta: f64) -> u32 {
        ((f64::from(flight) * beta) as u32).max(2 * self.mss)
    }

    /// A congestion event with `flight` bytes out: a cut by `beta`.
    fn reduce(&mut self, flight: u32, beta: f64) {
        let w = f64::from(self.cwnd);
        // Fast convergence (§4.7): a flow losing below its last W_max
        // leaves room for newcomers by aiming lower.
        self.w_max = Some(match self.w_max {
            Some(m) if FAST_CONVERGENCE && w < m => w * (1.0 + beta) / 2.0,
            _ => w,
        });
        self.cwnd_prior = w;
        self.ssthresh = self.decreased_by(flight, beta);
        self.epoch = None;
        self.credit = 0.0;
        self.hystart.finish();
    }
}

impl CongestionController for Cubic {
    fn name(&self) -> &'static str {
        "cubic"
    }

    fn hystart(&self) -> Option<(HyStartPhase, u32)> {
        let phase = match self.hystart.phase {
            Phase::SlowStart => HyStartPhase::SlowStart,
            Phase::Css { .. } => HyStartPhase::Conservative,
            Phase::Done => HyStartPhase::Done,
        };
        Some((phase, self.css_entries))
    }

    fn set_mss(&mut self, mss: u32) {
        self.mss = mss.max(1);
    }

    fn set_paced(&mut self, paced: bool) {
        self.paced = paced;
    }

    fn on_ack(&mut self, a: &Ack) {
        if let Some(rtt) = ack_rtt(a) {
            self.delay_min = Some(self.delay_min.map_or(rtt, |m| m.min(rtt)));
        }
        let limited = cwnd_limited(self.cwnd, self.ssthresh, self.mss, a.flight);
        // Time spent not using the window does not move the curve on
        // (RFC 9438 §5.8), or a sender back from an idle spell would find
        // W_cubic(t) far above its window.
        if !limited && let (Some(e), Some(prev)) = (self.epoch.as_mut(), self.last_ack) {
            e.start = (e.start + a.now.saturating_duration_since(prev)).min(a.now);
        }
        self.last_ack = Some(a.now);

        if self.cwnd < self.ssthresh {
            let was_css = self.hystart.in_css();
            let (divisor, exit) = self.hystart.on_ack(a, self.ssthresh == u32::MAX);
            if !was_css && self.hystart.in_css() {
                self.css_entries += 1;
            }
            if limited {
                let limit = if self.paced {
                    u32::MAX
                } else {
                    SS_LIMIT.saturating_mul(self.mss)
                };
                let inc = a.bytes_acked.min(limit) / divisor;
                self.cwnd = self.cwnd.saturating_add(inc);
            }
            if exit {
                // Congestion avoidance from here, with no loss to have set
                // W_max (RFC 9406 §4.2, RFC 9438 §4.10).
                self.ssthresh = self.cwnd;
            }
            return;
        }
        if limited {
            self.avoid_congestion(a);
        }
    }

    fn on_loss(&mut self, flight_size: u32) {
        self.reduce(flight_size, BETA);
    }

    /// RFC 8511's β_ecn in congestion avoidance; in slow start, which a
    /// mark ends having overshot by up to a window, β_cubic (RFC 8511 §3).
    fn on_ecn(&mut self, flight_size: u32) {
        let beta = if self.cwnd < self.ssthresh {
            BETA
        } else {
            BETA_ECN
        };
        self.reduce(flight_size, beta);
    }

    fn on_retransmit_timeout(&mut self, flight_size: u32, repeated: bool) {
        if !repeated {
            self.cwnd_prior = f64::from(self.cwnd);
            self.ssthresh = self.decreased(flight_size);
        }
        // The first stage after a timeout starts its curve where it
        // stands, as after the first slow start (§4.8). Linux forgets the
        // minimum RTT too: the path may have changed under the timeout.
        self.w_max = None;
        self.epoch = None;
        self.credit = 0.0;
        self.delay_min = None;
        self.cwnd = self.mss;
        self.hystart.finish();
    }

    fn set_cwnd(&mut self, cwnd: u32) {
        self.cwnd = cwnd.max(self.mss);
    }

    fn save_undo(&mut self) {
        self.saved = Some(Saved {
            w_max: self.w_max,
            cwnd_prior: self.cwnd_prior,
            epoch: self.epoch,
            hystart: self.hystart,
        });
    }

    fn undo(&mut self, cwnd: u32, ssthresh: u32) {
        // RFC 9438 §4.9.2: the curve before the cut, unless the window has
        // grown back past it already. Linux keeps the cut W_max and starts
        // a new epoch; putting the curve back is what makes the spurious
        // loss cost nothing.
        if let Some(s) = self.saved.take()
            && f64::from(self.cwnd) < s.cwnd_prior
        {
            self.w_max = s.w_max;
            self.cwnd_prior = s.cwnd_prior;
            self.epoch = s.epoch;
            self.hystart = s.hystart;
        }
        self.cwnd = cwnd.max(self.mss);
        self.ssthresh = ssthresh;
        self.credit = 0.0;
    }

    fn restart(&mut self, cwnd: u32, ssthresh: u32) {
        self.cwnd = cwnd.max(self.mss);
        self.ssthresh = ssthresh;
        self.epoch = None;
        self.credit = 0.0;
    }

    fn cwnd(&self) -> u32 {
        self.cwnd
    }

    fn ssthresh(&self) -> u32 {
        self.ssthresh
    }
}

/// The round trip an ACK measured, for the minimum RTT and HyStart++: the
/// time since the newest segment it delivered was sent, as Linux feeds
/// both. The RTO's sample (`a.rtt`) is Karn's one timed segment per round
/// trip without timestamps, too few for HyStart++'s N_RTT_SAMPLE a round.
fn ack_rtt(a: &Ack) -> Option<Duration> {
    a.newest_rtt.or(a.rtt).filter(|r| !r.is_zero())
}

// --- HyStart++ (RFC 9406) --------------------------------------------------

/// Where HyStart++ stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Standard slow start.
    SlowStart,
    /// Conservative Slow Start: the round trip rose. `baseline` is the
    /// round's minimum RTT that showed it, `rounds` how many rounds have
    /// ended since.
    Css { baseline: Duration, rounds: u32 },
    /// Out of slow start, or not in the first one.
    Done,
}

/// HyStart++ (RFC 9406): leave the first slow start when the round trip
/// starts to rise, the queue at the bottleneck filling, rather than when
/// it overflows. Standard slow start doubles the window per round trip
/// until a loss, which on a path with a large buffer means losing up to a
/// window's worth; HyStart++ turns to Conservative Slow Start (a quarter
/// of the growth) when a round's minimum RTT exceeds the last round's by
/// an eighth (4 to 16 ms), and to congestion avoidance if the rise holds
/// for CSS_ROUNDS rounds. A rise that goes away was jitter, and slow start
/// resumes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HyStart {
    phase: Phase,
    /// windowEnd: the round ends once this is acknowledged.
    window_end: Option<u32>,
    last_round_min: Option<Duration>,
    round_min: Option<Duration>,
    samples: u32,
}

impl HyStart {
    pub(crate) fn new() -> Self {
        Self {
            phase: Phase::SlowStart,
            window_end: None,
            last_round_min: None,
            round_min: None,
            samples: 0,
        }
    }

    /// Take an ACK in slow start. `initial` while ssthresh is still at its
    /// initial infinity: only the first slow start runs HyStart++ (RFC
    /// 9406 §4.3); later ones have ssthresh to stop them. Returns what to
    /// divide the growth by, and whether slow start ends here.
    pub(crate) fn on_ack(&mut self, a: &Ack, initial: bool) -> (u32, bool) {
        if !initial {
            self.phase = Phase::Done;
        }
        if self.phase == Phase::Done {
            return (1, false);
        }
        match self.window_end {
            None => self.window_end = Some(a.snd_nxt),
            Some(end) if seq_after_eq(a.ack, end) => {
                self.window_end = Some(a.snd_nxt);
                self.last_round_min = self.round_min;
                self.round_min = None;
                self.samples = 0;
                if let Phase::Css { baseline, rounds } = self.phase {
                    // A round begun in slow start and ended in CSS counts
                    // towards CSS_ROUNDS too.
                    let rounds = rounds + 1;
                    if rounds >= CSS_ROUNDS {
                        self.phase = Phase::Done;
                        return (CSS_GROWTH_DIVISOR, true);
                    }
                    self.phase = Phase::Css { baseline, rounds };
                }
            }
            Some(_) => {}
        }
        if let Some(rtt) = ack_rtt(a) {
            self.round_min = Some(self.round_min.map_or(rtt, |m| m.min(rtt)));
            self.samples += 1;
        }
        if self.samples < N_RTT_SAMPLE {
            return (self.divisor(), false);
        }
        let Some(cur) = self.round_min else {
            return (self.divisor(), false);
        };
        match self.phase {
            Phase::SlowStart => {
                if let Some(last) = self.last_round_min {
                    let thresh = (last / MIN_RTT_DIVISOR).clamp(MIN_RTT_THRESH, MAX_RTT_THRESH);
                    if cur >= last + thresh {
                        self.phase = Phase::Css {
                            baseline: cur,
                            rounds: 0,
                        };
                    }
                }
            }
            Phase::Css { baseline, .. } if cur < baseline => {
                // The rise was not the queue: back to slow start.
                self.phase = Phase::SlowStart;
            }
            _ => {}
        }
        (self.divisor(), false)
    }

    fn divisor(&self) -> u32 {
        match self.phase {
            Phase::Css { .. } => CSS_GROWTH_DIVISOR,
            _ => 1,
        }
    }

    /// Whether HyStart++ is over.
    #[cfg(test)]
    fn exited(&self) -> bool {
        self.phase == Phase::Done
    }

    /// A loss ends it (RFC 9406 §4.2).
    pub(crate) fn finish(&mut self) {
        self.phase = Phase::Done;
    }

    fn in_css(&self) -> bool {
        matches!(self.phase, Phase::Css { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: u32 = 1000;

    fn ack(now: Instant, bytes: u32, flight: u32) -> Ack {
        Ack::of(now, bytes, flight)
    }

    /// A CUBIC controller in congestion avoidance at `w` segments after a
    /// loss at `w_max` segments, with a minimum RTT of `rtt`.
    fn after_loss(w_max: u32, rtt: Duration) -> Cubic {
        let mut c = Cubic::new(MSS);
        c.cwnd = w_max * MSS;
        c.on_loss(w_max * MSS);
        c.set_cwnd(c.ssthresh());
        c.delay_min = Some(rtt);
        c
    }

    /// Run `c` for `secs` seconds of round trips of `rtt`, each ACKing its
    /// whole window two segments at a time, and return cwnd (segments)
    /// at the end of each round trip, and the time.
    fn trajectory(c: &mut Cubic, t0: Instant, rtt: Duration, rounds: u32) -> Vec<(f64, f64)> {
        let mut out = Vec::new();
        let mut now = t0;
        for _ in 0..rounds {
            let w = c.cwnd();
            let acks = (w / (2 * MSS)).max(1);
            for i in 0..acks {
                let at = now + rtt * (i + 1) / acks;
                c.on_ack(&ack(at, 2 * MSS, c.cwnd()));
            }
            now += rtt;
            out.push((
                now.duration_since(t0).as_secs_f64(),
                f64::from(c.cwnd()) / f64::from(MSS),
            ));
        }
        out
    }

    /// The window after a loss follows W_cubic(t) = C(t − K)³ + W_max with
    /// K = ∛(W_max(1 − β)/C): concave up to W_max, flat around it at K,
    /// convex past it.
    #[test]
    fn window_follows_the_cubic_curve() {
        let w_max = 1000.0;
        let rtt = Duration::from_millis(100);
        let mut c = after_loss(1000, rtt);
        assert_eq!(c.cwnd(), 700 * MSS, "β = 0.7");
        let k = (w_max * (1.0 - BETA) / C).cbrt();
        assert!((k - 9.086).abs() < 0.001, "K = {k}");
        let t0 = Instant::now();
        let traj = trajectory(&mut c, t0, rtt, 150);
        assert!((c.epoch.unwrap().k - k).abs() < 1e-9);
        for &(t, w) in &traj {
            // The curve, read one RTT ahead, reached by the end of the
            // round trip that started one RTT before t: W_cubic(t).
            let want = C * (t - k).powi(3) + w_max;
            let tol = 0.02 * want + 2.0;
            assert!(
                (w - want).abs() <= tol,
                "t={t:.1}: cwnd {w:.1} vs W_cubic {want:.1}"
            );
        }
        // Concave: growth slows towards K; convex: speeds up past it.
        let at = |secs: f64| traj.iter().find(|p| p.0 >= secs).unwrap().1;
        let (d1, d2) = (at(2.0) - at(1.0), at(8.0) - at(7.0));
        assert!(d1 > d2 && d2 >= 0.0, "concave: {d1} then {d2}");
        let (d3, d4) = (at(10.0) - at(9.0), at(14.0) - at(13.0));
        assert!(d4 > d3, "convex: {d3} then {d4}");
        assert!((at(k) - w_max).abs() < 0.02 * w_max, "at K: {}", at(k));
    }

    /// At a small window and a short round trip, Reno's additive increase
    /// outpaces the curve: the Reno-friendly region's W_est sets cwnd,
    /// with α_cubic = 3(1 − β)/(1 + β) segments per round trip.
    #[test]
    fn reno_friendly_region_takes_over_at_low_bdp() {
        let rtt = Duration::from_millis(1);
        let mut c = after_loss(20, rtt);
        let w0 = f64::from(c.cwnd()) / f64::from(MSS);
        let traj = trajectory(&mut c, Instant::now(), rtt, 100);
        let (t, w) = *traj.last().unwrap();
        // 100 round trips of 1 ms: the curve alone is still at 14 + 2.
        let e = c.epoch.unwrap();
        let w_cubic = C * (t - e.k).powi(3) + 20.0;
        assert!(w_cubic < 15.0);
        // W_est: α_cubic per round trip until it passes cwnd_prior (20),
        // then 1 per round trip.
        let to_prior = (20.0 - w0) / ALPHA;
        let want = 20.0 + (100.0 - to_prior);
        assert!(
            (w - want).abs() < 0.05 * want,
            "cwnd {w:.1}, Reno-friendly {want:.1}"
        );
        assert!((w - e.w_est / f64::from(MSS)).abs() < 1.0, "cwnd is W_est");
        const { assert!(ALPHA > 0.52 && ALPHA < 0.53) };
    }

    /// Loss cuts to 0.7 of the flight; losing again below W_max lowers
    /// W_max further (fast convergence).
    #[test]
    fn multiplicative_decrease_and_fast_convergence() {
        let mut c = Cubic::new(MSS);
        c.cwnd = 100 * MSS;
        c.on_loss(100 * MSS);
        assert_eq!(c.ssthresh(), 70 * MSS);
        assert_eq!(c.w_max, Some(100_000.0));
        c.set_cwnd(80 * MSS);
        c.on_loss(80 * MSS);
        assert_eq!(c.ssthresh(), 56 * MSS);
        assert_eq!(c.w_max, Some(80_000.0 * 0.85));
        // A loss above W_max takes W_max from it.
        c.set_cwnd(90 * MSS);
        c.on_loss(90 * MSS);
        assert_eq!(c.w_max, Some(90_000.0));
        // Never below two segments.
        c.on_loss(MSS);
        assert_eq!(c.ssthresh(), 2 * MSS);
    }

    /// A timeout: one segment, ssthresh at β of the flight, and the next
    /// congestion avoidance starts its curve at its own window (K = 0).
    /// ECN marks cut by β_ecn = 0.85 in congestion avoidance (RFC 8511),
    /// by β_cubic in slow start.
    #[test]
    fn ecn_marks_cut_less_in_congestion_avoidance() {
        let mut c = Cubic::new(MSS);
        c.cwnd = 100 * MSS;
        c.on_ecn(100 * MSS);
        assert_eq!(c.ssthresh(), 70 * MSS, "slow start");
        c.set_cwnd(c.ssthresh());
        c.on_ecn(70 * MSS);
        assert_eq!(c.ssthresh(), 59_500);
        // Fast convergence by β_ecn too: below W_max, aim at (1+β)/2 of it.
        assert_eq!(c.w_max, Some(70_000.0 * 1.85 / 2.0));

        let mut r = super::super::congestion::NewReno::new(MSS);
        r.set_cwnd(100 * MSS);
        r.on_ecn(100 * MSS);
        assert_eq!(r.ssthresh(), 50 * MSS, "slow start");
        r.set_cwnd(r.ssthresh());
        r.on_ecn(50 * MSS);
        assert_eq!(r.ssthresh(), 40 * MSS);
    }

    #[test]
    fn timeout_resets_w_max() {
        let mut c = after_loss(100, Duration::from_millis(10));
        c.on_retransmit_timeout(50 * MSS, false);
        assert_eq!((c.cwnd(), c.ssthresh()), (MSS, 35 * MSS));
        c.on_retransmit_timeout(50 * MSS, true);
        assert_eq!(c.ssthresh(), 35 * MSS, "a repeated timeout keeps it");
        c.set_cwnd(35 * MSS);
        c.on_ack(&ack(Instant::now(), MSS, 35 * MSS));
        let e = c.epoch.unwrap();
        assert_eq!(e.k, 0.0);
        assert_eq!(e.origin, 35_000.0);
    }

    /// Undoing a spurious loss puts the curve back where it was.
    #[test]
    fn undo_restores_the_curve() {
        let rtt = Duration::from_millis(50);
        let mut c = after_loss(200, rtt);
        let t0 = Instant::now();
        trajectory(&mut c, t0, rtt, 20);
        let (w_max, prior, epoch) = (c.w_max, c.cwnd_prior, c.epoch.unwrap());
        let (cwnd, ssthresh) = (c.cwnd(), c.ssthresh());
        c.save_undo();
        c.on_loss(cwnd);
        c.set_cwnd(c.ssthresh());
        assert_ne!(c.w_max, w_max);
        c.undo(cwnd, ssthresh);
        assert_eq!((c.cwnd(), c.ssthresh()), (cwnd, ssthresh));
        assert_eq!((c.w_max, c.cwnd_prior), (w_max, prior));
        let e = c.epoch.unwrap();
        assert_eq!(
            (e.start, e.k, e.origin),
            (epoch.start, epoch.k, epoch.origin)
        );

        // Grown back past cwnd_prior by the time it is found out: the
        // present curve stays.
        c.save_undo();
        c.on_loss(cwnd);
        let w_max = c.w_max;
        c.set_cwnd(4 * cwnd);
        c.undo(4 * cwnd, ssthresh);
        assert_eq!(c.w_max, w_max);
    }

    /// Congestion avoidance takes bytes acknowledged, not ACKs: with an
    /// ACK per two segments the window grows as with one per segment.
    #[test]
    fn growth_counts_bytes_with_delayed_acks() {
        let rtt = Duration::from_millis(20);
        let t0 = Instant::now();
        let mut per_seg = after_loss(100, rtt);
        let mut delayed = after_loss(100, rtt);
        let mut now = t0;
        for _ in 0..50 {
            let w = per_seg.cwnd();
            for i in 0..w / MSS {
                per_seg.on_ack(&ack(now + rtt * i / (w / MSS), MSS, per_seg.cwnd()));
            }
            let w = delayed.cwnd();
            for i in 0..w / (2 * MSS) {
                delayed.on_ack(&ack(
                    now + rtt * i / (w / (2 * MSS)),
                    2 * MSS,
                    delayed.cwnd(),
                ));
            }
            now += rtt;
        }
        let (a, b) = (per_seg.cwnd(), delayed.cwnd());
        assert!(a > 70 * MSS);
        assert!(a.abs_diff(b) <= 2 * MSS, "{a} vs {b}");
    }

    /// Time spent application-limited does not count on the curve.
    #[test]
    fn application_limited_time_is_left_out() {
        let rtt = Duration::from_millis(50);
        let mut c = after_loss(100, rtt);
        let t0 = Instant::now();
        c.on_ack(&ack(t0, MSS, c.cwnd()));
        let cwnd = c.cwnd();
        let start = c.epoch.unwrap().start;
        // Ten seconds of ACKs for a flight far short of the window.
        for i in 1..=100 {
            c.on_ack(&ack(t0 + Duration::from_millis(100 * i), MSS, 10 * MSS));
        }
        assert_eq!(c.cwnd(), cwnd, "no growth");
        let shifted = c.epoch.unwrap().start.duration_since(start);
        assert!(shifted >= Duration::from_millis(9_900), "{shifted:?}");
        // Back to a full window, it grows as if no time had passed.
        let t1 = t0 + Duration::from_secs(10);
        c.on_ack(&ack(t1 + rtt, 2 * MSS, c.cwnd()));
        assert!(c.cwnd() - cwnd < 5 * MSS, "jumped to {}", c.cwnd());
    }

    /// Drive HyStart++ through rounds of `per_round` ACKs, each round's
    /// ACKs measuring the RTT `rtt(round)`. Returns the controller.
    fn slow_start(rounds: u32, per_round: u32, rtt: impl Fn(u32) -> Duration) -> (Cubic, Vec<u32>) {
        slow_start_timed(rounds, per_round, rtt, true)
    }

    /// As [`slow_start`], but with `every_ack` false the RTO's sample
    /// (`Ack::rtt`) comes only with a round's first ACK, as Karn's one
    /// timed segment does without timestamps; every ACK still reports the
    /// round trip of the newest segment it delivered (`newest_rtt`).
    fn slow_start_timed(
        rounds: u32,
        per_round: u32,
        rtt: impl Fn(u32) -> Duration,
        every_ack: bool,
    ) -> (Cubic, Vec<u32>) {
        let mut c = Cubic::new(MSS);
        let mut seq = 0u32;
        let mut now = Instant::now();
        let mut css_at = Vec::new();
        for r in 0..rounds {
            // Everything of the round is out; its ACKs come back.
            let end = seq + per_round * 2 * MSS;
            for i in 0..per_round {
                seq += 2 * MSS;
                now += Duration::from_micros(100);
                let a = Ack {
                    now,
                    bytes_acked: 2 * MSS,
                    flight: c.cwnd(),
                    rtt: (every_ack || i == 0).then(|| rtt(r)),
                    newest_rtt: Some(rtt(r)),
                    ack: seq,
                    snd_nxt: end + (i + 1) * 2 * MSS,
                    ..Ack::of(now, 2 * MSS, c.cwnd())
                };
                c.on_ack(&a);
                if c.hystart.in_css() {
                    css_at.push(r);
                }
                if c.ssthresh() != u32::MAX {
                    return (c, css_at);
                }
            }
        }
        (c, css_at)
    }

    /// A steady round trip leaves slow start alone.
    #[test]
    fn hystart_stays_in_slow_start_on_stable_rtt() {
        let (c, css) = slow_start(12, 16, |_| Duration::from_millis(50));
        assert!(css.is_empty());
        assert_eq!(c.ssthresh(), u32::MAX);
        assert!(!c.hystart.exited());
    }

    /// A round trip that rises by more than the threshold (here 50 ms/8)
    /// and stays up: CSS, a quarter of the growth, and after CSS_ROUNDS
    /// rounds congestion avoidance with ssthresh at cwnd.
    #[test]
    fn hystart_exits_on_rtt_increase() {
        let rtt = |r| Duration::from_millis(if r < 4 { 50 } else { 60 });
        let (c, css) = slow_start(20, 16, rtt);
        assert_eq!(css.first(), Some(&4), "CSS once the RTT rose");
        // The round CSS began in, and CSS_ROUNDS − 1 more.
        assert_eq!(*css.last().unwrap(), 4 + CSS_ROUNDS - 1);
        assert_eq!(c.ssthresh(), c.cwnd());
        assert!(c.hystart.exited());
        // CSS grew a quarter as fast: 16 ACKs of 2 segments add 8 per
        // round, where slow start would have doubled the window each.
        let ss_only = initial_window(MSS) + 4 * 16 * 2 * MSS;
        let css = 14 * MSS + 9 * MSS / 2 + 4 * 8 * MSS + MSS / 2;
        assert_eq!(c.cwnd(), ss_only + css);
        // Then CUBIC's curve starts at that window, K = 0.
        let mut c = c;
        c.on_ack(&ack(Instant::now(), MSS, c.cwnd()));
        let e = c.epoch.unwrap();
        assert_eq!((e.k, e.origin), (0.0, c.cwnd_prior));
    }

    /// Without timestamps the RTO gets one sample per round trip, but
    /// HyStart++ still sees every ACK's round trip: it leaves slow start
    /// on the rise as it does with timestamps, and the minimum RTT the
    /// curve is read ahead by comes from the same samples.
    #[test]
    fn hystart_runs_without_timestamps() {
        let rtt = |r| Duration::from_millis(if r < 4 { 50 } else { 60 });
        let (c, css) = slow_start_timed(20, 16, rtt, false);
        assert_eq!(css.first(), Some(&4), "CSS once the RTT rose");
        assert!(c.hystart.exited());
        assert_eq!(c.ssthresh(), c.cwnd());
        assert_eq!(c.delay_min, Some(Duration::from_millis(50)));
    }

    /// A rise of less than the threshold is not a queue.
    #[test]
    fn hystart_ignores_a_small_rise() {
        let rtt = |r| Duration::from_millis(if r < 4 { 50 } else { 53 });
        let (c, css) = slow_start(12, 16, rtt);
        assert!(css.is_empty());
        assert_eq!(c.ssthresh(), u32::MAX);
    }

    /// A rise that goes away within CSS was jitter: back to slow start.
    #[test]
    fn hystart_resumes_slow_start_when_rtt_falls_back() {
        let rtt = |r| Duration::from_millis(if r == 4 { 60 } else { 50 });
        let (c, css) = slow_start(12, 16, rtt);
        assert!(!css.is_empty());
        assert!(css.iter().all(|&r| r <= 5), "{css:?}");
        assert_eq!(c.ssthresh(), u32::MAX);
        assert!(!c.hystart.in_css());
    }

    /// Too few samples in a round say nothing.
    #[test]
    fn hystart_needs_enough_samples() {
        let rtt = |r| Duration::from_millis(if r < 4 { 50 } else { 80 });
        let (c, css) = slow_start(12, N_RTT_SAMPLE - 1, rtt);
        assert!(css.is_empty());
        assert_eq!(c.ssthresh(), u32::MAX);
    }

    /// The window grows only when in use, in slow start and after.
    #[test]
    fn no_growth_when_application_limited() {
        let mut c = Cubic::new(MSS);
        let w = c.cwnd();
        for _ in 0..50 {
            c.on_ack(&ack(Instant::now(), 2 * MSS, 2 * MSS));
        }
        assert_eq!(c.cwnd(), w);
        let mut c = after_loss(100, Duration::from_millis(10));
        let w = c.cwnd();
        let t0 = Instant::now();
        for i in 0..500 {
            c.on_ack(&ack(t0 + Duration::from_millis(i), 2 * MSS, w / 2));
        }
        assert_eq!(c.cwnd(), w);
    }

    /// Unpaced, slow start takes at most L = 8 segments per ACK, so that a
    /// stretch ACK cannot let a burst go; paced it takes all it is told
    /// of (RFC 9406 §4.3's L = infinity), pacing spreading what follows.
    #[test]
    fn paced_slow_start_takes_stretch_acks_whole() {
        let mut c = Cubic::new(MSS);
        let w = c.cwnd();
        c.on_ack(&ack(Instant::now(), 20 * MSS, w));
        assert_eq!(c.cwnd(), w + 8 * MSS);
        let mut c = Cubic::new(MSS);
        c.set_paced(true);
        c.on_ack(&ack(Instant::now(), 20 * MSS, w));
        assert_eq!(c.cwnd(), w + 20 * MSS);
    }
}
