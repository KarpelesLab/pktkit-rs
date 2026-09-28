//! BBR (draft-ietf-ccwg-bbr-06, "BBRv3"), an opt-in model-based controller.
//!
//! Loss-based controllers (CUBIC, Reno) grow the window until the
//! bottleneck's queue overflows and read the loss as the path's limit: they
//! fill whatever buffer the path has, and on a path that loses packets for
//! reasons other than congestion they mistake every loss for it. BBR builds
//! a model of the path instead, its bottleneck bandwidth (the windowed
//! maximum of the delivery rate samples, [`super::rate`]) and its round-trip
//! propagation delay (a windowed minimum RTT), and paces at the bandwidth
//! with about a BDP in flight. It probes for more bandwidth now and then
//! (ProbeBW_UP), drains the queue that leaves (ProbeBW_DOWN), and every
//! five seconds without a lower RTT drops to half a BDP for 200 ms to
//! measure the propagation delay again (ProbeRTT).
//!
//! Loss enters the model as a bound: a probe that sees more than 2% loss
//! sets `inflight_longterm`, the most in flight that was safe; outside
//! probes, a round with loss pulls the short-term bounds (`bw_shortterm`,
//! `inflight_shortterm`) down by at most 30% towards what that round
//! delivered. Random loss under 2% leaves the model alone, which is what
//! keeps BBR at the path's rate where Reno and CUBIC collapse.
//!
//! Where the draft leaves a detail to the implementation, Linux's
//! `tcp_bbr.c` (BBRv3) is followed: Startup's exit on loss counts ACKs with
//! losses in a round, and the `max_bw` and `extra_acked` windowed filters
//! keep two slots. There is no ECN here, so neither its Startup exit nor its
//! bound applies.
//!
//! Amounts are bytes, rates bytes per second.

use super::congestion::{Ack, CongestionController, Lost, initial_window};
use crate::time::Instant;
use std::time::Duration;

/// 4 ln 2: the least pacing gain that still doubles the sending rate each
/// round (§2.5).
const STARTUP_PACING_GAIN: f64 = 2.77;
/// Drains Startup's queue, which cwnd_gain bounds to a BDP, in a round (§5.3.2).
const DRAIN_PACING_GAIN: f64 = 0.5;
const DEFAULT_CWND_GAIN: f64 = 2.0;
const PROBE_DOWN_PACING_GAIN: f64 = 0.9;
const PROBE_UP_PACING_GAIN: f64 = 1.25;
const PROBE_UP_CWND_GAIN: f64 = 2.25;
const PROBE_RTT_CWND_GAIN: f64 = 0.5;
/// Pace 1% under the bandwidth estimate, so a queue built by noise drains.
const PACING_MARGIN: f64 = 0.99;
/// The loss rate a bandwidth probe tolerates (§2.8).
const LOSS_THRESH: f64 = 0.02;
/// The most a round with loss cuts the short-term bounds by (§2.8).
const BETA: f64 = 0.7;
/// Headroom left for other flows under `inflight_longterm` (§2.8).
const HEADROOM: f64 = 0.15;
/// Startup exits on loss after this many ACKs with losses in a round.
const STARTUP_FULL_LOSS_CNT: u32 = 6;
/// Rounds without 25% growth before the pipe counts as full (§5.3.1.2).
const FULL_BW_COUNT: u32 = 3;
const FULL_BW_GROWTH: f64 = 1.25;
const MIN_RTT_FILTER_LEN: Duration = Duration::from_secs(10);
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(5);
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
/// `extra_acked` is kept over two slots of this many rounds.
const EXTRA_ACKED_WIN_RTTS: u32 = 5;
/// The largest send quantum (§5.6.3).
const MAX_SEND_QUANTUM: u64 = 64 * 1024;
/// Reno-coexistence bound on the rounds between probes (§5.3.3.8).
const RENO_ROUNDS_BOUND: u64 = 63;

/// Where the state machine stands (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Startup,
    Drain,
    ProbeBwDown,
    ProbeBwCruise,
    ProbeBwRefill,
    ProbeBwUp,
    ProbeRtt,
}

impl State {
    fn is_probe_bw(self) -> bool {
        matches!(
            self,
            State::ProbeBwDown | State::ProbeBwCruise | State::ProbeBwRefill | State::ProbeBwUp
        )
    }
}

/// What the ACKs are telling about a bandwidth probe (§2.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckPhase {
    Init,
    Refilling,
    ProbeStarting,
    ProbeFeedback,
    ProbeStopping,
}

/// BBR congestion control (draft-ietf-ccwg-bbr).
#[derive(Debug)]
pub struct Bbr {
    mss: u32,
    cwnd: u32,
    init_cwnd: u32,
    state: State,
    pacing_gain: f64,
    cwnd_gain: f64,
    pacing_rate: u64,
    /// The pacing rate was set from a measured round trip.
    has_seen_rtt: bool,

    // The model.
    /// max_bw over the previous and the current ProbeBW cycle.
    bw_hi: [u64; 2],
    max_bw: u64,
    bw_shortterm: u64,
    bw: u64,
    bw_latest: u64,
    inflight_latest: u64,
    min_rtt: Option<Duration>,
    min_rtt_stamp: Instant,
    probe_rtt_min_delay: Option<Duration>,
    probe_rtt_min_stamp: Instant,
    probe_rtt_expired: bool,
    extra_acked: [u64; 2],
    extra_acked_idx: usize,
    extra_acked_win_rtts: u32,
    extra_acked_interval_start: Instant,
    extra_acked_delivered: u64,
    inflight_longterm: u64,
    inflight_shortterm: u64,

    // Rounds.
    next_round_delivered: u64,
    round_start: bool,
    round_count: u64,
    rounds_since_probe_up: u64,
    drain_start_round: u64,

    // Startup.
    full_bw_reached: bool,
    full_bw_now: bool,
    full_bw: u64,
    full_bw_count: u32,

    // ProbeBW.
    ack_phase: AckPhase,
    is_bw_probe_sample: bool,
    bw_probe_up_acked: u64,
    probe_up_acked_per_inc: u64,
    bw_probe_up_rounds: u32,
    bw_probe_wait: Duration,
    cycle_stamp: Instant,
    prev_probe_too_high: bool,
    prev_probe_precautionary: bool,

    // Congestion signals.
    is_loss_in_round: bool,
    loss_round_delivered: u64,
    loss_round_start: bool,
    loss_events_in_round: u32,

    // ProbeRTT and idle.
    probe_rtt_done_stamp: Option<Instant>,
    probe_rtt_round_done: bool,
    idle_restart: bool,
    mark_app_limited: bool,

    // Loss recovery and undo.
    prior_cwnd: u32,
    in_recovery: bool,
    recovery_round: u64,
    undo_state: Option<State>,
    undo_bw_shortterm: u64,
    undo_inflight_shortterm: u64,
    undo_inflight_longterm: u64,

    // What the connection reported.
    delivered: u64,
    inflight: u32,
    cwnd_limited_now: bool,
    cwnd_limited_prev: bool,
    /// The peer SACKs (C.has_selective_acks).
    sack: bool,
    now: Instant,
}

impl Bbr {
    /// A controller for segments of `mss` bytes, from RFC 6928's initial
    /// window (OnInit, §5.2.1).
    pub fn new(mss: u32, now: Instant) -> Self {
        let mss = mss.max(1);
        let init_cwnd = initial_window(mss);
        let mut b = Self {
            mss,
            cwnd: init_cwnd,
            init_cwnd,
            state: State::Startup,
            pacing_gain: STARTUP_PACING_GAIN,
            cwnd_gain: DEFAULT_CWND_GAIN,
            pacing_rate: 0,
            has_seen_rtt: false,
            bw_hi: [0; 2],
            max_bw: 0,
            bw_shortterm: u64::MAX,
            bw: 0,
            bw_latest: 0,
            inflight_latest: 0,
            min_rtt: None,
            min_rtt_stamp: now,
            probe_rtt_min_delay: None,
            probe_rtt_min_stamp: now,
            probe_rtt_expired: false,
            extra_acked: [0; 2],
            extra_acked_idx: 0,
            extra_acked_win_rtts: 0,
            extra_acked_interval_start: now,
            extra_acked_delivered: 0,
            inflight_longterm: u64::MAX,
            inflight_shortterm: u64::MAX,
            next_round_delivered: 0,
            round_start: false,
            round_count: 0,
            rounds_since_probe_up: 0,
            drain_start_round: 0,
            full_bw_reached: false,
            full_bw_now: false,
            full_bw: 0,
            full_bw_count: 0,
            ack_phase: AckPhase::Init,
            is_bw_probe_sample: false,
            bw_probe_up_acked: 0,
            probe_up_acked_per_inc: u64::MAX,
            bw_probe_up_rounds: 0,
            bw_probe_wait: Duration::ZERO,
            cycle_stamp: now,
            prev_probe_too_high: false,
            prev_probe_precautionary: false,
            is_loss_in_round: false,
            loss_round_delivered: 0,
            loss_round_start: false,
            loss_events_in_round: 0,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            idle_restart: false,
            mark_app_limited: false,
            prior_cwnd: 0,
            in_recovery: false,
            recovery_round: 0,
            undo_state: None,
            undo_bw_shortterm: 0,
            undo_inflight_shortterm: 0,
            undo_inflight_longterm: 0,
            delivered: 0,
            inflight: 0,
            cwnd_limited_now: false,
            cwnd_limited_prev: false,
            sack: true,
            now,
        };
        b.init_pacing_rate(None);
        b.enter_startup();
        b
    }

    /// Where the state machine stands.
    #[cfg(test)]
    pub(crate) fn state(&self) -> State {
        self.state
    }

    /// The bandwidth estimate, BBR.max_bw.
    #[cfg(test)]
    pub(crate) fn max_bw(&self) -> u64 {
        self.max_bw
    }

    /// The minimum RTT estimate.
    #[cfg(test)]
    pub(crate) fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt
    }

    /// InitPacingRate (§5.6.2): the initial window over the first round
    /// trip, or a millisecond before there is one.
    fn init_pacing_rate(&mut self, rtt: Option<Duration>) {
        let rtt = rtt
            .filter(|r| !r.is_zero())
            .unwrap_or(Duration::from_millis(1));
        let nominal = f64::from(self.init_cwnd) / rtt.as_secs_f64();
        self.pacing_rate = (STARTUP_PACING_GAIN * nominal) as u64;
    }

    fn mss64(&self) -> u64 {
        u64::from(self.mss)
    }

    fn min_pipe_cwnd(&self) -> u64 {
        4 * self.mss64()
    }

    fn is_cwnd_limited(&self) -> bool {
        self.cwnd_limited_now || self.cwnd_limited_prev
    }

    // --- State transitions ---------------------------------------------

    fn enter_startup(&mut self) {
        self.state = State::Startup;
        self.pacing_gain = STARTUP_PACING_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
    }

    fn enter_drain(&mut self) {
        self.state = State::Drain;
        self.pacing_gain = DRAIN_PACING_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
        self.drain_start_round = self.round_count;
    }

    fn enter_probe_bw(&mut self) {
        self.cwnd_gain = DEFAULT_CWND_GAIN;
        self.start_probe_bw_down();
    }

    fn start_probe_bw_down(&mut self) {
        self.reset_congestion_signals();
        self.probe_up_acked_per_inc = u64::MAX;
        self.pick_probe_wait();
        self.cycle_stamp = self.now;
        self.ack_phase = AckPhase::ProbeStopping;
        self.start_round();
        self.state = State::ProbeBwDown;
        self.pacing_gain = PROBE_DOWN_PACING_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
    }

    fn start_probe_bw_cruise(&mut self) {
        self.state = State::ProbeBwCruise;
        self.pacing_gain = 1.0;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
    }

    fn start_probe_bw_refill(&mut self) {
        self.reset_short_term_model();
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acked = 0;
        self.prev_probe_precautionary = false;
        self.ack_phase = AckPhase::Refilling;
        self.start_round();
        self.state = State::ProbeBwRefill;
        self.pacing_gain = 1.0;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
    }

    fn start_probe_bw_up(&mut self, rate: u64) {
        self.ack_phase = AckPhase::ProbeStarting;
        self.start_round();
        self.reset_full_bw();
        self.full_bw = rate;
        self.state = State::ProbeBwUp;
        self.pacing_gain = PROBE_UP_PACING_GAIN;
        self.cwnd_gain = PROBE_UP_CWND_GAIN;
        self.raise_inflight_longterm_slope();
    }

    fn enter_probe_rtt(&mut self) {
        self.state = State::ProbeRtt;
        self.pacing_gain = 1.0;
        self.cwnd_gain = PROBE_RTT_CWND_GAIN;
    }

    fn exit_probe_rtt(&mut self) {
        self.reset_short_term_model();
        if self.full_bw_reached {
            self.start_probe_bw_down();
            self.start_probe_bw_cruise();
        } else {
            self.enter_startup();
        }
    }

    /// PickProbeWait (§5.3.3.8): 0 or 1 round, and 2 to 3 seconds.
    fn pick_probe_wait(&mut self) {
        let r = crate::rand::u32();
        self.rounds_since_probe_up = u64::from(r & 1);
        self.bw_probe_wait =
            Duration::from_secs(2) + Duration::from_micros(u64::from(r >> 1) % 1_000_000);
    }

    // --- Rounds and the full-pipe estimator ----------------------------

    fn start_round(&mut self) {
        self.next_round_delivered = self.delivered;
    }

    /// UpdateRound (§5.5.1), from the sample's P.delivered.
    fn update_round(&mut self, prior_delivered: u64) {
        if prior_delivered >= self.next_round_delivered {
            self.start_round();
            self.round_count += 1;
            self.rounds_since_probe_up += 1;
            self.round_start = true;
            self.cwnd_limited_prev = self.cwnd_limited_now;
            self.cwnd_limited_now = false;
        } else {
            self.round_start = false;
        }
    }

    fn reset_full_bw(&mut self) {
        self.full_bw = 0;
        self.full_bw_count = 0;
        self.full_bw_now = false;
    }

    /// CheckFullBWReached (§5.3.1.2): three rounds without 25% growth.
    fn check_full_bw_reached(&mut self, rate: u64, app_limited: bool) {
        if self.full_bw_now || !self.round_start || app_limited {
            return;
        }
        if rate as f64 >= self.full_bw as f64 * FULL_BW_GROWTH {
            self.reset_full_bw();
            self.full_bw = rate;
            return;
        }
        self.full_bw_count += 1;
        self.full_bw_now = self.full_bw_count >= FULL_BW_COUNT;
        if self.full_bw_now {
            self.full_bw_reached = true;
        }
    }

    // --- The model -----------------------------------------------------

    fn bdp_multiple(&self, bw: u64, gain: f64) -> u64 {
        match self.min_rtt {
            None => u64::from(self.init_cwnd),
            Some(rtt) => (gain * bw as f64 * rtt.as_secs_f64()) as u64,
        }
    }

    fn bdp(&self) -> u64 {
        self.bdp_multiple(self.bw, 1.0)
    }

    fn send_quantum(&self) -> u64 {
        (self.pacing_rate / 1000)
            .min(MAX_SEND_QUANTUM)
            .max(2 * self.mss64())
    }

    /// QuantizationBudget (§5.6.4.2).
    fn quantization_budget(&self, cap: u64) -> u64 {
        let offload = 3 * self.send_quantum();
        let mut cap = cap.max(offload).max(self.min_pipe_cwnd());
        if self.state == State::ProbeBwUp {
            cap += 2 * self.mss64();
        }
        cap
    }

    /// Inflight(bw, gain) (§5.6.4.2).
    fn inflight(&self, bw: u64, gain: f64) -> u64 {
        self.quantization_budget(self.bdp_multiple(bw, gain))
    }

    fn max_inflight(&self) -> u64 {
        let extra = self.extra_acked[0].max(self.extra_acked[1]);
        self.quantization_budget(self.bdp_multiple(self.bw, self.cwnd_gain) + extra)
    }

    /// InflightWithHeadroom (§5.3.3.9).
    fn inflight_with_headroom(&self) -> u64 {
        if self.inflight_longterm == u64::MAX {
            return u64::MAX;
        }
        let headroom = self
            .mss64()
            .max((HEADROOM * self.inflight_longterm as f64) as u64);
        self.inflight_longterm
            .saturating_sub(headroom)
            .max(self.min_pipe_cwnd())
    }

    /// TargetInflight (§5.3.3.8): the BDP, unless congestion cut cwnd.
    fn target_inflight(&self) -> u64 {
        self.bdp().min(u64::from(self.cwnd))
    }

    fn update_max_bw(&mut self, rate: u64, app_limited: bool) {
        if rate > 0 && (rate >= self.max_bw || !app_limited) {
            self.bw_hi[1] = self.bw_hi[1].max(rate);
            self.max_bw = self.bw_hi[0].max(self.bw_hi[1]);
        }
    }

    /// AdvanceMaxBwFilter (§5.5.6): a new ProbeBW cycle.
    fn advance_max_bw_filter(&mut self) {
        // A cycle without samples keeps the old one's.
        if self.bw_hi[1] == 0 {
            return;
        }
        self.bw_hi = [self.bw_hi[1], 0];
        self.max_bw = self.bw_hi[0];
    }

    /// UpdateACKAggregation (§5.5.9).
    fn update_ack_aggregation(&mut self, newly_acked: u64) {
        let interval = self
            .now
            .saturating_duration_since(self.extra_acked_interval_start);
        let mut expected = (self.bw as f64 * interval.as_secs_f64()) as u64;
        if self.extra_acked_delivered <= expected {
            self.extra_acked_delivered = 0;
            self.extra_acked_interval_start = self.now;
            expected = 0;
        }
        self.extra_acked_delivered += newly_acked;
        let extra = self
            .extra_acked_delivered
            .saturating_sub(expected)
            .min(u64::from(self.cwnd));
        if self.round_start {
            self.extra_acked_win_rtts += 1;
            let len = if self.full_bw_reached {
                EXTRA_ACKED_WIN_RTTS
            } else {
                1
            };
            if self.extra_acked_win_rtts >= len {
                self.extra_acked_win_rtts = 0;
                self.extra_acked_idx ^= 1;
                self.extra_acked[self.extra_acked_idx] = 0;
            }
        }
        let slot = &mut self.extra_acked[self.extra_acked_idx];
        *slot = (*slot).max(extra);
    }

    /// UpdateMinRTT (§5.3.4.3).
    fn update_min_rtt(&mut self, rtt: Option<Duration>) {
        self.probe_rtt_expired = self.now > self.probe_rtt_min_stamp + PROBE_RTT_INTERVAL;
        if let Some(rtt) = rtt
            && (self.probe_rtt_min_delay.is_none_or(|d| rtt < d) || self.probe_rtt_expired)
        {
            self.probe_rtt_min_delay = Some(rtt);
            self.probe_rtt_min_stamp = self.now;
        }
        let expired = self.now > self.min_rtt_stamp + MIN_RTT_FILTER_LEN;
        if let Some(d) = self.probe_rtt_min_delay
            && (self.min_rtt.is_none_or(|m| d < m) || expired)
        {
            self.min_rtt = Some(d);
            self.min_rtt_stamp = self.probe_rtt_min_stamp;
        }
    }

    // --- Congestion signals ---------------------------------------------

    fn reset_congestion_signals(&mut self) {
        self.is_loss_in_round = false;
        self.bw_latest = 0;
        self.inflight_latest = 0;
    }

    fn reset_short_term_model(&mut self) {
        self.bw_shortterm = u64::MAX;
        self.inflight_shortterm = u64::MAX;
    }

    /// UpdateLatestDeliverySignals (§5.5.10.3).
    fn update_latest_delivery_signals(&mut self, rate: u64, delivered: u64, prior: u64) {
        self.loss_round_start = false;
        self.bw_latest = self.bw_latest.max(rate);
        self.inflight_latest = self.inflight_latest.max(delivered);
        if prior >= self.loss_round_delivered {
            self.loss_round_delivered = self.delivered;
            self.loss_round_start = true;
        }
    }

    /// AdvanceLatestDeliverySignals (§5.5.10.3).
    fn advance_latest_delivery_signals(&mut self, rate: u64, delivered: u64) {
        if self.loss_round_start {
            self.bw_latest = rate;
            self.inflight_latest = delivered;
        }
    }

    /// AdaptLowerBoundsFromCongestion (§5.5.10.3), once per round.
    fn adapt_lower_bounds_from_congestion(&mut self) {
        if matches!(
            self.state,
            State::Startup | State::ProbeBwRefill | State::ProbeBwUp
        ) {
            return;
        }
        if self.is_loss_in_round {
            if self.bw_shortterm == u64::MAX {
                self.bw_shortterm = self.max_bw;
            }
            if self.inflight_shortterm == u64::MAX {
                self.inflight_shortterm = u64::from(self.cwnd);
            }
            self.bw_shortterm = self.bw_latest.max((BETA * self.bw_shortterm as f64) as u64);
            self.inflight_shortterm = self
                .inflight_latest
                .max((BETA * self.inflight_shortterm as f64) as u64);
        }
    }

    /// IsInflightTooHigh (§5.5.10.2).
    fn is_inflight_too_high(lost: u64, tx_in_flight: u32, sack: bool) -> bool {
        lost as f64 > f64::from(tx_in_flight) * LOSS_THRESH || (lost > 0 && !sack)
    }

    /// HandleInflightTooHigh (§5.5.10.2).
    fn handle_inflight_too_high(&mut self, tx_in_flight: u64, app_limited: bool) {
        self.prev_probe_too_high = true;
        self.is_bw_probe_sample = false;
        if !app_limited {
            self.inflight_longterm =
                tx_in_flight.max((self.target_inflight() as f64 * BETA) as u64);
        }
        if self.state == State::ProbeBwUp {
            self.undo_state = Some(State::ProbeBwUp);
            self.start_probe_bw_down();
        }
    }

    fn save_state_upon_loss(&mut self) {
        self.save_cwnd();
        self.undo_state = None;
        self.undo_bw_shortterm = self.bw_shortterm;
        self.undo_inflight_shortterm = self.inflight_shortterm;
        self.undo_inflight_longterm = self.inflight_longterm;
    }

    fn save_cwnd(&mut self) {
        if !self.in_recovery && self.state != State::ProbeRtt {
            self.prior_cwnd = self.cwnd;
        } else {
            self.prior_cwnd = self.prior_cwnd.max(self.cwnd);
        }
    }

    fn restore_cwnd(&mut self) {
        self.cwnd = self.cwnd.max(self.prior_cwnd);
    }

    /// CheckStartupHighLoss (§5.3.1.3), counting ACKs with losses in the
    /// round as Linux does.
    fn check_startup_high_loss(&mut self, a: &Ack) {
        if self.full_bw_reached || self.state != State::Startup {
            return;
        }
        if a.newly_lost > 0 {
            self.loss_events_in_round = self.loss_events_in_round.saturating_add(1);
        }
        let Some(rs) = a.rs else {
            return;
        };
        // Judged at the end of each round, over the round.
        let too_high = if a.sack {
            self.loss_round_start
                && self.in_recovery
                && self.round_count > self.recovery_round
                && self.loss_events_in_round >= STARTUP_FULL_LOSS_CNT
                && Self::is_inflight_too_high(rs.lost, rs.tx_in_flight, true)
        } else {
            self.in_recovery && a.newly_lost > 0
        };
        if too_high {
            self.undo_state = Some(State::Startup);
            self.full_bw_reached = true;
            self.inflight_longterm = self.bdp().max(self.inflight_latest);
            self.enter_drain();
        }
        if self.loss_round_start {
            self.loss_events_in_round = 0;
        }
    }

    // --- ProbeBW ---------------------------------------------------------

    fn raise_inflight_longterm_slope(&mut self) {
        let growth = 1u64 << self.bw_probe_up_rounds;
        self.bw_probe_up_rounds = (self.bw_probe_up_rounds + 1).min(30);
        self.probe_up_acked_per_inc = (u64::from(self.cwnd) / growth).max(self.mss64());
    }

    fn probe_inflight_longterm_upward(&mut self, newly_acked: u64) {
        if !self.is_cwnd_limited() || u64::from(self.cwnd) < self.inflight_longterm {
            return;
        }
        self.bw_probe_up_acked += newly_acked;
        if self.bw_probe_up_acked >= self.probe_up_acked_per_inc {
            let delta = self.bw_probe_up_acked / self.probe_up_acked_per_inc;
            self.bw_probe_up_acked -= delta * self.probe_up_acked_per_inc;
            self.inflight_longterm = self.inflight_longterm.saturating_add(delta * self.mss64());
        }
        if self.round_start {
            self.raise_inflight_longterm_slope();
        }
    }

    /// AdaptLongTermModel (§5.3.3.9). True if it decided a transition.
    fn adapt_long_term_model(&mut self, a: &Ack) -> bool {
        if self.ack_phase == AckPhase::ProbeStarting && self.round_start {
            self.ack_phase = AckPhase::ProbeFeedback;
        }
        let rs = a.rs.unwrap_or_default();
        if self.ack_phase == AckPhase::ProbeStopping && self.round_start {
            self.is_bw_probe_sample = false;
            self.ack_phase = AckPhase::Init;
            if self.state.is_probe_bw() && !rs.is_app_limited {
                self.advance_max_bw_filter();
            }
            if self.state.is_probe_bw()
                && self.prev_probe_precautionary
                && !self.prev_probe_too_high
            {
                self.start_probe_bw_refill();
                return true;
            }
        }
        if !Self::is_inflight_too_high(rs.lost, rs.tx_in_flight, a.sack) {
            if self.inflight_longterm == u64::MAX {
                return false;
            }
            if u64::from(rs.tx_in_flight) > self.inflight_longterm {
                self.inflight_longterm = u64::from(rs.tx_in_flight);
            }
            if self.state == State::ProbeBwUp {
                self.probe_inflight_longterm_upward(u64::from(a.newly_acked));
            }
        }
        false
    }

    fn has_elapsed_in_phase(&self, d: Duration) -> bool {
        self.now > self.cycle_stamp + d
    }

    /// IsTimeToProbeBW (§5.3.3.8).
    fn is_time_to_probe_bw(&mut self) -> bool {
        let reno_rounds = (self.target_inflight() / self.mss64()).min(RENO_ROUNDS_BOUND);
        if self.has_elapsed_in_phase(self.bw_probe_wait)
            || self.rounds_since_probe_up >= reno_rounds
        {
            self.start_probe_bw_refill();
            return true;
        }
        false
    }

    fn is_time_to_cruise(&self) -> bool {
        let inflight = u64::from(self.inflight);
        inflight <= self.inflight_with_headroom() && inflight <= self.inflight(self.max_bw, 1.0)
    }

    fn is_time_to_go_down(&mut self, rate: u64) -> bool {
        if self.prev_probe_too_high && u64::from(self.inflight) >= self.inflight_longterm {
            self.prev_probe_precautionary = true;
            return true;
        }
        if self.is_cwnd_limited() && u64::from(self.cwnd) >= self.inflight_longterm {
            self.reset_full_bw();
            self.full_bw = rate;
        } else if self.full_bw_now {
            return true;
        }
        false
    }

    /// UpdateProbeBWCyclePhase (§5.3.3.9).
    fn update_probe_bw_cycle_phase(&mut self, a: &Ack) {
        if !self.full_bw_reached || self.adapt_long_term_model(a) {
            return;
        }
        let rate = a.rs.map_or(0, |rs| rs.delivery_rate);
        let state = self.state;
        if state == State::ProbeBwDown {
            if !self.is_time_to_probe_bw() && self.is_time_to_cruise() {
                self.start_probe_bw_cruise();
            }
        } else if state == State::ProbeBwCruise {
            self.is_time_to_probe_bw();
        } else if state == State::ProbeBwRefill {
            // After a round of refill, up.
            if self.round_start {
                self.is_bw_probe_sample = true;
                self.start_probe_bw_up(rate);
            }
        } else if state == State::ProbeBwUp && self.is_time_to_go_down(rate) {
            self.prev_probe_too_high = false;
            self.start_probe_bw_down();
        }
    }

    // --- ProbeRTT --------------------------------------------------------

    fn probe_rtt_cwnd(&self) -> u64 {
        self.bdp_multiple(self.bw, PROBE_RTT_CWND_GAIN)
            .max(self.min_pipe_cwnd())
    }

    /// CheckProbeRTT (§5.3.4.3).
    fn check_probe_rtt(&mut self, delivered: u64) {
        if self.state != State::ProbeRtt && self.probe_rtt_expired && !self.idle_restart {
            self.enter_probe_rtt();
            self.save_cwnd();
            self.probe_rtt_done_stamp = None;
            self.ack_phase = AckPhase::ProbeStopping;
            self.start_round();
        }
        if self.state == State::ProbeRtt {
            self.handle_probe_rtt();
        }
        if delivered > 0 {
            self.idle_restart = false;
        }
    }

    fn handle_probe_rtt(&mut self) {
        // Its low-rate samples are not the path's.
        self.mark_app_limited = true;
        if self.probe_rtt_done_stamp.is_none() && u64::from(self.inflight) <= self.probe_rtt_cwnd()
        {
            self.probe_rtt_done_stamp = Some(self.now + PROBE_RTT_DURATION);
            self.probe_rtt_round_done = false;
            self.start_round();
        } else if self.probe_rtt_done_stamp.is_some() {
            if self.round_start {
                self.probe_rtt_round_done = true;
            }
            if self.probe_rtt_round_done {
                self.check_probe_rtt_done();
            }
        }
    }

    fn check_probe_rtt_done(&mut self) {
        if self.probe_rtt_done_stamp.is_some_and(|d| self.now > d) {
            self.probe_rtt_min_stamp = self.now;
            self.restore_cwnd();
            self.exit_probe_rtt();
        }
    }

    // --- Control parameters ------------------------------------------------

    fn set_pacing_rate_with_gain(&mut self, gain: f64) {
        let rate = (gain * self.bw as f64 * PACING_MARGIN) as u64;
        if self.full_bw_reached || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    /// SetCwnd (§5.6.4.6), with the ProbeRTT and model bounds.
    fn set_cwnd(&mut self, newly_acked: u64) {
        let max_inflight = self.max_inflight();
        let mut cwnd = u64::from(self.cwnd);
        if self.full_bw_reached {
            cwnd = (cwnd + newly_acked).min(max_inflight);
        } else if cwnd < max_inflight || self.delivered < u64::from(self.init_cwnd) {
            cwnd += newly_acked;
        }
        cwnd = cwnd.max(self.min_pipe_cwnd());
        if self.state == State::ProbeRtt {
            cwnd = cwnd.min(self.probe_rtt_cwnd());
        }
        // BoundCwndForModel (§5.6.4.7).
        let mut cap = u64::MAX;
        if self.state.is_probe_bw() && self.state != State::ProbeBwCruise {
            cap = self.inflight_longterm;
        } else if matches!(self.state, State::ProbeRtt | State::ProbeBwCruise) {
            cap = self.inflight_with_headroom();
        }
        cap = cap.min(self.inflight_shortterm).max(self.min_pipe_cwnd());
        self.cwnd = cwnd.min(cap).min(u64::from(u32::MAX)) as u32;
    }
}

impl CongestionController for Bbr {
    fn model_based(&self) -> bool {
        true
    }

    #[cfg(test)]
    fn as_bbr(&self) -> Option<&Bbr> {
        Some(self)
    }

    fn set_mss(&mut self, mss: u32) {
        self.mss = mss.max(1);
    }

    /// UpdateOnACK (§5.2.3).
    fn on_ack(&mut self, a: &Ack) {
        self.now = a.now;
        self.delivered = a.delivered;
        self.inflight = a.inflight;
        self.cwnd_limited_now |= a.cwnd_limited;
        self.sack = a.sack;
        let rtt = a.newest_rtt.or(a.rtt).filter(|r| !r.is_zero());
        if !self.has_seen_rtt && rtt.is_some() {
            self.has_seen_rtt = true;
            self.init_pacing_rate(rtt);
        }
        let rs = a.rs.unwrap_or_default();
        let (rate, delivered) = (rs.delivery_rate, rs.delivered);

        // UpdateModelAndState.
        if a.rs.is_some() {
            self.update_latest_delivery_signals(rate, delivered, rs.prior_delivered);
            self.update_round(rs.prior_delivered);
            self.update_max_bw(rate, rs.is_app_limited);
            if self.loss_round_start {
                self.adapt_lower_bounds_from_congestion();
                self.is_loss_in_round = false;
            }
        } else {
            self.round_start = false;
            self.loss_round_start = false;
        }
        self.update_ack_aggregation(u64::from(a.newly_acked));
        if a.rs.is_some() {
            self.check_full_bw_reached(rate, rs.is_app_limited);
        }
        self.check_startup_high_loss(a);
        if self.state == State::Startup && self.full_bw_reached {
            self.enter_drain();
        }
        if self.state == State::Drain
            && (u64::from(self.inflight) <= self.inflight(self.bw, 1.0)
                || self.round_count > self.drain_start_round + 3)
        {
            self.enter_probe_bw();
        }
        if a.rs.is_some() {
            self.update_probe_bw_cycle_phase(a);
        }
        self.update_min_rtt(rtt);
        self.check_probe_rtt(delivered);
        if a.rs.is_some() {
            self.advance_latest_delivery_signals(rate, delivered);
        }
        self.bw = self.max_bw.min(self.bw_shortterm);

        // UpdateControlParameters.
        self.set_pacing_rate_with_gain(self.pacing_gain);
        self.set_cwnd(u64::from(a.newly_acked));
    }

    /// HandleLostPacket (§5.5.10.2).
    fn on_lost(&mut self, l: &Lost) {
        if !self.is_loss_in_round {
            self.loss_round_delivered = l.delivered;
            self.save_state_upon_loss();
        }
        self.is_loss_in_round = true;
        if !self.is_bw_probe_sample {
            return;
        }
        let lost = l.total_lost.saturating_sub(l.tx.lost);
        if Self::is_inflight_too_high(lost, l.tx.tx_in_flight, self.sack) {
            // InflightAtLoss: where within this segment the loss rate
            // crossed the threshold.
            let size = f64::from(l.len);
            let inflight_prev = f64::from(l.tx.tx_in_flight) - size;
            let lost_prev = lost as f64 - size;
            let prefix = (LOSS_THRESH * inflight_prev - lost_prev) / (1.0 - LOSS_THRESH);
            let at_loss = (inflight_prev + prefix).max(0.0) as u64;
            self.handle_inflight_too_high(at_loss, l.tx.app_limited);
        }
    }

    /// OnEnterFastRecovery (§5.6.4.4).
    fn on_loss(&mut self, _flight_size: u32) {
        self.save_cwnd();
        self.save_state_upon_loss();
        self.in_recovery = true;
        self.recovery_round = self.round_count;
    }

    /// OnEnterRTO (§5.6.4.4). The connection then sets cwnd to what is in
    /// flight and a segment, once the timeout has marked what it lost.
    fn on_retransmit_timeout(&mut self, _flight_size: u32, _repeated: bool) {
        self.save_cwnd();
        self.save_state_upon_loss();
        self.in_recovery = true;
        self.recovery_round = self.round_count;
        self.cwnd = self.mss;
    }

    fn on_handshake_loss(&mut self) {
        self.cwnd = self.mss;
    }

    fn on_recovery_exit(&mut self) {
        self.in_recovery = false;
        self.restore_cwnd();
    }

    /// HandleRestartFromIdle (§5.4.1).
    fn on_transmit(&mut self, now: Instant, idle: bool) {
        self.now = now;
        if !idle {
            return;
        }
        self.idle_restart = true;
        self.extra_acked_interval_start = now;
        if self.state.is_probe_bw() {
            self.set_pacing_rate_with_gain(1.0);
        } else if self.state == State::ProbeRtt {
            self.check_probe_rtt_done();
        }
    }

    fn take_app_limited(&mut self) -> bool {
        std::mem::take(&mut self.mark_app_limited)
    }

    fn pacing_rate(&self) -> Option<u64> {
        Some(self.pacing_rate.max(1))
    }

    fn set_cwnd(&mut self, cwnd: u32) {
        self.cwnd = cwnd.max(self.mss);
    }

    /// HandleSpuriousLossDetection (§5.5.11.2).
    fn undo(&mut self, _cwnd: u32, _ssthresh: u32) {
        self.in_recovery = false;
        self.restore_cwnd();
        self.is_loss_in_round = false;
        self.reset_full_bw();
        self.bw_shortterm = self.bw_shortterm.max(self.undo_bw_shortterm);
        self.inflight_shortterm = self.inflight_shortterm.max(self.undo_inflight_shortterm);
        self.inflight_longterm = self.inflight_longterm.max(self.undo_inflight_longterm);
        // Back to the probe the episode cut short, ProbeRTT permitting.
        let (undo, now) = (self.undo_state.take(), self.state);
        if undo == Some(State::Startup) && now != State::Startup {
            self.full_bw_reached = false;
            if now != State::ProbeRtt {
                self.enter_startup();
            }
        } else if undo == Some(State::ProbeBwUp)
            && now != State::ProbeBwUp
            && now != State::ProbeRtt
        {
            self.start_probe_bw_refill();
        }
    }

    fn restart(&mut self, cwnd: u32, _ssthresh: u32) {
        self.cwnd = cwnd.max(self.mss);
    }

    fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// BBR has no slow-start threshold.
    fn ssthresh(&self) -> u32 {
        u32::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::super::rate::{RateSample, TxState};
    use super::*;

    const MSS: u32 = 1000;
    const RTT: Duration = Duration::from_millis(50);

    /// Drives a controller with one ACK per round trip, each carrying the
    /// sample of the round before.
    struct Feed {
        b: Bbr,
        now: Instant,
        delivered: u64,
        lost: u64,
    }

    impl Feed {
        fn new() -> Self {
            let now = Instant::now();
            Self {
                b: Bbr::new(MSS, now),
                now,
                delivered: 0,
                lost: 0,
            }
        }

        /// A round trip at `rate` with `inflight` in flight after it.
        fn round(&mut self, rate: u64, inflight: u32, app_limited: bool) {
            self.round_rtt(rate, inflight, app_limited, RTT);
        }

        fn round_rtt(&mut self, rate: u64, inflight: u32, app_limited: bool, rtt: Duration) {
            self.now += RTT;
            let prior = self.delivered;
            let bytes = (rate as f64 * RTT.as_secs_f64()) as u64;
            self.delivered += bytes;
            let rs = RateSample {
                delivery_rate: rate,
                delivered: bytes,
                interval: RTT,
                prior_delivered: prior,
                is_app_limited: app_limited,
                tx_in_flight: inflight,
                lost: 0,
            };
            let a = Ack {
                rs: Some(rs),
                newly_acked: bytes as u32,
                inflight,
                delivered: self.delivered,
                newest_rtt: Some(rtt),
                ..Ack::of(self.now, bytes as u32, inflight)
            };
            self.b.on_ack(&a);
        }

        /// `len` bytes sent with `tx_in_flight` in flight are marked lost,
        /// `lost_since` more having been lost since they were sent.
        fn lose(&mut self, len: u32, tx_in_flight: u32, lost_since: u64) {
            self.lost += u64::from(len);
            let tx = TxState {
                delivered: self.delivered,
                tx_in_flight,
                lost: self.lost - lost_since - u64::from(len),
                ..TxState::default()
            };
            self.b.on_lost(&Lost {
                tx,
                len,
                total_lost: self.lost,
                delivered: self.delivered,
            });
        }

        /// Run rounds at `rate` with a BDP in flight, their RTT a little
        /// over the minimum, until `state`, or panic after `max` rounds.
        /// Returns the rounds it took.
        fn until(&mut self, rate: u64, state: State, max: u32) -> u32 {
            let bdp = (rate as f64 * RTT.as_secs_f64()) as u32;
            for i in 0..max {
                if self.b.state == state {
                    return i;
                }
                self.round_rtt(rate, bdp, false, RTT + Duration::from_millis(1));
            }
            panic!("not in {state:?} after {max} rounds: {:?}", self.b.state);
        }
    }

    /// Startup doubles the rate each round, and ends once three rounds in
    /// a row fail to grow the bandwidth by a quarter (§5.3.1.2); rounds
    /// limited by the application do not count.
    #[test]
    fn startup_exits_on_a_bandwidth_plateau() {
        let mut f = Feed::new();
        for rate in [1_000_000, 2_000_000, 4_000_000, 8_000_000] {
            f.round(rate, 0, false);
            assert_eq!(f.b.state, State::Startup);
        }
        assert!((f.b.pacing_gain - 2.77).abs() < 1e-9);
        assert_eq!(f.b.cwnd_gain, 2.0);
        f.round(9_000_000, 0, false);
        f.round(9_500_000, 0, true);
        f.round(8_000_000, 0, true);
        assert_eq!(f.b.state, State::Startup, "app-limited rounds do not count");
        f.round(9_900_000, 0, false);
        assert_eq!(f.b.state, State::Startup, "two rounds without growth");
        // A BDP and more in flight: the queue Startup built.
        f.round(9_000_000, 900_000, false);
        assert_eq!(f.b.state, State::Drain, "three rounds without growth");
        assert!(f.b.full_bw_reached);
        assert_eq!(f.b.max_bw(), 9_900_000);
        assert_eq!(f.b.pacing_gain, 0.5);
        assert_eq!(f.b.min_rtt(), Some(RTT));
    }

    /// Drain holds until what is in flight is down to the BDP, then
    /// ProbeBW begins in its DOWN phase, and cruises once the queue and
    /// the headroom are there.
    #[test]
    fn drain_ends_at_the_bdp() {
        let mut f = Feed::new();
        for rate in [1_000_000, 2_000_000, 4_000_000, 4_000_000, 4_000_000] {
            f.round(rate, 400_000, false);
        }
        f.round(4_000_000, 400_000, false);
        assert_eq!(f.b.state, State::Drain);
        f.round(4_000_000, 300_000, false);
        assert_eq!(f.b.state, State::Drain, "1.5 BDP still queued");
        f.round(4_000_000, 190_000, false);
        assert!(f.b.state.is_probe_bw(), "down to the BDP: {:?}", f.b.state);
        f.round(4_000_000, 150_000, false);
        assert_eq!(f.b.state, State::ProbeBwCruise);
        assert_eq!(f.b.pacing_gain, 1.0);
        // Paced at the bandwidth, 1% under.
        assert_eq!(f.b.pacing_rate(), Some(3_960_000));
    }

    /// Drain gives up after three rounds even if the queue stays.
    #[test]
    fn drain_ends_after_three_rounds() {
        let mut f = Feed::new();
        for _ in 0..4 {
            f.round(1_000_000, 400_000, false);
        }
        assert_eq!(f.b.state, State::Drain);
        for _ in 0..3 {
            f.round(1_000_000, 400_000, false);
        }
        assert_eq!(f.b.state, State::Drain);
        f.round(1_000_000, 400_000, false);
        assert!(f.b.state.is_probe_bw());
    }

    fn in_probe_bw(rate: u64) -> Feed {
        let mut f = Feed::new();
        for _ in 0..5 {
            f.round(rate, 0, false);
        }
        assert!(f.b.state.is_probe_bw(), "{:?}", f.b.state);
        f
    }

    /// The ProbeBW cycle: cruise, refill after 2 to 3 seconds (the BDP is
    /// too large for the Reno-coexistence bound to come first), a round of
    /// refill, up at a gain of 1.25, and down once the bandwidth stops
    /// growing.
    #[test]
    fn probe_bw_cycles_through_its_phases() {
        let rate = 100_000_000;
        let mut f = in_probe_bw(rate);
        let t0 = f.now;
        f.until(rate, State::ProbeBwCruise, 10);
        f.until(rate, State::ProbeBwRefill, 100);
        let waited = f.now.saturating_duration_since(t0);
        assert!(
            waited >= Duration::from_secs(2) && waited <= Duration::from_millis(3100),
            "{waited:?}"
        );
        assert_eq!(f.b.bw_shortterm, u64::MAX, "the short-term model reset");
        f.round(rate, 5_000_000, false);
        assert_eq!(f.b.state, State::ProbeBwUp, "after one round");
        assert_eq!((f.b.pacing_gain, f.b.cwnd_gain), (1.25, 2.25));
        // No more bandwidth to find: three rounds on, back down.
        let rounds = f.until(rate, State::ProbeBwDown, 10);
        assert!((3..=5).contains(&rounds), "{rounds}");
        assert_eq!(f.b.pacing_gain, 0.9);
    }

    /// Past 2% loss while probing, the probe stops and inflight_longterm
    /// bounds cwnd from there on (§5.5.10.2); 1% does not.
    #[test]
    fn loss_while_probing_sets_inflight_longterm() {
        let rate = 100_000_000;
        let bdp = (rate as f64 * RTT.as_secs_f64()) as u32;
        let mut f = in_probe_bw(rate);
        f.until(rate, State::ProbeBwUp, 100);
        assert_eq!(f.b.inflight_longterm, u64::MAX);
        // 1% of what was in flight: tolerated.
        f.lose(bdp / 100, bdp, 0);
        assert_eq!(f.b.state, State::ProbeBwUp);
        assert_eq!(f.b.inflight_longterm, u64::MAX);
        // 3%: too high.
        f.lose(bdp / 50, bdp, u64::from(bdp / 100));
        assert_eq!(f.b.state, State::ProbeBwDown);
        let hi = f.b.inflight_longterm;
        assert!(hi < u64::from(bdp) && hi > u64::from(bdp) * 9 / 10, "{hi}");
        assert!(f.b.prev_probe_too_high);
        f.round(rate, bdp / 2, false);
        assert!(u64::from(f.b.cwnd()) <= hi);
    }

    /// Outside probes, a round with loss pulls the short-term bounds down
    /// by at most 30% (β), towards what the round delivered.
    #[test]
    fn loss_in_cruise_cuts_the_short_term_model() {
        let rate = 100_000_000;
        let mut f = in_probe_bw(rate);
        f.until(rate, State::ProbeBwCruise, 100);
        // The round the loss shows up in delivered at the full rate; the
        // next, lossy too, at half of it.
        for _ in 0..2 {
            f.lose(1000, 5_000_000, 0);
            f.round(rate / 2, 2_500_000, false);
        }
        assert_eq!(f.b.bw_shortterm, (rate as f64 * BETA) as u64);
        assert!(f.b.pacing_rate().unwrap() <= (rate as f64 * BETA) as u64);
    }

    /// Five seconds without a lower RTT: ProbeRTT holds cwnd to half the
    /// BDP for 200 ms and a round, then cruises again (§5.3.4).
    #[test]
    fn probe_rtt_every_five_seconds() {
        let rate = 10_000_000;
        let bdp = (rate as f64 * RTT.as_secs_f64()) as u64;
        let mut f = in_probe_bw(rate);
        let t0 = f.now;
        f.until(rate, State::ProbeRtt, 200);
        let after = f.now.saturating_duration_since(t0);
        assert!(
            after >= Duration::from_millis(4700) && after <= Duration::from_millis(5100),
            "{after:?}"
        );
        assert!(u64::from(f.b.cwnd()) <= bdp / 2, "cwnd {}", f.b.cwnd());
        assert!(f.b.take_app_limited(), "its samples are not the path's");
        // Down to half a BDP in flight: 200 ms and a round from there.
        let start = f.now;
        for _ in 0..10 {
            f.round(rate, (bdp / 2) as u32, false);
            if f.b.state != State::ProbeRtt {
                break;
            }
        }
        let held = f.now.saturating_duration_since(start);
        assert!(held >= Duration::from_millis(200), "{held:?}");
        assert_eq!(f.b.state, State::ProbeBwCruise);
        assert!(u64::from(f.b.cwnd()) > bdp / 2, "cwnd restored");
    }

    /// Heavy loss in Startup: after a round in recovery with at least six
    /// ACKs reporting losses and a loss rate over 2%, Startup ends, and
    /// what was in flight bounds the flow.
    #[test]
    fn startup_exits_on_high_loss() {
        let mut f = Feed::new();
        f.round(1_000_000, 50_000, false);
        f.round(2_000_000, 100_000, false);
        f.b.on_loss(100_000);
        f.round(4_000_000, 200_000, false);
        f.round(8_000_000, 400_000, false);
        assert_eq!(f.b.state, State::Startup);
        // Seven ACKs within a round each report a loss; the eighth starts
        // the next round, with 9 kB of 400 kB lost since it was sent.
        let round_start = f.delivered;
        for i in 0..8 {
            f.lose(1000, 400_000, 0);
            f.now += Duration::from_millis(1);
            let rs = RateSample {
                delivery_rate: 16_000_000,
                delivered: 10_000,
                interval: RTT,
                prior_delivered: if i < 7 { 0 } else { round_start },
                is_app_limited: false,
                tx_in_flight: 400_000,
                lost: 1000 * (i + 2),
            };
            f.delivered += 10_000;
            let a = Ack {
                rs: Some(rs),
                newly_acked: 10_000,
                newly_lost: 1000,
                inflight: 400_000,
                delivered: f.delivered,
                newest_rtt: Some(RTT),
                ..Ack::of(f.now, 10_000, 400_000)
            };
            f.b.on_ack(&a);
            if i < 7 {
                assert_eq!(f.b.state, State::Startup, "ACK {i}");
            }
        }
        // Through Drain at once: 400 kB is under the BDP at 16 MB/s.
        assert!(f.b.state.is_probe_bw(), "{:?}", f.b.state);
        assert!(f.b.full_bw_reached);
        assert_eq!(f.b.inflight_longterm, f.b.bdp());
    }

    /// A loss episode found spurious puts back cwnd, the bounds and the
    /// probe it cut short (§5.5.11).
    #[test]
    fn spurious_loss_is_undone() {
        let rate = 100_000_000;
        let bdp = (rate as f64 * RTT.as_secs_f64()) as u32;
        let mut f = in_probe_bw(rate);
        f.until(rate, State::ProbeBwUp, 100);
        let cwnd = f.b.cwnd();
        f.b.on_loss(bdp);
        f.lose(bdp / 20, bdp, 0);
        assert_eq!(f.b.state, State::ProbeBwDown);
        f.b.undo(0, 0);
        assert_eq!(f.b.state, State::ProbeBwRefill, "back to probing");
        assert_eq!(f.b.inflight_longterm, u64::MAX);
        assert!(f.b.cwnd() >= cwnd);
    }

    /// After a timeout cwnd starts from a segment; recovery's end brings
    /// back the window from before it.
    #[test]
    fn timeout_and_recovery_exit() {
        let rate = 10_000_000;
        let mut f = in_probe_bw(rate);
        f.until(rate, State::ProbeBwCruise, 100);
        let cwnd = f.b.cwnd();
        f.b.on_retransmit_timeout(cwnd, false);
        assert_eq!(f.b.cwnd(), MSS);
        f.b.on_recovery_exit();
        assert_eq!(f.b.cwnd(), cwnd);
    }
}
