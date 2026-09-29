//! A snapshot of a connection's internals, for diagnosis: Linux's `struct
//! tcp_info` (`getsockopt(TCP_INFO)`, what `ss -ti` prints), in the terms
//! of this engine.
//!
//! Throughput below what a path should carry has one of a handful of
//! causes, and each leaves its mark here: a window that stopped growing
//! (`cwnd`, `ssthresh`, how slow start ended), losses and whether they were
//! real (`total_retrans`, `dsack_dups`, `undos`), a pacing rate short of
//! the window's (`pacing_rate` against `cwnd / srtt`), or a sender held
//! back by something other than congestion control: the receiver's window
//! (`rwnd_limited`), its own send buffer (`sndbuf_limited`), or the
//! application (`delivery_rate_app_limited`).

use super::conn::State;
use super::ecn::EcnMode;
use crate::time::Instant;
use std::time::Duration;

/// Where loss recovery stands (Linux's `tcpi_ca_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaState {
    /// Nothing is amiss.
    Open,
    /// Something is SACKed or duplicate-ACKed, but nothing is yet deemed
    /// lost: reordering, or a loss RACK has yet to call.
    Disorder,
    /// The window is coming down for ECN congestion marks, with nothing to
    /// resend.
    Cwr,
    /// Fast recovery: losses found by RACK or duplicate ACKs are being
    /// repaired.
    Recovery,
    /// Recovery after a retransmission timeout.
    Loss,
}

/// Where HyStart++ (RFC 9406), CUBIC's first slow start, stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HyStartPhase {
    /// Standard slow start: the window doubles every round trip.
    SlowStart,
    /// Conservative Slow Start: the round trip rose, and the window grows
    /// by a quarter as fast until the rise goes away or lasts long enough
    /// to end slow start.
    Conservative,
    /// Slow start is over (see [`TcpInfo::slow_start_exit`]).
    Done,
}

/// What ended the first slow start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlowStartExit {
    /// HyStart++: the round trip stayed up through Conservative Slow
    /// Start's rounds, so the bottleneck's queue was filling.
    Delay,
    /// A loss.
    Loss,
    /// An ECN congestion mark.
    Ecn,
    /// A retransmission timeout.
    Timeout,
}

/// A connection's state and counters at one moment: see
/// [`Conn::info`](super::Conn::info). Modelled on Linux's `struct
/// tcp_info`; sizes are in bytes unless a name says segments, times since
/// the connection was made.
///
/// Counters count from the start of the connection and do not wrap in
/// practice (u64). Fields that need a measurement (a round trip, a rate)
/// are `None` until there is one.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TcpInfo {
    /// The connection's state.
    pub state: State,
    /// Where loss recovery stands.
    pub ca_state: CaState,
    /// The congestion controller: `"cubic"`, `"reno"`, `"highspeed"` or
    /// `"bbr"`.
    pub congestion: &'static str,
    /// The congestion window.
    pub cwnd: u32,
    /// The congestion window in segments of [`snd_mss`](Self::snd_mss),
    /// rounded down (Linux's `tcpi_snd_cwnd`).
    pub cwnd_segs: u32,
    /// The slow start threshold; `None` while it is still infinite, before
    /// the first slow start has ended.
    pub ssthresh: Option<u32>,
    /// The MSS we send with.
    pub snd_mss: u32,
    /// The largest segment the peer has sent us (up to our MSS).
    pub rcv_mss: u32,
    /// The path MTU we send for.
    pub path_mtu: u32,
    /// The window scale shifts the handshake agreed on (RFC 7323 §2): the
    /// peer's, which its windows are scaled by, and ours. `None` when
    /// either end did not offer window scaling. Linux's `tcpi_snd_wscale`
    /// and `tcpi_rcv_wscale`, with `TCPI_OPT_WSCALE`.
    pub wscale: Option<(u8, u8)>,
    /// SACK (RFC 2018) was agreed on (`TCPI_OPT_SACK`).
    pub sack: bool,
    /// Timestamps (RFC 7323) were agreed on (`TCPI_OPT_TIMESTAMPS`).
    pub timestamps: bool,
    /// Fast Open (RFC 7413) data in the SYN was taken: the server's
    /// SYN-ACK acknowledged the data of our SYN, or, as the server, we
    /// took the data of the peer's (`TCPI_OPT_SYN_DATA`).
    pub syn_data: bool,
    /// Smoothed round-trip time (RFC 6298).
    pub srtt: Option<Duration>,
    /// Round-trip time variation (RFC 6298).
    pub rttvar: Option<Duration>,
    /// The least round trip seen lately (RACK's windowed minimum).
    pub min_rtt: Option<Duration>,
    /// The retransmission timeout, backoff included.
    pub rto: Duration,
    /// Consecutive timeouts of the current segment (Linux's
    /// `tcpi_backoff`).
    pub backoff: u32,
    /// The receiver's own estimate of the round trip, which receive buffer
    /// auto-tuning goes by (Linux's `tcpi_rcv_rtt`).
    pub rcv_rtt: Option<Duration>,
    /// What auto-tuning last measured the application reading in a round
    /// trip (Linux's `tcpi_rcv_space`).
    pub rcv_space: usize,

    /// Data bytes sent, retransmissions included (`tcpi_bytes_sent`).
    pub bytes_sent: u64,
    /// Data bytes retransmitted (`tcpi_bytes_retrans`).
    pub bytes_retrans: u64,
    /// Data bytes cumulatively acknowledged (`tcpi_bytes_acked`).
    pub bytes_acked: u64,
    /// Data bytes received in order (`tcpi_bytes_received`).
    pub bytes_received: u64,
    /// Segments sent, pure ACKs and control segments included.
    pub segs_out: u64,
    /// Segments received.
    pub segs_in: u64,
    /// Segments sent carrying data, retransmissions included.
    pub data_segs_out: u64,
    /// Segments received carrying data.
    pub data_segs_in: u64,
    /// Segments retransmitted (`tcpi_total_retrans`).
    pub total_retrans: u64,
    /// Retransmission timeouts that fired.
    pub timeouts: u64,
    /// Fast recovery episodes entered.
    pub recoveries: u64,
    /// Bytes currently deemed lost and not yet resent.
    pub lost: u32,
    /// Bytes currently SACKed above SND.UNA.
    pub sacked: u32,
    /// Bytes in flight: sent, and neither acknowledged, SACKed nor deemed
    /// lost (RFC 6675's pipe).
    pub in_flight: u32,
    /// Segments found delivered out of order (`tcpi_reord_seen` counts
    /// episodes; this counts segments).
    pub reord_seen: u64,
    /// D-SACKs received: data the peer got twice (`tcpi_dsack_dups`).
    pub dsack_dups: u64,
    /// Loss responses undone as spurious (by D-SACK, Eifel or F-RTO).
    pub undos: u64,

    /// The pacing rate, in bytes per second; `None` when not pacing.
    pub pacing_rate: Option<u64>,
    /// The latest delivery rate sample, in bytes per second.
    pub delivery_rate: Option<u64>,
    /// That sample was taken while the application, not the network, set
    /// the pace: it understates the path.
    pub delivery_rate_app_limited: bool,
    /// Bytes delivered to the peer, SACKed or acknowledged.
    pub delivered: u64,
    /// Of those, bytes the peer reported CE-marked.
    pub delivered_ce: u64,

    /// The send buffer's size now, grown by auto-tuning.
    pub send_buf: usize,
    /// The receive buffer's size now, grown by auto-tuning.
    pub recv_buf: usize,
    /// What auto-tuning has grown both buffers by, together, from the
    /// process-wide budget.
    pub autotune_grown: usize,
    /// Bytes written by the application and not yet sent.
    pub send_queued: usize,
    /// Bytes sent and not yet acknowledged.
    pub unacked: u32,
    /// Bytes received and not yet read by the application.
    pub recv_queued: usize,
    /// The peer's window (SND.WND).
    pub snd_wnd: u32,
    /// The window we advertise (RCV.WND).
    pub rcv_wnd: u32,

    /// HyStart++'s phase; `None` for a controller other than CUBIC.
    pub hystart: Option<HyStartPhase>,
    /// What ended the first slow start, once it has ended.
    pub slow_start_exit: Option<SlowStartExit>,
    /// cwnd when the first slow start ended.
    pub slow_start_exit_cwnd: Option<u32>,
    /// Times HyStart++ entered Conservative Slow Start: more than one
    /// means round-trip rises that went away again.
    pub hystart_css_entries: u32,

    /// The ECN feedback the handshake settled on: [`EcnMode::Off`],
    /// [`EcnMode::Classic`] or [`EcnMode::Accurate`].
    pub ecn: EcnMode,
    /// Segments received CE-marked.
    pub ce_received: u64,
    /// Window reductions for ECN feedback.
    pub ecn_reductions: u64,

    /// Time spent with data to send or in flight (`tcpi_busy_time`), the
    /// two limited times below included.
    pub busy_time: Duration,
    /// Of that, time data waited on the peer's window
    /// (`tcpi_rwnd_limited`): the receiver's buffer, or its application,
    /// held the transfer back.
    pub rwnd_limited: Duration,
    /// Of that, time everything written had been sent while the
    /// application had more to write (`tcpi_sndbuf_limited`): the send
    /// buffer was too small to keep the window full.
    pub sndbuf_limited: Duration,
}

/// What the sender is doing, for the times in [`TcpInfo`] (Linux's
/// `tcp_chrono`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Chrono {
    Idle,
    Busy,
    RwndLimited,
    SndbufLimited,
}

/// Time spent in each [`Chrono`] but idle.
#[derive(Debug)]
pub(crate) struct Chronos {
    cur: Chrono,
    since: Instant,
    busy: Duration,
    rwnd: Duration,
    sndbuf: Duration,
}

impl Chronos {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            cur: Chrono::Idle,
            since: now,
            busy: Duration::ZERO,
            rwnd: Duration::ZERO,
            sndbuf: Duration::ZERO,
        }
    }

    fn slot(&mut self, c: Chrono) -> Option<&mut Duration> {
        match c {
            Chrono::Idle => None,
            Chrono::Busy => Some(&mut self.busy),
            Chrono::RwndLimited => Some(&mut self.rwnd),
            Chrono::SndbufLimited => Some(&mut self.sndbuf),
        }
    }

    /// The sender is now doing `c`.
    #[inline]
    pub(crate) fn set(&mut self, c: Chrono, now: Instant) {
        if c == self.cur {
            return;
        }
        let d = now.saturating_duration_since(self.since);
        if let Some(t) = self.slot(self.cur) {
            *t += d;
        }
        self.cur = c;
        self.since = now;
    }

    /// Busy (all of it), receive-window-limited and send-buffer-limited
    /// time up to `now`.
    pub(crate) fn totals(&self, now: Instant) -> (Duration, Duration, Duration) {
        let (mut busy, mut rwnd, mut sndbuf) = (self.busy, self.rwnd, self.sndbuf);
        let d = now.saturating_duration_since(self.since);
        match self.cur {
            Chrono::Idle => {}
            Chrono::Busy => busy += d,
            Chrono::RwndLimited => rwnd += d,
            Chrono::SndbufLimited => sndbuf += d,
        }
        (busy + rwnd + sndbuf, rwnd, sndbuf)
    }
}

/// The counters behind [`TcpInfo`], bumped as things happen.
#[derive(Debug, Default)]
pub(crate) struct Counters {
    pub bytes_sent: u64,
    pub bytes_retrans: u64,
    pub bytes_acked: u64,
    pub bytes_received: u64,
    pub segs_out: u64,
    pub segs_in: u64,
    pub data_segs_out: u64,
    pub data_segs_in: u64,
    pub total_retrans: u64,
    pub timeouts: u64,
    pub recoveries: u64,
    pub dsack_dups: u64,
    pub undos: u64,
    pub ce_received: u64,
    pub ecn_reductions: u64,
    /// The latest delivery rate sample worth reporting, and whether it
    /// was application-limited.
    pub delivery_rate: Option<(u64, bool)>,
    /// What scoreboards since replaced (at the end of the connection)
    /// counted delivered, and delivered CE-marked.
    pub delivered_before: u64,
    pub delivered_ce_before: u64,
    /// The minimum RTT the scoreboard it replaced had seen, which the
    /// new one, with no samples of its own, would otherwise lose.
    pub min_rtt_before: Option<std::time::Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chronos_add_up_limited_time_into_busy() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut c = Chronos::new(t0);
        c.set(Chrono::Busy, t0 + ms(10));
        c.set(Chrono::RwndLimited, t0 + ms(30));
        c.set(Chrono::RwndLimited, t0 + ms(35));
        c.set(Chrono::SndbufLimited, t0 + ms(40));
        c.set(Chrono::Idle, t0 + ms(45));
        assert_eq!(c.totals(t0 + ms(100)), (ms(35), ms(10), ms(5)));
        c.set(Chrono::Busy, t0 + ms(100));
        assert_eq!(c.totals(t0 + ms(110)), (ms(45), ms(10), ms(5)));
    }
}
