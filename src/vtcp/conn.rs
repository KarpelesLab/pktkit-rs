//! TCP connection state machine.
//!
//! This is a synchronous, callback-style port of the Go upstream's `Conn`.
//! Rather than asynchronous timers and condvars, the connection exposes a
//! [`tick`](Conn::tick) method that the caller invokes when
//! [`next_deadline`](Conn::next_deadline) comes due, to drive
//! retransmission, persist, keepalive, and TIME-WAIT timeouts. All outgoing
//! segments are returned from methods as `Vec<Vec<u8>>` — the caller is
//! responsible for wrapping each in IP+L2 and pushing it on the wire.
//!
//! The state machine follows RFC 9293 §3.10 (the rolled-up RFC 793 +
//! errata). Window scaling, SACK, and timestamps are all negotiated during
//! the handshake; congestion control plugs in via the [`CongestionController`]
//! trait.

use crate::time::Instant;
use std::net::SocketAddr;
use std::time::Duration;

use super::autotune::{self, Budget, RcvSpace};
use super::bbr::Bbr;
use super::congestion::{Ack, CongestionController, HighSpeed, Lost, NewReno, initial_window};
use super::cubic::Cubic;
use super::cwv::{self, PipeAck};
use super::ecn::{Ecn, EcnMode, IpEcn};
use super::fastopen::{self, FastOpen, Gate};
use super::options::{
    self, SackBlock, TcpOption, get_sack_blocks, get_timestamp, get_wscale, has_sack_perm,
    mss_option, sack_option, sack_perm_option, timestamp_option, wscale_option,
};
use super::plpmtud::{self, MtuProbing, Probe, Search};
use super::rate::RateSample;
use super::recvbuf::RecvBuf;
use super::rto::{DEFAULT_RTO, MAX_RTO, RtoState};
use super::scoreboard::{DUP_THRESH, Delivery, Scoreboard, dsack_block};
use super::segment::{Segment, flags};
use super::sendbuf::SendBuf;
use super::seqspace::{
    seq_after, seq_after_eq, seq_before, seq_before_eq, seq_in_range, seq_in_range_inclusive,
};

// --- Tunables -------------------------------------------------------------

/// Default MSS: the largest segment we accept, and send when the peer
/// allows it.
pub const DEFAULT_MSS: u16 = 1460;
/// Default advertised window when no SACK / Window Scale negotiated.
pub const DEFAULT_WINDOW_SIZE: u16 = 65535;
/// Default initial send buffer, 1 MiB: enough for a link of short round
/// trip without auto-tuning having to grow it.
pub const DEFAULT_SEND_BUF: usize = 1 << 20;
/// Default initial receive buffer, 1 MiB.
pub const DEFAULT_RECV_BUF: usize = 1 << 20;
/// Default most auto-tuning grows the send buffer to, 16 MiB: a window of
/// over 500 Mbit/s at a 250 ms round trip.
pub const DEFAULT_SEND_BUF_MAX: usize = 16 << 20;
/// Default most auto-tuning grows the receive buffer to, 16 MiB.
pub const DEFAULT_RECV_BUF_MAX: usize = 16 << 20;

/// Maximum retransmission attempts before declaring the connection dead.
pub const MAX_RETRIES: u32 = 8;
/// Zero-window probes a [released](Conn::release) connection sends before
/// giving up, answered or not (Linux's `tcp_orphan_retries`, 8 by default).
/// A connection with an application behind it probes a peer that keeps
/// answering for as long as it takes (RFC 9293 §3.8.6.1); one that nobody
/// will ever write to or read from again would otherwise be kept alive for
/// good by a peer that never opens its window. With the probe interval
/// doubling from the RTO up to [`MAX_RTO`], that is a few minutes.
pub const ORPHAN_RETRIES: u32 = 8;
/// Default TIME-WAIT length. RFC 9293 asks for 2*MSL (4 minutes); this is
/// Linux's 60 s, long enough for a delayed segment of the old connection to
/// die out before a new one can take its 4-tuple. A new connection that
/// needs the 4-tuple sooner can have it (see [`Conn::accepts_new_syn`]).
pub const TIME_WAIT_DURATION: Duration = Duration::from_secs(60);
/// The least a sender waits before acting on SACKs the receiver has
/// reneged on: Linux's, in `tcp_check_sack_reneging`.
const RENEGE_DELAY: Duration = Duration::from_millis(10);
/// What a loss probe allows for the delayed ACK of a lone segment (RFC
/// 8985 §7.2's TLP.max_ack_delay): Linux's, `TCP_RTO_MIN`, which covers
/// the 200 ms some receivers delay by.
const TLP_MAX_ACK_DELAY: Duration = Duration::from_millis(200);
/// Slack on a loss probe of more than one segment, as Linux's
/// `TCP_TIMEOUT_MIN`: at short round trips two SRTTs are within the jitter
/// of the ACK path and the timer's own wake-up, and a probe would go out
/// before ACKs already on their way.
const TLP_MIN_SLACK: Duration = Duration::from_millis(2);
/// How long an ACK may be delayed: Linux's `TCP_DELACK_MIN`, which is also
/// where its adaptive delay sits for anything but a slow trickle. RFC 9293
/// §3.8.6.3 allows up to 500 ms, and RFC 5681 §4.2 asks for less.
pub const DELAYED_ACK: Duration = Duration::from_millis(40);
/// Most segments ACKed at once in quick-ACK mode (Linux's
/// `TCP_MAX_QUICKACKS`).
const MAX_QUICKACKS: u32 = 16;
/// Minimum spacing of challenge ACKs and out-of-window duplicate ACKs on one
/// connection (RFC 5961 §7); Linux's `tcp_invalid_ratelimit` default.
const OOW_ACK_INTERVAL: Duration = Duration::from_millis(500);
/// How long TS.Recent stays valid without being updated (RFC 7323 §5.5).
/// A peer's timestamp clock may tick as fast as once per millisecond, so
/// after about 24.8 days an idle connection's TS.Recent can no longer be
/// compared with the peer's TSvals: they may have wrapped past it.
const PAWS_IDLE: Duration = Duration::from_secs(24 * 24 * 60 * 60);

pub const DEFAULT_KEEPALIVE_IDLE: Duration = Duration::from_secs(300);
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
pub const DEFAULT_KEEPALIVE_COUNT: u32 = 3;
/// Linux's `tcp_fin_timeout` default.
pub const DEFAULT_FIN_WAIT2_TIMEOUT: Duration = Duration::from_secs(60);

/// The smallest IPv4 path MTU a Fragmentation Needed message can bring the
/// connection down to: Linux's `ip_rt_min_pmtu`, room for 512 bytes of
/// data. RFC 1191 §3 only forbids going below 68, but no real path is that
/// narrow, and anyone able to send an ICMP message could otherwise have
/// the connection spend 40 bytes of headers on every few bytes of data.
pub const IPV4_MIN_PATH_MTU: u32 = 552;
/// IPv6's minimum link MTU (RFC 8200 §5), below which a Packet Too Big
/// never takes the path MTU (RFC 8201 §4).
pub const IPV6_MIN_PATH_MTU: u32 = 1280;
/// RFC 1191 §7's plateau table: where to go from a Fragmentation Needed
/// message that reports no next-hop MTU, as a router older than RFC 1191
/// sends.
const MTU_PLATEAUS: [u32; 10] = [32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68];

// --- TCP state -------------------------------------------------------------

/// TCP state per RFC 9293 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No connection: not yet opened, or finished.
    Closed,
    /// Waiting for a SYN.
    Listen,
    /// SYN sent ([`Conn::connect`]), waiting for the SYN-ACK.
    SynSent,
    /// SYN received and SYN-ACK sent, waiting for the final ACK.
    SynReceived,
    /// Open: data flows both ways.
    Established,
    /// We closed; our FIN is not yet acknowledged.
    FinWait1,
    /// We closed and our FIN is acknowledged; waiting for the peer's.
    FinWait2,
    /// The peer closed; we may still send until we close.
    CloseWait,
    /// Both sides closed at once; waiting for our FIN's ACK.
    Closing,
    /// The peer closed first, then we did; waiting for our FIN's ACK.
    LastAck,
    /// Both FINs exchanged; waiting out stray segments before the 4-tuple
    /// can be reused ([`ConnConfig::time_wait`]).
    TimeWait,
}

impl State {
    /// True in the states past the handshake (RFC 9293's synchronized
    /// states): ESTABLISHED and every closing state.
    pub fn is_synchronized(self) -> bool {
        matches!(
            self,
            State::Established
                | State::FinWait1
                | State::FinWait2
                | State::CloseWait
                | State::Closing
                | State::LastAck
                | State::TimeWait
        )
    }
}

/// Where loss recovery stands (Linux's `icsk_ca_state`, less its CWR and
/// Disorder, which nothing here needs apart).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaState {
    /// Nothing deemed lost.
    Open,
    /// Fast recovery (RFC 6675 §5): losses found by RACK, or by duplicate
    /// ACKs without SACK, are being repaired.
    Recovery,
    /// Recovery after a retransmission timeout (RFC 5681 §3.1).
    Loss,
}

/// F-RTO (RFC 5682): after a timeout, whether the next ACKs show it was
/// spurious, before resending everything the timeout marked lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frto {
    Off,
    /// Step 2: waiting for the ACK of the segment the timeout resent,
    /// which ended at `head_end`.
    First {
        head_end: u32,
    },
    /// Step 3: new data went out instead of retransmissions; waiting for
    /// the next ACK. `rp` is RecoveryPoint, SND.NXT at step 2.
    Second {
        rp: u32,
    },
}

/// A loss response, kept so it can be undone if it turns out spurious
/// (Linux's `undo_marker` and what goes with it).
#[derive(Debug, Default)]
struct Undo {
    /// SND.UNA when the episode began; `None` when nothing is to undo.
    marker: Option<u32>,
    /// RFC 4015 step (0): pipe_prev = max(FlightSize, ssthresh), what
    /// ssthresh goes back to.
    pipe_prev: u32,
    /// Whether the episode includes a timeout, and SRTT (plus two ticks of
    /// the clock) and RTTVAR before it, for RFC 4015 step (11).
    timeout: bool,
    srtt_prev: Duration,
    rttvar_prev: Duration,
    /// TSval of the episode's first retransmission: RFC 3522's
    /// RetransmitTS.
    retrans_ts: Option<u32>,
    /// The first ACK of that retransmission, which ends here, has not come
    /// yet: the one Eifel looks at. `None` once it has.
    eifel_end: Option<u32>,
    /// What the episode retransmitted and no D-SACK has reported yet (RFC
    /// 3708); `None` once there is too much to follow.
    retrans: Option<Vec<(u32, u32)>>,
}

/// Retransmitted ranges followed per episode for D-SACK undo.
const MAX_UNDO_RANGES: usize = 256;
/// The clock granularity RFC 4015 step (0) pads SRTT_prev with: the
/// timestamp clock's millisecond.
const CLOCK_TICK: Duration = Duration::from_millis(1);

/// What an ACK said, for loss recovery.
#[derive(Debug, Clone, Copy)]
struct AckEvent {
    ack: u32,
    /// It advanced SND.UNA, by `acked` bytes.
    advanced: bool,
    acked: u32,
    /// What the scoreboard counted newly delivered.
    d: Delivery,
    dsack: Option<SackBlock>,
    /// A duplicate ACK (RFC 5681 §2).
    dup: bool,
    /// Bytes outstanding before it.
    flight: u32,
    /// Its TSecr, if any.
    ecr: Option<u32>,
    /// The round trip it measured, if any.
    rtt: Option<Duration>,
    /// Its delivery rate sample, if it delivered anything.
    rs: Option<RateSample>,
    /// Its ECN feedback reports CE marks.
    ce: bool,
}

/// Choice of congestion controller.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum CongestionKind {
    /// CUBIC (RFC 9438), with HyStart++ (RFC 9406) in its first slow
    /// start: Linux's default, and this one's. After a loss it regrows
    /// the window along a cubic curve of the time since, which fills a
    /// long, fast path far sooner than a segment per round trip does,
    /// and is no slower than NewReno where NewReno does well.
    #[default]
    Cubic,
    /// NewReno (RFC 5681, with RFC 6582's partial-ACK handling).
    NewReno,
    /// HighSpeed TCP (RFC 3649).
    HighSpeed,
    /// BBR (draft-ietf-ccwg-bbr, "BBRv3"): paces at a model of the path's
    /// bottleneck bandwidth, with about a bandwidth-delay product in flight,
    /// instead of growing the window until a queue overflows. It keeps the
    /// bottleneck's queue short, and holds its rate through random loss
    /// below 2% that would cut a loss-based controller's to a fraction:
    /// the choice for long, lossy paths. It always paces, whatever
    /// [`ConnConfig::pacing`] says. Not the default, as it is not on
    /// Linux: at a shallow bottleneck queue it can take more than its share
    /// from CUBIC flows, which read its losses as congestion where it does
    /// not.
    Bbr,
}

/// A controller of `kind` for segments of `mss` bytes, told whether
/// sending is paced.
fn make_cc(
    kind: CongestionKind,
    mss: u32,
    paced: bool,
    now: Instant,
) -> Box<dyn CongestionController> {
    let mut cc: Box<dyn CongestionController> = match kind {
        CongestionKind::Cubic => Box::new(Cubic::new(mss)),
        CongestionKind::NewReno => Box::new(NewReno::new(mss)),
        CongestionKind::HighSpeed => Box::new(HighSpeed::new(mss)),
        CongestionKind::Bbr => Box::new(Bbr::new(mss, now)),
    };
    cc.set_paced(paced || cc.model_based());
    cc
}

/// Connection configuration.
///
/// Build one from `ConnConfig::default()` with the chainable setters:
/// `ConnConfig::default().local_port(40000).remote_port(80)`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConnConfig {
    /// Our address. The engine never writes IP headers; the addresses key
    /// the initial sequence number, and give the address family the path
    /// MTU floor depends on. `None` by default.
    pub local_addr: std::option::Option<SocketAddr>,
    /// The peer's address, as for `local_addr`. `None` by default.
    pub remote_addr: std::option::Option<SocketAddr>,
    /// Our TCP port.
    pub local_port: u16,
    /// The peer's TCP port.
    pub remote_port: u16,
    /// The largest segment we accept, advertised in our SYN, and the cap
    /// on what we send. 1460 by default.
    pub mss: u16,
    /// Do not offer window scaling (RFC 7323), which is offered by default.
    pub no_window_scaling: bool,
    /// Offer timestamps (RFC 7323); used only if the peer offers them too.
    /// On by default, as on Linux: they give an RTT sample with every ACK,
    /// which a retransmission cannot make ambiguous, and PAWS against old
    /// duplicates once sequence numbers wrap. They cost 12 bytes of every
    /// segment.
    pub enable_timestamps: bool,
    /// Offer SACK (RFC 2018); used only if the peer offers it too. On by
    /// default: without it a receiver can only report the first hole in the
    /// stream, a sender repairs one hole per round trip, and neither RACK
    /// nor the tail loss probe (RFC 8985), which need it, can run.
    pub enable_sack: bool,
    /// The congestion controller. CUBIC by default.
    pub congestion: CongestionKind,
    /// Pace sending (as Linux's `fq` does, or its internal pacing): spread
    /// each round trip's data over the round trip at about the rate cwnd
    /// allows (twice cwnd/SRTT in slow start, 1.2 times after), a
    /// millisecond's worth at a time, rather than send what each ACK lets
    /// go at once. Bursts that overflow a shallow bottleneck queue go away,
    /// slow start's included. The timer it runs on is part of
    /// [`Conn::next_deadline`]. BBR paces whatever this says. On by
    /// default.
    pub pacing: bool,
    /// Start again from the initial window after sending nothing for an
    /// RTO (RFC 5681 §4.1): the window halves for every RTO of the spell,
    /// down to the initial window, as on Linux with
    /// `tcp_slow_start_after_idle` (on by default there too). What the
    /// path carried before a pause is no measure of what it will take
    /// after, and a full window sent at once may overflow a queue others
    /// have filled meanwhile. Off, the window is kept for up to five
    /// minutes of disuse, as RFC 7661 allows. On by default.
    pub slow_start_after_idle: bool,
    /// Probe an idle connection with keepalives. Off by default.
    pub keepalive: bool,
    /// Idle time before the first keepalive probe. 300 s by default.
    pub keepalive_idle: Duration,
    /// Time between unanswered keepalive probes. 15 s by default.
    pub keepalive_interval: Duration,
    /// Unanswered keepalive probes before the connection is reset. 3 by
    /// default.
    pub keepalive_count: u32,
    /// Initial send buffer size in bytes: written data queued or not yet
    /// acknowledged. [Auto-tuning](Self::autotune) grows it up to
    /// `send_buf_max`. 1 MiB by default.
    pub send_buf_size: usize,
    /// Initial receive buffer size in bytes, which bounds the advertised
    /// window. [Auto-tuning](Self::autotune) grows it up to
    /// `recv_buf_max`. 1 MiB by default.
    pub recv_buf_size: usize,
    /// The most auto-tuning grows the send buffer to. At or below
    /// `send_buf_size`, the send buffer keeps that size. 16 MiB by default.
    pub send_buf_max: usize,
    /// The most auto-tuning grows the receive buffer to, which also sets
    /// the window scale offered in the handshake (RFC 7323): the window
    /// can only grow as far as that lets it be advertised. At or below
    /// `recv_buf_size`, the receive buffer keeps that size. 16 MiB by
    /// default.
    pub recv_buf_max: usize,
    /// Grow the buffers as the path needs, as Linux does. The receive
    /// buffer follows what the application reads per round trip (dynamic
    /// right-sizing), to twice that and more, so the window never holds a
    /// sender back that the application keeps up with; the send buffer
    /// follows the congestion window, to twice it, so the application can
    /// keep a growing window full. Without it, a connection moves at most
    /// one buffer per round trip: 1 MiB at 250 ms is 33 Mbit/s.
    ///
    /// Buffers only grow while data flows, and go back to their initial
    /// sizes when the connection closes. What all connections grow by
    /// together is bounded process-wide (256 MiB); past that they stay as
    /// they are. On by default.
    pub autotune: bool,
    /// How long FIN-WAIT-2 may go without hearing from the peer before the
    /// connection is reset, once it has been [released](Conn::release).
    /// RFC 9293 §3.10.7.4 allows a timeout here; a peer that never sends
    /// its FIN would otherwise hold an abandoned connection forever. Like
    /// Linux's `tcp_fin_timeout`, it spares a mere half-close
    /// ([`Conn::close`]): the application is still reading, and the peer
    /// may send for as long as it likes. Measured from the release or the
    /// last segment received, whichever is later. `None` waits forever.
    /// 60 s by default.
    pub fin_wait2_timeout: Option<Duration>,
    /// How long TIME-WAIT lasts. 60 s by default, as on Linux; RFC 9293
    /// asks for 2*MSL (4 minutes).
    pub time_wait: Duration,
    /// Turn off the Nagle algorithm (RFC 9293 §3.7.4), as `TCP_NODELAY`
    /// does: a write shorter than a segment goes out at once even with data
    /// in flight, instead of waiting for it to be acknowledged. For
    /// request/response traffic that writes a message in pieces, or that
    /// cannot wait out a delayed ACK. Off by default;
    /// [`Conn::set_nodelay`] changes it on an open connection.
    pub nodelay: bool,
    /// Explicit Congestion Notification (RFC 3168, and RFC 9768's
    /// AccECN): whether to ask for it in the handshake, and accept it. By
    /// default a peer's request is accepted, and none made, as on Linux.
    /// The engine writes no IP headers: `vclient` and `slirp` set the
    /// codepoints it asks for, and pass on the marks that arrive.
    pub ecn: EcnMode,
    /// Packetization Layer Path MTU Discovery (RFC 4821): whether the
    /// connection finds the path MTU from what gets delivered, where ICMP
    /// messages do not tell it (see [`MtuProbing`]). By default, once
    /// full-sized segments keep timing out, as on Linux.
    pub mtu_probing: MtuProbing,
    /// TCP Fast Open (RFC 7413), for a connection opened with
    /// [`Conn::accept_syn`], as Linux's `TCP_FASTOPEN` does on a listener:
    /// a SYN asking for a cookie is given one, and the data of a SYN that
    /// brings a valid cookie back is taken at once, readable before the
    /// handshake completes, and the application may answer it straight
    /// away. A request and its response then take one round trip, not two.
    ///
    /// The cookie is a MAC of the peer's address, which proves the SYN
    /// comes from it, so `local_addr` and `remote_addr` must be set. At
    /// most 64 connections with such data wait for their handshake at a
    /// time (RFC 7413 §5.1); past that, a SYN's data waits for the
    /// handshake, as it does without Fast Open.
    ///
    /// Off by default, as on Linux, because the application has to be
    /// ready for what RFC 7413 §6 warns of: a SYN may be duplicated on the
    /// way, and its data delivered twice, to two connections. Only
    /// requests safe to repeat belong in a SYN. `vclient` sends them
    /// (see its `ClientConfig::tcp`).
    pub fast_open: bool,
}

setters! {
    ConnConfig {
        some local_addr: SocketAddr;
        some remote_addr: SocketAddr;
        set local_port: u16;
        set remote_port: u16;
        set mss: u16;
        set no_window_scaling: bool;
        set enable_timestamps: bool;
        set enable_sack: bool;
        set congestion: CongestionKind;
        set pacing: bool;
        set slow_start_after_idle: bool;
        set keepalive: bool;
        set keepalive_idle: Duration;
        set keepalive_interval: Duration;
        set keepalive_count: u32;
        set send_buf_size: usize;
        set recv_buf_size: usize;
        set send_buf_max: usize;
        set recv_buf_max: usize;
        set autotune: bool;
        set fin_wait2_timeout: Option<Duration>;
        set time_wait: Duration;
        set nodelay: bool;
        set ecn: EcnMode;
        set mtu_probing: MtuProbing;
        set fast_open: bool;
    }
}

impl Default for ConnConfig {
    fn default() -> Self {
        Self {
            local_addr: None,
            remote_addr: None,
            local_port: 0,
            remote_port: 0,
            mss: DEFAULT_MSS,
            no_window_scaling: false,
            enable_timestamps: true,
            enable_sack: true,
            congestion: CongestionKind::default(),
            pacing: true,
            slow_start_after_idle: true,
            keepalive: false,
            keepalive_idle: DEFAULT_KEEPALIVE_IDLE,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            keepalive_count: DEFAULT_KEEPALIVE_COUNT,
            send_buf_size: DEFAULT_SEND_BUF,
            recv_buf_size: DEFAULT_RECV_BUF,
            send_buf_max: DEFAULT_SEND_BUF_MAX,
            recv_buf_max: DEFAULT_RECV_BUF_MAX,
            autotune: true,
            fin_wait2_timeout: Some(DEFAULT_FIN_WAIT2_TIMEOUT),
            time_wait: TIME_WAIT_DURATION,
            nodelay: false,
            ecn: EcnMode::default(),
            mtu_probing: MtuProbing::default(),
            fast_open: false,
        }
    }
}

impl ConnConfig {
    /// The most the send buffer grows to.
    fn send_max(&self) -> usize {
        if self.autotune {
            self.send_buf_max.max(self.send_buf_size)
        } else {
            self.send_buf_size
        }
    }

    /// The most the receive buffer grows to.
    fn recv_max(&self) -> usize {
        if self.autotune {
            self.recv_buf_max.max(self.recv_buf_size)
        } else {
            self.recv_buf_size
        }
    }

    /// The window scale to offer: enough to advertise the largest receive
    /// buffer (RFC 7323 §2.3), so it can grow after the handshake has fixed
    /// the shift. But no coarser than half the initial buffer: the window
    /// is advertised in whole units, rounded up, so the buffer takes up to
    /// a unit more than its size, and a small one would take several times
    /// its size.
    fn rcv_wscale(&self) -> u8 {
        if self.no_window_scaling {
            return 0;
        }
        let max = self.recv_max();
        let mut shift = 0u8;
        while shift < 14 && max >> shift > 65535 {
            shift += 1;
        }
        while shift > 0 && 1usize << shift > self.recv_buf_size / 2 {
            shift -= 1;
        }
        shift
    }
}

/// A virtual TCP connection.
///
/// `Conn` is single-threaded; if you need to share it across threads, wrap it
/// in your own `Mutex`. All methods that produce outgoing wire bytes return
/// them as `Vec<Vec<u8>>` so the caller can decide how to actually transmit.
pub struct Conn {
    cfg: ConnConfig,

    state: State,
    closed: bool,

    // Send / receive buffers and sequence space.
    send_buf: std::option::Option<SendBuf>,
    recv_buf: std::option::Option<RecvBuf>,
    snd_wnd: u32, // remote advertised window (already scaled)
    /// MAX.SND.WND (RFC 5961 §5): the largest window the peer has offered,
    /// which bounds how far below SND.UNA a genuine ACK can be.
    max_snd_wnd: u32,
    mss: u16,
    /// The most the peer takes, and we send, whatever the path: the peer's
    /// MSS capped by ours (Linux's `mss_clamp`).
    mss_clamp: u16,
    /// The most the path lets us send with, from Packet Too Big messages
    /// (see [`Conn::set_path_mtu`]): caps `mss` from then on, the
    /// handshake's included.
    path_mss: u16,
    /// PLPMTUD's search (RFC 4821), which caps `mss` too while it runs.
    plpmtud: Search,
    /// Its probe in flight.
    mtu_probe: Option<Probe>,
    /// A timeout lowered the MSS for a suspected black hole, and its
    /// retransmission at the new size is on its way: if that is ACKed
    /// before another timeout, the losses were the segments' size, not
    /// congestion (see `undo_black_hole`).
    black_hole_undo: bool,
    cc: Box<dyn CongestionController>,

    // RTO management.
    rto: RtoState,
    rto_deadline: std::option::Option<Instant>,
    retries: u32,
    /// What is in flight, SACKed and deemed lost, segment by segment.
    score: Scoreboard,
    /// Where loss recovery stands.
    ca: CaState,
    /// RecoveryPoint (RFC 6675), RFC 6582's `recover`: SND.NXT when the
    /// current, or last, recovery episode began. Whatever was sent before
    /// it and is deemed lost is resent before new data, as the window
    /// allows, so a lost flight is repaired in a few round trips, not a
    /// hole per round trip.
    recover: u32,
    /// Our SYN or SYN-ACK timed out and was resent. The data transfer then
    /// starts from the loss window (RFC 5681 §3.1), not the initial window.
    syn_lost: bool,
    /// When we last answered an invalid segment (a challenge ACK or an
    /// out-of-window duplicate), for the RFC 5961 §7 throttle.
    last_oow_ack: std::option::Option<Instant>,
    /// Duplicate ACKs since the last new one, from a peer without SACK.
    dup_acks: u32,
    /// The segments those duplicates say left the network, in bytes
    /// (Linux's Reno `sacked_out`).
    reno_sacked: u32,
    /// What the current, or last, loss response would take undoing.
    undo: Undo,
    /// Where F-RTO stands.
    frto: Frto,
    /// RFC 4015 step (11) is due on the first RTT sample from data sent
    /// after a spurious timeout: SRTT_prev, RTTVAR_prev, and SND.NXT when
    /// the timeout fired.
    rto_adapt: Option<(Duration, Duration, u32)>,
    /// PRR (RFC 6937): bytes delivered and sent since fast recovery began,
    /// and the flight it began with.
    prr_delivered: u64,
    prr_out: u64,
    recover_fs: u32,
    /// RACK's reordering timer (RFC 8985 §5.4): when what was sent before
    /// the last delivered segment, and is not yet deemed lost, will be.
    reo_deadline: std::option::Option<Instant>,
    /// The tail loss probe timeout (RFC 8985 §7.2).
    pto_deadline: std::option::Option<Instant>,
    /// TLP.end_seq: SND.NXT when the probe in flight went out.
    tlp_end: Option<u32>,
    /// TLP.is_retrans: that probe resent the last segment.
    tlp_retrans: bool,
    /// Congestion window validation (RFC 7661): what the path has carried
    /// lately, and since when cwnd has been more than twice that (the
    /// non-validated phase).
    pipe_ack: PipeAck,
    nvp_since: Option<Instant>,
    /// When data last went out, for the restart after idle (Linux's
    /// `lsndtime`).
    last_data_sent: Option<Instant>,
    /// An RTT sample came in since the last probe (RFC 8985 §7.3), so
    /// probes cannot keep SRTT from following a longer path.
    rtt_sampled: bool,
    /// cwnd held back data that was ready to go since the last ACK (for
    /// BBR's C.is_cwnd_limited).
    cwnd_blocked: bool,
    /// Whether cwnd was in use over the current window of data, as Linux's
    /// tcp_cwnd_validate keeps it: cwnd held data back, or the most the
    /// window had in flight (`max_flight`), until SND.UNA passes
    /// `cwnd_usage_seq`, SND.NXT when the window began. What the
    /// controllers' growth goes by (RFC 7661): with pacing, what is in
    /// flight when an ACK comes is short of cwnd even for a sender that
    /// fills it, as the rest of the round's data waits on the pacer.
    is_cwnd_limited: bool,
    max_flight: u32,
    cwnd_usage_seq: u32,

    // Pacing: a token bucket filled at the pacing rate, holding up to two
    // send quanta (see `pace_quantum`).
    /// Bytes that may go now; negative once a segment overdrew it.
    pace_credit: f64,
    /// When the credit was last brought up to date.
    pace_stamp: Instant,
    /// When enough credit will have built up to send again, while data is
    /// held back by pacing alone.
    pace_deadline: std::option::Option<Instant>,
    /// The smoothed round trip pacing goes by: SRTT's average (1/8) of
    /// the send-to-ACK times of the newest segment each ACK delivers,
    /// taken to the nanosecond as Linux takes its SRTT to the microsecond.
    /// The RTO's SRTT will not do: its samples between timed segments come
    /// from timestamp echoes, rounded up to the millisecond, and a path
    /// shorter than that would be paced at a fraction of what it carries.
    pace_srtt: Option<Duration>,
    /// How late the pacing timer was when data it held back was last
    /// looked at again (see `pace_ready`).
    pace_late: Duration,

    // Delayed ACK (RFC 9293 §3.8.6.3, RFC 5681 §4.2).
    /// When the ACK held back for data received goes out on its own,
    /// unless something we send first carries it.
    delack_deadline: std::option::Option<Instant>,
    /// Segments still to be ACKed at once, not delayed (Linux's quick-ACK
    /// mode): at the start of the connection, after an idle spell, and
    /// after a duplicate, when the sender's window is small and waiting on
    /// every ACK.
    quick_acks: u32,
    /// Our data answers the peer's within a delayed ACK's time (Linux's
    /// ping-pong mode): the ACK rides on the answer, so quick ACKs would
    /// only add segments. Ends when a delayed ACK has to go out alone.
    pingpong: bool,
    /// The largest segment the peer has sent, up to our MSS (Linux's
    /// `rcv_mss`): how "full-sized" is measured.
    rcv_mss: u32,
    /// When data last came in.
    last_data_recv: std::option::Option<Instant>,
    /// A segment shorter than `rcv_mss` is among those not yet ACKed: a
    /// sender with Nagle on holds its next one back until this ACK.
    ack_pushed: bool,

    // Buffer auto-tuning.
    /// Where buffer growth is drawn from, process-wide.
    budget: &'static Budget,
    /// What this connection's buffers have grown by, drawn from `budget`.
    grown: usize,
    /// The application's last write did not fit the send buffer (Linux's
    /// `SOCK_NOSPACE`): only then can a larger one help.
    snd_nospace: bool,
    /// Dynamic right-sizing of the receive buffer.
    rcv_space: RcvSpace,

    // Window scaling (RFC 7323).
    snd_wnd_shift: u8,
    rcv_wnd_shift: u8,
    wscale_ok: bool,

    // Timestamps.
    ts_enabled: bool,
    ts_ok: bool,
    ts_recent: u32,
    /// When TS.Recent was last set, for the PAWS idle rule (RFC 7323 §5.5).
    ts_recent_stamp: Instant,
    /// TSval is milliseconds since `ts_base` plus `ts_offset`: monotonic,
    /// since a wall clock stepped back by NTP would have the peer's PAWS
    /// drop everything we send, and offset so TSvals do not reveal the
    /// host's clock (RFC 7323 §7.1). The clock is the process's and the
    /// offset is per pair of addresses, not per connection, as on Linux:
    /// a new connection to a host then carries TSvals past the last one's,
    /// which is what lets its SYN take over a 4-tuple in TIME-WAIT (RFC
    /// 6191), and a per-connection offset would have refused half of them.
    ts_base: Instant,
    ts_offset: u32,
    /// Last.ACK.sent (RFC 7323 §4.3): the ACK field we last sent.
    last_ack_sent: Option<u32>,

    // SACK.
    sack_enabled: bool,
    sack_ok: bool,
    /// Data received twice, for the first SACK block of the next ACK: a
    /// D-SACK (RFC 2883), which tells the sender its retransmission was
    /// not needed, or that the network duplicated a segment.
    dsack_out: Option<SackBlock>,

    // SND.WL1 / SND.WL2: SEQ and ACK of the segment that last set snd_wnd.
    snd_wl: Option<(u32, u32)>,

    // Right edge of the receive window as last advertised (RCV.NXT +
    // RCV.WND), once an ACK has carried one.
    rcv_adv: Option<u32>,

    /// Text that came in the peer's SYN, held until ESTABLISHED (RFC 9293
    /// §3.10.7.2-3): before the handshake completes, the SYN may come from
    /// a spoofed source.
    syn_data: Vec<u8>,

    // Deferred FIN.
    fin_pending: bool,
    pending_fin_seq: u32,

    // Our own FIN. close() only queues it: it goes out once every byte
    // written before it has been sent, since the FIN takes the sequence
    // number right after the last data byte.
    fin_queued: bool,
    fin_sent: bool,
    /// When the owner let go of the connection (see [`Conn::release`]).
    released: Option<Instant>,

    // Persist (zero-window probing).
    persist_deadline: std::option::Option<Instant>,
    persist_backoff: Duration,
    /// Zero-window probes sent since the peer was last heard from, which
    /// is what tells a receiver that is only slow to read from a dead one
    /// (Linux's `icsk_probes_out`).
    probes_out: u32,
    /// Zero-window probes sent since the release, answered or not.
    orphan_probes: u32,

    // TIME-WAIT.
    time_wait_deadline: std::option::Option<Instant>,

    // Keepalive.
    keepalive_deadline: std::option::Option<Instant>,
    keepalive_sent: u32,
    last_recv: Instant,

    // Lifecycle flags.
    established_signaled: bool,
    fin_recvd_signaled: bool,

    // Output queue drained by callers via [`take_outgoing`] / returned from methods.
    outgoing: Vec<Vec<u8>>,
    /// The IP-ECN codepoint each of `outgoing` is to be sent with, and
    /// those of the segments last drained (see `ecn_marks`).
    outgoing_ecn: Vec<IpEcn>,
    last_marks: Vec<IpEcn>,

    /// TCP Fast Open (RFC 7413).
    tfo: FastOpen,

    // ECN (RFC 3168, RFC 9768).
    ecn: Ecn,
    /// The codepoint the segment being processed arrived with.
    rx_ecn: IpEcn,
    /// A reduction for ECN feedback is under way (Linux's CWR state), until
    /// data past this, SND.NXT when it began, is acknowledged: one per
    /// window of data, as for losses (RFC 3168 §6.1.2).
    cwr_high: Option<u32>,

    /// The time, read once at the start of each call into the connection
    /// (see [`clock`](Self::clock)) rather than by every step of it that
    /// needs it: a segment's processing would otherwise read the clock
    /// half a dozen times, which on some hosts costs as much as the rest
    /// of it together.
    now: Instant,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn")
            .field("state", &self.state)
            .field("local_port", &self.cfg.local_port)
            .field("remote_port", &self.cfg.remote_port)
            .field("snd_una", &self.send_buf.as_ref().map(|s| s.una()))
            .field("snd_nxt", &self.send_buf.as_ref().map(|s| s.nxt()))
            .field("rcv_nxt", &self.recv_buf.as_ref().map(|r| r.nxt()))
            .finish()
    }
}

impl Conn {
    /// A connection in CLOSED, configured by `cfg`. Open it with
    /// [`connect`](Self::connect) or [`accept_syn`](Self::accept_syn).
    pub fn new(cfg: ConnConfig) -> Self {
        let now = wall_clock();
        let rcv_shift = cfg.rcv_wscale();
        let mss = cfg.mss.max(1);
        let cc = make_cc(cfg.congestion, mss as u32, cfg.pacing, now);
        let ts_offset = super::secret::keyed_hash((
            "tsval",
            cfg.local_addr.map(|a| a.ip()),
            cfg.remote_addr.map(|a| a.ip()),
        )) as u32;

        Self {
            cfg: cfg.clone(),
            state: State::Closed,
            closed: false,
            send_buf: None,
            recv_buf: None,
            snd_wnd: DEFAULT_WINDOW_SIZE as u32,
            max_snd_wnd: 0,
            mss,
            mss_clamp: mss,
            path_mss: u16::MAX,
            plpmtud: {
                let v6 = cfg
                    .remote_addr
                    .or(cfg.local_addr)
                    .is_some_and(|a| a.is_ipv6());
                let (overhead, floor) = if v6 {
                    (60, IPV6_MIN_PATH_MTU)
                } else {
                    (40, IPV4_MIN_PATH_MTU)
                };
                Search::new(cfg.mtu_probing, overhead, floor, now)
            },
            mtu_probe: None,
            black_hole_undo: false,
            cc,
            rto: RtoState::new(now),
            rto_deadline: None,
            retries: 0,
            score: Scoreboard::new(0, now),
            ca: CaState::Open,
            recover: 0,
            syn_lost: false,
            last_oow_ack: None,
            dup_acks: 0,
            reno_sacked: 0,
            undo: Undo::default(),
            frto: Frto::Off,
            rto_adapt: None,
            prr_delivered: 0,
            prr_out: 0,
            recover_fs: 1,
            reo_deadline: None,
            pto_deadline: None,
            tlp_end: None,
            tlp_retrans: false,
            pipe_ack: PipeAck::new(now),
            nvp_since: None,
            last_data_sent: None,
            rtt_sampled: false,
            cwnd_blocked: false,
            is_cwnd_limited: false,
            max_flight: 0,
            cwnd_usage_seq: 0,
            pace_credit: 0.0,
            pace_stamp: now,
            pace_deadline: None,
            pace_srtt: None,
            pace_late: Duration::ZERO,
            delack_deadline: None,
            quick_acks: 0,
            pingpong: false,
            // Until the peer shows larger, RFC 9293's default send MSS,
            // as Linux's tcp_initialize_rcv_mss assumes.
            rcv_mss: u32::from(mss.min(536)),
            last_data_recv: None,
            ack_pushed: false,
            budget: &autotune::GLOBAL,
            grown: 0,
            snd_nospace: false,
            // What the peer's initial window brings in the first round trip.
            rcv_space: RcvSpace::new(10 * mss as usize),
            snd_wnd_shift: 0,
            rcv_wnd_shift: rcv_shift,
            wscale_ok: false,
            ts_enabled: cfg.enable_timestamps,
            ts_ok: false,
            ts_recent: 0,
            ts_recent_stamp: now,
            ts_base: super::secret::epoch(),
            ts_offset,
            last_ack_sent: None,
            sack_enabled: cfg.enable_sack,
            sack_ok: false,
            dsack_out: None,
            snd_wl: None,
            rcv_adv: None,
            syn_data: Vec::new(),
            fin_pending: false,
            pending_fin_seq: 0,
            fin_queued: false,
            fin_sent: false,
            released: None,
            persist_deadline: None,
            persist_backoff: Duration::ZERO,
            probes_out: 0,
            orphan_probes: 0,
            time_wait_deadline: None,
            keepalive_deadline: None,
            keepalive_sent: 0,
            last_recv: now,
            established_signaled: false,
            fin_recvd_signaled: false,
            outgoing: Vec::new(),
            outgoing_ecn: Vec::new(),
            last_marks: Vec::new(),
            tfo: FastOpen::default(),
            ecn: Ecn::default(),
            rx_ecn: IpEcn::NOT_ECT,
            cwr_high: None,
            now,
        }
    }

    /// Read the clock for this call into the connection: every public
    /// method that may send, receive or arm a timer starts with it, and
    /// everything it does from there takes the time from `self.now`.
    #[inline]
    fn clock(&mut self) -> Instant {
        self.now = wall_clock();
        self.now
    }

    // --- Accessors ---------------------------------------------------------

    /// The current state.
    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

    /// True once the connection has ended: closed, reset, aborted or timed
    /// out. A connection not yet opened is not closed.
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// True once the connection has reached ESTABLISHED at least once.
    #[inline]
    pub fn is_established(&self) -> bool {
        self.established_signaled
    }

    /// True once we have observed the remote's FIN.
    #[inline]
    pub fn fin_received(&self) -> bool {
        self.fin_recvd_signaled
    }

    /// The configuration the connection was made with.
    #[cfg(test)]
    pub(crate) fn config(&self) -> &ConnConfig {
        &self.cfg
    }

    /// [`ConnConfig::local_addr`].
    #[inline]
    pub fn local_addr(&self) -> std::option::Option<SocketAddr> {
        self.cfg.local_addr
    }
    /// [`ConnConfig::remote_addr`].
    #[inline]
    pub fn remote_addr(&self) -> std::option::Option<SocketAddr> {
        self.cfg.remote_addr
    }

    /// The MSS the connection sends with: the peer's, capped by our own
    /// ([`ConnConfig::mss`]) and by the path MTU, as ICMP reported it or
    /// PLPMTUD found it ([`ConnConfig::mtu_probing`]). Options in a segment
    /// come out of it, so a segment's payload may be a little less.
    #[inline]
    pub fn mss(&self) -> u16 {
        self.mss
    }

    /// The path MTU the connection sends for: [`mss`](Self::mss) plus the
    /// IP and TCP headers. The address family comes from
    /// [`ConnConfig::remote_addr`] (or `local_addr`); without either it is
    /// taken as IPv4.
    pub fn path_mtu(&self) -> u32 {
        self.mss as u32 + self.header_overhead()
    }

    /// Lower the path MTU to `mtu` bytes: from then on no segment, with its
    /// IP and TCP headers and options, is larger. What was in flight at the
    /// old size is sent again at the new one, the way Linux's
    /// `tcp_simple_retransmit` does: most of it went no further than the
    /// router that could not forward it. That is not congestion, so the
    /// window and the RTO stay as they are. Returns the segments to send.
    ///
    /// The path MTU only ever goes down (RFC 1191 §6.3, RFC 8201 §4): an
    /// `mtu` at or above [`path_mtu`](Self::path_mtu) changes nothing. Nor
    /// does it go below the family's floor: 1280 for IPv6, the minimum link
    /// MTU (RFC 8201 §4), and 552 for IPv4 (Linux's `ip_rt_min_pmtu`). An IPv4 `mtu`
    /// below 68, such as the 0 that a router predating RFC 1191 reports, is
    /// no MTU at all; the next plateau below the current path MTU (RFC 1191
    /// §7) is taken instead.
    ///
    /// For a Packet Too Big that came in off the network, use
    /// [`on_icmp_too_big`](Self::on_icmp_too_big), which checks it first.
    pub fn set_path_mtu(&mut self, mtu: u32) -> Vec<Vec<u8>> {
        self.clock();
        let ipv6 = self.is_ipv6();
        let current = self.path_mtu();
        let mut mtu = mtu;
        if !ipv6 && mtu < 68 {
            mtu = MTU_PLATEAUS
                .iter()
                .copied()
                .find(|&p| p < current)
                .unwrap_or(0);
        }
        let floor = if ipv6 {
            IPV6_MIN_PATH_MTU
        } else {
            IPV4_MIN_PATH_MTU
        };
        let mtu = mtu.max(floor);
        let mss = (mtu - self.header_overhead()).min(u16::MAX as u32) as u16;
        if mss >= self.path_mss {
            return self.take_outgoing();
        }
        self.path_mss = mss;
        self.plpmtud.clamp(mtu);
        // A probe larger than the path is a failure, told outright.
        let probe = self.mtu_probe.take_if(|p| p.mtu > mtu);
        let before = self.mss;
        self.sync_mss();
        if self.mss < before {
            self.resend_after_mtu_drop();
        } else if let Some(p) = probe {
            self.resend_probe(p);
        }
        self.take_outgoing()
    }

    /// Take an ICMP Packet Too Big (ICMPv6 type 2) or Fragmentation Needed
    /// (ICMPv4 type 3 code 4) reporting a next-hop MTU of `mtu`, about the
    /// segment whose SEQ it quotes as `seq`, and act on it as
    /// [`set_path_mtu`](Self::set_path_mtu) does. Returns the segments to
    /// send.
    ///
    /// The caller must have matched the quoted IP and TCP headers to this
    /// connection's addresses and ports. What is checked here is RFC 5927
    /// §4.1's defence against a forged message: `seq` has to start a
    /// segment we sent and have not had acknowledged, SND.UNA <= SEQ <
    /// SND.NXT. (Linux's `tcp_v4_err` lets SND.NXT itself through too, but
    /// nothing we sent starts there: a segment that did would have moved
    /// SND.NXT past it.) Anything else is ignored.
    pub fn on_icmp_too_big(&mut self, mtu: u32, seq: u32) -> Vec<Vec<u8>> {
        if self.closed || matches!(self.state, State::Closed | State::Listen | State::TimeWait) {
            return Vec::new();
        }
        let Some(sb) = self.send_buf.as_ref() else {
            return Vec::new();
        };
        if !seq_in_range(seq, sb.una(), sb.nxt()) {
            return Vec::new();
        }
        self.set_path_mtu(mtu)
    }

    /// Everything in flight was sent at an MSS the path cannot carry: mark
    /// it lost and resend it, cut to the new size, from SND.UNA on as cwnd
    /// allows, as Linux's `tcp_simple_retransmit` does. What the peer
    /// SACKed got through and stays. Unlike a timeout, no congestion is
    /// inferred, so ssthresh and the RTO are left alone, and cwnd too
    /// outside fast recovery.
    fn resend_after_mtu_drop(&mut self) {
        if !self.state.is_synchronized() {
            return;
        }
        let Some(sb) = self.send_buf.as_ref() else {
            return;
        };
        // A FIN alone is never too big. A zero window is the persist
        // timer's to probe, with segments already cut to the new size.
        if sb.data_at(sb.una(), 1).is_empty() || self.snd_wnd == 0 {
            return;
        }
        self.mtu_probe = None;
        self.score.mark_all_lost();
        self.enter_simple_loss();
        self.reo_deadline = None;
        self.flush_send_queue();
    }

    /// Recover from losses to a segment's size, not to congestion, as
    /// Linux's `tcp_simple_retransmit` does: what the scoreboard marks lost
    /// is resent, as cwnd allows, without cutting it. Unlike a timeout, no
    /// congestion is inferred, so ssthresh and the RTO are left alone, and
    /// cwnd too outside fast recovery.
    fn enter_simple_loss(&mut self) {
        let nxt = self.send_buf.as_ref().unwrap().nxt();
        // Fast recovery gives way, as Linux's CA_Loss replaces CA_Recovery:
        // the loss it was recovering from has cut the window already;
        // ending it just brings cwnd down to that.
        // So does a reduction for ECN. BBR sets cwnd by its model.
        let reducing = self.cwr_high.take().is_some();
        if (self.ca == CaState::Recovery || reducing) && !self.cc.model_based() {
            self.cc.set_cwnd(self.cc.ssthresh());
        }
        self.ca = CaState::Loss;
        self.recover = nxt;
        // Nothing to undo, nor a timeout for F-RTO to judge.
        self.undo.marker = None;
        self.frto = Frto::Off;
        self.reno_sacked = 0;
        self.dup_acks = 0;
        self.tlp_end = None;
        self.pto_deadline = None;
    }

    /// An MTU probe was too big for the path, as ICMP says: resend just it,
    /// cut to the MSS.
    fn resend_probe(&mut self, p: Probe) {
        if !self.state.is_synchronized() || self.send_buf.is_none() {
            return;
        }
        self.plpmtud.on_failure(p.mtu, self.now);
        if self.score.mark_range_lost(p.start, p.end) {
            self.enter_simple_loss();
            self.flush_send_queue();
        }
    }

    /// Losses were found (RACK, or duplicate ACKs) with nothing deemed lost
    /// before: start fast recovery, unless all that is lost is an MTU probe
    /// (RFC 4821 §7.6.2): then the path would not take its size, which is
    /// no sign of congestion, and it alone is resent at the MSS, as Linux's
    /// `tcp_mtup_probe_failed` has it.
    fn on_losses_found(&mut self) {
        if let Some(p) = self.mtu_probe
            && !self.score.lost_outside(p.start, p.end)
        {
            self.mtu_probe = None;
            self.plpmtud.on_failure(p.mtu, self.now);
            self.enter_simple_loss();
            return;
        }
        self.enter_recovery();
    }

    /// Set `mss` from what caps it: the peer, the path as ICMP reported it,
    /// and PLPMTUD's search (Linux's `tcp_sync_mss`).
    fn sync_mss(&mut self) {
        let mut mss = self.mss_clamp.min(self.path_mss);
        if let Some(cap) = self.plpmtud.cap() {
            let found = cap
                .saturating_sub(self.header_overhead())
                .max(u32::from(options::MIN_MSS));
            mss = mss.min(found.min(u32::from(u16::MAX)) as u16);
        }
        if mss != self.mss {
            self.mss = mss;
            self.cc.set_mss(u32::from(mss));
        }
    }

    /// The MTU probe to send now, if one is due and there is room for it
    /// (Linux's `tcp_mtu_probe`), as its payload and MTU: `room` is what an
    /// ordinary segment would carry beside `opts`, `pending` the data
    /// waiting, and `cc_room` and `rcv_room` what cwnd and the peer's
    /// window let go. A probe needs enough data behind it for the segments
    /// that follow to show its loss by their SACKs or duplicate ACKs, not
    /// only a timeout; and a window large enough (11 segments, as Linux
    /// asks) that one segment lost to its size costs little.
    fn probe_due(
        &mut self,
        opts: &[TcpOption],
        room: usize,
        pending: usize,
        cc_room: u32,
        rcv_room: u32,
    ) -> Option<(usize, u32)> {
        if self.mtu_probe.is_some()
            || self.ca != CaState::Open
            || self.cwr_high.is_some()
            || !matches!(self.state, State::Established | State::CloseWait)
            || self.cc.cwnd() < 11 * u32::from(self.mss)
        {
            return None;
        }
        let mtu = self.plpmtud.next_probe(self.now)?;
        let payload = (mtu as usize)
            .checked_sub(self.header_overhead() as usize + options::options_len(opts))?;
        let need = payload + (DUP_THRESH as usize + 1) * usize::from(self.mss);
        if payload <= room
            || pending < need
            || (rcv_room as usize) < need
            || (cc_room as usize) < payload
        {
            return None;
        }
        Some((payload, mtu))
    }

    /// Drain any queued outgoing segments.
    pub fn take_outgoing(&mut self) -> Vec<Vec<u8>> {
        self.last_marks = std::mem::take(&mut self.outgoing_ecn);
        std::mem::take(&mut self.outgoing)
    }

    /// The IP-ECN codepoint for each of `segs`, which this connection has
    /// just returned (from any call, and before the next): what the IP
    /// layer sets in each one's header. Not-ECT for all if they are not
    /// what it returned.
    #[cfg_attr(not(any(feature = "vclient", feature = "slirp")), allow(dead_code))]
    pub(crate) fn ecn_marks(&self, segs: &[Vec<u8>]) -> Vec<IpEcn> {
        if self.last_marks.len() == segs.len() {
            self.last_marks.clone()
        } else {
            vec![IpEcn::NOT_ECT; segs.len()]
        }
    }

    // --- Active / passive open --------------------------------------------

    fn new_iss(&self) -> u32 {
        let c = &self.cfg;
        super::secret::isn(
            c.local_addr.map(|a| a.ip()),
            c.local_port,
            c.remote_addr.map(|a| a.ip()),
            c.remote_port,
        )
    }

    /// Initiate active open (send the initial SYN). Returns the SYN segment.
    pub fn connect(&mut self) -> Vec<Vec<u8>> {
        self.clock();
        if self.state != State::Closed {
            return Vec::new();
        }
        let iss = self.new_iss();
        self.send_buf = Some(SendBuf::new(self.cfg.send_buf_size, iss));
        self.score = Scoreboard::new(iss, self.now);
        self.recv_buf = Some(RecvBuf::new(0, self.cfg.recv_buf_size));
        self.state = State::SynSent;

        let opts = self.build_syn_options();
        let win = self.syn_window();
        let (ecn, ae) = self.ecn.syn_flags(self.cfg.ecn);
        let syn = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq: iss,
            ack: 0,
            flags: flags::SYN | ecn,
            ae,
            window: win,
            options: opts,
            ..Default::default()
        };
        self.queue_seg(syn);
        self.send_buf.as_mut().unwrap().advance_sent(1); // SYN consumes 1 seq
        self.rto.start_timing(iss, self.now);
        self.start_rto();
        self.take_outgoing()
    }

    /// Active open with TCP Fast Open (RFC 7413): take `data`, as much as
    /// the send buffer holds, and send the SYN. With the server's `cookie`,
    /// the SYN carries what of the data fits beside its options in a
    /// segment of `mss` (the server's, as last seen, or the default for
    /// the family), and the server may take it at once; what does not fit,
    /// or what the server does not take, goes once the handshake is done.
    /// Without a cookie, the SYN asks for one ([`fast_open_cookie`](Self::fast_open_cookie)
    /// has it once the SYN-ACK is in) and all the data waits for the
    /// handshake. Returns what was taken of `data`, and the SYN.
    #[cfg_attr(not(feature = "vclient"), allow(dead_code))]
    pub(crate) fn connect_fast_open(
        &mut self,
        cookie: Option<&[u8]>,
        mss: Option<u16>,
        data: &[u8],
    ) -> (usize, Vec<Vec<u8>>) {
        self.clock();
        if self.state != State::Closed {
            return (0, Vec::new());
        }
        let iss = self.new_iss();
        let mut sb = SendBuf::new(self.cfg.send_buf_size, iss);
        // The buffer counts the SYN's sequence number as a byte of its own,
        // so the data after it lines up with the sequence space; the
        // SYN-ACK frees it, as it would any byte it acknowledges.
        sb.write(&[0]);
        let n = sb.write(data);
        sb.advance_sent(1);
        self.send_buf = Some(sb);
        self.score = Scoreboard::new(iss, self.now);
        self.recv_buf = Some(RecvBuf::new(0, self.cfg.recv_buf_size));
        self.state = State::SynSent;
        self.tfo.offered = true;
        self.tfo.request = Some(cookie.map_or_else(Vec::new, <[u8]>::to_vec));

        let opts = self.build_syn_options();
        let payload = match cookie {
            Some(_) => {
                let default = if self.is_ipv6() { 1220 } else { 536 };
                let mss = mss
                    .unwrap_or(default)
                    .min(self.cfg.mss.max(1))
                    .min(self.path_mss);
                let room = usize::from(mss).saturating_sub(options::options_len(&opts));
                self.send_buf.as_ref().unwrap().peek_unsent(room).to_vec()
            }
            None => Vec::new(),
        };
        let (ecn, ae) = self.ecn.syn_flags(self.cfg.ecn);
        let syn = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq: iss,
            ack: 0,
            flags: flags::SYN | ecn,
            ae,
            window: self.syn_window(),
            options: opts,
            payload,
            ..Default::default()
        };
        self.tfo.syn_data = syn.payload.len() as u32;
        self.send_buf
            .as_mut()
            .unwrap()
            .advance_sent(syn.payload.len());
        self.queue_seg(syn);
        self.rto.start_timing(iss, self.now);
        self.start_rto();
        (n, self.take_outgoing())
    }

    /// The Fast Open cookie the server's SYN-ACK brought, after
    /// [`connect_fast_open`](Self::connect_fast_open): the one to send
    /// next time.
    #[cfg_attr(
        any(not(feature = "vclient"), target_family = "wasm"),
        allow(dead_code)
    )]
    pub(crate) fn fast_open_cookie(&self) -> Option<&[u8]> {
        self.tfo.cookie.as_deref()
    }

    /// Whether the SYN of [`connect_fast_open`](Self::connect_fast_open)
    /// carried data that went unanswered: the server, or something on the
    /// way to it, may drop SYNs with data (RFC 7413 §4.1.3.1), and a client
    /// had better not send it one again for a while.
    #[cfg_attr(
        any(not(feature = "vclient"), target_family = "wasm"),
        allow(dead_code)
    )]
    pub(crate) fn fast_open_syn_lost(&self) -> bool {
        self.tfo.syn_data_lost
    }

    /// Whether the server's SYN-ACK acknowledged all the data of our SYN.
    #[cfg(test)]
    pub(crate) fn fast_open_data_acked(&self) -> bool {
        self.tfo.data_acked
    }

    /// Server side: whether this connection took data from its SYN (see
    /// [`ConnConfig::fast_open`]), so it may be read, and written to,
    /// before the handshake completes.
    #[cfg_attr(not(any(feature = "vclient", feature = "slirp")), allow(dead_code))]
    pub(crate) fn fast_open_accepted(&self) -> bool {
        self.tfo.accepted
    }

    /// Server side, before [`accept_syn`](Self::accept_syn): count this
    /// connection, if it takes Fast Open data, at `gate` rather than the
    /// process's, and take none at all if `refuse_data` (the driver has no
    /// room for it before the handshake completes).
    #[cfg_attr(not(any(feature = "vclient", feature = "slirp")), allow(dead_code))]
    pub(crate) fn set_fast_open_gate(
        &mut self,
        gate: Option<std::sync::Arc<Gate>>,
        refuse_data: bool,
    ) {
        self.tfo.gate = gate;
        self.tfo.refuse_data = refuse_data;
    }

    /// Process an incoming SYN, transition to SYN-RECEIVED, emit SYN-ACK.
    pub fn accept_syn(&mut self, syn: &Segment) -> Vec<Vec<u8>> {
        self.accept_syn_ecn(syn, IpEcn::NOT_ECT)
    }

    /// [`accept_syn`](Self::accept_syn) for a SYN that arrived with IP-ECN
    /// codepoint `ecn`, which an AccECN SYN-ACK reports.
    pub(crate) fn accept_syn_ecn(&mut self, syn: &Segment, ecn: IpEcn) -> Vec<Vec<u8>> {
        self.clock();
        self.rx_ecn = ecn;
        let iss = self.new_iss();
        self.open_passive(syn, iss)
    }

    /// Rebuild the SYN-RECEIVED state a SYN cookie stood in for, from `ack`,
    /// the segment that [`SynCookies::validate_ack`](super::SynCookies::validate_ack)
    /// accepted with `mss`, without completing the handshake: for a listener
    /// that cannot take the connection yet, its accept queue being full.
    /// `ack` itself is not processed, as Linux drops it on overflow.
    ///
    /// From then on the connection is as if the SYN had been kept: its
    /// SYN-ACK is retransmitted on the RTO, and the next segment from the
    /// peer that [`handle_segment`](Self::handle_segment) is given
    /// completes the handshake. Only the first segment after the handshake
    /// carries a valid cookie, so without this the peer's later segments
    /// would find no connection and be reset. It negotiates what a cookie
    /// can carry: the MSS, and no window scaling, SACK or timestamps.
    /// Nothing is sent now; the SYN-ACK went out, statelessly, already.
    #[cfg_attr(not(any(feature = "vclient", feature = "slirp")), allow(dead_code))]
    pub(crate) fn accept_cookie_syn_received(&mut self, ack: &Segment, our_iss: u32, mss: u16) {
        self.clock();
        let syn = Segment {
            src_port: ack.src_port,
            dst_port: ack.dst_port,
            seq: ack.seq.wrapping_sub(1),
            flags: flags::SYN,
            window: ack.window,
            options: vec![mss_option(mss.max(options::MIN_MSS))],
            ..Default::default()
        };
        let _ = self.open_passive(&syn, our_iss);
    }

    fn open_passive(&mut self, syn: &Segment, iss: u32) -> Vec<Vec<u8>> {
        if self.state != State::Closed && self.state != State::Listen {
            return Vec::new();
        }
        self.negotiate_options(&syn.options);
        self.ecn.on_syn(self.cfg.ecn, syn, self.rx_ecn);
        let fast_open = self.fast_open_syn(syn);

        self.send_buf = Some(SendBuf::new(self.cfg.send_buf_size, iss));
        self.score = Scoreboard::new(iss, self.now);
        self.recv_buf = Some(RecvBuf::new(
            syn.seq.wrapping_add(1),
            self.cfg.recv_buf_size,
        ));
        self.state = State::SynReceived;
        if fast_open == Some(true) {
            // The data is the application's now, and the SYN-ACK
            // acknowledges it. What the application answers may go before
            // the handshake completes, within the SYN's window (never
            // scaled, RFC 7323 §2.2): the buffer counts the SYN-ACK's
            // sequence number as a byte, so the answer lines up after it,
            // and the scoreboard starts past it.
            self.recv_buf
                .as_mut()
                .unwrap()
                .insert(syn.seq.wrapping_add(1), &syn.payload);
            self.send_buf.as_mut().unwrap().write(&[0]);
            self.score = Scoreboard::new(iss.wrapping_add(1), self.now);
            self.set_snd_wnd(u32::from(syn.window));
        }

        let opts = self.build_syn_options();
        let win = self.syn_window();
        let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
        let (ecn, ae) = self.ecn.synack_flags();
        let synack = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq: iss,
            ack: rcv_nxt,
            flags: flags::SYN | flags::ACK | ecn,
            ae,
            window: win,
            options: opts,
            ..Default::default()
        };
        self.queue_seg(synack);
        self.send_buf.as_mut().unwrap().advance_sent(1);
        self.rto.start_timing(iss, self.now);

        // Data in a SYN whose Fast Open cookie did not let it in is not
        // kept either (RFC 7413 §4.2.2): the client sends it again after
        // the handshake.
        if fast_open.is_none() {
            self.syn_data = syn.payload.clone();
        }

        self.start_rto();
        self.take_outgoing()
    }

    /// The Fast Open option of a SYN we are answering, if we take Fast
    /// Open: `None` without one, else whether its data is taken. A request
    /// for a cookie, or a cookie no longer valid, is answered with a fresh
    /// one in the SYN-ACK. Data comes in with a valid cookie while this
    /// connection's gate has room for one more pending handshake.
    fn fast_open_syn(&mut self, syn: &Segment) -> Option<bool> {
        if !self.cfg.fast_open {
            return None;
        }
        let offer = fastopen::offer(&syn.options)?;
        let (Some(local), Some(remote)) = (self.cfg.local_addr, self.cfg.remote_addr) else {
            return None;
        };
        let (server, client) = (local.ip(), remote.ip());
        if !matches!(offer, fastopen::Offer::Cookie(c) if fastopen::valid(server, client, c)) {
            self.tfo.reply = Some(fastopen::cookie(server, client));
            return Some(false);
        }
        if syn.payload.is_empty() || self.tfo.refuse_data {
            return Some(false);
        }
        let gate = self.tfo.gate.clone().unwrap_or_else(Gate::global);
        self.tfo.slot = Some(gate.take()?);
        self.tfo.accepted = true;
        Some(true)
    }

    /// Skip SYN-RECEIVED and jump straight to ESTABLISHED via a validated
    /// SYN cookie. The handshake is already complete (the SYN-ACK was sent
    /// statelessly by the cookie engine); `ack` is the segment that
    /// completed it, which [`SynCookies::validate_ack`](super::SynCookies::validate_ack)
    /// accepted with `mss`. Its payload, if any, is taken as data, and its
    /// window as the peer's (unscaled: a cookie cannot carry window scaling).
    #[cfg_attr(not(any(feature = "vclient", feature = "slirp")), allow(dead_code))]
    pub(crate) fn accept_cookie(&mut self, ack: &Segment, our_iss: u32, mss: u16) -> Vec<Vec<u8>> {
        self.clock();
        let remote_seq = ack.seq;
        let initial_data = &ack.payload[..];
        if self.state != State::Closed && self.state != State::Listen {
            return Vec::new();
        }
        self.set_mss(mss.max(options::MIN_MSS));
        self.send_buf = Some(SendBuf::new(
            self.cfg.send_buf_size,
            our_iss.wrapping_add(1),
        ));
        self.score = Scoreboard::new(our_iss.wrapping_add(1), self.now);
        self.recv_buf = Some(RecvBuf::new(remote_seq, self.cfg.recv_buf_size));
        // Seeds MAX.SND.WND too: at zero, every reordered older ACK would be
        // dropped until the next window update.
        self.set_snd_wnd(ack.window as u32);
        self.snd_wl = Some((ack.seq, ack.ack));
        self.state = State::Established;
        self.signal_established();

        if self.cfg.keepalive {
            self.start_keepalive();
        }

        if !initial_data.is_empty() {
            self.recv_buf
                .as_mut()
                .unwrap()
                .insert(remote_seq, initial_data);
        }

        self.queue_ack();
        self.take_outgoing()
    }

    // --- Options handling --------------------------------------------------

    /// Options for our SYN, or for our SYN-ACK once the peer's SYN is in.
    /// A SYN-ACK answers only what the SYN offered (RFC 7323 §2.2, §3.2;
    /// RFC 2018 §2), and echoes the SYN's TSval.
    fn build_syn_options(&self) -> Vec<TcpOption> {
        let synack = self.state != State::SynSent;
        let mut opts = Vec::with_capacity(4);
        // What we can receive, not the MSS we send with.
        opts.push(mss_option(self.cfg.mss.max(1)));
        // A SYN always offers wscale; shift=0 means "I support it".
        if !synack || self.wscale_ok {
            opts.push(wscale_option(self.rcv_wnd_shift));
        }
        if self.sack_enabled && (!synack || self.sack_ok) {
            opts.push(sack_perm_option());
        }
        if !synack && self.ts_enabled {
            opts.push(timestamp_option(self.ts_now(), 0));
        } else if synack && self.ts_ok {
            opts.push(timestamp_option(self.ts_now(), self.ts_recent));
        }
        if !synack && let Some(c) = self.tfo.request.as_deref() {
            opts.push(fastopen::option(c));
        } else if synack && let Some(c) = self.tfo.reply {
            opts.push(fastopen::option(&c));
        }
        opts
    }

    /// Send with at most `mss`, and size the congestion controller, which
    /// counts in segments, to match: a SYN's MSS applies only after `new`
    /// made one.
    fn set_mss(&mut self, mss: u16) {
        self.mss_clamp = mss.min(self.cfg.mss.max(1));
        let max = u32::from(self.mss_clamp.min(self.path_mss)) + self.header_overhead();
        self.plpmtud.set_max(max);
        self.sync_mss();
        self.cc = make_cc(
            self.cfg.congestion,
            self.mss as u32,
            self.cfg.pacing,
            self.now,
        );
    }

    fn is_ipv6(&self) -> bool {
        self.cfg
            .remote_addr
            .or(self.cfg.local_addr)
            .is_some_and(|a| a.is_ipv6())
    }

    /// IP and TCP headers, options aside: what separates the MSS from the
    /// MTU (RFC 9293 §3.7.1).
    fn header_overhead(&self) -> u32 {
        if self.is_ipv6() { 40 + 20 } else { 20 + 20 }
    }

    fn negotiate_options(&mut self, remote_opts: &[TcpOption]) {
        let ipv6 = self.is_ipv6();
        self.set_mss(options::peer_mss(remote_opts, ipv6));
        if let Some(ws) = get_wscale(remote_opts) {
            self.snd_wnd_shift = ws.min(14);
            self.wscale_ok = true;
        }
        if self.sack_enabled && has_sack_perm(remote_opts) {
            self.sack_ok = true;
        }
        if self.ts_enabled
            && let Some((ts_val, _)) = get_timestamp(remote_opts)
        {
            self.ts_recent = ts_val;
            self.ts_recent_stamp = self.now;
            self.ts_ok = true;
        }
    }

    /// The options a segment sent now carries: timestamps and SACK blocks.
    fn segment_options(&self) -> Vec<TcpOption> {
        let mut opts = Vec::with_capacity(2);
        if self.ts_ok {
            opts.push(timestamp_option(self.ts_now(), self.ts_recent));
        }
        if self.sack_ok
            && let Some(rb) = self.recv_buf.as_ref()
            && (rb.has_ooo() || self.dsack_out.is_some())
        {
            // Four blocks fit in the option space alone, three beside a
            // timestamp (RFC 2018 §3).
            let max = if self.ts_ok { 3 } else { 4 };
            let mut blocks = Vec::with_capacity(max);
            // A D-SACK goes first, followed by the range holding it, if
            // any (RFC 2883 §4).
            if let Some(d) = self.dsack_out {
                blocks.push(d);
                if let Some(around) = rb.sack_block_around(d.left, d.right) {
                    blocks.push(around);
                }
            }
            for b in rb.sack_blocks_up_to(max) {
                if blocks.len() == max {
                    break;
                }
                if !blocks[self.dsack_out.is_some() as usize..].contains(&b) {
                    blocks.push(b);
                }
            }
            if !blocks.is_empty() {
                opts.push(sack_option(&blocks));
            }
        }
        opts
    }

    fn add_options(&self, seg: &mut Segment) {
        seg.options.extend(self.segment_options());
    }

    /// Payload that fits a segment beside `opts`. The MSS counts data only
    /// and the sender must make room for its own options within it (RFC
    /// 6691 §2, RFC 9293 §3.7.1), like Linux's `tcp_current_mss`: a full
    /// segment with timestamps and SACK blocks would otherwise exceed the
    /// MTU the peer derived its MSS from.
    fn payload_room(&self, opts: &[TcpOption]) -> usize {
        (self.mss as usize)
            .saturating_sub(options::options_len(opts))
            .max(1)
    }

    /// [`payload_room`](Self::payload_room) for a segment sent now.
    fn send_mss(&self) -> usize {
        self.payload_room(&self.segment_options())
    }

    fn ts_now(&self) -> u32 {
        (self.now.saturating_duration_since(self.ts_base).as_millis() as u32)
            .wrapping_add(self.ts_offset)
    }

    /// PAWS validation at time `now`: drop segments with timestamps older
    /// than ts_recent.
    fn update_timestamp(&mut self, seg: &Segment, now: Instant) -> bool {
        if !self.ts_ok {
            return true;
        }
        let Some((ts_val, _)) = get_timestamp(&seg.options) else {
            return true;
        };
        // RFC 7323 §5.5: after 24 days without an update TS.Recent is
        // invalid, since the peer's clock may have wrapped past it; PAWS
        // would otherwise reject every segment of a long-idle connection
        // for good. Skip the test and take the new TSval as usual.
        let stale = now.saturating_duration_since(self.ts_recent_stamp) > PAWS_IDLE;
        if !stale && (ts_val.wrapping_sub(self.ts_recent) as i32) < 0 {
            return false;
        }
        // RFC 7323 §4.3: only a segment at or before Last.ACK.sent, so an
        // out-of-order one cannot put a TSval from beyond a hole in the
        // echo; the hole's repair is what the peer should time.
        if self
            .last_ack_sent
            .is_none_or(|last| seq_before_eq(seg.seq, last))
        {
            self.ts_recent = ts_val;
            self.ts_recent_stamp = now;
        }
        true
    }

    // --- Outgoing helpers -------------------------------------------------

    fn sws_thresh(&self) -> u32 {
        let size = self
            .recv_buf
            .as_ref()
            .map_or(self.cfg.recv_buf_size, |rb| rb.limit());
        let half = size / 2;
        (self.mss as usize).min(half.max(1)) as u32
    }

    /// Receive window to advertise, in bytes.
    fn rcv_wnd_bytes(&self) -> u32 {
        let Some(rb) = self.recv_buf.as_ref() else {
            return self.cfg.recv_buf_size as u32;
        };
        let avail = rb.window();
        let thresh = self.sws_thresh();
        // Receiver SWS avoidance (RFC 9293 §3.8.6.2.2): move the right edge
        // only in steps of at least `thresh`, and never back — a shrinking
        // window strands data the peer was already allowed to send.
        let Some(adv) = self.rcv_adv else {
            return if avail < thresh { 0 } else { avail };
        };
        let nxt = rb.nxt();
        if seq_after_eq(nxt.wrapping_add(avail), adv.wrapping_add(thresh)) {
            avail
        } else if seq_after(adv, nxt) {
            adv.wrapping_sub(nxt).min(avail)
        } else {
            0
        }
    }

    fn rcv_window(&self) -> u16 {
        let mut w = self.rcv_wnd_bytes() as usize;
        if self.wscale_ok {
            // Rounded up, not down: down, a window smaller than a unit
            // would read as closed, and a peer with just a FIN or a few
            // bytes left to send would wait on a window that is open. Up
            // overshoots the buffer by less than a unit, which the buffer
            // takes (RecvBuf::set_adv_edge). The edge is rounded from the
            // buffer's end each time, not from the last edge, so it never
            // passes that end by more, however often it is sent.
            w = w.div_ceil(1 << self.rcv_wnd_shift);
        }
        w.min(65535) as u16
    }

    /// Window for a SYN or SYN-ACK, which is never scaled (RFC 7323 §2.2).
    fn syn_window(&self) -> u16 {
        self.rcv_wnd_bytes().min(65535) as u16
    }

    fn queue_seg(&mut self, mut seg: Segment) {
        let new_data =
            !seg.payload.is_empty() && self.send_buf.as_ref().is_some_and(|s| s.nxt() == seg.seq);
        let ip = self.ecn.mark(&mut seg, new_data);
        self.outgoing_ecn.push(ip);
        if seg.has_flag(flags::ACK) && self.recv_buf.is_some() {
            // Whatever we send acknowledges everything received so far.
            self.delack_deadline = None;
            self.ack_pushed = false;
            self.last_ack_sent = Some(seg.ack);
            // Reported once (RFC 2883 §4).
            self.dsack_out = None;
            let shift = if seg.has_flag(flags::SYN) || !self.wscale_ok {
                0
            } else {
                self.rcv_wnd_shift
            };
            let edge = seg.ack.wrapping_add((seg.window as u32) << shift);
            if self.rcv_adv.is_none_or(|adv| seq_after(edge, adv)) {
                self.rcv_adv = Some(edge);
            }
            if let Some(rb) = self.recv_buf.as_mut() {
                rb.set_adv_edge(edge);
            }
        }
        self.outgoing.push(seg.marshal());
    }

    /// Answer an out-of-window segment with the duplicate ACK RFC 9293
    /// owes it, throttled like a [challenge ACK](Self::queue_challenge_ack)
    /// unless it occupies sequence space: data or a FIN is not part of an
    /// ACK loop, and the peer's retransmission may be waiting on exactly
    /// this ACK. That exemption is Linux's `tcp_oow_rate_limited`, and it
    /// never covers a SYN or RST, which are not part of the data flow.
    fn queue_oow_ack(&mut self, seg: &Segment) {
        let in_flow = seg.seg_len() > 0 && !seg.has_flag(flags::SYN) && !seg.has_flag(flags::RST);
        if in_flow {
            self.last_oow_ack = Some(self.now);
            self.queue_ack();
        } else {
            self.queue_challenge_ack();
        }
    }

    /// Send a challenge ACK (RFC 5961 §§3-5), throttled as §7 asks: at most
    /// one per 500 ms per connection, whatever the segment carried, like
    /// Linux's `tcp_invalid_ratelimit`. Otherwise a blind attacker gets an
    /// ACK for every guess (with a payload attached, if that bought an
    /// exemption), and two ends that disagree about the sequence space can
    /// ACK each other forever.
    fn queue_challenge_ack(&mut self) {
        let now = self.now;
        if self
            .last_oow_ack
            .is_some_and(|t| now.duration_since(t) < OOW_ACK_INTERVAL)
        {
            return;
        }
        self.last_oow_ack = Some(now);
        self.queue_ack();
    }

    fn queue_ack(&mut self) {
        let snd_nxt = self.send_buf.as_ref().map(|s| s.nxt()).unwrap_or(0);
        let rcv_nxt = self.recv_buf.as_ref().map(|r| r.nxt()).unwrap_or(0);
        let mut seg = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq: snd_nxt,
            ack: rcv_nxt,
            flags: flags::ACK,
            window: self.rcv_window(),
            ..Default::default()
        };
        self.add_options(&mut seg);
        self.queue_seg(seg);
    }

    fn queue_fin(&mut self) {
        let snd_nxt = self.send_buf.as_ref().map(|s| s.nxt()).unwrap_or(0);
        let rcv_nxt = self.recv_buf.as_ref().map(|r| r.nxt()).unwrap_or(0);
        let mut seg = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq: snd_nxt,
            ack: rcv_nxt,
            flags: flags::FIN | flags::ACK,
            window: self.rcv_window(),
            ..Default::default()
        };
        self.add_options(&mut seg);
        self.queue_seg(seg);
        if let Some(s) = self.send_buf.as_mut() {
            s.advance_sent(1); // FIN consumes 1 seq
        }
        let tsval = self.ts_now();
        self.score.on_send(snd_nxt, 1, true, self.now, tsval);
        self.note_sent(1);
        self.fin_queued = false;
        self.fin_sent = true;
        if self.rto_deadline.is_none() {
            self.start_rto();
        }
    }

    /// True once the peer has acknowledged our FIN (and so all data before it).
    fn fin_acked(&self) -> bool {
        self.fin_sent && self.send_buf.as_ref().is_some_and(|s| s.unacked() == 0)
    }

    // --- HandleSegment dispatcher (RFC 9293 §3.10.7) ----------------------

    /// Process an inbound segment. Returns any outgoing segments to transmit.
    pub fn handle_segment(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        self.handle_segment_ecn(seg, IpEcn::NOT_ECT)
    }

    /// [`handle_segment`](Self::handle_segment) for a segment that arrived
    /// with IP-ECN codepoint `ecn`.
    pub(crate) fn handle_segment_ecn(&mut self, seg: &Segment, ecn: IpEcn) -> Vec<Vec<u8>> {
        self.clock();
        self.rx_ecn = ecn;
        match self.state {
            State::Closed => self.handle_closed(seg),
            State::Listen => Vec::new(), // pure passive open uses accept_syn
            State::SynSent => self.handle_syn_sent(seg),
            State::SynReceived
            | State::Established
            | State::FinWait1
            | State::FinWait2
            | State::CloseWait
            | State::Closing
            | State::LastAck
            | State::TimeWait => self.handle_synchronized(seg),
        }
    }

    /// The peer is still there. Only for a segment that passed the
    /// sequence, PAWS and ACK checks: anyone can send one that fails them,
    /// and counting those would let a blind attacker (or a stray duplicate)
    /// hold off the keepalive, FIN-WAIT-2 and zero-window give-up timers of
    /// a peer that is long gone.
    fn note_alive(&mut self) {
        self.last_recv = self.now;
        self.keepalive_sent = 0;
        self.probes_out = 0;
    }

    /// The handshake is complete. Whatever a lost SYN or SYN-ACK left in
    /// the loss-recovery state belongs to the handshake, not to the data
    /// that follows.
    fn handshake_done(&mut self) {
        if self.syn_lost {
            // RFC 5681 §3.1 (and RFC 6928 §2): after a lost SYN or SYN-ACK
            // the initial window MUST be one segment, with ssthresh left
            // alone. The client's controller was only just rebuilt for the
            // peer's MSS, so this has to come after that. RFC 6298 §5.7:
            // the RTO, never sampled (Karn), starts data transfer at 3 s.
            self.cc.on_handshake_loss();
            self.rto.reset_after_syn_loss();
        }
        self.ca = CaState::Open;
        self.dup_acks = 0;
        self.reno_sacked = 0;
        if let Some(sb) = self.send_buf.as_ref() {
            // A Fast Open server may have sent data already, which stays.
            if self.score.is_empty() {
                self.score = Scoreboard::new(sb.una(), self.now);
            }
            self.score.set_rack(self.sack_ok);
            self.score.set_track_losses(self.cc.model_based());
        }
        // No longer a pending Fast Open connection.
        self.tfo.slot = None;
    }

    fn handle_closed(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        if seg.has_flag(flags::RST) {
            return Vec::new();
        }
        let rst = if seg.has_flag(flags::ACK) {
            Segment {
                src_port: self.cfg.local_port,
                dst_port: self.cfg.remote_port,
                seq: seg.ack,
                flags: flags::RST,
                ..Default::default()
            }
        } else {
            Segment {
                src_port: self.cfg.local_port,
                dst_port: self.cfg.remote_port,
                seq: 0,
                ack: seg.seq.wrapping_add(seg.seg_len()),
                flags: flags::RST | flags::ACK,
                ..Default::default()
            }
        };
        self.queue_seg(rst);
        self.take_outgoing()
    }

    /// RCV.NXT and the RCV.WND segments are checked against: what we
    /// advertised, or more if a read has freed room since.
    fn rcv_space(&self) -> Option<(u32, u32)> {
        let rb = self.recv_buf.as_ref()?;
        let rcv_nxt = rb.nxt();
        let advertised = self
            .rcv_adv
            .filter(|&adv| seq_after(adv, rcv_nxt))
            .map_or(0, |adv| adv.wrapping_sub(rcv_nxt));
        Some((rcv_nxt, advertised.max(rb.window())))
    }

    fn segment_acceptable(&self, seg: &Segment) -> bool {
        let Some((rcv_nxt, rcv_wnd)) = self.rcv_space() else {
            return true;
        };
        let seg_len = seg.seg_len();
        if seg_len == 0 {
            // RFC 9293 wants SEG.SEQ < RCV.NXT+RCV.WND, but a peer that has
            // filled our window sends its ACKs at exactly the right edge. If
            // part of that data was lost, rejecting them would also discard
            // the ACK field until the retransmission lands (Linux accepts
            // them too).
            return seq_in_range_inclusive(seg.seq, rcv_nxt, rcv_nxt.wrapping_add(rcv_wnd));
        }
        if rcv_wnd == 0 {
            // No data fits, but RFC 9293 §3.10.7.4 still wants valid ACKs
            // taken from a segment at RCV.NXT, as Linux's tcp_sequence does:
            // a peer probing our closed window, or sending into it, may be
            // acknowledging our data too, and rejecting the whole segment
            // would stall our side until the window reopens. The payload is
            // dropped later (the buffer takes none of it) and ACKed. A bare
            // FIN there takes no buffer space and is accepted outright, or a
            // peer could not close to a reader that has stopped reading.
            return seg.seq == rcv_nxt;
        }
        let seg_end = seg.seq.wrapping_add(seg_len.wrapping_sub(1));
        seq_in_range(seg.seq, rcv_nxt, rcv_nxt.wrapping_add(rcv_wnd))
            || seq_in_range(seg_end, rcv_nxt, rcv_nxt.wrapping_add(rcv_wnd))
    }

    /// An otherwise unacceptable segment whose ACK field still counts. RFC
    /// 9293 §3.10.7.4: with RCV.WND zero "no segments will be acceptable,
    /// but special allowance should be made to accept valid ACKs". A peer
    /// that sent one octet past our closed window, a window probe or its
    /// FIN, puts every later segment at RCV.NXT+1. Ignoring their ACK
    /// fields would stall our own sending until that octet gets in, which
    /// it cannot while our application is not reading. Only one past: a
    /// blind attacker gains a single SEQ value, and the ACK itself still
    /// has to pass RFC 5961's check in process_ack. RSTs and SYNs keep
    /// their own rules.
    fn acks_past_closed_window(&self, seg: &Segment) -> bool {
        if !matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) || seg.flags & (flags::ACK | flags::SYN | flags::RST) != flags::ACK
        {
            return false;
        }
        self.rcv_space()
            .is_some_and(|(rcv_nxt, wnd)| wnd == 0 && seg.seq == rcv_nxt.wrapping_add(1))
    }

    /// Take the ACK field of a segment [one past our closed
    /// window](Self::acks_past_closed_window), and answer for the octet
    /// that did not fit, so the peer sees the window is still shut.
    fn handle_ack_past_closed_window(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        if !self.check_paws(seg) {
            return self.take_outgoing();
        }
        if self.process_ack(seg) {
            self.note_alive();
            if self.state == State::FinWait1 && self.fin_acked() {
                self.state = State::FinWait2;
            }
        }
        self.queue_oow_ack(seg);
        self.take_outgoing()
    }

    /// Validate RST per RFC 9293 §3.10.7.4 + RFC 5961.
    /// Returns (accept, challenge_ack).
    fn validate_rst(&self, seg: &Segment) -> (bool, bool) {
        match self.state {
            State::SynSent => {
                let snd_nxt = self.send_buf.as_ref().map(|s| s.nxt()).unwrap_or(0);
                if seg.has_flag(flags::ACK) && seg.ack == snd_nxt {
                    (true, false)
                } else {
                    (false, false)
                }
            }
            _ => {
                let Some(rb) = self.recv_buf.as_ref() else {
                    return (true, false);
                };
                let rcv_nxt = rb.nxt();
                if seg.seq == rcv_nxt {
                    return (true, false);
                }
                // RFC 5961 §3.2 checks against the window we advertised,
                // not whatever the buffer could take now, which may be more.
                let edge = self
                    .rcv_adv
                    .filter(|&adv| seq_after(adv, rcv_nxt))
                    .unwrap_or_else(|| rcv_nxt.wrapping_add(rb.window()));
                if seq_in_range(seg.seq, rcv_nxt, edge) {
                    (false, true)
                } else {
                    (false, false)
                }
            }
        }
    }

    fn resend_syn_ack(&mut self) {
        let opts = self.build_syn_options();
        let win = self.syn_window();
        let una = self.send_buf.as_ref().unwrap().una();
        let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
        let (ecn, ae) = self.ecn.synack_flags();
        let synack = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq: una,
            ack: rcv_nxt,
            flags: flags::SYN | flags::ACK | ecn,
            ae,
            window: win,
            options: opts,
            ..Default::default()
        };
        self.queue_seg(synack);
    }

    fn handle_synchronized(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        // A retransmitted SYN means our SYN-ACK was lost. The RFC's answer,
        // an ACK for an unacceptable segment, is useless to a peer in
        // SYN-SENT, which then has to outlast our RTO; resend the SYN-ACK
        // now, as Linux does.
        if self.state == State::SynReceived
            && seg.flags & (flags::SYN | flags::ACK | flags::RST) == flags::SYN
            && seq_before(seg.seq, self.recv_buf.as_ref().unwrap().nxt())
        {
            self.ecn.on_syn_again(seg);
            self.resend_syn_ack();
            return self.take_outgoing();
        }

        let simopen_synack = self.is_simopen_synack(seg);

        // 1) Sequence number check. The SYN-ACK completing a simultaneous
        // open repeats the peer's SYN, before RCV.NXT.
        if !self.segment_acceptable(seg) && !simopen_synack {
            if self.acks_past_closed_window(seg) {
                return self.handle_ack_past_closed_window(seg);
            }
            if !seg.has_flag(flags::RST) {
                // Data that was all here already: the sender resent it
                // needlessly, or the network duplicated it. Say so with a
                // D-SACK (RFC 2883), and ACK at once, as Linux's
                // tcp_send_dupack does.
                if self.sack_ok
                    && !seg.payload.is_empty()
                    && let Some(rb) = self.recv_buf.as_ref()
                {
                    let end = seg.seq.wrapping_add(seg.payload.len() as u32);
                    if seq_before_eq(end, rb.nxt()) {
                        self.dsack_out = Some(SackBlock {
                            left: seg.seq,
                            right: end,
                        });
                        self.enter_quickack();
                    }
                }
                if self.state == State::TimeWait && seg.has_flag(flags::FIN) {
                    // The peer lost our last ACK: always answer.
                    self.restart_time_wait();
                    self.queue_ack();
                } else {
                    self.queue_oow_ack(seg);
                }
            }
            return self.take_outgoing();
        }

        // 2) RST.
        if seg.has_flag(flags::RST) {
            let (accept, challenge) = self.validate_rst(seg);
            if challenge {
                self.queue_challenge_ack();
                return self.take_outgoing();
            }
            if !accept {
                return self.take_outgoing();
            }
            self.tear_down(State::Closed);
            return self.take_outgoing();
        }

        // 4) Any other SYN → challenge ACK (RFC 5961 §4). In SYN-RECEIVED
        // too: a SYN-ACK there that does not restate the IRS is not the
        // peer's, and taking it would complete the handshake on a sequence
        // space a blind attacker's SYN chose.
        if seg.has_flag(flags::SYN) && !simopen_synack {
            self.queue_challenge_ack();
            return self.take_outgoing();
        }

        // 5) ACK required.
        if !seg.has_flag(flags::ACK) {
            return self.take_outgoing();
        }
        self.ecn.on_receive(seg, self.rx_ecn);

        match self.state {
            State::SynReceived => self.handle_syn_received(seg),
            State::Established => self.handle_data_state(seg),
            State::FinWait1 => self.handle_data_state(seg),
            State::FinWait2 => self.handle_data_state(seg),
            State::CloseWait => self.handle_close_wait(seg),
            State::Closing => self.handle_closing(seg),
            State::LastAck => self.handle_last_ack(seg),
            State::TimeWait => {
                // Only a retransmitted FIN calls for an answer (RFC 9293
                // §3.10.7.4); ACKing anything else can ping-pong forever.
                if seg.has_flag(flags::FIN) {
                    self.restart_time_wait();
                    self.queue_ack();
                }
                self.take_outgoing()
            }
            _ => self.take_outgoing(),
        }
    }

    /// The peer's SYN-ACK completing a simultaneous open: it repeats the
    /// SYN we took in SYN-SENT, so its SEQ is our IRS (RFC 9293
    /// §3.10.7.3), and acknowledges ours. Only the SEQ ties it to that
    /// SYN: an off-path attacker who knows our port can send a bare SYN
    /// before the real SYN-ACK, and without this check the real SYN-ACK,
    /// whatever its SEQ, would complete the handshake on the attacker's.
    fn is_simopen_synack(&self, seg: &Segment) -> bool {
        self.state == State::SynReceived
            && seg.flags & (flags::SYN | flags::ACK | flags::RST) == flags::SYN | flags::ACK
            && self.send_buf.as_ref().is_some_and(|s| s.nxt() == seg.ack)
            && self
                .recv_buf
                .as_ref()
                .is_some_and(|r| seg.seq.wrapping_add(1) == r.nxt())
    }

    fn handle_syn_sent(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        if seg.has_flag(flags::ACK) {
            let una = self.send_buf.as_ref().unwrap().una();
            let nxt = self.send_buf.as_ref().unwrap().nxt();
            if seq_before_eq(seg.ack, una) || seq_after(seg.ack, nxt) {
                if !seg.has_flag(flags::RST) {
                    let rst = Segment {
                        src_port: self.cfg.local_port,
                        dst_port: self.cfg.remote_port,
                        seq: seg.ack,
                        flags: flags::RST,
                        ..Default::default()
                    };
                    self.queue_seg(rst);
                }
                return self.take_outgoing();
            }
        }

        if seg.has_flag(flags::RST) {
            if seg.has_flag(flags::ACK) {
                self.tear_down(State::Closed);
            }
            return self.take_outgoing();
        }

        if !seg.has_flag(flags::SYN) {
            return self.take_outgoing();
        }

        // SYN is set. Negotiate.
        self.note_alive();
        self.negotiate_options(&seg.options);

        if seg.has_flag(flags::ACK) {
            // Normal SYN-ACK.
            self.ecn
                .on_synack(self.cfg.ecn, seg, self.rx_ecn, seg.seq.wrapping_add(1));
            if self.tfo.offered
                && let Some(fastopen::Offer::Cookie(c)) = fastopen::offer(&seg.options)
            {
                self.tfo.cookie = Some(c.to_vec());
            }
            let sb = self.send_buf.as_mut().unwrap();
            sb.acknowledge(seg.ack);
            if self.tfo.syn_data > 0 {
                // What of the SYN's data the server did not take goes
                // again once the handshake is done (RFC 7413 §4.2.2).
                self.tfo.data_acked = sb.unacked() == 0;
                sb.rewind_to(sb.una());
            }
            self.retries = 0;
            self.stop_rto();
            self.recv_buf = Some(RecvBuf::new(
                seg.seq.wrapping_add(1),
                self.cfg.recv_buf_size,
            ));
            // RFC 7323 §2.2: the window in a SYN or SYN-ACK is never
            // scaled. Scaling it made the first real ACK look like a window
            // change, so it could not count as a duplicate.
            self.set_snd_wnd(seg.window as u32);
            self.rtt_sampled |= self.rto.ack_received(seg.ack, self.now);
            self.state = State::Established;
            self.handshake_done();

            if !seg.payload.is_empty() {
                self.recv_buf
                    .as_mut()
                    .unwrap()
                    .insert(seg.seq.wrapping_add(1), &seg.payload);
            }
            self.queue_ack();
            self.flush_send_queue();
            if self.cfg.keepalive {
                self.start_keepalive();
            }
            self.signal_established();
            return self.take_outgoing();
        }

        // Simultaneous open: bare SYN without ACK. Data our SYN carried
        // goes after the handshake.
        if self.tfo.syn_data > 0 {
            self.tfo.syn_data = 0;
            let sb = self.send_buf.as_mut().unwrap();
            sb.rewind_to(sb.una().wrapping_add(1));
        }
        self.recv_buf = Some(RecvBuf::new(
            seg.seq.wrapping_add(1),
            self.cfg.recv_buf_size,
        ));
        // A SYN's window is never scaled (RFC 7323 §2.2).
        self.set_snd_wnd(seg.window as u32);
        self.state = State::SynReceived;
        self.retries = 0;
        self.stop_rto();
        self.syn_data = seg.payload.clone();

        let opts = self.build_syn_options();
        let win = self.syn_window();
        let una = self.send_buf.as_ref().unwrap().una();
        let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
        let synack = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq: una,
            ack: rcv_nxt,
            flags: flags::SYN | flags::ACK,
            window: win,
            options: opts,
            ..Default::default()
        };
        self.queue_seg(synack);
        self.start_rto();
        self.take_outgoing()
    }

    fn handle_syn_received(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        let sb = self.send_buf.as_ref().unwrap();
        let (una, snd_nxt) = (sb.una(), sb.nxt());
        // A Fast Open server may have sent data after its SYN-ACK, which
        // the ACK may cover in part or not at all.
        let valid = if self.tfo.accepted {
            seq_after(seg.ack, una) && seq_before_eq(seg.ack, snd_nxt)
        } else {
            seg.ack == snd_nxt
        };
        if !valid {
            let rst = Segment {
                src_port: self.cfg.local_port,
                dst_port: self.cfg.remote_port,
                seq: seg.ack,
                flags: flags::RST,
                ..Default::default()
            };
            self.queue_seg(rst);
            return self.take_outgoing();
        }
        // The SYN-ACK; any data after it is process_ack's, below.
        self.send_buf
            .as_mut()
            .unwrap()
            .acknowledge(una.wrapping_add(1));
        self.ecn.on_handshake_ack(seg);
        // The SYN-ACK's round trip, unless it was resent (Karn).
        self.rtt_sampled |= self.rto.ack_received(seg.ack, self.now);
        self.retries = 0;
        if self.send_buf.as_ref().unwrap().unacked() == 0 {
            self.stop_rto();
        } else {
            self.start_rto();
        }
        self.set_snd_wnd((seg.window as u32) << self.snd_wnd_shift);
        self.state = State::Established;
        self.handshake_done();
        if !self.syn_data.is_empty() {
            // Nothing else has been taken in yet, so RCV.NXT is still just
            // past the SYN, where this text belongs.
            let data = std::mem::take(&mut self.syn_data);
            let rb = self.recv_buf.as_mut().unwrap();
            let nxt = rb.nxt();
            rb.insert(nxt, &data);
            self.queue_ack();
        }
        if self.cfg.keepalive {
            self.start_keepalive();
        }
        self.signal_established();
        if self.fin_queued {
            self.state = State::FinWait1;
            self.flush_send_queue();
        }
        self.handle_data_state(seg)
    }

    /// PAWS (RFC 7323 §5), and TS.Recent for the echo. False if `seg`
    /// must be dropped.
    fn check_paws(&mut self, seg: &Segment) -> bool {
        if self.update_timestamp(seg, self.now) {
            return true;
        }
        // RFC 7323 §5.3 answers with an ACK, but through the invalid-
        // segment throttle as Linux does: replayed old segments must not
        // each draw one.
        self.queue_oow_ack(seg);
        false
    }

    fn handle_data_state(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        // Some ACK is owed; `ack_now` if it must not be delayed.
        let mut need_ack = false;
        let mut ack_now = false;

        if !self.check_paws(seg) {
            return self.take_outgoing();
        }

        if seg.has_flag(flags::ACK) && !self.process_ack(seg) {
            return self.take_outgoing();
        }
        self.note_alive();

        if !seg.payload.is_empty() {
            // Released: nobody will ever read this, and ACKing it would tell
            // the peer it was delivered. Linux resets instead
            // (TCPABORTONDATA); it also stops a peer that keeps talking from
            // holding the connection open past the FIN-WAIT-2 timeout.
            let end = seg.seq.wrapping_add(seg.payload.len() as u32);
            if self.released.is_some() && seq_after(end, self.recv_buf.as_ref().unwrap().nxt()) {
                return self.abort();
            }
            let rb = self.recv_buf.as_ref().unwrap();
            let (nxt, had_holes) = (rb.nxt(), rb.has_ooo());
            self.process_data(seg);
            let dup = self.recv_buf.as_mut().unwrap().take_dup();
            if self.sack_ok && dup.is_some() {
                self.dsack_out = dup;
            }
            let rb = self.recv_buf.as_ref().unwrap();
            // RFC 5681 §4.2: at once for a segment out of order, or one
            // that fills all or part of a hole, so the sender learns of
            // the loss, or of its repair, without delay. At once too for
            // one the window did not take all of, or that left less than a
            // segment of it: the sender, stopped by the window, must see
            // how far it has closed (and would only learn of the delay
            // what it cannot use). A duplicate means our ACK was lost, or
            // the sender timed out: Linux goes into quick-ACK mode.
            let duplicate = seq_before_eq(end, nxt);
            ack_now = duplicate
                || seg.seq != nxt
                || had_holes
                || rb.has_ooo()
                || seq_before(rb.nxt(), end)
                || self.rcv_wnd_bytes() < self.rcv_mss.max(seg.payload.len() as u32);
            if duplicate {
                self.enter_quickack();
            } else {
                self.note_data(seg.payload.len());
            }
            need_ack = true;
        }

        if seg.has_flag(flags::FIN) {
            let fin_seq = seg.seq.wrapping_add(seg.data_len());
            let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
            if fin_seq == rcv_nxt {
                self.recv_buf.as_mut().unwrap().bump_nxt(1);
                self.process_fin_transition();
            } else {
                self.fin_pending = true;
                self.pending_fin_seq = fin_seq;
            }
            // Nothing will follow to share an ACK with.
            need_ack = true;
            ack_now = true;
        } else if self.state == State::FinWait1 && self.fin_acked() {
            self.state = State::FinWait2;
        }
        // ECN feedback that must not wait (see `Ecn::on_receive`).
        if self.ecn.take_ack_now() {
            need_ack = true;
            ack_now = true;
        }

        if need_ack {
            self.ack_data(ack_now);
        }
        self.take_outgoing()
    }

    /// New data of `len` bytes came in (Linux's `tcp_event_data_recv`
    /// and `tcp_measure_rcv_mss`).
    fn note_data(&mut self, len: usize) {
        let now = self.now;
        // The first data, or data after longer than an RTO without any:
        // the sender is (again) in slow start from a small window, and each
        // delayed ACK would hold it up.
        if self
            .last_data_recv
            .is_none_or(|t| now.saturating_duration_since(t) > self.rto.rto())
        {
            self.incr_quickack();
        }
        self.last_data_recv = Some(now);
        let len = u32::try_from(len).unwrap_or(u32::MAX);
        if len > self.rcv_mss {
            self.rcv_mss = len.min(u32::from(self.cfg.mss.max(1)));
        }
        if len < self.rcv_mss {
            self.ack_pushed = true;
        }
    }

    /// Quick-ACK the next segments: as many as half the window holds, as
    /// Linux's `tcp_incr_quickack` does, at least two and at most
    /// [`MAX_QUICKACKS`].
    fn incr_quickack(&mut self) {
        let n = (self.rcv_wnd_bytes() / (2 * self.rcv_mss.max(1))).clamp(2, MAX_QUICKACKS);
        self.quick_acks = self.quick_acks.max(n);
    }

    /// Linux's `tcp_enter_quickack_mode`: quick-ACK the next segments even
    /// in ping-pong mode, which this leaves.
    fn enter_quickack(&mut self) {
        self.incr_quickack();
        self.pingpong = false;
    }

    /// ACK the data just received, now or delayed (RFC 9293 §3.8.6.3,
    /// RFC 1122 §4.2.3.2, RFC 5681 §4.2): at once when `now`, in quick-ACK
    /// mode, or once more than a full-sized segment is unacknowledged, so
    /// at least every second full-sized segment is ACKed; otherwise after
    /// at most [`DELAYED_ACK`], unless data we send carries it first.
    /// Halving the ACKs halves what the sender spends on them, and lets a
    /// request's ACK ride on its answer.
    fn ack_data(&mut self, now: bool) {
        let rb = self.recv_buf.as_ref().unwrap();
        let unacked = self
            .last_ack_sent
            .map_or(u32::MAX, |last| rb.nxt().wrapping_sub(last));
        let quick = self.quick_acks > 0 && !self.pingpong;
        if now || quick || unacked > self.rcv_mss {
            if quick {
                self.quick_acks -= 1;
            }
            self.queue_ack();
        } else if self.delack_deadline.is_none() {
            self.delack_deadline = Some(self.now + DELAYED_ACK);
        }
    }

    fn process_fin_transition(&mut self) {
        match self.state {
            State::Established => {
                self.state = State::CloseWait;
                self.signal_fin_recvd();
            }
            State::FinWait1 => {
                if self.fin_acked() {
                    self.state = State::TimeWait;
                    self.stop_rto();
                    self.start_time_wait();
                } else {
                    self.state = State::Closing;
                }
                self.signal_fin_recvd();
            }
            State::FinWait2 => {
                self.state = State::TimeWait;
                self.stop_rto();
                self.start_time_wait();
                self.signal_fin_recvd();
            }
            _ => {}
        }
    }

    // Here, in CLOSING and in LAST-ACK the peer's FIN is in, but its ACKs
    // still carry timestamps: without PAWS and TS.Recent, every echo we
    // send would be stale and the peer's RTT samples would keep growing.
    fn handle_close_wait(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        if !self.check_paws(seg) {
            return self.take_outgoing();
        }
        if seg.has_flag(flags::ACK) && self.process_ack(seg) {
            self.note_alive();
        }
        self.take_outgoing()
    }

    fn handle_closing(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        if !self.check_paws(seg) {
            return self.take_outgoing();
        }
        // Data and the FIN may still be in flight (or not yet sent), so ACKs
        // here need the full treatment, not just a check for the FIN's.
        if seg.has_flag(flags::ACK) && self.process_ack(seg) {
            self.note_alive();
        }
        if self.fin_acked() {
            self.state = State::TimeWait;
            self.stop_rto();
            self.start_time_wait();
        }
        // No ACK of our own: the peer's FIN is already in, and a
        // retransmission of it fails the sequence check, which ACKs it.
        // Answering every ACK would ping-pong with a peer doing the same.
        self.take_outgoing()
    }

    fn handle_last_ack(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        if !self.check_paws(seg) {
            return self.take_outgoing();
        }
        if seg.has_flag(flags::ACK) && self.process_ack(seg) {
            self.note_alive();
        }
        if self.fin_acked() {
            self.tear_down(State::Closed);
        }
        self.take_outgoing()
    }

    fn process_data(&mut self, seg: &Segment) {
        let n = self
            .recv_buf
            .as_mut()
            .unwrap()
            .insert(seg.seq, &seg.payload);
        if n > 0 && self.cfg.autotune {
            self.rcv_rtt_measure(seg);
        }

        let mut fin_ready = false;
        if self.fin_pending && self.pending_fin_seq == self.recv_buf.as_ref().unwrap().nxt() {
            self.recv_buf.as_mut().unwrap().bump_nxt(1);
            self.fin_pending = false;
            fin_ready = true;
        }
        if n > 0 {
            // Caller can poll [`read`]; no condvar in the synchronous model.
        }
        if fin_ready {
            self.process_fin_transition();
        }
    }

    /// Time the round trip from the receiving end, for dynamic right-sizing:
    /// a connection that only receives has nothing of its own to time. With
    /// timestamps, a full-sized segment echoes the TSval of the ACK that
    /// let it be sent; without, the time to fill a window will do.
    fn rcv_rtt_measure(&mut self, seg: &Segment) {
        if self.ts_ok {
            // A short segment may have been held back by the application,
            // not the window, and its echo be older than the round trip.
            if seg.payload.len() >= options::MIN_MSS as usize
                && let Some((_, ecr)) = get_timestamp(&seg.options)
                && ecr != 0
            {
                let ms = self.ts_now().wrapping_sub(ecr);
                // A wild echo reads as a huge (or negative) delay.
                if ms < 1 << 20 {
                    self.rcv_space
                        .measure_ts(Duration::from_millis(u64::from(ms)));
                }
            }
            return;
        }
        let nxt = self.recv_buf.as_ref().unwrap().nxt();
        let edge = self
            .rcv_adv
            .filter(|&adv| seq_after(adv, nxt))
            .unwrap_or(nxt);
        self.rcv_space.measure_window(nxt, edge, self.now);
    }

    /// Dynamic right-sizing, after a read: grow the receive buffer to what
    /// the application now reads per round trip calls for.
    fn rcv_space_adjust(&mut self) {
        let srtt = Some(self.rto.srtt()).filter(|d| !d.is_zero());
        let mss = self.cfg.mss.max(1) as usize;
        if let Some(want) = self.rcv_space.adjust(self.now, srtt, mss) {
            self.grow_recv(want);
        }
    }

    /// Grow the receive buffer towards `want` bytes, as far as the
    /// configured maximum, the advertisable window and the budget allow.
    fn grow_recv(&mut self, want: usize) {
        // Past what the negotiated window scale can advertise, a larger
        // buffer would never be filled.
        let advertisable = if self.wscale_ok {
            65535usize << self.rcv_wnd_shift
        } else {
            65535
        };
        let want = want.min(self.cfg.recv_max()).min(advertisable);
        let budget = self.budget;
        let Some(rb) = self.recv_buf.as_mut() else {
            return;
        };
        let cur = rb.limit();
        // Zero is no limit at all.
        if cur == 0 || want <= cur {
            return;
        }
        let got = budget.reserve(want - cur);
        rb.set_limit(cur + got);
        self.grown += got;
    }

    /// Send-buffer auto-tuning after an ACK (Linux's `tcp_sndbuf_expand`):
    /// grow it to twice the congestion window, but only while it is what
    /// holds the sender back: the application found it full, and everything
    /// in it has been sent with room to spare in both windows. Against a
    /// peer that does not read, or a full cwnd, a larger buffer would only
    /// hold more data waiting. Less than a segment left unsent is the tail
    /// that sender SWS avoidance holds back, not a window's doing; nor is
    /// what waits on the pacer, which will go within the round trip.
    fn sndbuf_expand(&mut self) {
        if !self.cfg.autotune || !self.snd_nospace {
            return;
        }
        let cwnd = self.cc.cwnd();
        let sb = self.send_buf.as_ref().unwrap();
        if (sb.pending() >= self.mss as usize && self.pace_deadline.is_none())
            || sb.unacked() as u32 >= self.snd_wnd
            || self.in_flight() >= cwnd
        {
            return;
        }
        let want = autotune::sndbuf_target(cwnd, self.mss as u32).min(self.cfg.send_max());
        let budget = self.budget;
        let Some(sb) = self.send_buf.as_mut() else {
            return;
        };
        let cur = sb.capacity();
        if want <= cur {
            return;
        }
        let got = budget.reserve(want - cur);
        sb.set_capacity(cur + got);
        self.grown += got;
    }

    /// Put the buffers back to their initial sizes and return what they
    /// grew by to the budget.
    fn release_growth(&mut self) {
        if let Some(sb) = self.send_buf.as_mut() {
            sb.set_capacity(self.cfg.send_buf_size);
        }
        if let Some(rb) = self.recv_buf.as_mut() {
            rb.set_limit(self.cfg.recv_buf_size);
        }
        self.budget.release(std::mem::take(&mut self.grown));
    }

    /// Apply the segment's window, per RFC 9293 §3.10.7.4: only from a
    /// segment no older than the one that last set it, so a reordered old
    /// segment cannot roll the window back. Returns true if it changed.
    fn update_send_window(&mut self, seg: &Segment) -> bool {
        if let Some((wl1, wl2)) = self.snd_wl
            && (seq_before(seg.seq, wl1) || (seg.seq == wl1 && seq_before(seg.ack, wl2)))
        {
            return false;
        }
        self.snd_wl = Some((seg.seq, seg.ack));
        let wnd = (seg.window as u32) << self.snd_wnd_shift;
        let changed = wnd != self.snd_wnd;
        self.set_snd_wnd(wnd);
        changed
    }

    fn set_snd_wnd(&mut self, wnd: u32) {
        self.snd_wnd = wnd;
        self.max_snd_wnd = self.max_snd_wnd.max(wnd);
    }

    /// Process the ACK field. Returns false if the segment must be dropped
    /// without looking at its data or FIN.
    fn process_ack(&mut self, seg: &Segment) -> bool {
        let ack = seg.ack;
        let opts = &seg.options;
        let una = self.send_buf.as_ref().unwrap().una();
        let snd_nxt = self.send_buf.as_ref().unwrap().nxt();
        // RFC 9293 §3.10.7.4 drops a segment acknowledging what was never
        // sent, and RFC 5961 §5.2 one acknowledging further back than any
        // window the peer offered: neither can come from the peer, and a
        // blind attacker who guessed only the SEQ would get its payload in.
        let oldest = una.wrapping_sub(self.max_snd_wnd.min(1 << 30));
        if seq_after(ack, snd_nxt) || seq_before(ack, oldest) {
            self.queue_challenge_ack();
            return false;
        }
        // Before anything this ACK lets go (draft-ietf-ccwg-bbr §4.1.2.4).
        self.check_app_limited();
        // The window comes first: the flush below must see this segment's.
        let wnd_changed = self.update_send_window(seg);
        let now = self.now;
        let ecr = self.ts_echo(seg);
        let flight = self.send_buf.as_ref().unwrap().unacked() as u32;
        let advanced = seq_after(ack, una);

        // The scoreboard: what this ACK says reached the receiver.
        self.score.begin_ack();
        let mut acked = 0;
        let mut d = Delivery::default();
        if advanced {
            acked = self.send_buf.as_mut().unwrap().acknowledge(ack);
            d = self.score.ack(ack, now, ecr);
        }
        let mut dsack = None;
        let mut sack_seen = false;
        if self.sack_ok {
            let blocks = get_sack_blocks(opts);
            if !blocks.is_empty() {
                sack_seen = true;
                dsack = dsack_block(&blocks, ack);
                let rest = &blocks[dsack.is_some() as usize..];
                d.merge(self.score.sack(rest, now, ecr));
            }
        }
        // ECN feedback, before the rate sample, which counts what it
        // reports marked.
        let progress = advanced || d.delivered > 0;
        let delivered_now = d.delivered.max(acked);
        let ce_bytes = self
            .ecn
            .on_ack(seg, progress, delivered_now, self.mss as u32);
        if let Some(b) = ce_bytes {
            self.score.on_ce(u64::from(b));
        }
        // An MTU probe delivered, as sent: the path carries its size.
        if let Some(p) = self.mtu_probe
            && (seq_after_eq(ack, p.end) || self.score.sacked_at(p.start))
        {
            self.mtu_probe = None;
            self.plpmtud.on_success(p.mtu, now);
            self.sync_mss();
        }
        let rs = self.score.rate_sample();
        if let Some(r) = self.score.ack_rtt() {
            self.pace_srtt = Some(self.pace_srtt.map_or(r, |s| (s * 7 + r) / 8));
        }

        // RFC 5681 §2: only an ACK of SND.UNA with data outstanding, no
        // payload or FIN, and the same window is a duplicate. A window
        // update is not a loss signal, and its window must be used. With
        // SACK, RFC 6675 §2 counts one that reports data not SACKed before
        // whatever its window: that is a segment arriving above a hole,
        // even at a receiver whose window moves as its application reads.
        //
        // Nor is an ACK of a zero window: it is what a probe draws, and
        // the receiver taking nothing says nothing about loss.
        let bare = seg.payload.is_empty() && !seg.has_flag(flags::FIN);
        let dup = !advanced
            && ack == una
            && una != snd_nxt
            && (!wnd_changed || d.delivered > 0)
            && self.snd_wnd > 0
            && bare;

        let mut rtt = None;
        if advanced {
            self.retries = 0;
            rtt = self.sample_rtt(seg, flight);
        }
        // A duplicate of the loss probe itself, SACK-less: both copies
        // arrived (RFC 8985 §7.4.2, case 2).
        let probe_dup = !advanced && !sack_seen && !wnd_changed && bare;
        self.tlp_on_ack(ack, dsack, probe_dup);
        self.recover_on_ack(AckEvent {
            ack,
            advanced,
            acked,
            d,
            dsack,
            dup,
            flight,
            ecr,
            rtt,
            rs,
            ce: ce_bytes.is_some(),
        });

        if self.snd_wnd > 0 && self.persist_deadline.is_some() && (advanced || wnd_changed) {
            self.stop_persist();
        }
        if advanced {
            if self.send_buf.as_ref().unwrap().unacked() == 0 {
                self.stop_rto();
            } else if self.score.head_sacked() {
                // The receiver would have acknowledged the first segment
                // had it kept it: it has dropped what it SACKed (reneged,
                // RFC 2018 §8). The RTO forgets the SACKs; let it fire a
                // moment from now, as Linux's tcp_check_sack_reneging does,
                // rather than a whole RTO, so a transient renege does not
                // draw a burst of retransmissions.
                let delay = (self.rto.srtt() / 2).max(RENEGE_DELAY);
                self.rto_deadline = Some(self.now + delay);
            } else {
                self.start_rto();
            }
        }

        self.flush_send_queue();
        if advanced {
            // RFC 8985 §7.2: on an ACK of new data, too.
            self.schedule_loss_probe();
            // After the flush, as Linux's tcp_check_space: only once what
            // the buffer held has gone out does it show whether it ran dry.
            self.sndbuf_expand();
        }
        true
    }

    /// TSecr of `seg`, if timestamps are on and it echoes one.
    fn ts_echo(&self, seg: &Segment) -> Option<u32> {
        if !self.ts_ok {
            return None;
        }
        get_timestamp(&seg.options)
            .map(|(_, ecr)| ecr)
            .filter(|&e| e != 0)
    }

    /// Loss detection, spurious-retransmission detection and the recovery
    /// state machine, for an ACK.
    fn recover_on_ack(&mut self, ev: AckEvent) {
        let AckEvent {
            ack,
            advanced,
            acked,
            d,
            dsack,
            dup,
            flight,
            ecr,
            rtt,
            rs,
            ce,
        } = ev;
        let mss = self.mss as u32;
        let model = self.cc.model_based();
        let lost_before = self.score.rate().lost();
        // RFC 6937's DeliveredData.
        let mut delivered = d.delivered;
        // Without SACK, each duplicate stands for a segment that left the
        // network, as Linux's Reno emulation counts it: the pipe shrinks by
        // a segment, which is Limited Transmit (RFC 3042) before recovery,
        // and what PRR counts as delivered during it.
        if !self.sack_ok {
            delivered = if dup {
                mss
            } else {
                acked.saturating_sub(self.reno_sacked).max(acked.min(mss))
            };
            if dup {
                self.dup_acks += 1;
                // After a timeout, duplicates count only once new data has
                // gone out past what it marked lost (F-RTO's, Linux's
                // tcp_process_loss): they report that new data arriving.
                let nxt = self.send_buf.as_ref().unwrap().nxt();
                if self.ca != CaState::Loss || seq_after(nxt, self.recover) {
                    let unacked = self.send_buf.as_ref().unwrap().unacked() as u32;
                    let holes = self.score.lost_bytes().max(mss);
                    self.reno_sacked = (self.reno_sacked + mss).min(unacked.saturating_sub(holes));
                }
            } else if advanced {
                self.dup_acks = 0;
                // The duplicates stood for segments this ACK covers, less
                // the one it was waiting for.
                self.reno_sacked = self.reno_sacked.saturating_sub(acked.saturating_sub(mss));
            }
        }

        // Was the response to a loss needless? A D-SACK for everything the
        // episode resent (RFC 3708), or the echo of a timestamp older than
        // its first retransmission (RFC 3522) says so; F-RTO (RFC 5682)
        // looks at the ACKs after a timeout.
        let was = self.ca;
        let mut undone = false;
        if self.undo.marker.is_some() {
            if let Some(b) = dsack
                && self.dsack_covers_retransmissions(b)
            {
                undone = self.undo_recovery(acked);
            }
            // Only the ACK of the retransmission itself tells: one that
            // advances SND.UNA short of it may echo an older segment, such
            // as one resent in an earlier episode and still outstanding.
            if !undone
                && advanced
                && let Some(end) = self.undo.eifel_end
                && seq_after_eq(ack, end)
            {
                self.undo.eifel_end = None;
                if self.ca != CaState::Open
                    && let (Some(e), Some(ts)) = (ecr, self.undo.retrans_ts)
                    && (e.wrapping_sub(ts) as i32) < 0
                {
                    undone = self.undo_recovery(acked);
                }
            }
        }
        let frto_was = self.frto;
        if !undone && self.ca == CaState::Loss && self.frto != Frto::Off {
            undone = self.frto_on_ack(ev);
        }
        if advanced && std::mem::take(&mut self.black_hole_undo) {
            self.undo_black_hole(acked);
        }

        let mut exiting = undone && was != CaState::Open;
        if advanced && self.ca != CaState::Open && self.recovered(ack) {
            // RFC 6675 §5: done once RecoveryPoint is acknowledged; without
            // SACK, only past it (RFC 6582 §3.2 step 1 and §4.1: segments
            // resent needlessly draw duplicates right at it).
            if model {
                self.cc.on_recovery_exit();
            } else if self.ca == CaState::Recovery {
                self.cc.set_cwnd(self.cc.ssthresh());
            }
            self.ca = CaState::Open;
            self.reno_sacked = 0;
            exiting = true;
        } else if advanced && self.ca == CaState::Recovery && !self.sack_ok {
            // A partial ACK (RFC 6582 §3.2 step 5): the segment it stops at
            // was lost too.
            self.score.mark_head_lost();
        }
        // A reduction for ECN is over once data sent after it began is
        // acknowledged: past its start, not up to it, as Linux has it, so
        // the CWR it sent has reached the receiver.
        if advanced && self.cwr_high.is_some_and(|h| seq_after(ack, h)) {
            self.cwr_high = None;
            if !model && self.ca == CaState::Open {
                self.cc.set_cwnd(self.cc.ssthresh());
            }
        }
        // ECN feedback: congestion, a round trip before any loss would
        // show it (RFC 3168 §6.1.2). Answered before growth, as Linux's
        // tcp_fastretrans_alert comes before tcp_cong_control.
        if ce {
            self.enter_cwr();
        }

        // Growth, outside fast recovery: in slow start after a timeout too.
        // Not on the ACK that undid a response: RFC 4015 step (9) has just
        // set cwnd for it. Nor during a reduction for ECN, which PRR runs.
        if advanced && self.ca != CaState::Recovery && !undone && !model && self.cwr_high.is_none()
        {
            let bytes = if self.sack_ok { d.delivered } else { acked };
            let use_ = self.cwnd_use(flight);
            let a = self.ack_info(bytes, use_, rtt, ack, rs, delivered, 0);
            self.cc.on_ack(&a);
        }
        // RFC 7661: what the path carried, sampled outside loss recovery
        // only, and forgotten once one is over (§4.2, §4.4.1).
        if exiting {
            self.pipe_ack.reset();
            self.nvp_since = None;
        } else if advanced && self.ca == CaState::Open {
            self.pipe_ack.on_ack(self.now, ack, self.rto.srtt());
            self.validate_cwnd();
        }
        // F-RTO step 2b sends up to two new segments (RFC 5682 §2.1).
        if frto_was != self.frto && matches!(self.frto, Frto::Second { .. }) && !model {
            let cap = self.in_flight().saturating_add(2 * mss);
            self.cc.set_cwnd(self.cc.cwnd().min(cap));
        }

        if self.sack_ok {
            self.rack_detect(dsack.is_some(), exiting);
        } else if dup && self.dup_acks == DUP_THRESH && self.ca == CaState::Open {
            // RFC 5681 §3.2: the third duplicate ACK.
            self.score.mark_head_lost();
        }
        if self.ca == CaState::Open && self.score.lost_bytes() > 0 {
            self.on_losses_found();
        }
        if self.ca == CaState::Recovery || (self.ca == CaState::Open && self.cwr_high.is_some()) {
            self.prr_update(delivered);
        }
        // A model-based controller takes every ACK, once the losses it
        // revealed are known (as Linux runs BBR after tcp_fastretrans_alert).
        if model {
            self.feed_losses();
            let newly_lost = (self.score.rate().lost() - lost_before) as u32;
            if advanced || delivered > 0 || newly_lost > 0 {
                let bytes = if self.sack_ok { d.delivered } else { acked };
                let mut a = self.ack_info(bytes, flight, rtt, ack, rs, delivered, newly_lost);
                a.ce = ce;
                self.cc.on_ack(&a);
                if self.cc.take_app_limited() {
                    self.score.mark_app_limited();
                }
            }
        }
    }

    /// What the controller is told of an ACK that delivered `bytes`
    /// (DeliveredData `delivered`, `newly_lost` marked lost on it).
    #[allow(clippy::too_many_arguments)]
    fn ack_info(
        &mut self,
        bytes: u32,
        flight: u32,
        rtt: Option<Duration>,
        ack: u32,
        rs: Option<RateSample>,
        delivered: u32,
        newly_lost: u32,
    ) -> Ack {
        Ack {
            now: self.now,
            bytes_acked: bytes,
            flight,
            rtt,
            ack,
            snd_nxt: self.send_buf.as_ref().unwrap().nxt(),
            rs,
            newly_acked: delivered,
            newly_lost,
            inflight: self.in_flight(),
            delivered: self.score.rate().delivered(),
            newest_rtt: self.score.ack_rtt(),
            cwnd_limited: std::mem::take(&mut self.cwnd_blocked),
            sack: self.sack_ok,
            ecn: self.ecn.active(),
            ce: false,
            delivered_ce: self.score.rate().delivered_ce(),
        }
    }

    /// Tell a model-based controller of each segment marked lost since
    /// last asked, with C.lost as it stood when that one was marked.
    fn feed_losses(&mut self) {
        let losses = self.score.take_losses();
        if losses.is_empty() {
            return;
        }
        let (total, delivered) = (self.score.rate().lost(), self.score.rate().delivered());
        let mut after: u64 = losses.iter().map(|&(_, len)| u64::from(len)).sum();
        for (tx, len) in losses {
            let total_lost = total - after + u64::from(len);
            after -= u64::from(len);
            self.cc.on_lost(&Lost {
                tx,
                len,
                total_lost,
                delivered,
            });
        }
    }

    /// Mark the connection application-limited if it has run out of data
    /// with room in the window and nothing to repair (draft-ietf-ccwg-bbr
    /// §4.1.2.4): delivery rate samples until what is in flight is
    /// delivered then show the application's pace, not the path's.
    fn check_app_limited(&mut self) {
        let Some(sb) = self.send_buf.as_ref() else {
            return;
        };
        if !self.state.is_synchronized() {
            return;
        }
        if sb.pending() < self.mss as usize
            && self.in_flight() < self.cc.cwnd()
            && self.score.lost_bytes() == 0
        {
            self.score.mark_app_limited();
        }
    }

    /// A loss response begins: keep what undoing it would restore (RFC
    /// 4015 step (0)). `timeout` if a retransmission timeout, not fast
    /// recovery.
    fn begin_undo(&mut self, timeout: bool) {
        self.cc.save_undo();
        let sb = self.send_buf.as_ref().unwrap();
        self.undo = Undo {
            marker: Some(sb.una()),
            pipe_prev: (sb.unacked() as u32).max(self.cc.ssthresh()),
            timeout,
            srtt_prev: self.rto.srtt() + 2 * CLOCK_TICK,
            rttvar_prev: self.rto.rttvar(),
            retrans_ts: None,
            eifel_end: None,
            retrans: Some(Vec::new()),
        };
    }

    /// Note a retransmission of `[seq, seq+len)` carrying `tsval`, for the
    /// episode's undo.
    fn note_retransmission(&mut self, seq: u32, len: u32, tsval: u32) {
        if self.ca == CaState::Open || self.undo.marker.is_none() {
            return;
        }
        let end = seq.wrapping_add(len);
        if self.undo.retrans_ts.is_none() {
            self.undo.retrans_ts = Some(tsval);
            self.undo.eifel_end = Some(end);
        }
        let Some(r) = self.undo.retrans.as_mut() else {
            return;
        };
        if let Some(last) = r.last_mut()
            && last.1 == seq
        {
            last.1 = end;
        } else if r.len() < MAX_UNDO_RANGES {
            r.push((seq, end));
        } else {
            self.undo.retrans = None;
        }
    }

    /// Take a D-SACK against what the episode retransmitted: true once
    /// every retransmission has been reported received twice, so none was
    /// needed (RFC 3708 §3). A D-SACK of data not retransmitted in the
    /// episode, which the network duplicated, counts for nothing.
    fn dsack_covers_retransmissions(&mut self, b: SackBlock) -> bool {
        let Some(marker) = self.undo.marker else {
            return false;
        };
        let Some(r) = self.undo.retrans.as_mut() else {
            return false;
        };
        if r.is_empty() || !seq_after(b.right, marker) {
            return false;
        }
        let before = r.len();
        let mut changed = false;
        let mut out = Vec::with_capacity(before + 1);
        for &(l, e) in r.iter() {
            if !seq_before(b.left, e) || !seq_after(b.right, l) {
                out.push((l, e));
                continue;
            }
            changed = true;
            if seq_before(l, b.left) {
                out.push((l, b.left));
            }
            if seq_after(e, b.right) {
                out.push((b.right, e));
            }
        }
        *r = out;
        changed && r.is_empty()
    }

    /// The loss response was spurious: put the window back, per RFC 4015
    /// steps (8) and (9), and return to the open state. What is still
    /// marked lost is unmarked, so new data goes out rather than needless
    /// retransmissions; RACK marks anything really lost again. `acked` is
    /// what the ACK acknowledged. Returns true.
    fn undo_recovery(&mut self, acked: u32) -> bool {
        self.score.unmark_lost();
        let mss = self.mss as u32;
        // cwnd = FlightSize + min(bytes_acked, IW): no burst, and slow
        // start back to where ssthresh was.
        let cwnd = self.cc.cwnd().max(
            self.in_flight()
                .saturating_add(acked.min(initial_window(mss))),
        );
        let ssthresh = self.cc.ssthresh().max(self.undo.pipe_prev);
        self.cc.undo(cwnd, ssthresh);
        if self.undo.timeout {
            self.rto_adapt = Some((self.undo.srtt_prev, self.undo.rttvar_prev, self.recover));
        }
        self.undo.marker = None;
        self.ca = CaState::Open;
        self.frto = Frto::Off;
        self.reno_sacked = 0;
        self.retries = 0;
        true
    }

    /// F-RTO's steps 2 and 3 (RFC 5682 §2.1, and §3.1 with SACK) for an
    /// ACK after a timeout. Returns true if it found the timeout spurious
    /// and undid it.
    fn frto_on_ack(&mut self, ev: AckEvent) -> bool {
        let mss = self.mss as u32;
        match self.frto {
            Frto::Off => false,
            Frto::First { head_end } => {
                if ev.advanced {
                    let sb = self.send_buf.as_ref().unwrap();
                    let rp = sb.nxt();
                    let room = self.snd_wnd > sb.unacked() as u32;
                    // 2a: the ACK covers RecoveryPoint, so it says nothing
                    // of data sent before the timeout; or it does not cover
                    // all of what the timeout resent. 2b needs new data to
                    // send, and room for it.
                    self.frto = if seq_after_eq(ev.ack, rp)
                        || seq_before(ev.ack, head_end)
                        || sb.pending() == 0
                        || !room
                    {
                        Frto::Off
                    } else {
                        Frto::Second { rp }
                    };
                } else if ev.dup && !self.sack_ok {
                    // 2a, without SACK: a duplicate.
                    self.frto = Frto::Off;
                }
                false
            }
            Frto::Second { rp } => {
                if !ev.advanced && !ev.dup {
                    return false;
                }
                // 3b: data sent before the timeout, and not resent, got
                // through after all. With SACK that has to lie below
                // RecoveryPoint, and nothing past it be acknowledged (3a).
                let spurious = if self.sack_ok {
                    let beyond =
                        seq_after(ev.ack, rp) || ev.d.max_end.is_some_and(|e| seq_after(e, rp));
                    !beyond && ev.d.orig_min_end.is_some_and(|e| seq_before_eq(e, rp))
                } else {
                    ev.advanced
                };
                if spurious {
                    return self.undo_recovery(ev.acked);
                }
                // 3a: the loss was real. Two round trips have passed since
                // the timeout, which a conventional sender would have
                // spent growing cwnd to three segments. The go-back-N
                // repair starts now, so `recover` covers the new data too:
                // duplicates its needless resends draw must not start fast
                // recovery once that new data is acknowledged (RFC 6582
                // §3.2 step 1).
                self.frto = Frto::Off;
                if !self.cc.model_based() {
                    self.cc.set_cwnd(self.cc.cwnd().min(3 * mss));
                }
                self.recover = self.send_buf.as_ref().unwrap().nxt();
                false
            }
        }
    }

    /// PRR (RFC 6937): after an ACK in fast recovery reporting `delivered`
    /// bytes, set cwnd so that what may be sent now keeps the flight on
    /// its way down to ssthresh in proportion to what is delivered, rather
    /// than falling silent for half a round trip and then bursting, as
    /// cwnd = ssthresh would; and once losses have taken the flight below
    /// ssthresh, lets it grow back no faster than slow start (PRR-SSRB).
    fn prr_update(&mut self, delivered: u32) {
        // BBR sets cwnd in recovery from its model.
        if self.cc.model_based() {
            return;
        }
        self.prr_delivered += u64::from(delivered);
        let pipe = self.in_flight();
        let mut sndcnt = prr_sndcnt(
            self.prr_delivered,
            self.prr_out,
            self.recover_fs,
            self.cc.ssthresh(),
            pipe,
            delivered,
            self.mss as u32,
        );
        // The fast retransmit goes at once, whatever the pipe (RFC 5681
        // §3.2 step 2, and Linux's PRR).
        if self.prr_out == 0 {
            sndcnt = sndcnt.max(self.mss as u32);
        }
        self.cc.set_cwnd(pipe.saturating_add(sndcnt));
    }

    /// Count `len` bytes sent, for PRR and pacing.
    #[inline]
    fn note_sent(&mut self, len: u32) {
        if self.ca == CaState::Recovery || self.cwr_high.is_some() {
            self.prr_out += u64::from(len);
        }
        if self.pacing_on() {
            self.pace_credit -= f64::from(len);
        }
    }

    /// Whether an ACK up to `ack` ends the current recovery episode.
    fn recovered(&self, ack: u32) -> bool {
        if self.sack_ok {
            seq_after_eq(ack, self.recover)
        } else {
            seq_after(ack, self.recover)
        }
    }

    /// RACK (RFC 8985 §6.2 steps 4 and 5) after an ACK, or when the
    /// reordering timer fires: mark what is overdue lost, and time the rest.
    fn rack_detect(&mut self, dsack: bool, exiting: bool) {
        let recovering = self.ca != CaState::Open;
        let reo = self
            .score
            .reo_wnd(dsack, recovering, exiting, self.rto.srtt());
        let (_, wait) = self.score.detect_loss(self.now, reo);
        self.reo_deadline = wait.map(|w| self.now + w);
    }

    /// Enter fast recovery (RFC 6675 §5, RFC 5681 §3.2): something is
    /// deemed lost.
    fn enter_recovery(&mut self) {
        let sb = self.send_buf.as_ref().unwrap();
        let (flight, nxt) = (sb.unacked() as u32, sb.nxt());
        // A loss while the window is coming down for ECN is part of the
        // same congestion: the reduction goes on, not a second one on top
        // (Linux's tcp_enter_recovery in CWR). Nor would undoing the loss
        // response bring back what ECN took.
        let reducing = self.cwr_high.take().is_some() && !self.cc.model_based();
        self.begin_undo(false);
        if reducing {
            self.undo.pipe_prev = self.cc.ssthresh();
        } else {
            let flight_used = self.loss_flight(flight);
            self.cc.on_loss(flight_used);
            // RFC 6937 §3's RecoverFS: the flight the reduction is spread
            // over.
            self.recover_fs = flight.max(1);
            self.prr_delivered = 0;
            self.prr_out = 0;
        }
        self.recover = nxt;
        self.ca = CaState::Recovery;
        self.ecn.queue_cwr();
        // RFC 8985 §7.1: a probe of the flight this recovery repairs is
        // moot.
        self.tlp_end = None;
        self.pto_deadline = None;
    }

    /// ECN feedback reported congestion: reduce the window (RFC 3168
    /// §6.1.2), once per window of data and not during loss recovery,
    /// which has reduced it already. Nothing is resent, and nothing is to
    /// undo: a mark is never spurious. PRR brings the window down over the
    /// round trip, as in fast recovery (Linux's CWR state).
    ///
    /// By less than for a loss, in congestion avoidance: RFC 8511's
    /// Alternative Backoff with ECN (see `on_ecn`), which FreeBSD offers
    /// and Linux does not. Only an AQM marks, and it marks while the queue
    /// is still short: a cut by β from there leaves the link idle, for
    /// seconds on a long fat path, as a cut at a shallow buffer's overflow
    /// does. Against a queue marking at a fifth of the BDP it was worth a
    /// quarter more goodput, at the same queueing delay.
    ///
    /// A model-based controller answers from the ACK itself.
    fn enter_cwr(&mut self) {
        if self.ca != CaState::Open || self.cwr_high.is_some() {
            return;
        }
        let sb = self.send_buf.as_ref().unwrap();
        let (flight, nxt) = (sb.unacked() as u32, sb.nxt());
        self.cwr_high = Some(nxt);
        self.ecn.queue_cwr();
        if self.cc.model_based() {
            return;
        }
        let used = self.loss_flight(flight);
        self.cc.on_ecn(used);
        self.recover_fs = flight.max(1);
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.undo.marker = None;
    }

    /// Note whether cwnd is validated (RFC 7661 §4.3): the non-validated
    /// phase begins when pipeACK falls below half of cwnd, and its time
    /// counts from then.
    fn validate_cwnd(&mut self) {
        let p = self.pipe_ack.value(self.now, self.rto.srtt());
        if cwv::non_validated(p, self.cc.cwnd()) {
            self.nvp_since.get_or_insert(self.now);
        } else {
            self.nvp_since = None;
        }
    }

    /// The flight a loss response is to be based on, for a loss found with
    /// `flight` bytes outstanding. In the non-validated phase cwnd is not
    /// what was in use: RFC 7661 §4.4.1 bases the response on
    /// max(pipeACK, LossFlightSize), and cwnd is brought down to that
    /// first, so the controller's cut starts from what the path carried.
    /// RFC 7661 also takes what was retransmitted off at the end of
    /// recovery; PRR has by then brought the flight down in step with what
    /// was delivered, which already leaves the losses out.
    fn loss_flight(&mut self, flight: u32) -> u32 {
        if self.nvp_since.is_none() || self.cc.model_based() {
            return flight;
        }
        let used = self
            .pipe_ack
            .value(self.now, self.rto.srtt())
            .unwrap_or(0)
            .max(flight);
        if self.cc.cwnd() > used {
            self.cc.set_cwnd(used);
        }
        self.nvp_since = None;
        used
    }

    /// Before new data goes out: a window unused for a while is cut back.
    /// After an idle spell of more than an RTO, halved per RTO down to the
    /// initial window, as Linux's `tcp_cwnd_restart` does (RFC 5681 §4.1,
    /// RFC 2861's decay); ssthresh keeps three quarters of it, so slow
    /// start regains what the pause took. Without that, or short of it,
    /// after RFC 7661's non-validated period: halved once per period
    /// (§4.4.3).
    fn restart_idle_window(&mut self) {
        // BBR restarts from idle by its own model (draft §5.4).
        if self.ca != CaState::Open || self.cc.model_based() {
            return;
        }
        let mss = self.mss as u32;
        let iw = initial_window(mss);
        let idle_from = self.last_data_sent.filter(|_| {
            self.cfg.slow_start_after_idle && self.send_buf.as_ref().unwrap().unacked() == 0
        });
        let rto = self.rto.rto();
        if let Some(t) = idle_from
            && self.now.saturating_duration_since(t) > rto
        {
            let cwnd = self.cc.cwnd();
            let restart = iw.min(cwnd);
            let ssthresh = self.cc.ssthresh().max(cwnd / 2 + cwnd / 4);
            let mut left = self.now.saturating_duration_since(t);
            let mut w = cwnd;
            while left > rto && w > restart {
                left -= rto;
                w >>= 1;
            }
            self.cc.restart(w.max(restart), ssthresh);
            self.pipe_ack.reset();
            self.nvp_since = None;
            // Once per spell.
            self.last_data_sent = Some(self.now);
            return;
        }
        self.validate_cwnd();
        let Some(mut since) = self.nvp_since else {
            return;
        };
        while self.now.saturating_duration_since(since) >= cwv::NVP {
            let cwnd = self.cc.cwnd();
            let ssthresh = self.cc.ssthresh().max(cwnd / 2 + cwnd / 4);
            self.cc.restart((cwnd / 2).max(iw).min(cwnd), ssthresh);
            since += cwv::NVP;
        }
        self.nvp_since = Some(since);
    }

    /// In fast recovery.
    #[cfg(test)]
    fn in_recovery(&self) -> bool {
        self.ca == CaState::Recovery
    }

    /// Take the RTT samples an ACK that advanced SND.UNA offers: the timed
    /// segment's (RFC 6298, Karn's algorithm), measured to the nanosecond,
    /// and failing that the timestamp echo, which with timestamps every
    /// such ACK carries (RFC 7323 §4.2) and which a retransmission cannot
    /// make ambiguous, since it carries a TSval of its own. `flight` is
    /// what was outstanding before the ACK. Returns the sample, if any.
    fn sample_rtt(&mut self, seg: &Segment, flight: u32) -> Option<Duration> {
        let timed = self.rto.timed_rtt(seg.ack, self.now);
        let rtt = timed.or_else(|| self.ts_echo_rtt(seg))?;
        // RFC 7323 Appendix G: a window of timestamps gives about one
        // sample per two segments, the ACKs of a delayed-ACK receiver.
        let per_window = if self.ts_ok {
            flight.div_ceil(2 * self.mss as u32).max(1)
        } else {
            1
        };
        match self.rto_adapt {
            // RFC 4015 step (11): the first sample of data sent after a
            // spurious timeout makes the timer no less conservative than
            // it was before it.
            Some((srtt, rttvar, recover)) if seq_after(seg.ack, recover) => {
                self.rto.after_spurious_timeout(srtt, rttvar, rtt);
                self.rto_adapt = None;
            }
            _ => self.rto.sample_of(rtt, per_window),
        }
        self.score.rtt_sample(rtt, self.now);
        self.rtt_sampled = true;
        Some(rtt)
    }

    /// The round trip the timestamp echoed in `seg` has made, if it has
    /// one: at least its age in whole milliseconds, and less than one more.
    /// Rounded up, not down: a sample never reads shorter than the path.
    fn ts_echo_rtt(&self, seg: &Segment) -> Option<Duration> {
        let ecr = self.ts_echo(seg)?;
        // A wild echo reads as a huge (or negative) age.
        let age = self.ts_now().wrapping_sub(ecr);
        if age >= 1 << 20 {
            return None;
        }
        // The TSval was taken in the millisecond `age` before this one:
        // what has passed of this one belongs to the round trip too.
        let since = self.now.saturating_duration_since(self.ts_base);
        let into_ms = (since.as_nanos() % 1_000_000) as u64;
        Some(Duration::from_millis(u64::from(age)) + Duration::from_nanos(into_ms))
    }

    /// Bytes in flight: RFC 6675's pipe, less what a peer without SACK has
    /// reported leaving the network with duplicate ACKs.
    fn in_flight(&self) -> u32 {
        self.score.pipe().saturating_sub(self.reno_sacked)
    }

    /// Arm the loss probe timeout (RFC 8985 §7.2), or disarm it where a
    /// probe has no place: without SACK, during recovery, once anything is
    /// SACKed (the reordering timer's business), or with nothing out.
    fn schedule_loss_probe(&mut self) {
        self.pto_deadline = None;
        let Some(sb) = self.send_buf.as_ref() else {
            return;
        };
        if !self.sack_ok
            || self.ca != CaState::Open
            || self.score.sacked_segs() > 0
            || sb.unacked() == 0
            || !self.state.is_synchronized()
        {
            return;
        }
        let srtt = self.rto.srtt();
        let pto = if srtt.is_zero() {
            DEFAULT_RTO
        } else if sb.unacked() <= self.mss as usize {
            // A lone segment's ACK may be delayed.
            srtt * 2 + TLP_MAX_ACK_DELAY
        } else {
            srtt * 2 + TLP_MIN_SLACK
        };
        let mut at = self.now + pto;
        if let Some(rto) = self.rto_deadline
            && rto < at
        {
            at = rto;
        }
        self.pto_deadline = Some(at);
    }

    /// The loss probe timeout expired (RFC 8985 §7.3): send one segment,
    /// new data if there is any, else the last one again, to draw the ACK
    /// that lets RACK see a tail loss, rather than wait for the RTO.
    fn on_loss_probe(&mut self) {
        self.pto_deadline = None;
        let Some(sb) = self.send_buf.as_ref() else {
            return;
        };
        let (unacked, pending, una) = (sb.unacked() as u32, sb.pending(), sb.una());
        if unacked == 0 {
            return;
        }
        if self.tlp_end.is_none()
            && self.rtt_sampled
            && self.ca == CaState::Open
            && self.score.sacked_segs() == 0
            && self.snd_wnd > 0
            && self.state.is_synchronized()
        {
            let opts = self.segment_options();
            let room = self.payload_room(&opts);
            let rcv_room = self.snd_wnd.saturating_sub(unacked) as usize;
            let n = room.min(pending).min(rcv_room);
            if n > 0 {
                self.send_new(n, opts);
                self.tlp_retrans = false;
            } else if let Some((seq, len, fin)) = self.score.last(room as u32) {
                self.resend(seq, len, fin);
                self.tlp_retrans = true;
            }
            self.tlp_end = Some(self.send_buf.as_ref().unwrap().nxt());
            self.rtt_sampled = false;
        }
        // The RTO, not another probe, is the last resort.
        if seq_before(una, self.send_buf.as_ref().unwrap().nxt()) {
            self.start_rto();
        }
    }

    /// TLP recovery detection (RFC 8985 §7.4.2) for an ACK up to `ack`,
    /// carrying `dsack` if any; `probe_dup` if it is a duplicate without
    /// SACK blocks.
    fn tlp_on_ack(&mut self, ack: u32, dsack: Option<SackBlock>, probe_dup: bool) {
        let Some(end) = self.tlp_end else {
            return;
        };
        if seq_before(ack, end) {
            return;
        }
        if !self.tlp_retrans {
            self.tlp_end = None;
        } else if dsack.is_some_and(|b| seq_before(b.left, end) && seq_after_eq(b.right, end)) {
            // Case 1: the original and the probe both arrived.
            self.tlp_end = None;
        } else if seq_after(ack, end) {
            // The probe repaired a loss: respond to it as to any other.
            self.tlp_end = None;
            if self.ca == CaState::Open && !self.cc.model_based() && self.cwr_high.is_none() {
                let flight = self.send_buf.as_ref().unwrap().unacked() as u32;
                let flight = self.loss_flight(flight);
                self.cc.on_loss(flight);
                self.cc.set_cwnd(self.cc.ssthresh());
                self.undo.marker = None;
            }
        } else if probe_dup {
            // Case 2, from a receiver without D-SACK.
            self.tlp_end = None;
        }
    }

    /// The reordering timer expired (RFC 8985 §6.2 step 5): what it waited
    /// on is lost unless an ACK came first.
    fn on_reorder_timeout(&mut self) {
        self.reo_deadline = None;
        if !self.sack_ok || !self.state.is_synchronized() || self.send_buf.is_none() {
            return;
        }
        self.rack_detect(false, false);
        if self.ca == CaState::Open && self.score.lost_bytes() > 0 {
            self.on_losses_found();
        }
        if self.cc.model_based() {
            self.feed_losses();
        }
        if self.ca == CaState::Recovery {
            self.prr_update(0);
        }
        self.flush_send_queue();
    }

    /// Send `[seq, seq+len)` again, or the FIN at `seq` if `fin`.
    fn resend(&mut self, seq: u32, len: u32, fin: bool) {
        let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
        let sb = self.send_buf.as_ref().unwrap();
        let una = sb.una();
        let payload = if fin {
            Vec::new()
        } else {
            sb.data_at(seq, len as usize).to_vec()
        };
        if !fin && payload.is_empty() {
            return;
        }
        let len = if fin { 1 } else { payload.len() as u32 };
        // Resending the probe settles it: lost, and to its size unless
        // something sent before it was lost too, which says congestion.
        if let Some(p) = self.mtu_probe.as_mut() {
            if seq_before(seq, p.start) {
                p.others_lost = true;
            } else if seq_before(seq, p.end) {
                let p = *p;
                self.mtu_probe = None;
                if !p.others_lost {
                    self.plpmtud.on_failure(p.mtu, self.now);
                }
            }
        }
        let mut seg = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq,
            ack: rcv_nxt,
            flags: if fin {
                flags::FIN | flags::ACK
            } else {
                flags::ACK | flags::PSH
            },
            window: self.rcv_window(),
            payload,
            ..Default::default()
        };
        self.add_options(&mut seg);
        self.queue_seg(seg);
        let tsval = self.ts_now();
        self.score.on_retransmit(seq, len, self.now, tsval);
        self.note_sent(len);
        self.note_retransmission(seq, len, tsval);
        self.last_data_sent = Some(self.now);
        // Karn's algorithm: no timing of a segment that went twice.
        self.rto.invalidate_timing();
        // Linux re-arms the RTO for the first segment only: re-arming it
        // for every retransmission would put off the timeout of a lost one
        // for as long as recovery goes on.
        if seq == una || self.rto_deadline.is_none() {
            self.start_rto();
        }
    }

    /// Resend what the scoreboard deems lost, lowest first, while the pipe
    /// has room (RFC 6675 §5 NextSeg rule 1, RFC 8985's retransmissions).
    fn retransmit_lost(&mut self) {
        // A zero window is the persist timer's and the RTO's to probe.
        // F-RTO holds retransmissions back until it knows the timeout was
        // not spurious (RFC 5682 §2.1 step 2b).
        if self.snd_wnd == 0
            || !self.state.is_synchronized()
            || self.frto != Frto::Off
            || self.score.lost_bytes() == 0
        {
            return;
        }
        loop {
            if self.in_flight() >= self.cc.cwnd() {
                self.cwnd_blocked = true;
                break;
            }
            let room = self.send_mss() as u32;
            let Some((seq, len, fin)) = self.score.next_lost(room) else {
                break;
            };
            // Nothing past the right edge but the first segment (Linux's
            // tcp_retransmit_skb): the receiver would drop it.
            let una = self.send_buf.as_ref().unwrap().una();
            if seq != una && !seq_before(seq, una.wrapping_add(self.snd_wnd)) {
                break;
            }
            if !self.pace_ready() {
                self.pace_wait();
                break;
            }
            self.resend(seq, len, fin);
        }
    }

    /// Send `n` bytes of new data as one segment carrying `opts`.
    fn send_new(&mut self, n: usize, opts: Vec<TcpOption>) {
        let data = self.send_buf.as_ref().unwrap().peek_unsent(n).to_vec();
        if data.is_empty() {
            return;
        }
        let snd_nxt = self.send_buf.as_ref().unwrap().nxt();
        let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
        let seg = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq: snd_nxt,
            ack: rcv_nxt,
            flags: flags::ACK | flags::PSH,
            window: self.rcv_window(),
            payload: data,
            options: opts,
            ..Default::default()
        };
        let len = seg.payload.len();
        self.queue_seg(seg);
        self.send_buf.as_mut().unwrap().advance_sent(len);
        let tsval = self.ts_now();
        self.score
            .on_send(snd_nxt, len as u32, false, self.now, tsval);
        self.note_sent(len as u32);
        self.last_data_sent = Some(self.now);
        // Answering the peer's data within a delayed ACK's time (Linux's
        // tcp_event_data_sent).
        if self
            .last_data_recv
            .is_some_and(|t| self.now.saturating_duration_since(t) < DELAYED_ACK)
        {
            self.pingpong = true;
        }
        self.rto.start_timing(snd_nxt, self.now);
        if self.rto_deadline.is_none() {
            self.start_rto();
        }
    }

    fn flush_send_queue(&mut self) {
        // Anything held back by pacing is looked at again now.
        self.pace_late = self
            .pace_deadline
            .take()
            .map_or(Duration::ZERO, |d| self.now.saturating_duration_since(d));
        let pending = self.send_buf.as_ref().unwrap().pending();
        if self.cc.model_based() && (pending > 0 || self.score.lost_bytes() > 0) {
            let idle = self.in_flight() == 0 && self.score.rate().is_app_limited();
            self.cc.on_transmit(self.now, idle);
        }
        // Lost data before new data: the receiver can deliver nothing past
        // the first hole until it is filled.
        self.retransmit_lost();
        if pending > 0 {
            self.restart_idle_window();
        }
        let mut sent_new = false;
        loop {
            let pending = self.send_buf.as_ref().unwrap().pending();
            if pending == 0 {
                break;
            }
            let cc_room = self.cc.cwnd().saturating_sub(self.in_flight());
            let unacked = self.send_buf.as_ref().unwrap().unacked() as u32;
            let rcv_room = self.snd_wnd.saturating_sub(unacked);
            let opts = self.segment_options();
            let room = self.payload_room(&opts);
            if (cc_room as usize) < pending.min(room) {
                self.cwnd_blocked = true;
            }
            if cc_room == 0 || rcv_room == 0 {
                break;
            }
            let avail = cc_room.min(rcv_room) as usize;
            if let Some((n, mtu)) = self.probe_due(&opts, room, pending, cc_room, rcv_room) {
                if !self.pace_ready() {
                    self.pace_wait();
                    break;
                }
                let start = self.send_buf.as_ref().unwrap().nxt();
                self.send_new(n, opts);
                self.mtu_probe = Some(Probe {
                    start,
                    end: start.wrapping_add(n as u32),
                    mtu,
                    others_lost: false,
                });
                sent_new = true;
                continue;
            }
            let n = avail.min(room).min(pending);

            // Sender SWS avoidance (RFC 9293 §3.8.6.2.1): avoid tiny
            // segments. Once closing, nothing more will be written to
            // coalesce with, so send what there is. A full segment is what
            // fits beside this segment's options; against a peer whose
            // window never reaches one, half the largest window it has
            // offered is as good, or every send would wait for all data in
            // flight to be ACKed.
            //
            // Without Nagle a short segment still goes out if it is all
            // there is to send, as Linux's TCP_NODELAY has it: only the
            // application is holding it back, and more may be long coming.
            // One the window cuts short still waits, or a peer reading
            // slowly would be sent a trickle of tiny segments.
            let half_wnd = self.max_snd_wnd / 2;
            let big_enough = n >= room
                || (half_wnd > 0 && n >= half_wnd as usize)
                || (self.cfg.nodelay && n == pending);
            // Nagle waits on data in flight, not on the SYN-ACK a Fast Open
            // server answers before the handshake completes.
            let syn = usize::from(self.state == State::SynReceived);
            let in_flight = self.send_buf.as_ref().unwrap().unacked() > syn;
            if !big_enough && in_flight && !self.fin_queued {
                break;
            }
            if !self.pace_ready() {
                self.pace_wait();
                break;
            }
            self.send_new(n, opts);
            sent_new = true;
        }

        if self.fin_queued
            && self.send_buf.as_ref().unwrap().pending() == 0
            && matches!(
                self.state,
                State::FinWait1 | State::Closing | State::LastAck
            )
        {
            // The FIN takes a sequence number, so it needs a byte of window
            // like data does. Past the right edge, every later segment from
            // us would carry an out-of-window SEQ and have its ACK ignored.
            let unacked = self.send_buf.as_ref().unwrap().unacked() as u32;
            if self.snd_wnd > unacked {
                self.queue_fin();
                sent_new = true;
            } else if unacked == 0 && self.persist_deadline.is_none() {
                self.start_persist();
            }
        }

        // Zero-window probing.
        if self
            .send_buf
            .as_ref()
            .map(|s| s.pending() > 0)
            .unwrap_or(false)
            && self.snd_wnd == 0
            && self.persist_deadline.is_none()
        {
            self.start_persist();
        }
        if sent_new {
            // RFC 8985 §7.2: after new data goes out.
            self.schedule_loss_probe();
        }
        self.cwnd_validate();
    }

    /// Note, after sending what may be sent, whether cwnd held anything
    /// back (Linux's tcp_cwnd_validate; see `is_cwnd_limited`).
    fn cwnd_validate(&mut self) {
        let sb = self.send_buf.as_ref().unwrap();
        let (una, nxt, unacked) = (sb.una(), sb.nxt(), sb.unacked() as u32);
        let waiting = sb.pending() > 0 || self.score.lost_bytes() > 0;
        let limited = waiting && self.in_flight().saturating_add(self.mss as u32) > self.cc.cwnd();
        if !seq_before(una, self.cwnd_usage_seq)
            || limited
            || (!self.is_cwnd_limited && unacked > self.max_flight)
        {
            self.is_cwnd_limited = limited;
            self.max_flight = unacked;
            self.cwnd_usage_seq = nxt;
        }
    }

    /// The flight a controller is to judge cwnd's use by, for an ACK that
    /// found `flight` outstanding: cwnd itself if it held data back this
    /// window, else the most the window had out.
    fn cwnd_use(&self, flight: u32) -> u32 {
        if self.is_cwnd_limited {
            flight.max(self.cc.cwnd())
        } else {
            flight.max(self.max_flight)
        }
    }

    // --- Pacing ---------------------------------------------------------------

    /// Whether sending is paced: as configured, and always for a
    /// controller that sets a pacing rate of its own (BBR).
    fn pacing_on(&self) -> bool {
        self.cfg.pacing || self.cc.model_based()
    }

    /// The pacing rate in bytes per second, if pacing: the controller's,
    /// or else Linux's (`tcp_update_pacing_rate`): cwnd (or what is
    /// outstanding, if more) per SRTT, doubled while cwnd is under half
    /// of ssthresh so slow start can still double it each round trip, and
    /// 1.2 times after, a little ahead of the ACK clock. None before a
    /// round trip has been measured: there is nothing to pace by. See
    /// `pace_srtt` for the round trip.
    fn pace_rate(&self) -> Option<u64> {
        if !self.pacing_on() {
            return None;
        }
        if let Some(r) = self.cc.pacing_rate() {
            return Some(r.max(1));
        }
        let srtt = self.pace_srtt.unwrap_or_else(|| self.rto.srtt());
        if srtt.is_zero() {
            return None;
        }
        let unacked = self.send_buf.as_ref().map_or(0, |s| s.unacked() as u32);
        let cwnd = self.cc.cwnd().max(unacked);
        let gain = if self.cc.cwnd() < self.cc.ssthresh() / 2 {
            2.0
        } else {
            1.2
        };
        Some(((f64::from(cwnd) * gain / srtt.as_secs_f64()) as u64).max(1))
    }

    /// What pacing sends at a time: a millisecond's worth at `rate`, and at
    /// least two segments, as Linux's TSO autosizing (`sk_pacing_shift`)
    /// has it. Not capped at 64 KB as it is there: the timer that releases
    /// the next quantum fires no sooner than a millisecond later (see the
    /// drivers' alarm), and a smaller quantum would cap the rate.
    fn pace_quantum(&self, rate: u64) -> f64 {
        (rate as f64 / 1000.0).max(2.0 * f64::from(self.mss))
    }

    /// Whether pacing lets a segment go now. The credit grows at the
    /// pacing rate to two quanta, and more by what the pacing timer was
    /// late (up to a round trip): data held back that long would have been
    /// sent had the timer been on time, and a host whose timers slip by a
    /// few milliseconds would otherwise pace a slow flow at a fraction of
    /// its rate. A sender idle for a while may burst two quanta, no more.
    fn pace_ready(&mut self) -> bool {
        let Some(rate) = self.pace_rate() else {
            return true;
        };
        let late = self
            .pace_late
            .min(self.pace_srtt.unwrap_or_else(|| self.rto.srtt()));
        let cap = 2.0 * self.pace_quantum(rate) + rate as f64 * late.as_secs_f64();
        let dt = self.now.saturating_duration_since(self.pace_stamp);
        self.pace_stamp = self.now;
        self.pace_credit = (self.pace_credit + rate as f64 * dt.as_secs_f64()).min(cap);
        self.pace_credit > 0.0
    }

    /// Pacing holds data back: send again once a quantum has built up.
    fn pace_wait(&mut self) {
        let Some(rate) = self.pace_rate() else {
            return;
        };
        let need = (self.pace_quantum(rate) - self.pace_credit).max(0.0);
        self.pace_deadline = Some(self.now + Duration::from_secs_f64(need / rate as f64));
    }

    // --- Timers (synchronous, deadline-based) -----------------------------

    fn start_rto(&mut self) {
        self.rto_deadline = Some(self.now + self.rto.rto());
    }

    fn stop_rto(&mut self) {
        self.rto_deadline = None;
    }

    fn start_persist(&mut self) {
        if self.persist_backoff == Duration::ZERO {
            self.persist_backoff = self.rto.rto();
        }
        self.persist_deadline = Some(self.now + self.persist_backoff);
    }

    fn stop_persist(&mut self) {
        self.persist_deadline = None;
        self.persist_backoff = Duration::ZERO;
    }

    fn start_time_wait(&mut self) {
        self.stop_keepalive();
        self.stop_persist();
        self.release_buffers();
        self.time_wait_deadline = Some(self.now + self.cfg.time_wait);
    }

    fn restart_time_wait(&mut self) {
        if self.time_wait_deadline.is_some() {
            self.time_wait_deadline = Some(self.now + self.cfg.time_wait);
        }
    }

    /// Whether `seg`, arriving at this connection, is a new connection's SYN
    /// that may take over its 4-tuple. True only in TIME-WAIT, for a bare SYN
    /// numbered beyond anything the old connection used (RFC 9293 §3.10.7.4
    /// and RFC 6191; Linux's `tcp_timewait_state_process`): nothing of the
    /// old connection can then be mistaken for the new one's. When both
    /// connections use timestamps, the SYN's TSval decides instead, as RFC
    /// 6191 §2 asks: one older than TS.Recent is an old duplicate (PAWS)
    /// whatever its sequence number, and a newer one is safe even with a
    /// lower ISN. The caller drops this `Conn` and handles the SYN as for a
    /// fresh connection.
    pub fn accepts_new_syn(&self, seg: &Segment) -> bool {
        if self.state != State::TimeWait
            || !seg.has_flag(flags::SYN)
            || seg.has_flag(flags::ACK)
            || seg.has_flag(flags::RST)
        {
            return false;
        }
        let Some(rb) = self.recv_buf.as_ref() else {
            return false;
        };
        let seq_newer = seq_after(seg.seq, rb.nxt());
        // ts_ok: the old connection used timestamps, and the new one will
        // too if its SYN offers them (we have them enabled).
        let ts_val = get_timestamp(&seg.options)
            .filter(|_| self.ts_ok)
            .map(|(v, _)| v);
        match ts_val {
            Some(v) => match (v.wrapping_sub(self.ts_recent) as i32).signum() {
                1 => true,
                0 => seq_newer,
                _ => false,
            },
            None => seq_newer,
        }
    }

    fn start_keepalive(&mut self) {
        self.stop_keepalive();
        self.keepalive_deadline = Some(self.now + self.cfg.keepalive_idle);
    }

    fn stop_keepalive(&mut self) {
        self.keepalive_deadline = None;
    }

    /// When the earliest pending timer comes due: the next time
    /// [`tick`](Self::tick) has something to do. `None` if no timer is
    /// running. It moves with every call that sends or takes in a segment
    /// (sending data arms the retransmission timer, taking in data may arm
    /// the delayed ACK), so a driver reads it again after each.
    ///
    /// A deadline already past is due now.
    pub fn next_deadline(&self) -> Option<Instant> {
        // Exactly the timers tick() acts on, under the same conditions: a
        // deadline it would leave in place would have its driver spin.
        let live = !self.closed && self.state != State::Closed;
        let mut next = self.time_wait_deadline;
        let mut consider = |d: Option<Instant>| {
            if let Some(d) = d {
                next = Some(next.map_or(d, |n| n.min(d)));
            }
        };
        if live {
            consider(self.reo_deadline);
            consider(self.pto_deadline);
            consider(self.pace_deadline);
            consider(self.rto_deadline);
            consider(self.persist_deadline);
            consider(self.keepalive_deadline);
            consider(self.delack_deadline);
        }
        consider(self.fin_wait2_deadline());
        next
    }

    /// When a released connection in FIN-WAIT-2 is reset for the peer's
    /// silence (see [`ConnConfig::fin_wait2_timeout`]).
    fn fin_wait2_deadline(&self) -> Option<Instant> {
        if self.state != State::FinWait2 {
            return None;
        }
        let released = self.released?;
        let t = self.cfg.fin_wait2_timeout?;
        released.max(self.last_recv).checked_add(t)
    }

    /// Drive any expired timers, and return the segments they produce.
    ///
    /// Call it once [`next_deadline`](Self::next_deadline) has passed. It
    /// is harmless to call it early or more often: a timer runs only once
    /// due. Each fires late by however late it is called, which is what a
    /// fixed polling interval costs: a retransmission or a delayed ACK
    /// waits for the next poll.
    pub fn tick(&mut self) -> Vec<Vec<u8>> {
        let now = self.clock();

        let live = !self.closed && self.state != State::Closed;
        // Before timers that may send (draft-ietf-ccwg-bbr §4.1.2.4).
        if live
            && [
                self.reo_deadline,
                self.pto_deadline,
                self.rto_deadline,
                self.pace_deadline,
            ]
            .iter()
            .any(|d| d.is_some_and(|d| now >= d))
        {
            self.check_app_limited();
        }
        // RACK's reordering timer and the loss probe, ahead of the RTO:
        // what they send restarts it, and then it has nothing to do.
        if let Some(d) = self.reo_deadline
            && now >= d
            && live
        {
            self.on_reorder_timeout();
        }
        if let Some(d) = self.pto_deadline
            && now >= d
            && live
        {
            self.on_loss_probe();
        }
        // Pacing released what it held back (the flush takes the deadline,
        // and how late it is).
        if let Some(d) = self.pace_deadline
            && now >= d
        {
            if live && self.state.is_synchronized() && self.send_buf.is_some() {
                self.flush_send_queue();
            } else {
                self.pace_deadline = None;
            }
        }
        // RTO.
        if let Some(d) = self.rto_deadline
            && now >= d
            && !self.closed
            && self.state != State::Closed
        {
            self.on_rto_timeout();
        }
        // Persist.
        if let Some(d) = self.persist_deadline
            && now >= d
            && !self.closed
            && self.state != State::Closed
        {
            self.on_persist_timeout();
        }
        // TIME-WAIT.
        if let Some(d) = self.time_wait_deadline
            && now >= d
        {
            self.time_wait_deadline = None;
            self.state = State::Closed;
            self.closed = true;
            self.release_buffers();
        }
        // FIN-WAIT-2: the peer has gone quiet without closing, and nothing
        // on our side is waiting for what it might still send. Quiet since
        // the release, that is: before it, a half-closed application was
        // still reading, and the peer was free to take its time.
        if self.fin_wait2_deadline().is_some_and(|d| now >= d) {
            let rst = self.abort();
            self.outgoing.extend(rst);
            let marks = std::mem::take(&mut self.last_marks);
            self.outgoing_ecn.extend(marks);
        }
        // Keepalive.
        if let Some(d) = self.keepalive_deadline
            && now >= d
            && !self.closed
            && self.state != State::Closed
        {
            self.on_keepalive();
        }
        // Delayed ACK, last: anything the timers above sent carried it.
        if let Some(d) = self.delack_deadline
            && now >= d
            && !self.closed
            && self.state != State::Closed
        {
            self.delack_deadline = None;
            // The answer the ACK was waiting to ride on did not come in
            // time: not a request/response exchange after all (Linux's
            // tcp_delack_timer_handler).
            self.pingpong = false;
            self.queue_ack();
        }

        self.take_outgoing()
    }

    fn on_rto_timeout(&mut self) {
        // The retransmission at a lowered MSS did not get through either.
        self.black_hole_undo = false;
        let zero_window =
            self.snd_wnd == 0 && !matches!(self.state, State::SynSent | State::SynReceived);
        if zero_window {
            // The receiver closed its window under data in flight, so our
            // retransmits are really zero-window probes and its duplicate
            // ACKs never count as progress. Keep going while it answers, as
            // Linux does; give up only once as many probes in a row as
            // retransmissions otherwise go unanswered. Not by the time since
            // it last answered: with the backoff at MAX_RTO, a timer
            // serviced a little late (a coarse tick) puts more than MAX_RTO
            // between an answer and the next timeout of a peer that
            // answered every probe at once.
            if self.probes_exhausted() {
                self.tear_down(State::Closed);
                return;
            }
        } else {
            self.retries += 1;
            if self.retries > MAX_RETRIES {
                self.tear_down(State::Closed);
                return;
            }
        }
        self.rto.backoff();
        self.rto.invalidate_timing();
        let synchronized = self.state.is_synchronized();
        let mut frto = false;
        self.reo_deadline = None;
        self.pto_deadline = None;
        self.tlp_end = None;
        if synchronized {
            // Only the first timeout of a segment sets ssthresh (RFC 5681
            // §3.1); `retries` counts timeouts without an ACK in between. A
            // zero window does not count them, but its timeouts after the
            // first are probes, not new losses.
            // Nor one during a reduction for ECN, which has set it for this
            // window already (Linux's tcp_enter_loss).
            let repeated = self.retries > 1
                || (zero_window && self.ca == CaState::Loss)
                || (self.cwr_high.take().is_some() && !self.cc.model_based());
            self.cwr_high = None;
            self.ecn.queue_cwr();
            let sb = self.send_buf.as_ref().unwrap();
            let (flight, nxt) = (sb.unacked() as u32, sb.nxt());
            // A new episode keeps what undoing it would take; a timeout in
            // fast recovery, or a repeated one, keeps the episode's.
            let fresh = self.ca == CaState::Open;
            if fresh && !self.score.is_empty() {
                self.begin_undo(true);
            } else {
                self.undo.timeout = true;
            }
            // F-RTO (RFC 5682): not after other recovery is underway (it
            // would read ACKs for that recovery's retransmissions as
            // progress), but again on a timeout repeated while it runs.
            frto = !zero_window && (fresh || self.frto != Frto::Off);
            self.frto = Frto::Off;
            self.cc.on_retransmit_timeout(flight, repeated);
            // RFC 7661 §4.4: a timeout ends the non-validated phase.
            self.pipe_ack.reset();
            self.nvp_since = None;
            // A SYN or SYN-ACK alone is not a loss the data's repair has to
            // track.
            if !self.score.is_empty() {
                // A receiver that still holds the first segment SACKed would
                // have acknowledged it: it has dropped what it SACKed, and
                // RFC 2018 §8 has the sender stop relying on any of it.
                // Otherwise SACKs stay, as Linux keeps them: what the
                // receiver holds need not go again.
                if self.score.head_sacked() {
                    self.score.clear_sacks();
                }
                if self.sack_ok {
                    let reo = self.score.reo_wnd(false, true, false, self.rto.srtt());
                    self.score.mark_lost_on_rto(self.now, reo);
                } else {
                    self.score.mark_all_lost();
                }
                self.ca = CaState::Loss;
                self.recover = nxt;
            }
            // BBR: what is in flight and one segment (draft §5.6.4.4).
            if self.cc.model_based() {
                self.feed_losses();
                let cwnd = self.in_flight().saturating_add(self.mss as u32);
                self.cc.set_cwnd(cwnd);
            }
        } else {
            // With only the SYN or SYN-ACK out there is no flight to halve:
            // ssthresh would drop to its 2-segment floor and hold the whole
            // connection in congestion avoidance from the start. RFC 5681
            // §3.1 asks only for the loss window once data begins.
            self.syn_lost = true;
        }
        self.dup_acks = 0;
        self.reno_sacked = 0;

        match self.state {
            State::SynSent => {
                // A SYN with data unanswered goes again without it, nor its
                // cookie: something on the way may drop SYNs that carry
                // data (RFC 7413 §4.1.3.1). SND.NXT stays past the data, as
                // on Linux: the server may have taken it from the first SYN
                // and lost only its SYN-ACK, whose ACK then covers it. If
                // the SYN-ACK does not, the data follows the handshake.
                if self.tfo.syn_data > 0 {
                    self.tfo.syn_data_lost = true;
                    self.tfo.request = None;
                }
                let opts = self.build_syn_options();
                let win = self.syn_window();
                let una = self.send_buf.as_ref().unwrap().una();
                let (ecn, ae) = self.ecn.syn_flags(self.cfg.ecn);
                let syn = Segment {
                    src_port: self.cfg.local_port,
                    dst_port: self.cfg.remote_port,
                    seq: una,
                    flags: flags::SYN | ecn,
                    ae,
                    window: win,
                    options: opts,
                    ..Default::default()
                };
                self.queue_seg(syn);
            }
            State::SynReceived => self.resend_syn_ack(),
            State::Established
            | State::CloseWait
            | State::FinWait1
            | State::Closing
            | State::LastAck => {
                // A timeout for a black hole's doing is no spurious one
                // for F-RTO to find: the loss is real, the size's.
                let black_hole = !zero_window
                    && self.retries >= plpmtud::BLACK_HOLE_RTOS
                    && self.check_black_hole();
                // RFC 6298 §5.4: the first unacknowledged segment, whatever
                // the window; the rest follows as ACKs open cwnd.
                let room = self.send_mss() as u32;
                if let Some((seq, len, fin)) = self.score.head(room) {
                    self.resend(seq, len, fin);
                    if frto && !black_hole && self.ca == CaState::Loss {
                        self.frto = Frto::First {
                            head_end: seq.wrapping_add(len),
                        };
                    }
                }
            }
            _ => {}
        }
        self.start_rto();
    }

    /// Timeouts keep coming for the first segment (RFC 4821 §5): the path
    /// may have a black hole that drops it for its size and sends no ICMP
    /// message to say so. Lower the MSS to PLPMTUD's base, or to half the
    /// segment if that is smaller already, for its retransmission, and let
    /// probing find what the path carries from there.
    /// Returns whether it did.
    fn check_black_hole(&mut self) -> bool {
        let Some((_, len, false)) = self.score.head(u32::MAX) else {
            return false;
        };
        // As it goes again: cut to the MSS, with the options it carries
        // now. A segment small enough, however often it times out, is not
        // the path's MTU's doing.
        let opts = options::options_len(&self.segment_options()) as u32;
        let size = (len + opts).min(u32::from(self.mss)) + self.header_overhead();
        if let Some(low) = self.plpmtud.black_hole_target(size) {
            self.plpmtud.on_black_hole(low, self.now);
            self.mtu_probe = None;
            self.sync_mss();
            // Whatever else went out at the old size is as lost, not only
            // what the timeout marked, as Linux's tcp_simple_retransmit
            // has it: left to RACK, each would take a timeout of its own,
            // nothing sent after it getting through to show its loss.
            self.score
                .mark_longer_lost(u32::from(self.mss).saturating_sub(opts));
            self.black_hole_undo = true;
            return true;
        }
        false
    }

    /// The first retransmission after a black hole was suspected got
    /// through at the smaller size: the timeouts that found it were the
    /// segments' size, not congestion. Their window cut is undone, as RFC
    /// 4015 undoes a spurious timeout's (ssthresh back, and cwnd to what
    /// is in flight and an initial window at most), but unlike a spurious
    /// timeout the losses were real: what went out at the old size is
    /// still resent. Without this, a black hole at the start of a transfer
    /// would leave it in congestion avoidance from a few segments, which
    /// on a long path takes CUBIC tens of seconds to grow out of.
    fn undo_black_hole(&mut self, acked: u32) {
        if self.undo.marker.take().is_none() || self.cc.model_based() {
            return;
        }
        let iw = initial_window(u32::from(self.mss));
        let cwnd = self
            .cc
            .cwnd()
            .max(self.in_flight().saturating_add(acked.min(iw)));
        let ssthresh = self.cc.ssthresh().max(self.undo.pipe_prev);
        self.cc.undo(cwnd, ssthresh);
        if self.undo.timeout {
            self.rto_adapt = Some((self.undo.srtt_prev, self.undo.rttvar_prev, self.recover));
        }
    }

    /// Count a zero-window probe about to be sent; true if the connection
    /// should give up instead. Unanswered probes are limited like
    /// retransmissions; once released, answered ones are limited too (see
    /// [`ORPHAN_RETRIES`]).
    fn probes_exhausted(&mut self) -> bool {
        if self.probes_out >= MAX_RETRIES
            || (self.released.is_some() && self.orphan_probes >= ORPHAN_RETRIES)
        {
            return true;
        }
        self.probes_out += 1;
        if self.released.is_some() {
            self.orphan_probes += 1;
        }
        false
    }

    fn on_persist_timeout(&mut self) {
        if self.snd_wnd > 0 {
            self.stop_persist();
            self.flush_send_queue();
            return;
        }
        if self.send_buf.as_ref().is_none_or(|s| s.pending() == 0) {
            // Nothing new to probe with; bytes already in flight are the
            // RTO's to resend. A FIN waiting on the window is the probe
            // instead: a receiver takes a bare FIN at RCV.NXT even into a
            // zero window.
            self.stop_persist();
            if self.fin_queued && self.send_buf.as_ref().is_some_and(|s| s.unacked() == 0) {
                self.queue_fin();
            }
            return;
        }
        // Linux's tcp_probe_timer: as many unanswered probes as the RTO
        // allows unanswered retransmissions. An answer, even one that still
        // shuts the window, resets the count, so a peer that is merely not
        // reading is probed for as long as it takes.
        if self.probes_exhausted() {
            self.tear_down(State::Closed);
            return;
        }
        // Bytes in flight from before the window closed are probed with
        // one of them, from SND.UNA (RFC 9293 §3.8.6.1); the RTO repairs
        // them as well.
        //
        // Otherwise the probe carries no data: SEQ = SND.UNA-1, which the
        // peer answers with an ACK showing its window, as Linux does
        // (tcp_xmit_probe_skb). RFC 9293 would send the next new byte, but
        // that lies past the peer's right edge. Counted as sent, it moves
        // the SEQ of every later segment out of a window that stays shut,
        // and the peer ignores their ACK fields. Held back, it leaves
        // SND.NXT behind a peer that took it but whose ACK was lost, and
        // our segments look stale to that peer.
        let sb = self.send_buf.as_ref().unwrap();
        let first = sb.data_at(sb.una(), 1);
        let (seq, payload) = if first.is_empty() {
            (sb.una().wrapping_sub(1), Vec::new())
        } else {
            (sb.una(), first.to_vec())
        };
        let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
        let mut seg = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq,
            ack: rcv_nxt,
            flags: flags::ACK,
            window: self.rcv_window(),
            payload,
            ..Default::default()
        };
        self.add_options(&mut seg);
        self.queue_seg(seg);
        self.persist_backoff = self.persist_backoff.saturating_mul(2);
        if self.persist_backoff > MAX_RTO {
            self.persist_backoff = MAX_RTO;
        }
        self.persist_deadline = Some(self.now + self.persist_backoff);
    }

    fn on_keepalive(&mut self) {
        // Like Linux, through the close handshake as well: a half-closed
        // application in FIN-WAIT-2 would otherwise wait forever on a peer
        // that vanished. TIME-WAIT has nobody left to probe for.
        if !self.state.is_synchronized() || self.state == State::TimeWait {
            self.stop_keepalive();
            return;
        }
        // With anything in flight or held back by the window, the RTO or
        // persist timer is already watching the peer, and a probe at
        // SND.NXT-1 may fall inside its window and draw no answer (Linux's
        // tcp_keepalive_timer holds off too). Released in FIN-WAIT-2, the
        // FIN-WAIT-2 timeout is in charge: answered probes would keep a
        // peer that never closes around for good.
        let busy = self
            .send_buf
            .as_ref()
            .is_some_and(|s| s.unacked() > 0 || s.pending() > 0);
        let orphaned = self.state == State::FinWait2
            && self.released.is_some()
            && self.cfg.fin_wait2_timeout.is_some();
        if busy || orphaned {
            self.start_keepalive();
            return;
        }
        if self.now.saturating_duration_since(self.last_recv) >= self.cfg.keepalive_idle {
            if self.keepalive_sent >= self.cfg.keepalive_count {
                self.tear_down(State::Closed);
                return;
            }
            let snd_nxt = self.send_buf.as_ref().unwrap().nxt().wrapping_sub(1);
            let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
            let mut seg = Segment {
                src_port: self.cfg.local_port,
                dst_port: self.cfg.remote_port,
                seq: snd_nxt,
                ack: rcv_nxt,
                flags: flags::ACK,
                window: self.rcv_window(),
                ..Default::default()
            };
            self.add_options(&mut seg);
            self.queue_seg(seg);
            self.keepalive_sent += 1;
        }
        if self.keepalive_sent > 0 {
            self.keepalive_deadline = Some(self.now + self.cfg.keepalive_interval);
        } else {
            // Heard from the peer since the timer was set: the idle time
            // runs from then, not from now, or a probe could come up to
            // twice the idle time after it went quiet.
            self.keepalive_deadline = Some(self.last_recv + self.cfg.keepalive_idle);
        }
    }

    // --- Application I/O --------------------------------------------------

    /// Non-blocking read: copies up to `buf.len()` bytes from the receive
    /// queue into `buf`. Returns the number of bytes read, or `Ok(0)` when
    /// no data is currently available. Use [`Conn::fin_received`] / [`Conn::is_closed`]
    /// to distinguish "would block" from EOF.
    ///
    /// A read that opens the receive window well past what was advertised
    /// queues a window update, sent with the next [`Conn::tick`] or
    /// [`Conn::take_outgoing`]; without it a peer facing a closed window
    /// would wait on its persist timer.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        self.clock();
        let Some(rb) = self.recv_buf.as_mut() else {
            return 0;
        };
        let n = rb.read(buf);
        if n > 0
            && self.cfg.autotune
            && matches!(
                self.state,
                State::Established | State::FinWait1 | State::FinWait2
            )
        {
            self.rcv_space.on_read(n);
            self.rcv_space_adjust();
        }
        let rb = self.recv_buf.as_ref().unwrap();
        let nxt = rb.nxt();
        let remaining = self
            .rcv_adv
            .filter(|&adv| seq_after(adv, nxt))
            .map_or(0, |adv| adv.wrapping_sub(nxt));
        // The same tests as Linux's tcp_cleanup_rbuf: worth a segment
        // once the window at least doubles; and a delayed ACK for a short
        // segment is not worth holding once the application has read
        // everything, outside a request/response exchange: that short
        // segment may have been the sender's last before Nagle holds the
        // next one back for this very ACK.
        let open = self.rcv_wnd_bytes();
        let drained = self.delack_deadline.is_some()
            && self.ack_pushed
            && !self.pingpong
            && rb.readable() == 0;
        if n > 0
            && (drained || (open > remaining && open >= remaining.saturating_mul(2)))
            && matches!(
                self.state,
                State::Established | State::FinWait1 | State::FinWait2
            )
        {
            self.queue_ack();
        }
        n
    }

    /// Non-blocking write: appends as much data as the send buffer can take
    /// (possibly less than `buf.len()`), schedules any sends the window allows,
    /// and returns the byte count accepted alongside any new outgoing segments.
    pub fn write(&mut self, buf: &[u8]) -> (usize, Vec<Vec<u8>>) {
        self.clock();
        if self.closed {
            return (0, Vec::new());
        }
        // A Fast Open server answers what the SYN brought before the
        // handshake completes.
        let early = self.state == State::SynReceived && self.tfo.accepted;
        if self.state != State::Established && self.state != State::CloseWait && !early {
            return (0, Vec::new());
        }
        // Before the new data is queued (draft-ietf-ccwg-bbr §4.1.2.4).
        self.check_app_limited();
        let n = self.send_buf.as_mut().unwrap().write(buf);
        self.snd_nospace = n < buf.len();
        if n > 0 {
            self.flush_send_queue();
        }
        (n, self.take_outgoing())
    }

    /// Whether the Nagle algorithm is off (see [`ConnConfig::nodelay`]).
    #[inline]
    pub fn nodelay(&self) -> bool {
        self.cfg.nodelay
    }

    /// Turn the Nagle algorithm off (`true`) or back on, as `TCP_NODELAY`
    /// does on a socket. Turning it off sends at once whatever it was
    /// holding back, as Linux does; those segments are returned.
    pub fn set_nodelay(&mut self, nodelay: bool) -> Vec<Vec<u8>> {
        self.clock();
        self.cfg.nodelay = nodelay;
        if nodelay
            && !self.closed
            && self.state.is_synchronized()
            && self.send_buf.as_ref().is_some_and(|s| s.pending() > 0)
        {
            self.flush_send_queue();
        }
        self.take_outgoing()
    }

    /// Initiate graceful close (FIN). Returns any segments produced.
    pub fn close(&mut self) -> Vec<Vec<u8>> {
        self.clock();
        if self.closed {
            return Vec::new();
        }
        // The FIN is only queued: flush_send_queue sends it after whatever
        // data is still waiting on the window or on SWS avoidance.
        match self.state {
            State::Established => {
                self.state = State::FinWait1;
                self.fin_queued = true;
                self.flush_send_queue();
            }
            State::CloseWait => {
                self.state = State::LastAck;
                self.fin_queued = true;
                self.flush_send_queue();
            }
            State::SynSent => {
                self.tear_down(State::Closed);
            }
            State::SynReceived => {
                // RFC 9293 §3.10.4: a FIN now would move SND.NXT past what
                // the handshake's ACK acknowledges; send it once established.
                self.fin_queued = true;
            }
            State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::LastAck
            | State::TimeWait => {
                // Already closing.
            }
            _ => {
                self.tear_down(State::Closed);
            }
        }
        self.take_outgoing()
    }

    /// The application is done with the connection: it will neither write
    /// nor read any more. Sends our FIN if [`close`](Self::close) has not
    /// already, and returns any segments produced.
    ///
    /// The connection itself carries on until the close handshake
    /// finishes, so keep driving it ([`handle_segment`](Self::handle_segment),
    /// [`tick`](Self::tick)) until [`is_closed`](Self::is_closed). What
    /// changes is that nobody is left to hear from the peer, so a peer that
    /// ACKs our FIN but never sends its own has the connection reset after
    /// [`ConnConfig::fin_wait2_timeout`], as Linux does for an orphaned
    /// socket. A half-close with `close` alone never times out that way.
    ///
    /// Call it where a socket API would drop or fully close its socket:
    /// when the last handle goes away, or on an explicit full close.
    ///
    /// If data the application never read is still buffered, the connection
    /// is reset instead of closed (RFC 2525 §2.17, as Linux's `tcp_close`):
    /// a FIN would tell the peer everything it sent was consumed. Not in
    /// TIME-WAIT, though: both sides have closed and ACKed, so a reset has
    /// nothing left to abort and would only cut TIME-WAIT short (Linux's
    /// socket is in CLOSE by then, where `tcp_close` sends nothing).
    pub fn release(&mut self) -> Vec<Vec<u8>> {
        let now = self.clock();
        self.released.get_or_insert(now);
        if matches!(self.state, State::TimeWait | State::Closed) {
            // Unread data kept for the application goes with it.
            self.release_buffers();
        } else if self.recv_buf.as_ref().is_some_and(|rb| rb.readable() > 0) {
            return self.abort();
        }
        self.close()
    }

    /// Immediate teardown: mark the connection closed and return a RST for
    /// the peer. From SYN-SENT no RST is sent, as RFC 9293 §3.10.5 has it:
    /// the peer has acknowledged nothing, so it holds nothing to reset.
    /// Nothing is sent from CLOSED either.
    pub fn abort(&mut self) -> Vec<Vec<u8>> {
        self.clock();
        if self.state == State::Closed {
            return Vec::new();
        }
        let was_established = self.state != State::Closed && self.state != State::SynSent;
        let snd_nxt = self.send_buf.as_ref().map(|s| s.nxt()).unwrap_or(0);
        self.tear_down(State::Closed);
        if was_established {
            let rst = Segment {
                src_port: self.cfg.local_port,
                dst_port: self.cfg.remote_port,
                seq: snd_nxt,
                flags: flags::RST,
                ..Default::default()
            };
            self.queue_seg(rst);
        }
        self.take_outgoing()
    }

    fn tear_down(&mut self, new_state: State) {
        self.state = new_state;
        self.closed = new_state == State::Closed;
        self.stop_rto();
        self.reo_deadline = None;
        self.pto_deadline = None;
        self.delack_deadline = None;
        self.stop_keepalive();
        self.stop_persist();
        self.time_wait_deadline = None;
        self.tfo.slot = None;
        if self.closed {
            self.signal_established();
            self.signal_fin_recvd();
            self.release_buffers();
        }
    }

    /// Give back the buffers' memory once nothing more will be sent or
    /// received (TIME-WAIT, CLOSED). Sized for the peak of the transfer,
    /// they would otherwise stay allocated through TIME-WAIT, or for as
    /// long as the owner keeps a closed connection around. Data the
    /// application has yet to read stays until it is read, unless it was
    /// [released](Self::release) and nobody will.
    fn release_buffers(&mut self) {
        self.release_growth();
        if let Some(sb) = self.send_buf.as_mut() {
            sb.release_memory();
            // Nothing will be resent: the scoreboard goes too.
            self.score = Scoreboard::new(sb.una(), self.now);
        }
        let keep_unread = self.released.is_none();
        if let Some(rb) = self.recv_buf.as_mut() {
            rb.release_memory(keep_unread);
        }
    }

    fn signal_established(&mut self) {
        self.established_signaled = true;
    }
    fn signal_fin_recvd(&mut self) {
        self.fin_recvd_signaled = true;
    }
}

/// RFC 6937 §3's sndcnt, PRR-SSRB: how much fast recovery may send on an
/// ACK that reported `delivered` bytes, `prr_delivered` and `prr_out`
/// having been delivered and sent since it began with a flight of
/// `recover_fs`, now that `pipe` bytes are in flight and the target is
/// `ssthresh`.
fn prr_sndcnt(
    prr_delivered: u64,
    prr_out: u64,
    recover_fs: u32,
    ssthresh: u32,
    pipe: u32,
    delivered: u32,
    mss: u32,
) -> u32 {
    let sndcnt = if pipe > ssthresh {
        // Proportional Rate Reduction.
        let target = (prr_delivered * u64::from(ssthresh)).div_ceil(u64::from(recover_fs.max(1)));
        target.saturating_sub(prr_out)
    } else {
        // Slow Start Reduction Bound.
        let banked = prr_delivered.saturating_sub(prr_out);
        let limit = banked.max(u64::from(delivered)) + u64::from(mss);
        u64::from(ssthresh - pipe).min(limit)
    };
    sndcnt.min(u64::from(u32::MAX)) as u32
}

/// The time now. Tests move it on at will: RACK and TLP go by the time
/// between events, which tests cannot wait out for real.
#[inline]
fn wall_clock() -> Instant {
    #[cfg(test)]
    return Instant::now() + tests::skew();
    #[cfg(not(test))]
    Instant::now()
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.budget.release(self.grown);
    }
}

// --- Helpers ---------------------------------------------------------------

// Silence a noisy lint on `seq_in_range` not currently exercised; the helper
// is part of the public seqspace surface and intentionally re-exported.
#[allow(dead_code)]
fn _options_export_is_used(_o: &TcpOption) {
    let _ = options::kind::End;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtcp::bbr;
    use crate::vtcp::options::get_mss;
    use crate::vtcp::rto::DEFAULT_RTO;

    thread_local! {
        static SKEW: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) };
    }

    /// How far this thread's connections' clock is ahead of the real one.
    pub(super) fn skew() -> Duration {
        SKEW.with(|s| s.get())
    }

    /// Move this thread's connections' clock on by `d`.
    fn advance(d: Duration) {
        SKEW.with(|s| s.set(s.get() + d));
    }

    /// The time as this thread's connections see it.
    fn test_now() -> Instant {
        Instant::now() + skew()
    }

    fn cfg(local: u16, remote: u16) -> ConnConfig {
        ConnConfig {
            local_port: local,
            remote_port: remote,
            mss: 1460,
            send_buf_size: 4096,
            recv_buf_size: 4096,
            // These tests count the window in bytes, unscaled.
            autotune: false,
            // And segments in whole MSS, which timestamps take 12 bytes
            // of; the tests of timestamps turn them on.
            enable_timestamps: false,
            // And expect what the window allows to go out at once; the
            // tests of pacing turn it on.
            pacing: false,
            ..Default::default()
        }
    }

    fn parse(bytes: &[u8]) -> Segment {
        Segment::parse(bytes).expect("parse seg")
    }

    fn drive_handshake(client: &mut Conn, server: &mut Conn) {
        // Client sends SYN.
        let pkts = client.connect();
        assert_eq!(pkts.len(), 1);
        let syn = parse(&pkts[0]);
        assert!(syn.has_flag(flags::SYN));
        assert!(!syn.has_flag(flags::ACK));

        // Server accepts SYN, replies SYN-ACK.
        let pkts = server.accept_syn(&syn);
        assert_eq!(pkts.len(), 1);
        let synack = parse(&pkts[0]);
        assert!(synack.has_flag(flags::SYN) && synack.has_flag(flags::ACK));

        // Client sees SYN-ACK, replies ACK.
        let pkts = client.handle_segment(&synack);
        assert_eq!(client.state(), State::Established);
        let ack = parse(&pkts[0]);
        assert!(ack.has_flag(flags::ACK));
        assert!(!ack.has_flag(flags::SYN));

        // Server processes the ACK, becomes ESTABLISHED.
        let _ = server.handle_segment(&ack);
        assert_eq!(server.state(), State::Established);
    }

    #[test]
    fn three_way_handshake() {
        let mut client = Conn::new(cfg(40000, 80));
        let mut server = Conn::new(cfg(80, 40000));
        drive_handshake(&mut client, &mut server);
        assert!(client.is_established());
        assert!(server.is_established());
    }

    #[test]
    fn data_transfer() {
        let mut client = Conn::new(cfg(40001, 80));
        let mut server = Conn::new(cfg(80, 40001));
        drive_handshake(&mut client, &mut server);

        let payload = b"hello, world!";
        let (n, pkts) = client.write(payload);
        assert_eq!(n, payload.len());
        assert_eq!(pkts.len(), 1);
        let seg = parse(&pkts[0]);
        assert_eq!(seg.payload, payload);

        // Server consumes, ACKs back.
        let ack_pkts = server.handle_segment(&seg);
        assert!(!ack_pkts.is_empty());
        let mut buf = [0u8; 64];
        let n = server.read(&mut buf);
        assert_eq!(&buf[..n], payload);

        // Client sees the ACK, send-buffer drains.
        let ack = parse(&ack_pkts[0]);
        let _ = client.handle_segment(&ack);
    }

    #[test]
    fn graceful_close() {
        let mut client = Conn::new(cfg(40002, 80));
        let mut server = Conn::new(cfg(80, 40002));
        drive_handshake(&mut client, &mut server);

        // Client closes — FIN-WAIT-1.
        let pkts = client.close();
        assert_eq!(client.state(), State::FinWait1);
        assert_eq!(pkts.len(), 1);
        let fin = parse(&pkts[0]);
        assert!(fin.has_flag(flags::FIN));

        // Server sees FIN — CLOSE-WAIT.
        let ack_pkts = server.handle_segment(&fin);
        assert_eq!(server.state(), State::CloseWait);
        assert!(server.fin_received());
        let ack = parse(&ack_pkts[0]);

        // Client sees ACK of FIN — FIN-WAIT-2.
        let _ = client.handle_segment(&ack);
        assert_eq!(client.state(), State::FinWait2);

        // Server closes — LAST-ACK, sends FIN.
        let pkts = server.close();
        assert_eq!(server.state(), State::LastAck);
        let fin2 = parse(&pkts[0]);
        assert!(fin2.has_flag(flags::FIN));

        // Client acks server's FIN — enters TIME-WAIT.
        let pkts = client.handle_segment(&fin2);
        assert_eq!(client.state(), State::TimeWait);
        let ack2 = parse(&pkts[0]);

        // Server sees the ack — CLOSED.
        let _ = server.handle_segment(&ack2);
        assert_eq!(server.state(), State::Closed);
        assert!(server.is_closed());
    }

    #[test]
    fn abort_emits_rst() {
        let mut client = Conn::new(cfg(40003, 80));
        let mut server = Conn::new(cfg(80, 40003));
        drive_handshake(&mut client, &mut server);
        let pkts = client.abort();
        assert_eq!(client.state(), State::Closed);
        assert_eq!(pkts.len(), 1);
        let rst = parse(&pkts[0]);
        assert!(rst.has_flag(flags::RST));
    }

    #[test]
    fn closed_replies_with_rst() {
        let mut c = Conn::new(cfg(80, 40004));
        let seg = Segment {
            src_port: 40004,
            dst_port: 80,
            seq: 1000,
            ack: 0,
            flags: flags::SYN,
            window: 65535,
            ..Default::default()
        };
        let pkts = c.handle_segment(&seg);
        assert_eq!(pkts.len(), 1);
        let rst = parse(&pkts[0]);
        assert!(rst.has_flag(flags::RST));
    }

    fn established(port: u16) -> (Conn, Conn) {
        let mut client = Conn::new(cfg(port, 80));
        let mut server = Conn::new(cfg(80, port));
        drive_handshake(&mut client, &mut server);
        (client, server)
    }

    /// Feed `pkts` to `to`, returning everything it sends in reply.
    fn deliver(to: &mut Conn, pkts: &[Vec<u8>]) -> Vec<Vec<u8>> {
        pkts.iter()
            .flat_map(|p| to.handle_segment(&parse(p)))
            .collect()
    }

    /// Let a pending delayed ACK go out, as its timer would within the
    /// round trip on a path of 40 ms or more.
    fn delack_expired(c: &mut Conn) -> Vec<Vec<u8>> {
        if c.delack_deadline.is_none() {
            return Vec::new();
        }
        c.delack_deadline = Some(Instant::now());
        c.tick()
    }

    /// Let the RTO run out: time moves on by as much.
    fn fire_rto(c: &mut Conn) -> Vec<Vec<u8>> {
        assert!(c.rto_deadline.is_some(), "RTO not armed");
        advance(c.rto.rto());
        c.rto_deadline = Some(test_now());
        // Not a loss probe, nor RACK's timer, which would have gone first.
        c.pto_deadline = None;
        c.reo_deadline = None;
        c.tick()
    }

    fn read_all(c: &mut Conn) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = c.read(&mut buf);
            if n == 0 {
                return out;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    // A write held back by sender SWS avoidance must go out before the FIN,
    // not be overtaken by it.
    #[test]
    fn close_sends_held_back_data_before_fin() {
        let (mut client, mut server) = established(40010);
        let (_, first) = client.write(&[1u8; 100]);
        assert_eq!(first.len(), 1);
        let (n, held) = client.write(b"close-frame");
        assert_eq!(n, 11);
        assert!(held.is_empty(), "small write should wait for the ACK");

        let pkts = client.close();
        assert_eq!(client.state(), State::FinWait1);
        assert_eq!(pkts.len(), 2);
        let data = parse(&pkts[0]);
        let fin = parse(&pkts[1]);
        assert_eq!(data.payload, b"close-frame");
        assert!(!data.has_flag(flags::FIN));
        assert!(fin.has_flag(flags::FIN));
        assert_eq!(fin.seq, data.seq.wrapping_add(11));

        let mut all = first;
        all.extend(pkts);
        let acks = deliver(&mut server, &all);
        assert!(server.fin_received());
        let got = read_all(&mut server);
        assert_eq!(got.len(), 111);
        assert_eq!(&got[100..], b"close-frame");

        deliver(&mut client, &acks);
        assert_eq!(client.state(), State::FinWait2);
    }

    // Data waiting on the peer's window: the FIN has to wait too, and ACKs of
    // the data alone must not be taken for an ACK of the FIN.
    #[test]
    fn close_waits_for_window_limited_data() {
        let (mut client, mut server) = established(40011);
        client.snd_wnd = 50;
        let (n, pkts) = client.write(&[7u8; 100]);
        assert_eq!(n, 100);
        assert_eq!(pkts.len(), 1);
        assert_eq!(parse(&pkts[0]).payload.len(), 50);

        assert!(
            client.close().is_empty(),
            "FIN must not overtake queued data"
        );
        assert_eq!(client.state(), State::FinWait1);

        let acks = deliver(&mut server, &pkts);
        let rest = deliver(&mut client, &acks);
        assert_eq!(client.state(), State::FinWait1);
        assert_eq!(rest.len(), 2);
        assert_eq!(parse(&rest[0]).payload.len(), 50);
        assert!(parse(&rest[1]).has_flag(flags::FIN));

        let acks = deliver(&mut server, &rest);
        assert_eq!(read_all(&mut server), vec![7u8; 100]);
        assert!(server.fin_received());
        deliver(&mut client, &acks);
        assert_eq!(client.state(), State::FinWait2);
    }

    // The passive closer (CLOSE-WAIT → LAST-ACK) has the same ordering
    // constraint, and a second close() must not abandon the connection.
    #[test]
    fn last_ack_sends_held_back_data_before_fin() {
        let (mut client, mut server) = established(40012);
        let fin = client.close();
        let acks = deliver(&mut server, &fin);
        deliver(&mut client, &acks);
        assert_eq!(server.state(), State::CloseWait);

        let (_, first) = server.write(&[3u8; 100]);
        let (_, held) = server.write(b"tail");
        assert!(held.is_empty());
        let pkts = server.close();
        assert_eq!(server.state(), State::LastAck);
        assert!(server.close().is_empty());
        assert_eq!(server.state(), State::LastAck);
        assert_eq!(pkts.len(), 2);
        assert_eq!(parse(&pkts[0]).payload, b"tail");
        assert!(parse(&pkts[1]).has_flag(flags::FIN));

        let mut all = first;
        all.extend(pkts);
        let acks = deliver(&mut client, &all);
        assert_eq!(client.state(), State::TimeWait);
        let got = read_all(&mut client);
        assert_eq!(got.len(), 104);
        assert_eq!(&got[100..], b"tail");

        deliver(&mut server, &acks);
        assert!(server.is_closed());
    }

    // After a timeout the oldest unacknowledged data is resent; a FIN at
    // SND.UNA would tell the peer the stream ends before that data.
    #[test]
    fn rto_retransmits_data_before_fin() {
        let (mut client, mut server) = established(40013);
        let (_, lost_data) = client.write(b"payload");
        let lost_fin = client.close();
        assert_eq!(lost_data.len() + lost_fin.len(), 2);

        let re = fire_rto(&mut client);
        assert_eq!(re.len(), 1);
        let seg = parse(&re[0]);
        assert_eq!(seg.payload, b"payload");
        assert!(!seg.has_flag(flags::FIN));

        let acks = deliver(&mut server, &re);
        assert!(!server.fin_received());
        deliver(&mut client, &acks);
        assert_eq!(client.state(), State::FinWait1);

        let re = fire_rto(&mut client);
        assert_eq!(re.len(), 1);
        let fin = parse(&re[0]);
        assert!(fin.has_flag(flags::FIN));
        assert_eq!(fin.seq, seg.seq.wrapping_add(7));

        let acks = deliver(&mut server, &re);
        assert!(server.fin_received());
        assert_eq!(read_all(&mut server), b"payload");
        deliver(&mut client, &acks);
        assert_eq!(client.state(), State::FinWait2);
    }

    // close() in SYN-RECEIVED: sending the FIN at once would move SND.NXT
    // past what the handshake ACK acknowledges, and the ACK would draw a RST.
    #[test]
    fn close_in_syn_received_sends_fin_after_handshake() {
        let mut client = Conn::new(cfg(40014, 80));
        let mut server = Conn::new(cfg(80, 40014));
        let syn = client.connect();
        let synack = server.accept_syn(&parse(&syn[0]));
        assert!(server.close().is_empty());

        let ack = deliver(&mut client, &synack);
        let out = deliver(&mut server, &ack);
        assert_eq!(server.state(), State::FinWait1);
        assert_eq!(out.len(), 1);
        let fin = parse(&out[0]);
        assert!(fin.has_flag(flags::FIN));
        assert!(!fin.has_flag(flags::RST));

        let acks = deliver(&mut client, &out);
        assert_eq!(client.state(), State::CloseWait);
        deliver(&mut server, &acks);
        assert_eq!(server.state(), State::FinWait2);
    }

    // Both sides close with data still held back: the FINs cross, so each
    // side passes through CLOSING, and must still deliver its tail.
    #[test]
    fn simultaneous_close_with_held_back_data() {
        let (mut a, mut b) = established(40015);
        let (_, a1) = a.write(&[1u8; 100]);
        let (_, b1) = b.write(&[2u8; 100]);
        a.write(b"a-tail");
        b.write(b"b-tail");
        let mut a_out = a1;
        a_out.extend(a.close());
        let mut b_out = b1;
        b_out.extend(b.close());

        // The FINs and the tails cross in flight.
        let from_b = deliver(&mut b, &a_out);
        let from_a = deliver(&mut a, &b_out);
        deliver(&mut a, &from_b);
        deliver(&mut b, &from_a);

        for c in [&a, &b] {
            assert!(
                matches!(c.state(), State::TimeWait | State::Closed),
                "{:?}",
                c.state()
            );
        }
        let got_a = read_all(&mut a);
        let got_b = read_all(&mut b);
        assert_eq!(&got_a[100..], b"b-tail");
        assert_eq!(&got_b[100..], b"a-tail");
    }

    // The reply to a window probe is lost. The next probe draws another,
    // which shows the window open, and the data and FIN go out.
    #[test]
    fn lost_reply_to_a_window_probe_is_recovered() {
        let (mut client, mut server) = established(40016);
        client.snd_wnd = 0;
        let (_, none) = client.write(b"x");
        assert!(none.is_empty());
        assert!(client.close().is_empty());

        let probe = fire_persist(&mut client);
        assert_eq!(probe.len(), 1);
        let _lost_ack = deliver(&mut server, &probe);

        // Time passes: the probes are further apart than the throttle on
        // the replies they draw.
        server.last_oow_ack = None;
        let re = fire_persist(&mut client);
        let ack = deliver(&mut server, &re);
        let out = deliver(&mut client, &ack);
        assert_eq!(parse(&out[0]).payload, b"x");
        assert!(parse(out.last().unwrap()).has_flag(flags::FIN));
        deliver(&mut server, &out);
        assert!(server.fin_received());
        assert_eq!(read_all(&mut server), b"x");
    }

    // Draining a full receive buffer must advertise the reopened window
    // rather than leave the sender to its persist timer.
    #[test]
    fn read_reopening_window_sends_update() {
        let (mut client, mut server) = established(40017);
        let (n, mut pkts) = client.write(&[9u8; 4096]);
        assert_eq!(n, 4096);
        let mut last_window = None;
        while !pkts.is_empty() {
            let acks = deliver(&mut server, &pkts);
            last_window = acks.last().map(|a| parse(a).window);
            pkts = deliver(&mut client, &acks);
        }
        assert_eq!(last_window, Some(0));

        let (n, blocked) = client.write(b"more");
        assert_eq!(n, 4);
        assert!(blocked.is_empty());

        let mut buf = [0u8; 4096];
        assert_eq!(server.read(&mut buf), 4096);
        let update = server.take_outgoing();
        assert_eq!(update.len(), 1);
        assert!(parse(&update[0]).window > 0);

        // The update ACKs nothing new, but it is no duplicate ACK: the
        // sender must use the window it brings.
        let sent = deliver(&mut client, &update);
        assert_eq!(parse(&sent[0]).payload, b"more");
    }

    // The peer filled our whole window and its first segment was lost: its
    // pure ACKs now carry SEQ at the right edge. Their ACK field still counts.
    #[test]
    fn ack_at_right_edge_of_window_is_processed() {
        let small = |local, remote| {
            let mut c = cfg(local, remote);
            c.mss = 1024;
            c.recv_buf_size = 2048;
            c
        };
        let mut client = Conn::new(small(40018, 80));
        let mut server = Conn::new(small(80, 40018));
        drive_handshake(&mut client, &mut server);

        let (n, fill) = client.write(&[5u8; 2048]);
        assert_eq!((n, fill.len()), (2048, 2));
        deliver(&mut server, &fill[1..]); // the first segment is lost

        let (_, pong) = server.write(b"pong");
        let edge_ack = client.handle_segment(&parse(&pong[0]));
        let seg = parse(edge_ack.last().unwrap());
        assert_eq!(seg.payload.len(), 0);
        assert_eq!(
            seg.seq
                .wrapping_sub(server.recv_buf.as_ref().unwrap().nxt()),
            2048,
            "the ACK should sit exactly at the server's right edge"
        );

        deliver(&mut server, &edge_ack);
        assert_eq!(server.send_buf.as_ref().unwrap().unacked(), 0);
    }

    // A segment arriving ahead of a loss must not pull the advertised right
    // edge back: the sender is entitled to fill the window it was given.
    #[test]
    fn out_of_order_data_keeps_right_edge() {
        let (mut client, mut server) = established(40019);
        let (_, pkts) = client.write(&[4u8; 2920]);
        assert_eq!(pkts.len(), 2);
        let first_ack = parse(&deliver(&mut server, &pkts[1..])[0]);
        let rcv_nxt = server.recv_buf.as_ref().unwrap().nxt();
        assert_eq!(first_ack.ack, rcv_nxt);
        assert_eq!(first_ack.window, 4096, "edge moved back by the OOO bytes");

        let acks = deliver(&mut server, &pkts[..1]);
        let ack = parse(acks.last().unwrap());
        assert_eq!(
            ack.ack.wrapping_add(ack.window as u32),
            rcv_nxt.wrapping_add(4096)
        );
        assert_eq!(read_all(&mut server), vec![4u8; 2920]);
    }

    // Once the window is nearly full, SWS avoidance holds the right edge
    // where it is rather than advertising a zero window that retracts it.
    #[test]
    fn sws_avoidance_does_not_retract_edge() {
        let (mut client, mut server) = established(40020);
        let (_, pkts) = client.write(&[1u8; 2920]);
        let acks = deliver(&mut server, &pkts);
        // 1176 bytes free is below the 1460-byte SWS threshold, but the
        // edge advertised at connection start still stands.
        assert_eq!(parse(acks.last().unwrap()).window, 1176);

        // Reading 100 bytes would move the edge by less than the threshold:
        // no update is worth sending, and ACKs keep showing the same edge.
        let mut buf = [0u8; 4096];
        assert_eq!(server.read(&mut buf[..100]), 100);
        assert!(server.take_outgoing().is_empty());
        server.queue_ack();
        assert_eq!(parse(&server.take_outgoing()[0]).window, 1176);

        // Reading the rest opens it enough to be worth a window update.
        assert_eq!(server.read(&mut buf), 2820);
        let update = server.take_outgoing();
        assert_eq!(parse(&update[0]).window, 4096);
    }

    #[test]
    fn duplicate_syn_resends_syn_ack() {
        let mut client = Conn::new(cfg(40022, 80));
        let mut server = Conn::new(cfg(80, 40022));
        let syn = client.connect();
        let _lost_synack = server.accept_syn(&parse(&syn[0]));

        let again = deliver(&mut server, &fire_rto(&mut client));
        assert_eq!(again.len(), 1);
        let synack = parse(&again[0]);
        assert_eq!(synack.flags, flags::SYN | flags::ACK);
        let ack = deliver(&mut client, &again);
        assert_eq!(client.state(), State::Established);
        deliver(&mut server, &ack);
        assert_eq!(server.state(), State::Established);
    }

    // A receiver that stops reading closes its window under our data. While
    // it keeps answering, that is flow control, not a dead peer.
    #[test]
    fn zero_window_under_data_in_flight_is_not_a_timeout() {
        let (mut client, server) = established(40023);
        client.write(b"data the peer cannot take");
        let una = client.send_buf.as_ref().unwrap().una();
        let zero_window_ack = Segment {
            src_port: 80,
            dst_port: 40023,
            seq: server.send_buf.as_ref().unwrap().nxt(),
            ack: una,
            flags: flags::ACK,
            window: 0,
            ..Default::default()
        };
        for _ in 0..MAX_RETRIES * 2 {
            client.handle_segment(&zero_window_ack);
            let probe = fire_rto(&mut client);
            assert_eq!(parse(&probe[0]).seq, una);
            assert!(!client.is_closed());
        }

        // A peer that stops answering is gone after all: the last probe
        // above is the first of MAX_RETRIES unanswered ones.
        for _ in 1..MAX_RETRIES {
            fire_rto(&mut client);
        }
        assert!(!client.is_closed());
        fire_rto(&mut client);
        assert!(client.is_closed());
    }

    /// The same, with the backoff at MAX_RTO and the timer serviced late
    /// (a coarse tick): the peer answers every probe within a millisecond,
    /// yet the gap from its last answer to the next timeout exceeds
    /// MAX_RTO. That is no sign of a dead peer.
    #[test]
    fn zero_window_probes_survive_a_late_timer() {
        let (mut client, server) = established(40028);
        client.write(b"data the peer cannot take");
        let una = client.send_buf.as_ref().unwrap().una();
        let zero_window_ack = Segment {
            src_port: 80,
            dst_port: 40028,
            seq: server.send_buf.as_ref().unwrap().nxt(),
            ack: una,
            flags: flags::ACK,
            window: 0,
            ..Default::default()
        };
        for round in 0..MAX_RETRIES * 4 {
            client.handle_segment(&zero_window_ack);
            let rto = client.rto.rto();
            client.last_recv = Instant::now() - (rto + Duration::from_millis(49));
            fire_rto(&mut client);
            assert!(
                !client.is_closed(),
                "torn down at round {round}, rto {rto:?}"
            );
        }
    }

    // The FIN needs a byte of window. Sent past the right edge, it would
    // put every later segment's SEQ out of the peer's window.
    #[test]
    fn fin_waits_for_window_room() {
        let (mut client, mut server) = established(40024);
        client.snd_wnd = 100;
        let (_, data) = client.write(&[8u8; 100]);
        assert_eq!(data.len(), 1);
        assert!(client.close().is_empty());

        let acks = deliver(&mut server, &data);
        let fin = deliver(&mut client, &acks);
        assert!(parse(&fin[0]).has_flag(flags::FIN));
    }

    // A reader that has stopped reading still lets the peer close: the FIN
    // goes out as the persist probe and is taken into a zero window.
    #[test]
    fn fin_into_zero_window() {
        let (mut client, mut server) = established(40025);
        let (_, mut pkts) = client.write(&[6u8; 4096]);
        while !pkts.is_empty() {
            let acks = deliver(&mut server, &pkts);
            pkts = deliver(&mut client, &acks);
        }
        assert_eq!(client.snd_wnd, 0);
        assert!(client.close().is_empty());

        client.persist_deadline = Some(Instant::now());
        let fin = client.tick();
        assert!(parse(&fin[0]).has_flag(flags::FIN));
        let ack = deliver(&mut server, &fin);
        assert!(server.fin_received());
        deliver(&mut client, &ack);
        assert_eq!(client.state(), State::FinWait2);
        assert_eq!(read_all(&mut server).len(), 4096);
    }

    // TCP_NODELAY: a short write goes out with data still in flight, but
    // one the window cuts short does not.
    #[test]
    fn nodelay_sends_short_writes_at_once() {
        let (mut client, _server) = established(40400);
        let (_, first) = client.write(&[1; 10]);
        assert_eq!(first.len(), 1);
        let (_, held) = client.write(&[2; 10]);
        assert!(held.is_empty(), "Nagle holds the second write back");
        // Turning Nagle off sends what it was holding.
        let pushed = client.set_nodelay(true);
        assert_eq!(pushed.len(), 1);
        assert_eq!(parse(&pushed[0]).payload, [2; 10]);
        let (_, third) = client.write(&[3; 10]);
        assert_eq!(third.len(), 1, "sent without waiting for an ACK");
        assert_eq!(parse(&third[0]).payload, [3; 10]);

        // From the config, too.
        let mut client = Conn::new(cfg(40401, 80).nodelay(true));
        let mut server = Conn::new(cfg(80, 40401));
        drive_handshake(&mut client, &mut server);
        assert!(client.nodelay());
        assert_eq!(client.write(&[1; 10]).1.len(), 1);
        assert_eq!(client.write(&[2; 10]).1.len(), 1);

        // A segment the peer's window cuts short still waits for room.
        client.set_snd_wnd(20 + 1050);
        client.max_snd_wnd = 4000;
        assert_eq!(client.write(&[4; 1000]).1.len(), 1);
        let (n, trickle) = client.write(&[5; 100]);
        assert_eq!(n, 100);
        assert!(trickle.is_empty(), "sent a runt into a closing window");
    }

    // RFC 9293 §3.8.6.2.1: with data in flight, a segment is still worth
    // sending once it is at least half the largest window the peer has
    // offered, even if short of the MSS; a peer that never offers a full
    // segment's worth would otherwise get one segment per round trip.
    #[test]
    fn sender_sws_sends_half_the_max_window() {
        let (mut client, _server) = established(40027);
        client.set_snd_wnd(1000);
        client.max_snd_wnd = 1000;
        let (_, first) = client.write(&[1; 400]);
        assert_eq!(seqs(&first).len(), 1);
        let (_, second) = client.write(&[2; 1000]);
        assert_eq!(second.len(), 1, "600 bytes fit, over half the max window");
        assert_eq!(parse(&second[0]).payload.len(), 600);
        // Less than half is still held back.
        client.snd_wnd = 1400;
        let (_, third) = client.write(&[3; 10]);
        assert!(third.is_empty());
    }

    // A segment at RCV.NXT carrying data into our zero window still has
    // its ACK processed (RFC 9293 §3.10.7.4); only the payload is dropped.
    #[test]
    fn zero_window_still_takes_the_ack_of_a_data_segment() {
        let (mut client, mut server) = established(40026);
        let (_, mut pkts) = client.write(&[6u8; 4096]);
        while !pkts.is_empty() {
            let acks = deliver(&mut server, &pkts);
            pkts = deliver(&mut client, &acks);
        }
        assert_eq!(server.rcv_wnd_bytes(), 0);
        let (_, reply) = server.write(b"reply");
        let reply_end = server.send_buf.as_ref().unwrap().nxt();
        assert_eq!(parse(&reply[0]).seq.wrapping_add(5), reply_end);

        // The client's next data acknowledges the reply, but lands in a
        // closed window.
        let rcv_nxt = server.recv_buf.as_ref().unwrap().nxt();
        let seg = data_with_ack(&server, &client, reply_end, b"more", false);
        let out = server.handle_segment(&seg);
        assert_eq!(
            server.send_buf.as_ref().unwrap().una(),
            reply_end,
            "ACK ignored"
        );
        let ack = parse(&out[0]);
        assert_eq!(ack.ack, rcv_nxt, "the payload must not be taken");
        assert_eq!(ack.window, 0);
        assert_eq!(read_all(&mut server), vec![6u8; 4096]);
    }

    // Pure ACKs get no reply in CLOSING or TIME-WAIT, or two ends answering
    // each other's ACKs would never stop.
    #[test]
    fn closing_and_time_wait_do_not_answer_pure_acks() {
        let (mut a, mut b) = established(40026);
        let a_fin = a.close();
        let b_fin = b.close();
        let b_ack = deliver(&mut b, &a_fin);
        assert_eq!(b.state(), State::Closing);
        let a_ack = deliver(&mut a, &b_fin);
        assert_eq!(a.state(), State::Closing);

        let bare_ack = |c: &Conn| Segment {
            src_port: c.cfg.remote_port,
            dst_port: c.cfg.local_port,
            seq: c.recv_buf.as_ref().unwrap().nxt(),
            ack: c.send_buf.as_ref().unwrap().una(),
            flags: flags::ACK,
            window: 4096,
            ..Default::default()
        };
        assert!(a.handle_segment(&bare_ack(&a)).is_empty());

        deliver(&mut a, &b_ack);
        deliver(&mut b, &a_ack);
        assert_eq!(a.state(), State::TimeWait);
        assert!(a.handle_segment(&bare_ack(&a)).is_empty());
        // A retransmitted FIN is still answered.
        assert_eq!(deliver(&mut a, &b_fin).len(), 1);
    }

    #[test]
    fn syn_ack_window_is_not_scaled() {
        let mut client = Conn::new(ConnConfig {
            recv_buf_size: 1 << 20,
            ..cfg(40021, 80)
        });
        let mut server = Conn::new(ConnConfig {
            recv_buf_size: 1 << 20,
            ..cfg(80, 40021)
        });
        let syn = parse(&client.connect()[0]);
        assert_eq!(syn.window, 65535);
        let synack = parse(&server.accept_syn(&syn)[0]);
        assert!(server.wscale_ok);
        assert_eq!(synack.window, 65535);
        // Nor does the receiving end scale it.
        client.handle_segment(&synack);
        assert_eq!(client.snd_wnd, 65535);
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    impl Conn {
        /// Timeouts in a row without an answer, whether retransmissions or
        /// zero-window probes: how close the connection is to giving up.
        fn unanswered(&self) -> u32 {
            self.retries.max(self.probes_out)
        }
    }

    struct Side {
        conn: Conn,
        to_send: Vec<u8>,
        written: usize,
        received: Vec<u8>,
        close_called: bool,
    }

    /// Both ends stream data over a link that drops, duplicates and reorders
    /// segments, then close. Every byte must arrive, in order, before EOF,
    /// and both ends must finish the close handshake.
    fn lossy_run(seed: u64) {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let (ts, sack) = (rng.below(2) == 0, rng.below(2) == 0);
        // Drawn apart, so each seed keeps the run it had before.
        let mut cc_rng = Rng(splitmix(seed ^ 0xCC) | 1);
        let mut small = |port| {
            let mut c = cfg(port, 80);
            c.congestion = CONTROLLERS[cc_rng.below(4) as usize];
            c.pacing = cc_rng.below(2) == 0;
            c.enable_timestamps = ts;
            c.enable_sack = sack;
            c.mss = 536;
            c.no_window_scaling = !ts;
            c.send_buf_size = 2048;
            c.recv_buf_size = 2048;
            c
        };
        let mut a = Conn::new(small(40100));
        let b = Conn::new({
            let mut c = small(80);
            c.remote_port = 40100;
            c
        });
        let syn = a.connect();

        let mut sides = [a, b].map(|conn| {
            let len = rng.below(20_000) as usize;
            Side {
                conn,
                to_send: (0..len).map(|_| rng.next() as u8).collect(),
                written: 0,
                received: Vec::new(),
                close_called: false,
            }
        });
        // links[i] carries segments sent by side i.
        // The handshake runs over the lossy link too.
        let mut links: [Vec<Vec<u8>>; 2] = [syn, Vec::new()];

        let done = |s: &[Side; 2]| {
            s.iter().all(|x| {
                x.close_called
                    && x.conn.fin_received()
                    && matches!(x.conn.state(), State::TimeWait | State::Closed)
            })
        };

        for step in 0..200_000 {
            if done(&sides) {
                break;
            }
            let i = rng.below(2) as usize;
            match rng.below(10) {
                // App writes a random chunk, then closes once all is written.
                0..=1 => {
                    let s = &mut sides[i];
                    if s.written < s.to_send.len() {
                        let end = (s.written + 1 + rng.below(1500) as usize).min(s.to_send.len());
                        let (n, out) = s.conn.write(&s.to_send[s.written..end]);
                        s.written += n;
                        links[i].extend(out);
                    } else if !s.close_called
                        && !matches!(s.conn.state(), State::Closed | State::SynSent)
                        && rng.below(4) == 0
                    {
                        s.close_called = true;
                        links[i].extend(s.conn.close());
                    }
                }
                // App reads a random amount.
                2..=3 => {
                    let s = &mut sides[i];
                    let mut buf = vec![0u8; 1 + rng.below(1500) as usize];
                    let n = s.conn.read(&mut buf);
                    s.received.extend_from_slice(&buf[..n]);
                    links[i].extend(s.conn.take_outgoing());
                }
                // Network delivers, drops, duplicates or reorders.
                4..=8 => {
                    if links[i].is_empty() {
                        continue;
                    }
                    let k = if rng.below(5) == 0 {
                        rng.below(links[i].len() as u64) as usize
                    } else {
                        0
                    };
                    let pkt = links[i].remove(k);
                    let fate = rng.below(20);
                    // Enough losses in a row make an end give up after
                    // MAX_RETRIES, which is correct but would make the run's
                    // outcome luck. The link stops losing while either end
                    // is halfway there, so giving up is the engine's fault.
                    let struggling = sides.iter().any(|s| s.conn.unanswered() >= MAX_RETRIES / 2);
                    if fate < 2 && !struggling {
                        continue;
                    }
                    if fate == 2 {
                        links[i].insert(0, pkt.clone());
                    }
                    let seg = parse(&pkt);
                    let peer = &mut sides[1 - i].conn;
                    // Side 1 plays the listener until the first SYN arrives.
                    let out = if peer.state() == State::Closed
                        && !peer.is_closed()
                        && seg.flags & (flags::SYN | flags::ACK) == flags::SYN
                    {
                        peer.accept_syn(&seg)
                    } else {
                        peer.handle_segment(&seg)
                    };
                    links[1 - i].extend(out);
                }
                // Time passes: fire whatever timer is armed.
                _ => {
                    if !links[0].is_empty() || !links[1].is_empty() {
                        continue;
                    }
                    // The clock does not really move, so neither would the
                    // challenge-ACK throttle's; a timer firing stands for
                    // more time than its interval, on both ends.
                    for s in sides.iter_mut() {
                        s.conn.last_oow_ack = None;
                    }
                    advance(Duration::from_micros(rng.below(20_000)));
                    let c = &mut sides[i].conn;
                    let now = test_now();
                    if c.rto_deadline.is_some() {
                        c.rto_deadline = Some(now);
                    }
                    if c.persist_deadline.is_some() {
                        c.persist_deadline = Some(now);
                    }
                    if c.reo_deadline.is_some() {
                        c.reo_deadline = Some(now);
                    }
                    if c.pto_deadline.is_some() {
                        c.pto_deadline = Some(now);
                    }
                    if c.delack_deadline.is_some() {
                        c.delack_deadline = Some(now);
                    }
                    if c.pace_deadline.is_some() {
                        c.pace_deadline = Some(now);
                    }
                    links[i].extend(c.tick());
                }
            }
            assert!(
                !sides[0].conn.is_closed() || sides[0].conn.fin_received(),
                "seed {seed} step {step}: side 0 torn down early"
            );
        }

        for s in &mut sides {
            s.received.extend(read_all(&mut s.conn));
        }
        assert!(
            done(&sides),
            "seed {seed}: did not finish: {:?} / {:?}",
            sides[0].conn,
            sides[1].conn
        );
        assert!(
            sides[1].received == sides[0].to_send,
            "seed {seed}: a→b stream corrupted"
        );
        assert!(
            sides[0].received == sides[1].to_send,
            "seed {seed}: b→a stream corrupted"
        );
    }

    /// Lose segments 1 and 4 of a ten-segment window. Fast retransmit
    /// repairs the first hole; the ACK for it is partial (it stops at the
    /// second hole), and RFC 6582 §3.2 has the sender retransmit the next
    /// hole on that ACK rather than wait for the RTO.
    fn partial_ack_run(sack: bool) {
        let conf = |local, remote| {
            let mut c = cfg(local, remote);
            c.mss = 1000;
            c.send_buf_size = 1 << 16;
            c.recv_buf_size = 1 << 16;
            c.enable_sack = sack;
            c
        };
        let mut client = Conn::new(conf(40200, 80));
        let mut server = Conn::new(conf(80, 40200));
        drive_handshake(&mut client, &mut server);
        let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let (n, segs) = client.write(&data);
        assert_eq!(
            (n, segs.len()),
            (10_000, 10),
            "initial window is ten segments"
        );
        let lost: Vec<u32> = [1, 4].iter().map(|&i| parse(&segs[i]).seq).collect();

        let arrived: Vec<Vec<u8>> = segs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1 && *i != 4)
            .map(|(_, s)| s.clone())
            .collect();
        let acks = deliver(&mut server, &arrived);
        let resent = deliver(&mut client, &acks);
        let resent_seqs: Vec<u32> = resent.iter().map(|p| parse(p).seq).collect();
        assert!(
            resent_seqs.contains(&lost[0]),
            "fast retransmit of the first hole"
        );
        if sack {
            // The SACKs in the duplicate ACKs already show the second hole
            // lost, so it goes out in the same round trip (RFC 6675), with
            // no partial ACK needed.
            assert!(
                resent_seqs.contains(&lost[1]),
                "SACK recovery resends both holes at once, sent {resent_seqs:?}"
            );
            let acks = deliver(&mut server, &resent);
            assert_eq!(parse(acks.last().unwrap()).ack, lost[0] + 9000);
            assert_eq!(read_all(&mut server), data);
            // The first of those ACKs is partial, stopping at the second
            // hole. That hole is below HighRxt, already resent this episode:
            // sending it again would be a spurious retransmission.
            assert!(
                acks.iter().any(|a| parse(a).ack == lost[1]),
                "a partial ACK up to the second hole"
            );
            let out = deliver(&mut client, &acks);
            assert!(
                !seqs(&out).contains(&lost[1]),
                "second hole retransmitted twice, sent {:?}",
                seqs(&out)
            );
            return;
        }

        let partial = deliver(&mut server, &resent);
        let seg = parse(partial.last().unwrap());
        assert_eq!(seg.ack, lost[1], "a partial ACK, up to the second hole");
        let out = deliver(&mut client, &partial);
        let out_seqs: Vec<u32> = out.iter().map(|p| parse(p).seq).collect();
        assert!(
            out_seqs.contains(&lost[1]),
            "sack={sack}: the partial ACK must retransmit the second hole, sent {out_seqs:?}"
        );

        deliver(&mut server, &out);
        assert_eq!(read_all(&mut server), data);
    }

    /// Segments 1 and 4 lost, and every ACK for the rest too, so only the
    /// RTO notices. After that one timeout, the ACKs the retransmissions
    /// draw must carry the repair through both holes (RFC 6582 §3.2 applies
    /// after a timeout too), not leave each hole to another, backed-off,
    /// timeout.
    #[test]
    fn one_rto_repairs_every_hole() {
        let conf = |local, remote| {
            let mut c = cfg(local, remote);
            c.mss = 1000;
            c.send_buf_size = 1 << 16;
            c.recv_buf_size = 1 << 16;
            c
        };
        let mut client = Conn::new(conf(40210, 80));
        let mut server = Conn::new(conf(80, 40210));
        drive_handshake(&mut client, &mut server);
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 7) as u8).collect();
        let (_, segs) = client.write(&data);
        let arrived: Vec<Vec<u8>> = segs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1 && *i != 4)
            .map(|(_, s)| s.clone())
            .collect();
        let _lost_acks = deliver(&mut server, &arrived);

        let mut to_server = fire_rto(&mut client);
        for _ in 0..10 {
            if to_server.is_empty() {
                break;
            }
            let acks = deliver(&mut server, &to_server);
            to_server = deliver(&mut client, &acks);
        }
        let got = read_all(&mut server);
        assert_eq!(got.len(), data.len(), "stalled waiting for another RTO");
        assert_eq!(got, data);
    }

    /// A lost SYN is repaired by the RTO, but that timeout says nothing
    /// about the data that follows: the first data loss must still be
    /// repaired by fast retransmit, not left to another timeout.
    #[test]
    fn lost_syn_does_not_disable_fast_retransmit() {
        let mut client = Conn::new(big(40230, 80));
        let mut server = Conn::new(big(80, 40230));
        let _lost = client.connect();
        let syn = fire_rto(&mut client);
        let synack = server.accept_syn(&parse(&syn[0]));
        let ack = deliver(&mut client, &synack);
        deliver(&mut server, &ack);
        assert_eq!(server.state(), State::Established);
        assert_eq!(
            client.ca,
            CaState::Open,
            "timeout recovery outlived the SYN"
        );
        // After the lost SYN data starts from one segment. Stand in for the
        // round trips of slow start that would grow it, without the new
        // ACKs that would also clear any stale loss state.
        client.cc = make_cc(
            client.cfg.congestion,
            client.mss as u32,
            client.cfg.pacing,
            client.now,
        );

        let (_, segs) = client.write(&[4; 10_000]);
        assert_eq!(segs.len(), 10);
        let dups = deliver(&mut server, &segs[1..]);
        let out = deliver(&mut client, &dups);
        assert!(client.in_recovery(), "no fast retransmit");
        assert!(seqs(&out).contains(&parse(&segs[0]).seq));
    }

    /// Rounds of: the sender fills its window, the receiver ACKs it all.
    fn stream_rounds(tx: &mut Conn, rx: &mut Conn, rounds: usize) {
        let (_, mut out) = tx.write(&vec![9; 1 << 20]);
        for _ in 0..rounds {
            let acks = deliver(rx, &out);
            read_all(rx);
            out = deliver(tx, &acks);
            out.extend(tx.take_outgoing());
        }
    }

    /// A lost SYN-ACK: the server's RTO fired with only the SYN-ACK out.
    /// That must not cut ssthresh to its two-segment floor, which would
    /// hold the connection in congestion avoidance for good; the data
    /// transfer starts from one segment (RFC 5681 §3.1) and slow-starts.
    #[test]
    fn lost_syn_ack_starts_from_the_loss_window_in_slow_start() {
        let conf = |l, r| big(l, r).send_buf_size(1 << 20).recv_buf_size(1 << 20);
        let mut client = Conn::new(conf(40232, 80));
        let mut server = Conn::new(conf(80, 40232));
        let syn = client.connect();
        let _lost = server.accept_syn(&parse(&syn[0]));
        let synack = fire_rto(&mut server);
        let ack = deliver(&mut client, &synack);
        deliver(&mut server, &ack);
        assert_eq!(server.state(), State::Established);
        let mss = server.mss as u32;
        assert_eq!(server.cc.cwnd(), mss, "loss window");
        assert_eq!(server.rto.rto(), Duration::from_secs(3));
        stream_rounds(&mut server, &mut client, 4);
        assert!(
            server.cc.cwnd() >= 16 * mss,
            "not in slow start: cwnd {}",
            server.cc.cwnd() / mss
        );
    }

    /// The client's controller is rebuilt when the SYN-ACK brings the
    /// peer's MSS; a SYN lost before it still means the loss window.
    #[test]
    fn lost_syn_starts_the_client_from_the_loss_window() {
        let mut client = Conn::new(big(40233, 80));
        let mut server = Conn::new(big(80, 40233));
        let _lost = client.connect();
        let syn = fire_rto(&mut client);
        let synack = server.accept_syn(&parse(&syn[0]));
        deliver(&mut client, &synack);
        assert_eq!(client.state(), State::Established);
        assert_eq!(client.cc.cwnd(), client.mss as u32);
        let (_, segs) = client.write(&[1; 5000]);
        assert_eq!(segs.len(), 1, "one segment, not the initial window");
    }

    /// A blackout loses a whole flight of a few hundred segments. After
    /// the RTO all of it counts as lost (RFC 5681 §3.1), and slow start
    /// resends it at a doubling rate: a logarithmic number of round trips,
    /// not one per segment.
    fn blackout_run(sack: bool, port: u16) {
        let conf = |l, r| {
            big(l, r)
                .send_buf_size(1 << 22)
                .recv_buf_size(1 << 20)
                .enable_sack(sack)
        };
        let mut client = Conn::new(conf(port, 80));
        let mut server = Conn::new(conf(80, port));
        drive_handshake(&mut client, &mut server);
        let data: Vec<u8> = (0..1u32 << 22).map(|i| ((i * 13) >> 5) as u8).collect();
        let (n, mut out) = client.write(&data);
        assert_eq!(n, data.len());
        let mut received = Vec::new();
        while out.len() < 300 {
            let acks = deliver(&mut server, &out);
            received.extend(read_all(&mut server));
            out = deliver(&mut client, &acks);
        }
        let lost = out.len();
        let recover = client.send_buf.as_ref().unwrap().nxt();

        let mut out = fire_rto(&mut client);
        let mut rtts = 0;
        while seq_before(client.send_buf.as_ref().unwrap().una(), recover) {
            rtts += 1;
            assert!(
                rtts <= 20,
                "sack={sack}: {lost} lost segments, {rtts} round trips"
            );
            let mut acks = deliver(&mut server, &out);
            acks.extend(delack_expired(&mut server));
            received.extend(read_all(&mut server));
            out = deliver(&mut client, &acks);
        }
        assert!(
            rtts <= 2 * (lost as f64).log2().ceil() as usize,
            "sack={sack}: {rtts} round trips for {lost} segments"
        );
        received.extend(read_all(&mut server));
        assert_eq!(received[..], data[..received.len()]);
    }

    #[test]
    fn blackout_recovers_in_log_round_trips() {
        blackout_run(false, 40235);
        blackout_run(true, 40236);
    }

    fn big(local: u16, remote: u16) -> ConnConfig {
        let mut c = cfg(local, remote);
        c.mss = 1000;
        c.send_buf_size = 1 << 16;
        c.recv_buf_size = 1 << 16;
        c
    }

    /// One round trip of data, so the sender has seen a scaled window. The
    /// SYN-ACK's is unscaled and rounds differently, which would make the
    /// first ACK after it a window update rather than a duplicate.
    fn warm_up(client: &mut Conn, server: &mut Conn) {
        let (_, data) = client.write(&[0; 100]);
        let mut acks = deliver(server, &data);
        read_all(server);
        acks.extend(server.take_outgoing());
        deliver(client, &acks);
    }

    /// A connected pair whose round trips take `rtt`, timed by both ends:
    /// the handshake's, and a round trip of data as [`warm_up`] sends.
    fn rtt_pair(conf: impl Fn(u16, u16) -> ConnConfig, port: u16, rtt: Duration) -> (Conn, Conn) {
        let mut client = Conn::new(conf(port, 80));
        let mut server = Conn::new(conf(80, port));
        let syn = client.connect();
        advance(rtt / 2);
        let synack = server.accept_syn(&parse(&syn[0]));
        advance(rtt / 2);
        let ack = deliver(&mut client, &synack);
        advance(rtt / 2);
        deliver(&mut server, &ack);
        let (_, data) = client.write(&[0; 100]);
        advance(rtt / 2);
        let mut acks = deliver(&mut server, &data);
        read_all(&mut server);
        acks.extend(server.take_outgoing());
        advance(rtt / 2);
        deliver(&mut client, &acks);
        (client, server)
    }

    fn seqs(pkts: &[Vec<u8>]) -> Vec<u32> {
        pkts.iter().map(|p| parse(p).seq).collect()
    }

    /// The first segment is lost and the duplicate ACKs for the rest are
    /// held up until after the RTO has fired. They report the same loss the
    /// timeout already handled, so they must not start fast recovery on top
    /// of it (RFC 6582 §3.2 step 1, §4.1): that would cut ssthresh a second
    /// time and inflate cwnd from one segment to half the old flight.
    #[test]
    fn duplicate_acks_below_rto_recover_do_not_fast_retransmit() {
        let mut client = Conn::new(big(40225, 80));
        let mut server = Conn::new(big(80, 40225));
        drive_handshake(&mut client, &mut server);
        warm_up(&mut client, &mut server);
        let (_, segs) = client.write(&[3; 10_000]);
        assert_eq!(segs.len(), 10);
        let late_dups = deliver(&mut server, &segs[1..]);
        assert!(late_dups.len() >= 3);

        let rexmit = fire_rto(&mut client);
        assert_eq!(seqs(&rexmit), vec![parse(&segs[0]).seq]);
        let cwnd = client.cc.cwnd();
        let out = deliver(&mut client, &late_dups);
        assert!(!client.in_recovery(), "fast recovery during RTO recovery");
        assert_eq!(client.cc.cwnd(), cwnd);
        assert!(
            !seqs(&out).contains(&parse(&segs[0]).seq),
            "resent again, sent {:?}",
            seqs(&out)
        );
    }

    /// Segments 0 and 5 lost, and the duplicate ACKs held up until the RTO
    /// has resent segment 0. They report nothing that left the network
    /// since the timeout, so with cwnd at one segment they send nothing,
    /// and leave cwnd alone. The partial ACK for segment 0 then resends
    /// segment 5, skipping the SACKed segments around it, and only once. A
    /// HighRxt left over from an earlier recovery must not hide the hole.
    #[test]
    fn duplicate_acks_during_rto_recovery_resend_sacked_holes() {
        let mut client = Conn::new(big(40228, 80));
        let mut server = Conn::new(big(80, 40228));
        drive_handshake(&mut client, &mut server);
        warm_up(&mut client, &mut server);
        let (_, segs) = client.write(&[3; 10_000]);
        assert_eq!(segs.len(), 10);
        let arrived: Vec<Vec<u8>> = segs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 0 && *i != 5)
            .map(|(_, s)| s.clone())
            .collect();
        let late_dups = deliver(&mut server, &arrived);

        let rexmit = fire_rto(&mut client);
        assert_eq!(seqs(&rexmit), vec![parse(&segs[0]).seq]);
        let cwnd = client.cc.cwnd();
        let out = deliver(&mut client, &late_dups);
        assert!(out.is_empty(), "past cwnd, sent {:?}", seqs(&out));
        assert!(!client.in_recovery());
        assert_eq!(client.cc.cwnd(), cwnd);

        // The partial ACK the first retransmission draws stops at segment
        // 5: the go-back-N resend goes straight to it.
        let partial = deliver(&mut server, &rexmit);
        assert_eq!(parse(partial.last().unwrap()).ack, parse(&segs[5]).seq);
        let out = deliver(&mut client, &partial);
        assert_eq!(
            seqs(&out),
            vec![parse(&segs[5]).seq],
            "the SACKed-around hole, once"
        );
        let acks = deliver(&mut server, &out);
        assert_eq!(read_all(&mut server).len(), 10_000);
        assert!(deliver(&mut client, &acks).is_empty(), "hole resent twice");
        assert_eq!(client.ca, CaState::Open);
    }

    /// With SACK, an ACK reporting newly SACKed data is a duplicate even
    /// if its window moved (RFC 6675 §2): here the receiver's application
    /// reads as the segments behind the hole arrive, so every one of the
    /// ACKs they draw carries a different window.
    #[test]
    fn sack_duplicates_count_despite_window_changes() {
        let mut client = Conn::new(big(40240, 80));
        let mut server = Conn::new(big(80, 40240));
        drive_handshake(&mut client, &mut server);
        warm_up(&mut client, &mut server);
        let (_, segs) = client.write(&[8; 10_000]);
        assert_eq!(segs.len(), 10);
        let mut dups = deliver(&mut server, &segs[1..]);
        for (i, d) in dups.iter_mut().enumerate() {
            let mut seg = parse(d);
            assert!(!get_sack_blocks(&seg.options).is_empty());
            seg.window = seg.window.wrapping_sub(i as u16 + 1);
            *d = seg.marshal();
        }
        let out = deliver(&mut client, &dups);
        assert!(client.in_recovery(), "no fast retransmit");
        assert!(seqs(&out).contains(&parse(&segs[0]).seq));
    }

    /// RFC 6675 §5: one ACK that SACKs more than two segments' worth above
    /// the first unacknowledged byte shows it lost (IsLost), and starts
    /// recovery without waiting for two more duplicates that may never
    /// come.
    #[test]
    fn sack_recovery_starts_once_the_scoreboard_shows_loss() {
        let mut client = Conn::new(big(40241, 80));
        let mut server = Conn::new(big(80, 40241));
        drive_handshake(&mut client, &mut server);
        warm_up(&mut client, &mut server);
        let (_, segs) = client.write(&[8; 10_000]);
        assert_eq!(segs.len(), 10);
        // Segments 1-3 arrive, but only the last ACK does: it SACKs all
        // three.
        let dups = deliver(&mut server, &segs[1..4]);
        let out = deliver(&mut client, &dups[dups.len() - 1..]);
        assert!(client.in_recovery(), "no recovery on IsLost");
        assert_eq!(seqs(&out)[0], parse(&segs[0]).seq);

        // Two segments SACKed are not yet enough: RACK gives the first a
        // quarter of the round trip to turn up (RFC 8985 §6.2 step 4).
        let rtt = Duration::from_millis(100);
        let (mut client, mut server) = rtt_pair(big, 40242, rtt);
        let (_, segs) = client.write(&[8; 10_000]);
        advance(rtt / 2);
        let dups = deliver(&mut server, &segs[1..3]);
        advance(rtt / 2);
        deliver(&mut client, &dups[dups.len() - 1..]);
        assert!(!client.in_recovery());
        assert!(client.reo_deadline.is_some(), "reordering timer");
    }

    // --- RACK-TLP (RFC 8985) ---------------------------------------------

    /// Let whatever timer is due by now run (RACK's, the loss probe's,
    /// the RTO's), without moving it forward.
    fn tick_due(c: &mut Conn) -> Vec<Vec<u8>> {
        c.tick()
    }

    /// Segment 0 of ten lost, 1 and 2 SACKed a round trip later: fewer
    /// than DupThresh and no reordering seen, so RACK gives segment 0 a
    /// quarter of the minimum RTT on top of the round trip, and then
    /// retransmits it without waiting for the RTO or a third duplicate.
    #[test]
    fn rack_marks_a_loss_once_the_reordering_window_passes() {
        let rtt = Duration::from_millis(100);
        let (mut client, mut server) = rtt_pair(big, 40700, rtt);
        let (_, segs) = client.write(&[8; 10_000]);
        advance(rtt / 2);
        let dups = deliver(&mut server, &segs[1..3]);
        advance(rtt / 2);
        assert!(deliver(&mut client, &dups).is_empty());
        let due = client.reo_deadline.expect("reordering timer");
        // Due a quarter RTT after the round trip of segment 0, which went
        // out together with segments 1 and 2.
        let wait = due.saturating_duration_since(test_now());
        assert!(
            wait > Duration::from_millis(20) && wait <= Duration::from_millis(26),
            "{wait:?}"
        );
        advance(Duration::from_millis(10));
        assert!(tick_due(&mut client).is_empty(), "not yet");
        advance(Duration::from_millis(20));
        let out = tick_due(&mut client);
        assert_eq!(
            seqs(&out)[..1],
            [parse(&segs[0]).seq],
            "RACK retransmission"
        );
        assert!(client.in_recovery());
        assert_eq!(client.retries, 0, "no RTO");
    }

    /// The same, but segment 0 was only reordered: it arrives within the
    /// window, so nothing is resent, no recovery starts, and RACK learns
    /// the path reorders.
    #[test]
    fn reordering_within_the_window_is_not_loss() {
        let rtt = Duration::from_millis(100);
        let (mut client, mut server) = rtt_pair(big, 40701, rtt);
        let (_, segs) = client.write(&[8; 10_000]);
        advance(rtt / 2);
        let mut acks = deliver(&mut server, &segs[1..3]);
        advance(Duration::from_millis(10));
        acks.extend(deliver(&mut server, &segs[..1]));
        acks.extend(deliver(&mut server, &segs[3..]));
        acks.extend(delack_expired(&mut server));
        advance(rtt / 2);
        let out = deliver(&mut client, &acks);
        let resent: Vec<u32> = seqs(&out)
            .into_iter()
            .filter(|&s| seq_before(s, parse(&segs[9]).seq + 1000))
            .collect();
        assert!(resent.is_empty(), "resent {resent:?}");
        assert!(!client.in_recovery());
        assert!(client.score.reordering_seen());
        assert_eq!(client.reo_deadline, None);
        advance(rtt);
        assert!(
            tick_due(&mut client)
                .iter()
                .all(|p| parse(p).payload.is_empty())
        );
    }

    /// Three SACKed segments show the loss at once while no reordering has
    /// been seen (RFC 8985 §6.2 step 4's DupThresh).
    #[test]
    fn three_sacked_segments_mark_the_loss_at_once() {
        let rtt = Duration::from_millis(100);
        let (mut client, mut server) = rtt_pair(big, 40702, rtt);
        let (_, segs) = client.write(&[8; 10_000]);
        advance(rtt / 2);
        let dups = deliver(&mut server, &segs[1..4]);
        advance(rtt / 2);
        let out = deliver(&mut client, &dups);
        assert!(client.in_recovery());
        assert_eq!(seqs(&out)[0], parse(&segs[0]).seq);
    }

    /// The last two segments of a flight are lost. No ACK will ever show
    /// it, and before RACK-TLP only the RTO found it. The loss probe goes
    /// out two SRTTs after the last ACK instead, resending the last
    /// segment; its SACK has RACK find the one before it lost, and fast
    /// recovery repairs it: no timeout.
    #[test]
    fn tail_loss_probe_recovers_without_an_rto() {
        let rtt = Duration::from_millis(100);
        let (mut client, mut server) = rtt_pair(big, 40703, rtt);
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 3) as u8).collect();
        let (_, segs) = client.write(&data);
        advance(rtt / 2);
        let mut acks = deliver(&mut server, &segs[..8]);
        acks.extend(delack_expired(&mut server));
        advance(rtt / 2);
        deliver(&mut client, &acks);
        let pto = client.pto_deadline.expect("loss probe armed");
        let rto = client.rto_deadline.unwrap();
        assert!(pto < rto, "the probe comes before the RTO");
        let wait = pto.saturating_duration_since(test_now());
        assert!(wait >= 2 * client.rto.srtt(), "{wait:?}");

        advance(wait);
        let probe = tick_due(&mut client);
        assert_eq!(seqs(&probe), vec![parse(&segs[9]).seq], "the last segment");
        assert_eq!(
            client.tlp_end,
            Some(client.send_buf.as_ref().unwrap().nxt())
        );
        advance(rtt / 2);
        let acks = deliver(&mut server, &probe);
        // A little over the round trip: RACK takes no sample from a
        // retransmission delivered sooner than the minimum RTT, and what
        // the real clock adds between calls would decide which it is.
        advance(rtt / 2 + Duration::from_millis(1));
        let mut out = deliver(&mut client, &acks);
        if out.is_empty() {
            // One SACKed segment: RACK waits out its reordering window.
            advance(
                client
                    .reo_deadline
                    .unwrap()
                    .saturating_duration_since(test_now()),
            );
            out = tick_due(&mut client);
        }
        assert_eq!(seqs(&out), vec![parse(&segs[8]).seq]);
        advance(rtt / 2);
        let acks = deliver(&mut server, &out);
        advance(rtt / 2);
        deliver(&mut client, &acks);
        assert_eq!(read_all(&mut server), data);
        assert_eq!(client.retries, 0, "no RTO");
        assert_eq!(client.send_buf.as_ref().unwrap().unacked(), 0);
    }

    /// A probe for a flight of one segment also allows for a delayed ACK
    /// (RFC 8985 §7.2); and none is scheduled without SACK.
    #[test]
    fn loss_probe_timing() {
        let rtt = Duration::from_millis(50);
        let (mut client, _server) = rtt_pair(big, 40704, rtt);
        client.write(&[1; 500]);
        let wait = client
            .pto_deadline
            .unwrap()
            .saturating_duration_since(test_now());
        let srtt = client.rto.srtt();
        let want = (2 * srtt + TLP_MAX_ACK_DELAY).min(client.rto.rto());
        assert!(
            wait.abs_diff(want) < Duration::from_millis(1),
            "{wait:?} vs {want:?}"
        );

        let (mut client, _server) = rtt_pair(|l, r| big(l, r).enable_sack(false), 40705, rtt);
        client.write(&[1; 500]);
        assert_eq!(client.pto_deadline, None);
    }

    /// A loss probe of new data counts as a probe too: only one at a time,
    /// and the RTO is the last resort after it.
    #[test]
    fn loss_probe_sends_new_data_first() {
        let rtt = Duration::from_millis(100);
        let (mut client, _server) = rtt_pair(big, 40706, rtt);
        let (_, segs) = client.write(&[2; 30_000]);
        assert_eq!(segs.len(), 10, "cwnd holds back the rest");
        let next = parse(&segs[9]).seq + 1000;
        advance(
            client
                .pto_deadline
                .unwrap()
                .saturating_duration_since(test_now()),
        );
        let probe = tick_due(&mut client);
        assert_eq!(seqs(&probe), vec![next]);
        assert_eq!(client.pto_deadline, None);
        assert!(client.rto_deadline.is_some());
        // No second probe while the first is out.
        client.pto_deadline = Some(test_now());
        assert!(tick_due(&mut client).is_empty());
    }

    /// The receiver SACKed segment 1, then acknowledged only segment 0:
    /// it has dropped segment 1 (reneged). The RTO, which forgets SACKs,
    /// fires a moment later rather than a whole RTO later, and resends it.
    #[test]
    fn reneged_sacks_are_acted_on_soon() {
        let rtt = Duration::from_millis(100);
        let (mut client, server) = rtt_pair(big, 40720, rtt);
        let (_, segs) = client.write(&[4; 5000]);
        let seq = |i: usize| parse(&segs[i]).seq;
        let mut sack = bare_ack(&client, &server, seq(0), 0xFFFF);
        sack.options = vec![sack_option(&[SackBlock {
            left: seq(1),
            right: seq(2),
        }])];
        advance(rtt);
        client.handle_segment(&sack);
        client.handle_segment(&bare_ack(&client, &server, seq(1), 64));
        let wait = client
            .rto_deadline
            .unwrap()
            .saturating_duration_since(test_now());
        assert!(
            wait <= client.rto.srtt() / 2 + Duration::from_millis(1),
            "{wait:?}"
        );
        advance(wait);
        client.pto_deadline = None;
        let out = client.tick();
        assert_eq!(seqs(&out), vec![seq(1)]);
        assert_eq!(client.score.sacked_segs(), 0, "SACKs forgotten");
    }

    // --- Spurious retransmissions (RFC 3708, 3522, 5682, 4015) ------------

    /// Eifel looks at the ACK of the retransmission, not at the first one
    /// advancing SND.UNA: one short of it may acknowledge a segment resent
    /// in an earlier episode, and echo that segment's older timestamp.
    #[test]
    fn eifel_waits_for_the_ack_of_the_retransmission() {
        let (mut client, _server, segs, late_and_rexmit) = spurious_fast_retransmit(true, 40735);
        // Stand in for a first retransmission ending past what this ACK
        // covers.
        let end = parse(&segs[9]).seq;
        client.undo.eifel_end = Some(end);
        advance(Duration::from_millis(50));
        deliver(&mut client, &late_and_rexmit[..1]);
        assert!(client.in_recovery(), "undone on the wrong ACK");
        assert_eq!(client.undo.eifel_end, Some(end), "still waiting");
    }

    /// Segment 0 is only delayed, past three later ones: RACK has fast
    /// recovery resend it and halve ssthresh. `ts` turns timestamps on.
    /// Returns the pair, the flight, and what the server sent back for the
    /// late original.
    fn spurious_fast_retransmit(ts: bool, port: u16) -> (Conn, Conn, Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let rtt = Duration::from_millis(100);
        let (mut client, mut server) = rtt_pair(|l, r| big(l, r).enable_timestamps(ts), port, rtt);
        let (_, segs) = client.write(&[6; 10_000]);
        advance(rtt / 2);
        let dups = deliver(&mut server, &segs[1..4]);
        advance(rtt / 2);
        let rexmit = deliver(&mut client, &dups);
        assert!(client.in_recovery());
        assert_eq!(seqs(&rexmit)[0], parse(&segs[0]).seq);
        assert!(client.cc.ssthresh() < u32::MAX);
        advance(Duration::from_millis(5));
        let late = deliver(&mut server, &segs[..1]);
        (client, server, segs, [late, rexmit].concat())
    }

    /// Without timestamps, the D-SACK the needless retransmission draws
    /// shows every retransmission of the episode arrived twice (RFC 3708),
    /// and the window is put back (RFC 4015).
    #[test]
    fn dsack_undoes_a_spurious_fast_retransmit() {
        let (mut client, mut server, _, late_and_rexmit) = spurious_fast_retransmit(false, 40730);
        let (late, rexmit) = late_and_rexmit.split_at(1);
        advance(Duration::from_millis(50));
        deliver(&mut client, late);
        assert!(client.cc.ssthresh() < u32::MAX, "no undo without evidence");
        let dsack = deliver(&mut server, &rexmit[..1]);
        let blocks = get_sack_blocks(&parse(&dsack[0]).options);
        assert!(!blocks.is_empty(), "a D-SACK");
        advance(Duration::from_millis(50));
        deliver(&mut client, &dsack);
        assert_eq!(client.ca, CaState::Open);
        assert_eq!(client.cc.ssthresh(), u32::MAX, "ssthresh put back");
        assert!(client.score.reo_wnd_mult() > 1, "RACK's window widened");
    }

    /// With timestamps, the ACK of the late original echoes its TSval,
    /// older than the retransmission's: Eifel (RFC 3522) knows at once.
    #[test]
    fn eifel_undoes_a_spurious_fast_retransmit() {
        let (mut client, _server, _, late_and_rexmit) = spurious_fast_retransmit(true, 40731);
        advance(Duration::from_millis(50));
        deliver(&mut client, &late_and_rexmit[..1]);
        assert_eq!(client.ca, CaState::Open);
        assert_eq!(client.cc.ssthresh(), u32::MAX);
    }

    /// A delay spike longer than the RTO: the timeout resends segment 0,
    /// but the originals all arrive after all. F-RTO (RFC 5682) sends new
    /// data instead of resending the rest, the next ACK acknowledges an
    /// original it never resent, and the timeout is undone: ssthresh is
    /// back, and none of the flight goes twice.
    #[test]
    fn frto_undoes_a_spurious_timeout() {
        let rtt = Duration::from_millis(100);
        let (mut client, mut server) = rtt_pair(big, 40732, rtt);
        let (_, segs) = client.write(&[7; 30_000]);
        assert_eq!(segs.len(), 10);
        let last = parse(&segs[9]).seq;
        let rexmit = fire_rto(&mut client);
        assert_eq!(seqs(&rexmit), vec![parse(&segs[0]).seq]);
        assert_eq!(
            client.frto,
            Frto::First {
                head_end: parse(&segs[1]).seq
            }
        );
        let mut acks = deliver(&mut server, &segs);
        acks.extend(delack_expired(&mut server));
        let mut sent = Vec::new();
        for a in &acks {
            advance(Duration::from_millis(1));
            sent.extend(client.handle_segment(&parse(a)));
        }
        assert_eq!(client.ca, CaState::Open, "timeout undone");
        assert_eq!(client.frto, Frto::Off);
        assert_eq!(client.cc.ssthresh(), u32::MAX);
        let resent: Vec<u32> = seqs(&sent)
            .into_iter()
            .filter(|&s| seq_before_eq(s, last))
            .collect();
        assert!(resent.is_empty(), "resent {resent:?}");
        assert!(!sent.is_empty(), "new data flows");
        assert!(client.rto_adapt.is_some() || client.rto.srtt() >= rtt);
    }

    /// Without SACK and timestamps, F-RTO still tells a spurious timeout
    /// (§2.1): the second ACK after it advances the window.
    #[test]
    fn frto_without_sack() {
        let rtt = Duration::from_millis(100);
        let (mut client, mut server) = rtt_pair(|l, r| big(l, r).enable_sack(false), 40733, rtt);
        let (_, segs) = client.write(&[7; 30_000]);
        fire_rto(&mut client);
        let mut acks = deliver(&mut server, &segs);
        acks.extend(delack_expired(&mut server));
        for a in &acks {
            client.handle_segment(&parse(a));
        }
        assert_eq!(client.ca, CaState::Open);
        assert_eq!(client.cc.ssthresh(), u32::MAX);
    }

    /// A tail loss probe that was not needed: the original last segment
    /// arrived, and so does the probe, drawing a D-SACK. That ends the
    /// probe's episode without the congestion response a repaired loss
    /// gets (RFC 8985 §7.4.2).
    #[test]
    fn dsack_of_a_needless_probe_keeps_the_window() {
        let rtt = Duration::from_millis(100);
        let (mut client, mut server) = rtt_pair(big, 40734, rtt);
        let (_, segs) = client.write(&[1; 10_000]);
        let mut acks = deliver(&mut server, &segs);
        acks.extend(delack_expired(&mut server));
        // The ACKs are slow: the probe fires first.
        advance(
            client
                .pto_deadline
                .unwrap()
                .saturating_duration_since(test_now()),
        );
        let probe = client.tick();
        assert_eq!(seqs(&probe), vec![parse(&segs[9]).seq]);
        let dsack = deliver(&mut server, &probe);
        let cwnd = client.cc.cwnd();
        deliver(&mut client, &acks);
        deliver(&mut client, &dsack);
        assert_eq!(client.tlp_end, None);
        assert_eq!(client.cc.ssthresh(), u32::MAX, "no loss response");
        assert!(client.cc.cwnd() >= cwnd);
    }

    // --- PRR (RFC 6937) ---------------------------------------------------

    /// RFC 6937 §3.1's examples, a segment a unit: 20 in flight, ssthresh
    /// 10. One loss: the reduction is spread over the round trip, a
    /// segment every other ACK, and the flight ends at ssthresh. Fifteen
    /// losses, which take the pipe below ssthresh: PRR-SSRB sends two
    /// segments per ACK, slow start's pace, rather than all at once.
    #[test]
    fn prr_send_quantities_follow_rfc_6937() {
        let (fs, ssthresh) = (20, 10);
        let (mut delivered, mut out) = (0u64, 0u64);
        let mut sent = Vec::new();
        let mut pipe = 19u32;
        for _ in 3..=19 {
            delivered += 1;
            pipe -= 1;
            let n = prr_sndcnt(delivered, out, fs, ssthresh, pipe, 1, 1).max(u32::from(out == 0));
            out += u64::from(n);
            pipe += n;
            sent.push(n);
        }
        assert_eq!(sent[..15], [1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]);
        assert_eq!(pipe, ssthresh, "ends at ssthresh");

        // The burst: ACKs 17, 18 and 19 each find the pipe below ssthresh.
        let (mut delivered, mut out) = (0u64, 0u64);
        let mut pipe = 5u32;
        let mut sent = Vec::new();
        for _ in 17..=19 {
            delivered += 1;
            pipe -= 1;
            let n = prr_sndcnt(delivered, out, fs, ssthresh, pipe, 1, 1);
            out += u64::from(n);
            pipe += n;
            sent.push(n);
        }
        assert_eq!(sent, [2, 2, 2]);
    }

    /// A loss in a window of twenty segments: fast recovery sends a
    /// segment for about every other ACK, never a burst, and leaves the
    /// window at ssthresh, where cwnd = ssthresh would have gone quiet for
    /// half the round trip and then sent the rest at once, and RFC 5681's
    /// inflation would have gone on past it.
    #[test]
    fn prr_spreads_the_reduction_over_the_round_trip() {
        let rtt = Duration::from_millis(100);
        let conf = |l, r| big(l, r).send_buf_size(1 << 20).recv_buf_size(1 << 20);
        let (mut client, mut server) = rtt_pair(conf, 40710, rtt);
        client.cc.set_cwnd(20_000);
        let (_, segs) = client.write(&[3; 100_000]);
        assert_eq!(segs.len(), 20);
        advance(rtt / 2);
        let acks = deliver(&mut server, &segs[1..]);
        advance(rtt / 2);
        let mut per_ack = Vec::new();
        let mut started = false;
        for a in &acks {
            let out = client.handle_segment(&parse(a));
            started |= client.in_recovery();
            if started {
                per_ack.push(out.len());
            }
        }
        assert!(client.in_recovery());
        assert!(per_ack.iter().all(|&n| n <= 2), "{per_ack:?}");
        let half = per_ack.len() / 2;
        assert!(per_ack[1..half].iter().sum::<usize>() >= 3, "{per_ack:?}");
        let ssthresh = client.cc.ssthresh();
        assert!(
            client.in_flight().abs_diff(ssthresh) <= 1000,
            "pipe {} vs ssthresh {ssthresh}",
            client.in_flight()
        );
    }

    /// The MSS counts payload only; options come out of it (RFC 6691 §2,
    /// RFC 9293 §3.7.1). A full-sized segment that also carries timestamps
    /// and SACK blocks would otherwise exceed the path MTU.
    #[test]
    fn segments_with_options_fit_the_mss() {
        let conf = |l, r| big(l, r).enable_timestamps(true);
        let mut client = Conn::new(conf(40226, 80));
        let mut server = Conn::new(conf(80, 40226));
        drive_handshake(&mut client, &mut server);
        assert!(server.ts_ok && server.sack_ok);
        let mss = server.mss as usize;
        let fits = |pkts: &[Vec<u8>]| {
            for p in pkts {
                assert!(
                    p.len() <= 20 + mss,
                    "{} bytes of TCP for MSS {mss}",
                    p.len()
                );
            }
        };

        // Timestamps only: a full segment carries MSS - 12 bytes of data.
        let (_, out) = server.write(&[1; 3000]);
        fits(&out);
        assert_eq!(parse(&out[0]).payload.len(), mss - 12);
        let acks = deliver(&mut client, &out);
        deliver(&mut server, &acks);

        // With a hole in what the server has received, its data segments
        // carry SACK blocks too, and a retransmission must fit as well.
        let (_, segs) = client.write(&[2; 4000]);
        deliver(&mut server, &segs[1..2]);
        deliver(&mut server, &segs[3..]);
        let (_, out) = server.write(&[3; 3000]);
        assert!(!get_sack_blocks(&parse(&out[0]).options).is_empty());
        fits(&out);
        fits(&fire_rto(&mut server));
    }

    /// With the window full and more to send, the first two duplicates
    /// each release one new segment (RFC 3042), and once in recovery the
    /// inflated window keeps new data flowing (RFC 5681 §3.2 step 4).
    #[test]
    fn duplicate_acks_keep_new_data_flowing() {
        let mut client = Conn::new(big(40230, 80));
        let mut server = Conn::new(big(80, 40230));
        drive_handshake(&mut client, &mut server);
        warm_up(&mut client, &mut server);
        let (n, segs) = client.write(&[9; 30_000]);
        assert_eq!((n, segs.len()), (30_000, 10), "cwnd holds back the rest");
        let first_unsent = parse(&segs[9]).seq + 1000;

        let dups = deliver(&mut server, &segs[1..2]);
        let out = deliver(&mut client, &dups);
        assert_eq!(
            seqs(&out),
            vec![first_unsent],
            "limited transmit, first dup"
        );
        let dups = deliver(&mut server, &segs[2..3]);
        let out = deliver(&mut client, &dups);
        assert_eq!(
            seqs(&out),
            vec![first_unsent + 1000],
            "limited transmit, second dup"
        );

        let dups = deliver(&mut server, &segs[3..]);
        let out = deliver(&mut client, &dups);
        let lost = parse(&segs[0]).seq;
        assert_eq!(
            out.first().map(|p| parse(p).seq),
            Some(lost),
            "fast retransmit"
        );
        assert!(
            seqs(&out).iter().any(|&s| s >= first_unsent + 2000),
            "new data once inflation passes the flight, sent {:?}",
            seqs(&out)
        );
    }

    /// Without timestamps, an ACK carries four SACK blocks, not three.
    #[test]
    fn four_sack_blocks_without_timestamps() {
        let mut client = Conn::new(big(40240, 80));
        let mut server = Conn::new(big(80, 40240));
        drive_handshake(&mut client, &mut server);
        assert!(server.sack_ok && !server.ts_ok);
        let (_, segs) = client.write(&[1; 9000]);
        // Every other segment arrives: four separate out-of-order ranges.
        let odd: Vec<Vec<u8>> = segs.iter().skip(1).step_by(2).cloned().collect();
        let acks = deliver(&mut server, &odd);
        let last = parse(acks.last().unwrap());
        let blocks = get_sack_blocks(&last.options);
        assert_eq!(blocks.len(), 4, "{blocks:?}");
        assert_eq!(blocks[0].left, parse(&segs[7]).seq, "newest first");
    }

    /// A segment received twice draws a D-SACK (RFC 2883): an old one
    /// alone, one held out of order followed by its range; reported once.
    #[test]
    fn duplicates_are_reported_with_dsack() {
        let mut client = Conn::new(big(40245, 80));
        let mut server = Conn::new(big(80, 40245));
        drive_handshake(&mut client, &mut server);
        let (_, segs) = client.write(&[1; 5000]);
        let seq = |i: usize| parse(&segs[i]).seq;
        let blocks = |pkts: &[Vec<u8>]| get_sack_blocks(&parse(pkts.last().unwrap()).options);
        let sb = |l, r| SackBlock { left: l, right: r };

        deliver(&mut server, &segs[..1]);
        let acks = deliver(&mut server, &segs[..1]);
        assert_eq!(blocks(&acks), vec![sb(seq(0), seq(1))], "below RCV.NXT");

        deliver(&mut server, &segs[2..4]);
        let acks = deliver(&mut server, &segs[3..4]);
        assert_eq!(
            blocks(&acks),
            vec![sb(seq(3), seq(4)), sb(seq(2), seq(4))],
            "inside an out-of-order range"
        );
        let acks = deliver(&mut server, &segs[4..5]);
        assert_eq!(blocks(&acks), vec![sb(seq(2), seq(4) + 1000)], "once");

        // Without SACK, no D-SACK either.
        let mut client = Conn::new(big(40246, 80).enable_sack(false));
        let mut server = Conn::new(big(80, 40246).enable_sack(false));
        drive_handshake(&mut client, &mut server);
        let (_, segs) = client.write(&[1; 100]);
        deliver(&mut server, &segs);
        let acks = deliver(&mut server, &segs);
        assert!(get_sack_blocks(&parse(&acks[0]).options).is_empty());
    }

    /// A data segment from `server` to `client` carrying `ack`.
    fn data_with_ack(client: &Conn, server: &Conn, ack: u32, payload: &[u8], fin: bool) -> Segment {
        Segment {
            src_port: server.cfg.local_port,
            dst_port: client.cfg.local_port,
            seq: client.recv_buf.as_ref().unwrap().nxt(),
            ack,
            flags: flags::ACK | if fin { flags::FIN } else { 0 },
            window: 4096,
            payload: payload.to_vec(),
            ..Default::default()
        }
    }

    // RFC 9293 §3.10.7.4: an ACK for something not yet sent gets an ACK
    // back and the segment is dropped, data and FIN included. Accepting the
    // payload would let a blind attacker who guessed only the SEQ inject it.
    #[test]
    fn ack_of_unsent_data_drops_the_segment() {
        let (mut client, server) = established(40250);
        let nxt = client.send_buf.as_ref().unwrap().nxt();
        let seg = data_with_ack(&client, &server, nxt.wrapping_add(1000), b"evil", true);
        let out = client.handle_segment(&seg);
        assert_eq!(out.len(), 1);
        assert_eq!(parse(&out[0]).ack, seg.seq, "the ACK must not cover it");
        assert!(read_all(&mut client).is_empty());
        assert!(!client.fin_received());
        assert_eq!(client.state(), State::Established);
    }

    // RFC 5961 §5.2: an ACK more than MAX.SND.WND below SND.UNA cannot come
    // from the peer; drop the segment and send a challenge ACK.
    #[test]
    fn ack_far_below_snd_una_drops_the_segment() {
        let (mut client, server) = established(40251);
        let una = client.send_buf.as_ref().unwrap().una();
        let seg = data_with_ack(&client, &server, una.wrapping_sub(100_000), b"evil", false);
        let out = client.handle_segment(&seg);
        assert_eq!(out.len(), 1);
        assert!(read_all(&mut client).is_empty());

        // An old ACK within the window is fine: the data is taken.
        let seg = data_with_ack(&client, &server, una.wrapping_sub(1000), b"good", false);
        client.handle_segment(&seg);
        assert_eq!(read_all(&mut client), b"good");
    }

    fn fire_persist(c: &mut Conn) -> Vec<Vec<u8>> {
        assert!(c.persist_deadline.is_some(), "persist not armed");
        c.persist_deadline = Some(Instant::now());
        c.tick()
    }

    /// A pure ACK from `server` to `client` for `ack`, offering `window`.
    fn bare_ack(client: &Conn, server: &Conn, ack: u32, window: u16) -> Segment {
        Segment {
            window,
            ..data_with_ack(client, server, ack, b"", false)
        }
    }

    // A window probe carries no data, at SND.UNA-1 (Linux's
    // tcp_xmit_probe_skb): a byte of new data would lie past a window the
    // receiver never opened, and SND.NXT does not move.
    #[test]
    fn persist_probes_take_no_sequence_space() {
        let (mut client, server) = established(40270);
        client.snd_wnd = 0;
        client.write(b"abcdef");
        let una = client.send_buf.as_ref().unwrap().una();
        for _ in 0..3 {
            let probe = fire_persist(&mut client);
            assert_eq!(probe.len(), 1);
            let seg = parse(&probe[0]);
            assert_eq!((seg.seq, seg.seg_len()), (una.wrapping_sub(1), 0));
            // The receiver still has no room.
            client.handle_segment(&bare_ack(&client, &server, una, 0));
        }
        assert_eq!(client.send_buf.as_ref().unwrap().nxt(), una);
        assert!(client.rto_deadline.is_none(), "nothing sent to time out");
    }

    // The zero-window ACK a probe draws matches SND.UNA and the last window,
    // but it is flow control, not a loss signal: no Early Retransmit.
    #[test]
    fn zero_window_probe_reply_is_not_a_duplicate_ack() {
        let (mut client, server) = established(40271);
        client.snd_wnd = 0;
        client.write(b"abcdef");
        let una = client.send_buf.as_ref().unwrap().una();
        let cwnd = client.cc.cwnd();
        fire_persist(&mut client);
        for _ in 0..3 {
            let out = client.handle_segment(&bare_ack(&client, &server, una, 0));
            assert!(out.is_empty(), "retransmitted on a zero-window ACK");
        }
        assert!(!client.in_recovery());
        assert_eq!(client.cc.cwnd(), cwnd);
    }

    /// B fills A's receive window and A's application stops reading, and
    /// B's persist timer probes it. A's own data to B must still be
    /// acknowledged: B's ACKs have to stay inside A's closed window.
    #[test]
    fn window_probe_does_not_blind_the_zero_window_peer() {
        let (mut a, mut b) = established(40272);
        let (_, mut pkts) = b.write(&[7u8; 4096]);
        while !pkts.is_empty() {
            let acks = deliver(&mut a, &pkts);
            pkts = deliver(&mut b, &acks);
        }
        assert_eq!(a.rcv_wnd_bytes(), 0);
        assert_eq!(b.snd_wnd, 0);
        b.write(&[8u8; 100]);
        let probe = fire_persist(&mut b);
        let replies = deliver(&mut a, &probe);
        assert_eq!(parse(&replies[0]).ack, a.recv_buf.as_ref().unwrap().nxt());
        assert_eq!(parse(&replies[0]).window, 0);
        deliver(&mut b, &replies);

        let (_, data) = a.write(b"request");
        let una = a.send_buf.as_ref().unwrap().una();
        let acks = deliver(&mut b, &data);
        assert_eq!(parse(&acks[0]).ack, una.wrapping_add(7));
        deliver(&mut a, &acks);
        assert_eq!(
            a.send_buf.as_ref().unwrap().una(),
            una.wrapping_add(7),
            "A ignored B's ACK"
        );
    }

    /// With nothing in flight only the persist timer watches a zero-window
    /// peer. It keeps probing for as long as the peer answers, and gives up
    /// once as many probes as the RTO would retransmit go unanswered.
    #[test]
    fn persist_gives_up_only_on_a_silent_peer() {
        let (mut client, server) = established(40276);
        client.snd_wnd = 0;
        client.write(b"abcdef");
        let una = client.send_buf.as_ref().unwrap().una();
        for _ in 0..MAX_RETRIES * 3 {
            assert_eq!(fire_persist(&mut client).len(), 1);
            client.handle_segment(&bare_ack(&client, &server, una, 0));
        }
        for _ in 0..MAX_RETRIES {
            assert_eq!(fire_persist(&mut client).len(), 1);
        }
        assert!(!client.is_closed());
        fire_persist(&mut client);
        assert!(client.is_closed());
    }

    /// Released, nobody will write or read again: a peer that answers
    /// every probe but never opens its window must not keep the
    /// connection forever (Linux's tcp_orphan_retries), on either timer.
    #[test]
    fn released_connection_gives_up_on_a_zero_window() {
        // Persist timer: nothing in flight.
        let (mut client, server) = established(40277);
        client.snd_wnd = 0;
        client.write(b"abcdef");
        let una = client.send_buf.as_ref().unwrap().una();
        client.release();
        for _ in 0..ORPHAN_RETRIES {
            assert!(!client.is_closed());
            assert_eq!(fire_persist(&mut client).len(), 1);
            client.handle_segment(&bare_ack(&client, &server, una, 0));
        }
        fire_persist(&mut client);
        assert!(client.is_closed(), "orphan probed a zero window forever");

        // Retransmission timer: data in flight when the window closed.
        let (mut client, server) = established(40278);
        client.write(b"data the peer cannot take");
        let una = client.send_buf.as_ref().unwrap().una();
        let zero_window_ack = Segment {
            src_port: 80,
            dst_port: 40278,
            seq: server.send_buf.as_ref().unwrap().nxt(),
            ack: una,
            flags: flags::ACK,
            window: 0,
            ..Default::default()
        };
        client.handle_segment(&zero_window_ack);
        client.release();
        for _ in 0..ORPHAN_RETRIES {
            assert!(!client.is_closed());
            fire_rto(&mut client);
            client.handle_segment(&zero_window_ack);
        }
        fire_rto(&mut client);
        assert!(client.is_closed(), "orphan probed a zero window forever");
    }

    /// RFC 9293 §3.10.7.4: with a zero receive window no segment is
    /// acceptable, "but special allowance should be made to accept valid
    /// ACKs". A peer that sent a probe byte or a FIN past our closed window
    /// sends its later ACKs one past RCV.NXT; their ACK fields count, the
    /// rest does not.
    #[test]
    fn ack_one_past_a_closed_window_is_processed() {
        let (mut client, mut server) = established(40274);
        let (_, mut pkts) = client.write(&[6u8; 4096]);
        while !pkts.is_empty() {
            let acks = deliver(&mut server, &pkts);
            pkts = deliver(&mut client, &acks);
        }
        assert_eq!(server.rcv_wnd_bytes(), 0);
        let (_, reply) = server.write(b"reply");
        assert_eq!(reply.len(), 1);
        let reply_end = server.send_buf.as_ref().unwrap().nxt();
        let rcv_nxt = server.recv_buf.as_ref().unwrap().nxt();

        // Two past the edge is still out of bounds.
        let mut seg = data_with_ack(&server, &client, reply_end, b"x", false);
        seg.seq = rcv_nxt.wrapping_add(2);
        server.handle_segment(&seg);
        assert_ne!(server.send_buf.as_ref().unwrap().una(), reply_end);

        seg.seq = rcv_nxt.wrapping_add(1);
        let out = server.handle_segment(&seg);
        assert_eq!(
            server.send_buf.as_ref().unwrap().una(),
            reply_end,
            "ACK ignored"
        );
        let ack = parse(&out[0]);
        assert_eq!(
            (ack.ack, ack.window),
            (rcv_nxt, 0),
            "the byte must not be taken"
        );

        // Nor does a FIN there count.
        let fin = Segment {
            seq: rcv_nxt.wrapping_add(1),
            ..data_with_ack(&server, &client, reply_end, b"", true)
        };
        server.handle_segment(&fin);
        assert!(!server.fin_received() && !server.fin_pending);
        assert_eq!(read_all(&mut server), vec![6u8; 4096]);
    }

    // A sender that never fills its window has not shown the network can
    // take more, so its cwnd must not grow (RFC 7661).
    #[test]
    fn application_limited_sender_keeps_cwnd() {
        let (mut client, mut server) = established(40280);
        let cwnd = client.cc.cwnd();
        let mut out = Vec::new();
        for _ in 0..200 {
            let (_, data) = client.write(&[1; 100]);
            out.extend(data);
            let acks = deliver(&mut server, &out);
            read_all(&mut server);
            out = deliver(&mut client, &acks);
        }
        assert_eq!(client.cc.cwnd(), cwnd);
    }

    /// A pair that has exchanged a segment of data, the client's window
    /// set to 64 segments.
    fn idle_pair(port: u16, ss_after_idle: bool) -> (Conn, Conn) {
        let conf = |l, r| big(l, r).slow_start_after_idle(ss_after_idle);
        let mut client = Conn::new(conf(port, 80));
        let mut server = Conn::new(conf(80, port));
        drive_handshake(&mut client, &mut server);
        let (_, data) = client.write(&[1; 1000]);
        let mut acks = deliver(&mut server, &data);
        acks.extend(delack_expired(&mut server));
        deliver(&mut client, &acks);
        assert_eq!(client.in_flight(), 0);
        client.cc.set_cwnd(64_000);
        (client, server)
    }

    /// Sending again after an idle spell of more than an RTO starts from
    /// a window halved per RTO of it, down to the initial window, as Linux
    /// does; ssthresh is left where it was (or at three quarters of the
    /// old window, if lower), so slow start regains it.
    #[test]
    fn idle_restart_decays_cwnd() {
        let (mut client, _server) = idle_pair(40281, true);
        let rto = client.rto.rto();
        advance(rto * 2 + Duration::from_millis(1));
        client.write(&[2; 100]);
        assert_eq!(client.cc.cwnd(), 16_000, "halved twice");
        assert_eq!(client.cc.ssthresh(), u32::MAX);

        let (mut client, _server) = idle_pair(40282, true);
        client.cc.undo(64_000, 40_000);
        advance(rto * 10);
        client.write(&[2; 100]);
        assert_eq!(client.cc.cwnd(), 10_000, "down to the initial window");
        assert_eq!(client.cc.ssthresh(), 48_000);

        // Less than an RTO is no idle spell.
        let (mut client, _server) = idle_pair(40283, true);
        advance(rto / 2);
        client.write(&[2; 100]);
        assert_eq!(client.cc.cwnd(), 64_000);
    }

    /// Without the restart the window is kept through a pause (RFC 7661),
    /// until the non-validated period ends: then it is halved (§4.4.3).
    #[test]
    fn non_validated_window_kept_for_the_period() {
        let (mut client, _server) = idle_pair(40284, false);
        let rto = client.rto.rto();
        advance(rto * 10);
        client.write(&[2; 100]);
        assert_eq!(client.cc.cwnd(), 64_000, "kept");

        let (mut client, _server) = idle_pair(40285, false);
        let srtt = Duration::from_millis(10);
        let t = test_now();
        client.pipe_ack.reset();
        client.pipe_ack.on_ack(t, 0, srtt);
        client.pipe_ack.on_ack(t + srtt, 2_000, srtt);
        client.now = t + srtt;
        client.validate_cwnd();
        assert!(client.nvp_since.is_some(), "non-validated");
        advance(Duration::from_secs(60));
        client.write(&[2; 100]);
        assert_eq!(client.cc.cwnd(), 64_000, "within the period");
        advance(cwv::NVP);
        client.write(&[2; 100]);
        assert_eq!(client.cc.cwnd(), 32_000, "halved at its end");
        assert_eq!(client.cc.ssthresh(), u32::MAX);
    }

    /// A loss in the non-validated phase is answered from what was in
    /// use, max(pipeACK, flight), not from the window kept (RFC 7661
    /// §4.4.1).
    #[test]
    fn loss_in_non_validated_phase_uses_pipe_ack() {
        let (mut client, _server) = idle_pair(40286, false);
        let srtt = Duration::from_millis(10);
        let t = test_now();
        client.pipe_ack.reset();
        client.pipe_ack.on_ack(t, 0, srtt);
        client.pipe_ack.on_ack(t + srtt, 8_000, srtt);
        client.now = t + srtt;
        client.validate_cwnd();
        assert_eq!(client.loss_flight(3_000), 8_000);
        assert_eq!(client.cc.cwnd(), 8_000);
        assert!(client.nvp_since.is_none(), "the loss ends the phase");
        // Validated, the flight is what counts, and cwnd is left alone.
        client.cc.set_cwnd(64_000);
        assert_eq!(client.loss_flight(3_000), 3_000);
        assert_eq!(client.cc.cwnd(), 64_000);
    }

    fn syn_with(opts: Vec<TcpOption>) -> Segment {
        Segment {
            src_port: 40290,
            dst_port: 80,
            seq: 1000,
            flags: flags::SYN,
            window: 65535,
            options: opts,
            ..Default::default()
        }
    }

    fn v6_cfg() -> ConnConfig {
        let mut c = cfg(80, 40290);
        c.local_addr = Some("[fd00::1]:80".parse().unwrap());
        c.remote_addr = Some("[fd00::2]:40290".parse().unwrap());
        c
    }

    // RFC 9293 §3.7.1: a SYN without an MSS option means 536 over IPv4, and
    // 1220 over IPv6 (RFC 8200 §5); a tiny MSS is raised to MIN_MSS.
    #[test]
    fn peer_mss_defaults_and_floor() {
        let mut c = Conn::new(cfg(80, 40290));
        c.accept_syn(&syn_with(vec![]));
        assert_eq!(c.mss, 536);
        let mut c = Conn::new(v6_cfg());
        c.accept_syn(&syn_with(vec![]));
        assert_eq!(c.mss, 1220);
        let mut c = Conn::new(cfg(80, 40290));
        let synack = parse(&c.accept_syn(&syn_with(vec![mss_option(1)]))[0]);
        assert_eq!(c.mss, options::MIN_MSS);
        // Our SYN-ACK still offers what we can receive.
        assert_eq!(get_mss(&synack.options), 1460);
    }

    /// The ACK completing a cookie handshake whose SYN had sequence 1000 and
    /// whose cookie was 5000.
    fn cookie_ack() -> Segment {
        Segment {
            src_port: 40290,
            dst_port: 80,
            seq: 1001,
            ack: 5001,
            flags: flags::ACK,
            window: 29200,
            ..Default::default()
        }
    }

    /// A released connection answers new data with a reset, and releasing
    /// with unread data resets rather than closes (RFC 2525 §2.17).
    #[test]
    fn released_connections_reset_on_data() {
        let (mut client, mut server) = established(40380);
        let fin = client.release();
        assert!(parse(&fin[0]).has_flag(flags::FIN));
        deliver(&mut server, &fin);
        let (_, data) = server.write(b"too late");
        let out = deliver(&mut client, &data);
        assert!(out.iter().any(|p| parse(p).has_flag(flags::RST)));
        assert!(client.is_closed());

        let (mut client, mut server) = established(40381);
        let (_, data) = server.write(b"unread");
        deliver(&mut client, &data);
        let out = client.release();
        assert!(
            parse(&out[0]).has_flag(flags::RST),
            "unread data: reset, not FIN"
        );
        assert!(client.is_closed());

        // A plain half-close keeps receiving.
        let (mut client, mut server) = established(40382);
        let fin = client.close();
        deliver(&mut server, &fin);
        let (_, data) = server.write(b"still wanted");
        deliver(&mut client, &data);
        assert_eq!(read_all(&mut client), b"still wanted");
    }

    /// Unread data at release resets only a connection that is still
    /// running. In TIME-WAIT both FINs are in and ACKed: there is nothing
    /// left to abort, and TIME-WAIT must carry on, as Linux's tcp_close
    /// does for a socket already in CLOSE.
    #[test]
    fn release_in_time_wait_with_unread_data_sends_nothing() {
        let (mut client, mut server) = established(40383);
        let fin = client.close();
        let acks = deliver(&mut server, &fin);
        deliver(&mut client, &acks);
        let (_, data) = server.write(b"never read");
        let mut out = data;
        out.extend(server.close());
        deliver(&mut client, &out);
        assert_eq!(client.state(), State::TimeWait);

        assert!(client.release().is_empty(), "reset from TIME-WAIT");
        assert_eq!(client.state(), State::TimeWait);
        assert!(client.time_wait_deadline.is_some());
        // Nobody will read it now.
        assert_eq!(client.recv_buf.as_ref().unwrap().allocated(), 0);
    }

    fn allocated(c: &Conn) -> (usize, usize) {
        (
            c.send_buf.as_ref().unwrap().allocated(),
            c.recv_buf.as_ref().unwrap().allocated(),
        )
    }

    /// TIME-WAIT and CLOSED send and receive nothing more, so they give
    /// back the buffers' memory, which an idle connection keeps as long as
    /// it stays under the shrink threshold. Unread data stays for the
    /// application to read.
    #[test]
    fn time_wait_and_closed_free_the_buffers() {
        let conf = |l, r| big(l, r).send_buf_size(1 << 20).recv_buf_size(1 << 20);
        let mut client = Conn::new(conf(40384, 80));
        let mut server = Conn::new(conf(80, 40384));
        drive_handshake(&mut client, &mut server);
        let chunk = vec![5u8; 30_000];
        let send = |tx: &mut Conn, rx: &mut Conn| {
            let (_, mut pkts) = tx.write(&chunk);
            while !pkts.is_empty() {
                let acks = deliver(rx, &pkts);
                pkts = deliver(tx, &acks);
                pkts.extend(tx.take_outgoing());
            }
        };
        send(&mut client, &mut server);
        send(&mut server, &mut client);
        assert_eq!(read_all(&mut server).len(), chunk.len());
        assert!(allocated(&client).0 > 0 && allocated(&server).0 > 0);
        assert!(allocated(&client).1 > 0 && allocated(&server).1 > 0);

        let fin = client.close();
        let acks = deliver(&mut server, &fin);
        deliver(&mut client, &acks);
        let fin = server.close();
        let acks = deliver(&mut client, &fin);
        assert_eq!(client.state(), State::TimeWait);
        deliver(&mut server, &acks);
        assert!(server.is_closed());

        assert_eq!(allocated(&server), (0, 0));
        // The client never read what the server sent.
        assert_eq!(allocated(&client).0, 0);
        assert_eq!(client.recv_buf.as_ref().unwrap().readable(), chunk.len());
        assert_eq!(read_all(&mut client).len(), chunk.len());

        // And an abort gives back the rest.
        let (mut client, mut server) = established(40385);
        let (_, data) = client.write(&[1; 1000]);
        deliver(&mut server, &data);
        client.abort();
        assert_eq!(allocated(&client), (0, 0));
    }

    /// A SYN numbered beyond the old connection may take over a 4-tuple in
    /// TIME-WAIT (RFC 6191); anything else may not.
    #[test]
    fn time_wait_gives_way_only_to_a_newer_syn() {
        let (mut client, mut server) = established(40370);
        assert_eq!(client.cfg.time_wait, TIME_WAIT_DURATION);
        let fin = client.close();
        let out = deliver(&mut server, &fin);
        deliver(&mut client, &out);
        let fin = server.close();
        deliver(&mut client, &fin);
        assert_eq!(client.state(), State::TimeWait);

        let rcv_nxt = client.recv_buf.as_ref().unwrap().nxt();
        let syn = |seq: u32, flags: u8| Segment {
            src_port: 80,
            dst_port: 40370,
            seq,
            flags,
            window: 4096,
            ..Default::default()
        };
        assert!(client.accepts_new_syn(&syn(rcv_nxt.wrapping_add(1000), flags::SYN)));
        assert!(!client.accepts_new_syn(&syn(rcv_nxt.wrapping_sub(1), flags::SYN)));
        assert!(!client.accepts_new_syn(&syn(rcv_nxt, flags::SYN)));
        assert!(!client.accepts_new_syn(&syn(rcv_nxt.wrapping_add(1000), flags::SYN | flags::ACK)));
        assert!(!server.accepts_new_syn(&syn(rcv_nxt.wrapping_add(1000), flags::SYN)));
    }

    /// RFC 5961 §7: invalid segments without data draw at most one ACK per
    /// OOW_ACK_INTERVAL, so a blind attacker gets no oracle per guess.
    #[test]
    fn challenge_acks_are_throttled() {
        let (mut client, server) = established(40360);
        let nxt = client.recv_buf.as_ref().unwrap().nxt();
        let (sport, dport) = (server.cfg.local_port, client.cfg.local_port);
        let rst = move |seq: u32| Segment {
            src_port: sport,
            dst_port: dport,
            seq,
            flags: flags::RST,
            ..Default::default()
        };
        // In the window but not exact: challenge ACK, once.
        assert_eq!(client.handle_segment(&rst(nxt.wrapping_add(10))).len(), 1);
        assert!(client.handle_segment(&rst(nxt.wrapping_add(20))).is_empty());
        assert_eq!(client.state(), State::Established);
        client.last_oow_ack = client.last_oow_ack.map(|t| t - OOW_ACK_INTERVAL);
        assert_eq!(client.handle_segment(&rst(nxt.wrapping_add(30))).len(), 1);

        // A data segment outside the window is always answered: the peer
        // may be retransmitting because it lost our ACK.
        let old = Segment {
            src_port: server.cfg.local_port,
            dst_port: client.cfg.local_port,
            seq: nxt.wrapping_sub(100),
            ack: client.send_buf.as_ref().unwrap().nxt(),
            flags: flags::ACK,
            window: 4096,
            payload: vec![1; 50],
            ..Default::default()
        };
        assert_eq!(client.handle_segment(&old).len(), 1);
        assert_eq!(client.handle_segment(&old).len(), 1);
    }

    /// A payload does not exempt a segment from the challenge-ACK throttle
    /// (RFC 5961 §7): a RST or SYN is never part of the data flow, and a
    /// blind attacker can attach bytes to each guess for free. Linux sends
    /// every challenge ACK through the per-socket limit.
    #[test]
    fn challenge_acks_are_throttled_for_segments_with_payload() {
        let (mut client, server) = established(40361);
        let nxt = client.recv_buf.as_ref().unwrap().nxt();
        let (sport, dport) = (server.cfg.local_port, client.cfg.local_port);
        let rst = move |seq: u32| Segment {
            src_port: sport,
            dst_port: dport,
            seq,
            flags: flags::RST,
            payload: vec![0; 20],
            ..Default::default()
        };
        assert_eq!(client.handle_segment(&rst(nxt.wrapping_add(10))).len(), 1);
        assert!(client.handle_segment(&rst(nxt.wrapping_add(20))).is_empty());
        assert_eq!(client.state(), State::Established);

        // An in-window segment whose ACK is further back than any window
        // the peer offered (RFC 5961 §5.2) draws a challenge ACK too.
        client.last_oow_ack = None;
        let una = client.send_buf.as_ref().unwrap().una();
        let seg = data_with_ack(&client, &server, una.wrapping_sub(100_000), b"evil", false);
        assert_eq!(client.handle_segment(&seg).len(), 1);
        assert!(client.handle_segment(&seg).is_empty());
    }

    /// A cookie connection takes the completing ACK's window, and its data.
    #[test]
    fn cookie_connection_takes_the_ack_window() {
        let mut c = Conn::new(cfg(80, 40290));
        let mut ack = cookie_ack();
        ack.payload = b"hi".to_vec();
        c.accept_cookie(&ack, 5000, 1460);
        assert_eq!(c.snd_wnd, 29200);
        assert_eq!(read_all(&mut c), b"hi");
    }

    // The congestion controller counts in segments of the negotiated MSS,
    // however the connection was opened.
    #[test]
    fn congestion_controller_uses_negotiated_mss() {
        let initial_cwnd = 10 * 536;
        let mut c = Conn::new(cfg(80, 40290));
        c.accept_syn(&syn_with(vec![mss_option(536)]));
        assert_eq!(c.cc.cwnd(), initial_cwnd, "passive open");

        let mut c = Conn::new(cfg(80, 40290));
        c.accept_cookie(&cookie_ack(), 5000, 536);
        assert_eq!(c.cc.cwnd(), initial_cwnd, "SYN cookie");

        let mut c = Conn::new(cfg(80, 40290));
        c.connect();
        c.handle_segment(&syn_with(vec![mss_option(536)]));
        assert_eq!(c.state(), State::SynReceived);
        assert_eq!(c.cc.cwnd(), initial_cwnd, "simultaneous open");
    }

    // Keepalive and persist are independent timers: a keepalive that
    // finds the peer active must not cancel zero-window probing.
    #[test]
    fn keepalive_keeps_persist_armed() {
        let mut c = cfg(40300, 80);
        c.keepalive = true;
        let mut client = Conn::new(c);
        let mut server = Conn::new(cfg(80, 40300));
        drive_handshake(&mut client, &mut server);
        client.snd_wnd = 0;
        client.write(b"blocked");
        assert!(client.persist_deadline.is_some());
        client.keepalive_deadline = Some(Instant::now());
        client.tick();
        assert!(client.persist_deadline.is_some(), "persist cancelled");
    }

    fn keepalive_pair(port: u16) -> (Conn, Conn) {
        let mut client = Conn::new(cfg(port, 80).keepalive(true));
        let mut server = Conn::new(cfg(80, port));
        drive_handshake(&mut client, &mut server);
        (client, server)
    }

    /// Expire the keepalive timer with the peer idle for longer than the
    /// keepalive idle time.
    fn fire_keepalive(c: &mut Conn) -> Vec<Vec<u8>> {
        assert!(c.keepalive_deadline.is_some(), "keepalive not armed");
        c.last_recv = Instant::now() - c.cfg.keepalive_idle - Duration::from_secs(1);
        c.keepalive_deadline = Some(Instant::now());
        c.tick()
    }

    // Linux keeps probing through the close handshake: a half-closed
    // application waiting in FIN-WAIT-2 for a peer that has vanished would
    // otherwise wait forever. While our FIN is still in flight the RTO is
    // watching the peer instead, but the timer must survive to take over.
    #[test]
    fn keepalive_runs_in_fin_wait_states() {
        let (mut client, mut server) = keepalive_pair(40301);
        let fin = client.close();
        assert_eq!(client.state(), State::FinWait1);
        assert!(
            fire_keepalive(&mut client).is_empty(),
            "probe beside the FIN"
        );
        let rearmed = client
            .keepalive_deadline
            .is_some_and(|d| d > Instant::now());
        assert!(rearmed, "stopped in FIN-WAIT-1");

        let ack = deliver(&mut server, &fin);
        deliver(&mut client, &ack);
        assert_eq!(client.state(), State::FinWait2);
        let probe = fire_keepalive(&mut client);
        assert_eq!(probe.len(), 1, "no probe in FIN-WAIT-2");
        let seg = parse(&probe[0]);
        assert_eq!(
            seg.seq,
            client.send_buf.as_ref().unwrap().nxt().wrapping_sub(1)
        );
        assert!(seg.payload.is_empty() && seg.flags == flags::ACK);
        // The peer answers it, since it is below RCV.NXT.
        assert_eq!(deliver(&mut server, &probe).len(), 1);
    }

    // Idle time counts from the last segment heard, not from whenever the
    // timer last fired: otherwise a probe could come up to twice the idle
    // time after the peer went quiet.
    #[test]
    fn keepalive_idle_counts_from_last_segment() {
        let (mut client, _server) = keepalive_pair(40303);
        let idle = client.cfg.keepalive_idle;
        client.last_recv = Instant::now() - idle / 2;
        client.keepalive_deadline = Some(Instant::now());
        assert!(client.tick().is_empty());
        let due = client.keepalive_deadline.unwrap();
        assert!(
            due <= client.last_recv + idle,
            "re-armed {:?} late",
            due - (client.last_recv + idle)
        );
    }

    // Only a segment that passes validation says the peer is alive: an
    // out-of-window one, or one acknowledging data never sent, can come
    // from anyone, and must not hold off the keepalive (or the FIN-WAIT-2
    // and zero-window timeouts that read the same clock).
    #[test]
    fn invalid_segments_do_not_refresh_liveness() {
        let (mut client, server) = keepalive_pair(40304);
        let stale = Instant::now() - client.cfg.keepalive_idle;
        client.last_recv = stale;
        client.keepalive_sent = 2;
        let snd_nxt = client.send_buf.as_ref().unwrap().nxt();
        let rcv_nxt = client.recv_buf.as_ref().unwrap().nxt();
        let mut oow = bare_ack(&client, &server, snd_nxt, 1000);
        oow.seq = rcv_nxt.wrapping_add(1 << 30);
        client.handle_segment(&oow);
        let bad_ack = bare_ack(&client, &server, snd_nxt.wrapping_add(1000), 1000);
        client.handle_segment(&bad_ack);
        assert_eq!(client.last_recv, stale, "refreshed by an invalid segment");
        assert_eq!(client.keepalive_sent, 2);

        client.handle_segment(&bare_ack(&client, &server, snd_nxt, 1000));
        assert!(client.last_recv > stale, "a valid ACK is a sign of life");
        assert_eq!(client.keepalive_sent, 0);
    }

    // Once released, FIN-WAIT-2 has its own timeout: answered probes would
    // keep a peer that never closes around forever.
    #[test]
    fn released_fin_wait_2_leaves_it_to_the_timeout() {
        let (mut client, mut server) = keepalive_pair(40302);
        let fin = client.release();
        let ack = deliver(&mut server, &fin);
        deliver(&mut client, &ack);
        assert_eq!(client.state(), State::FinWait2);
        client.released = Some(Instant::now());
        assert!(fire_keepalive(&mut client).is_empty());
    }

    fn ts_pair(port: u16) -> (Conn, Conn) {
        let conf = |l, r| {
            let mut c = cfg(l, r);
            c.enable_timestamps = true;
            c
        };
        let mut client = Conn::new(conf(port, 80));
        let mut server = Conn::new(conf(80, port));
        drive_handshake(&mut client, &mut server);
        (client, server)
    }

    // RFC 6191 §2: when the old connection used timestamps and the new SYN
    // carries one, the timestamp decides, not the sequence number: an
    // older TSval is an old duplicate (PAWS), a newer one is a new
    // connection even if its ISN happens to be lower.
    #[test]
    fn time_wait_reuse_goes_by_timestamps() {
        let (mut client, mut server) = ts_pair(40315);
        let fin = client.close();
        let out = deliver(&mut server, &fin);
        deliver(&mut client, &out);
        deliver(&mut client, &server.close());
        assert_eq!(client.state(), State::TimeWait);

        let rcv_nxt = client.recv_buf.as_ref().unwrap().nxt();
        let recent = client.ts_recent;
        let syn = |seq: u32, ts: Option<u32>| Segment {
            src_port: 80,
            dst_port: 40315,
            seq,
            flags: flags::SYN,
            window: 4096,
            options: ts.map(|v| timestamp_option(v, 0)).into_iter().collect(),
            ..Default::default()
        };
        let (newer_seq, older_seq) = (rcv_nxt.wrapping_add(1000), rcv_nxt.wrapping_sub(1000));
        let (newer_ts, older_ts) = (recent.wrapping_add(10), recent.wrapping_sub(10));
        assert!(
            !client.accepts_new_syn(&syn(newer_seq, Some(older_ts))),
            "PAWS"
        );
        assert!(client.accepts_new_syn(&syn(older_seq, Some(newer_ts))));
        assert!(client.accepts_new_syn(&syn(newer_seq, Some(newer_ts))));
        // An equal TSval falls back to the sequence number.
        assert!(client.accepts_new_syn(&syn(newer_seq, Some(recent))));
        assert!(!client.accepts_new_syn(&syn(older_seq, Some(recent))));
        // No timestamp on the SYN: the sequence number alone.
        assert!(client.accepts_new_syn(&syn(newer_seq, None)));
        assert!(!client.accepts_new_syn(&syn(older_seq, None)));
    }

    // RFC 7323 §3.2: the SYN-ACK echoes the SYN's TSval.
    #[test]
    fn syn_ack_echoes_syn_tsval() {
        let mut conf = cfg(80, 40310);
        conf.enable_timestamps = true;
        let mut server = Conn::new(conf);
        let syn = syn_with(vec![timestamp_option(123_456, 0)]);
        let synack = parse(&server.accept_syn(&syn)[0]);
        assert_eq!(get_timestamp(&synack.options).map(|t| t.1), Some(123_456));
    }

    // RFC 7323 §2.2, §3.2 and RFC 2018 §2: a SYN-ACK carries window scale,
    // SACK-permitted and timestamps only in answer to a SYN that did.
    #[test]
    fn syn_ack_answers_only_offered_options() {
        let mut conf = cfg(80, 40311);
        conf.enable_timestamps = true;
        let mut server = Conn::new(conf);
        let synack = parse(&server.accept_syn(&syn_with(vec![mss_option(1460)]))[0]);
        let kinds: Vec<u8> = synack.options.iter().map(|o| o.kind).collect();
        assert_eq!(kinds, vec![options::kind::Mss], "{kinds:?}");

        let mut conf = cfg(80, 40311);
        conf.enable_timestamps = true;
        let mut server = Conn::new(conf);
        let offered = vec![
            mss_option(1460),
            wscale_option(7),
            sack_perm_option(),
            timestamp_option(1, 0),
        ];
        let synack = parse(&server.accept_syn(&syn_with(offered))[0]);
        let o = &synack.options;
        assert!(get_wscale(o).is_some() && has_sack_perm(o) && get_timestamp(o).is_some());
    }

    // RFC 7323 §4.3: TS.Recent follows only segments at or below the last
    // ACK sent. An out-of-order one would have us echo a TSval from ahead
    // of the hole, and its RTT sample would miss the repair.
    #[test]
    fn paws_skipped_after_24_days_idle() {
        let (mut client, server) = ts_pair(40313);
        let una = client.send_buf.as_ref().unwrap().una();
        let mut seg = data_with_ack(&client, &server, una, b"", false);
        // Older than TS.Recent: the peer's clock wrapped while we sat idle.
        let old = client.ts_recent.wrapping_sub(1 << 30);
        seg.options = vec![timestamp_option(old, 0)];
        let now = Instant::now();
        assert!(!client.update_timestamp(&seg, now), "PAWS while fresh");
        assert!(!client.update_timestamp(&seg, now + Duration::from_secs(23 * 86400)));
        let later = now + Duration::from_secs(25 * 86400);
        assert!(
            client.update_timestamp(&seg, later),
            "rejected after 25 days idle"
        );
        assert_eq!(client.ts_recent, old, "the new TSval is adopted");
        // And TS.Recent is fresh again: older ones are rejected once more.
        seg.options = vec![timestamp_option(old.wrapping_sub(1), 0)];
        assert!(!client.update_timestamp(&seg, later));
    }

    #[test]
    fn out_of_order_segment_does_not_update_ts_recent() {
        let (mut client, server) = ts_pair(40312);
        let before = client.ts_recent;
        let mut seg = data_with_ack(
            &client,
            &server,
            client.send_buf.as_ref().unwrap().una(),
            b"x",
            false,
        );
        seg.seq = seg.seq.wrapping_add(100);
        seg.options = vec![timestamp_option(before.wrapping_add(1000), 0)];
        client.handle_segment(&seg);
        assert_eq!(client.ts_recent, before);

        seg.seq = seg.seq.wrapping_sub(100);
        client.handle_segment(&seg);
        assert_eq!(client.ts_recent, before.wrapping_add(1000));
    }

    // Timestamps keep working after the peer's FIN: a server answering a
    // half-closed client from CLOSE-WAIT must echo the TSvals of the ACKs
    // it gets, or the client's RTT samples (RFC 7323 §4) grow with every
    // one, and old segments must still meet PAWS.
    #[test]
    fn close_wait_tracks_timestamps() {
        let (mut client, mut server) = ts_pair(40316);
        let fin = client.close();
        let acks = deliver(&mut server, &fin);
        deliver(&mut client, &acks);
        assert_eq!(server.state(), State::CloseWait);

        let una = server.send_buf.as_ref().unwrap().una();
        let recent = server.ts_recent;
        let mut ack = bare_ack(&server, &client, una, 4096);
        ack.options = vec![timestamp_option(recent.wrapping_add(1000), 0)];
        server.handle_segment(&ack);
        assert_eq!(server.ts_recent, recent.wrapping_add(1000));

        // An old one is dropped, and draws only the throttled ACK.
        ack.options = vec![timestamp_option(recent, 0)];
        assert_eq!(server.handle_segment(&ack).len(), 1);
        assert_eq!(server.ts_recent, recent.wrapping_add(1000));
    }

    // The duplicate ACK a PAWS rejection draws goes through the same
    // throttle as other invalid segments (Linux's TCPACKSKIPPEDPAWS):
    // otherwise replayed old segments get an ACK each.
    #[test]
    fn paws_rejections_are_throttled() {
        let (mut client, server) = ts_pair(40314);
        let una = client.send_buf.as_ref().unwrap().una();
        let mut seg = bare_ack(&client, &server, una, 4096);
        seg.options = vec![timestamp_option(client.ts_recent.wrapping_sub(1000), 0)];
        assert_eq!(client.handle_segment(&seg).len(), 1);
        assert!(client.handle_segment(&seg).is_empty(), "unthrottled");
    }

    // Once negotiated, every segment but a RST carries a timestamp (RFC
    // 7323 §3.2), zero-window probes included.
    #[test]
    fn persist_probe_carries_timestamp() {
        let (mut client, _server) = ts_pair(40313);
        client.snd_wnd = 0;
        client.write(b"abc");
        let probe = parse(&fire_persist(&mut client)[0]);
        assert!(get_timestamp(&probe.options).is_some());
    }

    // Our FIN is ACKed but the peer never sends its own: without a
    // FIN-WAIT-2 timeout the connection would never go away.
    #[test]
    fn fin_wait_2_times_out_once_the_peer_goes_quiet() {
        let (mut client, mut server) = established(40320);
        let fin = client.release();
        let ack = deliver(&mut server, &fin);
        deliver(&mut client, &ack);
        assert_eq!(client.state(), State::FinWait2);

        // Not yet at half the timeout. (Data from the peer would reset it at
        // once: see released_connections_reset_on_data.)
        let half = client.cfg.fin_wait2_timeout.unwrap() / 2;
        client.last_recv = Instant::now() - half;
        client.released = Some(client.last_recv);
        assert!(client.tick().is_empty());

        client.last_recv = Instant::now() - client.cfg.fin_wait2_timeout.unwrap();
        client.released = Some(client.last_recv);
        let rst = client.tick();
        assert!(client.is_closed());
        assert!(parse(&rst[0]).has_flag(flags::RST));
    }

    // A half-close (shutdown(SHUT_WR)) leaves the application reading, so
    // however long the peer takes, the timeout is not for it: Linux applies
    // tcp_fin_timeout to orphaned sockets only.
    #[test]
    fn fin_wait_2_timeout_spares_a_half_close() {
        let (mut client, mut server) = established(40322);
        let fin = client.close();
        let ack = deliver(&mut server, &fin);
        deliver(&mut client, &ack);
        assert_eq!(client.state(), State::FinWait2);
        client.last_recv = Instant::now() - client.cfg.fin_wait2_timeout.unwrap();
        assert!(client.tick().is_empty());
        assert_eq!(client.state(), State::FinWait2);

        // Once the application lets go, the timeout applies, but it counts
        // from the release, as Linux's tcp_fin_timeout counts from close():
        // the peer's quiet spell before then was allowed.
        assert!(client.release().is_empty(), "the FIN is already out");
        assert!(client.tick().is_empty(), "reset at release");
        assert_eq!(client.state(), State::FinWait2);
        client.released = client
            .released
            .map(|_| Instant::now() - client.cfg.fin_wait2_timeout.unwrap());
        assert!(parse(&client.tick()[0]).has_flag(flags::RST));
        assert!(client.is_closed());
    }

    // A peer still sending ACKs is not gone: the timeout counts from the
    // later of the release and the last segment received.
    #[test]
    fn fin_wait_2_timeout_counts_from_the_last_segment() {
        let (mut client, mut server) = established(40323);
        let fin = client.release();
        let ack = deliver(&mut server, &fin);
        deliver(&mut client, &ack);
        assert_eq!(client.state(), State::FinWait2);
        let timeout = client.cfg.fin_wait2_timeout.unwrap();
        client.released = Some(Instant::now() - timeout);
        client.last_recv = Instant::now() - timeout / 2;
        assert!(client.tick().is_empty());
        client.last_recv = Instant::now() - timeout;
        assert!(parse(&client.tick()[0]).has_flag(flags::RST));
    }

    #[test]
    fn fin_wait_2_timeout_can_be_disabled() {
        let mut client = Conn::new(cfg(40321, 80).fin_wait2_timeout(None));
        let mut server = Conn::new(cfg(80, 40321));
        drive_handshake(&mut client, &mut server);
        let fin = client.release();
        let ack = deliver(&mut server, &fin);
        deliver(&mut client, &ack);
        client.last_recv = Instant::now() - Duration::from_secs(3600);
        client.tick();
        assert_eq!(client.state(), State::FinWait2);
    }

    // RFC 9293 §3.10.7.2-3: text in a SYN is queued until the connection is
    // established; until the handshake's ACK arrives it may be from a
    // spoofed source.
    #[test]
    fn syn_payload_waits_for_establishment() {
        let mut client = Conn::new(cfg(40330, 80));
        let mut server = Conn::new(cfg(80, 40330));
        let mut syn = parse(&client.connect()[0]);
        syn.payload = b"early".to_vec();
        let synack = server.accept_syn(&syn);
        assert_eq!(read_all(&mut server), b"");
        let ack = deliver(&mut client, &synack);
        deliver(&mut server, &ack);
        assert_eq!(server.state(), State::Established);
        assert_eq!(read_all(&mut server), b"early");
    }

    #[test]
    fn simultaneous_open_syn_payload_waits_for_establishment() {
        let mut a = Conn::new(cfg(40331, 80));
        let mut b = Conn::new(cfg(80, 40331));
        let a_syn = a.connect();
        let mut b_syn = parse(&b.connect()[0]);
        b_syn.payload = b"early".to_vec();
        let a_synack = a.handle_segment(&b_syn);
        assert_eq!(a.state(), State::SynReceived);
        assert_eq!(read_all(&mut a), b"");
        let b_synack = deliver(&mut b, &a_syn);
        deliver(&mut a, &b_synack);
        deliver(&mut b, &a_synack);
        assert_eq!(a.state(), State::Established);
        assert_eq!(read_all(&mut a), b"early");
    }

    // RFC 5961 §4: a blind SYN during a connect puts us in SYN-RECEIVED on
    // the attacker's sequence space, but the real SYN-ACK, whose SEQ is not
    // that IRS, must not complete the handshake there: it draws a challenge
    // ACK instead, and the attacker's data never gets in.
    #[test]
    fn blind_syn_during_connect_does_not_set_the_irs() {
        const EVIL: u32 = 0x4141_0000;
        let mut client = Conn::new(cfg(40332, 80));
        let mut server = Conn::new(cfg(80, 40332));
        let syn = client.connect();
        let evil = Segment {
            src_port: 80,
            dst_port: 40332,
            seq: EVIL,
            flags: flags::SYN,
            window: 4096,
            ..Default::default()
        };
        client.handle_segment(&evil);
        assert_eq!(client.state(), State::SynReceived);

        let synack = server.accept_syn(&parse(&syn[0]));
        let out = deliver(&mut client, &synack);
        assert_ne!(client.state(), State::Established);
        let challenge = parse(&out[0]);
        assert_eq!(challenge.flags, flags::ACK);

        let iss = client.send_buf.as_ref().unwrap().una();
        // Blind, the attacker cannot know SND.NXT; this ACK, a little
        // behind it, would do once the handshake were done.
        client.handle_segment(&Segment {
            seq: EVIL.wrapping_add(1),
            ack: iss,
            flags: flags::ACK | flags::PSH,
            payload: b"EVIL".to_vec(),
            ..evil.clone()
        });
        assert_eq!(read_all(&mut client), b"");

        // A SYN-ACK restating the IRS is the one a simultaneous open
        // expects, and still completes it.
        client.handle_segment(&Segment {
            seq: EVIL,
            ack: iss.wrapping_add(1),
            flags: flags::SYN | flags::ACK,
            ..evil
        });
        assert_eq!(client.state(), State::Established);
    }

    // A connection accepted from a SYN cookie still takes a reordered
    // segment whose ACK is a little behind SND.UNA.
    #[test]
    fn cookie_connection_accepts_slightly_old_ack() {
        let mut c = Conn::new(cfg(80, 40350));
        c.accept_cookie(&cookie_ack(), 5000, 1460);
        let una = c.send_buf.as_ref().unwrap().una();
        let seg = Segment {
            src_port: 40350,
            dst_port: 80,
            seq: 1001,
            ack: una.wrapping_sub(10),
            flags: flags::ACK,
            window: 4096,
            payload: b"hi".to_vec(),
            ..Default::default()
        };
        c.handle_segment(&seg);
        assert_eq!(read_all(&mut c), b"hi");
    }

    fn v6_pair(port: u16) -> (Conn, Conn) {
        let cfg = |local: u16, remote: u16| {
            let mut c = big(local, remote);
            c.mss = 1440;
            c.send_buf_size = 1 << 20;
            c.recv_buf_size = 1 << 20;
            let ip = |port: u16| if port == 80 { "fd00::1" } else { "fd00::2" };
            c.local_addr = Some(format!("[{}]:{local}", ip(local)).parse().unwrap());
            c.remote_addr = Some(format!("[{}]:{remote}", ip(remote)).parse().unwrap());
            c
        };
        let mut client = Conn::new(cfg(port, 80));
        let mut server = Conn::new(cfg(80, port));
        drive_handshake(&mut client, &mut server);
        (client, server)
    }

    /// Wire bytes of a segment as sent over IPv6.
    fn v6_len(p: &[u8]) -> u32 {
        40 + p.len() as u32
    }

    // RFC 8201: a Packet Too Big lowers the MSS to what fits the reported
    // MTU, and what was in flight at the old size goes again, cut to fit,
    // without costing the window.
    #[test]
    fn packet_too_big_resends_the_flight_at_the_new_size() {
        let (mut client, mut server) = v6_pair(40402);
        assert_eq!((client.mss(), client.path_mtu()), (1440, 1500));
        let (_, flight) = client.write(&[7; 5000]);
        assert!(flight.iter().all(|p| v6_len(p) == 1500));
        let cwnd = client.cc.cwnd();
        let rto = client.rto_deadline;

        let first = parse(&flight[0]);
        // A forged message quoting a SEQ we never sent is ignored.
        assert!(
            client
                .on_icmp_too_big(1400, first.seq.wrapping_sub(1))
                .is_empty()
        );
        // So is one quoting SND.NXT, where nothing we sent starts.
        let nxt = client.send_buf.as_ref().unwrap().nxt();
        assert!(client.on_icmp_too_big(1400, nxt).is_empty());
        assert_eq!(client.mss(), 1440);
        let resent = client.on_icmp_too_big(1400, first.seq);
        assert_eq!((client.mss(), client.path_mtu()), (1340, 1400));
        assert_eq!(client.cc.cwnd(), cwnd, "cwnd cut for a MTU drop");
        assert!(!resent.is_empty());
        assert!(resent.iter().all(|p| v6_len(p) <= 1400), "still too big");
        assert_eq!(parse(&resent[0]).seq, first.seq, "not from SND.UNA");
        assert_eq!(client.rto_deadline.is_some(), rto.is_some());

        // Over a 1400-byte path everything arrives.
        let mut to_server = resent;
        let mut got = Vec::new();
        for _ in 0..50 {
            let fits: Vec<_> = to_server.drain(..).filter(|p| v6_len(p) <= 1400).collect();
            let acks = deliver(&mut server, &fits);
            got.extend(read_all(&mut server));
            let mut acks = acks;
            acks.extend(server.take_outgoing());
            to_server = deliver(&mut client, &acks);
            if got.len() == 5000 {
                break;
            }
        }
        assert_eq!(got, [7; 5000]);
    }

    // The path MTU goes only down, and not below the family's floor; an
    // IPv4 message without an MTU steps down RFC 1191's plateaus.
    #[test]
    fn path_mtu_floors_and_plateaus() {
        let (mut v6, _) = v6_pair(40403);
        v6.set_path_mtu(1000);
        assert_eq!(v6.path_mtu(), 1280, "below IPv6's minimum MTU");
        v6.set_path_mtu(1400);
        assert_eq!(v6.path_mtu(), 1280, "went back up");

        let (mut v4, _) = established(40404);
        assert_eq!(v4.path_mtu(), 1500);
        v4.set_path_mtu(0);
        assert_eq!(v4.path_mtu(), 1492);
        v4.set_path_mtu(0);
        assert_eq!(v4.path_mtu(), 1006);
        v4.set_path_mtu(0);
        assert_eq!(v4.path_mtu(), IPV4_MIN_PATH_MTU);
        v4.set_path_mtu(100);
        assert_eq!(v4.path_mtu(), IPV4_MIN_PATH_MTU);

        // Learned before the handshake, it caps what the peer's MSS allows.
        let mut client = Conn::new(cfg(40405, 80));
        let mut server = Conn::new(cfg(80, 40405));
        let syn = client.connect();
        client.set_path_mtu(1200);
        let synack = server.accept_syn(&parse(&syn[0]));
        client.handle_segment(&parse(&synack[0]));
        assert_eq!(client.mss(), 1160);
    }

    // A cookie connection put back in SYN-RECEIVED resends the cookie's
    // SYN-ACK, and a later segment of the peer's completes it.
    #[test]
    fn cookie_connection_can_wait_in_syn_received() {
        let mut c = Conn::new(cfg(80, 40290));
        c.accept_cookie_syn_received(&cookie_ack(), 5000, 1400);
        assert_eq!(c.state(), State::SynReceived);
        assert!(c.take_outgoing().is_empty(), "sent before the RTO");
        let synack = parse(&fire_rto(&mut c)[0]);
        assert_eq!(synack.flags, flags::SYN | flags::ACK);
        assert_eq!((synack.seq, synack.ack), (5000, 1001));
        let seg = Segment {
            seq: 1003,
            payload: b"cd".to_vec(),
            ..cookie_ack()
        };
        c.handle_segment(&seg);
        assert_eq!(c.state(), State::Established);
        assert_eq!(c.mss, 1400);
        c.handle_segment(&Segment {
            payload: b"ab".to_vec(),
            ..cookie_ack()
        });
        assert_eq!(read_all(&mut c), b"abcd");
    }

    // RFC 6528: a new connection on the same 4-tuple starts just past the
    // last one in sequence space, and only the clock moved in between.
    #[test]
    fn isn_follows_rfc6528_clock() {
        let iss = |_| {
            let mut c = Conn::new(cfg(40260, 80));
            c.connect();
            c.send_buf.as_ref().unwrap().una()
        };
        let (first, second) = (iss(0), iss(1));
        assert!(second.wrapping_sub(first) < 1 << 20, "{first} {second}");
    }

    /// Every 4th segment of a large flight lost, and every ACK for the
    /// rest, so the RTO fires. Go-back-N then resends segments the
    /// receiver already holds, and their duplicate ACKs arrive once the
    /// cumulative ACK has reached `recover`. Returns whether fast recovery
    /// started after the timeout, and how many retransmissions were of
    /// data the receiver already had.
    fn post_rto_run(sack: bool, port: u16) -> (bool, usize) {
        let conf = |l, r| {
            big(l, r)
                .send_buf_size(1 << 20)
                .recv_buf_size(1 << 20)
                .enable_sack(sack)
        };
        let mut client = Conn::new(conf(port, 80));
        let mut server = Conn::new(conf(80, port));
        drive_handshake(&mut client, &mut server);
        let (_, mut out) = client.write(&vec![1u8; 1 << 20]);
        for _ in 0..3 {
            let acks = deliver(&mut server, &out);
            read_all(&mut server);
            out = deliver(&mut client, &acks);
        }
        assert!(out.len() >= 40);
        let arrived: Vec<Vec<u8>> = out
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 4 != 0)
            .map(|(_, p)| p.clone())
            .collect();
        let _lost_acks = deliver(&mut server, &arrived);
        let recover = client.send_buf.as_ref().unwrap().nxt();
        let mut out = fire_rto(&mut client);
        let (mut fast_recovery, mut spurious) = (false, 0);
        for _ in 0..40 {
            let mut acks = Vec::new();
            for p in &out {
                let s = parse(p);
                let rcv_nxt = server.recv_buf.as_ref().unwrap().nxt();
                let end = s.seq.wrapping_add(s.payload.len() as u32);
                if !s.payload.is_empty() && seq_before_eq(end, rcv_nxt) {
                    spurious += 1;
                }
                acks.extend(server.handle_segment(&s));
            }
            read_all(&mut server);
            acks.extend(server.take_outgoing());
            out = Vec::new();
            for a in &acks {
                out.extend(client.handle_segment(&parse(a)));
                fast_recovery |= client.in_recovery();
            }
            let una = client.send_buf.as_ref().unwrap().una();
            if seq_after(una, recover.wrapping_add(200_000)) {
                break;
            }
        }
        (fast_recovery, spurious)
    }

    #[test]
    fn go_back_n_duplicates_do_not_start_fast_recovery() {
        for (sack, port) in [(false, 40290), (true, 40291)] {
            let (fast_recovery, spurious) = post_rto_run(sack, port);
            assert!(
                !fast_recovery,
                "sack {sack}: fast recovery after the RTO, {spurious} needless resends"
            );
        }
    }

    #[test]
    fn partial_ack_retransmits_next_hole() {
        partial_ack_run(false);
    }

    #[test]
    fn sack_recovery_resends_every_lost_hole_in_one_round_trip() {
        partial_ack_run(true);
    }

    // VTCP_SEED=n replays one failing seed; VTCP_FUZZ_SEEDS=n widens the
    // sweep (worth running in release mode).
    #[test]
    fn lossy_link_delivers_everything_before_close() {
        let env = |k| {
            std::env::var(k)
                .ok()
                .map(|v: String| v.parse::<u64>().unwrap())
        };
        let seeds = match env("VTCP_SEED") {
            Some(s) => s..s + 1,
            None => 0..env("VTCP_FUZZ_SEEDS").unwrap_or(500),
        };
        for seed in seeds {
            lossy_run(seed);
        }
    }

    const CONTROLLERS: [CongestionKind; 4] = [
        CongestionKind::Cubic,
        CongestionKind::NewReno,
        CongestionKind::HighSpeed,
        CongestionKind::Bbr,
    ];

    /// What a [`stress_run`] varies per seed.
    #[derive(Debug)]
    struct StressCfg {
        buf: usize,
        mss: u16,
        ts: [bool; 2],
        sack: [bool; 2],
        wscale: [bool; 2],
        loss_pct: u64,
        blackout: bool,
        autotune: [bool; 2],
        congestion: [CongestionKind; 2],
        ss_after_idle: [bool; 2],
        pacing: [bool; 2],
        ecn: [EcnMode; 2],
        /// What the link does to ECN: see [`ecn_hop`].
        ecn_path: u64,
        /// Each end's PLPMTUD.
        mtu_probing: [MtuProbing; 2],
        /// Each direction's black hole, zero for none: packets larger than
        /// this vanish without an ICMP message. Only where the sender
        /// searches for the path MTU: without, a black hole is the end of
        /// the connection.
        black_hole: [u32; 2],
        /// TCP Fast Open, on both ends: 0 off; the client's SYN asks for a
        /// cookie (1), brings a valid one and data (2), or a stale one (3).
        fast_open: u64,
    }

    impl StressCfg {
        fn new(seed: u64) -> Self {
            let mut r = Rng(splitmix(seed ^ 0xABCDEF) | 1);
            let pair = |r: &mut Rng| [r.below(2) == 0, r.below(2) == 0];
            let (ts, sack, wscale) = (pair(&mut r), pair(&mut r), pair(&mut r));
            // In this order, so each seed keeps what it drew before
            // `autotune` was added.
            let buf = [4096, 65536, 1 << 18, 1 << 20][r.below(4) as usize];
            let mss = [536, 1000, 1460][r.below(3) as usize];
            let loss_pct = [0, 2, 10, 30][r.below(4) as usize];
            let blackout = r.below(2) == 0;
            Self {
                buf,
                mss,
                ts,
                sack,
                wscale,
                loss_pct,
                blackout,
                autotune: pair(&mut r),
                congestion: [
                    CONTROLLERS[r.below(4) as usize],
                    CONTROLLERS[r.below(4) as usize],
                ],
                ss_after_idle: pair(&mut r),
                pacing: pair(&mut r),
                // Drawn apart, so each seed keeps the run it had before.
                ecn: {
                    let mut e = Rng(splitmix(seed ^ 0xEC) | 1);
                    let modes = [
                        EcnMode::Off,
                        EcnMode::Passive,
                        EcnMode::Classic,
                        EcnMode::Accurate,
                    ];
                    [modes[e.below(4) as usize], modes[e.below(4) as usize]]
                },
                ecn_path: Rng(splitmix(seed ^ 0xECE) | 1).below(6),
                mtu_probing: [MtuProbing::Off; 2],
                black_hole: [0; 2],
                fast_open: Rng(splitmix(seed ^ 0xF0) | 1).below(8).saturating_sub(4),
            }
            .with_black_holes(seed)
        }

        fn with_black_holes(mut self, seed: u64) -> Self {
            let mut m = Rng(splitmix(seed ^ 0x3D1) | 1);
            let modes = [MtuProbing::Off, MtuProbing::OnBlackHole, MtuProbing::Always];
            for i in 0..2 {
                self.mtu_probing[i] = modes[m.below(3) as usize];
                // Between the smallest MTU a black hole can take the
                // connection to and the largest segment it sends.
                let widest = u64::from(self.mss) + 40;
                let floor = u64::from(IPV4_MIN_PATH_MTU);
                if self.mtu_probing[i] != MtuProbing::Off && m.below(3) == 0 {
                    self.black_hole[i] = (floor + m.below(widest - floor + 1)) as u32;
                }
            }
            self
        }
    }

    /// A packet crossing a link that, by `path`: leaves ECN be (0); marks
    /// ECN-capable packets CE, now and then (1) or half the time (2);
    /// clears every IP mark (3); clears the TCP ECN flags, as a middlebox
    /// may (4); or sets codepoints at random, Not-ECT ones included (5).
    /// None of it may cost a byte: ECN only ever changes how fast data is
    /// sent.
    fn ecn_hop(path: u64, rng: &mut Rng, pkt: Vec<u8>, ecn: IpEcn) -> (Vec<u8>, IpEcn) {
        let ect = matches!(ecn, IpEcn::ECT0 | IpEcn::ECT1);
        match path {
            1 if ect && rng.below(10) == 0 => (pkt, IpEcn::CE),
            2 if ect && rng.below(2) == 0 => (pkt, IpEcn::CE),
            3 => (pkt, IpEcn::NOT_ECT),
            4 => {
                let mut seg = parse(&pkt);
                seg.ae = false;
                seg.flags &= !(flags::ECE | flags::CWR);
                (seg.marshal(), ecn)
            }
            5 => (pkt, IpEcn(rng.below(4) as u8)),
            _ => (pkt, ecn),
        }
    }

    fn splitmix(mut z: u64) -> u64 {
        z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Loss-recovery bookkeeping that must hold after every event.
    fn check_invariants(c: &Conn, ctx: &dyn Fn() -> String) {
        let Some(sb) = c.send_buf.as_ref() else {
            return;
        };
        if !c.state.is_synchronized() {
            return;
        }
        let (una, nxt) = (sb.una(), sb.nxt());
        assert!(seq_before_eq(una, nxt), "{}: SND.UNA past SND.NXT", ctx());
        if !c.closed && c.state != State::TimeWait {
            c.score.check();
            assert_eq!(c.score.end_seq(), nxt, "{}: scoreboard end", ctx());
            assert!(
                c.score.is_empty() || c.score.head(u32::MAX).unwrap().0 == una,
                "{}: scoreboard start",
                ctx()
            );
            assert!(
                c.in_flight() as usize <= sb.unacked(),
                "{}: in_flight {} > unacked {}",
                ctx(),
                c.in_flight(),
                sb.unacked()
            );
            assert!(
                c.ca != CaState::Open || c.score.lost_bytes() == 0,
                "{}: losses left unrepaired",
                ctx()
            );
            if c.ca != CaState::Open {
                assert!(
                    seq_before_eq(c.recover, nxt),
                    "{}: recover past SND.NXT",
                    ctx()
                );
            }
            // Something always stands ready to act on what is out.
            assert!(
                sb.unacked() == 0 || c.rto_deadline.is_some() || c.persist_deadline.is_some(),
                "{}: data out and no timer",
                ctx()
            );
        }
        if let Some(rb) = c.recv_buf.as_ref()
            && !c.closed
        {
            // Whatever came in is ACKed, or its delayed ACK is on the way:
            // nothing waits on an ACK that will never be sent.
            assert!(
                c.last_ack_sent == Some(rb.nxt()) || c.delack_deadline.is_some(),
                "{}: data received and no ACK owed",
                ctx()
            );
        }
        if let Some(rb) = c.recv_buf.as_ref() {
            let grown = (sb.capacity() - c.cfg.send_buf_size) + (rb.limit() - c.cfg.recv_buf_size);
            assert_eq!(grown, c.grown, "{}: growth not accounted", ctx());
            assert!(
                sb.capacity() <= c.cfg.send_max(),
                "{}: send buffer past max",
                ctx()
            );
            assert!(
                rb.limit() <= c.cfg.recv_max(),
                "{}: recv buffer past max",
                ctx()
            );
        }
    }

    /// A harsher [`lossy_run`]: buffers up to a megabyte (so window
    /// scaling), each side choosing SACK, timestamps and window scaling on
    /// its own, loss rates up to 30%, blackouts that drop everything for a
    /// while, and timers that fire while segments are still in flight.
    /// Every byte must arrive, in order, and both ends must close.
    fn stress_run(seed: u64) {
        let sc = StressCfg::new(seed);
        let mut rng = Rng(splitmix(seed) | 1);
        let mk = |local, remote, i: usize| {
            // Fast Open's cookie goes by the addresses.
            let c = if sc.fast_open > 0 {
                tfo_cfg(local, remote)
            } else {
                cfg(local, remote)
            };
            c.enable_timestamps(sc.ts[i])
                .enable_sack(sc.sack[i])
                .mss(sc.mss)
                .no_window_scaling(!sc.wscale[i])
                .send_buf_size(sc.buf)
                .recv_buf_size(sc.buf)
                .autotune(sc.autotune[i])
                .congestion(sc.congestion[i])
                .slow_start_after_idle(sc.ss_after_idle[i])
                .pacing(sc.pacing[i])
                .send_buf_max(sc.buf * 4)
                .recv_buf_max(sc.buf * 4)
                .ecn(sc.ecn[i])
                .mtu_probing(sc.mtu_probing[i])
        };
        let mut ecn_rng = Rng(splitmix(seed ^ 0xEC0) | 1);
        let a = Conn::new(mk(40300, 80, 0));
        let b = Conn::new(mk(80, 40300, 1));
        let max_len = (sc.buf as u64 * 2).min(400_000);
        let mut sides = [a, b].map(|conn| {
            let len = rng.below(max_len) as usize;
            Side {
                conn,
                to_send: (0..len).map(|_| rng.next() as u8).collect(),
                written: 0,
                received: Vec::new(),
                close_called: false,
            }
        });
        let syn = match sc.fast_open {
            0 => sides[0].conn.connect(),
            k => {
                let valid = fastopen::cookie([10, 0, 0, 1].into(), [10, 0, 0, 2].into());
                let cookie = [None, Some(&valid[..]), Some(&[0xAA; 8][..])][k as usize - 1];
                let s = &mut sides[0];
                let (n, syn) = s.conn.connect_fast_open(cookie, None, &s.to_send);
                s.written = n;
                syn
            }
        };
        let syn = marked(&sides[0].conn, syn);
        // Segments with their IP-ECN codepoints.
        let mut links: [Vec<(Vec<u8>, IpEcn)>; 2] = [syn, Vec::new()];
        let done = |s: &[Side; 2]| {
            s.iter().all(|x| {
                x.close_called
                    && x.conn.fin_received()
                    && matches!(x.conn.state(), State::TimeWait | State::Closed)
            })
        };
        let mut blackout = [0u32; 2];
        // Each direction's path MTU, which now and then narrows: what no
        // longer fits is dropped, and its sender told (always: a lost
        // Packet Too Big is a black hole no TCP gets out of).
        let mut path_mtu = [u32::MAX; 2];
        let mut step = 0;
        while !done(&sides) {
            step += 1;
            assert!(
                step < 3_000_000,
                "seed {seed} {sc:?}: stuck: {:?} / {:?} (written {}/{} {}/{}, received {} {})",
                sides[0].conn,
                sides[1].conn,
                sides[0].written,
                sides[0].to_send.len(),
                sides[1].written,
                sides[1].to_send.len(),
                sides[0].received.len(),
                sides[1].received.len(),
            );
            let ctx = || format!("seed {seed} step {step}");
            let i = rng.below(2) as usize;
            match rng.below(12) {
                0..=1 => {
                    let s = &mut sides[i];
                    if s.written < s.to_send.len() {
                        let end = (s.written + 1 + rng.below(20_000) as usize).min(s.to_send.len());
                        let (n, out) = s.conn.write(&s.to_send[s.written..end]);
                        s.written += n;
                        links[i].extend(marked(&s.conn, out));
                    } else if !s.close_called
                        && !matches!(s.conn.state(), State::Closed | State::SynSent)
                        && rng.below(4) == 0
                    {
                        s.close_called = true;
                        links[i].extend(sent_by(&mut s.conn, Conn::close));
                    }
                }
                2..=3 => {
                    let s = &mut sides[i];
                    let mut buf = vec![0u8; 1 + rng.below(30_000) as usize];
                    let n = s.conn.read(&mut buf);
                    s.received.extend_from_slice(&buf[..n]);
                    links[i].extend(sent_by(&mut s.conn, Conn::take_outgoing));
                }
                4..=10 => {
                    if links[i].is_empty() {
                        continue;
                    }
                    let k = if rng.below(8) == 0 {
                        rng.below(links[i].len().min(20) as u64) as usize
                    } else {
                        0
                    };
                    let (pkt, ecn) = links[i].remove(k);
                    if rng.below(20_000) == 0 {
                        let now = path_mtu[i].min(sc.mss as u32 + 40);
                        path_mtu[i] = IPV4_MIN_PATH_MTU + rng.below(now as u64) as u32 / 2;
                    }
                    if 20 + pkt.len() as u32 > path_mtu[i] {
                        let seg = parse(&pkt);
                        let c = &mut sides[i].conn;
                        links[i].extend(sent_by(c, |c| c.on_icmp_too_big(path_mtu[i], seg.seq)));
                        check_invariants(c, &ctx);
                        continue;
                    }
                    // Whether either end struggles or not: it is PLPMTUD's
                    // to get out of.
                    if sc.black_hole[i] > 0 && 20 + pkt.len() as u32 > sc.black_hole[i] {
                        continue;
                    }
                    // As in lossy_run, the link stops losing while either end
                    // is halfway to giving up, so giving up is the engine's
                    // fault, not the dice's.
                    let struggling = sides.iter().any(|s| s.conn.unanswered() >= MAX_RETRIES / 2);
                    if sc.blackout && !struggling && blackout[i] == 0 && rng.below(3000) == 0 {
                        blackout[i] = 1 + rng.below(200) as u32;
                    }
                    if blackout[i] > 0 {
                        blackout[i] -= 1;
                        if !struggling {
                            continue;
                        }
                    }
                    let fate = rng.below(100);
                    if fate < sc.loss_pct && !struggling {
                        continue;
                    }
                    if fate == 99 {
                        links[i].insert(0, (pkt.clone(), ecn));
                    }
                    let (pkt, ecn) = ecn_hop(sc.ecn_path, &mut ecn_rng, pkt, ecn);
                    let seg = parse(&pkt);
                    let peer = &mut sides[1 - i].conn;
                    let out = if peer.state() == State::Closed
                        && !peer.is_closed()
                        && seg.flags & (flags::SYN | flags::ACK) == flags::SYN
                    {
                        peer.accept_syn_ecn(&seg, ecn)
                    } else {
                        peer.handle_segment_ecn(&seg, ecn)
                    };
                    check_invariants(peer, &ctx);
                    links[1 - i].extend(marked(peer, out));
                }
                _ => {
                    // Time passes: usually once the links are quiet, but
                    // now and then with segments still in flight, which is
                    // how a timer beats an ACK on a real network.
                    let calm = sides.iter().all(|s| s.conn.unanswered() < 2);
                    let busy = !links[0].is_empty() || !links[1].is_empty();
                    if busy && (rng.below(8) != 0 || !calm) {
                        continue;
                    }
                    // The clock does not really move, so neither would the
                    // challenge-ACK throttle's; a timer firing stands for
                    // more time than its interval, on both ends.
                    for s in sides.iter_mut() {
                        s.conn.last_oow_ack = None;
                    }
                    advance(Duration::from_micros(rng.below(20_000)));
                    let c = &mut sides[i].conn;
                    let now = test_now();
                    for d in [
                        &mut c.rto_deadline,
                        &mut c.persist_deadline,
                        &mut c.reo_deadline,
                        &mut c.pto_deadline,
                        &mut c.delack_deadline,
                        &mut c.pace_deadline,
                    ] {
                        if d.is_some() {
                            *d = Some(now);
                        }
                    }
                    links[i].extend(sent_by(c, Conn::tick));
                    check_invariants(c, &ctx);
                }
            }
        }
        for s in &mut sides {
            s.received.extend(read_all(&mut s.conn));
        }
        assert!(
            sides[1].received == sides[0].to_send,
            "seed {seed} {sc:?}: a to b stream corrupted"
        );
        assert!(
            sides[0].received == sides[1].to_send,
            "seed {seed} {sc:?}: b to a stream corrupted"
        );
    }

    // VTCP_SEED=n replays one seed, VTCP_FUZZ_SEEDS=n widens the sweep, as
    // for lossy_link_delivers_everything_before_close; each seed here costs
    // far more, so the default sweep is smaller.
    #[test]
    fn stressed_link_delivers_everything_before_close() {
        let env = |k| {
            std::env::var(k)
                .ok()
                .map(|v: String| v.parse::<u64>().unwrap())
        };
        let seeds = match env("VTCP_SEED") {
            Some(s) => s..s + 1,
            None => 0..env("VTCP_FUZZ_SEEDS").unwrap_or(200),
        };
        for seed in seeds {
            stress_run(seed);
        }
    }

    // --- Buffer auto-tuning ------------------------------------------------

    /// A budget of its own, so that a test neither starves nor is starved
    /// by the others running at the same time.
    fn own_budget(cap: usize) -> &'static Budget {
        Box::leak(Box::new(Budget::new(cap)))
    }

    fn tuned(local: u16, remote: u16) -> ConnConfig {
        big(local, remote)
            .autotune(true)
            .send_buf_max(1 << 20)
            .recv_buf_max(1 << 20)
    }

    fn tuned_pair(port: u16, conf: impl Fn(u16, u16) -> ConnConfig, budget: usize) -> (Conn, Conn) {
        let mut client = Conn::new(conf(port, 80));
        let mut server = Conn::new(conf(80, port));
        let budget = own_budget(budget);
        client.budget = budget;
        server.budget = budget;
        drive_handshake(&mut client, &mut server);
        // The handshake timed a round trip of next to nothing, which would
        // pace the receiver's measurements; these tests stand for their
        // round trips with RcvSpace::backdate instead.
        server.rto = RtoState::new(test_now());
        (client, server)
    }

    /// Stream from `tx` to `rx` for `rounds` round trips, `tx` writing
    /// `chunk` bytes each time and `rx` reading everything as if a round
    /// trip had passed. Returns `rx`'s last ACKs.
    fn tuned_rounds(tx: &mut Conn, rx: &mut Conn, chunk: usize, rounds: usize) -> Vec<Vec<u8>> {
        let chunk = vec![7u8; chunk];
        let (_, mut out) = tx.write(&chunk);
        let mut acks = Vec::new();
        for _ in 0..rounds {
            acks = deliver(rx, &out);
            rx.rcv_space.backdate(Duration::from_secs(1));
            read_all(rx);
            acks.extend(rx.take_outgoing());
            out = deliver(tx, &acks);
            out.extend(tx.write(&chunk).1);
        }
        acks
    }

    /// The receive buffer grows to what the application reads per round
    /// trip calls for, and the window advertised follows it past the
    /// initial size, but not past the maximum.
    #[test]
    fn receive_buffer_grows_with_what_is_read() {
        let (mut client, mut server) = tuned_pair(40500, tuned, usize::MAX);
        let acks = tuned_rounds(&mut client, &mut server, 1 << 18, 12);
        let limit = server.recv_buf.as_ref().unwrap().limit();
        assert!(limit > 1 << 16, "not grown: {limit}");
        assert_eq!(limit, 1 << 20, "not grown to the maximum");
        let wnd = (parse(acks.last().unwrap()).window as usize) << server.rcv_wnd_shift;
        assert!(
            wnd > 1 << 16,
            "window not advertised past the initial size: {wnd}"
        );
        assert_eq!(
            server.grown,
            limit - (1 << 16) + (server.send_buf.as_ref().unwrap().capacity() - (1 << 16))
        );

        // Without auto-tuning, it stays put.
        let fixed = |l, r| tuned(l, r).autotune(false);
        let (mut client, mut server) = tuned_pair(40501, fixed, usize::MAX);
        tuned_rounds(&mut client, &mut server, 1 << 18, 12);
        assert_eq!(server.recv_buf.as_ref().unwrap().limit(), 1 << 16);
        assert_eq!(client.send_buf.as_ref().unwrap().capacity(), 1 << 16);
        assert_eq!((client.grown, server.grown), (0, 0));
    }

    /// An application that reads no faster than before gets no more.
    #[test]
    fn receive_buffer_stays_for_a_slow_reader() {
        let (mut client, mut server) = tuned_pair(40502, tuned, usize::MAX);
        tuned_rounds(&mut client, &mut server, 5000, 12);
        assert_eq!(server.recv_buf.as_ref().unwrap().limit(), 1 << 16);
    }

    /// The window scale is chosen for the largest buffer auto-tuning may
    /// reach, since it cannot change after the handshake, but no coarser
    /// than half the initial buffer.
    #[test]
    fn window_scale_is_chosen_from_the_maximum() {
        let wscale = |c: ConnConfig| {
            let syn = parse(&Conn::new(c).connect()[0]);
            get_wscale(&syn.options).unwrap()
        };
        let c = ConnConfig::default().local_port(40503).remote_port(80);
        // 16 MiB >> 8 is 65536, one past the largest window.
        assert_eq!(wscale(c.clone()), 9);
        assert_eq!(wscale(c.clone().recv_buf_max(1 << 20)), 5);
        assert_eq!(wscale(c.clone().autotune(false)), 5);
        // A maximum below the initial size is no maximum.
        assert_eq!(wscale(c.clone().recv_buf_max(1000)), 5);
        assert_eq!(wscale(c.clone().recv_buf_size(600)), 8);
        assert_eq!(wscale(c.clone().recv_buf_size(0)), 0);
        assert_eq!(wscale(c.recv_buf_max(1 << 30)), 14);
    }

    /// With a scale larger than the buffer calls for, a window smaller than
    /// a unit is rounded up, not advertised as closed, and what the peer
    /// sends into the rounded-up part is taken.
    #[test]
    fn scaled_window_smaller_than_a_unit_stays_open() {
        let conf = |l, r| cfg(l, r).autotune(true).recv_buf_max(16 << 20);
        let (mut client, mut server) = tuned_pair(40504, conf, usize::MAX);
        assert_eq!(server.rcv_wnd_shift, 9);
        let (_, mut pkts) = client.write(&[1; 3996]);
        let mut last_ack = None;
        while !pkts.is_empty() {
            let acks = deliver(&mut server, &pkts);
            last_ack = acks.last().cloned().or(last_ack);
            pkts = deliver(&mut client, &acks);
        }
        assert_eq!(
            parse(&last_ack.unwrap()).window,
            1,
            "100 bytes left, advertised as one unit"
        );
        let (_, pkts) = client.write(&[2; 500]);
        assert!(!pkts.is_empty());
        deliver(&mut server, &pkts);
        assert_eq!(server.recv_buf.as_ref().unwrap().readable(), 4496);
    }

    /// The send buffer grows with cwnd while the application keeps it full,
    /// and not for one that writes little.
    #[test]
    fn send_buffer_grows_with_the_congestion_window() {
        let (mut client, mut server) = tuned_pair(40505, tuned, usize::MAX);
        tuned_rounds(&mut client, &mut server, 1 << 18, 12);
        let cap = client.send_buf.as_ref().unwrap().capacity();
        assert!(cap > 1 << 16, "not grown: {cap}");
        assert!(cap <= 1 << 20);
        let cwnd = client.cc.cwnd() as usize;
        assert!(cap <= 2 * cwnd, "grown past twice cwnd: {cap} for {cwnd}");

        let (mut client, mut server) = tuned_pair(40506, tuned, usize::MAX);
        tuned_rounds(&mut client, &mut server, 1000, 30);
        assert_eq!(client.send_buf.as_ref().unwrap().capacity(), 1 << 16);
    }

    /// Growth stops where the budget runs out, without failing anything,
    /// and is given back when the connection frees its buffers or goes
    /// away.
    #[test]
    fn budget_bounds_growth_and_is_given_back() {
        let (mut client, mut server) = tuned_pair(40507, tuned, 100_000);
        let budget = client.budget;
        let acks = tuned_rounds(&mut client, &mut server, 1 << 18, 12);
        assert_eq!(budget.used(), 100_000);
        assert_eq!(client.grown + server.grown, 100_000);
        let total = |c: &Conn| {
            c.send_buf.as_ref().unwrap().capacity() + c.recv_buf.as_ref().unwrap().limit()
        };
        assert_eq!(total(&client) + total(&server), 4 * (1 << 16) + 100_000);
        // Still moving data.
        assert!(!acks.is_empty());
        assert!(read_all(&mut server).is_empty());

        // Closed: back to the initial sizes, and the budget freed.
        assert!(server.grown > 0);
        server.abort();
        assert_eq!(total(&server), 2 * (1 << 16));
        assert_eq!(server.grown, 0);
        assert_eq!(budget.used(), client.grown);

        // Dropped without closing.
        let (mut client, mut server) = tuned_pair(40508, tuned, 100_000);
        let budget = client.budget;
        tuned_rounds(&mut client, &mut server, 1 << 18, 12);
        assert!(server.grown > 0);
        drop(server);
        assert_eq!(budget.used(), client.grown);
    }

    /// next_deadline is the earliest timer tick() would act on, and
    /// nothing once none is running.
    #[test]
    fn next_deadline_is_the_earliest_timer() {
        let (mut client, mut server) = established(40600);
        assert_eq!(client.next_deadline(), None);
        let (_, data) = client.write(&[7; 100]);
        let rto = client.rto_deadline.expect("RTO armed");
        assert_eq!(client.next_deadline(), Some(rto));
        client.keepalive_deadline = Some(rto + Duration::from_secs(1));
        assert_eq!(client.next_deadline(), Some(rto));
        client.reo_deadline = Some(rto - Duration::from_millis(1));
        assert_eq!(client.next_deadline(), client.reo_deadline);
        client.reo_deadline = None;
        let acks = deliver(&mut server, &data);
        deliver(&mut client, &acks);
        assert_eq!(client.next_deadline(), client.keepalive_deadline);
        client.keepalive_deadline = None;
        assert_eq!(client.next_deadline(), None);
        // A closed connection's leftovers are not due: tick() ignores them.
        client.rto_deadline = Some(Instant::now());
        client.closed = true;
        assert_eq!(client.next_deadline(), None);
    }

    /// With timestamps, an ACK advancing SND.UNA is an RTT sample even
    /// when no segment is being timed (RFC 7323 §4.2); without, only the
    /// timed segment's ACK is (RFC 6298).
    #[test]
    fn timestamps_give_a_sample_per_ack() {
        for ts in [true, false] {
            let (mut client, mut server) = if ts {
                ts_pair(40610)
            } else {
                established(40611)
            };
            let (_, data) = client.write(&[1; 100]);
            client.rto = RtoState::new(test_now());
            let acks = deliver(&mut server, &data);
            deliver(&mut client, &acks);
            assert_eq!(client.rto.rto() < DEFAULT_RTO, ts, "timestamps {ts}");
        }
    }

    /// The echo's round trip counts what has passed of the current
    /// millisecond, so it is never shorter than the path, nor zero.
    #[test]
    fn timestamp_echo_rtt_rounds_up() {
        let (client, _) = ts_pair(40612);
        let seg = |ecr| Segment {
            options: vec![timestamp_option(1, ecr)],
            ..Default::default()
        };
        let now = client.ts_now();
        let rtt = client.ts_echo_rtt(&seg(now.wrapping_sub(30))).unwrap();
        assert!(rtt >= Duration::from_millis(30) && rtt < Duration::from_millis(32));
        assert_eq!(client.ts_echo_rtt(&seg(0)), None);
        // From the future, or older than the connection could be.
        assert_eq!(client.ts_echo_rtt(&seg(now.wrapping_add(5))), None);
    }

    // --- Delayed ACK --------------------------------------------------------

    /// A pair past the quick-ACK start of the connection, with `n`
    /// full-sized segments from the client ready to deliver.
    fn delack_pair(port: u16, n: usize) -> (Conn, Conn, Vec<Vec<u8>>) {
        let mut client = Conn::new(big(port, 80));
        let mut server = Conn::new(big(80, port));
        drive_handshake(&mut client, &mut server);
        // Warm up: the first data is quick-ACKed, and sets rcv_mss.
        let (_, first) = client.write(&[0; 1000]);
        deliver(&mut client, &deliver(&mut server, &first));
        read_all(&mut server);
        server.quick_acks = 0;
        let (_, segs) = client.write(&vec![1; 1000 * n]);
        assert_eq!(segs.len(), n);
        (client, server, segs)
    }

    fn acks_in(pkts: &[Vec<u8>]) -> Vec<u32> {
        pkts.iter().map(|p| parse(p).ack).collect()
    }

    /// At least every second full-sized segment is ACKed; the odd one out
    /// waits for the delayed-ACK timer, no longer than DELAYED_ACK.
    #[test]
    fn delayed_ack_every_second_full_segment() {
        let (_client, mut server, segs) = delack_pair(40620, 5);
        let mut acks = Vec::new();
        for (i, s) in segs.iter().enumerate() {
            let out = deliver(&mut server, std::slice::from_ref(s));
            assert_eq!(out.len(), i % 2, "segment {i}");
            acks.extend(out);
        }
        let end = |s: &Vec<u8>| {
            let s = parse(s);
            s.seq.wrapping_add(s.payload.len() as u32)
        };
        assert_eq!(acks_in(&acks), [end(&segs[1]), end(&segs[3])]);
        // The fifth is owed an ACK, on a timer.
        let due = server.delack_deadline.expect("delayed ACK pending");
        assert!(due <= Instant::now() + DELAYED_ACK);
        assert_eq!(server.next_deadline(), Some(due));
        assert!(server.tick().is_empty(), "not yet due");
        let late = delack_expired(&mut server);
        assert_eq!(acks_in(&late), [end(&segs[4])]);
        assert_eq!(server.delack_deadline, None);
    }

    /// Out of order: ACKed at once, and so is the segment filling the hole
    /// (RFC 5681 §4.2).
    #[test]
    fn out_of_order_and_hole_filling_segments_are_acked_at_once() {
        let (_client, mut server, segs) = delack_pair(40621, 3);
        let dup = deliver(&mut server, &segs[1..2]);
        assert_eq!(dup.len(), 1, "out of order");
        assert_eq!(acks_in(&dup), [parse(&segs[0]).seq]);
        let filled = deliver(&mut server, &segs[0..1]);
        assert_eq!(filled.len(), 1, "hole filled");
        assert_eq!(acks_in(&filled), [parse(&segs[2]).seq]);
        // A duplicate is answered at once too.
        assert_eq!(deliver(&mut server, &segs[0..1]).len(), 1, "duplicate");
    }

    /// The first segments of a connection are each ACKed at once, so
    /// slow start from the initial window is not held up by the timer.
    #[test]
    fn quick_acks_at_the_start() {
        let mut client = Conn::new(big(40622, 80));
        let mut server = Conn::new(big(80, 40622));
        drive_handshake(&mut client, &mut server);
        let (_, segs) = client.write(&[1; 10_000]);
        assert_eq!(segs.len(), 10);
        let acks = deliver(&mut server, &segs);
        assert_eq!(acks.len(), 10);
        deliver(&mut client, &acks);
        // An idle spell longer than the RTO brings them back.
        server.quick_acks = 0;
        server.last_data_recv = Some(Instant::now() - Duration::from_secs(2));
        let (_, segs) = client.write(&[2; 1000]);
        assert_eq!(deliver(&mut server, &segs).len(), 1);
    }

    /// Our own data carries the ACK: nothing is left pending, and no bare
    /// ACK follows.
    #[test]
    fn data_sent_carries_the_delayed_ack() {
        let (_client, mut server, segs) = delack_pair(40623, 1);
        assert!(deliver(&mut server, &segs).is_empty());
        assert!(server.delack_deadline.is_some());
        let (_, reply) = server.write(b"answer");
        assert_eq!(reply.len(), 1);
        assert_eq!(parse(&reply[0]).ack, parse(&segs[0]).seq.wrapping_add(1000));
        assert_eq!(server.delack_deadline, None);
        assert!(delack_expired(&mut server).is_empty());
        // Answered within the delay: a request/response exchange, whose
        // ACKs ride on the answers.
        assert!(server.pingpong);
    }

    /// A short segment's delayed ACK goes out once the application has
    /// read everything: the sender's Nagle may be holding its next write
    /// back for it.
    #[test]
    fn reading_everything_acks_a_short_segment() {
        let (mut client, mut server, _) = delack_pair(40624, 0);
        let (_, segs) = client.write(&[3; 100]);
        assert!(deliver(&mut server, &segs).is_empty());
        let (_, held) = client.write(&[4; 100]);
        assert!(held.is_empty(), "Nagle holds the second write");
        let mut buf = [0; 50];
        assert_eq!(server.read(&mut buf), 50);
        assert!(server.take_outgoing().is_empty(), "not all read yet");
        assert_eq!(server.read(&mut buf), 50);
        let ack = server.take_outgoing();
        assert_eq!(ack.len(), 1);
        assert_eq!(deliver(&mut client, &ack).len(), 1, "Nagle let go");
    }

    /// The last segment the window has room for is ACKed at once: the
    /// sender can send nothing more until it hears how the window stands.
    #[test]
    fn filling_the_window_is_acked_at_once() {
        let small = |l, r| big(l, r).recv_buf_size(3000);
        let mut client = Conn::new(small(40625, 80));
        let mut server = Conn::new(small(80, 40625));
        drive_handshake(&mut client, &mut server);
        server.quick_acks = 0;
        server.last_data_recv = Some(Instant::now());
        let (_, segs) = client.write(&[5; 3000]);
        let acks = deliver(&mut server, &segs);
        assert_eq!(parse(acks.last().unwrap()).window, 0);
        assert_eq!(server.delack_deadline, None);
    }

    /// Timestamps are offered by default, and used when the peer offers
    /// them too; one that does not gets none.
    #[test]
    fn timestamps_are_on_by_default() {
        assert!(ConnConfig::default().enable_timestamps);
        let conf = |l, r| ConnConfig::default().local_port(l).remote_port(r);
        let mut client = Conn::new(conf(40630, 80));
        let mut server = Conn::new(conf(80, 40630));
        drive_handshake(&mut client, &mut server);
        assert!(client.ts_ok && server.ts_ok);
        let (_, data) = client.write(b"x");
        assert!(get_timestamp(&parse(&data[0]).options).is_some());

        let mut client = Conn::new(conf(40631, 80));
        let mut server = Conn::new(conf(80, 40631).enable_timestamps(false));
        drive_handshake(&mut client, &mut server);
        assert!(!client.ts_ok && !server.ts_ok);
        let (_, data) = client.write(b"x");
        assert!(parse(&data[0]).options.is_empty());
    }

    /// A later connection between the same two hosts sends TSvals past an
    /// earlier one's, whatever the ports, so its SYN passes RFC 6191's test
    /// against the old one in TIME-WAIT.
    #[test]
    fn tsvals_run_on_across_connections() {
        let addr = |port| SocketAddr::from(([10, 0, 0, 1], port));
        let conf = |port| {
            ConnConfig::default()
                .local_addr(addr(port))
                .remote_addr(SocketAddr::from(([10, 0, 0, 2], 80)))
        };
        let old = Conn::new(conf(1000));
        std::thread::sleep(Duration::from_millis(2));
        for port in 1000..1016 {
            let new = Conn::new(conf(port));
            let ahead = new.ts_now().wrapping_sub(old.ts_now());
            assert!(
                ahead < 1 << 31,
                "port {port}: behind by {}",
                ahead.wrapping_neg()
            );
        }
    }

    // --- Pacing ---------------------------------------------------------------

    fn paced(local: u16, remote: u16) -> ConnConfig {
        big(local, remote).pacing(true)
    }

    /// Paced, a write the window would let out at once goes out a quantum
    /// at a time: first the burst allowance, then a quantum per timer.
    #[test]
    fn pacing_spaces_out_what_the_window_allows() {
        let rtt = Duration::from_millis(100);
        let (mut client, _server) = rtt_pair(paced, 40700, rtt);
        client.cc.set_cwnd(400 * 1000);
        let rate = client
            .pace_rate()
            .expect("pacing once a round trip is known");
        // 400 kB over 100 ms, twice over in slow start (cwnd under half of
        // ssthresh), 1.2 times after.
        assert!((7_700_000..=8_100_000).contains(&rate), "{rate}");
        client.cc.on_loss(800 * 1000);
        let rate = client.pace_rate().unwrap();
        assert!((4_600_000..=4_900_000).contains(&rate), "{rate}");
        let quantum = client.pace_quantum(rate);
        assert_eq!(quantum as u64, rate / 1000, "a millisecond's worth");

        // Idle long enough to have banked the whole allowance, two quanta,
        // but not for the window to decay.
        advance(Duration::from_millis(20));
        let (_, burst) = client.write(&vec![1; 60_000]);
        let sent: usize = burst.iter().map(|p| parse(p).payload.len()).sum();
        assert!(
            sent as f64 <= 2.0 * quantum + 1000.0 && sent as f64 >= 2.0 * quantum - 1000.0,
            "burst of {sent} for a quantum of {quantum}"
        );
        let due = client
            .pace_deadline
            .expect("the rest waits for the pacing timer");
        assert_eq!(client.next_deadline(), Some(due), "the earliest timer");
        assert!(client.tick().is_empty(), "not before it is due");

        // From here on a quantum per timer, spaced by a quantum's time.
        let mut last = test_now();
        for _ in 0..5 {
            let due = client.pace_deadline.expect("still pacing");
            let wait = due.saturating_duration_since(last);
            assert!(
                wait >= Duration::from_micros(900) && wait <= Duration::from_micros(1100),
                "{wait:?}"
            );
            advance(due.saturating_duration_since(test_now()));
            last = test_now();
            let out = client.tick();
            let sent: usize = out.iter().map(|p| parse(p).payload.len()).sum();
            assert!(
                (sent as f64 - quantum).abs() <= 1000.0,
                "{sent} sent for a quantum of {quantum}"
            );
        }
    }

    /// At a low rate the quantum is two segments, not a millisecond's
    /// worth of a fraction of one.
    #[test]
    fn pacing_quantum_is_at_least_two_segments() {
        let rtt = Duration::from_millis(400);
        let (mut client, _server) = rtt_pair(paced, 40701, rtt);
        let rate = client.pace_rate().unwrap();
        assert!(rate < 1_000_000);
        assert_eq!(client.pace_quantum(rate), 2000.0);
        advance(Duration::from_secs(1));
        let (_, burst) = client.write(&vec![1; 20_000]);
        assert_eq!(burst.len(), 4, "two quanta of two segments");
        let due = client.pace_deadline.unwrap();
        advance(due.saturating_duration_since(test_now()));
        // A quantum, and a segment more if the real clock moved meanwhile:
        // one that finds credit left goes, overdrawing it.
        let n = client.tick().len();
        assert!((2..=3).contains(&n), "then a quantum: {n}");
    }

    /// Before any round trip is known there is nothing to pace by; off,
    /// nothing is paced; and a paced sender keeps its slow start whole: a
    /// full window goes out over the round trip, not a burst.
    #[test]
    fn pacing_waits_for_a_round_trip_and_can_be_off() {
        let mut c = Conn::new(paced(40702, 80));
        assert_eq!(c.pace_rate(), None);
        let rtt = Duration::from_millis(50);
        let (mut client, _server) = rtt_pair(big, 40703, rtt);
        assert!(!client.cfg.pacing);
        assert_eq!(client.pace_rate(), None);
        let (_, all) = client.write(&vec![1; 10_000]);
        assert_eq!(all.len(), 10, "the whole initial window at once");
        assert_eq!(client.pace_deadline, None);
        c.abort();
    }

    /// A round trip far under the timestamp clock's millisecond: pacing
    /// goes by the send-to-ACK time, not by an SRTT of echoes rounded up
    /// to the millisecond, which would pace at a fraction of the path.
    #[test]
    fn pacing_goes_by_a_precise_round_trip() {
        let conf = |l, r| paced(l, r).enable_timestamps(true);
        let rtt = Duration::from_micros(200);
        let (mut client, mut server) = rtt_pair(conf, 40720, rtt);
        for _ in 0..20 {
            let (_, data) = client.write(&[1; 3000]);
            advance(rtt / 2);
            let acks = deliver(&mut server, &data);
            read_all(&mut server);
            let mut acks = acks;
            acks.extend(delack_expired(&mut server));
            advance(rtt / 2);
            deliver(&mut client, &acks);
        }
        let precise = client.pace_srtt.unwrap();
        assert!(precise < Duration::from_millis(1), "{precise:?}");
        // Whatever the RTO's SRTT has made of it.
        for _ in 0..50 {
            client.rto.sample_of(Duration::from_millis(5), 1);
        }
        let rate = client.pace_rate().unwrap() as f64;
        let want = f64::from(client.cc.cwnd()) / precise.as_secs_f64();
        assert!(rate >= 1.2 * want * 0.99, "{rate} for {want}");
    }

    /// The pacing timer serviced late: what it held back that long goes
    /// at once, rather than the rate losing what the timer lost.
    #[test]
    fn a_late_pacing_timer_is_made_up_for() {
        let rtt = Duration::from_millis(100);
        let (mut client, _server) = rtt_pair(paced, 40721, rtt);
        client.cc.set_cwnd(400 * 1000);
        client.cc.on_loss(800 * 1000);
        advance(Duration::from_millis(20));
        client.write(&vec![1; 60_000]);
        let rate = client.pace_rate().unwrap() as f64;
        let quantum = client.pace_quantum(rate as u64);
        let due = client.pace_deadline.unwrap();
        // Five milliseconds late.
        advance(due.saturating_duration_since(test_now()) + Duration::from_millis(5));
        let sent: usize = client.tick().iter().map(|p| parse(p).payload.len()).sum();
        let owed = quantum + rate * 0.005;
        assert!(
            (sent as f64 - owed).abs() <= 1500.0,
            "{sent} sent, {owed} owed"
        );
    }

    /// Paced, what is in flight when an ACK comes is short of cwnd even
    /// for a sender that keeps it full: the rest waits on the pacer. The
    /// controller is told cwnd was in use, so it grows.
    #[test]
    fn a_paced_sender_counts_as_using_its_window() {
        let rtt = Duration::from_millis(100);
        let (mut client, mut server) = rtt_pair(paced, 40722, rtt);
        let (_, data) = client.write(&vec![1; 60_000]);
        assert!(data.len() < 10, "paced");
        advance(rtt);
        let mut out = data;
        while let Some(due) = client.pace_deadline {
            advance(due.saturating_duration_since(test_now()));
            out.extend(client.tick());
        }
        assert!(client.is_cwnd_limited, "cwnd held data back");
        let flight = client.send_buf.as_ref().unwrap().unacked() as u32;
        assert_eq!(client.cwnd_use(flight / 2), client.cc.cwnd());
        let cwnd = client.cc.cwnd();
        let acks = deliver(&mut server, &out[..2]);
        deliver(&mut client, &acks);
        assert!(client.cc.cwnd() > cwnd, "slow start grew");
    }

    /// A path through a bottleneck of `rate` bytes per second with a
    /// drop-tail queue of `queue` bytes and `delay` each way, from `a`
    /// (which always has data to send) to `b` (which reads all it gets).
    /// Time is the test clock, moved from event to event.
    struct Path {
        a: Conn,
        b: Conn,
        rate: f64,
        queue: f64,
        delay: Duration,
        /// Random loss before the bottleneck, in parts per million.
        loss_ppm: u64,
        rng: Rng,
        busy_until: Instant,
        /// Packets in flight each way, with their IP-ECN codepoints.
        fwd: std::collections::VecDeque<(Instant, Vec<u8>, IpEcn)>,
        rev: std::collections::VecDeque<(Instant, Vec<u8>, IpEcn)>,
        received: u64,
        drops: u64,
        /// Packets lost at random.
        lost: u64,
        /// Queueing delay each packet met at the bottleneck.
        queue_delays: Vec<Duration>,
        /// A step AQM: ECN-capable packets that find more than this many
        /// bytes queued ahead are marked CE; zero marks none.
        mark_bytes: f64,
        /// Packets marked CE.
        marked: u64,
        /// Data segments sent again, and how far data has been sent.
        retransmitted: u64,
        sent_end: Option<u32>,
        /// A black hole: packets larger than this many bytes (with an IPv4
        /// header) vanish, and nobody says so; zero lets all through.
        black_hole: u32,
        /// Packets it swallowed.
        swallowed: u64,
    }

    /// `pkts`, which `c` has just returned, with their codepoints.
    fn marked(c: &Conn, pkts: Vec<Vec<u8>>) -> Vec<(Vec<u8>, IpEcn)> {
        let marks = c.ecn_marks(&pkts);
        pkts.into_iter().zip(marks).collect()
    }

    impl Path {
        fn new(conf: ConnConfig, rate: f64, queue: f64, delay: Duration, port: u16) -> Path {
            let mut a = Conn::new(conf.clone().local_port(port).remote_port(80));
            let b = Conn::new(conf.local_port(80).remote_port(port).recv_buf_max(64 << 20));
            let syn = a.connect();
            let now = test_now();
            let mut p = Path {
                a,
                b,
                rate,
                queue,
                delay,
                loss_ppm: 0,
                rng: Rng(0x5EED | 1),
                busy_until: now,
                fwd: Default::default(),
                rev: Default::default(),
                received: 0,
                drops: 0,
                lost: 0,
                queue_delays: Vec::new(),
                mark_bytes: 0.0,
                marked: 0,
                retransmitted: 0,
                sent_end: None,
                black_hole: 0,
                swallowed: 0,
            };
            p.send(syn);
            p
        }

        /// Send what `a` has just returned.
        fn send(&mut self, pkts: Vec<Vec<u8>>) {
            let now = test_now();
            for (pkt, mut ecn) in marked(&self.a, pkts) {
                let seg = parse(&pkt);
                if !seg.payload.is_empty() {
                    let end = seg.seq.wrapping_add(seg.data_len());
                    match self.sent_end {
                        Some(e) if seq_before(seg.seq, e) => self.retransmitted += 1,
                        _ => self.sent_end = Some(end),
                    }
                }
                if self.loss_ppm > 0 && self.rng.below(1_000_000) < self.loss_ppm {
                    self.lost += 1;
                    continue;
                }
                if self.black_hole > 0 && 20 + pkt.len() as u32 > self.black_hole {
                    self.swallowed += 1;
                    continue;
                }
                let start = self.busy_until.max(now);
                let wait = start.saturating_duration_since(now);
                let backlog = wait.as_secs_f64() * self.rate;
                if backlog > self.queue {
                    self.drops += 1;
                    continue;
                }
                if self.mark_bytes > 0.0
                    && backlog > self.mark_bytes
                    && matches!(ecn, IpEcn::ECT0 | IpEcn::ECT1)
                {
                    ecn = IpEcn::CE;
                    self.marked += 1;
                }
                self.queue_delays.push(wait);
                let done = start + Duration::from_secs_f64(pkt.len() as f64 / self.rate);
                self.busy_until = done;
                self.fwd.push_back((done + self.delay, pkt, ecn));
            }
        }

        /// Run until `until` has passed on the test clock.
        fn run_for(&mut self, d: Duration) {
            let end = test_now() + d;
            let chunk = vec![7u8; 1 << 16];
            loop {
                let (_, out) = self.a.write(&chunk);
                self.send(out);
                let next = [
                    self.fwd.front().map(|x| x.0),
                    self.rev.front().map(|x| x.0),
                    self.a.next_deadline(),
                    self.b.next_deadline(),
                ]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(end)
                .min(end);
                let now = test_now();
                if next > now {
                    advance(next - now);
                }
                let now = test_now();
                if now >= end {
                    return;
                }
                while self.fwd.front().is_some_and(|x| x.0 <= now) {
                    let (_, pkt, ecn) = self.fwd.pop_front().unwrap();
                    let seg = parse(&pkt);
                    let out = if self.b.state() == State::Closed && !self.b.is_closed() {
                        self.b.accept_syn_ecn(&seg, ecn)
                    } else {
                        self.b.handle_segment_ecn(&seg, ecn)
                    };
                    let mut out = marked(&self.b, out);
                    let got = read_all(&mut self.b);
                    self.received += got.len() as u64;
                    let more = self.b.take_outgoing();
                    out.extend(marked(&self.b, more));
                    for (p, e) in out {
                        self.rev.push_back((now + self.delay, p, e));
                    }
                }
                while self.rev.front().is_some_and(|x| x.0 <= now) {
                    let (_, pkt, ecn) = self.rev.pop_front().unwrap();
                    let out = self.a.handle_segment_ecn(&parse(&pkt), ecn);
                    self.send(out);
                }
                let out = self.a.tick();
                self.send(out);
                let out = self.b.tick();
                for (p, e) in marked(&self.b, out) {
                    self.rev.push_back((now + self.delay, p, e));
                }
            }
        }

        /// Goodput over `d`, in bytes per second.
        fn goodput(&mut self, d: Duration) -> f64 {
            let before = self.received;
            self.run_for(d);
            (self.received - before) as f64 / d.as_secs_f64()
        }
    }

    /// A bulk transfer over 10 Mbit/s with 40 ms of round trip.
    fn bulk(conf: ConnConfig, queue_bdps: f64, port: u16) -> Path {
        let rate = 1_250_000.0;
        let rtt = Duration::from_millis(40);
        let queue = queue_bdps * rate * rtt.as_secs_f64();
        let conf = conf.mss(1460).send_buf_size(1 << 20).recv_buf_size(1 << 20);
        Path::new(conf, rate, queue.max(3000.0), rtt / 2, port)
    }

    /// BBR finds the bottleneck's rate and round trip and fills the link
    /// with little queue: its estimate within 10% of the rate, the link
    /// nearly full, and packets queueing for a fraction of the round trip.
    #[test]
    fn bbr_converges_on_the_bottleneck_rate() {
        let conf = ConnConfig::default().congestion(CongestionKind::Bbr);
        let mut p = bulk(conf, 2.0, 40710);
        p.run_for(Duration::from_secs(3));
        p.queue_delays.clear();
        let goodput = p.goodput(Duration::from_secs(10));
        let bbr = p.a.cc.as_bbr().unwrap();
        let bw = bbr.max_bw() as f64;
        assert!((bw / p.rate - 1.0).abs() < 0.1, "bw estimate {bw}");
        let min_rtt = bbr.min_rtt().unwrap();
        assert!(
            min_rtt >= Duration::from_millis(40) && min_rtt < Duration::from_millis(45),
            "{min_rtt:?}"
        );
        assert!(goodput > 0.9 * p.rate, "goodput {goodput}");
        let mut q = p.queue_delays.clone();
        q.sort();
        let median = q[q.len() / 2];
        assert!(
            median < Duration::from_millis(20),
            "median queueing {median:?}"
        );
        assert_eq!(p.drops, 0, "a queue of two BDPs never overflows");
        assert!(
            matches!(
                bbr.state(),
                bbr::State::ProbeBwDown
                    | bbr::State::ProbeBwCruise
                    | bbr::State::ProbeBwRefill
                    | bbr::State::ProbeBwUp
                    | bbr::State::ProbeRtt
            ),
            "{:?}",
            bbr.state()
        );
    }

    /// Random loss well below BBR's 2% threshold per round trip leaves
    /// its model alone: at 0.5% over 50 Mbit/s and 40 ms (170 segments in
    /// flight, fewer than one lost per round on average) it still nearly
    /// fills the link, where a loss-based controller cuts its window on
    /// every loss.
    #[test]
    fn bbr_holds_its_rate_through_random_loss() {
        let run = |conf: ConnConfig, port| {
            let mut p = bulk(conf, 1.0, port);
            p.rate *= 5.0;
            p.queue *= 5.0;
            p.loss_ppm = 5_000;
            p.run_for(Duration::from_secs(3));
            let goodput = p.goodput(Duration::from_secs(10));
            (goodput, p.rate)
        };
        let (bbr, rate) = run(ConnConfig::default().congestion(CongestionKind::Bbr), 40711);
        assert!(bbr > 0.8 * rate, "BBR goodput {bbr}");
        let (cubic, _) = run(ConnConfig::default(), 40712);
        assert!(cubic < 0.5 * bbr, "CUBIC {cubic}, BBR {bbr}");
    }

    /// Into a queue of a tenth of the BDP, CUBIC's slow start overflows it
    /// with every burst unless paced. Paced, it loses fewer packets and
    /// moves at least as much.
    #[test]
    fn pacing_spares_a_shallow_queue() {
        let run = |pacing, port| {
            let mut p = bulk(ConnConfig::default().pacing(pacing), 0.1, port);
            let goodput = p.goodput(Duration::from_secs(8));
            (goodput, p.drops)
        };
        let (paced_goodput, paced_drops) = run(true, 40713);
        let (bursty_goodput, bursty_drops) = run(false, 40714);
        assert!(
            paced_drops < bursty_drops,
            "drops paced {paced_drops}, not {bursty_drops}"
        );
        assert!(
            paced_goodput >= 0.95 * bursty_goodput,
            "goodput paced {paced_goodput}, not {bursty_goodput}"
        );
    }

    /// A sender that runs out of data with room in the window marks its
    /// delivery rate samples application-limited, until what it sent then
    /// is delivered; a bulk sender does not.
    #[test]
    fn running_dry_marks_samples_application_limited() {
        let mut c = Conn::new(big(40716, 80));
        let mut s = Conn::new(big(80, 40716));
        drive_handshake(&mut c, &mut s);
        let (_, data) = c.write(&[1; 1000]);
        assert!(c.score.rate().is_app_limited(), "ran dry with room");
        advance(Duration::from_millis(10));
        let acks = deliver(&mut s, &data);
        c.score.begin_ack();
        let ack = parse(&acks[0]).ack;
        c.send_buf.as_mut().unwrap().acknowledge(ack);
        c.score.ack(ack, test_now(), None);
        let rs = c.score.rate_sample().unwrap();
        assert!(rs.is_app_limited);
        assert_eq!(rs.delivered, 1000);
        assert!(!c.score.rate().is_app_limited(), "the bubble is delivered");

        // More than the window can take: the first flight still went out
        // of an application-limited connection, but once it is delivered
        // the window, not the application, holds the sender back.
        let (_, data) = c.write(&vec![1; 200_000]);
        assert!(!data.is_empty());
        assert!(c.score.rate().is_app_limited());
        advance(Duration::from_millis(10));
        let acks = deliver(&mut s, &data);
        read_all(&mut s);
        deliver(&mut c, &acks);
        assert!(!c.score.rate().is_app_limited());
    }

    // --- PLPMTUD -------------------------------------------------------------

    /// A bulk transfer over a path whose MTU is 1400 with nobody to say so:
    /// larger packets vanish without an ICMP message. PLPMTUD finds the
    /// black hole from the timeouts, drops to the base MSS, and probes back
    /// up to within a few bytes of the path's MTU, where the transfer runs
    /// at nearly the link's rate. Starting from the base, `Always` never
    /// falls in.
    #[test]
    fn a_black_hole_is_found_and_the_mss_converges_below_it() {
        for (mode, port) in [
            (MtuProbing::OnBlackHole, 40720),
            (MtuProbing::Always, 40721),
        ] {
            let mut p = bulk(ConnConfig::default().mtu_probing(mode), 2.0, port);
            p.black_hole = 1400;
            p.run_for(Duration::from_secs(10));
            let mtu = p.a.path_mtu();
            assert!(mtu <= 1400 && mtu > 1400 - 16, "{mode:?}: MTU {mtu}");
            let goodput = p.goodput(Duration::from_secs(5));
            assert!(goodput > 0.85 * p.rate, "{mode:?}: goodput {goodput}");
            if mode == MtuProbing::Always {
                assert!(p.swallowed < 20, "{} swallowed", p.swallowed);
            }
            // The probes lost to their size cost no window.
            assert!(!p.a.is_closed());
        }
    }

    /// The timeouts that found the black hole were no congestion: once the
    /// retransmission at the smaller size gets through, their window cut
    /// is undone, and slow start goes on where it was.
    #[test]
    fn a_black_hole_costs_no_window() {
        let mut p = bulk(ConnConfig::default(), 2.0, 40728);
        p.black_hole = 1400;
        for _ in 0..100 {
            if p.received > 0 {
                break;
            }
            p.run_for(Duration::from_millis(50));
        }
        assert!(p.received > 0, "never got through");
        assert!(p.a.retries == 0 && p.a.mss() <= 1360, "{:?}", p.a);
        assert_eq!(p.a.cc.ssthresh(), u32::MAX, "slow start cut short");
    }

    /// Without PLPMTUD the same path is the end of the connection: every
    /// full-sized segment is lost, and so is every retransmission of it.
    #[test]
    fn without_probing_a_black_hole_stalls() {
        let mut p = bulk(
            ConnConfig::default().mtu_probing(MtuProbing::Off),
            2.0,
            40722,
        );
        p.black_hole = 1400;
        p.run_for(Duration::from_secs(10));
        assert_eq!(p.received, 0);
        assert_eq!(p.a.path_mtu(), 1500);
    }

    /// With ICMP getting through as it should, PLPMTUD stays out of the
    /// way: a clean path sees no probes and no change of MSS, and repeated
    /// timeouts of small segments are not taken for a black hole.
    #[test]
    fn a_clean_path_is_left_alone() {
        let mut p = bulk(ConnConfig::default(), 2.0, 40723);
        p.run_for(Duration::from_secs(3));
        assert_eq!(p.a.path_mtu(), 1500);
        assert!(p.a.plpmtud.cap().is_none());

        let (mut c, _s) = established(40724);
        c.write(&[1; 100]);
        fire_rto(&mut c);
        fire_rto(&mut c);
        fire_rto(&mut c);
        assert_eq!(c.mss(), 1460, "small segments timing out");
    }

    fn probing(local: u16, remote: u16) -> ConnConfig {
        cfg(local, remote)
            .mtu_probing(MtuProbing::Always)
            .send_buf_size(1 << 20)
            .recv_buf_size(1 << 20)
    }

    /// A connection probing from the base MSS, with a window wide enough
    /// for a probe, and the segments of its first write.
    fn probing_pair(port: u16) -> (Conn, Conn, Vec<Segment>, Segment) {
        let mut c = Conn::new(probing(port, 80));
        let mut s = Conn::new(probing(80, port));
        drive_handshake(&mut c, &mut s);
        assert_eq!(c.mss(), 1024);
        c.cc.set_cwnd(40 * 1024);
        let (_, out) = c.write(&vec![5; 100_000]);
        let out: Vec<Segment> = out.iter().map(|p| parse(p)).collect();
        let probe = out
            .iter()
            .find(|p| p.payload.len() > 1024)
            .expect("no probe")
            .clone();
        (c, s, out, probe)
    }

    /// A probe lost to its size, while what follows it arrives, is resent
    /// alone, at the MSS, and the window stays as it was.
    #[test]
    fn a_probe_lost_to_its_size_keeps_the_window() {
        let (mut c, mut s, out, probe) = probing_pair(40725);
        let end = probe.seq.wrapping_add(probe.payload.len() as u32);
        let acks: Vec<_> = out
            .iter()
            .filter(|p| p.seq != probe.seq)
            .flat_map(|p| s.handle_segment(p))
            .collect();
        let cwnd = c.cc.cwnd();
        let resent: Vec<Segment> = deliver(&mut c, &acks).iter().map(|p| parse(p)).collect();
        let again: Vec<_> = resent
            .iter()
            .filter(|p| seq_in_range(p.seq, probe.seq, end))
            .collect();
        assert!(!again.is_empty(), "probe not resent");
        assert!(again.iter().all(|p| p.payload.len() <= 1024), "too big");
        assert!(c.cc.cwnd() >= cwnd, "window cut for a probe");
        assert!(c.mtu_probe.is_none());
        assert_eq!(c.mss(), 1024);
        // Nothing else went again.
        assert!(resent.iter().all(|p| !seq_before(p.seq, probe.seq)));
        // Once it is in, the next probe tries a smaller size.
        let acks: Vec<_> = again.iter().flat_map(|p| s.handle_segment(p)).collect();
        deliver(&mut c, &acks);
        assert!(!c.in_recovery());
    }

    /// A probe delivered raises the MSS to its size.
    #[test]
    fn a_probe_delivered_raises_the_mss() {
        let (mut c, mut s, out, probe) = probing_pair(40727);
        let acks: Vec<_> = out.iter().flat_map(|p| s.handle_segment(p)).collect();
        deliver(&mut c, &acks);
        assert_eq!(u32::from(c.mss()), probe.payload.len() as u32);
        assert_eq!(c.path_mtu(), 40 + probe.payload.len() as u32);
    }

    /// A Packet Too Big for a probe settles it at once: the search takes
    /// the reported MTU as its ceiling, and the probe goes again at the MSS.
    #[test]
    fn packet_too_big_for_a_probe() {
        let (mut c, _s, _out, probe) = probing_pair(40726);
        let resent = c.on_icmp_too_big(1100, probe.seq);
        assert!(c.mtu_probe.is_none());
        assert_eq!(c.plpmtud.range().1, 1100);
        let again = parse(&resent[0]);
        assert_eq!(again.seq, probe.seq);
        assert!(again.payload.len() <= 1024);
        assert_eq!(c.mss(), 1024);
    }

    // --- TCP Fast Open -------------------------------------------------------

    /// A client at 10.0.0.2 and a server at 10.0.0.1 taking Fast Open.
    fn tfo_cfg(local: u16, remote: u16) -> ConnConfig {
        let ip = |port: u16| {
            if port == 80 {
                [10, 0, 0, 1]
            } else {
                [10, 0, 0, 2]
            }
        };
        cfg(local, remote)
            .local_addr((ip(local), local).into())
            .remote_addr((ip(remote), remote).into())
            .send_buf_size(1 << 16)
            .recv_buf_size(1 << 16)
            .fast_open(true)
    }

    /// A cookie from the server, as a first connection gets it.
    fn tfo_cookie(port: u16) -> Vec<u8> {
        let mut c = Conn::new(tfo_cfg(port, 80));
        let mut s = Conn::new(tfo_cfg(80, port));
        let (n, syn) = c.connect_fast_open(None, None, b"");
        assert_eq!(n, 0);
        let syn = parse(&syn[0]);
        assert_eq!(
            fastopen::offer(&syn.options),
            Some(fastopen::Offer::Request)
        );
        assert!(syn.payload.is_empty());
        let synack = s.accept_syn(&syn);
        assert!(!s.fast_open_accepted());
        let ack = deliver(&mut c, &synack);
        assert_eq!(c.state(), State::Established);
        deliver(&mut s, &ack);
        assert_eq!(s.state(), State::Established);
        c.fast_open_cookie().expect("no cookie").to_vec()
    }

    // RFC 7413: with a cookie, the request rides in the SYN and the server
    // reads it, and answers, before the handshake completes: the answer is
    // in one round trip.
    #[test]
    fn fast_open_answers_in_one_round_trip() {
        let cookie = tfo_cookie(40800);
        assert_eq!(cookie.len(), fastopen::COOKIE_LEN);
        let mut c = Conn::new(tfo_cfg(40801, 80));
        let mut s = Conn::new(tfo_cfg(80, 40801));
        let (n, syn) = c.connect_fast_open(Some(&cookie), None, b"GET /");
        assert_eq!(n, 5);
        let syn = parse(&syn[0]);
        assert_eq!(syn.payload, b"GET /");
        let synack = s.accept_syn(&syn);
        assert!(s.fast_open_accepted());
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(read_all(&mut s), b"GET /");
        let synack_seg = parse(&synack[0]);
        assert_eq!(
            synack_seg.ack,
            syn.seq.wrapping_add(6),
            "data not acknowledged"
        );
        assert!(fastopen::offer(&synack_seg.options).is_none());
        // The answer goes at once.
        let (n, answer) = s.write(b"200 OK");
        assert_eq!(n, 6);
        assert_eq!(answer.len(), 1);

        // The client takes the SYN-ACK, then the answer.
        let ack = deliver(&mut c, &synack);
        assert_eq!(c.state(), State::Established);
        assert!(c.fast_open_data_acked());
        let ack2 = deliver(&mut c, &answer);
        assert_eq!(read_all(&mut c), b"200 OK");
        // The ACK of the SYN-ACK alone completes the handshake, with the
        // answer still out; the next acknowledges it.
        deliver(&mut s, &ack);
        assert_eq!(s.state(), State::Established);
        assert!(s.rto_deadline.is_some(), "answer out with no timer");
        deliver(&mut s, &ack2);
        assert_eq!(s.send_buf.as_ref().unwrap().unacked(), 0);
        // Both ways on from there.
        let (_, more) = c.write(b"more");
        deliver(&mut s, &more);
        assert_eq!(read_all(&mut s), b"more");
    }

    // A cookie the server does not know gets the data dropped and a fresh
    // cookie back; the client sends the data again after the handshake.
    #[test]
    fn a_bad_cookie_falls_back_to_the_handshake() {
        let mut c = Conn::new(tfo_cfg(40802, 80));
        let mut s = Conn::new(tfo_cfg(80, 40802));
        let (_, syn) = c.connect_fast_open(Some(&[1, 2, 3, 4, 5, 6, 7, 8]), None, b"hello");
        let synack = deliver_syn(&mut s, &syn);
        assert!(!s.fast_open_accepted());
        assert!(read_all(&mut s).is_empty());
        let synack_seg = parse(&synack[0]);
        assert_eq!(synack_seg.ack, parse(&syn[0]).seq.wrapping_add(1));
        let fresh = match fastopen::offer(&synack_seg.options) {
            Some(fastopen::Offer::Cookie(c)) => c.to_vec(),
            o => panic!("{o:?}"),
        };
        let out = deliver(&mut c, &synack);
        assert!(!c.fast_open_data_acked());
        assert_eq!(c.fast_open_cookie(), Some(&fresh[..]));
        let data = out.iter().map(|p| parse(p)).find(|p| !p.payload.is_empty());
        assert_eq!(data.expect("data not resent").payload, b"hello");
        deliver(&mut s, &out);
        assert_eq!(s.state(), State::Established);
        assert_eq!(read_all(&mut s), b"hello");
    }

    fn deliver_syn(s: &mut Conn, syn: &[Vec<u8>]) -> Vec<Vec<u8>> {
        s.accept_syn(&parse(&syn[0]))
    }

    // A SYN with data that goes unanswered is sent again without it, and
    // without the cookie; the data follows the handshake.
    #[test]
    fn a_lost_syn_with_data_goes_again_without_it() {
        let cookie = tfo_cookie(40803);
        let mut c = Conn::new(tfo_cfg(40804, 80));
        let mut s = Conn::new(tfo_cfg(80, 40804));
        let (_, _lost) = c.connect_fast_open(Some(&cookie), None, b"hello");
        let again = fire_rto(&mut c);
        let syn = parse(&again[0]);
        assert!(syn.payload.is_empty());
        assert!(fastopen::offer(&syn.options).is_none());
        assert!(c.fast_open_syn_lost());
        let synack = deliver_syn(&mut s, &again);
        let out = deliver(&mut c, &synack);
        deliver(&mut s, &out);
        assert_eq!(read_all(&mut s), b"hello");
    }

    // Without Fast Open, a server leaves the option be, and SYN data
    // waits for the handshake as RFC 9293 has it.
    #[test]
    fn fast_open_is_opt_in() {
        let cookie = tfo_cookie(40805);
        let mut c = Conn::new(tfo_cfg(40806, 80));
        let mut s = Conn::new(tfo_cfg(80, 40806).fast_open(false));
        let (_, syn) = c.connect_fast_open(Some(&cookie), None, b"hello");
        let synack = deliver_syn(&mut s, &syn);
        assert!(fastopen::offer(&parse(&synack[0]).options).is_none());
        assert!(read_all(&mut s).is_empty());
        assert!(s.write(b"no").0 == 0, "wrote before the handshake");
        let out = deliver(&mut c, &synack);
        deliver(&mut s, &out);
        assert_eq!(read_all(&mut s), b"hello");
    }

    // RFC 7413 §5.1: past the gate's capacity a SYN's data waits for the
    // handshake; a place is given back once a handshake completes.
    #[test]
    fn pending_fast_open_connections_are_capped() {
        let cookie = tfo_cookie(40807);
        let gate = Gate::new(1);
        let open = |port: u16| {
            let mut c = Conn::new(tfo_cfg(port, 80));
            let mut s = Conn::new(tfo_cfg(80, port));
            s.set_fast_open_gate(Some(gate.clone()), false);
            let (_, syn) = c.connect_fast_open(Some(&cookie), None, b"x");
            let synack = deliver_syn(&mut s, &syn);
            (c, s, synack)
        };
        let (mut c1, mut s1, synack1) = open(40808);
        assert!(s1.fast_open_accepted());
        let (_, s2, _) = open(40809);
        assert!(!s2.fast_open_accepted(), "past the cap");
        assert_eq!(gate.pending(), 1);
        let ack = deliver(&mut c1, &synack1);
        deliver(&mut s1, &ack);
        assert_eq!(gate.pending(), 0);
        let (_, s3, _) = open(40810);
        assert!(s3.fast_open_accepted());
        drop(s3);
        assert_eq!(gate.pending(), 0, "a dropped connection keeps its place");
        // A driver with no room refuses the data.
        let mut c = Conn::new(tfo_cfg(40811, 80));
        let mut s = Conn::new(tfo_cfg(80, 40811));
        s.set_fast_open_gate(None, true);
        let (_, syn) = c.connect_fast_open(Some(&cookie), None, b"x");
        deliver_syn(&mut s, &syn);
        assert!(!s.fast_open_accepted());
    }

    // --- ECN -----------------------------------------------------------------

    use super::super::ecn::Feedback;

    /// Deliver `pkts` with their codepoints, as `path` leaves them, and
    /// return the replies with theirs.
    fn deliver_marked(
        to: &mut Conn,
        pkts: &[(Vec<u8>, IpEcn)],
        path: impl Fn(usize, IpEcn) -> IpEcn,
    ) -> Vec<(Vec<u8>, IpEcn)> {
        let mut out = Vec::new();
        for (i, (p, e)) in pkts.iter().enumerate() {
            let r = to.handle_segment_ecn(&parse(p), path(i, *e));
            out.extend(marked(to, r));
        }
        out
    }

    /// What `f` has `c` send, with the codepoints.
    fn sent_by(c: &mut Conn, f: impl FnOnce(&mut Conn) -> Vec<Vec<u8>>) -> Vec<(Vec<u8>, IpEcn)> {
        let out = f(c);
        marked(c, out)
    }

    fn as_is(_: usize, e: IpEcn) -> IpEcn {
        e
    }

    /// A handshake carrying codepoints, each segment through `path`.
    fn ecn_pair_via(
        cm: EcnMode,
        sm: EcnMode,
        port: u16,
        path: impl Fn(&mut Segment, &mut IpEcn),
    ) -> (Conn, Conn) {
        let mut c = Conn::new(big(port, 80).ecn(cm));
        let mut s = Conn::new(big(80, port).ecn(sm));
        let hop = |pkts: Vec<(Vec<u8>, IpEcn)>| {
            pkts.into_iter()
                .map(|(p, mut e)| {
                    let mut seg = parse(&p);
                    path(&mut seg, &mut e);
                    (seg, e)
                })
                .collect::<Vec<_>>()
        };
        let syn = c.connect();
        let syn = marked(&c, syn);
        assert_eq!(syn[0].1, IpEcn::NOT_ECT, "a SYN is never ECN-capable");
        let syn = hop(syn);
        let synack = s.accept_syn_ecn(&syn[0].0, syn[0].1);
        let synack = marked(&s, synack);
        assert_eq!(synack[0].1, IpEcn::NOT_ECT);
        let synack = hop(synack);
        let ack = c.handle_segment_ecn(&synack[0].0, synack[0].1);
        for (seg, e) in hop(marked(&c, ack)) {
            s.handle_segment_ecn(&seg, e);
        }
        assert_eq!(
            (c.state(), s.state()),
            (State::Established, State::Established)
        );
        (c, s)
    }

    fn ecn_pair(cm: EcnMode, sm: EcnMode, port: u16) -> (Conn, Conn) {
        ecn_pair_via(cm, sm, port, |_, _| {})
    }

    /// Who asks for which ECN, and what each end ends up with: RFC 3168's
    /// and RFC 9768's negotiation between each pair of settings.
    #[test]
    fn ecn_negotiation_matrix() {
        use EcnMode::*;
        let modes = [Off, Passive, Classic, Accurate];
        for (i, &cm) in modes.iter().enumerate() {
            for (j, &sm) in modes.iter().enumerate() {
                let want = match (cm, sm) {
                    (Off | Passive, _) | (_, Off) => Feedback::Off,
                    (Accurate, Accurate) => Feedback::Accurate,
                    _ => Feedback::Classic,
                };
                let (c, s) = ecn_pair(cm, sm, 41000 + (i * 4 + j) as u16);
                assert_eq!((c.ecn.fb, s.ecn.fb), (want, want), "{cm:?} to {sm:?}");
                let on = want != Feedback::Off;
                assert_eq!((c.ecn.ect, s.ecn.ect), (on, on), "{cm:?} to {sm:?}");
                assert_eq!((c.ecn.active(), s.ecn.active()), (on, on));
            }
        }
    }

    /// Classic ECN end to end: a CE mark has every ACK echo ECE until the
    /// sender's CWR gets through; the sender cuts its window once for all
    /// of them, sends CWR once, resends nothing, and leaves loss recovery
    /// alone. Only new data is ECN-capable.
    #[test]
    fn classic_ecn_echo_reduces_once_without_retransmitting() {
        let (mut c, mut s) = ecn_pair(EcnMode::Classic, EcnMode::Passive, 41100);
        let (_, data) = c.write(&[1; 60_000]);
        let data = marked(&c, data);
        assert_eq!(data.len(), 10, "the initial window");
        assert!(
            data.iter().all(|(_, e)| *e == IpEcn::ECT0),
            "new data is ECT"
        );
        let mut acks = deliver_marked(&mut s, &data, |i, e| if i == 0 { IpEcn::CE } else { e });
        acks.extend(sent_by(&mut s, delack_expired));
        assert!(!acks.is_empty());
        for (a, e) in &acks {
            assert!(parse(a).has_flag(flags::ECE), "not echoed");
            assert_eq!(*e, IpEcn::NOT_ECT, "a pure ACK is not ECT");
        }
        let end = parse(&data[9].0).seq.wrapping_add(1000);

        let mut sent = Vec::new();
        let mut ssthresh = None;
        for a in &acks {
            sent.extend(deliver_marked(&mut c, std::slice::from_ref(a), as_is));
            let st = c.cc.ssthresh();
            assert!(st <= 7_000, "not cut by β: {st}");
            assert_eq!(*ssthresh.get_or_insert(st), st, "cut twice");
            assert_eq!(c.ca, CaState::Open, "no loss recovery");
            assert_eq!(c.score.lost_bytes(), 0);
        }
        assert!(c.cwr_high.is_some());
        assert!(!sent.is_empty(), "PRR sends on");
        for (p, e) in &sent {
            let seg = parse(p);
            assert!(seq_after_eq(seg.seq, end), "resent {}", seg.seq);
            assert_eq!(*e, IpEcn::ECT0);
        }
        let cwr: Vec<_> = sent
            .iter()
            .map(|(p, _)| parse(p).has_flag(flags::CWR))
            .collect();
        assert!(
            cwr[0] && !cwr[1..].contains(&true),
            "CWR once, first: {cwr:?}"
        );

        // The CWR stops the echo; its ACKs end the reduction.
        let mut acks = deliver_marked(&mut s, &sent, as_is);
        acks.extend(sent_by(&mut s, delack_expired));
        assert!(acks.iter().all(|(a, _)| !parse(a).has_flag(flags::ECE)));
        assert!(!s.ecn.echoing());
        let out = deliver_marked(&mut c, &acks, as_is);
        assert!(c.cwr_high.is_none(), "reduction not over");
        assert_eq!(c.cc.ssthresh(), ssthresh.unwrap());

        // A mark in the next window is a new signal: cut again.
        assert!(!out.is_empty());
        let acks = deliver_marked(&mut s, &out, |_, _| IpEcn::CE);
        deliver_marked(&mut c, &acks, as_is);
        assert!(c.cc.ssthresh() < ssthresh.unwrap(), "no second cut");
    }

    /// A retransmission is not ECN-capable under classic ECN (RFC 3168
    /// §6.1.5), nor a window probe; under AccECN, as on Linux, it is.
    #[test]
    fn retransmissions_are_ect_only_with_accecn() {
        for (mode, port, want) in [
            (EcnMode::Classic, 41101, IpEcn::NOT_ECT),
            (EcnMode::Accurate, 41102, IpEcn::ECT0),
        ] {
            let (mut c, _s) = ecn_pair(mode, mode, port);
            let (_, data) = c.write(&[1; 3000]);
            assert!(marked(&c, data).iter().all(|(_, e)| *e == IpEcn::ECT0));
            let re = fire_rto(&mut c);
            let re = marked(&c, re);
            assert!(!parse(&re[0].0).payload.is_empty());
            assert_eq!(re[0].1, want, "{mode:?}");
        }
    }

    /// AccECN end to end: the ACE field counts every mark, across its
    /// wrap, the sender's count follows the receiver's, and all the marks
    /// of a window make one reduction. Pure ACKs are ECN-capable too.
    #[test]
    fn accecn_counts_every_mark() {
        let (mut c, mut s) = ecn_pair(EcnMode::Accurate, EcnMode::Accurate, 41110);
        let mut total = 0;
        let mut ssthresh = None;
        let mut carry = Vec::new();
        for round in 0..6 {
            let (_, data) = c.write(&[1; 20_000]);
            let mut out = std::mem::take(&mut carry);
            out.extend(marked(&c, data));
            out.extend(sent_by(&mut c, Conn::take_outgoing));
            // Marks on every segment of the first rounds.
            let mark = |_, e| if round < 3 { IpEcn::CE } else { e };
            total += if round < 3 { out.len() } else { 0 };
            let mut acks = deliver_marked(&mut s, &out, mark);
            read_all(&mut s);
            acks.extend(sent_by(&mut s, Conn::take_outgoing));
            acks.extend(sent_by(&mut s, delack_expired));
            assert!(acks.iter().all(|(_, e)| *e == IpEcn::ECT0), "ACKs are ECT");
            carry = deliver_marked(&mut c, &acks, as_is);
            if round == 0 {
                ssthresh = Some(c.cc.ssthresh());
                assert!(ssthresh < Some(u32::MAX), "no reduction");
            }
        }
        assert_eq!(s.ecn.received_ce() as usize, total);
        assert_eq!(c.ecn.sent_ce() as usize, total);
        assert!(total > 8, "the counter never wrapped");
        assert_eq!(c.score.lost_bytes(), 0);
        assert!(
            c.cc.ssthresh() < ssthresh.unwrap(),
            "later windows' marks cut again"
        );
    }

    /// RFC 3168 §6.1.1.1: an ECN SYN may be dropped by the path, so a
    /// retransmitted SYN no longer asks; AccECN asks once more first (RFC
    /// 9768 §3.1.4).
    #[test]
    fn syn_retransmissions_stop_asking_for_ecn() {
        let ecn = |s: &Segment| (s.ae, s.flags & (flags::ECE | flags::CWR));
        let mut c = Conn::new(big(41120, 80).ecn(EcnMode::Classic));
        let syn = parse(&c.connect()[0]);
        assert_eq!(ecn(&syn), (false, flags::ECE | flags::CWR));
        let re = parse(&fire_rto(&mut c)[0]);
        assert_eq!(ecn(&re), (false, 0));

        let mut c = Conn::new(big(41121, 80).ecn(EcnMode::Accurate));
        let all = (true, flags::ECE | flags::CWR);
        assert_eq!(ecn(&parse(&c.connect()[0])), all);
        assert_eq!(ecn(&parse(&fire_rto(&mut c)[0])), all);
        assert_eq!(ecn(&parse(&fire_rto(&mut c)[0])), (false, 0));
        // A server answering only that gives no ECN.
        let mut s = Conn::new(big(80, 41121).ecn(EcnMode::Accurate));
        let synack = s.accept_syn(&parse(&fire_rto(&mut c)[0]));
        assert_eq!(s.ecn.fb, Feedback::Off);
        deliver(&mut c, &synack);
        assert_eq!(c.ecn.fb, Feedback::Off);
    }

    /// What a path that meddles with ECN leaves of it (RFC 9768 §3.1.5,
    /// §3.2.2.1, §3.2.2.3): a middlebox clearing the TCP flags leaves no
    /// ECN, or none trusted; one rewriting the IP field of the SYN leaves
    /// the client sending Not-ECT; one bleaching IP marks leaves nothing
    /// to answer, but no harm.
    #[test]
    fn ecn_through_meddling_paths() {
        use EcnMode::Accurate;
        let clear = |s: &mut Segment| {
            s.ae = false;
            s.flags &= !(flags::ECE | flags::CWR);
        };
        // Flags cleared both ways: no ECN at all.
        let (c, s) = ecn_pair_via(Accurate, Accurate, 41130, |s, _| clear(s));
        assert_eq!((c.ecn.fb, s.ecn.fb), (Feedback::Off, Feedback::Off));
        // Only on the SYN-ACK: the client sees no ECN; the server, AccECN
        // but a zeroed ACE on the ACK completing the handshake, which it
        // takes as the middlebox's, and so neither sends ECT nor answers.
        let (c, s) = ecn_pair_via(Accurate, Accurate, 41131, |s, _| {
            if s.has_flag(flags::SYN) && s.has_flag(flags::ACK) {
                clear(s)
            }
        });
        assert_eq!(c.ecn.fb, Feedback::Off);
        assert_eq!(s.ecn.fb, Feedback::Accurate);
        assert!(!s.ecn.ect && !s.ecn.respond);
        // Only on the ACK of the SYN-ACK: the same for the server; the
        // client goes on with AccECN.
        let (c, s) = ecn_pair_via(Accurate, Accurate, 41132, |s, _| {
            if !s.has_flag(flags::SYN) {
                clear(s)
            }
        });
        assert!(c.ecn.ect && !s.ecn.ect && !s.ecn.respond);
        // The SYN arrives ECT(0) though sent Not-ECT: the SYN-ACK says so,
        // and the client, still in AccECN, sends Not-ECT from then on.
        let (mut c, _) = ecn_pair_via(Accurate, Accurate, 41133, |s, e| {
            if s.has_flag(flags::SYN) && !s.has_flag(flags::ACK) {
                *e = IpEcn::ECT0;
            }
        });
        assert_eq!(c.ecn.fb, Feedback::Accurate);
        let (_, data) = c.write(&[1; 1000]);
        assert_eq!(marked(&c, data)[0].1, IpEcn::NOT_ECT);

        // Classic ECN over a path that clears every IP mark: nothing to
        // answer, and nothing goes amiss.
        let (mut c, mut s) = ecn_pair(EcnMode::Classic, EcnMode::Classic, 41134);
        let mut carry = Vec::new();
        for round in 0..20 {
            let mut out = std::mem::take(&mut carry);
            if round < 5 {
                let (_, data) = c.write(&[1; 20_000]);
                out.extend(marked(&c, data));
            }
            out.extend(sent_by(&mut c, Conn::take_outgoing));
            let mut acks = deliver_marked(&mut s, &out, |_, _| IpEcn::NOT_ECT);
            read_all(&mut s);
            acks.extend(sent_by(&mut s, delack_expired));
            carry = deliver_marked(&mut c, &acks, |_, _| IpEcn::NOT_ECT);
        }
        assert_eq!(c.cc.ssthresh(), u32::MAX);
        assert_eq!(c.send_buf.as_ref().unwrap().unacked(), 0);
    }

    /// Over a deep queue that marks past a fifth of the BDP, ECN keeps
    /// CUBIC's queue short with no loss at all, where without it CUBIC
    /// fills the queue until it overflows.
    #[test]
    fn ecn_keeps_a_marking_queue_short_without_loss() {
        let run = |mode, port| {
            let conf = ConnConfig::default().ecn(mode);
            let mut p = bulk(conf, 2.0, port);
            p.mark_bytes = 0.2 * p.rate * 0.04;
            p.run_for(Duration::from_secs(3));
            p.queue_delays.clear();
            let goodput = p.goodput(Duration::from_secs(10));
            let mut q = p.queue_delays.clone();
            q.sort();
            (p, goodput, q[q.len() / 2])
        };
        for (mode, port) in [(EcnMode::Classic, 41140), (EcnMode::Accurate, 41141)] {
            let (p, goodput, median) = run(mode, port);
            assert!(p.marked > 0, "{mode:?}: never marked");
            assert_eq!((p.drops, p.retransmitted), (0, 0), "{mode:?}");
            assert!(goodput > 0.85 * p.rate, "{mode:?}: goodput {goodput}");
            assert!(median < Duration::from_millis(10), "{mode:?}: {median:?}");
        }
        let (p, _, median) = run(EcnMode::Off, 41142);
        assert_eq!(p.marked, 0);
        assert!(
            p.drops > 0 || median > Duration::from_millis(20),
            "without ECN: {} drops, {median:?}",
            p.drops
        );
    }

    /// BBR over the same marking queue, with AccECN: it keeps the link
    /// full, the queue short and nothing lost, and its ecn_alpha follows
    /// the marks.
    #[test]
    fn bbr_heeds_ecn_marks() {
        let conf = ConnConfig::default()
            .congestion(CongestionKind::Bbr)
            .ecn(EcnMode::Accurate);
        let mut p = bulk(conf, 2.0, 41150);
        p.mark_bytes = 0.2 * p.rate * 0.04;
        p.run_for(Duration::from_secs(3));
        p.queue_delays.clear();
        let goodput = p.goodput(Duration::from_secs(10));
        assert!(goodput > 0.85 * p.rate, "goodput {goodput}");
        assert_eq!(p.drops, 0);
        let mut q = p.queue_delays.clone();
        q.sort();
        assert!(
            q[q.len() / 2] < Duration::from_millis(10),
            "{:?}",
            q[q.len() / 2]
        );
        assert!(p.a.ecn.sent_ce() > 0, "never marked");
    }
}
