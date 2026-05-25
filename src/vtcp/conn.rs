//! TCP connection state machine.
//!
//! This is a synchronous, callback-style port of the Go upstream's `Conn`.
//! Rather than asynchronous timers and condvars, the connection exposes a
//! [`tick`](Conn::tick) method that the caller invokes periodically to drive
//! retransmission, persist, keepalive, and TIME-WAIT timeouts. All outgoing
//! segments are returned from methods as `Vec<Vec<u8>>` — the caller is
//! responsible for wrapping each in IP+L2 and pushing it on the wire.
//!
//! The state machine follows RFC 9293 §3.10 (the rolled-up RFC 793 +
//! errata). Window scaling, SACK, and timestamps are all negotiated during
//! the handshake; congestion control plugs in via the [`CongestionController`]
//! trait. Anything not yet handled is flagged with `TODO(vtcp)`.

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::rand;

use super::congestion::{CongestionController, HighSpeed, NewReno};
use super::options::{
    self, get_mss, get_sack_blocks, get_timestamp, get_wscale, has_sack_perm, mss_option,
    sack_option, sack_perm_option, timestamp_option, wscale_option, TcpOption,
};
use super::recvbuf::RecvBuf;
use super::rto::{RtoState, MAX_RTO};
use super::segment::{flags, Segment};
use super::sendbuf::SendBuf;
use super::seqspace::{seq_after, seq_after_eq, seq_before_eq, seq_in_range};

// --- Tunables -------------------------------------------------------------

/// Default MSS used when the peer does not advertise one.
pub const DEFAULT_MSS: u16 = 1460;
/// Default advertised window when no SACK / Window Scale negotiated.
pub const DEFAULT_WINDOW_SIZE: u16 = 65535;
/// Default 1 MiB send buffer.
pub const DEFAULT_SEND_BUF: usize = 1 << 20;
/// Default 1 MiB receive buffer.
pub const DEFAULT_RECV_BUF: usize = 1 << 20;

/// Maximum retransmission attempts before declaring the connection dead.
pub const MAX_RETRIES: u32 = 8;
/// 2*MSL — shortened from RFC default for virtual environments.
pub const TIME_WAIT_DURATION: Duration = Duration::from_secs(2);

pub const DEFAULT_KEEPALIVE_IDLE: Duration = Duration::from_secs(300);
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
pub const DEFAULT_KEEPALIVE_COUNT: u32 = 3;

// --- TCP state -------------------------------------------------------------

/// TCP state per RFC 9293 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl State {
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

/// Choice of congestion controller.
#[derive(Debug, Clone, Copy, Default)]
pub enum CongestionKind {
    NewReno,
    /// HighSpeed TCP (RFC 3649). Default.
    #[default]
    HighSpeed,
}

fn make_cc(kind: CongestionKind, mss: u32) -> Box<dyn CongestionController> {
    match kind {
        CongestionKind::NewReno => Box::new(NewReno::new(mss)),
        CongestionKind::HighSpeed => Box::new(HighSpeed::new(mss)),
    }
}

/// Connection configuration.
#[derive(Debug, Clone)]
pub struct ConnConfig {
    pub local_addr: std::option::Option<SocketAddr>,
    pub remote_addr: std::option::Option<SocketAddr>,
    pub local_port: u16,
    pub remote_port: u16,
    pub mss: u16,
    pub no_window_scaling: bool,
    pub enable_timestamps: bool,
    pub enable_sack: bool,
    pub congestion: CongestionKind,
    pub keepalive: bool,
    pub keepalive_idle: Duration,
    pub keepalive_interval: Duration,
    pub keepalive_count: u32,
    pub send_buf_size: usize,
    pub recv_buf_size: usize,
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
            enable_timestamps: false,
            enable_sack: false,
            congestion: CongestionKind::default(),
            keepalive: false,
            keepalive_idle: DEFAULT_KEEPALIVE_IDLE,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            keepalive_count: DEFAULT_KEEPALIVE_COUNT,
            send_buf_size: DEFAULT_SEND_BUF,
            recv_buf_size: DEFAULT_RECV_BUF,
        }
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
    mss: u16,
    cc: Box<dyn CongestionController>,

    // RTO management.
    rto: RtoState,
    rto_deadline: std::option::Option<Instant>,
    retries: u32,

    // Window scaling (RFC 7323).
    snd_wnd_shift: u8,
    rcv_wnd_shift: u8,
    wscale_ok: bool,

    // Timestamps.
    ts_enabled: bool,
    ts_ok: bool,
    ts_recent: u32,
    ts_offset_ms: u64, // wall-clock offset baseline

    // SACK.
    sack_enabled: bool,
    sack_ok: bool,

    // Deferred FIN.
    fin_pending: bool,
    pending_fin_seq: u32,

    // Persist (zero-window probing).
    persist_deadline: std::option::Option<Instant>,
    persist_backoff: Duration,

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
    pub fn new(cfg: ConnConfig) -> Self {
        // Pick a window scale that lets the recv buffer fit into a 16-bit
        // advertised window after scaling.
        let mut rcv_shift = 0u8;
        if !cfg.no_window_scaling {
            for s in 0u8..=14 {
                rcv_shift = s;
                if cfg.recv_buf_size >> s <= 65535 {
                    break;
                }
            }
        }

        let mss = cfg.mss.max(1);
        let cc = make_cc(cfg.congestion, mss as u32);
        let ts_offset_ms = wallclock_ms();

        Self {
            cfg: cfg.clone(),
            state: State::Closed,
            closed: false,
            send_buf: None,
            recv_buf: None,
            snd_wnd: DEFAULT_WINDOW_SIZE as u32,
            mss,
            cc,
            rto: RtoState::new(),
            rto_deadline: None,
            retries: 0,
            snd_wnd_shift: 0,
            rcv_wnd_shift: rcv_shift,
            wscale_ok: false,
            ts_enabled: cfg.enable_timestamps,
            ts_ok: false,
            ts_recent: 0,
            ts_offset_ms,
            sack_enabled: cfg.enable_sack,
            sack_ok: false,
            fin_pending: false,
            pending_fin_seq: 0,
            persist_deadline: None,
            persist_backoff: Duration::ZERO,
            time_wait_deadline: None,
            keepalive_deadline: None,
            keepalive_sent: 0,
            last_recv: Instant::now(),
            established_signaled: false,
            fin_recvd_signaled: false,
            outgoing: Vec::new(),
        }
    }

    // --- Accessors ---------------------------------------------------------

    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

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

    #[inline]
    pub fn local_addr(&self) -> std::option::Option<SocketAddr> {
        self.cfg.local_addr
    }
    #[inline]
    pub fn remote_addr(&self) -> std::option::Option<SocketAddr> {
        self.cfg.remote_addr
    }

    /// Drain any queued outgoing segments.
    pub fn take_outgoing(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outgoing)
    }

    // --- Active / passive open --------------------------------------------

    /// Initiate active open (send the initial SYN). Returns the SYN segment.
    pub fn connect(&mut self) -> Vec<Vec<u8>> {
        if self.state != State::Closed {
            return Vec::new();
        }
        let iss = rand::u32();
        self.send_buf = Some(SendBuf::new(self.cfg.send_buf_size, iss));
        self.recv_buf = Some(RecvBuf::new(0, self.cfg.recv_buf_size));
        self.state = State::SynSent;

        let opts = self.build_syn_options();
        let win = self.rcv_window();
        let syn = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq: iss,
            ack: 0,
            flags: flags::SYN,
            window: win,
            options: opts,
            ..Default::default()
        };
        self.queue_seg(syn);
        self.send_buf.as_mut().unwrap().advance_sent(1); // SYN consumes 1 seq
        self.rto.start_timing(iss);
        self.start_rto();
        self.take_outgoing()
    }

    /// Process an incoming SYN, transition to SYN-RECEIVED, emit SYN-ACK.
    pub fn accept_syn(&mut self, syn: &Segment) -> Vec<Vec<u8>> {
        if self.state != State::Closed && self.state != State::Listen {
            return Vec::new();
        }
        let m = get_mss(&syn.options);
        if m > 0 && m < self.mss {
            self.mss = m;
        }
        self.negotiate_options(&syn.options);

        let iss = rand::u32();
        self.send_buf = Some(SendBuf::new(self.cfg.send_buf_size, iss));
        self.recv_buf = Some(RecvBuf::new(syn.seq.wrapping_add(1), self.cfg.recv_buf_size));
        self.state = State::SynReceived;

        let opts = self.build_syn_options();
        let win = self.rcv_window();
        let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
        let synack = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq: iss,
            ack: rcv_nxt,
            flags: flags::SYN | flags::ACK,
            window: win,
            options: opts,
            ..Default::default()
        };
        self.queue_seg(synack);
        self.send_buf.as_mut().unwrap().advance_sent(1);

        if !syn.payload.is_empty() {
            self.recv_buf
                .as_mut()
                .unwrap()
                .insert(syn.seq.wrapping_add(1), &syn.payload);
        }

        self.start_rto();
        self.take_outgoing()
    }

    /// Skip SYN-RECEIVED and jump straight to ESTABLISHED via a validated
    /// SYN cookie. The handshake is already complete (the SYN-ACK was sent
    /// statelessly by the cookie engine).
    pub fn accept_cookie(
        &mut self,
        remote_seq: u32,
        our_iss: u32,
        mss: u16,
        initial_data: &[u8],
    ) -> Vec<Vec<u8>> {
        if self.state != State::Closed && self.state != State::Listen {
            return Vec::new();
        }
        if mss < self.mss {
            self.mss = mss;
        }
        self.send_buf = Some(SendBuf::new(self.cfg.send_buf_size, our_iss.wrapping_add(1)));
        self.recv_buf = Some(RecvBuf::new(remote_seq, self.cfg.recv_buf_size));
        self.state = State::Established;
        self.signal_established();

        if self.cfg.keepalive {
            self.start_keepalive();
        }

        if !initial_data.is_empty() {
            self.recv_buf.as_mut().unwrap().insert(remote_seq, initial_data);
        }

        self.queue_ack();
        self.take_outgoing()
    }

    // --- Options handling --------------------------------------------------

    fn build_syn_options(&self) -> Vec<TcpOption> {
        let mut opts = Vec::with_capacity(4);
        opts.push(mss_option(self.mss));
        // Always offer wscale; shift=0 is valid and means "I support it".
        opts.push(wscale_option(self.rcv_wnd_shift));
        if self.sack_enabled {
            opts.push(sack_perm_option());
        }
        if self.ts_enabled {
            opts.push(timestamp_option(self.ts_now(), 0));
        }
        opts
    }

    fn negotiate_options(&mut self, remote_opts: &[TcpOption]) {
        if let Some(ws) = get_wscale(remote_opts) {
            self.snd_wnd_shift = ws.min(14);
            self.wscale_ok = true;
        }
        if self.sack_enabled && has_sack_perm(remote_opts) {
            self.sack_ok = true;
        }
        if self.ts_enabled {
            if let Some((ts_val, _)) = get_timestamp(remote_opts) {
                self.ts_recent = ts_val;
                self.ts_ok = true;
            }
        }
    }

    fn add_options(&self, seg: &mut Segment) {
        if self.ts_ok {
            seg.options.push(timestamp_option(self.ts_now(), self.ts_recent));
        }
        if self.sack_ok {
            if let Some(rb) = self.recv_buf.as_ref() {
                if rb.has_ooo() {
                    let blocks = rb.sack_blocks();
                    if !blocks.is_empty() {
                        seg.options.push(sack_option(&blocks));
                    }
                }
            }
        }
    }

    fn ts_now(&self) -> u32 {
        wallclock_ms().wrapping_sub(self.ts_offset_ms) as u32
    }

    /// PAWS validation: drop segments with timestamps older than ts_recent.
    fn update_timestamp(&mut self, opts: &[TcpOption]) -> bool {
        if !self.ts_ok {
            return true;
        }
        let Some((ts_val, _)) = get_timestamp(opts) else {
            return true;
        };
        if self.ts_recent != 0 && (ts_val.wrapping_sub(self.ts_recent) as i32) < 0 {
            return false;
        }
        self.ts_recent = ts_val;
        true
    }

    // --- Outgoing helpers -------------------------------------------------

    fn rcv_window(&self) -> u16 {
        let avail = self
            .recv_buf
            .as_ref()
            .map(|r| r.window() as usize)
            .unwrap_or(self.cfg.recv_buf_size);
        // SWS avoidance (RFC 9293 §3.8.6.2.2 / Clark's algorithm).
        let half = self.cfg.recv_buf_size / 2;
        let sws_thresh = (self.mss as usize).min(half.max(1));
        let mut w = if avail < sws_thresh { 0 } else { avail };
        if self.wscale_ok {
            w >>= self.rcv_wnd_shift;
        }
        if w > 65535 {
            w = 65535;
        }
        w as u16
    }

    fn queue_seg(&mut self, seg: Segment) {
        self.outgoing.push(seg.marshal());
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
    }

    // --- HandleSegment dispatcher (RFC 9293 §3.10.7) ----------------------

    /// Process an inbound segment. Returns any outgoing segments to transmit.
    pub fn handle_segment(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        self.last_recv = Instant::now();
        self.keepalive_sent = 0;

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

    fn segment_acceptable(&self, seg: &Segment) -> bool {
        let Some(rb) = self.recv_buf.as_ref() else {
            return true;
        };
        let rcv_nxt = rb.nxt();
        let mut rcv_wnd = self.cfg.recv_buf_size as u32;
        if rcv_wnd == 0 {
            rcv_wnd = DEFAULT_RECV_BUF as u32;
        }
        let seg_len = seg.seg_len();
        if seg_len == 0 {
            if rcv_wnd == 0 {
                return seg.seq == rcv_nxt;
            }
            return seq_in_range(seg.seq, rcv_nxt, rcv_nxt.wrapping_add(rcv_wnd));
        }
        if rcv_wnd == 0 {
            return false;
        }
        let seg_end = seg.seq.wrapping_add(seg_len.wrapping_sub(1));
        seq_in_range(seg.seq, rcv_nxt, rcv_nxt.wrapping_add(rcv_wnd))
            || seq_in_range(seg_end, rcv_nxt, rcv_nxt.wrapping_add(rcv_wnd))
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
                let rcv_wnd = rb.window();
                if seq_in_range(seg.seq, rcv_nxt, rcv_nxt.wrapping_add(rcv_wnd)) {
                    (false, true)
                } else {
                    (false, false)
                }
            }
        }
    }

    fn handle_synchronized(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        // 1) Sequence number check.
        if !self.segment_acceptable(seg) {
            let syn_rcvd_simopen = self.state == State::SynReceived
                && seg.has_flag(flags::SYN)
                && seg.has_flag(flags::ACK)
                && self.send_buf.as_ref().map(|s| s.nxt() == seg.ack).unwrap_or(false);
            if !syn_rcvd_simopen {
                if !seg.has_flag(flags::RST) {
                    self.queue_ack();
                }
                return self.take_outgoing();
            }
        }

        // 2) RST.
        if seg.has_flag(flags::RST) {
            let (accept, challenge) = self.validate_rst(seg);
            if challenge {
                self.queue_ack();
                return self.take_outgoing();
            }
            if !accept {
                return self.take_outgoing();
            }
            self.tear_down(State::Closed);
            return self.take_outgoing();
        }

        // 4) SYN in a synchronized state ≠ SYN-RECEIVED → challenge ACK.
        if seg.has_flag(flags::SYN) && self.state != State::SynReceived {
            self.queue_ack();
            return self.take_outgoing();
        }

        // 5) ACK required.
        if !seg.has_flag(flags::ACK) {
            return self.take_outgoing();
        }

        match self.state {
            State::SynReceived => self.handle_syn_received(seg),
            State::Established => self.handle_data_state(seg),
            State::FinWait1 => self.handle_data_state(seg),
            State::FinWait2 => self.handle_data_state(seg),
            State::CloseWait => self.handle_close_wait(seg),
            State::Closing => self.handle_closing(seg),
            State::LastAck => self.handle_last_ack(seg),
            State::TimeWait => {
                self.restart_time_wait();
                self.queue_ack();
                self.take_outgoing()
            }
            _ => self.take_outgoing(),
        }
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
        let m = get_mss(&seg.options);
        if m > 0 && m < self.mss {
            self.mss = m;
        }
        self.negotiate_options(&seg.options);

        if seg.has_flag(flags::ACK) {
            // Normal SYN-ACK.
            self.send_buf.as_mut().unwrap().acknowledge(seg.ack);
            self.retries = 0;
            self.stop_rto();
            self.recv_buf = Some(RecvBuf::new(seg.seq.wrapping_add(1), self.cfg.recv_buf_size));
            self.snd_wnd = (seg.window as u32) << self.snd_wnd_shift;
            self.cc = make_cc(self.cfg.congestion, self.mss as u32);
            self.rto.ack_received(seg.ack);
            self.state = State::Established;

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

        // Simultaneous open: bare SYN without ACK.
        self.recv_buf = Some(RecvBuf::new(seg.seq.wrapping_add(1), self.cfg.recv_buf_size));
        self.snd_wnd = (seg.window as u32) << self.snd_wnd_shift;
        self.state = State::SynReceived;
        self.retries = 0;
        self.stop_rto();

        if !seg.payload.is_empty() {
            self.recv_buf
                .as_mut()
                .unwrap()
                .insert(seg.seq.wrapping_add(1), &seg.payload);
        }

        let opts = self.build_syn_options();
        let win = self.rcv_window();
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
        let snd_nxt = self.send_buf.as_ref().unwrap().nxt();
        if seg.ack != snd_nxt {
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
        self.send_buf.as_mut().unwrap().acknowledge(seg.ack);
        self.retries = 0;
        self.stop_rto();
        self.snd_wnd = (seg.window as u32) << self.snd_wnd_shift;
        self.state = State::Established;
        if self.cfg.keepalive {
            self.start_keepalive();
        }
        self.signal_established();
        self.handle_data_state(seg)
    }

    fn handle_data_state(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        let mut need_ack = false;

        if !self.update_timestamp(&seg.options) {
            self.queue_ack();
            return self.take_outgoing();
        }

        if seg.has_flag(flags::ACK) {
            self.process_ack(seg.ack, &seg.options);
            self.snd_wnd = (seg.window as u32) << self.snd_wnd_shift;
        }

        if !seg.payload.is_empty() {
            self.process_data(seg);
            need_ack = true;
        }

        if seg.has_flag(flags::FIN) {
            let fin_seq = seg.seq.wrapping_add(seg.data_len());
            let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
            if fin_seq == rcv_nxt {
                self.recv_buf.as_mut().unwrap().bump_nxt(1);
                need_ack = true;
                self.process_fin_transition();
            } else {
                self.fin_pending = true;
                self.pending_fin_seq = fin_seq;
                need_ack = true;
            }
        } else if self.state == State::FinWait1
            && seg.has_flag(flags::ACK)
            && self.send_buf.as_ref().map(|s| seg.ack == s.nxt()).unwrap_or(false)
        {
            self.state = State::FinWait2;
        }

        if need_ack {
            self.queue_ack();
        }
        self.take_outgoing()
    }

    fn process_fin_transition(&mut self) {
        match self.state {
            State::Established => {
                self.state = State::CloseWait;
                self.signal_fin_recvd();
            }
            State::FinWait1 => {
                let unacked = self.send_buf.as_ref().map(|s| s.unacked()).unwrap_or(0);
                if unacked == 0 {
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

    fn handle_close_wait(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        if seg.has_flag(flags::ACK) {
            self.process_ack(seg.ack, &seg.options);
            self.snd_wnd = (seg.window as u32) << self.snd_wnd_shift;
        }
        self.take_outgoing()
    }

    fn handle_closing(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        let snd_nxt = self.send_buf.as_ref().map(|s| s.nxt()).unwrap_or(0);
        if seg.has_flag(flags::ACK) && seg.ack == snd_nxt {
            self.state = State::TimeWait;
            self.stop_rto();
            self.start_time_wait();
        }
        self.queue_ack();
        self.take_outgoing()
    }

    fn handle_last_ack(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        let snd_nxt = self.send_buf.as_ref().map(|s| s.nxt()).unwrap_or(0);
        if seg.has_flag(flags::ACK) && seg.ack == snd_nxt {
            self.tear_down(State::Closed);
        }
        self.take_outgoing()
    }

    fn process_data(&mut self, seg: &Segment) {
        let n = self.recv_buf.as_mut().unwrap().insert(seg.seq, &seg.payload);

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

    fn process_ack(&mut self, ack: u32, opts: &[TcpOption]) {
        let una = self.send_buf.as_ref().unwrap().una();
        if !seq_after(ack, una) {
            // Duplicate ACK.
            if self.cc.on_dup_ack() {
                let flight = self.send_buf.as_ref().unwrap().unacked() as u32;
                let snd_nxt = self.send_buf.as_ref().unwrap().nxt();
                self.cc.on_fast_retransmit(flight, snd_nxt);
                self.retransmit();
            }
            if self.sack_ok {
                let blocks = get_sack_blocks(opts);
                if !blocks.is_empty() {
                    self.send_buf.as_mut().unwrap().mark_sacked(&blocks);
                }
            }
            return;
        }
        let snd_nxt = self.send_buf.as_ref().unwrap().nxt();
        if seq_after(ack, snd_nxt) {
            self.queue_ack();
            return;
        }

        let acked = self.send_buf.as_mut().unwrap().acknowledge(ack);
        self.retries = 0;
        self.cc.on_ack(acked);

        if self.sack_ok {
            let blocks = get_sack_blocks(opts);
            if !blocks.is_empty() {
                self.send_buf.as_mut().unwrap().mark_sacked(&blocks);
            }
        }

        if self.snd_wnd > 0 && self.persist_deadline.is_some() {
            self.stop_persist();
        }

        self.rto.ack_received(ack);

        if self.cc.in_recovery() && seq_after_eq(ack, self.cc.recovery_seq()) {
            self.cc.exit_recovery();
        }

        if self.send_buf.as_ref().unwrap().unacked() > 0 {
            self.start_rto();
        } else {
            self.stop_rto();
        }

        self.flush_send_queue();
    }

    fn retransmit(&mut self) {
        let data: Vec<u8> = {
            let s = self.send_buf.as_ref().unwrap();
            s.retransmit_data(self.mss as usize).to_vec()
        };
        if data.is_empty() {
            return;
        }
        let una = self.send_buf.as_ref().unwrap().una();
        let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
        let mut seg = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq: una,
            ack: rcv_nxt,
            flags: flags::ACK | flags::PSH,
            window: self.rcv_window(),
            payload: data,
            ..Default::default()
        };
        self.add_options(&mut seg);
        self.queue_seg(seg);
        self.rto.invalidate_timing();
        self.start_rto();
    }

    fn flush_send_queue(&mut self) {
        loop {
            let pending = self.send_buf.as_ref().unwrap().pending();
            if pending == 0 {
                break;
            }
            let mut eff_wnd = self.snd_wnd;
            let cc_wnd = self.cc.send_window();
            if cc_wnd < eff_wnd {
                eff_wnd = cc_wnd;
            }
            let unacked = self.send_buf.as_ref().unwrap().unacked() as u32;
            if eff_wnd <= unacked {
                break;
            }
            let avail = (eff_wnd - unacked) as usize;
            let n = avail.min(self.mss as usize).min(pending);

            // Sender SWS avoidance: avoid tiny segments.
            if n < self.mss as usize && self.send_buf.as_ref().unwrap().unacked() > 0 {
                break;
            }

            let data: Vec<u8> = {
                let s = self.send_buf.as_ref().unwrap();
                let d = s.peek_unsent(n);
                if d.is_empty() {
                    break;
                }
                d.to_vec()
            };

            let snd_nxt = self.send_buf.as_ref().unwrap().nxt();
            let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
            let mut seg = Segment {
                src_port: self.cfg.local_port,
                dst_port: self.cfg.remote_port,
                seq: snd_nxt,
                ack: rcv_nxt,
                flags: flags::ACK | flags::PSH,
                window: self.rcv_window(),
                payload: data.clone(),
                ..Default::default()
            };
            self.add_options(&mut seg);
            self.queue_seg(seg);
            self.send_buf.as_mut().unwrap().advance_sent(data.len());
            self.rto.start_timing(snd_nxt);
            if self.send_buf.as_ref().unwrap().unacked() > 0 && self.rto_deadline.is_none() {
                self.start_rto();
            }
        }

        // Zero-window probing.
        if self.send_buf.as_ref().map(|s| s.pending() > 0).unwrap_or(false)
            && self.snd_wnd == 0
            && self.persist_deadline.is_none()
        {
            self.start_persist();
        }
    }

    // --- Timers (synchronous, deadline-based) -----------------------------

    fn start_rto(&mut self) {
        self.rto_deadline = Some(Instant::now() + self.rto.rto());
    }

    fn stop_rto(&mut self) {
        self.rto_deadline = None;
    }

    fn start_persist(&mut self) {
        if self.persist_backoff == Duration::ZERO {
            self.persist_backoff = self.rto.rto();
        }
        self.persist_deadline = Some(Instant::now() + self.persist_backoff);
    }

    fn stop_persist(&mut self) {
        self.persist_deadline = None;
        self.persist_backoff = Duration::ZERO;
    }

    fn start_time_wait(&mut self) {
        self.stop_keepalive();
        self.stop_persist();
        self.time_wait_deadline = Some(Instant::now() + TIME_WAIT_DURATION);
    }

    fn restart_time_wait(&mut self) {
        if self.time_wait_deadline.is_some() {
            self.time_wait_deadline = Some(Instant::now() + TIME_WAIT_DURATION);
        }
    }

    fn start_keepalive(&mut self) {
        self.stop_keepalive();
        self.stop_persist();
        self.keepalive_deadline = Some(Instant::now() + self.cfg.keepalive_idle);
    }

    fn stop_keepalive(&mut self) {
        self.keepalive_deadline = None;
    }

    /// Drive any expired timers. Call this periodically (e.g. every 100ms).
    /// Returns any segments produced by timer-driven actions.
    pub fn tick(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();

        // RTO.
        if let Some(d) = self.rto_deadline {
            if now >= d && !self.closed && self.state != State::Closed {
                self.on_rto_timeout();
            }
        }
        // Persist.
        if let Some(d) = self.persist_deadline {
            if now >= d && !self.closed && self.state != State::Closed {
                self.on_persist_timeout();
            }
        }
        // TIME-WAIT.
        if let Some(d) = self.time_wait_deadline {
            if now >= d {
                self.time_wait_deadline = None;
                self.state = State::Closed;
                self.closed = true;
            }
        }
        // Keepalive.
        if let Some(d) = self.keepalive_deadline {
            if now >= d && !self.closed && self.state != State::Closed {
                self.on_keepalive();
            }
        }

        self.take_outgoing()
    }

    fn on_rto_timeout(&mut self) {
        self.retries += 1;
        if self.retries > MAX_RETRIES {
            self.tear_down(State::Closed);
            return;
        }
        self.rto.backoff();
        self.rto.invalidate_timing();
        self.cc.on_timeout();

        match self.state {
            State::SynSent => {
                let opts = self.build_syn_options();
                let win = self.rcv_window();
                let una = self.send_buf.as_ref().unwrap().una();
                let syn = Segment {
                    src_port: self.cfg.local_port,
                    dst_port: self.cfg.remote_port,
                    seq: una,
                    flags: flags::SYN,
                    window: win,
                    options: opts,
                    ..Default::default()
                };
                self.queue_seg(syn);
            }
            State::SynReceived => {
                let opts = self.build_syn_options();
                let win = self.rcv_window();
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
            }
            State::Established | State::CloseWait => {
                self.retransmit();
            }
            State::FinWait1 | State::LastAck => {
                // Retransmit FIN. queueFIN advances NXT by 1 — but on retransmit we don't
                // want to advance again. Build it inline.
                let snd_nxt = self.send_buf.as_ref().unwrap().una();
                let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
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
            }
            _ => {}
        }
        self.start_rto();
    }

    fn on_persist_timeout(&mut self) {
        if self.snd_wnd > 0 {
            self.stop_persist();
            self.flush_send_queue();
            return;
        }
        // 1-byte window probe.
        if self.send_buf.as_ref().map(|s| s.pending() > 0).unwrap_or(false) {
            let data: Vec<u8> = self.send_buf.as_ref().unwrap().peek_unsent(1).to_vec();
            if !data.is_empty() {
                let snd_nxt = self.send_buf.as_ref().unwrap().nxt();
                let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
                let seg = Segment {
                    src_port: self.cfg.local_port,
                    dst_port: self.cfg.remote_port,
                    seq: snd_nxt,
                    ack: rcv_nxt,
                    flags: flags::ACK,
                    window: self.rcv_window(),
                    payload: data.clone(),
                    ..Default::default()
                };
                self.queue_seg(seg);
                self.send_buf.as_mut().unwrap().advance_sent(data.len());
            }
        }
        self.persist_backoff = self.persist_backoff.saturating_mul(2);
        if self.persist_backoff > MAX_RTO {
            self.persist_backoff = MAX_RTO;
        }
        self.persist_deadline = Some(Instant::now() + self.persist_backoff);
    }

    fn on_keepalive(&mut self) {
        if self.state != State::Established && self.state != State::CloseWait {
            return;
        }
        if self.last_recv.elapsed() > self.cfg.keepalive_idle {
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
            self.keepalive_deadline = Some(Instant::now() + self.cfg.keepalive_interval);
        } else {
            self.start_keepalive();
        }
    }

    // --- Application I/O --------------------------------------------------

    /// Non-blocking read: copies up to `buf.len()` bytes from the receive
    /// queue into `buf`. Returns the number of bytes read, or `Ok(0)` when
    /// no data is currently available. Use [`fin_received`] / [`is_closed`]
    /// to distinguish "would block" from EOF.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let Some(rb) = self.recv_buf.as_mut() else {
            return 0;
        };
        rb.read(buf)
    }

    /// Non-blocking write: appends as much data as the send buffer can take
    /// (possibly less than `buf.len()`), schedules any sends the window allows,
    /// and returns the byte count accepted alongside any new outgoing segments.
    pub fn write(&mut self, buf: &[u8]) -> (usize, Vec<Vec<u8>>) {
        if self.closed {
            return (0, Vec::new());
        }
        if self.state != State::Established && self.state != State::CloseWait {
            return (0, Vec::new());
        }
        let n = self.send_buf.as_mut().unwrap().write(buf);
        if n > 0 {
            self.flush_send_queue();
        }
        (n, self.take_outgoing())
    }

    /// Initiate graceful close (FIN). Returns any segments produced.
    pub fn close(&mut self) -> Vec<Vec<u8>> {
        if self.closed {
            return Vec::new();
        }
        match self.state {
            State::Established => {
                self.flush_send_queue();
                self.state = State::FinWait1;
                self.queue_fin();
                self.start_rto();
            }
            State::CloseWait => {
                self.state = State::LastAck;
                self.queue_fin();
                self.start_rto();
            }
            State::SynSent => {
                self.tear_down(State::Closed);
            }
            State::SynReceived => {
                self.state = State::FinWait1;
                self.queue_fin();
                self.start_rto();
            }
            State::FinWait1 | State::FinWait2 => {
                // Already closing.
            }
            _ => {
                self.tear_down(State::Closed);
            }
        }
        self.take_outgoing()
    }

    /// Immediate teardown: send RST and mark closed.
    pub fn abort(&mut self) -> Vec<Vec<u8>> {
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
        self.stop_keepalive();
        self.stop_persist();
        self.time_wait_deadline = None;
        if self.closed {
            self.signal_established();
            self.signal_fin_recvd();
        }
    }

    fn signal_established(&mut self) {
        self.established_signaled = true;
    }
    fn signal_fin_recvd(&mut self) {
        self.fin_recvd_signaled = true;
    }
}

// --- Helpers ---------------------------------------------------------------

fn wallclock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// Silence a noisy lint on `seq_in_range` not currently exercised; the helper
// is part of the public seqspace surface and intentionally re-exported.
#[allow(dead_code)]
fn _options_export_is_used(_o: &TcpOption) {
    let _ = options::kind::End;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(local: u16, remote: u16) -> ConnConfig {
        ConnConfig {
            local_port: local,
            remote_port: remote,
            mss: 1460,
            send_buf_size: 4096,
            recv_buf_size: 4096,
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
}
