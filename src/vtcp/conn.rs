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

use crate::time::Instant;
use std::net::SocketAddr;
use std::time::Duration;

use crate::rand;

use super::congestion::{CongestionController, HighSpeed, NewReno};
use super::options::{
    self, TcpOption, get_mss, get_sack_blocks, get_timestamp, get_wscale, has_sack_perm,
    mss_option, sack_option, sack_perm_option, timestamp_option, wscale_option,
};
use super::recvbuf::RecvBuf;
use super::rto::{MAX_RTO, RtoState};
use super::segment::{Segment, flags};
use super::sendbuf::SendBuf;
use super::seqspace::{
    seq_after, seq_after_eq, seq_before, seq_before_eq, seq_in_range, seq_in_range_inclusive,
};

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
#[non_exhaustive]
pub struct ConnConfig {
    pub local_addr: std::option::Option<SocketAddr>,
    pub remote_addr: std::option::Option<SocketAddr>,
    pub local_port: u16,
    pub remote_port: u16,
    pub mss: u16,
    pub no_window_scaling: bool,
    pub enable_timestamps: bool,
    /// Offer SACK (RFC 2018); used only if the peer offers it too. On by
    /// default: without it a receiver can only report the first hole in the
    /// stream, and a sender repairs one hole per round trip.
    pub enable_sack: bool,
    pub congestion: CongestionKind,
    pub keepalive: bool,
    pub keepalive_idle: Duration,
    pub keepalive_interval: Duration,
    pub keepalive_count: u32,
    pub send_buf_size: usize,
    pub recv_buf_size: usize,
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
        set keepalive: bool;
        set keepalive_idle: Duration;
        set keepalive_interval: Duration;
        set keepalive_count: u32;
        set send_buf_size: usize;
        set recv_buf_size: usize;
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
            enable_timestamps: false,
            enable_sack: true,
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
    /// SND.NXT when the last RTO fired, while data sent before it is still
    /// unacknowledged. ACKs short of it are partial: each one retransmits the
    /// next hole (RFC 6582 §3.2 applied to timeout recovery), where the
    /// cumulative ACK alone would leave every hole to its own timeout.
    rto_recover: std::option::Option<u32>,

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

    // SND.WL1 / SND.WL2: SEQ and ACK of the segment that last set snd_wnd.
    snd_wl: Option<(u32, u32)>,

    // Right edge of the receive window as last advertised (RCV.NXT +
    // RCV.WND), once an ACK has carried one.
    rcv_adv: Option<u32>,

    // Deferred FIN.
    fin_pending: bool,
    pending_fin_seq: u32,

    // Our own FIN. close() only queues it: it goes out once every byte
    // written before it has been sent, since the FIN takes the sequence
    // number right after the last data byte.
    fin_queued: bool,
    fin_sent: bool,

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
            rto_recover: None,
            snd_wnd_shift: 0,
            rcv_wnd_shift: rcv_shift,
            wscale_ok: false,
            ts_enabled: cfg.enable_timestamps,
            ts_ok: false,
            ts_recent: 0,
            ts_offset_ms,
            sack_enabled: cfg.enable_sack,
            sack_ok: false,
            snd_wl: None,
            rcv_adv: None,
            fin_pending: false,
            pending_fin_seq: 0,
            fin_queued: false,
            fin_sent: false,
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
        let win = self.syn_window();
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
        self.recv_buf = Some(RecvBuf::new(
            syn.seq.wrapping_add(1),
            self.cfg.recv_buf_size,
        ));
        self.state = State::SynReceived;

        let opts = self.build_syn_options();
        let win = self.syn_window();
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
        self.send_buf = Some(SendBuf::new(
            self.cfg.send_buf_size,
            our_iss.wrapping_add(1),
        ));
        self.recv_buf = Some(RecvBuf::new(remote_seq, self.cfg.recv_buf_size));
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
        if self.ts_enabled
            && let Some((ts_val, _)) = get_timestamp(remote_opts)
        {
            self.ts_recent = ts_val;
            self.ts_ok = true;
        }
    }

    fn add_options(&self, seg: &mut Segment) {
        if self.ts_ok {
            seg.options
                .push(timestamp_option(self.ts_now(), self.ts_recent));
        }
        if self.sack_ok
            && let Some(rb) = self.recv_buf.as_ref()
            && rb.has_ooo()
        {
            let blocks = rb.sack_blocks();
            if !blocks.is_empty() {
                seg.options.push(sack_option(&blocks));
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

    fn sws_thresh(&self) -> u32 {
        let half = self.cfg.recv_buf_size / 2;
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
            w >>= self.rcv_wnd_shift;
        }
        w.min(65535) as u16
    }

    /// Window for a SYN or SYN-ACK, which is never scaled (RFC 7323 §2.2).
    fn syn_window(&self) -> u16 {
        self.rcv_wnd_bytes().min(65535) as u16
    }

    fn queue_seg(&mut self, seg: Segment) {
        if seg.has_flag(flags::ACK) && self.recv_buf.is_some() {
            let shift = if seg.has_flag(flags::SYN) || !self.wscale_ok {
                0
            } else {
                self.rcv_wnd_shift
            };
            let edge = seg.ack.wrapping_add((seg.window as u32) << shift);
            if self.rcv_adv.is_none_or(|adv| seq_after(edge, adv)) {
                self.rcv_adv = Some(edge);
            }
        }
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
        // What we advertised, or more if a read has freed room since.
        let advertised = self
            .rcv_adv
            .filter(|&adv| seq_after(adv, rcv_nxt))
            .map_or(0, |adv| adv.wrapping_sub(rcv_nxt));
        let rcv_wnd = advertised.max(rb.window());
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
            // A bare FIN at RCV.NXT takes no buffer space; refusing it would
            // leave a peer unable to close to a reader that has stopped
            // reading (Linux accepts it too).
            return seg.payload.is_empty() && seg.seq == rcv_nxt;
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

    fn resend_syn_ack(&mut self) {
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
            self.resend_syn_ack();
            return self.take_outgoing();
        }

        // 1) Sequence number check.
        if !self.segment_acceptable(seg) {
            let syn_rcvd_simopen = self.state == State::SynReceived
                && seg.has_flag(flags::SYN)
                && seg.has_flag(flags::ACK)
                && self
                    .send_buf
                    .as_ref()
                    .map(|s| s.nxt() == seg.ack)
                    .unwrap_or(false);
            if !syn_rcvd_simopen {
                if !seg.has_flag(flags::RST) {
                    if self.state == State::TimeWait && seg.has_flag(flags::FIN) {
                        self.restart_time_wait();
                    }
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
            self.recv_buf = Some(RecvBuf::new(
                seg.seq.wrapping_add(1),
                self.cfg.recv_buf_size,
            ));
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
        self.recv_buf = Some(RecvBuf::new(
            seg.seq.wrapping_add(1),
            self.cfg.recv_buf_size,
        ));
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
        if self.fin_queued {
            self.state = State::FinWait1;
            self.flush_send_queue();
        }
        self.handle_data_state(seg)
    }

    fn handle_data_state(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        let mut need_ack = false;

        if !self.update_timestamp(&seg.options) {
            self.queue_ack();
            return self.take_outgoing();
        }

        if seg.has_flag(flags::ACK) {
            self.process_ack(seg);
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
        } else if self.state == State::FinWait1 && self.fin_acked() {
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

    fn handle_close_wait(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        if seg.has_flag(flags::ACK) {
            self.process_ack(seg);
        }
        self.take_outgoing()
    }

    fn handle_closing(&mut self, seg: &Segment) -> Vec<Vec<u8>> {
        // Data and the FIN may still be in flight (or not yet sent), so ACKs
        // here need the full treatment, not just a check for the FIN's.
        if seg.has_flag(flags::ACK) {
            self.process_ack(seg);
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
        if seg.has_flag(flags::ACK) {
            self.process_ack(seg);
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
        self.snd_wnd = wnd;
        changed
    }

    fn process_ack(&mut self, seg: &Segment) {
        let ack = seg.ack;
        let opts = &seg.options;
        let una = self.send_buf.as_ref().unwrap().una();
        let snd_nxt = self.send_buf.as_ref().unwrap().nxt();
        if seq_after(ack, snd_nxt) {
            self.queue_ack();
            return;
        }
        // The window comes first: the flush below must see this segment's.
        let wnd_changed = self.update_send_window(seg);
        if !seq_after(ack, una) {
            // RFC 5681 §2: only an ACK of SND.UNA with data outstanding, no
            // payload or FIN, and the same window is a duplicate. A window
            // update is not a loss signal, and its window must be used.
            if ack == una
                && una != snd_nxt
                && !wnd_changed
                && seg.payload.is_empty()
                && !seg.has_flag(flags::FIN)
                && self.cc.on_dup_ack()
            {
                let flight = self.send_buf.as_ref().unwrap().unacked() as u32;
                self.cc.on_fast_retransmit(flight, snd_nxt);
                let _ = self.retransmit();
            }
            if self.sack_ok {
                let blocks = get_sack_blocks(opts);
                if !blocks.is_empty() {
                    self.send_buf.as_mut().unwrap().mark_sacked(&blocks);
                }
            }
            if wnd_changed {
                if self.snd_wnd > 0 && self.persist_deadline.is_some() {
                    self.stop_persist();
                }
                self.flush_send_queue();
            }
            return;
        }

        let acked = self.send_buf.as_mut().unwrap().acknowledge(ack);
        self.retries = 0;
        // An ACK short of the recovery point means the segment after it was
        // lost too. Resend it now; waiting would cost an RTO per hole.
        let fast_partial = self.cc.in_recovery() && seq_before(ack, self.cc.recovery_seq());
        let rto_partial = match self.rto_recover {
            Some(r) if seq_before(ack, r) => true,
            Some(_) => {
                self.rto_recover = None;
                false
            }
            None => false,
        };
        if fast_partial {
            self.cc.on_partial_ack(acked);
        } else {
            // After a timeout this is slow start, which a partial ACK
            // should keep growing.
            self.cc.on_ack(acked);
        }

        if self.sack_ok {
            let blocks = get_sack_blocks(opts);
            if !blocks.is_empty() {
                self.send_buf.as_mut().unwrap().mark_sacked(&blocks);
            }
        }
        if fast_partial || rto_partial {
            let _ = self.retransmit();
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

    /// Resend the oldest unacknowledged data. Returns false when there is
    /// none (at most the FIN is outstanding).
    fn retransmit(&mut self) -> bool {
        let Some((seq, data)) = self
            .send_buf
            .as_ref()
            .unwrap()
            .retransmit_data(self.mss as usize)
            .map(|(seq, d)| (seq, d.to_vec()))
        else {
            return false;
        };
        let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
        let mut seg = Segment {
            src_port: self.cfg.local_port,
            dst_port: self.cfg.remote_port,
            seq,
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
        true
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

            // Sender SWS avoidance: avoid tiny segments. Once closing, nothing
            // more will be written to coalesce with, so send what there is.
            if n < self.mss as usize
                && self.send_buf.as_ref().unwrap().unacked() > 0
                && !self.fin_queued
            {
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
        }
        // Keepalive.
        if let Some(d) = self.keepalive_deadline
            && now >= d
            && !self.closed
            && self.state != State::Closed
        {
            self.on_keepalive();
        }

        self.take_outgoing()
    }

    fn on_rto_timeout(&mut self) {
        if self.snd_wnd == 0 && !matches!(self.state, State::SynSent | State::SynReceived) {
            // The receiver closed its window under data in flight, so our
            // retransmits are really zero-window probes and its duplicate
            // ACKs never count as progress. Keep going while it answers, as
            // Linux does; give up only once it has gone quiet.
            if self.last_recv.elapsed() > MAX_RTO {
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
        self.cc.on_timeout();
        if let Some(sb) = self.send_buf.as_mut() {
            sb.clear_sacked();
            if sb.unacked() > 0 {
                self.rto_recover = Some(sb.nxt());
            }
        }

        match self.state {
            State::SynSent => {
                let opts = self.build_syn_options();
                let win = self.syn_window();
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
            State::SynReceived => self.resend_syn_ack(),
            State::Established
            | State::CloseWait
            | State::FinWait1
            | State::Closing
            | State::LastAck => {
                // Data before the FIN goes first; the FIN is resent on its own
                // once only it is outstanding.
                let resent = self.retransmit();
                if !resent && self.fin_sent && !self.fin_acked() {
                    // queue_fin advances NXT by 1, which a retransmit must not do.
                    let fin_seq = self.send_buf.as_ref().unwrap().nxt().wrapping_sub(1);
                    let rcv_nxt = self.recv_buf.as_ref().unwrap().nxt();
                    let mut seg = Segment {
                        src_port: self.cfg.local_port,
                        dst_port: self.cfg.remote_port,
                        seq: fin_seq,
                        ack: rcv_nxt,
                        flags: flags::FIN | flags::ACK,
                        window: self.rcv_window(),
                        ..Default::default()
                    };
                    self.add_options(&mut seg);
                    self.queue_seg(seg);
                }
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
        // 1-byte window probe.
        if self
            .send_buf
            .as_ref()
            .map(|s| s.pending() > 0)
            .unwrap_or(false)
        {
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
                // The probe byte is real data: if it or its ACK is lost, only
                // the RTO will send it again.
                if self.rto_deadline.is_none() {
                    self.start_rto();
                }
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
    /// no data is currently available. Use [`Conn::fin_received`] / [`Conn::is_closed`]
    /// to distinguish "would block" from EOF.
    ///
    /// A read that opens the receive window well past what was advertised
    /// queues a window update, sent with the next [`Conn::tick`] or
    /// [`Conn::take_outgoing`]; without it a peer facing a closed window
    /// would wait on its persist timer.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let Some(rb) = self.recv_buf.as_mut() else {
            return 0;
        };
        let n = rb.read(buf);
        let nxt = rb.nxt();
        let remaining = self
            .rcv_adv
            .filter(|&adv| seq_after(adv, nxt))
            .map_or(0, |adv| adv.wrapping_sub(nxt));
        // The same test as Linux's tcp_cleanup_rbuf: worth a segment once
        // the window at least doubles.
        let open = self.rcv_wnd_bytes();
        if n > 0
            && open > remaining
            && open >= remaining.saturating_mul(2)
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
    crate::time::unix_now().as_millis() as u64
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

    fn fire_rto(c: &mut Conn) -> Vec<Vec<u8>> {
        assert!(c.rto_deadline.is_some(), "RTO not armed");
        c.rto_deadline = Some(Instant::now());
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

    // A zero-window probe carries the last byte before the FIN. If the
    // probe's ACK is lost, the RTO has to resend it: the persist timer has
    // no unsent data left to probe with.
    #[test]
    fn lost_ack_of_last_probe_byte_is_recovered() {
        let (mut client, mut server) = established(40016);
        client.snd_wnd = 0;
        let (_, none) = client.write(b"x");
        assert!(none.is_empty());
        assert!(client.close().is_empty());

        client.persist_deadline = Some(Instant::now());
        let probe = client.tick();
        assert_eq!(probe.len(), 1);
        assert_eq!(parse(&probe[0]).payload, b"x");
        let _lost_ack = deliver(&mut server, &probe);

        // Persist has nothing left to send; the RTO resends the byte.
        client.persist_deadline = client.persist_deadline.map(|_| Instant::now());
        assert!(client.tick().is_empty());
        let re = fire_rto(&mut client);
        assert_eq!(parse(&re[0]).payload, b"x");

        let ack = deliver(&mut server, &re);
        let fin = deliver(&mut client, &ack);
        assert!(parse(&fin[0]).has_flag(flags::FIN));
        deliver(&mut server, &fin);
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
        let seg = parse(&edge_ack[0]);
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

        // A peer silent for longer than MAX_RTO is gone after all.
        client.last_recv = Instant::now() - MAX_RTO - Duration::from_secs(1);
        fire_rto(&mut client);
        assert!(client.is_closed());
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
        let small = |port| {
            let mut c = cfg(port, 80);
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
                    let struggling = sides.iter().any(|s| s.conn.retries >= MAX_RETRIES / 2);
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
                    let c = &mut sides[i].conn;
                    let now = Instant::now();
                    if c.rto_deadline.is_some() {
                        c.rto_deadline = Some(now);
                    }
                    if c.persist_deadline.is_some() {
                        c.persist_deadline = Some(now);
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

    #[test]
    fn partial_ack_retransmits_next_hole() {
        partial_ack_run(false);
    }

    #[test]
    fn partial_ack_retransmits_next_hole_with_sack() {
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
}
