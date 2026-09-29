//! Outbound (virtual→real) TCP NAT, backed by [`vtcp::Conn`].
//!
//! When a virtual client opens a TCP connection to a *real* destination, the
//! stack dials a real OS [`TcpStream`] to the destination on a background
//! thread and, once it connects, passively terminates the virtual side with a
//! server-side [`vtcp::Conn`] (via `accept_syn`). This mirrors Go's `tcpNATConn`, which
//! bridges a `vtcp.Conn` (facing the virtual client) to a real `net.Conn`
//! (facing the server) with `io.Copy` in both directions.
//!
//! The virtual side reuses the exact same machinery as the inbound accept path
//! ([`ConnState`]): inbound segments are fed via [`ConnState::deliver`],
//! outbound segments are wrapped back into IP and pushed into the virtual
//! network, and the stack's tick thread drives RTO / persist / keepalive /
//! TIME-WAIT timers. Two background threads form the byte pump, started only
//! once the client has ACKed our SYN-ACK (within [`HANDSHAKE_TIMEOUT`]):
//!
//! - **remote→client**: read from the real socket, `Conn::write` the bytes
//!   (blocking on the send window via the shared `Condvar`), and flush the
//!   resulting segments. On EOF, `Conn::close()` sends a FIN to the client;
//!   on a reset from the server, the client is reset too.
//! - **client→remote**: `Conn::read` data delivered by the engine (blocking on
//!   the same `Condvar`) and `write_all` it to the real socket. When the client
//!   half-closes (FIN), the real socket's write side is shut down.
//!
//! Unlike the old hand-rolled engine, this inherits vtcp's out-of-order
//! reassembly, SACK, window scaling, and congestion control on the virtual
//! side.

use crate::Result;
use crate::slirp::tcp_stream::{ConnState, Endpoints};
use crate::time::Instant;
use crate::vtcp::ecn::IpEcn;
use crate::vtcp::fastopen::Gate;
use crate::vtcp::segment::Segment;
use crate::vtcp::{Conn, ConnConfig, State, Tuning};

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// How long to wait for the real destination to accept. Well under the OS's
/// own connect timeout (75 s to over two minutes), and still longer than a
/// client usually keeps retransmitting its SYN.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Initial send and receive buffer of the virtual side of each bridge.
/// When the guest is in-process its round trip is short and a window this
/// size keeps it full; the engine's 1 MiB default would let a guest that
/// stops reading, or sends to a server that does, pin 2 MiB per bridge: 8
/// GiB over the 2048 bridges of each address family.
///
/// A guest further away (behind a VPN, say) needs more, so the buffers
/// auto-tune from here up to the engine's default maximum. They grow only
/// while data moves at a rate that needs them, and what all connections grow
/// by together is bounded process-wide: however many bridges a guest grows
/// and then stalls, they hold this much each, plus that bound in all.
const BRIDGE_BUF: usize = 256 * 1024;

/// Longest a pump waits on the virtual side before looking again, although
/// every change it waits for (data, window, FIN, close) wakes it: only a
/// backstop, so that the thousands of pumps a stack may run do not each
/// wake ten times a second to find nothing new.
const PUMP_BACKSTOP: Duration = Duration::from_secs(5);

/// How long the client has to ACK our SYN-ACK once the destination has
/// accepted, as for the inbound handshakes of a listener. Until then the
/// bridge holds a real connection to a third party on the client's behalf,
/// and vtcp's own SYN-ACK retransmissions would keep it for minutes: a client
/// that never ACKs could otherwise hold every outbound slot, and as many
/// host connections, with a trickle of SYNs.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A live outbound TCP NAT bridge: a server-side `vtcp::Conn` facing the
/// virtual client, glued to a real OS [`TcpStream`] facing the destination.
pub(crate) struct TcpOutConn {
    /// Virtual-side connection state (shared with the byte-pump threads and the
    /// stack's tick thread). Reuses the inbound accept-path machinery.
    state: Arc<ConnState>,
    /// Real upstream socket, set once the dial succeeds. The client→remote
    /// pump writes through a clone of the `Arc` taken under the lock and
    /// written without it, so `close` can still shut the socket down from
    /// another thread: a shutdown is exactly what unblocks a write stuck on a
    /// peer that stopped reading. The read half was cloned out for the
    /// remote→client pump thread. Taken out (closing the descriptor) once the
    /// bridge reaches TIME-WAIT, where nothing needs it any more.
    pub(super) remote: Mutex<Option<Arc<TcpStream>>>,
    /// Set once the bridge has been torn down (RST/abort or both-ways close).
    closed: Arc<AtomicBool>,
    /// The client's SYN, kept while the real destination is being dialed and
    /// taken once the dial finishes.
    syn: Mutex<Option<Segment>>,
    /// The IP-ECN codepoint the SYN arrived with, for the SYN-ACK.
    syn_ecn: IpEcn,
    /// When the stack's tick first saw the virtual side in TIME-WAIT; the
    /// oldest go first when there are too many.
    time_wait_since: OnceLock<Instant>,
    /// Called if the bridge goes while its dial is still running; taken
    /// once the dial finishes.
    on_orphan: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// From the SYN-ACK until the client's ACK: the read half of the real
    /// socket, waiting for the pumps, and the deadline for that ACK. The
    /// pumps (two threads and their buffers) start only once the client
    /// has completed the handshake, so a client that never does costs no
    /// thread; taken by whichever comes first, the ACK or the deadline.
    handshake: Mutex<Option<(Instant, TcpStream)>>,
}

impl TcpOutConn {
    /// Take the virtual client's SYN for a real destination, without answering
    /// it yet. The SYN-ACK goes out only once [`start_dial`](Self::start_dial)
    /// has reached the destination, so the client sees the real outcome:
    /// a handshake if the destination accepted, a RST if it refused.
    ///
    /// The caller registers the bridge in its connection table before calling
    /// `start_dial`, so that neither the client's retransmitted SYNs nor its
    /// ACK of the SYN-ACK can miss it and draw a spurious RST.
    ///
    /// The virtual side takes `tuning`; with Fast Open, data from the SYN
    /// counts at `gate` until the handshake completes.
    pub(crate) fn pending(
        endpoints: Endpoints,
        syn: &Segment,
        syn_ecn: IpEcn,
        mss: u16,
        tuning: &Tuning,
        gate: Option<Arc<Gate>>,
        sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    ) -> Arc<TcpOutConn> {
        let (local_addr, remote_addr, local_port, remote_port) = match endpoints {
            Endpoints::V4 {
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            } => (
                SocketAddr::new(IpAddr::V4(local_ip), local_port),
                SocketAddr::new(IpAddr::V4(remote_ip), remote_port),
                local_port,
                remote_port,
            ),
            Endpoints::V6 {
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            } => (
                SocketAddr::new(IpAddr::V6(local_ip), local_port),
                SocketAddr::new(IpAddr::V6(remote_ip), remote_port),
                local_port,
                remote_port,
            ),
        };

        let cfg = ConnConfig {
            local_addr: Some(local_addr),
            remote_addr: Some(remote_addr),
            local_port,
            remote_port,
            mss,
            keepalive: true,
            // Whether to hold small writes back is the host application's
            // call, made on its own socket (TCP_NODELAY or not) and already
            // applied by the host kernel: the pump passes on each read as
            // it arrives. Nagle here would add a round trip to the guest on
            // top, for every small write sent with data in flight, which an
            // application that set TCP_NODELAY asked not to wait.
            nodelay: true,
            send_buf_size: BRIDGE_BUF,
            recv_buf_size: BRIDGE_BUF,
            ..Default::default()
        };
        let mut conn = Conn::new(tuning.apply(cfg));
        conn.set_fast_open_gate(gate, false);

        Arc::new(TcpOutConn {
            state: ConnState::new(endpoints, conn, sink),
            remote: Mutex::new(None),
            closed: Arc::new(AtomicBool::new(false)),
            syn: Mutex::new(Some(syn.clone())),
            syn_ecn,
            time_wait_since: OnceLock::new(),
            on_orphan: Mutex::new(None),
            handshake: Mutex::new(None),
        })
    }

    /// Dial `dest` on a thread of its own and, once it answers, answer the
    /// client's SYN; the byte pumps start once the client ACKs. `on_done` runs when the
    /// dial has finished either way; `on_orphan` runs before that if the
    /// bridge is torn down (the guest reset it, say) while the dial is still
    /// running, as nothing waits on the dial from then on.
    ///
    /// The dial must not run on the caller's thread: that is the packet path,
    /// and a destination that drops SYNs would stall every other flow of the
    /// stack for as long as the OS keeps retrying the connect.
    pub(crate) fn start_dial(
        self: &Arc<Self>,
        dest: SocketAddr,
        on_orphan: impl FnOnce() + Send + 'static,
        on_done: impl FnOnce() + Send + 'static,
    ) {
        *self.on_orphan.lock().expect("poisoned") = Some(Box::new(on_orphan));
        // Torn down before the hook was in place: nothing else will call it.
        if self.closed.load(Ordering::SeqCst) {
            self.orphan_dial();
        }
        let bridge = self.clone();
        // Runs `on_done` however the dial ends, even if its thread never
        // starts: a failed spawn drops the closure, and with it this guard.
        let done = OnDrop(Some(on_done));
        let spawned = super::spawn_flow_thread(move || {
            let _done = done;
            let res = TcpStream::connect_timeout(&dest, CONNECT_TIMEOUT)
                .and_then(|s| s.try_clone().map(|r| (s, r)));
            bridge.finish_dial(res);
        });
        if let Err(e) = spawned {
            // Refuse the client as for an unreachable destination.
            self.clone().finish_dial(Err(e));
        }
    }

    fn finish_dial(self: Arc<Self>, res: std::io::Result<(TcpStream, TcpStream)>) {
        // The dial is over: its place is given back as it returns, orphaned
        // or not.
        drop(self.on_orphan.lock().expect("poisoned").take());
        // The SYN stays in place until the engine has taken it: while it is
        // there, handle_segment holds back the client's segments, and a
        // retransmitted SYN reaching the engine before accept_syn would draw
        // a RST, as would a RST from the client go unheard.
        let mut pending = self.syn.lock().expect("poisoned");
        let Some(syn) = pending.as_ref() else {
            return;
        };
        if self.closed.load(Ordering::SeqCst) {
            *pending = None;
            return; // torn down while dialing; dropping `res` closes the socket
        }
        let (remote, remote_read) = match res {
            Ok(pair) => pair,
            Err(_) => {
                // Refused / unreachable / timed out: RST+ACK so the client
                // doesn't hang.
                let (local_port, remote_port) = self.state.endpoints.ports();
                let rst = build_refused_rst(remote_port, local_port, syn.seq);
                self.closed.store(true, Ordering::SeqCst);
                *pending = None;
                // Not under the lock: the sink may answer synchronously.
                drop(pending);
                self.state.send(vec![rst]);
                return;
            }
        };
        *self.remote.lock().expect("poisoned") = Some(Arc::new(remote));
        // close() sets `closed` before it shuts the socket down, so either it
        // sees the socket stored above or this sees the flag.
        if self.closed.load(Ordering::SeqCst) {
            *pending = None;
            drop(pending);
            self.shutdown_remote(Shutdown::Both);
            return;
        }
        // In place before the SYN-ACK goes out: the client's ACK may come
        // back through the sink before `emit` even returns. (Harmless
        // before the engine has the SYN: only a synchronized connection
        // starts the pumps, and the deadline is far off.)
        *self.handshake.lock().expect("poisoned") =
            Some((Instant::now() + HANDSHAKE_TIMEOUT, remote_read));
        let mut conn = self.state.conn.lock().expect("poisoned");
        let synack = conn.accept_syn_ecn(syn, self.syn_ecn);
        *pending = None;
        drop(pending);
        self.state.emit(conn, synack);
        // Fast Open data in the SYN goes to the server now, and its answer
        // may come back before the client's ACK.
        self.start_pumps();
    }

    /// Start the byte pumps if the client has just completed the handshake,
    /// or sent data the engine took from its SYN (Fast Open).
    fn start_pumps(self: &Arc<Self>) {
        let remote_read = {
            let mut hs = self.handshake.lock().expect("poisoned");
            // Checked and taken under the lock the deadline is taken under
            // too, so exactly one of the ACK and the deadline gets it.
            let up = {
                let conn = self.state.conn.lock().expect("poisoned");
                conn.state().is_synchronized() || conn.fast_open_accepted()
            };
            if hs.is_none() || !up {
                return;
            }
            hs.take().expect("checked above").1
        };
        if self.closed.load(Ordering::SeqCst) {
            return; // torn down meanwhile; dropping the half closes it
        }
        // remote → client: real socket bytes become vtcp writes (→ segments).
        let b_r = self.clone();
        let reader = super::spawn_flow_thread(move || b_r.pump_remote_to_client(remote_read));
        // client → remote: vtcp-delivered bytes are written to the real socket.
        let b_w = self.clone();
        if reader.is_err() || super::spawn_flow_thread(move || b_w.pump_client_to_remote()).is_err()
        {
            // Out of threads: a bridge with half its pumps would stall, so
            // reset both sides instead.
            self.close();
        }
    }

    /// Whether the client has let the handshake run past its deadline
    /// (as of `now`). Once this has said so, the ACK can no longer start the
    /// pumps, and the caller should [`close`](Self::close) the bridge.
    pub(crate) fn handshake_expired(&self, now: Instant) -> bool {
        let mut hs = self.handshake.lock().expect("poisoned");
        let due = hs.as_ref().is_some_and(|(deadline, _)| now >= *deadline);
        // An ACK that has completed the handshake but not yet started the
        // pumps wins: the connection is up, and resetting it would lose it.
        if !due
            || self
                .state
                .conn
                .lock()
                .expect("poisoned")
                .state()
                .is_synchronized()
        {
            return false;
        }
        hs.take();
        true
    }

    /// Feed an inbound TCP segment from the virtual client, which arrived
    /// with IP-ECN codepoint `ecn`, into the engine and transmit its
    /// replies. (Called from the stack's packet dispatch path.)
    pub(crate) fn handle_segment(self: &Arc<Self>, tcp: &[u8], ecn: IpEcn) -> Result<()> {
        let Ok(seg) = Segment::parse(tcp) else {
            return Ok(());
        };
        let dialing = self.syn.lock().expect("poisoned").is_some();
        if dialing {
            // Nothing to answer yet: retransmitted SYNs wait for the dial. A
            // RST means the client gave up, so the dial's result is moot.
            if seg.has_flag(crate::vtcp::segment::flags::RST) {
                self.closed.store(true, Ordering::SeqCst);
                self.orphan_dial();
            }
            return Ok(());
        }
        self.state.deliver_ecn(&seg, ecn);
        self.start_pumps();
        Ok(())
    }

    /// The shared connection state, so the stack's tick thread can drive timers.
    pub(crate) fn state(&self) -> &Arc<ConnState> {
        &self.state
    }

    /// If the virtual side is in TIME-WAIT, since when (first asked at
    /// `now`).
    pub(crate) fn time_wait_since(&self, now: Instant) -> Option<Instant> {
        if self.state.conn.lock().expect("poisoned").state() != State::TimeWait {
            return None;
        }
        Some(*self.time_wait_since.get_or_init(|| {
            // Both sides have finished, so the real socket is done with.
            // Holding it for the whole of TIME-WAIT would let a guest keep
            // a host descriptor open per parked bridge (up to MAX_TIME_WAIT
            // per family), enough to run the process out of them.
            //
            // Shut down, not merely dropped: the client→remote pump may be
            // blocked writing, through its own clone, to a server that
            // stopped reading. Dropping our handle would close nothing, and
            // leave `close` nothing to shut down: the pump, its thread and
            // the descriptor would stay stuck for good. A TIME-WAIT bridge
            // holds no thread, so the bytes the server never took are lost,
            // as they are whenever a bridge is torn down.
            if let Some(s) = self.remote.lock().expect("poisoned").take() {
                shutdown(&s, Shutdown::Both);
            }
            now
        }))
    }

    /// True once the bridge has fully torn down.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.state.conn.lock().expect("poisoned").is_closed()
    }

    /// Tell the dial, if one is still running, that nothing waits on it.
    fn orphan_dial(&self) {
        let f = self.on_orphan.lock().expect("poisoned").take();
        if let Some(f) = f {
            f();
        }
    }

    /// Forcibly tear the bridge down: RST the virtual client and close the real
    /// socket. Called by `Stack::shutdown` and namespace cleanup.
    pub(crate) fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.orphan_dial();
        let mut conn = self.state.conn.lock().expect("poisoned");
        // In TIME-WAIT both sides have already finished; a RST would only
        // reach a peer that has moved on.
        let finished = conn.state() == State::TimeWait;
        let segs = conn.abort();
        self.state
            .emit(conn, if finished { Vec::new() } else { segs });
        self.state.signal.notify_all();
        self.shutdown_remote(Shutdown::Both);
    }

    /// Shut down the real socket (or a half of it). Tolerates a missing socket.
    fn shutdown_remote(&self, how: Shutdown) {
        let s = self.remote.lock().expect("poisoned").clone();
        if let Some(s) = s {
            shutdown(&s, how);
        }
    }

    /// remote→client pump: copy bytes from the real socket into the engine's
    /// send buffer, blocking on the send window when it is full. On EOF,
    /// gracefully close the virtual side (FIN); on a reset or other error,
    /// reset it and tear the bridge down.
    fn pump_remote_to_client(self: Arc<Self>, mut remote_read: TcpStream) {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            let n = match remote_read.read(&mut buf) {
                Ok(0) => break, // remote EOF
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => {
                    // The server reset the connection (or it failed some
                    // other way): the stream did not end whole, so the
                    // client gets a reset too. A FIN would pass what it
                    // has received off as the entire transfer.
                    self.close();
                    return;
                }
            };
            if !self.write_all_to_engine(&buf[..n]) {
                // Virtual side closed underneath us; abandon.
                self.teardown_remote_read();
                return;
            }
        }
        // Remote closed: send FIN to the client.
        let mut conn = self.state.conn.lock().expect("poisoned");
        let segs = conn.close();
        self.state.emit(conn, segs);
        self.state.signal.notify_all();
        // Don't slam the real socket shut here — the client→remote pump may
        // still be draining bytes the client sent. The bridge is reaped once
        // vtcp reaches CLOSED.
    }

    /// Write `data` into the engine's send buffer in full, flushing produced
    /// segments. Blocks on the `Condvar` while the send window is closed.
    /// Returns `false` if the connection closed before all bytes were accepted.
    fn write_all_to_engine(&self, mut data: &[u8]) -> bool {
        while !data.is_empty() {
            if self.closed.load(Ordering::Acquire) {
                return false;
            }
            let mut conn = self.state.conn.lock().expect("poisoned");
            if conn.is_closed() {
                return false;
            }
            let (n, segs) = conn.write(data);
            self.state.emit(conn, segs);
            if n > 0 {
                self.state.signal.notify_all();
                data = &data[n..];
            } else {
                // Window full or not yet ESTABLISHED: wait for an ACK / state
                // change (an inbound segment or a tick will notify us).
                let conn = self.state.conn.lock().expect("poisoned");
                if conn.is_closed() {
                    return false;
                }
                let _ = self
                    .state
                    .signal
                    .wait_timeout(conn, PUMP_BACKSTOP)
                    .expect("poisoned");
            }
        }
        true
    }

    /// client→remote pump: copy bytes the engine has received from the virtual
    /// client to the real socket, blocking on the `Condvar` when no data is
    /// available. Exits on FIN/EOF (half-close the real socket) or close.
    fn pump_client_to_remote(self: Arc<Self>) {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let (n, eof) = {
                let mut conn = self.state.conn.lock().expect("poisoned");
                let n = conn.read(&mut buf);
                if n > 0 {
                    // See `TcpStream::read`: a reopened window goes out now,
                    // not on the next tick.
                    let segs = conn.take_outgoing();
                    self.state.emit(conn, segs);
                    (n, false)
                } else if conn.is_closed() {
                    // Reset, or our timers gave up: nothing will ever reach
                    // the client again, so the remote→client pump must not
                    // stay parked in a read the server may never end.
                    drop(conn);
                    self.close();
                    return;
                } else if conn.fin_received() {
                    (0, true)
                } else {
                    // Block until data arrives, the client FINs, or we close.
                    let _ = self
                        .state
                        .signal
                        .wait_timeout(conn, PUMP_BACKSTOP)
                        .expect("poisoned");
                    (0, false)
                }
            };
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            if n > 0 {
                let remote = self.remote.lock().expect("poisoned").clone();
                let res = match remote {
                    Some(s) => (&*s).write_all(&buf[..n]),
                    None => Ok(()),
                };
                if res.is_err() {
                    // Shut down on entering TIME-WAIT (see `time_wait_since`):
                    // both sides are done, and TIME-WAIT runs its course.
                    if self.state.conn.lock().expect("poisoned").state() == State::TimeWait {
                        return;
                    }
                    // Real socket gone: RST the virtual client and tear down.
                    self.close();
                    return;
                }
            } else if eof {
                // Client won't send more: half-close the real write side so the
                // server sees EOF, then exit. The remote→client pump keeps
                // running until the server also closes.
                self.shutdown_remote(Shutdown::Write);
                return;
            }
        }
    }

    /// Close the real socket fully (used when the virtual side disappeared).
    fn teardown_remote_read(&self) {
        self.shutdown_remote(Shutdown::Both);
        self.closed.store(true, Ordering::Release);
        self.state.signal.notify_all();
    }
}

/// Shut down `s`, or a half of it, ignoring errors.
///
/// Both halves are shut down one at a time: macOS refuses a `Both` with
/// `ENOTCONN`, shutting down neither half, once the peer has sent its FIN.
/// That is just when a server that half-closed and stopped reading leaves a
/// pump blocked writing to it, which only shutting the write half unblocks.
fn shutdown(s: &TcpStream, how: Shutdown) {
    match how {
        Shutdown::Both => {
            let _ = s.shutdown(Shutdown::Write);
            let _ = s.shutdown(Shutdown::Read);
        }
        how => {
            let _ = s.shutdown(how);
        }
    }
}

/// Calls its function when dropped.
struct OnDrop<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

impl Drop for TcpOutConn {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.shutdown_remote(Shutdown::Both);
    }
}

/// Build a standalone RST segment used to reject a segment, other than a
/// bare SYN, to no connection, as RFC 9293 §3.10.7.1 asks of the CLOSED
/// state. Returns the marshaled TCP segment bytes (the caller wraps it in IP).
pub(crate) fn build_rst_for_stray(tcp: &[u8], dst_port: u16, src_port: u16) -> Option<Vec<u8>> {
    let seg = Segment::parse(tcp).ok()?;
    // A RST is never answered: two stacks that each reset the other's
    // resets would bounce them forever.
    if seg.has_flag(crate::vtcp::segment::flags::RST) {
        return None;
    }
    let rst = if seg.has_flag(crate::vtcp::segment::flags::ACK) {
        // Send RST with SEQ=SEG.ACK, no ACK.
        Segment {
            src_port: dst_port,
            dst_port: src_port,
            seq: seg.ack,
            flags: crate::vtcp::segment::flags::RST,
            ..Default::default()
        }
    } else {
        // Send RST+ACK with SEQ=0, ACK=SEG.SEQ+SEG.LEN, where SEG.LEN counts
        // the SYN and FIN as well as the data.
        let data_len = seg.data_len()
            + seg.has_flag(crate::vtcp::segment::flags::SYN) as u32
            + seg.has_flag(crate::vtcp::segment::flags::FIN) as u32;
        Segment {
            src_port: dst_port,
            dst_port: src_port,
            seq: 0,
            ack: seg.seq.wrapping_add(data_len),
            flags: crate::vtcp::segment::flags::RST | crate::vtcp::segment::flags::ACK,
            ..Default::default()
        }
    };
    Some(rst.marshal())
}

/// Build a RST+ACK to reject a SYN we couldn't dial (connection refused on the
/// real side). Mirrors the Go fallback that keeps the client from hanging.
pub(crate) fn build_refused_rst(src_port: u16, dst_port: u16, client_seq: u32) -> Vec<u8> {
    Segment {
        src_port: dst_port,
        dst_port: src_port,
        ack: client_seq.wrapping_add(1),
        flags: crate::vtcp::segment::flags::RST | crate::vtcp::segment::flags::ACK,
        ..Default::default()
    }
    .marshal()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dial whose thread never starts still reports that it is done: the
    /// spawn drops the unrun closure, and the guard inside fires then.
    #[test]
    fn the_done_guard_fires_when_the_closure_is_dropped_unrun() {
        use std::sync::atomic::AtomicUsize;
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let done = OnDrop(Some(move || {
            n2.fetch_add(1, Ordering::SeqCst);
        }));
        let closure = move || {
            let _done = done;
        };
        drop(closure);
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }
    use crate::vtcp::segment::flags;

    /// A bridge starts at BRIDGE_BUF, not at the engine's larger default:
    /// only a transfer that needs more grows it.
    #[test]
    fn bridge_buffers_are_bounded() {
        let mut client = Conn::new(ConnConfig::default().local_port(5000).remote_port(80));
        let syn = Segment::parse(&client.connect()[0]).unwrap();
        let bridge = TcpOutConn::pending(
            Endpoints::V4 {
                local_ip: "1.1.1.1".parse().unwrap(),
                local_port: 80,
                remote_ip: "10.0.0.5".parse().unwrap(),
                remote_port: 5000,
            },
            &syn,
            IpEcn::NOT_ECT,
            1460,
            &Tuning::default(),
            None,
            Arc::new(|_: &[u8]| {}),
        );
        let mut conn = bridge.state().conn.lock().unwrap();
        let synack = conn.accept_syn(&syn);
        for s in synack {
            for r in client.handle_segment(&Segment::parse(&s).unwrap()) {
                conn.handle_segment(&Segment::parse(&r).unwrap());
            }
        }
        assert_eq!(conn.state(), State::Established);
        let (n, _) = conn.write(&vec![0u8; 4 << 20]);
        assert_eq!(n, BRIDGE_BUF);
    }

    #[test]
    fn build_rst_with_ack() {
        let seg = Segment {
            src_port: 5000,
            dst_port: 80,
            ack: 12345,
            flags: flags::ACK,
            ..Default::default()
        };
        let rst = build_rst_for_stray(&seg.marshal(), 80, 5000).unwrap();
        let parsed = Segment::parse(&rst).unwrap();
        assert_eq!(parsed.flags, flags::RST);
        assert_eq!(parsed.seq, 12345);
    }

    #[test]
    fn build_rst_without_ack() {
        let seg = Segment {
            src_port: 5000,
            dst_port: 80,
            seq: 100,
            flags: flags::SYN | flags::FIN,
            ..Default::default()
        };
        let rst = build_rst_for_stray(&seg.marshal(), 80, 5000).unwrap();
        let parsed = Segment::parse(&rst).unwrap();
        assert_eq!(parsed.flags, flags::RST | flags::ACK);
        // SEG.LEN counts the SYN and the FIN.
        assert_eq!(parsed.ack, 102);
    }

    #[test]
    fn stray_rst_is_not_answered() {
        for f in [flags::RST, flags::RST | flags::ACK, flags::RST | flags::SYN] {
            let seg = Segment {
                src_port: 5000,
                dst_port: 80,
                seq: 100,
                ack: 7,
                flags: f,
                ..Default::default()
            };
            assert!(build_rst_for_stray(&seg.marshal(), 80, 5000).is_none());
        }
    }

    #[test]
    fn refused_rst_acks_syn() {
        let rst = build_refused_rst(5000, 80, 1000);
        let parsed = Segment::parse(&rst).unwrap();
        assert_eq!(parsed.flags, flags::RST | flags::ACK);
        assert_eq!(parsed.ack, 1001);
        assert_eq!(parsed.src_port, 80);
        assert_eq!(parsed.dst_port, 5000);
    }
}
