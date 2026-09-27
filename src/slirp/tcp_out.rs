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
//! TIME-WAIT timers. Two background threads form the byte pump:
//!
//! - **remote→client**: read from the real socket, `Conn::write` the bytes
//!   (blocking on the send window via the shared `Condvar`), and flush the
//!   resulting segments. On EOF, `Conn::close()` sends a FIN to the client.
//! - **client→remote**: `Conn::read` data delivered by the engine (blocking on
//!   the same `Condvar`) and `write_all` it to the real socket. When the client
//!   half-closes (FIN), the real socket's write side is shut down.
//!
//! Unlike the old hand-rolled engine, this inherits vtcp's out-of-order
//! reassembly, SACK, window scaling, and congestion control on the virtual
//! side.

use crate::Result;
use crate::slirp::tcp_stream::{ConnState, Endpoints};
use crate::vtcp::segment::Segment;
use crate::vtcp::{Conn, ConnConfig};

use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// MSS advertised on the virtual side (mirrors the Go constants).
const MSS_V4: u16 = 1460;
const MSS_V6: u16 = 1440;

/// How long to wait for the real destination to accept. Well under the OS's
/// own connect timeout (75 s to over two minutes), and still longer than a
/// client usually keeps retransmitting its SYN.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A live outbound TCP NAT bridge: a server-side `vtcp::Conn` facing the
/// virtual client, glued to a real OS [`TcpStream`] facing the destination.
pub(crate) struct TcpOutConn {
    /// Virtual-side connection state (shared with the byte-pump threads and the
    /// stack's tick thread). Reuses the inbound accept-path machinery.
    state: Arc<ConnState>,
    /// Real upstream socket, set once the dial succeeds. The client→remote
    /// pump writes through it while `close` may shut it down from another
    /// thread, so it sits behind no lock: a shutdown is exactly what unblocks
    /// a write stuck on a peer that stopped reading. The read half was cloned
    /// out for the remote→client pump thread.
    remote: OnceLock<TcpStream>,
    /// Set once the bridge has been torn down (RST/abort or both-ways close).
    closed: Arc<AtomicBool>,
    /// The client's SYN, kept while the real destination is being dialed and
    /// taken once the dial finishes.
    syn: Mutex<Option<Segment>>,
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
    pub(crate) fn pending(
        endpoints: Endpoints,
        syn: &Segment,
        sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    ) -> Arc<TcpOutConn> {
        let (local_addr, remote_addr, local_port, remote_port, mss) = match endpoints {
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
                MSS_V4,
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
                MSS_V6,
            ),
        };

        let cfg = ConnConfig {
            local_addr: Some(local_addr),
            remote_addr: Some(remote_addr),
            local_port,
            remote_port,
            mss,
            keepalive: true,
            ..Default::default()
        };

        Arc::new(TcpOutConn {
            state: ConnState::new(endpoints, Conn::new(cfg), sink),
            remote: OnceLock::new(),
            closed: Arc::new(AtomicBool::new(false)),
            syn: Mutex::new(Some(syn.clone())),
        })
    }

    /// Dial `dest` on a thread of its own and, once it answers, complete the
    /// virtual handshake and start the byte pumps. `on_done` runs when the
    /// dial has finished either way.
    ///
    /// The dial must not run on the caller's thread: that is the packet path,
    /// and a destination that drops SYNs would stall every other flow of the
    /// stack for as long as the OS keeps retrying the connect.
    pub(crate) fn start_dial(
        self: &Arc<Self>,
        dest: SocketAddr,
        on_done: impl FnOnce() + Send + 'static,
    ) {
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
        let Some(syn) = self.syn.lock().expect("poisoned").take() else {
            return;
        };
        if self.closed.load(Ordering::SeqCst) {
            return; // torn down while dialing; dropping `res` closes the socket
        }
        let (remote, remote_read) = match res {
            Ok(pair) => pair,
            Err(_) => {
                // Refused / unreachable / timed out: RST+ACK so the client
                // doesn't hang.
                let (local_port, remote_port) = self.state.endpoints.ports();
                let rst = build_refused_rst(remote_port, local_port, syn.seq);
                self.state.wrap_and_send(vec![rst]);
                self.closed.store(true, Ordering::SeqCst);
                return;
            }
        };
        let _ = self.remote.set(remote);
        // close() sets `closed` before it shuts the socket down, so either it
        // sees the socket stored above or this sees the flag.
        if self.closed.load(Ordering::SeqCst) {
            self.shutdown_remote(Shutdown::Both);
            return;
        }
        let synack = self.state.conn.lock().expect("poisoned").accept_syn(&syn);

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
            return;
        }

        self.state.wrap_and_send(synack);
    }

    /// Feed an inbound TCP segment from the virtual client into the engine and
    /// transmit its replies. (Called from the stack's packet dispatch path.)
    pub(crate) fn handle_segment(&self, tcp: &[u8]) -> Result<()> {
        let Ok(seg) = Segment::parse(tcp) else {
            return Ok(());
        };
        let dialing = self.syn.lock().expect("poisoned").is_some();
        if dialing {
            // Nothing to answer yet: retransmitted SYNs wait for the dial. A
            // RST means the client gave up, so the dial's result is moot.
            if seg.has_flag(crate::vtcp::segment::flags::RST) {
                self.closed.store(true, Ordering::SeqCst);
            }
            return Ok(());
        }
        self.state.deliver(&seg);
        Ok(())
    }

    /// The shared connection state, so the stack's tick thread can drive timers.
    pub(crate) fn state(&self) -> &Arc<ConnState> {
        &self.state
    }

    /// True once the bridge has fully torn down.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.state.conn.lock().expect("poisoned").is_closed()
    }

    /// Forcibly tear the bridge down: RST the virtual client and close the real
    /// socket. Called by `Stack::shutdown` and namespace cleanup.
    pub(crate) fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let segs = self.state.conn.lock().expect("poisoned").abort();
        self.state.wrap_and_send(segs);
        self.state.signal.notify_all();
        self.shutdown_remote(Shutdown::Both);
    }

    /// Shut down the real socket (or a half of it). Tolerates a missing socket.
    fn shutdown_remote(&self, how: Shutdown) {
        if let Some(s) = self.remote.get() {
            let _ = s.shutdown(how);
        }
    }

    /// remote→client pump: copy bytes from the real socket into the engine's
    /// send buffer, blocking on the send window when it is full. On EOF or
    /// error, gracefully close the virtual side (FIN) and tear the bridge down.
    fn pump_remote_to_client(self: Arc<Self>, mut remote_read: TcpStream) {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            let n = match remote_read.read(&mut buf) {
                Ok(0) => break, // remote EOF
                Ok(n) => n,
                Err(_) => break, // remote error
            };
            if !self.write_all_to_engine(&buf[..n]) {
                // Virtual side closed underneath us; abandon.
                self.teardown_remote_read();
                return;
            }
        }
        // Remote closed (or errored): send FIN to the client.
        let segs = {
            let mut conn = self.state.conn.lock().expect("poisoned");
            conn.close()
        };
        self.state.wrap_and_send(segs);
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
            let (n, segs) = {
                let mut conn = self.state.conn.lock().expect("poisoned");
                if conn.is_closed() {
                    return false;
                }
                conn.write(data)
            };
            if n > 0 {
                self.state.wrap_and_send(segs);
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
                    .wait_timeout(conn, Duration::from_millis(100))
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
                    (n, false)
                } else if conn.fin_received() || conn.is_closed() {
                    (0, true)
                } else {
                    // Block until data arrives, the client FINs, or we close.
                    let _ = self
                        .state
                        .signal
                        .wait_timeout(conn, Duration::from_millis(100))
                        .expect("poisoned");
                    (0, false)
                }
            };
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            if n > 0 {
                let res = match self.remote.get() {
                    Some(mut s) => s.write_all(&buf[..n]),
                    None => Ok(()),
                };
                if res.is_err() {
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

/// Build a standalone RST segment used to reject a non-SYN to nothing.
/// Mirrors the Go `slirp` RFC 9293 §3.10.7.1 behaviour. Returns the marshaled
/// TCP segment bytes (the caller wraps it in IP).
pub(crate) fn build_rst_for_stray(tcp: &[u8], dst_port: u16, src_port: u16) -> Option<Vec<u8>> {
    let seg = Segment::parse(tcp).ok()?;
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
        // Send RST+ACK with SEQ=0, ACK=SEG.SEQ+SEG.LEN.
        let mut data_len = seg.data_len();
        if seg.has_flag(crate::vtcp::segment::flags::FIN) {
            data_len = data_len.wrapping_add(1);
        }
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
            flags: flags::SYN,
            ..Default::default()
        };
        let rst = build_rst_for_stray(&seg.marshal(), 80, 5000).unwrap();
        let parsed = Segment::parse(&rst).unwrap();
        assert_eq!(parsed.flags, flags::RST | flags::ACK);
        // SYN does not count toward data_len here (only FIN does), so ack=100.
        assert_eq!(parsed.ack, 100);
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
