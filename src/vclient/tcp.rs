//! TCP connections over the virtual network, backed by [`vtcp::Conn`].
//!
//! A [`TcpConn`] is a blocking, `std::net::TcpStream`-flavoured handle. The
//! per-connection state lives in a [`ConnState`] shared with the owning
//! [`Client`](super::Client): inbound IP packets the client receives are
//! demultiplexed to the matching `ConnState`, fed into the `vtcp::Conn`, and
//! the segments the engine emits are wrapped back into IP and pushed out the
//! client's L3 handler. A single tick thread per client drives RTO / keepalive
//! timers for every connection.

use crate::vtcp::{segment::Segment, Conn, ConnConfig, State};
use crate::{checksum, IpPrefix, Packet, Protocol};
use std::collections::HashMap;
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// 4-tuple identifying a connection from the client's point of view.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) struct ConnKey {
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
}

/// Shared per-connection state. The `Client` holds an `Arc<ConnState>` in its
/// table; the user holds a [`TcpConn`] wrapping the same `Arc`.
pub(crate) struct ConnState {
    pub key: ConnKey,
    pub local_ip: IpAddr,
    conn: Mutex<Conn>,
    /// Notified whenever the connection's readable/writable/closed status may
    /// have changed (inbound data, state transition).
    signal: Condvar,
    /// Sink for fully-framed IP packets the engine wants to transmit.
    sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
}

impl ConnState {
    fn wrap_and_send(&self, segments: Vec<Vec<u8>>) {
        for seg in segments {
            let pkt = wrap_segment(self.local_ip, self.key.remote, &seg);
            (self.sink)(&pkt);
        }
    }
}

/// A blocking TCP stream over the virtual network.
///
/// Dropping the handle initiates a graceful close.
pub struct TcpConn {
    state: Arc<ConnState>,
    read_timeout: Mutex<Option<Duration>>,
}

impl core::fmt::Debug for TcpConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("vclient::TcpConn")
            .field("key", &self.state.key)
            .finish()
    }
}

impl TcpConn {
    pub(crate) fn new(state: Arc<ConnState>) -> TcpConn {
        TcpConn {
            state,
            read_timeout: Mutex::new(None),
        }
    }

    /// Local socket address.
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.state.local_ip, self.state.key.local_port)
    }

    /// Remote socket address.
    pub fn peer_addr(&self) -> SocketAddr {
        SocketAddr::new(self.state.key.remote, self.state.key.remote_port)
    }

    /// Set a read timeout. `None` blocks indefinitely.
    pub fn set_read_timeout(&self, t: Option<Duration>) {
        *self.read_timeout.lock().unwrap() = t;
    }

    /// Write all of `buf`, blocking until the engine accepts it. Returns the
    /// number of bytes queued (always `buf.len()` on success).
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let mut conn = self.state.conn.lock().unwrap();
            if conn.is_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection closed",
                ));
            }
            let (n, segs) = conn.write(&buf[written..]);
            drop(conn);
            if n > 0 {
                self.state.wrap_and_send(segs);
                written += n;
            } else {
                // Send window full — wait for an ACK to open it.
                let conn = self.state.conn.lock().unwrap();
                let _ = self
                    .state
                    .signal
                    .wait_timeout(conn, Duration::from_millis(100))
                    .unwrap();
            }
        }
        Ok(written)
    }

    /// Read into `buf`, blocking until data is available or the peer closes.
    /// Returns 0 at end of stream.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let deadline = self
            .read_timeout
            .lock()
            .unwrap()
            .map(|t| Instant::now() + t);
        let mut conn = self.state.conn.lock().unwrap();
        loop {
            let n = conn.read(buf);
            if n > 0 {
                return Ok(n);
            }
            if conn.fin_received() || conn.is_closed() {
                return Ok(0); // clean EOF
            }
            // Block until inbound data arrives or we time out.
            match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        return Err(io::Error::new(io::ErrorKind::WouldBlock, "read timeout"));
                    }
                    let (c, _) = self.state.signal.wait_timeout(conn, d - now).unwrap();
                    conn = c;
                }
                None => {
                    conn = self.state.signal.wait(conn).unwrap();
                }
            }
        }
    }

    /// Initiate a graceful close (sends FIN).
    pub fn close(&self) -> io::Result<()> {
        let mut conn = self.state.conn.lock().unwrap();
        let segs = conn.close();
        drop(conn);
        self.state.wrap_and_send(segs);
        Ok(())
    }
}

impl io::Read for TcpConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        TcpConn::read(self, buf)
    }
}

impl io::Write for TcpConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        TcpConn::write(self, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for TcpConn {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// TCP connection table + tick thread owned by a [`Client`](super::Client).
pub(crate) struct TcpStack {
    conns: Mutex<HashMap<ConnKey, Arc<ConnState>>>,
    sink: Arc<dyn Fn(&[u8]) + Send + Sync>,
    next_port: Mutex<u16>,
    stop: Arc<Mutex<bool>>,
}

impl TcpStack {
    pub fn new(sink: Arc<dyn Fn(&[u8]) + Send + Sync>) -> Arc<TcpStack> {
        let stack = Arc::new(TcpStack {
            conns: Mutex::new(HashMap::new()),
            sink,
            next_port: Mutex::new(49152),
            stop: Arc::new(Mutex::new(false)),
        });
        // Tick thread: drive timers for all connections every 100ms.
        let weak = Arc::downgrade(&stack);
        let stop = stack.stop.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(100));
            if *stop.lock().unwrap() {
                return;
            }
            let Some(stack) = weak.upgrade() else { return };
            stack.tick_all();
        });
        stack
    }

    fn alloc_port(&self) -> u16 {
        let mut p = self.next_port.lock().unwrap();
        let port = *p;
        *p = if *p == 65535 { 49152 } else { *p + 1 };
        port
    }

    fn tick_all(&self) {
        let conns: Vec<Arc<ConnState>> = self.conns.lock().unwrap().values().cloned().collect();
        let mut dead = Vec::new();
        for cs in conns {
            let mut conn = cs.conn.lock().unwrap();
            let segs = conn.tick();
            let closed = conn.is_closed();
            drop(conn);
            if !segs.is_empty() {
                cs.wrap_and_send(segs);
            }
            cs.signal.notify_all();
            if closed {
                dead.push(cs.key);
            }
        }
        if !dead.is_empty() {
            let mut map = self.conns.lock().unwrap();
            for k in dead {
                map.remove(&k);
            }
        }
    }

    /// Dial a remote endpoint, blocking until the handshake completes or fails.
    pub fn dial(
        &self,
        local_ip: IpAddr,
        remote: SocketAddr,
        connect_timeout: Duration,
    ) -> io::Result<TcpConn> {
        let local_port = self.alloc_port();
        let mss = if remote.is_ipv6() { 1440 } else { 1460 };
        let cfg = ConnConfig {
            local_addr: Some(SocketAddr::new(local_ip, local_port)),
            remote_addr: Some(remote),
            local_port,
            remote_port: remote.port(),
            mss,
            keepalive: true,
            ..Default::default()
        };
        let conn = Conn::new(cfg);
        let key = ConnKey {
            local_port,
            remote: remote.ip(),
            remote_port: remote.port(),
        };
        let state = Arc::new(ConnState {
            key,
            local_ip,
            conn: Mutex::new(conn),
            signal: Condvar::new(),
            sink: self.sink.clone(),
        });
        self.conns.lock().unwrap().insert(key, state.clone());

        // Send SYN.
        let segs = {
            let mut conn = state.conn.lock().unwrap();
            conn.connect()
        };
        state.wrap_and_send(segs);

        // Wait for ESTABLISHED.
        let deadline = Instant::now() + connect_timeout;
        let mut conn = state.conn.lock().unwrap();
        loop {
            match conn.state() {
                State::Established => return Ok(TcpConn::new(state.clone())),
                State::Closed => {
                    self.conns.lock().unwrap().remove(&key);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "connection reset during handshake",
                    ));
                }
                _ => {}
            }
            let now = Instant::now();
            if now >= deadline {
                self.conns.lock().unwrap().remove(&key);
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout"));
            }
            let (c, _) = state.signal.wait_timeout(conn, deadline - now).unwrap();
            conn = c;
        }
    }

    /// Demultiplex an inbound TCP packet to the matching connection.
    /// Returns `true` if the packet was consumed.
    pub fn handle_inbound(&self, pkt: &Packet) -> bool {
        if pkt.ip_protocol() != Protocol::TCP {
            return false;
        }
        let (src, dst) = match (pkt.src_addr(), pkt.dst_addr()) {
            (Some(s), Some(d)) => (s, d),
            _ => return false,
        };
        let payload = pkt.payload();
        let seg = match Segment::parse(payload) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // Inbound: packet src=remote, dst=us. Key uses remote = src.
        let key = ConnKey {
            local_port: seg.dst_port,
            remote: src,
            remote_port: seg.src_port,
        };
        let state = match self.conns.lock().unwrap().get(&key) {
            Some(s) => s.clone(),
            None => return false,
        };
        let _ = dst; // local addr is implied by the connection
        let segs = {
            let mut conn = state.conn.lock().unwrap();
            conn.handle_segment(&seg)
        };
        state.wrap_and_send(segs);
        state.signal.notify_all();
        true
    }

    pub fn shutdown(&self) {
        *self.stop.lock().unwrap() = true;
    }
}

// --- IP framing ------------------------------------------------------------

/// Wrap a marshaled TCP segment in an IPv4 or IPv6 header with a correct TCP
/// checksum.
fn wrap_segment(src: IpAddr, dst: IpAddr, seg: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => wrap_v4(s, d, seg),
        (IpAddr::V6(s), IpAddr::V6(d)) => wrap_v6(s, d, seg),
        // Mismatched families shouldn't happen for a single connection.
        _ => Vec::new(),
    }
}

fn tcp_checksum(src: IpAddr, dst: IpAddr, seg: &[u8]) -> u16 {
    let pseudo = checksum::pseudo_header_checksum(Protocol::TCP, src, dst, seg.len() as u16);
    let body = !checksum::checksum(seg); // raw (un-complemented) sum of the segment
    !checksum::combine_checksums(pseudo, body)
}

fn wrap_v4(src: Ipv4Addr, dst: Ipv4Addr, seg: &[u8]) -> Vec<u8> {
    let total = 20 + seg.len();
    let mut ip = vec![0u8; total];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = Protocol::TCP.as_u8();
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let cs = checksum::checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&cs.to_be_bytes());
    ip[20..].copy_from_slice(seg);
    // Patch the TCP checksum into the segment region.
    let tcp_cs = tcp_checksum(IpAddr::V4(src), IpAddr::V4(dst), seg);
    ip[20 + 16..20 + 18].copy_from_slice(&tcp_cs.to_be_bytes());
    ip
}

fn wrap_v6(src: Ipv6Addr, dst: Ipv6Addr, seg: &[u8]) -> Vec<u8> {
    let total = 40 + seg.len();
    let mut ip = vec![0u8; total];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(seg.len() as u16).to_be_bytes());
    ip[6] = Protocol::TCP.as_u8();
    ip[7] = 64;
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    ip[40..].copy_from_slice(seg);
    let tcp_cs = tcp_checksum(IpAddr::V6(src), IpAddr::V6(dst), seg);
    ip[40 + 16..40 + 18].copy_from_slice(&tcp_cs.to_be_bytes());
    ip
}

/// Compute the local IP for a connection from the client's prefix.
pub(crate) fn local_ip_for(prefix: IpPrefix, remote: IpAddr) -> Option<IpAddr> {
    match (prefix.addr(), remote) {
        (IpAddr::V4(_), IpAddr::V4(_)) if prefix.is_v4() => Some(prefix.addr()),
        (IpAddr::V6(_), IpAddr::V6(_)) if prefix.is_v6() => Some(prefix.addr()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtcp::segment::flags;

    #[test]
    fn wrap_v4_has_valid_ip_checksum() {
        // minimal SYN segment
        let mut seg = vec![0u8; 20];
        seg[12] = 5 << 4;
        seg[13] = flags::SYN;
        let pkt = wrap_v4(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), &seg);
        // IP header checksum should validate (sum over header == 0xFFFF).
        assert_eq!(checksum::checksum(&pkt[..20]), 0);
        assert_eq!(pkt[9], Protocol::TCP.as_u8());
        // TCP checksum field is non-zero now.
        let tcp_cs = u16::from_be_bytes([pkt[20 + 16], pkt[20 + 17]]);
        assert_ne!(tcp_cs, 0);
    }

    #[test]
    fn tcp_checksum_validates_at_receiver() {
        // Build a segment, wrap it, then verify the receiver-side checksum
        // (pseudo-header + full segment including checksum) folds to zero.
        let mut seg = vec![0u8; 24];
        seg[12] = 5 << 4;
        seg[13] = flags::ACK;
        seg[0..2].copy_from_slice(&1234u16.to_be_bytes());
        seg[2..4].copy_from_slice(&80u16.to_be_bytes());
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let pkt = wrap_v4(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), &seg);
        let recv_seg = &pkt[20..];
        // Verify: pseudo + full segment (with checksum filled) == 0xFFFF complement 0.
        let pseudo =
            checksum::pseudo_header_checksum(Protocol::TCP, src, dst, recv_seg.len() as u16);
        let body = !checksum::checksum(recv_seg);
        assert_eq!(checksum::combine_checksums(pseudo, body), 0xFFFF);
    }
}
