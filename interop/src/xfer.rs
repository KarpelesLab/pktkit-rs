//! Transfers between the vclient and the guest: the vclient's end run
//! here, the guest's by the agent, and each end's report of how it went.

use crate::image::{GUEST_IP, HOST_IP};
use crate::pattern::{Pattern, Verifier, reverse_seed};
use crate::vm::Reply;
use pktkit::vclient::{Client, Listener, TcpConn};
use pktkit::vtcp::{State, TcpInfo};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const CHUNK: usize = 256 * 1024;

/// A vtcp connection's handle, from vclient or from slirp.
pub trait Stream: Send + 'static {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
    fn close(&self) -> io::Result<()>;
    fn info(&self) -> TcpInfo;
    fn set_timeouts(&self, t: Duration);
}

impl Stream for TcpConn {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        TcpConn::read(self, buf)
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        TcpConn::write(self, buf)
    }
    fn close(&self) -> io::Result<()> {
        TcpConn::close(self)
    }
    fn info(&self) -> TcpInfo {
        TcpConn::info(self)
    }
    fn set_timeouts(&self, t: Duration) {
        self.set_read_timeout(Some(t));
        self.set_write_timeout(Some(t));
    }
}

impl Stream for pktkit::slirp::TcpStream {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        pktkit::slirp::TcpStream::read(self, buf)
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        pktkit::slirp::TcpStream::write(self, buf)
    }
    fn close(&self) -> io::Result<()> {
        pktkit::slirp::TcpStream::close(self)
    }
    fn info(&self) -> TcpInfo {
        pktkit::slirp::TcpStream::info(self)
    }
    fn set_timeouts(&self, t: Duration) {
        self.set_read_timeout(Some(t));
        self.set_write_timeout(Some(t));
    }
}

/// How one end of a connection saw it.
#[derive(Debug)]
pub struct VcEnd {
    pub rx: u64,
    pub rx_ok: bool,
    pub bad_at: Option<u64>,
    /// From the first byte received to EOF.
    pub rx_time: Option<Duration>,
    pub elapsed: Duration,
    pub err: Option<String>,
    pub info: Option<TcpInfo>,
    /// The largest the receive buffer grew to while data came in: `info`
    /// is read after the close, when the growth has been given back.
    pub recv_buf_peak: usize,
}

impl VcEnd {
    fn failed(err: String, start: Instant) -> VcEnd {
        VcEnd {
            rx: 0,
            rx_ok: false,
            bad_at: None,
            rx_time: None,
            elapsed: start.elapsed(),
            err: Some(err),
            info: None,
            recv_buf_peak: 0,
        }
    }

    pub fn ok(&self) -> bool {
        self.rx_ok && self.err.is_none()
    }

    pub fn info(&self) -> Result<&TcpInfo, String> {
        self.info
            .as_ref()
            .ok_or_else(|| format!("vclient: {}", self.err.as_deref().unwrap_or("no info")))
    }
}

pub fn guest_addr(port: u16) -> SocketAddr {
    format!("{GUEST_IP}:{port}").parse().unwrap()
}

pub fn host_ip() -> &'static str {
    HOST_IP
}

fn send_pattern(c: &impl Stream, seed: u64, n: u64, skip: u64) -> io::Result<()> {
    let mut p = Pattern::new(seed);
    let mut buf = vec![0u8; CHUNK];
    let mut sent = 0u64;
    // Already sent (in a SYN): generated, not written.
    while sent < skip {
        let k = ((skip - sent) as usize).min(CHUNK);
        p.fill(&mut buf[..k]);
        sent += k as u64;
    }
    while sent < n {
        let k = ((n - sent) as usize).min(CHUNK);
        p.fill(&mut buf[..k]);
        let w = c.write(&buf[..k])?;
        if w < k {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "write timed out"));
        }
        sent += k as u64;
    }
    Ok(())
}

struct Received {
    v: Verifier,
    /// From the first byte to EOF.
    time: Option<Duration>,
    err: Option<io::Error>,
    recv_buf_peak: usize,
}

fn recv_pattern(c: &impl Stream, seed: u64) -> Received {
    let mut v = Verifier::new(seed);
    let mut buf = vec![0u8; CHUNK];
    let mut first = None;
    let mut peak = 0;
    let err = loop {
        match c.read(&mut buf) {
            Ok(0) => break None,
            Ok(n) => {
                first.get_or_insert_with(Instant::now);
                v.update(&buf[..n]);
                peak = peak.max(c.info().recv_buf);
            }
            Err(e) => break Some(e),
        }
    };
    Received {
        v,
        time: first.map(|f: Instant| f.elapsed()),
        err,
        recv_buf_peak: peak,
    }
}

/// Wait until our FIN, and everything before it, is acknowledged.
fn wait_acked(c: &impl Stream, limit: Duration) {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        let i = c.info();
        // Closed: acknowledged, or reset, and nothing more will be.
        if i.state == State::Closed
            || i.unacked == 0
                && i.send_queued == 0
                && matches!(i.state, State::FinWait2 | State::TimeWait)
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn err_name(e: &io::Error) -> String {
    format!("{:?}", e.kind())
}

/// Send `send` bytes, half-close, then read to EOF expecting `recv`.
fn client_body(
    c: &impl Stream,
    send: u64,
    recv: u64,
    seed: u64,
    skip: u64,
    start: Instant,
) -> VcEnd {
    let werr = send_pattern(c, seed, send, skip).err();
    let _ = c.close();
    let r = recv_pattern(c, reverse_seed(seed));
    wait_acked(c, Duration::from_secs(10));
    VcEnd {
        rx: r.v.len,
        rx_ok: r.v.ok(recv),
        bad_at: r.v.bad_at,
        rx_time: r.time,
        elapsed: start.elapsed(),
        err: werr.or(r.err).map(|e| err_name(&e)),
        info: Some(c.info()),
        recv_buf_peak: r.recv_buf_peak,
    }
}

/// The vclient connects to the guest and runs a transfer. With
/// `fast_open`, the first bytes go through `dial_tcp_with_data`.
pub fn vc_client(
    client: &Client,
    port: u16,
    send: u64,
    recv: u64,
    seed: u64,
    fast_open: bool,
    timeout: Duration,
) -> VcEnd {
    let start = Instant::now();
    let addr = guest_addr(port);
    let (conn, skip) = if fast_open {
        let first = send.min(1000) as usize;
        let mut buf = vec![0u8; first];
        Pattern::new(seed).fill(&mut buf);
        (client.dial_tcp_with_data(addr, &buf), first as u64)
    } else {
        (client.dial_tcp_timeout(addr, Duration::from_secs(10)), 0)
    };
    let c = match conn {
        Ok(c) => c,
        Err(e) => return VcEnd::failed(format!("dial: {}", err_name(&e)), start),
    };
    c.set_read_timeout(Some(timeout));
    c.set_write_timeout(Some(timeout));
    client_body(&c, send, recv, seed, skip, start)
}

/// What a vclient server does with each connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerMode {
    /// Read to EOF checking the stream, then send `send` bytes and close.
    Sink,
    /// Wait for data to arrive, then drop the connection unread: a reset
    /// (RFC 2525 §2.17).
    ResetOnData,
}

fn accept(l: &Listener, deadline: Instant) -> io::Result<TcpConn> {
    l.set_nonblocking(true);
    loop {
        match l.accept() {
            Ok(c) => return Ok(c),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "accept timed out"));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
        }
    }
}

fn serve_one<S: Stream>(c: S, mode: ServerMode, send: u64, seed: u64, timeout: Duration) -> VcEnd {
    let start = Instant::now();
    c.set_timeouts(timeout);
    match mode {
        ServerMode::ResetOnData => {
            let end = Instant::now() + timeout;
            while c.info().recv_queued == 0 && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(1));
            }
            let info = c.info();
            drop(c);
            VcEnd {
                rx: info.recv_queued as u64,
                rx_ok: info.recv_queued > 0,
                bad_at: None,
                rx_time: None,
                elapsed: start.elapsed(),
                err: None,
                info: Some(info),
                recv_buf_peak: 0,
            }
        }
        ServerMode::Sink => {
            let r = recv_pattern(&c, seed);
            let werr = if r.err.is_none() {
                send_pattern(&c, reverse_seed(seed), send, 0).err()
            } else {
                None
            };
            let _ = c.close();
            wait_acked(&c, Duration::from_secs(10));
            VcEnd {
                rx: r.v.len,
                rx_ok: r.v.bad_at.is_none(),
                bad_at: r.v.bad_at,
                rx_time: r.time,
                elapsed: start.elapsed(),
                err: r.err.or(werr).map(|e| err_name(&e)),
                info: Some(c.info()),
                recv_buf_peak: r.recv_buf_peak,
            }
        }
    }
}

/// Serve `count` connections on `port` in the background, one at a time,
/// the n-th expecting the stream of `seed + n` (as the agent's `connect`
/// sends them).
pub fn vc_server(
    client: &Arc<Client>,
    port: u16,
    mode: ServerMode,
    send: u64,
    seed: u64,
    count: u64,
    timeout: Duration,
) -> io::Result<JoinHandle<Vec<VcEnd>>> {
    let l = client.listen_tcp(port)?;
    Ok(std::thread::spawn(move || {
        let mut out = Vec::new();
        let deadline = Instant::now() + timeout;
        for i in 0..count {
            let start = Instant::now();
            match accept(&l, deadline) {
                Ok(c) => out.push(serve_one(c, mode, send, seed.wrapping_add(i), timeout)),
                Err(e) => {
                    out.push(VcEnd::failed(format!("accept: {e}"), start));
                    break;
                }
            }
        }
        out
    }))
}

/// A transfer's two ends: the vclient's, and the guest's report.
#[derive(Debug)]
pub struct Run {
    pub vc: VcEnd,
    pub linux: Reply,
    /// Bytes client to server, and back.
    pub c2s: u64,
    pub s2c: u64,
    pub vc_is_client: bool,
}

impl Run {
    pub fn ok(&self) -> bool {
        self.vc.ok() && self.linux.flag("ok")
    }

    /// Why it failed, for the report.
    pub fn failure(&self) -> String {
        format!(
            "vclient: rx={} ok={} bad_at={:?} err={:?}; linux: {}",
            self.vc.rx,
            self.vc.rx_ok,
            self.vc.bad_at,
            self.vc.err,
            self.linux.line.trim()
        )
    }

    /// Throughput of the vclient→Linux direction, in Mbit/s, measured by
    /// the receiver from its first byte to EOF.
    pub fn mbps_vc_to_linux(&self) -> Option<f64> {
        let bytes = if self.vc_is_client {
            self.c2s
        } else {
            self.s2c
        };
        let us = self.linux.num("rx_us");
        (bytes > 0 && us > 0).then(|| bytes as f64 * 8.0 / us as f64)
    }

    pub fn mbps_linux_to_vc(&self) -> Option<f64> {
        let bytes = if self.vc_is_client {
            self.s2c
        } else {
            self.c2s
        };
        let t = self.vc.rx_time?;
        (bytes > 0).then(|| bytes as f64 * 8.0 / t.as_micros().max(1) as f64)
    }
}

/// Serve one connection from a slirp listener in the background, as
/// `vc_server` does. slirp's `accept` only blocks, so a timer closes the
/// listener if nobody comes.
pub fn slirp_server(
    l: Arc<pktkit::slirp::Listener>,
    send: u64,
    seed: u64,
    timeout: Duration,
) -> JoinHandle<VcEnd> {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let lt = l.clone();
    std::thread::spawn(move || {
        if rx.recv_timeout(timeout).is_err() {
            let _ = lt.close();
        }
    });
    std::thread::spawn(move || {
        let start = Instant::now();
        let r = match l.accept() {
            Ok(c) => {
                let _ = tx.send(());
                serve_one(c, ServerMode::Sink, send, seed, timeout)
            }
            Err(e) => VcEnd::failed(format!("accept: {e}"), start),
        };
        let _ = l.close();
        r
    })
}

/// A plain host socket server, for what slirp relays to: reads to EOF
/// checking the stream, sends `send` bytes back, and says whether all it
/// read was right, and how much.
pub fn host_server(
    l: std::net::TcpListener,
    send: u64,
    seed: u64,
    timeout: Duration,
) -> JoinHandle<Result<u64, String>> {
    use std::io::{Read, Write};
    std::thread::spawn(move || {
        l.set_nonblocking(true).map_err(|e| e.to_string())?;
        let deadline = Instant::now() + timeout;
        let mut s = loop {
            match l.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(e) => return Err(format!("host accept: {e}")),
            }
        };
        s.set_nonblocking(false).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        let mut v = Verifier::new(seed);
        let mut buf = vec![0u8; CHUNK];
        loop {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => v.update(&buf[..n]),
                Err(e) => return Err(format!("host read: {e}")),
            }
        }
        let mut p = Pattern::new(reverse_seed(seed));
        let mut left = send;
        while left > 0 {
            let k = (left as usize).min(CHUNK);
            p.fill(&mut buf[..k]);
            s.write_all(&buf[..k])
                .map_err(|e| format!("host write: {e}"))?;
            left -= k as u64;
        }
        let _ = s.shutdown(std::net::Shutdown::Write);
        // Wait for the peer's close, so nothing is cut short by a reset.
        let _ = s.read(&mut buf);
        match v.bad_at {
            Some(b) => Err(format!("host: stream wrong at byte {b}")),
            None => Ok(v.len),
        }
    })
}

/// A non-loopback address of this host, which slirp can dial: the one the
/// host would send from towards a documentation address (no packet is
/// sent to find out).
pub fn host_lan_ip() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}
