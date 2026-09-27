//! QEMU userspace network socket protocol.
//!
//! QEMU's `-netdev socket` uses trivial framing on top of a stream socket:
//! each Ethernet frame is prefixed with a 4-byte big-endian length.
//!
//! [`Conn`] wraps any stream socket as an [`L2Device`]. [`Listener`] accepts
//! incoming sockets and yields [`Conn`]s via
//! [`L2Acceptor`](crate::L2Acceptor) so it plugs straight into
//! [`serve`](crate::serve).
//!
//! Both transports QEMU offers are here. The TCP one works everywhere; the
//! Unix-domain one needs a platform with `std::os::unix::net`, and
//! [`dial_unix`] / [`Listener::bind_unix`] report `ErrorKind::Unsupported`
//! where there is none.

use crate::{Frame, L2Device, L2Handler, MacAddr, Result};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const MAX_FRAME_SIZE: usize = 65535;

/// How long [`close`](L2Device::close) lets the writer thread flush frames
/// already queued before it hangs up regardless. Bounded, because a peer
/// that has stopped reading would otherwise hold the writer, and the
/// socket, open for as long as it pleases.
const CLOSE_GRACE: Duration = Duration::from_secs(1);

/// Most frames queued for one peer's socket; past it, frames are dropped.
///
/// A switch port with a full transmit queue drops, and so does this: QEMU
/// stops reading its socket whenever the guest's receive ring is full (or the
/// VM is paused), and a sender that blocked on that would stall whatever sent
/// the frame -- a hub forwarding inline to every port, or another peer's
/// reader, which with two peers doing it to each other is a deadlock.
const OUT_QUEUE_LIMIT: usize = 128;

/// Default for [`ListenerConfig::max_peers`]. Each peer holds a socket (three
/// descriptors, with its clones) and two threads, three with
/// [`serve`](crate::serve)'s wait for its hang-up.
pub const DEFAULT_MAX_PEERS: usize = 1024;

struct DoneSignal {
    closed: AtomicBool,
    wait: (Mutex<bool>, Condvar),
}

/// The frame handler, plus a condvar the reader waits on until one is
/// installed. The stream is reliable: QEMU sent every frame on it once, so a
/// frame that arrives before [`set_handler`](L2Device::set_handler) must be
/// held, not dropped. Waiting in the reader leaves it in the socket buffer.
struct HandlerSlot {
    handler: Mutex<Option<L2Handler>>,
    ready: Condvar,
}

impl HandlerSlot {
    /// The handler, waiting for one if none is installed yet. `None` once
    /// the connection is closed.
    fn get(&self, done: &DoneSignal) -> Option<L2Handler> {
        let mut h = self.handler.lock().unwrap();
        loop {
            if done.closed.load(Ordering::Acquire) {
                return None;
            }
            if let Some(h) = h.as_ref() {
                return Some(h.clone());
            }
            h = self.ready.wait(h).unwrap();
        }
    }
}

/// Signals a [`DoneSignal`] when dropped, so the reader thread signals it
/// however it ends, a panic included.
struct SignalOnDrop(Arc<DoneSignal>);

impl Drop for SignalOnDrop {
    fn drop(&mut self) {
        self.0.signal();
    }
}

/// Set once, by the writer thread as it exits; waited on with a timeout.
struct Latch {
    set: Mutex<bool>,
    cvar: Condvar,
}

impl Latch {
    fn new() -> Arc<Self> {
        Arc::new(Latch {
            set: Mutex::new(false),
            cvar: Condvar::new(),
        })
    }
    fn set(&self) {
        *self.set.lock().unwrap() = true;
        self.cvar.notify_all();
    }
    /// Whether the latch was set within `timeout`.
    fn wait_timeout(&self, timeout: Duration) -> bool {
        let g = self.set.lock().unwrap();
        let (g, _) = self
            .cvar
            .wait_timeout_while(g, timeout, |set| !*set)
            .unwrap();
        *g
    }
}

impl DoneSignal {
    fn new() -> Arc<Self> {
        Arc::new(DoneSignal {
            closed: AtomicBool::new(false),
            wait: (Mutex::new(false), Condvar::new()),
        })
    }
    fn signal(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let (lock, cvar) = &self.wait;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }
    fn wait(&self) {
        let (lock, cvar) = &self.wait;
        let mut done = lock.lock().unwrap();
        while !*done {
            done = cvar.wait(done).unwrap();
        }
    }
}

/// One QEMU socket peer. Each Ethernet frame is wrapped in a 4-byte
/// big-endian length prefix in both directions.
///
/// [`send`](L2Device::send) never waits on the socket: frames are queued for
/// a writer thread, and while the peer is not reading and the queue is full,
/// further frames are dropped with `ErrorKind::WouldBlock`, as a congested
/// switch port would drop them.
pub struct Conn {
    mac: MacAddr,
    /// Length-prefixed frames for the writer thread, which alone touches the
    /// socket's write side. Taken on close, which lets that thread finish.
    out: Mutex<Option<SyncSender<Vec<u8>>>>,
    handler: Arc<HandlerSlot>,
    done: Arc<DoneSignal>,
    /// Set when the writer thread has finished, and hung up the socket.
    writer_done: Arc<Latch>,
    /// Shuts the socket down in both directions: the peer sees EOF and the
    /// reader thread's blocked read returns, as does a blocked write.
    shutdown: Arc<dyn Fn() + Send + Sync>,
}

impl core::fmt::Debug for Conn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("qemu::Conn")
            .field("mac", &self.mac)
            .finish()
    }
}

impl Conn {
    /// Build a Conn from a pre-split read/write pair and a way to shut the
    /// socket down. Spawns a reader thread that invokes the installed handler
    /// for each received frame, and a writer thread that drains the outbound
    /// queue into the socket.
    ///
    /// Fails if a thread cannot be started, which, like running out of
    /// descriptors, is a condition that passes: the caller may retry.
    fn from_split(
        read: Box<dyn Read + Send + 'static>,
        write: Box<dyn Write + Send + 'static>,
        shutdown: Arc<dyn Fn() + Send + Sync>,
        slot: Option<PeerSlot>,
    ) -> Result<Arc<Conn>> {
        let mac = MacAddr::random_local_unicast();
        let handler = Arc::new(HandlerSlot {
            handler: Mutex::new(None),
            ready: Condvar::new(),
        });
        let done = DoneSignal::new();

        let handler_t = handler.clone();
        let done_t = done.clone();
        let shutdown_r = shutdown.clone();
        // Spawned with the Builder: `thread::spawn` panics when no thread
        // can be had, which would take the accept loop down with it.
        std::thread::Builder::new().spawn(move || {
            // Signals done however the thread ends: whatever else fails,
            // `wait_done` and `serve`'s cleanup must still learn of it.
            let _done = SignalOnDrop(done_t.clone());
            // The listener's count of peers drops once the peer has gone.
            let _slot = slot;
            let mut read = read;
            let mut hdr = [0u8; 4];
            let mut buf = vec![0u8; MAX_FRAME_SIZE];
            // A read that timed out is a peer idle past the listener's
            // limit: hang up on it, so it learns it has been dropped. Not
            // once closed, though: then the writer is flushing, and hangs up
            // itself when done.
            let hang_up_if_idle = |e: std::io::Error| {
                let idle = matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                );
                if idle && !done_t.closed.load(Ordering::Acquire) {
                    shutdown_r();
                }
            };
            loop {
                if let Err(e) = read.read_exact(&mut hdr) {
                    hang_up_if_idle(e);
                    break;
                }
                let len = u32::from_be_bytes(hdr) as usize;
                if !(14..=MAX_FRAME_SIZE).contains(&len) {
                    break;
                }
                if let Err(e) = read.read_exact(&mut buf[..len]) {
                    hang_up_if_idle(e);
                    break;
                }
                // Once closed, frames are read and discarded until the writer
                // hangs up: a socket closed with unread data answers with a
                // RST, which could cost the peer the frames still being
                // flushed to it.
                //
                // A panicking handler costs the frame, not the reader: ended
                // by it, the reader would no longer notice the peer hang up.
                if let Some(h) = handler_t.get(&done_t) {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        h(Frame::from_slice(&buf[..len]))
                    }));
                }
            }
        })?;

        let (out, rx) = mpsc::sync_channel::<Vec<u8>>(OUT_QUEUE_LIMIT);
        let shutdown_t = shutdown.clone();
        let writer_done = Latch::new();
        let writer_done_t = writer_done.clone();
        // Ends once the queue's sender is dropped (on close) and drained, or
        // when a write fails, and hangs up either way: on close, only now
        // that every queued frame has gone out whole; after a failed write,
        // because it may have left half a frame on the stream, after which
        // nothing sent could be framed right.
        let writer = std::thread::Builder::new().spawn(move || {
            let mut write = write;
            while let Ok(frame) = rx.recv() {
                if write.write_all(&frame).is_err() {
                    break;
                }
            }
            shutdown_t();
            writer_done_t.set();
        });
        if let Err(e) = writer {
            // The reader is running: hanging up is what ends it.
            shutdown();
            return Err(e);
        }

        Ok(Arc::new(Conn {
            mac,
            out: Mutex::new(Some(out)),
            handler,
            done,
            writer_done,
            shutdown,
        }))
    }

    fn shut(&self) {
        self.done.signal();
        // Wake a reader waiting for a handler, so it sees the close.
        let _guard = self.handler.handler.lock().unwrap();
        self.handler.ready.notify_all();
        drop(_guard);
        // Closing the queue lets the writer flush what is on it and then hang
        // up, so no frame is lost or cut in half. Only the first close does.
        if self.out.lock().unwrap().take().is_none() {
            return;
        }
        // A peer that has stopped reading would hold the writer forever:
        // past the grace period, hang up under it. That can cut a frame, but
        // the peer was not taking them anyway.
        let (writer_done, shutdown) = (self.writer_done.clone(), self.shutdown.clone());
        let watchdog = std::thread::Builder::new().spawn(move || {
            if !writer_done.wait_timeout(CLOSE_GRACE) {
                shutdown();
            }
        });
        if watchdog.is_err() {
            (self.shutdown)();
        }
    }

    /// Wait until the connection is closed (peer disconnects or
    /// [`close`](L2Device::close) is called). Cheap to call from many threads.
    pub fn wait_done(&self) {
        self.done.wait();
    }
}

impl L2Device for Conn {
    fn set_handler(&self, h: L2Handler) {
        *self.handler.handler.lock().unwrap() = Some(h);
        self.handler.ready.notify_all();
    }
    fn send(&self, f: &Frame) -> Result<()> {
        let bytes = f.as_bytes();
        if bytes.len() < 14 {
            return Ok(());
        }
        if bytes.len() > MAX_FRAME_SIZE {
            // Our own reader hangs up on a larger one, so a Conn at the other
            // end would too.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "qemu: frame larger than the protocol allows",
            ));
        }
        let mut out = Vec::with_capacity(4 + bytes.len());
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
        let q = self.out.lock().unwrap();
        let Some(q) = q.as_ref() else {
            return Err(closed());
        };
        match q.try_send(out) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "qemu: peer is not reading, frame dropped",
            )),
            Err(TrySendError::Disconnected(_)) => Err(closed()),
        }
    }
    fn hw_addr(&self) -> MacAddr {
        self.mac
    }
    fn close(&self) -> Result<()> {
        self.shut();
        Ok(())
    }
    fn done_signal(&self) -> Option<Arc<dyn crate::DoneSignal + Send + Sync>> {
        Some(self.done.clone())
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        // The reader thread holds no reference to the Conn, so without this
        // the socket would stay open, and the thread blocked on it, until the
        // peer happened to hang up.
        self.shut();
    }
}

fn closed() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::NotConnected, "qemu: connection closed")
}

impl crate::DoneSignal for DoneSignal {
    fn wait_done(&self) {
        self.wait();
    }
}

impl crate::DoneSignal for Arc<Conn> {
    fn wait_done(&self) {
        self.done.wait();
    }
}

/// Dial a QEMU socket netdev over TCP.
pub fn dial_tcp(addr: impl ToSocketAddrs) -> Result<Arc<Conn>> {
    tcp_conn(TcpStream::connect(addr)?, None, None)
}

/// `idle`: how long the peer may go without sending before it is hung up
/// on. The receive timeout is the socket's, which the clones share, but only
/// the reader reads.
fn tcp_conn(s: TcpStream, idle: Option<Duration>, slot: Option<PeerSlot>) -> Result<Arc<Conn>> {
    s.set_read_timeout(idle)?;
    let (w, c) = (s.try_clone()?, s.try_clone()?);
    let shutdown = Arc::new(move || {
        let _ = c.shutdown(Shutdown::Both);
    });
    Conn::from_split(Box::new(s), Box::new(w), shutdown, slot)
}

/// Dial a QEMU socket netdev over a Unix domain socket.
///
/// Reports `ErrorKind::Unsupported` on platforms without Unix-domain sockets;
/// use [`dial_tcp`] there.
#[cfg(unix)]
pub fn dial_unix(path: impl AsRef<Path>) -> Result<Arc<Conn>> {
    unix_conn(UnixStream::connect(path)?, None, None)
}

/// As [`tcp_conn`].
#[cfg(unix)]
fn unix_conn(s: UnixStream, idle: Option<Duration>, slot: Option<PeerSlot>) -> Result<Arc<Conn>> {
    s.set_read_timeout(idle)?;
    let (w, c) = (s.try_clone()?, s.try_clone()?);
    let shutdown = Arc::new(move || {
        let _ = c.shutdown(Shutdown::Both);
    });
    Conn::from_split(Box::new(s), Box::new(w), shutdown, slot)
}

/// Dial a QEMU socket netdev over a Unix domain socket.
///
/// This platform has none, so the call always fails; use [`dial_tcp`].
#[cfg(not(unix))]
pub fn dial_unix(path: impl AsRef<Path>) -> Result<Arc<Conn>> {
    let _ = path.as_ref();
    Err(no_unix_sockets())
}

/// The error returned by the Unix-domain entry points off Unix.
#[cfg(not(unix))]
fn no_unix_sockets() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Unix-domain sockets are not available on this platform; use TCP",
    )
}

/// Limits a [`Listener`] puts on its peers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ListenerConfig {
    /// Most peers connected at once ([`DEFAULT_MAX_PEERS`] unless set).
    /// Each costs a socket and threads, so without a bound anyone who can
    /// reach the listener could open peers until the process runs out of
    /// either. A peer arriving past it is hung up on at once; it counts
    /// until its socket's reader has seen it go.
    pub max_peers: usize,
    /// Hang up on a peer that sends nothing for this long. `None` (the
    /// default) never does: a guest with nothing to say sends nothing, so
    /// only set it where peers are known to keep talking, or to be
    /// expendable when they stop.
    pub idle_timeout: Option<Duration>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            max_peers: DEFAULT_MAX_PEERS,
            idle_timeout: None,
        }
    }
}

setters! {
    ListenerConfig {
        set max_peers: usize;
        some idle_timeout: Duration;
    }
}

/// One of a listener's peer slots, given back when dropped.
struct PeerSlot(Arc<AtomicUsize>);

impl Drop for PeerSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

enum Socket {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

/// Listens for QEMU peers over TCP or Unix sockets, within the limits of
/// its [`ListenerConfig`].
pub struct Listener {
    socket: Socket,
    cfg: ListenerConfig,
    /// Peers connected now, bounded by `cfg.max_peers`.
    peers: Arc<AtomicUsize>,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = match self.socket {
            Socket::Tcp(_) => "tcp",
            #[cfg(unix)]
            Socket::Unix(_) => "unix",
        };
        f.debug_struct("qemu::Listener")
            .field("kind", &kind)
            .field("cfg", &self.cfg)
            .field("peers", &self.peers.load(Ordering::Relaxed))
            .finish()
    }
}

impl From<TcpListener> for Listener {
    fn from(l: TcpListener) -> Listener {
        Listener::new(Socket::Tcp(l))
    }
}

#[cfg(unix)]
impl From<UnixListener> for Listener {
    fn from(l: UnixListener) -> Listener {
        Listener::new(Socket::Unix(l))
    }
}

impl Listener {
    fn new(socket: Socket) -> Listener {
        Listener {
            socket,
            cfg: ListenerConfig::default(),
            peers: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Bind a TCP listener.
    pub fn bind_tcp(addr: impl ToSocketAddrs) -> Result<Listener> {
        Ok(TcpListener::bind(addr)?.into())
    }

    /// Apply `cfg` to peers accepted from now on.
    #[must_use]
    pub fn with_config(mut self, cfg: ListenerConfig) -> Listener {
        self.cfg = cfg;
        self
    }

    /// The limits in force.
    pub fn config(&self) -> &ListenerConfig {
        &self.cfg
    }

    /// The address a TCP listener is bound to. A Unix-domain one reports
    /// `ErrorKind::InvalidInput`: its address is the path it was bound to.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        match &self.socket {
            Socket::Tcp(l) => l.local_addr(),
            #[cfg(unix)]
            Socket::Unix(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "qemu: a Unix-domain listener has no socket address",
            )),
        }
    }

    /// Take a peer slot, if one is free.
    fn reserve(&self) -> Option<PeerSlot> {
        crate::stats::add_within(&self.peers, 1, self.cfg.max_peers)
            .then(|| PeerSlot(self.peers.clone()))
    }

    /// Bind a Unix-domain listener. Any stale socket file at `path` is
    /// removed first.
    ///
    /// Reports `ErrorKind::Unsupported` on platforms without Unix-domain
    /// sockets; use [`bind_tcp`](Self::bind_tcp) there.
    #[cfg(unix)]
    pub fn bind_unix(path: impl AsRef<Path>) -> Result<Listener> {
        let _ = std::fs::remove_file(path.as_ref());
        Ok(UnixListener::bind(path)?.into())
    }

    /// Bind a Unix-domain listener.
    ///
    /// This platform has none, so the call always fails; use
    /// [`bind_tcp`](Self::bind_tcp).
    #[cfg(not(unix))]
    pub fn bind_unix(path: impl AsRef<Path>) -> Result<Listener> {
        let _ = path.as_ref();
        Err(no_unix_sockets())
    }

    /// Block until a peer arrives, then wrap it as a [`Conn`]. Peers past
    /// [`max_peers`](ListenerConfig::max_peers) are hung up on as they
    /// arrive, and the wait goes on.
    pub fn accept(&self) -> Result<Arc<Conn>> {
        let idle = self.cfg.idle_timeout;
        loop {
            // Accepted before the check, and dropped if over: left in the
            // backlog, a refused peer would sit connected to nothing.
            match &self.socket {
                Socket::Tcp(l) => {
                    let s = l.accept()?.0;
                    if let Some(slot) = self.reserve() {
                        return tcp_conn(s, idle, Some(slot));
                    }
                }
                #[cfg(unix)]
                Socket::Unix(l) => {
                    let s = l.accept()?.0;
                    if let Some(slot) = self.reserve() {
                        return unix_conn(s, idle, Some(slot));
                    }
                }
            }
        }
    }
}

impl crate::L2Acceptor for Listener {
    fn accept_l2(&self) -> Result<Arc<dyn L2Device>> {
        self.accept().map(|c| c as Arc<dyn L2Device>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EtherType, build_frame};
    use std::sync::mpsc;
    use std::time::Duration;

    /// How long to wait for the echo. Only reached when the test is failing:
    /// a passing run returns as soon as the frame is back.
    const ECHO_TIMEOUT: Duration = Duration::from_secs(10);

    fn tcp_addr(ln: &Listener) -> std::net::SocketAddr {
        ln.local_addr().unwrap()
    }

    /// Whether `conn`'s peer hangs up within the echo timeout.
    fn hangs_up(conn: &Arc<Conn>) -> bool {
        let (tx, rx) = mpsc::channel();
        let c = conn.clone();
        std::thread::spawn(move || {
            c.wait_done();
            let _ = tx.send(());
        });
        rx.recv_timeout(ECHO_TIMEOUT).is_ok()
    }

    /// Past `max_peers`, a peer is hung up on as it arrives, and the listener
    /// goes on: a slot freed by a peer leaving is there for the next one.
    #[test]
    fn peers_past_the_limit_are_refused() {
        let ln = Listener::bind_tcp("127.0.0.1:0")
            .unwrap()
            .with_config(ListenerConfig::default().max_peers(1));
        let addr = tcp_addr(&ln);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            while let Ok(c) = ln.accept() {
                c.set_handler(Arc::new(|_: &Frame| Ok(())));
                if tx.send(c).is_err() {
                    return;
                }
            }
        });
        let first = dial_tcp(addr).unwrap();
        let served = rx.recv_timeout(ECHO_TIMEOUT).expect("first never accepted");
        let second = dial_tcp(addr).unwrap();
        assert!(hangs_up(&second), "a peer past the limit was kept");

        first.close().unwrap();
        assert!(hangs_up(&served));
        // The slot is free once the reader has seen the peer go.
        let third = dial_tcp(addr).unwrap();
        rx.recv_timeout(ECHO_TIMEOUT)
            .expect("the freed slot was not reused");
        drop(third);
    }

    /// With an idle timeout, a peer that sends nothing is hung up on.
    #[test]
    fn idle_peers_are_hung_up_on_when_asked() {
        let ln = Listener::bind_tcp("127.0.0.1:0")
            .unwrap()
            .with_config(ListenerConfig::default().idle_timeout(Duration::from_millis(100)));
        let client = dial_tcp(tcp_addr(&ln)).unwrap();
        let server = ln.accept().unwrap();
        server.set_handler(Arc::new(|_: &Frame| Ok(())));
        assert!(hangs_up(&server), "the idle peer was kept");
        assert!(hangs_up(&client));
    }

    /// Accept one peer on `ln` and echo every frame back to it, holding the
    /// connection until the returned sender fires (or is dropped).
    fn echo_server(ln: Listener) -> (std::thread::JoinHandle<()>, mpsc::Sender<()>) {
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            let conn = ln.accept().unwrap();
            let conn_for_handler = conn.clone();
            conn.set_handler(Arc::new(move |f: &Frame| conn_for_handler.send(f)));
            let _ = done_rx.recv();
            drop(conn);
        });
        (t, done_tx)
    }

    /// Send `payload` through `client` and wait for the echo. Channels rather
    /// than sleeps, so a slow runner makes the test slower, not flaky.
    fn assert_echoes(client: &Arc<Conn>, payload: &[u8]) {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        client.set_handler(Arc::new(move |f: &Frame| {
            let _ = tx.send(f.as_bytes().to_vec());
            Ok(())
        }));

        let m = MacAddr([2, 0, 0, 0, 0, 1]);
        let frame = build_frame(m, m, EtherType::IPV4, payload);
        client.send(Frame::from_slice(&frame)).unwrap();

        let echoed = rx.recv_timeout(ECHO_TIMEOUT).expect("no echo");
        assert_eq!(echoed, frame);
        // Exactly one copy: nothing else may already be queued behind it.
        assert!(rx.try_recv().is_err(), "frame echoed more than once");
    }

    /// A frame that arrives before the handler is installed is delivered
    /// once it is, not dropped: the race behind the old flaky roundtrips,
    /// made certain here by sending before installing.
    #[test]
    fn frames_before_the_handler_are_held() {
        let ln = Listener::bind_tcp("127.0.0.1:0").unwrap();
        let addr = tcp_addr(&ln);
        let client = dial_tcp(addr).unwrap();
        let server = ln.accept().unwrap();

        let m = MacAddr([2, 0, 0, 0, 0, 1]);
        let frame = build_frame(m, m, EtherType::IPV4, b"early");
        client.send(Frame::from_slice(&frame)).unwrap();
        std::thread::sleep(Duration::from_millis(50)); // let the reader get it

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        server.set_handler(Arc::new(move |f: &Frame| {
            let _ = tx.send(f.as_bytes().to_vec());
            Ok(())
        }));
        assert_eq!(rx.recv_timeout(ECHO_TIMEOUT).expect("frame dropped"), frame);
    }

    /// Closing one end hangs up the socket, so the other end's reader sees
    /// EOF and its done signal fires.
    #[test]
    fn close_hangs_up_the_socket() {
        let ln = Listener::bind_tcp("127.0.0.1:0").unwrap();
        let addr = tcp_addr(&ln);
        let client = dial_tcp(addr).unwrap();
        let server = ln.accept().unwrap();
        server.set_handler(Arc::new(|_: &Frame| Ok(())));

        let (tx, rx) = mpsc::channel();
        let s = server.clone();
        std::thread::spawn(move || {
            s.wait_done();
            let _ = tx.send(());
        });
        client.close().unwrap();
        rx.recv_timeout(ECHO_TIMEOUT)
            .expect("peer never saw the close");
        // Closing is idempotent, and dropping after it is fine.
        client.close().unwrap();
        drop(client);
    }

    /// A handler that panics costs its frame, not the reader: the next frame
    /// is still delivered, and a hangup still noticed.
    #[test]
    fn a_panicking_handler_does_not_stop_the_reader() {
        let ln = Listener::bind_tcp("127.0.0.1:0").unwrap();
        let addr = tcp_addr(&ln);
        let client = dial_tcp(addr).unwrap();
        let server = ln.accept().unwrap();

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let tx = Mutex::new(tx);
        server.set_handler(Arc::new(move |f: &Frame| {
            if f.as_bytes().ends_with(b"boom") {
                panic!("handler panics");
            }
            let _ = tx.lock().unwrap().send(f.as_bytes().to_vec());
            Ok(())
        }));
        let m = MacAddr([2, 0, 0, 0, 0, 1]);
        for payload in [&b"boom"[..], b"after"] {
            let frame = build_frame(m, m, EtherType::IPV4, payload);
            client.send(Frame::from_slice(&frame)).unwrap();
        }
        let got = rx.recv_timeout(ECHO_TIMEOUT).expect("reader stopped");
        assert!(got.ends_with(b"after"));

        let (tx, rx) = mpsc::channel();
        let s = server.clone();
        std::thread::spawn(move || {
            s.wait_done();
            let _ = tx.send(());
        });
        client.close().unwrap();
        rx.recv_timeout(ECHO_TIMEOUT).expect("hangup never noticed");
    }

    /// `serve` detaches a peer once it hangs up, rather than keeping its
    /// port for good.
    #[test]
    fn serve_detaches_a_peer_that_hangs_up() {
        struct Count(Arc<Mutex<usize>>, mpsc::Sender<()>);
        impl crate::L2Connector for Count {
            fn connect_l2(&self, dev: Arc<dyn L2Device>) -> Result<crate::Cleanup> {
                *self.0.lock().unwrap() += 1;
                let _ = self.1.send(());
                let (n, tx) = (self.0.clone(), self.1.clone());
                // Holds the device while attached, as a hub port would.
                Ok(Box::new(move || {
                    drop(dev);
                    *n.lock().unwrap() -= 1;
                    let _ = tx.send(());
                    Ok(())
                }))
            }
        }

        let ln = Listener::bind_tcp("127.0.0.1:0").unwrap();
        let addr = tcp_addr(&ln);
        let attached = Arc::new(Mutex::new(0));
        let (tx, rx) = mpsc::channel();
        let connector = Count(attached.clone(), tx);
        std::thread::spawn(move || crate::serve(&ln, &connector));

        let client = dial_tcp(addr).unwrap();
        rx.recv_timeout(ECHO_TIMEOUT).expect("never attached");
        assert_eq!(*attached.lock().unwrap(), 1);
        client.close().unwrap();
        rx.recv_timeout(ECHO_TIMEOUT).expect("never detached");
        assert_eq!(*attached.lock().unwrap(), 0);
    }

    /// A peer that stops reading costs frames, not the sender: `send` keeps
    /// returning at once, with the overflow dropped, and `close` still hangs
    /// up. Before the queue, the first send past the socket buffers blocked
    /// for as long as the peer did.
    #[test]
    fn a_peer_that_stops_reading_does_not_block_the_sender() {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = dial_tcp(ln.local_addr().unwrap()).unwrap();
        // Accepted and held, never read from.
        let (_peer, _) = ln.accept().unwrap();

        let m = MacAddr([2, 0, 0, 0, 0, 1]);
        let (tx, rx) = mpsc::channel();
        let c = client.clone();
        std::thread::spawn(move || {
            let frame = build_frame(m, m, EtherType::IPV4, &[0u8; 60_000]);
            // ~120 MB offered: far more than any socket buffers hold.
            let mut dropped = 0;
            for _ in 0..2_000 {
                if let Err(e) = c.send(Frame::from_slice(&frame)) {
                    assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
                    dropped += 1;
                }
            }
            let _ = tx.send(dropped);
        });
        let dropped = rx.recv_timeout(ECHO_TIMEOUT).expect("send blocked");
        assert!(dropped > 0, "nothing was dropped");

        // The writer is still blocked on the socket; close must free it.
        client.close().unwrap();
        let frame = build_frame(m, m, EtherType::IPV4, b"late");
        assert_eq!(
            client.send(Frame::from_slice(&frame)).unwrap_err().kind(),
            std::io::ErrorKind::NotConnected
        );
    }

    /// Frames queued when `close` is called still reach the peer, each one
    /// whole, before it sees the hang-up.
    #[test]
    fn close_flushes_the_queue_before_hanging_up() {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = dial_tcp(ln.local_addr().unwrap()).unwrap();
        let (mut peer, _) = ln.accept().unwrap();

        let m = MacAddr([2, 0, 0, 0, 0, 1]);
        // More than the socket buffers hold, so most are still queued when
        // `close` is called.
        let mut sent = Vec::new();
        for i in 0..OUT_QUEUE_LIMIT as u8 {
            let frame = build_frame(m, m, EtherType::IPV4, &[i; 60_000]);
            if client.send(Frame::from_slice(&frame)).is_ok() {
                sent.push(i);
            }
        }
        client.close().unwrap();

        peer.set_read_timeout(Some(ECHO_TIMEOUT)).unwrap();
        let mut got = Vec::new();
        peer.read_to_end(&mut got)
            .expect("peer never saw the hang-up");
        let mut frames = Vec::new();
        let mut rest = &got[..];
        while !rest.is_empty() {
            assert!(rest.len() >= 4, "length prefix cut short");
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            assert!(rest.len() >= 4 + len, "frame {} cut short", frames.len());
            frames.push(rest[4 + 14]);
            rest = &rest[4 + len..];
        }
        assert_eq!(frames, sent);
    }

    /// A peer that never reads cannot hold a closed connection open: the
    /// writer is cut loose once the grace period runs out.
    #[test]
    fn close_gives_up_on_a_peer_that_never_reads() {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = dial_tcp(ln.local_addr().unwrap()).unwrap();
        let (_peer, _) = ln.accept().unwrap();

        let m = MacAddr([2, 0, 0, 0, 0, 1]);
        let frame = build_frame(m, m, EtherType::IPV4, &[0u8; 60_000]);
        for _ in 0..OUT_QUEUE_LIMIT * 2 {
            let _ = client.send(Frame::from_slice(&frame));
        }
        assert!(!client.writer_done.wait_timeout(Duration::from_millis(100)));
        client.close().unwrap();
        assert!(
            client.writer_done.wait_timeout(CLOSE_GRACE + ECHO_TIMEOUT),
            "writer still stuck on the peer"
        );
    }

    #[test]
    fn tcp_roundtrip() {
        let ln = Listener::bind_tcp("127.0.0.1:0").unwrap();
        let addr = tcp_addr(&ln);
        let (server, done) = echo_server(ln);

        let client = dial_tcp(addr).unwrap();
        assert_echoes(&client, b"hello world");

        drop(client);
        let _ = done.send(());
        server.join().unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn unix_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("pktkit-qemu-{}.sock", std::process::id()));
        let ln = Listener::bind_unix(&tmp).unwrap();
        let (server, done) = echo_server(ln);

        let client = dial_unix(&tmp).unwrap();
        assert_echoes(&client, b"hi");

        drop(client);
        let _ = done.send(());
        server.join().unwrap();
        let _ = std::fs::remove_file(&tmp);
    }
}
