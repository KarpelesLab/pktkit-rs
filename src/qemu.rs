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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

const MAX_FRAME_SIZE: usize = 65535;

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
pub struct Conn {
    mac: MacAddr,
    write: Mutex<Box<dyn Write + Send>>,
    handler: Arc<HandlerSlot>,
    done: Arc<DoneSignal>,
    /// Shuts the socket down in both directions: the peer sees EOF and the
    /// reader thread's blocked read returns.
    shutdown: Box<dyn Fn() + Send + Sync>,
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
    /// for each received frame.
    fn from_split(
        read: Box<dyn Read + Send + 'static>,
        write: Box<dyn Write + Send + 'static>,
        shutdown: Box<dyn Fn() + Send + Sync>,
    ) -> Arc<Conn> {
        let mac = MacAddr::random_local_unicast();
        let handler = Arc::new(HandlerSlot {
            handler: Mutex::new(None),
            ready: Condvar::new(),
        });
        let done = DoneSignal::new();

        let handler_t = handler.clone();
        let done_t = done.clone();
        std::thread::spawn(move || {
            let mut read = read;
            let mut hdr = [0u8; 4];
            let mut buf = vec![0u8; MAX_FRAME_SIZE];
            loop {
                if read.read_exact(&mut hdr).is_err() {
                    break;
                }
                let len = u32::from_be_bytes(hdr) as usize;
                if !(14..=MAX_FRAME_SIZE).contains(&len) {
                    break;
                }
                if read.read_exact(&mut buf[..len]).is_err() {
                    break;
                }
                let Some(h) = handler_t.get(&done_t) else {
                    break;
                };
                let _ = h(Frame::from_slice(&buf[..len]));
            }
            done_t.signal();
        });

        Arc::new(Conn {
            mac,
            write: Mutex::new(write),
            handler,
            done,
            shutdown,
        })
    }

    fn shut(&self) {
        self.done.signal();
        // Wake a reader waiting for a handler, so it sees the close.
        let _guard = self.handler.handler.lock().unwrap();
        self.handler.ready.notify_all();
        drop(_guard);
        (self.shutdown)();
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
        let mut out = Vec::with_capacity(4 + bytes.len());
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
        let mut w = self.write.lock().unwrap();
        w.write_all(&out)?;
        Ok(())
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
    tcp_conn(TcpStream::connect(addr)?)
}

fn tcp_conn(s: TcpStream) -> Result<Arc<Conn>> {
    let (w, c) = (s.try_clone()?, s.try_clone()?);
    let shutdown = Box::new(move || {
        let _ = c.shutdown(Shutdown::Both);
    });
    Ok(Conn::from_split(Box::new(s), Box::new(w), shutdown))
}

/// Dial a QEMU socket netdev over a Unix domain socket.
///
/// Reports `ErrorKind::Unsupported` on platforms without Unix-domain sockets;
/// use [`dial_tcp`] there.
#[cfg(unix)]
pub fn dial_unix(path: impl AsRef<Path>) -> Result<Arc<Conn>> {
    unix_conn(UnixStream::connect(path)?)
}

#[cfg(unix)]
fn unix_conn(s: UnixStream) -> Result<Arc<Conn>> {
    let (w, c) = (s.try_clone()?, s.try_clone()?);
    let shutdown = Box::new(move || {
        let _ = c.shutdown(Shutdown::Both);
    });
    Ok(Conn::from_split(Box::new(s), Box::new(w), shutdown))
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

/// Listens for QEMU peers over TCP or Unix sockets.
pub enum Listener {
    Tcp(TcpListener),
    /// Only present on platforms with Unix-domain sockets.
    #[cfg(unix)]
    Unix(UnixListener),
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Listener::Tcp(_) => f.write_str("qemu::Listener::Tcp"),
            #[cfg(unix)]
            Listener::Unix(_) => f.write_str("qemu::Listener::Unix"),
        }
    }
}

impl Listener {
    /// Bind a TCP listener.
    pub fn bind_tcp(addr: impl ToSocketAddrs) -> Result<Listener> {
        Ok(Listener::Tcp(TcpListener::bind(addr)?))
    }

    /// Bind a Unix-domain listener. Any stale socket file at `path` is
    /// removed first.
    ///
    /// Reports `ErrorKind::Unsupported` on platforms without Unix-domain
    /// sockets; use [`bind_tcp`](Self::bind_tcp) there.
    #[cfg(unix)]
    pub fn bind_unix(path: impl AsRef<Path>) -> Result<Listener> {
        let _ = std::fs::remove_file(path.as_ref());
        Ok(Listener::Unix(UnixListener::bind(path)?))
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

    /// Block until a peer arrives, then wrap it as a [`Conn`].
    pub fn accept(&self) -> Result<Arc<Conn>> {
        match self {
            Listener::Tcp(l) => tcp_conn(l.accept()?.0),
            #[cfg(unix)]
            Listener::Unix(l) => unix_conn(l.accept()?.0),
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

    /// The address a TCP listener is bound to. A `match` rather than
    /// `let ... else`: where there are no Unix sockets `Tcp` is the only
    /// variant, and a refutable pattern there is a warning.
    fn tcp_addr(ln: &Listener) -> std::net::SocketAddr {
        match ln {
            Listener::Tcp(l) => l.local_addr().unwrap(),
            #[cfg(unix)]
            _ => unreachable!(),
        }
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

    #[test]
    fn tcp_roundtrip() {
        let ln = Listener::bind_tcp("127.0.0.1:0").unwrap();
        let addr = match &ln {
            Listener::Tcp(l) => l.local_addr().unwrap(),
            #[cfg(unix)]
            _ => unreachable!(),
        };
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
