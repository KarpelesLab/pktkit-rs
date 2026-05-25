//! QEMU userspace network socket protocol.
//!
//! QEMU's `-netdev socket` uses trivial framing on top of a stream socket:
//! each Ethernet frame is prefixed with a 4-byte big-endian length.
//!
//! [`Conn`] wraps any stream socket as an [`L2Device`]. [`Listener`] accepts
//! incoming sockets and yields [`Conn`]s via
//! [`L2Acceptor`](crate::L2Acceptor) so it plugs straight into
//! [`serve`](crate::serve).

use crate::{Frame, L2Device, L2Handler, MacAddr, Result};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

const MAX_FRAME_SIZE: usize = 65535;

struct DoneSignal {
    closed: AtomicBool,
    wait: (Mutex<bool>, Condvar),
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
    handler: Arc<Mutex<Option<L2Handler>>>,
    done: Arc<DoneSignal>,
}

impl core::fmt::Debug for Conn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("qemu::Conn")
            .field("mac", &self.mac)
            .finish()
    }
}

impl Conn {
    /// Build a Conn from a pre-split read/write pair. Spawns a reader thread
    /// that invokes the installed handler for each received frame.
    fn from_split(
        read: Box<dyn Read + Send + 'static>,
        write: Box<dyn Write + Send + 'static>,
    ) -> Arc<Conn> {
        let mac = MacAddr::random_local_unicast();
        let handler: Arc<Mutex<Option<L2Handler>>> = Arc::new(Mutex::new(None));
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
                let h = handler_t.lock().unwrap().clone();
                if let Some(h) = h {
                    let _ = h(Frame::from_slice(&buf[..len]));
                }
            }
            done_t.signal();
        });

        Arc::new(Conn {
            mac,
            write: Mutex::new(write),
            handler,
            done,
        })
    }

    /// Wait until the connection is closed (peer disconnects or
    /// [`close`](L2Device::close) is called). Cheap to call from many threads.
    pub fn wait_done(&self) {
        self.done.wait();
    }
}

impl L2Device for Conn {
    fn set_handler(&self, h: L2Handler) {
        *self.handler.lock().unwrap() = Some(h);
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
        self.done.signal();
        Ok(())
    }
}

impl crate::DoneSignal for Arc<Conn> {
    fn wait_done(&self) {
        self.done.wait();
    }
}

/// Dial a QEMU socket netdev over TCP.
pub fn dial_tcp(addr: impl ToSocketAddrs) -> Result<Arc<Conn>> {
    let s = TcpStream::connect(addr)?;
    let s2 = s.try_clone()?;
    Ok(Conn::from_split(Box::new(s), Box::new(s2)))
}

/// Dial a QEMU socket netdev over a Unix domain socket.
pub fn dial_unix(path: impl AsRef<Path>) -> Result<Arc<Conn>> {
    let s = UnixStream::connect(path)?;
    let s2 = s.try_clone()?;
    Ok(Conn::from_split(Box::new(s), Box::new(s2)))
}

/// Listens for QEMU peers over TCP or Unix sockets.
pub enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Listener::Tcp(_) => f.write_str("qemu::Listener::Tcp"),
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
    pub fn bind_unix(path: impl AsRef<Path>) -> Result<Listener> {
        let _ = std::fs::remove_file(path.as_ref());
        Ok(Listener::Unix(UnixListener::bind(path)?))
    }

    /// Block until a peer arrives, then wrap it as a [`Conn`].
    pub fn accept(&self) -> Result<Arc<Conn>> {
        match self {
            Listener::Tcp(l) => {
                let (s, _) = l.accept()?;
                let s2 = s.try_clone()?;
                Ok(Conn::from_split(Box::new(s), Box::new(s2)))
            }
            Listener::Unix(l) => {
                let (s, _) = l.accept()?;
                let s2 = s.try_clone()?;
                Ok(Conn::from_split(Box::new(s), Box::new(s2)))
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
    use crate::{build_frame, EtherType};
    use std::time::Duration;

    #[test]
    fn tcp_roundtrip() {
        let ln = Listener::bind_tcp("127.0.0.1:0").unwrap();
        let addr = match &ln {
            Listener::Tcp(l) => l.local_addr().unwrap(),
            _ => unreachable!(),
        };

        let server_thread = std::thread::spawn(move || {
            let conn = ln.accept().unwrap();
            let conn_for_handler = conn.clone();
            conn.set_handler(Arc::new(move |f: &Frame| conn_for_handler.send(f)));
            std::thread::sleep(Duration::from_millis(200));
            drop(conn);
        });

        let client = dial_tcp(addr).unwrap();
        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let rc = received.clone();
        client.set_handler(Arc::new(move |f: &Frame| {
            rc.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }));

        let m = MacAddr([2, 0, 0, 0, 0, 1]);
        let frame = build_frame(m, m, EtherType::IPV4, b"hello world");
        client.send(Frame::from_slice(&frame)).unwrap();

        std::thread::sleep(Duration::from_millis(100));
        let r = received.lock().unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0], frame);
        drop(client);
        server_thread.join().unwrap();
    }

    #[test]
    fn unix_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("pktkit-qemu-{}.sock", std::process::id()));
        let ln = Listener::bind_unix(&tmp).unwrap();
        let path = tmp.clone();

        let server_thread = std::thread::spawn(move || {
            let conn = ln.accept().unwrap();
            let conn_for_handler = conn.clone();
            conn.set_handler(Arc::new(move |f: &Frame| conn_for_handler.send(f)));
            std::thread::sleep(Duration::from_millis(200));
            drop(conn);
        });

        let client = dial_unix(&path).unwrap();
        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let rc = received.clone();
        client.set_handler(Arc::new(move |f: &Frame| {
            rc.lock().unwrap().push(f.as_bytes().to_vec());
            Ok(())
        }));

        let m = MacAddr([2, 0, 0, 0, 0, 1]);
        let frame = build_frame(m, m, EtherType::IPV4, b"hi");
        client.send(Frame::from_slice(&frame)).unwrap();

        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(received.lock().unwrap().len(), 1);
        drop(client);
        server_thread.join().unwrap();
        let _ = std::fs::remove_file(&tmp);
    }
}
