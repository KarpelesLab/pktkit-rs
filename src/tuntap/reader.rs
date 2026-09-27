//! What the Linux and macOS backends share: a device fd that can be closed
//! under a reader blocked on it, and the handler slot that reader waits on.
//!
//! A blocked `read(2)` on a TUN/TAP fd does not return when another thread
//! closes the fd, and closing a number another thread is still using is a
//! reuse race. So the reader blocks in `poll(2)` on the device and on a wake
//! pipe instead, and holds the fd under a read lock while it does; `close`
//! writes to the pipe, then takes the write lock — which the woken reader
//! gives up at once — and only then closes the device.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};

use crate::{DeviceStats, Result};

/// The device fd, shared by the device and its reader thread.
pub(super) struct DevFd {
    /// `None` once closed. Readers of the fd (the reader thread, `send`) hold
    /// the read lock for as long as they use the number.
    fd: RwLock<Option<OwnedFd>>,
    wake_rx: OwnedFd,
    wake_tx: OwnedFd,
    closed: AtomicBool,
}

impl DevFd {
    pub(super) fn new(fd: OwnedFd) -> Result<DevFd> {
        let (wake_rx, wake_tx) = pipe()?;
        Ok(DevFd {
            fd: RwLock::new(Some(fd)),
            wake_rx,
            wake_tx,
            closed: AtomicBool::new(false),
        })
    }

    /// Set once [`DevFd::close`] has been called.
    #[inline]
    pub(super) fn closed(&self) -> &AtomicBool {
        &self.closed
    }

    /// Close the device: wake the reader, then close the fd once nothing is
    /// using it. Returns `false` if it was already closed.
    pub(super) fn close(&self) -> bool {
        if self.closed.swap(true, Ordering::AcqRel) {
            return false;
        }
        // A pipe with nothing in it has room for the byte, and nothing else
        // is ever written to it, so this cannot block.
        let b = 1u8;
        // SAFETY: writes one byte from a live local to an fd we own.
        unsafe { libc::write(self.wake_tx.as_raw_fd(), &b as *const u8 as *const _, 1) };
        drop(self.fd.write().unwrap().take());
        true
    }

    /// Write all of `buf` as one message.
    pub(super) fn write_all(&self, buf: &[u8]) -> Result<()> {
        let guard = self.fd.read().unwrap();
        let Some(fd) = guard.as_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tuntap: device is closed",
            ));
        };
        let mut written = 0;
        while written < buf.len() {
            // SAFETY: the slice is readable for its length, and the fd stays
            // open while we hold the read lock.
            let n = unsafe {
                libc::write(
                    fd.as_raw_fd(),
                    buf[written..].as_ptr() as *const libc::c_void,
                    buf.len() - written,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            written += n as usize;
        }
        Ok(())
    }

    /// Block until one message has been read into `buf` and return its
    /// length; `Ok(None)` once the device is closed.
    ///
    /// An error means the device failed under us: the interface was deleted
    /// (`ip link del` leaves the fd answering `EBADFD`), or the fd broke some
    /// other way. Nothing more will come from it, so the device is closed
    /// here as if [`DevFd::close`] had been called, and a `send` reports it
    /// gone, as it would after a close, rather than whatever errno the dead
    /// fd happens to give.
    pub(super) fn read(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        let r = self.read_inner(buf);
        if r.is_err() {
            // `read_inner` has let go of the read lock that `close` waits on.
            self.close();
        }
        r
    }

    fn read_inner(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        loop {
            if self.closed.load(Ordering::Acquire) {
                return Ok(None);
            }
            let guard = self.fd.read().unwrap();
            let Some(fd) = guard.as_ref() else {
                return Ok(None);
            };
            let fd = fd.as_raw_fd();
            let mut fds = [
                libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.wake_rx.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: two live pollfds; the kernel writes only `revents`.
            let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if fds[1].revents != 0 || self.closed.load(Ordering::Acquire) {
                return Ok(None);
            }
            if fds[0].revents == 0 {
                continue;
            }
            // POLLERR / POLLHUP fall through to the read, which reports what
            // went wrong.
            // SAFETY: `buf` is writable for its length, and the fd stays open
            // while we hold the read lock.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => continue,
                    _ => return Err(e),
                }
            }
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tuntap: device reported end of file",
                ));
            }
            return Ok(Some(n as usize));
        }
    }
}

/// The next message's length, or `None` to stop reading. A read that failed
/// has closed the device (see [`DevFd::read`]); it counts as an error, so a
/// device that died on its own can be told from one closed on purpose.
pub(super) fn read_or_record(dev: &DevFd, buf: &mut [u8], stats: &DeviceStats) -> Option<usize> {
    dev.read(buf).unwrap_or_else(|_| {
        stats.record_error();
        None
    })
}

/// The largest MTU the kernel lets an interface have (`ETH_MAX_MTU`, and the
/// most an IPv4 or non-jumbo IPv6 packet can be anyway).
pub(super) const MAX_MTU: usize = 65535;

/// A buffer for [`DevFd::read`] that holds messages of up to `max` bytes, and
/// one byte more.
///
/// A TUN/TAP read that does not fit is cut to the buffer's length and
/// returned with no other sign of it (Linux `tun_chr_read_iter` clamps the
/// count it returns; a utun control socket is a datagram socket), so the only
/// tell is a read that fills the buffer. The spare byte keeps a message of
/// exactly `max` bytes from looking like one.
pub(super) fn msg_buffer(max: usize) -> Vec<u8> {
    vec![0u8; max + 1]
}

/// Whether a read of `n` bytes into `buf`, from [`msg_buffer`], got the whole
/// message rather than the front of a longer one.
#[inline]
pub(super) fn is_whole(n: usize, buf: &[u8]) -> bool {
    n < buf.len()
}

/// Hand one message to the handler, containing a panic in it.
///
/// This runs on the reader thread, which nothing joins or watches: a panic
/// that unwound out of it would end receive for good, silently, while the
/// device still looked open and `send` still worked. One bad message should
/// cost that message, not the device.
pub(super) fn deliver<T: ?Sized>(h: &Arc<dyn Fn(&T) -> Result<()> + Send + Sync>, msg: &T) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h(msg)));
}

/// A handler the reader thread can wait for.
///
/// Until one is installed, the reader holds on to the message it has and
/// stops reading, so the kernel queues what follows (and drops once its queue
/// is full, as for a NIC with no driver bound) instead of the device throwing
/// away what the kernel sends first: router and neighbor solicitations, MLD
/// reports, DHCP.
pub(super) struct HandlerSlot<H> {
    handler: Mutex<Option<H>>,
    ready: Condvar,
}

impl<H: Clone> HandlerSlot<H> {
    pub(super) fn new() -> HandlerSlot<H> {
        HandlerSlot {
            handler: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    pub(super) fn set(&self, h: H) {
        *self.handler.lock().unwrap() = Some(h);
        self.ready.notify_all();
    }

    /// The handler, waiting for one if none is installed yet. `None` once
    /// `closed` is set and [`HandlerSlot::wake`] has been called.
    pub(super) fn wait(&self, closed: &AtomicBool) -> Option<H> {
        let mut h = self.handler.lock().unwrap();
        loop {
            // Checked under the lock `wake` takes, so a close cannot slip in
            // between this and the wait.
            if closed.load(Ordering::Acquire) {
                return None;
            }
            if let Some(h) = h.as_ref() {
                return Some(h.clone());
            }
            h = self.ready.wait(h).unwrap();
        }
    }

    /// Wake a reader waiting in [`HandlerSlot::wait`], after `closed` is set.
    pub(super) fn wake(&self) {
        let _guard = self.handler.lock().unwrap();
        self.ready.notify_all();
    }
}

/// A close-on-exec pipe: `(read end, write end)`.
fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    #[cfg(target_os = "linux")]
    // SAFETY: `fds` has room for the two fds pipe2 writes.
    let r = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    #[cfg(not(target_os = "linux"))]
    // SAFETY: `fds` has room for the two fds pipe writes.
    let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: two fresh fds nothing else owns.
    let (rx, tx) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    #[cfg(not(target_os = "linux"))]
    for fd in [&rx, &tx] {
        // SAFETY: plain fcntl on an fd we own. Best effort: without it the
        // pipe merely leaks into a child that execs.
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    Ok((rx, tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    /// A datagram socket pair stands in for the device: one message per read,
    /// like a TUN/TAP fd.
    fn device() -> (Arc<DevFd>, UnixDatagram) {
        let (dev, peer) = UnixDatagram::pair().unwrap();
        (Arc::new(DevFd::new(OwnedFd::from(dev)).unwrap()), peer)
    }

    #[test]
    fn a_message_is_read_whole() {
        let (dev, peer) = device();
        peer.send(b"hello").unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(dev.read(&mut buf).unwrap(), Some(5));
        assert_eq!(&buf[..5], b"hello");
        dev.write_all(b"back").unwrap();
        let mut got = [0u8; 8];
        assert_eq!(peer.recv(&mut got).unwrap(), 4);
    }

    #[test]
    fn a_message_too_long_for_the_buffer_is_told_apart() {
        let (dev, peer) = device();
        let mut buf = msg_buffer(8);
        // Exactly the most the buffer is for: whole.
        peer.send(&[1; 8]).unwrap();
        let n = dev.read(&mut buf).unwrap().unwrap();
        assert_eq!(n, 8);
        assert!(is_whole(n, &buf));
        // Longer: the kernel cuts it short, and nothing but the length shows.
        peer.send(&[2; 20]).unwrap();
        let n = dev.read(&mut buf).unwrap().unwrap();
        assert!(!is_whole(n, &buf), "a truncated read passed as whole");
        // The next message is unaffected.
        peer.send(&[3; 5]).unwrap();
        let n = dev.read(&mut buf).unwrap().unwrap();
        assert!(is_whole(n, &buf));
        assert_eq!(&buf[..n], &[3; 5]);
    }

    #[test]
    fn deliver_contains_a_panicking_handler() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let h: Arc<dyn Fn(&[u8]) -> Result<()> + Send + Sync> = Arc::new(move |m: &[u8]| {
            assert_ne!(m, b"boom", "handler panics");
            s.lock().unwrap().push(m.to_vec());
            Ok(())
        });
        deliver(&h, &b"boom"[..]);
        deliver(&h, &b"next"[..]);
        assert_eq!(*seen.lock().unwrap(), [b"next".to_vec()]);
    }

    #[test]
    fn close_wakes_a_blocked_reader_and_closes_the_fd() {
        let (dev, peer) = device();
        let d = dev.clone();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            d.read(&mut buf).unwrap()
        });
        // Let the reader block in poll.
        std::thread::sleep(Duration::from_millis(50));
        assert!(dev.close());
        assert_eq!(reader.join().unwrap(), None);
        // The device end is closed even though `dev` is still alive: the peer
        // can no longer reach it.
        assert!(peer.send(b"x").is_err());
        assert!(!dev.close(), "a second close is a no-op");
        assert_eq!(
            dev.write_all(b"x").unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[test]
    fn close_from_the_reader_thread_does_not_deadlock() {
        // A handler may close the device it was called from.
        let (dev, peer) = device();
        peer.send(b"one").unwrap();
        let d = dev.clone();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let first = d.read(&mut buf).unwrap();
            d.close();
            (first, d.read(&mut buf).unwrap())
        });
        assert_eq!(reader.join().unwrap(), (Some(3), None));
    }

    #[test]
    fn a_failed_device_is_closed_so_send_reports_it_gone() {
        // A directory polls readable and then fails every read (EISDIR),
        // standing in for a TUN fd whose interface was deleted.
        let dir = std::fs::File::open("/").unwrap();
        let dev = DevFd::new(OwnedFd::from(dir)).unwrap();
        let mut buf = [0u8; 64];
        assert!(dev.read(&mut buf).is_err());
        assert!(dev.closed().load(Ordering::Acquire));
        assert_eq!(
            dev.write_all(b"x").unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        // Further reads see a closed device, not a fresh error.
        assert_eq!(dev.read(&mut buf).unwrap(), None);
        assert!(!dev.close(), "already closed by the failure");
    }

    #[test]
    fn the_reader_waits_for_a_handler() {
        let slot: Arc<HandlerSlot<u32>> = Arc::new(HandlerSlot::new());
        let closed = Arc::new(AtomicBool::new(false));
        let (s, c) = (slot.clone(), closed.clone());
        let waiter = std::thread::spawn(move || s.wait(&c));
        std::thread::sleep(Duration::from_millis(50));
        assert!(!waiter.is_finished(), "returned before a handler was set");
        slot.set(7);
        assert_eq!(waiter.join().unwrap(), Some(7));
    }

    #[test]
    fn close_releases_a_reader_waiting_for_a_handler() {
        let slot: Arc<HandlerSlot<u32>> = Arc::new(HandlerSlot::new());
        let closed = Arc::new(AtomicBool::new(false));
        let (s, c) = (slot.clone(), closed.clone());
        let waiter = std::thread::spawn(move || s.wait(&c));
        std::thread::sleep(Duration::from_millis(50));
        closed.store(true, Ordering::Release);
        slot.wake();
        assert_eq!(waiter.join().unwrap(), None);
    }

    #[test]
    fn the_wake_pipe_is_a_pipe() {
        let (rx, tx) = pipe().unwrap();
        let mut tx = std::fs::File::from(tx);
        let mut rx = std::fs::File::from(rx);
        tx.write_all(b"z").unwrap();
        let mut b = [0u8; 1];
        rx.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"z");
    }
}
