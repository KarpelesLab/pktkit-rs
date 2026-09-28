//! Joining devices to a topology as they arrive.
//!
//! Where [`connect_l2`](crate::connect_l2) wires two known devices together,
//! this is the other shape: something produces devices over time -- a listening
//! socket accepting VM connections, say -- and each one should be attached to a
//! hub as it appears and detached when it goes away.
//!
//! [`L2Acceptor`] is the source of devices, [`L2Connector`] is what they are
//! joined to (any `Arc<L2Hub>` is one), and [`serve`] runs the loop that
//! marries the two.

use crate::{L2Device, L3Device, Result};
use std::sync::Arc;

/// A cleanup function returned by a `Connector` implementation. Calling it
/// detaches the device that was attached and releases any per-device resources.
///
/// `Cleanup` is callable exactly once; dropping it without calling typically
/// also releases the device (each connector decides), but the explicit call is
/// the contract used by [`serve`].
pub type Cleanup = Box<dyn FnOnce() -> Result<()> + Send>;

/// Produces [`L2Device`]s, typically by accepting incoming network connections.
///
/// Implemented by the `qemu` feature's `Listener` and similar.
pub trait L2Acceptor {
    /// Block until the next device is available.
    fn accept_l2(&self) -> Result<Arc<dyn L2Device>>;
}

/// Receives [`L2Device`]s and owns their attachment lifecycle.
///
/// Implementations:
/// - `Arc<L2Hub>`: every device joins the shared hub
pub trait L2Connector {
    /// Attach `dev`. The returned [`Cleanup`] detaches it again.
    fn connect_l2(&self, dev: Arc<dyn L2Device>) -> Result<Cleanup>;
}

/// Receives [`L3Device`]s and owns their attachment lifecycle.
///
/// Natural for protocols that operate at the IP layer (e.g. WireGuard),
/// avoiding unnecessary L2 framing overhead.
pub trait L3Connector {
    /// Attach `dev`. The returned [`Cleanup`] detaches it again.
    fn connect_l3(&self, dev: Arc<dyn L3Device>) -> Result<Cleanup>;
}

/// A device that signals when its connection has terminated.
///
/// A device hands one out through [`L2Device::done_signal`], and [`serve`]
/// uses it to trigger cleanup automatically — typical for transient
/// connections like QEMU VM sockets.
pub trait DoneSignal {
    /// Blocks the current thread until the device is closed remotely.
    /// Returning unblocks `serve`'s cleanup thread for this device.
    fn wait_done(&self);
}

/// Accept loop: receive devices from `acceptor` and attach each one to
/// `connector`. If a device offers a [`DoneSignal`] (see
/// [`L2Device::done_signal`]), its cleanup is invoked automatically when the
/// remote end disconnects; any other device stays attached for as long as
/// the connector keeps it.
///
/// Blocks until the acceptor returns an error that retrying cannot cure.
/// One that can -- out of file descriptors or memory, a peer that gave up
/// while queued -- is waited out, backing off from 5 ms to 1 s, rather than
/// end the loop, and with it every future connection, over a condition
/// that passes when a peer leaves.
pub fn serve(acceptor: &dyn L2Acceptor, connector: &dyn L2Connector) -> Result<()> {
    let mut backoff = Backoff::default();
    loop {
        let dev = match acceptor.accept_l2() {
            Ok(dev) => dev,
            Err(e) => {
                backoff.wait_out(e)?;
                continue;
            }
        };
        backoff.reset();
        let cleanup = match connector.connect_l2(dev.clone()) {
            Ok(c) => c,
            Err(_) => {
                let _ = dev.close();
                continue;
            }
        };

        // Waiting on the signal needs a thread of its own; without threads
        // (wasm) there is no waiting, and the device stays attached.
        #[cfg(not(target_family = "wasm"))]
        if let Some(done) = dev.done_signal() {
            detach_when(&*dev, cleanup, move || done.wait_done());
            continue;
        }

        // Nothing will say when this device goes away, so it stays attached
        // until the connector itself is dropped.
        std::mem::forget(cleanup);
    }
}

/// Like [`serve`], but the acceptor returns `(device, optional done signal)`
/// pairs so cleanup can be triggered when the connection drops. Use this when
/// your acceptor implementation knows when a peer disconnects.
///
/// Each done signal is waited on from its own thread, so this is absent on
/// targets without threads (`wasm32`).
#[cfg(not(target_family = "wasm"))]
pub fn serve_with_done<A>(acceptor: &A, connector: &dyn L2Connector) -> Result<()>
where
    A: L2AcceptorWithDone + ?Sized,
{
    let mut backoff = Backoff::default();
    loop {
        let (dev, done) = match acceptor.accept_l2_with_done() {
            Ok(accepted) => accepted,
            Err(e) => {
                backoff.wait_out(e)?;
                continue;
            }
        };
        backoff.reset();
        let cleanup = match connector.connect_l2(dev.clone()) {
            Ok(c) => c,
            Err(_) => {
                let _ = dev.close();
                continue;
            }
        };

        if let Some(done) = done {
            detach_when(&*dev, cleanup, move || done.wait());
        } else {
            std::mem::forget(cleanup);
        }
    }
}

/// Run `cleanup` once `wait` returns, from a thread of its own. Out of
/// threads, as with descriptors, `thread::spawn` would panic and take the
/// accept loop down: instead the device is detached and closed at once,
/// since nothing would be left to notice it go.
#[cfg(not(target_family = "wasm"))]
fn detach_when(dev: &dyn L2Device, cleanup: Cleanup, wait: impl FnOnce() + Send + 'static) {
    let cell = Arc::new(std::sync::Mutex::new(Some(cleanup)));
    let c = cell.clone();
    let spawned = std::thread::Builder::new().spawn(move || {
        wait();
        if let Some(cleanup) = c.lock().unwrap().take() {
            let _ = cleanup();
        }
    });
    if spawned.is_err() {
        if let Some(cleanup) = cell.lock().unwrap().take() {
            let _ = cleanup();
        }
        let _ = dev.close();
    }
}

/// The accept loops' answer to a failed accept: wait and retry if the error
/// is one that passes, give up with it otherwise.
#[derive(Default)]
struct Backoff {
    /// The next wait; zero until an error has been seen.
    delay: std::time::Duration,
}

impl Backoff {
    const FIRST: std::time::Duration = std::time::Duration::from_millis(5);
    const MAX: std::time::Duration = std::time::Duration::from_secs(1);

    fn reset(&mut self) {
        self.delay = std::time::Duration::ZERO;
    }

    /// Sleep before the next attempt if `e` is transient, or hand it back.
    /// Without threads (wasm) nothing can change while we sleep, and sleep
    /// is not allowed, so every error ends the loop there.
    ///
    /// Only real failures back off further each time. `WouldBlock` is a
    /// non-blocking listener with nobody waiting, not a failure: it is
    /// polled again at the shortest interval, and leaves the backoff where
    /// it was. An interrupted call is simply made again.
    fn wait_out(&mut self, e: std::io::Error) -> Result<()> {
        if cfg!(target_family = "wasm") || !transient(&e) {
            return Err(e);
        }
        let wait = match e.kind() {
            std::io::ErrorKind::Interrupted => return Ok(()),
            std::io::ErrorKind::WouldBlock => Self::FIRST,
            _ => {
                self.delay = (self.delay * 2).clamp(Self::FIRST, Self::MAX);
                self.delay
            }
        };
        #[cfg(not(target_family = "wasm"))]
        std::thread::sleep(wait);
        #[cfg(target_family = "wasm")]
        let _ = wait;
        Ok(())
    }
}

/// Whether an accept that failed with `e` may succeed if tried again: the
/// process or system is out of descriptors, buffers or memory (which a
/// departing peer gives back), the connection was dropped while it waited
/// in the backlog, or the call was interrupted. Linux's accept(2) also
/// asks for its pending network errors to be treated as a retry (they
/// belong to the connection being accepted, not the listener), and the
/// BSDs can report the same network conditions for a queued connection.
/// Anything else, such as a listener that was closed, ends the loop.
fn transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    if matches!(
        e.kind(),
        ConnectionAborted
            | ConnectionReset
            | Interrupted
            | WouldBlock
            | OutOfMemory
            | NetworkDown
            | NetworkUnreachable
            | HostUnreachable
    ) {
        return true;
    }
    // The rest have no ErrorKind of their own, and there is no libc to name
    // them here, so by number, which is fixed per ABI -- but not the same on
    // every Linux architecture.
    //
    // Linux: EMFILE, ENFILE, ENOBUFS, then accept(2)'s network errors:
    // ENETDOWN, EPROTO, ENOPROTOOPT, EHOSTDOWN, ENONET, EHOSTUNREACH,
    // EOPNOTSUPP, ENETUNREACH.
    #[cfg(all(
        any(target_os = "linux", target_os = "android", target_os = "fullrust"),
        not(any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ))]
    const CODES: &[i32] = &[24, 23, 105, 100, 71, 92, 112, 64, 113, 95, 101];
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "mips",
            target_arch = "mips32r6",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    ))]
    const CODES: &[i32] = &[24, 23, 132, 127, 71, 99, 147, 64, 148, 122, 128];
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "sparc", target_arch = "sparc64")
    ))]
    const CODES: &[i32] = &[24, 23, 55, 50, 86, 42, 64, 80, 65, 45, 51];
    // WSAEMFILE, WSAENOBUFS, WSAENETDOWN, WSAEHOSTDOWN, WSAEHOSTUNREACH,
    // WSAENETUNREACH.
    #[cfg(windows)]
    const CODES: &[i32] = &[10024, 10055, 10050, 10064, 10065, 10051];
    // The BSDs and Apple: EMFILE, ENFILE, ENOBUFS, ENETDOWN, ENETUNREACH,
    // EHOSTDOWN, EHOSTUNREACH, and EPROTO, which each numbers its own way.
    // Not EOPNOTSUPP or ENOPROTOOPT: from a BSD accept those are about the
    // listener, and permanent.
    #[cfg(target_vendor = "apple")]
    const CODES: &[i32] = &[24, 23, 55, 50, 51, 64, 65, 100];
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    const CODES: &[i32] = &[24, 23, 55, 50, 51, 64, 65, 92];
    #[cfg(target_os = "netbsd")]
    const CODES: &[i32] = &[24, 23, 55, 50, 51, 64, 65, 96];
    #[cfg(target_os = "openbsd")]
    const CODES: &[i32] = &[24, 23, 55, 50, 51, 64, 65, 95];
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "fullrust",
        windows,
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    const CODES: &[i32] = &[24, 23, 55, 50, 51, 64, 65];
    e.raw_os_error().is_some_and(|c| CODES.contains(&c))
}

/// Variant of [`L2Acceptor`] that yields an optional connection-closed signal
/// alongside each device.
pub trait L2AcceptorWithDone {
    /// Block until the next device is available, returning it with the signal
    /// that its connection has closed, if it has one.
    fn accept_l2_with_done(&self) -> Result<(Arc<dyn L2Device>, Option<Box<dyn Done + Send>>)>;
}

/// A blocking signal raised when a peer connection is fully closed. The
/// connector uses this to release per-peer resources.
pub trait Done {
    /// Block until the connection has closed.
    fn wait(self: Box<Self>);
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use super::*;
    use crate::{Frame, L2Handler, MacAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    /// Raised by the test, standing in for a peer hanging up.
    #[derive(Default)]
    struct Hangup(Mutex<bool>, Condvar);

    impl Hangup {
        fn raise(&self) {
            *self.0.lock().unwrap() = true;
            self.1.notify_all();
        }
    }

    impl DoneSignal for Hangup {
        fn wait_done(&self) {
            let mut up = self.0.lock().unwrap();
            while !*up {
                up = self.1.wait(up).unwrap();
            }
        }
    }

    struct Transient(Arc<Hangup>);

    impl L2Device for Transient {
        fn set_handler(&self, _: L2Handler) {}
        fn send(&self, _: &Frame) -> Result<()> {
            Ok(())
        }
        fn hw_addr(&self) -> MacAddr {
            MacAddr::zero()
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
        fn done_signal(&self) -> Option<Arc<dyn DoneSignal + Send + Sync>> {
            Some(self.0.clone())
        }
    }

    /// Hands out its devices, then fails, which ends `serve`.
    struct Queue(Mutex<Vec<Arc<dyn L2Device>>>);

    impl L2Acceptor for Queue {
        fn accept_l2(&self) -> Result<Arc<dyn L2Device>> {
            self.0
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| std::io::ErrorKind::BrokenPipe.into())
        }
    }

    /// Counts attachments still in place.
    struct Attached(Arc<AtomicUsize>, mpsc::Sender<()>);

    impl L2Connector for Attached {
        fn connect_l2(&self, _: Arc<dyn L2Device>) -> Result<Cleanup> {
            self.0.fetch_add(1, Ordering::SeqCst);
            let (n, tx) = (self.0.clone(), self.1.clone());
            Ok(Box::new(move || {
                n.fetch_sub(1, Ordering::SeqCst);
                let _ = tx.send(());
                Ok(())
            }))
        }
    }

    /// Fails as the acceptor is told to, then hands out its devices.
    struct Flaky(Mutex<Vec<std::io::Error>>, Queue);

    impl L2Acceptor for Flaky {
        fn accept_l2(&self) -> Result<Arc<dyn L2Device>> {
            match self.0.lock().unwrap().pop() {
                Some(e) => Err(e),
                None => self.1.accept_l2(),
            }
        }
    }

    /// Running out of file descriptors, or a peer giving up in the backlog,
    /// passes: the loop must wait it out, not stop accepting for good.
    #[test]
    fn serve_retries_transient_accept_errors() {
        #[cfg(not(windows))]
        let emfile = std::io::Error::from_raw_os_error(24);
        #[cfg(windows)]
        let emfile = std::io::Error::from_raw_os_error(10024);
        let hangup = Arc::new(Hangup::default());
        let acceptor = Flaky(
            Mutex::new(vec![
                emfile,
                std::io::ErrorKind::ConnectionAborted.into(),
                std::io::ErrorKind::Interrupted.into(),
            ]),
            Queue(Mutex::new(vec![Arc::new(Transient(hangup.clone()))])),
        );
        let attached = Arc::new(AtomicUsize::new(0));
        let (tx, _rx) = mpsc::channel();
        let connector = Attached(attached.clone(), tx);
        let err = serve(&acceptor, &connector).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(
            attached.load(Ordering::SeqCst),
            1,
            "gave up before the device"
        );
        hangup.raise();
    }

    /// The network errors Linux's accept(2) says to retry on, and their
    /// counterparts elsewhere, are retried; a closed listener is not.
    #[test]
    fn pending_network_errors_are_transient() {
        #[cfg(all(
            any(target_os = "linux", target_os = "android"),
            not(any(
                target_arch = "mips",
                target_arch = "mips64",
                target_arch = "sparc",
                target_arch = "sparc64"
            ))
        ))]
        let (unreach, host_unreach, eproto) = (101, 113, Some(71));
        #[cfg(target_vendor = "apple")]
        let (unreach, host_unreach, eproto) = (51, 65, Some(100));
        #[cfg(windows)]
        let (unreach, host_unreach, eproto) = (10051, 10065, None);
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            windows
        )))]
        let (unreach, host_unreach, eproto) = (51, 65, None);
        for code in [Some(unreach), Some(host_unreach), eproto]
            .into_iter()
            .flatten()
        {
            let e = std::io::Error::from_raw_os_error(code);
            assert!(transient(&e), "{e} ends the accept loop");
        }
        assert!(!transient(&std::io::ErrorKind::InvalidInput.into()));
        assert!(!transient(&std::io::ErrorKind::BrokenPipe.into()));
    }

    /// A non-blocking listener with nothing to accept is not failing: it
    /// is polled at the shortest interval, and the backoff does not grow.
    #[test]
    fn would_block_does_not_grow_the_backoff() {
        let mut b = Backoff::default();
        for _ in 0..4 {
            b.wait_out(std::io::ErrorKind::WouldBlock.into()).unwrap();
        }
        assert_eq!(b.delay, std::time::Duration::ZERO);
        b.wait_out(std::io::ErrorKind::ConnectionAborted.into())
            .unwrap();
        assert_eq!(b.delay, Backoff::FIRST);
        b.wait_out(std::io::ErrorKind::WouldBlock.into()).unwrap();
        assert_eq!(b.delay, Backoff::FIRST);
    }

    #[test]
    fn serve_detaches_a_device_once_its_peer_hangs_up() {
        let hangup = Arc::new(Hangup::default());
        let acceptor = Queue(Mutex::new(vec![Arc::new(Transient(hangup.clone()))]));
        let attached = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        let connector = Attached(attached.clone(), tx);

        assert!(serve(&acceptor, &connector).is_err(), "acceptor ran dry");
        assert_eq!(attached.load(Ordering::SeqCst), 1);

        hangup.raise();
        rx.recv_timeout(Duration::from_secs(5))
            .expect("cleanup never ran");
        assert_eq!(attached.load(Ordering::SeqCst), 0);
    }
}
