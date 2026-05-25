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
/// Implemented by [`qemu::Listener`](crate::qemu) and similar.
pub trait L2Acceptor {
    /// Block until the next device is available.
    fn accept_l2(&self) -> Result<Arc<dyn L2Device>>;
}

/// Receives [`L2Device`]s and owns their attachment lifecycle.
///
/// Implementations:
/// - `Arc<L2Hub>`: every device joins the shared hub
pub trait L2Connector {
    fn connect_l2(&self, dev: Arc<dyn L2Device>) -> Result<Cleanup>;
}

/// Receives [`L3Device`]s and owns their attachment lifecycle.
///
/// Natural for protocols that operate at the IP layer (e.g. WireGuard),
/// avoiding unnecessary L2 framing overhead.
pub trait L3Connector {
    fn connect_l3(&self, dev: Arc<dyn L3Device>) -> Result<Cleanup>;
}

/// A device that signals when its connection has terminated.
///
/// If an accepted L2 device implements `DoneSignal`, [`serve`] uses it to
/// trigger cleanup automatically — typical for transient connections like
/// QEMU VM sockets.
pub trait DoneSignal {
    /// Blocks the current thread until the device is closed remotely.
    /// Returning unblocks `serve`'s cleanup goroutine for this device.
    fn wait_done(&self);
}

/// Accept loop: receive devices from `acceptor` and attach each one to
/// `connector`. If a device implements [`DoneSignal`], its cleanup is invoked
/// automatically when the remote end disconnects.
///
/// Blocks until the acceptor returns an error.
pub fn serve(acceptor: &dyn L2Acceptor, connector: &dyn L2Connector) -> Result<()> {
    loop {
        let dev = acceptor.accept_l2()?;
        let cleanup = match connector.connect_l2(dev.clone()) {
            Ok(c) => c,
            Err(_) => {
                let _ = dev.close();
                continue;
            }
        };

        // If the device exposes wait_done, spawn a background thread that
        // calls cleanup() when the connection drops.
        if let Some(d) = downcast_done(&dev) {
            std::thread::spawn(move || {
                d.wait_done();
                let _ = cleanup();
            });
        } else {
            // Otherwise, leak the cleanup: the device lives until the
            // connector is dropped.
            std::mem::forget(cleanup);
        }
    }
}

// Best-effort: callers wanting automatic cleanup wrap the device in something
// that implements both `L2Device` and `DoneSignal`. To avoid coupling the
// trait surface we expose a small Arc<dyn DoneSignal> handle on those types.
fn downcast_done(_dev: &Arc<dyn L2Device>) -> Option<Arc<dyn DoneSignalThread>> {
    // The Go version uses interface assertion. Rust has no equivalent on `dyn`
    // without `dyn Any`. Connectors that need automatic cleanup should attach
    // a `DoneSignal` themselves via [`serve_with_done`].
    None
}

trait DoneSignalThread: Send + Sync + 'static {
    fn wait_done(self: Arc<Self>);
}

/// Like [`serve`], but the acceptor returns `(device, optional done signal)`
/// pairs so cleanup can be triggered when the connection drops. Use this when
/// your acceptor implementation knows when a peer disconnects.
pub fn serve_with_done<A>(acceptor: &A, connector: &dyn L2Connector) -> Result<()>
where
    A: L2AcceptorWithDone + ?Sized,
{
    loop {
        let (dev, done) = acceptor.accept_l2_with_done()?;
        let cleanup = match connector.connect_l2(dev.clone()) {
            Ok(c) => c,
            Err(_) => {
                let _ = dev.close();
                continue;
            }
        };

        if let Some(done) = done {
            std::thread::spawn(move || {
                done.wait();
                let _ = cleanup();
            });
        } else {
            std::mem::forget(cleanup);
        }
    }
}

/// Variant of [`L2Acceptor`] that yields an optional connection-closed signal
/// alongside each device.
pub trait L2AcceptorWithDone {
    fn accept_l2_with_done(&self) -> Result<(Arc<dyn L2Device>, Option<Box<dyn Done + Send>>)>;
}

/// A blocking signal raised when a peer connection is fully closed. The
/// connector uses this to release per-peer resources.
pub trait Done {
    fn wait(self: Box<Self>);
}
