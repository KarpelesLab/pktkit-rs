//! `AF_PACKET` sockets: attach to an existing network interface.
//!
//! This is the plainest way to put a real NIC into a topology. Unlike the
//! `tuntap` feature it does not create a new interface — it binds to one that
//! already exists — and unlike the `afxdp` feature it needs no eBPF, no driver
//! support and no special interface configuration. It is the slowest of the
//! three and the one most likely to just work.
//!
//! (Those modules are named without links here because either may be compiled
//! out while this one is not.)
//!
//! ```no_run
//! use pktkit::afpacket::{Config, Socket};
//! use pktkit::{Frame, L2Device};
//! use std::sync::Arc;
//!
//! # fn main() -> std::io::Result<()> {
//! let dev = Socket::open(Config {
//!     interface: "eth0".into(),
//!     promiscuous: true,
//!     ..Default::default()
//! })?;
//!
//! dev.set_handler(Arc::new(|f: &Frame| {
//!     println!("{:?} -> {:?}", f.src_mac(), f.dst_mac());
//!     Ok(())
//! }));
//! # Ok(())
//! # }
//! ```
//!
//! # Privileges
//!
//! Opening an `AF_PACKET` socket needs `CAP_NET_RAW`. Without it, [`Socket::open`]
//! fails with `PermissionDenied`.
//!
//! # What you will see
//!
//! A bound socket receives every frame the interface accepts, including traffic
//! for the host itself, and — with [`Config::promiscuous`] set — traffic
//! addressed to other stations. Frames the host *sends* are also delivered back
//! unless [`Config::inbound_only`] is set. Frames written with
//! [`send`](L2Device::send) go out the interface as-is, so the Ethernet header
//! is yours to fill in.
//!
//! # Platform support
//!
//! Linux only. On other platforms the type is still present so cross-platform
//! code compiles, but [`Socket::open`] returns `ErrorKind::Unsupported`.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Socket;

#[cfg(not(target_os = "linux"))]
mod unsupported;
#[cfg(not(target_os = "linux"))]
pub use unsupported::Socket;

use std::time::Duration;

/// How to open an [`Socket`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Interface to bind to, e.g. `eth0`. Required.
    pub interface: String,
    /// Put the interface into promiscuous mode, so frames addressed to other
    /// stations are delivered too. Reverted when the socket is closed.
    pub promiscuous: bool,
    /// Deliver only frames the interface received, hiding those the host sent.
    /// Off by default, matching what `tcpdump` shows.
    pub inbound_only: bool,
    /// Kernel receive buffer in bytes; 0 leaves the system default. Raising
    /// this is the first thing to try when the drop counter climbs under load.
    pub recv_buffer: usize,
    /// How long a blocked read waits before checking whether the socket has
    /// been closed. Lower is a more responsive [`close`](L2Device::close),
    /// higher is fewer wakeups on an idle link.
    pub poll_interval: Duration,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            interface: String::new(),
            promiscuous: false,
            inbound_only: false,
            recv_buffer: 0,
            poll_interval: Duration::from_millis(250),
        }
    }
}

#[allow(unused_imports)]
use crate::L2Device;
