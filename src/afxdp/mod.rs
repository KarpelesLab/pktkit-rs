//! Linux AF_XDP zero-copy sockets.
//!
//! Opens an `AF_XDP` socket, registers a UMEM region, sizes and `mmap`s the
//! FILL/COMPLETION/RX/TX rings, binds to an interface/queue, and runs a poll
//! loop that delivers received Ethernet frames to an
//! [`L2Handler`](crate::L2Handler) while recycling UMEM frames back to the
//! kernel.
//!
//! The in-kernel half — the XDP program that decides which packets reach this
//! socket, and the maps that steer it — lives in [`crate::xdp`].
//!
//! ```no_run
//! use pktkit::afxdp::{Config, Device};
//! use pktkit::xdp::Rule;
//! use pktkit::{Frame, IpPrefix, L2Device, Protocol};
//! use std::net::Ipv4Addr;
//! use std::sync::Arc;
//!
//! # fn main() -> std::io::Result<()> {
//! // One socket per RX queue, native-mode attach, zero-copy where the driver
//! // supports it.
//! let dev = Device::open(Config::new("eth0"))?;
//!
//! dev.set_handler(Arc::new(|frame: &Frame| {
//!     println!("{} bytes", frame.as_bytes().len());
//!     Ok(())
//! }));
//!
//! // Nothing is diverted until an address is named.
//! dev.capture_add(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 7).into(), 32))?;
//! // Or one port of an address the host stack keeps using.
//! dev.capture_add_rule(
//!     IpPrefix::new(Ipv4Addr::new(10, 0, 0, 1).into(), 32),
//!     Rule::Port(Protocol::UDP, 51820),
//! )?;
//!
//! println!("zero-copy: {}, queues: {:?}", dev.zerocopy(), dev.queue_ids());
//! # Ok(())
//! # }
//! ```
//!
//! The device is presented as an [`L2Device`](crate::L2Device):
//!
//! - [`Device::open`] performs the full setup.
//! - [`L2Device::send`](crate::L2Device::send) copies a frame into a free
//!   UMEM slot and enqueues it on the TX ring.
//! - the background poll loop invokes the installed handler per RX frame.
//!
//! # Requirements
//!
//! AF_XDP needs root (or `CAP_NET_ADMIN` + `CAP_BPF`) and a real NIC. The pure
//! pieces — ring index math, eBPF byte encoding, netlink message layout,
//! UMEM offset arithmetic — are unit-tested. Paths that require hardware are
//! marked `// TODO(afxdp): needs hardware to verify`.
//!
//! # Module layout
//!
//! - [`ring`]: lock-free SPSC rings over the `mmap`'d shared memory.
//! - `xdp` (private): socket setup and datapath; defines [`Config`]/[`Device`].

mod xdp;

pub mod ring;

pub use xdp::{BusyPoll, Config, Device, ProgramSource, Statistics, Zerocopy};
