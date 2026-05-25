//! Linux AF_XDP zero-copy sockets.
//!
//! A port of the Go upstream's `afxdp` package (`xdp.go`, `ring.go`,
//! `bpf.go`). It opens an `AF_XDP` socket, registers a UMEM region, sizes and
//! `mmap`s the FILL/COMPLETION/RX/TX rings, loads a minimal `XDP_REDIRECT`
//! eBPF program into an XSKMAP, binds to an interface/queue, and runs a poll
//! loop that delivers received Ethernet frames to an [`L2Handler`](crate::L2Handler) while
//! recycling UMEM frames back to the kernel.
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
//! - [`bpf`]: eBPF program builder/loader and XSKMAP helpers.
//! - `xdp` (private): socket setup and datapath; defines [`Config`]/[`Device`].

mod xdp;

pub mod bpf;
pub mod ring;

pub use xdp::{Config, Device};
