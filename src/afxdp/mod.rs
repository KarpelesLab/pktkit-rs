//! Linux AF_XDP zero-copy sockets (work in progress).
//!
//! The Go upstream implements an AF_XDP socket driver with UMEM rings, a
//! minimal eBPF program loaded via `BPF_PROG_LOAD`, and shared
//! FILL/COMPLETION/RX/TX rings via `mmap`. Porting it to Rust requires
//! reproducing roughly 1200 lines of low-level kernel-ABI code (`bpf(2)`,
//! `mmap(2)` of `xsk_ring_offsets`, register allocation for eBPF, …) and
//! is a separate work-package.
//!
//! This stub exposes the public types so the `afxdp` feature compiles, but
//! every constructor returns
//! `io::Error::new(io::ErrorKind::Unsupported, "TODO(afxdp): not yet ported")`.
//! Track progress under `// TODO(afxdp): …` markers.

use crate::{Frame, L2Device, L2Handler, MacAddr, Result};
use std::io;

/// Configuration for an AF_XDP socket. Mirrors the Go upstream's `Config`.
#[derive(Debug, Clone)]
pub struct Config {
    /// Interface to bind, e.g. `"eth0"`.
    pub interface: String,
    /// NIC queue ID (usually 0).
    pub queue_id: u32,
    /// Ring size (must be a power of two). Default 2048.
    pub ring_size: u32,
    /// Frame size in bytes. Default 4096.
    pub frame_size: u32,
    /// Number of frames in the UMEM. Default 4096.
    pub num_frames: u32,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            interface: String::new(),
            queue_id: 0,
            ring_size: 2048,
            frame_size: 4096,
            num_frames: 4096,
        }
    }
}

/// AF_XDP socket presented as an [`L2Device`].
///
/// **TODO(afxdp):** the real implementation lives behind the `linux` cfg in
/// the Go upstream (`xdp.go`, `ring.go`, `bpf.go`). This Rust stub returns
/// `ErrorKind::Unsupported` from every constructor.
#[derive(Debug)]
pub struct Device {
    _private: (),
}

impl Device {
    /// Open an AF_XDP socket. Always returns `Unsupported` until the
    /// implementation lands.
    pub fn open(_cfg: Config) -> Result<Device> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TODO(afxdp): not yet ported from Go upstream",
        ))
    }
}

impl L2Device for Device {
    fn set_handler(&self, _h: L2Handler) {}
    fn send(&self, _f: &Frame) -> Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TODO(afxdp): send not yet implemented",
        ))
    }
    fn hw_addr(&self) -> MacAddr {
        MacAddr::zero()
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}
