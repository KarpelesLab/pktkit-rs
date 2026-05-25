//! OS-level TUN and TAP devices.
//!
//! - [`Tun`] is an L3 device that reads/writes raw IP packets via `/dev/net/tun`.
//! - [`Tap`] is an L2 device that reads/writes Ethernet frames.
//!
//! Both spawn a background reader thread which invokes the installed handler
//! for each received message.
//!
//! Currently Linux-only; the Go upstream supports macOS via `utun` and that
//! port is on the to-do list. Use `cargo build --features tuntap` on Linux.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{Tap, Tun, TuntapConfig};

#[cfg(not(target_os = "linux"))]
compile_error!("the `tuntap` feature is currently only implemented for Linux");
