//! OS-level TUN and TAP devices.
//!
//! - [`Tun`] is an L3 device that reads/writes raw IP packets.
//! - [`Tap`] is an L2 device that reads/writes Ethernet frames.
//!
//! Both spawn a background reader thread which invokes the installed handler
//! for each received message.
//!
//! Platform support:
//! - **Linux**: TUN and TAP via `/dev/net/tun`.
//! - **macOS**: TUN via the `utun` kernel control. TAP is not available
//!   (the OS has no kernel TAP driver); [`Tap::open`] returns
//!   `ErrorKind::Unsupported`. The macOS path is compiled and type-checked
//!   against the `x86_64-apple-darwin` target but cannot be exercised in the
//!   Linux CI sandbox; runtime paths are marked `// TODO(tuntap): needs macOS`.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{Tap, Tun, TuntapConfig};

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::{Tap, Tun, TuntapConfig};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("the `tuntap` feature is only implemented for Linux and macOS");
