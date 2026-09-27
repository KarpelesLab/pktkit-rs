//! OS-level TUN and TAP devices.
//!
//! - [`Tun`] is an L3 device that reads/writes raw IP packets.
//! - [`Tap`] is an L2 device that reads/writes Ethernet frames.
//!
//! Both spawn a background reader thread which invokes the installed handler
//! for each received message. Until a handler is installed the reader waits
//! for one rather than discarding what arrives, so the first packets the
//! kernel sends on a fresh interface (router solicitations, MLD reports,
//! DHCP) are not lost; meanwhile the kernel queues, and drops once its queue
//! is full.
//!
//! `close` — or dropping the device — closes the fd and stops the reader, so
//! a non-persistent interface disappears and its name can be opened again.
//!
//! Platform support:
//! - **Linux**: TUN and TAP via `/dev/net/tun`.
//! - **macOS**: TUN via the `utun` kernel control. TAP is not available
//!   (the OS has no kernel TAP driver); [`Tap::open`] returns
//!   `ErrorKind::Unsupported`. The macOS path is compiled and type-checked
//!   against the `x86_64-apple-darwin` target but cannot be exercised in the
//!   Linux CI sandbox; runtime paths are marked `// TODO(tuntap): needs macOS`.
//! - **Everywhere else**: the types compile but [`Tun::open`] and [`Tap::open`]
//!   return `ErrorKind::Unsupported`.

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod reader;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{Tap, Tun, TuntapConfig};

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::{Tap, Tun, TuntapConfig};

// Everywhere else the types still exist so that `full` -- and any
// cross-platform code naming them -- compiles; opening one reports
// `Unsupported` rather than failing the build.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use unsupported::{Tap, Tun, TuntapConfig};

setters! {
    TuntapConfig {
        into name: String;
    }
}

impl TuntapConfig {
    /// Ask for the device `name`. Empty lets the kernel pick one.
    pub fn new(name: impl Into<String>) -> TuntapConfig {
        TuntapConfig::default().name(name)
    }
}
