//! Stub for platforms with no TUN/TAP driver.
//!
//! The types exist so cross-platform code compiles; opening one reports
//! `Unsupported`.

use crate::{Frame, IpPrefix, L2Device, L2Handler, L3Device, L3Handler, MacAddr, Packet, Result};
use std::io;

/// Knobs for opening a TUN or TAP device.
#[derive(Debug, Clone, Default)]
pub struct TuntapConfig {
    /// Requested interface name; ignored on this platform.
    pub name: String,
}

fn unsupported<T>() -> Result<T> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TUN/TAP is only implemented for Linux and macOS",
    ))
}

/// A TUN device. Not available on this platform.
#[derive(Debug)]
pub struct Tun(());

impl Tun {
    /// Always fails with [`io::ErrorKind::Unsupported`] here.
    pub fn open(_cfg: TuntapConfig) -> Result<Tun> {
        unsupported()
    }

    pub fn name(&self) -> &str {
        ""
    }
}

/// A TAP device. Not available on this platform.
#[derive(Debug)]
pub struct Tap(());

impl Tap {
    /// Always fails with [`io::ErrorKind::Unsupported`] here.
    pub fn open(_cfg: TuntapConfig) -> Result<Tap> {
        unsupported()
    }

    pub fn name(&self) -> &str {
        ""
    }
}

impl L3Device for Tun {
    fn set_handler(&self, _h: L3Handler) {}
    fn send(&self, _p: &Packet) -> Result<()> {
        unsupported()
    }
    fn addr(&self) -> IpPrefix {
        IpPrefix::default()
    }
    fn set_addr(&self, _p: IpPrefix) -> Result<()> {
        unsupported()
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}

impl L2Device for Tap {
    fn set_handler(&self, _h: L2Handler) {}
    fn send(&self, _f: &Frame) -> Result<()> {
        unsupported()
    }
    fn hw_addr(&self) -> MacAddr {
        MacAddr::zero()
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}
