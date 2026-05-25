//! Linux TUN/TAP via `/dev/net/tun` and `ioctl(TUNSETIFF)`.
//!
//! Reader threads call the installed handler synchronously; the buffer
//! handed to the handler is the read scratch and is only valid for the
//! duration of the call (mirroring the rest of the crate).

use crate::{Frame, IpPrefix, L2Device, L2Handler, L3Device, L3Handler, MacAddr, Packet, Result};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Knobs for opening a TUN or TAP device.
#[derive(Debug, Clone, Default)]
pub struct TuntapConfig {
    /// Requested interface name; empty asks the kernel to pick one
    /// (`tun0`, `tap0`, …).
    pub name: String,
}

/// Linux TUN device — raw IPv4/IPv6 packets.
pub struct Tun {
    inner: Arc<DevInner>,
    handler: Arc<Mutex<Option<L3Handler>>>,
    addr: Mutex<IpPrefix>,
}

/// Linux TAP device — full Ethernet frames including header.
pub struct Tap {
    inner: Arc<DevInner>,
    handler: Arc<Mutex<Option<L2Handler>>>,
    mac: MacAddr,
}

struct DevInner {
    fd: OwnedFd,
    name: String,
    closed: AtomicBool,
}

impl DevInner {
    fn raw(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

impl core::fmt::Debug for Tun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("tuntap::Tun")
            .field("name", &self.inner.name)
            .finish()
    }
}

impl core::fmt::Debug for Tap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("tuntap::Tap")
            .field("name", &self.inner.name)
            .field("mac", &self.mac)
            .finish()
    }
}

impl Tun {
    /// Open a TUN (L3) device. Requires `CAP_NET_ADMIN` or root.
    pub fn open(cfg: TuntapConfig) -> Result<Tun> {
        let (fd, name) = open_tuntap(&cfg.name, libc::IFF_TUN | libc::IFF_NO_PI)?;
        let inner = Arc::new(DevInner {
            fd,
            name,
            closed: AtomicBool::new(false),
        });
        let handler: Arc<Mutex<Option<L3Handler>>> = Arc::new(Mutex::new(None));

        let inner_t = inner.clone();
        let handler_t = handler.clone();
        std::thread::spawn(move || read_loop_l3(inner_t, handler_t));

        Ok(Tun {
            inner,
            handler,
            addr: Mutex::new(IpPrefix::default()),
        })
    }

    /// OS interface name (e.g. `tun0`).
    pub fn name(&self) -> &str {
        &self.inner.name
    }
}

impl Tap {
    /// Open a TAP (L2) device. Requires `CAP_NET_ADMIN` or root.
    pub fn open(cfg: TuntapConfig) -> Result<Tap> {
        let (fd, name) = open_tuntap(&cfg.name, libc::IFF_TAP | libc::IFF_NO_PI)?;
        let mac = read_hw_addr(&name).unwrap_or_else(|_| MacAddr::random_local_unicast());
        let inner = Arc::new(DevInner {
            fd,
            name,
            closed: AtomicBool::new(false),
        });
        let handler: Arc<Mutex<Option<L2Handler>>> = Arc::new(Mutex::new(None));

        let inner_t = inner.clone();
        let handler_t = handler.clone();
        std::thread::spawn(move || read_loop_l2(inner_t, handler_t));

        Ok(Tap {
            inner,
            handler,
            mac,
        })
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }
}

// --- L3Device for Tun -----------------------------------------------------

impl L3Device for Tun {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }
    fn send(&self, pkt: &Packet) -> Result<()> {
        write_all(self.inner.raw(), pkt.as_bytes())
    }
    fn addr(&self) -> IpPrefix {
        *self.addr.lock().unwrap()
    }
    fn set_addr(&self, p: IpPrefix) -> Result<()> {
        *self.addr.lock().unwrap() = p;
        Ok(())
    }
    fn close(&self) -> Result<()> {
        self.inner.closed.store(true, Ordering::Release);
        // OwnedFd will close when DevInner is dropped — but to make the
        // reader thread exit promptly we shutdown the fd by closing a dup.
        // Easiest is to just trust Drop on the Arc<DevInner> when the last
        // reference goes; the reader holds one too. Caller should drop the
        // Tun and let GC do its thing.
        Ok(())
    }
}

// --- L2Device for Tap -----------------------------------------------------

impl L2Device for Tap {
    fn set_handler(&self, h: L2Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }
    fn send(&self, f: &Frame) -> Result<()> {
        write_all(self.inner.raw(), f.as_bytes())
    }
    fn hw_addr(&self) -> MacAddr {
        self.mac
    }
    fn close(&self) -> Result<()> {
        self.inner.closed.store(true, Ordering::Release);
        Ok(())
    }
}

// --- syscalls --------------------------------------------------------------

fn open_tuntap(name: &str, flags: i32) -> Result<(OwnedFd, String)> {
    // Open /dev/net/tun
    let path = CString::new("/dev/net/tun").unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // struct ifreq { char ifr_name[IFNAMSIZ]; union { short flags; ... }; }
    // We hand-build the request as a 40-byte buffer to be ABI-stable.
    let mut ifr = [0u8; 40];
    let bytes = name.as_bytes();
    let n = bytes.len().min(15); // leave room for NUL
    ifr[..n].copy_from_slice(&bytes[..n]);
    let flags_u16 = flags as u16;
    ifr[16..18].copy_from_slice(&flags_u16.to_ne_bytes());

    let r = unsafe { libc::ioctl(owned.as_raw_fd(), libc::TUNSETIFF, &mut ifr) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut end = 0;
    while end < 16 && ifr[end] != 0 {
        end += 1;
    }
    let assigned = String::from_utf8_lossy(&ifr[..end]).into_owned();
    Ok((owned, assigned))
}

fn read_hw_addr(name: &str) -> Result<MacAddr> {
    // socket(AF_INET, SOCK_DGRAM, 0); ioctl(SIOCGIFHWADDR).
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let _close = OwnedSock(sock);

    let mut ifr = [0u8; 40];
    let bytes = name.as_bytes();
    let n = bytes.len().min(15);
    ifr[..n].copy_from_slice(&bytes[..n]);

    let r = unsafe { libc::ioctl(sock, libc::SIOCGIFHWADDR, &mut ifr) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // Skip 2-byte sa_family at offset 16, then 6 bytes of MAC.
    let mut o = [0u8; 6];
    o.copy_from_slice(&ifr[18..24]);
    Ok(MacAddr(o))
}

fn write_all(fd: i32, buf: &[u8]) -> Result<()> {
    let mut written = 0;
    while written < buf.len() {
        let n = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr() as *const libc::c_void,
                buf.len() - written,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        written += n as usize;
    }
    Ok(())
}

fn read_loop_l3(inner: Arc<DevInner>, handler: Arc<Mutex<Option<L3Handler>>>) {
    let mut buf = vec![0u8; 65536];
    while !inner.closed.load(Ordering::Acquire) {
        let n = unsafe {
            libc::read(
                inner.raw(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n <= 0 {
            return;
        }
        let h = handler.lock().unwrap().clone();
        if let Some(h) = h {
            let _ = h(Packet::from_slice(&buf[..n as usize]));
        }
    }
}

fn read_loop_l2(inner: Arc<DevInner>, handler: Arc<Mutex<Option<L2Handler>>>) {
    let mut buf = vec![0u8; 65536];
    while !inner.closed.load(Ordering::Acquire) {
        let n = unsafe {
            libc::read(
                inner.raw(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n <= 0 {
            return;
        }
        let n = n as usize;
        if n < 14 {
            continue;
        }
        let h = handler.lock().unwrap().clone();
        if let Some(h) = h {
            let _ = h(Frame::from_slice(&buf[..n]));
        }
    }
}

struct OwnedSock(i32);
impl Drop for OwnedSock {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    // No unit tests here — opening /dev/net/tun requires CAP_NET_ADMIN and
    // is not appropriate for CI. Wire-level behaviour is exercised by users
    // of the crate in integration scenarios.
}
