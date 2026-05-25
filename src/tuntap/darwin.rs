//! macOS TUN via the `utun` kernel control (`AF_SYSTEM` / `SYSPROTO_CONTROL`).
//!
//! utun frames carry a 4-byte protocol-family header (`AF_INET` / `AF_INET6`)
//! ahead of the IP packet; we strip it on read and prepend it on write.
//!
//! TAP mode has no macOS kernel driver, so [`Tap::open`] returns
//! `ErrorKind::Unsupported`.
//!
//! This module is compiled for `target_os = "macos"` and type-checked via
//! `cargo check --target x86_64-apple-darwin`, but the live device paths
//! require a real macOS host + root and are marked
//! `// TODO(tuntap): needs macOS to verify`.

use crate::{Frame, IpPrefix, L2Device, L2Handler, L3Device, L3Handler, MacAddr, Packet, Result};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
const UTUN_OPT_IFNAME: libc::c_int = 2;

/// Knobs for opening a utun device. `name` is ignored on macOS (the kernel
/// assigns `utunN`); present for API parity with the Linux backend.
#[derive(Debug, Clone, Default)]
pub struct TuntapConfig {
    pub name: String,
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

/// macOS TUN device — raw IPv4/IPv6 packets.
pub struct Tun {
    inner: Arc<DevInner>,
    handler: Arc<Mutex<Option<L3Handler>>>,
    addr: Mutex<IpPrefix>,
}

impl core::fmt::Debug for Tun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("tuntap::Tun").field("name", &self.inner.name).finish()
    }
}

impl Tun {
    /// Open a utun device. Requires root.
    pub fn open(_cfg: TuntapConfig) -> Result<Tun> {
        let (fd, name) = open_utun()?;
        let inner = Arc::new(DevInner {
            fd,
            name,
            closed: AtomicBool::new(false),
        });
        let handler: Arc<Mutex<Option<L3Handler>>> = Arc::new(Mutex::new(None));

        let inner_t = inner.clone();
        let handler_t = handler.clone();
        std::thread::spawn(move || read_loop(inner_t, handler_t));

        Ok(Tun {
            inner,
            handler,
            addr: Mutex::new(IpPrefix::default()),
        })
    }

    /// OS interface name (e.g. `utun3`).
    pub fn name(&self) -> &str {
        &self.inner.name
    }
}

impl L3Device for Tun {
    fn set_handler(&self, h: L3Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }
    fn send(&self, pkt: &Packet) -> Result<()> {
        let bytes = pkt.as_bytes();
        if bytes.is_empty() {
            return Ok(());
        }
        // Prepend the 4-byte protocol-family header.
        let proto: u32 = match bytes[0] >> 4 {
            4 => libc::AF_INET as u32,
            6 => libc::AF_INET6 as u32,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown IP version")),
        };
        let mut framed = Vec::with_capacity(4 + bytes.len());
        framed.extend_from_slice(&proto.to_be_bytes());
        framed.extend_from_slice(bytes);
        write_all(self.inner.raw(), &framed)
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
        Ok(())
    }
}

/// macOS TAP placeholder — no kernel driver exists, so this always fails.
#[derive(Debug)]
pub struct Tap {
    _private: (),
}

impl Tap {
    /// Always returns `ErrorKind::Unsupported` on macOS.
    pub fn open(_cfg: TuntapConfig) -> Result<Tap> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TAP mode is not supported on macOS",
        ))
    }
    pub fn name(&self) -> &str {
        ""
    }
}

impl L2Device for Tap {
    fn set_handler(&self, _h: L2Handler) {}
    fn send(&self, _f: &Frame) -> Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TAP mode is not supported on macOS",
        ))
    }
    fn hw_addr(&self) -> MacAddr {
        MacAddr::zero()
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}

// --- syscalls --------------------------------------------------------------

fn open_utun() -> Result<(OwnedFd, String)> {
    // socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
    let fd = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // ioctl(CTLIOCGINFO) to resolve the utun control id by name.
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    let n = UTUN_CONTROL_NAME.len().min(info.ctl_name.len() - 1);
    for (i, &b) in UTUN_CONTROL_NAME[..n].iter().enumerate() {
        info.ctl_name[i] = b as libc::c_char;
    }
    let r = unsafe { libc::ioctl(owned.as_raw_fd(), libc::CTLIOCGINFO, &mut info) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }

    // Try unit numbers 0..256 until connect() succeeds.
    let mut chosen_unit = None;
    for unit in 0u32..256 {
        let mut addr: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
        addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = unit;
        let rc = unsafe {
            libc::connect(
                owned.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            chosen_unit = Some(unit);
            break;
        }
    }
    let unit = chosen_unit
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no available utun unit"))?;

    // getsockopt(UTUN_OPT_IFNAME) for the assigned name; fall back to utunN.
    let name = getsockopt_ifname(owned.as_raw_fd()).unwrap_or_else(|| format!("utun{unit}"));

    Ok((owned, name))
}

fn getsockopt_ifname(fd: i32) -> Option<String> {
    let mut buf = [0u8; 64];
    let mut len = buf.len() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if r < 0 || len == 0 {
        return None;
    }
    // The returned name is NUL-terminated.
    let end = buf[..len as usize]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(len as usize);
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
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

fn read_loop(inner: Arc<DevInner>, handler: Arc<Mutex<Option<L3Handler>>>) {
    // TODO(tuntap): needs macOS to verify the live read path.
    let mut buf = vec![0u8; 65536];
    while !inner.closed.load(Ordering::Acquire) {
        let n = unsafe {
            libc::read(
                inner.raw(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n <= 4 {
            // <= 4 means header-only or error/EOF.
            if n <= 0 {
                return;
            }
            continue;
        }
        // Strip the 4-byte protocol-family header.
        let pkt = &buf[4..n as usize];
        let h = handler.lock().unwrap().clone();
        if let Some(h) = h {
            let _ = h(Packet::from_slice(pkt));
        }
    }
}
