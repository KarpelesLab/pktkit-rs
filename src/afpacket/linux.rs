//! `AF_PACKET` / `SOCK_RAW` on Linux.
//!
//! One socket bound to one interface, with a background thread that hands each
//! received frame to the installed handler. The buffer given to the handler is
//! the reader's scratch space and is valid only for the duration of the call,
//! as everywhere else in this crate.

use super::Config;
use crate::sys::if_hw_addr;
use crate::{DeviceStats, Frame, L2Device, L2Handler, MacAddr, Result};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// `PACKET_OUTGOING`: the frame was sent by this host, not received.
const PACKET_OUTGOING: u8 = 4;

/// An `AF_PACKET` socket bound to one interface, presented as an [`L2Device`].
pub struct Socket {
    fd: OwnedFd,
    interface: String,
    ifindex: u32,
    mac: MacAddr,
    mtu: usize,
    promiscuous: bool,
    handler: Arc<Mutex<Option<L2Handler>>>,
    closed: Arc<AtomicBool>,
    stats: Arc<DeviceStats>,
}

impl core::fmt::Debug for Socket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("afpacket::Socket")
            .field("interface", &self.interface)
            .field("mac", &self.mac)
            .field("mtu", &self.mtu)
            .finish()
    }
}

impl Socket {
    /// Bind to the configured interface and start receiving.
    ///
    /// Requires `CAP_NET_RAW`.
    pub fn open(cfg: Config) -> Result<Arc<Socket>> {
        if cfg.interface.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "afpacket: an interface name is required",
            ));
        }
        let ifindex = crate::sys::if_index(&cfg.interface)?;

        // ETH_P_ALL in network byte order: the kernel compares the protocol
        // field of the frame against it, and that field is big-endian.
        let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
        let raw =
            unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, valid fd that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        bind_to_interface(&fd, ifindex, proto)?;

        if cfg.recv_buffer > 0 {
            set_recv_buffer(&fd, cfg.recv_buffer)?;
        }
        // A read timeout is what lets the reader thread notice `close`; an
        // AF_PACKET socket cannot be shut down out from under a blocked read.
        set_recv_timeout(&fd, cfg.poll_interval)?;

        if cfg.promiscuous {
            set_promiscuous(&fd, ifindex, true)?;
        }

        let mac = if_hw_addr(&cfg.interface).unwrap_or_else(|_| MacAddr::zero());
        let mtu = crate::sys::if_mtu(&cfg.interface).unwrap_or(crate::DEFAULT_MTU);

        let sock = Arc::new(Socket {
            fd,
            interface: cfg.interface.clone(),
            ifindex,
            mac,
            mtu,
            promiscuous: cfg.promiscuous,
            handler: Arc::new(Mutex::new(None)),
            closed: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(DeviceStats::new()),
        });

        spawn_reader(&sock, cfg.inbound_only);
        Ok(sock)
    }

    /// The interface this socket is bound to.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// The interface MTU, as reported by the kernel when the socket was opened.
    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

/// Start the receive thread. It holds only the pieces it needs, so the socket
/// itself can be dropped while the thread is still winding down.
fn spawn_reader(sock: &Arc<Socket>, inbound_only: bool) {
    let fd = sock.fd.as_raw_fd();
    let handler = sock.handler.clone();
    let closed = sock.closed.clone();
    let stats = sock.stats.clone();
    // Room for a jumbo frame plus its header.
    let mut buf = vec![0u8; 65_536];

    std::thread::spawn(move || {
        while !closed.load(Ordering::Acquire) {
            let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut from_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut from as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                    &mut from_len,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    // The read timeout fired: loop round and re-check `closed`.
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => continue,
                    io::ErrorKind::Interrupted => continue,
                    _ => {
                        stats.record_error();
                        return;
                    }
                }
            }
            let n = n as usize;
            if n < 14 {
                stats.record_rx_drop();
                continue;
            }
            if inbound_only && from.sll_pkttype == PACKET_OUTGOING {
                continue;
            }
            stats.record_rx(n);
            let h = handler.lock().unwrap().clone();
            if let Some(h) = h {
                let _ = h(Frame::from_slice(&buf[..n]));
            } else {
                stats.record_rx_drop();
            }
        }
    });
}

impl L2Device for Socket {
    fn set_handler(&self, h: L2Handler) {
        *self.handler.lock().unwrap() = Some(h);
    }

    fn send(&self, frame: &Frame) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            self.stats.record_tx_drop();
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "afpacket: socket is closed",
            ));
        }
        let buf = frame.as_bytes();
        loop {
            let n = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                self.stats.record_error();
                self.stats.record_tx_drop();
                return Err(e);
            }
            self.stats.record_tx(n as usize);
            return Ok(());
        }
    }

    fn hw_addr(&self) -> MacAddr {
        self.mac
    }

    fn close(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        if self.promiscuous {
            // Best-effort: the membership is dropped anyway when the socket is
            // closed, so a failure here is not worth propagating.
            let _ = set_promiscuous(&self.fd, self.ifindex, false);
        }
        Ok(())
    }

    fn stats(&self) -> Option<&DeviceStats> {
        Some(&self.stats)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

// --- syscalls --------------------------------------------------------------

fn bind_to_interface(fd: &OwnedFd, ifindex: u32, proto: libc::c_int) -> Result<()> {
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = proto as u16;
    addr.sll_ifindex = ifindex as i32;
    let r = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_recv_buffer(fd: &OwnedFd, bytes: usize) -> Result<()> {
    let size = bytes.min(i32::MAX as usize) as libc::c_int;
    let r = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &size as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_recv_timeout(fd: &OwnedFd, timeout: std::time::Duration) -> Result<()> {
    // A zero timeout means "block forever" to the kernel, which would leave a
    // reader stuck past close; keep a floor under it.
    let timeout = timeout.max(std::time::Duration::from_millis(1));
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    let r = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_promiscuous(fd: &OwnedFd, ifindex: u32, on: bool) -> Result<()> {
    let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
    mreq.mr_ifindex = ifindex as i32;
    mreq.mr_type = libc::PACKET_MR_PROMISC as u16;
    let opt = if on {
        libc::PACKET_ADD_MEMBERSHIP
    } else {
        libc::PACKET_DROP_MEMBERSHIP
    };
    let r = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            opt,
            &mreq as *const libc::packet_mreq as *const libc::c_void,
            std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_interface_is_rejected_before_any_syscall() {
        let err = Socket::open(Config::default()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn unknown_interface_reports_not_found() {
        let err = Socket::open(Config {
            interface: "definitely-not-an-interface".into(),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    // Binding a real interface needs CAP_NET_RAW, so the success path is
    // covered by the ignored integration test in tests/afpacket_loopback.rs.
}
