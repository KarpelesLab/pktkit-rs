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
    /// Shared with the reader thread, which may still be inside `recvfrom`
    /// when the socket is dropped: the fd is closed only once both are done
    /// with it, so the reader can never read from a number the process has
    /// since reused for something else.
    fd: Arc<OwnedFd>,
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
        // Protocol 0 at creation, ETH_P_ALL only at bind, as libpcap does: a
        // socket created with a protocol starts receiving from *every*
        // interface at once, and whatever arrives before `bind` narrows it
        // would be handed to us as if it came from this one.
        let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, valid fd that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // Before `bind`, so no frame arrives without it and loses its tag.
        set_int_opt(&fd, libc::SOL_PACKET, PACKET_AUXDATA, 1)?;
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
            fd: Arc::new(fd),
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

/// `PACKET_AUXDATA`: per-frame metadata as a control message, the only place
/// the kernel reports an 802.1Q tag it has stripped.
const PACKET_AUXDATA: libc::c_int = 8;

/// `struct tpacket_auxdata`, our own so an old `libc` need not have it.
/// Declared whole for its layout; only the VLAN fields are read.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct TpacketAuxdata {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
}

const _: () = assert!(std::mem::size_of::<TpacketAuxdata>() == 20);

/// Start the receive thread. It holds only the pieces it needs, so the socket
/// itself can be dropped while the thread is still winding down.
fn spawn_reader(sock: &Arc<Socket>, inbound_only: bool) {
    let fd = sock.fd.clone();
    let handler = sock.handler.clone();
    let closed = sock.closed.clone();
    let stats = sock.stats.clone();
    // Room for a jumbo frame plus its header, behind headroom for a VLAN tag.
    // Grown if the kernel hands us anything larger.
    let mut buf = vec![0u8; super::VLAN_TAG_LEN + 65_536];

    std::thread::spawn(move || {
        // u64s for the alignment `cmsghdr` needs; room for one auxdata.
        let mut control = [0u64; 8];
        while !closed.load(Ordering::Acquire) {
            let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let data = &mut buf[super::VLAN_TAG_LEN..];
            let mut iov = libc::iovec {
                iov_base: data.as_mut_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            };
            // SAFETY: all-zero is a valid msghdr; the pointers are set below.
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut from as *mut libc::sockaddr_ll as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = std::mem::size_of_val(&control) as _;
            // SAFETY: every pointer in `msg` is to a live local sized as stated.
            // MSG_TRUNC: return the frame's real length even when it did not
            // fit, so a truncated frame can be told apart and dropped.
            let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, libc::MSG_TRUNC) };
            if n < 0 {
                let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                match classify_recv_error(errno) {
                    RecvFailure::Retry => continue,
                    RecvFailure::Backoff => {
                        stats.record_error();
                        std::thread::sleep(RECV_ERROR_BACKOFF);
                        continue;
                    }
                    RecvFailure::Fatal => {
                        stats.record_error();
                        return;
                    }
                }
            }
            let n = n as usize;
            if n > buf.len() - super::VLAN_TAG_LEN {
                // A GRO or BIG TCP super-frame larger than the buffer. Half of
                // one is worse than none, so drop it, and make room for the
                // next: the kernel bounds how large they get.
                stats.record_rx_drop();
                buf.resize(super::VLAN_TAG_LEN + n, 0);
                continue;
            }
            if n < 14 {
                stats.record_rx_drop();
                continue;
            }
            if inbound_only && from.sll_pkttype == PACKET_OUTGOING {
                continue;
            }
            // SAFETY: `msg` is as `recvmsg` left it, its control buffer live.
            let tag = unsafe { vlan_tag(&msg) };
            let range = super::reinsert_vlan(&mut buf, n, tag);
            let frame = &buf[range];
            stats.record_rx(frame.len());
            let h = handler.lock().unwrap().clone();
            if let Some(h) = h {
                let _ = h(Frame::from_slice(frame));
            } else {
                stats.record_rx_drop();
            }
        }
    });
}

/// What the reader thread does after `recvmsg` fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecvFailure {
    /// Nothing went wrong: loop round and re-check `closed`.
    Retry,
    /// Something the socket recovers from; pause briefly so an error that
    /// repeats cannot spin the thread, then read again.
    Backoff,
    /// The socket itself is unusable. Nothing but `close` can follow.
    Fatal,
}

/// Pause after a recoverable receive error.
const RECV_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);

/// Classify a `recvmsg` errno.
///
/// The one the reader must survive is `ENETDOWN`: when the bound interface
/// goes down, `packet_notifier` unhooks the socket and reports `ENETDOWN`
/// through `sk_err`, and on the way back up it re-registers the socket on its
/// own. A reader that took that for the end of the socket would leave the
/// device deaf for good once the link returned. Only errors that say the fd
/// is not a usable socket end the thread; anything else is waited out, and
/// `close` still stops the loop.
fn classify_recv_error(errno: i32) -> RecvFailure {
    match errno {
        // EAGAIN is the SO_RCVTIMEO timeout.
        libc::EAGAIN | libc::EINTR | libc::ETIMEDOUT => RecvFailure::Retry,
        libc::EBADF | libc::ENOTSOCK | libc::EFAULT | libc::EINVAL => RecvFailure::Fatal,
        // ENETDOWN, ENODEV and ENXIO as the interface goes and comes back,
        // ENOBUFS and ENOMEM under memory pressure, and whatever else.
        _ => RecvFailure::Backoff,
    }
}

/// The stripped VLAN tag reported in `msg`'s `PACKET_AUXDATA`, if any.
///
/// # Safety
/// `msg` must be a header `recvmsg` has just filled in, with its control
/// buffer still live.
unsafe fn vlan_tag(msg: &libc::msghdr) -> Option<(u16, u16)> {
    // SAFETY: the caller guarantees `msg` and its control buffer; the CMSG_*
    // walk stays within `msg_controllen`, and each auxdata is read unaligned
    // only after checking the message is long enough to hold it.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(msg);
        while !c.is_null() {
            let h = &*c;
            if h.cmsg_level == libc::SOL_PACKET
                && h.cmsg_type == PACKET_AUXDATA
                && h.cmsg_len as usize
                    >= libc::CMSG_LEN(std::mem::size_of::<TpacketAuxdata>() as u32) as usize
            {
                let aux = (libc::CMSG_DATA(c) as *const TpacketAuxdata).read_unaligned();
                return super::aux_vlan_tag(aux.tp_status, aux.tp_vlan_tci, aux.tp_vlan_tpid);
            }
            c = libc::CMSG_NXTHDR(msg, c);
        }
    }
    None
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
    set_int_opt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, size)
}

fn set_int_opt(fd: &OwnedFd, level: libc::c_int, opt: libc::c_int, val: libc::c_int) -> Result<()> {
    let r = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            opt,
            &val as *const libc::c_int as *const libc::c_void,
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

    #[test]
    fn a_link_going_down_does_not_end_the_reader() {
        for errno in [
            libc::ENETDOWN,
            libc::ENODEV,
            libc::ENXIO,
            libc::ENOBUFS,
            libc::ENOMEM,
        ] {
            assert_eq!(classify_recv_error(errno), RecvFailure::Backoff, "{errno}");
        }
    }

    #[test]
    fn timeouts_and_signals_just_loop() {
        for errno in [
            libc::EAGAIN,
            libc::EWOULDBLOCK,
            libc::EINTR,
            libc::ETIMEDOUT,
        ] {
            assert_eq!(classify_recv_error(errno), RecvFailure::Retry, "{errno}");
        }
    }

    #[test]
    fn only_a_broken_fd_ends_the_reader() {
        for errno in [libc::EBADF, libc::ENOTSOCK, libc::EFAULT, libc::EINVAL] {
            assert_eq!(classify_recv_error(errno), RecvFailure::Fatal, "{errno}");
        }
    }

    // Binding a real interface needs CAP_NET_RAW, so the success path is
    // covered by the ignored integration test in tests/afpacket_loopback.rs.
}
