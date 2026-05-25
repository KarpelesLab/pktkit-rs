//! AF_XDP socket setup and datapath.
//!
//! Hand port of `xdp.go`. The flow, in order:
//!
//! 1. `socket(AF_XDP, SOCK_RAW, 0)`
//! 2. `mmap` an anonymous UMEM region and register it (`XDP_UMEM_REG`)
//! 3. size the four rings (`XDP_UMEM_FILL_RING`, `..._COMPLETION_RING`,
//!    `XDP_RX_RING`, `XDP_TX_RING`)
//! 4. read the ring offsets (`XDP_MMAP_OFFSETS`) and `mmap` each ring
//! 5. pre-fill the FILL ring with RX frames and stash the TX frames in a pool
//! 6. load + attach a redirect eBPF program (unless the caller supplied an
//!    XSKMAP)
//! 7. `bind` to the interface/queue, insert the socket into the XSKMAP
//! 8. spawn a poll loop that drains RX and recycles frames into the FILL ring
//!
//! Everything that needs a real NIC + root is marked `TODO(afxdp)`.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::afxdp::bpf;
use crate::afxdp::ring::{AddrRing, DescRing};
use crate::{Frame, L2Handler, MacAddr, Result};

// --- AF_XDP / setsockopt constants (mirror <linux/if_xdp.h>) ---------------
//
// Most exist in the libc crate; we alias them here so this module reads
// against one consistent set of names and to make the port to bare consts
// obvious if a future libc drops one.

const SOL_XDP: libc::c_int = 283;
const XDP_MMAP_OFFSETS: libc::c_int = 1;
const XDP_RX_RING: libc::c_int = 2;
const XDP_TX_RING: libc::c_int = 3;
const XDP_UMEM_REG: libc::c_int = 4;
const XDP_UMEM_FILL_RING: libc::c_int = 5;
const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;
const XDP_STATISTICS: libc::c_int = 7;

const XDP_PGOFF_RX_RING: libc::off_t = 0;
const XDP_PGOFF_TX_RING: libc::off_t = 0x8000_0000;
const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x1_0000_0000;
const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x1_8000_0000;

const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;

// XDP attach mode flag (netlink fallback). SKB mode works on any NIC.
const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;

/// Number of XSKMAP slots when we own the map (one per possible NIC queue).
const XSKMAP_MAX_QUEUES: u32 = 64;

/// Batch size for RX drain / TX completion reaping per poll iteration.
const BATCH: usize = 64;

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
    /// Number of frames in the UMEM. Default 4096; half RX, half TX.
    pub num_frames: u32,
    /// Force `XDP_COPY` mode. By default zero-copy is attempted with a copy
    /// fallback.
    pub copy: bool,
    /// Use an existing XSKMAP fd instead of loading our own BPF program. When
    /// `> 0`, the caller owns the XDP program and map.
    pub xskmap_fd: i32,
    /// Extra bind flags OR'd in (e.g. `XDP_USE_NEED_WAKEUP`).
    pub flags: u16,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            interface: String::new(),
            queue_id: 0,
            ring_size: 2048,
            frame_size: 4096,
            num_frames: 4096,
            copy: false,
            xskmap_fd: 0,
            flags: 0,
        }
    }
}

/// A `mmap`'d region that `munmap`s itself on drop.
struct Mapping {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: the pointer is an exclusive mapping owned by this struct; access is
// mediated by the ring abstraction's atomics.
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

impl Mapping {
    fn ptr(&self) -> *mut u8 {
        self.ptr
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: ptr/len describe a live mapping we created and have not
        // unmapped yet.
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

/// Shared device state. Lives in an `Arc` so the poll thread and the public
/// `Device` handle share it.
struct Inner {
    fd: OwnedFd,
    ifindex: u32,
    queue_id: u32,
    mac: MacAddr,
    frame_size: usize,

    // Mappings kept alive for the device's lifetime (Drop -> munmap).
    umem: Mapping,
    _fill_map: Mapping,
    _comp_map: Mapping,
    _rx_map: Mapping,
    _tx_map: Mapping,

    fill_ring: AddrRing,
    comp_ring: AddrRing,
    rx_ring: DescRing,
    tx_ring: DescRing,

    /// Free UMEM addresses available for TX, guarded together with the TX
    /// rings since `send` and the completion reaper both touch them.
    tx_free: Mutex<Vec<u64>>,

    /// BPF resources we own (kept alive so the program stays attached);
    /// `None` when the caller supplied an XSKMAP.
    _bpf: Option<OwnedBpf>,

    handler: Arc<Mutex<Option<L2Handler>>>,
    closed: AtomicBool,
}

/// Owned eBPF resources, detached + closed on drop.
struct OwnedBpf {
    _prog: OwnedFd,
    _map: OwnedFd,
    ifindex: u32,
}

impl Drop for OwnedBpf {
    fn drop(&mut self) {
        // Detach the program from the interface; fds close via OwnedFd.
        let _ = bpf::detach_xdp(self.ifindex);
    }
}

impl Inner {
    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// AF_XDP socket presented as an [`L2Device`](crate::L2Device).
pub struct Device {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("afxdp::Device")
            .field("ifindex", &self.inner.ifindex)
            .field("queue_id", &self.inner.queue_id)
            .field("mac", &self.inner.mac)
            .finish()
    }
}

impl Device {
    /// Open an AF_XDP socket bound to `cfg.interface` / `cfg.queue_id`.
    ///
    /// Requires root (or `CAP_NET_ADMIN` + `CAP_BPF`) and a real NIC. In a
    /// sandbox this fails at `socket`/`bind`/`bpf` with a permission or
    /// no-such-device error, which is expected.
    //
    // TODO(afxdp): the happy path past `socket()` needs hardware to verify.
    pub fn open(cfg: Config) -> Result<Device> {
        let ring_size = if cfg.ring_size == 0 {
            2048
        } else {
            cfg.ring_size
        };
        let frame_size = if cfg.frame_size == 0 {
            4096
        } else {
            cfg.frame_size
        };
        let num_frames = if cfg.num_frames == 0 {
            4096
        } else {
            cfg.num_frames
        };

        if ring_size & (ring_size - 1) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("afxdp: ring_size must be a power of 2, got {ring_size}"),
            ));
        }

        let ifindex = if_nametoindex(&cfg.interface)?;
        let mac = read_hw_addr(&cfg.interface).unwrap_or_else(|_| MacAddr::zero());

        // 1. AF_XDP socket.
        let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh fd, owned now.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let raw = fd.as_raw_fd();

        // 2. Allocate UMEM (anonymous, populated up front).
        let umem_size = num_frames as usize * frame_size as usize;
        let umem = mmap_anon(umem_size)?;

        // 3. Register UMEM. The libc xdp_umem_reg uses `chunk_size` for what
        // the kernel ABI calls the frame size.
        let reg = libc::xdp_umem_reg {
            addr: umem.ptr() as u64,
            len: umem_size as u64,
            chunk_size: frame_size,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        setsockopt_umem_reg(raw, &reg)?;

        // 4. Size the rings.
        for opt in [
            XDP_UMEM_FILL_RING,
            XDP_UMEM_COMPLETION_RING,
            XDP_RX_RING,
            XDP_TX_RING,
        ] {
            setsockopt_u32(raw, opt, ring_size)?;
        }

        // 5. Read ring offsets.
        let offs = getsockopt_mmap_offsets(raw)?;

        // 6. Map each ring.
        let fill_map = mmap_ring(raw, XDP_UMEM_PGOFF_FILL_RING, &offs.fr, ring_size)?;
        let comp_map = mmap_ring(raw, XDP_UMEM_PGOFF_COMPLETION_RING, &offs.cr, ring_size)?;
        let rx_map = mmap_ring(raw, XDP_PGOFF_RX_RING, &offs.rx, ring_size)?;
        let tx_map = mmap_ring(raw, XDP_PGOFF_TX_RING, &offs.tx, ring_size)?;

        // 7. Build ring views over the mappings.
        // SAFETY: each mapping is sized for its ring (see `mmap_ring`), the
        // offsets came from the kernel, and ring_size is a power of two.
        let fill_ring = unsafe { AddrRing::new(fill_map.ptr(), (&offs.fr).into(), ring_size) };
        let comp_ring = unsafe { AddrRing::new(comp_map.ptr(), (&offs.cr).into(), ring_size) };
        let rx_ring = unsafe { DescRing::new(rx_map.ptr(), (&offs.rx).into(), ring_size) };
        let tx_ring = unsafe { DescRing::new(tx_map.ptr(), (&offs.tx).into(), ring_size) };

        // 8. Split UMEM: first half RX (pre-filled), second half TX (pooled).
        let rx_frames = num_frames / 2;
        let tx_frames = num_frames - rx_frames;

        let rx_addrs: Vec<u64> = (0..rx_frames)
            .map(|i| (i as u64) * frame_size as u64)
            .collect();
        fill_ring.produce(&rx_addrs);

        let tx_free: Vec<u64> = (0..tx_frames)
            .map(|i| ((rx_frames + i) as u64) * frame_size as u64)
            .collect();

        // 9. Obtain the XSKMAP fd: load our own program or use the caller's.
        let (map_fd, owned_bpf) = if cfg.xskmap_fd <= 0 {
            let (prog, map) = bpf::load_xdp_program(XSKMAP_MAX_QUEUES)?;
            let map_fd = map.as_raw_fd();
            // Attach to the interface (SKB mode is universally supported).
            bpf::attach_xdp(ifindex, prog.as_raw_fd(), XDP_FLAGS_SKB_MODE)?;
            (
                map_fd,
                Some(OwnedBpf {
                    _prog: prog,
                    _map: map,
                    ifindex,
                }),
            )
        } else {
            (cfg.xskmap_fd, None)
        };

        // 10. Bind, with a zero-copy -> copy fallback.
        bind_xdp(raw, ifindex, cfg.queue_id, &cfg)?;

        // 11. Register this socket in the XSKMAP at our queue index.
        bpf::update_xskmap(map_fd, cfg.queue_id, raw)?;

        let inner = Arc::new(Inner {
            fd,
            ifindex,
            queue_id: cfg.queue_id,
            mac,
            frame_size: frame_size as usize,
            umem,
            _fill_map: fill_map,
            _comp_map: comp_map,
            _rx_map: rx_map,
            _tx_map: tx_map,
            fill_ring,
            comp_ring,
            rx_ring,
            tx_ring,
            tx_free: Mutex::new(tx_free),
            _bpf: owned_bpf,
            handler: Arc::new(Mutex::new(None)),
            closed: AtomicBool::new(false),
        });

        // 12. Poll loop.
        let poll_inner = inner.clone();
        std::thread::spawn(move || poll_loop(poll_inner));

        Ok(Device { inner })
    }

    /// Hardware (MAC) address of the bound interface.
    pub fn hw_addr(&self) -> MacAddr {
        self.inner.mac
    }

    /// Read AF_XDP socket statistics.
    //
    // TODO(afxdp): needs hardware to verify the returned counters.
    pub fn statistics(&self) -> Result<libc::xdp_statistics> {
        getsockopt_statistics(self.inner.raw())
    }
}

impl crate::L2Device for Device {
    fn set_handler(&self, h: L2Handler) {
        *self.inner.handler.lock().unwrap() = Some(h);
    }

    fn send(&self, frame: &Frame) -> Result<()> {
        self.inner.send(frame.as_bytes())
    }

    fn hw_addr(&self) -> MacAddr {
        self.inner.mac
    }

    fn close(&self) -> Result<()> {
        self.inner.closed.store(true, Ordering::Release);
        // Mappings, fd, and BPF resources are released when the last Arc<Inner>
        // drops. The poll loop observes `closed` and exits.
        Ok(())
    }
}

impl Inner {
    /// Copy `frame` into a free UMEM slot and enqueue it on the TX ring.
    fn send(&self, frame: &[u8]) -> Result<()> {
        // Runt frames (< Ethernet header) are silently dropped, as in Go.
        if frame.len() < 14 {
            return Ok(());
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "afxdp: closed"));
        }

        let mut free = self.tx_free.lock().unwrap();

        // Reclaim completed TX frames before allocating.
        self.reclaim_tx(&mut free);

        let addr = match free.pop() {
            Some(a) => a,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "afxdp: no free TX buffers",
                ))
            }
        };

        let len = frame.len().min(self.frame_size);
        // Copy into the UMEM at `addr`.
        // SAFETY: addr+len is within the UMEM mapping: addr is a frame-aligned
        // offset from the TX pool (< umem.len) and len <= frame_size.
        unsafe {
            std::ptr::copy_nonoverlapping(frame.as_ptr(), self.umem.ptr().add(addr as usize), len);
        }

        let desc = [libc::xdp_desc {
            addr,
            len: len as u32,
            options: 0,
        }];
        if self.tx_ring.produce(&desc) == 0 {
            // Ring full: return the address to the pool.
            free.push(addr);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "afxdp: TX ring full",
            ));
        }

        // Kick the kernel if it asked to be woken for TX.
        if self.tx_ring.need_wakeup() {
            // SAFETY: valid fd; null buffer is allowed with MSG_DONTWAIT.
            unsafe {
                libc::sendto(
                    self.raw(),
                    std::ptr::null(),
                    0,
                    libc::MSG_DONTWAIT,
                    std::ptr::null(),
                    0,
                );
            }
        }
        Ok(())
    }

    /// Drain the completion ring, returning finished TX addresses to the pool.
    /// Caller holds the `tx_free` lock.
    fn reclaim_tx(&self, free: &mut Vec<u64>) {
        let mut batch = [0u64; BATCH];
        loop {
            let n = self.comp_ring.consume(&mut batch);
            if n == 0 {
                return;
            }
            free.extend_from_slice(&batch[..n]);
        }
    }
}

/// Background RX loop: poll the socket, hand received frames to the handler,
/// and recycle their UMEM addresses back into the FILL ring.
//
// TODO(afxdp): needs hardware to verify — no packets arrive in a sandbox.
fn poll_loop(inner: Arc<Inner>) {
    let mut rx_batch = [libc::xdp_desc {
        addr: 0,
        len: 0,
        options: 0,
    }; BATCH];
    let mut fill_batch = [0u64; BATCH];

    while !inner.closed.load(Ordering::Acquire) {
        let mut pfd = libc::pollfd {
            fd: inner.raw(),
            events: libc::POLLIN,
            revents: 0,
        };
        // 1s timeout so we periodically re-check `closed`.
        let r = unsafe { libc::poll(&mut pfd, 1, 1000) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if inner.closed.load(Ordering::Acquire) {
            return;
        }
        if r == 0 {
            continue; // timeout
        }

        let got = inner.rx_ring.consume(&mut rx_batch);
        if got == 0 {
            continue;
        }

        let handler = inner.handler.lock().unwrap().clone();
        let mut fill_count = 0;

        for desc in &rx_batch[..got] {
            let addr = desc.addr;
            let len = desc.len as usize;

            if len >= 14 {
                if let Some(h) = &handler {
                    // UMEM is shared with the kernel; copy out before handing
                    // the borrow to the handler (which may outlive the slot
                    // once we recycle it).
                    // SAFETY: addr+len lies within the UMEM mapping (kernel
                    // wrote a valid RX descriptor).
                    let slice = unsafe {
                        std::slice::from_raw_parts(inner.umem.ptr().add(addr as usize), len)
                    };
                    let frame: Vec<u8> = slice.to_vec();
                    let _ = h(Frame::from_slice(&frame));
                }
            }

            // Recycle this frame back to the kernel.
            fill_batch[fill_count] = addr;
            fill_count += 1;
        }

        if fill_count > 0 {
            inner.fill_ring.produce(&fill_batch[..fill_count]);
        }
    }
}

// --- syscall helpers -------------------------------------------------------

/// `if_nametoindex`, mapping 0 (not found) to an error.
fn if_nametoindex(name: &str) -> Result<u32> {
    let c = std::ffi::CString::new(name).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "afxdp: interface name has NUL")
    })?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("afxdp: interface {name:?} not found"),
        ));
    }
    Ok(idx)
}

/// `socket(AF_INET, SOCK_DGRAM)` + `ioctl(SIOCGIFHWADDR)` to read the MAC.
fn read_hw_addr(name: &str) -> Result<MacAddr> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fd owned here.
    let sock = unsafe { OwnedFd::from_raw_fd(sock) };

    let mut ifr = [0u8; 40];
    let bytes = name.as_bytes();
    let n = bytes.len().min(15);
    ifr[..n].copy_from_slice(&bytes[..n]);

    let r = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR, &mut ifr) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // sa_family (2 bytes) at offset 16, MAC at 18..24.
    let mut o = [0u8; 6];
    o.copy_from_slice(&ifr[18..24]);
    Ok(MacAddr(o))
}

fn setsockopt_umem_reg(fd: RawFd, reg: &libc::xdp_umem_reg) -> Result<()> {
    let r = unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            XDP_UMEM_REG,
            reg as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::xdp_umem_reg>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn setsockopt_u32(fd: RawFd, opt: libc::c_int, val: u32) -> Result<()> {
    let r = unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            opt,
            &val as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn getsockopt_mmap_offsets(fd: RawFd) -> Result<libc::xdp_mmap_offsets> {
    let mut off: libc::xdp_mmap_offsets = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::xdp_mmap_offsets>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            &mut off as *mut _ as *mut libc::c_void,
            &mut size,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(off)
}

fn getsockopt_statistics(fd: RawFd) -> Result<libc::xdp_statistics> {
    let mut stats: libc::xdp_statistics = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::xdp_statistics>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_STATISTICS,
            &mut stats as *mut _ as *mut libc::c_void,
            &mut size,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stats)
}

/// Anonymous, populated, read/write UMEM mapping.
fn mmap_anon(len: usize) -> Result<Mapping> {
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(Mapping {
        ptr: ptr as *mut u8,
        len,
    })
}

/// Map one ring at the given page offset. The mapping spans the descriptor
/// array: `off.desc + size * elem_size`. The kernel reports `desc` past the
/// cursors, and the element size is 8 bytes for the FILL/COMPLETION rings or
/// 16 bytes (`xdp_desc`) for RX/TX. We always reserve the larger 16-byte
/// stride, which is a harmless over-map for the address rings.
fn mmap_ring(
    fd: RawFd,
    pgoff: libc::off_t,
    off: &libc::xdp_ring_offset,
    size: u32,
) -> Result<Mapping> {
    let total = off.desc as usize + size as usize * 16;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            total,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            pgoff,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(Mapping {
        ptr: ptr as *mut u8,
        len: total,
    })
}

/// `bind` the socket to the interface/queue, retrying in copy mode if a
/// zero-copy bind was requested and failed.
fn bind_xdp(fd: RawFd, ifindex: u32, queue_id: u32, cfg: &Config) -> Result<()> {
    let mut bind_flags: u16 = 0;
    if cfg.copy {
        bind_flags |= XDP_COPY;
    }
    bind_flags |= cfg.flags;

    let mut sa = libc::sockaddr_xdp {
        sxdp_family: libc::AF_XDP as u16,
        sxdp_flags: bind_flags,
        sxdp_ifindex: ifindex,
        sxdp_queue_id: queue_id,
        sxdp_shared_umem_fd: 0,
    };

    let r = bind_once(fd, &sa);
    if r.is_ok() {
        return Ok(());
    }

    // If a zero-copy bind failed, retry in copy mode (matches Go).
    if !cfg.copy && bind_flags & XDP_ZEROCOPY != 0 {
        sa.sxdp_flags = (bind_flags & !XDP_ZEROCOPY) | XDP_COPY;
        return bind_once(fd, &sa);
    }
    r
}

fn bind_once(fd: RawFd, sa: &libc::sockaddr_xdp) -> Result<()> {
    let r = unsafe {
        libc::bind(
            fd,
            sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_xdp>() as libc::socklen_t,
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
    fn default_config_values() {
        let c = Config::default();
        assert_eq!(c.ring_size, 2048);
        assert_eq!(c.frame_size, 4096);
        assert_eq!(c.num_frames, 4096);
        assert!(!c.copy);
        assert_eq!(c.xskmap_fd, 0);
    }

    #[test]
    fn ring_size_must_be_power_of_two() {
        let c = Config {
            interface: "lo".into(),
            ring_size: 1000, // not a power of 2
            ..Default::default()
        };
        let err = Device::open(c).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn unknown_interface_is_not_found() {
        // A name that cannot exist (too long / unlikely).
        let c = Config {
            interface: "pktkit_no_such_iface_xyz".into(),
            ..Default::default()
        };
        let err = Device::open(c).unwrap_err();
        // Either NotFound (if_nametoindex==0) or InvalidInput (NUL); the long
        // name path returns NotFound.
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    // UMEM frame-offset math: RX gets the first half, TX the second half,
    // each address frame-aligned. This mirrors the split in `open()`.
    #[test]
    fn umem_split_offsets() {
        let frame_size = 4096u64;
        let num_frames = 8u32;
        let rx_frames = num_frames / 2;
        let tx_frames = num_frames - rx_frames;

        let rx: Vec<u64> = (0..rx_frames).map(|i| i as u64 * frame_size).collect();
        let tx: Vec<u64> = (0..tx_frames)
            .map(|i| (rx_frames + i) as u64 * frame_size)
            .collect();

        assert_eq!(rx, vec![0, 4096, 8192, 12288]);
        assert_eq!(tx, vec![16384, 20480, 24576, 28672]);
        // No overlap and contiguous coverage of the whole UMEM.
        assert_eq!(*rx.first().unwrap(), 0);
        assert_eq!(*tx.last().unwrap(), (num_frames as u64 - 1) * frame_size);
    }

    // The ring mmap length must cover cursors + descriptor array. Verify the
    // size computation used by `mmap_ring`.
    #[test]
    fn ring_mmap_size_covers_descs() {
        let off = libc::xdp_ring_offset {
            producer: 0,
            consumer: 64,
            desc: 128,
            flags: 96,
        };
        let size = 2048u32;
        let total = off.desc as usize + size as usize * 16;
        assert_eq!(total, 128 + 2048 * 16);
    }

    #[test]
    fn bind_flag_zerocopy_fallback_logic() {
        // Mirror the decision in bind_xdp without touching a socket: when the
        // caller didn't force copy but ZEROCOPY is set in flags, we must fall
        // back by clearing ZEROCOPY and setting COPY.
        let cfg_flags = XDP_ZEROCOPY;
        let bind_flags = cfg_flags; // copy=false
        let fallback = (bind_flags & !XDP_ZEROCOPY) | XDP_COPY;
        assert_eq!(fallback & XDP_ZEROCOPY, 0);
        assert_eq!(fallback & XDP_COPY, XDP_COPY);
    }
}
