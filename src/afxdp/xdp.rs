//! AF_XDP socket setup and datapath.
//!
//! One [`Device`] owns one AF_XDP socket per NIC receive queue. Each socket has
//! its own UMEM, its own four rings and its own poll thread; they share the XDP
//! program and the XSKMAP that steers frames to them. Per queue, the flow is:
//!
//! 1. `socket(AF_XDP, SOCK_RAW, 0)`
//! 2. `mmap` an anonymous UMEM region and register it (`XDP_UMEM_REG`)
//! 3. size the four rings (`XDP_UMEM_FILL_RING`, `..._COMPLETION_RING`,
//!    `XDP_RX_RING`, `XDP_TX_RING`)
//! 4. read the ring offsets (`XDP_MMAP_OFFSETS`) and `mmap` each ring
//! 5. pre-fill the FILL ring with RX frames and stash the TX frames in a pool
//! 6. `bind` to the interface/queue, negotiating zero-copy
//! 7. insert the socket into the XSKMAP at its queue index
//! 8. spawn a poll loop that drains RX and recycles frames into the FILL ring
//!
//! The program that decides *which* frames arrive here is set up first, once,
//! by [`crate::xdp::Capture`].
//!
//! # Why every queue
//!
//! A NIC spreads received packets across its queues by hashing the flow, and an
//! AF_XDP socket is bound to exactly one queue. Binding only queue 0 means the
//! traffic for a captured address is delivered only when RSS happens to hash it
//! there. [`Config::queue_ids`] defaults to every RX queue for that reason.
//!
//! Everything that needs a real NIC + root is marked `TODO(afxdp)`.

use std::cell::Cell;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::afxdp::ring::{AddrRing, DescRing};
use crate::xdp::{self, Capture, CaptureConfig, Mode};
use crate::{Frame, IpPrefix, L2Handler, MacAddr, Result};

// --- AF_XDP / setsockopt constants (mirror <linux/if_xdp.h>) ---------------

const SOL_XDP: libc::c_int = 283;
const XDP_MMAP_OFFSETS: libc::c_int = 1;
const XDP_RX_RING: libc::c_int = 2;
const XDP_TX_RING: libc::c_int = 3;
const XDP_UMEM_REG: libc::c_int = 4;
const XDP_UMEM_FILL_RING: libc::c_int = 5;
const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;
const XDP_STATISTICS: libc::c_int = 7;
const XDP_OPTIONS: libc::c_int = 8;

/// `XDP_OPTIONS_ZEROCOPY`: set once the kernel has actually put the socket on
/// a driver's zero-copy path. The authoritative answer, as opposed to guessing
/// from which bind flags were accepted.
const XDP_OPTIONS_ZEROCOPY: u32 = 1 << 0;

const XDP_PGOFF_RX_RING: libc::off_t = 0;
const XDP_PGOFF_TX_RING: libc::off_t = 0x8000_0000;
const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x1_0000_0000;
const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x1_8000_0000;

// Bind flags.
const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;
/// Lets the kernel tell us, through a flag in the ring, when it actually needs
/// a syscall to make progress. Without it every batch pays for a `sendto`.
const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

// Busy-poll socket options (SOL_SOCKET). Not in the libc crate.
const SO_BUSY_POLL: libc::c_int = 46;
const SO_PREFER_BUSY_POLL: libc::c_int = 69;
const SO_BUSY_POLL_BUDGET: libc::c_int = 70;

/// Smallest UMEM chunk the kernel accepts (`XDP_UMEM_MIN_CHUNK_SIZE`).
const MIN_FRAME_SIZE: u32 = 2048;

/// Descriptors moved per RX drain / TX completion reap. Matches what the
/// kernel's own sample uses; large enough to amortise the ring cursor updates,
/// small enough to stay in cache.
const BATCH: usize = 64;

/// How long the poll loop blocks before re-checking whether it should exit.
const POLL_TIMEOUT_MS: libc::c_int = 1000;

/// Whether to insist on a zero-copy bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Zerocopy {
    /// Try zero-copy, fall back to copy mode. The default.
    #[default]
    Auto,
    /// Fail to open unless every socket got a zero-copy bind. Use when a
    /// silent fall back to copy mode would be worse than an error.
    Require,
    /// Always bind in copy mode.
    Off,
}

/// Kernel-side busy polling.
///
/// Makes `poll()` run the driver's NAPI loop on the calling core instead of
/// waiting for an interrupt, which removes the interrupt and the context switch
/// from the receive path. Needs Linux 5.11+.
#[derive(Debug, Clone, Copy)]
pub struct BusyPoll {
    /// `SO_BUSY_POLL`, in microseconds.
    pub timeout_us: u32,
    /// `SO_BUSY_POLL_BUDGET`: packets per NAPI poll. The kernel's AF_XDP
    /// documentation suggests matching it to the RX batch size.
    pub budget: u32,
}

impl Default for BusyPoll {
    fn default() -> BusyPoll {
        BusyPoll {
            timeout_us: 20,
            budget: BATCH as u32,
        }
    }
}

/// Which XDP program feeds this device.
#[derive(Debug, Clone)]
pub enum ProgramSource {
    /// Load a program that redirects only the addresses added through
    /// [`Device::capture_add`], and passes everything else to the host stack.
    Capture(CaptureConfig),
    /// The caller owns the program and its XSKMAP; sockets register themselves
    /// in the map at this fd and nothing is attached or detached here.
    External { xskmap_fd: RawFd },
}

impl Default for ProgramSource {
    fn default() -> ProgramSource {
        ProgramSource::Capture(CaptureConfig::default())
    }
}

/// Configuration for an AF_XDP device.
#[derive(Debug, Clone)]
pub struct Config {
    /// Interface to bind, e.g. `"eth0"`.
    pub interface: String,
    /// NIC queues to bind, one socket each. Empty means every RX queue the
    /// interface reports, which is what a capture device usually wants.
    pub queue_ids: Vec<u32>,
    /// Ring size (must be a power of two). Default 2048.
    pub ring_size: u32,
    /// UMEM chunk size in bytes: a power of two between 2048 and the page
    /// size. Default 4096. This is the hard cap on frame length.
    pub frame_size: u32,
    /// Frames per UMEM, per socket. Default 4096; half RX, half TX.
    pub num_frames: u32,
    /// Zero-copy policy. See [`Zerocopy`].
    pub zerocopy: Zerocopy,
    /// Where the program runs. [`Mode::AUTO`] prefers the driver hook, which
    /// is what makes zero-copy possible at all.
    pub mode: Mode,
    /// The program that steers traffic to this device.
    pub program: ProgramSource,
    /// Kernel-side busy polling; off by default because it trades CPU for
    /// latency.
    pub busy_poll: Option<BusyPoll>,
    /// Back the UMEM with huge pages when possible, falling back silently.
    /// Cuts TLB pressure on the packet buffers at the cost of holding a scarce
    /// system resource.
    pub huge_pages: bool,
    /// Extra bind flags OR'd in.
    pub flags: u16,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            interface: String::new(),
            queue_ids: Vec::new(),
            ring_size: 2048,
            frame_size: 4096,
            num_frames: 4096,
            zerocopy: Zerocopy::Auto,
            mode: Mode::AUTO,
            program: ProgramSource::default(),
            busy_poll: None,
            huge_pages: false,
            flags: 0,
        }
    }
}

impl Config {
    /// Fill in defaults for the zero-valued fields and reject impossible
    /// geometry. Split out from `open` so it is testable without a NIC.
    fn normalize(&self) -> Result<Config> {
        let mut c = self.clone();
        if c.ring_size == 0 {
            c.ring_size = 2048;
        }
        if c.frame_size == 0 {
            c.frame_size = 4096;
        }
        if c.num_frames == 0 {
            c.num_frames = 4096;
        }

        if !c.ring_size.is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("afxdp: ring_size must be a power of 2, got {}", c.ring_size),
            ));
        }
        if !c.frame_size.is_power_of_two() || c.frame_size < MIN_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "afxdp: frame_size must be a power of 2 >= {MIN_FRAME_SIZE}, got {}",
                    c.frame_size
                ),
            ));
        }
        // Aligned-mode UMEM: a chunk may not straddle a page.
        let page = page_size();
        if c.frame_size as usize > page {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "afxdp: frame_size {} exceeds the page size {page}",
                    c.frame_size
                ),
            ));
        }
        // Every RX frame has to be reachable from the FILL ring, and TX needs a
        // pool of its own, so anything under two frames cannot work.
        if c.num_frames < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("afxdp: num_frames must be at least 2, got {}", c.num_frames),
            ));
        }
        Ok(c)
    }
}

/// A `mmap`'d region that `munmap`s itself on drop.
#[derive(Debug)]
struct Mapping {
    ptr: *mut u8,
    len: usize,
}

impl Mapping {
    #[inline]
    fn ptr(&self) -> *mut u8 {
        self.ptr
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: ptr/len came from a successful mmap and are unmapped once.
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

// SAFETY: the UMEM and ring mappings are shared with the kernel and accessed
// either through atomics (cursors) or through the SPSC discipline the rings
// enforce; the pointer itself is immutable for the mapping's life.
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

/// One AF_XDP socket, bound to one NIC queue.
struct Socket {
    fd: OwnedFd,
    queue_id: u32,
    frame_size: usize,
    zerocopy: bool,

    // Mappings kept alive for the socket's lifetime (Drop -> munmap).
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

    handler: Arc<Mutex<Option<L2Handler>>>,
    closed: Arc<AtomicBool>,
}

impl std::fmt::Debug for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socket")
            .field("fd", &self.fd.as_raw_fd())
            .field("queue_id", &self.queue_id)
            .field("zerocopy", &self.zerocopy)
            .finish()
    }
}

impl Socket {
    #[inline]
    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Shared device state.
struct Inner {
    ifindex: u32,
    mac: MacAddr,
    sockets: Vec<Arc<Socket>>,
    /// The program we loaded, if we own one. Dropping it detaches.
    capture: Option<Capture>,
    handler: Arc<Mutex<Option<L2Handler>>>,
    closed: Arc<AtomicBool>,
    /// Hands each sending thread a queue, round-robin.
    tx_cursor: AtomicUsize,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Without this the poll threads, which hold their own Arc<Socket>,
        // would spin forever on a device nobody references any more.
        self.closed.store(true, Ordering::Release);
    }
}

thread_local! {
    /// Sticky queue index per sending thread, so frames from one thread keep
    /// their relative order instead of being sprayed across queues.
    static TX_SLOT: Cell<usize> = const { Cell::new(usize::MAX) };
}

/// AF_XDP sockets presented as a single [`L2Device`](crate::L2Device).
pub struct Device {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("ifindex", &self.inner.ifindex)
            .field("mac", &self.inner.mac)
            .field("queues", &self.inner.sockets.len())
            .field("zerocopy", &self.zerocopy())
            .finish()
    }
}

impl Device {
    /// Open an AF_XDP device on `cfg.interface`.
    ///
    /// Requires root (or `CAP_NET_ADMIN` + `CAP_BPF`) and a real NIC. In a
    /// sandbox this fails at `socket`/`bind`/`bpf` with a permission or
    /// no-such-device error, which is expected.
    ///
    /// With the default [`ProgramSource::Capture`] the device receives nothing
    /// until [`Device::capture_add`] names an address; the interface keeps
    /// working normally in the meantime.
    //
    // TODO(afxdp): the happy path past `socket()` needs hardware to verify.
    pub fn open(cfg: Config) -> Result<Device> {
        let cfg = cfg.normalize()?;

        let ifindex = if_nametoindex(&cfg.interface)?;
        let mac = read_hw_addr(&cfg.interface).unwrap_or_else(|_| MacAddr::zero());

        let queue_ids = if cfg.queue_ids.is_empty() {
            let n = rx_queue_count(&cfg.interface).unwrap_or(1).max(1);
            (0..n).collect()
        } else {
            let mut q = cfg.queue_ids.clone();
            q.sort_unstable();
            q.dedup();
            q
        };

        // The program goes on before any socket binds, so no frame can be
        // redirected at a map slot we have not filled in yet.
        let capture = match &cfg.program {
            ProgramSource::Capture(ccfg) => Some(Capture::attach(ifindex, ccfg.clone(), cfg.mode)?),
            ProgramSource::External { .. } => None,
        };
        let xskmap_fd = match (&capture, &cfg.program) {
            (Some(c), _) => c.xskmap().as_raw_fd(),
            (None, ProgramSource::External { xskmap_fd }) => *xskmap_fd,
            (None, _) => unreachable!("capture is Some for ProgramSource::Capture"),
        };

        // Zero-copy is only reachable from a native-mode attachment; asking for
        // it behind generic XDP just burns a failing bind per socket.
        let attached_mode = capture.as_ref().map(|c| c.mode());
        let want_zc = match cfg.zerocopy {
            Zerocopy::Off => false,
            _ => attached_mode.map(|m| m.supports_zerocopy()).unwrap_or(true),
        };
        if cfg.zerocopy == Zerocopy::Require && !want_zc {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "afxdp: zero-copy requires a native XDP attachment, got {:?}",
                    attached_mode
                ),
            ));
        }

        let closed = Arc::new(AtomicBool::new(false));
        let handler: Arc<Mutex<Option<L2Handler>>> = Arc::new(Mutex::new(None));

        let mut sockets = Vec::with_capacity(queue_ids.len());
        for &queue_id in &queue_ids {
            let sock = Socket::open(
                ifindex,
                queue_id,
                &cfg,
                want_zc,
                handler.clone(),
                closed.clone(),
            )?;
            if cfg.zerocopy == Zerocopy::Require && !sock.zerocopy {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("afxdp: queue {queue_id} bound in copy mode"),
                ));
            }
            xdp::set_socket_raw(xskmap_fd, queue_id, sock.raw())?;
            sockets.push(Arc::new(sock));
        }

        let inner = Arc::new(Inner {
            ifindex,
            mac,
            sockets,
            capture,
            handler,
            closed,
            tx_cursor: AtomicUsize::new(0),
        });

        for sock in &inner.sockets {
            let s = sock.clone();
            std::thread::spawn(move || poll_loop(s));
        }

        Ok(Device { inner })
    }

    /// Hardware (MAC) address of the bound interface.
    #[inline]
    pub fn hw_addr(&self) -> MacAddr {
        self.inner.mac
    }

    /// The NIC queues this device is bound to.
    pub fn queue_ids(&self) -> Vec<u32> {
        self.inner.sockets.iter().map(|s| s.queue_id).collect()
    }

    /// True when every socket negotiated a zero-copy bind, as reported by
    /// `XDP_OPTIONS`.
    pub fn zerocopy(&self) -> bool {
        !self.inner.sockets.is_empty() && self.inner.sockets.iter().all(|s| s.zerocopy)
    }

    /// The mode the XDP program attached in, or `None` for an externally
    /// managed program.
    pub fn mode(&self) -> Option<Mode> {
        self.inner.capture.as_ref().map(|c| c.mode())
    }

    /// The capture set, when this device loaded its own program.
    pub fn capture(&self) -> Option<&Capture> {
        self.inner.capture.as_ref()
    }

    /// Start delivering traffic for `prefix` to this device.
    ///
    /// Takes effect immediately: the prefix goes into a map the running program
    /// reads, so nothing is reloaded or reattached.
    pub fn capture_add(&self, prefix: IpPrefix) -> Result<()> {
        self.require_capture()?.add(prefix)
    }

    /// Stop capturing `prefix`. Returns `false` if it was not in the set.
    pub fn capture_remove(&self, prefix: IpPrefix) -> Result<bool> {
        self.require_capture()?.remove(prefix)
    }

    fn require_capture(&self) -> Result<&Capture> {
        self.inner.capture.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "afxdp: device uses an external XDP program; manage its maps directly",
            )
        })
    }

    /// Kernel counters, summed across every bound queue.
    pub fn statistics(&self) -> Result<libc::xdp_statistics> {
        let mut total = libc::xdp_statistics {
            rx_dropped: 0,
            rx_invalid_descs: 0,
            tx_invalid_descs: 0,
            rx_ring_full: 0,
            rx_fill_ring_empty_descs: 0,
            tx_ring_empty_descs: 0,
        };
        for s in &self.inner.sockets {
            let st = getsockopt_statistics(s.raw())?;
            total.rx_dropped += st.rx_dropped;
            total.rx_invalid_descs += st.rx_invalid_descs;
            total.tx_invalid_descs += st.tx_invalid_descs;
            total.rx_ring_full += st.rx_ring_full;
            total.rx_fill_ring_empty_descs += st.rx_fill_ring_empty_descs;
            total.tx_ring_empty_descs += st.tx_ring_empty_descs;
        }
        Ok(total)
    }

    /// The socket a given caller transmits on. Each thread sticks to one queue
    /// so that a single sender cannot reorder its own frames.
    fn tx_socket(&self) -> &Arc<Socket> {
        let n = self.inner.sockets.len();
        if n == 1 {
            return &self.inner.sockets[0];
        }
        let slot = TX_SLOT.with(|c| {
            if c.get() == usize::MAX {
                c.set(self.inner.tx_cursor.fetch_add(1, Ordering::Relaxed));
            }
            c.get()
        });
        &self.inner.sockets[slot % n]
    }
}

impl crate::L2Device for Device {
    fn set_handler(&self, h: L2Handler) {
        *self.inner.handler.lock().unwrap() = Some(h);
    }

    fn send(&self, frame: &Frame) -> Result<()> {
        self.tx_socket().send(frame.as_bytes())
    }

    fn hw_addr(&self) -> MacAddr {
        self.inner.mac
    }

    fn close(&self) -> Result<()> {
        self.inner.closed.store(true, Ordering::Release);
        // Mappings, fds and the XDP attachment are released when the last Arc
        // drops. The poll loops observe `closed` and exit.
        Ok(())
    }
}

impl Socket {
    fn open(
        ifindex: u32,
        queue_id: u32,
        cfg: &Config,
        want_zerocopy: bool,
        handler: Arc<Mutex<Option<L2Handler>>>,
        closed: Arc<AtomicBool>,
    ) -> Result<Socket> {
        let ring_size = cfg.ring_size;
        let frame_size = cfg.frame_size;
        let num_frames = cfg.num_frames;

        let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh fd, owned now.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let raw = fd.as_raw_fd();

        let umem_size = num_frames as usize * frame_size as usize;
        let umem = mmap_umem(umem_size, cfg.huge_pages)?;

        // The libc `xdp_umem_reg` calls the frame size `chunk_size`. Headroom
        // stays 0: the kernel reserves XDP_PACKET_HEADROOM inside the chunk on
        // its own, and asking for more only shrinks the usable frame.
        let reg = libc::xdp_umem_reg {
            addr: umem.ptr() as u64,
            len: umem_size as u64,
            chunk_size: frame_size,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        setsockopt_umem_reg(raw, &reg)?;

        for opt in [
            XDP_UMEM_FILL_RING,
            XDP_UMEM_COMPLETION_RING,
            XDP_RX_RING,
            XDP_TX_RING,
        ] {
            setsockopt_u32(raw, opt, ring_size)?;
        }

        let offs = getsockopt_mmap_offsets(raw)?;

        let fill_map = mmap_ring(raw, XDP_UMEM_PGOFF_FILL_RING, &offs.fr, ring_size)?;
        let comp_map = mmap_ring(raw, XDP_UMEM_PGOFF_COMPLETION_RING, &offs.cr, ring_size)?;
        let rx_map = mmap_ring(raw, XDP_PGOFF_RX_RING, &offs.rx, ring_size)?;
        let tx_map = mmap_ring(raw, XDP_PGOFF_TX_RING, &offs.tx, ring_size)?;

        // SAFETY: each mapping is sized for its ring (see `mmap_ring`), the
        // offsets came from the kernel, and ring_size is a power of two.
        let fill_ring = unsafe { AddrRing::new(fill_map.ptr(), (&offs.fr).into(), ring_size) };
        let comp_ring = unsafe { AddrRing::new(comp_map.ptr(), (&offs.cr).into(), ring_size) };
        let rx_ring = unsafe { DescRing::new(rx_map.ptr(), (&offs.rx).into(), ring_size) };
        let tx_ring = unsafe { DescRing::new(tx_map.ptr(), (&offs.tx).into(), ring_size) };

        // Split the UMEM: first half RX (handed to the kernel up front), second
        // half a TX pool we allocate from.
        let (rx_frames, tx_frames) = umem_split(num_frames);
        let rx_addrs: Vec<u64> = (0..rx_frames)
            .map(|i| (i as u64) * frame_size as u64)
            .collect();
        fill_ring.produce(&rx_addrs);
        let tx_free: Vec<u64> = (0..tx_frames)
            .map(|i| ((rx_frames + i) as u64) * frame_size as u64)
            .collect();

        let zerocopy = bind_xdp(raw, ifindex, queue_id, cfg, want_zerocopy)?;

        if let Some(bp) = cfg.busy_poll {
            set_busy_poll(raw, bp)?;
        }

        Ok(Socket {
            fd,
            queue_id,
            frame_size: frame_size as usize,
            zerocopy,
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
            handler,
            closed,
        })
    }

    /// Copy `frame` into a free UMEM slot and enqueue it on the TX ring.
    fn send(&self, frame: &[u8]) -> Result<()> {
        // Runt frames (< Ethernet header) are silently dropped, as in Go.
        if frame.len() < 14 {
            return Ok(());
        }
        if frame.len() > self.frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "afxdp: frame of {} bytes exceeds the {}-byte UMEM chunk",
                    frame.len(),
                    self.frame_size
                ),
            ));
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "afxdp: closed"));
        }

        let mut free = self.tx_free.lock().unwrap();

        // Reaping completions is a ring read, not a syscall, but it still costs
        // two cache-line touches; only pay for it once the pool runs dry.
        let addr = match free.pop() {
            Some(a) => a,
            None => {
                self.reclaim_tx(&mut free);
                match free.pop() {
                    Some(a) => a,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "afxdp: no free TX buffers",
                        ))
                    }
                }
            }
        };

        let len = frame.len();
        // SAFETY: addr is a frame-aligned offset from the TX pool and
        // len <= frame_size, so addr+len stays inside the UMEM mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(frame.as_ptr(), self.umem.ptr().add(addr as usize), len);
        }

        let desc = [libc::xdp_desc {
            addr,
            len: len as u32,
            options: 0,
        }];
        if self.tx_ring.produce(&desc) == 0 {
            free.push(addr);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "afxdp: TX ring full",
            ));
        }
        drop(free);

        // With XDP_USE_NEED_WAKEUP this is only true when the kernel has gone
        // idle on this ring, so the common case costs no syscall at all.
        if self.tx_ring.need_wakeup() {
            self.kick_tx();
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

    /// Ask the kernel to pick up queued TX descriptors.
    fn kick_tx(&self) {
        // SAFETY: valid fd; a null buffer is allowed with MSG_DONTWAIT.
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

    /// Block until there is RX work or `timeout_ms` elapses.
    ///
    /// `poll` doubles as the RX wakeup: when the FILL ring carries
    /// `XDP_RING_NEED_WAKEUP` the kernel has stopped pulling buffers from it and
    /// this is what restarts it. With busy polling configured, the same call
    /// runs the driver's NAPI loop inline.
    fn wait(&self, timeout_ms: libc::c_int) {
        let mut pfd = libc::pollfd {
            fd: self.raw(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: single valid pollfd, kernel writes only revents.
        unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    }
}

/// Split a UMEM into RX and TX halves, guaranteeing at least one frame each.
fn umem_split(num_frames: u32) -> (u32, u32) {
    let rx = (num_frames / 2).max(1);
    (rx, num_frames - rx)
}

/// Background RX loop: drain the RX ring, hand frames to the handler, and
/// recycle their UMEM addresses into the FILL ring.
//
// TODO(afxdp): needs hardware to verify — no packets arrive in a sandbox.
fn poll_loop(sock: Arc<Socket>) {
    let mut rx_batch = [libc::xdp_desc {
        addr: 0,
        len: 0,
        options: 0,
    }; BATCH];
    let mut fill_batch = [0u64; BATCH];

    while !sock.closed.load(Ordering::Acquire) {
        let got = sock.rx_ring.consume(&mut rx_batch);
        if got == 0 {
            // Idle: give TX completions back to the pool for whichever thread
            // sends next, then sleep until the kernel has something for us.
            {
                let mut free = sock.tx_free.lock().unwrap();
                sock.reclaim_tx(&mut free);
            }
            sock.wait(POLL_TIMEOUT_MS);
            continue;
        }

        // One clone per batch rather than per frame.
        let handler = sock.handler.lock().unwrap().clone();
        let mut fill_count = 0;

        for desc in &rx_batch[..got] {
            let addr = desc.addr;
            let len = desc.len as usize;

            if len >= 14 {
                if let Some(h) = &handler {
                    // Handed to the handler in place. `L2Handler` takes `&Frame`
                    // so the borrow cannot outlive the call, and the chunk is not
                    // recycled into the FILL ring until after this loop — so the
                    // kernel cannot be writing it while the handler reads.
                    //
                    // SAFETY: addr+len lies within the UMEM mapping (the kernel
                    // wrote a valid RX descriptor).
                    let slice = unsafe {
                        std::slice::from_raw_parts(sock.umem.ptr().add(addr as usize), len)
                    };
                    let _ = h(Frame::from_slice(slice));
                }
            }

            fill_batch[fill_count] = addr;
            fill_count += 1;
        }

        if fill_count > 0 {
            sock.fill_ring.produce(&fill_batch[..fill_count]);
            // The driver stops consuming the FILL ring when it finds it empty;
            // this is the flag that says it is waiting on us.
            if sock.fill_ring.need_wakeup() {
                sock.wait(0);
            }
        }
    }
}

// --- syscall helpers -------------------------------------------------------

fn page_size() -> usize {
    // SAFETY: sysconf with a valid name; -1 on failure, handled below.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n <= 0 {
        4096
    } else {
        n as usize
    }
}

/// `if_nametoindex`, mapping 0 (not found) to an error.
fn if_nametoindex(name: &str) -> Result<u32> {
    let c = std::ffi::CString::new(name).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "afxdp: interface name has NUL")
    })?;
    // SAFETY: NUL-terminated string from CString.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("afxdp: interface {name:?} not found"),
        ));
    }
    Ok(idx)
}

/// Read an interface's MAC through `SIOCGIFHWADDR`.
fn read_hw_addr(name: &str) -> Result<MacAddr> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fd; OwnedFd closes it.
    let sock = unsafe { OwnedFd::from_raw_fd(sock) };

    let mut req = IfReq::new(name)?;
    // SAFETY: SIOCGIFHWADDR writes sa_data inside the ifreq we own.
    let r = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR, &mut req) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // struct sockaddr { sa_family: u16, sa_data: [c_char; 14] } — the address
    // starts 2 bytes into the union.
    let b = req.union_bytes();
    Ok(MacAddr::new([b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// `struct ifreq`: a 16-byte name followed by a 24-byte union.
#[repr(C)]
struct IfReq {
    name: [u8; 16],
    union_: [u8; 24],
}

impl IfReq {
    fn new(name: &str) -> Result<IfReq> {
        let b = name.as_bytes();
        if b.len() >= 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("afxdp: interface name {name:?} too long"),
            ));
        }
        let mut req = IfReq {
            name: [0; 16],
            union_: [0; 24],
        };
        req.name[..b.len()].copy_from_slice(b);
        Ok(req)
    }

    fn set_data_ptr(&mut self, p: *mut libc::c_void) {
        self.union_[..8].copy_from_slice(&(p as usize as u64).to_ne_bytes());
    }

    fn union_bytes(&self) -> &[u8; 24] {
        &self.union_
    }
}

// ethtool commands used to count receive queues.
const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GRXRINGS: u32 = 0x0000_002f;
const ETHTOOL_GCHANNELS: u32 = 0x0000_003c;

#[repr(C)]
#[derive(Default)]
struct EthtoolChannels {
    cmd: u32,
    max_rx: u32,
    max_tx: u32,
    max_other: u32,
    max_combined: u32,
    rx_count: u32,
    tx_count: u32,
    other_count: u32,
    combined_count: u32,
}

#[repr(C)]
#[derive(Default)]
struct EthtoolRxnfc {
    cmd: u32,
    flow_type: u32,
    data: u64,
    // The kernel copies back only as much as the command produces; the rest of
    // `struct ethtool_rxnfc` is not read for ETHTOOL_GRXRINGS.
    _rest: [u64; 8],
}

/// Number of receive queues on `name`.
///
/// `ETHTOOL_GCHANNELS` is the modern answer; drivers that predate it still
/// report `ETHTOOL_GRXRINGS`. Neither is fatal — a device that answers neither
/// is treated as single-queue.
//
// TODO(afxdp): needs a real NIC to verify; virtual devices answer EOPNOTSUPP.
fn rx_queue_count(name: &str) -> Result<u32> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fd; OwnedFd closes it.
    let sock = unsafe { OwnedFd::from_raw_fd(sock) };
    let raw = sock.as_raw_fd();

    let mut ch = EthtoolChannels {
        cmd: ETHTOOL_GCHANNELS,
        ..Default::default()
    };
    let mut req = IfReq::new(name)?;
    req.set_data_ptr(&mut ch as *mut _ as *mut libc::c_void);
    // SAFETY: req.name is NUL-padded and the data pointer refers to `ch`, which
    // outlives the call.
    if unsafe { libc::ioctl(raw, SIOCETHTOOL, &mut req) } >= 0 {
        // A driver reports its queues as `combined` (shared RX/TX) or as
        // dedicated `rx`; either can be zero.
        let n = ch.combined_count + ch.rx_count;
        if n > 0 {
            return Ok(n);
        }
    }

    let mut nfc = EthtoolRxnfc {
        cmd: ETHTOOL_GRXRINGS,
        ..Default::default()
    };
    let mut req = IfReq::new(name)?;
    req.set_data_ptr(&mut nfc as *mut _ as *mut libc::c_void);
    // SAFETY: as above, for `nfc`.
    if unsafe { libc::ioctl(raw, SIOCETHTOOL, &mut req) } >= 0 && nfc.data > 0 {
        return Ok(nfc.data as u32);
    }

    Ok(1)
}

fn setsockopt_umem_reg(fd: RawFd, reg: &libc::xdp_umem_reg) -> Result<()> {
    // SAFETY: valid fd and a correctly sized option value.
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
    setsockopt_u32_level(fd, SOL_XDP, opt, val)
}

fn setsockopt_u32_level(fd: RawFd, level: libc::c_int, opt: libc::c_int, val: u32) -> Result<()> {
    // SAFETY: valid fd and a correctly sized option value.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
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

/// Turn on kernel-side busy polling.
///
/// `SO_PREFER_BUSY_POLL` and `SO_BUSY_POLL_BUDGET` arrived in 5.11; a kernel
/// that does not know them leaves plain `SO_BUSY_POLL` doing the useful part,
/// so those two are best-effort.
fn set_busy_poll(fd: RawFd, bp: BusyPoll) -> Result<()> {
    let _ = setsockopt_u32_level(fd, libc::SOL_SOCKET, SO_PREFER_BUSY_POLL, 1);
    setsockopt_u32_level(fd, libc::SOL_SOCKET, SO_BUSY_POLL, bp.timeout_us)?;
    let _ = setsockopt_u32_level(fd, libc::SOL_SOCKET, SO_BUSY_POLL_BUDGET, bp.budget);
    Ok(())
}

fn getsockopt_mmap_offsets(fd: RawFd) -> Result<libc::xdp_mmap_offsets> {
    let mut offs: libc::xdp_mmap_offsets = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::xdp_mmap_offsets>() as libc::socklen_t;
    // SAFETY: valid fd; the kernel writes at most `len` bytes into `offs`.
    let r = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            &mut offs as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(offs)
}

fn getsockopt_statistics(fd: RawFd) -> Result<libc::xdp_statistics> {
    let mut stats: libc::xdp_statistics = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::xdp_statistics>() as libc::socklen_t;
    // SAFETY: valid fd; the kernel writes at most `len` bytes into `stats`.
    let r = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_STATISTICS,
            &mut stats as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stats)
}

/// Ask the kernel whether this socket ended up on a zero-copy path.
fn socket_is_zerocopy(fd: RawFd) -> bool {
    let mut opts: libc::xdp_options = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::xdp_options>() as libc::socklen_t;
    // SAFETY: valid fd; the kernel writes at most `len` bytes into `opts`.
    let r = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_OPTIONS,
            &mut opts as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    r >= 0 && opts.flags & XDP_OPTIONS_ZEROCOPY != 0
}

/// UMEM backing store. Huge pages cut TLB misses on the packet buffers, but
/// they need pre-reserved hugetlb pages, so a failure falls back silently.
fn mmap_umem(len: usize, huge_pages: bool) -> Result<Mapping> {
    if huge_pages {
        if let Ok(m) = mmap_anon(len, libc::MAP_HUGETLB) {
            return Ok(m);
        }
    }
    mmap_anon(len, 0)
}

fn mmap_anon(len: usize, extra_flags: libc::c_int) -> Result<Mapping> {
    // MAP_POPULATE faults the whole region in now rather than taking the page
    // faults on the receive path.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE | extra_flags,
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
    let total = ring_map_len(off.desc, size);
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

fn ring_map_len(desc_off: u64, size: u32) -> usize {
    desc_off as usize + size as usize * std::mem::size_of::<libc::xdp_desc>()
}

/// The bind flag sequence to try, most preferred first.
///
/// Zero-copy first when it is reachable, then copy mode; `XDP_USE_NEED_WAKEUP`
/// is dropped last of all because kernels before 5.4 reject it outright and a
/// working copy-mode socket beats no socket.
fn bind_flag_candidates(extra: u16, want_zerocopy: bool) -> Vec<u16> {
    let mut v = Vec::with_capacity(3);
    if want_zerocopy {
        v.push(XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP | extra);
    }
    v.push(XDP_COPY | XDP_USE_NEED_WAKEUP | extra);
    v.push(XDP_COPY | extra);
    v
}

/// `bind` the socket to the interface/queue. Returns whether the kernel put it
/// on a zero-copy path.
fn bind_xdp(
    fd: RawFd,
    ifindex: u32,
    queue_id: u32,
    cfg: &Config,
    want_zerocopy: bool,
) -> Result<bool> {
    let mut last = None;
    for flags in bind_flag_candidates(cfg.flags, want_zerocopy) {
        let sa = libc::sockaddr_xdp {
            sxdp_family: libc::AF_XDP as u16,
            sxdp_flags: flags,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };
        match bind_once(fd, &sa) {
            Ok(()) => return Ok(socket_is_zerocopy(fd)),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "afxdp: no bind flags to try")
    }))
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
        assert_eq!(c.zerocopy, Zerocopy::Auto);
        assert_eq!(c.mode, Mode::AUTO);
        // Every queue by default: binding only queue 0 silently loses whatever
        // RSS hashes elsewhere.
        assert!(c.queue_ids.is_empty());
    }

    #[test]
    fn default_program_captures_nothing_and_passes_everything() {
        match Config::default().program {
            ProgramSource::Capture(c) => {
                assert_eq!(c.default_action, crate::xdp::Action::PASS);
                assert!(c.arp);
            }
            _ => panic!("default should be a capture program"),
        }
    }

    #[test]
    fn zero_fields_normalize_to_defaults() {
        let c = Config {
            interface: "eth0".into(),
            ring_size: 0,
            frame_size: 0,
            num_frames: 0,
            ..Default::default()
        }
        .normalize()
        .unwrap();
        assert_eq!(c.ring_size, 2048);
        assert_eq!(c.frame_size, 4096);
        assert_eq!(c.num_frames, 4096);
    }

    #[test]
    fn ring_size_must_be_power_of_two() {
        let e = Config {
            ring_size: 1000,
            ..Default::default()
        }
        .normalize()
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn frame_size_must_be_a_valid_umem_chunk() {
        // Below XDP_UMEM_MIN_CHUNK_SIZE.
        assert!(Config {
            frame_size: 1024,
            ..Default::default()
        }
        .normalize()
        .is_err());
        // Not a power of two.
        assert!(Config {
            frame_size: 3000,
            ..Default::default()
        }
        .normalize()
        .is_err());
        // Larger than a page: an aligned-mode chunk may not straddle one.
        assert!(Config {
            frame_size: (page_size() * 2) as u32,
            ..Default::default()
        }
        .normalize()
        .is_err());
        // 2048 is the smallest the kernel accepts.
        assert!(Config {
            frame_size: 2048,
            ..Default::default()
        }
        .normalize()
        .is_ok());
    }

    #[test]
    fn umem_always_splits_into_a_usable_rx_and_tx_pool() {
        for n in [2u32, 3, 4096, 4097] {
            let (rx, tx) = umem_split(n);
            assert_eq!(rx + tx, n);
            assert!(rx >= 1 && tx >= 1, "n={n} split {rx}/{tx}");
        }
    }

    #[test]
    fn umem_split_offsets() {
        // The TX pool starts where the RX pool ends, and no address escapes the
        // region.
        let frame_size = 4096u64;
        let num_frames = 8u32;
        let (rx, tx) = umem_split(num_frames);
        let last_tx = ((rx + tx - 1) as u64) * frame_size;
        assert_eq!((rx as u64) * frame_size, 4 * frame_size);
        assert!(last_tx + frame_size <= num_frames as u64 * frame_size);
    }

    #[test]
    fn ring_mmap_size_covers_descs() {
        // A ring mapping must reach past the cursors to the end of the array.
        assert_eq!(ring_map_len(64, 8), 64 + 8 * 16);
    }

    #[test]
    fn zerocopy_is_tried_first_then_copy() {
        let c = bind_flag_candidates(0, true);
        assert_eq!(c[0], XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP);
        assert_eq!(c[1], XDP_COPY | XDP_USE_NEED_WAKEUP);
        // Last resort for pre-5.4 kernels, which reject XDP_USE_NEED_WAKEUP.
        assert_eq!(c[2], XDP_COPY);
    }

    #[test]
    fn copy_mode_never_attempts_a_zerocopy_bind() {
        let c = bind_flag_candidates(0, false);
        assert!(c.iter().all(|f| f & XDP_ZEROCOPY == 0));
    }

    #[test]
    fn extra_bind_flags_are_preserved() {
        let extra = 1 << 6;
        for f in bind_flag_candidates(extra, true) {
            assert_eq!(f & extra, extra);
        }
    }

    #[test]
    fn ifreq_layout_matches_the_kernel_struct() {
        assert_eq!(std::mem::size_of::<IfReq>(), 40);
        let req = IfReq::new("eth0").unwrap();
        assert_eq!(&req.name[..5], b"eth0\0");
        assert!(IfReq::new("an-interface-name-that-is-far-too-long").is_err());
    }

    #[test]
    fn unknown_interface_is_not_found() {
        let e = if_nametoindex("pktkit-no-such-if").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn opening_an_unknown_interface_fails_before_touching_bpf() {
        let e = Device::open(Config {
            interface: "pktkit-no-such-if".into(),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn busy_poll_defaults_match_the_rx_batch() {
        let bp = BusyPoll::default();
        assert_eq!(bp.budget as usize, BATCH);
        assert!(bp.timeout_us > 0);
    }
}
