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
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::afxdp::ring::{AddrRing, DescRing, RingOffset, XdpDesc};
use crate::syscall::{self, CPU_SETSIZE, CpuSet, IfReq};
use crate::xdp::{self, Capture, CaptureConfig, Mode, Rule};
use crate::{Frame, IpPrefix, L2Handler, MacAddr, Result};

// --- AF_XDP / setsockopt constants (mirror <linux/if_xdp.h>) ---------------

const SOL_XDP: i32 = 283;
const XDP_MMAP_OFFSETS: i32 = 1;
const XDP_RX_RING: i32 = 2;
const XDP_TX_RING: i32 = 3;
const XDP_UMEM_REG: i32 = 4;
const XDP_UMEM_FILL_RING: i32 = 5;
const XDP_UMEM_COMPLETION_RING: i32 = 6;
const XDP_STATISTICS: i32 = 7;
const XDP_OPTIONS: i32 = 8;

/// `XDP_OPTIONS_ZEROCOPY`: set once the kernel has actually put the socket on
/// a driver's zero-copy path. The authoritative answer, as opposed to guessing
/// from which bind flags were accepted.
const XDP_OPTIONS_ZEROCOPY: u32 = 1 << 0;

const XDP_PGOFF_RX_RING: i64 = 0;
const XDP_PGOFF_TX_RING: i64 = 0x8000_0000;
const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x1_0000_0000;
const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x1_8000_0000;

// Bind flags.
const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;
/// Lets the kernel tell us, through a flag in the ring, when it actually needs
/// a syscall to make progress. Without it every batch pays for a `sendto`.
const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

// Busy-poll socket options (SOL_SOCKET).
const SO_BUSY_POLL: i32 = 46;
const SO_PREFER_BUSY_POLL: i32 = 69;
const SO_BUSY_POLL_BUDGET: i32 = 70;

/// `struct xdp_umem_reg`.
#[repr(C)]
struct UmemReg {
    addr: u64,
    len: u64,
    /// The UMEM frame size.
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
}

/// `struct xdp_mmap_offsets`.
#[repr(C)]
#[derive(Default)]
struct MmapOffsets {
    rx: RingOffset,
    tx: RingOffset,
    fr: RingOffset,
    cr: RingOffset,
}

/// `struct sockaddr_xdp`.
#[repr(C)]
struct SockaddrXdp {
    family: u16,
    flags: u16,
    ifindex: u32,
    queue_id: u32,
    shared_umem_fd: u32,
}

/// Kernel counters for an AF_XDP socket (`struct xdp_statistics`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
#[non_exhaustive]
pub struct Statistics {
    /// Dropped for reasons other than invalid descriptors.
    pub rx_dropped: u64,
    /// Dropped because of invalid descriptors.
    pub rx_invalid_descs: u64,
    /// Dropped because of invalid descriptors.
    pub tx_invalid_descs: u64,
    /// Dropped because the RX ring was full.
    pub rx_ring_full: u64,
    /// Times the FILL ring was found empty.
    pub rx_fill_ring_empty_descs: u64,
    /// Times the TX ring was found empty.
    pub tx_ring_empty_descs: u64,
}

// The kernel ABI. `UmemReg` is the size a 6.8+ kernel knows; older ones accept
// it as long as the fields they do not know are zero.
const _: () = {
    assert!(std::mem::size_of::<UmemReg>() == 32);
    assert!(std::mem::size_of::<MmapOffsets>() == 128);
    assert!(std::mem::size_of::<SockaddrXdp>() == 16);
    assert!(std::mem::size_of::<Statistics>() == 48);
};

/// Smallest UMEM chunk the kernel accepts (`XDP_UMEM_MIN_CHUNK_SIZE`).
const MIN_FRAME_SIZE: u32 = 2048;

/// Descriptors moved per RX drain / TX completion reap. Matches what the
/// kernel's own sample uses; large enough to amortise the ring cursor updates,
/// small enough to stay in cache.
const BATCH: usize = 64;

/// How long the poll loop blocks before re-checking whether it should exit.
const POLL_TIMEOUT_MS: i32 = 1000;

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
#[non_exhaustive]
pub struct BusyPoll {
    /// `SO_BUSY_POLL`, in microseconds.
    pub timeout_us: u32,
    /// `SO_BUSY_POLL_BUDGET`: packets per NAPI poll. The kernel's AF_XDP
    /// documentation suggests matching it to the RX batch size.
    pub budget: u32,
}

setters! {
    BusyPoll {
        set timeout_us: u32;
        set budget: u32;
    }
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
#[non_exhaustive]
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
    /// How many times an RX thread re-checks an empty ring before it blocks in
    /// `poll()`. 0, the default, blocks at once. A few thousand keeps a thread
    /// that is receiving a steady stream out of the kernel between batches —
    /// the wakeup from `poll()` costs far more than a batch does — at the
    /// price of a core that stays busy for that long after traffic stops.
    pub rx_spin: u32,
    /// CPUs to pin the RX threads to: thread `i`, serving the `i`th bound
    /// queue, goes on `rx_cpus[i]`. Queues past the end of the list are left
    /// to the scheduler; empty, the default, pins nothing.
    ///
    /// The core to name is the one that takes the queue's interrupt, or a
    /// neighbour sharing its cache. With [`Config::busy_poll`] it should be
    /// the same core, since the NAPI loop then runs on the calling thread.
    pub rx_cpus: Vec<usize>,
    /// Back the UMEM with huge pages when possible, falling back silently.
    /// Cuts TLB pressure on the packet buffers at the cost of holding a scarce
    /// system resource.
    pub huge_pages: bool,
    /// Extra bind flags OR'd in.
    pub flags: u16,
}

setters! {
    Config {
        into interface: String;
        set queue_ids: Vec<u32>;
        set ring_size: u32;
        set frame_size: u32;
        set num_frames: u32;
        set zerocopy: Zerocopy;
        set mode: Mode;
        set program: ProgramSource;
        some busy_poll: BusyPoll;
        set rx_spin: u32;
        set rx_cpus: Vec<usize>;
        set huge_pages: bool;
        set flags: u16;
    }
}

impl Config {
    /// Defaults for everything but the interface, e.g. `"eth0"`.
    pub fn new(interface: impl Into<String>) -> Config {
        Config::default().interface(interface)
    }
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
            rx_spin: 0,
            rx_cpus: Vec::new(),
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
        let page = syscall::page_size();
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
        if let Some(&cpu) = c.rx_cpus.iter().find(|&&cpu| cpu >= CPU_SETSIZE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("afxdp: rx_cpus names CPU {cpu}, past the {CPU_SETSIZE} a cpu_set_t holds"),
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
        let _ = unsafe { syscall::munmap(self.ptr, self.len) };
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
    /// [`Config::rx_spin`].
    rx_spin: u32,
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

        for (i, sock) in inner.sockets.iter().enumerate() {
            let s = sock.clone();
            let Some(&cpu) = cfg.rx_cpus.get(i) else {
                std::thread::spawn(move || poll_loop(s));
                continue;
            };
            // The thread pins itself before it touches a ring, and reports
            // back so that a CPU that does not exist fails the open instead
            // of being lost. On error `inner` drops, which is what stops the
            // threads already running.
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let pinned = pin_current_thread(cpu);
                let ok = pinned.is_ok();
                let _ = tx.send(pinned);
                if ok {
                    poll_loop(s);
                }
            });
            rx.recv().map_err(|_| {
                io::Error::other(format!(
                    "afxdp: RX thread for CPU {cpu} died before pinning"
                ))
            })??;
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

    /// Start delivering all traffic for `prefix` to this device.
    ///
    /// Takes effect immediately: the prefix goes into a map the running program
    /// reads, so nothing is reloaded or reattached.
    pub fn capture_add(&self, prefix: IpPrefix) -> Result<()> {
        self.require_capture()?.add(prefix)
    }

    /// Start delivering the traffic `rule` selects for `prefix` — one
    /// protocol, or one TCP/UDP port — leaving the rest of the address to the
    /// host stack. See [`Rule`].
    pub fn capture_add_rule(&self, prefix: IpPrefix, rule: Rule) -> Result<()> {
        self.require_capture()?.add_rule(prefix, rule)
    }

    /// Stop capturing `prefix` under every rule. Returns `false` if it was
    /// not in the set.
    pub fn capture_remove(&self, prefix: IpPrefix) -> Result<bool> {
        self.require_capture()?.remove(prefix)
    }

    /// Stop capturing what `rule` selects for `prefix`. Returns `false` if the
    /// prefix did not hold that rule.
    pub fn capture_remove_rule(&self, prefix: IpPrefix, rule: Rule) -> Result<bool> {
        self.require_capture()?.remove_rule(prefix, rule)
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
    pub fn statistics(&self) -> Result<Statistics> {
        let mut total = Statistics::default();
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

    /// Send several frames at once: one ring update and at most one wakeup
    /// syscall for the lot, where [`L2Device::send`](crate::L2Device::send)
    /// pays for both per frame. In copy mode, where the kernel wants a wakeup
    /// for nearly every transmission, that is the difference between one
    /// `sendto` per packet and one per burst.
    ///
    /// Returns how many frames, from the front of `frames`, were taken; fewer
    /// than `frames.len()` means the TX buffers or the ring ran out, and the
    /// rest can be offered again. Runt frames are taken and dropped, as `send`
    /// does. A frame too large for a UMEM chunk fails the call before anything
    /// is queued.
    pub fn send_batch(&self, frames: &[&Frame]) -> Result<usize> {
        self.tx_socket().send_batch(frames)
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

        let fd = syscall::socket(syscall::AF_XDP, syscall::SOCK_RAW, 0)
            .map_err(|e| step("socket(AF_XDP)", e))?;
        let raw = fd.as_raw_fd();

        let umem_size = num_frames as usize * frame_size as usize;
        let umem = mmap_umem(umem_size, cfg.huge_pages).map_err(|e| step("mmap UMEM", e))?;

        // Headroom stays 0: the kernel reserves XDP_PACKET_HEADROOM inside the
        // chunk on its own, and asking for more only shrinks the usable frame.
        let reg = UmemReg {
            addr: umem.ptr() as u64,
            len: umem_size as u64,
            chunk_size: frame_size,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        syscall::setsockopt(raw, SOL_XDP, XDP_UMEM_REG, &reg)
            .map_err(|e| step("XDP_UMEM_REG", e))?;

        for opt in [
            XDP_UMEM_FILL_RING,
            XDP_UMEM_COMPLETION_RING,
            XDP_RX_RING,
            XDP_TX_RING,
        ] {
            setsockopt_u32(raw, opt, ring_size).map_err(|e| step("set ring size", e))?;
        }

        let offs = getsockopt_mmap_offsets(raw).map_err(|e| step("XDP_MMAP_OFFSETS", e))?;

        // FILL and COMPLETION carry bare u64 addresses, RX and TX full
        // descriptors. The kernel refuses a mapping longer than the ring it
        // allocated, so each has to be asked for at its own element size.
        let addr = std::mem::size_of::<u64>();
        let desc = std::mem::size_of::<XdpDesc>();
        let fill_map = mmap_ring(raw, XDP_UMEM_PGOFF_FILL_RING, &offs.fr, ring_size, addr)
            .map_err(|e| step("mmap FILL ring", e))?;
        let comp_map = mmap_ring(
            raw,
            XDP_UMEM_PGOFF_COMPLETION_RING,
            &offs.cr,
            ring_size,
            addr,
        )
        .map_err(|e| step("mmap COMPLETION ring", e))?;
        let rx_map = mmap_ring(raw, XDP_PGOFF_RX_RING, &offs.rx, ring_size, desc)
            .map_err(|e| step("mmap RX ring", e))?;
        let tx_map = mmap_ring(raw, XDP_PGOFF_TX_RING, &offs.tx, ring_size, desc)
            .map_err(|e| step("mmap TX ring", e))?;

        // SAFETY: each mapping is sized for its ring (see `mmap_ring`), the
        // offsets came from the kernel, and ring_size is a power of two.
        let fill_ring = unsafe { AddrRing::new(fill_map.ptr(), offs.fr, ring_size) };
        let comp_ring = unsafe { AddrRing::new(comp_map.ptr(), offs.cr, ring_size) };
        let rx_ring = unsafe { DescRing::new(rx_map.ptr(), offs.rx, ring_size) };
        let tx_ring = unsafe { DescRing::new(tx_map.ptr(), offs.tx, ring_size) };

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

        let zerocopy = bind_xdp(raw, ifindex, queue_id, cfg, want_zerocopy)
            .map_err(|e| step(&format!("bind queue {queue_id}"), e))?;

        if let Some(bp) = cfg.busy_poll {
            set_busy_poll(raw, bp).map_err(|e| step("SO_BUSY_POLL", e))?;
        }

        Ok(Socket {
            fd,
            queue_id,
            frame_size: frame_size as usize,
            rx_spin: cfg.rx_spin,
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
                        ));
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

        let desc = [XdpDesc {
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

    /// As [`Socket::send`] for a burst. See [`Device::send_batch`].
    fn send_batch(&self, frames: &[&Frame]) -> Result<usize> {
        if let Some(f) = frames.iter().find(|f| f.as_bytes().len() > self.frame_size) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "afxdp: frame of {} bytes exceeds the {}-byte UMEM chunk",
                    f.as_bytes().len(),
                    self.frame_size
                ),
            ));
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "afxdp: closed"));
        }

        let mut free = self.tx_free.lock().unwrap();
        let mut taken = 0;
        let mut queued = false;
        let mut descs = [XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        }; BATCH];

        while taken < frames.len() {
            // We are the ring's only producer and hold the lock, so the room
            // seen here cannot shrink before the produce below.
            let room = self.tx_ring.free().min(BATCH);
            let mut n = 0;
            let mut upto = taken;
            while n < room && upto < frames.len() {
                let bytes = frames[upto].as_bytes();
                if bytes.len() < 14 {
                    upto += 1;
                    continue;
                }
                if free.is_empty() {
                    self.reclaim_tx(&mut free);
                }
                let Some(addr) = free.pop() else { break };
                // SAFETY: addr is a frame-aligned offset from the TX pool and
                // the length was checked against frame_size above.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        self.umem.ptr().add(addr as usize),
                        bytes.len(),
                    );
                }
                descs[n] = XdpDesc {
                    addr,
                    len: bytes.len() as u32,
                    options: 0,
                };
                n += 1;
                upto += 1;
            }
            if n > 0 {
                let produced = self.tx_ring.produce(&descs[..n]);
                debug_assert_eq!(produced, n, "TX ring shrank under its only producer");
                queued = true;
            }
            if upto == taken {
                // Neither a buffer nor a ring slot to be had.
                break;
            }
            taken = upto;
        }
        drop(free);

        if queued && self.tx_ring.need_wakeup() {
            self.kick_tx();
        }
        Ok(taken)
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
        // Failure is not ours to act on: EAGAIN/EBUSY mean the kernel is
        // already busy with the ring, and the next kick retries anyway.
        let _ = syscall::sendto(self.raw(), &[], syscall::MSG_DONTWAIT, None);
    }

    /// Block until there is RX work or `timeout_ms` elapses.
    ///
    /// `poll` doubles as the RX wakeup: when the FILL ring carries
    /// `XDP_RING_NEED_WAKEUP` the kernel has stopped pulling buffers from it and
    /// this is what restarts it. With busy polling configured, the same call
    /// runs the driver's NAPI loop inline.
    fn wait(&self, timeout_ms: i32) {
        let _ = syscall::poll(self.raw(), syscall::POLLIN, timeout_ms);
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
    let mut rx_batch = [XdpDesc {
        addr: 0,
        len: 0,
        options: 0,
    }; BATCH];
    let mut fill_batch = [0u64; BATCH];

    let mut idle = 0u32;

    while !sock.closed.load(Ordering::Acquire) {
        let got = sock.rx_ring.consume(&mut rx_batch);
        if got == 0 && idle < sock.rx_spin {
            // Traffic was here a moment ago; look again before paying for a
            // trip through poll().
            idle += 1;
            std::hint::spin_loop();
            continue;
        }
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
        idle = 0;

        // One clone per batch rather than per frame.
        let handler = sock.handler.lock().unwrap().clone();
        let mut fill_count = 0;

        for desc in &rx_batch[..got] {
            let addr = desc.addr;
            let len = desc.len as usize;

            if len >= 14
                && let Some(h) = &handler
            {
                // Handed to the handler in place. `L2Handler` takes `&Frame`
                // so the borrow cannot outlive the call, and the chunk is not
                // recycled into the FILL ring until after this loop — so the
                // kernel cannot be writing it while the handler reads.
                //
                // SAFETY: addr+len lies within the UMEM mapping (the kernel
                // wrote a valid RX descriptor).
                let slice =
                    unsafe { std::slice::from_raw_parts(sock.umem.ptr().add(addr as usize), len) };
                let _ = h(Frame::from_slice(slice));
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

/// Name the setup step an errno came from. `Device::open` makes a dozen
/// syscalls that can all answer a bare `EINVAL`.
fn step(what: &str, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("afxdp: {what}: {e}"))
}

/// Restrict the calling thread to `cpu`, which `Config::normalize` has checked
/// is below `CPU_SETSIZE`.
fn pin_current_thread(cpu: usize) -> Result<()> {
    let mut set = CpuSet::new();
    set.set(cpu);
    syscall::sched_setaffinity(&set)
        .map_err(|e| io::Error::new(e.kind(), format!("afxdp: pin RX thread to CPU {cpu}: {e}")))
}

/// `if_nametoindex`, with the interface named in the error.
fn if_nametoindex(name: &str) -> Result<u32> {
    syscall::if_nametoindex(name).map_err(|e| step(&format!("interface {name:?}"), e))
}

/// Read an interface's MAC through `SIOCGIFHWADDR`.
fn read_hw_addr(name: &str) -> Result<MacAddr> {
    let sock = syscall::socket(syscall::AF_INET, syscall::SOCK_DGRAM, 0)?;
    let mut req = IfReq::new(name)?;
    // SAFETY: SIOCGIFHWADDR writes sa_data inside the ifreq we own.
    unsafe { syscall::ioctl(sock.as_raw_fd(), syscall::SIOCGIFHWADDR, &mut req)? };
    // struct sockaddr { sa_family: u16, sa_data: [c_char; 14] } — the address
    // starts 2 bytes into the union.
    let b = &req.data;
    Ok(MacAddr::new([b[2], b[3], b[4], b[5], b[6], b[7]]))
}

// ethtool commands used to count receive queues.
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
    let sock: OwnedFd = syscall::socket(syscall::AF_INET, syscall::SOCK_DGRAM, 0)?;
    let raw = sock.as_raw_fd();

    let mut ch = EthtoolChannels {
        cmd: ETHTOOL_GCHANNELS,
        ..Default::default()
    };
    let mut req = IfReq::new(name)?;
    req.set_data_ptr(&mut ch);
    // SAFETY: req.name is NUL-padded and the data pointer refers to `ch`, which
    // outlives the call.
    if unsafe { syscall::ioctl(raw, syscall::SIOCETHTOOL, &mut req) }.is_ok() {
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
    req.set_data_ptr(&mut nfc);
    // SAFETY: as above, for `nfc`.
    if unsafe { syscall::ioctl(raw, syscall::SIOCETHTOOL, &mut req) }.is_ok() && nfc.data > 0 {
        return Ok(nfc.data as u32);
    }

    Ok(1)
}

fn setsockopt_u32(fd: RawFd, opt: i32, val: u32) -> Result<()> {
    syscall::setsockopt(fd, SOL_XDP, opt, &val)
}

/// Turn on kernel-side busy polling.
///
/// `SO_PREFER_BUSY_POLL` and `SO_BUSY_POLL_BUDGET` arrived in 5.11; a kernel
/// that does not know them leaves plain `SO_BUSY_POLL` doing the useful part,
/// so those two are best-effort.
fn set_busy_poll(fd: RawFd, bp: BusyPoll) -> Result<()> {
    let _ = syscall::setsockopt(fd, syscall::SOL_SOCKET, SO_PREFER_BUSY_POLL, &1u32);
    syscall::setsockopt(fd, syscall::SOL_SOCKET, SO_BUSY_POLL, &bp.timeout_us)?;
    let _ = syscall::setsockopt(fd, syscall::SOL_SOCKET, SO_BUSY_POLL_BUDGET, &bp.budget);
    Ok(())
}

fn getsockopt_mmap_offsets(fd: RawFd) -> Result<MmapOffsets> {
    let mut offs = MmapOffsets::default();
    // SAFETY: plain integers; any bytes are a valid MmapOffsets.
    unsafe { syscall::getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &mut offs)? };
    Ok(offs)
}

fn getsockopt_statistics(fd: RawFd) -> Result<Statistics> {
    let mut stats = Statistics::default();
    // SAFETY: plain integers; any bytes are a valid Statistics.
    unsafe { syscall::getsockopt(fd, SOL_XDP, XDP_STATISTICS, &mut stats)? };
    Ok(stats)
}

/// Ask the kernel whether this socket ended up on a zero-copy path.
fn socket_is_zerocopy(fd: RawFd) -> bool {
    // `struct xdp_options` is a single u32 of flags.
    let mut flags = 0u32;
    // SAFETY: any bytes are a valid u32.
    let r = unsafe { syscall::getsockopt(fd, SOL_XDP, XDP_OPTIONS, &mut flags) };
    r.is_ok() && flags & XDP_OPTIONS_ZEROCOPY != 0
}

/// UMEM backing store. Huge pages cut TLB misses on the packet buffers, but
/// they need pre-reserved hugetlb pages, so a failure falls back silently.
fn mmap_umem(len: usize, huge_pages: bool) -> Result<Mapping> {
    if huge_pages && let Ok(m) = mmap_anon(len, syscall::MAP_HUGETLB) {
        return Ok(m);
    }
    mmap_anon(len, 0)
}

fn mmap_anon(len: usize, extra_flags: i32) -> Result<Mapping> {
    // MAP_POPULATE faults the whole region in now rather than taking the page
    // faults on the receive path.
    // SAFETY: a fresh private anonymous mapping aliases nothing.
    let ptr = unsafe {
        syscall::mmap(
            len,
            syscall::PROT_READ | syscall::PROT_WRITE,
            syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS | syscall::MAP_POPULATE | extra_flags,
            -1,
            0,
        )?
    };
    Ok(Mapping { ptr, len })
}

/// Map one ring at the given page offset. The mapping spans the descriptor
/// array: `off.desc + size * elem_size`. The kernel reports `desc` past the
/// cursors, and the element size is 8 bytes for the FILL/COMPLETION rings or
/// 16 bytes (`xdp_desc`) for RX/TX. We always reserve the larger 16-byte
/// stride, which is a harmless over-map for the address rings.
fn mmap_ring(fd: RawFd, pgoff: i64, off: &RingOffset, size: u32, elem: usize) -> Result<Mapping> {
    let total = ring_map_len(off.desc, size, elem);
    // SAFETY: the ring is shared with the kernel, not with any Rust object;
    // the rings only touch it through atomics and the SPSC discipline.
    let ptr = unsafe {
        syscall::mmap(
            total,
            syscall::PROT_READ | syscall::PROT_WRITE,
            syscall::MAP_SHARED | syscall::MAP_POPULATE,
            fd,
            pgoff,
        )?
    };
    Ok(Mapping { ptr, len: total })
}

/// Bytes from the start of a ring mapping to the end of its `size` elements
/// of `elem` bytes each.
fn ring_map_len(desc_off: u64, size: u32, elem: usize) -> usize {
    desc_off as usize + size as usize * elem
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
        let sa = SockaddrXdp {
            family: syscall::AF_XDP as u16,
            flags,
            ifindex,
            queue_id,
            shared_umem_fd: 0,
        };
        match syscall::bind(fd, &sa) {
            Ok(()) => return Ok(socket_is_zerocopy(fd)),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "afxdp: no bind flags to try")
    }))
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
        assert!(
            Config {
                frame_size: 1024,
                ..Default::default()
            }
            .normalize()
            .is_err()
        );
        // Not a power of two.
        assert!(
            Config {
                frame_size: 3000,
                ..Default::default()
            }
            .normalize()
            .is_err()
        );
        // Larger than a page: an aligned-mode chunk may not straddle one.
        assert!(
            Config {
                frame_size: (syscall::page_size() * 2) as u32,
                ..Default::default()
            }
            .normalize()
            .is_err()
        );
        // 2048 is the smallest the kernel accepts.
        assert!(
            Config {
                frame_size: 2048,
                ..Default::default()
            }
            .normalize()
            .is_ok()
        );
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
        // A ring mapping must reach past the cursors to the end of the array
        // and no further: the kernel answers EINVAL to a mapping longer than
        // the ring, which is what sizing an address ring by descriptors does.
        assert_eq!(ring_map_len(64, 8, std::mem::size_of::<u64>()), 64 + 8 * 8);
        assert_eq!(
            ring_map_len(64, 8, std::mem::size_of::<XdpDesc>()),
            64 + 8 * 16
        );
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
    fn spinning_and_pinning_are_off_by_default() {
        let c = Config::default();
        assert_eq!(c.rx_spin, 0);
        assert!(c.rx_cpus.is_empty());
    }

    #[test]
    fn a_cpu_past_the_set_size_is_refused_before_open() {
        let e = Config {
            interface: "lo".into(),
            rx_cpus: vec![0, CPU_SETSIZE],
            ..Default::default()
        }
        .normalize()
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_thread_can_be_pinned_to_a_cpu_we_are_allowed_on() {
        // Pick from our own mask: a container may not own CPU 0.
        let allowed = syscall::sched_getaffinity()
            .unwrap()
            .iter()
            .next()
            .expect("running on some CPU");
        let got = std::thread::spawn(move || {
            pin_current_thread(allowed).unwrap();
            syscall::sched_getaffinity()
                .unwrap()
                .iter()
                .collect::<Vec<_>>()
        })
        .join()
        .unwrap();
        assert_eq!(got, vec![allowed]);
    }

    #[test]
    fn pinning_to_a_cpu_that_does_not_exist_is_an_error() {
        // Inside cpu_set_t, but no machine running this has 1024 cores online.
        let e = std::thread::spawn(|| pin_current_thread(CPU_SETSIZE - 1))
            .join()
            .unwrap()
            .unwrap_err();
        assert!(e.to_string().contains("pin RX thread"), "{e}");
    }

    #[test]
    fn busy_poll_defaults_match_the_rx_batch() {
        let bp = BusyPoll::default();
        assert_eq!(bp.budget as usize, BATCH);
        assert!(bp.timeout_us > 0);
    }
}
