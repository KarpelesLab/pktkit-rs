//! Linux TUN/TAP via `/dev/net/tun` and `ioctl(TUNSETIFF)`.
//!
//! Reader threads call the installed handler synchronously; the buffer
//! handed to the handler is the read scratch and is only valid for the
//! duration of the call (mirroring the rest of the crate).

use super::reader::{DevFd, HandlerSlot, MAX_MTU, deliver, is_whole, msg_buffer, read_or_record};
use crate::sys::if_hw_addr;
use crate::{
    DeviceStats, Frame, IpPrefix, L2Device, L2Handler, L3Device, L3Handler, MacAddr, Packet, Result,
};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

/// Knobs for opening a TUN or TAP device.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct TuntapConfig {
    /// Requested interface name; empty asks the kernel to pick one
    /// (`tun0`, `tap0`, …). At most 15 bytes: a longer name is refused.
    pub name: String,
}

/// Linux TUN device — raw IPv4/IPv6 packets.
///
/// Dropping it closes the device, as [`L3Device::close`] does.
pub struct Tun {
    dev: Arc<DevFd>,
    name: String,
    handler: Arc<HandlerSlot<L3Handler>>,
    addr: Mutex<IpPrefix>,
    stats: Arc<DeviceStats>,
}

/// Linux TAP device — full Ethernet frames including header.
///
/// Dropping it closes the device, as [`L2Device::close`] does.
pub struct Tap {
    dev: Arc<DevFd>,
    name: String,
    handler: Arc<HandlerSlot<L2Handler>>,
    mac: MacAddr,
    stats: Arc<DeviceStats>,
}

impl core::fmt::Debug for Tun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("tuntap::Tun")
            .field("name", &self.name)
            .finish()
    }
}

impl core::fmt::Debug for Tap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("tuntap::Tap")
            .field("name", &self.name)
            .field("mac", &self.mac)
            .finish()
    }
}

impl Tun {
    /// Open a TUN (L3) device. Requires `CAP_NET_ADMIN` or root.
    pub fn open(cfg: TuntapConfig) -> Result<Tun> {
        let (fd, name) = open_tuntap(&cfg.name, libc::IFF_TUN | libc::IFF_NO_PI)?;
        let dev = Arc::new(DevFd::new(fd)?);
        let handler: Arc<HandlerSlot<L3Handler>> = Arc::new(HandlerSlot::new());
        let stats = Arc::new(DeviceStats::new());

        let dev_t = dev.clone();
        let handler_t = handler.clone();
        let stats_t = stats.clone();
        std::thread::spawn(move || read_loop_l3(dev_t, handler_t, stats_t));

        Ok(Tun {
            dev,
            name,
            handler,
            addr: Mutex::new(IpPrefix::default()),
            stats,
        })
    }

    /// OS interface name (e.g. `tun0`).
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Tap {
    /// Open a TAP (L2) device. Requires `CAP_NET_ADMIN` or root.
    pub fn open(cfg: TuntapConfig) -> Result<Tap> {
        let (fd, name) = open_tuntap(&cfg.name, libc::IFF_TAP | libc::IFF_NO_PI)?;
        let mac = peer_mac(if_hw_addr(&name).ok());
        let dev = Arc::new(DevFd::new(fd)?);
        let handler: Arc<HandlerSlot<L2Handler>> = Arc::new(HandlerSlot::new());
        let stats = Arc::new(DeviceStats::new());

        let dev_t = dev.clone();
        let handler_t = handler.clone();
        let stats_t = stats.clone();
        std::thread::spawn(move || read_loop_l2(dev_t, handler_t, stats_t));

        Ok(Tap {
            dev,
            name,
            handler,
            mac,
            stats,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The MAC address of the kernel's side of the device: the interface the
    /// host stack sees, and a different station from [`L2Device::hw_addr`].
    pub fn kernel_hw_addr(&self) -> Result<MacAddr> {
        if_hw_addr(&self.name)
    }
}

/// The address this end of the TAP answers to.
///
/// A TAP is two stations on one wire: the kernel interface and whoever holds
/// the fd. Reporting the kernel interface's own MAC here would have a
/// userspace stack on the fd claim the host's address — same EUI-64
/// link-local, so IPv6 duplicate address detection fails on one side or the
/// other, and the host sees its own source MAC arrive from the wire. So this
/// side gets a locally administered address of its own, never equal to the
/// kernel's.
fn peer_mac(kernel: Option<MacAddr>) -> MacAddr {
    loop {
        let m = MacAddr::random_local_unicast();
        if Some(m) != kernel {
            return m;
        }
    }
}

// --- L3Device for Tun -----------------------------------------------------

impl L3Device for Tun {
    fn set_handler(&self, h: L3Handler) {
        self.handler.set(h);
    }
    fn send(&self, pkt: &Packet) -> Result<()> {
        match self.dev.write_all(pkt.as_bytes()) {
            Ok(()) => {
                self.stats.record_tx(pkt.len());
                Ok(())
            }
            Err(e) => {
                self.stats.record_error();
                self.stats.record_tx_drop();
                Err(e)
            }
        }
    }
    fn addr(&self) -> IpPrefix {
        *self.addr.lock().unwrap()
    }
    fn set_addr(&self, p: IpPrefix) -> Result<()> {
        *self.addr.lock().unwrap() = p;
        Ok(())
    }
    /// Close the fd, which for a non-persistent device removes the interface,
    /// and stop the reader thread.
    fn close(&self) -> Result<()> {
        if self.dev.close() {
            self.handler.wake();
        }
        Ok(())
    }
    fn stats(&self) -> Option<&DeviceStats> {
        Some(&self.stats)
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        let _ = L3Device::close(self);
    }
}

// --- L2Device for Tap -----------------------------------------------------

impl L2Device for Tap {
    fn set_handler(&self, h: L2Handler) {
        self.handler.set(h);
    }
    fn send(&self, f: &Frame) -> Result<()> {
        match self.dev.write_all(f.as_bytes()) {
            Ok(()) => {
                self.stats.record_tx(f.len());
                Ok(())
            }
            Err(e) => {
                self.stats.record_error();
                self.stats.record_tx_drop();
                Err(e)
            }
        }
    }
    /// This end's address, distinct from the kernel interface's; see
    /// [`Tap::kernel_hw_addr`].
    fn hw_addr(&self) -> MacAddr {
        self.mac
    }
    /// Close the fd, which for a non-persistent device removes the interface,
    /// and stop the reader thread.
    fn close(&self) -> Result<()> {
        if self.dev.close() {
            self.handler.wake();
        }
        Ok(())
    }
    fn stats(&self) -> Option<&DeviceStats> {
        Some(&self.stats)
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        let _ = L2Device::close(self);
    }
}

// --- syscalls --------------------------------------------------------------

fn open_tuntap(name: &str, flags: i32) -> Result<(OwnedFd, String)> {
    // Checked before anything is opened: TUNSETIFF would attach to (or create)
    // whatever a truncated name names.
    let ifname = crate::sys::ifname(name)?;
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
    ifr[..16].copy_from_slice(&ifname);
    let flags_u16 = flags as u16;
    ifr[16..18].copy_from_slice(&flags_u16.to_ne_bytes());

    let r = unsafe { libc::ioctl(owned.as_raw_fd(), libc::TUNSETIFF as _, &mut ifr) };
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

/// The largest frame a TAP hands over: a packet at the largest MTU behind an
/// Ethernet header and the 802.1Q tag the kernel puts back into a frame whose
/// tag was offloaded.
const MAX_TAP_FRAME: usize = MAX_MTU + 14 + 4;

fn read_loop_l3(dev: Arc<DevFd>, handler: Arc<HandlerSlot<L3Handler>>, stats: Arc<DeviceStats>) {
    let mut buf = msg_buffer(MAX_MTU);
    while let Some(n) = read_or_record(&dev, &mut buf, &stats) {
        if !is_whole(n, &buf) {
            // Half a packet is worse than none.
            stats.record_rx_drop();
            continue;
        }
        stats.record_rx(n);
        let Some(h) = handler.wait(dev.closed()) else {
            return;
        };
        deliver(&h, Packet::from_slice(&buf[..n]));
    }
}

fn read_loop_l2(dev: Arc<DevFd>, handler: Arc<HandlerSlot<L2Handler>>, stats: Arc<DeviceStats>) {
    // 65536 bytes, as this was, cut the last few bytes off a frame at the
    // largest MTU, and handed on what was left as if it were the frame.
    let mut buf = msg_buffer(MAX_TAP_FRAME);
    while let Some(n) = read_or_record(&dev, &mut buf, &stats) {
        if n < 14 || !is_whole(n, &buf) {
            stats.record_rx_drop();
            continue;
        }
        stats.record_rx(n);
        let Some(h) = handler.wait(dev.closed()) else {
            return;
        };
        deliver(&h, Frame::from_slice(&buf[..n]));
    }
}

#[cfg(test)]
mod tests {
    // Opening /dev/net/tun requires CAP_NET_ADMIN, so the device itself is not
    // exercised here; the reader and close machinery is, in `reader.rs`.
    use super::*;

    /// A handler that panics costs its message, not the reader thread, in
    /// both TUN and TAP mode.
    #[test]
    fn a_panicking_handler_does_not_stop_the_reader() {
        use std::os::unix::net::UnixDatagram;
        use std::sync::mpsc;
        use std::time::Duration;

        let (boom, next) = ([0xbb_u8; 20], [0x11_u8; 20]);
        let device = || {
            let (dev, peer) = UnixDatagram::pair().unwrap();
            (Arc::new(DevFd::new(OwnedFd::from(dev)).unwrap()), peer)
        };

        let (dev, peer) = device();
        let slot: Arc<HandlerSlot<L3Handler>> = Arc::new(HandlerSlot::new());
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        slot.set(Arc::new(move |p: &Packet| {
            assert_ne!(p.as_bytes(), boom, "handler panics");
            let _ = tx.lock().unwrap().send(p.as_bytes().to_vec());
            Ok(())
        }));
        let (d, s) = (dev.clone(), slot.clone());
        let reader = std::thread::spawn(move || read_loop_l3(d, s, Arc::new(DeviceStats::new())));
        peer.send(&boom).unwrap();
        peer.send(&next).unwrap();
        let got = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("tun reader stopped");
        assert_eq!(got, next);
        dev.close();
        slot.wake();
        reader.join().unwrap();

        let (dev, peer) = device();
        let slot: Arc<HandlerSlot<L2Handler>> = Arc::new(HandlerSlot::new());
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        slot.set(Arc::new(move |f: &Frame| {
            assert_ne!(f.as_bytes(), boom, "handler panics");
            let _ = tx.lock().unwrap().send(f.as_bytes().to_vec());
            Ok(())
        }));
        let (d, s) = (dev.clone(), slot.clone());
        let reader = std::thread::spawn(move || read_loop_l2(d, s, Arc::new(DeviceStats::new())));
        peer.send(&boom).unwrap();
        peer.send(&next).unwrap();
        let got = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("tap reader stopped");
        assert_eq!(got, next);
        dev.close();
        slot.wake();
        reader.join().unwrap();
    }

    #[test]
    fn the_tap_peer_never_shares_the_kernel_mac() {
        let kernel = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
        for _ in 0..1000 {
            let m = peer_mac(Some(kernel));
            assert_ne!(m, kernel);
            // Locally administered unicast.
            assert_eq!(m.0[0] & 0x03, 0x02);
        }
    }
}
