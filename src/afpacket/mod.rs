//! `AF_PACKET` sockets: attach to an existing network interface.
//!
//! This is the plainest way to put a real NIC into a topology. Unlike the
//! `tuntap` feature it does not create a new interface — it binds to one that
//! already exists — and unlike the `afxdp` feature it needs no eBPF, no driver
//! support and no special interface configuration. It is the slowest of the
//! three and the one most likely to just work.
//!
//! (Those modules are named without links here because either may be compiled
//! out while this one is not.)
//!
//! ```no_run
//! use pktkit::afpacket::{Config, Socket};
//! use pktkit::{Frame, L2Device};
//! use std::sync::Arc;
//!
//! # fn main() -> std::io::Result<()> {
//! let dev = Socket::open(Config::new("eth0").promiscuous(true))?;
//!
//! dev.set_handler(Arc::new(|f: &Frame| {
//!     println!("{:?} -> {:?}", f.src_mac(), f.dst_mac());
//!     Ok(())
//! }));
//! # Ok(())
//! # }
//! ```
//!
//! # Privileges
//!
//! Opening an `AF_PACKET` socket needs `CAP_NET_RAW`. Without it, [`Socket::open`]
//! fails with `PermissionDenied`.
//!
//! # What you will see
//!
//! A bound socket receives every frame the interface accepts, including traffic
//! for the host itself, and — with [`Config::promiscuous`] set — traffic
//! addressed to other stations. Frames the host *sends* are also delivered back
//! unless [`Config::inbound_only`] is set. Frames written with
//! [`send`](L2Device::send) go out the interface as-is, so the Ethernet header
//! is yours to fill in.
//!
//! Received frames carry their 802.1Q/802.1ad tag as they had it on the wire,
//! even when the NIC or kernel took it out before the socket saw the frame.
//!
//! # Platform support
//!
//! Linux only. On other platforms the type is still present so cross-platform
//! code compiles, but [`Socket::open`] returns `ErrorKind::Unsupported`.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Socket;

#[cfg(not(target_os = "linux"))]
mod unsupported;
#[cfg(not(target_os = "linux"))]
pub use unsupported::Socket;

use std::time::Duration;

/// How to open an [`Socket`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// Interface to bind to, e.g. `eth0`. Required.
    pub interface: String,
    /// Put the interface into promiscuous mode, so frames addressed to other
    /// stations are delivered too. Reverted when the socket is closed.
    pub promiscuous: bool,
    /// Deliver only frames the interface received, hiding those the host sent.
    /// Off by default, matching what `tcpdump` shows.
    pub inbound_only: bool,
    /// Kernel receive buffer in bytes; 0 leaves the system default. Raising
    /// this is the first thing to try when the drop counter climbs under load.
    pub recv_buffer: usize,
    /// How long a blocked read waits before checking whether the socket has
    /// been closed. Lower is a more responsive [`close`](L2Device::close),
    /// higher is fewer wakeups on an idle link.
    pub poll_interval: Duration,
}

setters! {
    Config {
        into interface: String;
        set promiscuous: bool;
        set inbound_only: bool;
        set recv_buffer: usize;
        set poll_interval: Duration;
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
            promiscuous: false,
            inbound_only: false,
            recv_buffer: 0,
            poll_interval: Duration::from_millis(250),
        }
    }
}

#[allow(unused_imports)]
use crate::L2Device;

/// Room the reader leaves in front of each received frame, so an 802.1Q tag
/// the kernel took out can be put back without moving the payload.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const VLAN_TAG_LEN: usize = 4;

/// Put back the 802.1Q tag the kernel stripped from a received frame.
///
/// The kernel takes the tag out of the frame before `AF_PACKET` sees it (NIC
/// VLAN offload, or `skb_vlan_untag` in software) and reports it only in
/// `PACKET_AUXDATA`, as libpcap relies on. `buf` holds the frame at
/// `buf[VLAN_TAG_LEN..VLAN_TAG_LEN + len]`; the MAC addresses are moved down
/// into the headroom and the tag written after them. Returns the range of
/// `buf` that holds the frame, tagged or not.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn reinsert_vlan(buf: &mut [u8], len: usize, tag: Option<(u16, u16)>) -> std::ops::Range<usize> {
    let frame = VLAN_TAG_LEN..VLAN_TAG_LEN + len;
    let Some((tpid, tci)) = tag else {
        return frame;
    };
    if len < 12 {
        return frame;
    }
    buf.copy_within(VLAN_TAG_LEN..VLAN_TAG_LEN + 12, 0);
    buf[12..14].copy_from_slice(&tpid.to_be_bytes());
    buf[14..16].copy_from_slice(&tci.to_be_bytes());
    0..VLAN_TAG_LEN + len
}

/// The tag `PACKET_AUXDATA` reports, as (TPID, TCI), if the frame had one.
///
/// Mirrors libpcap: kernels before 3.0 have no `TP_STATUS_VLAN_VALID` and
/// flag a tag only by a non-zero TCI, and before 3.14 no TPID either, which
/// then can only have been 802.1Q.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn aux_vlan_tag(status: u32, tci: u16, tpid: u16) -> Option<(u16, u16)> {
    const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
    const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;
    const ETH_P_8021Q: u16 = 0x8100;
    if tci == 0 && status & TP_STATUS_VLAN_VALID == 0 {
        return None;
    }
    let tpid = if tpid != 0 && status & TP_STATUS_VLAN_TPID_VALID != 0 {
        tpid
    } else {
        ETH_P_8021Q
    };
    Some((tpid, tci))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aux_vlan_tag_validity() {
        assert_eq!(aux_vlan_tag(0, 0, 0), None);
        // VLAN 0 (priority tag) is only recognisable by the status bit.
        assert_eq!(aux_vlan_tag(1 << 4, 0, 0), Some((0x8100, 0)));
        // Old kernel: no status bits, a non-zero TCI is the tag.
        assert_eq!(aux_vlan_tag(0, 5, 0), Some((0x8100, 5)));
        // 802.1ad outer tag, TPID reported.
        assert_eq!(aux_vlan_tag(1 << 4 | 1 << 6, 7, 0x88a8), Some((0x88a8, 7)));
        // A TPID without its valid bit is not trusted.
        assert_eq!(aux_vlan_tag(1 << 4, 7, 0x88a8), Some((0x8100, 7)));
    }

    fn received(frame: &[u8]) -> Vec<u8> {
        let mut buf = vec![0xee; VLAN_TAG_LEN];
        buf.extend_from_slice(frame);
        buf
    }

    #[test]
    fn untagged_frame_left_in_place() {
        let f: Vec<u8> = (0..20).collect();
        let mut buf = received(&f);
        let r = reinsert_vlan(&mut buf, f.len(), None);
        assert_eq!(&buf[r], &f[..]);
    }

    #[test]
    fn stripped_tag_is_reinserted_after_the_macs() {
        // dst, src, then EtherType IPv4 and a payload byte.
        let mut f = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        f.extend_from_slice(&[0x08, 0x00, 0x45]);
        let mut buf = received(&f);
        let r = reinsert_vlan(&mut buf, f.len(), Some((0x8100, 0x2064)));
        assert_eq!(
            &buf[r],
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x81, 0x00, 0x20, 0x64, 0x08, 0x00, 0x45
            ]
        );
    }

    #[test]
    fn runt_frame_not_tagged() {
        let f = [1u8, 2, 3];
        let mut buf = received(&f);
        let r = reinsert_vlan(&mut buf, f.len(), Some((0x8100, 1)));
        assert_eq!(&buf[r], &f[..]);
    }
}
