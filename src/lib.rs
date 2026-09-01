//! Zero-copy L2/L3 packet handling toolkit.
//!
//! `pktkit` provides primitives for building virtual network topologies:
//! devices, hubs, adapters, NAT, and tunnels that move Ethernet frames and IP
//! packets without copying buffers on the hot path.
//!
//! See the crate-level [README](https://github.com/KarpelesLab/pktkit-rs) for
//! a tour of what each Cargo feature adds. The default build ships only the
//! core types — everything else is opt-in.
//!
//! # Core
//!
//! - [`Frame`] is an Ethernet frame; [`Packet`] is an IP packet. Both are
//!   `#[repr(transparent)]` newtypes over `[u8]` so `&Frame` is the same shape
//!   as `&[u8]` and accessors are free.
//! - [`L2Device`] and [`L3Device`] are object-safe traits for anything that
//!   sends/receives frames or packets. Forwarding is a synchronous callback;
//!   the buffer is only valid for the duration of the call.
//! - [`L2Hub`] is a MAC-learning switch with 5-minute aging. [`L3Hub`] is a
//!   prefix-routing hub with a default route fallback.
//! - [`PipeL2`] and [`PipeL3`] are in-memory devices for tests and for wiring
//!   subpackages together.
//! - [`connect_l2`] and [`connect_l3`] wire two devices point-to-point.
//! - [`serve`] runs an accept loop, joining each incoming L2 device into a
//!   connector.
//!
//! # Reading and writing wire formats
//!
//! [`Frame`] covers L2 and [`Packet`] covers L3; the [`l4`] module adds the
//! transport layer ([`TcpSegment`], [`UdpDatagram`], [`IcmpMessage`]) and the
//! [`FiveTuple`] that identifies a flow. Get an L4 view straight from a packet
//! with [`Packet::tcp`], [`Packet::udp`] or [`Packet::icmp`].
//!
//! Going the other way, [`build`] constructs well-formed packets with lengths
//! and checksums filled in, [`icmp`] generates the error messages a forwarder
//! owes to senders, and [`fragment`] splits a datagram that is too large for
//! the next hop.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// A low-level networking crate carries inherently rich callback/handler types
// and a few wide protocol constructors; and several modules mirror the Go
// upstream's `pkg/pkg.rs` layout. These clippy lints fight that on purpose, so
// we opt out crate-wide rather than scatter per-item allows.
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::module_inception)]

// --- Core (always compiled) -------------------------------------------------

mod accept;
pub mod build;
mod checksum;
mod connect;
mod ethertype;
pub mod fragment;
mod frame;
pub mod icmp;
mod iface;
mod ip;
mod l2hub;
mod l3hub;
pub mod l4;
mod mac;
mod packet;
mod pipe;
mod pool;
mod protocol;
mod rand;
mod stats;
#[cfg(feature = "wg")]
mod zeroize;

pub use accept::{
    Cleanup, Done, DoneSignal, L2Acceptor, L2AcceptorWithDone, L2Connector, L3Connector, serve,
    serve_with_done,
};
pub use checksum::{
    checksum, combine_checksums, incremental_update, pseudo_header_checksum, transport_checksum,
};
pub use connect::{connect_l2, connect_l3};
pub use ethertype::EtherType;
pub use frame::{Frame, build_frame};
pub use iface::{Handler, L2Device, L2Handler, L3Device, L3Handler};
pub use ip::IpPrefix;
pub use l2hub::{L2Hub, L2HubHandle, PortMode, VlanSet};
pub use l3hub::{L3Hub, L3HubHandle};
pub use l4::{FiveTuple, IcmpMessage, TcpFlags, TcpSegment, UdpDatagram};
pub use mac::{BROADCAST_MAC, MacAddr};
pub use packet::Packet;
pub use pipe::{PipeL2, PipeL3};
pub use pool::{BufferPool, DEFAULT_MTU};
pub use protocol::Protocol;
pub use stats::{DeviceStats, HubCounters, HubStats, Stats};

/// Crate-wide `Result` alias.
pub type Result<T> = std::io::Result<T>;

// Linux syscall helpers, compiled only for the features that issue them.
#[cfg(all(target_os = "linux", any(feature = "tuntap", feature = "afpacket")))]
mod sys;

// Parser entry points collected for fuzzing. Not an API; see `src/fuzz.rs`.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz;

// --- Feature modules --------------------------------------------------------

#[cfg(feature = "l2adapter")]
#[cfg_attr(docsrs, doc(cfg(feature = "l2adapter")))]
pub mod arp;

#[cfg(feature = "l2adapter")]
#[cfg_attr(docsrs, doc(cfg(feature = "l2adapter")))]
pub mod ndp;

#[cfg(feature = "l2adapter")]
#[cfg_attr(docsrs, doc(cfg(feature = "l2adapter")))]
mod l2adapter;

#[cfg(feature = "l2adapter")]
#[cfg_attr(docsrs, doc(cfg(feature = "l2adapter")))]
pub use l2adapter::{L2Adapter, L2AdapterConfig};

#[cfg(feature = "dhcp")]
#[cfg_attr(docsrs, doc(cfg(feature = "dhcp")))]
pub mod dhcp;

#[cfg(feature = "afpacket")]
#[cfg_attr(docsrs, doc(cfg(feature = "afpacket")))]
pub mod afpacket;

#[cfg(feature = "impair")]
#[cfg_attr(docsrs, doc(cfg(feature = "impair")))]
pub mod impair;

#[cfg(feature = "pcap")]
#[cfg_attr(docsrs, doc(cfg(feature = "pcap")))]
pub mod pcap;

#[cfg(feature = "qemu")]
#[cfg_attr(docsrs, doc(cfg(feature = "qemu")))]
pub mod qemu;

#[cfg(feature = "tuntap")]
#[cfg_attr(docsrs, doc(cfg(feature = "tuntap")))]
pub mod tuntap;

// XDP and AF_XDP are Linux kernel interfaces with no analogue elsewhere, and
// unlike `tuntap` or `afpacket` there is no meaningful stub to offer: the API
// is built around eBPF programs, maps and UMEM rings. The modules are simply
// absent off Linux, so that enabling `full` -- which includes them -- still
// builds everywhere.
#[cfg(all(feature = "xdp", target_os = "linux"))]
#[cfg_attr(docsrs, doc(cfg(feature = "xdp")))]
pub mod xdp;

#[cfg(all(feature = "afxdp", target_os = "linux"))]
#[cfg_attr(docsrs, doc(cfg(feature = "afxdp")))]
pub mod afxdp;

#[cfg(feature = "vtcp")]
#[cfg_attr(docsrs, doc(cfg(feature = "vtcp")))]
pub mod vtcp;

#[cfg(feature = "slirp")]
#[cfg_attr(docsrs, doc(cfg(feature = "slirp")))]
pub mod slirp;

#[cfg(feature = "vclient")]
#[cfg_attr(docsrs, doc(cfg(feature = "vclient")))]
pub mod vclient;

#[cfg(feature = "nat")]
#[cfg_attr(docsrs, doc(cfg(feature = "nat")))]
pub mod nat;

#[cfg(feature = "wg")]
#[cfg_attr(docsrs, doc(cfg(feature = "wg")))]
pub mod wg;

#[cfg(feature = "ovpn")]
#[cfg_attr(docsrs, doc(cfg(feature = "ovpn")))]
pub mod ovpn;
