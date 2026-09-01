//! Linux XDP: eBPF programs attached to the receive path of a network device.
//!
//! This is the kernel-side half of packet capture. It loads a program, attaches
//! it to an interface, and manages the maps the program reads. The userspace
//! half — an `AF_XDP` socket that receives the redirected frames — lives in
//! the `afxdp` module (feature `afxdp`), which builds on this one.
//!
//! # Capturing specific addresses
//!
//! The program this crate ships redirects only traffic belonging to a set of IP
//! prefixes and passes everything else to the host stack, so attaching to a
//! live NIC does not black-hole it:
//!
//! ```no_run
//! use pktkit::xdp::{Capture, CaptureConfig, Mode};
//! use pktkit::IpPrefix;
//! use std::net::Ipv4Addr;
//!
//! # fn main() -> std::io::Result<()> {
//! let cap = Capture::attach(2, CaptureConfig::default(), Mode::AUTO)?;
//! cap.add(IpPrefix::new(Ipv4Addr::new(10, 0, 0, 7).into(), 32))?;
//! // Everything else on the interface still reaches the kernel.
//! # Ok(())
//! # }
//! ```
//!
//! The set lives in `LPM_TRIE` maps, so adds and removes take effect without
//! reloading the program, and matching is longest-prefix — a `/24` captures the
//! whole subnet.
//!
//! A capture can never widen into the whole interface: `add` refuses a `/0`
//! outright, refuses anything under [`CaptureConfig::min_prefix_v4`] /
//! [`CaptureConfig::min_prefix_v6`], and refuses any addition that would leave
//! the set covering an entire address family. See the [`capture`] module docs.
//!
//! # Attach modes
//!
//! [`Mode::DRIVER`] runs the program in the NIC driver's NAPI poll, before an
//! `sk_buff` exists; it is both the fast path and a precondition for AF_XDP
//! zero-copy. [`Mode::GENERIC`] works anywhere but always copies.
//! [`Mode::AUTO`] tries the former and falls back to the latter, and
//! [`Link::mode`] reports which one took effect.
//!
//! # Requirements
//!
//! Loading and attaching needs `CAP_BPF` + `CAP_NET_ADMIN` (or root) and a real
//! interface. The pure pieces — instruction encoding, jump resolution, program
//! codegen, map key layout, netlink message layout — are unit-tested; paths
//! that require the kernel are marked `TODO(xdp)`.

pub mod capture;
mod netlink;
mod prog;
mod sys;

pub mod insn;
pub mod map;

pub use capture::{
    Capture, CaptureConfig, CaptureMaps, MatchField, build_program, solicited_node_multicast,
};
pub use insn::{Asm, Insn, Label};
pub use map::{LpmKey, Map, MapType, UpdateFlags, lpm_key, set_socket_raw};
pub use prog::{Action, Link, Mode, Program, detach};
