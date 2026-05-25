//! Packet-level network address translation.
//!
//! Two top-level types:
//!
//! - [`Nat`] — IPv4 NAT between an inside (private) and outside (public) L3
//!   network. Implements both [`L3Device`](crate::L3Device) (as the outside
//!   edge) and [`L3Connector`](crate::L3Connector) (for namespace-isolated
//!   inside attachments).
//! - [`Nat64`] — RFC 6146 stateful translation between an IPv6 inside and an
//!   IPv4 outside, using IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`).
//!
//! Optional pieces:
//!
//! - [`Defragger`] — IPv4 reassembly, enabled per-NAT via
//!   [`Nat::enable_defrag`].
//! - ALGs: [`FtpHelper`], [`TftpHelper`], [`IrcHelper`], plus stubs for SIP,
//!   H.323, PPTP (see TODO markers).
//! - [`UPnPHelper`] / [`UPnPConfig`] — scaffolding; the SOAP server depends
//!   on the virtual TCP feature and is not yet wired up here.

mod alg_ftp;
mod alg_h323;
mod alg_irc;
mod alg_pptp;
mod alg_sip;
mod alg_tftp;
mod defrag;
mod helper;
mod nat;
mod nat64;
mod upnp;

pub use alg_ftp::FtpHelper;
pub use alg_h323::H323Helper;
pub use alg_irc::IrcHelper;
pub use alg_pptp::PptpHelper;
pub use alg_sip::SipHelper;
pub use alg_tftp::TftpHelper;
pub use defrag::Defragger;
pub use helper::{Expectation, Helper, LocalHelper, NatMapping, PacketHelper, PortForward};
pub use nat::Nat;
pub use nat64::Nat64;
pub use upnp::{UPnPConfig, UPnPHelper};
