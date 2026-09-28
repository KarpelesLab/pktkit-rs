//! Packet-level network address translation.
//!
//! Two top-level types:
//!
//! - [`Nat`] — IPv4 NAT between an inside (private) and outside (public) L3
//!   network. Implements both [`L3Device`](crate::L3Device) (as the outside
//!   edge) and [`L3Connector`](crate::L3Connector) (for namespace-isolated
//!   inside attachments).
//! - [`Nat64`] — RFC 6146 stateful translation between an IPv6 inside and an
//!   IPv4 outside, with IPv4 hosts mapped into a NAT64 prefix (RFC 6052).
//!
//! Optional pieces, each switched on per NAT:
//!
//! - IPv4 reassembly, via [`Nat::enable_defrag`].
//! - ALGs, registered with [`Nat::add_packet_helper`]: [`FtpHelper`],
//!   [`TftpHelper`], [`IrcHelper`], [`SipHelper`], [`H323Helper`],
//!   [`PptpHelper`].
//! - Static port forwards ([`PortForward`], [`Nat::add_port_forward`]).
//! - [`UPnPHelper`] / [`UPnPConfig`], registered with
//!   [`Nat::add_local_helper`]: SSDP discovery plus the IGD SOAP control
//!   port, through which inside hosts add their own port forwards. The
//!   control port is terminated with the in-tree `vtcp` engine and a minimal
//!   one-shot HTTP/1.1 server; pipelined / chunked requests are not handled
//!   (see `TODO(nat)` in `upnp.rs`).

mod alg_ftp;
mod alg_h323;
mod alg_irc;
mod alg_pptp;
mod alg_sip;
mod alg_tftp;
pub(crate) mod defrag;
mod frag;
mod helper;
mod l4;
mod nat;
mod nat64;
mod ports;
mod track;
mod upnp;

pub use alg_ftp::FtpHelper;
pub use alg_h323::H323Helper;
pub use alg_irc::IrcHelper;
pub use alg_pptp::PptpHelper;
pub use alg_sip::SipHelper;
pub use alg_tftp::TftpHelper;
pub use helper::PortForward;
pub use nat::Nat;
pub use nat64::Nat64;
pub use track::NatLimits;
pub use upnp::{UPnPConfig, UPnPHelper};
