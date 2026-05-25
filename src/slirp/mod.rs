//! Userspace NAT stack (userspace SLIRP-style routing).
//!
//! [`Stack`] is an [`L3Device`](crate::L3Device): packets handed to it via
//! `send` are translated to real OS-level [`TcpStream`](std::net::TcpStream)
//! / [`UdpSocket`](std::net::UdpSocket) connections. Responses are pushed
//! back through the handler installed with `set_handler`.
//!
//! [`Stack`] is also an [`L3Connector`](crate::L3Connector): each device
//! attached gets its own private NAT namespace, so multiple peers may use
//! overlapping IPs without colliding in the connection-tracking table.
//!
//! # Limitations versus the Go upstream
//!
//! - The virtual TCP listener path (`Stack::listen` + `Listener::accept`)
//!   currently registers ports but cannot accept connections — it needs
//!   the in-tree `vtcp` crate, which isn't ported yet.
//! - SYN-cookie defense (`vtcp::SYNCookies`) is similarly unimplemented.
//! - The internal TCP NAT state machine is a hand-rolled subset of the
//!   features `vtcp` will eventually provide. It handles the
//!   SYN/SYN-ACK/ACK handshake, bulk data in both directions, FIN-initiated
//!   graceful close, and RST. Out-of-order reassembly, SACK, and
//!   congestion control are missing.

mod checksum;
mod icmpv4;
mod icmpv6;
mod ipv6;
mod listener;
mod listener6;
mod packet;
mod tcp_nat;
mod udp;
mod udp6;
mod usernat;

pub use listener::Listener;
pub use listener6::Listener6;
pub use usernat::{NsSide, Stack};
