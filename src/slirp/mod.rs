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
//! - The virtual TCP listener path (`Stack::listen` + `Listener::accept`) is
//!   wired through the in-tree `vtcp` engine: inbound SYNs destined for a
//!   registered listener mint a server-side [`vtcp::Conn`](crate::vtcp::Conn)
//!   and, on ESTABLISHED, surface a [`TcpStream`] to the application.
//! - SYN-cookie defense (`vtcp::SynCookies`) for the accept-queue overflow
//!   case is not yet wired in — see `TODO(slirp)` in `usernat`.
//! - The *outbound* (virtual→real) NAT path is also wired through the in-tree
//!   `vtcp` engine (see `tcp_out`): a virtual client's SYN passively opens a
//!   server-side [`vtcp::Conn`](crate::vtcp::Conn) terminating the virtual
//!   side, while a real OS [`TcpStream`](std::net::TcpStream) is dialed to the
//!   destination and bytes are pumped both ways. This inherits out-of-order
//!   reassembly, SACK, window scaling, and congestion control on the virtual
//!   side.

mod checksum;
mod icmpv4;
mod icmpv6;
mod ipv6;
mod listener;
mod listener6;
mod packet;
mod tcp_out;
mod tcp_stream;
mod udp;
mod udp6;
mod usernat;

pub use listener::Listener;
pub use listener6::Listener6;
pub use tcp_stream::TcpStream;
pub use usernat::{NsSide, Stack};
