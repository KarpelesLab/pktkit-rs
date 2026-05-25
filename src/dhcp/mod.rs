//! DHCP wire codec, client state machine, and server.
//!
//! - [`wire`] holds option codes, message types, and the parser/builder.
//! - [`Client`] is a minimal RFC 2131 client driven by [`Client::handle_packet`]
//!   for inbound DHCP and [`Client::start`] / [`Client::stop`] for lifecycle.
//! - [`Server`] is a full DHCP server (DISCOVER / OFFER / REQUEST / ACK /
//!   RELEASE / DECLINE / INFORM) and ships as an `L2Device` so you can plug
//!   it into an [`L2Hub`](crate::L2Hub).

pub mod wire;

mod client;
mod server;

pub use client::{Client, ClientConfig, ClientTransport};
pub use server::{Server, ServerConfig};
