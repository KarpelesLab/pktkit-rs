//! High-level virtual network client.
//!
//! [`Client`] implements [`L3Device`](crate::L3Device), so it plugs into a
//! `slirp::Stack`, a `wg::Adapter`, or any [`L3Connector`](crate::L3Connector).
//! Layered on top of [`vtcp`](crate::vtcp), it provides:
//!
//! - [`Client::dial_tcp`] → a blocking [`TcpConn`] (`std::io::Read` + `Write`),
//!   driven by a per-client TCP engine with a tick thread.
//! - [`Client::dial_udp`] → a connected [`UdpConn`] over the virtual network.
//! - [`Resolver`]: an RFC 1035 DNS resolver (A / AAAA), and [`Client::resolve`].
//! - A hand-rolled HTTP/1.1 client ([`Request`] / [`Response`],
//!   [`Client::http_get`]) — no third-party HTTP crate.

mod client;
mod dns;
mod http;
mod tcp;
mod udp;

pub use client::{Client, ClientConfig};
pub use dns::{RecordType, Resolver, ResolverConfig};
pub use http::{Request, Response};
pub use tcp::TcpConn;
pub use udp::UdpConn;
