//! High-level virtual network client.
//!
//! [`Client`] implements [`L3Device`](crate::L3Device), so it plugs into a
//! `slirp::Stack`, a `wg::Adapter`, or any [`L3Connector`](crate::L3Connector).
//! Layered on top of [`vtcp`](crate::vtcp), it provides:
//!
//! - [`Client::dial_tcp`] → a blocking [`TcpConn`] (`std::io::Read` + `Write`),
//!   driven by a per-client TCP engine with a tick thread.
//! - [`Client::listen_tcp`] → a [`Listener`] whose [`accept`](Listener::accept)
//!   yields inbound [`TcpConn`]s (server side).
//! - [`Client::dial_udp`] → a connected [`UdpConn`] over the virtual network.
//! - [`Resolver`]: an RFC 1035 DNS resolver (A / AAAA), and [`Client::resolve`].
//! - A hand-rolled HTTP/1.1 client ([`Request`] / [`Response`],
//!   [`Client::http_get`]) — no third-party HTTP crate.
//!
//! # wasm32
//!
//! Without threads nothing may block, so on `wasm32` the handles never wait
//! (they return [`WouldBlock`](std::io::ErrorKind::WouldBlock) instead),
//! connections are opened with [`Client::dial_tcp_nonblocking`], and the
//! caller drives the TCP timers with [`Client::tick`]. The resolver (host UDP
//! sockets) and the HTTP client (built on blocking reads) are not available
//! there.

mod client;
pub(crate) mod dns;
#[cfg(not(target_family = "wasm"))]
mod http;
mod tcp;
mod udp;

pub use client::{Client, ClientConfig};
#[cfg(not(target_family = "wasm"))]
pub use dns::{RecordType, Resolver, ResolverConfig};
#[cfg(not(target_family = "wasm"))]
pub use http::{DEFAULT_HTTP_TIMEOUT, DEFAULT_MAX_RESPONSE_BODY, Request, Response};
pub use tcp::{Listener, TcpConn};
pub use udp::UdpConn;

/// Identification for the IPv4 datagrams the client sends. They go out
/// without DF, so they may be fragmented on the way, and the ID is what
/// tells one datagram's fragments from another's: it must differ between
/// datagrams of one source, destination and protocol in flight together
/// (RFC 6864 §4.1). One counter for every client covers that.
fn next_ipv4_id() -> u16 {
    static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
