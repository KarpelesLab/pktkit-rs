//! High-level virtual network client (work in progress).
//!
//! The Go upstream layers `Dial`, `Listen`, `net.Conn`, DNS, and a minimal
//! `http.Client` on top of [`vtcp`](crate::vtcp). This port lays out the
//! shape and exposes the public types so dependent crates compile; the
//! actual TCP layer integration lands once [`vtcp`](crate::vtcp)'s API
//! stabilises.
//!
//! Anchors that are in place:
//! - [`Client`] type and [`ClientConfig`] builder
//! - DNS resolver scaffolding ([`Resolver`]) — query types parse, sending
//!   is gated behind the vtcp wiring
//! - Public `dial` / `listen` entry points (return `Unsupported` for now)
//!
//! TODO (tracked under `// TODO(vclient): …` markers):
//! - Bind `vtcp::Conn` for the TCP path
//! - UDP socket abstraction
//! - HTTP/1.1 client (hand-rolled — no third-party HTTP crate)

mod client;
mod dns;
mod http;
mod tcp;

pub use client::{Client, ClientConfig};
pub use dns::{RecordType, Resolver, ResolverConfig};
pub use http::{Request, Response};
pub use tcp::TcpConn;
