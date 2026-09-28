//! WireGuard tunnel: Noise IKpsk2 handshake + ChaCha20-Poly1305 transport.
//!
//! This module is a Rust port of the Go `wg` package. Use [`Adapter`] for the
//! one-line setup that bridges WireGuard peers into a pktkit
//! [`L3Connector`](crate::L3Connector). For lower-level control, use
//! [`Handler`] directly (one identity) or [`MultiHandler`] (multiple
//! identities sharing a single UDP socket).
//!
//! # Wire format
//!
//! The packet types are exactly those in the WireGuard whitepaper:
//!
//! | Type | Size | Direction               |
//! |------|------|-------------------------|
//! |   1  | 148  | initiator → responder   |
//! |   2  |  92  | responder → initiator   |
//! |   3  |  64  | responder → initiator   |
//! |   4  | var  | both                    |
//!
//! Cookie replies (type 3) implement the DoS-mitigation path: under load the
//! responder validates MAC2 and answers a missing/invalid one with an
//! address-bound cookie reply; the initiator decrypts it and retries with a
//! valid MAC2.
//!
//! # Crypto
//!
//! All primitives come from [`purecrypto`](https://crates.io/crates/purecrypto):
//!
//! - X25519 (`purecrypto::ec::x25519`).
//! - ChaCha20-Poly1305 and XChaCha20-Poly1305 (`purecrypto::cipher`).
//! - BLAKE2s-128 / BLAKE2s-256 and HMAC-BLAKE2s (`purecrypto::hash`), from
//!   which the whitepaper's HKDF is built.
//!
//! The `crypto` submodule wraps these into the KDF/AEAD helpers the handshake
//! and transport layers use.

#[cfg(not(target_family = "wasm"))]
mod adapter;
mod constants;
mod cookie;
mod crypto;
mod handler;
mod handshake;
mod multihandler;
mod ratelimiter;
mod replay;
#[cfg(not(target_family = "wasm"))]
mod server;
mod time;
mod timers;
mod transport;

#[cfg(not(target_family = "wasm"))]
pub use adapter::{Adapter, AdapterConfig};
pub use constants::{NoisePresharedKey, NoisePrivateKey, NoisePublicKey};
pub use crypto::{generate_preshared_key, generate_private_key};
pub use handler::{Config, Handler, PacketResult, PacketType, PeerInfo, UnknownPeerFn};
pub use multihandler::{MultiHandler, MultiPacketResult};
#[cfg(not(target_family = "wasm"))]
pub use server::{OnPacketFn, OnPeerConnectedFn, Server, ServerConfig};
pub use timers::TimerAction;
