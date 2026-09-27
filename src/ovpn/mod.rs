//! OpenVPN server.
//!
//! The control channel runs a purecrypto TLS server connection *inside*
//! OpenVPN's own reliable transport (no TCP socket under the TLS); the data
//! channel uses purecrypto's AES-GCM / AES-CBC + HMAC.
//!
//! What works:
//! - [`Options`] parse / `Display` (`V4,dev-type tun,…`).
//! - TLS control channel over the reliable layer, with sessions routed by
//!   session id as in OpenVPN's `ssl.c`.
//! - Key-method 2 key exchange and TLS-1.0 PRF key derivation.
//! - Renegotiation (soft reset) from either side, with the previous key's
//!   data channel kept for the transition window.
//! - Data channel: AES-256/128-GCM (AEAD) and AES-CBC + HMAC.
//! - Replay window, PKCS#7 padding, control-packet framing.
//! - UDP and TCP [`Server`]; per-peer [`Adapter`] over an `L3Connector` (tun)
//!   or `L2Connector` (tap).
//!
//! Timers -- control-packet retransmission, handshake window, keepalive,
//! renegotiation -- are driven by [`Peer::tick`] (wired into the
//! [`Server`]'s maintenance loop), and peer-info / repeated `PUSH_REQUEST`
//! control messages are handled after authentication.
//!
//! Not implemented:
//! - tls-crypt / tls-auth HMAC wrapping of control packets. Without it
//!   anyone can send a hard reset from a client's address; see
//!   [`Peer`] for how such resets are kept from disturbing a session.
//! - PUSH_REPLY options beyond ifconfig, ping / ping-restart, cipher and
//!   comp-lzo (no routes, DNS, or `topology subnet`).
//! - P_DATA_V2 / peer-id, and the CHACHA20-POLY1305 data cipher.

#[cfg(not(target_family = "wasm"))]
mod adapter;
mod addr;
mod consts;
#[cfg(not(target_family = "wasm"))]
mod cookie;
mod data;
mod keys;
mod opcode;
mod options;
pub(crate) mod packet_ctrl;
mod peer;
mod pkcs5;
mod prf;
mod reliable;
#[cfg(not(target_family = "wasm"))]
mod server;
#[cfg(test)]
mod tests;
mod window;

#[cfg(not(target_family = "wasm"))]
pub use adapter::{Adapter, AdapterConfig, Connector};
pub use addr::{PeerKey, Transport};
pub use consts::{AES, CBC, CipherBlockMethod, CipherCryptoAlg, GCM};
pub use opcode::Opcode;
pub use options::Options;
pub use peer::{AuthInfo, AuthRequest, OnAuth, Peer, PeerConfig, PeerOutput, PeerTimers};
#[cfg(not(target_family = "wasm"))]
pub use server::{OnConnect, OnData, OnDisconnect, Server, ServerConfig};
