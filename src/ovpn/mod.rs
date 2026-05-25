//! OpenVPN server.
//!
//! This module ports the Go `ovpn` subpackage. The control channel runs a
//! `rustls::ServerConnection` *inside* OpenVPN's own reliable transport (no TCP
//! socket under the TLS); the data channel uses RustCrypto AES-GCM / AES-CBC.
//!
//! What works:
//! - [`Options`] parse / `Display` (`V4,dev-type tun,…`).
//! - TLS 1.2 control channel over the reliable layer (rustls in buffered mode).
//! - Key-method 2 key exchange and TLS-1.0 PRF key derivation.
//! - Data channel: AES-256/128-GCM (AEAD) and AES-CBC + HMAC.
//! - Replay window, PKCS#7 padding, control-packet framing.
//! - UDP and TCP [`Server`]; per-peer [`Adapter`] over an `L3Connector` (tun)
//!   or `L2Connector` (tap).
//!
//! Control-packet retransmission is driven by [`Peer::tick`] (wired into the
//! [`Server`]'s maintenance loop), and peer-info / repeated `PUSH_REQUEST`
//! control messages are handled after authentication.
//!
//! TODO (tracked under `// TODO(ovpn): …` markers):
//! - tls-crypt / tls-auth HMAC wrapping of control packets.
//! - Full PUSH_REPLY option negotiation beyond ifconfig/ping/comp-lzo.
//! - Idle-peer reaping / keepalive ping generation.

mod adapter;
mod addr;
mod consts;
mod data;
mod keys;
mod opcode;
mod options;
mod packet_ctrl;
mod peer;
mod pkcs5;
mod prf;
mod reliable;
mod server;
#[cfg(test)]
mod tests;
mod window;

pub use adapter::{Adapter, AdapterConfig, Connector};
pub use addr::{PeerKey, Transport};
pub use consts::{CipherBlockMethod, CipherCryptoAlg, AES, CBC, GCM};
pub use opcode::Opcode;
pub use options::Options;
pub use peer::{AuthInfo, OnAuth, Peer, PeerConfig, PeerOutput};
pub use server::{
    crypto_provider, install_crypto_provider, OnConnect, OnData, OnDisconnect, Server, ServerConfig,
};
