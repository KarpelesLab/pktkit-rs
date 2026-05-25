//! OpenVPN server (work in progress).
//!
//! This module ports the Go `ovpn` subpackage. The shape is in place —
//! [`Options`] parses and renders the OpenVPN options string, and the wire
//! types and constants are mirrored from the Go upstream — but the full
//! TLS-control + AES-CBC/GCM data-channel implementation is not yet
//! complete in this Rust port.
//!
//! What works:
//! - `Options` parse / `Display` (`V4,dev-type tun,…`)
//! - `Opcode` and `CipherCrypto` / `CipherBlockMethod` enums
//!
//! TODO (tracked under `// TODO(ovpn): …` markers):
//! - `Peer` connection state machine
//! - Control-channel TLS 1.2 (currently hand-rolled — see notes in CLAUDE.md)
//! - Data-channel AES-CBC and AES-GCM
//! - PRF 1.2 key derivation
//! - Replay window
//! - UDP and TCP servers
//! - L3/L2 adapter integration

mod consts;
mod options;
mod opcode;

pub use consts::{CipherBlockMethod, CipherCryptoAlg, AES, CBC, GCM};
pub use opcode::Opcode;
pub use options::Options;
