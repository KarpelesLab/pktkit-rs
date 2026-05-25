//! Wire constants for OpenVPN.

use core::fmt;

/// Encryption cipher algorithm.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum CipherCryptoAlg {
    #[default]
    None = 0,
    Aes = 1,
}

/// Cipher block mode.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum CipherBlockMethod {
    #[default]
    None = 0,
    Cbc = 1,
    Gcm = 2,
}

pub const AES: CipherCryptoAlg = CipherCryptoAlg::Aes;
pub const CBC: CipherBlockMethod = CipherBlockMethod::Cbc;
pub const GCM: CipherBlockMethod = CipherBlockMethod::Gcm;

impl fmt::Display for CipherCryptoAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CipherCryptoAlg::None => f.write_str("none"),
            CipherCryptoAlg::Aes => f.write_str("AES"),
        }
    }
}

impl fmt::Display for CipherBlockMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CipherBlockMethod::None => f.write_str("NONE"),
            CipherBlockMethod::Cbc => f.write_str("CBC"),
            CipherBlockMethod::Gcm => f.write_str("GCM"),
        }
    }
}

// Wire-level magic numbers (matched against the Go const.go).

pub const KEY_EXPANSION_ID: &str = "OpenVPN";
pub const P_KEY_ID_MASK: u8 = 0x07;
pub const P_OPCODE_SHIFT: u8 = 3;

pub const CONTROL_SEND_ACK_MAX: usize = 4;
pub const TLS_RELIABLE_N_SEND_BUFFERS: usize = 4;
pub const TLS_RELIABLE_N_REC_BUFFERS: usize = 8;

pub const PUBLIC_NETWORK_MTU: usize = 1500;
pub const MAX_CONTROL_HEADER_SIZE: usize = 38;
pub const CONTROL_CHANNEL_MTU: usize = PUBLIC_NETWORK_MTU - MAX_CONTROL_HEADER_SIZE;

pub const KEY_METHOD_MASK: u8 = 0x0f;

/// PIA control payload prefix used in `P_CONTROL_HARD_RESET_CLIENT_V2`.
pub const PIA_CONTROL_PREFIX: &str = "53eo0rk92gxic98p1asgl5auh59r1vp4lmry1e3chzi100qntd";

/// Magic ping payload OpenVPN sends to keep connections alive.
pub const OPENVPN_PING: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
    0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];
