//! Wire constants for OpenVPN.
//!
//! Several of these are not yet referenced because the control/data channel
//! is still a work in progress; allow dead_code until the state machine that
//! consumes them lands.
#![allow(dead_code)]

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

// Wire-level magic numbers.

pub const KEY_EXPANSION_ID: &str = "OpenVPN";
pub const P_KEY_ID_MASK: u8 = 0x07;
pub const P_OPCODE_SHIFT: u8 = 3;

/// Most ACKs one control packet carries (ssl.h CONTROL_SEND_ACK_MAX).
pub const CONTROL_SEND_ACK_MAX: usize = 4;
/// Control packets in flight at once, per key: the send window
/// (ssl_pkt.h TLS_RELIABLE_N_SEND_BUFFERS in OpenVPN 2.6).
pub const TLS_RELIABLE_N_SEND_BUFFERS: usize = 6;
/// How far past the next control packet due one may be and still be
/// taken: the receive window (ssl_pkt.h TLS_RELIABLE_N_REC_BUFFERS).
pub const TLS_RELIABLE_N_REC_BUFFERS: usize = 12;

/// Largest datagram a control packet makes, IP and UDP headers included
/// (OpenVPN 2.6's default `tls-mtu`): small enough to cross a path with a
/// reduced MTU unfragmented. The same bound serves TCP.
pub const TLS_MTU: usize = 1250;
/// The IP and UDP headers counted against [`TLS_MTU`]: IPv6's, the larger
/// (ssl.c calc_control_channel_frame_overhead counts the peer's own
/// family's; over TCP it counts UDP's all the same).
pub const DATAGRAM_OVERHEAD: usize = 40 + 8;
/// A control packet's header at its largest: opcode and key id, session
/// id, ACK count, [`CONTROL_SEND_ACK_MAX`] ACKs and the session id they
/// name, and packet id.
pub const MAX_CONTROL_HEADER_SIZE: usize = 1 + 8 + 1 + 4 * CONTROL_SEND_ACK_MAX + 8 + 4;
/// Most TLS bytes a control packet carries.
pub const CONTROL_CHANNEL_MTU: usize = TLS_MTU - DATAGRAM_OVERHEAD - MAX_CONTROL_HEADER_SIZE;

pub const KEY_METHOD_MASK: u8 = 0x0f;

/// PIA control payload prefix used in `P_CONTROL_HARD_RESET_CLIENT_V2`.
pub const PIA_CONTROL_PREFIX: &str = "53eo0rk92gxic98p1asgl5auh59r1vp4lmry1e3chzi100qntd";

/// Magic ping payload OpenVPN sends to keep connections alive.
pub const OPENVPN_PING: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];
