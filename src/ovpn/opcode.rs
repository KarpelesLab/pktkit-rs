//! OpenVPN packet opcodes (the high 5 bits of the first byte).

use core::fmt;

/// OpenVPN packet opcodes (RFC-equivalent: see openvpn-protocol.txt).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Opcode(pub u8);

impl Opcode {
    pub const CONTROL_HARD_RESET_CLIENT_V1: Opcode = Opcode(1);
    pub const CONTROL_HARD_RESET_SERVER_V1: Opcode = Opcode(2);
    pub const CONTROL_SOFT_RESET_V1: Opcode = Opcode(3);
    pub const CONTROL_V1: Opcode = Opcode(4);
    pub const ACK_V1: Opcode = Opcode(5);
    pub const DATA_V1: Opcode = Opcode(6);
    pub const CONTROL_HARD_RESET_CLIENT_V2: Opcode = Opcode(7);
    pub const CONTROL_HARD_RESET_SERVER_V2: Opcode = Opcode(8);
    pub const DATA_V2: Opcode = Opcode(9);

    /// The opcode is encoded in the high 5 bits of the first packet byte.
    /// The low 3 bits hold the key ID.
    #[inline]
    pub fn from_byte(b: u8) -> (Opcode, u8) {
        (Opcode(b >> 3), b & 0x07)
    }

    /// Pack an opcode and key ID into a single byte.
    #[inline]
    pub fn to_byte(self, key_id: u8) -> u8 {
        (self.0 << 3) | (key_id & 0x07)
    }

    /// True if this opcode is part of the reliable control channel (i.e. not a
    /// data packet and within the known opcode range).
    #[inline]
    pub fn is_control(self) -> bool {
        match self {
            Opcode::DATA_V1 | Opcode::DATA_V2 | Opcode(0) => false,
            Opcode(o) if o > 9 => false,
            _ => true,
        }
    }
}

impl fmt::Debug for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Opcode::CONTROL_HARD_RESET_CLIENT_V1 => f.write_str("P_CONTROL_HARD_RESET_CLIENT_V1"),
            Opcode::CONTROL_HARD_RESET_SERVER_V1 => f.write_str("P_CONTROL_HARD_RESET_SERVER_V1"),
            Opcode::CONTROL_SOFT_RESET_V1 => f.write_str("P_CONTROL_SOFT_RESET_V1"),
            Opcode::CONTROL_V1 => f.write_str("P_CONTROL_V1"),
            Opcode::ACK_V1 => f.write_str("P_ACK_V1"),
            Opcode::DATA_V1 => f.write_str("P_DATA_V1"),
            Opcode::CONTROL_HARD_RESET_CLIENT_V2 => f.write_str("P_CONTROL_HARD_RESET_CLIENT_V2"),
            Opcode::CONTROL_HARD_RESET_SERVER_V2 => f.write_str("P_CONTROL_HARD_RESET_SERVER_V2"),
            Opcode::DATA_V2 => f.write_str("P_DATA_V2"),
            Opcode(o) => write!(f, "Opcode({})", o),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        for op in [
            Opcode::CONTROL_V1,
            Opcode::DATA_V1,
            Opcode::DATA_V2,
            Opcode::CONTROL_HARD_RESET_CLIENT_V2,
        ] {
            for key_id in 0..8u8 {
                let b = op.to_byte(key_id);
                let (op2, k2) = Opcode::from_byte(b);
                assert_eq!(op2, op);
                assert_eq!(k2, key_id);
            }
        }
    }
}
