//! Control-channel packet framing (the reliable layer's wire format).
//!
//! A control packet carries the local session ID, an optional list of ACKs for
//! packets received from the peer (each ACK references the *remote* session
//! ID), an optional packet ID for this packet, and the payload (a slice of the
//! TLS record stream). Ported from the Go `packet-ctrl.go`.
//!
//! Wire layout (after the 1-byte opcode/key-id header):
//! ```text
//! [session_id:8]
//! [ack_count:1]
//! [ack_pid:4]*ack_count
//! [remote_session_id:8]   // present only when ack_count > 0
//! [pid:4]                 // present unless this is a P_ACK_V1
//! [payload...]
//! ```

use std::io;

use super::consts::P_OPCODE_SHIFT;
use super::Opcode;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// A parsed or to-be-serialized control packet.
#[derive(Clone, Debug)]
pub struct ControlPacket {
    pub opcode: Opcode,
    pub key_id: u8,

    /// This packet's own packet ID (absent for P_ACK_V1).
    pub pid: Option<u32>,

    /// Local session ID (the `sid` field on the wire).
    pub session_id: [u8; 8],

    /// Remote session ID echoed back when carrying ACKs.
    pub remote_id: [u8; 8],

    /// Payload bytes (a chunk of the TLS record stream).
    pub payload: Vec<u8>,

    /// ACKs the peer reported as received (filled only on parse).
    pub acked_pids: Vec<u32>,
}

impl ControlPacket {
    /// Construct an outgoing control packet with the given session IDs.
    pub fn new(
        opcode: Opcode,
        key_id: u8,
        session_id: [u8; 8],
        remote_id: [u8; 8],
    ) -> ControlPacket {
        ControlPacket {
            opcode,
            key_id,
            pid: None,
            session_id,
            remote_id,
            payload: Vec::new(),
            acked_pids: Vec::new(),
        }
    }

    /// Set the packet ID for this outgoing packet.
    pub fn set_pid(&mut self, pid: u32) {
        self.pid = Some(pid);
    }

    /// Parse a control packet. `data` is the full datagram including the
    /// opcode byte at `data[0]`. ACKs found in the packet are returned in
    /// `acked_pids`; the caller applies them to the reliable layer.
    pub fn parse(data: &[u8]) -> io::Result<ControlPacket> {
        if data.is_empty() {
            return Err(invalid("empty control packet"));
        }
        let head = data[0];
        let opcode = Opcode(head >> P_OPCODE_SHIFT);
        let key_id = head & super::consts::P_KEY_ID_MASK;

        let mut r = Reader::new(&data[1..]);
        let session_id = r.take_8()?;

        let has_pid = opcode != Opcode::ACK_V1;

        let ack_count = r.take_u8()?;
        let mut acked = Vec::with_capacity(ack_count as usize);
        let mut remote_id = [0u8; 8];
        if ack_count > 0 {
            for _ in 0..ack_count {
                acked.push(r.take_u32()?);
            }
            remote_id = r.take_8()?;
        }

        let pid = if has_pid { Some(r.take_u32()?) } else { None };

        let payload = r.rest().to_vec();

        Ok(ControlPacket {
            opcode,
            key_id,
            pid,
            session_id,
            remote_id,
            payload,
            acked_pids: acked,
        })
    }

    /// Serialize this packet, attaching the given list of ACKs to include.
    pub fn to_bytes(&self, ack: &[u32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 1 + ack.len() * 4 + 8 + 4 + self.payload.len());
        out.push(self.opcode.to_byte(self.key_id));
        out.extend_from_slice(&self.session_id);

        out.push(ack.len() as u8);
        if !ack.is_empty() {
            for &a in ack {
                out.extend_from_slice(&a.to_be_bytes());
            }
            out.extend_from_slice(&self.remote_id);
        }
        if let Some(pid) = self.pid {
            out.extend_from_slice(&pid.to_be_bytes());
        }
        out.extend_from_slice(&self.payload);
        out
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }
    fn take_u8(&mut self) -> io::Result<u8> {
        if self.pos >= self.buf.len() {
            return Err(invalid("control packet truncated"));
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }
    fn take_u32(&mut self) -> io::Result<u32> {
        if self.pos + 4 > self.buf.len() {
            return Err(invalid("control packet truncated"));
        }
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }
    fn take_8(&mut self) -> io::Result<[u8; 8]> {
        if self.pos + 8 > self.buf.len() {
            return Err(invalid("control packet truncated"));
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(out)
    }
    fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> ([u8; 8], [u8; 8]) {
        let mut local = [0u8; 8];
        let mut remote = [0u8; 8];
        for i in 0..8 {
            local[i] = (i + 1) as u8;
            remote[i] = (i + 0x10) as u8;
        }
        (local, remote)
    }

    #[test]
    fn make_control_packet() {
        let (local, remote) = ids();
        let pkt = ControlPacket::new(Opcode::CONTROL_V1, 0, local, remote);
        assert_eq!(pkt.opcode, Opcode::CONTROL_V1);
        assert_eq!(pkt.key_id, 0);
        assert_eq!(pkt.session_id, local);
        assert_eq!(pkt.remote_id, remote);
        assert!(pkt.pid.is_none());
    }

    #[test]
    fn set_pid() {
        let (local, remote) = ids();
        let mut pkt = ControlPacket::new(Opcode::CONTROL_V1, 0, local, remote);
        pkt.set_pid(42);
        assert_eq!(pkt.pid, Some(42));
    }

    #[test]
    fn bytes_no_ack() {
        let (local, _remote) = ids();
        let mut pkt = ControlPacket::new(Opcode::CONTROL_V1, 0, local, ids().1);
        pkt.set_pid(1);
        pkt.payload = b"test payload".to_vec();
        let data = pkt.to_bytes(&[]);

        let head = data[0];
        assert_eq!(head >> P_OPCODE_SHIFT, Opcode::CONTROL_V1.0);
        assert_eq!(head & 0x07, 0);
        assert_eq!(&data[1..9], &local);
        assert_eq!(data[9], 0); // ack count
                                // No remote id when ack_count==0; pid at bytes 10..14.
        assert_eq!(&data[10..14], &[0, 0, 0, 1]);
        assert_eq!(&data[14..], b"test payload");
    }

    #[test]
    fn bytes_with_ack() {
        let (local, remote) = ids();
        let mut pkt = ControlPacket::new(Opcode::CONTROL_V1, 0, local, remote);
        pkt.set_pid(5);
        let data = pkt.to_bytes(&[1, 2, 3]);
        assert_eq!(data[9], 3); // ack count
                                // After count: 3*4 ack bytes then remote id.
        assert_eq!(&data[10..14], &[0, 0, 0, 1]);
        assert_eq!(&data[22..30], &remote);
    }

    #[test]
    fn parse_roundtrip() {
        let (local, remote) = ids();
        let mut pkt = ControlPacket::new(Opcode::CONTROL_V1, 2, local, remote);
        pkt.set_pid(100);
        pkt.payload = b"roundtrip test data".to_vec();
        let data = pkt.to_bytes(&[]);

        let parsed = ControlPacket::parse(&data).unwrap();
        assert_eq!(parsed.opcode, Opcode::CONTROL_V1);
        assert_eq!(parsed.key_id, 2);
        assert_eq!(parsed.pid, Some(100));
        assert_eq!(parsed.payload, pkt.payload);
        assert_eq!(parsed.session_id, local);
    }

    #[test]
    fn parse_with_acks() {
        let (local, remote) = ids();
        let mut pkt = ControlPacket::new(Opcode::CONTROL_V1, 0, local, remote);
        pkt.set_pid(7);
        let data = pkt.to_bytes(&[10, 20, 30]);
        let parsed = ControlPacket::parse(&data).unwrap();
        assert_eq!(parsed.acked_pids, vec![10, 20, 30]);
        assert_eq!(parsed.remote_id, remote);
        assert_eq!(parsed.pid, Some(7));
    }

    #[test]
    fn parse_ack_has_no_pid() {
        let (local, remote) = ids();
        let pkt = ControlPacket::new(Opcode::ACK_V1, 0, local, remote);
        let data = pkt.to_bytes(&[42]);
        let parsed = ControlPacket::parse(&data).unwrap();
        assert!(parsed.pid.is_none());
        assert_eq!(parsed.acked_pids, vec![42]);
    }

    #[test]
    fn parse_truncated() {
        // 3 bytes: opcode + 2 bytes -> too short for session id.
        let data = [0x20u8, 0x02, 0x03];
        assert!(ControlPacket::parse(&data).is_err());
    }

    #[test]
    fn is_control_classification() {
        for op in [
            Opcode::CONTROL_HARD_RESET_CLIENT_V1,
            Opcode::CONTROL_HARD_RESET_SERVER_V1,
            Opcode::CONTROL_SOFT_RESET_V1,
            Opcode::CONTROL_V1,
            Opcode::ACK_V1,
            Opcode::CONTROL_HARD_RESET_CLIENT_V2,
            Opcode::CONTROL_HARD_RESET_SERVER_V2,
        ] {
            assert!(op.is_control(), "{op} should be control");
        }
        for op in [Opcode(0), Opcode::DATA_V1, Opcode::DATA_V2, Opcode(10)] {
            assert!(!op.is_control(), "{op} should not be control");
        }
    }
}
