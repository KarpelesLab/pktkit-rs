//! H.323 (Q.931/H.225) Application Layer Gateway.
//!
//! TODO(nat): scan TCP payload for binary IP / IP+port fields, replace inside
//! addresses with the outside address, and register expectations for H.245
//! and RTP channels (port range 1024+). The Go upstream takes a heuristic
//! 4/6-byte pattern-match approach; reproduce that here when needed.

use crate::nat::helper::{Helper, NatMapping, PacketHelper, PROTO_TCP};
use crate::nat::nat::Nat;

const H323_PORT: u16 = 1720;

#[derive(Debug, Default)]
pub struct H323Helper;

impl H323Helper {
    pub fn new() -> H323Helper {
        H323Helper
    }
}

impl Helper for H323Helper {
    fn name(&self) -> &str {
        "h323"
    }
}

impl PacketHelper for H323Helper {
    fn match_outbound(&self, proto: u8, dst_port: u16) -> bool {
        proto == PROTO_TCP && dst_port == H323_PORT
    }

    fn process_outbound(&self, _nat: &Nat, pkt: Vec<u8>, _m: &NatMapping) -> Vec<u8> {
        // TODO(nat): heuristic binary address rewrite + expectations.
        pkt
    }
}
