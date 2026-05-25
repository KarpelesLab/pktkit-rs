//! PPTP Application Layer Gateway.
//!
//! TODO(nat): track PPTP control messages (TCP/1723) to learn each Call-ID,
//! then translate the Call-ID in the associated GRE (proto 47) tunnel. Full
//! PPTP NAT traversal also needs GRE forwarding in the NAT core — currently
//! the core handles TCP/UDP/ICMP only.

use crate::nat::helper::{Helper, NatMapping, PacketHelper, PROTO_TCP};
use crate::nat::nat::Nat;

const PPTP_PORT: u16 = 1723;

#[derive(Debug, Default)]
pub struct PptpHelper;

impl PptpHelper {
    pub fn new() -> PptpHelper {
        PptpHelper
    }
}

impl Helper for PptpHelper {
    fn name(&self) -> &str {
        "pptp"
    }
}

impl PacketHelper for PptpHelper {
    fn match_outbound(&self, proto: u8, dst_port: u16) -> bool {
        proto == PROTO_TCP && dst_port == PPTP_PORT
    }

    fn process_outbound(&self, _nat: &Nat, pkt: Vec<u8>, _m: &NatMapping) -> Vec<u8> {
        // TODO(nat): parse PPTP control messages, track call IDs, and create
        // GRE-related expectations.
        pkt
    }

    fn process_inbound(&self, _nat: &Nat, pkt: Vec<u8>, _m: &NatMapping) -> Vec<u8> {
        // TODO(nat): inverse rewrite for inbound control messages.
        pkt
    }
}
