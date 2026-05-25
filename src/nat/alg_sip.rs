//! SIP (RFC 3261) Application Layer Gateway.
//!
//! TODO(nat): full SIP/SDP rewrite + RTP/RTCP expectation creation. The Go
//! upstream parses Via/Contact headers and `c=`/`m=` SDP lines, allocates
//! outside ports for each media stream, and registers two-way expectations.
//! This stub matches the wire trigger but performs no transformation.

use crate::nat::helper::{Helper, NatMapping, PacketHelper, PROTO_TCP, PROTO_UDP};
use crate::nat::nat::Nat;

const SIP_PORT: u16 = 5060;

#[derive(Debug, Default)]
pub struct SipHelper;

impl SipHelper {
    pub fn new() -> SipHelper {
        SipHelper
    }
}

impl Helper for SipHelper {
    fn name(&self) -> &str {
        "sip"
    }
}

impl PacketHelper for SipHelper {
    fn match_outbound(&self, proto: u8, dst_port: u16) -> bool {
        dst_port == SIP_PORT && (proto == PROTO_TCP || proto == PROTO_UDP)
    }

    fn process_outbound(&self, _nat: &Nat, pkt: Vec<u8>, _m: &NatMapping) -> Vec<u8> {
        // TODO(nat): rewrite Via/Contact headers, SDP `c=`/`m=` lines, and
        // register expectations for RTP/RTCP streams.
        pkt
    }

    fn process_inbound(&self, _nat: &Nat, pkt: Vec<u8>, _m: &NatMapping) -> Vec<u8> {
        // TODO(nat): inverse rewrite for inbound SIP messages.
        pkt
    }
}
