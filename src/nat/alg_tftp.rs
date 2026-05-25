//! TFTP Application Layer Gateway (RFC 1350).
//!
//! TFTP uses port 69 only for the initial request; the server replies from a
//! random ephemeral port. This helper registers a NAT expectation when it
//! sees an outbound RRQ/WRQ so the response can flow back through.

use crate::nat::helper::{Expectation, Helper, NatMapping, PacketHelper, PROTO_UDP};
use crate::nat::nat::Nat;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

const TFTP_EXPECT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub struct TftpHelper;

impl TftpHelper {
    pub fn new() -> TftpHelper {
        TftpHelper
    }
}

impl Helper for TftpHelper {
    fn name(&self) -> &str {
        "tftp"
    }
}

impl PacketHelper for TftpHelper {
    fn match_outbound(&self, proto: u8, dst_port: u16) -> bool {
        proto == PROTO_UDP && dst_port == 69
    }

    fn process_outbound(&self, nat: &Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
        if pkt.len() < 28 {
            return pkt;
        }
        let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let inside_ip = match m.inside_ip {
            IpAddr::V4(a) => a,
            _ => return pkt,
        };
        nat.add_expectation(Expectation {
            proto: PROTO_UDP,
            remote_ip: dst_ip,
            remote_port: 0,
            inside_ip,
            inside_port: m.inside_port,
            expires: Instant::now() + TFTP_EXPECT_TIMEOUT,
        });
        pkt
    }
}
