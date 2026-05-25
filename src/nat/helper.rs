//! Shared helper types for NAT: mapping views, expectations, port forwards,
//! and the trait surface exposed to ALGs.
//!
//! Mirrors `helper.go`: `Helper`, `PacketHelper`, `LocalHelper`,
//! `NATMapping`, `Expectation`, `PortForward`.

use crate::Packet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

/// IP protocol numbers used throughout the NAT.
pub(crate) const PROTO_ICMP: u8 = 1;
pub(crate) const PROTO_TCP: u8 = 6;
pub(crate) const PROTO_UDP: u8 = 17;
pub(crate) const PROTO_ICMPV6: u8 = 58;

/// Common base every NAT helper exposes.
///
/// Mirrors Go's `nat.Helper`.
pub trait Helper: Send + Sync {
    fn name(&self) -> &str;
    fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A read-only view of a NAT mapping, handed to a [`PacketHelper`] at the
/// moment a packet is being translated.
#[derive(Debug, Clone, Copy)]
pub struct NatMapping {
    pub proto: u8,
    pub inside_ip: IpAddr,
    pub inside_port: u16,
    pub outside_port: u16,
}

/// A packet-level helper inspects/modifies translated packets.
///
/// Hot path: only invoked if [`match_outbound`](Self::match_outbound) returns
/// true. `process_outbound` is called after NAT rewrite on egress;
/// `process_inbound` after reverse-rewrite on ingress.
pub trait PacketHelper: Helper {
    fn match_outbound(&self, proto: u8, dst_port: u16) -> bool;

    /// Returns a (possibly rewritten) packet buffer. Default: pass through.
    fn process_outbound(&self, nat: &super::nat::Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
        let _ = (nat, m);
        pkt
    }

    fn process_inbound(&self, nat: &super::nat::Nat, pkt: Vec<u8>, m: &NatMapping) -> Vec<u8> {
        let _ = (nat, m);
        pkt
    }
}

/// A helper that consumes packets addressed to the NAT itself (e.g. UPnP
/// control endpoints, SSDP discovery). Returns `true` if the packet was
/// handled and should not flow further.
pub trait LocalHelper: Helper {
    fn handle_local(&self, nat: &super::nat::Nat, pkt: &Packet) -> bool;
}

/// An expected future connection registered by an ALG so the NAT will pass
/// it through (e.g. FTP data channels, RTP streams).
#[derive(Debug, Clone)]
pub struct Expectation {
    pub proto: u8,
    /// Zero (`Ipv4Addr::UNSPECIFIED`) means any remote.
    pub remote_ip: Ipv4Addr,
    /// Zero means any source port.
    pub remote_port: u16,
    pub inside_ip: Ipv4Addr,
    pub inside_port: u16,
    pub expires: Instant,
}

/// A static port mapping configured on the NAT.
#[derive(Debug, Clone)]
pub struct PortForward {
    pub proto: u8,
    pub outside_port: u16,
    pub inside_ip: Ipv4Addr,
    pub inside_port: u16,
    pub description: String,
    /// `None` = permanent.
    pub expires: Option<Instant>,
}
