//! Shared helper types for NAT: mapping views, expectations, port forwards,
//! and the trait surface exposed to ALGs.
//!
//! Mirrors `helper.go`: `Helper`, `PacketHelper`, `LocalHelper`,
//! `NATMapping`, `Expectation`, `PortForward`.

use crate::Packet;
use crate::time::Instant;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::Duration;

/// IP protocol numbers used throughout the NAT.
pub(crate) const PROTO_ICMP: u8 = 1;
pub(crate) const PROTO_TCP: u8 = 6;
pub(crate) const PROTO_UDP: u8 = 17;
pub(crate) const PROTO_ICMPV6: u8 = 58;

/// The inside ports an ALG has opened for each inside host (namespace,
/// address), with when each was last announced, so that it can cap them.
///
/// ALGs open ports on what inside hosts send, and every one opened is
/// reachable by any remote; without a cap, a host sending one message after
/// another could spread open mappings across the NAT's whole port pool.
#[derive(Debug)]
pub(crate) struct OpenedPorts {
    by_host: Mutex<HashMap<(u64, Ipv4Addr), Vec<(u16, Instant)>>>,
    /// Most distinct ports one host may have open at a time.
    max_per_host: usize,
    /// How long an announced port counts as open.
    window: Duration,
}

impl OpenedPorts {
    pub(crate) fn new(max_per_host: usize, window: Duration) -> OpenedPorts {
        OpenedPorts {
            by_host: Mutex::new(HashMap::new()),
            max_per_host,
            window,
        }
    }

    /// Whether `host` may open all of inside `ports` now; if so, they are
    /// counted, or refreshed where already open, and those newly counted
    /// are returned, to be [`refund`](Self::refund)ed if they cannot be
    /// opened after all. All or none, so a media stream is never left with
    /// only part of its ports.
    pub(crate) fn admit(
        &self,
        host: (u64, Ipv4Addr),
        ports: &[u16],
        now: Instant,
    ) -> Option<Vec<u16>> {
        let window = self.window;
        let live = |t: &Instant| now.saturating_duration_since(*t) < window;
        let mut by_host = self.by_host.lock().unwrap();
        let open = by_host.entry(host).or_default();
        open.retain(|(_, t)| live(t));
        let mut new: Vec<u16> = ports
            .iter()
            .copied()
            .filter(|p| !open.iter().any(|(q, _)| q == p))
            .collect();
        new.sort_unstable();
        new.dedup();
        if open.len() + new.len() > self.max_per_host {
            return None;
        }
        for (p, t) in open.iter_mut() {
            if ports.contains(p) {
                *t = now;
            }
        }
        open.extend(new.iter().map(|&p| (p, now)));
        // Hosts that went quiet leave no record behind.
        if by_host.len() > 64 {
            by_host.retain(|_, open| {
                open.retain(|(_, t)| live(t));
                !open.is_empty()
            });
        }
        Some(new)
    }

    /// Uncount `ports`, newly admitted for `host` but never opened (the
    /// mapping failed): a host at its mapping cap, or a full pool, must not
    /// use up its allowance of open ports for nothing.
    pub(crate) fn refund(&self, host: (u64, Ipv4Addr), ports: &[u16]) {
        if ports.is_empty() {
            return;
        }
        let mut by_host = self.by_host.lock().unwrap();
        if let Some(open) = by_host.get_mut(&host) {
            open.retain(|(p, _)| !ports.contains(p));
            if open.is_empty() {
                by_host.remove(&host);
            }
        }
    }
}

// The helper traits are the interface between the NAT and the ALGs in this
// module. They are `pub` only so that `Nat::add_packet_helper` and
// `Nat::add_local_helper` can name them in their bounds: this module is
// private and they are not re-exported, so no other crate can name or
// implement them. Their methods hand a helper the NAT's own state (mappings,
// expectations), which is not an interface to commit to.

/// Common base every NAT helper exposes.
pub trait Helper: Send + Sync {
    fn name(&self) -> &str;
    fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A read-only view of a NAT mapping, handed to a [`PacketHelper`] at the
/// moment a packet is being translated.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct NatMapping {
    pub proto: u8,
    pub inside_ip: IpAddr,
    pub inside_port: u16,
    pub outside_port: u16,
    /// The inside namespace the mapping belongs to: 0 for the NAT's own inside
    /// interface, otherwise the attachment made through
    /// [`L3Connector::connect_l3`](crate::L3Connector::connect_l3). Mappings
    /// and expectations an ALG creates for this session belong here too, since
    /// another namespace may reuse the same private addresses.
    pub namespace: u64,
}

impl NatMapping {
    pub fn new(proto: u8, inside_ip: IpAddr, inside_port: u16, outside_port: u16) -> NatMapping {
        NatMapping {
            proto,
            inside_ip,
            inside_port,
            outside_port,
            namespace: 0,
        }
    }
}

setters! {
    NatMapping {
        set namespace: u64;
    }
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
///
/// It sees packets from the inside sent to the NAT's inside address or to a
/// multicast or broadcast address. Nothing from the outside reaches it: a
/// local service answering there would let any Internet host make the NAT
/// send packets into the inside network.
pub trait LocalHelper: Helper {
    fn handle_local(&self, nat: &super::nat::Nat, pkt: &Packet) -> bool;

    /// Like [`handle_local`](Self::handle_local), for a packet that arrived on
    /// inside namespace `namespace` (see [`NatMapping::namespace`]). A helper
    /// that answers should reply with
    /// [`Nat::send_inside_in`](super::nat::Nat::send_inside_in) on the same
    /// namespace. The NAT calls this one; the default ignores the namespace.
    fn handle_local_in(&self, nat: &super::nat::Nat, namespace: u64, pkt: &Packet) -> bool {
        let _ = namespace;
        self.handle_local(nat, pkt)
    }
}

/// An expected future connection registered by an ALG so the NAT will pass
/// it through (e.g. FTP data channels, RTP streams).
///
/// It matches only a connection to `outside_port`, the port the ALG told the
/// peer to use; a connection to any other port is not the one expected.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Expectation {
    pub proto: u8,
    /// Zero (`Ipv4Addr::UNSPECIFIED`) means any remote.
    pub remote_ip: Ipv4Addr,
    /// Zero means any source port.
    pub remote_port: u16,
    pub inside_ip: Ipv4Addr,
    pub inside_port: u16,
    /// The outside port the connection is expected on.
    pub outside_port: u16,
    /// Inside namespace of `inside_ip` (see [`NatMapping::namespace`]).
    pub namespace: u64,
    pub expires: Instant,
}

impl Expectation {
    /// Expect a `proto` connection from any remote to `outside_port`, to be
    /// delivered to `inside_ip:inside_port`, until `expires`.
    pub fn new(
        proto: u8,
        inside_ip: Ipv4Addr,
        inside_port: u16,
        outside_port: u16,
        expires: Instant,
    ) -> Expectation {
        Expectation {
            proto,
            remote_ip: Ipv4Addr::UNSPECIFIED,
            remote_port: 0,
            inside_ip,
            inside_port,
            outside_port,
            namespace: 0,
            expires,
        }
    }
}

setters! {
    Expectation {
        set remote_ip: Ipv4Addr;
        set namespace: u64;
    }
}

/// A static port mapping configured on the NAT.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PortForward {
    /// IP protocol number: 6 for TCP, 17 for UDP.
    pub proto: u8,
    /// Port on the NAT's outside address that is forwarded.
    pub outside_port: u16,
    /// Inside host the traffic goes to.
    pub inside_ip: Ipv4Addr,
    /// Port on the inside host the traffic goes to.
    pub inside_port: u16,
    /// Free-form label, e.g. the UPnP `NewPortMappingDescription`.
    pub description: String,
    /// `None` = permanent.
    pub expires: Option<Instant>,
    /// Inside namespace of `inside_ip`: 0 for the NAT's own inside
    /// interface, otherwise the attachment made through
    /// [`L3Connector::connect_l3`](crate::L3Connector::connect_l3).
    pub namespace: u64,
    /// Which [`Nat::add_port_forward`](super::Nat::add_port_forward) call
    /// installed this forward, assigned by the NAT. Whoever added a forward
    /// can tell it from one added over it later, even an identical one.
    pub(crate) id: u64,
}

impl PortForward {
    /// Forward `proto` traffic arriving on `outside_port` to
    /// `inside_ip:inside_port`, permanently.
    pub fn new(proto: u8, outside_port: u16, inside_ip: Ipv4Addr, inside_port: u16) -> PortForward {
        PortForward {
            proto,
            outside_port,
            inside_ip,
            inside_port,
            description: String::new(),
            expires: None,
            namespace: 0,
            id: 0,
        }
    }
}

setters! {
    PortForward {
        into description: String;
        some expires: Instant;
        set namespace: u64;
    }
}
