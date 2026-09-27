//! Per-mapping session tracking shared by [`Nat`](super::Nat) and
//! [`Nat64`](super::Nat64): which remote endpoints a mapping talks to, the TCP
//! life cycle of each, and the idle timeouts that follow from it.

use crate::nat::helper::{PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use crate::time::Instant;
use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::Duration;

/// RFC 5382 REQ-5: an established TCP connection must not be dropped for
/// being idle less than 2 hours 4 minutes.
pub(crate) const TCP_ESTABLISHED_TIMEOUT: Duration = Duration::from_secs(2 * 3600 + 4 * 60);
/// RFC 5382 REQ-5: a partially open or closing TCP connection may go after
/// 4 minutes idle (and no sooner).
pub(crate) const TCP_TRANSITORY_TIMEOUT: Duration = Duration::from_secs(4 * 60);
/// RFC 4787 REQ-5: a UDP mapping must not expire in less than 2 minutes;
/// 5 minutes is recommended.
pub(crate) const UDP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// RFC 5508 REQ-1: an ICMP query mapping must not expire in less than 60 s.
pub(crate) const ICMP_TIMEOUT: Duration = Duration::from_secs(60);

/// Cap on remotes tracked per mapping. A forwarded server can have many
/// clients; past the cap, new remotes still get through but are not tracked,
/// and the mapping's own idle timer covers them.
const MAX_PEERS: usize = 1024;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

// Peer state bits.
const SEEN_OUT: u8 = 1 << 0;
const SEEN_IN: u8 = 1 << 1;
const FIN_OUT: u8 = 1 << 2;
const FIN_IN: u8 = 1 << 3;
const RESET: u8 = 1 << 4;

/// One remote endpoint a mapping exchanges traffic with.
#[derive(Debug)]
pub(crate) struct Peer {
    last: Instant,
    state: u8,
}

impl Peer {
    fn closing(&self) -> bool {
        self.state & RESET != 0 || self.state & (FIN_OUT | FIN_IN) == FIN_OUT | FIN_IN
    }

    fn timeout(&self, proto: u8) -> Duration {
        match proto {
            PROTO_TCP => {
                let both_ways = self.state & (SEEN_OUT | SEEN_IN) == SEEN_OUT | SEEN_IN;
                // A half-closed connection still carries data the other way,
                // so only FINs in both directions (or a reset) end it.
                if both_ways && !self.closing() {
                    TCP_ESTABLISHED_TIMEOUT
                } else {
                    TCP_TRANSITORY_TIMEOUT
                }
            }
            PROTO_ICMP => ICMP_TIMEOUT,
            _ => UDP_TIMEOUT,
        }
    }
}

/// The remotes of one mapping.
#[derive(Debug, Default)]
pub(crate) struct Peers {
    map: HashMap<SocketAddrV4, Peer>,
}

impl Peers {
    /// Record a packet between the mapping and `peer`. `outbound` is true for
    /// a packet from the inside host; `tcp_flags` carries the TCP flags byte
    /// for TCP.
    pub(crate) fn note(
        &mut self,
        peer: SocketAddrV4,
        outbound: bool,
        tcp_flags: Option<u8>,
        now: Instant,
    ) {
        let flags = tcp_flags.unwrap_or(0);
        if !self.map.contains_key(&peer) {
            // A reset from a remote this mapping never talked to proves
            // nothing and must not end anyone's session; the inside host
            // judges it by its sequence number.
            if (!outbound && flags & TCP_RST != 0) || self.map.len() >= MAX_PEERS {
                return;
            }
            self.map.insert(
                peer,
                Peer {
                    last: now,
                    state: 0,
                },
            );
        }
        let p = self.map.get_mut(&peer).expect("inserted above");
        p.last = now;
        if tcp_flags.is_none() {
            return;
        }
        // A fresh SYN on a finished connection is a new connection reusing
        // the same endpoints (RFC 793 TIME-WAIT reuse): forget the old one.
        if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 && p.closing() {
            p.state = 0;
        }
        p.state |= if outbound { SEEN_OUT } else { SEEN_IN };
        if flags & TCP_FIN != 0 {
            p.state |= if outbound { FIN_OUT } else { FIN_IN };
        }
        if flags & TCP_RST != 0 {
            p.state |= RESET;
        }
    }

    /// True if the mapping has exchanged traffic with `peer`.
    pub(crate) fn contains(&self, peer: &SocketAddrV4) -> bool {
        self.map.contains_key(peer)
    }

    /// Forget remotes idle past their timeout, and report whether the whole
    /// mapping (last active at `last_active`) is now idle and may go.
    pub(crate) fn expire(&mut self, proto: u8, last_active: Instant, now: Instant) -> bool {
        self.map
            .retain(|_, p| now.saturating_duration_since(p.last) <= p.timeout(proto));
        if !self.map.is_empty() {
            return false;
        }
        let base = match proto {
            PROTO_TCP => TCP_TRANSITORY_TIMEOUT,
            PROTO_UDP => UDP_TIMEOUT,
            PROTO_ICMP => ICMP_TIMEOUT,
            _ => UDP_TIMEOUT,
        };
        now.saturating_duration_since(last_active) > base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn peer(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 9), port)
    }

    #[test]
    fn established_tcp_outlives_two_hours() {
        let now = Instant::now();
        let mut p = Peers::default();
        p.note(peer(80), true, Some(TCP_SYN), now);
        p.note(peer(80), false, Some(TCP_SYN | TCP_ACK), now);
        assert!(!p.expire(PROTO_TCP, now, now + Duration::from_secs(2 * 3600)));
        assert!(p.expire(
            PROTO_TCP,
            now,
            now + TCP_ESTABLISHED_TIMEOUT + Duration::from_secs(1)
        ));
    }

    #[test]
    fn half_close_is_still_established() {
        let now = Instant::now();
        let mut p = Peers::default();
        p.note(peer(80), true, Some(TCP_SYN), now);
        p.note(peer(80), false, Some(TCP_SYN | TCP_ACK), now);
        p.note(peer(80), true, Some(TCP_FIN | TCP_ACK), now);
        assert!(!p.expire(PROTO_TCP, now, now + Duration::from_secs(3600)));
    }

    #[test]
    fn full_close_is_transitory() {
        let now = Instant::now();
        let mut p = Peers::default();
        p.note(peer(80), true, Some(TCP_SYN), now);
        p.note(peer(80), false, Some(TCP_SYN | TCP_ACK), now);
        p.note(peer(80), true, Some(TCP_FIN | TCP_ACK), now);
        p.note(peer(80), false, Some(TCP_FIN | TCP_ACK), now);
        assert!(!p.expire(PROTO_TCP, now, now + Duration::from_secs(200)));
        assert!(p.expire(
            PROTO_TCP,
            now,
            now + TCP_TRANSITORY_TIMEOUT + Duration::from_secs(1)
        ));
    }

    #[test]
    fn reset_from_a_stranger_is_ignored() {
        let now = Instant::now();
        let mut p = Peers::default();
        p.note(peer(80), true, Some(TCP_SYN), now);
        p.note(peer(80), false, Some(TCP_SYN | TCP_ACK), now);
        p.note(peer(81), false, Some(TCP_RST), now);
        assert!(!p.contains(&peer(81)));
        assert!(!p.expire(PROTO_TCP, now, now + Duration::from_secs(3600)));
    }

    #[test]
    fn new_syn_reopens_a_closed_connection() {
        let now = Instant::now();
        let mut p = Peers::default();
        p.note(peer(80), true, Some(TCP_SYN), now);
        p.note(peer(80), false, Some(TCP_SYN | TCP_ACK), now);
        p.note(peer(80), true, Some(TCP_RST), now);
        p.note(peer(80), true, Some(TCP_SYN), now);
        p.note(peer(80), false, Some(TCP_SYN | TCP_ACK), now);
        assert!(!p.expire(PROTO_TCP, now, now + Duration::from_secs(3600)));
    }

    #[test]
    fn udp_lasts_the_recommended_five_minutes() {
        let now = Instant::now();
        let mut p = Peers::default();
        p.note(peer(53), true, None, now);
        assert!(!p.expire(PROTO_UDP, now, now + Duration::from_secs(299)));
        assert!(p.expire(PROTO_UDP, now, now + Duration::from_secs(301)));
    }
}
