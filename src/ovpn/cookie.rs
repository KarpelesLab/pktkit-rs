//! Stateless answer to a client's hard reset (OpenVPN 2.6's three-way
//! handshake: mudp.c do_pre_decrypt_check, ssl_pkt.c
//! calculate_session_id_hmac / check_session_hmac_and_pkt_id).
//!
//! Without tls-auth anyone can send a hard reset from any address. Opening a
//! session for each -- a peer slot, a TLS connection, a minute of
//! retransmissions to the claimed source -- would let a trickle of spoofed
//! packets fill the peer table and turn the server into a reflector. So the
//! first reset is answered with no state kept: our session id is a MAC of
//! the client's address and session id and the time, and only a client that
//! echoes it back -- in the ACK of our reset, which it sends whether or not
//! it knows about any of this -- gets a session. OpenVPN clients from before
//! 2.6 need nothing new: to them it is just the server's session id.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use purecrypto::hash::{Hmac, Mac, Sha256};

use super::Opcode;
use super::packet_ctrl::ControlPacket;
use crate::time::Instant;

/// Computes and checks the server session ids handed out in stateless
/// replies.
pub(super) struct Cookies {
    key: [u8; 32],
    epoch: Instant,
    /// A session id is valid for the time slot it was made in and the two
    /// after; a slot is half the handshake window, as in OpenVPN.
    slot: Duration,
}

impl Cookies {
    pub(super) fn new(handshake_window: Duration) -> Cookies {
        let mut key = [0u8; 32];
        purecrypto::rng::RngCore::fill_bytes(&mut purecrypto::rng::OsRng, &mut key);
        Cookies {
            key,
            epoch: Instant::now(),
            slot: Duration::from_secs((handshake_window.as_secs().div_ceil(2)).max(1)),
        }
    }

    fn slot_at(&self, now: Instant) -> u64 {
        let elapsed = now.saturating_duration_since(self.epoch);
        (elapsed.as_millis() / self.slot.as_millis()) as u64
    }

    /// Our session id for `client_sid` at `from` in time slot `slot`.
    fn session_id(&self, client_sid: [u8; 8], from: SocketAddr, slot: u64) -> [u8; 8] {
        let mut mac = Hmac::<Sha256>::new(&self.key);
        mac.update(&slot.to_be_bytes());
        match from.ip() {
            std::net::IpAddr::V4(ip) => mac.update(&ip.octets()),
            std::net::IpAddr::V6(ip) => mac.update(&ip.octets()),
        }
        mac.update(&from.port().to_be_bytes());
        mac.update(&client_sid);
        let mut tag = [0u8; 32];
        mac.finalize_into(&mut tag);
        let mut sid = [0u8; 8];
        sid.copy_from_slice(&tag[..8]);
        sid
    }

    /// The server hard reset answering `reset` from `from`
    /// (ssl_pkt.c tls_reset_standalone): packet 0, acknowledging the
    /// client's packet 0, under a session id [`check`](Self::check) will
    /// recognise.
    pub(super) fn reply(&self, reset: &ControlPacket, from: SocketAddr, now: Instant) -> Vec<u8> {
        let sid = self.session_id(reset.session_id, from, self.slot_at(now));
        let mut pkt = ControlPacket::new(
            Opcode::CONTROL_HARD_RESET_SERVER_V2,
            0,
            sid,
            reset.session_id,
        );
        pkt.set_pid(0);
        pkt.to_bytes(&[0])
    }

    /// Whether `pkt`, from an address with no session, is the client's
    /// next step after our stateless reply: a P_CONTROL_V1 or P_ACK_V1 on
    /// key 0 whose ACK names a session id we handed `from` for this client
    /// session recently, and that belongs to the start of the handshake
    /// (no packet id past 1, acknowledged or its own).
    pub(super) fn check(&self, pkt: &ControlPacket, from: SocketAddr, now: Instant) -> bool {
        if pkt.key_id != 0 || !matches!(pkt.opcode, Opcode::CONTROL_V1 | Opcode::ACK_V1) {
            return false;
        }
        // Only an ACK record carries our session id.
        if pkt.acked_pids.is_empty() || pkt.acked_pids.iter().any(|&p| p > 1) {
            return false;
        }
        if pkt.opcode == Opcode::CONTROL_V1 && pkt.pid.is_none_or(|p| p > 1) {
            return false;
        }
        let current = self.slot_at(now);
        (current.saturating_sub(2)..=current).any(|slot| {
            let expected = self.session_id(pkt.session_id, from, slot);
            // Constant time: the id is a MAC.
            expected
                .iter()
                .zip(pkt.remote_id)
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
        })
    }
}

/// OpenVPN's `connect-freq-initial`: at most `max` stateless replies per
/// `period` (reflect_filter.c). A reply is a packet sent to an address
/// nobody vouched for, so without a bound the server would reflect a
/// spoofed flood at its victim.
pub(super) struct RateLimit {
    max: u32,
    period: Duration,
    start: Instant,
    count: u32,
}

impl RateLimit {
    pub(super) fn new(max: u32, period: Duration) -> RateLimit {
        RateLimit {
            max,
            period,
            start: Instant::now(),
            count: 0,
        }
    }

    /// Count one reply; whether it may be sent.
    pub(super) fn allow(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.start) > self.period {
            self.start = now;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.count <= self.max
    }

    /// A reply that led to a session does not count against the limit
    /// (reflect_filter_rate_limit_decrease).
    pub(super) fn refund(&mut self) {
        self.count = self.count.saturating_sub(1);
    }
}

/// A [`RateLimit`] for each source (the server's `connect_freq`), keeping
/// at most `sources` of them. A source's count is kept for a period after it
/// last started one; to make room for a new source, those whose period has
/// run out are forgotten, or failing that the one whose period started
/// first. Forgetting a count lets that source start over: under a flood of
/// sources the limit weakens, but nobody is ever refused for want of room.
pub(super) struct SourceRateLimit {
    max: u32,
    period: Duration,
    sources: usize,
    limits: HashMap<IpAddr, RateLimit>,
}

impl SourceRateLimit {
    pub(super) fn new(max: u32, period: Duration, sources: usize) -> SourceRateLimit {
        SourceRateLimit {
            max,
            period,
            sources: sources.max(1),
            limits: HashMap::new(),
        }
    }

    /// Count one new peer from `source`; whether it may be made.
    pub(super) fn allow(&mut self, source: IpAddr, now: Instant) -> bool {
        if !self.limits.contains_key(&source) && self.limits.len() >= self.sources {
            let period = self.period;
            self.limits
                .retain(|_, l| now.saturating_duration_since(l.start) <= period);
            if self.limits.len() >= self.sources
                && let Some(stalest) = self
                    .limits
                    .iter()
                    .min_by_key(|(_, l)| l.start)
                    .map(|(ip, _)| *ip)
            {
                self.limits.remove(&stalest);
            }
        }
        self.limits
            .entry(source)
            .or_insert_with(|| RateLimit {
                max: self.max,
                period: self.period,
                start: now,
                count: 0,
            })
            .allow(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset(sid: [u8; 8]) -> ControlPacket {
        let mut p = ControlPacket::new(Opcode::CONTROL_HARD_RESET_CLIENT_V2, 0, sid, [0; 8]);
        p.set_pid(0);
        p
    }

    fn echo(opcode: Opcode, client: [u8; 8], server: [u8; 8], acks: &[u32]) -> ControlPacket {
        let mut p = ControlPacket::new(opcode, 0, client, server);
        if opcode == Opcode::CONTROL_V1 {
            p.set_pid(1);
        }
        ControlPacket::parse(&p.to_bytes(acks)).unwrap()
    }

    #[test]
    fn echo_is_checked_against_address_session_and_time() {
        let c = Cookies::new(Duration::from_secs(60));
        let from: SocketAddr = "192.0.2.1:1194".parse().unwrap();
        let t0 = Instant::now();
        let reply = ControlPacket::parse(&c.reply(&reset(*b"CLIENTID"), from, t0)).unwrap();
        assert_eq!(reply.opcode, Opcode::CONTROL_HARD_RESET_SERVER_V2);
        assert_eq!(reply.acked_pids, vec![0]);
        assert_eq!(reply.remote_id, *b"CLIENTID");
        let sid = reply.session_id;

        // The ACK of our reset, alone or riding on the client's first
        // control packet, proves the client got it.
        assert!(c.check(&echo(Opcode::ACK_V1, *b"CLIENTID", sid, &[0]), from, t0));
        assert!(c.check(&echo(Opcode::CONTROL_V1, *b"CLIENTID", sid, &[0]), from, t0));
        // Valid for the slot it was made in and the next two.
        assert!(c.check(
            &echo(Opcode::ACK_V1, *b"CLIENTID", sid, &[0]),
            from,
            t0 + Duration::from_secs(61)
        ));
        assert!(!c.check(
            &echo(Opcode::ACK_V1, *b"CLIENTID", sid, &[0]),
            from,
            t0 + Duration::from_secs(91)
        ));

        // Another address, another client session, a wrong id, no ACK, or
        // ids past the start of the handshake: no.
        let elsewhere: SocketAddr = "192.0.2.1:1195".parse().unwrap();
        assert!(!c.check(
            &echo(Opcode::ACK_V1, *b"CLIENTID", sid, &[0]),
            elsewhere,
            t0
        ));
        assert!(!c.check(&echo(Opcode::ACK_V1, *b"OTHERSID", sid, &[0]), from, t0));
        assert!(!c.check(&echo(Opcode::ACK_V1, *b"CLIENTID", [1; 8], &[0]), from, t0));
        assert!(!c.check(&echo(Opcode::CONTROL_V1, *b"CLIENTID", sid, &[]), from, t0));
        assert!(!c.check(&echo(Opcode::ACK_V1, *b"CLIENTID", sid, &[2]), from, t0));
        let mut late = ControlPacket::new(Opcode::CONTROL_V1, 0, *b"CLIENTID", sid);
        late.set_pid(2);
        let late = ControlPacket::parse(&late.to_bytes(&[0])).unwrap();
        assert!(!c.check(&late, from, t0));
    }

    #[test]
    fn source_rate_limit_is_per_source_and_bounded() {
        let t0 = Instant::now();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let mut r = SourceRateLimit::new(1, Duration::from_secs(10), 2);
        assert!(r.allow(ip("192.0.2.1"), t0));
        assert!(!r.allow(ip("192.0.2.1"), t0));
        let t1 = t0 + Duration::from_secs(1);
        assert!(r.allow(ip("192.0.2.2"), t1));
        assert!(!r.allow(ip("192.0.2.2"), t1));
        // A third source is never refused for want of room: the stalest
        // count goes, the others stay.
        assert!(r.allow(ip("192.0.2.3"), t1));
        assert_eq!(r.limits.len(), 2);
        assert!(!r.allow(ip("192.0.2.2"), t1));
        assert!(!r.allow(ip("192.0.2.3"), t1));
        // Counts whose period ran out go first.
        let t2 = t1 + Duration::from_secs(11);
        assert!(r.allow(ip("192.0.2.4"), t2));
        assert_eq!(r.limits.len(), 1);
    }

    #[test]
    fn rate_limit_refills_each_period_and_refunds() {
        let t0 = Instant::now();
        let mut r = RateLimit::new(2, Duration::from_secs(10));
        assert!(r.allow(t0));
        assert!(r.allow(t0));
        assert!(!r.allow(t0));
        r.refund();
        r.refund();
        assert!(r.allow(t0));
        assert!(r.allow(t0 + Duration::from_secs(11)));
        assert!(r.allow(t0 + Duration::from_secs(11)));
        assert!(!r.allow(t0 + Duration::from_secs(11)));
    }
}
