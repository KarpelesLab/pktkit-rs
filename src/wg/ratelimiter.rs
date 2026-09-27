//! Per-source rate limit on handshakes under load, after the reference's
//! `ratelimiter.c`.
//!
//! A valid MAC2 only proves the sender can receive at its address, not that
//! it is sending at a reasonable rate: once it holds a cookie, one host could
//! still keep the responder busy with DH work. Under load, each source gets
//! a token bucket of `PACKETS_PER_SECOND` with a burst of
//! `PACKETS_BURSTABLE`, keyed by IPv4 address or IPv6 /64 (a host is
//! typically handed a whole /64).

use crate::time::Instant;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

const PACKETS_PER_SECOND: u64 = 20;
const PACKETS_BURSTABLE: u64 = 5;
const NANOS_PER_SEC: u64 = 1_000_000_000;
const PACKET_COST: u64 = NANOS_PER_SEC / PACKETS_PER_SECOND;
const TOKEN_MAX: u64 = PACKET_COST * PACKETS_BURSTABLE;
/// Sources tracked at once: the reference's largest table (8192 buckets,
/// 8 entries each). A source not yet tracked when the table is full is
/// refused, as there, so a flood of spoofed-then-validated sources cannot
/// grow it; entries a second idle are collected, and a source idle that
/// long starts with a full bucket anyway.
const MAX_ENTRIES: usize = 8192 * 8;
const GC_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Source {
    V4([u8; 4]),
    V6([u8; 8]),
}

impl Source {
    fn of(ip: IpAddr) -> Source {
        match ip.to_canonical() {
            IpAddr::V4(a) => Source::V4(a.octets()),
            IpAddr::V6(a) => Source::V6(a.octets()[..8].try_into().unwrap()),
        }
    }
}

struct Bucket {
    last: Instant,
    /// Nanoseconds' worth of allowance, each packet costing PACKET_COST.
    tokens: u64,
}

#[derive(Default)]
pub(crate) struct RateLimiter {
    table: HashMap<Source, Bucket>,
    last_gc: Option<Instant>,
}

impl RateLimiter {
    /// Whether a handshake from `ip` arriving at `now` may be processed.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.gc(now);
        let src = Source::of(ip);
        if let Some(b) = self.table.get_mut(&src) {
            let elapsed = now.saturating_duration_since(b.last).as_nanos();
            let tokens = TOKEN_MAX.min(
                b.tokens
                    .saturating_add(elapsed.min(TOKEN_MAX as u128) as u64),
            );
            // Two callers may read the clock in one order and take the lock
            // in the other: moving back would count the gap twice.
            b.last = b.last.max(now);
            let ok = tokens >= PACKET_COST;
            b.tokens = if ok { tokens - PACKET_COST } else { tokens };
            return ok;
        }
        if self.table.len() >= MAX_ENTRIES {
            return false;
        }
        self.table.insert(
            src,
            Bucket {
                last: now,
                tokens: TOKEN_MAX - PACKET_COST,
            },
        );
        true
    }

    fn gc(&mut self, now: Instant) {
        if self
            .last_gc
            .is_some_and(|t| now.saturating_duration_since(t) < GC_INTERVAL)
        {
            return;
        }
        self.last_gc = Some(now);
        self.table
            .retain(|_, b| now.saturating_duration_since(b.last) <= GC_INTERVAL);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.table.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn a_source_gets_a_burst_of_5_then_20_a_second() {
        let mut rl = RateLimiter::default();
        let t0 = Instant::now();
        let allowed = (0..10).filter(|_| rl.allow(v4(1), t0)).count();
        assert_eq!(allowed, PACKETS_BURSTABLE as usize);
        // Another source is not held back by the first.
        assert!(rl.allow(v4(2), t0));
        // One more every 50 ms.
        assert!(!rl.allow(v4(1), t0 + Duration::from_millis(49)));
        assert!(rl.allow(v4(1), t0 + Duration::from_millis(50)));
        assert!(!rl.allow(v4(1), t0 + Duration::from_millis(60)));
        // Over a long run, 20 a second.
        let allowed = (0..10_000u64)
            .filter(|i| rl.allow(v4(1), t0 + Duration::from_millis(100 + i)))
            .count();
        assert!((200..=206).contains(&allowed), "{allowed} in 10 s");
    }

    #[test]
    fn ipv6_is_limited_per_64() {
        let mut rl = RateLimiter::default();
        let t0 = Instant::now();
        let host = |h: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, h));
        let allowed = (0..10u16).filter(|&h| rl.allow(host(h), t0)).count();
        assert_eq!(allowed, PACKETS_BURSTABLE as usize);
        assert!(rl.allow(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1)),
            t0
        ));
        // A v4-mapped address shares the v4 address's bucket.
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
        for _ in 0..PACKETS_BURSTABLE {
            assert!(rl.allow(v4(1), t0));
        }
        assert!(!rl.allow(mapped, t0));
    }

    #[test]
    fn the_table_is_bounded_and_collected() {
        let mut rl = RateLimiter::default();
        let t0 = Instant::now();
        for i in 0..MAX_ENTRIES as u32 {
            assert!(rl.allow(IpAddr::V4(Ipv4Addr::from(i)), t0));
        }
        // Full: a new source is refused, a known one still served.
        assert!(!rl.allow(IpAddr::V4(Ipv4Addr::from(u32::MAX)), t0));
        assert!(rl.allow(IpAddr::V4(Ipv4Addr::from(7)), t0));
        assert_eq!(rl.len(), MAX_ENTRIES);
        // Once idle a second, entries go and new sources get in again.
        let later = t0 + Duration::from_millis(1_500);
        assert!(rl.allow(IpAddr::V4(Ipv4Addr::from(u32::MAX)), later));
        assert_eq!(rl.len(), 1);
    }
}
