//! TCP Fast Open (RFC 7413): data in the SYN, delivered by the server
//! before the handshake completes, which saves a request/response exchange
//! a round trip.
//!
//! A server takes SYN data only from a client that has shown it owns its
//! address: the client first asks for a cookie (a Fast Open option with no
//! cookie in its SYN), the server answers in its SYN-ACK with a MAC of the
//! client's address, and from then on the client's SYNs carry the cookie
//! and data. A SYN spoofed from another address has no valid cookie, so
//! its data is dropped and only the SYN is acknowledged, as for any SYN.
//!
//! The cookie's MAC is the keyed SipHash vtcp also derives its ISNs and SYN
//! cookies from (see `secret`), which is what Linux has computed its Fast
//! Open cookies with since 2019, when SipHash replaced AES there, over the
//! server's and the client's address and a key generation. The generation
//! advances every [`KEY_PERIOD`], and a cookie of the one before is still
//! taken: that is the key rotation RFC 7413 §4.1.2 asks for, with no key
//! to change by hand. A client whose cookie has aged out is given a fresh
//! one and pays a round trip once.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use super::options::{TcpOption, kind};
use super::secret;

/// The length of the cookies this server issues: Linux's.
pub(crate) const COOKIE_LEN: usize = 8;
/// How long a key generation lasts.
pub(crate) const KEY_PERIOD: Duration = Duration::from_secs(3600);
/// Connections a server holds with data taken from their SYN whose
/// handshake has not completed (RFC 7413 §5.1): past it, a SYN's data is
/// left for the client to send again after the handshake, as for any SYN.
/// Such a connection has the application working for a client whose
/// address a valid cookie vouches for, but whose ACK may never come; and
/// whatever it answers is sent before any ACK has shown the client wants
/// it. Linux takes the limit from the listen backlog.
pub(crate) const MAX_PENDING: usize = 64;

/// A Fast Open option: a cookie, or with none, a request for one.
pub(crate) fn option(cookie: &[u8]) -> TcpOption {
    TcpOption {
        kind: kind::FastOpen,
        data: cookie.to_vec(),
    }
}

/// What a segment's Fast Open option carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Offer<'a> {
    /// A request for a cookie.
    Request,
    /// A cookie.
    Cookie(&'a [u8]),
}

/// The Fast Open option of `opts`, if it has a well-formed one: empty, or
/// a cookie of 4 to 16 bytes (RFC 7413 §4.1.1).
pub(crate) fn offer(opts: &[TcpOption]) -> Option<Offer<'_>> {
    let o = opts.iter().find(|o| o.kind == kind::FastOpen)?;
    match o.data.len() {
        0 => Some(Offer::Request),
        4..=16 => Some(Offer::Cookie(&o.data)),
        _ => None,
    }
}

fn mac(generation: u64, server: IpAddr, client: IpAddr) -> [u8; COOKIE_LEN] {
    secret::keyed_hash(("tfo", generation, server, client)).to_be_bytes()
}

fn generation() -> u64 {
    secret::elapsed().as_secs() / KEY_PERIOD.as_secs()
}

/// The cookie for `client` at our address `server`.
pub(crate) fn cookie(server: IpAddr, client: IpAddr) -> [u8; COOKIE_LEN] {
    mac(generation(), server.to_canonical(), client.to_canonical())
}

/// Whether `cookie` is one this process issued `client` at `server`, in
/// this key generation or the last.
pub(crate) fn valid(server: IpAddr, client: IpAddr, cookie: &[u8]) -> bool {
    if cookie.len() != COOKIE_LEN {
        return false;
    }
    let (server, client) = (server.to_canonical(), client.to_canonical());
    let now = generation();
    [Some(now), now.checked_sub(1)]
        .into_iter()
        .flatten()
        .any(|g| same(&mac(g, server, client), cookie))
}

/// Constant-time comparison: how far a guess matched must not show in how
/// long it took to reject.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Bounds the connections with Fast Open data that have not completed
/// their handshake (see [`MAX_PENDING`]): one per listener, or one for
/// the process.
#[derive(Debug)]
pub(crate) struct Gate {
    pending: AtomicUsize,
    cap: usize,
}

impl Gate {
    pub(crate) fn new(cap: usize) -> Arc<Gate> {
        Arc::new(Gate {
            pending: AtomicUsize::new(0),
            cap,
        })
    }

    /// The gate of connections opened with no listener's own.
    pub(crate) fn global() -> Arc<Gate> {
        static GLOBAL: OnceLock<Arc<Gate>> = OnceLock::new();
        GLOBAL.get_or_init(|| Gate::new(MAX_PENDING)).clone()
    }

    /// A place for one more, if there is room.
    pub(crate) fn take(self: &Arc<Self>) -> Option<Slot> {
        crate::stats::add_within(&self.pending, 1, self.cap).then(|| Slot(self.clone()))
    }

    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }
}

/// A connection's place at its [`Gate`], given back when dropped.
#[derive(Debug)]
pub(crate) struct Slot(Arc<Gate>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connection's Fast Open state.
#[derive(Debug, Default)]
pub(crate) struct FastOpen {
    // Client side.
    /// The SYN carried a Fast Open option: a cookie, or a request.
    pub offered: bool,
    /// What that option carries: the cookie, or nothing for a request.
    /// Dropped when the SYN goes again without data.
    pub request: Option<Vec<u8>>,
    /// Bytes of data the SYN carried.
    pub syn_data: u32,
    /// The cookie the server's SYN-ACK brought.
    pub cookie: Option<Vec<u8>>,
    /// The SYN with data went unanswered and was sent again without it.
    pub syn_data_lost: bool,
    /// The SYN-ACK acknowledged all the SYN's data.
    pub data_acked: bool,

    // Server side.
    /// Where the pending connections with SYN data are counted; the
    /// process's unless set.
    pub gate: Option<Arc<Gate>>,
    /// The driver has no room for a connection's data before the
    /// handshake completes (its accept queue or data budget is full): take
    /// none from the SYN.
    pub refuse_data: bool,
    /// The cookie for our SYN-ACK: the SYN asked for one, or carried one
    /// no longer valid.
    pub reply: Option<[u8; COOKIE_LEN]>,
    /// The SYN's data was taken: the connection holds `slot` until its
    /// handshake completes.
    pub accepted: bool,
    pub slot: Option<Slot>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtcp::options::{parse_options, write_options};

    const S: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    const C: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

    #[test]
    fn cookies_are_per_address_pair() {
        let c = cookie(S, C);
        assert!(valid(S, C, &c));
        assert!(!valid(S, S, &c), "another client's");
        assert!(!valid(C, C, &c), "another server's");
        let mut bad = c;
        bad[0] ^= 1;
        assert!(!valid(S, C, &bad));
        assert!(!valid(S, C, &c[..4]));
        // An IPv4-mapped address is its IPv4 one.
        let mapped = match C {
            IpAddr::V4(v4) => IpAddr::V6(v4.to_ipv6_mapped()),
            _ => unreachable!(),
        };
        assert!(valid(S, mapped, &c));
    }

    #[test]
    fn the_last_generation_is_still_taken() {
        let g = generation();
        if let Some(prev) = g.checked_sub(1) {
            assert!(valid(S, C, &mac(prev, S, C)));
        }
        if let Some(older) = g.checked_sub(2) {
            assert!(!valid(S, C, &mac(older, S, C)));
        }
        assert!(!valid(S, C, &mac(g + 1, S, C)));
    }

    #[test]
    fn option_codec() {
        for (cookie, want) in [
            (&[][..], Some(Offer::Request)),
            (&[1, 2, 3, 4][..], Some(Offer::Cookie(&[1, 2, 3, 4][..]))),
            (&[1, 2][..], None),
            (&[0; 18][..], None),
        ] {
            let opts = [option(cookie)];
            let mut raw = vec![0; crate::vtcp::options::options_len(&opts)];
            write_options(&opts, &mut raw);
            assert_eq!(raw[0], 34);
            let parsed = parse_options(&raw);
            assert_eq!(offer(&parsed), want);
        }
    }

    #[test]
    fn the_gate_bounds_what_is_pending() {
        let g = Gate::new(2);
        let a = g.take().unwrap();
        let _b = g.take().unwrap();
        assert!(g.take().is_none());
        drop(a);
        assert_eq!(g.pending(), 1);
        assert!(g.take().is_some());
    }
}
