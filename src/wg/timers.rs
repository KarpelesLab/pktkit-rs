//! Per-peer protocol timers (whitepaper §6).
//!
//! WireGuard keeps sessions alive and fresh with a handful of timers:
//! retransmitting an unanswered initiation, rekeying before a keypair
//! expires, answering data with a keepalive so the sender knows it arrived,
//! and starting a new handshake when sent data draws no reply. The handler is
//! sans-I/O, so the timers only record what happened;
//! [`Handler::poll_timers`](crate::wg::Handler::poll_timers) turns that into
//! packets for the caller to send. [`Server`](crate::wg::Server) polls it from
//! its maintenance thread; without threads (`wasm32`), poll it from a timer.

use crate::time::Instant;
use std::time::Duration;

use crate::wg::NoisePublicKey;

/// How long to wait for a handshake response before sending the initiation
/// again.
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to keep retrying a handshake before giving up.
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
/// How long after receiving data to wait for something to send back before
/// sending a keepalive instead.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Up to this much random delay is added to each retransmission, so peers
/// that lost a handshake together do not retry in lockstep.
const REKEY_TIMEOUT_JITTER_MAX_MS: u32 = 334;

/// Something the timers want sent. The packets go to the peer's last known
/// endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimerAction {
    /// A handshake initiation: a rekey, a retry of one that went
    /// unanswered, or a new handshake because sent data drew no reply.
    SendHandshake {
        peer: NoisePublicKey,
        packet: Vec<u8>,
    },
    /// A keepalive, confirming received data or holding a NAT mapping open.
    SendKeepalive {
        peer: NoisePublicKey,
        packet: Vec<u8>,
    },
    /// No handshake response came within `REKEY_ATTEMPT_TIME`, or an
    /// initiation could not be built at all (the peer's authorization
    /// expired, say). Anything queued for this peer should be dropped.
    HandshakeFailed { peer: NoisePublicKey },
}

/// Timer state for one peer.
#[derive(Debug, Default)]
pub(crate) struct PeerTimers {
    /// When the current handshake attempt began; `None` when not trying.
    pub attempt_started: Option<Instant>,
    /// When the last initiation went out, and how much jitter to add before
    /// the next.
    pub last_initiation: Option<Instant>,
    pub jitter: Duration,
    /// Something wants a new handshake as soon as one may be sent.
    pub want_handshake: bool,
    /// Data arrived at this time and nothing has been sent back since.
    pub keepalive_due_since: Option<Instant>,
    /// Data was sent at this time and nothing has been received since.
    pub reply_due_since: Option<Instant>,
    /// When anything was last sent, for persistent keepalive.
    pub last_sent: Option<Instant>,
    /// Keepalive interval for peers behind NAT, if configured.
    pub persistent_keepalive: Option<Duration>,
}

impl PeerTimers {
    pub fn initiation_sent(&mut self, now: Instant) {
        self.attempt_started.get_or_insert(now);
        self.last_initiation = Some(now);
        self.want_handshake = false;
        self.jitter =
            Duration::from_millis((crate::rand::u32() % REKEY_TIMEOUT_JITTER_MAX_MS) as u64);
    }

    pub fn handshake_complete(&mut self) {
        self.attempt_started = None;
        self.want_handshake = false;
        self.reply_due_since = None;
    }

    pub fn packet_sent(&mut self, now: Instant, data: bool) {
        self.last_sent = Some(now);
        self.keepalive_due_since = None;
        if data {
            self.reply_due_since.get_or_insert(now);
        }
    }

    pub fn packet_received(&mut self, now: Instant, data: bool) {
        self.reply_due_since = None;
        if data {
            self.keepalive_due_since.get_or_insert(now);
        }
    }

    /// Whether an initiation should go out now. `None` means the attempt has
    /// run out of time.
    pub fn handshake_due(&mut self, now: Instant) -> Option<bool> {
        if let Some(start) = self.attempt_started {
            if now.duration_since(start) >= REKEY_ATTEMPT_TIME {
                self.attempt_started = None;
                self.want_handshake = false;
                self.reply_due_since = None;
                return None;
            }
            let last = self.last_initiation.unwrap_or(start);
            return Some(now.duration_since(last) >= REKEY_TIMEOUT + self.jitter);
        }
        if self
            .reply_due_since
            .is_some_and(|t| now.duration_since(t) >= KEEPALIVE_TIMEOUT + REKEY_TIMEOUT)
        {
            self.want_handshake = true;
        }
        // At most one initiation per REKEY_TIMEOUT (whitepaper §6.1), even
        // when a rekey is wanted.
        let may_send = self
            .last_initiation
            .is_none_or(|t| now.duration_since(t) >= REKEY_TIMEOUT);
        Some(self.want_handshake && may_send)
    }

    pub fn keepalive_due(&self, now: Instant) -> bool {
        let confirm = self
            .keepalive_due_since
            .is_some_and(|t| now.duration_since(t) >= KEEPALIVE_TIMEOUT);
        let persistent = self.persistent_keepalive.is_some_and(|every| {
            self.last_sent
                .is_none_or(|t| now.duration_since(t) >= every)
        });
        confirm || persistent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unanswered_initiation_is_retried_then_abandoned() {
        let t0 = Instant::now();
        let mut t = PeerTimers::default();
        t.initiation_sent(t0);
        assert_eq!(t.handshake_due(t0 + Duration::from_secs(1)), Some(false));
        assert_eq!(
            t.handshake_due(t0 + REKEY_TIMEOUT + Duration::from_millis(400)),
            Some(true)
        );
        t.initiation_sent(t0 + REKEY_TIMEOUT);
        assert_eq!(t.handshake_due(t0 + REKEY_ATTEMPT_TIME), None, "gave up");
        assert_eq!(t.handshake_due(t0 + REKEY_ATTEMPT_TIME), Some(false));
    }

    #[test]
    fn data_without_reply_starts_a_handshake() {
        let t0 = Instant::now();
        let mut t = PeerTimers::default();
        t.packet_sent(t0, true);
        assert_eq!(t.handshake_due(t0 + KEEPALIVE_TIMEOUT), Some(false));
        assert_eq!(
            t.handshake_due(t0 + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT),
            Some(true)
        );
        // A reply in time cancels it.
        let mut t = PeerTimers::default();
        t.packet_sent(t0, true);
        t.packet_received(t0 + Duration::from_secs(1), false);
        assert_eq!(t.handshake_due(t0 + Duration::from_secs(60)), Some(false));
    }

    #[test]
    fn received_data_is_confirmed_with_a_keepalive() {
        let t0 = Instant::now();
        let mut t = PeerTimers::default();
        t.packet_received(t0, true);
        assert!(!t.keepalive_due(t0 + Duration::from_secs(9)));
        assert!(t.keepalive_due(t0 + KEEPALIVE_TIMEOUT));
        // Sending anything in the meantime is confirmation enough.
        t.packet_sent(t0 + Duration::from_secs(2), false);
        assert!(!t.keepalive_due(t0 + Duration::from_secs(60)));
    }

    #[test]
    fn persistent_keepalive() {
        let t0 = Instant::now();
        let mut t = PeerTimers {
            persistent_keepalive: Some(Duration::from_secs(25)),
            ..Default::default()
        };
        t.packet_sent(t0, false);
        assert!(!t.keepalive_due(t0 + Duration::from_secs(24)));
        assert!(t.keepalive_due(t0 + Duration::from_secs(25)));
    }

    #[test]
    fn wanted_rekeys_are_rate_limited() {
        let t0 = Instant::now();
        let mut t = PeerTimers::default();
        t.initiation_sent(t0);
        t.handshake_complete();
        t.want_handshake = true;
        assert_eq!(t.handshake_due(t0 + Duration::from_secs(1)), Some(false));
        assert_eq!(t.handshake_due(t0 + REKEY_TIMEOUT), Some(true));
    }
}
