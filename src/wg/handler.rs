//! Per-identity WireGuard state machine.
//!
//! A [`Handler`] owns one private key, the table of authorized peers, the set
//! of pending handshakes, the active keypairs (indexed by local sender), and
//! the per-peer sessions. It is the synchronous core of the implementation —
//! all I/O happens in [`super::server::Server`].

use crate::time::Instant;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use crate::Result;
use crate::wg::constants::{
    CHACHAPOLY_KEY_SIZE, DEFAULT_LOAD_THRESHOLD, MIN_INITIATION_INTERVAL, NoisePresharedKey,
    NoisePrivateKey, NoisePublicKey, REJECT_AFTER_TIME, TAI64N_TIMESTAMP_SIZE,
};
use crate::wg::crypto::x25519_public;
use crate::wg::replay::SlidingWindow;
use crate::wg::timers::{PeerTimers, TimerAction};
use crate::wg::transport::EncryptError;

/// Callback invoked when a handshake arrives from a peer not in the authorized
/// list. The packet slice is only valid for the call; the callback must copy
/// it if it needs to keep the data (e.g. for later `accept_unknown_peer`).
pub type UnknownPeerFn = Arc<dyn Fn(NoisePublicKey, SocketAddr, &[u8]) + Send + Sync + 'static>;

/// Per-handler configuration.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Config {
    /// Local static private key. If zero, a fresh key is generated.
    pub private_key: NoisePrivateKey,

    /// Optional callback for unauthorized peers.
    pub on_unknown_peer: Option<UnknownPeerFn>,

    /// Handshake initiations per second allowed before MAC2 cookie
    /// validation kicks in (whitepaper §5.3). `None` uses the default
    /// (1000); `Some(n)` sets it exactly, so `Some(0)` makes every
    /// initiation under-load (useful in tests to force the cookie path).
    pub load_threshold: Option<usize>,

    /// Peers [`Handler::accept_unknown_peer`] (and
    /// [`Adapter::accept_unknown_peer`](crate::wg::Adapter::accept_unknown_peer))
    /// will take the handler to: past this many authorized peers, a new one
    /// is refused. An `on_unknown_peer` that accepts every key would
    /// otherwise let anyone grow the peer table without end, one fresh key
    /// per initiation. Peers added with [`Handler::add_peer`] are not
    /// limited, but count. `None` uses the default (10000, the most that
    /// can hold a session at once).
    pub unknown_peer_limit: Option<usize>,
}

setters! {
    Config {
        set private_key: NoisePrivateKey;
        some on_unknown_peer: UnknownPeerFn;
        some load_threshold: usize;
        some unknown_peer_limit: usize;
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("private_key", &self.private_key)
            .field("on_unknown_peer", &self.on_unknown_peer.is_some())
            .field("load_threshold", &self.load_threshold)
            .field("unknown_peer_limit", &self.unknown_peer_limit)
            .finish()
    }
}

/// Outcome of feeding one incoming WireGuard packet into [`Handler::process_packet`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PacketResult {
    /// What the packet was, and so which of the other fields are set.
    pub ty: PacketType,
    /// Bytes to send back to the peer (handshake response or cookie reply).
    pub response: Vec<u8>,
    /// Decrypted plaintext, valid for `TransportData`.
    pub data: Vec<u8>,
    /// Identifies which peer the packet belongs to.
    pub peer_key: NoisePublicKey,
}

/// Classifies the result of decoding an incoming packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    /// A successfully built handshake response (responder side) or a
    /// freshly generated keepalive (initiator side after receiving response).
    HandshakeResponse,
    /// A cookie reply (DoS mitigation) the caller should send back.
    CookieReply,
    /// A decrypted transport data packet.
    TransportData,
    /// A keepalive (empty transport data).
    Keepalive,
    /// A cookie reply was *received*; nothing to send. Retry the handshake.
    CookieReceived,
}

/// Public summary of a peer's session state, from
/// [`Handler::get_peer_info`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PeerInfo {
    /// The peer's static public key.
    pub public_key: NoisePublicKey,
    /// Whether handshakes with the peer mix in a preshared key.
    pub has_psk: bool,
    /// When the peer was first authorized.
    pub created_at: Instant,
    /// When its authorization lapses, if it does
    /// ([`Handler::set_peer_expiry`]).
    pub expires_at: Option<Instant>,
    /// When a handshake with it last went through (an initiation from it
    /// accepted, or its response to ours), if one has.
    pub last_handshake: Option<Instant>,
}

/// Internal per-peer record.
struct PeerEntry {
    public_key: NoisePublicKey,
    preshared_key: NoisePresharedKey,
    has_psk: bool,
    created_at: Instant,
    expires_at: Option<Instant>,
    last_handshake: Option<Instant>,
    last_timestamp: [u8; TAI64N_TIMESTAMP_SIZE],
    has_timestamp: bool,
    /// When an initiation from the peer was last accepted.
    last_initiation_consumed: Option<Instant>,
    /// Initiator-side cookie state: writes MAC1/MAC2 on outgoing handshakes.
    cookie_gen: Mutex<crate::wg::cookie::CookieGenerator>,
    timers: Mutex<PeerTimers>,
}

impl PeerEntry {
    fn new(key: NoisePublicKey, psk: NoisePresharedKey, has_psk: bool) -> PeerEntry {
        PeerEntry {
            public_key: key,
            preshared_key: psk,
            has_psk,
            created_at: Instant::now(),
            expires_at: None,
            last_handshake: None,
            last_timestamp: [0u8; TAI64N_TIMESTAMP_SIZE],
            has_timestamp: false,
            last_initiation_consumed: None,
            cookie_gen: Mutex::new(crate::wg::cookie::CookieGenerator::new(&key)),
            timers: Mutex::new(PeerTimers::default()),
        }
    }
}

#[derive(Default)]
struct LoadMeter {
    window_start: Option<Instant>,
    count: usize,
    until: Option<Instant>,
}

/// A derived transport keypair (rotates on each handshake completion).
pub(crate) struct Keypair {
    pub send_key: [u8; CHACHAPOLY_KEY_SIZE],
    pub receive_key: [u8; CHACHAPOLY_KEY_SIZE],
    pub send_counter: AtomicU64,
    pub created: Instant,
    pub local_index: u32,
    pub remote_index: u32,
    pub peer_key: NoisePublicKey,
    pub is_initiator: bool,
    pub replay_filter: SlidingWindow,
}

impl Drop for Keypair {
    fn drop(&mut self) {
        // Forward secrecy is only as good as the old keys' disappearance.
        crate::zeroize::zeroize(&mut self.send_key);
        crate::zeroize::zeroize(&mut self.receive_key);
    }
}

/// A peer's session: the keypairs of its last three handshakes, as in the
/// reference implementation (whitepaper §5.4.6).
///
/// - `keypair_next`: derived by us as responder, not yet confirmed. The
///   initiator may never have received our response, so we must not send
///   with it; the first transport packet that authenticates under it
///   promotes it to current.
/// - `keypair_current`: the one we send with.
/// - `keypair_prev`: the one before, still accepted on receive so packets in
///   flight across a rekey are not lost.
pub(crate) struct Session {
    pub keypair_current: Option<Arc<Keypair>>,
    pub keypair_prev: Option<Arc<Keypair>>,
    pub keypair_next: Option<Arc<Keypair>>,
    pub last_received: Instant,
    pub last_sent: Instant,
    #[allow(dead_code)]
    pub peer_key: NoisePublicKey,
}

/// The full WireGuard state machine for one identity.
pub struct Handler {
    private_key: NoisePrivateKey,
    public_key: NoisePublicKey,

    peers: RwLock<HashMap<NoisePublicKey, PeerEntry>>,

    pub(crate) handshakes: Mutex<HashMap<u32, crate::wg::handshake::Handshake>>,
    pub(crate) keypairs: RwLock<HashMap<u32, Arc<Keypair>>>,
    pub(crate) sessions: RwLock<HashMap<NoisePublicKey, Session>>,

    on_unknown_peer: Mutex<Option<UnknownPeerFn>>,
    unknown_peer_limit: usize,
    load_threshold: usize,
    /// Initiations seen in the current one-second window, and when being
    /// under load lapses. Initiations are processed inline, so the
    /// reference's measure (the depth of a handshake queue) has no
    /// equivalent here; their rate is what costs CPU.
    load: Mutex<LoadMeter>,
    /// Responder-side cookie validator + reply generator.
    cookie_checker: Mutex<crate::wg::cookie::CookieChecker>,
    /// Handshakes per source address, limited under load.
    ratelimiter: Mutex<crate::wg::ratelimiter::RateLimiter>,
    /// The multiplexer this handler is a member of, if any. Its members
    /// share one UDP port and a packet is routed to them by receiver index,
    /// so an index has to be unique across all of them, not only here.
    group: RwLock<Weak<crate::wg::MultiHandler>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler")
            .field("public_key", &self.public_key)
            .field("load_threshold", &self.load_threshold)
            .finish()
    }
}

impl Handler {
    /// Build a handler from `cfg`. Generates a fresh private key if
    /// `cfg.private_key` is zero.
    pub fn new(cfg: Config) -> Result<Arc<Self>> {
        let priv_key = if cfg.private_key.is_zero() {
            crate::wg::crypto::generate_private_key()?
        } else {
            cfg.private_key
        };
        let pub_key = x25519_public(&priv_key);

        let lt = cfg.load_threshold.unwrap_or(DEFAULT_LOAD_THRESHOLD);

        Ok(Arc::new(Handler {
            private_key: priv_key,
            public_key: pub_key,
            peers: RwLock::new(HashMap::new()),
            handshakes: Mutex::new(HashMap::new()),
            keypairs: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            on_unknown_peer: Mutex::new(cfg.on_unknown_peer),
            unknown_peer_limit: cfg
                .unknown_peer_limit
                .unwrap_or(crate::wg::constants::DEFAULT_UNKNOWN_PEER_LIMIT),
            load_threshold: lt,
            load: Mutex::new(LoadMeter::default()),
            cookie_checker: Mutex::new(crate::wg::cookie::CookieChecker::new(&pub_key)),
            ratelimiter: Mutex::default(),
            group: RwLock::new(Weak::new()),
        }))
    }

    /// This identity's public key.
    #[inline]
    pub fn public_key(&self) -> NoisePublicKey {
        self.public_key
    }

    #[inline]
    pub(crate) fn private_key(&self) -> &NoisePrivateKey {
        &self.private_key
    }

    /// Add (or refresh) an authorized peer with no preshared key.
    ///
    /// Refreshing a known peer clears any [expiry](Self::set_peer_expiry),
    /// so a peer that lapsed can be authorized again. A preshared key it
    /// already has is kept: dropping it here would quietly weaken the
    /// handshake, and [`Adapter::add_peer`](crate::wg::Adapter::add_peer)
    /// calls this on every identity. Use [`remove_peer`](Self::remove_peer)
    /// first to take the key away.
    pub fn add_peer(&self, peer_key: NoisePublicKey) {
        Self::add_peer_locked(&mut self.peers.write().expect("peers lock"), peer_key);
    }

    fn add_peer_locked(peers: &mut HashMap<NoisePublicKey, PeerEntry>, peer_key: NoisePublicKey) {
        match peers.get_mut(&peer_key) {
            // Update in place, as add_peer_with_psk does, to keep the replay
            // state.
            Some(p) => p.expires_at = None,
            None => {
                peers.insert(
                    peer_key,
                    PeerEntry::new(peer_key, NoisePresharedKey::zero(), false),
                );
            }
        }
    }

    /// Install (or replace) the callback invoked when a handshake arrives from
    /// an unauthorized peer. Lets callers set the hook after construction —
    /// notably the [`Adapter`](crate::wg::Adapter) applies it to every handler
    /// in multi-handler mode.
    pub fn set_on_unknown_peer(&self, cb: UnknownPeerFn) {
        *self.on_unknown_peer.lock().expect("unknown lock") = Some(cb);
    }

    /// Add (or refresh) an authorized peer with a preshared key. Refreshing
    /// a known peer replaces its key and clears any expiry.
    pub fn add_peer_with_psk(&self, peer_key: NoisePublicKey, psk: NoisePresharedKey) {
        let mut peers = self.peers.write().expect("peers lock");
        match peers.get_mut(&peer_key) {
            // Update in place: replacing the entry would forget the peer's
            // last initiation timestamp, and a captured initiation could
            // then be replayed once.
            Some(p) => {
                p.preshared_key = psk;
                p.has_psk = true;
                p.expires_at = None;
            }
            None => {
                peers.insert(peer_key, PeerEntry::new(peer_key, psk, true));
            }
        }
    }

    /// Remove a peer and tear down all session state belonging to it,
    /// including initiations still waiting for an answer: a response to one
    /// would otherwise install a session for the revoked key, even after the
    /// peer is authorized again under new terms.
    pub fn remove_peer(&self, peer_key: &NoisePublicKey) {
        // Deauthorize first: install() checks authorization under the
        // sessions lock, so a handshake finishing concurrently either sees
        // the peer gone or installs before the sweep below removes it.
        self.peers.write().expect("peers lock").remove(peer_key);

        self.handshakes
            .lock()
            .expect("handshakes lock")
            .retain(|_, hs| hs.remote_static != *peer_key);
        let mut sess = self.sessions.write().expect("sessions lock");
        sess.remove(peer_key);
        // Sweep the index rather than only the session's slots, so nothing
        // indexed for the peer outlives it whichever way it got there.
        self.keypairs
            .write()
            .expect("keypairs lock")
            .retain(|_, kp| kp.peer_key != *peer_key);
    }

    /// True if the peer is in the authorized table and (if `expires_at` is
    /// set) the deadline has not passed.
    pub fn is_authorized_peer(&self, peer_key: &NoisePublicKey) -> bool {
        let peers = self.peers.read().expect("peers lock");
        let Some(p) = peers.get(peer_key) else {
            return false;
        };
        if let Some(exp) = p.expires_at
            && Instant::now() > exp
        {
            return false;
        }
        true
    }

    /// Set an expiry time on an existing peer. No effect if the peer is unknown.
    ///
    /// Past `at` the peer counts as unauthorized, though it stays in the
    /// table: its handshakes are refused (or handed to the unknown-peer
    /// callback), and sessions already established stop at once, both ways
    /// -- [`encrypt`](Self::encrypt) refuses them and its transport packets
    /// are refused -- rather than running on until they expire by
    /// themselves. [`add_peer`](Self::add_peer) or
    /// [`add_peer_with_psk`](Self::add_peer_with_psk) clears the expiry and
    /// authorizes the peer again.
    pub fn set_peer_expiry(&self, peer_key: &NoisePublicKey, at: Instant) {
        let mut peers = self.peers.write().expect("peers lock");
        if let Some(p) = peers.get_mut(peer_key) {
            p.expires_at = Some(at);
        }
    }

    /// List authorized peer keys.
    pub fn peers(&self) -> Vec<NoisePublicKey> {
        self.peers
            .read()
            .expect("peers lock")
            .keys()
            .copied()
            .collect()
    }

    /// What the handler knows about an authorized peer, or `None` if the
    /// key is not in its table. An expired peer is still reported, with its
    /// [`expires_at`](PeerInfo::expires_at).
    pub fn get_peer_info(&self, peer_key: &NoisePublicKey) -> Option<PeerInfo> {
        let peers = self.peers.read().expect("peers lock");
        peers.get(peer_key).map(|p| PeerInfo {
            public_key: p.public_key,
            has_psk: p.has_psk,
            created_at: p.created_at,
            expires_at: p.expires_at,
            last_handshake: p.last_handshake,
        })
    }

    /// Return the preshared key for `peer_key`, or zero if none.
    pub(crate) fn preshared_key(&self, peer_key: &NoisePublicKey) -> NoisePresharedKey {
        let peers = self.peers.read().expect("peers lock");
        match peers.get(peer_key) {
            Some(p) if p.has_psk => p.preshared_key.clone(),
            _ => NoisePresharedKey::zero(),
        }
    }

    /// Accept an initiation from `peer_key` carrying timestamp `ts`,
    /// arriving at `now`, and record it; false to refuse it. Refused are a
    /// timestamp not strictly greater than the last accepted (a replay), and,
    /// as in the reference's wg_noise_handshake_consume_initiation, any
    /// initiation within MIN_INITIATION_INTERVAL of the last accepted: a peer
    /// (or anyone replaying its fresh initiations faster than it rekeys) could
    /// otherwise make us run the responder's DH work and replace its session
    /// as fast as it could send.
    pub(crate) fn accept_peer_initiation(
        &self,
        peer_key: &NoisePublicKey,
        ts: &[u8],
        now: Instant,
    ) -> Result<()> {
        let mut peers = self.peers.write().expect("peers lock");
        let Some(p) = peers.get_mut(peer_key) else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unauthorized peer",
            ));
        };
        if p.has_timestamp && ts <= &p.last_timestamp[..] {
            return Err(io::Error::other("replayed handshake timestamp"));
        }
        if p.last_initiation_consumed
            .is_some_and(|t| now.saturating_duration_since(t) < MIN_INITIATION_INTERVAL)
        {
            return Err(io::Error::other("handshake initiations too frequent"));
        }
        let n = ts.len().min(TAI64N_TIMESTAMP_SIZE);
        p.last_timestamp[..n].copy_from_slice(&ts[..n]);
        p.has_timestamp = true;
        // Never moved back, as in the reference, should `now` be older.
        if p.last_initiation_consumed.is_none_or(|t| t < now) {
            p.last_initiation_consumed = Some(now);
        }
        p.last_handshake = Some(now);
        Ok(())
    }

    pub(crate) fn touch_peer_handshake(&self, peer_key: &NoisePublicKey) {
        let mut peers = self.peers.write().expect("peers lock");
        if let Some(p) = peers.get_mut(peer_key) {
            p.last_handshake = Some(Instant::now());
        }
    }

    pub(crate) fn notify_unknown_peer(
        &self,
        peer_key: &NoisePublicKey,
        addr: &SocketAddr,
        packet: &[u8],
    ) {
        // Clone the callback out and release the lock before calling it: in
        // edition 2024 an `if let` scrutinee's guard lives through the
        // block, and a callback that calls set_on_unknown_peer would wait
        // on itself.
        let cb = self.on_unknown_peer.lock().expect("unknown lock").clone();
        let Some(cb) = cb else { return };
        // The callback is expected to authorize the peer and feed the packet
        // back in. If that still leaves it unauthorized (it expired again,
        // was removed meanwhile, or the callback re-feeds without
        // authorizing), calling back again from inside the call recurses
        // until the stack runs out. The packet is refused either way.
        thread_local! {
            static IN_UNKNOWN_PEER_CB: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        }
        if IN_UNKNOWN_PEER_CB.with(|f| f.replace(true)) {
            return;
        }
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                IN_UNKNOWN_PEER_CB.with(|f| f.set(false));
            }
        }
        let _reset = Reset;
        cb(*peer_key, *addr, packet);
    }

    /// Process one incoming UDP datagram. Dispatches on the WireGuard type byte.
    pub fn process_packet(&self, data: &[u8], remote_addr: &SocketAddr) -> Result<PacketResult> {
        if data.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet too short",
            ));
        }
        let msg_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        use crate::wg::constants::{
            MESSAGE_COOKIE_REPLY_TYPE, MESSAGE_INITIATION_TYPE, MESSAGE_RESPONSE_TYPE,
            MESSAGE_TRANSPORT_TYPE,
        };
        match msg_type {
            MESSAGE_INITIATION_TYPE => {
                crate::wg::handshake::process_handshake_initiation(self, data, remote_addr)
            }
            MESSAGE_RESPONSE_TYPE => crate::wg::handshake::process_handshake_response(self, data),
            MESSAGE_COOKIE_REPLY_TYPE => crate::wg::handshake::process_cookie_reply(self, data),
            MESSAGE_TRANSPORT_TYPE => crate::wg::transport::process_data_packet(self, data),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown message type: {}", other),
            )),
        }
    }

    /// Encrypt `data` for `peer_key`. Empty `data` produces a keepalive.
    pub fn encrypt(&self, data: &[u8], peer_key: &NoisePublicKey) -> Result<Vec<u8>> {
        match crate::wg::transport::encrypt_data_packet(self, data, peer_key) {
            Ok(v) => Ok(v),
            Err(EncryptError::RekeyRequired(v)) => Ok(v),
            Err(e) => Err(e.into()),
        }
    }

    /// Generate a keepalive packet.
    pub fn generate_keepalive(&self, peer_key: &NoisePublicKey) -> Result<Vec<u8>> {
        self.encrypt(&[], peer_key)
    }

    /// Initiate a handshake to a peer. The peer must be authorized first.
    ///
    /// A responder, this one included, accepts at most 50 initiations a
    /// second from one peer and only with a newer timestamp than the last,
    /// and timestamps are only precise to about 17 ms: of two initiations
    /// made within 20 ms of each other, the second is refused if the first
    /// was accepted.
    pub fn initiate_handshake(&self, peer_key: &NoisePublicKey) -> Result<Vec<u8>> {
        crate::wg::handshake::initiate_handshake(self, peer_key)
    }

    /// True if `peer_key` has a current keypair that can still send: one
    /// past `REJECT_AFTER_TIME` or `REJECT_AFTER_MESSAGES` stays installed
    /// until the next [`maintenance`](Self::maintenance), but
    /// [`encrypt`](Self::encrypt) refuses it. The same goes for every
    /// keypair of a peer past its [expiry](Self::set_peer_expiry).
    pub fn has_session(&self, peer_key: &NoisePublicKey) -> bool {
        self.is_authorized_peer(peer_key)
            && self
                .sessions
                .read()
                .expect("sessions lock")
                .get(peer_key)
                .and_then(|s| s.keypair_current.as_ref())
                .is_some_and(|kp| {
                    kp.created.elapsed() <= REJECT_AFTER_TIME
                        && kp.send_counter.load(std::sync::atomic::Ordering::Relaxed)
                            < crate::wg::constants::REJECT_AFTER_MESSAGES
                })
    }

    /// Keep sending keepalives to `peer_key` whenever nothing else has gone
    /// to it for `interval`, so a NAT or stateful firewall between the two
    /// keeps its mapping (whitepaper §6.5). `None` turns it off.
    pub fn set_persistent_keepalive(&self, peer_key: &NoisePublicKey, interval: Option<Duration>) {
        self.with_timers(peer_key, |t| t.persistent_keepalive = interval);
    }

    /// Run the protocol timers (whitepaper §6) and return what they want
    /// sent: handshake retries and rekeys, keepalives, and notice of
    /// handshakes abandoned after `REKEY_ATTEMPT_TIME`. Call this every
    /// 100 ms or so. [`Server`](crate::wg::Server) does it for you; without
    /// one, the caller sends each packet to the peer's endpoint.
    pub fn poll_timers(&self) -> Vec<TimerAction> {
        self.poll_timers_at(Instant::now())
    }

    pub(crate) fn poll_timers_at(&self, now: Instant) -> Vec<TimerAction> {
        let peers: Vec<NoisePublicKey> = self.peers().into_iter().collect();
        let mut out = Vec::new();
        for peer in peers {
            // Claim the initiation under the timers lock, where it is
            // decided: initiate_handshake records it only after its DH
            // work, and a concurrent poll (the maintenance thread and an
            // inline one from a send) would otherwise send a second, which
            // supersedes the first (whitepaper §6.1).
            let Some((due, keepalive)) = self.with_timers(&peer, |t| {
                let due = t.handshake_due(now);
                if due == Some(true) {
                    t.initiation_sent(now);
                }
                (due, t.keepalive_due(now))
            }) else {
                continue;
            };
            match due {
                None => out.push(TimerAction::HandshakeFailed { peer }),
                Some(true) => match crate::wg::handshake::initiate_handshake_at(self, &peer, now) {
                    Ok(packet) => out.push(TimerAction::SendHandshake { peer, packet }),
                    // Nothing can answer an initiation that never went out,
                    // so what waits on this handshake would wait in vain.
                    Err(_) => out.push(TimerAction::HandshakeFailed { peer }),
                },
                Some(false) => {}
            }
            if keepalive {
                if self.has_session(&peer) {
                    if let Ok(packet) = self.encrypt(&[], &peer) {
                        out.push(TimerAction::SendKeepalive { peer, packet });
                    }
                } else {
                    // A keepalive needs a keypair; get one. The passive
                    // keepalive fires once, as the reference's one-shot
                    // timer does: left pending, it asked for a new handshake
                    // on every poll, each abandoned attempt was followed at
                    // once by another, and an offline peer drew initiations
                    // forever. A peer no longer authorized gets none at all:
                    // its initiation cannot even be built, and asking would
                    // only report the handshake failed on every poll.
                    let authorized = self.is_authorized_peer(&peer);
                    self.with_timers(&peer, |t| {
                        t.keepalive_due_since = None;
                        if authorized {
                            t.want_handshake = true;
                        }
                    });
                }
            }
        }
        out
    }

    pub(crate) fn with_timers<R>(
        &self,
        peer_key: &NoisePublicKey,
        f: impl FnOnce(&mut PeerTimers) -> R,
    ) -> Option<R> {
        let peers = self.peers.read().expect("peers lock");
        let p = peers.get(peer_key)?;
        let mut t = p.timers.lock().expect("timers lock");
        Some(f(&mut t))
    }

    /// Run periodic cleanup: drop stale handshakes and inactive sessions.
    pub fn maintenance(&self) {
        self.cleanup_handshakes();
        self.cleanup_sessions();
    }

    fn cleanup_handshakes(&self) {
        let mut hs = self.handshakes.lock().expect("handshakes lock");
        let n = Instant::now();
        hs.retain(|_, h| n.duration_since(h.created) <= REJECT_AFTER_TIME);
    }

    fn cleanup_sessions(&self) {
        let n = Instant::now();
        let mut sess = self.sessions.write().expect("sessions lock");
        let mut kps = self.keypairs.write().expect("keypairs lock");
        // A keypair past REJECT_AFTER_TIME can neither send nor receive, so
        // its index entry and slot only take up room.
        sess.retain(|_, s| {
            for slot in [
                &mut s.keypair_current,
                &mut s.keypair_prev,
                &mut s.keypair_next,
            ] {
                if slot
                    .as_ref()
                    .is_some_and(|kp| n.duration_since(kp.created) > REJECT_AFTER_TIME)
                {
                    kps.remove(&slot.take().unwrap().local_index);
                }
            }
            let last_active = s.last_received.max(s.last_sent);
            n.duration_since(last_active) <= REJECT_AFTER_TIME
                || s.keypair_current.is_some()
                || s.keypair_next.is_some()
        });
    }

    /// Drop all per-connection state. Peer authorizations survive.
    pub fn close(&self) -> Result<()> {
        self.handshakes.lock().expect("handshakes lock").clear();
        self.keypairs.write().expect("keypairs lock").clear();
        self.sessions.write().expect("sessions lock").clear();
        Ok(())
    }

    // --- Handshake-table accessors used by handshake.rs ------------------

    pub(crate) fn set_group(&self, group: Weak<crate::wg::MultiHandler>) {
        *self.group.write().expect("group lock") = group;
    }

    /// Leave `group`, unless the handler has joined another since.
    pub(crate) fn leave_group(&self, group: &Weak<crate::wg::MultiHandler>) {
        let mut g = self.group.write().expect("group lock");
        if Weak::ptr_eq(&g, group) {
            *g = Weak::new();
        }
    }

    /// Draw a fresh, non-zero local index that no pending handshake or
    /// keypair uses, as the reference's index hashtable does. A random u32
    /// alone could repeat one in use and replace another peer's entry.
    ///
    /// In a [`MultiHandler`](crate::wg::MultiHandler) the index must also be
    /// free in every other member: packets are routed to the first member
    /// that owns their receiver index, so one index held by two members
    /// sends one member's traffic to the other, where it fails to decrypt.
    /// With enough sessions per member, a draw checked only locally does
    /// that routinely.
    pub(crate) fn allocate_index(&self) -> Result<u32> {
        self.allocate_index_with(|| {
            let mut buf = [0u8; 4];
            crate::wg::crypto::fill_random(&mut buf)?;
            Ok(u32::from_le_bytes(buf))
        })
    }

    fn allocate_index_with(&self, mut draw: impl FnMut() -> Result<u32>) -> Result<u32> {
        let group = self.group.read().expect("group lock").upgrade();
        let members = group.map(|mh| mh.handlers()).unwrap_or_default();
        // Each table is looked at under its own lock, one at a time: two
        // members allocating at once would otherwise each hold their own
        // while waiting for the other's. The tables are bounded far below
        // 2^32, so this ends quickly.
        let in_use = |h: &Handler, idx| h.has_handshake_index(idx) || h.has_keypair_index(idx);
        loop {
            let idx = draw()?;
            if idx != 0
                && !in_use(self, idx)
                && !members
                    .iter()
                    .any(|m| !std::ptr::eq(&**m, self) && in_use(m, idx))
            {
                return Ok(idx);
            }
        }
    }

    pub(crate) fn insert_handshake(
        &self,
        idx: u32,
        hs: crate::wg::handshake::Handshake,
    ) -> Result<()> {
        let mut g = self.handshakes.lock().expect("handshakes lock");
        // One pending initiation per peer, as in the reference: a retry
        // supersedes the last, and a response to the old one is refused.
        // Keeping them would stack up an entry per retry.
        g.retain(|_, old| old.remote_static != hs.remote_static);
        // allocate_index handed out a free index, but another handshake may
        // have drawn the same one since: refuse rather than replace it.
        if g.contains_key(&idx) || self.has_keypair_index(idx) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "local index in use",
            ));
        }
        if g.len() >= crate::wg::constants::MAX_HANDSHAKES {
            return Err(io::Error::other("handshake table full"));
        }
        g.insert(idx, hs);
        Ok(())
    }

    /// A copy of the pending handshake at `idx`. The entry stays in place
    /// until [`complete_handshake`](Self::complete_handshake), so a forged
    /// response that fails authentication cannot discard it.
    pub(crate) fn peek_handshake(&self, idx: u32) -> Option<crate::wg::handshake::Handshake> {
        self.handshakes
            .lock()
            .expect("handshakes lock")
            .get(&idx)
            .cloned()
    }

    /// Remove the pending handshake at `idx` once a response for it has
    /// authenticated. False if it is already gone: another copy of the same
    /// response completed it first.
    pub(crate) fn complete_handshake(&self, idx: u32) -> bool {
        self.handshakes
            .lock()
            .expect("handshakes lock")
            .remove(&idx)
            .is_some()
    }

    pub(crate) fn has_handshake_index(&self, idx: u32) -> bool {
        self.handshakes
            .lock()
            .expect("handshakes lock")
            .contains_key(&idx)
    }

    pub(crate) fn lookup_keypair(&self, idx: u32) -> Option<Arc<Keypair>> {
        self.keypairs
            .read()
            .expect("keypairs lock")
            .get(&idx)
            .cloned()
    }

    pub(crate) fn has_keypair_index(&self, idx: u32) -> bool {
        self.keypairs
            .read()
            .expect("keypairs lock")
            .contains_key(&idx)
    }

    /// Index `kp` and give it a slot in `peer_key`'s session, via `place`,
    /// which returns the keypairs it displaced; their index entries go too.
    /// Capacity is checked before anything is touched, so a refusal leaves
    /// no orphan entry behind.
    fn install(
        &self,
        peer_key: NoisePublicKey,
        kp: Arc<Keypair>,
        place: impl FnOnce(&mut Session, Arc<Keypair>) -> Vec<Arc<Keypair>>,
    ) -> Result<()> {
        use crate::wg::constants::{MAX_HANDSHAKES, MAX_SESSIONS};
        let mut sess = self.sessions.write().expect("sessions lock");
        let mut kps = self.keypairs.write().expect("keypairs lock");
        // Checked here, under the sessions lock, and not only by the caller:
        // remove_peer deauthorizes and then sweeps under this lock, so a
        // handshake that finishes while the peer is being removed cannot
        // slip a session in after the sweep.
        if !self.is_authorized_peer(&peer_key) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "peer not authorized",
            ));
        }
        if sess.len() >= MAX_SESSIONS && !sess.contains_key(&peer_key) {
            return Err(io::Error::other("session table full"));
        }
        if kps.len() >= MAX_HANDSHAKES {
            return Err(io::Error::other("keypair table full"));
        }
        // The index was free when allocated; one drawn again meanwhile must
        // not take over another keypair's entry.
        if kps.contains_key(&kp.local_index) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "local index in use",
            ));
        }
        kps.insert(kp.local_index, kp.clone());
        let s = sess.entry(peer_key).or_insert_with(|| Session {
            keypair_current: None,
            keypair_prev: None,
            keypair_next: None,
            last_received: Instant::now(),
            last_sent: Instant::now(),
            peer_key,
        });
        for old in place(s, kp) {
            kps.remove(&old.local_index);
        }
        Ok(())
    }

    /// Install the keypair from a handshake we initiated. The response
    /// proved the peer holds it, so it becomes current at once.
    ///
    /// An unconfirmed next keypair means both ends initiated at once and we
    /// answered the peer's too. The peer, once our response reaches it,
    /// sends with that one, so it is kept as previous (in place of current,
    /// which it supersedes), as the reference's add_new_keypair does.
    /// Dropping it cut traffic from the peer until the next rekey.
    pub(crate) fn install_initiator_keypair(
        &self,
        peer_key: NoisePublicKey,
        kp: Arc<Keypair>,
    ) -> Result<()> {
        self.install(peer_key, kp, |s, kp| {
            let mut gone: Vec<_> = s.keypair_prev.take().into_iter().collect();
            s.keypair_prev = match s.keypair_next.take() {
                Some(next) => {
                    gone.extend(s.keypair_current.take());
                    Some(next)
                }
                None => s.keypair_current.take(),
            };
            s.keypair_current = Some(kp);
            gone
        })
    }

    /// Install the keypair from a handshake we answered. Held as next until
    /// the initiator's first transport packet shows it got our response.
    pub(crate) fn install_responder_keypair(
        &self,
        peer_key: NoisePublicKey,
        kp: Arc<Keypair>,
    ) -> Result<()> {
        self.install(peer_key, kp, |s, kp| {
            s.keypair_next.replace(kp).into_iter().collect()
        })
    }

    pub(crate) fn is_current_keypair(&self, kp: &Arc<Keypair>) -> bool {
        self.sessions
            .read()
            .expect("sessions lock")
            .get(&kp.peer_key)
            .and_then(|s| s.keypair_current.as_ref())
            .is_some_and(|c| Arc::ptr_eq(c, kp))
    }

    /// A transport packet authenticated under `kp`. If that is the session's
    /// unconfirmed next keypair, the initiator has it: make it current.
    pub(crate) fn received_with_keypair(&self, kp: &Arc<Keypair>) {
        let mut sess = self.sessions.write().expect("sessions lock");
        let Some(s) = sess.get_mut(&kp.peer_key) else {
            return;
        };
        if !s.keypair_next.as_ref().is_some_and(|n| Arc::ptr_eq(n, kp)) {
            return;
        }
        let next = s.keypair_next.take();
        let old_prev = std::mem::replace(&mut s.keypair_prev, s.keypair_current.take());
        s.keypair_current = next;
        drop(sess);
        if let Some(old) = old_prev {
            self.keypairs
                .write()
                .expect("keypairs lock")
                .remove(&old.local_index);
        }
        // The handshake is complete from our side too, as in the reference
        // (wg_timers_handshake_complete). An attempt of our own still under
        // way, after both ends initiated at once, would otherwise keep
        // retrying for REKEY_ATTEMPT_TIME, replacing this keypair each time.
        self.with_timers(&kp.peer_key, |t| t.handshake_complete());
    }

    /// Snapshot of `(last_received, last_sent)` for `peer_key`.
    pub fn session_info(&self, peer_key: &NoisePublicKey) -> Option<(Instant, Instant)> {
        self.sessions
            .read()
            .expect("sessions lock")
            .get(peer_key)
            .map(|s| (s.last_received, s.last_sent))
    }

    pub(crate) fn touch_session_received(&self, peer_key: &NoisePublicKey) {
        if let Some(s) = self
            .sessions
            .write()
            .expect("sessions lock")
            .get_mut(peer_key)
        {
            s.last_received = Instant::now();
        }
    }

    pub(crate) fn touch_session_sent(&self, peer_key: &NoisePublicKey) {
        if let Some(s) = self
            .sessions
            .write()
            .expect("sessions lock")
            .get_mut(peer_key)
        {
            s.last_sent = Instant::now();
        }
    }

    /// Return the current keypair and its age. Updates `last_sent` as a
    /// side effect. The `Arc` keeps the keypair alive for the caller without
    /// holding the sessions lock, and releases it when dropped.
    pub(crate) fn with_current_keypair(
        &self,
        peer_key: &NoisePublicKey,
    ) -> Option<(Arc<Keypair>, Duration)> {
        let kp = {
            let s = self.sessions.read().expect("sessions lock");
            s.get(peer_key)
                .and_then(|s| s.keypair_current.as_ref().cloned())?
        };
        self.touch_session_sent(peer_key);
        let age = Instant::now().duration_since(kp.created);
        Some((kp, age))
    }

    /// Count one incoming initiation and say whether we are under load, the
    /// trigger for requiring a valid MAC2. As in the reference, being under
    /// load lasts a second past the last time the threshold was exceeded,
    /// so a flood does not flicker between the two paths.
    pub(crate) fn note_initiation_under_load(&self) -> bool {
        let now = Instant::now();
        let mut m = self.load.lock().expect("load lock");
        if m.window_start
            .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1))
        {
            m.window_start = Some(now);
            m.count = 0;
        }
        m.count = m.count.saturating_add(1);
        if m.count > self.load_threshold {
            m.until = Some(now + Duration::from_secs(1));
        }
        m.until.is_some_and(|u| now < u)
    }

    // --- cookie integration ------------------------------------------------

    /// Validate MAC1 on an incoming handshake against our own public key.
    pub(crate) fn cookie_check_mac1(&self, data: &[u8]) -> bool {
        self.cookie_checker
            .lock()
            .expect("cookie lock")
            .check_mac1(data)
    }

    /// Validate MAC2 (under-load path).
    pub(crate) fn cookie_check_mac2(&self, data: &[u8], src: &[u8]) -> bool {
        self.cookie_checker
            .lock()
            .expect("cookie lock")
            .check_mac2(data, src)
    }

    /// Whether a handshake from `ip` may be processed now, under load and
    /// with a valid MAC2.
    pub(crate) fn ratelimit_allow(&self, ip: std::net::IpAddr) -> bool {
        self.ratelimiter
            .lock()
            .expect("ratelimiter lock")
            .allow(ip, Instant::now())
    }

    /// Mint a cookie-reply message for a requester.
    pub(crate) fn cookie_generate_reply(
        &self,
        src: &[u8],
        receiver_idx: u32,
        init_mac1: &[u8],
    ) -> Result<Vec<u8>> {
        self.cookie_checker
            .lock()
            .expect("cookie lock")
            .generate_reply(src, receiver_idx, init_mac1)
    }

    /// Write MAC1 (+ MAC2 if a cookie is held) into an outgoing handshake for
    /// `peer`. Falls back to a plain MAC1 if the peer is unknown.
    pub(crate) fn cookie_add_macs(&self, peer: &NoisePublicKey, pkt: &mut [u8]) {
        let peers = self.peers.read().expect("peers lock");
        if let Some(entry) = peers.get(peer) {
            entry
                .cookie_gen
                .lock()
                .expect("cookie_gen lock")
                .add_macs(pkt);
        } else {
            // Unknown peer: still write a valid MAC1.
            let n = pkt.len();
            if n >= crate::wg::constants::BLAKE2S_128_SIZE * 2 {
                let smac2 = n - crate::wg::constants::BLAKE2S_128_SIZE;
                let smac1 = smac2 - crate::wg::constants::BLAKE2S_128_SIZE;
                let key = crate::wg::crypto::calculate_mac1_key(peer);
                let mac1 = crate::wg::crypto::blake2s_mac_128(&key, &pkt[..smac1]);
                pkt[smac1..smac2].copy_from_slice(&mac1);
            }
        }
    }

    /// Look up the peer static key associated with a pending handshake by its
    /// (our) local sender index.
    pub(crate) fn handshake_remote_static(&self, idx: u32) -> Option<NoisePublicKey> {
        self.handshakes
            .lock()
            .expect("handshakes lock")
            .get(&idx)
            .map(|hs| hs.remote_static)
    }

    /// Decrypt and store a cookie received in a reply, for `peer`.
    pub(crate) fn peer_consume_cookie(
        &self,
        peer: &NoisePublicKey,
        nonce: &[u8; 24],
        ct: &[u8],
    ) -> Result<()> {
        let peers = self.peers.read().expect("peers lock");
        let entry = match peers.get(peer) {
            Some(e) => e,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no peer for cookie reply",
                ));
            }
        };

        entry
            .cookie_gen
            .lock()
            .expect("cookie_gen lock")
            .consume_reply(nonce, ct)
    }

    /// [`add_peer`](Self::add_peer) for a peer accepted from
    /// `on_unknown_peer`: refused if it is new and the table already holds
    /// [`unknown_peer_limit`](Config::unknown_peer_limit) peers.
    pub(crate) fn add_unknown_peer(&self, peer_key: NoisePublicKey) -> Result<()> {
        let mut peers = self.peers.write().expect("peers lock");
        if !peers.contains_key(&peer_key) && peers.len() >= self.unknown_peer_limit {
            return Err(io::Error::other("peer table full"));
        }
        Self::add_peer_locked(&mut peers, peer_key);
        Ok(())
    }

    /// Authorize a previously unknown peer and complete its handshake by
    /// re-running the initiation through the responder path. Returns the
    /// raw response bytes the caller should send back to `remote_addr`.
    ///
    /// A new peer is refused once the handler has
    /// [`unknown_peer_limit`](Config::unknown_peer_limit) peers.
    pub fn accept_unknown_peer(
        &self,
        peer_key: NoisePublicKey,
        initiation_packet: &[u8],
        remote_addr: &SocketAddr,
    ) -> Result<Vec<u8>> {
        self.add_unknown_peer(peer_key)?;
        // Re-running an initiation from a peer still unauthorized would only
        // be refused again, after invoking on_unknown_peer once more.
        if !self.is_authorized_peer(&peer_key) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "peer not authorized after adding it",
            ));
        }
        let res = self.process_packet(initiation_packet, remote_addr)?;
        Ok(res.response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::net::SocketAddrV4;

    fn loopback() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 51820))
    }

    #[test]
    fn handler_roundtrip_handshake_and_transport() {
        // Build two handlers: A initiates to B.
        let a = Handler::new(Config::default()).unwrap();
        let b = Handler::new(Config::default()).unwrap();
        a.add_peer(b.public_key());
        b.add_peer(a.public_key());

        let init = a.initiate_handshake(&b.public_key()).unwrap();
        let addr = loopback();
        let resp = b.process_packet(&init, &addr).unwrap();
        assert_eq!(resp.ty, PacketType::HandshakeResponse);
        assert_eq!(resp.peer_key, a.public_key());

        // A processes the response; should produce a keepalive.
        let res = a.process_packet(&resp.response, &addr).unwrap();
        assert_eq!(res.ty, PacketType::HandshakeResponse);
        assert!(!res.response.is_empty(), "expect keepalive ciphertext");

        // B decodes the keepalive.
        let kp_res = b.process_packet(&res.response, &addr).unwrap();
        assert_eq!(kp_res.ty, PacketType::Keepalive);
        assert!(kp_res.data.is_empty());

        // Now A sends a real payload to B.
        let pt = b"hello over wg";
        let enc = a.encrypt(pt, &b.public_key()).unwrap();
        let dec = b.process_packet(&enc, &addr).unwrap();
        assert_eq!(dec.ty, PacketType::TransportData);
        assert_eq!(dec.data, pt);
    }

    #[test]
    fn encrypting_does_not_leak_the_keypair() {
        let a = Handler::new(Config::default()).unwrap();
        let b = Handler::new(Config::default()).unwrap();
        a.add_peer(b.public_key());
        b.add_peer(a.public_key());
        let addr = loopback();
        let init = a.initiate_handshake(&b.public_key()).unwrap();
        let resp = b.process_packet(&init, &addr).unwrap();
        a.process_packet(&resp.response, &addr).unwrap();

        let kp = a.sessions.read().unwrap()[&b.public_key()]
            .keypair_current
            .clone()
            .unwrap();
        let before = Arc::strong_count(&kp);
        for _ in 0..100 {
            a.encrypt(b"x", &b.public_key()).unwrap();
        }
        assert_eq!(
            Arc::strong_count(&kp),
            before,
            "each encrypt leaked a reference"
        );
    }

    /// Full handshake a→b, returning the keepalive a sent. Returns only
    /// once another initiation from a would be accepted.
    fn handshake(a: &Handler, b: &Handler) -> Vec<u8> {
        let addr = loopback();
        let init = a.initiate_handshake(&b.public_key()).unwrap();
        let resp = b.process_packet(&init, &addr).unwrap();
        let ka = a.process_packet(&resp.response, &addr).unwrap();
        b.process_packet(&ka.response, &addr).unwrap();
        pace();
        ka.response
    }

    /// Wait until a responder takes another initiation from the same peer:
    /// it refuses one within MIN_INITIATION_INTERVAL of the last, and the
    /// timestamps of two made closer together than that may be equal.
    fn pace() {
        std::thread::sleep(MIN_INITIATION_INTERVAL + Duration::from_millis(5));
    }

    /// As the reference does, a peer's initiations are accepted at most
    /// INITIATIONS_PER_SECOND times a second, each with a timestamp newer
    /// than the last. Before, any newer timestamp was taken at once, so a
    /// peer could have the responder redo its DH work and replace the
    /// session as fast as it could send.
    #[test]
    fn a_peers_initiations_are_accepted_at_most_50_a_second() {
        let (a, b) = pair();
        let peer = b.public_key();
        let ts = |n: u32| crate::wg::time::encode_tai64n(1_000, n << 24);
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        assert!(a.accept_peer_initiation(&peer, &ts(1), at(0)).is_ok());
        assert!(a.accept_peer_initiation(&peer, &ts(2), at(10)).is_err());
        assert!(a.accept_peer_initiation(&peer, &ts(2), at(19)).is_err());
        assert!(a.accept_peer_initiation(&peer, &ts(2), at(20)).is_ok());
        // The replay check still stands on its own.
        assert!(a.accept_peer_initiation(&peer, &ts(2), at(100)).is_err());
        assert!(a.accept_peer_initiation(&peer, &ts(3), at(100)).is_ok());

        // End to end: an initiation right after an accepted one is refused.
        handshake(&a, &b);
        let init = a.initiate_handshake(&b.public_key()).unwrap();
        b.process_packet(&init, &loopback()).unwrap();
        let init = a.initiate_handshake(&b.public_key()).unwrap();
        assert!(b.process_packet(&init, &loopback()).is_err());
    }

    fn pair() -> (Arc<Handler>, Arc<Handler>) {
        let a = Handler::new(Config::default()).unwrap();
        let b = Handler::new(Config::default()).unwrap();
        a.add_peer(b.public_key());
        b.add_peer(a.public_key());
        (a, b)
    }

    /// The responder must not send with a keypair the initiator may never
    /// have derived (whitepaper §5.4.6): if the response is lost, traffic
    /// from the responder has to keep working on the old keypair.
    #[test]
    fn responder_keeps_sending_on_the_old_keypair_until_confirmed() {
        let (a, b) = pair();
        let addr = loopback();
        handshake(&a, &b);

        // Rekey, but the response never reaches a.
        let init = a.initiate_handshake(&b.public_key()).unwrap();
        let _lost = b.process_packet(&init, &addr).unwrap();
        let pkt = b.encrypt(b"still here", &a.public_key()).unwrap();
        let got = a.process_packet(&pkt, &addr).unwrap();
        assert_eq!(got.data, b"still here");

        // First handshake: nothing to send with until a confirms.
        let (c, d) = pair();
        let init = c.initiate_handshake(&d.public_key()).unwrap();
        let resp = d.process_packet(&init, &addr).unwrap();
        assert!(!d.has_session(&c.public_key()));
        let ka = c.process_packet(&resp.response, &addr).unwrap();
        d.process_packet(&ka.response, &addr).unwrap();
        assert!(d.has_session(&c.public_key()), "confirmed by c's keepalive");
    }

    /// Handshake after handshake, each side indexes at most its three
    /// keypairs (previous, current, next) for the peer.
    #[test]
    fn rekeying_does_not_grow_the_keypair_table() {
        let (a, b) = pair();
        for i in 0..20 {
            if i % 2 == 0 {
                handshake(&a, &b);
            } else {
                handshake(&b, &a);
            }
        }
        assert!(
            a.keypairs.read().unwrap().len() <= 3,
            "{}",
            a.keypairs.read().unwrap().len()
        );
        assert!(
            b.keypairs.read().unwrap().len() <= 3,
            "{}",
            b.keypairs.read().unwrap().len()
        );
        let pkt = a.encrypt(b"after", &b.public_key()).unwrap();
        assert_eq!(b.process_packet(&pkt, &loopback()).unwrap().data, b"after");
    }

    /// A forged response with the right receiver index and a valid MAC1
    /// (both computable from public information) must not cost the initiator
    /// its pending handshake.
    #[test]
    fn forged_response_does_not_discard_the_pending_handshake() {
        use crate::wg::constants::MESSAGE_RESPONSE_SIZE;
        let (a, b) = pair();
        let addr = loopback();
        let init = a.initiate_handshake(&b.public_key()).unwrap();
        let resp = b.process_packet(&init, &addr).unwrap();

        let mut forged = resp.response.clone();
        forged[12..MESSAGE_RESPONSE_SIZE - 32].fill(0x42);
        let mac1_key = crate::wg::crypto::calculate_mac1_key(&a.public_key());
        let mac1 =
            crate::wg::crypto::blake2s_mac_128(&mac1_key, &forged[..MESSAGE_RESPONSE_SIZE - 32]);
        forged[MESSAGE_RESPONSE_SIZE - 32..MESSAGE_RESPONSE_SIZE - 16].copy_from_slice(&mac1);
        assert!(a.process_packet(&forged, &addr).is_err());

        let ka = a.process_packet(&resp.response, &addr).unwrap();
        assert_eq!(ka.ty, PacketType::HandshakeResponse);
    }

    /// A small-order peer key makes the static-static DH zero on both sides
    /// and so known to anyone; the handshake must refuse it.
    #[test]
    fn small_order_peer_keys_are_refused() {
        let a = Handler::new(Config::default()).unwrap();
        let zero = NoisePublicKey::zero();
        a.add_peer(zero);
        assert!(a.initiate_handshake(&zero).is_err());
    }

    /// Re-adding a peer with a PSK keeps its last initiation timestamp, so a
    /// captured initiation still cannot be replayed.
    #[test]
    fn re_adding_a_peer_keeps_its_replay_state() {
        let (a, b) = pair();
        let addr = loopback();
        let init = a.initiate_handshake(&b.public_key()).unwrap();
        b.process_packet(&init, &addr).unwrap();
        b.add_peer_with_psk(a.public_key(), NoisePresharedKey::zero());
        assert!(
            b.process_packet(&init, &addr).is_err(),
            "replayed initiation accepted"
        );
    }

    #[test]
    fn handshake_messages_must_be_exact_size() {
        let (a, b) = pair();
        let mut init = a.initiate_handshake(&b.public_key()).unwrap();
        init.push(0);
        assert!(b.process_packet(&init, &loopback()).is_err());
    }

    /// Under load, a source holding a valid cookie is still held to its
    /// share of handshakes (20 a second, 5 at once), as in the reference.
    /// Before, a cookie let one host have us do DH work as fast as it sent.
    #[test]
    fn under_load_handshakes_are_rate_limited_per_source() {
        let a = Handler::new(Config::default()).unwrap();
        let b = Handler::new(Config::default().load_threshold(0)).unwrap();
        a.add_peer(b.public_key());
        b.add_peer(a.public_key());
        let with_cookie = |addr: &SocketAddr| {
            let init = a.initiate_handshake(&b.public_key()).unwrap();
            let reply = b.process_packet(&init, addr).unwrap();
            assert_eq!(reply.ty, PacketType::CookieReply);
            let got = a.process_packet(&reply.response, addr).unwrap();
            assert_eq!(got.ty, PacketType::CookieReceived);
            a.initiate_handshake(&b.public_key()).unwrap()
        };
        let here = loopback();
        let init = with_cookie(&here);
        for _ in 0..5 {
            b.ratelimit_allow(here.ip());
        }
        let err = b.process_packet(&init, &here).unwrap_err();
        assert!(err.to_string().contains("rate limited"), "{err}");

        // Another address has its own allowance.
        let there: SocketAddr = "127.0.0.2:51820".parse().unwrap();
        let init = with_cookie(&there);
        assert_eq!(
            b.process_packet(&init, &there).unwrap().ty,
            PacketType::HandshakeResponse
        );
    }

    /// Past the threshold of initiations per second, MAC2 is demanded. With
    /// inline processing a count of concurrent handshakes never passed 1, so
    /// the cookie defence never engaged.
    #[test]
    fn an_initiation_burst_triggers_the_cookie_path() {
        let a = Handler::new(Config::default()).unwrap();
        let b = Handler::new(Config::default().load_threshold(3)).unwrap();
        a.add_peer(b.public_key());
        b.add_peer(a.public_key());
        let tys: Vec<PacketType> = (0..5)
            .map(|_| {
                pace();
                let init = a.initiate_handshake(&b.public_key()).unwrap();
                b.process_packet(&init, &loopback()).unwrap().ty
            })
            .collect();
        assert_eq!(tys[..3], [PacketType::HandshakeResponse; 3]);
        assert_eq!(tys[3..], [PacketType::CookieReply; 2]);
    }

    fn timer_actions(h: &Handler) -> Vec<&'static str> {
        h.poll_timers()
            .iter()
            .map(|a| match a {
                TimerAction::SendHandshake { .. } => "handshake",
                TimerAction::SendKeepalive { .. } => "keepalive",
                TimerAction::HandshakeFailed { .. } => "failed",
            })
            .collect()
    }

    fn rewind(h: &Handler, peer: &NoisePublicKey, by: Duration) {
        h.with_timers(peer, |t| {
            let back = |x: &mut Option<Instant>| {
                if let Some(v) = x {
                    *v = v.checked_sub(by).unwrap();
                }
            };
            back(&mut t.attempt_started);
            back(&mut t.last_initiation);
            back(&mut t.keepalive_due_since);
            back(&mut t.reply_due_since);
            back(&mut t.last_sent);
        });
    }

    #[test]
    fn an_unanswered_initiation_is_sent_again() {
        let (a, b) = pair();
        a.initiate_handshake(&b.public_key()).unwrap();
        assert!(timer_actions(&a).is_empty());
        rewind(&a, &b.public_key(), Duration::from_secs(6));
        assert_eq!(timer_actions(&a), ["handshake"]);
        a.with_timers(&b.public_key(), |t| {
            t.attempts = crate::wg::MAX_TIMER_HANDSHAKES + 1;
        });
        rewind(&a, &b.public_key(), Duration::from_secs(6));
        assert_eq!(timer_actions(&a), ["failed"]);
    }

    /// Past REKEY_AFTER_MESSAGES the next send starts a new handshake:
    /// before, the rekey signal was dropped and the tunnel ran into the
    /// hard limits.
    #[test]
    fn sending_past_the_rekey_limit_starts_a_handshake() {
        let (a, b) = pair();
        handshake(&a, &b);
        rewind(&a, &b.public_key(), Duration::from_secs(6));
        assert!(timer_actions(&a).is_empty());
        let kp = a.sessions.read().unwrap()[&b.public_key()]
            .keypair_current
            .clone()
            .unwrap();
        kp.send_counter.store(
            crate::wg::constants::REKEY_AFTER_MESSAGES,
            std::sync::atomic::Ordering::SeqCst,
        );
        a.encrypt(b"x", &b.public_key()).unwrap();
        assert_eq!(timer_actions(&a), ["handshake"]);
    }

    /// Data received and nothing sent back for KEEPALIVE_TIMEOUT: send a
    /// keepalive, so the sender knows the session is alive.
    #[test]
    fn received_data_is_answered_with_a_keepalive() {
        let (a, b) = pair();
        handshake(&a, &b);
        let pkt = a.encrypt(b"ping", &b.public_key()).unwrap();
        b.process_packet(&pkt, &loopback()).unwrap();
        assert!(timer_actions(&b).is_empty());
        rewind(&b, &a.public_key(), crate::wg::KEEPALIVE_TIMEOUT);
        assert_eq!(timer_actions(&b), ["keepalive"]);
    }

    /// Whitepaper §6.1: at most one initiation per REKEY_TIMEOUT. The
    /// server polls the timers from its maintenance thread and inline from
    /// send; two polls that both saw a handshake due each sent one, and
    /// the second superseded the first.
    #[test]
    fn concurrent_timer_polls_send_one_initiation() {
        let (a, b) = pair();
        for _ in 0..5 {
            a.with_timers(&b.public_key(), |t| {
                *t = PeerTimers::default();
                t.want_handshake = true;
            });
            let barrier = Arc::new(std::sync::Barrier::new(8));
            let sent: usize = (0..8)
                .map(|_| {
                    let (a, barrier) = (a.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        a.poll_timers()
                            .iter()
                            .filter(|x| matches!(x, TimerAction::SendHandshake { .. }))
                            .count()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|t| t.join().unwrap())
                .sum();
            assert_eq!(sent, 1);
        }
    }

    /// Both ends initiate at once and ours is lost. The peer's handshake,
    /// once its first packet confirms it, is a completed handshake for us
    /// too (the reference calls wg_timers_handshake_complete there): our
    /// own attempt must stop, not keep retrying and rotating keys.
    #[test]
    fn a_confirmed_responder_handshake_ends_our_attempt() {
        let (a, b) = pair();
        let addr = loopback();
        let _lost = a.initiate_handshake(&b.public_key()).unwrap();
        let init = b.initiate_handshake(&a.public_key()).unwrap();
        let resp = a.process_packet(&init, &addr).unwrap();
        let ka = b.process_packet(&resp.response, &addr).unwrap();
        a.process_packet(&ka.response, &addr).unwrap();
        assert!(a.has_session(&b.public_key()));
        rewind(&a, &b.public_key(), Duration::from_secs(6));
        assert!(timer_actions(&a).is_empty(), "still retrying");
    }

    /// A local index names one handshake or keypair: one drawn again must
    /// not replace another peer's entry, which would hand that peer's
    /// traffic to the wrong keypair and cut off the peer it belonged to.
    #[test]
    fn a_local_index_in_use_is_not_taken_over() {
        let (a, b) = pair();
        let (_, c) = pair();
        a.add_peer(c.public_key());
        handshake(&a, &b);
        let kp_idx = *a.keypairs.read().unwrap().keys().next().unwrap();
        a.initiate_handshake(&c.public_key()).unwrap();
        let hs_idx = *a.handshakes.lock().unwrap().keys().next().unwrap();

        // Allocation skips both tables (and zero).
        let mut draws = [0, kp_idx, hs_idx, 7].into_iter();
        let got = a.allocate_index_with(|| Ok(draws.next().unwrap())).unwrap();
        assert_eq!(got, 7);

        // And an index that is taken anyway, by a race, is refused.
        let hs = |idx| {
            let mut h = a.handshakes.lock().unwrap()[&hs_idx].clone();
            h.remote_static = b.public_key();
            h.local_index = idx;
            h
        };
        assert!(a.insert_handshake(kp_idx, hs(kp_idx)).is_err());
        assert!(a.insert_handshake(hs_idx, hs(hs_idx)).is_err());
        assert_eq!(
            a.handshakes.lock().unwrap()[&hs_idx].remote_static,
            c.public_key()
        );
        let old = a.keypairs.read().unwrap()[&kp_idx].clone();
        let kp = Arc::new(Keypair {
            send_key: [0; CHACHAPOLY_KEY_SIZE],
            receive_key: [0; CHACHAPOLY_KEY_SIZE],
            send_counter: AtomicU64::new(0),
            created: Instant::now(),
            local_index: kp_idx,
            remote_index: 1,
            peer_key: c.public_key(),
            is_initiator: true,
            replay_filter: SlidingWindow::new(),
        });
        assert!(a.install_initiator_keypair(c.public_key(), kp).is_err());
        assert!(Arc::ptr_eq(&a.keypairs.read().unwrap()[&kp_idx], &old));
        assert!(!a.sessions.read().unwrap().contains_key(&c.public_key()));
    }

    /// Members of a MultiHandler draw indexes no other member uses: the
    /// multiplexer routes by index to the first member owning it, so a
    /// shared one sent a member's traffic to another.
    #[test]
    fn a_local_index_is_unique_across_a_multihandler() {
        let (a, b) = pair();
        let c = Handler::new(Config::default()).unwrap();
        handshake(&a, &b);
        let kp_idx = *a.keypairs.read().unwrap().keys().next().unwrap();
        a.add_peer(c.public_key());
        a.initiate_handshake(&c.public_key()).unwrap();
        let hs_idx = *a.handshakes.lock().unwrap().keys().next().unwrap();
        let other = Handler::new(Config::default()).unwrap();
        let mh = crate::wg::MultiHandler::new(vec![a.clone(), other.clone()]).unwrap();

        let mut draws = [kp_idx, hs_idx, 7].into_iter();
        let got = other
            .allocate_index_with(|| Ok(draws.next().unwrap()))
            .unwrap();
        assert_eq!(got, 7);

        // Once out of the multiplexer, only its own tables count.
        mh.remove_handler(&other.public_key()).unwrap();
        let got = other.allocate_index_with(|| Ok(kp_idx)).unwrap();
        assert_eq!(got, kp_idx);
        // And a handler added later joins in.
        mh.add_handler(other.clone()).unwrap();
        let mut draws = [kp_idx, 9].into_iter();
        let got = other
            .allocate_index_with(|| Ok(draws.next().unwrap()))
            .unwrap();
        assert_eq!(got, 9);
    }

    /// Both ends initiate at once and both handshakes complete. Each side
    /// then sends with the keypair from its own initiation, which the other
    /// holds as the one it answered: that one must still decrypt.
    #[test]
    fn crossing_handshakes_leave_traffic_flowing_both_ways() {
        let (a, b) = pair();
        let addr = loopback();
        let init_a = a.initiate_handshake(&b.public_key()).unwrap();
        let init_b = b.initiate_handshake(&a.public_key()).unwrap();
        let resp_a = a.process_packet(&init_b, &addr).unwrap();
        let resp_b = b.process_packet(&init_a, &addr).unwrap();
        let ka_a = a.process_packet(&resp_b.response, &addr).unwrap();
        let ka_b = b.process_packet(&resp_a.response, &addr).unwrap();
        assert_eq!(
            b.process_packet(&ka_a.response, &addr).unwrap().ty,
            PacketType::Keepalive
        );
        assert_eq!(
            a.process_packet(&ka_b.response, &addr).unwrap().ty,
            PacketType::Keepalive
        );
        for _ in 0..3 {
            let pkt = a.encrypt(b"a to b", &b.public_key()).unwrap();
            assert_eq!(b.process_packet(&pkt, &addr).unwrap().data, b"a to b");
            let pkt = b.encrypt(b"b to a", &a.public_key()).unwrap();
            assert_eq!(a.process_packet(&pkt, &addr).unwrap().data, b"b to a");
        }
    }

    /// A response to an initiation made before the peer was removed must not
    /// bring it back: it would install a session for a revoked key, and a
    /// server would report the peer connected again.
    #[test]
    fn a_removed_peer_cannot_return_through_a_late_response() {
        let (a, b) = pair();
        let addr = loopback();
        let init = a.initiate_handshake(&b.public_key()).unwrap();
        a.remove_peer(&b.public_key());
        let resp = b.process_packet(&init, &addr).unwrap();
        assert!(a.process_packet(&resp.response, &addr).is_err());
        assert!(!a.has_session(&b.public_key()));
        assert!(a.sessions.read().unwrap().is_empty());
        assert!(a.keypairs.read().unwrap().is_empty());

        // Nor once it is authorized again: that handshake belonged to the
        // authorization that was revoked.
        let (a, b) = pair();
        let init = a.initiate_handshake(&b.public_key()).unwrap();
        a.remove_peer(&b.public_key());
        a.add_peer(b.public_key());
        let resp = b.process_packet(&init, &addr).unwrap();
        assert!(a.process_packet(&resp.response, &addr).is_err());
        assert!(!a.has_session(&b.public_key()));
    }

    /// Past its expiry a peer's session is unusable at once, both ways, not
    /// only once maintenance gets round to it.
    #[test]
    fn an_expired_peer_can_neither_send_nor_receive() {
        let (a, b) = pair();
        let addr = loopback();
        handshake(&a, &b);
        let from_b = b.encrypt(b"late", &a.public_key()).unwrap();
        a.set_peer_expiry(&b.public_key(), Instant::now() - Duration::from_secs(1));
        assert!(!a.has_session(&b.public_key()));
        assert!(a.encrypt(b"x", &b.public_key()).is_err());
        assert!(a.process_packet(&from_b, &addr).is_err());
    }

    /// The unknown-peer callback may replace itself: it must not run under
    /// the lock that set_on_unknown_peer takes.
    #[test]
    fn unknown_peer_callback_may_replace_itself() {
        use std::sync::Weak;
        let slot: Arc<Mutex<Option<Weak<Handler>>>> = Arc::new(Mutex::new(None));
        let s = slot.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        let cb: UnknownPeerFn = Arc::new(move |_, _, _| {
            let h = s.lock().unwrap().as_ref().and_then(Weak::upgrade);
            if let Some(h) = h {
                h.set_on_unknown_peer(Arc::new(|_, _, _| {}));
            }
            let _ = tx.lock().unwrap().send(());
        });
        let b = Handler::new(Config::default().on_unknown_peer(cb)).unwrap();
        *slot.lock().unwrap() = Some(Arc::downgrade(&b));
        let a = Handler::new(Config::default()).unwrap();
        a.add_peer(b.public_key());
        let init = a.initiate_handshake(&b.public_key()).unwrap();
        let b2 = b.clone();
        std::thread::spawn(move || {
            let _ = b2.process_packet(&init, &loopback());
        });
        rx.recv_timeout(Duration::from_secs(10))
            .expect("deadlocked in the unknown-peer callback");
    }

    /// "Add (or refresh)": adding an expired peer again authorizes it
    /// again, whichever way it is added. Before, both left the expiry in
    /// place and the peer could never come back short of remove_peer.
    #[test]
    fn re_adding_an_expired_peer_authorizes_it_again() {
        let a = Handler::new(Config::default()).unwrap();
        let k = NoisePublicKey([7; 32]);
        let past = Instant::now() - Duration::from_secs(1);
        a.add_peer(k);
        a.set_peer_expiry(&k, past);
        a.add_peer(k);
        assert!(a.is_authorized_peer(&k));
        a.set_peer_expiry(&k, past);
        a.add_peer_with_psk(k, NoisePresharedKey([1; 32]));
        assert!(a.is_authorized_peer(&k));
        // add_peer keeps the preshared key it already had.
        a.add_peer(k);
        assert!(a.get_peer_info(&k).unwrap().has_psk);
    }

    /// An expired peer's initiation, accepted from the unknown-peer callback
    /// as documented, completes the handshake. Before, the peer stayed
    /// unauthorized, the re-fed initiation invoked the callback again, and
    /// the two recursed until the stack overflowed.
    #[test]
    fn accepting_an_expired_peer_from_the_callback_completes() {
        use std::sync::Weak;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let slot: Arc<Mutex<Option<Weak<Handler>>>> = Arc::default();
        let (c, s) = (calls.clone(), slot.clone());
        let resp: Arc<Mutex<Option<Result<Vec<u8>>>>> = Arc::default();
        let r = resp.clone();
        let b = Handler::new(Config::default().on_unknown_peer(Arc::new(
            move |k, addr, pkt: &[u8]| {
                // Bail out well before the stack would overflow.
                if c.fetch_add(1, Ordering::SeqCst) > 20 {
                    return;
                }
                let h = s.lock().unwrap().as_ref().and_then(Weak::upgrade);
                if let Some(h) = h {
                    let got = h.accept_unknown_peer(k, pkt, &addr);
                    r.lock().unwrap().get_or_insert(got);
                }
            },
        )))
        .unwrap();
        *slot.lock().unwrap() = Some(Arc::downgrade(&b));
        let a = Handler::new(Config::default()).unwrap();
        a.add_peer(b.public_key());
        b.add_peer(a.public_key());
        b.set_peer_expiry(&a.public_key(), Instant::now() - Duration::from_secs(1));

        let init = a.initiate_handshake(&b.public_key()).unwrap();
        assert!(b.process_packet(&init, &loopback()).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let resp = resp.lock().unwrap().take().unwrap().unwrap();
        assert_eq!(
            a.process_packet(&resp, &loopback()).unwrap().ty,
            PacketType::HandshakeResponse
        );
    }

    /// A callback that re-feeds the initiation without authorizing the peer
    /// is not invoked again from inside itself.
    #[test]
    fn the_unknown_peer_callback_does_not_recurse() {
        use std::sync::Weak;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let slot: Arc<Mutex<Option<Weak<Handler>>>> = Arc::default();
        let (c, s) = (calls.clone(), slot.clone());
        let b = Handler::new(Config::default().on_unknown_peer(Arc::new(
            move |_, addr, pkt: &[u8]| {
                if c.fetch_add(1, Ordering::SeqCst) > 20 {
                    return;
                }
                let h = s.lock().unwrap().as_ref().and_then(Weak::upgrade);
                if let Some(h) = h {
                    assert!(h.process_packet(pkt, &addr).is_err());
                }
            },
        )))
        .unwrap();
        *slot.lock().unwrap() = Some(Arc::downgrade(&b));
        let a = Handler::new(Config::default()).unwrap();
        a.add_peer(b.public_key());
        for _ in 0..2 {
            let init = a.initiate_handshake(&b.public_key()).unwrap();
            assert!(b.process_packet(&init, &loopback()).is_err());
        }
        // Once per packet: the guard is released between them.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// Tally what the timers of `h` do over `secs` seconds from `t0`,
    /// polled every 100 ms: (initiations, failures, and when each
    /// initiation went out).
    fn run_timers(h: &Handler, t0: Instant, secs: u64) -> (usize, usize, Vec<Duration>) {
        let (mut inits, mut failed, mut at) = (0, 0, Vec::new());
        for i in 0..secs * 10 {
            let off = Duration::from_millis(100 * i);
            for act in h.poll_timers_at(t0 + off) {
                match act {
                    TimerAction::SendHandshake { .. } => {
                        inits += 1;
                        at.push(off);
                    }
                    TimerAction::HandshakeFailed { .. } => failed += 1,
                    TimerAction::SendKeepalive { .. } => {}
                }
            }
        }
        (inits, failed, at)
    }

    /// A keepalive that comes due with no session starts one handshake
    /// attempt, which gives up like any other. It stayed pending, so every
    /// abandoned attempt was followed at once by the next: an offline peer
    /// drew some 690 initiations an hour, for ever.
    #[test]
    fn a_keepalive_due_without_a_session_is_one_attempt() {
        let (a, b) = pair();
        let t0 = Instant::now();
        a.with_timers(&b.public_key(), |t| t.keepalive_due_since = Some(t0));
        let (inits, failed, _) = run_timers(&a, t0, 3600);
        assert_eq!(inits, crate::wg::MAX_TIMER_HANDSHAKES as usize + 2);
        assert_eq!(failed, 1);
    }

    /// Nor does a keepalive due for a peer whose authorization lapsed ask
    /// for a handshake, which could never be built: that reported
    /// HandshakeFailed on every poll.
    #[test]
    fn a_keepalive_due_for_an_expired_peer_asks_for_nothing() {
        let (a, b) = pair();
        let t0 = Instant::now();
        a.with_timers(&b.public_key(), |t| t.keepalive_due_since = Some(t0));
        a.set_peer_expiry(&b.public_key(), t0 - Duration::from_secs(1));
        assert_eq!(run_timers(&a, t0, 600), (0, 0, Vec::new()));
    }

    /// Persistent keepalive keeps trying an unreachable peer, as the
    /// reference does, but each new attempt waits an interval after the
    /// last initiation rather than following the one given up at once.
    #[test]
    fn persistent_keepalive_retries_an_unreachable_peer_an_interval_apart() {
        let (a, b) = pair();
        let every = Duration::from_secs(25);
        a.set_persistent_keepalive(&b.public_key(), Some(every));
        let (inits, failed, at) = run_timers(&a, Instant::now(), 600);
        assert!(failed >= 2, "gave up {failed} times");
        assert!(inits > 20, "stopped after {inits} initiations");
        assert!(
            at.windows(2)
                .all(|w| w[1] - w[0] >= crate::wg::REKEY_TIMEOUT),
            "{at:?}"
        );
        let gaps = at.windows(2).filter(|w| w[1] - w[0] >= every).count();
        assert_eq!(gaps, failed, "{at:?}");
    }

    #[test]
    fn sending_with_no_session_asks_for_a_handshake() {
        let (a, b) = pair();
        assert!(a.encrypt(b"x", &b.public_key()).is_err());
        assert_eq!(timer_actions(&a), ["handshake"]);
    }

    /// Accepting unknown peers stops at the configured limit: an
    /// on_unknown_peer that takes every key let anyone grow the peer table
    /// without end, one fresh key per initiation.
    #[test]
    fn accepting_unknown_peers_stops_at_the_limit() {
        let b = Handler::new(Config::default().unknown_peer_limit(3)).unwrap();
        b.add_peer(NoisePublicKey([1; 32]));
        let accept = |a: &Handler| {
            a.add_peer(b.public_key());
            let init = a.initiate_handshake(&b.public_key()).unwrap();
            b.accept_unknown_peer(a.public_key(), &init, &loopback())
        };
        let (a1, a2, a3) = (pair().0, pair().0, pair().0);
        assert!(accept(&a1).is_ok());
        assert!(accept(&a2).is_ok());
        assert!(accept(&a3).is_err(), "grew past the limit");
        assert_eq!(b.peers().len(), 3);
        // A peer already there is still refreshed: an expired one can be
        // accepted again.
        b.set_peer_expiry(&a1.public_key(), Instant::now() - Duration::from_secs(1));
        pace();
        assert!(accept(&a1).is_ok());
        // Explicit authorization is the caller's call and is not limited.
        b.add_peer(a3.public_key());
        assert_eq!(b.peers().len(), 4);
    }

    #[test]
    fn unknown_peer_rejected() {
        let a = Handler::new(Config::default()).unwrap();
        let b = Handler::new(Config::default()).unwrap();
        a.add_peer(b.public_key());
        // Note: B does NOT add A as authorized.

        let init = a.initiate_handshake(&b.public_key()).unwrap();
        let addr = loopback();
        let err = b.process_packet(&init, &addr).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn transport_counter_advances_and_replays_blocked() {
        let a = Handler::new(Config::default()).unwrap();
        let b = Handler::new(Config::default()).unwrap();
        a.add_peer(b.public_key());
        b.add_peer(a.public_key());

        // Drive handshake.
        let init = a.initiate_handshake(&b.public_key()).unwrap();
        let addr = loopback();
        let resp = b.process_packet(&init, &addr).unwrap();
        let _ = a.process_packet(&resp.response, &addr).unwrap();

        // Two distinct payloads should produce two distinct ciphertexts
        // (counters differ).
        let c1 = a.encrypt(b"one", &b.public_key()).unwrap();
        let c2 = a.encrypt(b"two", &b.public_key()).unwrap();
        assert_ne!(c1, c2);
        assert_eq!(crate::wg::encrypted_size(3), c1.len());

        // Receive c1, then a replay of c1 should be rejected.
        let r1 = b.process_packet(&c1, &addr).unwrap();
        assert_eq!(r1.data, b"one");
        let err = b.process_packet(&c1, &addr).unwrap_err();
        assert!(err.to_string().contains("replay"), "got: {}", err);
    }

    #[test]
    fn peer_lookup_smoke() {
        let h = Handler::new(Config::default()).unwrap();
        let k1 = NoisePublicKey([1u8; 32]);
        let k2 = NoisePublicKey([2u8; 32]);
        assert!(!h.is_authorized_peer(&k1));
        h.add_peer(k1);
        assert!(h.is_authorized_peer(&k1));
        assert!(!h.is_authorized_peer(&k2));
        let list = h.peers();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], k1);

        h.remove_peer(&k1);
        assert!(!h.is_authorized_peer(&k1));
    }
}
