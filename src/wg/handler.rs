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
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::Result;
use crate::wg::constants::{
    CHACHAPOLY_KEY_SIZE, DEFAULT_LOAD_THRESHOLD, NoisePresharedKey, NoisePrivateKey,
    NoisePublicKey, REJECT_AFTER_TIME, TAI64N_TIMESTAMP_SIZE,
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
}

setters! {
    Config {
        set private_key: NoisePrivateKey;
        some on_unknown_peer: UnknownPeerFn;
        some load_threshold: usize;
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("private_key", &self.private_key)
            .field("on_unknown_peer", &self.on_unknown_peer.is_some())
            .field("load_threshold", &self.load_threshold)
            .finish()
    }
}

/// Outcome of feeding one incoming WireGuard packet into [`Handler::process_packet`].
#[derive(Clone, Debug)]
pub struct PacketResult {
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

/// Public summary of a peer's session state.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub public_key: NoisePublicKey,
    pub has_psk: bool,
    pub created_at: Instant,
    pub expires_at: Option<Instant>,
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
    load_threshold: usize,
    /// Initiations seen in the current one-second window, and when being
    /// under load lapses. Initiations are processed inline, so the
    /// reference's measure (the depth of a handshake queue) has no
    /// equivalent here; their rate is what costs CPU.
    load: Mutex<LoadMeter>,
    /// Responder-side cookie validator + reply generator.
    cookie_checker: Mutex<crate::wg::cookie::CookieChecker>,
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
            load_threshold: lt,
            load: Mutex::new(LoadMeter::default()),
            cookie_checker: Mutex::new(crate::wg::cookie::CookieChecker::new(&pub_key)),
        }))
    }

    #[inline]
    pub fn public_key(&self) -> NoisePublicKey {
        self.public_key
    }

    #[inline]
    pub(crate) fn private_key(&self) -> &NoisePrivateKey {
        &self.private_key
    }

    /// Add (or refresh) an authorized peer with no preshared key.
    pub fn add_peer(&self, peer_key: NoisePublicKey) {
        let mut peers = self.peers.write().expect("peers lock");
        peers
            .entry(peer_key)
            .or_insert_with(|| PeerEntry::new(peer_key, NoisePresharedKey::zero(), false));
    }

    /// Install (or replace) the callback invoked when a handshake arrives from
    /// an unauthorized peer. Lets callers set the hook after construction —
    /// notably the [`Adapter`](crate::wg::Adapter) applies it to every handler
    /// in multi-handler mode.
    pub fn set_on_unknown_peer(&self, cb: UnknownPeerFn) {
        *self.on_unknown_peer.lock().expect("unknown lock") = Some(cb);
    }

    /// Add (or refresh) an authorized peer with a preshared key.
    pub fn add_peer_with_psk(&self, peer_key: NoisePublicKey, psk: NoisePresharedKey) {
        let mut peers = self.peers.write().expect("peers lock");
        match peers.get_mut(&peer_key) {
            // Update in place: replacing the entry would forget the peer's
            // last initiation timestamp, and a captured initiation could
            // then be replayed once.
            Some(p) => {
                p.preshared_key = psk;
                p.has_psk = true;
            }
            None => {
                peers.insert(peer_key, PeerEntry::new(peer_key, psk, true));
            }
        }
    }

    /// Remove a peer and tear down all session state belonging to it.
    pub fn remove_peer(&self, peer_key: &NoisePublicKey) {
        self.peers.write().expect("peers lock").remove(peer_key);

        let removed = self
            .sessions
            .write()
            .expect("sessions lock")
            .remove(peer_key);
        if let Some(sess) = removed {
            let mut kps = self.keypairs.write().expect("keypairs lock");
            if let Some(kp) = sess.keypair_current.as_ref() {
                kps.remove(&kp.local_index);
            }
            if let Some(kp) = sess.keypair_prev.as_ref() {
                kps.remove(&kp.local_index);
            }
            if let Some(kp) = sess.keypair_next.as_ref() {
                kps.remove(&kp.local_index);
            }
        }
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

    /// Check & update the per-peer last-timestamp. Returns true if the new
    /// timestamp is strictly greater than the previously stored one (or no
    /// previous one existed).
    pub(crate) fn accept_peer_timestamp(&self, peer_key: &NoisePublicKey, ts: &[u8]) -> bool {
        let mut peers = self.peers.write().expect("peers lock");
        let Some(p) = peers.get_mut(peer_key) else {
            return false;
        };
        if p.has_timestamp && ts <= &p.last_timestamp[..] {
            return false;
        }
        let n = ts.len().min(TAI64N_TIMESTAMP_SIZE);
        p.last_timestamp[..n].copy_from_slice(&ts[..n]);
        p.has_timestamp = true;
        p.last_handshake = Some(Instant::now());
        true
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
        if let Some(cb) = self.on_unknown_peer.lock().expect("unknown lock").clone() {
            cb(*peer_key, *addr, packet);
        }
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
    pub fn initiate_handshake(&self, peer_key: &NoisePublicKey) -> Result<Vec<u8>> {
        crate::wg::handshake::initiate_handshake(self, peer_key)
    }

    /// True if there is a current session with an installed keypair for `peer_key`.
    pub fn has_session(&self, peer_key: &NoisePublicKey) -> bool {
        self.sessions
            .read()
            .expect("sessions lock")
            .get(peer_key)
            .and_then(|s| s.keypair_current.as_ref())
            .is_some()
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
        let now = Instant::now();
        let peers: Vec<NoisePublicKey> = self.peers().into_iter().collect();
        let mut out = Vec::new();
        for peer in peers {
            let Some((due, keepalive)) =
                self.with_timers(&peer, |t| (t.handshake_due(now), t.keepalive_due(now)))
            else {
                continue;
            };
            match due {
                None => out.push(TimerAction::HandshakeFailed { peer }),
                Some(true) => {
                    if let Ok(packet) = self.initiate_handshake(&peer) {
                        out.push(TimerAction::SendHandshake { peer, packet });
                    }
                }
                Some(false) => {}
            }
            if keepalive {
                if self.has_session(&peer) {
                    if let Ok(packet) = self.encrypt(&[], &peer) {
                        out.push(TimerAction::SendKeepalive { peer, packet });
                    }
                } else {
                    // A keepalive needs a keypair; get one.
                    self.with_timers(&peer, |t| t.want_handshake = true);
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
        if g.len() >= crate::wg::constants::MAX_HANDSHAKES && !g.contains_key(&idx) {
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
        if sess.len() >= MAX_SESSIONS && !sess.contains_key(&peer_key) {
            return Err(io::Error::other("session table full"));
        }
        if kps.len() >= MAX_HANDSHAKES {
            return Err(io::Error::other("keypair table full"));
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
    pub(crate) fn install_initiator_keypair(
        &self,
        peer_key: NoisePublicKey,
        kp: Arc<Keypair>,
    ) -> Result<()> {
        self.install(peer_key, kp, |s, kp| {
            let mut gone: Vec<_> = s.keypair_next.take().into_iter().collect();
            gone.extend(s.keypair_prev.take());
            s.keypair_prev = s.keypair_current.replace(kp);
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

    /// Authorize a previously unknown peer and complete its handshake by
    /// re-running the initiation through the responder path. Returns the
    /// raw response bytes the caller should send back to `remote_addr`.
    pub fn accept_unknown_peer(
        &self,
        peer_key: NoisePublicKey,
        initiation_packet: &[u8],
        remote_addr: &SocketAddr,
    ) -> Result<Vec<u8>> {
        self.add_peer(peer_key);
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

    /// Full handshake a→b, returning the keepalive a sent.
    fn handshake(a: &Handler, b: &Handler) -> Vec<u8> {
        let addr = loopback();
        let init = a.initiate_handshake(&b.public_key()).unwrap();
        let resp = b.process_packet(&init, &addr).unwrap();
        let ka = a.process_packet(&resp.response, &addr).unwrap();
        b.process_packet(&ka.response, &addr).unwrap();
        ka.response
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
        rewind(&a, &b.public_key(), crate::wg::REKEY_ATTEMPT_TIME);
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

    #[test]
    fn sending_with_no_session_asks_for_a_handshake() {
        let (a, b) = pair();
        assert!(a.encrypt(b"x", &b.public_key()).is_err());
        assert_eq!(timer_actions(&a), ["handshake"]);
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
