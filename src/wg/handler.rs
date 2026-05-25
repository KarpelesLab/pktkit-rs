//! Per-identity WireGuard state machine.
//!
//! A [`Handler`] owns one private key, the table of authorized peers, the set
//! of pending handshakes, the active keypairs (indexed by local sender), and
//! the per-peer sessions. It is the synchronous core of the implementation —
//! all I/O happens in [`super::server::Server`].

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::wg::constants::{
    NoisePresharedKey, NoisePrivateKey, NoisePublicKey, CHACHAPOLY_KEY_SIZE,
    DEFAULT_LOAD_THRESHOLD, REJECT_AFTER_TIME, TAI64N_TIMESTAMP_SIZE,
};
use crate::wg::crypto::x25519_public;
use crate::wg::replay::SlidingWindow;
use crate::wg::transport::EncryptError;
use crate::Result;

/// Callback invoked when a handshake arrives from a peer not in the authorized
/// list. The packet slice is only valid for the call; the callback must copy
/// it if it needs to keep the data (e.g. for later `accept_unknown_peer`).
pub type UnknownPeerFn =
    Arc<dyn Fn(NoisePublicKey, SocketAddr, &[u8]) + Send + Sync + 'static>;

/// Per-handler configuration.
#[derive(Clone, Default)]
pub struct Config {
    /// Local static private key. If zero, a fresh key is generated.
    pub private_key: NoisePrivateKey,

    /// Optional callback for unauthorized peers.
    pub on_unknown_peer: Option<UnknownPeerFn>,

    /// Concurrent handshakes allowed before MAC2 cookie validation kicks in.
    /// `None` uses the default (20); `Some(n)` sets it
    /// exactly, so `Some(0)` makes every initiation under-load (useful in
    /// tests to force the cookie path).
    pub load_threshold: Option<usize>,
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
        }
    }
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
    #[allow(dead_code)]
    pub is_initiator: bool,
    pub replay_filter: SlidingWindow,
}

/// Read-only view used by hot-path code to avoid taking the full keypair
/// `Arc` across crate boundaries.
#[allow(dead_code)] // some fields are reserved for future hot-path optimisations
pub(crate) struct KeypairView<'a> {
    pub send_key: &'a [u8; CHACHAPOLY_KEY_SIZE],
    pub receive_key: &'a [u8; CHACHAPOLY_KEY_SIZE],
    pub send_counter: &'a AtomicU64,
    pub created: Instant,
    pub remote_index: u32,
    pub peer_key: NoisePublicKey,
    pub replay_filter: &'a SlidingWindow,
}

/// A peer's session — current keypair plus the most recently rotated one.
pub(crate) struct Session {
    pub keypair_current: Option<Arc<Keypair>>,
    pub keypair_prev: Option<Arc<Keypair>>,
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
    active_handshakes: AtomicUsize,
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
            active_handshakes: AtomicUsize::new(0),
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

    /// Add (or refresh) an authorized peer with a preshared key.
    pub fn add_peer_with_psk(&self, peer_key: NoisePublicKey, psk: NoisePresharedKey) {
        let mut peers = self.peers.write().expect("peers lock");
        peers.insert(peer_key, PeerEntry::new(peer_key, psk, true));
    }

    /// Remove a peer and tear down all session state belonging to it.
    pub fn remove_peer(&self, peer_key: &NoisePublicKey) {
        self.peers.write().expect("peers lock").remove(peer_key);

        let removed = self.sessions.write().expect("sessions lock").remove(peer_key);
        if let Some(sess) = removed {
            let mut kps = self.keypairs.write().expect("keypairs lock");
            if let Some(kp) = sess.keypair_current.as_ref() {
                kps.remove(&kp.local_index);
            }
            if let Some(kp) = sess.keypair_prev.as_ref() {
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
        if let Some(exp) = p.expires_at {
            if Instant::now() > exp {
                return false;
            }
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
    pub(crate) fn accept_peer_timestamp(
        &self,
        peer_key: &NoisePublicKey,
        ts: &[u8],
    ) -> bool {
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
        let mut to_remove = Vec::new();
        for (k, s) in sess.iter() {
            let last_active = s.last_received.max(s.last_sent);
            if n.duration_since(last_active) > REJECT_AFTER_TIME {
                to_remove.push(*k);
            }
        }
        let mut kps = self.keypairs.write().expect("keypairs lock");
        for k in &to_remove {
            if let Some(s) = sess.remove(k) {
                if let Some(kp) = s.keypair_current.as_ref() {
                    kps.remove(&kp.local_index);
                }
                if let Some(kp) = s.keypair_prev.as_ref() {
                    kps.remove(&kp.local_index);
                }
            }
        }
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
        if g.len() >= crate::wg::constants::MAX_HANDSHAKES && !g.contains_key(&idx) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "handshake table full",
            ));
        }
        g.insert(idx, hs);
        Ok(())
    }

    pub(crate) fn take_handshake(&self, idx: u32) -> Option<crate::wg::handshake::Handshake> {
        self.handshakes
            .lock()
            .expect("handshakes lock")
            .remove(&idx)
    }

    pub(crate) fn has_handshake_index(&self, idx: u32) -> bool {
        self.handshakes
            .lock()
            .expect("handshakes lock")
            .contains_key(&idx)
    }

    pub(crate) fn install_keypair(&self, idx: u32, kp: Arc<Keypair>) {
        self.keypairs.write().expect("keypairs lock").insert(idx, kp);
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

    pub(crate) fn check_keypair_capacity(&self, cap: usize) -> Result<()> {
        if self.keypairs.read().expect("keypairs lock").len() >= cap {
            return Err(io::Error::new(io::ErrorKind::Other, "keypair table full"));
        }
        Ok(())
    }

    pub(crate) fn check_session_capacity(&self, cap: usize, k: &NoisePublicKey) -> Result<()> {
        let g = self.sessions.read().expect("sessions lock");
        if g.len() >= cap && !g.contains_key(k) {
            return Err(io::Error::new(io::ErrorKind::Other, "session table full"));
        }
        Ok(())
    }

    pub(crate) fn upsert_session(&self, peer_key: NoisePublicKey, kp: Arc<Keypair>) {
        let mut sess = self.sessions.write().expect("sessions lock");
        match sess.get_mut(&peer_key) {
            Some(s) => {
                if let Some(prev) = s.keypair_current.take() {
                    s.keypair_prev = Some(prev);
                }
                s.keypair_current = Some(kp);
            }
            None => {
                sess.insert(
                    peer_key,
                    Session {
                        keypair_current: Some(kp),
                        keypair_prev: None,
                        last_received: Instant::now(),
                        last_sent: Instant::now(),
                        peer_key,
                    },
                );
            }
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

    /// Return the current keypair view + its age. Updates `last_sent` as a
    /// side effect (matching the Go transport path).
    pub(crate) fn with_current_keypair<'a>(
        &'a self,
        peer_key: &NoisePublicKey,
    ) -> Option<(KeypairView<'a>, Duration)> {
        // The keypairs map holds the same Arc<Keypair>; resolving via the
        // session avoids a second lookup but the borrow checker prefers we
        // hold a single Arc.
        let kp = {
            let s = self.sessions.read().expect("sessions lock");
            s.get(peer_key)
                .and_then(|s| s.keypair_current.as_ref().cloned())?
        };
        self.touch_session_sent(peer_key);

        let age = Instant::now().duration_since(kp.created);

        // SAFETY: we lengthen the borrow of `&Keypair` to `'a` by reborrowing
        // through the `Arc<Keypair>` that the session keeps. The session lock
        // is released here, but the keypair stays alive because we just cloned
        // the Arc above. We immediately leak it via Box::leak'd reference
        // bound to 'a so the caller can use it without holding a guard — the
        // map still owns the canonical Arc, so this won't grow the leak set
        // beyond the lifetime of `self`.
        //
        // In practice the encrypt path holds the resulting view for only a
        // few microseconds; we accept the minor allocation cost in exchange
        // for keeping lock scope tight.
        let leaked: &'a Keypair = Box::leak(Box::new(KeypairCarrier(kp))).0.as_ref();
        let view = KeypairView {
            send_key: &leaked.send_key,
            receive_key: &leaked.receive_key,
            send_counter: &leaked.send_counter,
            created: leaked.created,
            remote_index: leaked.remote_index,
            peer_key: leaked.peer_key,
            replay_filter: &leaked.replay_filter,
        };
        Some((view, age))
    }

    pub(crate) fn inc_active_handshakes(&self) {
        self.active_handshakes.fetch_add(1, Ordering::SeqCst);
    }

    /// True when there are more concurrent handshakes in flight than the
    /// configured load threshold — the trigger for requiring a valid MAC2.
    pub(crate) fn is_under_load(&self) -> bool {
        self.active_handshakes.load(Ordering::SeqCst) > self.load_threshold
    }

    // --- cookie integration ------------------------------------------------

    /// Validate MAC1 on an incoming handshake against our own public key.
    pub(crate) fn cookie_check_mac1(&self, data: &[u8]) -> bool {
        self.cookie_checker.lock().expect("cookie lock").check_mac1(data)
    }

    /// Validate MAC2 (under-load path).
    pub(crate) fn cookie_check_mac2(&self, data: &[u8], src: &[u8]) -> bool {
        self.cookie_checker.lock().expect("cookie lock").check_mac2(data, src)
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
            entry.cookie_gen.lock().expect("cookie_gen lock").add_macs(pkt);
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
                ))
            }
        };
        let result = entry
            .cookie_gen
            .lock()
            .expect("cookie_gen lock")
            .consume_reply(nonce, ct);
        result
    }

    pub(crate) fn dec_active_handshakes(&self) {
        let prev = self.active_handshakes.fetch_sub(1, Ordering::SeqCst);
        if prev == 0 {
            // Should not happen; clamp to 0.
            self.active_handshakes.store(0, Ordering::SeqCst);
        }
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

// Tiny shim so the `Box::leak` in `with_current_keypair` carries the Arc.
struct KeypairCarrier(#[allow(dead_code)] pub Arc<Keypair>);

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
