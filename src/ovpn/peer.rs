//! Per-peer state machine.
//!
//! A [`Peer`] drives one OpenVPN client through:
//!
//! 1. **Hard reset** — the client's `P_CONTROL_HARD_RESET_CLIENT_V2` opens a
//!    session keyed by its session id; we reply with our own server hard
//!    reset carrying a fresh session id of ours.
//! 2. **TLS handshake** — a purecrypto TLS server connection runs *inside* the
//!    reliable control channel. We feed it the TLS bytes carried by
//!    `P_CONTROL_V1` packets and pump its output back out as more
//!    `P_CONTROL_V1` packets. There is no TCP socket under the TLS; the
//!    reliable layer is the transport.
//! 3. **Key-method 2 exchange** — over the established TLS stream the client
//!    sends `[0:4][key_method:1][pre_master:48][random1:32][random2:32]` plus
//!    the options, username, password, and peer-info strings. We reply
//!    symmetrically, then derive the data-channel keys with the TLS-1.0 PRF.
//! 4. **Data channel** — `P_DATA_V1` packets are decrypted to IP packets (tun)
//!    or Ethernet frames (tap) and delivered to the adapter; outgoing packets
//!    are encrypted and emitted.
//!
//! The structure follows OpenVPN's `ssl.c`: a peer holds up to three
//! [`Session`]s (`tls_session`) -- the *active* one carrying the data channel,
//! an *initial* one a new hard reset is negotiating, and an *untrusted* one
//! whose hard reset has not yet been shown to come from whoever sent it --
//! and every control packet is routed to a session by the sender's session
//! id. A session that authenticates replaces the active one, so a client
//! that restarts from the same address reconnects, while a stray hard reset
//! can disturb neither a working session nor one being negotiated. Each
//! session runs its TLS handshake in a [`KeyState`] (`key_state`).
//!
//! The Rust code is single-threaded and event-driven — each inbound datagram
//! is processed synchronously and any work that can make progress does so.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use purecrypto::tls::Connection as TlsConnection;

use super::Opcode;
use super::consts::{KEY_EXPANSION_ID, KEY_METHOD_MASK, OPENVPN_PING};
use super::data;
use super::keys::PeerKeys;
use super::options::Options;
use super::packet_ctrl::ControlPacket;
use super::prf::prf10;
use super::reliable::Reliable;
use super::window::Window;
use crate::time::Instant;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Credentials and metadata presented by a client during the key exchange.
///
/// Built by the crate and read by [`OnAuth`], so it is `#[non_exhaustive]`:
/// more of what the client presents can be added without breaking anyone.
/// Every field is what the client sent, as it sent it: checking it is the
/// callback's job.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AuthInfo {
    /// The `auth-user-pass` username; empty if the client sent none.
    pub username: String,
    /// The `auth-user-pass` password; empty if the client sent none.
    pub password: String,
    /// The client's peer-info key/values (`IV_VER`, `IV_PLAT`,
    /// `IV_CIPHERS`, ...), for information: a client can claim anything.
    pub peer_info: HashMap<String, String>,
    /// The `dev-type` from the client's options string: `"tun"` or
    /// `"tap"`.
    pub dev_type: String,
}

/// IP configuration the server pushes back to an authenticated client.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PeerConfig {
    /// Tunnel address assigned to the client. In tun mode the
    /// [`Adapter`](super::Adapter) passes on only packets from this address
    /// or from one of the [`iroutes`](Self::iroutes); any other source is
    /// dropped, as OpenVPN drops it ("bad source address from client").
    pub ip: std::net::IpAddr,
    /// Peer/gateway address used in the net30 topology push (tun mode).
    pub gateway: std::net::IpAddr,
    /// Netmask string used for tap-mode ifconfig.
    pub mask: std::net::IpAddr,
    /// Prefix length for the per-peer device address.
    pub prefix_len: u8,
    /// Networks behind the client (OpenVPN's `iroute`), whose hosts it may
    /// send for in tun mode as well as its own address. Empty by default.
    ///
    /// This only widens what the [`Adapter`](super::Adapter) accepts from
    /// the client. Traffic *to* these networks reaches the client when the
    /// connector sends it to the client's device: the device names one
    /// address, so a connector that routes by device address, such as an
    /// [`L3Hub`](crate::L3Hub), needs a route of its own for them.
    pub iroutes: Vec<crate::IpPrefix>,
}

setters! {
    PeerConfig {
        set iroutes: Vec<crate::IpPrefix>;
    }
}

impl PeerConfig {
    /// Every field is required; see each for what it does.
    pub fn new(
        ip: std::net::IpAddr,
        gateway: std::net::IpAddr,
        mask: std::net::IpAddr,
        prefix_len: u8,
    ) -> PeerConfig {
        PeerConfig {
            ip,
            gateway,
            mask,
            prefix_len,
            iroutes: Vec::new(),
        }
    }
}

/// Authentication callback: given the credentials, return the IP config to push
/// or an error to reject the connection.
///
/// Threading: the [`Server`](super::Server) calls it on auth threads of
/// its own, with no lock held -- the way OpenVPN defers authentication to a
/// plugin or script (`KS_AUTH_DEFERRED`). It may take its time (asking an
/// auth backend, say) without holding up other clients, and may call back
/// into the server, `send_to_peer` included. At most
/// [`max_auth_threads`](super::ServerConfig::max_auth_threads) calls run at
/// once, and one client's run one at a time; the others wait their turn.
/// The client's handshake window bounds how long it has, waiting included:
/// a verdict that comes later is discarded, along with the session. A
/// panic counts as a refusal. It can still be running when
/// [`Server::close`](super::Server::close) returns.
///
/// A [`Peer`] used on its own calls it inline, from
/// [`handle_packet`](Peer::handle_packet), unless
/// [`deferred_auth`](Peer::deferred_auth) hands that job to the caller.
pub type OnAuth = Arc<dyn Fn(&AuthInfo) -> io::Result<PeerConfig> + Send + Sync>;

/// A client's credentials awaiting a verdict, from a [`Peer`] with
/// [`deferred_auth`](Peer::deferred_auth): pass it back to
/// [`Peer::complete_auth`] with the result.
#[derive(Debug, Clone)]
pub struct AuthRequest {
    /// What the client presented.
    pub info: AuthInfo,
    /// Names the key exchange awaiting the verdict.
    token: u64,
}

/// How a session gets its authentication verdict.
enum AuthMode {
    /// From the callback, called there and then.
    Inline(OnAuth),
    /// Later, from [`Peer::complete_auth`]; the key exchange is tagged with
    /// this token meanwhile.
    Deferred(u64),
}

/// Effects produced by processing one inbound datagram: raw datagrams to send
/// back to the peer, and an optional decrypted data-channel payload to deliver.
///
/// Built by the crate and read by callers, so it is `#[non_exhaustive]`: a
/// new kind of effect can be added without breaking anyone.
#[derive(Default, Debug)]
#[non_exhaustive]
pub struct PeerOutput {
    /// Raw datagrams (each already framed with opcode etc.) to transmit.
    pub send: Vec<Vec<u8>>,
    /// Decrypted payload to deliver to the adapter, if a data packet arrived.
    pub deliver: Option<Vec<u8>>,
    /// Whether, once this output is acted on, the peer has an authenticated
    /// session with a usable data channel key. Set in every output --
    /// from [`Peer::handle_packet`], [`Peer::tick`] and
    /// [`Peer::complete_auth`] alike -- and false in one that closes the
    /// connection.
    pub authenticated: bool,
    /// Set exactly once per session, by the datagram that completed its
    /// authentication: the config pushed to the client.
    pub connected: Option<PeerConfig>,
    /// With `connected`: the new session replaced an established one (the
    /// client reconnected from the same address), so the old connection is
    /// gone.
    pub replaced: bool,
    /// With [`Peer::deferred_auth`]: credentials to check, the verdict to
    /// be passed to [`Peer::complete_auth`].
    pub auth: Option<AuthRequest>,
    /// True if the connection should be torn down.
    pub close: bool,
    /// Why the connection is being torn down, when `close` is set and the
    /// reason is known.
    pub error: Option<io::Error>,
}

/// Timers a [`Peer`] runs on, driven by [`Peer::tick`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct PeerTimers {
    /// How long a TLS handshake plus key exchange may take (OpenVPN's
    /// `hand-window`).
    pub handshake_window: Duration,
    /// Send a keepalive ping after this long without sending anything
    /// (`--keepalive` first argument); zero disables.
    pub keepalive_interval: Duration,
    /// The `ping-restart` pushed to the client (`--keepalive` second
    /// argument). The server itself gives up after twice this without
    /// hearing from the client, as OpenVPN's server does; zero disables.
    pub keepalive_timeout: Duration,
    /// Renegotiate the data-channel key this long after it was negotiated
    /// (OpenVPN's `reneg-sec`); zero disables time-based renegotiation. A
    /// key is also renegotiated when its packet ids run low, or when an
    /// AES-GCM key has protected as much data as is safe, whatever this
    /// says.
    pub renegotiate_interval: Duration,
    /// How long the previous key keeps working after a renegotiation
    /// (OpenVPN's `tran-window`).
    pub transition_window: Duration,
}

impl Default for PeerTimers {
    /// OpenVPN's defaults: `hand-window 60`, `reneg-sec 3600`, `tran-window
    /// 3600`, and the `keepalive 10 60` its sample server configuration uses.
    fn default() -> PeerTimers {
        PeerTimers {
            handshake_window: Duration::from_secs(60),
            keepalive_interval: Duration::from_secs(10),
            keepalive_timeout: Duration::from_secs(60),
            renegotiate_interval: Duration::from_secs(3600),
            transition_window: Duration::from_secs(3600),
        }
    }
}

setters! {
    PeerTimers {
        set handshake_window: Duration;
        set keepalive_interval: Duration;
        set keepalive_timeout: Duration;
        set renegotiate_interval: Duration;
        set transition_window: Duration;
    }
}

/// Renegotiate a key once its outgoing packet id reaches this, well before
/// the id space runs out (packet_id.h PACKET_ID_WRAP_TRIGGER).
const PACKET_ID_WRAP_TRIGGER: u32 = 0xFF00_0000;

/// Renegotiate an AES-GCM key once the AES blocks it protected plus the
/// packets it protected pass this. It is OpenVPN's: 7/8 of `2^36 - 1`
/// (crypto.c cipher_get_aead_limits, ssl.c tls_get_limit_aead), the bound
/// that keeps the forgery probability under 2^-57, with room for the
/// renegotiation to finish before the bound itself is reached.
const AEAD_USAGE_LIMIT: u64 = ((1 << 36) - 1) / 8 * 7;

/// The bound itself: an AES-GCM key that has protected this much is used
/// no more, whether or not a successor is ready.
const AEAD_HARD_LIMIT: u64 = (1 << 36) - 1;

/// How long a rejected session lingers to deliver AUTH_FAILED (OpenVPN's
/// scheduled exit after send_auth_failed).
const AUTH_FAILED_EXIT: Duration = Duration::from_secs(5);

/// Longest control-channel plaintext message we buffer. The key exchange is
/// the largest (OpenVPN reads it into a 2 KiB buffer); this is generous.
const MAX_CONTROL_MESSAGE: usize = 64 * 1024;

/// Most TLS output a key holds back while its send window is full. A TLS
/// handshake flight, certificate chain included, fits several times over;
/// past it the client is not reading what we send, and the key fails.
const MAX_HELD_TLS: usize = 64 * 1024;

/// After a PUSH_REPLY, repeated PUSH_REQUESTs are ignored this long
/// (push.c: sent_push_reply_expiry). The reply itself is retransmitted by
/// the reliable layer until the client has it.
const PUSH_REPLY_HOLDOFF: Duration = Duration::from_secs(30);

/// Most TLS bytes a key holds from the client before it has ACKed our
/// reset. Until then nothing shows the reset came from whoever receives at
/// its address, so the bytes wait, unread by any TLS engine: running the
/// handshake -- a signature for the server's flight -- for anyone able to
/// forge two datagrams is work an attacker gets for free. A genuine client
/// sends its ClientHello, a few packets at most, and then waits for our
/// answer; one TLS record's worth is generous.
const MAX_UNPROVEN_TLS: usize = 16 * 1024;

/// A peer starts at most this many sessions beyond its first, per period:
/// each costs a TLS handshake, which a sender that does receive at the
/// address could otherwise have the server run back to back by restarting
/// its session over and over. A client restarting for real does so a
/// handful of times at most. Charged when the new session's sender ACKs our
/// reset, so resets from anyone else -- spoofed, and never ACKed -- cannot
/// use up the budget of the genuine client.
const NEW_SESSIONS: (u32, Duration) = (4, Duration::from_secs(60));

/// One OpenVPN peer (one client address).
pub struct Peer {
    config: Arc<purecrypto::tls::Config>,
    on_auth: OnAuth,
    /// Local session id for the first session; later ones draw a random id.
    first_local_id: Option<[u8; 8]>,
    /// The session carrying the data channel (OpenVPN's `TM_ACTIVE`).
    active: Option<Session>,
    /// A session still negotiating (OpenVPN's `TM_INITIAL`). It replaces
    /// `active` once it authenticates.
    initial: Option<Session>,
    /// A session opened by a hard reset while another session exists, not
    /// yet shown to come from whoever sent the reset: without tls-auth
    /// anyone can send one from the client's address. It displaces
    /// `initial` only once the sender has ACKed our hard reset, proving it
    /// receives what we send to that address.
    untrusted: Option<Session>,
    timers: PeerTimers,
    /// Hand authentication to the caller rather than calling `on_auth`.
    defer_auth: bool,
    /// The last [`AuthRequest`] token handed out.
    next_auth_token: u64,
    /// Last time an accepted packet arrived from the client.
    last_recv: Instant,
    /// Last time we produced a datagram for the client.
    last_sent: Instant,
    /// Sessions beyond the first started this period, and when it began
    /// (see [`NEW_SESSIONS`]).
    new_sessions: (Instant, u32),
    /// Since when the peer has had no authenticated session; `None` while
    /// it has one.
    unauthenticated_since: Option<Instant>,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("active", &self.active.is_some())
            .field("initial", &self.initial.is_some())
            .field("untrusted", &self.untrusted.is_some())
            .finish()
    }
}

/// Which of the peer's sessions a control packet belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Active,
    Initial,
    Untrusted,
}

impl Peer {
    /// Create a peer with the given TLS config, local session id, and auth
    /// hook. The local session id identifies the peer's first session on the
    /// wire (the server draws it at random); later sessions draw their own.
    ///
    /// Fails if `config` cannot make a TLS server connection.
    pub fn new(
        config: Arc<purecrypto::tls::Config>,
        local_id: [u8; 8],
        on_auth: OnAuth,
    ) -> io::Result<Peer> {
        // Sessions build their TLS connection on demand; surface a config
        // that cannot make one now rather than on the first client packet.
        TlsConnection::server(&config)
            .map_err(|e| invalid(format!("TLS server connection: {e:?}")))?;
        Ok(Peer::with_checked_config(config, local_id, on_auth))
    }

    /// [`new`](Self::new), for a `config` already known to make a TLS server
    /// connection: making one just to find out costs more than all else a
    /// bare hard reset costs, and the server checked when it started.
    pub(super) fn with_checked_config(
        config: Arc<purecrypto::tls::Config>,
        local_id: [u8; 8],
        on_auth: OnAuth,
    ) -> Peer {
        let now = Instant::now();
        Peer {
            config,
            on_auth,
            first_local_id: Some(local_id),
            active: None,
            initial: None,
            untrusted: None,
            timers: PeerTimers::default(),
            defer_auth: false,
            next_auth_token: 0,
            last_recv: now,
            last_sent: now,
            new_sessions: (now, 0),
            unauthenticated_since: Some(now),
        }
    }

    /// Whether `data` is a datagram that opens a session: a well-formed
    /// `P_CONTROL_HARD_RESET_CLIENT_V2`, packet 0 on key 0. A server should
    /// allocate a peer for an unknown address only on one of these.
    pub fn is_session_start(data: &[u8]) -> bool {
        let Some(&first) = data.first() else {
            return false;
        };
        let (opcode, key_id) = Opcode::from_byte(first);
        if opcode != Opcode::CONTROL_HARD_RESET_CLIENT_V2 || key_id != 0 {
            return false;
        }
        ControlPacket::parse(data)
            .is_ok_and(|p| p.pid == Some(0) && p.session_id != [0; 8] && p.acked_pids.is_empty())
    }

    /// Open the peer's first session for a client whose hard reset was
    /// answered statelessly, and which has since proved it got the answer
    /// (OpenVPN 2.6's HMAC session id; ssl.c session_skip_to_pre_start).
    /// The local session id given to [`new`](Self::new) must be the one the
    /// answer carried, and `remote_id` is the client's. The hard resets
    /// then count as exchanged: pass the client's packet that proved it to
    /// [`handle_packet`](Self::handle_packet) next.
    // Only the server answers resets statelessly, and it is absent on wasm.
    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn open_after_stateless_reset(&mut self, remote_id: [u8; 8]) -> io::Result<()> {
        let local_id = self
            .first_local_id
            .ok_or_else(|| invalid("the peer already opened a session"))?;
        let session = Session::after_reset(local_id, remote_id, self.timers);
        self.first_local_id = None;
        self.initial = Some(session);
        Ok(())
    }

    /// Replace the default timers.
    pub fn with_timers(mut self, timers: PeerTimers) -> Peer {
        self.timers = timers;
        self
    }

    /// Do not call `on_auth` from [`handle_packet`](Self::handle_packet):
    /// hand the credentials out as [`PeerOutput::auth`] instead, for the
    /// caller to check wherever suits it -- without the peer locked, say --
    /// and report back through [`complete_auth`](Self::complete_auth).
    pub fn deferred_auth(mut self) -> Peer {
        self.defer_auth = true;
        self
    }

    /// The session whose settings describe the connection: the active one,
    /// or the one negotiating if nothing is active yet.
    fn current(&self) -> Option<&Session> {
        self.active.as_ref().or(self.initial.as_ref())
    }

    /// The peer config pushed to the client after authentication (if any).
    pub fn peer_config(&self) -> Option<&PeerConfig> {
        self.active.as_ref()?.peer_cfg.as_ref()
    }

    /// Layer (2 for tap, 3 for tun).
    pub fn layer(&self) -> u8 {
        self.current().map_or(3, |s| s.layer)
    }

    /// Peer-info (`IV_*`) key/values the client advertised during the key
    /// exchange. Empty until the peer authenticates.
    pub fn peer_info(&self) -> &HashMap<String, String> {
        static EMPTY: std::sync::OnceLock<HashMap<String, String>> = std::sync::OnceLock::new();
        match &self.active {
            Some(s) => &s.peer_info,
            None => EMPTY.get_or_init(HashMap::new),
        }
    }

    /// TLS output held back, across all sessions' current keys: what the
    /// TLS engines produced and the reliable layer has not sent yet.
    #[cfg(test)]
    pub(super) fn held_tls(&self) -> usize {
        [&self.active, &self.initial, &self.untrusted]
            .into_iter()
            .flatten()
            .map(|s| s.primary.reliable.held_len())
            .sum()
    }

    /// Control packets sent and not yet acknowledged, across all sessions.
    #[cfg(test)]
    pub(super) fn unacked_count(&self) -> usize {
        [&self.active, &self.initial, &self.untrusted]
            .into_iter()
            .flatten()
            .map(|s| s.primary.reliable.unacked_count())
            .sum()
    }

    fn session_mut(&mut self, slot: Slot) -> Option<&mut Session> {
        match slot {
            Slot::Active => self.active.as_mut(),
            Slot::Initial => self.initial.as_mut(),
            Slot::Untrusted => self.untrusted.as_mut(),
        }
    }

    /// Drive periodic maintenance: retransmit any unacknowledged control
    /// packets whose deadline has passed at `now`.
    ///
    /// The OpenVPN reliable layer must re-send `P_CONTROL` packets that the
    /// peer has not ACKed within a timeout (~1s, backing off exponentially).
    /// Because the crate is caller-driven (no per-peer background thread), the
    /// server/[`Adapter`](super::Adapter) must call this on a timer — roughly
    /// once per retransmit interval (~1s) — for each live peer. Returns the
    /// datagrams to re-send in [`PeerOutput`]`::send`. As in OpenVPN, a
    /// packet is retried for as long as its key lives: a lost ACK alone never
    /// ends a session.
    ///
    /// The same tick runs the peer's other timers: a session that has not
    /// completed its key exchange within the handshake window is abandoned,
    /// as is a peer that has gone that long without an authenticated
    /// session, however many sessions it started meanwhile; an idle established peer is sent a keepalive ping, and one not heard
    /// from for the ping-restart timeout is closed.
    pub fn tick(&mut self, now: Instant) -> io::Result<PeerOutput> {
        let mut out = PeerOutput::default();
        for slot in [Slot::Active, Slot::Initial, Slot::Untrusted] {
            let Some(s) = self.session_mut(slot) else {
                continue;
            };
            // Only the primary key's: the lame duck's control channel is
            // over (see Session::lame).
            out.send.extend(s.primary.reliable.tick(now).resend);
            if let Some((at, why)) = &s.auth_failed {
                if now >= *at {
                    let e = io::Error::new(io::ErrorKind::PermissionDenied, why.clone());
                    self.fail_session(slot, &mut out, Some(e));
                }
                continue;
            }
            if s.lame
                .as_ref()
                .and_then(|k| k.must_die)
                .is_some_and(|t| now >= t)
            {
                s.lame = None;
            }
            if s.primary.must_die.is_some_and(|t| now >= t) {
                // A fallback key reached the end of its transition window
                // with no successor.
                let e = io::Error::new(io::ErrorKind::TimedOut, "data channel key expired");
                self.fail_session(slot, &mut out, Some(e));
            } else if !s.primary.kx_done && s.primary.must_negotiate.is_some_and(|t| now >= t) {
                let e = io::Error::new(
                    io::ErrorKind::TimedOut,
                    "key negotiation did not complete within the handshake window",
                );
                self.fail_key(slot, &mut out, e);
            }
        }

        if let Some(s) = self.active.as_mut()
            && s.retire_exhausted_keys()
        {
            let e = io::Error::other("data channel key reached its AES-GCM usage limit");
            self.fail_session(Slot::Active, &mut out, Some(e));
        }

        let timers = self.timers;
        if let Some(s) = self.active.as_mut()
            && s.should_renegotiate(now, &timers)
        {
            let reset = s.soft_reset(&timers, now);
            out.send.push(reset.to_bytes(&[]));
        }

        // Each session has the handshake window to authenticate in, but a
        // new hard reset brings a new session, with a window of its own:
        // someone sending one now and then would keep a peer that never
        // authenticates, holding its place in the server's table, for as
        // long as they liked. So the peer itself has the window too,
        // counted from when it was created or lost its authenticated
        // session, whatever new sessions come meanwhile.
        match self.unauthenticated_since {
            _ if self.active.is_some() => self.unauthenticated_since = None,
            None => self.unauthenticated_since = Some(now),
            Some(since) => {
                if since
                    .checked_add(self.timers.handshake_window)
                    .is_some_and(|t| now >= t)
                {
                    self.initial = None;
                    self.untrusted = None;
                    out.close = true;
                    out.error = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no session authenticated within the handshake window",
                    ));
                    return Ok(self.report(out));
                }
            }
        }

        if self.active.is_some() {
            let restart = self.timers.keepalive_timeout.saturating_mul(2);
            if !restart.is_zero() && now.saturating_duration_since(self.last_recv) >= restart {
                out.close = true;
                out.error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "nothing received within the ping-restart timeout",
                ));
                return Ok(self.report(out));
            }
            let interval = self.timers.keepalive_interval;
            if !interval.is_zero()
                && now.saturating_duration_since(self.last_sent) >= interval
                && let Ok(ping) = self.send_data_at(&OPENVPN_PING, now)
            {
                out.send.push(ping);
            }
        }
        if !out.send.is_empty() {
            self.last_sent = now;
        }
        Ok(self.report(out))
    }

    /// Process one inbound datagram from the peer.
    ///
    /// An `Err` means this one datagram was dropped (malformed, replayed,
    /// out of window, undecryptable, from an unknown session, ...) and the
    /// peer is unaffected: anyone can put a datagram on the peer's address,
    /// so none of those may cost the peer its connection. A condition that is
    /// fatal to the connection is reported as `Ok` with
    /// [`PeerOutput::close`] set instead.
    pub fn handle_packet(&mut self, data: &[u8]) -> io::Result<PeerOutput> {
        self.handle_packet_at(data, Instant::now())
    }

    /// [`handle_packet`](Self::handle_packet), as if received at `now`.
    pub(super) fn handle_packet_at(&mut self, data: &[u8], now: Instant) -> io::Result<PeerOutput> {
        let Some(&first) = data.first() else {
            return Err(invalid("empty packet"));
        };
        let (opcode, key_id) = Opcode::from_byte(first);
        let (out, active) = match opcode {
            // Data only ever goes to the active session.
            Opcode::DATA_V1 => (self.handle_data(key_id, data)?, true),
            // Only a client (key method 2) hard reset may open a session;
            // P_DATA_V2 needs a peer-id we never push; the rest are unknown.
            Opcode::CONTROL_HARD_RESET_CLIENT_V2
            | Opcode::CONTROL_SOFT_RESET_V1
            | Opcode::CONTROL_V1
            | Opcode::ACK_V1 => self.handle_control(key_id, data, now)?,
            _ => return Err(invalid(format!("unexpected opcode {opcode}"))),
        };
        // Only a packet that got past validation, and that belongs to the
        // session in use, counts as hearing from the client: a hard reset
        // anyone can send from its address must not hold off ping-restart.
        // A session that has just taken over counts too.
        if active || out.connected.is_some() {
            self.last_recv = now;
        }
        if !out.send.is_empty() {
            self.last_sent = now;
        }
        Ok(self.report(out))
    }

    /// Handle a control packet. Returns the output, and whether the packet
    /// belonged to the active session -- the only one whose packets say the
    /// client is still there.
    fn handle_control(
        &mut self,
        key_id: u8,
        data: &[u8],
        now: Instant,
    ) -> io::Result<(PeerOutput, bool)> {
        let pkt = ControlPacket::parse(data)?;
        let sid = pkt.session_id;
        if sid == [0; 8] {
            return Err(invalid("control packet without a session id"));
        }

        // Route by the sender's session id (ssl.c tls_pre_decrypt).
        let mut out = PeerOutput::default();
        let mut reset = None;
        // For a new session or key: what its reliable layer made of the
        // reset that opened it.
        let mut opened = None;
        let mut slot = if self.active.as_ref().is_some_and(|s| s.remote_id == sid) {
            Slot::Active
        } else if self.initial.as_ref().is_some_and(|s| s.remote_id == sid) {
            Slot::Initial
        } else if self.untrusted.as_ref().is_some_and(|s| s.remote_id == sid) {
            Slot::Untrusted
        } else if pkt.opcode == Opcode::CONTROL_HARD_RESET_CLIENT_V2 {
            // A new session: it starts with packet 0 on key 0.
            if pkt.pid != Some(0) || key_id != 0 {
                return Err(invalid("hard reset must be packet 0 on key 0"));
            }
            let local_id = match self.first_local_id {
                Some(id) => id,
                None => {
                    let mut id = [0u8; 8];
                    fill_random(&mut id)?;
                    id
                }
            };
            let (mut session, server_reset) = Session::new(local_id, sid, self.timers);
            // The packet has to pass the new session's checks before the
            // session takes a slot (tls_pre_decrypt validates first).
            opened = Some(session.primary.recv(key_id, pkt.clone())?);
            self.first_local_id = None;
            reset = Some(server_reset);
            // The peer's first session has nothing to displace. Any later
            // one waits in the untrusted slot -- replacing whatever reset
            // was waiting there, which costs nothing -- until the sender
            // shows it gets our answers: a reset anyone could send must
            // not end a handshake in progress.
            if self.active.is_none() && self.initial.is_none() {
                self.initial = Some(session);
                Slot::Initial
            } else {
                self.untrusted = Some(session);
                Slot::Untrusted
            }
        } else {
            return Err(invalid("control packet for no known session"));
        };

        let auth = if self.defer_auth {
            self.next_auth_token += 1;
            AuthMode::Deferred(self.next_auth_token)
        } else {
            AuthMode::Inline(self.on_auth.clone())
        };
        let config = self.config.clone();
        let timers = self.timers;
        let session = self.session_mut(slot).expect("slot just resolved");
        // The client asks for a new key (ssl.c key_state_soft_reset): only
        // once the current one is in use, and only for the next key id, so a
        // retransmission of the soft reset that started the current key is
        // just a duplicate. The packet must pass the new key's checks --
        // packet 0 of its stream, ACKs for this session -- before the key
        // replaces the working one (tls_pre_decrypt validates first).
        if pkt.opcode == Opcode::CONTROL_SOFT_RESET_V1
            && session.primary.data.is_some()
            && session.auth_failed.is_none()
            && key_id == session.next_key_id
        {
            if pkt.pid != Some(0) {
                return Err(invalid("soft reset must be packet 0 of its key"));
            }
            let (mut ks, server_reset) = session.next_key(&timers, now);
            opened = Some(ks.recv(key_id, pkt.clone())?);
            session.install_key(ks, &timers, now);
            reset = Some(server_reset);
        }
        let tls_bytes = match opened {
            Some(bytes) => bytes,
            None => session.primary.recv(key_id, pkt)?,
        };
        // The ACK of our hard reset proves the sender receives what we send
        // to this address: the client restarted, and has given up on any
        // session still negotiating, which this one now replaces.
        if slot == Slot::Untrusted && session.primary.reliable.reset_acked() {
            if !self.allow_new_session(now) {
                self.untrusted = None;
                return Err(invalid("too many new sessions from this address"));
            }
            self.initial = self.untrusted.take();
            slot = Slot::Initial;
        }
        let session = self.session_mut(slot).expect("slot just resolved");
        if let Some(reset) = reset {
            // Our reset carries the ACK for theirs.
            out.send
                .push(reset.to_bytes(&session.primary.reliable.take_pending_acks()));
        }
        if let Err(e) = session.process_tls(&config, &tls_bytes, &auth, &mut out) {
            self.fail_key(slot, &mut out, e);
            return Ok((out, slot == Slot::Active));
        }
        self.settle(slot, &mut out);
        Ok((out, slot == Slot::Active))
    }

    /// Count a session beyond the first starting its handshake; whether the
    /// budget allows it (see [`NEW_SESSIONS`]).
    fn allow_new_session(&mut self, now: Instant) -> bool {
        let (max, period) = NEW_SESSIONS;
        let (start, count) = &mut self.new_sessions;
        if now.saturating_duration_since(*start) >= period {
            *start = now;
            *count = 0;
        }
        *count += 1;
        *count <= max
    }

    /// Record in `out` whether the peer is authenticated once it is acted
    /// on (see [`PeerOutput::authenticated`]).
    fn report(&self, mut out: PeerOutput) -> PeerOutput {
        // Mid-renegotiation the new key is not ready but the old one is.
        out.authenticated = !out.close
            && self.active.as_ref().is_some_and(|s| {
                s.primary.data.is_some() || s.lame.as_ref().is_some_and(|k| k.data.is_some())
            });
        out
    }

    /// After a session made progress: a session that has authenticated
    /// takes over the data channel.
    fn settle(&mut self, slot: Slot, out: &mut PeerOutput) {
        // Authenticating is as good a proof as any that an untrusted
        // session's client is the real one.
        let done = match slot {
            Slot::Active => None,
            Slot::Initial => self.initial.as_ref(),
            Slot::Untrusted => self.untrusted.as_ref(),
        };
        if done.is_some_and(|s| s.primary.kx_done) {
            let session = match slot {
                Slot::Untrusted => self.untrusted.take(),
                _ => self.initial.take(),
            };
            out.connected = session.as_ref().and_then(|s| s.peer_cfg.clone());
            out.replaced = self.active.is_some();
            self.active = session;
        }
    }

    /// Finish an authentication handed out as [`PeerOutput::auth`], with
    /// what [`OnAuth`] -- or whatever stands in for it -- decided.
    ///
    /// A request whose key is gone by now (its handshake window ran out,
    /// the client started over, ...) is ignored, and so is one completed
    /// twice: the output is then empty.
    pub fn complete_auth(
        &mut self,
        req: &AuthRequest,
        result: io::Result<PeerConfig>,
    ) -> PeerOutput {
        let mut out = PeerOutput::default();
        let Some(slot) = self.awaiting(req) else {
            return self.report(out);
        };
        let session = self.session_mut(slot).expect("slot just resolved");
        let (_, kx) = session.primary.auth_pending.take().expect("checked above");
        let res = session.apply_auth(
            kx,
            result.map_err(|e| format!("authentication failed: {e}")),
        );
        let pumped = session.pump_tls(&mut out);
        if let Err(e) = res.and(pumped) {
            self.fail_key(slot, &mut out, e);
            return self.report(out);
        }
        self.settle(slot, &mut out);
        if !out.send.is_empty() {
            self.last_sent = Instant::now();
        }
        self.report(out)
    }

    /// Whether a verdict on `req` would still be acted on: its key exchange
    /// is still waiting for one. Checking credentials no longer awaited is
    /// wasted work.
    pub fn awaits(&self, req: &AuthRequest) -> bool {
        self.awaiting(req).is_some()
    }

    /// The session whose key exchange awaits the verdict on `req`.
    fn awaiting(&self, req: &AuthRequest) -> Option<Slot> {
        let pending = |s: &Option<Session>| {
            s.as_ref().is_some_and(|s| {
                s.primary
                    .auth_pending
                    .as_ref()
                    .is_some_and(|(t, _)| *t == req.token)
            })
        };
        if pending(&self.active) {
            Some(Slot::Active)
        } else if pending(&self.initial) {
            Some(Slot::Initial)
        } else if pending(&self.untrusted) {
            Some(Slot::Untrusted)
        } else {
            None
        }
    }

    /// The session's newest key failed to negotiate (TLS error, timeout). A
    /// renegotiation that fails falls back to the previous key for the rest
    /// of its transition window (OpenVPN keeps its lame duck key the same
    /// way); a session with nothing to fall back to fails.
    fn fail_key(&mut self, slot: Slot, out: &mut PeerOutput, err: io::Error) {
        if let Some(s) = self.session_mut(slot)
            && let Some(lame) = s.lame.take()
        {
            s.primary = lame;
            return;
        }
        self.fail_session(slot, out, Some(err));
    }

    /// A session hit a fatal error or timed out: drop it. The connection
    /// only ends when no session is left.
    fn fail_session(&mut self, slot: Slot, out: &mut PeerOutput, err: Option<io::Error>) {
        match slot {
            Slot::Active => self.active = None,
            Slot::Initial => self.initial = None,
            Slot::Untrusted => self.untrusted = None,
        }
        if self.active.is_none() && self.initial.is_none() && self.untrusted.is_none() {
            out.close = true;
            out.error = err;
        }
    }

    // --- data channel ---------------------------------------------------------

    fn handle_data(&mut self, key_id: u8, data: &[u8]) -> io::Result<PeerOutput> {
        let mut out = PeerOutput::default();
        let session = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("stream not ready for data transmission"))?;
        let opts = session
            .opts
            .as_ref()
            .ok_or_else(|| invalid("stream not ready for data transmission"))?;
        // During a renegotiation both the new and the previous key are live;
        // the packet's key id says which one it is under.
        let dk = [Some(&mut session.primary), session.lame.as_mut()]
            .into_iter()
            .flatten()
            .find(|k| k.key_id == key_id)
            .and_then(|k| k.data.as_mut())
            .ok_or_else(|| invalid("data packet for an unknown key id"))?;
        if opts.cipher_block == super::GCM && dk.aead_exhausted() {
            return Err(invalid("data channel key reached its AES-GCM usage limit"));
        }

        let mut buf = data.to_vec();
        let dec = data::decrypt(opts, &dk.keys, &mut buf)?
            .ok_or_else(|| invalid("data packet failed authentication"))?;
        if !dk.replay.check(dec.pid) {
            return Err(invalid("replayed data packet"));
        }
        dk.in_pid = dk.in_pid.max(dec.pid);
        dk.dec_blocks += aead_blocks(opts, data.len());
        if !dec.is_ping {
            out.deliver = Some(dec.payload.to_vec());
        }
        Ok(out)
    }

    /// Encrypt and frame an outbound IP packet / Ethernet frame for the peer.
    pub fn send_data(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.send_data_at(payload, Instant::now())
    }

    pub(super) fn send_data_at(&mut self, payload: &[u8], now: Instant) -> io::Result<Vec<u8>> {
        let session = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("stream not ready for data transmission"))?;
        let opts = session
            .opts
            .as_ref()
            .ok_or_else(|| invalid("stream not ready for data transmission"))?;
        // A new key only takes over sending once the client has had time to
        // install it (ssl.c tls_select_encryption_key and its
        // auth_deferred_expire); until then the previous key, if any, is used.
        let primary_ready = session.primary.data.is_some()
            && (session.primary.send_from.is_some_and(|t| now >= t)
                || !session.lame.as_ref().is_some_and(|k| k.data.is_some()));
        let ks = if primary_ready {
            &mut session.primary
        } else {
            session
                .lame
                .as_mut()
                .filter(|k| k.data.is_some())
                .ok_or_else(|| invalid("stream not ready for data transmission"))?
        };
        let key_id = ks.key_id;
        let dk = ks.data.as_mut().expect("checked above");
        if opts.cipher_block == super::GCM && dk.aead_exhausted() {
            return Err(invalid("data channel key reached its AES-GCM usage limit"));
        }
        // The packet id is the GCM nonce prefix: wrapping it would reuse a
        // nonce under the same key. OpenVPN (packet_id_send_update) refuses
        // to send once the id space is spent; only a new key resets it, and
        // one is negotiated well before (PACKET_ID_WRAP_TRIGGER).
        dk.out_pid = dk
            .out_pid
            .checked_add(1)
            .ok_or_else(|| invalid("data channel packet id exhausted; renegotiation required"))?;
        self.last_sent = now;
        let pkt = data::encrypt(opts, &dk.keys, key_id, dk.out_pid, payload, fill_random)?;
        dk.enc_blocks += aead_blocks(opts, pkt.len());
        Ok(pkt)
    }
}

/// One TLS session with the client (OpenVPN's `tls_session`), named on the
/// wire by the pair of session ids the two hard resets carry.
struct Session {
    local_id: [u8; 8],
    remote_id: [u8; 8],
    /// The newest key: negotiating, or in use (OpenVPN's `KS_PRIMARY`).
    primary: KeyState,
    /// The previous key, still accepted until its transition window ends
    /// (OpenVPN's `KS_LAME_DUCK`). Only its data channel lives on: as in
    /// OpenVPN, which only services the primary key's reliable layer and
    /// takes control packets for the primary key id alone
    /// (tls_pre_decrypt: "key IDs out of sync"), its control channel is
    /// neither retransmitted nor fed. Were it kept running, whatever it
    /// had in flight would be resent to a client that has moved on, for
    /// the whole transition window.
    lame: Option<KeyState>,
    /// Key id the next renegotiation uses: 1..=7, then back to 1 (0 is the
    /// session's first key only).
    next_key_id: u8,

    // Negotiated state, populated during the key exchange.
    opts: Option<Options>,
    peer_cfg: Option<PeerConfig>,
    /// Layer: 2 = tap (frames), 3 = tun (packets).
    layer: u8,
    /// Peer-info key/values (`IV_*`) the client advertised during the key
    /// exchange, retained for post-auth queries / diagnostics.
    peer_info: HashMap<String, String>,
    timers: PeerTimers,
    /// Set when the client was refused (credentials, data cipher): when to
    /// drop the session, which lingers only to deliver AUTH_FAILED, and why.
    auth_failed: Option<(Instant, String)>,
    /// Data cipher chosen by negotiation, pushed to the client.
    pushed_cipher: Option<&'static str>,
    /// Until then, a PUSH_REQUEST gets no new PUSH_REPLY: one was just
    /// sent.
    push_reply_until: Option<Instant>,
}

/// One TLS handshake and what it produced (OpenVPN's `key_state`): its own
/// reliable transport, the key-method-2 exchange, and the data-channel keys.
struct KeyState {
    key_id: u8,
    /// Made when the client's first TLS bytes are fed to it, once it has
    /// ACKed our reset: a reset alone does not cost a TLS connection.
    tls: Option<TlsConnection>,
    reliable: Reliable,
    /// TLS bytes from the client held until it ACKs our reset (see
    /// [`MAX_UNPROVEN_TLS`]).
    unproven_tls: Vec<u8>,
    /// Key-method-2 exchange scratch (read incrementally from the TLS stream).
    ctrl_buf: Vec<u8>,
    kx_done: bool,
    /// The key exchange must complete by then; `None` if the handshake
    /// window is too long for a deadline to be computed: never.
    must_negotiate: Option<Instant>,
    /// When the key exchange completed.
    established: Option<Instant>,
    /// Send with this key only from then on, if an older one is usable;
    /// `None`: not while the older one is.
    send_from: Option<Instant>,
    /// The key stops being used then (set once it is superseded).
    must_die: Option<Instant>,
    /// Server random material (r1||r2) generated for the key exchange and
    /// reused by [`Session::derive_keys`] so the PRF inputs match what was
    /// sent.
    server_random: [u8; 64],
    /// A key exchange awaiting its authentication verdict, with the token
    /// of the [`AuthRequest`] handed out for it.
    auth_pending: Option<(u64, KeyExchange)>,
    data: Option<DataKeys>,
}

/// Data-channel keys and packet-id state for one key.
struct DataKeys {
    keys: PeerKeys,
    replay: Window,
    /// Outgoing data-channel packet id (the last one used).
    out_pid: u32,
    /// Highest packet id accepted from the client.
    in_pid: u32,
    /// AES blocks of plaintext encrypted / decrypted under this key, for
    /// the AEAD usage limit.
    enc_blocks: u64,
    dec_blocks: u64,
}

impl DataKeys {
    fn new(keys: PeerKeys) -> DataKeys {
        DataKeys {
            keys,
            replay: Window::new(),
            out_pid: 0,
            in_pid: 0,
            enc_blocks: 0,
            dec_blocks: 0,
        }
    }

    /// Whether the key has protected as much as AES-GCM safely allows
    /// (crypto.h aead_usage_limit_reached): blocks plus packets, in
    /// either direction.
    fn aead_limit_reached(&self) -> bool {
        self.aead_usage() > AEAD_USAGE_LIMIT
    }

    /// Whether the key has reached the AES-GCM bound itself.
    fn aead_exhausted(&self) -> bool {
        self.aead_usage() >= AEAD_HARD_LIMIT
    }

    /// Blocks plus packets, in whichever direction has seen more.
    fn aead_usage(&self) -> u64 {
        let enc = self.enc_blocks.saturating_add(u64::from(self.out_pid));
        let dec = self.dec_blocks.saturating_add(u64::from(self.in_pid));
        enc.max(dec)
    }
}

/// AES blocks a data packet of `len` bytes carried, if it is AES-GCM
/// (`[opcode][pid][tag][ciphertext]`, the ciphertext as long as the
/// plaintext); 0 otherwise, as only AEAD ciphers have a usage limit.
fn aead_blocks(opts: &Options, len: usize) -> u64 {
    if opts.cipher_block != super::GCM {
        return 0;
    }
    (len.saturating_sub(1 + 4 + 16) as u64).div_ceil(16)
}

impl KeyState {
    fn new(
        key_id: u8,
        local_id: [u8; 8],
        remote_id: [u8; 8],
        timers: &PeerTimers,
        now: Instant,
    ) -> KeyState {
        let mut reliable = Reliable::new(local_id);
        reliable.peer_id = remote_id;
        reliable.key_id = key_id;
        // ssl.c auth_deferred_expire_window: the handshake window, or half
        // the renegotiation interval if that is shorter.
        let mut defer = timers.handshake_window;
        if !timers.renegotiate_interval.is_zero() {
            defer = defer.min(timers.renegotiate_interval / 2);
        }
        KeyState {
            key_id,
            tls: None,
            reliable,
            unproven_tls: Vec::new(),
            ctrl_buf: Vec::new(),
            kx_done: false,
            must_negotiate: now.checked_add(timers.handshake_window),
            established: None,
            send_from: now.checked_add(defer),
            must_die: None,
            server_random: [0u8; 64],
            auth_pending: None,
            data: None,
        }
    }

    /// The key's TLS connection. It exists once the client's TLS has been
    /// fed to it, and nothing is written to it before that.
    fn tls(&mut self) -> io::Result<&mut TlsConnection> {
        self.tls
            .as_mut()
            .ok_or_else(|| invalid("no TLS connection yet"))
    }

    /// Run a control packet through this key's reliable layer, returning the
    /// TLS bytes it made available in order. `Err` drops the packet.
    fn recv(&mut self, key_id: u8, pkt: ControlPacket) -> io::Result<Vec<u8>> {
        if key_id != self.key_id {
            return Err(invalid("control packet for another key id"));
        }
        Ok(self.reliable.recv_packet(pkt)?.tls_bytes)
    }

    /// Emit any pending TLS output as P_CONTROL_V1 packets, plus standalone
    /// ACKs for what we owe but no control packet carried.
    fn pump(&mut self, out: &mut PeerOutput) -> io::Result<()> {
        // `pop` returns the whole pending wire stream in one call.
        let tls_out = match &mut self.tls {
            Some(tls) => tls.pop().map_err(|e| invalid(format!("tls pop: {e:?}")))?,
            None => Vec::new(),
        };

        self.reliable.queue_tls(&tls_out);
        // OpenVPN gives up on a key whose output it has no buffer for; a
        // client that never ACKs would otherwise have us hold its output
        // without bound.
        if self.reliable.held_len() > MAX_HELD_TLS {
            return Err(invalid("control channel send backlog exceeded"));
        }
        // No TLS goes out until the client has ACKed our reset (ssl.c moves
        // TLS output to the reliable layer only from S_START): until then
        // nothing shows the reset came from whoever receives at the
        // address, and without tls-auth anyone can send one and a
        // ClientHello, to have our whole flight -- many times their size,
        // and retransmitted -- sent to a victim. Past that, whatever the
        // send window has room for: ACKs arriving later open it, and this
        // runs again for every packet received.
        if self.reliable.reset_acked() {
            for pkt in self.reliable.flush_tls() {
                // The ACKs we owe ride along, as many as fit each packet.
                let acks = self.reliable.take_pending_acks();
                out.send.push(pkt.to_bytes(&acks));
            }
        }

        // ACKs no control packet carried go in plain ACKs.
        while self.reliable.has_pending_acks() {
            let acks = self.reliable.take_pending_acks();
            let ack = self.reliable.build_ack();
            out.send.push(ack.to_bytes(&acks));
        }
        Ok(())
    }
}

impl Session {
    /// Open a session for a client hard reset from `remote_id`, returning it
    /// with the server hard reset to send back.
    fn new(local_id: [u8; 8], remote_id: [u8; 8], timers: PeerTimers) -> (Session, ControlPacket) {
        let mut ks = KeyState::new(0, local_id, remote_id, &timers, Instant::now());
        let reset = ks.reliable.build_hard_reset();
        (Session::with_key(ks, timers), reset)
    }

    /// Open a session whose hard resets were exchanged statelessly: the
    /// client's reset was answered, ours acknowledged.
    // Only the server answers resets statelessly, and it is absent on wasm.
    #[cfg(not(target_family = "wasm"))]
    fn after_reset(local_id: [u8; 8], remote_id: [u8; 8], timers: PeerTimers) -> Session {
        let mut ks = KeyState::new(0, local_id, remote_id, &timers, Instant::now());
        ks.reliable.skip_reset();
        Session::with_key(ks, timers)
    }

    fn with_key(ks: KeyState, timers: PeerTimers) -> Session {
        Session {
            local_id: ks.reliable.local_id,
            remote_id: ks.reliable.peer_id,
            primary: ks,
            lame: None,
            next_key_id: 1,
            opts: None,
            peer_cfg: None,
            layer: 3,
            peer_info: HashMap::new(),
            timers,
            auth_failed: None,
            pushed_cipher: None,
            push_reply_until: None,
        }
    }

    /// Whether the server should start a renegotiation itself: the key in
    /// use is due by age, packet count or AEAD usage, and none is under way.
    fn should_renegotiate(&self, now: Instant, timers: &PeerTimers) -> bool {
        let k = &self.primary;
        let (Some(established), Some(data)) = (k.established, k.data.as_ref()) else {
            return false;
        };
        if self.auth_failed.is_some() {
            return false;
        }
        let used_up =
            data.out_pid >= PACKET_ID_WRAP_TRIGGER || (self.is_gcm() && data.aead_limit_reached());
        // A key we fell back to after a failed renegotiation just runs out
        // its transition window -- unless it cannot safely last that long:
        // then the renegotiation is tried again.
        if k.must_die.is_some() {
            return used_up;
        }
        let by_age = !timers.renegotiate_interval.is_zero()
            && now.saturating_duration_since(established) >= timers.renegotiate_interval;
        by_age || used_up
    }

    /// Whether the data channel runs AES-GCM, which has a usage limit.
    fn is_gcm(&self) -> bool {
        self.opts
            .as_ref()
            .is_some_and(|o| o.cipher_block == super::GCM)
    }

    /// Stop using AES-GCM keys that reached the bound itself. Whether the
    /// session is left without a usable key, and must end.
    fn retire_exhausted_keys(&mut self) -> bool {
        if !self.is_gcm() {
            return false;
        }
        let exhausted = |k: &KeyState| k.data.as_ref().is_some_and(DataKeys::aead_exhausted);
        if self.lame.as_ref().is_some_and(exhausted) {
            self.lame = None;
        }
        exhausted(&self.primary)
    }

    /// Start negotiating the next key (ssl.c key_state_soft_reset): the
    /// current key becomes the lame duck, kept for the transition window,
    /// and a fresh TLS handshake runs on the next key id. Returns our
    /// P_CONTROL_SOFT_RESET_V1, which opens the new key's reliable stream.
    fn soft_reset(&mut self, timers: &PeerTimers, now: Instant) -> ControlPacket {
        let (ks, reset) = self.next_key(timers, now);
        self.install_key(ks, timers, now);
        reset
    }

    /// The next key, not yet installed, with the soft reset that opens its
    /// stream.
    fn next_key(&self, timers: &PeerTimers, now: Instant) -> (KeyState, ControlPacket) {
        let key_id = self.next_key_id;
        let mut ks = KeyState::new(key_id, self.local_id, self.remote_id, timers, now);
        let reset = ks.reliable.build_soft_reset();
        (ks, reset)
    }

    /// Make `ks`, from [`next_key`](Self::next_key), the primary key; the
    /// current one becomes the lame duck.
    fn install_key(&mut self, ks: KeyState, timers: &PeerTimers, now: Instant) {
        let key_id = ks.key_id;
        self.next_key_id = if key_id >= 7 { 1 } else { key_id + 1 };
        let mut old = std::mem::replace(&mut self.primary, ks);
        if old.data.is_some() {
            // A transition window too long to add up is no deadline at all.
            let die = now.checked_add(timers.transition_window);
            old.must_die = match (old.must_die, die) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            self.lame = Some(old);
        }
    }

    /// Feed in-order TLS bytes to the engine, run the control exchange on the
    /// plaintext, and queue the TLS output. An error is fatal to the session:
    /// past the reliable layer the bytes are part of its TLS stream, and a
    /// TLS error ends an OpenVPN key state too.
    fn process_tls(
        &mut self,
        config: &purecrypto::tls::Config,
        tls_bytes: &[u8],
        auth: &AuthMode,
        out: &mut PeerOutput,
    ) -> io::Result<()> {
        let res = self.advance_tls(config, tls_bytes, auth, &mut out.auth);
        // Flush what the TLS engine queued even on failure (an alert,
        // typically), along with the ACKs we owe.
        let pumped = self.pump_tls(out);
        res.and(pumped)
    }

    fn advance_tls(
        &mut self,
        config: &purecrypto::tls::Config,
        tls_bytes: &[u8],
        auth: &AuthMode,
        request: &mut Option<AuthRequest>,
    ) -> io::Result<()> {
        let k = &mut self.primary;
        // Nothing reaches the TLS engine before the client has ACKed our
        // reset (see MAX_UNPROVEN_TLS); what came before is fed then.
        if !k.reliable.reset_acked() {
            k.unproven_tls.extend_from_slice(tls_bytes);
            if k.unproven_tls.len() > MAX_UNPROVEN_TLS {
                return Err(invalid("too much TLS before our reset was acknowledged"));
            }
            return Ok(());
        }
        let mut bytes = std::mem::take(&mut k.unproven_tls);
        bytes.extend_from_slice(tls_bytes);
        if bytes.is_empty() {
            return Ok(());
        }
        let tls = match &mut k.tls {
            Some(tls) => tls,
            None => k.tls.insert(
                TlsConnection::server(config)
                    .map_err(|e| invalid(format!("TLS server connection: {e:?}")))?,
            ),
        };
        // `feed` consumes the whole slice.
        tls.feed(&bytes)
            .map_err(|e| invalid(format!("tls feed: {e:?}")))?;
        // Drain decrypted plaintext into the control buffer. `recv` hands
        // back everything buffered in one call.
        let plain = tls
            .recv()
            .map_err(|e| invalid(format!("tls recv: {e:?}")))?;
        // A rejected session is only kept to deliver AUTH_FAILED; nothing
        // the client says on it is acted on any more.
        if self.auth_failed.is_none() {
            self.primary.ctrl_buf.extend_from_slice(&plain);
            self.advance_control(auth, request)?;
            // Whatever is left is an incomplete message; bound how much of
            // one we are willing to hold.
            if self.primary.ctrl_buf.len() > MAX_CONTROL_MESSAGE {
                return Err(invalid("control channel message too long"));
            }
        }
        Ok(())
    }

    /// Emit the primary key's pending TLS output and ACKs.
    fn pump_tls(&mut self, out: &mut PeerOutput) -> io::Result<()> {
        self.primary.pump(out)
    }

    /// Advance the key-method-2 control exchange using whatever plaintext bytes
    /// are buffered. Runs at most once (after which the connection only carries
    /// PUSH_REQUEST and data). Writes the server reply into the TLS writer.
    fn advance_control(
        &mut self,
        auth: &AuthMode,
        request: &mut Option<AuthRequest>,
    ) -> io::Result<()> {
        if self.primary.kx_done {
            return self.handle_post_auth_control();
        }
        // Whatever the client sends while its credentials are being checked
        // (a PUSH_REQUEST, typically) waits for the verdict.
        if self.primary.auth_pending.is_some() {
            return Ok(());
        }

        // We need the full fixed prefix + four control strings before we can
        // respond. Parse non-destructively; bail (waiting for more) if short.
        let (parsed, used) = match try_parse_key_exchange(&self.primary.ctrl_buf)? {
            Some(p) => p,
            None => return Ok(()), // not enough bytes yet
        };
        // What follows the key exchange is NUL-terminated control messages.
        self.primary.ctrl_buf.drain(..used);

        // Generate the server random once; it's used both in the reply and in
        // the PRF key derivation.
        fill_random(&mut self.primary.server_random)?;

        // Build the server reply onto the TLS stream.
        let reply = build_kx_reply(&self.primary.server_random, &parsed);
        self.primary
            .tls()?
            .send(&reply)
            .map_err(|e| invalid(format!("tls write reply: {e:?}")))?;

        // A renegotiation re-runs the check (OpenVPN re-verifies the
        // credentials), but the session keeps the options and config it
        // pushed: the client does not ask for them again.
        if let Some(why) = parsed.cipher_refused.clone() {
            return self.apply_auth(parsed, Err(why));
        }
        let info = AuthInfo {
            username: parsed.username.clone(),
            password: parsed.password.clone(),
            peer_info: parsed.peer_info.clone(),
            dev_type: parsed.opts.dev_type.clone(),
        };
        match auth {
            AuthMode::Inline(on_auth) => {
                let res = on_auth(&info).map_err(|e| format!("authentication failed: {e}"));
                self.apply_auth(parsed, res)
            }
            // The key waits (OpenVPN's KS_AUTH_DEFERRED) until the caller
            // hands the verdict to Peer::complete_auth; the handshake
            // window bounds how long.
            AuthMode::Deferred(token) => {
                self.primary.auth_pending = Some((*token, parsed));
                *request = Some(AuthRequest {
                    info,
                    token: *token,
                });
                Ok(())
            }
        }
    }

    /// Act on the authentication verdict for the key exchange `kx`: refuse
    /// the client, or generate the key and start the data channel.
    fn apply_auth(
        &mut self,
        kx: KeyExchange,
        verdict: Result<PeerConfig, String>,
    ) -> io::Result<()> {
        let cfg = match verdict {
            Ok(cfg) => cfg,
            Err(why) => {
                // As OpenVPN's server does (send_auth_failed): tell the
                // client, generate no keys, and end the session a few
                // seconds later, once the message has had time to arrive.
                self.primary
                    .tls()?
                    .send(b"AUTH_FAILED\0")
                    .map_err(|e| invalid(format!("tls write AUTH_FAILED: {e:?}")))?;
                self.auth_failed = Some((Instant::now() + AUTH_FAILED_EXIT, why));
                return Ok(());
            }
        };
        self.derive_keys(&kx);
        self.primary.kx_done = true;
        self.primary.established = Some(Instant::now());
        if self.opts.is_none() {
            self.peer_cfg = Some(cfg);
            self.layer = match kx.opts.dev_type.as_str() {
                "tap" => 2,
                _ => 3,
            };
            self.peer_info = kx.peer_info;
            self.opts = Some(kx.opts);
            self.pushed_cipher = kx.ncp_cipher;
        }
        // Control messages that arrived with the key exchange, or while it
        // was being checked, are answered now.
        self.handle_post_auth_control()
    }

    /// After authentication the client keeps sending NUL-terminated control
    /// messages over the TLS stream. Mirrors the post-auth loop in the Go
    /// `peer-control.go`:
    ///
    /// - `PUSH_REQUEST` — send the `PUSH_REPLY`. OpenVPN clients repeat the
    ///   request until they see a reply, but the reply travels on the
    ///   reliable layer, which retransmits it until it arrives; so, as
    ///   OpenVPN's server does, repeats within [`PUSH_REPLY_HOLDOFF`] of a
    ///   reply are ignored rather than answered with another copy each.
    /// - everything else (`PING`, `INFO`, additional `PUSH_*`, etc.) is
    ///   gracefully ignored: we consume the message and keep the channel open.
    fn handle_post_auth_control(&mut self) -> io::Result<()> {
        while let Some(nul) = self.primary.ctrl_buf.iter().position(|&b| b == 0) {
            let line: Vec<u8> = self.primary.ctrl_buf.drain(..=nul).collect();
            // Drop the trailing NUL; empty (bare-NUL) keepalives are ignored.
            let body = &line[..line.len() - 1];
            if body.is_empty() {
                continue;
            }
            let s = String::from_utf8_lossy(body).into_owned();
            // OpenVPN control commands are comma-separated; the verb is the
            // first field (`PUSH_REQUEST`, `PUSH_UPDATE,...`, etc.). Only
            // `PUSH_REQUEST` is actioned; every other message (`PING`, `INFO`,
            // additional `PUSH_*`, …) is gracefully consumed and ignored,
            // matching the Go upstream's permissive post-auth loop.
            let verb = s.split(',').next().unwrap_or("");
            if verb == "PUSH_REQUEST" {
                let now = Instant::now();
                if self.push_reply_until.is_some_and(|t| now < t) {
                    continue;
                }
                let reply = self.build_push_reply();
                self.primary
                    .tls()?
                    .send(reply.as_bytes())
                    .map_err(|e| invalid(format!("tls push reply: {e:?}")))?;
                self.push_reply_until = now.checked_add(PUSH_REPLY_HOLDOFF);
            }
        }
        Ok(())
    }

    fn build_push_reply(&self) -> String {
        let cfg = self.peer_cfg.as_ref();
        let (ip, gw_or_mask) = match cfg {
            Some(c) if self.layer == 2 => (c.ip.to_string(), c.mask.to_string()),
            Some(c) => (c.ip.to_string(), c.gateway.to_string()),
            None => ("0.0.0.0".to_string(), "0.0.0.0".to_string()),
        };
        let mut reply = String::from("PUSH_REPLY");
        let t = &self.timers;
        if !t.keepalive_interval.is_zero() {
            reply += &format!(",ping {}", t.keepalive_interval.as_secs().max(1));
        }
        if !t.keepalive_timeout.is_zero() {
            reply += &format!(",ping-restart {}", t.keepalive_timeout.as_secs().max(1));
        }
        if let Some(c) = self.pushed_cipher {
            reply += &format!(",cipher {c}");
        }
        reply += &format!(",comp-lzo no,topology net30,ifconfig {ip} {gw_or_mask}\0");
        reply
    }

    /// Derive the 256-byte key expansion via the TLS-1.0 PRF and split it into
    /// per-direction keys (ssl.c generate_key_expansion). Uses the server
    /// random generated in [`advance_control`](Self::advance_control) so the
    /// PRF inputs match what was sent to the client.
    fn derive_keys(&mut self, kx: &KeyExchange) {
        let (sr1, sr2) = self.primary.server_random.split_at(32);

        // master = PRF10(pre_master, "OpenVPN master secret", r1 || server_r1)
        let mut master = [0u8; 48];
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&kx.random1);
        seed.extend_from_slice(sr1);
        let label = format!("{} master secret", KEY_EXPANSION_ID);
        prf10(&mut master, &kx.pre_master, label.as_bytes(), &seed);

        // expansion = PRF10(master, "OpenVPN key expansion",
        //                   r2 || server_r2 || client_sid || server_sid)
        let mut expansion = [0u8; 256];
        let mut seed2 = Vec::with_capacity(32 + 32 + 8 + 8);
        seed2.extend_from_slice(&kx.random2);
        seed2.extend_from_slice(sr2);
        seed2.extend_from_slice(&self.remote_id);
        seed2.extend_from_slice(&self.local_id);
        let label2 = format!("{} key expansion", KEY_EXPANSION_ID);
        prf10(&mut expansion, &master, label2.as_bytes(), &seed2);

        self.primary.data = Some(DataKeys::new(PeerKeys::from_expansion(&expansion)));
    }
}

// --- key-method 2 parsing -----------------------------------------------------

/// Parse the client's key-method-2 message, returning it and the number of
/// bytes it took, or `None` until the whole message has arrived.
fn try_parse_key_exchange(buf: &[u8]) -> io::Result<Option<(KeyExchange, usize)>> {
    // Fixed prefix: 4 zero bytes, key_method, pre_master(48), r1(32), r2(32).
    let fixed = 4 + 1 + 48 + 32 + 32;
    if buf.len() < fixed {
        return Ok(None);
    }
    let zero = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if zero != 0 {
        return Err(invalid("control channel: expected 4 zero bytes"));
    }
    let key_method = buf[4];
    if key_method & KEY_METHOD_MASK != 2 {
        return Err(invalid("invalid key method, expected method 2"));
    }
    let mut pos = 5;
    let mut pre_master = [0u8; 48];
    pre_master.copy_from_slice(&buf[pos..pos + 48]);
    pos += 48;
    let mut random1 = [0u8; 32];
    random1.copy_from_slice(&buf[pos..pos + 32]);
    pos += 32;
    let mut random2 = [0u8; 32];
    random2.copy_from_slice(&buf[pos..pos + 32]);
    pos += 32;

    // Four NUL-terminated, length-prefixed control strings.
    let (options_string, p1) = match read_control_string(buf, pos)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let (username, p2) = match read_control_string(buf, p1)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let (password, p3) = match read_control_string(buf, p2)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let (peer_info_raw, used) = match read_control_string(buf, p3)? {
        Some(v) => v,
        None => return Ok(None),
    };

    // OpenVPN only warns when the peer's options string differs from its
    // own (key_method_2_read -> options_warning), so take what we need from
    // it and ignore the rest rather than insisting it round-trips.
    // The cipher is taken out before parsing: whether the one named is
    // usable is part of choosing the data cipher, below, not a malformed
    // options string. A negotiating client may well name one we lack.
    let (options_rest, remote_cipher) = split_cipher(&options_string);
    let mut opts = Options::parse(&options_rest)?;
    opts.is_server = false;
    // The PUSH_REPLY carries `comp-lzo no`, which puts the client on
    // stub framing (every packet starts with the no-compression byte)
    // whatever it had configured, so both directions frame.
    opts.compression = "lzo".into();

    let peer_info = parse_peer_info(&peer_info_raw)?;
    let (ncp_cipher, cipher_refused) = match select_cipher(&peer_info, remote_cipher, &mut opts) {
        Ok(c) => (c, None),
        Err(why) => (None, Some(why)),
    };

    let options_server = {
        let mut o = opts.clone();
        o.is_server = true;
        o.to_string()
    };

    let kx = KeyExchange {
        ncp_cipher,
        cipher_refused,
        pre_master,
        random1,
        random2,
        options_server,
        opts,
        username,
        password,
        peer_info,
    };
    Ok(Some((kx, used)))
}

/// Data ciphers the server negotiates, in its order of preference (OpenVPN's
/// default `data-ciphers`, less CHACHA20-POLY1305, which is not implemented).
const DATA_CIPHERS: [&str; 2] = ["AES-256-GCM", "AES-128-GCM"];

/// Pick the data cipher for a client that negotiates (ssl_ncp.c
/// ncp_get_best_cipher): the first of ours in its IV_CIPHERS list, or, for a
/// 2.4 client announcing only IV_NCP=2, the first of ours among the AES-GCM
/// ciphers that implies. `None` for a client that does not negotiate: it
/// uses the cipher of its options string. A negotiating client with no
/// cipher in common is refused, as OpenVPN refuses it.
fn negotiate_cipher(peer_info: &HashMap<String, String>) -> io::Result<Option<&'static str>> {
    let theirs: Vec<&str> = if let Some(list) = peer_info.get("IV_CIPHERS") {
        list.split(':').collect()
    } else if peer_info
        .get("IV_NCP")
        .and_then(|v| v.parse::<u32>().ok())
        .is_some_and(|v| v >= 2)
    {
        vec!["AES-256-GCM", "AES-128-GCM"]
    } else {
        return Ok(None);
    };
    DATA_CIPHERS
        .into_iter()
        .find(|ours| theirs.iter().any(|t| t.eq_ignore_ascii_case(ours)))
        .map(Some)
        .ok_or_else(|| invalid("client supports none of our data ciphers"))
}

/// Choose the data cipher and install it in `opts` (multi.c
/// multi_client_setup_ncp): the negotiated one if the client negotiates,
/// else the one its options string names (ssl_ncp.c tls_poor_mans_ncp).
/// Returns the cipher to push -- `None` when the client keeps its own -- or
/// why no usable cipher could be agreed on.
fn select_cipher(
    peer_info: &HashMap<String, String>,
    remote: Option<&str>,
    opts: &mut Options,
) -> Result<Option<&'static str>, String> {
    let ncp = negotiate_cipher(peer_info).map_err(|e| e.to_string())?;
    match (ncp, remote) {
        (Some(c), _) => opts.set_cipher(c)?,
        (None, Some(c)) => opts
            .set_cipher(c)
            .map_err(|e| format!("client's data cipher {c:?} is not supported: {e}"))?,
        // Such a client runs OpenVPN's old default, BF-CBC (options.c);
        // guessing anything else would leave neither side able to decrypt.
        (None, None) => {
            return Err("client neither negotiates a data cipher nor names one, \
                        so it uses BF-CBC, which is not supported"
                .into());
        }
    }
    data::check_supported(opts).map_err(|e| e.to_string())?;
    Ok(ncp)
}

/// Take the `cipher` option out of an options string (options_string.c
/// options_string_extract_option), returning the rest and its value.
fn split_cipher(options: &str) -> (String, Option<&str>) {
    let mut cipher = None;
    let rest: Vec<&str> = options
        .split(',')
        .filter(|part| {
            let (k, v) = part.split_once(' ').unwrap_or((part, ""));
            if k == "cipher" {
                cipher = Some(v);
            }
            k != "cipher"
        })
        .collect();
    (rest.join(","), cipher)
}

fn build_kx_reply(server_random: &[u8; 64], kx: &KeyExchange) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.push(2u8); // key_method

    // Server random material (generated in advance_control).
    buf.extend_from_slice(server_random); // r1(32)||r2(32)

    write_control_string(&mut buf, &kx.options_server);
    write_control_string(&mut buf, ""); // username
    write_control_string(&mut buf, ""); // password
    // Our own peer info, which is nothing (write_empty_string, as OpenVPN
    // writes when it has none to push): echoing the client's would claim
    // its version and platform as ours, and send back whatever it put there.
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf
}

/// Parsed key-method 2 client exchange.
struct KeyExchange {
    /// The cipher chosen by negotiation, to be pushed; `None` for a client
    /// without NCP, which uses the cipher of its options string.
    ncp_cipher: Option<&'static str>,
    /// Why no data cipher could be agreed on, if none could: the client is
    /// then refused with AUTH_FAILED, as OpenVPN refuses a client whose
    /// cipher negotiation fails (multi.c, CAS_FAILED).
    cipher_refused: Option<String>,
    pre_master: [u8; 48],
    random1: [u8; 32],
    random2: [u8; 32],
    options_server: String,
    opts: Options,
    username: String,
    password: String,
    peer_info: std::collections::HashMap<String, String>,
}

/// Read a control string at `pos`: a big-endian u16 length followed by that
/// many bytes, NUL-terminated. Returns the string (without the NUL) and the
/// new position, or `None` if the buffer doesn't yet hold the whole string.
///
/// A zero length is an absent string: OpenVPN's write_empty_string sends
/// one for the username and password of a client without auth-user-pass,
/// and ssl.c read_string reads it as empty.
fn read_control_string(buf: &[u8], pos: usize) -> io::Result<Option<(String, usize)>> {
    if pos + 2 > buf.len() {
        return Ok(None);
    }
    let len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    let start = pos + 2;
    if len == 0 {
        return Ok(Some((String::new(), start)));
    }
    if start + len > buf.len() {
        return Ok(None);
    }
    let raw = &buf[start..start + len];
    if raw[len - 1] != 0 {
        return Err(invalid("control string not NUL-terminated"));
    }
    let s = String::from_utf8_lossy(&raw[..len - 1]).into_owned();
    Ok(Some((s, start + len)))
}

fn write_control_string(buf: &mut Vec<u8>, s: &str) {
    let len = s.len() + 1;
    buf.extend_from_slice(&(len as u16).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

/// Parse the client's peer-info block: newline-separated `KEY=VALUE` pairs
/// (the `IV_*` advertisements OpenVPN clients send — `IV_VER`, `IV_PROTO`,
/// `IV_CIPHERS`, etc.). Mirrors the loop in the Go `peer-control.go`: blank
/// lines are skipped, a line without `=` is a hard error, and a value may
/// itself contain `=` (only the first one separates key from value).
fn parse_peer_info(raw: &str) -> io::Result<std::collections::HashMap<String, String>> {
    let mut peer_info = std::collections::HashMap::new();
    for line in raw.split('\n') {
        // Tolerate CRLF line endings some clients emit.
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        match line.find('=') {
            Some(i) => {
                peer_info.insert(line[..i].to_string(), line[i + 1..].to_string());
            }
            None => return Err(invalid("invalid string in peer_info")),
        }
    }
    Ok(peer_info)
}

/// Cryptographic randomness for IVs and session material.
pub(crate) fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    purecrypto::rng::RngCore::fill_bytes(&mut purecrypto::rng::OsRng, buf);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer with data-channel keys installed directly, skipping the TLS
    /// handshake that normally derives them.
    fn keyed_peer() -> Peer {
        let tls = crate::ovpn::tests::server_config();
        let on_auth: OnAuth = Arc::new(|_: &AuthInfo| Err(invalid("unused")));
        let mut p = Peer::new(tls.clone(), *b"SERVERID", on_auth).unwrap();
        let (mut s, _) = Session::new(*b"SERVERID", *b"CLIENTID", PeerTimers::default());
        s.opts = Some(Options {
            cipher_block: super::super::GCM,
            cipher_size: 256,
            auth: super::super::options::AuthHash::None,
            ..Options::default()
        });
        s.primary.data = Some(DataKeys::new(PeerKeys::from_expansion(&[7u8; 256])));
        s.primary.kx_done = true;
        s.primary.established = Some(Instant::now());
        p.active = Some(s);
        p
    }

    #[test]
    fn ncp_follows_server_preference_and_refuses_no_overlap() {
        let pi = |kv: &[(&str, &str)]| -> HashMap<String, String> {
            kv.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        assert_eq!(negotiate_cipher(&pi(&[])).unwrap(), None);
        assert_eq!(negotiate_cipher(&pi(&[("IV_NCP", "1")])).unwrap(), None);
        assert_eq!(
            negotiate_cipher(&pi(&[("IV_NCP", "2")])).unwrap(),
            Some("AES-256-GCM")
        );
        assert_eq!(
            negotiate_cipher(&pi(&[("IV_CIPHERS", "aes-128-gcm:AES-256-GCM")])).unwrap(),
            Some("AES-256-GCM")
        );
        assert!(negotiate_cipher(&pi(&[("IV_CIPHERS", "CHACHA20-POLY1305")])).is_err());
    }

    /// Long before the packet ids run out, the server renegotiates
    /// (PACKET_ID_WRAP_TRIGGER), whatever reneg-sec says.
    #[test]
    fn low_packet_ids_trigger_renegotiation() {
        let mut p = keyed_peer().with_timers(
            PeerTimers::default()
                .renegotiate_interval(Duration::ZERO)
                .keepalive_interval(Duration::ZERO),
        );
        let quiet = p.tick(Instant::now()).unwrap();
        assert!(quiet.send.is_empty());
        let dk = p.active.as_mut().unwrap().primary.data.as_mut().unwrap();
        dk.out_pid = PACKET_ID_WRAP_TRIGGER;
        let out = p.tick(Instant::now()).unwrap();
        let pkt = ControlPacket::parse(&out.send[0]).unwrap();
        assert_eq!(pkt.opcode, Opcode::CONTROL_SOFT_RESET_V1);
        assert_eq!(pkt.key_id, 1);
        // Meanwhile the old key keeps sending.
        assert!(p.send_data(b"x").is_ok());
    }

    /// An AES-GCM key is renegotiated before it has protected too much
    /// (ssl.c tls_get_limit_aead): once the blocks it encrypted, plus
    /// the packets, pass the limit -- in either direction.
    #[test]
    fn aead_usage_limit_triggers_renegotiation() {
        let quiet = PeerTimers::default()
            .renegotiate_interval(Duration::ZERO)
            .keepalive_interval(Duration::ZERO);
        let soft_reset = |out: &PeerOutput| {
            out.send.iter().any(|d| {
                ControlPacket::parse(d).is_ok_and(|p| p.opcode == Opcode::CONTROL_SOFT_RESET_V1)
            })
        };

        // Sending: one more packet goes over.
        let mut p = keyed_peer().with_timers(quiet);
        let dk = p.active.as_mut().unwrap().primary.data.as_mut().unwrap();
        dk.enc_blocks = AEAD_USAGE_LIMIT - 1;
        assert!(!soft_reset(&p.tick(Instant::now()).unwrap()));
        p.send_data(b"x").unwrap();
        assert!(soft_reset(&p.tick(Instant::now()).unwrap()));

        // Receiving: the same, for what the client encrypted.
        let mut p = keyed_peer().with_timers(quiet);
        let dk = p.active.as_mut().unwrap().primary.data.as_mut().unwrap();
        dk.dec_blocks = AEAD_USAGE_LIMIT - 1;
        assert!(!soft_reset(&p.tick(Instant::now()).unwrap()));
        let opts = p.active.as_ref().unwrap().opts.clone().unwrap();
        let keys = PeerKeys::from_expansion(&[7u8; 256]);
        let pkt = data::encrypt(&opts, &keys, 0, 1, b"x", fill_random).unwrap();
        assert!(p.handle_packet(&pkt).unwrap().deliver.is_some());
        assert!(soft_reset(&p.tick(Instant::now()).unwrap()));
    }

    /// A key fallen back to after a failed renegotiation normally just
    /// runs out its transition window; one that has reached its AES-GCM
    /// usage limit must still be renegotiated, not used on regardless.
    #[test]
    fn a_fallback_key_past_its_usage_limit_is_renegotiated() {
        let mut p = keyed_peer().with_timers(
            PeerTimers::default()
                .renegotiate_interval(Duration::ZERO)
                .keepalive_interval(Duration::ZERO),
        );
        let far = Instant::now() + Duration::from_secs(3600);
        let s = p.active.as_mut().unwrap();
        s.primary.must_die = Some(far);
        assert!(p.tick(Instant::now()).unwrap().send.is_empty());
        let dk = p.active.as_mut().unwrap().primary.data.as_mut().unwrap();
        dk.enc_blocks = AEAD_USAGE_LIMIT + 1;
        let out = p.tick(Instant::now()).unwrap();
        assert!(
            out.send.iter().any(|d| {
                ControlPacket::parse(d).is_ok_and(|p| p.opcode == Opcode::CONTROL_SOFT_RESET_V1)
            }),
            "no renegotiation"
        );
    }

    /// At the AES-GCM bound itself a key is used no more, in either
    /// direction, and a session left with nothing else is closed.
    #[test]
    fn an_exhausted_gcm_key_ends_the_session() {
        let quiet = PeerTimers::default()
            .renegotiate_interval(Duration::ZERO)
            .keepalive_interval(Duration::ZERO);
        let mut p = keyed_peer().with_timers(quiet);
        let dk = p.active.as_mut().unwrap().primary.data.as_mut().unwrap();
        dk.dec_blocks = AEAD_HARD_LIMIT;
        let opts = p.active.as_ref().unwrap().opts.clone().unwrap();
        let keys = PeerKeys::from_expansion(&[7u8; 256]);
        let pkt = data::encrypt(&opts, &keys, 0, 1, b"x", fill_random).unwrap();
        assert!(p.handle_packet(&pkt).is_err());
        assert!(p.send_data(b"x").is_err());
        let out = p.tick(Instant::now()).unwrap();
        assert!(out.close);
        assert!(out.error.is_some());
    }

    #[test]
    fn send_data_refuses_to_wrap_the_packet_id() {
        let mut p = keyed_peer();
        p.active
            .as_mut()
            .unwrap()
            .primary
            .data
            .as_mut()
            .unwrap()
            .out_pid = u32::MAX - 1;
        // The last id OpenVPN allows is u32::MAX.
        let pkt = p.send_data(b"x").unwrap();
        assert_eq!(&pkt[1..5], &u32::MAX.to_be_bytes());
        // Going further would reuse GCM nonce `0 || implicit IV` under the
        // same key; the peer must refuse instead.
        assert!(p.send_data(b"y").is_err());
        assert!(p.send_data(b"z").is_err());
    }

    #[test]
    fn peer_info_parses_iv_keys() {
        let raw = "IV_VER=2.6.0\nIV_PLAT=linux\nIV_PROTO=6\nIV_CIPHERS=AES-256-GCM:AES-128-GCM\n";
        let pi = parse_peer_info(raw).unwrap();
        assert_eq!(pi.get("IV_VER").map(String::as_str), Some("2.6.0"));
        assert_eq!(pi.get("IV_PLAT").map(String::as_str), Some("linux"));
        assert_eq!(pi.get("IV_PROTO").map(String::as_str), Some("6"));
        assert_eq!(
            pi.get("IV_CIPHERS").map(String::as_str),
            Some("AES-256-GCM:AES-128-GCM")
        );
        assert_eq!(pi.len(), 4);
    }

    #[test]
    fn peer_info_value_may_contain_equals() {
        // Only the first '=' splits key from value.
        let pi = parse_peer_info("UV_OPT=a=b=c\n").unwrap();
        assert_eq!(pi.get("UV_OPT").map(String::as_str), Some("a=b=c"));
    }

    #[test]
    fn peer_info_skips_blank_and_crlf_lines() {
        let pi = parse_peer_info("\nIV_VER=2.6\r\n\n").unwrap();
        assert_eq!(pi.len(), 1);
        assert_eq!(pi.get("IV_VER").map(String::as_str), Some("2.6"));
    }

    #[test]
    fn peer_info_rejects_line_without_equals() {
        assert!(parse_peer_info("IV_VER=2.6\nGARBAGE\n").is_err());
    }

    #[test]
    fn peer_info_empty_is_ok() {
        let pi = parse_peer_info("").unwrap();
        assert!(pi.is_empty());
    }
}
