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
//! The structure follows OpenVPN's `ssl.c`: a peer holds up to two
//! [`Session`]s (`tls_session`) -- the *active* one carrying the data channel
//! and an *initial* one a new hard reset is negotiating -- and every control
//! packet is routed to a session by the sender's session id. A session that
//! authenticates replaces the active one, so a client that restarts from the
//! same address reconnects, while a stray hard reset cannot disturb a working
//! session. Each session runs its TLS handshake in a [`KeyState`]
//! (`key_state`).
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
#[derive(Debug, Clone)]
pub struct AuthInfo {
    pub username: String,
    pub password: String,
    pub peer_info: HashMap<String, String>,
    pub dev_type: String,
}

/// IP configuration the server pushes back to an authenticated client.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PeerConfig {
    /// Tunnel address assigned to the client.
    pub ip: std::net::IpAddr,
    /// Peer/gateway address used in the net30 topology push (tun mode).
    pub gateway: std::net::IpAddr,
    /// Netmask string used for tap-mode ifconfig.
    pub mask: std::net::IpAddr,
    /// Prefix length for the per-peer device address.
    pub prefix_len: u8,
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
        }
    }
}

/// Authentication callback: given the credentials, return the IP config to push
/// or an error to reject the connection.
pub type OnAuth = Arc<dyn Fn(&AuthInfo) -> io::Result<PeerConfig> + Send + Sync>;

/// Effects produced by processing one inbound datagram: raw datagrams to send
/// back to the peer, and an optional decrypted data-channel payload to deliver.
#[derive(Default, Debug)]
pub struct PeerOutput {
    /// Raw datagrams (each already framed with opcode etc.) to transmit.
    pub send: Vec<Vec<u8>>,
    /// Decrypted payload to deliver to the adapter, if a data packet arrived.
    pub deliver: Option<Vec<u8>>,
    /// True once the peer has authenticated and the data channel is active.
    pub authenticated: bool,
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
}

impl Default for PeerTimers {
    /// OpenVPN's defaults: `hand-window 60`, and the `keepalive 10 60` its
    /// sample server configuration uses.
    fn default() -> PeerTimers {
        PeerTimers {
            handshake_window: Duration::from_secs(60),
            keepalive_interval: Duration::from_secs(10),
            keepalive_timeout: Duration::from_secs(60),
        }
    }
}

setters! {
    PeerTimers {
        set handshake_window: Duration;
        set keepalive_interval: Duration;
        set keepalive_timeout: Duration;
    }
}

/// One OpenVPN peer (one client address).
pub struct Peer {
    config: Arc<purecrypto::tls::Config>,
    on_auth: OnAuth,
    /// Local session id for the first session; later ones draw a random id.
    first_local_id: Option<[u8; 8]>,
    /// The session carrying the data channel (OpenVPN's `TM_ACTIVE`).
    active: Option<Session>,
    /// A session still negotiating (OpenVPN's `TM_INITIAL`). Every session
    /// starts here and replaces `active` once it authenticates.
    initial: Option<Session>,
    timers: PeerTimers,
    /// Last time an accepted packet arrived from the client.
    last_recv: Instant,
    /// Last time we produced a datagram for the client.
    last_sent: Instant,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("active", &self.active.is_some())
            .field("initial", &self.initial.is_some())
            .finish()
    }
}

/// Which of the peer's sessions a control packet belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Active,
    Initial,
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
        Ok(Peer {
            config,
            on_auth,
            first_local_id: Some(local_id),
            active: None,
            initial: None,
            timers: PeerTimers::default(),
            last_recv: Instant::now(),
            last_sent: Instant::now(),
        })
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

    /// Replace the default timers.
    pub fn with_timers(mut self, timers: PeerTimers) -> Peer {
        self.timers = timers;
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

    fn session_mut(&mut self, slot: Slot) -> Option<&mut Session> {
        match slot {
            Slot::Active => self.active.as_mut(),
            Slot::Initial => self.initial.as_mut(),
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
    /// datagrams to re-send in [`PeerOutput`]`::send`; if a packet exhausts its
    /// retries the connection is abandoned and `PeerOutput::close` is set.
    ///
    /// The same tick runs the peer's other timers: a session that has not
    /// completed its key exchange within the handshake window is abandoned,
    /// an idle established peer is sent a keepalive ping, and one not heard
    /// from for the ping-restart timeout is closed.
    pub fn tick(&mut self, now: Instant) -> io::Result<PeerOutput> {
        let mut out = PeerOutput::default();
        for slot in [Slot::Active, Slot::Initial] {
            let Some(s) = self.session_mut(slot) else {
                continue;
            };
            let tick = s.ks.reliable.tick(now);
            out.send.extend(tick.resend);
            if tick.timed_out {
                self.fail_session(slot, &mut out, None);
            } else if !s.ks.kx_done && now >= s.ks.must_negotiate {
                let e = io::Error::new(
                    io::ErrorKind::TimedOut,
                    "key negotiation did not complete within the handshake window",
                );
                self.fail_session(slot, &mut out, Some(e));
            }
        }

        if self.active.is_some() {
            let restart = self.timers.keepalive_timeout * 2;
            if !restart.is_zero() && now.saturating_duration_since(self.last_recv) >= restart {
                out.close = true;
                out.error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "nothing received within the ping-restart timeout",
                ));
                return Ok(out);
            }
            let interval = self.timers.keepalive_interval;
            if !interval.is_zero()
                && now.saturating_duration_since(self.last_sent) >= interval
                && let Ok(ping) = self.send_data(&OPENVPN_PING)
            {
                out.send.push(ping);
            }
        }
        if !out.send.is_empty() {
            self.last_sent = now;
        }
        Ok(out)
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
        let Some(&first) = data.first() else {
            return Err(invalid("empty packet"));
        };
        let (opcode, key_id) = Opcode::from_byte(first);
        let out = match opcode {
            Opcode::DATA_V1 => self.handle_data(key_id, data),
            // Only a client (key method 2) hard reset may open a session;
            // P_DATA_V2 needs a peer-id we never push; the rest are unknown.
            Opcode::CONTROL_HARD_RESET_CLIENT_V2
            | Opcode::CONTROL_SOFT_RESET_V1
            | Opcode::CONTROL_V1
            | Opcode::ACK_V1 => self.handle_control(key_id, data),
            _ => Err(invalid(format!("unexpected opcode {opcode}"))),
        }?;
        // Only a packet that got past validation counts as hearing from
        // the client.
        let now = Instant::now();
        self.last_recv = now;
        if !out.send.is_empty() {
            self.last_sent = now;
        }
        Ok(out)
    }

    fn handle_control(&mut self, key_id: u8, data: &[u8]) -> io::Result<PeerOutput> {
        let pkt = ControlPacket::parse(data)?;
        let sid = pkt.session_id;
        if sid == [0; 8] {
            return Err(invalid("control packet without a session id"));
        }

        // Route by the sender's session id (ssl.c tls_pre_decrypt).
        let mut out = PeerOutput::default();
        let mut reset = None;
        let slot = if self.active.as_ref().is_some_and(|s| s.remote_id == sid) {
            Slot::Active
        } else if self.initial.as_ref().is_some_and(|s| s.remote_id == sid) {
            Slot::Initial
        } else if pkt.opcode == Opcode::CONTROL_HARD_RESET_CLIENT_V2 {
            // A new session: it starts with packet 0 on key 0.
            if pkt.pid != Some(0) || key_id != 0 {
                return Err(invalid("hard reset must be packet 0 on key 0"));
            }
            let local_id = match self.first_local_id.take() {
                Some(id) => id,
                None => {
                    let mut id = [0u8; 8];
                    fill_random(&mut id)?;
                    id
                }
            };
            let (session, server_reset) = Session::new(&self.config, local_id, sid, self.timers)?;
            // Replaces any session still negotiating: the client that sent
            // it has given up on it.
            self.initial = Some(session);
            reset = Some(server_reset);
            Slot::Initial
        } else {
            return Err(invalid("control packet for no known session"));
        };

        let on_auth = self.on_auth.clone();
        let session = self.session_mut(slot).expect("slot just resolved");
        let tls_bytes = session.ks.recv(key_id, pkt)?;
        if let Some(reset) = reset {
            // Our reset carries the ACK for theirs.
            out.send
                .push(reset.to_bytes(&session.ks.reliable.take_pending_acks()));
        }
        if let Err(e) = session.process_tls(&tls_bytes, &on_auth, &mut out) {
            self.fail_session(slot, &mut out, Some(e));
            return Ok(out);
        }

        // A session that has authenticated takes over the data channel.
        if slot == Slot::Initial && self.initial.as_ref().is_some_and(|s| s.ks.kx_done) {
            self.active = self.initial.take();
        }
        out.authenticated = self.active.as_ref().is_some_and(|s| s.ks.kx_done);
        Ok(out)
    }

    /// A session hit a fatal error or timed out: drop it. The connection
    /// only ends when no session is left.
    fn fail_session(&mut self, slot: Slot, out: &mut PeerOutput, err: Option<io::Error>) {
        match slot {
            Slot::Active => self.active = None,
            Slot::Initial => self.initial = None,
        }
        if self.active.is_none() && self.initial.is_none() {
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
        let (Some(opts), Some(dk)) = (session.opts.as_ref(), session.ks.data.as_mut()) else {
            return Err(invalid("stream not ready for data transmission"));
        };
        if session.ks.key_id != key_id {
            return Err(invalid("data packet for an unknown key id"));
        }

        let mut buf = data.to_vec();
        let dec = data::decrypt(opts, &dk.keys, &mut buf)?
            .ok_or_else(|| invalid("data packet failed authentication"))?;
        if !dk.replay.check(dec.pid) {
            return Err(invalid("replayed data packet"));
        }
        if !dec.is_ping {
            out.deliver = Some(dec.payload.to_vec());
        }
        Ok(out)
    }

    /// Encrypt and frame an outbound IP packet / Ethernet frame for the peer.
    pub fn send_data(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let session = self
            .active
            .as_mut()
            .ok_or_else(|| invalid("stream not ready for data transmission"))?;
        let (Some(opts), Some(dk)) = (session.opts.as_ref(), session.ks.data.as_mut()) else {
            return Err(invalid("stream not ready for data transmission"));
        };
        // The packet id is the GCM nonce prefix: wrapping it would reuse a
        // nonce under the same key. OpenVPN (packet_id_send_update) refuses
        // to send once the id space is spent; only a new key resets it.
        dk.out_pid = dk
            .out_pid
            .checked_add(1)
            .ok_or_else(|| invalid("data channel packet id exhausted; renegotiation required"))?;
        self.last_sent = Instant::now();
        data::encrypt(opts, &dk.keys, dk.out_pid, payload, fill_random)
    }
}

/// One TLS session with the client (OpenVPN's `tls_session`), named on the
/// wire by the pair of session ids the two hard resets carry.
struct Session {
    local_id: [u8; 8],
    remote_id: [u8; 8],
    ks: KeyState,

    // Negotiated state, populated during the key exchange.
    opts: Option<Options>,
    peer_cfg: Option<PeerConfig>,
    /// Layer: 2 = tap (frames), 3 = tun (packets).
    layer: u8,
    /// Peer-info key/values (`IV_*`) the client advertised during the key
    /// exchange, retained for post-auth queries / diagnostics.
    peer_info: HashMap<String, String>,
    timers: PeerTimers,
}

/// One TLS handshake and what it produced (OpenVPN's `key_state`): its own
/// reliable transport, the key-method-2 exchange, and the data-channel keys.
struct KeyState {
    key_id: u8,
    tls: TlsConnection,
    reliable: Reliable,
    /// Key-method-2 exchange scratch (read incrementally from the TLS stream).
    ctrl_buf: Vec<u8>,
    kx_done: bool,
    /// The key exchange must complete by then.
    must_negotiate: Instant,
    /// Server random material (r1||r2) generated for the key exchange and
    /// reused by [`Session::derive_keys`] so the PRF inputs match what was
    /// sent.
    server_random: [u8; 64],
    data: Option<DataKeys>,
}

/// Data-channel keys and packet-id state for one key.
struct DataKeys {
    keys: PeerKeys,
    replay: Window,
    /// Outgoing data-channel packet id (the last one used).
    out_pid: u32,
}

impl KeyState {
    fn new(
        config: &purecrypto::tls::Config,
        key_id: u8,
        local_id: [u8; 8],
        remote_id: [u8; 8],
        must_negotiate: Instant,
    ) -> io::Result<KeyState> {
        let tls = TlsConnection::server(config)
            .map_err(|e| invalid(format!("TLS server connection: {e:?}")))?;
        let mut reliable = Reliable::new(local_id);
        reliable.peer_id = remote_id;
        Ok(KeyState {
            key_id,
            tls,
            reliable,
            ctrl_buf: Vec::new(),
            kx_done: false,
            must_negotiate,
            server_random: [0u8; 64],
            data: None,
        })
    }

    /// Run a control packet through this key's reliable layer, returning the
    /// TLS bytes it made available in order. `Err` drops the packet.
    fn recv(&mut self, key_id: u8, pkt: ControlPacket) -> io::Result<Vec<u8>> {
        if key_id != self.key_id {
            return Err(invalid("control packet for another key id"));
        }
        Ok(self.reliable.recv_packet(pkt)?.tls_bytes)
    }
}

impl Session {
    /// Open a session for a client hard reset from `remote_id`, returning it
    /// with the server hard reset to send back.
    fn new(
        config: &purecrypto::tls::Config,
        local_id: [u8; 8],
        remote_id: [u8; 8],
        timers: PeerTimers,
    ) -> io::Result<(Session, ControlPacket)> {
        let must_negotiate = Instant::now() + timers.handshake_window;
        let mut ks = KeyState::new(config, 0, local_id, remote_id, must_negotiate)?;
        let reset = ks.reliable.build_hard_reset();
        Ok((
            Session {
                local_id,
                remote_id,
                ks,
                opts: None,
                peer_cfg: None,
                layer: 3,
                peer_info: HashMap::new(),
                timers,
            },
            reset,
        ))
    }

    /// Feed in-order TLS bytes to the engine, run the control exchange on the
    /// plaintext, and queue the TLS output. An error is fatal to the session:
    /// past the reliable layer the bytes are part of its TLS stream, and a
    /// TLS error ends an OpenVPN key state too.
    fn process_tls(
        &mut self,
        tls_bytes: &[u8],
        on_auth: &OnAuth,
        out: &mut PeerOutput,
    ) -> io::Result<()> {
        let res = self.advance_tls(tls_bytes, on_auth);
        // Flush what the TLS engine queued even on failure (an alert,
        // typically), along with the ACKs we owe.
        let pumped = self.pump_tls(out);
        res.and(pumped)
    }

    fn advance_tls(&mut self, tls_bytes: &[u8], on_auth: &OnAuth) -> io::Result<()> {
        if tls_bytes.is_empty() {
            return Ok(());
        }
        // `feed` consumes the whole slice.
        self.ks
            .tls
            .feed(tls_bytes)
            .map_err(|e| invalid(format!("tls feed: {e:?}")))?;
        // Drain decrypted plaintext into the control buffer. `recv` hands
        // back everything buffered in one call.
        let plain = self
            .ks
            .tls
            .recv()
            .map_err(|e| invalid(format!("tls recv: {e:?}")))?;
        self.ks.ctrl_buf.extend_from_slice(&plain);
        self.advance_control(on_auth)
    }

    /// Emit any pending TLS output as P_CONTROL_V1 packets, plus a standalone
    /// ACK if we owe acknowledgements but produced no control packet to ride on.
    fn pump_tls(&mut self, out: &mut PeerOutput) -> io::Result<()> {
        let ks = &mut self.ks;
        // `pop` returns the whole pending wire stream in one call.
        let tls_out = ks
            .tls
            .pop()
            .map_err(|e| invalid(format!("tls pop: {e:?}")))?;

        if !tls_out.is_empty() {
            let chunks = ks.reliable.chunk_tls_stream(&tls_out);
            for (i, pkt) in chunks.iter().enumerate() {
                // Attach pending acks only to the first packet of the burst.
                let acks = if i == 0 {
                    ks.reliable.take_pending_acks()
                } else {
                    Vec::new()
                };
                out.send.push(pkt.to_bytes(&acks));
            }
        }

        // If we still owe acks (no control packet carried them), send a plain ACK.
        if ks.reliable.has_pending_acks() {
            let acks = ks.reliable.take_pending_acks();
            let ack = ks.reliable.build_ack();
            out.send.push(ack.to_bytes(&acks));
        }
        Ok(())
    }

    /// Advance the key-method-2 control exchange using whatever plaintext bytes
    /// are buffered. Runs at most once (after which the connection only carries
    /// PUSH_REQUEST and data). Writes the server reply into the TLS writer.
    fn advance_control(&mut self, on_auth: &OnAuth) -> io::Result<()> {
        if self.ks.kx_done {
            return self.handle_post_auth_control();
        }

        // We need the full fixed prefix + four control strings before we can
        // respond. Parse non-destructively; bail (waiting for more) if short.
        let parsed = match try_parse_key_exchange(&self.ks.ctrl_buf)? {
            Some(p) => p,
            None => return Ok(()), // not enough bytes yet
        };

        // Generate the server random once; it's used both in the reply and in
        // the PRF key derivation.
        fill_random(&mut self.ks.server_random)?;

        // Build the server reply onto the TLS stream.
        let reply = build_kx_reply(&self.ks.server_random, &parsed);
        self.ks
            .tls
            .send(&reply)
            .map_err(|e| invalid(format!("tls write reply: {e:?}")))?;

        // Derive the data-channel keys.
        self.derive_keys(&parsed);

        // Authenticate via the hook.
        let auth = AuthInfo {
            username: parsed.username.clone(),
            password: parsed.password.clone(),
            peer_info: parsed.peer_info.clone(),
            dev_type: parsed.opts.dev_type.clone(),
        };
        let cfg = on_auth(&auth)?;
        self.peer_cfg = Some(cfg);

        self.layer = match parsed.opts.dev_type.as_str() {
            "tap" => 2,
            _ => 3,
        };
        self.peer_info = parsed.peer_info;
        self.opts = Some(parsed.opts);
        self.ks.kx_done = true;
        Ok(())
    }

    /// After authentication the client keeps sending NUL-terminated control
    /// messages over the TLS stream. Mirrors the post-auth loop in the Go
    /// `peer-control.go`:
    ///
    /// - `PUSH_REQUEST` — (re)send the `PUSH_REPLY`. OpenVPN clients repeat the
    ///   request until they see a reply, so every occurrence must be answered,
    ///   not just the first.
    /// - everything else (`PING`, `INFO`, additional `PUSH_*`, etc.) is
    ///   gracefully ignored: we consume the message and keep the channel open.
    fn handle_post_auth_control(&mut self) -> io::Result<()> {
        while let Some(nul) = self.ks.ctrl_buf.iter().position(|&b| b == 0) {
            let line: Vec<u8> = self.ks.ctrl_buf.drain(..=nul).collect();
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
                let reply = self.build_push_reply();
                self.ks
                    .tls
                    .send(reply.as_bytes())
                    .map_err(|e| invalid(format!("tls push reply: {e:?}")))?;
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
        reply += &format!(",comp-lzo no,topology net30,ifconfig {ip} {gw_or_mask}\0");
        reply
    }

    /// Derive the 256-byte key expansion via the TLS-1.0 PRF and split it into
    /// per-direction keys (ssl.c generate_key_expansion). Uses the server
    /// random generated in [`advance_control`](Self::advance_control) so the
    /// PRF inputs match what was sent to the client.
    fn derive_keys(&mut self, kx: &KeyExchange) {
        let (sr1, sr2) = self.ks.server_random.split_at(32);

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

        self.ks.data = Some(DataKeys {
            keys: PeerKeys::from_expansion(&expansion),
            replay: Window::new(),
            out_pid: 0,
        });
    }
}

// --- key-method 2 parsing -----------------------------------------------------

fn try_parse_key_exchange(buf: &[u8]) -> io::Result<Option<KeyExchange>> {
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
    let (peer_info_raw, _p4) = match read_control_string(buf, p3)? {
        Some(v) => v,
        None => return Ok(None),
    };

    // Validate the options string round-trips (as the Go upstream does).
    let mut opts = Options::parse(&options_string).map_err(invalid)?;
    opts.is_server = false;
    if opts.to_string() != options_string {
        return Err(invalid("invalid options provided"));
    }

    let peer_info = parse_peer_info(&peer_info_raw)?;

    let options_server = {
        let mut o = opts.clone();
        o.is_server = true;
        o.to_string()
    };

    Ok(Some(KeyExchange {
        pre_master,
        random1,
        random2,
        options_server,
        opts,
        username,
        password,
        peer_info,
        peer_info_raw,
    }))
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
    write_control_string(&mut buf, &kx.peer_info_raw);
    buf
}

/// Parsed key-method 2 client exchange.
struct KeyExchange {
    pre_master: [u8; 48],
    random1: [u8; 32],
    random2: [u8; 32],
    options_server: String,
    opts: Options,
    username: String,
    password: String,
    peer_info: std::collections::HashMap<String, String>,
    peer_info_raw: String,
}

/// Read a control string at `pos`: a big-endian u16 length followed by that
/// many bytes, NUL-terminated. Returns the string (without the NUL) and the
/// new position, or `None` if the buffer doesn't yet hold the whole string.
fn read_control_string(buf: &[u8], pos: usize) -> io::Result<Option<(String, usize)>> {
    if pos + 2 > buf.len() {
        return Ok(None);
    }
    let len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    if len == 0 {
        return Err(invalid("empty control string"));
    }
    let start = pos + 2;
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
        let (mut s, _) =
            Session::new(&tls, *b"SERVERID", *b"CLIENTID", PeerTimers::default()).unwrap();
        s.opts = Some(Options {
            cipher_block: super::super::GCM,
            cipher_size: 256,
            auth: super::super::options::AuthHash::None,
            ..Options::default()
        });
        s.ks.data = Some(DataKeys {
            keys: PeerKeys::from_expansion(&[7u8; 256]),
            replay: Window::new(),
            out_pid: 0,
        });
        s.ks.kx_done = true;
        p.active = Some(s);
        p
    }

    #[test]
    fn send_data_refuses_to_wrap_the_packet_id() {
        let mut p = keyed_peer();
        p.active.as_mut().unwrap().ks.data.as_mut().unwrap().out_pid = u32::MAX - 1;
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
