//! Per-peer state machine.
//!
//! A [`Peer`] drives one OpenVPN client through:
//!
//! 1. **Hard reset** — the client's `P_CONTROL_HARD_RESET_CLIENT_V2` sets the
//!    peer session id; we reply with our own server hard reset.
//! 2. **TLS handshake** — a `rustls::ServerConnection` runs *inside* the
//!    reliable control channel. We feed it the TLS bytes carried by
//!    `P_CONTROL_V1` packets (`read_tls` + `process_new_packets`) and pump its
//!    output back out as more `P_CONTROL_V1` packets (`write_tls`). There is no
//!    TCP socket under the TLS; the reliable layer is the transport.
//! 3. **Key-method 2 exchange** — over the established TLS stream the client
//!    sends `[0:4][key_method:1][pre_master:48][random1:32][random2:32]` plus
//!    the options, username, password, and peer-info strings. We reply
//!    symmetrically, then derive the data-channel keys with the TLS-1.0 PRF.
//! 4. **Data channel** — `P_DATA_V1` packets are decrypted to IP packets (tun)
//!    or Ethernet frames (tap) and delivered to the adapter; outgoing packets
//!    are encrypted and emitted.
//!
//! Ported from the Go `peer.go` + `peer-control.go` + `peerconn.go`. The Go
//! version used blocking reads on a `tls.Conn` from a dedicated goroutine; the
//! Rust port is single-threaded and event-driven — each inbound datagram is
//! processed synchronously and any work that can make progress does so.

use std::io::{self, Read, Write};
use std::sync::Arc;

use rustls::ServerConnection;

use super::consts::{KEY_EXPANSION_ID, KEY_METHOD_MASK};
use super::data;
use super::keys::PeerKeys;
use super::options::Options;
use super::prf::prf10;
use super::reliable::Reliable;
use super::window::Window;
use super::Opcode;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Credentials and metadata presented by a client during the key exchange.
#[derive(Debug, Clone)]
pub struct AuthInfo {
    pub username: String,
    pub password: String,
    pub peer_info: std::collections::HashMap<String, String>,
    pub dev_type: String,
}

/// IP configuration the server pushes back to an authenticated client.
#[derive(Debug, Clone)]
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
}

/// Phase of the control flow.
#[derive(Debug, PartialEq, Eq)]
enum Phase {
    /// Waiting for the client hard reset.
    Init,
    /// TLS handshake / key exchange in progress.
    Handshaking,
    /// Authenticated; data channel active.
    Established,
}

/// One OpenVPN peer.
pub struct Peer {
    tls: ServerConnection,
    reliable: Reliable,
    phase: Phase,

    on_auth: OnAuth,

    // Negotiated state, populated during the key exchange.
    opts: Option<Options>,
    keys: Option<PeerKeys>,
    replay: Window,
    /// Layer: 2 = tap (frames), 3 = tun (packets).
    layer: u8,
    /// Outgoing data-channel packet id.
    out_pid: u32,

    // Key-method 2 exchange scratch (read incrementally from the TLS stream).
    ctrl_buf: Vec<u8>,
    kx_done: bool,
    peer_cfg: Option<PeerConfig>,
    /// Server random material (r1||r2) generated for the key exchange and
    /// reused by [`derive_keys`] so the PRF inputs match what was sent.
    server_random: [u8; 64],
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("phase", &self.phase)
            .field("authenticated", &self.kx_done)
            .finish()
    }
}

impl Peer {
    /// Create a peer with the given rustls config, local session id, and auth
    /// hook. The local session id is typically random; the server uses it to
    /// identify reliable-layer packets.
    pub fn new(
        config: Arc<rustls::ServerConfig>,
        local_id: [u8; 8],
        on_auth: OnAuth,
    ) -> io::Result<Peer> {
        let tls = ServerConnection::new(config)
            .map_err(|e| invalid(format!("rustls server connection: {e}")))?;
        Ok(Peer {
            tls,
            reliable: Reliable::new(local_id),
            phase: Phase::Init,
            on_auth,
            opts: None,
            keys: None,
            replay: Window::new(),
            layer: 3,
            out_pid: 0,
            ctrl_buf: Vec::new(),
            kx_done: false,
            peer_cfg: None,
            server_random: [0u8; 64],
        })
    }

    /// The peer config pushed to the client after authentication (if any).
    pub fn peer_config(&self) -> Option<&PeerConfig> {
        self.peer_cfg.as_ref()
    }

    /// Layer (2 for tap, 3 for tun).
    pub fn layer(&self) -> u8 {
        self.layer
    }

    /// Process one inbound datagram from the peer.
    pub fn handle_packet(&mut self, data: &[u8]) -> io::Result<PeerOutput> {
        if data.is_empty() {
            return Ok(PeerOutput::default());
        }
        let (opcode, _kid) = Opcode::from_byte(data[0]);

        if opcode.is_control() {
            self.handle_control(data)
        } else if opcode == Opcode::DATA_V1 || opcode == Opcode::DATA_V2 {
            self.handle_data(data)
        } else {
            Ok(PeerOutput::default())
        }
    }

    fn handle_control(&mut self, data: &[u8]) -> io::Result<PeerOutput> {
        let mut out = PeerOutput::default();

        let recv = self.reliable.recv(data)?;

        if recv.got_client_reset {
            if self.phase == Phase::Init {
                self.phase = Phase::Handshaking;
            }
            // Reply with a server hard reset, then ACK.
            let reset = self.reliable.build_hard_reset();
            let acks = self.reliable.take_pending_acks();
            out.send.push(reset.to_bytes(&acks));
            self.pump_tls(&mut out)?;
            return Ok(out);
        }

        // Feed any newly-ordered TLS bytes into rustls.
        if !recv.tls_bytes.is_empty() {
            let mut cursor = io::Cursor::new(&recv.tls_bytes);
            while (cursor.position() as usize) < recv.tls_bytes.len() {
                let n = self
                    .tls
                    .read_tls(&mut cursor)
                    .map_err(|e| invalid(format!("read_tls: {e}")))?;
                if n == 0 {
                    break;
                }
                self.tls
                    .process_new_packets()
                    .map_err(|e| invalid(format!("tls process: {e}")))?;
            }

            // Drain decrypted plaintext into the control buffer.
            let mut plain = Vec::new();
            let _ = self.tls.reader().read_to_end(&mut plain);
            if !plain.is_empty() {
                self.ctrl_buf.extend_from_slice(&plain);
            }

            // Try to advance the key-method-2 exchange / push handling.
            self.advance_control()?;
        }

        // Pump any TLS output (handshake records or our control replies) back
        // onto the reliable layer, then attach pending ACKs.
        self.pump_tls(&mut out)?;

        if self.kx_done {
            out.authenticated = true;
        }
        Ok(out)
    }

    /// Emit any pending TLS output as P_CONTROL_V1 packets, plus a standalone
    /// ACK if we owe acknowledgements but produced no control packet to ride on.
    fn pump_tls(&mut self, out: &mut PeerOutput) -> io::Result<()> {
        let mut tls_out = Vec::new();
        while self.tls.wants_write() {
            let n = self
                .tls
                .write_tls(&mut tls_out)
                .map_err(|e| invalid(format!("write_tls: {e}")))?;
            if n == 0 {
                break;
            }
        }

        if !tls_out.is_empty() {
            let chunks = self.reliable.chunk_tls_stream(&tls_out);
            for (i, pkt) in chunks.iter().enumerate() {
                // Attach pending acks only to the first packet of the burst.
                let acks = if i == 0 {
                    self.reliable.take_pending_acks()
                } else {
                    Vec::new()
                };
                out.send.push(pkt.to_bytes(&acks));
            }
        }

        // If we still owe acks (no control packet carried them), send a plain ACK.
        if self.reliable.has_pending_acks() {
            let acks = self.reliable.take_pending_acks();
            let ack = self.reliable.build_ack();
            out.send.push(ack.to_bytes(&acks));
        }
        Ok(())
    }

    /// Advance the key-method-2 control exchange using whatever plaintext bytes
    /// are buffered. Runs at most once (after which the connection only carries
    /// PUSH_REQUEST and data). Writes the server reply into the TLS writer.
    fn advance_control(&mut self) -> io::Result<()> {
        if self.kx_done {
            self.handle_post_auth_control()?;
            return Ok(());
        }

        // We need the full fixed prefix + four control strings before we can
        // respond. Parse non-destructively; bail (waiting for more) if short.
        let parsed = match self.try_parse_key_exchange()? {
            Some(p) => p,
            None => return Ok(()), // not enough bytes yet
        };

        // Generate the server random once; it's used both in the reply and in
        // the PRF key derivation.
        fill_random(&mut self.server_random)?;

        // Build the server reply onto the TLS stream.
        let reply = self.build_kx_reply(&parsed)?;
        self.tls
            .writer()
            .write_all(&reply)
            .map_err(|e| invalid(format!("tls write reply: {e}")))?;

        // Derive the data-channel keys.
        self.derive_keys(&parsed)?;

        // Authenticate via the hook.
        let auth = AuthInfo {
            username: parsed.username.clone(),
            password: parsed.password.clone(),
            peer_info: parsed.peer_info.clone(),
            dev_type: parsed.opts.dev_type.clone(),
        };
        let cfg = (self.on_auth)(&auth)?;
        self.peer_cfg = Some(cfg);

        self.layer = match parsed.opts.dev_type.as_str() {
            "tap" => 2,
            _ => 3,
        };
        self.opts = Some(parsed.opts);
        self.kx_done = true;
        self.phase = Phase::Established;
        Ok(())
    }

    /// After authentication the only control traffic the happy path handles is
    /// `PUSH_REQUEST` (NUL-terminated), to which we reply with a `PUSH_REPLY`.
    fn handle_post_auth_control(&mut self) -> io::Result<()> {
        while let Some(nul) = self.ctrl_buf.iter().position(|&b| b == 0) {
            let line: Vec<u8> = self.ctrl_buf.drain(..=nul).collect();
            let s = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
            if s == "PUSH_REQUEST" {
                let reply = self.build_push_reply();
                self.tls
                    .writer()
                    .write_all(reply.as_bytes())
                    .map_err(|e| invalid(format!("tls push reply: {e}")))?;
            }
            // Other control messages are ignored on the happy path.
            // TODO(ovpn): handle peer-info exchange / additional PUSH commands.
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
        format!(
            "PUSH_REPLY,ping 10,comp-lzo no,topology net30,ifconfig {} {}\0",
            ip, gw_or_mask
        )
    }

    // --- key-method 2 parsing -------------------------------------------------

    fn try_parse_key_exchange(&self) -> io::Result<Option<KeyExchange>> {
        let buf = &self.ctrl_buf;

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

        let mut peer_info = std::collections::HashMap::new();
        for line in peer_info_raw.split('\n') {
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

        let options_server = {
            let mut o = opts.clone();
            o.is_server = true;
            o.to_string()
        };
        // options_string was validated above (round-trip check); not retained.
        let _ = options_string;

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

    fn build_kx_reply(&self, kx: &KeyExchange) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.push(2u8); // key_method

        // Server random material (generated in advance_control).
        buf.extend_from_slice(&self.server_random); // r1(32)||r2(32)

        write_control_string(&mut buf, &kx.options_server);
        write_control_string(&mut buf, ""); // username
        write_control_string(&mut buf, ""); // password
        write_control_string(&mut buf, &kx.peer_info_raw);
        Ok(buf)
    }

    /// Derive the 256-byte key expansion via the TLS-1.0 PRF and split it into
    /// per-direction keys, exactly as the Go `ovpnControl` does. Uses the
    /// server random generated in [`advance_control`] so the PRF inputs match
    /// what was sent to the client.
    fn derive_keys(&mut self, kx: &KeyExchange) -> io::Result<()> {
        let (sr1, sr2) = self.server_random.split_at(32);

        // master = PRF10(pre_master, "OpenVPN master secret", r1 || server_r1)
        let mut master = [0u8; 48];
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&kx.random1);
        seed.extend_from_slice(sr1);
        let label = format!("{} master secret", KEY_EXPANSION_ID);
        prf10(&mut master, &kx.pre_master, label.as_bytes(), &seed);

        // expansion = PRF10(master, "OpenVPN key expansion",
        //                   r2 || server_r2 || peer_id || local_id)
        let mut expansion = [0u8; 256];
        let mut seed2 = Vec::with_capacity(32 + 32 + 8 + 8);
        seed2.extend_from_slice(&kx.random2);
        seed2.extend_from_slice(sr2);
        seed2.extend_from_slice(&self.reliable.peer_id);
        seed2.extend_from_slice(&self.reliable.local_id);
        let label2 = format!("{} key expansion", KEY_EXPANSION_ID);
        prf10(&mut expansion, &master, label2.as_bytes(), &seed2);

        self.keys = Some(PeerKeys::from_expansion(&expansion));
        Ok(())
    }

    // --- data channel ---------------------------------------------------------

    fn handle_data(&mut self, data: &[u8]) -> io::Result<PeerOutput> {
        let mut out = PeerOutput::default();
        let (Some(opts), Some(keys)) = (self.opts.as_ref(), self.keys.as_ref()) else {
            return Err(invalid("stream not ready for data transmission"));
        };

        let mut buf = data.to_vec();
        // `None` = auth failure; drop silently.
        if let Some(dec) = data::decrypt(opts, keys, &mut buf)? {
            if !self.replay.check(dec.pid) {
                return Ok(out); // replay — drop
            }
            if dec.is_ping {
                return Ok(out);
            }
            out.deliver = Some(dec.payload.to_vec());
        }
        Ok(out)
    }

    /// Encrypt and frame an outbound IP packet / Ethernet frame for the peer.
    pub fn send_data(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let (Some(opts), Some(keys)) = (self.opts.as_ref(), self.keys.as_ref()) else {
            return Err(invalid("stream not ready for data transmission"));
        };
        self.out_pid = self.out_pid.wrapping_add(1);
        data::encrypt(opts, keys, self.out_pid, payload, fill_random)
    }
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

/// Cryptographic randomness for IVs and session material.
pub(crate) fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    getrandom::getrandom(buf).map_err(|e| io::Error::other(format!("getrandom: {e}")))
}
