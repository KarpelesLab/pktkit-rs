//! Noise IKpsk2 handshake — the two-message exchange that establishes a
//! session keypair from a known peer static key + an ephemeral key pair.
//!
//! Ported from `wg/handshake.go`. The state machine follows the WireGuard
//! whitepaper §5.4 directly; comments mark each Noise token.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use zeroize::Zeroize;

use crate::wg::constants::{
    HandshakeState, NoisePrivateKey, NoisePublicKey, BLAKE2S_128_SIZE, BLAKE2S_256_SIZE,
    CHACHAPOLY_KEY_SIZE, CHACHAPOLY_OVERHEAD, MAX_HANDSHAKES, MAX_SESSIONS,
    MESSAGE_INITIATION_SIZE, MESSAGE_INITIATION_TYPE, MESSAGE_RESPONSE_SIZE,
    MESSAGE_RESPONSE_TYPE, NOISE_PUBLIC_KEY_SIZE, TAI64N_TIMESTAMP_SIZE,
};
use crate::wg::crypto::{
    aead_open_zero, aead_seal_zero, blake2s_mac_128, calculate_mac1_key, ct_eq, fill_random,
    generate_private_key, initial_chain_key, initial_hash, is_zero, mix_hash, mix_key, mix_psk,
    x25519_dh, x25519_public,
};
use crate::wg::handler::{Handler, Keypair, PacketResult, PacketType};
use crate::wg::replay::SlidingWindow;
use crate::wg::time::tai64n_now;
use crate::Result;

/// In-flight Noise transcript state for one handshake (initiator side or
/// responder mid-roundtrip).
#[derive(Clone)]
pub(crate) struct Handshake {
    pub state: HandshakeState,
    pub hash: [u8; BLAKE2S_256_SIZE],
    pub chain_key: [u8; BLAKE2S_256_SIZE],
    pub local_ephemeral: NoisePrivateKey,
    pub local_index: u32,
    pub remote_index: u32,
    pub remote_static: NoisePublicKey,
    pub remote_ephemeral: NoisePublicKey,
    pub precomputed_static_static: [u8; NOISE_PUBLIC_KEY_SIZE],
    pub created: Instant,
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.hash.zeroize();
        self.chain_key.zeroize();
        self.precomputed_static_static.zeroize();
    }
}

// === Wire layout offsets ===================================================
// All offsets below are spelled out in WireGuard §5.4.

const INIT_OFF_TYPE: usize = 0;
const INIT_OFF_SENDER: usize = 4;
const INIT_OFF_EPHEMERAL: usize = 8;
const INIT_OFF_STATIC: usize = 40;
const INIT_OFF_STATIC_END: usize = INIT_OFF_STATIC + NOISE_PUBLIC_KEY_SIZE + CHACHAPOLY_OVERHEAD; // 88
const INIT_OFF_TIMESTAMP: usize = INIT_OFF_STATIC_END;
const INIT_OFF_TIMESTAMP_END: usize =
    INIT_OFF_TIMESTAMP + TAI64N_TIMESTAMP_SIZE + CHACHAPOLY_OVERHEAD; // 116
const INIT_OFF_MAC1: usize = INIT_OFF_TIMESTAMP_END; // 116
const INIT_OFF_MAC2: usize = INIT_OFF_MAC1 + BLAKE2S_128_SIZE; // 132
#[allow(dead_code)]
const INIT_OFF_END: usize = INIT_OFF_MAC2 + BLAKE2S_128_SIZE; // 148

const RESP_OFF_TYPE: usize = 0;
const RESP_OFF_SENDER: usize = 4;
const RESP_OFF_RECEIVER: usize = 8;
const RESP_OFF_EPHEMERAL: usize = 12;
const RESP_OFF_EMPTY: usize = 44;
const RESP_OFF_EMPTY_END: usize = RESP_OFF_EMPTY + CHACHAPOLY_OVERHEAD; // 60
const RESP_OFF_MAC1: usize = RESP_OFF_EMPTY_END;
const RESP_OFF_MAC2: usize = RESP_OFF_MAC1 + BLAKE2S_128_SIZE;
#[allow(dead_code)]
const RESP_OFF_END: usize = RESP_OFF_MAC2 + BLAKE2S_128_SIZE;

// === Initiator side =========================================================

/// Build a handshake-initiation message for `peer_key`. The peer must be
/// pre-authorized via [`Handler::add_peer`]. On success, the returned 148-byte
/// packet is the wire form ready to send; the handler retains an entry in its
/// handshakes table keyed by the freshly-allocated `senderIdx`.
pub(crate) fn initiate_handshake(h: &Handler, peer_key: &NoisePublicKey) -> Result<Vec<u8>> {
    if !h.is_authorized_peer(peer_key) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer not authorized",
        ));
    }

    let client_priv = h.private_key().clone();
    let client_pub = h.public_key();

    // === Noise IK initiator state ===
    let mut hs = Handshake {
        state: HandshakeState::Zeroed,
        hash: initial_hash(),
        chain_key: initial_chain_key(),
        local_ephemeral: NoisePrivateKey::zero(),
        local_index: 0,
        remote_index: 0,
        remote_static: *peer_key,
        remote_ephemeral: NoisePublicKey::zero(),
        precomputed_static_static: [0u8; NOISE_PUBLIC_KEY_SIZE],
        created: Instant::now(),
    };

    // Precompute static-static DH (used twice: now and again after the response).
    let temp_ss = x25519_dh(&client_priv, peer_key);
    hs.precomputed_static_static.copy_from_slice(&temp_ss);
    let mut temp_ss = temp_ss; // shadow so we can zeroize
    temp_ss.zeroize();

    // h = MixHash(h, responder's static pk).
    let h_save = hs.hash;
    mix_hash(&mut hs.hash, &h_save, &peer_key.0);

    // Generate ephemeral keypair.
    hs.local_ephemeral = generate_private_key()?;
    let eph_pub = x25519_public(&hs.local_ephemeral);

    // h = MixHash(h, eph_pub) ; ck = MixKey(ck, eph_pub)
    let h_save = hs.hash;
    mix_hash(&mut hs.hash, &h_save, &eph_pub.0);
    let ck_save = hs.chain_key;
    mix_key(&mut hs.chain_key, &ck_save, &eph_pub.0);

    // DH: eph_priv * peer_static
    let mut temp_ss = x25519_dh(&hs.local_ephemeral, peer_key);
    let mut key = [0u8; CHACHAPOLY_KEY_SIZE];
    let mut ck_next = [0u8; BLAKE2S_256_SIZE];
    crate::wg::crypto::kdf2(&mut ck_next, &mut key_blake(&mut key), &hs.chain_key, &temp_ss);
    hs.chain_key = ck_next;
    temp_ss.zeroize();

    // Encrypt our static public key under k with AD=h.
    let enc_static = aead_seal_zero(&key, &client_pub.0, &hs.hash);
    if enc_static.len() != NOISE_PUBLIC_KEY_SIZE + CHACHAPOLY_OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "unexpected static field size",
        ));
    }
    let h_save = hs.hash;
    mix_hash(&mut hs.hash, &h_save, &enc_static);

    // Static-static: use the precomputed SS.
    let mut ck_next = [0u8; BLAKE2S_256_SIZE];
    crate::wg::crypto::kdf2(
        &mut ck_next,
        &mut key_blake(&mut key),
        &hs.chain_key,
        &hs.precomputed_static_static,
    );
    hs.chain_key = ck_next;

    // Encrypt the TAI64N timestamp under k with AD=h.
    let timestamp = tai64n_now();
    let enc_timestamp = aead_seal_zero(&key, &timestamp, &hs.hash);
    if enc_timestamp.len() != TAI64N_TIMESTAMP_SIZE + CHACHAPOLY_OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "unexpected timestamp field size",
        ));
    }
    let h_save = hs.hash;
    mix_hash(&mut hs.hash, &h_save, &enc_timestamp);

    // Allocate a non-zero sender index.
    let mut sender_idx: u32 = 0;
    while sender_idx == 0 {
        let mut buf = [0u8; 4];
        fill_random(&mut buf)?;
        sender_idx = u32::from_le_bytes(buf);
    }
    hs.local_index = sender_idx;
    hs.state = HandshakeState::InitiationCreated;
    hs.created = Instant::now();

    // Serialize the wire packet (148 bytes).
    let mut pkt = vec![0u8; MESSAGE_INITIATION_SIZE];
    pkt[INIT_OFF_TYPE..INIT_OFF_SENDER].copy_from_slice(&MESSAGE_INITIATION_TYPE.to_le_bytes());
    pkt[INIT_OFF_SENDER..INIT_OFF_EPHEMERAL].copy_from_slice(&sender_idx.to_le_bytes());
    pkt[INIT_OFF_EPHEMERAL..INIT_OFF_STATIC].copy_from_slice(&eph_pub.0);
    pkt[INIT_OFF_STATIC..INIT_OFF_STATIC_END].copy_from_slice(&enc_static);
    pkt[INIT_OFF_TIMESTAMP..INIT_OFF_TIMESTAMP_END].copy_from_slice(&enc_timestamp);

    // Persist handshake state *before* computing MACs so the cookie generator
    // is the single source of truth for the peer's MAC1/MAC2.
    h.insert_handshake(sender_idx, hs)?;

    // MAC1 (+ MAC2 if a cookie reply has been received for this peer). This
    // writes the trailing 32 bytes of the packet.
    h.cookie_add_macs(peer_key, &mut pkt);

    key.zeroize();
    Ok(pkt)
}

/// Process a handshake-response message arriving from the wire (initiator
/// side). Looks up the pending handshake by receiver index, completes the
/// Noise transcript, installs the freshly derived keypair into the session,
/// and returns a single keepalive frame to confirm the session is up.
pub(crate) fn process_handshake_response(h: &Handler, data: &[u8]) -> Result<PacketResult> {
    if data.len() < MESSAGE_RESPONSE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response too short",
        ));
    }

    let msg_type = u32::from_le_bytes(data[RESP_OFF_TYPE..RESP_OFF_SENDER].try_into().unwrap());
    if msg_type != MESSAGE_RESPONSE_TYPE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wrong message type for response",
        ));
    }

    let sender_idx =
        u32::from_le_bytes(data[RESP_OFF_SENDER..RESP_OFF_RECEIVER].try_into().unwrap());
    let receiver_idx =
        u32::from_le_bytes(data[RESP_OFF_RECEIVER..RESP_OFF_EPHEMERAL].try_into().unwrap());

    let mut hs = h
        .take_handshake(receiver_idx)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no pending handshake"))?;

    // MAC1 is keyed on *our* public key.
    if !check_mac1(h.public_key().as_bytes(), data) {
        // Put the handshake back so a later retransmit can complete.
        h.insert_handshake(receiver_idx, hs)?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid MAC1 on response",
        ));
    }

    let mut server_eph_pub = NoisePublicKey::zero();
    server_eph_pub
        .0
        .copy_from_slice(&data[RESP_OFF_EPHEMERAL..RESP_OFF_EMPTY]);

    // h = MixHash(h, server_eph_pub) ; ck = MixKey(ck, server_eph_pub)
    let h_save = hs.hash;
    mix_hash(&mut hs.hash, &h_save, &server_eph_pub.0);
    let ck_save = hs.chain_key;
    mix_key(&mut hs.chain_key, &ck_save, &server_eph_pub.0);

    // ee: client_eph * server_eph
    let mut temp = x25519_dh(&hs.local_ephemeral, &server_eph_pub);
    let ck_save = hs.chain_key;
    mix_key(&mut hs.chain_key, &ck_save, &temp);
    temp.zeroize();

    // se: client_static * server_eph
    let mut temp = x25519_dh(h.private_key(), &server_eph_pub);
    let ck_save = hs.chain_key;
    mix_key(&mut hs.chain_key, &ck_save, &temp);
    temp.zeroize();

    // PSK mix.
    let psk = h.preshared_key(&hs.remote_static);
    let mut k = [0u8; CHACHAPOLY_KEY_SIZE];
    let mut chain = hs.chain_key;
    let mut hash = hs.hash;
    mix_psk(&mut chain, &mut hash, &mut k, &psk);
    hs.chain_key = chain;
    hs.hash = hash;

    // Open empty under k with AD=h.
    let empty_ct = &data[RESP_OFF_EMPTY..RESP_OFF_EMPTY_END];
    let opened = aead_open_zero(&k, empty_ct, &hs.hash)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decrypt empty"))?;
    if !opened.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "non-empty empty field",
        ));
    }
    let h_save = hs.hash;
    mix_hash(&mut hs.hash, &h_save, empty_ct);

    // Bind remote index/eph for later use (also touches the local copy).
    hs.remote_index = sender_idx;
    hs.remote_ephemeral = server_eph_pub;

    // KDF2 from chain key with empty input. Initiator: first = send, second = receive.
    let mut send_key = [0u8; CHACHAPOLY_KEY_SIZE];
    let mut recv_key = [0u8; CHACHAPOLY_KEY_SIZE];
    let mut t0 = [0u8; BLAKE2S_256_SIZE];
    let mut t1 = [0u8; BLAKE2S_256_SIZE];
    crate::wg::crypto::kdf2(&mut t0, &mut t1, &hs.chain_key, &[]);
    send_key.copy_from_slice(&t0[..CHACHAPOLY_KEY_SIZE]);
    recv_key.copy_from_slice(&t1[..CHACHAPOLY_KEY_SIZE]);
    t0.zeroize();
    t1.zeroize();
    k.zeroize();

    let peer_key = hs.remote_static;
    let local_idx = hs.local_index;
    let remote_idx = hs.remote_index;

    let kp = Arc::new(Keypair {
        send_key,
        receive_key: recv_key,
        send_counter: AtomicU64::new(0),
        created: Instant::now(),
        local_index: local_idx,
        remote_index: remote_idx,
        peer_key,
        is_initiator: true,
        replay_filter: SlidingWindow::new(),
    });

    h.install_keypair(local_idx, kp.clone());
    h.upsert_session(peer_key, kp);

    // Touch peer last-handshake.
    h.touch_peer_handshake(&peer_key);

    // Standard WG behaviour: send a keepalive to confirm.
    let keepalive = match crate::wg::transport::encrypt_data_packet(h, &[], &peer_key) {
        Ok(buf) => buf,
        Err(crate::wg::transport::EncryptError::RekeyRequired(buf)) => buf,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
    };

    Ok(PacketResult {
        ty: PacketType::HandshakeResponse,
        response: keepalive,
        data: Vec::new(),
        peer_key,
    })
}

// === Responder side ========================================================

/// Process an incoming handshake-initiation. Returns either a 92-byte response
/// packet ready to send (peer authorized) or a cookie reply when under load.
pub(crate) fn process_handshake_initiation(
    h: &Handler,
    data: &[u8],
    remote_addr: &SocketAddr,
) -> Result<PacketResult> {
    if data.len() < MESSAGE_INITIATION_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "initiation too short",
        ));
    }

    h.inc_active_handshakes();
    let _guard = DecGuard(h);

    // Validate MAC1 against our public key — always drop if invalid.
    if !h.cookie_check_mac1(data) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid MAC1"));
    }

    // Under load: require a valid MAC2. The sender index lives at
    // data[4..8]; MAC1 occupies data[116..132] on a 148-byte initiation.
    if h.is_under_load() {
        let sender = u32::from_le_bytes(
            data[INIT_OFF_SENDER..INIT_OFF_EPHEMERAL].try_into().unwrap(),
        );
        let src = ip_bytes(remote_addr);
        let mac2_ok = !is_zero(&data[INIT_OFF_MAC2..INIT_OFF_END])
            && h.cookie_check_mac2(data, &src);
        if !mac2_ok {
            let reply = h.cookie_generate_reply(&src, sender, &data[INIT_OFF_MAC1..INIT_OFF_MAC2])?;
            return Ok(PacketResult {
                ty: PacketType::CookieReply,
                response: reply,
                data: Vec::new(),
                peer_key: NoisePublicKey::zero(),
            });
        }
    }

    let msg_type =
        u32::from_le_bytes(data[INIT_OFF_TYPE..INIT_OFF_SENDER].try_into().unwrap());
    if msg_type != MESSAGE_INITIATION_TYPE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wrong message type",
        ));
    }
    let sender_idx =
        u32::from_le_bytes(data[INIT_OFF_SENDER..INIT_OFF_EPHEMERAL].try_into().unwrap());

    let server_priv = h.private_key().clone();
    let server_pub = h.public_key();

    // Build noise state.
    let mut hs = Handshake {
        state: HandshakeState::Zeroed,
        hash: initial_hash(),
        chain_key: initial_chain_key(),
        local_ephemeral: NoisePrivateKey::zero(),
        local_index: 0,
        remote_index: sender_idx,
        remote_static: NoisePublicKey::zero(),
        remote_ephemeral: NoisePublicKey::zero(),
        precomputed_static_static: [0u8; NOISE_PUBLIC_KEY_SIZE],
        created: Instant::now(),
    };

    // h = MixHash(h, our static pk).
    let h_save = hs.hash;
    mix_hash(&mut hs.hash, &h_save, &server_pub.0);

    // Pull client ephemeral.
    let mut remote_eph = NoisePublicKey::zero();
    remote_eph
        .0
        .copy_from_slice(&data[INIT_OFF_EPHEMERAL..INIT_OFF_STATIC]);
    hs.remote_ephemeral = remote_eph;

    let h_save = hs.hash;
    mix_hash(&mut hs.hash, &h_save, &remote_eph.0);
    let ck_save = hs.chain_key;
    mix_key(&mut hs.chain_key, &ck_save, &remote_eph.0);

    // Decrypt the client's static public key.
    let mut k = [0u8; CHACHAPOLY_KEY_SIZE];
    let mut temp_ss = x25519_dh(&server_priv, &remote_eph);
    let mut t0 = [0u8; BLAKE2S_256_SIZE];
    let mut t1 = [0u8; BLAKE2S_256_SIZE];
    crate::wg::crypto::kdf2(&mut t0, &mut t1, &hs.chain_key, &temp_ss);
    hs.chain_key = t0;
    k.copy_from_slice(&t1[..CHACHAPOLY_KEY_SIZE]);
    temp_ss.zeroize();
    t1.zeroize();

    let enc_static = &data[INIT_OFF_STATIC..INIT_OFF_STATIC_END];
    let client_static = aead_open_zero(&k, enc_static, &hs.hash)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decrypt static"))?;
    if client_static.len() != NOISE_PUBLIC_KEY_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client static wrong length",
        ));
    }
    hs.remote_static
        .0
        .copy_from_slice(&client_static);

    let h_save = hs.hash;
    mix_hash(&mut hs.hash, &h_save, enc_static);

    // Static-static DH.
    let mut temp_ss = x25519_dh(&server_priv, &hs.remote_static);
    hs.precomputed_static_static.copy_from_slice(&temp_ss);
    let mut t0 = [0u8; BLAKE2S_256_SIZE];
    let mut t1 = [0u8; BLAKE2S_256_SIZE];
    crate::wg::crypto::kdf2(&mut t0, &mut t1, &hs.chain_key, &temp_ss);
    hs.chain_key = t0;
    k.copy_from_slice(&t1[..CHACHAPOLY_KEY_SIZE]);
    temp_ss.zeroize();
    t1.zeroize();

    // Decrypt timestamp; we don't enforce monotonicity yet (TODO).
    let enc_timestamp = &data[INIT_OFF_TIMESTAMP..INIT_OFF_TIMESTAMP_END];
    let timestamp = aead_open_zero(&k, enc_timestamp, &hs.hash)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decrypt timestamp"))?;
    let h_save = hs.hash;
    mix_hash(&mut hs.hash, &h_save, enc_timestamp);

    // Peer authorization gate.
    if !h.is_authorized_peer(&hs.remote_static) {
        h.notify_unknown_peer(&hs.remote_static, remote_addr, data);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unauthorized peer",
        ));
    }

    // Timestamp replay: must be strictly greater than the last accepted one.
    if !h.accept_peer_timestamp(&hs.remote_static, &timestamp) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "replayed handshake timestamp",
        ));
    }

    // === Build response ===
    let mut sender_idx_local: u32 = 0;
    while sender_idx_local == 0 {
        let mut buf = [0u8; 4];
        fill_random(&mut buf)?;
        sender_idx_local = u32::from_le_bytes(buf);
    }

    hs.local_ephemeral = generate_private_key()?;
    let eph_pub = x25519_public(&hs.local_ephemeral);

    let h_save = hs.hash;
    mix_hash(&mut hs.hash, &h_save, &eph_pub.0);
    let ck_save = hs.chain_key;
    mix_key(&mut hs.chain_key, &ck_save, &eph_pub.0);

    // ee: local_eph * remote_eph
    let mut temp = x25519_dh(&hs.local_ephemeral, &hs.remote_ephemeral);
    let ck_save = hs.chain_key;
    mix_key(&mut hs.chain_key, &ck_save, &temp);
    temp.zeroize();

    // se: local_eph * remote_static
    let mut temp = x25519_dh(&hs.local_ephemeral, &hs.remote_static);
    let ck_save = hs.chain_key;
    mix_key(&mut hs.chain_key, &ck_save, &temp);
    temp.zeroize();

    // PSK.
    let psk = h.preshared_key(&hs.remote_static);
    let mut chain = hs.chain_key;
    let mut hash = hs.hash;
    mix_psk(&mut chain, &mut hash, &mut k, &psk);
    hs.chain_key = chain;
    hs.hash = hash;

    // Encrypt empty under k with AD=h.
    let empty_ct = aead_seal_zero(&k, &[], &hs.hash);
    if empty_ct.len() != CHACHAPOLY_OVERHEAD {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "empty seal wrong size",
        ));
    }
    let h_save = hs.hash;
    mix_hash(&mut hs.hash, &h_save, &empty_ct);

    // Build wire packet.
    let mut pkt = vec![0u8; MESSAGE_RESPONSE_SIZE];
    pkt[RESP_OFF_TYPE..RESP_OFF_SENDER].copy_from_slice(&MESSAGE_RESPONSE_TYPE.to_le_bytes());
    pkt[RESP_OFF_SENDER..RESP_OFF_RECEIVER].copy_from_slice(&sender_idx_local.to_le_bytes());
    pkt[RESP_OFF_RECEIVER..RESP_OFF_EPHEMERAL].copy_from_slice(&sender_idx.to_le_bytes());
    pkt[RESP_OFF_EPHEMERAL..RESP_OFF_EMPTY].copy_from_slice(&eph_pub.0);
    pkt[RESP_OFF_EMPTY..RESP_OFF_EMPTY_END].copy_from_slice(&empty_ct);

    // MAC1 keyed on remote_static; covers everything up to MAC1 offset.
    let mac1_key = calculate_mac1_key(&hs.remote_static);
    let mac1 = blake2s_mac_128(&mac1_key, &pkt[..RESP_OFF_MAC1]);
    pkt[RESP_OFF_MAC1..RESP_OFF_MAC2].copy_from_slice(&mac1);
    // MAC2 stays zero (we don't generate cookies yet — TODO).

    // === Derive transport keys: responder = recv | send order ===
    let mut t0 = [0u8; BLAKE2S_256_SIZE];
    let mut t1 = [0u8; BLAKE2S_256_SIZE];
    crate::wg::crypto::kdf2(&mut t0, &mut t1, &hs.chain_key, &[]);
    let mut recv_key = [0u8; CHACHAPOLY_KEY_SIZE];
    let mut send_key = [0u8; CHACHAPOLY_KEY_SIZE];
    recv_key.copy_from_slice(&t0[..CHACHAPOLY_KEY_SIZE]);
    send_key.copy_from_slice(&t1[..CHACHAPOLY_KEY_SIZE]);
    t0.zeroize();
    t1.zeroize();
    k.zeroize();

    hs.local_index = sender_idx_local;
    hs.state = HandshakeState::ResponseCreated;
    hs.created = Instant::now();

    let peer_key = hs.remote_static;

    let kp = Arc::new(Keypair {
        send_key,
        receive_key: recv_key,
        send_counter: AtomicU64::new(0),
        created: Instant::now(),
        local_index: sender_idx_local,
        remote_index: sender_idx,
        peer_key,
        is_initiator: false,
        replay_filter: SlidingWindow::new(),
    });

    h.check_keypair_capacity(MAX_HANDSHAKES)?;
    h.install_keypair(sender_idx_local, kp.clone());
    h.check_session_capacity(MAX_SESSIONS, &peer_key)?;
    h.upsert_session(peer_key, kp);

    h.touch_peer_handshake(&peer_key);

    Ok(PacketResult {
        ty: PacketType::HandshakeResponse,
        response: pkt,
        data: Vec::new(),
        peer_key,
    })
}

// === Cookie reply (initiator-side parse only — minimal) ====================

pub(crate) fn process_cookie_reply(h: &Handler, data: &[u8]) -> Result<PacketResult> {
    if data.len() < crate::wg::constants::MESSAGE_COOKIE_REPLY_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cookie reply too short",
        ));
    }
    // Receiver index (our local sender index) identifies the pending handshake,
    // which tells us which peer the reply is for.
    let receiver = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let peer = h
        .handshake_remote_static(receiver)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no pending handshake for cookie reply"))?;

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&data[8..32]);
    h.peer_consume_cookie(&peer, &nonce, &data[32..crate::wg::constants::MESSAGE_COOKIE_REPLY_SIZE])?;

    Ok(PacketResult {
        ty: PacketType::CookieReceived,
        response: Vec::new(),
        data: Vec::new(),
        peer_key: peer,
    })
}

/// Source-address bytes for cookie derivation: 4 for v4, 16 for v6.
fn ip_bytes(addr: &SocketAddr) -> Vec<u8> {
    match addr.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    }
}

// === MAC1 check ============================================================

/// Verify the MAC1 field at the end of a handshake-shaped message. The MAC
/// covers everything before the MAC1 field.
pub(crate) fn check_mac1(local_pub: &[u8; NOISE_PUBLIC_KEY_SIZE], msg: &[u8]) -> bool {
    if msg.len() < 2 * BLAKE2S_128_SIZE {
        return false;
    }
    let smac2 = msg.len() - BLAKE2S_128_SIZE;
    let smac1 = smac2 - BLAKE2S_128_SIZE;
    let key = calculate_mac1_key(&NoisePublicKey(*local_pub));
    let computed = blake2s_mac_128(&key, &msg[..smac1]);
    ct_eq(&computed, &msg[smac1..smac2])
}

// === Helpers ===============================================================

struct DecGuard<'a>(&'a Handler);
impl<'a> Drop for DecGuard<'a> {
    fn drop(&mut self) {
        self.0.dec_active_handshakes();
    }
}

/// Helper: produce a mutable view of a `[u8; 32]` as the type the kdf2 helper
/// in `crypto` expects (a 32-byte chain-key shaped buffer). We use this when
/// we want kdf2 to deliver a chacha key into a 32-byte stack slot — the inner
/// types are identical because both are `[u8; 32]`.
fn key_blake(k: &mut [u8; CHACHAPOLY_KEY_SIZE]) -> &mut [u8; BLAKE2S_256_SIZE] {
    // Both arrays are 32 bytes; transmute by reborrow.
    // SAFETY: BLAKE2S_256_SIZE == CHACHAPOLY_KEY_SIZE == 32 at compile time.
    let _: [(); 0] =
        [(); (BLAKE2S_256_SIZE == CHACHAPOLY_KEY_SIZE) as usize - 1];
    unsafe { &mut *(k.as_mut_ptr() as *mut [u8; BLAKE2S_256_SIZE]) }
}

