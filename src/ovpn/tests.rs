//! End-to-end control-channel test.
//!
//! Drives a purecrypto TLS client against our [`Peer`] (server) entirely
//! through the OpenVPN reliable layer — there is no socket; datagrams are
//! passed between the two sides in-memory. This exercises the full happy path:
//! client hard reset → TLS 1.2 handshake (over P_CONTROL packets) → key-method
//! 2 exchange → data-channel key derivation → an AES-256-GCM data roundtrip in
//! both directions.

use std::sync::Arc;

use purecrypto::tls::{Config as TlsConfig, Connection as TlsConnection, ProtocolVersion};

use super::data;
use super::keys::PeerKeys;
use super::options::Options;
use super::packet_ctrl::ControlPacket;
use super::peer::PeerTimers;
use super::peer::{AuthInfo, OnAuth, Peer, PeerConfig};
use super::prf::prf10;
use super::reliable::Reliable;
use super::{CipherBlockMethod, CipherCryptoAlg, Opcode};
use crate::time::Instant;
use std::time::Duration;

const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUIivmiQqCMO8WqOV9OJFs/D3JLRUwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJb3Zwbi10ZXN0MCAXDTI2MDUyNTEyNDcxM1oYDzIxMjYw
NTAxMTI0NzEzWjAUMRIwEAYDVQQDDAlvdnBuLXRlc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCbtz3SIMlRZW4uxbYk7cYH/aVsCd2eYnnc9GeTv52l
HbncXxNWyXGDPaxdTX8f02+dV3DsUK2Q3mgeeiCEJtZtlIdqLAWEi24Nnppg5uYV
EYjk6yd4AZnuFoE73C3ghqcAIDgDcRJufsusBN8tGyGy3EN5qrfJpiRhc/FQa80M
UWkacUkqwlfJgFk+r/r7Qm8eB8DPRLnp+m0BtfSXeifGaNZqqV9aFpceKLCH0NF2
2iPWmCVtxQKTpoOK/cHTZYL6jC/473EAs9yHMCCdODZxtiQKoqlV4EafdsDcs5Jn
xcawlFF0UlKcnDlqBjGMkkFQ4D/5NTqRywBZh438h2yvAgMBAAGjUzBRMB0GA1Ud
DgQWBBTPzkOvBGNIGQMWjD8AvntnpsUiRDAfBgNVHSMEGDAWgBTPzkOvBGNIGQMW
jD8AvntnpsUiRDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCP
C6W5Kgqqr5oR16SaKDfa7lg/SqBCY6rqUGfmu0WhNaffGfPn5Wji3LDjTCoaCJaY
Bmvhz1DSE/OVnCbBx4mmOiSajvRqNnlvJU7mlTGva3SjcADw9oDAYC8THlfqnZxj
iX2UTMQZjuROUVmKyJLKPl44oHvsvnbVYlU2yQUKezGw5axgL8j2i6SNC3b/2nSx
SfjZ6IIGT3DfeW8PQ3Tw4E1POrNZ6w4PNG4YAunJEF0qqGqOkKE8iFzwKHRldLqH
u0EcLXIDphBc7jtvWy5bc6QtFFKdUdosbwMyyqXhTpZ3c1GjkmBTWchX7DoEaRYb
rPldEadwW1C3H/sskvgC
-----END CERTIFICATE-----
";

const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCbtz3SIMlRZW4u
xbYk7cYH/aVsCd2eYnnc9GeTv52lHbncXxNWyXGDPaxdTX8f02+dV3DsUK2Q3mge
eiCEJtZtlIdqLAWEi24Nnppg5uYVEYjk6yd4AZnuFoE73C3ghqcAIDgDcRJufsus
BN8tGyGy3EN5qrfJpiRhc/FQa80MUWkacUkqwlfJgFk+r/r7Qm8eB8DPRLnp+m0B
tfSXeifGaNZqqV9aFpceKLCH0NF22iPWmCVtxQKTpoOK/cHTZYL6jC/473EAs9yH
MCCdODZxtiQKoqlV4EafdsDcs5JnxcawlFF0UlKcnDlqBjGMkkFQ4D/5NTqRywBZ
h438h2yvAgMBAAECggEADRUn/lkJ1lW0HFLj0EDNOWD6qSk/s5hozlhsbAdBKp0P
lK/E6K7pDhKRl480xeBA9D0N/D91AwMPSAw7t3lUh7AJxoZR+luv5eNe62hK3sHy
je/MiPJy09mT3GB4gZuJOWNQ7B0aZCqGrc+vo9MFPElG6Vh0s4j1bTNNYX6FI5Ur
4kXYViwdRupAShBSS0VWZatSV6xnF58SAqUkIehYHI2XARxze5L8PIzmn4B4CijJ
v3CtbEa7WMUwKIWylJHpTe+IOZ+/P3LK2adX+r3hhMwzGzhJ01dJ23S3haIdtQNw
AWrZitDTChDNu2IdJ1w3IeApzBGwFx/gh38RhuJwzQKBgQDHusRkbRv8xNHqhkHx
/iMyxU0wnxfS0C7rVcVc0gYDm6OW3mHnrZWcxFFuCDqdtaoOspIUHFXwGPKsEISk
LcxwJR048OQbJ8d+YJRIDqLtozAnPKkW/wLvvRVISlJQrH6e0vgi2H0YNALb5saP
uuphMin2J/KSbR9yi9cyIxKIFQKBgQDHlgnl+NqF/gQaOjfyXY79eMiSmyckBXpA
2ZTbOxkvFwxHlPu1wbrBM4QnEmSTjFU6MWrROq0KxOGIUFFvzbrVZGR9HmC76hPV
oCwL6aGdw9XUKli12qz2LLBq7Nt01lKVnrIi9FbTyZVuNeoBU0EWOemT9KpuJM+m
GiSDdsSuswKBgEUJdKr13++uJJT5FUBNRONeuYCt7TEsTpt/yTl9SyDiIliaw6Ku
KIHIhhEPfRtYWNC9vqp+5OGZ7f+1sfOB9SFqYsB025PbWyR+w6JolL6pYpKdcCEH
wn8Vj46uSeeiyB2j9Ksuw4ajK73Q9h9mT2+LRF/WjQ059N3GInstDlHFAoGBAJn0
MZR0nlPHenCkwe0xoBADsGvuRIXzt7b4X2uwrZ92XuGEmZk9ZAqN632cIXrzP/bQ
kb3tTffFoNbeZcMhZeIfO6iL20B4sm4RzIgv4pvoqTOsqps0oECQflEsfaglfrSt
Imn2Ilfh4mOOMQBusQEtEPExRJoLySUue0XxQowjAoGALwlmYzpu2vzDfglTwj20
ZDOnkH0eeipIO6MLIcZa2xa2L7MuDM6AtnLegDys2tFveMDyF2BkuzfecwWFOqhe
Aj0kuBCfSQxBJMZH0c+pWzY5svm3XY9YI3Qxl3saoEN8X6CmMu4MkCvQL30U7Mn3
hTUd0ADAoahUGAiz1Wal4L0=
-----END PRIVATE KEY-----
";

/// Decode a PEM block into DER.
fn der(pem: &str, label: &str) -> Vec<u8> {
    purecrypto::der::pem_decode(pem, label).expect("PEM decodes")
}

/// OpenVPN's control channel is classically TLS 1.2, but a server built with
/// the default version range accepts 1.3 as well and picks the engine from the
/// ClientHello. Both paths are exercised.
const TLS12_ONLY: (ProtocolVersion, ProtocolVersion) =
    (ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_2);
const TLS12_TO_13: (ProtocolVersion, ProtocolVersion) =
    (ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3);

fn server_config_versions(versions: (ProtocolVersion, ProtocolVersion)) -> Arc<TlsConfig> {
    let chain = vec![der(TEST_CERT, "CERTIFICATE")];
    let key = purecrypto::rsa::BoxedRsaPrivateKey::from_pkcs8_der(&der(TEST_KEY, "PRIVATE KEY"))
        .expect("test key parses");
    Arc::new(
        TlsConfig::builder()
            .versions(versions.0, versions.1)
            .rng(Arc::new(purecrypto::rng::OsRng))
            .identity(chain, purecrypto::tls::SigningKey::Rsa(key))
            .build(),
    )
}

pub(super) fn server_config() -> Arc<TlsConfig> {
    server_config_versions(TLS12_ONLY)
}

fn client_config_versions(versions: (ProtocolVersion, ProtocolVersion)) -> Arc<TlsConfig> {
    Arc::new(
        TlsConfig::builder()
            .versions(versions.0, versions.1)
            .rng(Arc::new(purecrypto::rng::OsRng))
            .server_name("ovpn-test")
            // The test certificate is self-signed and there is no trust anchor
            // to check it against; this test is about the OpenVPN plumbing, not
            // about X.509 validation.
            .verify_certificates(false)
            .build(),
    )
}

fn client_config() -> Arc<TlsConfig> {
    client_config_versions(TLS12_ONLY)
}

/// A minimal OpenVPN client that mirrors the server's reliable+TLS plumbing,
/// used only to drive the e2e test.
pub(super) struct TestClient {
    tls: TlsConnection,
    reliable: Reliable,
    ctrl_buf: Vec<u8>,
    /// What the client puts in its key-method-2 message.
    kx: ClientKx,
}

/// The strings of a client's key-method-2 message. `None` is sent the way
/// OpenVPN's write_empty_string does: a zero length and no bytes.
struct ClientKx {
    options: String,
    username: Option<String>,
    password: Option<String>,
    peer_info: Option<String>,
}

impl Default for ClientKx {
    fn default() -> ClientKx {
        let opts = Options {
            cipher_crypto: CipherCryptoAlg::Aes,
            cipher_size: 256,
            cipher_block: CipherBlockMethod::Gcm,
            auth: super::options::AuthHash::None,
            compression: "lzo".into(),
            is_server: false,
            ..Default::default()
        };
        ClientKx {
            options: opts.to_string(),
            username: Some(String::new()),
            password: Some(String::new()),
            peer_info: Some("IV_VER=2.6\n".into()),
        }
    }
}

impl TestClient {
    pub(super) fn new(local_id: [u8; 8]) -> TestClient {
        Self::with_config(local_id, client_config())
    }

    fn with_config(local_id: [u8; 8], config: Arc<TlsConfig>) -> TestClient {
        let tls = TlsConnection::client(&config).unwrap();
        TestClient {
            tls,
            reliable: Reliable::new(local_id),
            ctrl_buf: Vec::new(),
            kx: ClientKx::default(),
        }
    }

    // Build the client hard reset datagram (pid 0, advancing out_counter).
    pub(super) fn hard_reset(&mut self) -> Vec<u8> {
        let pkt = self.reliable.build_client_hard_reset();
        pkt.to_bytes(&[])
    }

    // Process an inbound datagram from the server; return datagrams to send.
    fn handle(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut send = Vec::new();
        let recv = self.reliable.recv(data).expect("client recv");

        if !recv.tls_bytes.is_empty() {
            let mut fed = 0usize;
            while fed < recv.tls_bytes.len() {
                let n = self.tls.feed(&recv.tls_bytes[fed..]).unwrap();
                if n == 0 {
                    break;
                }
                fed += n;
            }
            let plain = self.tls.recv().unwrap();
            self.ctrl_buf.extend_from_slice(&plain);
        }

        self.pump_tls(&mut send);
        send
    }

    pub(super) fn pump_tls(&mut self, send: &mut Vec<Vec<u8>>) {
        // As an OpenVPN client, start TLS only once the server has answered
        // the hard reset: until then there is no session to send it on.
        let tls_out = if self.reliable.peer_id == [0; 8] {
            Vec::new()
        } else {
            self.tls.pop().expect("client tls pop")
        };
        if !tls_out.is_empty() {
            let chunks = self.reliable.chunk_tls_stream(&tls_out);
            for (i, pkt) in chunks.iter().enumerate() {
                let acks = if i == 0 {
                    self.reliable.take_pending_acks()
                } else {
                    Vec::new()
                };
                send.push(pkt.to_bytes(&acks));
            }
        }
        if self.reliable.has_pending_acks() {
            let acks = self.reliable.take_pending_acks();
            let ack = self.reliable.build_ack();
            send.push(ack.to_bytes(&acks));
        }
    }

    pub(super) fn handshake_done(&self) -> bool {
        self.tls.is_handshake_complete()
    }

    /// Send a control-channel message (e.g. `PUSH_REQUEST\0`) over TLS,
    /// returning the datagrams that carry it.
    pub(super) fn send_control(&mut self, msg: &[u8]) -> Vec<Vec<u8>> {
        self.tls.send(msg).unwrap();
        let mut out = Vec::new();
        self.pump_tls(&mut out);
        out
    }

    /// Process a datagram from the server, returning the control-channel
    /// plaintext it completed (data-channel packets are ignored) and the
    /// datagrams to send back.
    pub(super) fn handle_any(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        if Opcode::from_byte(data[0]).0 == Opcode::DATA_V1 {
            return Vec::new();
        }
        self.handle(data)
    }

    /// Start renegotiating on `key_id` as an OpenVPN client does
    /// (key_state_soft_reset): a fresh TLS session over a fresh reliable
    /// stream, opened by a P_CONTROL_SOFT_RESET_V1, which is returned.
    fn renegotiate(&mut self, key_id: u8) -> Vec<u8> {
        self.tls = TlsConnection::client(&client_config()).unwrap();
        let mut r = Reliable::new(self.reliable.local_id);
        r.peer_id = self.reliable.peer_id;
        r.key_id = key_id;
        self.reliable = r;
        self.ctrl_buf.clear();
        self.reliable.build_soft_reset().to_bytes(&[])
    }

    /// Whether a control datagram from the server belongs to this client's
    /// session, for tests running several clients over one socket.
    pub(super) fn owns(&self, data: &[u8]) -> bool {
        let Ok(p) = ControlPacket::parse(data) else {
            return false;
        };
        if self.reliable.peer_id == [0; 8] {
            p.remote_id == self.reliable.local_id
        } else {
            p.session_id == self.reliable.peer_id
        }
    }

    /// Control-channel plaintext received so far.
    pub(super) fn control_text(&self) -> &[u8] {
        &self.ctrl_buf
    }
}

/// Drive `client` through hard reset, TLS handshake and key exchange over a
/// real transport, returning the keys it encrypts with (which also decrypt
/// what the server sends) and any data-channel packets that arrived.
pub(super) fn connect_via(
    client: &mut TestClient,
    send: &mut dyn FnMut(&[u8]),
    recv: &mut dyn FnMut() -> Option<Vec<u8>>,
) -> (PeerKeys, Vec<Vec<u8>>) {
    send(&client.hard_reset());
    let mut kx = None;
    let mut data = Vec::new();
    for _ in 0..200 {
        let mut out = Vec::new();
        client.pump_tls(&mut out);
        for d in out {
            send(&d);
        }
        if client.handshake_done() && kx.is_none() {
            kx = Some(send_client_key_material(client));
            continue;
        }
        if kx.is_some() && client.ctrl_buf.len() >= 69 {
            break;
        }
        let Some(d) = recv() else {
            continue;
        };
        if Opcode::from_byte(d[0]).0 == Opcode::DATA_V1 {
            data.push(d);
            continue;
        }
        for o in client.handle(&d) {
            send(&o);
        }
    }
    let (pre_master, random1, random2) = kx.expect("TLS handshake");
    let server_random = read_server_key_reply(client);
    let keys = derive_client_keys(
        &pre_master,
        &random1,
        &random2,
        &server_random,
        client.reliable.local_id,
        client.reliable.peer_id,
    )
    .encrypt_side;
    (keys, data)
}

/// Run the reliable-layer pump until the TLS handshake completes on both
/// sides, or give up. Returns whether it completed.
fn drive_handshake(server: &mut Peer, client: &mut TestClient) -> bool {
    let first = vec![client.hard_reset()];
    drive_from(server, client, first)
}

/// [`drive_handshake`] starting from the given client datagrams.
fn drive_from(server: &mut Peer, client: &mut TestClient, first: Vec<Vec<u8>>) -> bool {
    let mut server_inbox = first;
    let mut client_inbox: Vec<Vec<u8>> = Vec::new();

    for _round in 0..50 {
        for dg in server_inbox.drain(..) {
            let out = server.handle_packet(&dg).expect("server handle");
            client_inbox.extend(out.send);
        }
        let mut extra = Vec::new();
        client.pump_tls(&mut extra);
        server_inbox.extend(extra);

        for dg in client_inbox.drain(..) {
            server_inbox.extend(client.handle(&dg));
        }
        if client.handshake_done() {
            return true;
        }
    }
    client.handshake_done()
}

/// A server built with the default 1.2–1.3 range picks its engine from the
/// ClientHello rather than from config, which is a different code path than
/// the version-pinned one the main e2e test drives. Real deployments leave the
/// range at its default, so both ends of it need to work.
#[test]
fn tls_handshake_completes_across_the_version_range() {
    for (name, client_versions) in [
        ("1.2 client", TLS12_ONLY),
        ("1.3-capable client", TLS12_TO_13),
    ] {
        let mut server = Peer::new(
            server_config_versions(TLS12_TO_13),
            *b"SERVERID",
            auth_hook(),
        )
        .unwrap();
        let mut client =
            TestClient::with_config(*b"CLIENTID", client_config_versions(client_versions));

        assert!(
            drive_handshake(&mut server, &mut client),
            "{name}: handshake did not complete against a 1.2-1.3 server"
        );
    }
}

#[test]
fn e2e_tls_handshake_and_key_exchange() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");

    // 1. Client hard reset -> server.
    let mut server_inbox: Vec<Vec<u8>> = vec![client.hard_reset()];
    let mut client_inbox: Vec<Vec<u8>> = Vec::new();

    // Kick the client's TLS so its ClientHello is queued once the session is up.
    // (The client only generates TLS output after it has a peer id, which it
    // learns from the server hard reset — so we just pump in the loop.)

    let mut authenticated = false;
    for _round in 0..50 {
        // Deliver everything queued for the server.
        for dg in server_inbox.drain(..) {
            let out = server.handle_packet(&dg).expect("server handle");
            if out.authenticated {
                authenticated = true;
            }
            client_inbox.extend(out.send);
        }
        // After the very first round (server hard reset received), the client
        // must start the TLS handshake. We trigger it by pumping the client's
        // TLS even with no inbound data.
        {
            let mut extra = Vec::new();
            client.pump_tls(&mut extra);
            server_inbox.extend(extra);
        }
        // Deliver everything queued for the client.
        for dg in client_inbox.drain(..) {
            let out = client.handle(&dg);
            server_inbox.extend(out);
        }

        if authenticated && client.handshake_done() {
            break;
        }
    }

    assert!(
        client.handshake_done(),
        "client TLS handshake did not complete"
    );

    // Send the key-method-2 client blob once the TLS handshake is done.
    if authenticated {
        // Already authenticated through the loop's data exchange below.
    }

    // Drive the key exchange: client writes its key material, server replies.
    let (pre_master, random1, random2) = send_client_key_material(&mut client);
    let mut server_inbox: Vec<Vec<u8>> = Vec::new();
    {
        let mut extra = Vec::new();
        client.pump_tls(&mut extra);
        server_inbox.extend(extra);
    }

    let mut client_inbox: Vec<Vec<u8>> = Vec::new();
    for _round in 0..30 {
        for dg in server_inbox.drain(..) {
            let out = server.handle_packet(&dg).expect("server handle kx");
            if out.authenticated {
                authenticated = true;
            }
            client_inbox.extend(out.send);
        }
        for dg in client_inbox.drain(..) {
            let out = client.handle(&dg);
            server_inbox.extend(out);
        }
        if authenticated {
            break;
        }
    }

    assert!(authenticated, "server did not authenticate the peer");

    // Read the server's key-exchange reply and derive client-side keys.
    let server_random = read_server_key_reply(&mut client);

    // Derive the data-channel keys on both ends and confirm a GCM roundtrip.
    let client_keys = derive_client_keys(
        &pre_master,
        &random1,
        &random2,
        &server_random,
        *b"CLIENTID", // client's local id
        *b"SERVERID", // server's id, as the client sees it
    );

    // Build matching GCM options.
    let opts = Options {
        cipher_crypto: CipherCryptoAlg::Aes,
        cipher_size: 256,
        cipher_block: CipherBlockMethod::Gcm,
        auth: super::options::AuthHash::None,
        compression: "lzo".into(),
        ..Default::default()
    };

    // Client encrypts -> server-side keys decrypt. The server derived its keys
    // internally; we can't read them directly, but we *can* verify the client's
    // own decrypt path against its own encrypt path, and that the server
    // accepts a packet the client sent (round-trips through the live server).
    let payload = b"hello over the data channel";
    let pkt = data::encrypt(&opts, &client_keys.encrypt_side, 0, 1, payload, |b| {
        b.fill(0xAB);
        Ok(())
    })
    .unwrap();

    // Feed it to the live server peer; it should decrypt and want to deliver it.
    let out = server.handle_packet(&pkt).expect("server data");
    assert_eq!(
        out.deliver.as_deref(),
        Some(&payload[..]),
        "server failed to decrypt the client's data packet"
    );
}

/// When the client withholds its ACK, the server's reliable layer must
/// retransmit the unacknowledged control packet once its deadline passes; once
/// the client finally ACKs it, the retransmit stops.
#[test]
fn retransmit_fires_when_ack_withheld() {
    use super::packet_ctrl::ControlPacket;
    use super::reliable::RETRANSMIT_INITIAL;
    use crate::time::Instant;
    use std::time::Duration;

    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");

    // Client hard reset -> server. The server replies with its own hard reset
    // (pid 0, an unacked reliable packet). We deliberately do NOT feed it back
    // to the client, so it never gets ACKed.
    let out = server.handle_packet(&client.hard_reset()).expect("reset");
    let server_reset = out
        .send
        .iter()
        .map(|d| ControlPacket::parse(d).unwrap())
        .find(|p| p.opcode == Opcode::CONTROL_HARD_RESET_SERVER_V2)
        .expect("server should emit a hard reset");
    assert_eq!(server_reset.pid, Some(0));

    // Before the retransmit deadline: tick is quiet.
    let start = Instant::now();
    let early = server
        .tick(start + RETRANSMIT_INITIAL - Duration::from_millis(50))
        .expect("tick early");
    assert!(early.send.is_empty(), "no retransmit before the deadline");
    assert!(!early.close);

    // Past the deadline: the unacked hard reset is re-sent. Compare by
    // opcode/pid/payload (the on-wire ACK list may differ from the first send).
    let late = server
        .tick(start + RETRANSMIT_INITIAL + Duration::from_millis(50))
        .expect("tick late");
    assert!(!late.close, "should not be closing yet");
    let resent: Vec<ControlPacket> = late
        .send
        .iter()
        .map(|d| ControlPacket::parse(d).unwrap())
        .collect();
    assert!(
        resent.iter().any(|p| p.opcode == server_reset.opcode
            && p.pid == server_reset.pid
            && p.payload == server_reset.payload),
        "server should retransmit the unacked hard reset"
    );

    // The client now ACKs pid 0. A standalone ACK references the server's
    // session id as the remote id.
    let ack = ControlPacket::new(Opcode::ACK_V1, 0, *b"CLIENTID", server_reset.session_id);
    server.handle_packet(&ack.to_bytes(&[0])).expect("ack");

    // With pid 0 acknowledged, a tick well past any deadline is quiet.
    let quiet = server
        .tick(start + RETRANSMIT_INITIAL * 8)
        .expect("tick quiet");
    assert!(
        quiet.send.is_empty(),
        "no retransmit once the packet is acked, got {}",
        quiet.send.len()
    );
}

/// Garbage on the session's in-order TLS stream is fatal to the session and
/// says so through `close`, not through an `Err` (which means "dropped").
#[test]
fn tls_garbage_closes_the_session() {
    use super::packet_ctrl::ControlPacket;

    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    server.handle_packet(&client.hard_reset()).unwrap();

    let mut p = ControlPacket::new(Opcode::CONTROL_V1, 0, *b"CLIENTID", [0; 8]);
    p.set_pid(1);
    p.payload = vec![0x99, 0x03, 0x03, 0x00, 0x01, 0x00];
    let out = server.handle_packet(&p.to_bytes(&[])).unwrap();
    assert!(out.close, "TLS failure must end the session");
    assert!(out.error.is_some());
}

/// A client that restarts and reconnects from the same address starts a new
/// session (new session id). The server must run it from scratch alongside
/// the old one, rather than mixing it into the old session's reliable state,
/// and switch the data channel over once it is up.
#[test]
fn client_restart_from_same_address_gets_a_fresh_session() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut first = TestClient::new(*b"CLIENT-1");
    let k1 = connect(&mut server, &mut first);
    assert_eq!(deliver(&mut server, &k1, 1, b"one"), Some(b"one".to_vec()));

    let mut second = TestClient::new(*b"CLIENT-2");
    let k2 = connect(&mut server, &mut second);
    assert_ne!(
        second.reliable.peer_id, first.reliable.peer_id,
        "a new session gets a new server session id"
    );
    assert_eq!(deliver(&mut server, &k2, 1, b"two"), Some(b"two".to_vec()));
    // The old session is gone with the old client.
    assert_eq!(deliver(&mut server, &k1, 2, b"old"), None);
}

/// A hard reset carrying a new session id must not disturb an established
/// session until the new one has authenticated: without tls-auth, anyone can
/// send one.
#[test]
fn stray_hard_reset_does_not_disturb_the_active_session() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    let keys = connect(&mut server, &mut client);

    let mut spoofer = TestClient::new(*b"SPOOFER!");
    let out = server.handle_packet(&spoofer.hard_reset()).unwrap();
    assert!(!out.close);
    assert_eq!(
        deliver(&mut server, &keys, 1, b"still"),
        Some(b"still".to_vec())
    );
}

/// Without tls-auth anyone who knows a client's address can send a hard
/// reset from it. One arriving while the client's own handshake is under
/// way must not displace it: the new session waits in an untrusted slot
/// until it proves the sender got our answer.
#[test]
fn spoofed_hard_reset_does_not_kill_a_handshake_in_progress() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    let out = server.handle_packet(&client.hard_reset()).unwrap();
    let mut to_server = Vec::new();
    for d in out.send {
        to_server.extend(client.handle(&d));
    }
    client.pump_tls(&mut to_server);
    assert!(!to_server.is_empty());

    for sid in [*b"SPOOFER1", *b"SPOOFER2"] {
        let out = server
            .handle_packet(&TestClient::new(sid).hard_reset())
            .unwrap();
        assert!(!out.close);
    }
    // The genuine client carries on where it was, and gets through.
    let keys = connect_from(&mut server, &mut client, to_server);
    assert_eq!(deliver(&mut server, &keys, 1, b"hi"), Some(b"hi".to_vec()));
}

/// Control datagrams in `send` carrying TLS (P_CONTROL_V1).
fn tls_packets(send: &[Vec<u8>]) -> usize {
    send.iter()
        .filter(|d| ControlPacket::parse(d).is_ok_and(|p| p.opcode == Opcode::CONTROL_V1))
        .count()
}

/// Without tls-auth, anyone can send a hard reset and a ClientHello from a
/// client's address. Until the sender ACKs our reset -- which only whoever
/// receives at that address can -- the server must answer with no more
/// than the reset and ACKs, not its TLS flight (ssl.c only moves TLS
/// output to the reliable layer from S_START): else a few small spoofed
/// datagrams make it send kilobytes to the victim, and retransmit them.
#[test]
fn no_tls_flight_before_our_reset_is_acked() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook())
        .unwrap()
        .with_timers(quiet_timers());
    let mut client = TestClient::new(*b"CLIENTID");
    connect(&mut server, &mut client);

    let mut attacker = TestClient::new(*b"ATTACKER");
    let mut dgrams = vec![attacker.hard_reset()];
    // It never sees our reset, so it guesses our session id.
    attacker.reliable.peer_id = [0x55; 8];
    attacker.pump_tls(&mut dgrams);
    let sent_in: usize = dgrams.iter().map(Vec::len).sum();
    let mut sent_out = 0;
    for d in &dgrams {
        let out = server.handle_packet(d).unwrap();
        assert_eq!(tls_packets(&out.send), 0, "TLS before the reset was ACKed");
        sent_out += out.send.iter().map(Vec::len).sum::<usize>();
    }
    let start = Instant::now();
    for s in 1..=59 {
        // Only what the attacker's session sends: the genuine client's
        // (our first session id) may have something of its own in flight.
        let out: Vec<Vec<u8>> = server
            .tick(start + Duration::from_secs(s))
            .unwrap()
            .send
            .into_iter()
            .filter(|d| ControlPacket::parse(d).is_ok_and(|p| p.session_id != *b"SERVERID"))
            .collect();
        assert_eq!(tls_packets(&out), 0, "TLS retransmitted at {s}s");
        sent_out += out.iter().map(Vec::len).sum::<usize>();
    }
    // The reset and its retransmissions: small datagrams, few of them.
    assert!(
        sent_out < 4 * sent_in,
        "{sent_out} bytes out for {sent_in} in"
    );
}

/// The same holds for a renegotiation: the new key's TLS flight waits for
/// the ACK of our soft reset, then goes out.
#[test]
fn soft_reset_key_sends_tls_only_after_our_reset_is_acked() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook())
        .unwrap()
        .with_timers(quiet_timers());
    let mut client = TestClient::new(*b"CLIENTID");
    connect(&mut server, &mut client);

    let mut dgrams = vec![client.renegotiate(1)];
    client.pump_tls(&mut dgrams);
    let mut replies = Vec::new();
    for d in &dgrams {
        replies.extend(server.handle_packet(d).unwrap().send);
    }
    assert_eq!(tls_packets(&replies), 0, "TLS before the reset was ACKed");
    let reset = replies
        .iter()
        .map(|d| ControlPacket::parse(d).unwrap())
        .find(|p| p.opcode == Opcode::CONTROL_SOFT_RESET_V1)
        .expect("our soft reset");
    let ack = ControlPacket::new(Opcode::ACK_V1, 1, *b"CLIENTID", reset.session_id);
    let out = server.handle_packet(&ack.to_bytes(&[0])).unwrap();
    assert!(tls_packets(&out.send) > 0, "the ACK releases the flight");
}

/// A new session that does prove the client got our answer -- the ACK of
/// our hard reset -- takes over from one still negotiating: the client
/// restarted and gave up on the old one.
#[test]
fn a_reachable_new_session_replaces_a_negotiating_one() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut stale = TestClient::new(*b"CLIENT-1");
    server.handle_packet(&stale.hard_reset()).unwrap();
    let mut client = TestClient::new(*b"CLIENT-2");
    let keys = connect(&mut server, &mut client);
    assert_eq!(deliver(&mut server, &keys, 1, b"hi"), Some(b"hi".to_vec()));
    let mut again = ControlPacket::new(Opcode::CONTROL_V1, 0, *b"CLIENT-1", [0; 8]);
    again.set_pid(1);
    assert!(
        server.handle_packet(&again.to_bytes(&[])).is_err(),
        "the abandoned session is gone"
    );
}

/// Only the session carrying the data channel says the client is alive:
/// hard resets anyone can send from its address must not hold off
/// ping-restart.
#[test]
fn packets_for_other_sessions_do_not_count_as_hearing_from_the_client() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    connect(&mut server, &mut client);
    let t0 = Instant::now();
    for (i, s) in [100u64, 110, 120].into_iter().enumerate() {
        let sid = [b'0' + i as u8; 8];
        let reset = TestClient::new(sid).hard_reset();
        server
            .handle_packet_at(&reset, t0 + Duration::from_secs(s))
            .unwrap();
    }
    let out = server.tick(t0 + Duration::from_secs(125)).unwrap();
    assert!(out.close, "ping-restart should have fired");
}

/// Every control packet, headers and ACKs included, makes a datagram
/// within OpenVPN 2.6's default tls-mtu of 1250 bytes, IPv6 and UDP headers
/// counted: a full 1500-byte one is fragmented, or dropped, on many paths,
/// and the handshake then never completes.
#[test]
fn control_packets_fit_the_tls_mtu() {
    // A chain of a few certificates, so the server's first flight takes
    // several packets.
    let chain = vec![der(TEST_CERT, "CERTIFICATE"); 4];
    let key =
        purecrypto::rsa::BoxedRsaPrivateKey::from_pkcs8_der(&der(TEST_KEY, "PRIVATE KEY")).unwrap();
    let config = Arc::new(
        TlsConfig::builder()
            .versions(TLS12_ONLY.0, TLS12_ONLY.1)
            .rng(Arc::new(purecrypto::rng::OsRng))
            .identity(chain, purecrypto::tls::SigningKey::Rsa(key))
            .build(),
    );
    let mut server = Peer::new(config, *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    let mut to_server = vec![client.hard_reset()];
    let mut largest = 0;
    let mut sent = 0;
    for _ in 0..50 {
        let mut next = Vec::new();
        for d in to_server.drain(..) {
            for s in server.handle_packet(&d).unwrap().send {
                largest = largest.max(s.len());
                sent += 1;
                next.extend(client.handle(&s));
            }
        }
        client.pump_tls(&mut next);
        if client.handshake_done() && next.is_empty() {
            break;
        }
        to_server = next;
    }
    assert!(client.handshake_done());
    assert!(sent > 2);
    assert!(largest + 40 + 8 <= 1250, "{largest}-byte control packet");
}

/// A retransmitted hard reset is a duplicate of the session's packet 0: it is
/// ACKed again, not answered with another server reset.
#[test]
fn repeated_hard_reset_is_only_acked() {
    use super::packet_ctrl::ControlPacket;

    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    let reset = client.hard_reset();
    server.handle_packet(&reset).unwrap();
    let out = server.handle_packet(&reset).unwrap();
    let pkts: Vec<ControlPacket> = out
        .send
        .iter()
        .map(|d| ControlPacket::parse(d).unwrap())
        .collect();
    assert_eq!(pkts.len(), 1);
    assert_eq!(pkts[0].opcode, Opcode::ACK_V1);
    assert_eq!(pkts[0].acked_pids, vec![0]);
    assert_eq!(pkts[0].session_id, *b"SERVERID");
    assert_eq!(pkts[0].remote_id, *b"CLIENTID");
}

/// A hard reset opening a new session is validated before the session
/// takes the negotiating slot (ssl.c tls_pre_decrypt): one the new session
/// would refuse -- here, with an ACK record for a session it cannot know --
/// must not displace a legitimate handshake in progress.
#[test]
fn invalid_hard_reset_does_not_displace_a_negotiating_session() {
    use super::packet_ctrl::ControlPacket;

    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    let reset = client.hard_reset();
    server.handle_packet(&reset).unwrap();

    let mut bogus = ControlPacket::new(
        Opcode::CONTROL_HARD_RESET_CLIENT_V2,
        0,
        *b"SPOOFER!",
        *b"GUESSED!",
    );
    bogus.set_pid(0);
    assert!(server.handle_packet(&bogus.to_bytes(&[0])).is_err());

    // The client's retransmitted reset still reaches its own session.
    let out = server.handle_packet(&reset).unwrap();
    let pkts: Vec<ControlPacket> = out
        .send
        .iter()
        .map(|d| ControlPacket::parse(d).unwrap())
        .collect();
    assert_eq!(pkts.len(), 1);
    assert_eq!(pkts[0].opcode, Opcode::ACK_V1);
    assert_eq!(pkts[0].session_id, *b"SERVERID");
}

/// Control packets are routed by the sender's session id: one that matches
/// no session (and is not a hard reset starting one) is dropped unread.
#[test]
fn control_packet_from_unknown_session_is_dropped() {
    use super::packet_ctrl::ControlPacket;

    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    server.handle_packet(&client.hard_reset()).unwrap();

    // Garbage TLS would be fatal to the session it belongs to; it belongs to
    // none, so nothing happens.
    let mut p = ControlPacket::new(Opcode::CONTROL_V1, 0, *b"STRANGER", [0; 8]);
    p.set_pid(1);
    p.payload = vec![0x99, 0x03, 0x03, 0x00, 0x01, 0x00];
    assert!(server.handle_packet(&p.to_bytes(&[])).is_err());
}

/// An ACK names the session it acknowledges. One naming another session must
/// not release our unacknowledged packets, or a forged ACK could stop our
/// retransmissions.
#[test]
fn ack_for_another_session_is_ignored() {
    use super::packet_ctrl::ControlPacket;
    use super::reliable::RETRANSMIT_INITIAL;
    use crate::time::Instant;
    use std::time::Duration;

    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    let start = Instant::now();
    server.handle_packet(&client.hard_reset()).unwrap();

    let forged = ControlPacket::new(Opcode::ACK_V1, 0, *b"CLIENTID", *b"NOTUS!!!");
    let _ = server.handle_packet(&forged.to_bytes(&[0]));

    let late = server
        .tick(start + RETRANSMIT_INITIAL + Duration::from_millis(50))
        .unwrap();
    assert_eq!(
        late.send.len(),
        1,
        "server reset must still be retransmitted"
    );
}

/// A session that has not finished its key exchange within the handshake
/// window (OpenVPN's `hand-window`, 60s) is abandoned.
#[test]
fn handshake_window_expires_a_stalled_session() {
    use crate::time::Instant;
    use std::time::Duration;

    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    let start = Instant::now();
    server.handle_packet(&client.hard_reset()).unwrap();
    let out = server.tick(start + Duration::from_secs(59)).unwrap();
    assert!(!out.close);
    let out = server.tick(start + Duration::from_secs(61)).unwrap();
    assert!(out.close, "handshake window should have expired");
}

/// An established peer that goes quiet is pinged every keepalive interval,
/// and dropped once nothing has been heard for twice the keepalive timeout
/// (OpenVPN's `--keepalive 10 60` on a server).
#[test]
fn keepalive_pings_and_restarts() {
    use crate::time::Instant;
    use std::time::Duration;

    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    let keys = connect(&mut server, &mut client);
    let start = Instant::now();

    let out = server.tick(start + Duration::from_secs(11)).unwrap();
    assert!(!out.close);
    let mut pings = out
        .send
        .into_iter()
        .filter(|d| Opcode::from_byte(d[0]).0 == Opcode::DATA_V1);
    let mut ping = pings.next().expect("a keepalive ping");
    let dec = data::decrypt(&gcm_opts(), &keys, &mut ping)
        .unwrap()
        .unwrap();
    assert!(dec.is_ping);

    // Hearing from the client keeps it alive...
    assert_eq!(deliver(&mut server, &keys, 1, b"hi"), Some(b"hi".to_vec()));
    let out = server.tick(start + Duration::from_secs(100)).unwrap();
    assert!(!out.close);
    // ...silence past the restart timeout ends it.
    let out = server.tick(start + Duration::from_secs(125)).unwrap();
    assert!(out.close, "ping-restart should have fired");
}

/// A rejected client is told so -- OpenVPN sends `AUTH_FAILED` and closes the
/// session a few seconds later -- and meanwhile nothing more it sends on that
/// session is processed: in particular, not another round of credentials.
#[test]
fn auth_failure_sends_auth_failed_and_stops() {
    use crate::time::Instant;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    let calls = Arc::new(AtomicUsize::new(0));
    let hook: OnAuth = {
        let calls = calls.clone();
        Arc::new(move |_: &AuthInfo| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "bad password",
            ))
        })
    };
    let mut server = Peer::new(server_config(), *b"SERVERID", hook).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    assert!(drive_handshake(&mut server, &mut client));
    send_client_key_material(&mut client);
    assert!(!pump(&mut server, &mut client), "closed before AUTH_FAILED");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let text = client.control_text();
    assert!(
        text.windows(12).any(|w| w == b"AUTH_FAILED\0"),
        "client was not told"
    );

    // A second try on the same session is ignored.
    send_client_key_material(&mut client);
    assert!(!pump(&mut server, &mut client));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let out = server
        .tick(Instant::now() + Duration::from_secs(6))
        .unwrap();
    assert!(out.close, "session should end after AUTH_FAILED");
    assert!(server.peer_config().is_none());
}

/// With deferred authentication the peer never calls on_auth: it hands the
/// credentials out and holds the key exchange (and whatever the client says
/// meanwhile) until complete_auth brings the verdict.
#[test]
fn deferred_auth_waits_for_the_verdict() {
    let hook: OnAuth = Arc::new(|_: &AuthInfo| panic!("on_auth called inline"));
    let mut server = Peer::new(server_config(), *b"SERVERID", hook)
        .unwrap()
        .deferred_auth();
    let mut client = TestClient::new(*b"CLIENTID");
    assert!(drive_handshake(&mut server, &mut client));
    send_client_key_material(&mut client);
    client.tls.send(b"PUSH_REQUEST\0").unwrap();

    let mut to_server = Vec::new();
    client.pump_tls(&mut to_server);
    let reqs = exchange_deferred(&mut server, &mut client, to_server);
    assert_eq!(reqs.len(), 1, "one request per key exchange");
    let req = reqs.into_iter().next().unwrap();
    assert!(server.peer_config().is_none(), "not authenticated yet");
    assert!(
        !client
            .control_text()
            .windows(10)
            .any(|w| w == b"PUSH_REPLY"),
        "PUSH_REQUEST answered before the verdict"
    );

    let out = server.complete_auth(&req, auth_hook()(&req.info));
    assert!(out.connected.is_some());
    assert!(server.peer_config().is_some());
    let mut to_server = Vec::new();
    for dg in out.send {
        to_server.extend(client.handle(&dg));
    }
    assert!(exchange_deferred(&mut server, &mut client, to_server).is_empty());
    assert!(
        client
            .control_text()
            .windows(10)
            .any(|w| w == b"PUSH_REPLY"),
        "the waiting PUSH_REQUEST is answered"
    );

    // A verdict for a key exchange no longer waiting does nothing.
    let again = server.complete_auth(&req, Err(std::io::Error::other("late")));
    assert!(again.send.is_empty() && !again.close && again.connected.is_none());
    assert!(server.peer_config().is_some());
}

/// Exchange datagrams between a deferred-auth `server` and `client`,
/// starting from `to_server`, until quiet; returns the auth requests the
/// server handed out.
fn exchange_deferred(
    server: &mut Peer,
    client: &mut TestClient,
    mut to_server: Vec<Vec<u8>>,
) -> Vec<super::peer::AuthRequest> {
    let mut reqs = Vec::new();
    for _ in 0..30 {
        let mut to_client = Vec::new();
        for dg in to_server.drain(..) {
            let out = server.handle_packet(&dg).unwrap();
            assert!(out.connected.is_none(), "connected without a verdict");
            reqs.extend(out.auth);
            to_client.extend(out.send);
        }
        for dg in to_client {
            to_server.extend(client.handle(&dg));
        }
        if to_server.is_empty() {
            break;
        }
    }
    reqs
}

/// A client without auth-user-pass sends its username and password as
/// OpenVPN's write_empty_string does -- a zero length, not even a NUL -- and
/// may send no peer info the same way. That is a valid key exchange.
#[test]
fn empty_strings_in_key_exchange_are_accepted() {
    use std::sync::Mutex;

    let seen = Arc::new(Mutex::new(None));
    let hook: OnAuth = {
        let seen = seen.clone();
        Arc::new(move |info: &AuthInfo| {
            *seen.lock().unwrap() = Some(info.clone());
            auth_hook()(info)
        })
    };
    let mut server = Peer::new(server_config(), *b"SERVERID", hook).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    client.kx.username = None;
    client.kx.password = None;
    client.kx.peer_info = None;
    let keys = connect(&mut server, &mut client);
    assert_eq!(
        deliver(&mut server, &keys, 1, b"hello"),
        Some(b"hello".to_vec())
    );
    let info = seen.lock().unwrap().clone().expect("on_auth called");
    assert_eq!(info.username, "");
    assert_eq!(info.password, "");
    assert!(info.peer_info.is_empty());
}

/// OpenVPN only warns when the client's options string differs from what
/// it expects (ssl.c key_method_2_read -> options_warning). Real clients'
/// strings rarely match ours byte for byte -- this one is what a 2.6 client
/// with `cipher AES-256-GCM` and no compression sends -- and must still be
/// served. The server pushes `comp-lzo no`, so the client frames its packets
/// with the no-compression byte all the same.
#[test]
fn real_client_options_string_is_accepted() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    client.kx.options = "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto UDPv4,\
                         cipher AES-256-GCM,auth [null-digest],keysize 256,\
                         key-method 2,tls-client"
        .into();
    let keys = connect(&mut server, &mut client);
    assert_eq!(
        deliver(&mut server, &keys, 1, b"hello"),
        Some(b"hello".to_vec())
    );
}

/// A client asking for a data channel without encryption, or CBC without
/// an HMAC, is refused: the server will not run an unauthenticated tunnel.
/// Like any client left without a data cipher, it is told AUTH_FAILED.
#[test]
fn insecure_data_channel_is_refused() {
    for opts in [
        "V4,dev-type tun,cipher AES-256-CBC,auth [null-digest],keysize 256,key-method 2,tls-client",
        "V4,dev-type tun,cipher [null-cipher],auth SHA256,keysize 128,key-method 2,tls-client",
    ] {
        let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
        let mut client = TestClient::new(*b"CLIENTID");
        client.kx.options = opts.into();
        assert!(drive_handshake(&mut server, &mut client));
        send_client_key_material(&mut client);
        pump(&mut server, &mut client);
        assert!(server.peer_config().is_none(), "{opts}: must be refused");
        assert!(
            client
                .control_text()
                .windows(12)
                .any(|w| w == b"AUTH_FAILED\0"),
            "{opts}: client was not told"
        );
    }
}

/// A negotiating client's options string may name a cipher we lack --
/// a 2.4 client's default `cipher BF-CBC`, say. Negotiation overrides it,
/// so it is no reason to refuse the client.
#[test]
fn negotiating_client_may_name_an_unsupported_cipher() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    client.kx.options = "V4,dev-type tun,link-mtu 1542,tun-mtu 1500,proto UDPv4,\
                         cipher BF-CBC,auth SHA1,keysize 128,key-method 2,tls-client"
        .into();
    client.kx.peer_info = Some("IV_VER=2.4.12\nIV_NCP=2\n".into());
    let keys = connect(&mut server, &mut client);
    assert_eq!(
        deliver(&mut server, &keys, 1, b"hello"),
        Some(b"hello".to_vec())
    );
}

/// A client that does not negotiate (no IV_NCP=2, no IV_CIPHERS) uses the
/// cipher its options string names. One that names none runs OpenVPN's
/// historical default, BF-CBC, which is not implemented here; so is a named
/// BF-CBC. Guessing another cipher would leave both ends unable to decrypt
/// each other, so the client is refused the way OpenVPN refuses a failed
/// cipher negotiation: AUTH_FAILED, and the session ends shortly after.
#[test]
fn client_without_a_usable_cipher_is_refused() {
    use crate::time::Instant;
    use std::time::Duration;

    for opts in [
        "V4,dev-type tun,link-mtu 1542,tun-mtu 1500,proto UDPv4,auth SHA1,keysize 128,\
         key-method 2,tls-client",
        "V4,dev-type tun,link-mtu 1542,tun-mtu 1500,proto UDPv4,cipher BF-CBC,auth SHA1,\
         keysize 128,key-method 2,tls-client",
    ] {
        let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
        let mut client = TestClient::new(*b"CLIENTID");
        client.kx.options = opts.into();
        client.kx.peer_info = Some("IV_VER=2.3.18\nIV_PLAT=linux\n".into());
        assert!(drive_handshake(&mut server, &mut client));
        send_client_key_material(&mut client);
        pump(&mut server, &mut client);
        assert!(server.peer_config().is_none(), "{opts}: must be refused");
        assert!(
            client
                .control_text()
                .windows(12)
                .any(|w| w == b"AUTH_FAILED\0"),
            "{opts}: client was not told"
        );
        let out = server
            .tick(Instant::now() + Duration::from_secs(6))
            .unwrap();
        assert!(out.close, "{opts}: session should end after AUTH_FAILED");
        let why = out.error.expect("reason").to_string();
        assert!(why.contains("cipher"), "{opts}: unclear reason {why:?}");
    }
}

/// A 2.5+ client announces its data ciphers in IV_CIPHERS and leaves the
/// choice to the server (NCP): its options string names no cipher at all.
/// The server picks from its own list in preference order and pushes it
/// (ssl_ncp.c ncp_get_best_cipher).
#[test]
fn cipher_is_negotiated_from_iv_ciphers() {
    for (iv_ciphers, want, opts) in [
        (
            "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
            "AES-256-GCM",
            gcm_opts(),
        ),
        (
            "CHACHA20-POLY1305:AES-128-GCM",
            "AES-128-GCM",
            Options {
                cipher_size: 128,
                ..gcm_opts()
            },
        ),
    ] {
        let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
        let mut client = TestClient::new(*b"CLIENTID");
        client.kx.options = "V4,dev-type tun,link-mtu 1521,tun-mtu 1500,proto UDPv4,\
                             auth SHA1,keysize 128,key-method 2,tls-client"
            .into();
        client.kx.peer_info = Some(format!("IV_VER=2.6.8\nIV_CIPHERS={iv_ciphers}\n"));
        let keys = connect(&mut server, &mut client);

        let pkt = data::encrypt(&opts, &keys, 0, 1, b"ncp", |b| {
            b.fill(0);
            Ok(())
        })
        .unwrap();
        let out = server.handle_packet(&pkt).unwrap();
        assert_eq!(out.deliver.as_deref(), Some(&b"ncp"[..]), "{want}");

        for d in client.send_control(b"PUSH_REQUEST\0") {
            for reply in server.handle_packet(&d).unwrap().send {
                client.handle(&reply);
            }
        }
        let text = String::from_utf8_lossy(client.control_text()).into_owned();
        assert!(text.contains(&format!(",cipher {want}")), "{text}");
    }
}

/// Key id of a data packet.
fn key_id_of(pkt: &[u8]) -> u8 {
    Opcode::from_byte(pkt[0]).1
}

/// Timers without keepalive, so ticks far in the future only exercise
/// renegotiation.
fn quiet_timers() -> PeerTimers {
    PeerTimers::default()
        .keepalive_interval(Duration::ZERO)
        .keepalive_timeout(Duration::ZERO)
}

/// A client renegotiates (reneg-sec on its side): the server runs a new TLS
/// handshake and key exchange on key id 1 alongside the working key 0,
/// accepts both keys during the transition, and moves its own sending to the
/// new key once the client has had time to install it.
#[test]
fn client_initiated_renegotiation() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook())
        .unwrap()
        .with_timers(quiet_timers());
    let mut client = TestClient::new(*b"CLIENTID");
    let k0 = connect(&mut server, &mut client);
    assert_eq!(deliver(&mut server, &k0, 1, b"k0"), Some(b"k0".to_vec()));

    let first = vec![client.renegotiate(1)];
    let k1 = connect_from(&mut server, &mut client, first);
    assert_eq!(
        deliver_on(&mut server, &k1, 1, 1, b"k1"),
        Some(b"k1".to_vec())
    );
    // The previous key still works during the transition window.
    assert_eq!(
        deliver_on(&mut server, &k0, 0, 2, b"old"),
        Some(b"old".to_vec())
    );

    let now = Instant::now();
    let early = server.send_data_at(b"x", now).unwrap();
    assert_eq!(
        key_id_of(&early),
        0,
        "new key used before the client has it"
    );
    let mut late = server
        .send_data_at(b"y", now + Duration::from_secs(61))
        .unwrap();
    assert_eq!(key_id_of(&late), 1);
    let d = data::decrypt(&gcm_opts(), &k1, &mut late).unwrap().unwrap();
    assert_eq!(d.payload, b"y");

    // After the transition window only the new key is accepted.
    let out = server.tick(now + Duration::from_secs(3601)).unwrap();
    assert!(!out.close);
    assert_eq!(deliver_on(&mut server, &k0, 0, 3, b"gone"), None);
    assert_eq!(
        deliver_on(&mut server, &k1, 1, 2, b"k1"),
        Some(b"k1".to_vec())
    );
}

/// The server renegotiates on its own once the key is reneg-sec old, with a
/// P_CONTROL_SOFT_RESET_V1 on the next key id; the client answers the way
/// OpenVPN does and a new key results.
#[test]
fn server_initiated_renegotiation() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook())
        .unwrap()
        .with_timers(quiet_timers().transition_window(Duration::from_secs(7200)));
    let mut client = TestClient::new(*b"CLIENTID");
    let k0 = connect(&mut server, &mut client);

    let out = server
        .tick(Instant::now() + Duration::from_secs(3601))
        .unwrap();
    let soft: Vec<ControlPacket> = out
        .send
        .iter()
        .map(|d| ControlPacket::parse(d).unwrap())
        .filter(|p| p.opcode == Opcode::CONTROL_SOFT_RESET_V1)
        .collect();
    assert_eq!(soft.len(), 1, "one soft reset");
    assert_eq!(soft[0].key_id, 1);
    assert_eq!(soft[0].pid, Some(0));

    let mut first = vec![client.renegotiate(1)];
    first.extend(client.handle(&soft[0].to_bytes(&[])));
    let k1 = connect_from(&mut server, &mut client, first);
    assert_eq!(
        deliver_on(&mut server, &k1, 1, 1, b"k1"),
        Some(b"k1".to_vec())
    );
    assert_eq!(
        deliver_on(&mut server, &k0, 0, 1, b"k0"),
        Some(b"k0".to_vec())
    );
}

/// A renegotiation the client never answers must not take the connection
/// down with it: the working key carries on until its transition window
/// ends (then the connection is over, as in OpenVPN).
#[test]
fn failed_renegotiation_falls_back_to_the_old_key() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook())
        .unwrap()
        .with_timers(quiet_timers());
    let mut client = TestClient::new(*b"CLIENTID");
    let k0 = connect(&mut server, &mut client);
    let start = Instant::now();

    let t_reneg = start + Duration::from_secs(3601);
    assert!(!server.tick(t_reneg).unwrap().close);
    let t_failed = t_reneg + Duration::from_secs(61);
    assert!(!server.tick(t_failed).unwrap().close);
    assert_eq!(
        deliver(&mut server, &k0, 1, b"still"),
        Some(b"still".to_vec())
    );
    let pkt = server.send_data_at(b"x", t_failed).unwrap();
    assert_eq!(key_id_of(&pkt), 0);
    // No automatic retry on a key we fell back to; it expires.
    let out = server.tick(t_reneg + Duration::from_secs(3601)).unwrap();
    assert!(out.close);
}

/// The client may start the next renegotiation itself after a failed one.
#[test]
fn client_may_renegotiate_after_a_failed_attempt() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook())
        .unwrap()
        .with_timers(quiet_timers());
    let mut client = TestClient::new(*b"CLIENTID");
    connect(&mut server, &mut client);
    let t_reneg = Instant::now() + Duration::from_secs(3601);
    server.tick(t_reneg).unwrap();
    server.tick(t_reneg + Duration::from_secs(61)).unwrap();

    // The server's attempt used key id 1; the client's next one is 2.
    let first = vec![client.renegotiate(2)];
    let k2 = connect_from(&mut server, &mut client, first);
    assert_eq!(
        deliver_on(&mut server, &k2, 2, 1, b"k2"),
        Some(b"k2".to_vec())
    );
}

/// After a renegotiation the previous key is a lame duck: its data keys
/// keep working, but its control channel is over, as in OpenVPN (ssl.c
/// services only the primary key's reliable layer, and tls_pre_decrypt
/// takes control packets for the primary key id alone). What it still had
/// in flight is not retransmitted to a client that has moved on, and a
/// control packet on its key id is dropped.
#[test]
fn nothing_is_retransmitted_on_the_old_key_after_renegotiation() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook())
        .unwrap()
        .with_timers(quiet_timers());
    let mut client = TestClient::new(*b"CLIENTID");
    let k0 = connect(&mut server, &mut client);
    // A reply on key 0 that the client never ACKs.
    let mut lost = Vec::new();
    for d in client.send_control(b"PUSH_REQUEST\0") {
        for s in server.handle_packet(&d).unwrap().send {
            let p = ControlPacket::parse(&s).unwrap();
            if p.opcode == Opcode::CONTROL_V1 {
                lost.push(p.pid.unwrap());
            }
        }
    }
    assert!(!lost.is_empty());
    let first = vec![client.renegotiate(1)];
    connect_from(&mut server, &mut client, first);

    let start = Instant::now();
    for s in 1..=120 {
        let out = server.tick(start + Duration::from_secs(s)).unwrap();
        let old = out
            .send
            .iter()
            .filter(|d| ControlPacket::parse(d).is_ok_and(|p| p.key_id == 0))
            .count();
        assert_eq!(old, 0, "retransmitted on the old key at {s}s");
    }

    let ack = ControlPacket::new(Opcode::ACK_V1, 0, *b"CLIENTID", *b"SERVERID");
    assert!(
        server.handle_packet(&ack.to_bytes(&lost)).is_err(),
        "control packet on the old key id taken"
    );
    // Its data keys still work.
    assert_eq!(
        deliver_on(&mut server, &k0, 0, 2, b"old"),
        Some(b"old".to_vec())
    );
}

/// The server's key-method-2 reply carries its own peer info, not the
/// client's echoed back: that would claim the client's version and
/// platform as the server's, and hand back whatever the client put there.
#[test]
fn server_does_not_echo_the_client_peer_info() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook()).unwrap();
    let mut client = TestClient::new(*b"CLIENTID");
    client.kx.peer_info = Some("IV_VER=2.6.8\nIV_PLAT=linux\nUV_SECRET=hunter2\n".into());
    connect(&mut server, &mut client);
    // [0:4][key method:1][random:64], then the options string, username,
    // password and peer info, each a u16 length and its bytes.
    let buf = client.control_text();
    let mut pos = 4 + 1 + 64;
    let mut strings = Vec::new();
    for _ in 0..4 {
        let len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        strings.push(buf[pos + 2..pos + 2 + len].to_vec());
        pos += 2 + len;
    }
    let peer_info = String::from_utf8_lossy(&strings[3]);
    assert!(!peer_info.contains("UV_SECRET"), "{peer_info:?}");
    assert!(!peer_info.contains("IV_PLAT=linux"), "{peer_info:?}");
}

/// Have the client ask for its config and lose the server's reply, leaving
/// a control packet on `server` that is never acknowledged.
fn lose_a_control_reply(server: &mut Peer, client: &mut TestClient) {
    for d in client.send_control(b"PUSH_REQUEST\0") {
        let out = server.handle_packet(&d).unwrap();
        assert!(!out.send.is_empty(), "server answers PUSH_REQUEST");
    }
}

/// Tick `server` once a second for `secs` seconds from `start`, returning
/// how many datagrams it retransmitted in the last minute.
fn tick_for(server: &mut Peer, start: Instant, secs: u64) -> usize {
    let mut late = 0;
    for s in 1..=secs {
        let out = server.tick(start + Duration::from_secs(s)).unwrap();
        assert!(!out.close, "closed at {s}s: {:?}", out.error);
        if s + 60 > secs {
            late += out.send.len();
        }
    }
    late
}

/// Once a key is negotiated, an unacknowledged control packet is retried
/// for as long as the session lives (reliable.c has no retry limit): only
/// ping-restart ends an established session, not a lost ACK.
#[test]
fn unacked_control_packet_does_not_end_an_established_session() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook())
        .unwrap()
        .with_timers(quiet_timers());
    let mut client = TestClient::new(*b"CLIENTID");
    let keys = connect(&mut server, &mut client);
    lose_a_control_reply(&mut server, &mut client);
    let resent = tick_for(&mut server, Instant::now(), 300);
    assert!(resent > 0, "still retransmitting");
    assert_eq!(
        deliver(&mut server, &keys, 1, b"alive"),
        Some(b"alive".to_vec())
    );
}

/// The same after a renegotiation: a lost ACK on the new key must not
/// throw it away and bring the previous key back, which the client has
/// moved on from.
#[test]
fn unacked_control_packet_does_not_undo_a_renegotiation() {
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook())
        .unwrap()
        .with_timers(quiet_timers());
    let mut client = TestClient::new(*b"CLIENTID");
    connect(&mut server, &mut client);
    let first = vec![client.renegotiate(1)];
    let k1 = connect_from(&mut server, &mut client, first);
    lose_a_control_reply(&mut server, &mut client);
    tick_for(&mut server, Instant::now(), 300);
    assert_eq!(
        deliver_on(&mut server, &k1, 1, 1, b"k1"),
        Some(b"k1".to_vec())
    );
}

/// A client that keeps asking for its config and never ACKs anything must
/// not make the server hold, and retransmit, a reply for each request:
/// OpenVPN answers one PUSH_REQUEST and ignores repeats for a while
/// (push.c sent_push_reply_expiry), and never has more than
/// TLS_RELIABLE_N_SEND_BUFFERS control packets in flight.
#[test]
fn push_request_flood_does_not_grow_the_send_queue() {
    use super::consts::TLS_RELIABLE_N_SEND_BUFFERS;

    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook())
        .unwrap()
        .with_timers(quiet_timers());
    let mut client = TestClient::new(*b"CLIENTID");
    let keys = connect(&mut server, &mut client);
    let mut replies = 0;
    for _ in 0..500 {
        for d in client.send_control(b"PUSH_REQUEST\0") {
            let out = server.handle_packet(&d).unwrap();
            assert!(!out.close);
            replies += out
                .send
                .iter()
                .filter(|d| ControlPacket::parse(d).is_ok_and(|p| p.opcode == Opcode::CONTROL_V1))
                .count();
        }
    }
    assert!(replies <= 1, "{replies} PUSH_REPLY packets");
    assert!(server.unacked_count() <= TLS_RELIABLE_N_SEND_BUFFERS);
    let out = server
        .tick(Instant::now() + Duration::from_secs(9))
        .unwrap();
    assert!(out.send.len() <= TLS_RELIABLE_N_SEND_BUFFERS);
    assert_eq!(
        deliver(&mut server, &keys, 1, b"alive"),
        Some(b"alive".to_vec())
    );
}

/// Timers are the caller's to set, and a huge one means "never", not a
/// panic on the first deadline computed from it.
#[test]
fn huge_timers_do_not_panic() {
    let timers = PeerTimers::default()
        .handshake_window(Duration::MAX)
        .keepalive_interval(Duration::MAX)
        .keepalive_timeout(Duration::MAX)
        .renegotiate_interval(Duration::MAX)
        .transition_window(Duration::MAX);
    let mut server = Peer::new(server_config(), *b"SERVERID", auth_hook())
        .unwrap()
        .with_timers(timers);
    let mut client = TestClient::new(*b"CLIENTID");
    let k0 = connect(&mut server, &mut client);
    let first = vec![client.renegotiate(1)];
    let k1 = connect_from(&mut server, &mut client, first);
    let later = Instant::now() + Duration::from_secs(365 * 24 * 3600);
    let out = server.tick(later).unwrap();
    assert!(!out.close, "{:?}", out.error);
    assert_eq!(
        deliver_on(&mut server, &k1, 1, 1, b"k1"),
        Some(b"k1".to_vec())
    );
    assert_eq!(
        deliver_on(&mut server, &k0, 0, 1, b"k0"),
        Some(b"k0".to_vec())
    );
}

// --- helpers ----------------------------------------------------------------

/// Exchange what `client` has queued with `server` until both go quiet;
/// returns whether the server asked to close.
fn pump(server: &mut Peer, client: &mut TestClient) -> bool {
    let mut server_inbox = Vec::new();
    client.pump_tls(&mut server_inbox);
    let mut client_inbox: Vec<Vec<u8>> = Vec::new();
    let mut closed = false;
    for _ in 0..30 {
        for dg in server_inbox.drain(..) {
            if let Ok(out) = server.handle_packet(&dg) {
                closed |= out.close;
                client_inbox.extend(out.send);
            }
        }
        for dg in client_inbox.drain(..) {
            server_inbox.extend(client.handle(&dg));
        }
        if server_inbox.is_empty() {
            break;
        }
    }
    closed
}

/// Drive a client through hard reset, TLS handshake and key exchange against
/// `server`, returning the keys the client encrypts with.
fn connect(server: &mut Peer, client: &mut TestClient) -> PeerKeys {
    let first = vec![client.hard_reset()];
    connect_from(server, client, first)
}

/// [`connect`] starting from the given client datagrams (a soft reset, say).
fn connect_from(server: &mut Peer, client: &mut TestClient, first: Vec<Vec<u8>>) -> PeerKeys {
    assert!(drive_from(server, client, first), "TLS handshake");
    let (pre_master, random1, random2) = send_client_key_material(client);
    let mut server_inbox = Vec::new();
    client.pump_tls(&mut server_inbox);
    let mut client_inbox: Vec<Vec<u8>> = Vec::new();
    for _ in 0..30 {
        for dg in server_inbox.drain(..) {
            let out = server.handle_packet(&dg).expect("server handle kx");
            assert!(!out.close, "server closed: {:?}", out.error);
            client_inbox.extend(out.send);
        }
        for dg in client_inbox.drain(..) {
            server_inbox.extend(client.handle(&dg));
        }
        if client.ctrl_buf.len() >= 69 && server_inbox.is_empty() {
            break;
        }
    }
    let server_random = read_server_key_reply(client);
    derive_client_keys(
        &pre_master,
        &random1,
        &random2,
        &server_random,
        client.reliable.local_id,
        client.reliable.peer_id,
    )
    .encrypt_side
}

pub(super) fn gcm_opts() -> Options {
    Options {
        cipher_crypto: CipherCryptoAlg::Aes,
        cipher_size: 256,
        cipher_block: CipherBlockMethod::Gcm,
        auth: super::options::AuthHash::None,
        compression: "lzo".into(),
        ..Default::default()
    }
}

/// Encrypt `payload` as the client and return what the server delivers.
fn deliver(server: &mut Peer, keys: &PeerKeys, pid: u32, payload: &[u8]) -> Option<Vec<u8>> {
    deliver_on(server, keys, 0, pid, payload)
}

/// [`deliver`] under the given key id.
fn deliver_on(
    server: &mut Peer,
    keys: &PeerKeys,
    key_id: u8,
    pid: u32,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let pkt = data::encrypt(&gcm_opts(), keys, key_id, pid, payload, |b| {
        b.fill(0);
        Ok(())
    })
    .unwrap();
    server.handle_packet(&pkt).ok()?.deliver
}

fn auth_hook() -> OnAuth {
    Arc::new(|_info: &AuthInfo| {
        Ok(PeerConfig {
            ip: "10.8.0.2".parse().unwrap(),
            gateway: "10.8.0.1".parse().unwrap(),
            mask: "255.255.255.0".parse().unwrap(),
            prefix_len: 24,
        })
    })
}

/// Write the client's key-method-2 blob and return its secret material.
pub(super) fn send_client_key_material(client: &mut TestClient) -> ([u8; 48], [u8; 32], [u8; 32]) {
    let mut pre_master = [0u8; 48];
    let mut random1 = [0u8; 32];
    let mut random2 = [0u8; 32];
    for (i, b) in pre_master.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(5).wrapping_add(1);
    }
    for (i, b) in random1.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(3).wrapping_add(7);
    }
    for (i, b) in random2.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11).wrapping_add(2);
    }

    let mut blob = Vec::new();
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.push(2u8); // key_method
    blob.extend_from_slice(&pre_master);
    blob.extend_from_slice(&random1);
    blob.extend_from_slice(&random2);

    let kx = &client.kx;
    write_ctrl_string(&mut blob, &kx.options);
    for s in [&kx.username, &kx.password, &kx.peer_info] {
        match s {
            Some(s) => write_ctrl_string(&mut blob, s),
            None => blob.extend_from_slice(&0u16.to_be_bytes()),
        }
    }

    client.tls.send(&blob).unwrap();
    (pre_master, random1, random2)
}

fn read_server_key_reply(client: &mut TestClient) -> [u8; 64] {
    // The server reply is in client.ctrl_buf: [0:4][2][r1:32][r2:32][strings..].
    let buf = &client.ctrl_buf;
    assert!(
        buf.len() >= 4 + 1 + 64,
        "server reply too short: {}",
        buf.len()
    );
    assert_eq!(&buf[0..4], &[0, 0, 0, 0]);
    assert_eq!(buf[4], 2);
    let mut sr = [0u8; 64];
    sr.copy_from_slice(&buf[5..69]);
    sr
}

struct ClientKeys {
    // From the client's perspective, "encrypt_side" are the keys the client
    // uses to encrypt toward the server (= the server's decrypt keys).
    encrypt_side: PeerKeys,
}

fn derive_client_keys(
    pre_master: &[u8; 48],
    random1: &[u8; 32],
    random2: &[u8; 32],
    server_random: &[u8; 64],
    client_id: [u8; 8],
    server_id: [u8; 8],
) -> ClientKeys {
    let (sr1, sr2) = server_random.split_at(32);

    let mut master = [0u8; 48];
    let mut seed = Vec::new();
    seed.extend_from_slice(random1);
    seed.extend_from_slice(sr1);
    prf10(&mut master, pre_master, b"OpenVPN master secret", &seed);

    // The server's expansion seed is r2 || sr2 || peer_id || local_id, where
    // (from the server's view) peer_id = client_id and local_id = server_id.
    let mut expansion = [0u8; 256];
    let mut seed2 = Vec::new();
    seed2.extend_from_slice(random2);
    seed2.extend_from_slice(sr2);
    seed2.extend_from_slice(&client_id);
    seed2.extend_from_slice(&server_id);
    prf10(&mut expansion, &master, b"OpenVPN key expansion", &seed2);

    // The server splits the expansion with from_expansion (server layout). For
    // the client to *encrypt* toward the server, it must use the bytes the
    // server treats as its *decrypt* keys: cipher_decrypt/hmac_decrypt =
    // expansion[0..64]/[64..128]. We construct a PeerKeys whose encrypt halves
    // are exactly those, so data::encrypt uses the right material.
    let mut k = PeerKeys::from_expansion(&expansion);
    // from_expansion put expansion[0..64] into cipher_decrypt. Swap so the
    // encrypt side carries the server's decrypt material.
    std::mem::swap(&mut k.cipher_encrypt, &mut k.cipher_decrypt);
    std::mem::swap(&mut k.hmac_encrypt, &mut k.hmac_decrypt);
    ClientKeys { encrypt_side: k }
}

fn write_ctrl_string(buf: &mut Vec<u8>, s: &str) {
    let len = s.len() + 1;
    buf.extend_from_slice(&(len as u16).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}
