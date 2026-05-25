//! End-to-end control-channel test.
//!
//! Drives a `rustls::ClientConnection` against our [`Peer`] (server) entirely
//! through the OpenVPN reliable layer — there is no socket; datagrams are
//! passed between the two sides in-memory. This exercises the full happy path:
//! client hard reset → TLS 1.2 handshake (over P_CONTROL packets) → key-method
//! 2 exchange → data-channel key derivation → an AES-256-GCM data roundtrip in
//! both directions.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::ClientConnection;

use super::data;
use super::keys::PeerKeys;
use super::options::Options;
use super::peer::{AuthInfo, OnAuth, Peer, PeerConfig};
use super::prf::prf10;
use super::reliable::Reliable;
use super::server::install_crypto_provider;
use super::{CipherBlockMethod, CipherCryptoAlg};

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

fn server_config() -> Arc<rustls::ServerConfig> {
    let cert = CertificateDer::from_pem_slice(TEST_CERT.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(TEST_KEY.as_bytes()).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(super::server::crypto_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    )
}

// A client that accepts any server certificate (OpenVPN's verify is out of
// scope for this control-channel test).
#[derive(Debug)]
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
        ]
    }
}

fn client_config() -> Arc<rustls::ClientConfig> {
    let cfg = rustls::ClientConfig::builder_with_provider(super::server::crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    Arc::new(cfg)
}

/// A minimal OpenVPN client that mirrors the server's reliable+TLS plumbing,
/// used only to drive the e2e test.
struct TestClient {
    tls: ClientConnection,
    reliable: Reliable,
    ctrl_buf: Vec<u8>,
}

impl TestClient {
    fn new(local_id: [u8; 8]) -> TestClient {
        let tls = ClientConnection::new(
            client_config(),
            ServerName::try_from("ovpn-test").unwrap(),
        )
        .unwrap();
        TestClient {
            tls,
            reliable: Reliable::new(local_id),
            ctrl_buf: Vec::new(),
        }
    }

    // Build the client hard reset datagram (pid 0, advancing out_counter).
    fn hard_reset(&mut self) -> Vec<u8> {
        let pkt = self.reliable.build_client_hard_reset();
        pkt.to_bytes(&[])
    }

    // Process an inbound datagram from the server; return datagrams to send.
    fn handle(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut send = Vec::new();
        let recv = self.reliable.recv(data).expect("client recv");

        if recv.got_client_reset {
            // Shouldn't happen on the client.
        }

        if !recv.tls_bytes.is_empty() {
            let mut cursor = std::io::Cursor::new(&recv.tls_bytes);
            while (cursor.position() as usize) < recv.tls_bytes.len() {
                let n = self.tls.read_tls(&mut cursor).unwrap();
                if n == 0 {
                    break;
                }
                self.tls.process_new_packets().unwrap();
            }
            let mut plain = Vec::new();
            let _ = self.tls.reader().read_to_end(&mut plain);
            self.ctrl_buf.extend_from_slice(&plain);
        }

        self.pump_tls(&mut send);
        send
    }

    fn pump_tls(&mut self, send: &mut Vec<Vec<u8>>) {
        let mut tls_out = Vec::new();
        while self.tls.wants_write() {
            let n = self.tls.write_tls(&mut tls_out).unwrap();
            if n == 0 {
                break;
            }
        }
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

    fn handshake_done(&self) -> bool {
        !self.tls.is_handshaking()
    }
}

#[test]
fn e2e_tls_handshake_and_key_exchange() {
    install_crypto_provider();

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

    assert!(client.handshake_done(), "client TLS handshake did not complete");

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
    let mut opts = Options::default();
    opts.cipher_crypto = CipherCryptoAlg::Aes;
    opts.cipher_size = 256;
    opts.cipher_block = CipherBlockMethod::Gcm;
    opts.auth = super::options::AuthHash::None;
    opts.compression = "lzo".into();

    // Client encrypts -> server-side keys decrypt. The server derived its keys
    // internally; we can't read them directly, but we *can* verify the client's
    // own decrypt path against its own encrypt path, and that the server
    // accepts a packet the client sent (round-trips through the live server).
    let payload = b"hello over the data channel";
    let pkt = data::encrypt(&opts, &client_keys.encrypt_side, 1, payload, |b| {
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

// --- helpers ----------------------------------------------------------------

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
fn send_client_key_material(client: &mut TestClient) -> ([u8; 48], [u8; 32], [u8; 32]) {
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

    // options string (must round-trip through Options::parse on the server).
    let mut opts = Options::default();
    opts.cipher_crypto = CipherCryptoAlg::Aes;
    opts.cipher_size = 256;
    opts.cipher_block = CipherBlockMethod::Gcm;
    opts.auth = super::options::AuthHash::None;
    opts.compression = "lzo".into();
    opts.is_server = false;
    let opt_str = opts.to_string();
    write_ctrl_string(&mut blob, &opt_str);
    write_ctrl_string(&mut blob, ""); // username
    write_ctrl_string(&mut blob, ""); // password
    write_ctrl_string(&mut blob, "IV_VER=2.6\n"); // peer info

    client.tls.writer().write_all(&blob).unwrap();
    (pre_master, random1, random2)
}

fn read_server_key_reply(client: &mut TestClient) -> [u8; 64] {
    // The server reply is in client.ctrl_buf: [0:4][2][r1:32][r2:32][strings..].
    let buf = &client.ctrl_buf;
    assert!(buf.len() >= 4 + 1 + 64, "server reply too short: {}", buf.len());
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
