//! Data-channel encryption/decryption.
//!
//! Two cipher families are supported, both keyed from [`PeerKeys`]:
//!
//! - **AES-GCM** (AEAD). Wire format: `[opcode:1][pid:4][tag:16][ciphertext..]`.
//!   The nonce is `pid(4) || implicit_iv(8)` where the implicit IV is taken
//!   from the per-direction HMAC key. The 4-byte packet ID is the AAD. This is
//!   the modern happy path and is fully implemented.
//! - **AES-CBC + HMAC** (encrypt-then-MAC: the HMAC covers IV and ciphertext).
//!   Wire format: `[opcode:1][hmac:N][iv:16][ct..]` where the ciphertext
//!   encrypts `[pid:4][compression:1][payload..]` PKCS#7-padded -- OpenVPN
//!   frames for compression first and then prepends the packet id.
//!
//! Decryption returns the inner payload with the leading compression byte
//! consumed (only the `0xfa` "no compression" marker is accepted; LZO/LZ4 are
//! rejected). Ported from the data paths in the Go `peer.go`.

use std::io;

use purecrypto::cipher::{Aes128, Aes128Gcm, Aes256, Aes256Gcm, Cbc};
use purecrypto::hash::{Hmac, Mac, Sha1, Sha224, Sha256};

use super::consts::OPENVPN_PING;
use super::keys::PeerKeys;
use super::options::{AuthHash, Options};
use super::pkcs5;
use super::{CipherBlockMethod, CipherCryptoAlg, Opcode};

/// No-compression marker OpenVPN prepends to the plaintext when compression is
/// framed but disabled.
const COMP_NONE: u8 = 0xfa;
const COMP_LZO: u8 = 0x66;
const COMP_LZ4: u8 = 0x69;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Result of a successful decrypt: the validated packet ID and the decoded
/// payload (compression byte already stripped). `payload` is empty for a ping.
pub struct Decrypted<'a> {
    pub pid: u32,
    pub payload: &'a [u8],
    pub is_ping: bool,
}

#[inline]
fn cipher_key_bytes(opts: &Options) -> usize {
    (opts.cipher_size / 8) as usize
}

/// Encrypt `payload` into a full data packet (including the opcode byte), using
/// the per-peer keys, options, and a monotonically increasing packet ID.
///
/// `rng` fills the CBC IV with cryptographic randomness; ignored for GCM.
pub fn encrypt(
    opts: &Options,
    keys: &PeerKeys,
    key_id: u8,
    pid: u32,
    payload: &[u8],
    rng: impl FnOnce(&mut [u8]) -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    check_supported(opts)?;
    if opts.cipher_block == CipherBlockMethod::Gcm {
        return encrypt_gcm(opts, keys, key_id, pid, payload);
    }
    encrypt_cbc(opts, keys, key_id, pid, payload, rng)
}

/// Refuse a data channel this implementation will not run: anything but
/// AES, and AES-CBC without an HMAC. OpenVPN would allow both (`cipher
/// none`, `auth none`) with a warning; here they would mean an unencrypted
/// or unauthenticated tunnel, so they are a policy error.
pub(crate) fn check_supported(opts: &Options) -> io::Result<()> {
    if opts.cipher_crypto != CipherCryptoAlg::Aes {
        return Err(invalid("refusing an unencrypted data channel"));
    }
    match opts.cipher_block {
        CipherBlockMethod::Gcm => Ok(()),
        CipherBlockMethod::Cbc if opts.auth != AuthHash::None => Ok(()),
        CipherBlockMethod::Cbc => Err(invalid("refusing AES-CBC without an HMAC")),
        CipherBlockMethod::None => Err(invalid("no cipher mode")),
    }
}

/// Decrypt a full data packet (`data[0]` is the opcode byte). On AEAD/HMAC
/// failure, returns `Ok(None)` so the caller drops the packet silently, exactly
/// like the Go upstream.
pub fn decrypt<'a>(
    opts: &Options,
    keys: &PeerKeys,
    data: &'a mut [u8],
) -> io::Result<Option<Decrypted<'a>>> {
    check_supported(opts)?;
    // GCM has no separate digest, whatever `auth` the client's options named.
    if opts.cipher_block == CipherBlockMethod::Gcm {
        return decrypt_gcm(opts, keys, data);
    }
    decrypt_cbc(opts, keys, data)
}

// --- GCM --------------------------------------------------------------------

/// GCM nonce size is 12 bytes; the first 4 are the packet ID and the remaining
/// 8 are the implicit IV taken from the HMAC key.
const GCM_NONCE: usize = 12;
const GCM_TAG: usize = 16;

fn encrypt_gcm(
    opts: &Options,
    keys: &PeerKeys,
    key_id: u8,
    pid: u32,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let nbytes = cipher_key_bytes(opts);

    // Build nonce = pid(4) || implicit_iv(8 from hmac_encrypt).
    let mut nonce = [0u8; GCM_NONCE];
    nonce[0..4].copy_from_slice(&pid.to_be_bytes());
    nonce[4..].copy_from_slice(&keys.hmac_encrypt[..GCM_NONCE - 4]);

    let ad = pid.to_be_bytes();

    // Plaintext = [compression?:1][payload..].
    let mut pt = Vec::with_capacity(payload.len() + 1);
    if opts.compression_framing() {
        pt.push(COMP_NONE);
    }
    pt.extend_from_slice(payload);

    let tag = gcm_seal_in_place(&keys.cipher_encrypt[..nbytes], &nonce, &ad, &mut pt)?;

    // Output: [opcode:1][pid:4][tag:16][ciphertext..].
    let mut out = Vec::with_capacity(1 + 4 + GCM_TAG + pt.len());
    out.push(Opcode::DATA_V1.to_byte(key_id));
    out.extend_from_slice(&pid.to_be_bytes());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&pt);
    Ok(out)
}

fn decrypt_gcm<'a>(
    opts: &Options,
    keys: &PeerKeys,
    data: &'a mut [u8],
) -> io::Result<Option<Decrypted<'a>>> {
    // Minimum: opcode(1) + pid(4) + tag(16) = 21.
    if data.len() < 21 {
        return Err(invalid("GCM packet too short"));
    }
    let nbytes = cipher_key_bytes(opts);

    let pid = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

    let mut nonce = [0u8; GCM_NONCE];
    nonce[0..4].copy_from_slice(&data[1..5]);
    nonce[4..].copy_from_slice(&keys.hmac_decrypt[..GCM_NONCE - 4]);
    let ad = [data[1], data[2], data[3], data[4]];

    // payload = [tag:16][ct..]; split into tag and ciphertext.
    let (tag, ct) = data[5..].split_at_mut(GCM_TAG);
    let mut tag_arr = [0u8; GCM_TAG];
    tag_arr.copy_from_slice(tag);

    let pt_len = match gcm_open_in_place(&keys.cipher_decrypt[..nbytes], &nonce, &ad, &tag_arr, ct)
    {
        Ok(n) => n,
        Err(_) => return Ok(None), // auth failure — drop silently
    };

    // ct now holds the plaintext in its first pt_len bytes.
    let plaintext = &data[21..21 + pt_len];
    finish_plaintext(opts, pid, plaintext)
}

/// Seal `buf` in place, returning the 16-byte tag. Selects key size by length.
fn gcm_seal_in_place(
    key: &[u8],
    nonce: &[u8; GCM_NONCE],
    ad: &[u8],
    buf: &mut [u8],
) -> io::Result<[u8; GCM_TAG]> {
    Ok(match key.len() {
        16 => Aes128Gcm::new(Aes128::new(&fixed::<16>(key)?)).encrypt(nonce, ad, buf),
        32 => Aes256Gcm::new(Aes256::new(&fixed::<32>(key)?)).encrypt(nonce, ad, buf),
        _ => return Err(invalid("unsupported AES-GCM key size")),
    })
}

/// Copy a key slice into a fixed-size array, or report a bad length.
fn fixed<const N: usize>(key: &[u8]) -> io::Result<[u8; N]> {
    key.try_into().map_err(|_| invalid("bad key length"))
}

/// Open `ct` in place against `tag`; on success `ct[..return]` is the plaintext.
fn gcm_open_in_place(
    key: &[u8],
    nonce: &[u8; GCM_NONCE],
    ad: &[u8],
    tag: &[u8; GCM_TAG],
    ct: &mut [u8],
) -> io::Result<usize> {
    let len = ct.len();
    match key.len() {
        16 => Aes128Gcm::new(Aes128::new(&fixed::<16>(key)?)).decrypt(nonce, ad, ct, tag),
        32 => Aes256Gcm::new(Aes256::new(&fixed::<32>(key)?)).decrypt(nonce, ad, ct, tag),
        _ => return Err(invalid("unsupported AES-GCM key size")),
    }
    .map_err(|_| invalid("gcm auth failure"))?;
    Ok(len)
}

// --- CBC + HMAC -------------------------------------------------------------

fn encrypt_cbc(
    opts: &Options,
    keys: &PeerKeys,
    key_id: u8,
    pid: u32,
    payload: &[u8],
    rng: impl FnOnce(&mut [u8]) -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    let nbytes = cipher_key_bytes(opts);
    if opts.cipher_block != CipherBlockMethod::Cbc {
        return Err(invalid("unsupported cipher block method for encrypt"));
    }

    let mut iv = [0u8; 16];
    rng(&mut iv)?;

    // Plaintext = [pid:4][compression?:1][payload..], PKCS#7 padded to 16.
    let mut pt = Vec::with_capacity(5 + payload.len() + 16);
    pt.extend_from_slice(&pid.to_be_bytes());
    if opts.compression_framing() {
        pt.push(COMP_NONE);
    }
    pt.extend_from_slice(payload);
    let mut padded = pkcs5::pad(&pt, 16);

    cbc_encrypt(&keys.cipher_encrypt[..nbytes], &iv, &mut padded)?;

    // body = iv || ciphertext.
    let mut body = Vec::with_capacity(16 + padded.len());
    body.extend_from_slice(&iv);
    body.extend_from_slice(&padded);

    let id = Opcode::DATA_V1.to_byte(key_id);
    // check_supported guarantees an HMAC.
    let n = opts.auth.size();
    let mac = hmac_compute(opts.auth, &keys.hmac_encrypt[..n], &body);
    let mut out = Vec::with_capacity(1 + n + body.len());
    out.push(id);
    out.extend_from_slice(&mac[..n]);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decrypt_cbc<'a>(
    opts: &Options,
    keys: &PeerKeys,
    data: &'a mut [u8],
) -> io::Result<Option<Decrypted<'a>>> {
    let nbytes = cipher_key_bytes(opts);
    // [opcode:1][hmac:n][iv:16][ct..]; check_supported guarantees an HMAC.
    let n = opts.auth.size();
    if data.len() < 1 + n {
        return Err(invalid("CBC packet too short for HMAC"));
    }
    let mac = hmac_compute(opts.auth, &keys.hmac_decrypt[..n], &data[1 + n..]);
    if !ct_eq(&data[1..1 + n], &mac[..n]) {
        return Ok(None);
    }
    let pos = 1 + n;

    // [iv:16][ciphertext..].
    if data.len() < pos + 16 {
        return Err(invalid("CBC packet too short for IV"));
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&data[pos..pos + 16]);
    let ct_start = pos + 16;
    let ct_len = data.len() - ct_start;
    if ct_len == 0 || !ct_len.is_multiple_of(16) {
        return Err(invalid("CBC ciphertext not block-aligned"));
    }

    let ct = &mut data[ct_start..];
    cbc_decrypt(&keys.cipher_decrypt[..nbytes], &iv, ct)?;
    // Authenticated, so bad padding is a broken peer, not an oracle.
    let unpadded_len = pkcs5::unpad(ct, 16)
        .ok_or_else(|| invalid("bad CBC padding"))?
        .len();
    let plain = &data[ct_start..ct_start + unpadded_len];

    // plain = [pid:4][compression:1][payload..].
    if plain.len() < 4 {
        return Ok(None);
    }
    let pid = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]);
    finish_plaintext(opts, pid, &plain[4..])
}

fn cbc_encrypt(key: &[u8], iv: &[u8; 16], buf: &mut [u8]) -> io::Result<()> {
    match key.len() {
        16 => Cbc::new(Aes128::new(&fixed::<16>(key)?), iv).encrypt(buf),
        32 => Cbc::new(Aes256::new(&fixed::<32>(key)?), iv).encrypt(buf),
        _ => return Err(invalid("unsupported AES-CBC key size")),
    }
    .map_err(|_| invalid("CBC input is not a whole number of blocks"))
}

fn cbc_decrypt(key: &[u8], iv: &[u8; 16], buf: &mut [u8]) -> io::Result<()> {
    match key.len() {
        16 => Cbc::new(Aes128::new(&fixed::<16>(key)?), iv).decrypt(buf),
        32 => Cbc::new(Aes256::new(&fixed::<32>(key)?), iv).decrypt(buf),
        _ => return Err(invalid("unsupported AES-CBC key size")),
    }
    .map_err(|_| invalid("CBC input is not a whole number of blocks"))
}

fn hmac_compute(auth: AuthHash, key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    match auth {
        AuthHash::Sha1 => {
            let mut m = Hmac::<Sha1>::new(key);
            m.update(data);
            m.finalize_into(&mut out[..20]);
        }
        AuthHash::Sha224 => {
            let mut m = Hmac::<Sha224>::new(key);
            m.update(data);
            m.finalize_into(&mut out[..28]);
        }
        AuthHash::Sha256 => {
            let mut m = Hmac::<Sha256>::new(key);
            m.update(data);
            m.finalize_into(&mut out[..32]);
        }
        AuthHash::None => {}
    }
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// --- shared plaintext post-processing --------------------------------------

/// Plaintext after the packet id is `[compression?:1][payload..]` (the pid
/// is in the clear header for GCM, inside the ciphertext for CBC). Strip the
/// compression byte, if framed, and detect a ping.
fn finish_plaintext<'a>(
    opts: &Options,
    pid: u32,
    plaintext: &'a [u8],
) -> io::Result<Option<Decrypted<'a>>> {
    let payload = if opts.compression_framing() {
        let Some((&comp, rest)) = plaintext.split_first() else {
            return Ok(None);
        };
        match comp {
            COMP_NONE => rest,
            COMP_LZO => return Err(invalid("lzo compression not supported")),
            COMP_LZ4 => return Err(invalid("lz4 compression not supported")),
            _ => return Err(invalid("unsupported compression format")),
        }
    } else {
        plaintext
    };
    let is_ping = payload.len() == OPENVPN_PING.len() && payload == OPENVPN_PING;
    Ok(Some(Decrypted {
        pid,
        payload,
        is_ping,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ovpn::consts::P_OPCODE_SHIFT;

    fn rng_zero(b: &mut [u8]) -> io::Result<()> {
        // Deterministic non-zero IV for tests that need a real IV.
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        Ok(())
    }

    // Build a sender/receiver key pair from random material (swapped halves),
    // exactly mirroring the Go data_test.go setupPeerPair.
    fn key_pair() -> (PeerKeys, PeerKeys) {
        let mut material = [0u8; 256];
        for (i, b) in material.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(3);
        }
        let sender = PeerKeys::from_expansion(&material);
        // Receiver = swapped encrypt/decrypt.
        let mut recv = PeerKeys {
            cipher_encrypt: [0; 64],
            hmac_encrypt: [0; 64],
            cipher_decrypt: [0; 64],
            hmac_decrypt: [0; 64],
        };
        recv.cipher_decrypt.copy_from_slice(&sender.cipher_encrypt);
        recv.hmac_decrypt.copy_from_slice(&sender.hmac_encrypt);
        recv.cipher_encrypt.copy_from_slice(&sender.cipher_decrypt);
        recv.hmac_encrypt.copy_from_slice(&sender.hmac_decrypt);
        (sender, recv)
    }

    fn gcm_opts(size: u32) -> Options {
        Options {
            cipher_crypto: CipherCryptoAlg::Aes,
            cipher_size: size,
            cipher_block: CipherBlockMethod::Gcm,
            auth: AuthHash::None,
            compression: "lzo".into(),
            ..Default::default()
        }
    }

    fn cbc_opts(size: u32) -> Options {
        Options {
            cipher_crypto: CipherCryptoAlg::Aes,
            cipher_size: size,
            cipher_block: CipherBlockMethod::Cbc,
            auth: AuthHash::Sha256,
            compression: "lzo".into(),
            ..Default::default()
        }
    }

    #[test]
    fn gcm_roundtrip() {
        let (sk, rk) = key_pair();
        let opts = gcm_opts(256);
        let payload = b"Hello, OpenVPN GCM roundtrip test!";
        let mut pkt = encrypt(&opts, &sk, 0, 1, payload, rng_zero).unwrap();
        let d = decrypt(&opts, &rk, &mut pkt).unwrap().unwrap();
        assert_eq!(d.pid, 1);
        assert_eq!(d.payload, payload);
        assert!(!d.is_ping);
    }

    #[test]
    fn gcm_aes128_roundtrip() {
        let (sk, rk) = key_pair();
        let opts = gcm_opts(128);
        let payload = b"smaller key";
        let mut pkt = encrypt(&opts, &sk, 0, 7, payload, rng_zero).unwrap();
        let d = decrypt(&opts, &rk, &mut pkt).unwrap().unwrap();
        assert_eq!(d.payload, payload);
    }

    #[test]
    fn gcm_corrupted_tag_dropped() {
        let (sk, rk) = key_pair();
        let opts = gcm_opts(256);
        let mut pkt = encrypt(&opts, &sk, 0, 1, b"corrupt me", rng_zero).unwrap();
        pkt[10] ^= 0xff; // flip a tag byte
        assert!(decrypt(&opts, &rk, &mut pkt).unwrap().is_none());
    }

    #[test]
    fn gcm_short_packet_errors() {
        let (_sk, rk) = key_pair();
        let opts = gcm_opts(256);
        let mut short = vec![Opcode::DATA_V1.0 << P_OPCODE_SHIFT, 0, 0, 0, 1];
        assert!(decrypt(&opts, &rk, &mut short).is_err());
    }

    #[test]
    fn gcm_large_payload() {
        let (sk, rk) = key_pair();
        let opts = gcm_opts(256);
        let payload: Vec<u8> = (0..1400).map(|i| i as u8).collect();
        let mut pkt = encrypt(&opts, &sk, 0, 99, &payload, rng_zero).unwrap();
        let d = decrypt(&opts, &rk, &mut pkt).unwrap().unwrap();
        assert_eq!(d.payload, &payload[..]);
    }

    #[test]
    fn cbc_roundtrip_sha256() {
        let (sk, rk) = key_pair();
        let opts = cbc_opts(128);
        let payload = b"Hello, OpenVPN CBC!";
        let mut pkt = encrypt(&opts, &sk, 0, 5, payload, rng_zero).unwrap();
        // Opcode check.
        assert_eq!(pkt[0] >> P_OPCODE_SHIFT, Opcode::DATA_V1.0);
        // [opcode:1][hmac:32][iv:16][ct..] => >= 65.
        assert!(pkt.len() >= 65, "len={}", pkt.len());
        let d = decrypt(&opts, &rk, &mut pkt).unwrap().unwrap();
        assert_eq!(d.pid, 5);
        assert_eq!(d.payload, payload);
    }

    #[test]
    fn cbc_aes256_roundtrip() {
        let (sk, rk) = key_pair();
        let opts = cbc_opts(256);
        let payload = b"256-bit CBC payload";
        let mut pkt = encrypt(&opts, &sk, 0, 11, payload, rng_zero).unwrap();
        let d = decrypt(&opts, &rk, &mut pkt).unwrap().unwrap();
        assert_eq!(d.payload, payload);
    }

    #[test]
    fn cbc_bad_hmac_dropped() {
        let (sk, rk) = key_pair();
        let opts = cbc_opts(128);
        let mut pkt = encrypt(&opts, &sk, 0, 1, b"tamper", rng_zero).unwrap();
        pkt[2] ^= 0x01; // corrupt the HMAC
        assert!(decrypt(&opts, &rk, &mut pkt).unwrap().is_none());
    }

    #[test]
    fn cbc_different_ivs_differ() {
        let (sk, _rk) = key_pair();
        let opts = cbc_opts(128);
        // Two distinct IVs => distinct ciphertext for the same payload.
        let p1 = encrypt(&opts, &sk, 0, 1, b"same", |b| {
            b.fill(1);
            Ok(())
        })
        .unwrap();
        let p2 = encrypt(&opts, &sk, 0, 1, b"same", |b| {
            b.fill(2);
            Ok(())
        })
        .unwrap();
        assert_ne!(p1, p2);
    }

    /// OpenVPN compresses (frames) first and then prepends the packet id, so
    /// the CBC plaintext is `[pid][compression byte][payload]` plus PKCS#7
    /// padding (crypto.c openvpn_encrypt_v1 / openvpn_decrypt_v1).
    #[test]
    fn cbc_plaintext_layout_matches_openvpn() {
        let (sk, rk) = key_pair();
        let opts = cbc_opts(128);
        let pkt = encrypt(&opts, &sk, 0, 0x0102_0304, b"xyz", rng_zero).unwrap();
        // [opcode:1][hmac:32][iv:16][ct..]
        let iv: [u8; 16] = pkt[33..49].try_into().unwrap();
        let mut ct = pkt[49..].to_vec();
        cbc_decrypt(&rk.cipher_decrypt[..16], &iv, &mut ct).unwrap();
        assert_eq!(&ct[..8], &[1, 2, 3, 4, COMP_NONE, b'x', b'y', b'z']);
        assert_eq!(&ct[8..], &[8u8; 8]);

        // And a packet laid out that way decrypts.
        let mut plain = vec![0, 0, 0, 9, COMP_NONE];
        plain.extend_from_slice(b"from openvpn");
        let mut padded = pkcs5::pad(&plain, 16);
        let iv = [0x42u8; 16];
        cbc_encrypt(&sk.cipher_encrypt[..16], &iv, &mut padded).unwrap();
        let mut body = iv.to_vec();
        body.extend_from_slice(&padded);
        let mac = hmac_compute(AuthHash::Sha256, &sk.hmac_encrypt[..32], &body);
        let mut wire = vec![Opcode::DATA_V1.to_byte(0)];
        wire.extend_from_slice(&mac);
        wire.extend_from_slice(&body);
        let d = decrypt(&opts, &rk, &mut wire).unwrap().unwrap();
        assert_eq!(d.pid, 9);
        assert_eq!(d.payload, b"from openvpn");
    }

    /// Whether packets carry the compression byte is one setting, and both
    /// directions must honour it.
    #[test]
    fn compression_framing_is_symmetric() {
        let (sk, rk) = key_pair();
        for mut opts in [gcm_opts(256), cbc_opts(256)] {
            opts.compression = "none".into();
            let mut pkt = encrypt(&opts, &sk, 0, 3, b"no framing", rng_zero).unwrap();
            let d = decrypt(&opts, &rk, &mut pkt).unwrap().unwrap();
            assert_eq!(d.payload, b"no framing");
        }
    }

    /// CBC without an HMAC is unauthenticated: refuse it in both directions.
    #[test]
    fn cbc_without_hmac_is_refused() {
        let (sk, rk) = key_pair();
        let mut opts = cbc_opts(256);
        opts.auth = AuthHash::None;
        assert!(encrypt(&opts, &sk, 0, 1, b"x", rng_zero).is_err());
        let mut pkt = encrypt(&cbc_opts(256), &sk, 0, 1, b"x", rng_zero).unwrap();
        // Strip the HMAC to make a packet an auth-less peer would send.
        pkt.drain(1..33);
        assert!(decrypt(&opts, &rk, &mut pkt).is_err());
    }

    /// `[null-cipher]` would mean sending the tunnel in the clear.
    #[test]
    fn null_cipher_is_refused() {
        let (sk, rk) = key_pair();
        let opts = Options {
            cipher_crypto: CipherCryptoAlg::None,
            ..cbc_opts(256)
        };
        assert!(encrypt(&opts, &sk, 0, 1, b"x", rng_zero).is_err());
        let mut pkt = encrypt(&cbc_opts(256), &sk, 0, 1, b"x", rng_zero).unwrap();
        assert!(decrypt(&opts, &rk, &mut pkt).is_err());
    }

    /// The HMAC authenticates the ciphertext, so bad padding means a broken
    /// peer; the packet is dropped rather than delivered truncated.
    #[test]
    fn cbc_bad_padding_is_dropped() {
        let (sk, rk) = key_pair();
        let opts = cbc_opts(128);
        let mut block = vec![0, 0, 0, 1, COMP_NONE];
        block.extend_from_slice(&[b'p'; 6]);
        block.extend_from_slice(&[5, 5, 5, 2, 5]); // claims 5, is not
        let iv = [7u8; 16];
        cbc_encrypt(&sk.cipher_encrypt[..16], &iv, &mut block).unwrap();
        let mut body = iv.to_vec();
        body.extend_from_slice(&block);
        let mac = hmac_compute(AuthHash::Sha256, &sk.hmac_encrypt[..32], &body);
        let mut wire = vec![Opcode::DATA_V1.to_byte(0)];
        wire.extend_from_slice(&mac);
        wire.extend_from_slice(&body);
        assert!(!matches!(decrypt(&opts, &rk, &mut wire), Ok(Some(_))));
    }

    /// GCM ignores the HMAC digest setting in both directions (the client's
    /// options may name one), as encrypt already did.
    #[test]
    fn gcm_does_not_depend_on_auth() {
        let (sk, rk) = key_pair();
        let opts = Options {
            auth: AuthHash::Sha1,
            ..gcm_opts(256)
        };
        let mut pkt = encrypt(&opts, &sk, 0, 1, b"gcm", rng_zero).unwrap();
        let d = decrypt(&opts, &rk, &mut pkt).unwrap().unwrap();
        assert_eq!(d.payload, b"gcm");
    }

    #[test]
    fn gcm_ping_detected() {
        let (sk, rk) = key_pair();
        let opts = gcm_opts(256);
        let mut pkt = encrypt(&opts, &sk, 0, 1, &OPENVPN_PING, rng_zero).unwrap();
        let d = decrypt(&opts, &rk, &mut pkt).unwrap().unwrap();
        assert!(d.is_ping);
    }
}
