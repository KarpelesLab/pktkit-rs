//! Data-channel encryption/decryption.
//!
//! Two cipher families are supported, both keyed from [`PeerKeys`]:
//!
//! - **AES-GCM** (AEAD). Wire format: `[opcode:1][pid:4][tag:16][ciphertext..]`.
//!   The nonce is `pid(4) || implicit_iv(8)` where the implicit IV is taken
//!   from the per-direction HMAC key. The 4-byte packet ID is the AAD. This is
//!   the modern happy path and is fully implemented.
//! - **AES-CBC + HMAC** (encrypt-then-... actually OpenVPN HMACs the opcode-less
//!   ciphertext). Wire format with auth: `[opcode:1][hmac:N][iv:16][ct..]` where
//!   the ciphertext encrypts `[pid:4][compression:1][payload..]` PKCS#7-padded.
//!
//! Decryption returns the inner payload with the leading compression byte
//! consumed (only the `0xfa` "no compression" marker is accepted; LZO/LZ4 are
//! rejected). Ported from the data paths in the Go `peer.go`.

use std::io;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use cbc::{Decryptor, Encryptor};
use hmac::{Mac, SimpleHmac};
use sha1::Sha1;
use sha2::{Sha224, Sha256};

use super::consts::OPENVPN_PING;
use super::keys::PeerKeys;
use super::options::{AuthHash, Options};
use super::pkcs5;
use super::{CipherBlockMethod, CipherCryptoAlg, Opcode};
use crate::ovpn::consts::P_OPCODE_SHIFT;

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
    pid: u32,
    payload: &[u8],
    rng: impl FnOnce(&mut [u8]) -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    if opts.cipher_crypto == CipherCryptoAlg::Aes && opts.cipher_block == CipherBlockMethod::Gcm {
        return encrypt_gcm(opts, keys, pid, payload);
    }
    encrypt_cbc(opts, keys, pid, payload, rng)
}

/// Decrypt a full data packet (`data[0]` is the opcode byte). On AEAD/HMAC
/// failure, returns `Ok(None)` so the caller drops the packet silently, exactly
/// like the Go upstream.
pub fn decrypt<'a>(
    opts: &Options,
    keys: &PeerKeys,
    data: &'a mut [u8],
) -> io::Result<Option<Decrypted<'a>>> {
    if opts.cipher_crypto == CipherCryptoAlg::Aes
        && opts.cipher_block == CipherBlockMethod::Gcm
        && opts.auth == AuthHash::None
    {
        return decrypt_gcm(opts, keys, data);
    }
    decrypt_cbc(opts, keys, data)
}

// --- GCM --------------------------------------------------------------------

/// GCM nonce size is 12 bytes; the first 4 are the packet ID and the remaining
/// 8 are the implicit IV taken from the HMAC key.
const GCM_NONCE: usize = 12;
const GCM_TAG: usize = 16;

fn encrypt_gcm(opts: &Options, keys: &PeerKeys, pid: u32, payload: &[u8]) -> io::Result<Vec<u8>> {
    let nbytes = cipher_key_bytes(opts);

    // Build nonce = pid(4) || implicit_iv(8 from hmac_encrypt).
    let mut nonce = [0u8; GCM_NONCE];
    nonce[0..4].copy_from_slice(&pid.to_be_bytes());
    nonce[4..].copy_from_slice(&keys.hmac_encrypt[..GCM_NONCE - 4]);

    let ad = pid.to_be_bytes();

    // Plaintext = [compression?:1][payload..].
    let has_comp = opts.compression != "none" && !opts.compression.is_empty();
    let mut pt = Vec::with_capacity(payload.len() + 1);
    if has_comp {
        pt.push(COMP_NONE);
    }
    pt.extend_from_slice(payload);

    let tag = gcm_seal_in_place(&keys.cipher_encrypt[..nbytes], &nonce, &ad, &mut pt)?;

    // Output: [opcode:1][pid:4][tag:16][ciphertext..].
    let mut out = Vec::with_capacity(1 + 4 + GCM_TAG + pt.len());
    out.push(Opcode::DATA_V1.0 << P_OPCODE_SHIFT);
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

    let pt_len = match gcm_open_in_place(&keys.cipher_decrypt[..nbytes], &nonce, &ad, &tag_arr, ct) {
        Ok(n) => n,
        Err(_) => return Ok(None), // auth failure — drop silently
    };

    // ct now holds the plaintext in its first pt_len bytes.
    let plaintext = &data[21..21 + pt_len];
    finish_plaintext(pid, plaintext)
}

/// Seal `buf` in place, returning the 16-byte tag. Selects key size by length.
fn gcm_seal_in_place(
    key: &[u8],
    nonce: &[u8; GCM_NONCE],
    ad: &[u8],
    buf: &mut [u8],
) -> io::Result<[u8; GCM_TAG]> {
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let tag = match key.len() {
        16 => {
            let c = Aes128Gcm::new_from_slice(key).map_err(|_| invalid("bad gcm key"))?;
            c.encrypt_in_place_detached(nonce, ad, buf)
        }
        32 => {
            let c = Aes256Gcm::new_from_slice(key).map_err(|_| invalid("bad gcm key"))?;
            c.encrypt_in_place_detached(nonce, ad, buf)
        }
        _ => return Err(invalid("unsupported AES-GCM key size")),
    }
    .map_err(|_| invalid("gcm seal failed"))?;
    let mut out = [0u8; GCM_TAG];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Open `ct` in place against `tag`; on success `ct[..return]` is the plaintext.
fn gcm_open_in_place(
    key: &[u8],
    nonce: &[u8; GCM_NONCE],
    ad: &[u8],
    tag: &[u8; GCM_TAG],
    ct: &mut [u8],
) -> io::Result<usize> {
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let tag = aes_gcm::Tag::from_slice(tag);
    let len = ct.len();
    match key.len() {
        16 => {
            let c = Aes128Gcm::new_from_slice(key).map_err(|_| invalid("bad gcm key"))?;
            c.decrypt_in_place_detached(nonce, ad, ct, tag)
        }
        32 => {
            let c = Aes256Gcm::new_from_slice(key).map_err(|_| invalid("bad gcm key"))?;
            c.decrypt_in_place_detached(nonce, ad, ct, tag)
        }
        _ => return Err(invalid("unsupported AES-GCM key size")),
    }
    .map_err(|_| invalid("gcm auth failure"))?;
    Ok(len)
}

// --- CBC + HMAC -------------------------------------------------------------

type Aes128CbcEnc = Encryptor<aes::Aes128>;
type Aes128CbcDec = Decryptor<aes::Aes128>;
type Aes256CbcEnc = Encryptor<aes::Aes256>;
type Aes256CbcDec = Decryptor<aes::Aes256>;

fn encrypt_cbc(
    opts: &Options,
    keys: &PeerKeys,
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

    // Plaintext = [compression?:1][pid:4][payload..], PKCS#7 padded to 16.
    let has_comp = opts.compression != "none" && !opts.compression.is_empty();
    let mut pt = Vec::with_capacity(5 + payload.len() + 16);
    if has_comp {
        pt.push(COMP_NONE);
    }
    pt.extend_from_slice(&pid.to_be_bytes());
    pt.extend_from_slice(payload);
    let mut padded = pkcs5::pad(&pt, 16);

    cbc_encrypt(&keys.cipher_encrypt[..nbytes], &iv, &mut padded)?;

    // body = iv || ciphertext.
    let mut body = Vec::with_capacity(16 + padded.len());
    body.extend_from_slice(&iv);
    body.extend_from_slice(&padded);

    let id = Opcode::DATA_V1.0 << P_OPCODE_SHIFT;
    let mut out = Vec::new();
    if opts.auth != AuthHash::None {
        let n = opts.auth.size();
        let mac = hmac_compute(opts.auth, &keys.hmac_encrypt[..n], &body);
        out.push(id);
        out.extend_from_slice(&mac[..n]);
        out.extend_from_slice(&body);
    } else {
        out.push(id);
        out.extend_from_slice(&body);
    }
    Ok(out)
}

fn decrypt_cbc<'a>(
    opts: &Options,
    keys: &PeerKeys,
    data: &'a mut [u8],
) -> io::Result<Option<Decrypted<'a>>> {
    let nbytes = cipher_key_bytes(opts);
    // data[0] is the opcode byte.
    let mut pos = 1usize;

    if opts.auth != AuthHash::None {
        let n = opts.auth.size();
        if data.len() < 1 + n {
            return Err(invalid("CBC packet too short for HMAC"));
        }
        let mut got = [0u8; 32];
        got[..n].copy_from_slice(&data[1..1 + n]);
        let body = &data[1 + n..];
        let mac = hmac_compute(opts.auth, &keys.hmac_decrypt[..n], body);
        // Constant-time compare via the hmac crate's verify would need the
        // Mac state; a direct compare is acceptable here (drop on mismatch).
        if !ct_eq(&got[..n], &mac[..n]) {
            return Ok(None);
        }
        pos = 1 + n;
    }

    if opts.cipher_block != CipherBlockMethod::Cbc {
        return Err(invalid("unsupported cipher block method for decrypt"));
    }

    // [iv:16][ciphertext..].
    if data.len() < pos + 16 {
        return Err(invalid("CBC packet too short for IV"));
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&data[pos..pos + 16]);
    let ct_start = pos + 16;
    let ct_len = data.len() - ct_start;
    if ct_len == 0 || ct_len % 16 != 0 {
        return Err(invalid("CBC ciphertext not block-aligned"));
    }

    let ct = &mut data[ct_start..];
    cbc_decrypt(&keys.cipher_decrypt[..nbytes], &iv, ct)?;
    let unpadded_len = pkcs5::trim(ct).len();
    let plain = &data[ct_start..ct_start + unpadded_len];

    // plain = [compression?:1][pid:4][payload..]. The compression byte is read
    // by finish_plaintext after the pid; but in CBC the pid is *inside* the
    // encrypted region, preceding compression is also inside. OpenVPN orders it
    // as [compression][pid][payload] when compression is present, matching the
    // encrypt path above.
    finish_plaintext_cbc(plain)
}

fn cbc_encrypt(key: &[u8], iv: &[u8; 16], buf: &mut [u8]) -> io::Result<()> {
    match key.len() {
        16 => {
            Aes128CbcEnc::new_from_slices(key, iv)
                .map_err(|_| invalid("bad cbc key/iv"))?
                .encrypt_blocks_mut(as_blocks_mut(buf));
        }
        32 => {
            Aes256CbcEnc::new_from_slices(key, iv)
                .map_err(|_| invalid("bad cbc key/iv"))?
                .encrypt_blocks_mut(as_blocks_mut(buf));
        }
        _ => return Err(invalid("unsupported AES-CBC key size")),
    }
    Ok(())
}

fn cbc_decrypt(key: &[u8], iv: &[u8; 16], buf: &mut [u8]) -> io::Result<()> {
    match key.len() {
        16 => {
            Aes128CbcDec::new_from_slices(key, iv)
                .map_err(|_| invalid("bad cbc key/iv"))?
                .decrypt_blocks_mut(as_blocks_mut(buf));
        }
        32 => {
            Aes256CbcDec::new_from_slices(key, iv)
                .map_err(|_| invalid("bad cbc key/iv"))?
                .decrypt_blocks_mut(as_blocks_mut(buf));
        }
        _ => return Err(invalid("unsupported AES-CBC key size")),
    }
    Ok(())
}

fn as_blocks_mut(buf: &mut [u8]) -> &mut [aes::cipher::generic_array::GenericArray<u8, aes::cipher::consts::U16>] {
    use aes::cipher::generic_array::GenericArray;
    let n = buf.len() / 16;
    // SAFETY: GenericArray<u8, U16> is repr(transparent) over [u8; 16]; buf is
    // a multiple of 16 (checked by callers).
    unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut GenericArray<u8, _>, n) }
}

fn hmac_compute(auth: AuthHash, key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    match auth {
        AuthHash::Sha1 => {
            let mut m = <SimpleHmac<Sha1> as Mac>::new_from_slice(key).expect("hmac key");
            m.update(data);
            out[..20].copy_from_slice(&m.finalize().into_bytes());
        }
        AuthHash::Sha224 => {
            let mut m = <SimpleHmac<Sha224> as Mac>::new_from_slice(key).expect("hmac key");
            m.update(data);
            out[..28].copy_from_slice(&m.finalize().into_bytes());
        }
        AuthHash::Sha256 => {
            let mut m = <SimpleHmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
            m.update(data);
            out[..32].copy_from_slice(&m.finalize().into_bytes());
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

/// For GCM: plaintext is `[compression:1][payload..]`; pid was already parsed
/// from the wire header. Strip the compression byte and detect a ping.
fn finish_plaintext(pid: u32, plaintext: &[u8]) -> io::Result<Option<Decrypted<'_>>> {
    if plaintext.is_empty() {
        return Ok(None);
    }
    let payload = match plaintext[0] {
        COMP_NONE => &plaintext[1..],
        COMP_LZO => return Err(invalid("lzo compression not supported")),
        COMP_LZ4 => return Err(invalid("lz4 compression not supported")),
        _ => return Err(invalid("unsupported compression format")),
    };
    let is_ping = payload.len() == OPENVPN_PING.len() && payload == OPENVPN_PING;
    Ok(Some(Decrypted {
        pid,
        payload,
        is_ping,
    }))
}

/// For CBC: plaintext is `[compression:1][pid:4][payload..]`.
fn finish_plaintext_cbc(plaintext: &[u8]) -> io::Result<Option<Decrypted<'_>>> {
    if plaintext.is_empty() {
        return Ok(None);
    }
    let rest = match plaintext[0] {
        COMP_NONE => &plaintext[1..],
        COMP_LZO => return Err(invalid("lzo compression not supported")),
        COMP_LZ4 => return Err(invalid("lz4 compression not supported")),
        _ => return Err(invalid("unsupported compression format")),
    };
    if rest.len() < 4 {
        return Ok(None);
    }
    let pid = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
    let payload = &rest[4..];
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
        let mut o = Options::default();
        o.cipher_crypto = CipherCryptoAlg::Aes;
        o.cipher_size = size;
        o.cipher_block = CipherBlockMethod::Gcm;
        o.auth = AuthHash::None;
        o.compression = "lzo".into();
        o
    }

    fn cbc_opts(size: u32) -> Options {
        let mut o = Options::default();
        o.cipher_crypto = CipherCryptoAlg::Aes;
        o.cipher_size = size;
        o.cipher_block = CipherBlockMethod::Cbc;
        o.auth = AuthHash::Sha256;
        o.compression = "lzo".into();
        o
    }

    #[test]
    fn gcm_roundtrip() {
        let (sk, rk) = key_pair();
        let opts = gcm_opts(256);
        let payload = b"Hello, OpenVPN GCM roundtrip test!";
        let mut pkt = encrypt(&opts, &sk, 1, payload, rng_zero).unwrap();
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
        let mut pkt = encrypt(&opts, &sk, 7, payload, rng_zero).unwrap();
        let d = decrypt(&opts, &rk, &mut pkt).unwrap().unwrap();
        assert_eq!(d.payload, payload);
    }

    #[test]
    fn gcm_corrupted_tag_dropped() {
        let (sk, rk) = key_pair();
        let opts = gcm_opts(256);
        let mut pkt = encrypt(&opts, &sk, 1, b"corrupt me", rng_zero).unwrap();
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
        let mut pkt = encrypt(&opts, &sk, 99, &payload, rng_zero).unwrap();
        let d = decrypt(&opts, &rk, &mut pkt).unwrap().unwrap();
        assert_eq!(d.payload, &payload[..]);
    }

    #[test]
    fn cbc_roundtrip_sha256() {
        let (sk, rk) = key_pair();
        let opts = cbc_opts(128);
        let payload = b"Hello, OpenVPN CBC!";
        let mut pkt = encrypt(&opts, &sk, 5, payload, rng_zero).unwrap();
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
        let mut pkt = encrypt(&opts, &sk, 11, payload, rng_zero).unwrap();
        let d = decrypt(&opts, &rk, &mut pkt).unwrap().unwrap();
        assert_eq!(d.payload, payload);
    }

    #[test]
    fn cbc_bad_hmac_dropped() {
        let (sk, rk) = key_pair();
        let opts = cbc_opts(128);
        let mut pkt = encrypt(&opts, &sk, 1, b"tamper", rng_zero).unwrap();
        pkt[2] ^= 0x01; // corrupt the HMAC
        assert!(decrypt(&opts, &rk, &mut pkt).unwrap().is_none());
    }

    #[test]
    fn cbc_different_ivs_differ() {
        let (sk, _rk) = key_pair();
        let opts = cbc_opts(128);
        // Two distinct IVs => distinct ciphertext for the same payload.
        let p1 = encrypt(&opts, &sk, 1, b"same", |b| {
            b.fill(1);
            Ok(())
        })
        .unwrap();
        let p2 = encrypt(&opts, &sk, 1, b"same", |b| {
            b.fill(2);
            Ok(())
        })
        .unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn gcm_ping_detected() {
        let (sk, rk) = key_pair();
        let opts = gcm_opts(256);
        let mut pkt = encrypt(&opts, &sk, 1, &OPENVPN_PING, rng_zero).unwrap();
        let d = decrypt(&opts, &rk, &mut pkt).unwrap().unwrap();
        assert!(d.is_ping);
    }
}
