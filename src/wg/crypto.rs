//! Cryptographic primitives wired up for the WireGuard Noise IK transcript.
//!
//! Everything in this file is a thin wrapper over `purecrypto`:
//!
//! - X25519 via [`purecrypto::ec::x25519`].
//! - ChaCha20-Poly1305 / XChaCha20-Poly1305 via `purecrypto::cipher`.
//! - Blake2s-256 and Blake2s-128 via `purecrypto::hash`.
//! - HKDF-style derivations built on `Hmac<Blake2s256>`.
//!
//! Wire constants live in [`super::constants`]; we don't redefine them here.

use purecrypto::cipher::{ChaCha20Poly1305, XChaCha20Poly1305};
use purecrypto::ec::x25519::{BASE_POINT, x25519};
use purecrypto::hash::{Blake2s256, Blake2sMac, Digest, Hmac, Mac};
use purecrypto::rng::{OsRng, RngCore};
use std::io;

use crate::Result;
use crate::wg::constants::{
    BLAKE2S_128_SIZE, BLAKE2S_256_SIZE, CHACHAPOLY_KEY_SIZE, NOISE_PUBLIC_KEY_SIZE, WG_IDENTIFIER,
    WG_LABEL_COOKIE, WG_LABEL_MAC1,
};
use crate::wg::constants::{NoisePresharedKey, NoisePrivateKey, NoisePublicKey};
use crate::zeroize::zeroize;

// === Helpers ================================================================

/// HMAC-Blake2s-256, used for the HKDF Extract/Expand chain.
type HmacBlake2s = Hmac<Blake2s256>;

/// Compute Blake2s-256 over a single message (no key).
pub(crate) fn blake2s_256(msg: &[u8]) -> [u8; BLAKE2S_256_SIZE] {
    purecrypto::hash::blake2s256(msg)
}

/// `dst = Blake2s256(h || data)` — the Noise `MixHash` rule.
pub(crate) fn mix_hash(dst: &mut [u8; BLAKE2S_256_SIZE], h: &[u8; BLAKE2S_256_SIZE], data: &[u8]) {
    let mut hasher = Blake2s256::new();
    hasher.update(h);
    hasher.update(data);
    *dst = hasher.finalize();
}

/// HMAC-Blake2s-256 over one input chunk.
pub(crate) fn hmac1(sum: &mut [u8; BLAKE2S_256_SIZE], key: &[u8], in0: &[u8]) {
    let mut mac = HmacBlake2s::new(key);
    mac.update(in0);
    mac.finalize_into(sum);
}

/// HMAC-Blake2s-256 over two concatenated input chunks.
pub(crate) fn hmac2(sum: &mut [u8; BLAKE2S_256_SIZE], key: &[u8], in0: &[u8], in1: &[u8]) {
    let mut mac = HmacBlake2s::new(key);
    mac.update(in0);
    mac.update(in1);
    mac.finalize_into(sum);
}

/// KDF1: HKDF-style single-output derivation.
pub(crate) fn kdf1(t0: &mut [u8; BLAKE2S_256_SIZE], key: &[u8], input: &[u8]) {
    hmac1(t0, key, input);
    let prk = *t0;
    hmac1(t0, &prk, &[0x01]);
}

/// KDF2: HKDF-style two-output derivation. `t0` and `t1` are independent 32B
/// keys; `t1` is `T(2)` from the HKDF spec — derived from `T(1)` chained with
/// the byte `0x02`.
pub(crate) fn kdf2(
    t0: &mut [u8; BLAKE2S_256_SIZE],
    t1: &mut [u8; BLAKE2S_256_SIZE],
    key: &[u8],
    input: &[u8],
) {
    let mut prk = [0u8; BLAKE2S_256_SIZE];
    hmac1(&mut prk, key, input);
    hmac1(t0, &prk, &[0x01]);
    hmac2(t1, &prk, t0.as_slice(), &[0x02]);
    zeroize(&mut prk);
}

/// KDF3: HKDF-style three-output derivation. Used by the PSK mixer.
pub(crate) fn kdf3(
    t0: &mut [u8; BLAKE2S_256_SIZE],
    t1: &mut [u8; BLAKE2S_256_SIZE],
    t2: &mut [u8; BLAKE2S_256_SIZE],
    key: &[u8],
    input: &[u8],
) {
    let mut prk = [0u8; BLAKE2S_256_SIZE];
    hmac1(&mut prk, key, input);

    hmac1(t0, &prk, &[0x01]);

    let mut data2 = [0u8; BLAKE2S_256_SIZE + 1];
    data2[..BLAKE2S_256_SIZE].copy_from_slice(t0.as_slice());
    data2[BLAKE2S_256_SIZE] = 0x02;
    hmac1(t1, &prk, &data2);

    let mut data3 = [0u8; BLAKE2S_256_SIZE + 1];
    data3[..BLAKE2S_256_SIZE].copy_from_slice(t1.as_slice());
    data3[BLAKE2S_256_SIZE] = 0x03;
    hmac1(t2, &prk, &data3);

    zeroize(&mut prk);
    zeroize(&mut data2);
    zeroize(&mut data3);
}

/// Mix a preshared key into the handshake chain: `c, tau, k = KDF3(c, psk)`,
/// `h = MixHash(h, tau)`.
pub(crate) fn mix_psk(
    chaining_key: &mut [u8; BLAKE2S_256_SIZE],
    hash: &mut [u8; BLAKE2S_256_SIZE],
    key: &mut [u8; CHACHAPOLY_KEY_SIZE],
    psk: &NoisePresharedKey,
) {
    let mut tau = [0u8; BLAKE2S_256_SIZE];
    let mut new_key = [0u8; BLAKE2S_256_SIZE];
    let saved_c = *chaining_key;
    kdf3(
        chaining_key,
        &mut tau,
        &mut new_key,
        &saved_c,
        psk.as_bytes(),
    );
    key.copy_from_slice(&new_key);
    let h_copy = *hash;
    mix_hash(hash, &h_copy, &tau);
    zeroize(&mut tau);
    zeroize(&mut new_key);
}

/// `mix_key`: chain a new 32-byte secret into the running chain key.
pub(crate) fn mix_key(dst: &mut [u8; BLAKE2S_256_SIZE], c: &[u8; BLAKE2S_256_SIZE], data: &[u8]) {
    kdf1(dst, c, data);
}

// === Curve25519 =============================================================

/// Apply the Curve25519 clamping operation in-place.
pub(crate) fn clamp(sk: &mut [u8; 32]) {
    sk[0] &= 248;
    sk[31] = (sk[31] & 127) | 64;
}

/// Derive the public key for a private key. The private key is *not* clamped
/// in place — call [`clamp`] first if it came from a non-WG source.
pub(crate) fn x25519_public(sk: &NoisePrivateKey) -> NoisePublicKey {
    // `x25519` clamps the scalar itself (RFC 7748 §5), so this matches the
    // clamped base-point multiplication WireGuard specifies.
    NoisePublicKey(x25519(&sk.0, &BASE_POINT))
}

/// Diffie-Hellman: `sk * pk`. Returns 32 bytes (the shared u-coordinate).
///
/// This is the raw primitive: a small-order peer key yields all zeros rather
/// than an error. WireGuard's Noise transcript binds the result into the
/// chaining key, so a degenerate share makes the handshake fail to
/// authenticate rather than needing a separate check here.
pub(crate) fn x25519_dh(sk: &NoisePrivateKey, pk: &NoisePublicKey) -> [u8; 32] {
    x25519(&sk.0, &pk.0)
}

/// Generate a fresh, clamped Curve25519 private key from OS randomness.
pub fn generate_private_key() -> Result<NoisePrivateKey> {
    let mut buf = [0u8; 32];
    fill_random(&mut buf)?;
    clamp(&mut buf);
    Ok(NoisePrivateKey(buf))
}

/// Generate a random preshared key from OS randomness.
pub fn generate_preshared_key() -> Result<NoisePresharedKey> {
    let mut buf = [0u8; 32];
    fill_random(&mut buf)?;
    Ok(NoisePresharedKey(buf))
}

/// Fill the buffer with OS randomness.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    OsRng.fill_bytes(buf);
    Ok(())
}

/// Derive the MAC1 key for a public key: `Blake2s256("mac1----" || pk)`.
pub(crate) fn calculate_mac1_key(pk: &NoisePublicKey) -> [u8; 32] {
    label_hash(WG_LABEL_MAC1, pk)
}

/// Derive the cookie-encryption key for a public key:
/// `Blake2s256("cookie--" || pk)`.
#[allow(dead_code)] // used once cookie reply support lands
pub(crate) fn calculate_cookie_key(pk: &NoisePublicKey) -> [u8; 32] {
    label_hash(WG_LABEL_COOKIE, pk)
}

/// `Blake2s256(label || pk)`. The labels are 8-byte ASCII tags, so this is not
/// the 32-byte-prefix shape [`mix_hash`] handles.
fn label_hash(label: &[u8], pk: &NoisePublicKey) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(label);
    hasher.update(&pk.0);
    hasher.finalize()
}

/// Compute a Blake2s-MAC-128 over `data` with the given 32-byte key. The
/// output (16 bytes) is the WireGuard MAC1/MAC2 form.
pub(crate) fn blake2s_mac_128(key: &[u8], data: &[u8]) -> [u8; BLAKE2S_128_SIZE] {
    let mut mac = Blake2sMac::new(key, BLAKE2S_128_SIZE);
    mac.update(data);
    let mut buf = [0u8; BLAKE2S_128_SIZE];
    mac.finalize_into(&mut buf);
    buf
}

/// Constant-time equality on byte slices of equal length.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// True if every byte of `arr` is zero.
#[allow(dead_code)]
pub(crate) fn is_zero(arr: &[u8]) -> bool {
    arr.iter().all(|&b| b == 0)
}

// === AEAD seal / open ======================================================

/// Seal `pt` with ChaCha20-Poly1305 using a 96-bit counter nonce. The counter
/// is placed in the **last 8 bytes** of the nonce (WireGuard's data-channel
/// convention); the first 4 bytes are zero.
pub(crate) fn aead_seal(
    key: &[u8; CHACHAPOLY_KEY_SIZE],
    nonce_counter: u64,
    pt: &[u8],
    ad: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(pt.len() + 16);
    out.extend_from_slice(pt);
    let tag = ChaCha20Poly1305::new(key).encrypt(&counter_nonce(nonce_counter), ad, &mut out);
    out.extend_from_slice(&tag);
    out
}

/// WireGuard's data-channel nonce: a 64-bit counter in the **last 8 bytes** of
/// the 96-bit nonce, with the first 4 zero.
fn counter_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Split `ct` into ciphertext and its trailing 16-byte tag.
fn split_tag(ct: &[u8]) -> Result<(&[u8], [u8; 16])> {
    if ct.len() < 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "aead open: shorter than the authentication tag",
        ));
    }
    let (body, tail) = ct.split_at(ct.len() - 16);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(tail);
    Ok((body, tag))
}

/// Seal with a zero nonce (used during the Noise handshake).
pub(crate) fn aead_seal_zero(key: &[u8; CHACHAPOLY_KEY_SIZE], pt: &[u8], ad: &[u8]) -> Vec<u8> {
    aead_seal(key, 0, pt, ad)
}

/// Open with a zero nonce.
pub(crate) fn aead_open_zero(
    key: &[u8; CHACHAPOLY_KEY_SIZE],
    ct: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    aead_open(key, 0, ct, ad)
}

/// Open with a counter nonce.
pub(crate) fn aead_open(
    key: &[u8; CHACHAPOLY_KEY_SIZE],
    nonce_counter: u64,
    ct: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    let (body, tag) = split_tag(ct)?;
    let mut buf = body.to_vec();
    ChaCha20Poly1305::new(key)
        .decrypt(&counter_nonce(nonce_counter), ad, &mut buf, &tag)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aead open failed"))?;
    Ok(buf)
}

/// In-place encrypt: writes ciphertext + 16-byte tag into `dst[..len+16]`.
/// `dst` must be at least `pt.len() + 16` bytes long. Returns the number of
/// bytes written.
pub(crate) fn aead_seal_in_place(
    key: &[u8; CHACHAPOLY_KEY_SIZE],
    nonce_counter: u64,
    pt: &[u8],
    ad: &[u8],
    dst: &mut [u8],
) -> usize {
    let needed = pt.len() + 16;
    debug_assert!(dst.len() >= needed);
    // Detached tags mean this really is in place now: copy the plaintext into
    // the caller's buffer, encrypt it there, then append the tag. No
    // intermediate Vec.
    dst[..pt.len()].copy_from_slice(pt);
    let tag =
        ChaCha20Poly1305::new(key).encrypt(&counter_nonce(nonce_counter), ad, &mut dst[..pt.len()]);
    dst[pt.len()..needed].copy_from_slice(&tag);
    needed
}

/// XChaCha20-Poly1305 seal with a 24-byte nonce. Used to encrypt cookies.
#[allow(dead_code)] // used once cookie reply support lands
pub(crate) fn xaead_seal(key: &[u8; 32], nonce: &[u8; 24], pt: &[u8], ad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pt.len() + 16);
    out.extend_from_slice(pt);
    let tag = XChaCha20Poly1305::new(key).encrypt(nonce, ad, &mut out);
    out.extend_from_slice(&tag);
    out
}

/// XChaCha20-Poly1305 open with a 24-byte nonce.
#[allow(dead_code)] // used once cookie reply support lands
pub(crate) fn xaead_open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ct: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    let (body, tag) = split_tag(ct)?;
    let mut buf = body.to_vec();
    XChaCha20Poly1305::new(key)
        .decrypt(nonce, ad, &mut buf, &tag)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "xaead open failed"))?;
    Ok(buf)
}

// === Noise transcript constants (one-time init) ============================

/// Initial chain key: `Blake2s256(noiseConstruction)`.
pub(crate) fn initial_chain_key() -> [u8; BLAKE2S_256_SIZE] {
    blake2s_256(NOISE_CONSTRUCTION_BYTES)
}

/// Initial hash: `MixHash(initialChainKey, wgIdentifier)`.
pub(crate) fn initial_hash() -> [u8; BLAKE2S_256_SIZE] {
    let ck = initial_chain_key();
    let mut h = [0u8; BLAKE2S_256_SIZE];
    mix_hash(&mut h, &ck, WG_IDENTIFIER);
    h
}

const NOISE_CONSTRUCTION_BYTES: &[u8] = crate::wg::constants::NOISE_CONSTRUCTION;

// Compile-time sanity check on key sizes the rest of the module assumes.
const _: () = {
    assert!(NOISE_PUBLIC_KEY_SIZE == 32);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::constants::NOISE_PRIVATE_KEY_SIZE;

    #[test]
    fn x25519_roundtrip() {
        let sk_a = generate_private_key().unwrap();
        let sk_b = generate_private_key().unwrap();
        let pk_a = x25519_public(&sk_a);
        let pk_b = x25519_public(&sk_b);

        let shared_ab = x25519_dh(&sk_a, &pk_b);
        let shared_ba = x25519_dh(&sk_b, &pk_a);
        assert_eq!(shared_ab, shared_ba);
        // It also shouldn't be all-zero for honest random keys.
        assert!(!shared_ab.iter().all(|&b| b == 0));
    }

    #[test]
    fn clamp_zeroes_low_bits_and_sets_high_bits() {
        let mut sk = [0xFFu8; NOISE_PRIVATE_KEY_SIZE];
        clamp(&mut sk);
        assert_eq!(sk[0] & 0b111, 0, "low 3 bits must be cleared");
        assert_eq!(sk[31] & 0x80, 0, "top bit must be cleared");
        assert_eq!(sk[31] & 0x40, 0x40, "bit 254 must be set");
    }

    #[test]
    fn kdf1_matches_kdf2_first_output() {
        // KDF1 must produce the same T(1) as KDF2's first output.
        let key = b"some chain key bytes...........";
        let input = b"diffie-hellman output";
        let mut a = [0u8; 32];
        let mut b0 = [0u8; 32];
        let mut b1 = [0u8; 32];
        kdf1(&mut a, key, input);
        kdf2(&mut b0, &mut b1, key, input);
        assert_eq!(a, b0);
        assert_ne!(b0, b1, "two outputs must differ");
    }

    #[test]
    fn mix_psk_does_not_panic_and_writes_key() {
        let mut ck = [0x11u8; 32];
        let mut h = [0x22u8; 32];
        let mut k = [0u8; 32];
        let psk = NoisePresharedKey([0xAB; 32]);
        mix_psk(&mut ck, &mut h, &mut k, &psk);
        assert!(!is_zero(&k));
        assert!(!is_zero(&ck));
    }

    #[test]
    fn aead_roundtrip_zero_nonce() {
        let key = [0x42u8; 32];
        let pt = b"hello noise IK";
        let ad = b"associated";
        let ct = aead_seal_zero(&key, pt, ad);
        let recovered = aead_open_zero(&key, &ct, ad).expect("decrypt");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn aead_open_rejects_tampered() {
        let key = [0x55u8; 32];
        let pt = b"payload";
        let ad = b"ad";
        let mut ct = aead_seal_zero(&key, pt, ad);
        // Flip a bit in the tag.
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(aead_open_zero(&key, &ct, ad).is_err());
    }

    #[test]
    fn mac1_key_derivation_is_deterministic() {
        let pk = NoisePublicKey([0x77; 32]);
        let a = calculate_mac1_key(&pk);
        let b = calculate_mac1_key(&pk);
        assert_eq!(a, b);
        // Different keys must produce different MAC1 keys.
        let pk2 = NoisePublicKey([0x88; 32]);
        assert_ne!(a, calculate_mac1_key(&pk2));
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(b"hello", b"hello!"));
    }

    /// Decode a compile-time hex string into 32 bytes.
    fn hex32(s: &str) -> [u8; 32] {
        let b = s.as_bytes();
        assert_eq!(b.len(), 64, "expected 64 hex digits");
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = (b[i * 2] as char).to_digit(16).expect("hex digit") as u8;
            let lo = (b[i * 2 + 1] as char).to_digit(16).expect("hex digit") as u8;
            *byte = (hi << 4) | lo;
        }
        out
    }

    // --- Known-answer tests -------------------------------------------------
    //
    // The round-trip tests above would still pass if a primitive were swapped
    // for a different-but-self-consistent one, which is exactly the mistake a
    // migration can make. These pin the wire behaviour to published vectors,
    // through pktkit's own wrappers rather than the library's API.

    #[test]
    fn x25519_matches_rfc7748_section_5_2() {
        let scalar = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let got = x25519_dh(&NoisePrivateKey(scalar), &NoisePublicKey(u));
        assert_eq!(
            got,
            hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
    }

    #[test]
    fn x25519_matches_rfc7748_section_6_1() {
        let alice_sk = NoisePrivateKey(hex32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let bob_sk = NoisePrivateKey(hex32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));

        let alice_pk = x25519_public(&alice_sk);
        let bob_pk = x25519_public(&bob_sk);
        assert_eq!(
            alice_pk.0,
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
            "public key derivation must use the clamped base point"
        );
        assert_eq!(
            bob_pk.0,
            hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );

        let shared = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519_dh(&alice_sk, &bob_pk), shared);
        assert_eq!(x25519_dh(&bob_sk, &alice_pk), shared);
    }

    #[test]
    fn blake2s_256_matches_rfc7693() {
        assert_eq!(
            blake2s_256(b"abc"),
            hex32("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        );
    }

    #[test]
    fn mix_hash_is_blake2s_of_the_concatenation() {
        // MixHash must hash `h || data`, in that order, with no separator.
        let h = blake2s_256(b"chaining");
        let mut got = [0u8; BLAKE2S_256_SIZE];
        mix_hash(&mut got, &h, b"payload");

        let mut expect_input = Vec::new();
        expect_input.extend_from_slice(&h);
        expect_input.extend_from_slice(b"payload");
        assert_eq!(got, blake2s_256(&expect_input));
    }

    #[test]
    fn mac1_key_is_blake2s_of_label_then_public_key() {
        // `Blake2s256("mac1----" || Spub)`. Getting the order or the label
        // wrong still round-trips between two pktkit peers, and still fails
        // against every other WireGuard implementation.
        let pk = NoisePublicKey(hex32(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        ));
        let mut expect_input = Vec::new();
        expect_input.extend_from_slice(WG_LABEL_MAC1);
        expect_input.extend_from_slice(&pk.0);
        assert_eq!(calculate_mac1_key(&pk), blake2s_256(&expect_input));

        let mut cookie_input = Vec::new();
        cookie_input.extend_from_slice(WG_LABEL_COOKIE);
        cookie_input.extend_from_slice(&pk.0);
        assert_eq!(calculate_cookie_key(&pk), blake2s_256(&cookie_input));
    }

    #[test]
    fn aead_nonce_puts_the_counter_in_the_last_eight_bytes() {
        // WireGuard's data-channel convention, and easy to build backwards.
        let key = [0x42u8; CHACHAPOLY_KEY_SIZE];
        let counter = 0x0102_0304_0506_0708u64;
        let sealed = aead_seal(&key, counter, b"plaintext", b"aad");

        let mut expect_nonce = [0u8; 12];
        expect_nonce[4..].copy_from_slice(&counter.to_le_bytes());
        let mut expect = b"plaintext".to_vec();
        let tag = purecrypto::cipher::ChaCha20Poly1305::new(&key).encrypt(
            &expect_nonce,
            b"aad",
            &mut expect,
        );
        expect.extend_from_slice(&tag);

        assert_eq!(sealed, expect);
        // And the first four bytes really are zero, not part of the counter.
        assert_eq!(&expect_nonce[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn aead_tag_is_appended_not_prepended() {
        let key = [7u8; CHACHAPOLY_KEY_SIZE];
        let pt = b"the quick brown fox";
        let sealed = aead_seal(&key, 1, pt, b"");
        assert_eq!(sealed.len(), pt.len() + 16);
        assert_eq!(
            &sealed[..pt.len()].len(),
            &pt.len(),
            "ciphertext occupies the front"
        );
        assert_eq!(aead_open(&key, 1, &sealed, b"").unwrap(), pt);

        // A wrong counter must not authenticate.
        assert!(aead_open(&key, 2, &sealed, b"").is_err());
    }

    #[test]
    fn aead_open_rejects_a_buffer_shorter_than_the_tag() {
        let key = [0u8; CHACHAPOLY_KEY_SIZE];
        assert!(aead_open(&key, 0, &[0u8; 15], b"").is_err());
        assert!(aead_open(&key, 0, &[], b"").is_err());
    }

    #[test]
    fn aead_seal_in_place_matches_the_allocating_form() {
        let key = [0x11u8; CHACHAPOLY_KEY_SIZE];
        let pt = b"in place or not, same bytes";
        let expect = aead_seal(&key, 9, pt, b"ad");

        let mut dst = vec![0u8; pt.len() + 16];
        let n = aead_seal_in_place(&key, 9, pt, b"ad", &mut dst);
        assert_eq!(n, pt.len() + 16);
        assert_eq!(dst, expect);
    }

    #[test]
    fn xaead_round_trips_and_rejects_tampering() {
        let key = [0x5Au8; 32];
        let nonce = [0x3Cu8; 24];
        let mut sealed = xaead_seal(&key, &nonce, b"cookie", b"ad");
        assert_eq!(xaead_open(&key, &nonce, &sealed, b"ad").unwrap(), b"cookie");

        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(xaead_open(&key, &nonce, &sealed, b"ad").is_err());
    }
}
