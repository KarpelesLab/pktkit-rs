//! Cryptographic primitives wired up for the WireGuard Noise IK transcript.
//!
//! Everything in this file is a thin wrapper over RustCrypto:
//!
//! - X25519 via [`curve25519_dalek::montgomery::MontgomeryPoint`].
//! - ChaCha20-Poly1305 / XChaCha20-Poly1305 via the `chacha20poly1305` crate.
//! - Blake2s-256 and Blake2s-128 via the `blake2` crate.
//! - HKDF-style derivations built on `hmac::Hmac<Blake2s256>`.
//!
//! Wire constants live in [`super::constants`]; we don't redefine them here.

use blake2::digest::{consts::U16, KeyInit as MacKeyInit, Mac, Update};
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::{Aead, AeadInPlace, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hmac::SimpleHmac;
use std::io;
use zeroize::Zeroize;

use crate::wg::constants::{NoisePresharedKey, NoisePrivateKey, NoisePublicKey};
use crate::wg::constants::{
    BLAKE2S_128_SIZE, BLAKE2S_256_SIZE, CHACHAPOLY_KEY_SIZE, NOISE_PUBLIC_KEY_SIZE, WG_IDENTIFIER,
    WG_LABEL_COOKIE, WG_LABEL_MAC1,
};
use crate::Result;

// === Helpers ================================================================

/// Variable-output Blake2s with 16-byte digest (used for MAC1/MAC2 and the
/// per-peer cookie). The library exposes this as `Blake2sMac<U16>`.
type Blake2sMac128 = Blake2sMac<U16>;

/// HMAC-Blake2s-256, used for the HKDF Extract/Expand chain.
///
/// We use `SimpleHmac` rather than `Hmac` because Blake2s exposes a
/// `Lazy`-kind buffer that the optimised `Hmac` API rejects.
type HmacBlake2s = SimpleHmac<Blake2s256>;

/// Compute Blake2s-256 over a single message (no key).
pub(crate) fn blake2s_256(msg: &[u8]) -> [u8; BLAKE2S_256_SIZE] {
    let mut h = Blake2s256::new();
    Digest::update(&mut h, msg);
    let out = h.finalize();
    let mut buf = [0u8; BLAKE2S_256_SIZE];
    buf.copy_from_slice(&out);
    buf
}

/// `dst = Blake2s256(h || data)` — the Noise `MixHash` rule.
pub(crate) fn mix_hash(dst: &mut [u8; BLAKE2S_256_SIZE], h: &[u8; BLAKE2S_256_SIZE], data: &[u8]) {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, h);
    Digest::update(&mut hasher, data);
    let out = hasher.finalize();
    dst.copy_from_slice(&out);
}

/// HMAC-Blake2s-256 over one input chunk.
pub(crate) fn hmac1(sum: &mut [u8; BLAKE2S_256_SIZE], key: &[u8], in0: &[u8]) {
    let mut mac = <HmacBlake2s as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    Mac::update(&mut mac, in0);
    let out = mac.finalize().into_bytes();
    sum.copy_from_slice(&out);
}

/// HMAC-Blake2s-256 over two concatenated input chunks.
pub(crate) fn hmac2(sum: &mut [u8; BLAKE2S_256_SIZE], key: &[u8], in0: &[u8], in1: &[u8]) {
    let mut mac = <HmacBlake2s as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    Mac::update(&mut mac, in0);
    Mac::update(&mut mac, in1);
    let out = mac.finalize().into_bytes();
    sum.copy_from_slice(&out);
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
    prk.zeroize();
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

    prk.zeroize();
    data2.zeroize();
    data3.zeroize();
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
    tau.zeroize();
    new_key.zeroize();
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
    NoisePublicKey(MontgomeryPoint::mul_base_clamped(sk.0).to_bytes())
}

/// Diffie-Hellman: `sk * pk`. Returns 32 bytes (the shared u-coordinate).
pub(crate) fn x25519_dh(sk: &NoisePrivateKey, pk: &NoisePublicKey) -> [u8; 32] {
    let point = MontgomeryPoint(pk.0);
    point.mul_clamped(sk.0).to_bytes()
}

/// Generate a fresh, clamped Curve25519 private key from OS randomness.
pub fn generate_private_key() -> Result<NoisePrivateKey> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|e| io::Error::other(format!("getrandom: {}", e)))?;
    clamp(&mut buf);
    Ok(NoisePrivateKey(buf))
}

/// Generate a random preshared key from OS randomness.
pub fn generate_preshared_key() -> Result<NoisePresharedKey> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|e| io::Error::other(format!("getrandom: {}", e)))?;
    Ok(NoisePresharedKey(buf))
}

/// Fill the buffer with OS randomness.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| io::Error::other(format!("getrandom: {}", e)))
}

/// Derive the MAC1 key for a public key: `Blake2s256("mac1----" || pk)`.
pub(crate) fn calculate_mac1_key(pk: &NoisePublicKey) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, WG_LABEL_MAC1);
    Digest::update(&mut hasher, pk.0);
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// Derive the cookie-encryption key for a public key:
/// `Blake2s256("cookie--" || pk)`.
#[allow(dead_code)] // used once cookie reply support lands
pub(crate) fn calculate_cookie_key(pk: &NoisePublicKey) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, WG_LABEL_COOKIE);
    Digest::update(&mut hasher, pk.0);
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// Compute a Blake2s-MAC-128 over `data` with the given 32-byte key. The
/// output (16 bytes) is the WireGuard MAC1/MAC2 form.
pub(crate) fn blake2s_mac_128(key: &[u8], data: &[u8]) -> [u8; BLAKE2S_128_SIZE] {
    let mut mac =
        <Blake2sMac128 as MacKeyInit>::new_from_slice(key).expect("Blake2sMac accepts <=32B keys");
    Update::update(&mut mac, data);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; BLAKE2S_128_SIZE];
    buf.copy_from_slice(&out);
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
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&nonce_counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(nonce, Payload { msg: pt, aad: ad })
        .expect("AEAD encrypt cannot fail for valid inputs")
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
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&nonce_counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ct, aad: ad })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aead open failed"))
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
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&nonce_counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    // Use a Vec buffer because AeadInPlace requires a buffer trait we
    // implement only for Vec by default. Copying once is acceptable here;
    // hot-path callers (Server) can later switch to `encrypt_in_place_detached`.
    let mut buf: Vec<u8> = pt.to_vec();
    cipher
        .encrypt_in_place(nonce, ad, &mut buf)
        .expect("AEAD encrypt_in_place cannot fail for valid inputs");
    dst[..buf.len()].copy_from_slice(&buf);
    buf.len()
}

/// XChaCha20-Poly1305 seal with a 24-byte nonce. Used to encrypt cookies.
#[allow(dead_code)] // used once cookie reply support lands
pub(crate) fn xaead_seal(key: &[u8; 32], nonce: &[u8; 24], pt: &[u8], ad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad: ad })
        .expect("XChaCha encrypt cannot fail for valid inputs")
}

/// XChaCha20-Poly1305 open with a 24-byte nonce.
#[allow(dead_code)] // used once cookie reply support lands
pub(crate) fn xaead_open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ct: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: ad })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "xaead open failed"))
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
}
