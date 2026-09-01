//! TLS PRF used by OpenVPN key-method 2 to derive the data-channel keys.
//!
//! OpenVPN's key-method 2 builds the master secret with the **TLS 1.0** PRF
//! (`prf10`, MD5 XOR SHA1 per RFC 2246 §5) and is also able to expand with the
//! **TLS 1.2** PRF (`prf12`, a single `P_hash` over a configurable hash, RFC
//! 5246 §5). Ported from the Go `prf.go`.
//!
//! The control channel itself is TLS; this PRF is *only* the OpenVPN
//! key-derivation step that runs over the negotiated random material, so it
//! lives here in the data-channel crypto layer rather than in the TLS code.

use purecrypto::hash::{Digest, Hmac, Mac, Md5, Sha1, Sha256};

/// Split the secret in half for the TLS 1.0 PRF. The halves overlap by one
/// byte when the length is odd, which is what RFC 2246 §5 specifies.
fn split_premaster_secret(secret: &[u8]) -> (&[u8], &[u8]) {
    let s1 = &secret[0..secret.len().div_ceil(2)];
    let s2 = &secret[secret.len() / 2..];
    (s1, s2)
}

/// The `P_hash` function (RFC 4346 §5), generic over the hash.
///
/// ```text
/// A(0) = seed
/// A(i) = HMAC(secret, A(i-1))
/// P_hash = HMAC(secret, A(1) || seed) || HMAC(secret, A(2) || seed) || ...
/// ```
fn p_hash<H: Digest>(result: &mut [u8], secret: &[u8], seed: &[u8]) {
    let out_len = H::OUTPUT_LEN;
    let mut a = H::zeroed_output();
    let a = a.as_mut();

    // A(1) = HMAC(secret, seed)
    let mut mac = Hmac::<H>::new(secret);
    mac.update(seed);
    mac.finalize_into(a);

    let mut written = 0;
    while written < result.len() {
        // HMAC(secret, A(i) || seed) -> one output block.
        let mut block = H::zeroed_output();
        let block = block.as_mut();
        let mut mac = Hmac::<H>::new(secret);
        mac.update(a);
        mac.update(seed);
        mac.finalize_into(block);

        let n = (result.len() - written).min(out_len);
        result[written..written + n].copy_from_slice(&block[..n]);
        written += n;

        // A(i+1) = HMAC(secret, A(i))
        let mut next = H::zeroed_output();
        let next = next.as_mut();
        let mut mac = Hmac::<H>::new(secret);
        mac.update(a);
        mac.finalize_into(next);
        a.copy_from_slice(next);
    }
}

/// TLS 1.0 PRF (RFC 2246 §5): MD5 over the first half XOR SHA-1 over the second.
pub fn prf10(result: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
    let mut label_and_seed = Vec::with_capacity(label.len() + seed.len());
    label_and_seed.extend_from_slice(label);
    label_and_seed.extend_from_slice(seed);

    let (s1, s2) = split_premaster_secret(secret);
    p_hash::<Md5>(result, s1, &label_and_seed);
    let mut result2 = vec![0u8; result.len()];
    p_hash::<Sha1>(&mut result2, s2, &label_and_seed);
    for (r, b) in result.iter_mut().zip(result2.iter()) {
        *r ^= *b;
    }
}

/// TLS 1.2 PRF (RFC 5246 §5) using SHA-256. OpenVPN key-method 2 derives its
/// master/expansion with the TLS-1.0 PRF ([`prf10`]); this variant is provided
/// for completeness (and exercised by the tests) for future tls-crypt-v2 use.
#[allow(dead_code)]
pub fn prf12_sha256(result: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
    let mut label_and_seed = Vec::with_capacity(label.len() + seed.len());
    label_and_seed.extend_from_slice(label);
    label_and_seed.extend_from_slice(seed);
    p_hash::<Sha256>(result, secret, &label_and_seed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn md5_bytes(data: &[u8]) -> [u8; 16] {
        Md5::digest(data)
    }

    #[test]
    fn md5_known_vectors() {
        // RFC 1321 test suite.
        assert_eq!(
            md5_bytes(b""),
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );
        assert_eq!(
            md5_bytes(b"abc"),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ]
        );
        assert_eq!(
            md5_bytes(b"The quick brown fox jumps over the lazy dog"),
            [
                0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4,
                0x19, 0xd6
            ]
        );
    }

    #[test]
    fn md5_long_input_spans_blocks() {
        // 1,000,000 'a's per RFC 1321.
        let mut h = Md5::new();
        let chunk = vec![b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        let out = h.finalize();
        assert_eq!(
            out,
            [
                0x77, 0x07, 0xd6, 0xae, 0x4e, 0x02, 0x7c, 0x70, 0xee, 0xa2, 0xa9, 0x35, 0xc2, 0x29,
                0x6f, 0x21
            ]
        );
    }

    #[test]
    fn prf10_deterministic_and_nonzero() {
        let secret = [0u8; 48];
        let label = b"test label";
        let mut seed = [0u8; 64];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut r1 = [0u8; 128];
        let mut r2 = [0u8; 128];
        prf10(&mut r1, &secret, label, &seed);
        prf10(&mut r2, &secret, label, &seed);
        assert_eq!(r1, r2);
        assert!(r1.iter().any(|&b| b != 0));
    }

    #[test]
    fn prf10_different_secrets_differ() {
        let secret1 = [0u8; 48];
        let mut secret2 = [0u8; 48];
        secret2[0] = 1;
        let label = b"key expansion";
        let seed = [0u8; 64];
        let mut r1 = [0u8; 128];
        let mut r2 = [0u8; 128];
        prf10(&mut r1, &secret1, label, &seed);
        prf10(&mut r2, &secret2, label, &seed);
        assert_ne!(r1, r2);
    }

    #[test]
    fn prf10_various_lengths_nonzero() {
        let secret = [0u8; 48];
        let label = b"key expansion";
        let seed = [0u8; 64];
        for size in [48usize, 128, 256] {
            let mut r = vec![0u8; size];
            prf10(&mut r, &secret, label, &seed);
            assert!(r.iter().any(|&b| b != 0), "len {size}");
        }
    }

    #[test]
    fn prf12_deterministic() {
        let secret = [0u8; 48];
        let label = b"test label";
        let seed = [0u8; 64];
        let mut r1 = [0u8; 128];
        let mut r2 = [0u8; 128];
        prf12_sha256(&mut r1, &secret, label, &seed);
        prf12_sha256(&mut r2, &secret, label, &seed);
        assert_eq!(r1, r2);
    }

    #[test]
    fn split_secret_lengths() {
        let secret = [0u8; 48];
        let (s1, s2) = split_premaster_secret(&secret);
        assert_eq!(s1.len(), 24);
        assert_eq!(s2.len(), 24);
        let secret = [0u8; 49];
        let (s1, s2) = split_premaster_secret(&secret);
        assert_eq!(s1.len(), 25);
        assert_eq!(s2.len(), 25);
    }

    #[test]
    fn phash_nonzero() {
        let mut result = [0u8; 32];
        p_hash::<Sha256>(&mut result, b"secret", b"seed");
        assert!(result.iter().any(|&b| b != 0));
    }

    #[test]
    fn prf12_matches_rfc5705_style_hmac() {
        // Cross-check P_hash<SHA256> against a direct HMAC-SHA256 expansion of
        // one block to catch an HMAC bug. A(1)=HMAC(secret, seed);
        // out = HMAC(secret, A(1)||seed).
        let secret = b"abracadabra";
        let seed = b"open sesame";
        let mut a1 = Hmac::<Sha256>::new(secret);
        a1.update(seed);
        let mut a1_out = [0u8; 32];
        a1.finalize_into(&mut a1_out);

        let mut out = Hmac::<Sha256>::new(secret);
        out.update(&a1_out);
        out.update(seed);
        let mut expect = [0u8; 32];
        out.finalize_into(&mut expect);

        let mut got = [0u8; 32];
        p_hash::<Sha256>(&mut got, secret, seed);
        assert_eq!(got, expect);
    }
}
