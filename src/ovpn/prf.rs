//! TLS PRF used by OpenVPN key-method 2 to derive the data-channel keys.
//!
//! OpenVPN's key-method 2 builds the master secret with the **TLS 1.0** PRF
//! (`prf10`, MD5 XOR SHA1 per RFC 2246 §5) and is also able to expand with the
//! **TLS 1.2** PRF (`prf12`, a single `P_hash` over a configurable hash, RFC
//! 5246 §5). Ported from the Go `prf.go`.
//!
//! The control channel itself is TLS handled by rustls; this PRF is *only* the
//! OpenVPN key-derivation step that runs over the negotiated random material,
//! so it lives here in the data-channel crypto layer rather than in rustls.
//!
//! MD5 is required for `prf10` but is not provided by any of the RustCrypto
//! crates pulled in by the `ovpn` feature, so a small, self-contained MD5 is
//! implemented here. SHA-1 / SHA-256 come from the `sha1` / `sha2` crates via
//! a tiny internal hash abstraction so a single `p_hash` implementation serves
//! every variant.

use sha1::{Digest, Sha1};
use sha2::Sha256;

/// Block size (bytes) and a streaming hash, enough to implement HMAC.
trait Hash {
    const BLOCK: usize;
    const OUT: usize;
    fn reset(&mut self);
    fn update(&mut self, data: &[u8]);
    /// Finalize into `out` (length `OUT`) and reset for reuse.
    fn finish(&mut self, out: &mut [u8]);
}

// --- SHA-1 / SHA-256 wrappers over RustCrypto ------------------------------

#[derive(Default)]
struct Sha1Hash(Sha1);
impl Hash for Sha1Hash {
    const BLOCK: usize = 64;
    const OUT: usize = 20;
    fn reset(&mut self) {
        self.0 = Sha1::new();
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finish(&mut self, out: &mut [u8]) {
        let d = std::mem::take(&mut self.0).finalize();
        out[..Self::OUT].copy_from_slice(&d);
    }
}

#[derive(Default)]
struct Sha256Hash(Sha256);
impl Hash for Sha256Hash {
    const BLOCK: usize = 64;
    const OUT: usize = 32;
    fn reset(&mut self) {
        self.0 = Sha256::new();
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finish(&mut self, out: &mut [u8]) {
        let d = std::mem::take(&mut self.0).finalize();
        out[..Self::OUT].copy_from_slice(&d);
    }
}

// --- minimal MD5 (RFC 1321) -------------------------------------------------

struct Md5 {
    state: [u32; 4],
    buf: [u8; 64],
    buflen: usize,
    len: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Md5 {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            buf: [0; 64],
            buflen: 0,
            len: 0,
        }
    }
}

impl Md5 {
    #[rustfmt::skip]
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    #[rustfmt::skip]
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    fn process(state: &mut [u32; 4], block: &[u8; 64]) {
        let mut m = [0u32; 16];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let [mut a, mut b, mut c, mut d] = *state;
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f
                .wrapping_add(a)
                .wrapping_add(Self::K[i])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(Self::S[i]));
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
}

impl Hash for Md5 {
    const BLOCK: usize = 64;
    const OUT: usize = 16;

    fn reset(&mut self) {
        *self = Md5::default();
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.buflen > 0 {
            let need = 64 - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                let block = self.buf;
                Md5::process(&mut self.state, &block);
                self.buflen = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            Md5::process(&mut self.state, &block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    fn finish(&mut self, out: &mut [u8]) {
        let bit_len = self.len.wrapping_mul(8);
        // Padding: 0x80 then zeros, last 8 bytes = length in bits (LE).
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let pad_len = if self.buflen < 56 {
            56 - self.buflen
        } else {
            120 - self.buflen
        };
        self.update_no_len(&pad[..pad_len]);
        self.update_no_len(&bit_len.to_le_bytes());

        for (i, s) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&s.to_le_bytes());
        }
        self.reset();
    }
}

impl Md5 {
    // Like update but without counting toward the message length (used for the
    // padding/length tail which must not feed back into the length field).
    fn update_no_len(&mut self, mut data: &[u8]) {
        if self.buflen > 0 {
            let need = 64 - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                let block = self.buf;
                Md5::process(&mut self.state, &block);
                self.buflen = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            Md5::process(&mut self.state, &block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }
}

// --- HMAC + P_hash ----------------------------------------------------------

/// HMAC over the internal `Hash` abstraction. Holds the ipad/opad-keyed inner
/// state precomputed once so it can be reset between P_hash iterations.
struct Hmac<H: Hash + Default> {
    inner: H,
    ikey: [u8; 128],
    okey: [u8; 128],
}

impl<H: Hash + Default> Hmac<H> {
    fn new(key: &[u8]) -> Hmac<H> {
        let mut ikey = [0u8; 128];
        let mut okey = [0u8; 128];

        // Keys longer than the block are hashed first.
        let mut keybuf = [0u8; 64];
        let k: &[u8] = if key.len() > H::BLOCK {
            let mut h = H::default();
            h.update(key);
            h.finish(&mut keybuf);
            &keybuf[..H::OUT]
        } else {
            key
        };

        ikey[..H::BLOCK].fill(0x36);
        okey[..H::BLOCK].fill(0x5c);
        for (i, &b) in k.iter().enumerate() {
            ikey[i] ^= b;
            okey[i] ^= b;
        }

        let mut inner = H::default();
        inner.update(&ikey[..H::BLOCK]);
        Hmac { inner, ikey, okey }
    }

    fn reset(&mut self) {
        self.inner.reset();
        self.inner.update(&self.ikey[..H::BLOCK]);
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize into `out` (length `H::OUT`) and reset for the next message.
    fn finish(&mut self, out: &mut [u8]) {
        let mut inner_out = [0u8; 64];
        self.inner.finish(&mut inner_out[..H::OUT]);
        let mut outer = H::default();
        outer.update(&self.okey[..H::BLOCK]);
        outer.update(&inner_out[..H::OUT]);
        outer.finish(&mut out[..H::OUT]);
        self.reset();
    }
}

/// Split a premaster secret in two as specified in RFC 4346 §5.
fn split_premaster_secret(secret: &[u8]) -> (&[u8], &[u8]) {
    let s1 = &secret[0..secret.len().div_ceil(2)];
    let s2 = &secret[secret.len() / 2..];
    (s1, s2)
}

/// The `P_hash` function (RFC 4346 §5), generic over the hash.
fn p_hash<H: Hash + Default>(result: &mut [u8], secret: &[u8], seed: &[u8]) {
    let mut hmac = Hmac::<H>::new(secret);
    hmac.update(seed);
    let mut a = [0u8; 64];
    hmac.finish(&mut a[..H::OUT]);

    let mut j = 0;
    let mut b = [0u8; 64];
    while j < result.len() {
        hmac.update(&a[..H::OUT]);
        hmac.update(seed);
        hmac.finish(&mut b[..H::OUT]);
        let n = (result.len() - j).min(H::OUT);
        result[j..j + n].copy_from_slice(&b[..n]);
        j += H::OUT;

        hmac.update(&a[..H::OUT]);
        let mut a2 = [0u8; 64];
        hmac.finish(&mut a2[..H::OUT]);
        a[..H::OUT].copy_from_slice(&a2[..H::OUT]);
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
    p_hash::<Sha1Hash>(&mut result2, s2, &label_and_seed);
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
    p_hash::<Sha256Hash>(result, secret, &label_and_seed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn md5_bytes(data: &[u8]) -> [u8; 16] {
        let mut h = Md5::default();
        h.update(data);
        let mut out = [0u8; 16];
        h.finish(&mut out);
        out
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
        let mut h = Md5::default();
        let chunk = vec![b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        let mut out = [0u8; 16];
        h.finish(&mut out);
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
        p_hash::<Sha256Hash>(&mut result, b"secret", b"seed");
        assert!(result.iter().any(|&b| b != 0));
    }

    #[test]
    fn prf12_matches_rfc5705_style_hmac() {
        // Cross-check P_hash<SHA256> against a direct HMAC-SHA256 expansion of
        // one block to catch an HMAC bug. A(1)=HMAC(secret, seed);
        // out = HMAC(secret, A(1)||seed).
        use hmac::{Mac, SimpleHmac};
        type HmacSha256 = SimpleHmac<Sha256>;
        let secret = b"abracadabra";
        let seed = b"open sesame";
        let mut a1 = HmacSha256::new_from_slice(secret).unwrap();
        a1.update(seed);
        let a1 = a1.finalize().into_bytes();
        let mut out = HmacSha256::new_from_slice(secret).unwrap();
        out.update(&a1);
        out.update(seed);
        let expect = out.finalize().into_bytes();

        let mut got = [0u8; 32];
        p_hash::<Sha256Hash>(&mut got, secret, seed);
        assert_eq!(&got[..], &expect[..]);
    }
}
