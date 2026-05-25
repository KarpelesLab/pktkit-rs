//! SYN-cookie generator/validator for stateless TCP handshake completion.
//!
//! When a listener's accept queue is full, SYN cookies allow handshakes to
//! finish without allocating any per-connection state until the final ACK.
//! The tradeoff is that SYN-cookie-established connections do not negotiate
//! window scaling, SACK, or timestamps (the 32-bit ISS isn't wide enough).
//! This matches the Linux behavior.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::rand;

use super::segment::{flags, Segment};
use super::options::mss_option;

const COOKIE_COUNTER_PERIOD_SECS: u64 = 64;
const COOKIE_SECRET_ROTATION: Duration = Duration::from_secs(60);

/// MSS table — values indexed by 3 bits in the cookie.
const MSS_TABLE: [u16; 8] = [536, 1200, 1360, 1440, 1452, 1460, 4312, 8960];

/// SYN-cookie engine. One per listener.
pub struct SynCookies {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for SynCookies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SynCookies").finish_non_exhaustive()
    }
}

struct Inner {
    secret: [u8; 32],
    prev: [u8; 32],
    last_rotate: Instant,
}

impl Default for SynCookies {
    fn default() -> Self {
        Self::new()
    }
}

impl SynCookies {
    pub fn new() -> Self {
        let mut s = [0u8; 32];
        let mut p = [0u8; 32];
        rand::fill(&mut s);
        rand::fill(&mut p);
        Self {
            inner: Mutex::new(Inner {
                secret: s,
                prev: p,
                last_rotate: Instant::now(),
            }),
        }
    }

    /// Build a SYN-ACK whose ISS is a SYN cookie. No per-connection state
    /// is allocated. The caller is responsible for sending the segment.
    pub fn generate_syn_ack(&self, syn: &Segment, local_port: u16, mss: u16) -> Segment {
        let secret = {
            let mut g = self.inner.lock().unwrap();
            rotate_if_needed(&mut g);
            g.secret
        };
        let counter = (now_unix_seconds() / COOKIE_COUNTER_PERIOD_SECS) as u32 & 0x1F;
        let mss_idx = closest_mss_index(mss);
        let cookie = compute_cookie(
            &secret,
            syn.src_port,
            syn.dst_port,
            local_port,
            syn.seq,
            counter,
            mss_idx,
        );
        Segment {
            src_port: local_port,
            dst_port: syn.src_port,
            seq: cookie,
            ack: syn.seq.wrapping_add(1),
            flags: flags::SYN | flags::ACK,
            window: 65535,
            options: vec![mss_option(mss)],
            ..Default::default()
        }
    }

    /// Check whether a final ACK completes a SYN-cookie handshake.
    /// Returns `Some((mss, remote_isn))` if valid.
    pub fn validate_ack(&self, seg: &Segment, local_port: u16) -> Option<(u16, u32)> {
        if !seg.has_flag(flags::ACK) {
            return None;
        }
        let cookie = seg.ack.wrapping_sub(1);
        let counter = cookie & 0x1F;
        let mss_idx = ((cookie >> 5) & 0x07) as u8;
        let remote_isn = seg.seq.wrapping_sub(1);

        let (secret, prev) = {
            let mut g = self.inner.lock().unwrap();
            rotate_if_needed(&mut g);
            (g.secret, g.prev)
        };
        let now = (now_unix_seconds() / COOKIE_COUNTER_PERIOD_SECS) as u32 & 0x1F;

        for s in [&secret, &prev] {
            for delta in 0u32..=1 {
                let check_counter = now.wrapping_sub(delta) & 0x1F;
                if check_counter != counter {
                    continue;
                }
                let candidate = compute_cookie(
                    s,
                    seg.src_port,
                    seg.dst_port,
                    local_port,
                    remote_isn,
                    check_counter,
                    mss_idx,
                );
                if candidate == cookie {
                    return Some((MSS_TABLE[mss_idx as usize], remote_isn));
                }
            }
        }
        None
    }
}

fn rotate_if_needed(inner: &mut Inner) {
    if inner.last_rotate.elapsed() < COOKIE_SECRET_ROTATION {
        return;
    }
    inner.prev = inner.secret;
    rand::fill(&mut inner.secret);
    inner.last_rotate = Instant::now();
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Cookie layout (32 bits):
///   31..8 : truncated HMAC (24 bits)
///   7..5  : MSS table index (3 bits)
///   4..0  : counter (5 bits)
fn compute_cookie(
    secret: &[u8; 32],
    src_port: u16,
    dst_port: u16,
    local_port: u16,
    remote_isn: u32,
    counter: u32,
    mss_idx: u8,
) -> u32 {
    let mut buf = [0u8; 14];
    buf[0..2].copy_from_slice(&src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buf[4..6].copy_from_slice(&local_port.to_be_bytes());
    buf[6..10].copy_from_slice(&remote_isn.to_be_bytes());
    buf[10..14].copy_from_slice(&counter.to_be_bytes());

    let sum = hmac_sha256(secret, &buf);
    let hash24 = ((sum[0] as u32) << 16) | ((sum[1] as u32) << 8) | sum[2] as u32;
    (hash24 << 8) | (((mss_idx & 0x07) as u32) << 5) | (counter & 0x1F)
}

fn closest_mss_index(mss: u16) -> u8 {
    let mut best = 0u8;
    for (i, v) in MSS_TABLE.iter().enumerate() {
        if *v <= mss {
            best = i as u8;
        }
    }
    best
}

// --- HMAC-SHA256 (RFCs 2104, 6234) ----------------------------------------
//
// std-only port: we implement SHA-256 and HMAC here rather than pulling in a
// dependency. The cookie path is not performance-critical (one HMAC per
// half-open connection) so the loop is straightforward.

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = sha256(key);
        k_block[..32].copy_from_slice(&h);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    // inner = SHA256(ipad || msg)
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);
    // outer = SHA256(opad || inner_hash)
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

// --- SHA-256 (FIPS 180-4) -------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Pre-processing: append 0x80, pad with zeros to 56 mod 64, then 8-byte length.
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let mut padded: Vec<u8> = Vec::with_capacity(msg.len() + 72);
    padded.extend_from_slice(msg);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in padded.chunks_exact(64) {
        for (i, word) in chunk.chunks_exact(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(mj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty_string() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = sha256(b"");
        assert_eq!(
            h,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn sha256_abc() {
        // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let h = sha256(b"abc");
        assert_eq!(
            h,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    #[test]
    fn cookie_roundtrip() {
        let sc = SynCookies::new();
        let syn = Segment {
            src_port: 12345,
            dst_port: 80,
            seq: 1_000_000,
            flags: flags::SYN,
            window: 65535,
            ..Default::default()
        };
        let synack = sc.generate_syn_ack(&syn, 80, 1460);
        assert_eq!(synack.src_port, 80);
        assert_eq!(synack.dst_port, 12345);
        assert_eq!(synack.ack, syn.seq + 1);
        assert_eq!(synack.flags, flags::SYN | flags::ACK);

        let ack = Segment {
            src_port: 12345,
            dst_port: 80,
            seq: syn.seq + 1,
            ack: synack.seq + 1,
            flags: flags::ACK,
            window: 65535,
            ..Default::default()
        };
        let (mss, isn) = sc.validate_ack(&ack, 80).expect("valid cookie");
        assert_eq!(isn, syn.seq);
        assert_eq!(mss, 1460);
    }

    #[test]
    fn cookie_rejects_random_ack() {
        let sc = SynCookies::new();
        let ack = Segment {
            src_port: 12345,
            dst_port: 80,
            seq: 5000,
            ack: 99999,
            flags: flags::ACK,
            ..Default::default()
        };
        assert!(sc.validate_ack(&ack, 80).is_none());
    }

    #[test]
    fn cookie_rejects_tampered_ack() {
        let sc = SynCookies::new();
        let syn = Segment {
            src_port: 12345,
            dst_port: 80,
            seq: 1_000_000,
            flags: flags::SYN,
            ..Default::default()
        };
        let synack = sc.generate_syn_ack(&syn, 80, 1460);
        let ack = Segment {
            src_port: 12345,
            dst_port: 80,
            seq: syn.seq + 1,
            ack: (synack.seq + 1) ^ 0x0001_0000,
            flags: flags::ACK,
            ..Default::default()
        };
        assert!(sc.validate_ack(&ack, 80).is_none());
    }
}
