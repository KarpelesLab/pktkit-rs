//! The byte stream every transfer carries, shared with the guest agent
//! (which includes this file by path): both ends generate it from a seed,
//! so a receiver checks every byte against what the sender must have sent,
//! and reports where the first difference is, not only that there is one.

/// An endless xorshift64* stream of bytes.
#[derive(Debug, Clone)]
pub struct Pattern {
    state: u64,
    word: [u8; 8],
    used: usize,
}

impl Pattern {
    pub fn new(seed: u64) -> Pattern {
        Pattern {
            // xorshift has one fixed point, zero; any seed maps off it.
            state: seed ^ 0x9e37_79b9_7f4a_7c15 | 1,
            word: [0; 8],
            used: 8,
        }
    }

    fn next_word(&mut self) -> [u8; 8] {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes()
    }

    /// The next `buf.len()` bytes of the stream.
    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() && self.used < 8 {
            buf[i] = self.word[self.used];
            self.used += 1;
            i += 1;
        }
        let (words, rest) = buf[i..].as_chunks_mut::<8>();
        for w in words {
            *w = self.next_word();
        }
        if !rest.is_empty() {
            self.word = self.next_word();
            let n = rest.len();
            rest.copy_from_slice(&self.word[..n]);
            self.used = n;
        }
    }
}

/// Checks received bytes against the stream.
#[derive(Debug)]
pub struct Verifier {
    pattern: Pattern,
    scratch: Vec<u8>,
    /// Bytes checked so far.
    pub len: u64,
    /// Offset of the first byte that differed.
    pub bad_at: Option<u64>,
}

impl Verifier {
    pub fn new(seed: u64) -> Verifier {
        Verifier {
            pattern: Pattern::new(seed),
            scratch: Vec::new(),
            len: 0,
            bad_at: None,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.scratch.resize(data.len(), 0);
        self.pattern.fill(&mut self.scratch);
        if self.bad_at.is_none()
            && let Some(i) = data.iter().zip(&self.scratch).position(|(a, b)| a != b)
        {
            self.bad_at = Some(self.len + i as u64);
        }
        self.len += data.len() as u64;
    }

    /// Whether exactly `expected` bytes arrived, all of them right.
    pub fn ok(&self, expected: u64) -> bool {
        self.bad_at.is_none() && self.len == expected
    }
}

/// The seed of the stream a connection's server sends, given the client's:
/// the two directions carry different bytes, so data reflected back the
/// wrong way cannot pass for the real thing.
pub fn reverse_seed(seed: u64) -> u64 {
    seed.rotate_left(32) ^ 0x5555_5555_5555_5555
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunking_does_not_change_the_stream() {
        let mut whole = vec![0u8; 1000];
        Pattern::new(7).fill(&mut whole);
        let mut p = Pattern::new(7);
        let mut pieces = Vec::new();
        for n in [1usize, 3, 8, 13, 100, 875] {
            let mut b = vec![0u8; n];
            p.fill(&mut b);
            pieces.extend_from_slice(&b);
        }
        assert_eq!(whole, pieces);
        let mut v = Verifier::new(7);
        v.update(&whole[..500]);
        v.update(&whole[500..]);
        assert!(v.ok(1000));
        let mut bad = whole.clone();
        bad[777] ^= 1;
        let mut v = Verifier::new(7);
        v.update(&bad);
        assert_eq!(v.bad_at, Some(777));
    }
}
