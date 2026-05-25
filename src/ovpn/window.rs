//! Replay protection via a bitmap-based sliding window (RFC 6479).
//!
//! Tracks which packet IDs have been seen so duplicates and replays are
//! rejected. Ported from the Go `window.go`. The window is 2048 bits wide and
//! advances forward as higher IDs arrive; IDs that fall before the window are
//! rejected as too old.

const REPLAY_WINDOW_SIZE: u64 = 2048; // bits
const WORDS: usize = (REPLAY_WINDOW_SIZE / 64) as usize;

/// A sliding replay window keyed by packet ID.
#[derive(Debug)]
pub struct Window {
    bitmap: [u64; WORDS],
    position: u64, // ID at the start of the bitmap (multiple of 64)
    offset: u64,   // ring-buffer offset within `bitmap`
    init: bool,
}

impl Default for Window {
    fn default() -> Self {
        Window::new()
    }
}

impl Window {
    pub fn new() -> Window {
        Window {
            bitmap: [0; WORDS],
            position: 0,
            offset: 0,
            init: false,
        }
    }

    /// Returns true if `id` is new (not a replay), recording it. Returns false
    /// if the ID has already been seen or is too old to track.
    pub fn check(&mut self, id: u32) -> bool {
        let counter = id as u64;

        if !self.init {
            self.position = counter - (counter % 64);
            self.offset = 0;
            self.init = true;
            self.bitmap = [0; WORDS];
        }

        // Too old.
        if counter < self.position {
            return false;
        }

        // Outside the window — advance it forward.
        if counter >= self.position + REPLAY_WINDOW_SIZE {
            let mut diff = counter - (self.position + REPLAY_WINDOW_SIZE) + 1;
            let n = diff % 64;
            if n != 0 {
                diff += 64 - n;
            }

            self.position += diff;

            if diff >= REPLAY_WINDOW_SIZE {
                self.bitmap = [0; WORDS];
                self.offset = 0;
            } else {
                let word_shift = diff / 64;
                let bitmap_words = WORDS as u64;
                let new_offset = (self.offset + word_shift) % bitmap_words;
                for i in 0..word_shift {
                    let idx = ((new_offset + bitmap_words - 1 - i) % bitmap_words) as usize;
                    self.bitmap[idx] = 0;
                }
                self.offset = new_offset;
            }

            let pos = counter - self.position;
            let word_index = ((self.offset + pos / 64) % WORDS as u64) as usize;
            let bit_index = pos % 64;
            self.bitmap[word_index] |= 1u64 << bit_index;
            return true;
        }

        // Within the window — consult the bitmap.
        let pos = counter - self.position;
        let word_index = ((self.offset + pos / 64) % WORDS as u64) as usize;
        let bit_index = pos % 64;

        let mask = 1u64 << bit_index;
        if self.bitmap[word_index] & mask != 0 {
            return false; // replay
        }

        self.bitmap[word_index] |= mask;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential() {
        let mut w = Window::new();
        for i in 0..100u32 {
            assert!(w.check(i), "sequential id {i} rejected");
        }
    }

    #[test]
    fn duplicate() {
        let mut w = Window::new();
        assert!(w.check(42));
        assert!(!w.check(42));
    }

    #[test]
    fn out_of_order() {
        let mut w = Window::new();
        w.check(0);
        w.check(1);
        w.check(2);
        assert!(w.check(10));
        assert!(w.check(5));
        assert!(!w.check(5));
    }

    #[test]
    fn old_reject() {
        let mut w = Window::new();
        for i in 0..(REPLAY_WINDOW_SIZE as u32 + 100) {
            w.check(i);
        }
        assert!(!w.check(0));
        assert!(!w.check(50));
    }

    #[test]
    fn reset() {
        let mut w = Window::new();
        w.check(0);
        w.check(1);
        let far_ahead = REPLAY_WINDOW_SIZE as u32 * 2;
        assert!(w.check(far_ahead));
        assert!(!w.check(0));
        assert!(!w.check(1));
    }

    #[test]
    fn large_gap() {
        let mut w = Window::new();
        w.check(0);
        let gap = REPLAY_WINDOW_SIZE as u32 - 100;
        assert!(w.check(gap));
        assert!(w.check(gap / 2));
    }

    #[test]
    fn init_nonzero() {
        let mut w = Window::new();
        assert!(w.check(1000));
        assert!(!w.check(1000));
        assert!(w.check(999));
    }
}
