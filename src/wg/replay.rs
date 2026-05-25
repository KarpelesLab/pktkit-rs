//! Sliding-window replay protection for the WireGuard data channel.
//!
//! Ported from `wg/replay.go`. The window is a fixed-size bitmap; counters
//! older than `position` are rejected outright, counters within the window
//! are accepted exactly once (a bit flip on first sight), and counters past
//! the window cause the window to advance.

use std::sync::Mutex;

use crate::wg::constants::WINDOW_SIZE;

/// Number of 64-bit words backing the window bitmap.
const BITMAP_WORDS: usize = WINDOW_SIZE / 64;

/// Bitmap-based sliding window. `CheckReplay` is the only public operation;
/// it returns `true` if the counter has already been seen (or is too old).
#[derive(Debug)]
pub struct SlidingWindow {
    inner: Mutex<Inner>,
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct Inner {
    bitmap: [u64; BITMAP_WORDS],
    /// Lowest counter representable in the bitmap (always a multiple of 64).
    position: u64,
    /// Index of the bitmap word that currently holds `position..position+64`
    /// — the bitmap is a ring buffer; this is the rotation offset.
    offset: u64,
    initialized: bool,
}

impl SlidingWindow {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                bitmap: [0; BITMAP_WORDS],
                position: 0,
                offset: 0,
                initialized: false,
            }),
        }
    }

    /// Check whether `counter` has been seen before. Returns `true` if it is a
    /// replay (either already-seen or older than the window). Otherwise marks
    /// the counter as seen and returns `false`.
    pub fn check_replay(&self, counter: u64) -> bool {
        let mut g = self.inner.lock().expect("replay mutex poisoned");

        if !g.initialized {
            g.position = counter - (counter % 64);
            g.offset = 0;
            g.bitmap = [0; BITMAP_WORDS];
            g.initialized = true;
        }

        // Too old: below the window.
        if counter < g.position {
            return true;
        }

        // Past the window: advance and accept.
        if counter >= g.position + WINDOW_SIZE as u64 {
            let mut diff = counter - (g.position + WINDOW_SIZE as u64) + 1;
            let rem = diff % 64;
            if rem != 0 {
                diff += 64 - rem;
            }

            g.position += diff;

            if diff >= WINDOW_SIZE as u64 {
                g.bitmap = [0; BITMAP_WORDS];
                g.offset = 0;
            } else {
                let word_shift = diff / 64;
                let bitmap_words = BITMAP_WORDS as u64;

                let new_offset = (g.offset + word_shift) % bitmap_words;

                // Zero the freshly-uncovered slots (one word per shift).
                for i in 0..word_shift {
                    let idx = (new_offset + bitmap_words - 1 - i) % bitmap_words;
                    g.bitmap[idx as usize] = 0;
                }

                g.offset = new_offset;
            }

            let new_pos = counter - g.position;
            let word_index = (g.offset + new_pos / 64) % BITMAP_WORDS as u64;
            let bit_index = new_pos % 64;
            g.bitmap[word_index as usize] |= 1u64 << bit_index;
            return false;
        }

        // Within the window: bitmap check + set.
        let pos = counter - g.position;
        let word_index = (g.offset + pos / 64) % BITMAP_WORDS as u64;
        let bit_index = pos % 64;

        let mask = 1u64 << bit_index;
        if g.bitmap[word_index as usize] & mask != 0 {
            return true;
        }
        g.bitmap[word_index as usize] |= mask;
        false
    }

    /// Reset the window. Subsequent `check_replay` calls re-initialize on the
    /// first counter they see.
    pub fn reset(&self) {
        let mut g = self.inner.lock().expect("replay mutex poisoned");
        g.initialized = false;
        g.bitmap = [0; BITMAP_WORDS];
        g.position = 0;
        g.offset = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_counter_accepted() {
        let w = SlidingWindow::new();
        assert!(!w.check_replay(0));
        assert!(!w.check_replay(1));
        assert!(!w.check_replay(WINDOW_SIZE as u64));
    }

    #[test]
    fn duplicate_rejected() {
        let w = SlidingWindow::new();
        assert!(!w.check_replay(42));
        assert!(w.check_replay(42));
    }

    #[test]
    fn old_counter_rejected_after_advance() {
        let w = SlidingWindow::new();
        let large = 100_000u64;
        assert!(!w.check_replay(large));
        // Anything more than WindowSize behind `large` should be rejected.
        assert!(w.check_replay(0));
    }

    #[test]
    fn within_window_accepts_each_unique_counter() {
        let w = SlidingWindow::new();
        // Walk through a contiguous span; each must be accepted exactly once.
        for i in 0..500u64 {
            assert!(!w.check_replay(i), "first sight at {} rejected", i);
            assert!(w.check_replay(i), "duplicate at {} accepted", i);
        }
    }

    #[test]
    fn out_of_order_within_window_works() {
        let w = SlidingWindow::new();
        for c in [10, 30, 20, 25, 5, 0, 1].iter().copied() {
            assert!(!w.check_replay(c), "fresh {} should be accepted", c);
        }
        // And again — all replays.
        for c in [10, 30, 20, 25, 5, 0, 1].iter().copied() {
            assert!(w.check_replay(c), "replay of {} should be rejected", c);
        }
    }

    #[test]
    fn jump_far_then_old() {
        let w = SlidingWindow::new();
        assert!(!w.check_replay(50));
        assert!(!w.check_replay(50 + WINDOW_SIZE as u64 + 1000));
        // 50 is now below the window; reject.
        assert!(w.check_replay(50));
    }

    #[test]
    fn reset_allows_replay() {
        let w = SlidingWindow::new();
        assert!(!w.check_replay(7));
        assert!(w.check_replay(7));
        w.reset();
        assert!(!w.check_replay(7));
    }
}
