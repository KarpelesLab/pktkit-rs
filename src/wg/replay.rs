//! Sliding-window replay protection for the WireGuard data channel.
//!
//! The algorithm is the kernel implementation's `counter_validate` (RFC 6479
//! style): a ring of 64-bit words, advanced a word at a time as higher
//! counters arrive. It accepts each counter once while it is within
//! `WINDOW_SIZE - 64` of the highest seen, and never one at or past
//! `REJECT_AFTER_MESSAGES`.
//!
//! [`check_replay`](SlidingWindow::check_replay) records the counter, so it
//! must only be called once the packet has authenticated: a forged packet
//! must not be able to move the window (whitepaper §5.4.6).

use std::sync::Mutex;

use crate::wg::constants::{REJECT_AFTER_MESSAGES, WINDOW_SIZE};

/// Number of 64-bit words backing the window bitmap.
const BITMAP_WORDS: usize = WINDOW_SIZE / 64;
/// How far behind the highest counter a packet may be and still be taken:
/// one word short of the bitmap, which holds the word being filled.
const WINDOW: u64 = (WINDOW_SIZE - 64) as u64;

/// Bitmap-based sliding window.
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
    /// One past the highest counter accepted; 0 before the first.
    next: u64,
}

impl Inner {
    fn too_old_or_invalid(&self, counter: u64) -> bool {
        // `counter + 1 + WINDOW` cannot overflow: counter < REJECT_AFTER_MESSAGES.
        counter >= REJECT_AFTER_MESSAGES || counter + 1 + WINDOW < self.next
    }
}

impl SlidingWindow {
    /// A window that has accepted no counter yet.
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                bitmap: [0; BITMAP_WORDS],
                next: 0,
            }),
        }
    }

    /// Whether `counter` would be rejected, without recording anything.
    /// Lets a receiver drop obvious replays before paying to decrypt them;
    /// a `false` here must still be confirmed by
    /// [`check_replay`](Self::check_replay) after decryption.
    pub fn is_replay(&self, counter: u64) -> bool {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.too_old_or_invalid(counter) {
            return true;
        }
        let (word, bit) = Self::slot(counter);
        counter < g.next && g.bitmap[word] & bit != 0
    }

    /// Check whether `counter` has been seen before. Returns `true` if it is a
    /// replay (already seen, too old, or past `REJECT_AFTER_MESSAGES`).
    /// Otherwise records it and returns `false`. Call only for packets that
    /// have authenticated.
    pub fn check_replay(&self, counter: u64) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.too_old_or_invalid(counter) {
            return true;
        }
        let their_next = counter + 1;
        if their_next > g.next {
            // Advance, clearing the words past the one holding the highest
            // counter up to the new one's: they still hold the previous lap.
            let cur = g.next.saturating_sub(1) / 64;
            let new = counter / 64;
            let clear = (new.saturating_sub(cur)).min(BITMAP_WORDS as u64);
            for i in 1..=clear {
                g.bitmap[((cur + i) % BITMAP_WORDS as u64) as usize] = 0;
            }
            g.next = their_next;
        }
        let (word, bit) = Self::slot(counter);
        let seen = g.bitmap[word] & bit != 0;
        g.bitmap[word] |= bit;
        seen
    }

    fn slot(counter: u64) -> (usize, u64) {
        (
            ((counter / 64) % BITMAP_WORDS as u64) as usize,
            1u64 << (counter % 64),
        )
    }

    /// Reset the window to its initial state.
    pub fn reset(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.bitmap = [0; BITMAP_WORDS];
        g.next = 0;
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
    fn lower_counters_than_the_first_are_accepted() {
        // The window starts at 0, not at whatever arrives first: a packet
        // reordered behind the first one to arrive is still good.
        let w = SlidingWindow::new();
        assert!(!w.check_replay(100));
        assert!(!w.check_replay(3));
        assert!(!w.check_replay(99));
    }

    #[test]
    fn window_edges() {
        let w = SlidingWindow::new();
        let top = 50_000u64;
        assert!(!w.check_replay(top));
        // `top - WINDOW` is the oldest still accepted.
        assert!(!w.check_replay(top - WINDOW));
        assert!(w.check_replay(top - WINDOW - 1));
        // Advancing by one word forgets exactly what fell out.
        assert!(!w.check_replay(top + 64));
        assert!(w.check_replay(top - WINDOW), "fell out of the window");
        assert!(!w.check_replay(top + 1));
        assert!(w.check_replay(top + 1));
    }

    #[test]
    fn advancing_from_the_end_of_a_word_clears_the_next() {
        // The highest counter (8191) ends a word, and the word after it
        // still holds counter 5 from the previous lap of the ring. 8197
        // lands on that word and is new.
        let w = SlidingWindow::new();
        for c in [5, 70, 8191] {
            assert!(!w.check_replay(c));
        }
        assert!(!w.check_replay(8197), "stale bit from counter 5");
    }

    /// Against a model that remembers every counter: accept a counter iff it
    /// is new and no more than WINDOW below the highest accepted.
    #[test]
    fn matches_a_reference_model() {
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20 {
            let w = SlidingWindow::new();
            let mut seen = std::collections::HashSet::new();
            let mut highest: Option<u64> = None;
            let mut base = 0u64;
            for _ in 0..20_000 {
                // Mostly near the top, sometimes far behind or far ahead.
                let c = match rnd() % 10 {
                    0 => base.saturating_sub(rnd() % 20_000),
                    1 => base + rnd() % 20_000,
                    _ => (base + rnd() % 200).saturating_sub(100),
                };
                let fresh = !seen.contains(&c) && highest.is_none_or(|h| c + WINDOW >= h);
                assert_eq!(
                    w.check_replay(c),
                    !fresh,
                    "counter {c}, highest {highest:?}"
                );
                if fresh {
                    seen.insert(c);
                    highest = Some(highest.map_or(c, |h| h.max(c)));
                    base = highest.unwrap();
                }
            }
        }
    }

    #[test]
    fn counters_near_the_limit_do_not_overflow() {
        let w = SlidingWindow::new();
        assert!(w.check_replay(u64::MAX), "past REJECT_AFTER_MESSAGES");
        assert!(w.check_replay(REJECT_AFTER_MESSAGES));
        assert!(!w.check_replay(REJECT_AFTER_MESSAGES - 1));
        assert!(w.check_replay(REJECT_AFTER_MESSAGES - 1));
        assert!(w.check_replay(0), "far below the window now");
    }

    #[test]
    fn is_replay_does_not_record() {
        let w = SlidingWindow::new();
        assert!(!w.is_replay(5));
        assert!(!w.is_replay(5));
        assert!(!w.check_replay(5));
        assert!(w.is_replay(5));
        assert!(w.is_replay(u64::MAX));
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
