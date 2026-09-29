//! The clock pktkit reads its timers from.
//!
//! Everywhere except `wasm32-unknown-unknown`, [`Instant`] *is*
//! [`std::time::Instant`], re-exported, so nothing changes for native callers.
//!
//! `wasm32-unknown-unknown` has no clock of its own: std's `Instant::now` and
//! `SystemTime::now` panic there. On that target [`Instant`] is pktkit's own
//! type with the same API, and both clocks come from the embedder through two
//! imports in the `pktkit` module, which a browser page supplies as:
//!
//! ```js
//! const imports = {
//!   pktkit: {
//!     now_ms: () => performance.now(), // monotonic, milliseconds
//!     unix_ms: () => Date.now(),       // wall clock, ms since the Unix epoch
//!   },
//!   // ...plus `purecrypto.random_get` when the `wg` or `ovpn` feature is on.
//! };
//! ```
//!
//! An import is only linked in if something reachable calls it, so a module
//! that never reads the clock does not need them. WASI targets have real
//! clocks and use std's.

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub use std::time::Instant;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub use host::Instant;

/// The current wall-clock time.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
#[inline]
pub(crate) fn system_now() -> std::time::SystemTime {
    std::time::SystemTime::now()
}

/// The current wall-clock time.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub(crate) fn system_now() -> std::time::SystemTime {
    let since = host::ms_to_duration(unsafe { host::unix_ms() });
    std::time::UNIX_EPOCH
        .checked_add(since)
        .unwrap_or(std::time::UNIX_EPOCH)
}

/// Host clocks hand back floats; anything negative or non-finite is a
/// broken embedder, and is read as the epoch rather than panicking. So is
/// anything past what a `Duration` holds, which `from_secs_f64` would panic
/// on: it saturates instead.
#[cfg(any(test, all(target_family = "wasm", target_os = "unknown")))]
fn ms_to_duration(ms: f64) -> std::time::Duration {
    use std::time::Duration;
    if ms.is_finite() && ms > 0.0 {
        Duration::try_from_secs_f64(ms / 1000.0).unwrap_or(Duration::MAX)
    } else {
        Duration::ZERO
    }
}

/// How long to wait, of the `remaining` time to a deadline, before looking
/// at the clock again, for a timer thread that must wake on time.
///
/// macOS coalesces timers: a thread of default QoS blocked in a timed wait
/// wakes up to half the timeout late, up to 10 ms, so a 25 ms wait ends
/// after 33 to 35. For a delay line or a TCP timer that is error of the
/// size of what it measures: an impaired link whose delay wanders by 10 ms
/// looks congested to a sender watching its RTT (HyStart ends slow start on
/// it), and a delayed ACK meant for 40 ms goes out after 50. Halving the
/// wait each time bounds the lateness by the last, short, wait's: tens of
/// microseconds, for a handful of extra wakeups. Elsewhere timers are
/// already precise (Linux's default slack is 50 µs), and the whole wait is
/// taken at once.
#[allow(dead_code)] // used by the timer threads of some features only
#[inline]
pub(crate) fn wait_slice(remaining: std::time::Duration) -> std::time::Duration {
    #[cfg(target_vendor = "apple")]
    {
        const FINE: std::time::Duration = std::time::Duration::from_micros(50);
        if remaining > FINE {
            return remaining / 2;
        }
    }
    remaining
}

/// Time since the Unix epoch, or zero if the clock is set before it.
#[inline]
#[allow(dead_code)] // unused under some feature sets
pub(crate) fn unix_now() -> std::time::Duration {
    system_now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod host {
    use core::ops::{Add, AddAssign, Sub, SubAssign};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    #[link(wasm_import_module = "pktkit")]
    unsafe extern "C" {
        /// Monotonic milliseconds from an arbitrary origin.
        pub(super) fn now_ms() -> f64;
        /// Milliseconds since the Unix epoch.
        pub(super) fn unix_ms() -> f64;
    }

    pub(super) use super::ms_to_duration;

    /// The latest reading handed out, in nanoseconds. Timer code assumes the
    /// clock never runs backwards; `performance.now()` promises that, but the
    /// import is whatever the embedder wired up, so it is enforced here.
    static LAST_NS: AtomicU64 = AtomicU64::new(0);

    /// A point on the monotonic clock. Mirrors [`std::time::Instant`].
    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
    pub struct Instant(Duration);

    impl Instant {
        /// The current time, from the `pktkit.now_ms` import.
        pub fn now() -> Instant {
            let d = ms_to_duration(unsafe { now_ms() });
            let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
            let prev = LAST_NS.fetch_max(ns, Ordering::Relaxed);
            Instant(Duration::from_nanos(ns.max(prev)))
        }

        /// Time elapsed from `earlier` to `self`; zero if `earlier` is later.
        pub fn duration_since(&self, earlier: Instant) -> Duration {
            self.saturating_duration_since(earlier)
        }

        /// Time elapsed from `earlier` to `self`; `None` if `earlier` is later.
        pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
            self.0.checked_sub(earlier.0)
        }

        /// Time elapsed from `earlier` to `self`; zero if `earlier` is later.
        pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
            self.0.saturating_sub(earlier.0)
        }

        /// Time elapsed since `self`.
        pub fn elapsed(&self) -> Duration {
            Instant::now().saturating_duration_since(*self)
        }

        /// `self + d`, or `None` on overflow.
        pub fn checked_add(&self, d: Duration) -> Option<Instant> {
            self.0.checked_add(d).map(Instant)
        }

        /// `self - d`, or `None` if that is before the clock's origin.
        pub fn checked_sub(&self, d: Duration) -> Option<Instant> {
            self.0.checked_sub(d).map(Instant)
        }
    }

    impl Add<Duration> for Instant {
        type Output = Instant;
        fn add(self, d: Duration) -> Instant {
            self.checked_add(d)
                .expect("overflow when adding duration to instant")
        }
    }

    impl AddAssign<Duration> for Instant {
        fn add_assign(&mut self, d: Duration) {
            *self = *self + d;
        }
    }

    impl Sub<Duration> for Instant {
        type Output = Instant;
        fn sub(self, d: Duration) -> Instant {
            self.checked_sub(d)
                .expect("overflow when subtracting duration from instant")
        }
    }

    impl SubAssign<Duration> for Instant {
        fn sub_assign(&mut self, d: Duration) {
            *self = *self - d;
        }
    }

    impl Sub<Instant> for Instant {
        type Output = Duration;
        fn sub(self, other: Instant) -> Duration {
            self.duration_since(other)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn host_clock_readings_never_panic() {
        assert_eq!(ms_to_duration(1500.0), Duration::from_millis(1500));
        assert_eq!(ms_to_duration(-1.0), Duration::ZERO);
        assert_eq!(ms_to_duration(f64::NAN), Duration::ZERO);
        assert_eq!(ms_to_duration(f64::INFINITY), Duration::ZERO);
        // Finite, but past what a Duration holds: an embedder bug, not a
        // reason to take the whole module down.
        assert_eq!(ms_to_duration(1e300), Duration::MAX);
        assert_eq!(ms_to_duration(f64::MAX), Duration::MAX);
    }

    /// On Apple hosts a wait is taken in halves, down to 50 µs, so the
    /// OS's timer slack (half the wait, up to 10 ms) only ever applies to
    /// a short last slice; elsewhere it is taken whole. Checked without a
    /// clock: how late a real wait ends says as much about the machine as
    /// about this.
    #[test]
    fn waits_are_sliced_where_timers_are_coarse() {
        let ms25 = Duration::from_millis(25);
        let tiny = Duration::from_micros(40);
        assert_eq!(wait_slice(tiny), tiny);
        assert_eq!(wait_slice(Duration::ZERO), Duration::ZERO);
        if cfg!(target_vendor = "apple") {
            assert_eq!(wait_slice(ms25), ms25 / 2);
            // Halving converges: a 25 ms wait is a handful of slices.
            let (mut left, mut slices) = (ms25, 0);
            while left > Duration::ZERO {
                let s = wait_slice(left).max(Duration::from_nanos(1));
                left = left.saturating_sub(s);
                slices += 1;
                assert!(slices < 32, "the wait never ends");
            }
        } else {
            assert_eq!(wait_slice(ms25), ms25);
        }
    }
}
