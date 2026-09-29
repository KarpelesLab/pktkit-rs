//! Waking a driver's tick thread when a connection's next timer is due.
//!
//! The drivers (`vclient`, `slirp`) run every connection's timers from one
//! thread. Polling on a fixed interval fires each timer up to that
//! interval late, which for a delayed ACK (40 ms) or RACK's reordering timer
//! (a quarter of an RTT) is most of the timer. Instead the thread sleeps until
//! the earliest deadline, and a connection whose deadline moves earlier
//! than that (data sent, a delayed ACK armed) wakes it.

use crate::time::Instant;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// Timers closer together than this are run together: the floor under a
/// sleep, so a deadline that somehow stays in the past cannot spin the
/// thread.
const GRANULARITY: Duration = Duration::from_millis(1);

pub(crate) struct Alarm {
    base: Instant,
    /// When the tick thread next wakes, in nanoseconds past `base`.
    /// `u64::MAX` while it is running the timers: every deadline armed
    /// meanwhile then lowers it, and the thread sleeps until the earliest.
    at: AtomicU64,
    lock: Mutex<()>,
    wake: Condvar,
}

impl std::fmt::Debug for Alarm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Alarm").finish_non_exhaustive()
    }
}

impl Alarm {
    pub(crate) fn new() -> Self {
        Self {
            base: Instant::now(),
            at: AtomicU64::new(u64::MAX),
            lock: Mutex::new(()),
            wake: Condvar::new(),
        }
    }

    fn nanos(&self, t: Instant) -> u64 {
        let d = t.saturating_duration_since(self.base);
        u64::try_from(d.as_nanos()).unwrap_or(u64::MAX - 1)
    }

    /// A connection's earliest timer is now `deadline`: have the tick
    /// thread up in time for it. Cheap when it already is, which is nearly
    /// always, so call it after anything that may have moved the deadline.
    pub(crate) fn arm(&self, deadline: Option<Instant>) {
        let Some(d) = deadline else {
            return;
        };
        let n = self.nanos(d);
        if self.at.load(Ordering::Acquire) <= n {
            return;
        }
        if self.at.fetch_min(n, Ordering::AcqRel) > n {
            // Under the lock, so the sleeper is either still to read `at`
            // or already waiting for this notification.
            let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
            self.wake.notify_one();
        }
    }

    /// The tick thread is about to run the timers: from here on, whatever
    /// the connections arm, as each is ticked or by their own traffic, sets
    /// the next wake.
    pub(crate) fn begin(&self) {
        self.at.store(u64::MAX, Ordering::Release);
    }

    /// Sleep until the earliest deadline armed since [`begin`](Self::begin),
    /// or `latest`, whichever is sooner, and at least [`GRANULARITY`].
    pub(crate) fn sleep_until(&self, latest: Instant) {
        let floor = self.nanos(Instant::now() + GRANULARITY);
        self.at.fetch_min(self.nanos(latest), Ordering::AcqRel);
        let mut g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let at = self.at.load(Ordering::Acquire).max(floor);
            let now = self.nanos(Instant::now());
            if now >= at {
                return;
            }
            let wait = crate::time::wait_slice(Duration::from_nanos(at - now));
            g = match self.wake.wait_timeout(g, wait) {
                Ok((g, _)) => g,
                Err(e) => e.into_inner().0,
            };
        }
    }

    /// Wake the tick thread now, as when its owner shuts down.
    pub(crate) fn ring(&self) {
        self.at.store(0, Ordering::Release);
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.wake.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn sleeps_until_the_earliest_deadline() {
        let alarm = Alarm::new();
        alarm.begin();
        let start = Instant::now();
        alarm.arm(Some(start + Duration::from_millis(20)));
        alarm.arm(Some(start + Duration::from_secs(5)));
        alarm.sleep_until(start + Duration::from_secs(10));
        let slept = start.elapsed();
        assert!(slept >= Duration::from_millis(20), "{slept:?}");
        assert!(slept < Duration::from_secs(5), "{slept:?}");
    }

    /// A delayed ACK armed for 40 ms went out after 50 on macOS, whose
    /// timer coalescing let the wait run over by up to 10 ms: the tick
    /// thread wakes on time now, within the median (see
    /// `crate::time::wait_slice`).
    #[test]
    fn wakes_on_time() {
        let alarm = Alarm::new();
        let mut late = Vec::new();
        for _ in 0..7 {
            alarm.begin();
            let due = Instant::now() + Duration::from_millis(25);
            alarm.arm(Some(due));
            alarm.sleep_until(due + Duration::from_secs(10));
            late.push(Instant::now().saturating_duration_since(due));
        }
        late.sort();
        assert!(late[3] < Duration::from_millis(3), "late by {late:?}");
    }

    #[test]
    fn an_earlier_deadline_wakes_a_sleeper() {
        let alarm = Arc::new(Alarm::new());
        alarm.begin();
        let start = Instant::now();
        let a = alarm.clone();
        let sleeper = std::thread::spawn(move || a.sleep_until(start + Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(20));
        alarm.arm(Some(Instant::now()));
        sleeper.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(30));
    }

    #[test]
    fn a_later_deadline_does_not_delay_an_earlier_one() {
        let alarm = Alarm::new();
        alarm.begin();
        let start = Instant::now();
        alarm.arm(Some(start + Duration::from_millis(10)));
        alarm.arm(Some(start + Duration::from_secs(60)));
        alarm.arm(None);
        alarm.sleep_until(start + Duration::from_secs(60));
        assert!(start.elapsed() < Duration::from_secs(60));
    }
}
