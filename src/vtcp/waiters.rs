//! How the blocking drivers (`vclient`, `slirp`) hand segments to a
//! connection that application threads also use.
//!
//! One thread delivers a connection's segments, taking its lock for each;
//! the application's readers and writers take the same lock, and wait on a
//! `Condvar` for what they need. Waking them for every segment is simplest,
//! and costly: each one woken takes the lock back at once, and the
//! delivering thread, coming for the lock with the next segment, finds it
//! held and parks in the kernel. At a few hundred thousand segments a
//! second the two fell into lockstep, each waking the other for every
//! segment: a transfer on a clean, fast path ran at a tenth of its rate or
//! less, and stayed there, since every stall let the queue in front of the
//! delivering thread grow and the round trip with it. It set in at random,
//! seconds into a run, as thread placement happened to fall.
//!
//! Linux keeps its softirq off a lock the application holds (it queues the
//! segment to the socket's backlog instead), and wakes a writer only once a
//! good part of the send buffer is free (`sk_stream_write_space`). The same
//! two cures here: waiters are woken only for what can let them go on
//! ([`Waiters`]), and the delivering thread spins briefly for a lock an
//! application thread holds for a few microseconds rather than parking
//! ([`lock_for_delivery`]).

use super::conn::{Conn, State};
use std::sync::{LockResult, Mutex, MutexGuard, TryLockError};

/// How many times [`lock_for_delivery`] tries the lock before it waits:
/// some tens of microseconds, more than a reader or writer holds it for,
/// less than parking and being woken costs.
const DELIVERY_SPINS: u32 = 2000;

/// What a thread blocked on a connection may be waiting for, as it stood
/// before a segment or a timer: compared with after, whether a waiter is
/// worth waking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Waiters {
    state: State,
    closed: bool,
    fin: bool,
    writable: bool,
}

impl Waiters {
    pub(crate) fn of(conn: &Conn) -> Waiters {
        Waiters {
            state: conn.state(),
            closed: conn.is_closed(),
            fin: conn.fin_received(),
            writable: conn.writable(),
        }
    }

    /// Whether what `conn` went through since `self` was taken may let a
    /// waiter go on: data to read, a writer's room that was not there
    /// (see [`Conn::writable`]), or a change of state (a handshake done, a
    /// FIN, an end).
    pub(crate) fn wake(self, conn: &Conn) -> bool {
        let now = Waiters::of(conn);
        conn.readable() > 0
            || (now != self && (now.writable || now.state != self.state || now.closed || now.fin))
    }
}

/// Take a connection's lock for the thread delivering its segments,
/// spinning a little before parking: see the module's documentation.
/// Poisoning is reported as `Mutex::lock` reports it.
pub(crate) fn lock_for_delivery<T>(m: &Mutex<T>) -> LockResult<MutexGuard<'_, T>> {
    for _ in 0..DELIVERY_SPINS {
        match m.try_lock() {
            Ok(g) => return Ok(g),
            Err(TryLockError::WouldBlock) => std::hint::spin_loop(),
            Err(TryLockError::Poisoned(e)) => return Err(e),
        }
    }
    m.lock()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vtcp::ConnConfig;

    #[test]
    fn a_closed_connection_wakes_its_waiters() {
        let mut c = Conn::new(ConnConfig::default().local_port(1).remote_port(2));
        c.connect();
        let before = Waiters::of(&c);
        assert!(!before.wake(&c), "nothing happened");
        c.abort();
        assert!(before.wake(&c));
    }

    #[test]
    fn delivery_takes_the_lock_once_it_is_free() {
        let m = std::sync::Arc::new(Mutex::new(0));
        let g = m.lock().unwrap();
        let m2 = m.clone();
        let t = std::thread::spawn(move || *lock_for_delivery(&m2).unwrap() += 1);
        std::thread::sleep(std::time::Duration::from_millis(20));
        drop(g);
        t.join().unwrap();
        assert_eq!(*lock_for_delivery(&m).unwrap(), 1);
    }
}
