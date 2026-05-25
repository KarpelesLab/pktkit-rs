use std::sync::Mutex;

/// Default packet buffer size — enough for an Ethernet MTU plus a little
/// headroom for tunnel overlays.
pub const DEFAULT_MTU: usize = 1536;

/// A thread-safe buffer pool for packet/frame storage.
///
/// Buffers are recycled to minimise allocator pressure on the data plane.
/// The pool grows on demand and never shrinks — keep a single shared pool
/// per process so all subsystems amortise allocations.
///
/// ```
/// # use pktkit::BufferPool;
/// let pool = BufferPool::new();
/// let mut buf = pool.alloc(1500);
/// buf.fill(0);
/// pool.free(buf);
/// ```
///
/// Concretely the pool stores `Vec<u8>`s in a `Mutex<Vec<Vec<u8>>>`. The hot
/// path is a single mutex acquire-then-pop / push-then-release — a fair
/// match for Go's `sync.Pool` without an extra dependency.
pub struct BufferPool {
    free: Mutex<Vec<Vec<u8>>>,
    max_pooled: usize,
}

impl core::fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let n = self.free.lock().map(|v| v.len()).unwrap_or(0);
        f.debug_struct("BufferPool")
            .field("free", &n)
            .field("max_pooled", &self.max_pooled)
            .finish()
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

impl BufferPool {
    /// Create an unbounded pool (pool size grows with peak concurrency).
    pub fn new() -> BufferPool {
        BufferPool {
            free: Mutex::new(Vec::new()),
            max_pooled: usize::MAX,
        }
    }

    /// Create a pool capped at `max_pooled` retained buffers. Buffers freed
    /// when the pool is full are simply dropped — this bounds memory in
    /// adversarial workloads.
    pub fn with_cap(max_pooled: usize) -> BufferPool {
        BufferPool {
            free: Mutex::new(Vec::new()),
            max_pooled,
        }
    }

    /// Return a buffer of length `n`. The buffer is taken from the pool when
    /// possible, allocated otherwise; capacity may be larger than `n`.
    pub fn alloc(&self, n: usize) -> Vec<u8> {
        let mut free = self.free.lock().unwrap();
        let mut buf = free.pop().unwrap_or_default();
        drop(free);
        if buf.capacity() < n {
            buf.resize(n, 0);
        } else {
            // Safety: we know capacity ≥ n; resize_with avoids reinitialising
            // bytes we don't need to touch, but for predictability we just
            // truncate-or-extend with zeros.
            buf.clear();
            buf.resize(n, 0);
        }
        buf
    }

    /// Return a buffer obtained from [`alloc`](Self::alloc) to the pool.
    /// Buffers are cleared back to capacity before being recycled.
    pub fn free(&self, mut buf: Vec<u8>) {
        // Reset the logical length to capacity (matching the Go contract).
        let cap = buf.capacity();
        // Safety: clearing zeros isn't required by Rust, but mirror Go's
        // intent of recycling the storage with its full capacity available.
        unsafe {
            buf.set_len(cap);
        }
        let mut free = self.free.lock().unwrap();
        if free.len() < self.max_pooled {
            free.push(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_returns_requested_length() {
        let p = BufferPool::new();
        let b = p.alloc(100);
        assert_eq!(b.len(), 100);
        p.free(b);
    }

    #[test]
    fn alloc_reuses_buffer() {
        let p = BufferPool::new();
        let mut b = p.alloc(100);
        b[0] = 0x42;
        let cap = b.capacity();
        p.free(b);
        let b2 = p.alloc(100);
        assert!(b2.capacity() >= cap);
        // (We don't assert on contents; alloc clears+resizes which zeros.)
    }

    #[test]
    fn cap_drops_overflow() {
        let p = BufferPool::with_cap(2);
        let b1 = p.alloc(10);
        let b2 = p.alloc(10);
        let b3 = p.alloc(10);
        p.free(b1);
        p.free(b2);
        p.free(b3); // dropped
        assert_eq!(p.free.lock().unwrap().len(), 2);
    }
}
