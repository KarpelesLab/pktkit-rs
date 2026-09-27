use std::sync::Mutex;

/// Default packet buffer size — enough for an Ethernet MTU plus a little
/// headroom for tunnel overlays.
pub const DEFAULT_MTU: usize = 1536;

/// Buffers a pool made with [`BufferPool::new`] keeps for reuse: about
/// 1.5 MiB at [`DEFAULT_MTU`], enough to absorb bursts without letting one
/// spike pin its peak memory forever.
pub const DEFAULT_MAX_POOLED: usize = 1024;

/// A thread-safe buffer pool for packet/frame storage.
///
/// Buffers are recycled to minimise allocator pressure on the data plane.
/// The pool grows on demand up to its cap ([`DEFAULT_MAX_POOLED`] unless
/// made [`with_cap`](Self::with_cap)) — keep a single shared pool per process
/// so all subsystems amortise allocations.
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
    /// Create a pool retaining up to [`DEFAULT_MAX_POOLED`] buffers.
    pub fn new() -> BufferPool {
        Self::with_cap(DEFAULT_MAX_POOLED)
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
        // Zeroed, so a recycled buffer never leaks its last packet.
        buf.clear();
        buf.resize(n, 0);
        buf
    }

    /// Return a buffer obtained from [`alloc`](Self::alloc) to the pool.
    /// Only its storage is kept: the length goes back to zero, since the
    /// bytes past it may never have been initialised.
    pub fn free(&self, mut buf: Vec<u8>) {
        buf.clear();
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

    #[test]
    fn free_never_exposes_uninitialised_bytes() {
        let p = BufferPool::new();
        // Capacity nobody ever wrote to.
        let mut b = Vec::with_capacity(4096);
        b.push(1u8);
        p.free(b);
        let pooled = p.free.lock().unwrap();
        assert!(pooled[0].len() <= 1, "length covers uninitialised memory");
    }

    #[test]
    fn the_default_pool_is_bounded() {
        let p = BufferPool::new();
        for _ in 0..DEFAULT_MAX_POOLED + 10 {
            p.free(Vec::with_capacity(8));
        }
        assert_eq!(p.free.lock().unwrap().len(), DEFAULT_MAX_POOLED);
    }
}
