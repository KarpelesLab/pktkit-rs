//! Lock-free single-producer/single-consumer rings over `mmap`'d AF_XDP
//! memory.
//!
//! Each ring is a region the kernel and userspace share. Two `u32` cursors
//! (`producer`, `consumer`) live at fixed offsets in that region; between
//! them sits the descriptor array. One side only advances `producer`, the
//! other only advances `consumer`, so a pair of atomic loads plus one atomic
//! store per batch is enough — no locks. This mirrors `ring.go` in the Go
//! upstream.
//!
//! There are two element types: the FILL and COMPLETION rings carry bare
//! `u64` UMEM addresses ([`AddrRing`]); the RX and TX rings carry
//! [`libc::xdp_desc`] descriptors ([`DescRing`]).
//!
//! # Safety
//!
//! The pointers stored here alias kernel-shared `mmap` memory and must stay
//! valid for the life of the ring. The owning `Device` keeps the mappings
//! alive and never moves them, and the cursors are only ever touched through
//! atomics, so concurrent kernel access is sound. The rings are therefore
//! `Send`/`Sync` (see the explicit impls below).

use std::sync::atomic::{AtomicU32, Ordering};

/// Offsets of the producer/consumer/flags cursors and the descriptor array
/// within a ring's `mmap` region, as reported by `XDP_MMAP_OFFSETS`.
#[derive(Debug, Clone, Copy)]
pub struct RingOffset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

impl From<&libc::xdp_ring_offset> for RingOffset {
    fn from(o: &libc::xdp_ring_offset) -> RingOffset {
        RingOffset {
            producer: o.producer,
            consumer: o.consumer,
            desc: o.desc,
            flags: o.flags,
        }
    }
}

/// Common cursor plumbing shared by both ring flavours.
///
/// `mask` is `size - 1` so `(cursor + i) & mask` wraps without a modulo; the
/// kernel ABI requires the ring size to be a power of two for exactly this
/// reason. `producer`/`consumer` are `&'static`-lifetime atomics borrowed from
/// the mapping — we hold them as raw pointers cast on demand to avoid baking a
/// lifetime into the struct.
#[derive(Debug)]
struct Cursors {
    producer: *const AtomicU32,
    consumer: *const AtomicU32,
    /// `XDP_RING_NEED_WAKEUP` flags word, or null if the ring predates it.
    flags: *const AtomicU32,
    mask: u32,
    size: u32,
}

impl Cursors {
    /// # Safety
    /// `mem` must point at a live ring mapping of at least
    /// `off.desc + size * elem_size` bytes, and `size` must be a power of two.
    unsafe fn new(mem: *mut u8, off: RingOffset, size: u32) -> Cursors {
        let flags = if off.flags != 0 {
            mem.add(off.flags as usize) as *const AtomicU32
        } else {
            std::ptr::null()
        };
        Cursors {
            producer: mem.add(off.producer as usize) as *const AtomicU32,
            consumer: mem.add(off.consumer as usize) as *const AtomicU32,
            flags,
            mask: size - 1,
            size,
        }
    }

    #[inline]
    fn producer(&self) -> &AtomicU32 {
        // SAFETY: pointer is into a live mapping for the ring's lifetime.
        unsafe { &*self.producer }
    }

    #[inline]
    fn consumer(&self) -> &AtomicU32 {
        unsafe { &*self.consumer }
    }

    /// True if the kernel signalled it needs a wakeup (`sendto`/`poll`) to make
    /// progress. Rings without a flags word are treated as always needing one,
    /// matching the Go fallback.
    #[inline]
    fn need_wakeup(&self) -> bool {
        if self.flags.is_null() {
            return true;
        }
        // SAFETY: non-null flags pointer is into the live mapping.
        let f = unsafe { &*self.flags };
        f.load(Ordering::Acquire) & XDP_RING_NEED_WAKEUP != 0
    }
}

/// `XDP_RING_NEED_WAKEUP` from `<linux/if_xdp.h>` (also in `libc`, repeated
/// here so the ring layer has no cross-module constant dependency).
const XDP_RING_NEED_WAKEUP: u32 = 1 << 0;

/// A FILL or COMPLETION ring of bare `u64` UMEM addresses.
#[derive(Debug)]
pub struct AddrRing {
    cur: Cursors,
    /// Base of the `u64` descriptor array inside the mapping.
    addrs: *mut u64,
}

// SAFETY: all shared state is accessed through atomics on the cursors; the
// address slots are only written by the producing side and read by the
// consuming side after observing the producer cursor, so there is no data
// race. The mapping outlives the ring.
unsafe impl Send for AddrRing {}
unsafe impl Sync for AddrRing {}

impl AddrRing {
    /// # Safety
    /// See [`Cursors::new`]; additionally the element size at `off.desc` must
    /// be `u64`.
    pub unsafe fn new(mem: *mut u8, off: RingOffset, size: u32) -> AddrRing {
        AddrRing {
            cur: Cursors::new(mem, off, size),
            addrs: mem.add(off.desc as usize) as *mut u64,
        }
    }

    #[inline]
    fn slot(&self, idx: u32) -> *mut u64 {
        // SAFETY: idx is always masked into [0, size); array has `size` slots.
        unsafe { self.addrs.add((idx & self.cur.mask) as usize) }
    }

    /// Enqueue `addrs` into a producer ring (the FILL ring: app hands free
    /// UMEM frames to the kernel). Returns how many were enqueued, which may
    /// be fewer than requested if the ring filled up.
    pub fn produce(&self, addrs: &[u64]) -> usize {
        let prod = self.cur.producer().load(Ordering::Relaxed);
        let cons = self.cur.consumer().load(Ordering::Acquire);

        // `prod - cons` is the number of occupied slots; wrapping subtraction
        // is correct because both cursors are free-running u32 counters.
        let free = self.cur.size - prod.wrapping_sub(cons);
        let n = (addrs.len() as u32).min(free);
        if n == 0 {
            return 0;
        }
        for i in 0..n {
            // SAFETY: slot is in-bounds; we own producer slots until publish.
            unsafe { *self.slot(prod.wrapping_add(i)) = addrs[i as usize] };
        }
        // Release: make the writes above visible before the kernel sees the
        // bumped producer cursor.
        self.cur
            .producer()
            .store(prod.wrapping_add(n), Ordering::Release);
        n as usize
    }

    /// Dequeue from a consumer ring (the COMPLETION ring: kernel hands back
    /// addresses of frames it finished transmitting) into `out`. Returns how
    /// many were dequeued.
    pub fn consume(&self, out: &mut [u64]) -> usize {
        let cons = self.cur.consumer().load(Ordering::Relaxed);
        let prod = self.cur.producer().load(Ordering::Acquire);

        let avail = prod.wrapping_sub(cons);
        let n = (out.len() as u32).min(avail);
        if n == 0 {
            return 0;
        }
        for i in 0..n {
            // SAFETY: slot is in-bounds and published by the producer.
            out[i as usize] = unsafe { *self.slot(cons.wrapping_add(i)) };
        }
        self.cur
            .consumer()
            .store(cons.wrapping_add(n), Ordering::Release);
        n as usize
    }
}

/// An RX or TX ring of [`libc::xdp_desc`] descriptors.
#[derive(Debug)]
pub struct DescRing {
    cur: Cursors,
    descs: *mut libc::xdp_desc,
}

// SAFETY: same argument as `AddrRing`.
unsafe impl Send for DescRing {}
unsafe impl Sync for DescRing {}

impl DescRing {
    /// # Safety
    /// See [`Cursors::new`]; additionally the element size at `off.desc` must
    /// be `xdp_desc`.
    pub unsafe fn new(mem: *mut u8, off: RingOffset, size: u32) -> DescRing {
        DescRing {
            cur: Cursors::new(mem, off, size),
            descs: mem.add(off.desc as usize) as *mut libc::xdp_desc,
        }
    }

    #[inline]
    fn slot(&self, idx: u32) -> *mut libc::xdp_desc {
        // SAFETY: idx masked into [0, size).
        unsafe { self.descs.add((idx & self.cur.mask) as usize) }
    }

    /// Enqueue TX descriptors (app asks the kernel to transmit). Returns how
    /// many were enqueued.
    pub fn produce(&self, descs: &[libc::xdp_desc]) -> usize {
        let prod = self.cur.producer().load(Ordering::Relaxed);
        let cons = self.cur.consumer().load(Ordering::Acquire);

        let free = self.cur.size - prod.wrapping_sub(cons);
        let n = (descs.len() as u32).min(free);
        if n == 0 {
            return 0;
        }
        for i in 0..n {
            let d = &descs[i as usize];
            // SAFETY: slot in-bounds; producer-owned until publish.
            unsafe {
                *self.slot(prod.wrapping_add(i)) = libc::xdp_desc {
                    addr: d.addr,
                    len: d.len,
                    options: d.options,
                };
            }
        }
        self.cur
            .producer()
            .store(prod.wrapping_add(n), Ordering::Release);
        n as usize
    }

    /// Dequeue RX descriptors (kernel delivered received packets) into `out`.
    /// Returns how many were dequeued.
    pub fn consume(&self, out: &mut [libc::xdp_desc]) -> usize {
        let cons = self.cur.consumer().load(Ordering::Relaxed);
        let prod = self.cur.producer().load(Ordering::Acquire);

        let avail = prod.wrapping_sub(cons);
        let n = (out.len() as u32).min(avail);
        if n == 0 {
            return 0;
        }
        for i in 0..n {
            // SAFETY: slot in-bounds and published by the producer.
            let d = unsafe { &*self.slot(cons.wrapping_add(i)) };
            out[i as usize] = libc::xdp_desc {
                addr: d.addr,
                len: d.len,
                options: d.options,
            };
        }
        self.cur
            .consumer()
            .store(cons.wrapping_add(n), Ordering::Release);
        n as usize
    }

    /// See [`Cursors::need_wakeup`].
    #[inline]
    pub fn need_wakeup(&self) -> bool {
        self.cur.need_wakeup()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A ring lives in a flat byte buffer laid out as:
    //   [producer: u32][pad u32][consumer: u32][pad u32][flags: u32][pad]
    //   [desc array...]
    // We pick offsets that mimic a real kernel layout (cursors cache-line
    // separated) so the index math is exercised against non-trivial offsets.
    const PRODUCER_OFF: u64 = 0;
    const CONSUMER_OFF: u64 = 64;
    const FLAGS_OFF: u64 = 128;
    const DESC_OFF: u64 = 192;

    fn offsets() -> RingOffset {
        RingOffset {
            producer: PRODUCER_OFF,
            consumer: CONSUMER_OFF,
            desc: DESC_OFF,
            flags: FLAGS_OFF,
        }
    }

    fn backing(size: u32, elem: usize) -> Vec<u8> {
        // 8-byte aligned via Vec<u64> would be ideal; Vec<u8> from the global
        // allocator is at least 8-aligned in practice for these sizes, and the
        // offsets we use are all 8-aligned, so u32/u64 access is aligned.
        vec![0u8; DESC_OFF as usize + size as usize * elem]
    }

    #[test]
    fn addr_ring_produce_consume_roundtrip() {
        let size = 8u32;
        let mut mem = backing(size, 8);
        let ring = unsafe { AddrRing::new(mem.as_mut_ptr(), offsets(), size) };

        let in_addrs = [4096u64, 8192, 12288];
        assert_eq!(ring.produce(&in_addrs), 3);

        let mut out = [0u64; 8];
        assert_eq!(ring.consume(&mut out), 3);
        assert_eq!(&out[..3], &in_addrs);

        // Nothing left.
        assert_eq!(ring.consume(&mut out), 0);
    }

    #[test]
    fn addr_ring_respects_capacity() {
        let size = 4u32;
        let mut mem = backing(size, 8);
        let ring = unsafe { AddrRing::new(mem.as_mut_ptr(), offsets(), size) };

        // Ring of 4 can hold at most 4 entries at once.
        let many: Vec<u64> = (0..10).map(|i| i as u64 * 64).collect();
        assert_eq!(ring.produce(&many), 4);
        // Full now.
        assert_eq!(ring.produce(&[999]), 0);

        let mut out = [0u64; 2];
        assert_eq!(ring.consume(&mut out), 2);
        assert_eq!(out, [0, 64]);

        // Two slots freed; can produce two more.
        assert_eq!(ring.produce(&[1000, 2000, 3000]), 2);
    }

    #[test]
    fn addr_ring_wraps_around_mask() {
        let size = 4u32;
        let mut mem = backing(size, 8);
        let ring = unsafe { AddrRing::new(mem.as_mut_ptr(), offsets(), size) };

        // Cycle through more than `size` total entries to force the index
        // wrap (cursor keeps climbing, slot index masks back to 0..size).
        let mut next = 0u64;
        for _ in 0..5 {
            let batch = [next, next + 1];
            assert_eq!(ring.produce(&batch), 2);
            let mut out = [0u64; 2];
            assert_eq!(ring.consume(&mut out), 2);
            assert_eq!(out, batch);
            next += 2;
        }
    }

    #[test]
    fn desc_ring_produce_consume_roundtrip() {
        let size = 8u32;
        let mut mem = backing(size, std::mem::size_of::<libc::xdp_desc>());
        let ring = unsafe { DescRing::new(mem.as_mut_ptr(), offsets(), size) };

        let descs = [
            libc::xdp_desc { addr: 0, len: 60, options: 0 },
            libc::xdp_desc { addr: 4096, len: 1514, options: 0 },
        ];
        assert_eq!(ring.produce(&descs), 2);

        let mut out = [libc::xdp_desc { addr: 0, len: 0, options: 0 }; 8];
        assert_eq!(ring.consume(&mut out), 2);
        assert_eq!(out[0].addr, 0);
        assert_eq!(out[0].len, 60);
        assert_eq!(out[1].addr, 4096);
        assert_eq!(out[1].len, 1514);
    }

    #[test]
    fn empty_consume_is_zero() {
        let size = 8u32;
        let mut mem = backing(size, 8);
        let ring = unsafe { AddrRing::new(mem.as_mut_ptr(), offsets(), size) };
        let mut out = [0u64; 4];
        assert_eq!(ring.consume(&mut out), 0);
    }

    #[test]
    fn need_wakeup_reads_flags_word() {
        let size = 4u32;
        let mut mem = backing(size, std::mem::size_of::<libc::xdp_desc>());
        let ring = unsafe { DescRing::new(mem.as_mut_ptr(), offsets(), size) };

        // Flags word starts at 0 -> no wakeup needed.
        assert!(!ring.need_wakeup());

        // Set XDP_RING_NEED_WAKEUP in the flags word.
        let flags = &mut mem[FLAGS_OFF as usize..FLAGS_OFF as usize + 4];
        flags.copy_from_slice(&XDP_RING_NEED_WAKEUP.to_ne_bytes());
        // Rebuild the ring view over the mutated buffer.
        let ring = unsafe { DescRing::new(mem.as_mut_ptr(), offsets(), size) };
        assert!(ring.need_wakeup());
    }

    #[test]
    fn need_wakeup_true_without_flags() {
        let size = 4u32;
        let mut mem = backing(size, std::mem::size_of::<libc::xdp_desc>());
        let off = RingOffset { flags: 0, ..offsets() };
        let ring = unsafe { DescRing::new(mem.as_mut_ptr(), off, size) };
        assert!(ring.need_wakeup());
    }
}
