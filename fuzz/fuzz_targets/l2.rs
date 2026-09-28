//! Fuzzes an L2Adapter with a sequence of frames, packets and the passing of
//! time: ARP and NDP handling, the neighbour caches, the queues waiting on
//! them, and the timers that retry, probe and give up on neighbours.
//!
//! ```sh
//! cargo +nightly fuzz run l2
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pktkit::fuzz::l2adapter_frames(data);
});
