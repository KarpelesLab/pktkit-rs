//! Fuzzes an L2Adapter with a sequence of frames and packets: ARP and NDP
//! handling, the neighbour caches and the queues waiting on them.
//!
//! ```sh
//! cargo +nightly fuzz run l2
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pktkit::fuzz::l2adapter_frames(data);
});
