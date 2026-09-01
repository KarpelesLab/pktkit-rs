//! Fuzzes the TCP, UDP and ICMP views and their option iteration.
//!
//! ```sh
//! cargo +nightly fuzz run l4
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pktkit::fuzz::l4_views(data);
});
