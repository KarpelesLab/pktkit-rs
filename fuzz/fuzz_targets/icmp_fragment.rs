//! Fuzzes ICMP error generation and IPv4 fragmentation, both of which assert properties of what they produce.
//!
//! ```sh
//! cargo +nightly fuzz run icmp_fragment
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pktkit::fuzz::icmp_errors(data);
    pktkit::fuzz::fragmentation(data);
});
