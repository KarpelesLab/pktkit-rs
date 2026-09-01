//! Fuzzes the DNS response parser, including compression-pointer handling.
//!
//! ```sh
//! cargo +nightly fuzz run dns
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pktkit::fuzz::dns_parse(data);
});
