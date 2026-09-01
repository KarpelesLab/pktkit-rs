//! Fuzzes the DHCP wire decoder.
//!
//! ```sh
//! cargo +nightly fuzz run dhcp
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pktkit::fuzz::dhcp_parse(data);
});
