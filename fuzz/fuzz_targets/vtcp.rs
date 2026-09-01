//! Fuzzes TCP segment and option parsing in the virtual TCP engine.
//!
//! ```sh
//! cargo +nightly fuzz run vtcp
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pktkit::fuzz::vtcp_segment(data);
});
