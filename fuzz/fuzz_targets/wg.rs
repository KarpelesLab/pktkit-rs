//! Fuzzes the WireGuard packet entry point: handshake, cookie and transport messages.
//!
//! ```sh
//! cargo +nightly fuzz run wg
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pktkit::fuzz::wg_process(data);
});
