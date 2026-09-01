//! Fuzzes every parser at once — the target to run when you have no particular suspect.
//!
//! ```sh
//! cargo +nightly fuzz run all
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pktkit::fuzz::all(data);
});
