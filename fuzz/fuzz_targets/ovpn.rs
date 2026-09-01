//! Fuzzes the OpenVPN control-channel packet decoder and option parser.
//!
//! ```sh
//! cargo +nightly fuzz run ovpn
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pktkit::fuzz::ovpn_control(data);
});
