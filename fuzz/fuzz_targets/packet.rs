//! Fuzzes the Frame and Packet accessors and mutators, including the IPv6 extension-header walk.
//!
//! ```sh
//! cargo +nightly fuzz run packet
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pktkit::fuzz::frame_accessors(data);
    pktkit::fuzz::packet_accessors(data);
    pktkit::fuzz::packet_mutators(data);
});
