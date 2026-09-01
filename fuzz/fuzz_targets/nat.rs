//! Fuzzes fragment reassembly and the NAT with every ALG registered — the ALGs scan attacker-controlled payloads.
//!
//! ```sh
//! cargo +nightly fuzz run nat
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pktkit::fuzz::defrag(data);
    pktkit::fuzz::nat_forward(data);
});
