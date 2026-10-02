#![no_main]

//! Wrapper. The harness is `aether::fuzzing::tunnel_addresses`, which the
//! stable build compiles and the ordinary test suite runs over its seeds.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    aether::fuzzing::tunnel_addresses(data);
});
