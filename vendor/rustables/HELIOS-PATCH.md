# Helios patch to rustables

This directory contains the crates.io `rustables` 0.8.8 source, from upstream
revision `81e36090615defa5832847dcc54c63c008bc5c2e` (`rustwall/rustables`,
GPL-3.0-or-later). Upstream files retain their original copyright and license
notices; `LICENSE` contains the GPL-3.0 text.

Helios adds `src/expr/exthdr.rs`, registers that expression in
`src/expr/mod.rs`, and extends `TCPHeaderField::Flags` in `src/expr/payload.rs`.
This adds typed TCP MSS option write encoding and the TCP SYN flag byte. Two
inherited marker comments were rewritten in `src/batch.rs` and `src/tests/mod.rs`
to meet repository conventions; they do not change behavior.

The patch also adds `CounterObject` and its nested counter data, immediate
`Objref` references and `Fib::source_route_present`. The FIB constructor fixes
the source address, incoming interface and existence result; callers choose
explicitly whether packet marks participate in policy routing. Object names
are bounded to 255 bytes and refuse NUL. Socket handling and batch transport
remain upstream. Expression decoding explicitly calls the `Expression` trait
to avoid collision with the generated `Objref::get_name(&self)` field getter.
Helios ABI tests in
`crates/helios-firewall/src/netlink/capabilities_tests.rs` inspect actual
serialized attributes and object ordering. The Objref module's unit test also
checks typed decoding; rerun these and the MSS ABI tests when rebasing to
another upstream release.
