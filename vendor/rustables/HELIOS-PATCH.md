# Helios patch to rustables

This directory contains the crates.io `rustables` 0.8.8 source, from upstream
revision `81e36090615defa5832847dcc54c63c008bc5c2e` (`rustwall/rustables`,
GPL-3.0-or-later). Upstream files retain their original copyright and license
notices; `LICENSE` contains the GPL-3.0 text.

Helios adds `src/expr/exthdr.rs`, registers that expression in
`src/expr/mod.rs`, and extends `TCPHeaderField::Flags` in `src/expr/payload.rs`.
This adds typed TCP MSS option write encoding and the TCP SYN flag byte. Two
inherited marker comments were rewritten in `src/batch.rs` and `src/tests/mod.rs`
to meet repository conventions; they do not change behavior. Keep the functional
patch limited to the expression and field support, and rerun the ABI tests when
rebasing to another upstream release.
