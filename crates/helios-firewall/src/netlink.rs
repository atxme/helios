//! Real Netlink backend, based on `rustables` (nf_tables).
//!
//! ⚠️ **Target-only.** This module compiles everywhere, but can only be
//! *exercised* on a kernel with `nf_tables` — not WSL2. To validate on the
//! dedicated machine:
//!
//! ```sh
//! cargo build -p heliosd --features netlink
//! sudo ./target/debug/heliosd run
//! sudo nft list table inet helios
//! ```
//!
//! # Atomicity and fail-closed
//!
//! The whole application goes through **a single Netlink transaction**
//! (`Batch`): the kernel applies it entirely or not at all. So there is no
//! instant where the table would be half-populated — i.e. no instant where
//! the kill-switch would be partially lifted.
//!
//! The table is **recreated on every application** (`Add`, `Del`, then `Add`
//! within the same transaction): this is the only way to get an atomic
//! replacement without leaving stale rules behind.
//!
//! The first `Add` guarantees the table exists before it is deleted. The
//! kernel does **not** tolerate a `Del` on an absent table: it responds
//! `ENOENT` and rejects the whole transaction. Without this `Add`, no
//! kill-switch was applied on a machine's very first startup and heliosd
//! would stop — a behavior only a real-target trial could reveal.
//!
//! # Known limitation: MSS clamping
//!
//! `Ruleset::mss_clamp` is **not** applied here: rewriting the TCP MSS option
//! is a *mangle* action that `rustables`' high-level API does not expose.
//! This is a performance optimization (avoiding fragmentation), not a
//! security rule: its absence leaves no gap. It is logged at `warn` level so
//! it does not silently disappear.

mod expressions;
mod maintenance;
mod transaction;

pub use maintenance::FirewallDisabledBackend;
pub use transaction::NetlinkBackend;

const TABLE_NAME: &str = "helios";
