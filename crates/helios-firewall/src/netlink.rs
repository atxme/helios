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
//! Rewriting the TCP MSS option needs the nf_tables `exthdr` expression, which
//! `rustables 0.8.7` neither models nor lets a downstream crate add. A ruleset
//! requesting a clamp is therefore rejected during translation, before any
//! Netlink message is sent. It must never be accepted and silently applied
//! without the requested mangle action.

mod expressions;
mod maintenance;
mod transaction;

pub use maintenance::FirewallDisabledBackend;
pub use transaction::NetlinkBackend;

const TABLE_NAME: &str = "helios";
