//! Firewall data plane: the **kill-switch**.
//!
//! The rendering engine ([`ruleset`]) translates a [`FirewallPolicy`] + a
//! [`TunnelState`] into a declarative ruleset, independent of the backend. Two
//! backends consume this ruleset:
//!
//! * [`DryRunBackend`] — logs the rules without touching the kernel. Default
//!   backend, usable everywhere (including WSL2).
//! * `NetlinkBackend` (feature `netlink`) — applies the rules atomically via
//!   nf_tables' Netlink API (`rustables` crate). Target-only.
//!
//! Guiding principle: **fail-closed**. At startup, before any network access,
//! the kill-switch is engaged; LAN traffic is only opened once the state
//! transitions to `Up`.

pub mod ruleset;

mod dryrun;
#[cfg(feature = "netlink")]
mod netlink;

pub use dryrun::DryRunBackend;
pub use ruleset::{render, Ruleset, Verdict};

#[cfg(feature = "netlink")]
pub use netlink::NetlinkBackend;

use aether::{FirewallPolicy, Result, TunnelState};
use async_trait::async_trait;

/// Backend responsible for concretely enforcing the firewall policy.
#[async_trait]
pub trait FirewallBackend: Send + Sync {
    /// Applies the ruleset matching the tunnel's current state.
    async fn apply(&self, policy: &FirewallPolicy, state: TunnelState) -> Result<()>;

    /// Engages the kill-switch (equivalent to `apply(policy, TunnelState::Down)`).
    /// To be called at daemon startup, before any network contact.
    async fn engage_kill_switch(&self, policy: &FirewallPolicy) -> Result<()> {
        self.apply(policy, TunnelState::Down).await
    }

    /// Entirely removes the Helios table (cleanup at shutdown).
    async fn teardown(&self) -> Result<()>;
}
