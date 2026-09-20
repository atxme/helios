//! Firewall data plane: the **kill-switch**.
//!
//! The rendering engine ([`ruleset`]) translates a [`FirewallPolicy`] + a
//! [`TunnelState`] into a declarative ruleset, independent of the backend. Three
//! backends consume this ruleset:
//!
//! * [`DryRunBackend`] — logs the rules without touching the kernel. Default
//!   backend, usable everywhere (including WSL2).
//! * `NetlinkBackend` (feature `netlink`) — applies the rules atomically via
//!   nf_tables' Netlink API (`rustables` crate). Target-only.
//! * `FirewallDisabledBackend` (feature `netlink`) — explicit maintenance
//!   backend which atomically removes only the Helios table and keeps it
//!   absent. It is never selected implicitly.
//!
//! Guiding principle in nominal operation: **fail-closed**. At startup, before
//! any network access, the kill-switch is engaged; LAN traffic is only opened
//! once the state transitions to `Up`. The maintenance backend is the explicit
//! operator exception documented in ADR-001 §3 ter.

pub mod ruleset;

mod dryrun;
#[cfg(feature = "netlink")]
mod netlink;

pub use dryrun::DryRunBackend;
pub use ruleset::{render, Ruleset, Verdict};

#[cfg(feature = "netlink")]
pub use netlink::{FirewallDisabledBackend, NetlinkBackend};

use aether::{FirewallPolicy, Result, TunnelState};
use async_trait::async_trait;

/// Operations a backend can faithfully encode.
///
/// Callers use this before accepting runtime policy updates. Translation
/// still rejects unsupported operations as a defense in depth.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FirewallCapabilities {
    pub mss_clamp: bool,
}

/// Backend responsible for concretely enforcing the firewall policy.
#[async_trait]
pub trait FirewallBackend: Send + Sync {
    /// Operations this backend can faithfully encode and apply.
    fn capabilities(&self) -> FirewallCapabilities;

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
