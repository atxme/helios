//! The explicit maintenance backend of ADR-001 §3 ter.
//!
//! Separate from the transaction module because it is a separate decision:
//! this backend is selected by an operator through a systemd drop-in, never
//! reached by a Netlink failure. A failure of [`NetlinkBackend`] stays fatal.

use aether::{FirewallPolicy, Result, TunnelState};
use async_trait::async_trait;
use rustables::{Batch, MsgType, ProtocolFamily, Table};
use tracing::warn;

use super::{NetlinkBackend, TABLE_NAME};
use crate::FirewallBackend;

/// Explicit maintenance backend: no Helios filtering, real kernel networking.
///
/// This is deliberately separate from [`NetlinkBackend`] and from the dry-run
/// backend. Selecting it is an operator decision, never a fallback after a
/// Netlink failure. Every application removes the Helios table atomically so
/// a table left by the previous daemon cannot keep blocking remote access.
pub struct FirewallDisabledBackend {
    table_name: String,
}

impl FirewallDisabledBackend {
    pub fn new() -> Self {
        Self {
            table_name: TABLE_NAME.to_string(),
        }
    }

    /// The initial `Add` makes removal idempotent: deleting an absent table on
    /// its own rejects the transaction with `ENOENT`.
    const REMOVE_SEQUENCE: [MsgType; 2] = [MsgType::Add, MsgType::Del];

    fn remove(&self) -> Result<()> {
        let mut batch = Batch::new();
        let table = Table::new(ProtocolFamily::Inet).with_name(self.table_name.clone());
        for message in Self::REMOVE_SEQUENCE {
            batch.add(&table, message);
        }
        batch.send().map_err(|error| {
            NetlinkBackend::err(format!(
                "Netlink maintenance transaction rejected for table {}: {error}",
                self.table_name
            ))
        })?;
        warn!(
            "UNSAFE MAINTENANCE MODE: table inet {} removed; Helios firewall enforcement is disabled",
            self.table_name
        );
        Ok(())
    }
}

impl Default for FirewallDisabledBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallBackend for FirewallDisabledBackend {
    async fn apply(&self, _policy: &FirewallPolicy, _state: TunnelState) -> Result<()> {
        self.remove()
    }

    async fn teardown(&self) -> Result<()> {
        self.remove()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintenance_removal_is_idempotent_and_does_not_recreate_the_table() {
        assert_eq!(
            FirewallDisabledBackend::REMOVE_SEQUENCE,
            [MsgType::Add, MsgType::Del],
            "maintenance must make an absent table removable, then leave it absent"
        );
    }
}
