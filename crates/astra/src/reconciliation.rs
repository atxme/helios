//! Repairing the one cut a §7.5 recovery cannot make atomic.
//!
//! # The cut
//!
//! A recovery ends with two writes in two systems. The gateway promotes the
//! peer to its recovered generation, over the private channel; this authority
//! then adopts what the gateway serves. Nothing can make those one write —
//! they are different processes, on different disks, and the second is a
//! consequence of the first rather than part of it.
//!
//! A crash between them leaves this registry naming a generation that expired.
//! The next lifecycle contact repairs it on its own, because
//! [`crate::renewal::transcribe_peer`] re-reads the gateway every time. But a
//! client that never comes back — which is exactly the population a recovery
//! serves — would leave the disagreement standing, invisible, until somebody
//! looked.
//!
//! # The intent
//!
//! So the intent is written **before** the gateway is asked to commit, and
//! cleared only once this registry has caught up. It names a peer and the
//! generation it is expected to reach. It is not a queue and not a journal: at
//! most one recovery is repaired at a time, and re-reading the gateway is
//! idempotent, so replaying it costs one private-channel call and can never
//! move anything backwards.
//!
//! It is deliberately not the operation itself. Recovery operations live five
//! minutes and are held in memory on purpose (see [`crate::recovery`]);
//! persisting them would resurrect a request an operator may have declined.
//! What outlives the window is not the request but the fact that a promotion
//! was asked for, and that is all this file carries.

use std::path::{Path, PathBuf};

use aether::certificates::encoding::WireGuardKey;
use serde::{Deserialize, Serialize};

/// Name of the intent file, in Astra's state directory.
pub const RECONCILIATION_FILE: &str = "pending-reconciliation.json";

/// A promotion this authority asked for and has not yet adopted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingReconciliation {
    pub peer: WireGuardKey,
    /// The generation the gateway was asked to promote to.
    ///
    /// Compared rather than trusted: the intent is cleared when the registry
    /// has reached **at least** it, so a later renewal that overtook the
    /// recovery closes it too.
    pub expected_generation: u64,
    pub recorded_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ReconciliationError {
    #[error("reconciliation intent input/output: {0}")]
    Io(#[from] std::io::Error),
    #[error("reconciliation intent is unreadable: {0}")]
    Corrupt(String),
}

fn path_of(state_dir: &Path) -> PathBuf {
    state_dir.join(RECONCILIATION_FILE)
}

/// Reads the intent, if one is outstanding.
///
/// A file that cannot be parsed is reported rather than ignored: it was
/// written by this authority, and treating it as absent would silently drop
/// the repair it exists to carry.
pub fn load(state_dir: &Path) -> Result<Option<PendingReconciliation>, ReconciliationError> {
    let raw = match std::fs::read(path_of(state_dir)) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|error| ReconciliationError::Corrupt(error.to_string()))
}

/// Records the intent before the gateway is asked to promote.
pub fn record(state_dir: &Path, intent: &PendingReconciliation) -> Result<(), ReconciliationError> {
    let encoded = serde_json::to_vec_pretty(intent)
        .map_err(|error| ReconciliationError::Corrupt(error.to_string()))?;
    aether::private_file::write_private_atomic(&path_of(state_dir), &encoded)?;
    Ok(())
}

/// Drops the intent once the registry has caught up.
pub fn clear(state_dir: &Path) -> Result<(), ReconciliationError> {
    match std::fs::remove_file(path_of(state_dir)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> WireGuardKey {
        WireGuardKey::from_bytes([7; 32])
    }

    fn intent() -> PendingReconciliation {
        PendingReconciliation {
            peer: key(),
            expected_generation: 2,
            recorded_at: 1_000,
        }
    }

    #[test]
    fn an_absent_intent_is_not_an_error() {
        let directory = tempfile::tempdir().expect("temp");
        assert_eq!(load(directory.path()).expect("absent"), None);
    }

    #[test]
    fn an_intent_survives_the_restart_it_exists_for() {
        let directory = tempfile::tempdir().expect("temp");
        record(directory.path(), &intent()).expect("recorded");
        assert_eq!(load(directory.path()).expect("read"), Some(intent()));
        clear(directory.path()).expect("cleared");
        assert_eq!(load(directory.path()).expect("gone"), None);
    }

    /// Clearing twice is what a crash between the adoption and the removal
    /// produces, and it must not turn a repaired registry into a failure.
    #[test]
    fn clearing_an_absent_intent_is_a_no_op() {
        let directory = tempfile::tempdir().expect("temp");
        clear(directory.path()).expect("first");
        clear(directory.path()).expect("second");
    }

    /// A file this authority wrote and can no longer read is a fact worth
    /// surfacing: reading it as «rien à réparer» would lose the repair.
    #[test]
    fn an_unreadable_intent_is_reported_rather_than_ignored() {
        let directory = tempfile::tempdir().expect("temp");
        std::fs::write(directory.path().join(RECONCILIATION_FILE), b"{").expect("written");
        assert!(matches!(
            load(directory.path()),
            Err(ReconciliationError::Corrupt(_))
        ));
    }
}
