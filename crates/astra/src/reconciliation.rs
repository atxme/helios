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
//! `crate::renewal::transcribe_peer` re-reads the gateway every time. But a
//! client that never comes back — which is exactly the population a recovery
//! serves — would leave the disagreement standing, invisible, until somebody
//! looked.
//!
//! # The intent
//!
//! So the intent is written **before** the gateway is asked to commit, and
//! cleared once this registry has caught up — or once a fresh gateway read
//! proves that the candidate was never retained. It names a peer and the
//! generation it is expected to reach. Several recoveries may commit at the
//! same time, so the file is a bounded set keyed by peer. Re-reading the
//! gateway is idempotent, so replaying every entry costs one private-channel
//! call per peer and can never move anything backwards.
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

/// Same ceiling as the in-memory recovery store.
pub const MAX_PENDING_RECONCILIATIONS: usize = 16;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationSet {
    version: u16,
    entries: Vec<PendingReconciliation>,
}

const RECONCILIATION_VERSION: u16 = 1;

#[derive(Deserialize)]
#[serde(untagged)]
enum ReconciliationDocument {
    Set(ReconciliationSet),
    /// Format written by the first implementation. Kept readable so an
    /// upgrade cannot discard the very crash-repair marker it is loading.
    Legacy(PendingReconciliation),
}

#[derive(Debug, thiserror::Error)]
pub enum ReconciliationError {
    #[error("reconciliation intent input/output: {0}")]
    Io(#[from] std::io::Error),
    #[error("reconciliation intent is unreadable: {0}")]
    Corrupt(String),
    #[error("too many pending reconciliations")]
    Full,
}

fn path_of(state_dir: &Path) -> PathBuf {
    state_dir.join(RECONCILIATION_FILE)
}

/// Reads the intent, if one is outstanding.
///
/// A file that cannot be parsed is reported rather than ignored: it was
/// written by this authority, and treating it as absent would silently drop
/// the repair it exists to carry.
pub fn load(state_dir: &Path) -> Result<Vec<PendingReconciliation>, ReconciliationError> {
    let raw = match std::fs::read(path_of(state_dir)) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let document: ReconciliationDocument = serde_json::from_slice(&raw)
        .map_err(|error| ReconciliationError::Corrupt(error.to_string()))?;
    let entries = match document {
        ReconciliationDocument::Set(set) if set.version == RECONCILIATION_VERSION => set.entries,
        ReconciliationDocument::Set(set) => {
            return Err(ReconciliationError::Corrupt(format!(
                "unsupported reconciliation version {}",
                set.version
            )))
        }
        ReconciliationDocument::Legacy(intent) => vec![intent],
    };
    if entries.len() > MAX_PENDING_RECONCILIATIONS {
        return Err(ReconciliationError::Corrupt(format!(
            "{} entries exceed the ceiling of {MAX_PENDING_RECONCILIATIONS}",
            entries.len()
        )));
    }
    for (index, entry) in entries.iter().enumerate() {
        if entries[..index]
            .iter()
            .any(|earlier| earlier.peer == entry.peer)
        {
            return Err(ReconciliationError::Corrupt(
                "the same peer appears more than once".into(),
            ));
        }
    }
    Ok(entries)
}

/// Records the intent before the gateway is asked to promote.
///
/// Callers serialize this read-modify-write through `AstraService`'s
/// reconciliation mutex. Keeping that lock beside the service makes the file
/// format independent from the async runtime while preventing two commits
/// from publishing sets that each forgot the other.
pub fn record(state_dir: &Path, intent: &PendingReconciliation) -> Result<(), ReconciliationError> {
    let mut entries = load(state_dir)?;
    match entries.iter().position(|entry| entry.peer == intent.peer) {
        Some(index) if intent.expected_generation > entries[index].expected_generation => {
            entries[index] = intent.clone();
        }
        Some(_) => return Ok(()),
        None if entries.len() >= MAX_PENDING_RECONCILIATIONS => {
            return Err(ReconciliationError::Full)
        }
        None => entries.push(intent.clone()),
    }
    entries.sort_by_key(|entry| entry.recorded_at);
    let encoded = serde_json::to_vec_pretty(&ReconciliationSet {
        version: RECONCILIATION_VERSION,
        entries,
    })
    .map_err(|error| ReconciliationError::Corrupt(error.to_string()))?;
    aether::private_file::write_private_atomic(&path_of(state_dir), &encoded)?;
    Ok(())
}

/// Drops this peer's reached intent once the registry has caught up.
pub fn clear(
    state_dir: &Path,
    peer: &WireGuardKey,
    reached_generation: u64,
) -> Result<(), ReconciliationError> {
    let mut entries = load(state_dir)?;
    entries.retain(|entry| entry.peer != *peer || entry.expected_generation > reached_generation);
    if entries.is_empty() {
        return match std::fs::remove_file(path_of(state_dir)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        };
    }
    let encoded = serde_json::to_vec_pretty(&ReconciliationSet {
        version: RECONCILIATION_VERSION,
        entries,
    })
    .map_err(|error| ReconciliationError::Corrupt(error.to_string()))?;
    aether::private_file::write_private_atomic(&path_of(state_dir), &encoded)?;
    Ok(())
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
        assert!(load(directory.path()).expect("absent").is_empty());
    }

    #[test]
    fn an_intent_survives_the_restart_it_exists_for() {
        let directory = tempfile::tempdir().expect("temp");
        record(directory.path(), &intent()).expect("recorded");
        assert_eq!(load(directory.path()).expect("read"), vec![intent()]);
        clear(directory.path(), &key(), 2).expect("cleared");
        assert!(load(directory.path()).expect("gone").is_empty());
    }

    /// Clearing twice is what a crash between the adoption and the removal
    /// produces, and it must not turn a repaired registry into a failure.
    #[test]
    fn clearing_an_absent_intent_is_a_no_op() {
        let directory = tempfile::tempdir().expect("temp");
        clear(directory.path(), &key(), 2).expect("first");
        clear(directory.path(), &key(), 2).expect("second");
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

    #[test]
    fn concurrent_peers_do_not_replace_each_other() {
        let directory = tempfile::tempdir().expect("temp");
        let first = intent();
        let second = PendingReconciliation {
            peer: WireGuardKey::from_bytes([8; 32]),
            expected_generation: 7,
            recorded_at: 1_001,
        };
        record(directory.path(), &first).expect("first");
        record(directory.path(), &second).expect("second");
        assert_eq!(load(directory.path()).expect("both"), vec![first, second]);
    }

    #[test]
    fn clearing_one_peer_preserves_the_other() {
        let directory = tempfile::tempdir().expect("temp");
        let first = intent();
        let second = PendingReconciliation {
            peer: WireGuardKey::from_bytes([8; 32]),
            expected_generation: 7,
            recorded_at: 1_001,
        };
        record(directory.path(), &first).expect("first");
        record(directory.path(), &second).expect("second");
        clear(directory.path(), &first.peer, first.expected_generation).expect("first cleared");
        assert_eq!(
            load(directory.path()).expect("second remains"),
            vec![second]
        );
    }

    #[test]
    fn the_legacy_single_intent_is_migrated_without_being_lost() {
        let directory = tempfile::tempdir().expect("temp");
        std::fs::write(
            directory.path().join(RECONCILIATION_FILE),
            serde_json::to_vec(&intent()).expect("encoded"),
        )
        .expect("written");
        assert_eq!(load(directory.path()).expect("legacy"), vec![intent()]);
    }

    fn set(entries: Vec<PendingReconciliation>) -> ReconciliationSet {
        ReconciliationSet {
            version: RECONCILIATION_VERSION,
            entries,
        }
    }

    fn persist_raw(directory: &Path, bytes: &[u8]) {
        std::fs::write(path_of(directory), bytes).expect("write reconciliation fixture");
    }

    #[test]
    fn loader_rejects_unknown_versions_duplicate_peers_and_oversized_sets() {
        let directory = tempfile::tempdir().expect("temp");
        let unsupported = serde_json::to_vec(&ReconciliationSet {
            version: RECONCILIATION_VERSION + 1,
            entries: vec![intent()],
        })
        .expect("encode unsupported version");
        persist_raw(directory.path(), &unsupported);
        assert!(matches!(
            load(directory.path()),
            Err(ReconciliationError::Corrupt(_))
        ));

        let duplicate = set(vec![intent(), intent()]);
        persist_raw(
            directory.path(),
            &serde_json::to_vec(&duplicate).expect("encode duplicate peers"),
        );
        assert!(matches!(
            load(directory.path()),
            Err(ReconciliationError::Corrupt(message)) if message.contains("same peer")
        ));

        let oversized = (0..=MAX_PENDING_RECONCILIATIONS)
            .map(|index| PendingReconciliation {
                peer: WireGuardKey::from_bytes([index as u8 + 1; 32]),
                expected_generation: 1,
                recorded_at: index as u64,
            })
            .collect();
        persist_raw(
            directory.path(),
            &serde_json::to_vec(&set(oversized)).expect("encode oversized set"),
        );
        assert!(matches!(
            load(directory.path()),
            Err(ReconciliationError::Corrupt(message)) if message.contains("ceiling")
        ));
    }

    #[test]
    fn loader_reports_non_not_found_io_errors() {
        let directory = tempfile::tempdir().expect("temp");
        std::fs::create_dir(path_of(directory.path())).expect("directory at file path");

        assert!(matches!(
            load(directory.path()),
            Err(ReconciliationError::Io(_))
        ));
    }

    #[test]
    fn recording_is_monotone_and_stale_or_equal_generations_are_no_ops() {
        let directory = tempfile::tempdir().expect("temp");
        let first = intent();
        let second = PendingReconciliation {
            peer: WireGuardKey::from_bytes([8; 32]),
            expected_generation: 7,
            recorded_at: 1_001,
        };
        record(directory.path(), &first).expect("record first generation");
        record(directory.path(), &second).expect("record independent peer");

        let replacement = PendingReconciliation {
            expected_generation: 3,
            recorded_at: 900,
            ..first.clone()
        };
        record(directory.path(), &replacement).expect("record higher generation");
        let expected = vec![replacement.clone(), second];
        assert_eq!(load(directory.path()).expect("read updated set"), expected);

        let path = path_of(directory.path());
        let before_stale_record = std::fs::read(&path).expect("read persisted set");
        record(directory.path(), &first).expect("stale generation is harmless");
        let equal_generation = PendingReconciliation {
            recorded_at: 1,
            ..replacement
        };
        record(directory.path(), &equal_generation).expect("equal generation is harmless");
        assert_eq!(
            std::fs::read(path).expect("read unchanged set"),
            before_stale_record
        );
    }

    #[test]
    fn capacity_is_exactly_bounded_and_rejection_preserves_all_intents() {
        let directory = tempfile::tempdir().expect("temp");
        for seed in 1..=MAX_PENDING_RECONCILIATIONS as u8 {
            record(
                directory.path(),
                &PendingReconciliation {
                    peer: WireGuardKey::from_bytes([seed; 32]),
                    expected_generation: u64::from(seed),
                    recorded_at: u64::from(seed),
                },
            )
            .expect("entry within bound");
        }
        let full_set = load(directory.path()).expect("maximum-size set");
        assert_eq!(full_set.len(), MAX_PENDING_RECONCILIATIONS);
        let persisted = std::fs::read(path_of(directory.path())).expect("persisted maximum set");
        let over_limit = PendingReconciliation {
            peer: WireGuardKey::from_bytes([MAX_PENDING_RECONCILIATIONS as u8 + 1; 32]),
            expected_generation: 99,
            recorded_at: 99,
        };

        assert!(matches!(
            record(directory.path(), &over_limit),
            Err(ReconciliationError::Full)
        ));
        assert_eq!(
            load(directory.path()).expect("all original entries remain"),
            full_set
        );
        assert_eq!(
            std::fs::read(path_of(directory.path())).expect("unchanged persisted set"),
            persisted
        );
    }

    #[test]
    fn clear_keeps_a_future_generation_then_removes_only_reached_intents() {
        let directory = tempfile::tempdir().expect("temp");
        let first = PendingReconciliation {
            expected_generation: 5,
            ..intent()
        };
        let second = PendingReconciliation {
            peer: WireGuardKey::from_bytes([8; 32]),
            expected_generation: 9,
            recorded_at: 1_001,
        };
        record(directory.path(), &first).expect("first intent");
        record(directory.path(), &second).expect("second intent");

        clear(directory.path(), &first.peer, 4).expect("future generation remains pending");
        assert_eq!(
            load(directory.path()).expect("both remain"),
            vec![first.clone(), second.clone()]
        );

        clear(directory.path(), &first.peer, 5).expect("reached first intent");
        assert_eq!(
            load(directory.path()).expect("second remains"),
            vec![second.clone()]
        );

        clear(directory.path(), &second.peer, 9).expect("reached final intent");
        assert!(
            !path_of(directory.path()).exists(),
            "empty set removes its file"
        );
    }
}
