//! Monotonic anti-rollback counter (F5).
//!
//! A recovery artifact or a re-keying authorization carries the counter value
//! it was issued for. It is valid **if and only if** that value equals the
//! TPM counter; the gateway then increments the counter **before** acting, so
//! an artifact can be consumed once. A counter that cannot be read or moved
//! refuses the artifact and never blocks the boot.
//!
//! The counter lives in an owner-written NV counter index, `no_da`, so a
//! failing attempt cannot lock it out. Its public status is published to
//! `TpmSettings::counter_status_path`.

use crate::{
    boot_controller::open_tpm, settings::TpmSettings, tpm_interface::TpmSealer, Result, TpmError,
};

/// Reads the anti-rollback counter without moving it.
pub fn current(cfg: &TpmSettings) -> Result<u64> {
    let mut tpm = open_tpm(cfg)?;
    tpm.read_counter()
}

/// Moves the counter forward unconditionally (identity rotation), defining it
/// first if needed, and publishes the new value.
pub fn advance(cfg: &TpmSettings) -> Result<u64> {
    let outcome = open_tpm(cfg).and_then(|mut tpm| {
        tpm.ensure_counter()?;
        tpm.increment_counter()
    });
    publish_outcome(cfg, outcome)
}

/// Consumes an artifact issued for counter value `artifact`: accepted only if
/// it equals the TPM counter, which is then incremented and returned.
///
/// Any failure to read or increment the counter is reported as
/// [`TpmError::CounterUnavailable`]; a value that does not match is
/// [`TpmError::CounterMismatch`]. The outcome is published either way.
// Not called outside tests yet: the artifact verification path is its only caller.
#[allow(dead_code)]
pub(crate) fn consume<T: TpmSealer>(tpm: &mut T, cfg: &TpmSettings, artifact: u64) -> Result<u64> {
    let outcome = (|| {
        let current = tpm.read_counter()?;
        if current != artifact {
            return Err(TpmError::CounterMismatch { artifact, current });
        }
        tpm.increment_counter()
    })();
    publish_outcome(cfg, outcome)
}

/// Writes the public status atomically. A failed write is logged, never
/// propagated: the status is information, not a gate.
pub(crate) fn publish_status(cfg: &TpmSettings, value: std::result::Result<u64, &TpmError>) {
    let document = match value {
        Ok(counter) => serde_json::json!({ "counter": counter }),
        Err(error) => serde_json::json!({ "counter": null, "error": error.to_string() }),
    };
    let written = serde_json::to_vec(&document)
        .map_err(|error| TpmError::Serde(error.to_string()))
        .and_then(|bytes| crate::blob_store::atomic_write(&cfg.counter_status_path, &bytes));
    if let Err(error) = written {
        tracing::warn!(
            path = %cfg.counter_status_path,
            error = %error,
            "anti-rollback status could not be published"
        );
    }
}

fn publish_outcome(cfg: &TpmSettings, outcome: Result<u64>) -> Result<u64> {
    publish_status(
        cfg,
        match &outcome {
            Ok(value) => Ok(*value),
            Err(error) => Err(error),
        },
    );
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm_interface::{CounterState, DryRunTpm};

    /// The `(artifact, current)` pair of a refused consumption.
    fn mismatch_of(result: Result<u64>) -> (u64, u64) {
        match result {
            Err(TpmError::CounterMismatch { artifact, current }) => (artifact, current),
            other => panic!("expected a counter mismatch, got {other:?}"),
        }
    }

    /// Settings whose simulated counter and status live in a temporary directory.
    fn cfg(dir: &std::path::Path) -> TpmSettings {
        TpmSettings {
            simulated_counter_path: dir.join("simulated-nv-counter").to_string_lossy().into(),
            counter_status_path: dir.join("anti-rollback.json").to_string_lossy().into(),
            ..TpmSettings::default()
        }
    }

    #[test]
    fn ensure_then_read_starts_a_counter() {
        let mut tpm = DryRunTpm::with_digest([1; 32]);

        tpm.ensure_counter().unwrap();

        assert_eq!(tpm.read_counter().unwrap(), 1);
    }

    #[test]
    fn ensure_is_idempotent() {
        let mut tpm = DryRunTpm::with_digest([1; 32]);
        tpm.ensure_counter().unwrap();
        let before = tpm.read_counter().unwrap();

        tpm.ensure_counter().unwrap();

        assert_eq!(tpm.read_counter().unwrap(), before);
    }

    #[test]
    fn consume_accepts_only_the_current_value() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let mut tpm = DryRunTpm::with_digest([1; 32]);
        tpm.ensure_counter().unwrap();
        let current = tpm.read_counter().unwrap();

        assert_eq!(
            mismatch_of(consume(&mut tpm, &cfg, current + 1)),
            (current + 1, current)
        );
        assert!(current > 0, "ensure must leave the counter above zero");
        assert_eq!(
            mismatch_of(consume(&mut tpm, &cfg, current - 1)),
            (current - 1, current)
        );
        assert_eq!(
            tpm.read_counter().unwrap(),
            current,
            "a refused artifact must not move the counter"
        );

        assert_eq!(consume(&mut tpm, &cfg, current).unwrap(), current + 1);
    }

    #[test]
    fn a_consumed_value_cannot_be_consumed_again() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let counter = CounterState::default();
        let mut first = DryRunTpm::with_digest([1; 32]).sharing_counter(&counter);
        first.ensure_counter().unwrap();
        let current = first.read_counter().unwrap();
        assert_eq!(consume(&mut first, &cfg, current).unwrap(), current + 1);

        // A second instance over the same TPM, as after a reboot.
        let mut second = DryRunTpm::with_digest([1; 32]).sharing_counter(&counter);
        assert_eq!(
            mismatch_of(consume(&mut second, &cfg, current)),
            (current, current + 1),
            "the replayed artifact must be refused"
        );
    }

    #[test]
    fn the_simulated_counter_survives_a_new_instance() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let mut first = DryRunTpm::from_env(&cfg).unwrap();
        first.ensure_counter().unwrap();
        let advanced = first.increment_counter().unwrap();

        let mut second = DryRunTpm::from_env(&cfg).unwrap();

        assert_eq!(second.read_counter().unwrap(), advanced);
    }

    #[test]
    fn publish_status_writes_the_value_and_the_failure() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let path = std::path::PathBuf::from(&cfg.counter_status_path);

        publish_status(&cfg, Ok(7));
        let published: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(published, serde_json::json!({ "counter": 7 }));

        let failure = TpmError::CounterUnavailable("injected".into());
        publish_status(&cfg, Err(&failure));
        let published: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            published,
            serde_json::json!({
                "counter": null,
                "error": "TPM counter unavailable: injected"
            })
        );
    }
}
