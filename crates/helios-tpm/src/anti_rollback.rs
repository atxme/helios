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
/// Consumption takes no lock. The read and the increment are two TPM commands,
/// so two concurrent consumptions of the same value can both pass the read.
/// The second increment then returns `artifact + 2`, which the `next == artifact
/// + 1` check below refuses: concurrent consumers fail closed.
///
/// A value that does not match is refused and publishes nothing: a replayed or
/// forged artifact must not overwrite the public status. A failure to read or
/// increment, or an increment that does not produce `artifact + 1`, is
/// published and reported as [`TpmError::CounterUnavailable`].
pub(crate) fn consume<T: TpmSealer>(tpm: &mut T, cfg: &TpmSettings, artifact: u64) -> Result<u64> {
    let current = tpm
        .read_counter()
        .map_err(|error| publish_failure(cfg, error))?;
    if current != artifact {
        return Err(TpmError::CounterMismatch { artifact, current });
    }
    let next = tpm
        .increment_counter()
        .map_err(|error| publish_failure(cfg, error))?;
    if artifact.checked_add(1) != Some(next) {
        let error = TpmError::CounterUnavailable(format!(
            "increment returned {next} for artifact {artifact}, expected {artifact} + 1"
        ));
        return Err(publish_failure(cfg, error));
    }
    publish_status(cfg, Ok(next));
    Ok(next)
}

/// Publishes a read or increment failure as `CounterUnavailable` and returns it.
fn publish_failure(cfg: &TpmSettings, error: TpmError) -> TpmError {
    let error = match error {
        unavailable @ TpmError::CounterUnavailable(_) => unavailable,
        other => TpmError::CounterUnavailable(other.to_string()),
    };
    publish_status(cfg, Err(&error));
    error
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
    use crate::tpm_interface::{CounterState, DryRunTpm, SealedBlob};
    use crate::SecretKey;
    use zeroize::Zeroizing;

    /// A TPM whose increment advances the counter by two, to exercise the
    /// `artifact + 1` check.
    struct SkewedIncrement(DryRunTpm);

    impl TpmSealer for SkewedIncrement {
        fn current_pcr_digest(&mut self) -> Result<[u8; 32]> {
            self.0.current_pcr_digest()
        }
        fn seal(&mut self, secret: &SecretKey) -> Result<SealedBlob> {
            self.0.seal(secret)
        }
        fn unseal(&mut self, blob: &SealedBlob) -> Result<SecretKey> {
            self.0.unseal(blob)
        }
        fn arm_update_window(&mut self, payload: &[u8]) -> Result<()> {
            self.0.arm_update_window(payload)
        }
        fn unseal_update_window(&mut self) -> Result<Zeroizing<Vec<u8>>> {
            self.0.unseal_update_window()
        }
        fn revoke_update_window(&mut self) -> Result<()> {
            self.0.revoke_update_window()
        }
        fn update_window_armed(&mut self) -> Result<bool> {
            self.0.update_window_armed()
        }
        fn ensure_counter(&mut self) -> Result<()> {
            self.0.ensure_counter()
        }
        fn read_counter(&mut self) -> Result<u64> {
            self.0.read_counter()
        }
        fn increment_counter(&mut self) -> Result<u64> {
            self.0.increment_counter()?;
            self.0.increment_counter()
        }
    }

    /// The published status file, as written.
    fn published(cfg: &TpmSettings) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(&cfg.counter_status_path).unwrap()).unwrap()
    }

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
    fn a_successful_consumption_publishes_the_new_value() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let mut tpm = DryRunTpm::with_digest([1; 32]);
        tpm.ensure_counter().unwrap();
        let current = tpm.read_counter().unwrap();

        consume(&mut tpm, &cfg, current).unwrap();

        assert_eq!(
            published(&cfg),
            serde_json::json!({ "counter": current + 1 })
        );
    }

    #[test]
    fn a_refused_artifact_publishes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let mut tpm = DryRunTpm::with_digest([1; 32]);
        tpm.ensure_counter().unwrap();
        let current = tpm.read_counter().unwrap();
        consume(&mut tpm, &cfg, current).unwrap();
        let before = std::fs::read(&cfg.counter_status_path).unwrap();

        // A replay and a forged value, both refused.
        assert_eq!(
            mismatch_of(consume(&mut tpm, &cfg, current)),
            (current, current + 1)
        );
        assert_eq!(
            mismatch_of(consume(&mut tpm, &cfg, u64::MAX)),
            (u64::MAX, current + 1)
        );

        assert_eq!(
            std::fs::read(&cfg.counter_status_path).unwrap(),
            before,
            "a refused artifact must not overwrite the public status"
        );
    }

    #[test]
    fn a_read_failure_publishes_the_error() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        // Never ensured: the counter is undefined.
        let mut tpm = DryRunTpm::with_digest([1; 32]);

        let error = consume(&mut tpm, &cfg, 1).unwrap_err();

        assert!(matches!(error, TpmError::CounterUnavailable(_)));
        assert_eq!(
            published(&cfg),
            serde_json::json!({
                "counter": null,
                "error": "TPM counter unavailable: counter not defined"
            })
        );
    }

    #[test]
    fn an_increment_that_does_not_produce_artifact_plus_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let mut tpm = SkewedIncrement(DryRunTpm::with_digest([1; 32]));
        tpm.ensure_counter().unwrap();
        let current = tpm.read_counter().unwrap();

        let error = consume(&mut tpm, &cfg, current).unwrap_err();

        assert!(
            matches!(error, TpmError::CounterUnavailable(_)),
            "{error:?}"
        );
        assert!(published(&cfg)["error"].is_string());
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
        let mut first = DryRunTpm::from_env(&cfg);
        first.ensure_counter().unwrap();
        let advanced = first.increment_counter().unwrap();

        let mut second = DryRunTpm::from_env(&cfg);

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
