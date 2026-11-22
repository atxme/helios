//! Authenticated recovery of the WireGuard gateway identity (F5).
//!
//! The publisher signs the public half of the identity and the anti-rollback
//! counter value the recovery is valid for. The operator adds the private key,
//! which only the operator holds. Acceptance checks, in order: the hybrid
//! signatures and the key binding, the PCR state when the authorization names
//! one, and only then spends the counter. A refusal before the last step never
//! touches the counter.

use std::sync::Once;

use aether::sig::{
    verify_wireguard_recovery, SignedWireGuardRecovery, PUBLISHER_KEYS,
    USING_DEVELOPMENT_PUBLISHER_KEYS,
};

use crate::{
    anti_rollback, boot_controller::open_tpm, tpm_interface::TpmSealer, Result, TpmError,
    TpmSettings,
};

/// Accepts a WireGuard recovery for the TPM described by `cfg`, spending the
/// anti-rollback counter it was issued for.
pub fn accept(
    cfg: &TpmSettings,
    authorization: &SignedWireGuardRecovery,
    private_key: &[u8; 32],
) -> Result<()> {
    accept_with(|| open_tpm(cfg), cfg, authorization, private_key)
}

fn accept_with<T: TpmSealer>(
    open: impl FnOnce() -> Result<T>,
    cfg: &TpmSettings,
    authorization: &SignedWireGuardRecovery,
    private_key: &[u8; 32],
) -> Result<()> {
    warn_on_development_keys();
    verify(authorization, private_key)?;
    let mut tpm = open()?;
    if let Some(expected) = authorization.payload.expected_pcr_digest {
        if tpm.current_pcr_digest()? != expected {
            return Err(TpmError::RecoveryRefused(
                "the PCR state differs from the one the recovery was issued for".into(),
            ));
        }
    }
    anti_rollback::consume(&mut tpm, cfg, authorization.payload.counter)?;
    Ok(())
}

/// Signatures under the compiled keyring, then the binding of the private key
/// to the public key the publisher signed.
fn verify(authorization: &SignedWireGuardRecovery, private_key: &[u8; 32]) -> Result<()> {
    verify_wireguard_recovery(authorization, PUBLISHER_KEYS, private_key)
        .map_err(|error| TpmError::RecoveryRefused(error.to_string()))
}

fn warn_on_development_keys() {
    if USING_DEVELOPMENT_PUBLISHER_KEYS {
        static WARN_ONCE: Once = Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                "DEVELOPMENT publisher keyring used for WireGuard recovery — \
                 supply HELIOS_PUBLISHER_KEYRING_PATH for a production build"
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use aether::sig::{
        PublisherSigner, ResealPayload, SignedWireGuardRecovery, WireGuardRecoveryPayload,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    use super::*;
    use crate::tpm_interface::{CounterState, DryRunTpm};

    const DEV_ED_SEED: [u8; 32] = *b"helios-sign-ed25519-dev-seed-001";
    const DEV_ML_SEED: [u8; 32] = *b"helios-sign-mldsa65-dev-seed-001";
    const OTHER_ED_SEED: [u8; 32] = *b"helios-sign-ed25519-other-seed01";
    const OTHER_ML_SEED: [u8; 32] = *b"helios-sign-mldsa65-other-seed01";

    /// A WireGuard private key and the public key it derives to.
    fn gateway_identity() -> ([u8; 32], [u8; 32]) {
        let pair = aether::wg::generate_keypair().expect("keypair");
        let private = STANDARD
            .decode(pair.private_key.expose())
            .expect("base64 private key");
        let public = STANDARD
            .decode(&pair.public_key)
            .expect("base64 public key");
        (
            private.try_into().expect("32-byte private key"),
            public.try_into().expect("32-byte public key"),
        )
    }

    fn sign(
        counter: u64,
        gateway_public_key: [u8; 32],
        expected_pcr_digest: Option<[u8; 32]>,
    ) -> SignedWireGuardRecovery {
        PublisherSigner::from_seed_material(1, &DEV_ED_SEED, &DEV_ML_SEED)
            .unwrap()
            .sign(WireGuardRecoveryPayload {
                counter,
                gateway_public_key,
                expected_pcr_digest,
            })
            .unwrap()
    }

    /// A TPM over the shared counter, with the given PCR digest.
    fn tpm_with(counter: &CounterState, pcr: [u8; 32]) -> DryRunTpm {
        DryRunTpm::with_digest(pcr).sharing_counter(counter)
    }

    fn cfg(dir: &std::path::Path) -> TpmSettings {
        TpmSettings {
            simulated_counter_path: dir.join("simulated-nv-counter").to_string_lossy().into(),
            counter_status_path: dir.join("anti-rollback.json").to_string_lossy().into(),
            ..TpmSettings::default()
        }
    }

    /// A counter defined at its initial value, as the boot flow leaves it.
    fn counter_at_start() -> (CounterState, u64) {
        let counter = CounterState::default();
        let mut tpm = tpm_with(&counter, [1; 32]);
        tpm.ensure_counter().unwrap();
        let current = tpm.read_counter().unwrap();
        (counter, current)
    }

    fn counter_now(counter: &CounterState) -> u64 {
        tpm_with(counter, [1; 32]).read_counter().unwrap()
    }

    #[test]
    fn a_recovery_for_the_current_counter_is_accepted_and_spends_it() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (counter, current) = counter_at_start();
        let (private, public) = gateway_identity();
        let authorization = sign(current, public, None);

        accept_with(
            || Ok(tpm_with(&counter, [1; 32])),
            &cfg,
            &authorization,
            &private,
        )
        .unwrap();

        assert_eq!(counter_now(&counter), current + 1);
    }

    #[test]
    fn a_recovery_for_another_counter_is_refused_and_moves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (counter, current) = counter_at_start();
        let (private, public) = gateway_identity();
        let authorization = sign(current + 1, public, None);

        let error = accept_with(
            || Ok(tpm_with(&counter, [1; 32])),
            &cfg,
            &authorization,
            &private,
        )
        .unwrap_err();

        assert!(
            matches!(error, TpmError::CounterMismatch { artifact, current: now }
                if artifact == current + 1 && now == current),
            "{error:?}"
        );
        assert_eq!(counter_now(&counter), current);
    }

    #[test]
    fn an_undefined_counter_refuses_the_recovery_and_spends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (private, public) = gateway_identity();
        let authorization = sign(1, public, None);
        // No counter defined: its value cannot be read, so the recovery is refused.
        let undefined = CounterState::default();

        let error = accept_with(
            || Ok(tpm_with(&undefined, [1; 32])),
            &cfg,
            &authorization,
            &private,
        )
        .unwrap_err();

        assert!(
            matches!(error, TpmError::CounterUnavailable(_)),
            "{error:?}"
        );
        assert!(
            tpm_with(&undefined, [1; 32]).read_counter().is_err(),
            "the counter is still undefined: nothing was defined or spent"
        );
    }

    #[test]
    fn a_consumed_recovery_cannot_be_replayed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (counter, current) = counter_at_start();
        let (private, public) = gateway_identity();
        let authorization = sign(current, public, None);
        accept_with(
            || Ok(tpm_with(&counter, [1; 32])),
            &cfg,
            &authorization,
            &private,
        )
        .unwrap();

        let replay = accept_with(
            || Ok(tpm_with(&counter, [1; 32])),
            &cfg,
            &authorization,
            &private,
        );

        assert!(
            matches!(replay, Err(TpmError::CounterMismatch { .. })),
            "{replay:?}"
        );
    }

    #[test]
    fn a_key_that_does_not_derive_the_authorized_public_key_is_refused_before_the_counter() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (counter, current) = counter_at_start();
        let (_, public) = gateway_identity();
        let (foreign_private, _) = gateway_identity();
        let authorization = sign(current, public, None);

        let error = accept_with(
            || Ok(tpm_with(&counter, [1; 32])),
            &cfg,
            &authorization,
            &foreign_private,
        )
        .unwrap_err();

        assert!(matches!(error, TpmError::RecoveryRefused(_)), "{error:?}");
        assert_eq!(counter_now(&counter), current);
    }

    #[test]
    fn a_signature_from_an_unknown_key_is_refused_before_the_counter() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (counter, current) = counter_at_start();
        let (private, public) = gateway_identity();
        let authorization = PublisherSigner::from_seed_material(9, &OTHER_ED_SEED, &OTHER_ML_SEED)
            .unwrap()
            .sign(WireGuardRecoveryPayload {
                counter: current,
                gateway_public_key: public,
                expected_pcr_digest: None,
            })
            .unwrap();

        let error = accept_with(
            || Ok(tpm_with(&counter, [1; 32])),
            &cfg,
            &authorization,
            &private,
        )
        .unwrap_err();

        assert!(matches!(error, TpmError::RecoveryRefused(_)), "{error:?}");
        assert_eq!(counter_now(&counter), current);
    }

    #[test]
    fn a_tampered_payload_is_refused_before_the_counter() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (counter, current) = counter_at_start();
        let (private, public) = gateway_identity();
        let mut authorization = sign(current, public, None);
        authorization.payload.counter = current + 1;

        let error = accept_with(
            || Ok(tpm_with(&counter, [1; 32])),
            &cfg,
            &authorization,
            &private,
        )
        .unwrap_err();

        assert!(matches!(error, TpmError::RecoveryRefused(_)), "{error:?}");
        assert_eq!(counter_now(&counter), current);
    }

    /// Signatures made over another artifact's domain must not validate here,
    /// even with the same keys and epoch.
    #[test]
    fn a_signature_over_another_domain_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (counter, current) = counter_at_start();
        let (private, public) = gateway_identity();
        let reseal = PublisherSigner::from_seed_material(1, &DEV_ED_SEED, &DEV_ML_SEED)
            .unwrap()
            .sign(ResealPayload {
                counter: current,
                sealed_blob_anchor: [0; 32],
                expected_pcr_digest: None,
            })
            .unwrap();
        let transplanted = SignedWireGuardRecovery {
            payload: WireGuardRecoveryPayload {
                counter: current,
                gateway_public_key: public,
                expected_pcr_digest: None,
            },
            key_epoch: reseal.key_epoch,
            signatures: reseal.signatures,
        };

        let error = accept_with(
            || Ok(tpm_with(&counter, [1; 32])),
            &cfg,
            &transplanted,
            &private,
        )
        .unwrap_err();

        assert!(matches!(error, TpmError::RecoveryRefused(_)), "{error:?}");
        assert_eq!(counter_now(&counter), current);
    }

    #[test]
    fn a_pcr_mismatch_is_refused_before_the_counter() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (counter, current) = counter_at_start();
        let (private, public) = gateway_identity();
        let authorization = sign(current, public, Some([9; 32]));

        let error = accept_with(
            || Ok(tpm_with(&counter, [1; 32])),
            &cfg,
            &authorization,
            &private,
        )
        .unwrap_err();

        assert!(matches!(error, TpmError::RecoveryRefused(_)), "{error:?}");
        assert_eq!(counter_now(&counter), current);
    }

    #[test]
    fn a_matching_pcr_binding_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg(dir.path());
        let (counter, current) = counter_at_start();
        let (private, public) = gateway_identity();
        let authorization = sign(current, public, Some([1; 32]));

        accept_with(
            || Ok(tpm_with(&counter, [1; 32])),
            &cfg,
            &authorization,
            &private,
        )
        .unwrap();

        assert_eq!(counter_now(&counter), current + 1);
    }
}
