//! Authenticated restoration of the same root after firmware changes PCR 0/7.
//! Backup ciphertext belongs to the operator; its private key never reaches
//! the gateway. The nominal PCR selection is never relaxed (ADR-007).

use aether::sig::{FirmwareRecoveryPayload, SignedFirmwareRecovery, PUBLISHER_KEYS};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    blob_store::BlobStore, boot_controller::open_tpm, provisioning, tpm_interface::TpmSealer,
    Result, SecretKey, TpmError, TpmSettings,
};

/// Contains only public authorization context and an encrypted escrow.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirmwareBackup {
    pub request: FirmwareRecoveryPayload,
    pub encrypted_secret: Vec<u8>,
}

/// Bound for the offline SSH input protocol. Only the authorization is JSON;
/// the root remains an opaque fixed-length suffix in a zeroizing buffer.
pub const MAX_RESTORE_FRAME: usize = 65_536;

pub fn encode_restore_frame(
    authorization: &SignedFirmwareRecovery,
    secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if secret.len() != 32 {
        return Err(refused("invalid root length"));
    }
    let json = serde_json::to_vec(authorization).map_err(|e| TpmError::Serde(e.to_string()))?;
    if json.len() > MAX_RESTORE_FRAME - 36 {
        return Err(refused("authorization exceeds the frame limit"));
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + json.len() + 32));
    frame.extend_from_slice(&(json.len() as u32).to_be_bytes());
    frame.extend_from_slice(&json);
    frame.extend_from_slice(secret);
    Ok(frame)
}

pub fn decode_restore_frame(frame: &[u8]) -> Result<(SignedFirmwareRecovery, &[u8])> {
    if frame.len() < 36 || frame.len() > MAX_RESTORE_FRAME {
        return Err(refused("invalid recovery frame size"));
    }
    let length = u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| refused("invalid frame header"))?,
    ) as usize;
    if length > MAX_RESTORE_FRAME - 36 || frame.len() != 4 + length + 32 {
        return Err(refused("invalid recovery frame length"));
    }
    let auth = serde_json::from_slice(&frame[4..4 + length])
        .map_err(|e| TpmError::Serde(e.to_string()))?;
    Ok((auth, &frame[4 + length..]))
}

fn refused(reason: impl Into<String>) -> TpmError {
    TpmError::FirmwareRecovery(reason.into())
}

pub fn commitment(anchor: &[u8; 32], secret: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"helios-firmware-root-commitment-v1");
    digest.update(anchor);
    digest.update(secret);
    digest.finalize().into()
}

pub fn export(
    cfg: &TpmSettings,
    operator_public: &[u8],
    device_id: String,
    target_version: String,
) -> Result<FirmwareBackup> {
    require_enabled(cfg)?;
    export_with(
        &mut open_tpm(cfg)?,
        &BlobStore::new(cfg),
        operator_public,
        device_id,
        target_version,
    )
}

fn require_enabled(cfg: &TpmSettings) -> Result<()> {
    if !cfg.enabled || !cfg.enforce {
        return Err(refused("an enforced TPM-enabled binary is required"));
    }
    Ok(())
}

fn export_with(
    tpm: &mut impl TpmSealer,
    store: &BlobStore<'_>,
    public: &[u8],
    device_id: String,
    target_version: String,
) -> Result<FirmwareBackup> {
    clean_state(store)?;
    let blob = store.load_blob()?.ok_or(TpmError::MissingBlobOnField)?;
    // Direct nominal unseal: never consume a ticket or recover a window while
    // claiming this is a safe pre-maintenance export.
    let root = tpm.unseal(&blob)?;
    let anchor = Sha256::digest(blob.as_bytes()).into();
    let version = store
        .load_state()?
        .version
        .checked_add(1)
        .ok_or_else(|| refused("anti-replay counter exhausted"))?;
    let request = FirmwareRecoveryPayload {
        version,
        sealed_blob_anchor: anchor,
        secret_commitment: commitment(&anchor, root.as_bytes()),
        device_id,
        target_version,
    };
    request.validate().map_err(refused)?;
    // A missing marker excludes a legitimate live OS window. Revoke any
    // orphaned NV copy by Owner, without reading a PCR-bound old index.
    provisioning::disarm_window(tpm, store)?;
    let encrypted_secret = helios_escrow::seal_to_operator(public, root.as_bytes())
        .map_err(|e| refused(e.to_string()))?;
    Ok(FirmwareBackup {
        request,
        encrypted_secret,
    })
}

fn clean_state(store: &BlobStore<'_>) -> Result<()> {
    if store.load_ticket()?.is_some() || store.load_window_marker()?.is_some() {
        return Err(refused(
            "cancel the OS window and remove any reseal ticket before firmware maintenance",
        ));
    }
    Ok(())
}

/// Public preflight checks on the gateway, before any installation.
pub fn preflight(cfg: &TpmSettings, authorization: &SignedFirmwareRecovery) -> Result<()> {
    require_enabled(cfg)?;
    let store = BlobStore::new(cfg);
    let mut tpm = open_tpm(cfg)?;
    validate_authorization(authorization)?;
    clean_state(&store)?;
    check_anchor_and_version(&store, &authorization.payload)?;
    let blob = store.load_blob()?.ok_or(TpmError::MissingBlobOnField)?;
    let root = tpm.unseal(&blob)?;
    check_secret(&authorization.payload, root.as_bytes())?;
    provisioning::disarm_window(&mut tpm, &store)
}

pub fn validate_authorization(authorization: &SignedFirmwareRecovery) -> Result<()> {
    authorization
        .verify(PUBLISHER_KEYS)
        .map_err(|_| TpmError::TicketInvalidSignature)?;
    authorization.payload.validate().map_err(refused)
}

fn check_anchor_and_version(
    store: &BlobStore<'_>,
    request: &FirmwareRecoveryPayload,
) -> Result<()> {
    let current = store.load_state()?.version;
    if request.version <= current {
        return Err(TpmError::TicketRollback {
            ticket: request.version,
            current,
        });
    }
    let blob = store.load_blob()?.ok_or(TpmError::MissingBlobOnField)?;
    let anchor: [u8; 32] = Sha256::digest(blob.as_bytes()).into();
    if anchor != request.sealed_blob_anchor {
        return Err(refused("backup belongs to another sealed root"));
    }
    Ok(())
}

pub fn check_secret(request: &FirmwareRecoveryPayload, secret: &[u8]) -> Result<()> {
    if secret.len() != 32
        || commitment(&request.sealed_blob_anchor, secret) != request.secret_commitment
    {
        return Err(refused(
            "recovered root does not match the signed commitment",
        ));
    }
    Ok(())
}

/// Returns `true` if the same root was already sealed on this boot. This is
/// safe to retry after a lost SSH response without replaying a mutation.
pub fn restore(
    cfg: &TpmSettings,
    authorization: &SignedFirmwareRecovery,
    recovered: &[u8],
) -> Result<bool> {
    require_enabled(cfg)?;
    restore_with(
        &mut open_tpm(cfg)?,
        &BlobStore::new(cfg),
        authorization,
        recovered,
    )
}

fn restore_with(
    tpm: &mut impl TpmSealer,
    store: &BlobStore<'_>,
    authorization: &SignedFirmwareRecovery,
    recovered: &[u8],
) -> Result<bool> {
    validate_authorization(authorization)?;
    check_secret(&authorization.payload, recovered)?;
    clean_state(store)?;
    let blob = store.load_blob()?.ok_or(TpmError::MissingBlobOnField)?;
    match tpm.unseal(&blob) {
        Ok(root) => {
            check_secret(&authorization.payload, root.as_bytes())?;
            provisioning::disarm_window(tpm, store)?;
            return Ok(true);
        }
        Err(TpmError::UnsealPolicyFail) => {}
        Err(error) => return Err(error),
    }
    check_anchor_and_version(store, &authorization.payload)?;
    let bytes = Zeroizing::new(
        <[u8; 32]>::try_from(recovered).map_err(|_| refused("invalid root length"))?,
    );
    let root = SecretKey::from_bytes(*bytes);
    let replacement = tpm.seal(&root)?;
    // Verify the replacement before consuming authorization or touching disk.
    let verified = tpm.unseal(&replacement)?;
    check_secret(&authorization.payload, verified.as_bytes())?;
    provisioning::disarm_window(tpm, store)?;
    let mut state = store.load_state()?;
    state.version = authorization.payload.version;
    // Counter first: interruption between these writes consumes authorization,
    // rather than permitting replay. Recovery then requires a newer signed
    // authorization; the encrypted backup still contains the original root.
    store.store_state(&state)?;
    store.store_blob(&replacement)?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm_interface::DryRunTpm;
    use aether::sig::PublisherSigner;

    fn setup() -> (
        tempfile::TempDir,
        TpmSettings,
        DryRunTpm,
        FirmwareBackup,
        Zeroizing<Vec<u8>>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = TpmSettings {
            enabled: true,
            sealed_blob_path: dir.path().join("root").to_str().unwrap().into(),
            state_path: dir.path().join("state").to_str().unwrap().into(),
            ticket_path: dir.path().join("ticket").to_str().unwrap().into(),
            update_window_marker_path: dir.path().join("window").to_str().unwrap().into(),
            ..TpmSettings::default()
        };
        let mut tpm = DryRunTpm::with_digest([1; 32]);
        let root = SecretKey::generate().unwrap();
        BlobStore::new(&cfg)
            .store_blob(&tpm.seal(&root).unwrap())
            .unwrap();
        let (private, public) = helios_escrow::generate_operator_keypair().unwrap();
        let backup = export_with(
            &mut tpm,
            &BlobStore::new(&cfg),
            &public,
            "5bc922b7bd1adb5b6f99592611404036bd9f42d0".into(),
            "2023".into(),
        )
        .unwrap();
        let recovered =
            helios_escrow::open_as_operator(private.as_slice(), &backup.encrypted_secret).unwrap();
        (dir, cfg, tpm, backup, recovered)
    }
    fn sign(request: FirmwareRecoveryPayload) -> SignedFirmwareRecovery {
        PublisherSigner::from_seed_material(
            1,
            b"helios-sign-ed25519-dev-seed-001",
            b"helios-sign-mldsa65-dev-seed-001",
        )
        .unwrap()
        .sign(request)
        .unwrap()
    }
    #[test]
    fn firmware_recovery_preserves_the_root_across_pcr_0_and_7_changes() {
        let (_dir, cfg, _old, backup, recovered) = setup();
        let auth = sign(backup.request);
        let mut new = DryRunTpm::with_digest([9; 32]).with_window_digest([8; 32]);
        assert!(!restore_with(&mut new, &BlobStore::new(&cfg), &auth, &recovered).unwrap());
        let store = BlobStore::new(&cfg);
        assert_eq!(
            new.unseal(&store.load_blob().unwrap().unwrap())
                .unwrap()
                .as_bytes()
                .as_slice(),
            recovered.as_slice()
        );
        assert_eq!(store.load_state().unwrap().version, 1);
        assert!(restore_with(&mut new, &store, &auth, &recovered).unwrap());
        let mut later = DryRunTpm::with_digest([10; 32]);
        assert!(restore_with(&mut later, &store, &auth, &recovered).is_err());
    }
    #[test]
    fn unauthenticated_wrong_root_and_stale_requests_never_replace_the_blob() {
        let (_dir, cfg, _old, backup, recovered) = setup();
        let store = BlobStore::new(&cfg);
        let before = store.load_blob().unwrap().unwrap();
        let auth = sign(backup.request);
        let mut changed = DryRunTpm::with_digest([9; 32]);
        let mut bad = auth.clone();
        bad.signatures.pop();
        assert!(restore_with(&mut changed, &store, &bad, &recovered).is_err());
        assert!(restore_with(&mut changed, &store, &auth, &[42; 32]).is_err());
        let mut bad = auth.clone();
        bad.payload.device_id.replace_range(..1, "0");
        assert!(restore_with(&mut changed, &store, &bad, &recovered).is_err());
        let mut state = store.load_state().unwrap();
        state.version = 1;
        store.store_state(&state).unwrap();
        assert!(restore_with(&mut changed, &store, &auth, &recovered).is_err());
        assert_eq!(
            before.as_bytes(),
            store.load_blob().unwrap().unwrap().as_bytes()
        );
    }
    #[test]
    fn export_requires_nominal_unseal_and_no_window_or_ticket() {
        let (_dir, cfg, mut old, backup, _recovered) = setup();
        let (_, public) = helios_escrow::generate_operator_keypair().unwrap();
        let store = BlobStore::new(&cfg);
        let mut changed = DryRunTpm::with_digest([9; 32]);
        assert!(export_with(
            &mut changed,
            &store,
            &public,
            backup.request.device_id.clone(),
            "2023".into()
        )
        .is_err());
        store
            .store_window_marker(&crate::tpm_interface::SealedBlob::from_bytes(
                b"marker".to_vec(),
            ))
            .unwrap();
        assert!(export_with(
            &mut old,
            &store,
            &public,
            backup.request.device_id,
            "2023".into()
        )
        .is_err());
        assert!(store.load_state().unwrap().version == 0);
    }
    struct FaultTpm {
        inner: DryRunTpm,
        fail_seal: bool,
        fail_revoke: bool,
    }
    impl TpmSealer for FaultTpm {
        fn current_pcr_digest(&mut self) -> Result<[u8; 32]> {
            self.inner.current_pcr_digest()
        }
        fn seal(&mut self, secret: &SecretKey) -> Result<crate::tpm_interface::SealedBlob> {
            if self.fail_seal {
                return Err(TpmError::Connection("seal failed".into()));
            }
            self.inner.seal(secret)
        }
        fn unseal(&mut self, blob: &crate::tpm_interface::SealedBlob) -> Result<SecretKey> {
            self.inner.unseal(blob)
        }
        fn arm_update_window(&mut self, payload: &[u8]) -> Result<()> {
            self.inner.arm_update_window(payload)
        }
        fn unseal_update_window(&mut self) -> Result<Zeroizing<Vec<u8>>> {
            Err(TpmError::UnsealPolicyFail)
        }
        fn update_window_armed(&mut self) -> Result<bool> {
            panic!("firmware recovery must not read an NV index bound to old PCR 0/7")
        }
        fn revoke_update_window(&mut self) -> Result<()> {
            if self.fail_revoke {
                return Err(TpmError::Connection("NV unavailable".into()));
            }
            self.inner.revoke_update_window()
        }
    }
    #[test]
    fn recovery_preserves_both_vaults_without_reading_the_old_nv_policy() {
        let (dir, cfg, _old, backup, recovered) = setup();
        let old_root = SecretKey::from_bytes(recovered.as_slice().try_into().unwrap());
        let context = crate::Context::new().field("gateway", b"same identity");
        let wg = crate::SealedKeystore::new(dir.path().join("wg"), crate::DOMAIN_GATEWAY_WG_KEY);
        let negotiation = crate::SealedKeystore::new(
            dir.path().join("negotiation"),
            crate::DOMAIN_KEY_NEGOTIATION_IDENTITY,
        );
        wg.store(&old_root, &context, b"wireguard private identity")
            .unwrap();
        negotiation
            .store(&old_root, &context, b"negotiation keys and static PSKs")
            .unwrap();
        let auth = sign(backup.request);
        let mut new = FaultTpm {
            inner: DryRunTpm::with_digest([9; 32]).with_window_digest([8; 32]),
            fail_seal: false,
            fail_revoke: false,
        };
        restore_with(&mut new, &BlobStore::new(&cfg), &auth, &recovered).unwrap();
        let root = new
            .unseal(&BlobStore::new(&cfg).load_blob().unwrap().unwrap())
            .unwrap();
        assert_eq!(
            wg.load(&root, &context).unwrap().as_slice(),
            b"wireguard private identity"
        );
        assert_eq!(
            negotiation.load(&root, &context).unwrap().as_slice(),
            b"negotiation keys and static PSKs"
        );
    }
    #[test]
    fn sealing_and_nv_errors_preserve_the_old_blob_and_unspent_counter() {
        let (_dir, cfg, _old, backup, recovered) = setup();
        let store = BlobStore::new(&cfg);
        let before = store.load_blob().unwrap().unwrap();
        let auth = sign(backup.request);
        for (fail_seal, fail_revoke) in [(true, false), (false, true)] {
            let mut tpm = FaultTpm {
                inner: DryRunTpm::with_digest([9; 32]),
                fail_seal,
                fail_revoke,
            };
            assert!(restore_with(&mut tpm, &store, &auth, &recovered).is_err());
            assert_eq!(
                store.load_blob().unwrap().unwrap().as_bytes(),
                before.as_bytes()
            );
            assert_eq!(store.load_state().unwrap().version, 0);
        }
    }
}
