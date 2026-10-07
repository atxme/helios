//! **Real** TPM2 backend — hardened sealing/unsealing (target only).
//!
//! Warning: **security-critical module, fully validatable only on real TPM hardware.**
//! Like `helios-firewall/src/netlink.rs`, this code only compiles with
//! `--features tpm` (libtss2-esys present). A software TPM exercises the ESAPI
//! command flow, but PCR measurement, Secure Boot, bus protection, and NV
//! persistence must still be re-checked during hardware bring-up.
//!
//! ## Hardening measures applied
//!
//! 1. **PCR binding by policy (PolicyPCR)**: the secret is only unsealable if
//!    PCR 0/4/7 (SHA-256 bank) are identical to sealing time. A tampered
//!    kernel or bootloader changes the PCRs -> `TPM2_RC_POLICY_FAIL`.
//! 2. **Salted + encrypted sessions (anti-sniffing on the SPI/I2C bus)**:
//!    the sessions carrying the secret (Create, Unseal) are *salted* by the
//!    ECC primary key and carry the `decrypt|encrypt` attributes. The secret
//!    never transits in the clear on the hardware bus — a direct mitigation
//!    of the MITM attack described in the threat model.
//! 3. **Non-duplicable object**: `fixedTPM` + `fixedParent` bind the blob to
//!    *this* TPM; it is unusable elsewhere even if copied.
//! 4. **Authorization by policy alone**: `userWithAuth = false` forbids
//!    unsealing by simple password; only the PCR policy opens the object.
//! 5. **Weak bank refused**: SHA-1 is rejected; only SHA-256 is accepted.
//! 6. **Handle hygiene**: transient sessions and objects are systematically
//!    purged (`flush_context`), including on the error path.
//! 7. **Secret minimized in memory**: the unsealed data is immediately
//!    copied into [`SecretKey`] (zeroized on drop) and intermediate buffers
//!    are wiped.

use std::str::FromStr;

use sha2::{Digest as _, Sha256};
use tss_esapi::{
    attributes::{NvIndexAttributesBuilder, ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{
        nv_index_type::NvIndexType, CapabilityType, CommandCode, SessionType, Tss2ResponseCodeKind,
    },
    handles::{KeyHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle, SessionHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::AesKeyBits,
        resource_handles::{Hierarchy, NvAuth, Provision},
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        CapabilityData, Digest, EccPoint, EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme,
        MaxNvBuffer, NvPublicBuilder, Private, Public, PublicBuilder, PublicEccParametersBuilder,
        PublicKeyedHashParameters, SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    Context, Error as TssError, TctiNameConf,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    secret::SecretKey,
    tpm_interface::{SealedBlob, TpmSealer},
    update_window::{is_armed_payload, is_armed_prefix, PAYLOAD_LEN},
    Result, TpmError,
};

/// Header of the persistent blob: magic + version + bank + PCR selection.
/// Storing the selection keeps unsealing self-consistent even if the config drifts.
const BLOB_MAGIC: &[u8; 4] = b"HTPM";
const BLOB_VERSION: u8 = 1;
const BANK_SHA256: u8 = 1;

pub(crate) struct TpmDevice {
    device_path: String,
    bank: String,
    indices: Vec<u8>,
    window_indices: Vec<u8>,
    window_nv_index: u32,
}

impl TpmDevice {
    pub(crate) fn new(cfg: &crate::settings::TpmSettings) -> Result<Self> {
        // Immediate refusal of weak banks (SHA-1) — defense in depth.
        hash_alg_from_bank(&cfg.pcr_bank)?;
        // The window must never be able to open more than the nominal policy:
        // a selection that drifted out of subset would silently widen what a
        // planned upgrade unlocks.
        if cfg.update_window_pcr_selection != [0, 7] {
            return Err(TpmError::Connection(
                "update-window PCR selection must be exactly [0, 7]".into(),
            ));
        }
        if !cfg
            .update_window_pcr_selection
            .iter()
            .all(|index| cfg.pcr_selection.contains(index))
            || cfg.update_window_pcr_selection.len() >= cfg.pcr_selection.len()
        {
            return Err(TpmError::Connection(
                "update-window PCR selection must be a strict subset of nominal sealing".into(),
            ));
        }
        if cfg.update_window_seconds == 0 {
            return Err(TpmError::Connection(
                "update-window duration must be greater than zero".into(),
            ));
        }
        Ok(Self {
            device_path: cfg.device.clone(),
            bank: cfg.pcr_bank.clone(),
            indices: cfg.pcr_selection.clone(),
            window_indices: cfg.update_window_pcr_selection.clone(),
            window_nv_index: cfg.update_window_nv_index,
        })
    }
}

impl TpmSealer for TpmDevice {
    fn current_pcr_digest(&mut self) -> Result<[u8; 32]> {
        let mut ctx = open_context(&self.device_path)?;
        let alg = hash_alg_from_bank(&self.bank)?;
        let selection = pcr_selection(alg, &self.indices)?;

        let (_, _, digests) = ctx.pcr_read(selection).map_err(|e| TpmError::PcrRead {
            index: 0,
            cause: e.to_string(),
        })?;

        // Identity digest of the PCR state (used to bind the reseal ticket):
        // SHA-256 of the concatenation of the PCR values read, in order.
        let mut hasher = Sha256::new();
        for d in digests.value() {
            hasher.update(d.value());
        }
        Ok(hasher.finalize().into())
    }

    fn seal(&mut self, secret: &SecretKey) -> Result<SealedBlob> {
        let mut ctx = open_context(&self.device_path)?;
        let alg = hash_alg_from_bank(&self.bank)?;
        let selection = pcr_selection(alg, &self.indices)?;

        // ECC primary key (Owner hierarchy): serves both as the blob's parent
        // and as the salt key for encrypted sessions. Deterministic for this TPM.
        let primary = create_primary(&mut ctx)?;

        let outcome = (|| {
            // authPolicy = PCR policy digest computed by the TPM over the
            // current PCRs (trial session -> the digest is not secret).
            let auth_policy = compute_pcr_policy_digest(&mut ctx, alg, &selection)?;
            let public = sealed_template(auth_policy)?;

            // Salted + encrypted HMAC session: protects the secret (command
            // parameter) against bus eavesdropping during TPM2_Create.
            let session = start_salted_session(&mut ctx, primary.key_handle, SessionType::Hmac)?;

            let mut sensitive_bytes = secret.as_bytes().to_vec();
            let sensitive = SensitiveData::try_from(sensitive_bytes.clone())
                .map_err(|e| TpmError::Connection(format!("sensitive: {e}")))?;
            sensitive_bytes.zeroize();

            let created = ctx
                .execute_with_session(Some(session), |ctx| {
                    ctx.create(
                        primary.key_handle,
                        public,
                        None,
                        Some(sensitive),
                        None,
                        None,
                    )
                })
                .map_err(|e| TpmError::Connection(format!("create (seal): {e}")));

            log_cleanup_error(
                "flush seal session",
                ctx.flush_context(SessionHandle::from(session).into()),
            );
            let created = created?;

            let blob = marshal_blob(&self.indices, &created.out_public, &created.out_private)?;
            Ok(SealedBlob::from_bytes(blob))
        })();

        log_cleanup_error(
            "flush seal primary",
            ctx.flush_context(primary.key_handle.into()),
        );
        outcome
    }

    fn unseal(&mut self, blob: &SealedBlob) -> Result<SecretKey> {
        let mut ctx = open_context(&self.device_path)?;
        let (indices, public, private) = unmarshal_blob(blob.as_bytes())?;
        let alg = hash_alg_from_bank(&self.bank)?;
        let selection = pcr_selection(alg, &indices)?;

        let primary = create_primary(&mut ctx)?;

        let outcome = (|| {
            // Loads the sealed object under the primary (parent auth = null).
            let object: ObjectHandle = ctx
                .execute_with_nullauth_session(|ctx| ctx.load(primary.key_handle, private, public))
                .map_err(|e| TpmError::Connection(format!("load (unseal): {e}")))?
                .into();

            // Salted + encrypted policy session: PolicyPCR reads the current
            // PCRs, and the `encrypt` attribute encrypts the secret returned on the bus.
            let session = start_salted_session(&mut ctx, primary.key_handle, SessionType::Policy)?;
            let policy_session = PolicySession::try_from(session)
                .map_err(|e| TpmError::Connection(format!("policy session: {e}")))?;

            let policy_step = ctx
                .policy_pcr(policy_session, empty_digest()?, selection)
                .map_err(|e| TpmError::Connection(format!("policy_pcr: {e}")));

            let unsealed = policy_step.and_then(|()| {
                ctx.execute_with_session(Some(session), |ctx| ctx.unseal(object))
                    .map_err(|e| {
                        // PCRs changed -> TPM2_RC_POLICY_FAIL: this is the
                        // signal of an OTA (resealing under ticket) or of tampering (refusal).
                        if is_policy_fail(&e) {
                            TpmError::UnsealPolicyFail
                        } else {
                            TpmError::Connection(format!("unseal: {e}"))
                        }
                    })
            });

            log_cleanup_error(
                "flush unseal session",
                ctx.flush_context(SessionHandle::from(session).into()),
            );
            log_cleanup_error("flush unseal object", ctx.flush_context(object));

            let sensitive = unsealed?;
            to_secret_key(sensitive)
        })();

        log_cleanup_error(
            "flush unseal primary",
            ctx.flush_context(primary.key_handle.into()),
        );
        outcome
    }

    // ── Update window ────────────────────────────────────────────────────────

    fn arm_update_window(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() != PAYLOAD_LEN {
            return Err(TpmError::Connection(format!(
                "update-window payload has {} bytes; {PAYLOAD_LEN} expected",
                payload.len(),
            )));
        }
        let mut ctx = open_context(&self.device_path)?;
        let alg = hash_alg_from_bank(&self.bank)?;
        let selection = pcr_selection(alg, &self.window_indices)?;

        let primary = create_primary(&mut ctx)?;
        let outcome = (|| {
            let auth_policy = compute_window_policy_digest(&mut ctx, &selection)?;
            let handle =
                redefine_window_index(&mut ctx, self.window_nv_index, auth_policy, payload.len())?;
            let session = start_salted_session(&mut ctx, primary.key_handle, SessionType::Hmac)?;
            let data = MaxNvBuffer::try_from(payload.to_vec())
                .map_err(|e| TpmError::Connection(format!("NV payload: {e}")))?;
            let written = ctx
                .execute_with_session(Some(session), |ctx| {
                    ctx.nv_write(NvAuth::Owner, handle, data, 0)
                })
                .map_err(|e| TpmError::Connection(format!("NV write (arm window): {e}")));

            log_cleanup_error(
                "flush update-window write session",
                ctx.flush_context(SessionHandle::from(session).into()),
            );
            let mut object = ObjectHandle::from(handle);
            log_cleanup_error("close update-window write index", ctx.tr_close(&mut object));
            written
        })();

        log_cleanup_error(
            "flush update-window write primary",
            ctx.flush_context(primary.key_handle.into()),
        );
        outcome
    }

    fn unseal_update_window(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        self.read_update_window_payload()?
            .ok_or(TpmError::UpdateWindowUnavailable)
    }

    fn revoke_update_window(&mut self) -> Result<()> {
        let mut ctx = open_context(&self.device_path)?;
        let Some(handle) = open_nv_index(&mut ctx, self.window_nv_index)? else {
            return Ok(());
        };
        let data = MaxNvBuffer::try_from(vec![0u8; PAYLOAD_LEN])
            .map_err(|e| TpmError::Connection(format!("NV buffer: {e}")))?;
        let written = ctx
            .execute_with_nullauth_session(|ctx| ctx.nv_write(NvAuth::Owner, handle, data, 0))
            .map_err(|e| TpmError::Connection(format!("NV write (revoke window): {e}")));
        let mut object = ObjectHandle::from(handle);
        log_cleanup_error(
            "close revoked update-window index",
            ctx.tr_close(&mut object),
        );
        written
    }

    fn update_window_armed(&mut self) -> Result<bool> {
        Ok(self
            .read_update_window_bytes(4)?
            .is_some_and(|prefix| is_armed_prefix(&prefix)))
    }
}

impl TpmDevice {
    /// Reads the policy-protected NV slot. The secret never exists in a disk
    /// blob; revocation overwrites this data area inside the TPM.
    fn read_update_window_payload(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let data = self.read_update_window_bytes(PAYLOAD_LEN as u16)?;
        Ok(data.filter(|bytes| is_armed_payload(bytes)))
    }

    /// Reads part of the policy-protected NV slot through an encrypted
    /// session. Callers that only need status read four magic bytes so the
    /// secret does not leave the TPM.
    fn read_update_window_bytes(&self, size: u16) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let mut ctx = open_context(&self.device_path)?;
        let Some(handle) = open_nv_index(&mut ctx, self.window_nv_index)? else {
            return Ok(None);
        };
        let alg = hash_alg_from_bank(&self.bank)?;
        let selection = pcr_selection(alg, &self.window_indices)?;
        let primary = create_primary(&mut ctx)?;

        let outcome = (|| {
            let session = start_salted_session(&mut ctx, primary.key_handle, SessionType::Policy)?;
            let policy_session = PolicySession::try_from(session)
                .map_err(|e| TpmError::Connection(format!("policy session (window): {e}")))?;
            let policy_step = window_policy_steps(&mut ctx, policy_session, selection);
            let read = policy_step.and_then(|()| {
                ctx.execute_with_session(Some(session), |ctx| {
                    ctx.nv_read(NvAuth::NvIndex(handle), handle, size, 0)
                })
                .map_err(|error| {
                    if is_policy_fail(&error) {
                        TpmError::UnsealPolicyFail
                    } else {
                        TpmError::Connection(format!("NV read (window): {error}"))
                    }
                })
            });
            log_cleanup_error(
                "flush update-window read session",
                ctx.flush_context(SessionHandle::from(session).into()),
            );
            read
        })();

        log_cleanup_error(
            "flush update-window read primary",
            ctx.flush_context(primary.key_handle.into()),
        );
        let mut object = ObjectHandle::from(handle);
        log_cleanup_error("close update-window read index", ctx.tr_close(&mut object));
        Ok(Some(Zeroizing::new(outcome?.value().to_vec())))
    }
}

// ─────────────────────────────── Helpers TPM2 ───────────────────────────────

fn open_context(device: &str) -> Result<Context> {
    let tcti_name = if device.contains(':') {
        device.to_string()
    } else {
        format!("device:{device}")
    };
    let tcti = TctiNameConf::from_str(&tcti_name)
        .map_err(|e| TpmError::Connection(format!("TCTI {device}: {e}")))?;
    Context::new(tcti).map_err(|e| TpmError::Connection(e.to_string()))
}

/// Refuses any bank other than SHA-256 (obsolete SHA-1 = attack vector).
fn hash_alg_from_bank(bank: &str) -> Result<HashingAlgorithm> {
    match bank.to_ascii_lowercase().as_str() {
        "sha256" => Ok(HashingAlgorithm::Sha256),
        other => Err(TpmError::Connection(format!(
            "PCR bank refused: {other} (only sha256 is allowed)"
        ))),
    }
}

fn pcr_selection(
    alg: HashingAlgorithm,
    indices: &[u8],
) -> Result<tss_esapi::structures::PcrSelectionList> {
    use tss_esapi::structures::{PcrSelectionListBuilder, PcrSlot};

    let slot_for = |i: &u8| -> Result<PcrSlot> {
        Ok(match i {
            0 => PcrSlot::Slot0,
            1 => PcrSlot::Slot1,
            2 => PcrSlot::Slot2,
            3 => PcrSlot::Slot3,
            4 => PcrSlot::Slot4,
            5 => PcrSlot::Slot5,
            6 => PcrSlot::Slot6,
            7 => PcrSlot::Slot7,
            other => {
                return Err(TpmError::PcrRead {
                    index: *other,
                    cause: "unsupported PCR index (0-7 expected)".into(),
                })
            }
        })
    };
    let slots: Vec<PcrSlot> = indices.iter().map(slot_for).collect::<Result<_>>()?;
    PcrSelectionListBuilder::new()
        .with_selection(alg, &slots)
        .build()
        .map_err(|e| TpmError::Connection(format!("PCR selection: {e}")))
}

fn empty_digest() -> Result<Digest> {
    Digest::try_from(Vec::<u8>::new())
        .map_err(|e| TpmError::Connection(format!("empty digest: {e}")))
}

/// Template of the ECC P-256 primary key (restricted storage key).
/// Deterministic: recreated identically at unseal time -> same parent.
fn primary_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()
        .map_err(|e| TpmError::Connection(format!("primary attributes: {e}")))?;

    let ecc = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        // Symmetric scheme of the storage key: AES-128-CFB.
        .with_symmetric(SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes128,
            mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
        })
        .build()
        .map_err(|e| TpmError::Connection(format!("primary ECC params: {e}")))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| TpmError::Connection(format!("primary template: {e}")))
}

/// Template of the sealed object (keyedhash, supplied data) bound to `auth_policy`.
fn sealed_template(auth_policy: Digest) -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        // We supply the data -> the origin is not the TPM.
        .with_sensitive_data_origin(false)
        // No password auth: only the PCR policy opens the object.
        .with_user_with_auth(false)
        .with_admin_with_policy(true)
        .with_no_da(true)
        .with_restricted(false)
        .with_decrypt(false)
        .with_sign_encrypt(false)
        .build()
        .map_err(|e| TpmError::Connection(format!("sealed attributes: {e}")))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_auth_policy(auth_policy)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(empty_digest()?)
        .build()
        .map_err(|e| TpmError::Connection(format!("sealed template: {e}")))
}

fn create_primary(ctx: &mut Context) -> Result<tss_esapi::structures::CreatePrimaryKeyResult> {
    let public = primary_template()?;
    ctx.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
    })
    .map_err(|e| TpmError::Connection(format!("create_primary: {e}")))
}

/// Salted session (by the ECC primary) with parameter encryption.
///
/// The salt makes the session key inaccessible to passive bus eavesdropping;
/// `decrypt|encrypt` encrypt the sensitive parameters (secret) in both directions.
fn start_salted_session(
    ctx: &mut Context,
    salt_key: KeyHandle,
    session_type: SessionType,
) -> Result<AuthSession> {
    let session = ctx
        .start_auth_session(
            Some(salt_key), // salt key -> resistance to bus sniffing
            None,
            None,
            session_type,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| TpmError::Connection(format!("start_auth_session: {e}")))?
        .ok_or_else(|| TpmError::Connection("empty authorization session".into()))?;

    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .with_continue_session(true)
        .build();
    ctx.tr_sess_set_attributes(session, attrs, mask)
        .map_err(|e| TpmError::Connection(format!("session attributes: {e}")))?;

    Ok(session)
}

/// Computes the PCR policy digest via a trial session (public digest).
fn compute_pcr_policy_digest(
    ctx: &mut Context,
    _alg: HashingAlgorithm,
    selection: &tss_esapi::structures::PcrSelectionList,
) -> Result<Digest> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| TpmError::Connection(format!("trial session: {e}")))?
        .ok_or_else(|| TpmError::Connection("empty trial session".into()))?;

    let result = (|| {
        let policy_session = PolicySession::try_from(session)
            .map_err(|e| TpmError::Connection(format!("policy session: {e}")))?;
        // Empty pcrDigest -> the TPM incorporates the current PCR values.
        ctx.policy_pcr(policy_session, empty_digest()?, selection.clone())
            .map_err(|e| TpmError::Connection(format!("policy_pcr (trial): {e}")))?;
        ctx.policy_get_digest(policy_session)
            .map_err(|e| TpmError::Connection(format!("policy_get_digest: {e}")))
    })();

    log_cleanup_error(
        "flush PCR policy session",
        ctx.flush_context(SessionHandle::from(session).into()),
    );
    result
}

// ───────────────────────────── Update window ─────────────────────────────

/// The window's policy, in the order both sessions must replay.
///
/// A policy digest is a chain: the same three assertions in another order
/// produce another digest, and the object would never open. Sealing and
/// unsealing therefore go through this one function.
fn window_policy_steps(
    ctx: &mut Context,
    policy_session: PolicySession,
    selection: tss_esapi::structures::PcrSelectionList,
) -> Result<()> {
    // 1. PCR 0/7 — firmware and Secure Boot, not PCR 4.
    ctx.policy_pcr(policy_session, empty_digest()?, selection)
        .map_err(|e| TpmError::Connection(format!("policy_pcr (window): {e}")))?;
    // 2. The NV slot must have been initialized. This assertion is valid here
    // because the policy authorizes NV_Read on the index itself, rather than
    // trying to make one NV index gate an unrelated keyed-hash object.
    ctx.policy_nv_written(policy_session, true)
        .map_err(|e| TpmError::Connection(format!("policy_nv_written: {e}")))?;
    // 3. The policy can only release the NV payload through NV_Read.
    ctx.policy_command_code(policy_session, CommandCode::NvRead)
        .map_err(|e| TpmError::Connection(format!("policy_command_code: {e}")))?;
    Ok(())
}

/// Computes the window's policy digest through a trial session.
fn compute_window_policy_digest(
    ctx: &mut Context,
    selection: &tss_esapi::structures::PcrSelectionList,
) -> Result<Digest> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| TpmError::Connection(format!("trial session (window): {e}")))?
        .ok_or_else(|| TpmError::Connection("empty trial session (window)".into()))?;

    let result = (|| {
        let policy_session = PolicySession::try_from(session)
            .map_err(|e| TpmError::Connection(format!("policy session (window): {e}")))?;
        window_policy_steps(ctx, policy_session, selection.clone())?;
        ctx.policy_get_digest(policy_session)
            .map_err(|e| TpmError::Connection(format!("policy_get_digest (window): {e}")))
    })();

    log_cleanup_error(
        "flush update-window policy session",
        ctx.flush_context(SessionHandle::from(session).into()),
    );
    result
}

/// Reports a failed best-effort cleanup without replacing the TPM operation's
/// result. The primary operation remains the authoritative failure: cleanup
/// runs after it and cannot make a successful operation fail retroactively.
fn log_cleanup_error(operation: &'static str, result: std::result::Result<(), TssError>) {
    if let Err(error) = result {
        tracing::warn!(operation, error = %error, "TPM resource cleanup failed");
    }
}

/// Opens the revocation index, or `None` if it is not defined.
fn open_nv_index(ctx: &mut Context, index: u32) -> Result<Option<NvIndexHandle>> {
    let tpm_handle = NvIndexTpmHandle::new(index)
        .map_err(|e| TpmError::Connection(format!("NV index {index:#x}: {e}")))?;
    // Asked before opening, and not deduced from a failed open: see
    // `nv_index_is_defined`.
    if !nv_index_is_defined(ctx, index)? {
        return Ok(None);
    }
    match ctx.execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle.into())) {
        Ok(object) => Ok(Some(NvIndexHandle::from(object))),
        // An undefined index is the ordinary state of a gateway that has
        // never armed a window, not an error. Still handled here: the index
        // can be undefined between the two commands above.
        Err(error) if is_missing_handle(&error) => Ok(None),
        Err(error) => Err(TpmError::Connection(format!(
            "open NV index {index:#x}: {error}"
        ))),
    }
}

/// Is this NV index defined? Asked without provoking a failure.
///
/// `TPM2_GetCapability` returns the defined handles at or after `index`, and
/// **succeeds** when there are none — where `Esys_TR_FromTPMPublic` fails with
/// `TPM_RC_HANDLE` (`0x18b`). Both answer the same question, but the failing
/// one makes the TSS stack print three `WARNING`/`ERROR` lines on stderr, plus
/// one from `tss_esapi`, for the ordinary state of a gateway with no update
/// window armed. An operator running `helios update` read those as the
/// diagnosis of a TPM problem; the diagnosis was that nothing was wrong.
///
/// Cost: one extra TPM command on a path that only runs on operator commands
/// and at boot. Cheaper than an alarm that has to be explained every time.
fn nv_index_is_defined(ctx: &mut Context, index: u32) -> Result<bool> {
    let (capability, _more) = ctx
        .execute_without_session(|ctx| ctx.get_capability(CapabilityType::Handles, index, 1))
        .map_err(|e| TpmError::Connection(format!("listing NV index {index:#x}: {e}")))?;
    let CapabilityData::Handles(handles) = capability else {
        return Err(TpmError::Connection(format!(
            "listing NV index {index:#x}: the TPM answered with another capability"
        )));
    };
    // The TPM answers with the first handle **at or after** `index`, so a
    // non-empty answer proves nothing on its own — a window index that does
    // not exist yields the next defined one. Only equality is an answer.
    Ok(handles
        .into_inner()
        .first()
        .is_some_and(|handle| u32::from(*handle) == index))
}

/// Undefines then defines the policy-protected NV window slot.
fn redefine_window_index(
    ctx: &mut Context,
    index: u32,
    auth_policy: Digest,
    data_size: usize,
) -> Result<NvIndexHandle> {
    let tpm_handle = NvIndexTpmHandle::new(index)
        .map_err(|e| TpmError::Connection(format!("NV index {index:#x}: {e}")))?;

    if let Some(existing) = open_nv_index(ctx, index)? {
        ctx.execute_with_nullauth_session(|ctx| ctx.nv_undefine_space(Provision::Owner, existing))
            .map_err(|e| TpmError::Connection(format!("NV undefine: {e}")))?;
    }

    let attributes = NvIndexAttributesBuilder::new()
        .with_owner_write(true)
        .with_policy_read(true)
        .with_nv_index_type(NvIndexType::Ordinary)
        .with_no_da(true)
        .build()
        .map_err(|e| TpmError::Connection(format!("NV attributes: {e}")))?;
    let public = NvPublicBuilder::new()
        .with_nv_index(tpm_handle)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(attributes)
        .with_index_auth_policy(auth_policy)
        .with_data_area_size(data_size)
        .build()
        .map_err(|e| TpmError::Connection(format!("NV public: {e}")))?;

    ctx.execute_with_nullauth_session(|ctx| ctx.nv_define_space(Provision::Owner, None, public))
        .map_err(|e| TpmError::Connection(format!("NV define: {e}")))
}

fn to_secret_key(sensitive: SensitiveData) -> Result<SecretKey> {
    let bytes = sensitive.value();
    if bytes.len() != 32 {
        return Err(TpmError::Connection(format!(
            "unsealed secret of unexpected size: {} bytes (32 expected)",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    let secret = SecretKey::from_bytes(key);
    key.zeroize();
    Ok(secret)
}

// ───────────────────────────── Blob (de)serialization ─────────────────────────────

fn marshal_blob(indices: &[u8], public: &Public, private: &Private) -> Result<Vec<u8>> {
    let pub_bytes = public
        .marshall()
        .map_err(|e| TpmError::Serde(format!("marshall public: {e}")))?;
    // `Private` is already an opaque TPM2B (wire format) -> direct raw bytes.
    let priv_bytes = private.value().to_vec();

    let mut out = Vec::new();
    out.extend_from_slice(BLOB_MAGIC);
    out.push(BLOB_VERSION);
    out.push(BANK_SHA256);
    out.push(indices.len() as u8);
    out.extend_from_slice(indices);
    out.extend_from_slice(&(pub_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&pub_bytes);
    out.extend_from_slice(&(priv_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&priv_bytes);
    Ok(out)
}

fn unmarshal_blob(bytes: &[u8]) -> Result<(Vec<u8>, Public, Private)> {
    let mut cur = bytes;

    let take = |cur: &mut &[u8], n: usize| -> Result<Vec<u8>> {
        if cur.len() < n {
            return Err(TpmError::Serde("truncated blob".into()));
        }
        let (head, tail) = cur.split_at(n);
        *cur = tail;
        Ok(head.to_vec())
    };
    let take_u32 = |cur: &mut &[u8]| -> Result<u32> {
        let b = take(cur, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    if take(&mut cur, 4)? != BLOB_MAGIC {
        return Err(TpmError::Serde("invalid blob magic".into()));
    }
    if take(&mut cur, 1)?[0] != BLOB_VERSION {
        return Err(TpmError::Serde("unsupported blob version".into()));
    }
    if take(&mut cur, 1)?[0] != BANK_SHA256 {
        return Err(TpmError::Serde("unsupported blob bank".into()));
    }
    let n = take(&mut cur, 1)?[0] as usize;
    let indices = take(&mut cur, n)?;

    let pub_len = take_u32(&mut cur)? as usize;
    let pub_bytes = take(&mut cur, pub_len)?;
    let priv_len = take_u32(&mut cur)? as usize;
    let priv_bytes = take(&mut cur, priv_len)?;

    let public =
        Public::unmarshall(&pub_bytes).map_err(|e| TpmError::Serde(format!("public: {e}")))?;
    let private =
        Private::try_from(priv_bytes).map_err(|e| TpmError::Serde(format!("private: {e}")))?;
    Ok((indices, public, private))
}

/// Detects TPM2_RC_POLICY_FAIL (PCRs no longer matching the authPolicy).
///
/// Only this exact TPM response triggers the policy-refusal path; transport,
/// resource-manager, and wrapper errors remain hard failures.
fn is_policy_fail(error: &TssError) -> bool {
    matches!(
        error,
        TssError::Tss2Error(code) if code.kind() == Some(Tss2ResponseCodeKind::PolicyFail)
    )
}

/// `TR_FromTPMPublic` returns TPM2_RC_HANDLE for an undefined NV index.
/// No transport, resource-manager, or wrapper error may be mistaken for this
/// ordinary absent state, especially on the revocation path.
fn is_missing_handle(error: &TssError) -> bool {
    matches!(
        error,
        TssError::Tss2Error(code) if code.kind() == Some(Tss2ResponseCodeKind::Handle)
    )
}
