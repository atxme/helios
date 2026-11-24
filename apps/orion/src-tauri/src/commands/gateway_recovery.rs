//! Offline recovery of a gateway's WireGuard identity, run from the operator's
//! workstation: the ceremony of `helios escrow`, through the same offline core
//! (`helios_escrow::recovery`).
//!
//! The commands run in the unprivileged UI process. They need neither
//! elevation nor an open operator vault: they read only what the operator
//! hands over. Refusals cross as closed codes; no key and no free text does.
//!
//! The escrow private key is chosen in a native dialog and read here; the
//! recovery frame, which holds the gateway's WireGuard private key, is written
//! here, to a path chosen in a native save dialog. Neither crosses IPC, JS or
//! the DOM (ADR-006 §5). Off Windows the dialogs do not exist, so both commands
//! refuse with `platform_unsupported`.

// Off Windows the ceremony refuses before any of its pure steps run: they are
// compiled and tested everywhere, and only the dialog wiring is Windows-only.
#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

use aether::sig::{SignedWireGuardRecovery, WireGuardRecoveryPayload};
use base64::Engine as _;
use helios_escrow::recovery::{self, CounterSource, RecoveryError};
use helios_escrow::KEY_LEN;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::operator::{ArtifactEncoding, OperatorArtifact};

#[cfg(any(windows, test))]
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// The file the publisher signs, as `helios escrow prepare-recovery` writes it.
const REQUEST_FILE: &str = "wg-recovery-request.json";
/// The frame deposited on the gateway, as `helios escrow assemble-recovery` writes it.
const RECOVERY_FILE: &str = "wg-key.recovery";

/// Where the counter of a prepared request comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterOrigin {
    /// Given by the operator.
    Given,
    /// Read from the escrow, plus one: a recovery follows a consumed ticket.
    EscrowAfterTicket,
}

/// The public request prepared from an escrow. Holds no private key.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryPrepared {
    pub gateway_public_key: String,
    pub counter: u64,
    pub counter_source: CounterOrigin,
    pub request: OperatorArtifact,
}

/// The recovery frame was written: the name of the file chosen, and nothing
/// else. The frame itself never leaves this process.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct RecoveryAssembled {
    pub file_name: String,
}

/// A refusal of the ceremony, as the window reads it: a closed code, with no
/// free text.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum RecoveryRefusalView {
    EscrowUnreadable,
    LegacyEscrow,
    EscrowInconsistent,
    CounterUnknown,
    AuthorizationInvalid,
    ForeignGateway,
    RequestMismatch,
    FrameMalformed,
    RequestMalformed,
    /// Only built where the ceremony does not run.
    #[cfg_attr(windows, allow(dead_code))]
    PlatformUnsupported,
}

impl From<RecoveryError> for RecoveryRefusalView {
    fn from(error: RecoveryError) -> Self {
        match error {
            RecoveryError::EscrowUnreadable => Self::EscrowUnreadable,
            RecoveryError::LegacyEscrow => Self::LegacyEscrow,
            RecoveryError::EscrowInconsistent => Self::EscrowInconsistent,
            RecoveryError::CounterUnknown => Self::CounterUnknown,
            RecoveryError::AuthorizationInvalid => Self::AuthorizationInvalid,
            RecoveryError::ForeignGateway => Self::ForeignGateway,
            RecoveryError::RequestMismatch => Self::RequestMismatch,
            RecoveryError::FrameMalformed => Self::FrameMalformed,
        }
    }
}

/// Opens the escrow with the operator's key, chosen in a dialog, and prepares
/// the request the publisher signs.
///
/// `None` when the operator cancels the key dialog. `counter` is optional:
/// without it, the escrow's counter plus one is used. `expected_pcr_digest` is
/// 64 hex digits when given.
#[tauri::command]
pub(crate) async fn gateway_recovery_prepare(
    window: tauri::Window,
    escrow_b64: String,
    counter: Option<u64>,
    expected_pcr_digest: Option<String>,
) -> Result<Option<RecoveryPrepared>, RecoveryRefusalView> {
    #[cfg(windows)]
    {
        let escrow = decode_escrow(&escrow_b64)?;
        let digest = decode_pcr_digest(expected_pcr_digest)?;
        let Some(key) = read_escrow_key(&window).await? else {
            return Ok(None);
        };
        prepare_with_key(&escrow, &key, counter, digest).map(Some)
    }
    #[cfg(not(windows))]
    {
        let _ = (window, escrow_b64, counter, expected_pcr_digest);
        Err(RecoveryRefusalView::PlatformUnsupported)
    }
}

/// Verifies the publisher's authorization against the escrow, then asks where
/// to write `wg-key.recovery` and writes it, owner-only and atomically.
///
/// `request` is the JSON text of the prepared request; `authorization` is the
/// JSON the publisher returned. `None` when the operator cancels either dialog;
/// nothing is written when cancelled or refused. Every refusal happens before
/// the output dialog opens.
#[tauri::command]
pub(crate) async fn gateway_recovery_assemble(
    window: tauri::Window,
    escrow_b64: String,
    request: String,
    authorization: String,
) -> Result<Option<RecoveryAssembled>, RecoveryRefusalView> {
    #[cfg(windows)]
    {
        let escrow = decode_escrow(&escrow_b64)?;
        let Some(key) = read_escrow_key(&window).await? else {
            return Ok(None);
        };
        let frame = assemble_frame(&escrow, &key, &request, &authorization)?;
        let Some(target) = pick_output(&window).await? else {
            return Ok(None);
        };
        write_frame(&target, &frame).map(Some)
    }
    #[cfg(not(windows))]
    {
        let _ = (window, escrow_b64, request, authorization);
        Err(RecoveryRefusalView::PlatformUnsupported)
    }
}

#[cfg(any(windows, test))]
fn prepare_with_key(
    escrow: &[u8],
    key: &[u8],
    counter: Option<u64>,
    expected_pcr_digest: Option<[u8; 32]>,
) -> Result<RecoveryPrepared, RecoveryRefusalView> {
    let request = recovery::prepare(escrow, key, counter, expected_pcr_digest)?;
    let contents = serde_json::to_string_pretty(&request.payload)
        .map_err(|_| RecoveryRefusalView::FrameMalformed)?;
    Ok(RecoveryPrepared {
        gateway_public_key: request.gateway_public_key_b64,
        counter: request.payload.counter,
        counter_source: match request.counter_source {
            CounterSource::Given => CounterOrigin::Given,
            CounterSource::EscrowAfterTicket => CounterOrigin::EscrowAfterTicket,
        },
        request: OperatorArtifact {
            file_name: REQUEST_FILE.to_string(),
            contents,
            encoding: ArtifactEncoding::Text,
            fingerprint: None,
        },
    })
}

/// Runs the core `assemble`: every refusal of the ceremony is raised here.
#[cfg(any(windows, test))]
fn assemble_frame(
    escrow: &[u8],
    key: &[u8],
    request: &str,
    authorization: &str,
) -> Result<Zeroizing<Vec<u8>>, RecoveryRefusalView> {
    let request: WireGuardRecoveryPayload =
        serde_json::from_str(request).map_err(|_| RecoveryRefusalView::RequestMalformed)?;
    let authorization: SignedWireGuardRecovery = serde_json::from_str(authorization)
        .map_err(|_| RecoveryRefusalView::AuthorizationInvalid)?;
    Ok(recovery::assemble(escrow, key, &request, &authorization)?)
}

/// Writes the frame at `target`, owner-only and atomically, and names the file.
#[cfg(any(windows, test))]
fn write_frame(target: &Path, frame: &[u8]) -> Result<RecoveryAssembled, RecoveryRefusalView> {
    aether::private_file::write_private_atomic(target, frame).map_err(|error| {
        tracing::error!(%error, "écriture du fichier de récupération impossible");
        RecoveryRefusalView::FrameMalformed
    })?;
    let file_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(RecoveryAssembled { file_name })
}

/// Assembles and writes in one step, for the tests: the command itself opens
/// the output dialog between the two.
#[cfg(test)]
fn assemble_to(
    escrow: &[u8],
    key: &[u8],
    request: &str,
    authorization: &str,
    target: &Path,
) -> Result<RecoveryAssembled, RecoveryRefusalView> {
    let frame = assemble_frame(escrow, key, request, authorization)?;
    write_frame(target, &frame)
}

/// Shows a dialog on its own thread, as the vault dialogs do: it sets that
/// thread's COM apartment, which a pooled worker would carry into other work.
/// `None` when the operator cancels; a dialog that fails is logged and reported.
#[cfg(windows)]
async fn pick_on_thread(
    window: &tauri::Window,
    thread: &'static str,
    pick: impl FnOnce(isize) -> Result<Option<PathBuf>, String> + Send + 'static,
) -> Result<Option<PathBuf>, String> {
    let owner = super::ceremonies::owner_window(window);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(thread.into())
        .spawn(move || {
            let _ = sender.send(pick(owner));
        })
        .map_err(|error| format!("boîte de dialogue de récupération : {error}"))?;
    receiver
        .await
        .map_err(|_| "la boîte de dialogue de récupération s'est arrêtée".to_string())?
}

/// Asks for the escrow private key and reads it, as `helios escrow keygen`
/// writes it. The bytes are wiped when this returns; the path never leaves here.
#[cfg(windows)]
async fn read_escrow_key(
    window: &tauri::Window,
) -> Result<Option<Zeroizing<Vec<u8>>>, RecoveryRefusalView> {
    let picked = pick_on_thread(window, "orion-recovery-key", |owner| {
        crate::operator::location::pick_escrow_key(owner)
    })
    .await
    .map_err(|error| {
        tracing::error!(%error, "boîte de la clé de séquestre en échec");
        RecoveryRefusalView::EscrowUnreadable
    })?;
    let Some(path) = picked else {
        return Ok(None);
    };
    let bytes = Zeroizing::new(std::fs::read(&path).map_err(|error| {
        tracing::error!(%error, "clé de séquestre illisible");
        RecoveryRefusalView::EscrowUnreadable
    })?);
    let text = std::str::from_utf8(&bytes).map_err(|_| RecoveryRefusalView::EscrowUnreadable)?;
    decode_operator_key(text).map(Some)
}

/// Asks where to write the frame. `None` when the operator cancels.
#[cfg(windows)]
async fn pick_output(window: &tauri::Window) -> Result<Option<PathBuf>, RecoveryRefusalView> {
    let proposed = PathBuf::from(RECOVERY_FILE);
    pick_on_thread(window, "orion-recovery-output", move |owner| {
        crate::operator::location::pick_recovery_output(owner, &proposed)
    })
    .await
    .map_err(|error| {
        tracing::error!(%error, "boîte d'enregistrement du fichier de récupération en échec");
        RecoveryRefusalView::FrameMalformed
    })
}

#[cfg(any(windows, test))]
fn decode_escrow(text: &str) -> Result<Vec<u8>, RecoveryRefusalView> {
    B64.decode(text.trim())
        .map_err(|_| RecoveryRefusalView::EscrowUnreadable)
}

/// Reads the operator's escrow private key, as `helios escrow keygen` writes it.
#[cfg(any(windows, test))]
fn decode_operator_key(text: &str) -> Result<Zeroizing<Vec<u8>>, RecoveryRefusalView> {
    let key = Zeroizing::new(
        B64.decode(text.trim())
            .map_err(|_| RecoveryRefusalView::EscrowUnreadable)?,
    );
    if key.len() != KEY_LEN {
        return Err(RecoveryRefusalView::EscrowUnreadable);
    }
    Ok(key)
}

#[cfg(any(windows, test))]
fn decode_pcr_digest(text: Option<String>) -> Result<Option<[u8; 32]>, RecoveryRefusalView> {
    text.map(|text| {
        hex::decode(text.trim())
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or(RecoveryRefusalView::RequestMalformed)
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use aether::sig::PublisherSigner;
    use helios_escrow::{generate_operator_keypair, seal_to_operator, EscrowMetadata};
    use serde_json::json;

    use super::*;

    // Development seeds, shared with the recovery tests of `helios-escrow`: they
    // match the development `PUBLISHER_KEYS` compiled into `aether`.
    const DEV_ED_SEED: [u8; 32] = *b"helios-sign-ed25519-dev-seed-001";
    const DEV_ML_SEED: [u8; 32] = *b"helios-sign-mldsa65-dev-seed-001";

    /// An operator, and a gateway whose WireGuard key is escrowed to it.
    struct Fixture {
        operator_private: Zeroizing<[u8; KEY_LEN]>,
        escrow: Vec<u8>,
        wg_private: [u8; KEY_LEN],
    }

    fn fixture(counter: Option<u64>) -> Fixture {
        let (operator_private, operator_public) = generate_operator_keypair().unwrap();
        let mut wg_private = [0u8; KEY_LEN];
        aether::random::fill_secret(&mut wg_private).unwrap();
        let metadata = EscrowMetadata {
            counter,
            gateway_public_key: wg_public(&wg_private),
        };
        let plaintext = B64.encode(wg_private);
        let escrow = seal_to_operator(&operator_public, plaintext.as_bytes(), &metadata).unwrap();
        Fixture {
            operator_private,
            escrow,
            wg_private,
        }
    }

    fn wg_public(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
        let secret = x25519_dalek::StaticSecret::from(*private);
        *x25519_dalek::PublicKey::from(&secret).as_bytes()
    }

    /// Signs a payload as the publisher does, and returns the JSON the window receives.
    fn authorization_json(payload: WireGuardRecoveryPayload) -> String {
        let publisher = PublisherSigner::from_seed_material(1, &DEV_ED_SEED, &DEV_ML_SEED).unwrap();
        let signed: SignedWireGuardRecovery = publisher.sign(payload).unwrap();
        serde_json::to_string(&signed).unwrap()
    }

    fn payload(counter: u64, gateway_public_key: [u8; KEY_LEN]) -> WireGuardRecoveryPayload {
        WireGuardRecoveryPayload {
            counter,
            gateway_public_key,
            expected_pcr_digest: None,
        }
    }

    /// A directory of its own per test, removed when the test ends.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let directory =
                std::env::temp_dir().join(format!("orion-recovery-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&directory);
            std::fs::create_dir_all(&directory).expect("scratch directory");
            Self(directory)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn code_of(error: &RecoveryError) -> &'static str {
        match error {
            RecoveryError::EscrowUnreadable => "escrow_unreadable",
            RecoveryError::LegacyEscrow => "legacy_escrow",
            RecoveryError::EscrowInconsistent => "escrow_inconsistent",
            RecoveryError::CounterUnknown => "counter_unknown",
            RecoveryError::AuthorizationInvalid => "authorization_invalid",
            RecoveryError::ForeignGateway => "foreign_gateway",
            RecoveryError::RequestMismatch => "request_mismatch",
            RecoveryError::FrameMalformed => "frame_malformed",
        }
    }

    #[test]
    fn prepare_returns_the_public_request_only() {
        let fx = fixture(Some(5));

        let prepared = prepare_with_key(&fx.escrow, &fx.operator_private[..], None, None).unwrap();

        assert_eq!(prepared.counter, 6);
        assert_eq!(prepared.counter_source, CounterOrigin::EscrowAfterTicket);
        assert_eq!(
            prepared.gateway_public_key,
            B64.encode(wg_public(&fx.wg_private))
        );
        assert_eq!(prepared.request.file_name, REQUEST_FILE);
        assert_eq!(prepared.request.encoding, ArtifactEncoding::Text);
        assert!(!prepared
            .request
            .contents
            .contains(&B64.encode(fx.wg_private)));
        assert!(!prepared
            .request
            .contents
            .contains(&B64.encode(fx.operator_private.as_slice())));
        let request: WireGuardRecoveryPayload =
            serde_json::from_str(&prepared.request.contents).unwrap();
        assert_eq!(request, payload(6, wg_public(&fx.wg_private)));
    }

    #[test]
    fn assemble_returns_the_frame_for_the_request_it_was_prepared_for() {
        let fx = fixture(Some(5));
        let prepared = prepare_with_key(&fx.escrow, &fx.operator_private[..], None, None).unwrap();
        let authorization = authorization_json(payload(6, wg_public(&fx.wg_private)));

        let frame = assemble_frame(
            &fx.escrow,
            &fx.operator_private[..],
            &prepared.request.contents,
            &authorization,
        )
        .unwrap();

        let (_, key) = recovery::decode_recovery_frame(&frame).unwrap();
        assert_eq!(key.as_slice(), &fx.wg_private);
    }

    #[test]
    fn assemble_writes_the_frame_owner_only_and_returns_no_key_bytes() {
        let fx = fixture(Some(5));
        let prepared = prepare_with_key(&fx.escrow, &fx.operator_private[..], None, None).unwrap();
        let authorization = authorization_json(payload(6, wg_public(&fx.wg_private)));
        let scratch = Scratch::new("owner-only");
        let target = scratch.0.join(RECOVERY_FILE);

        let assembled = assemble_to(
            &fx.escrow,
            &fx.operator_private[..],
            &prepared.request.contents,
            &authorization,
            &target,
        )
        .unwrap();

        assert_eq!(assembled.file_name, RECOVERY_FILE);
        let written = std::fs::read(&target).unwrap();
        let (_, key) = recovery::decode_recovery_frame(&written).unwrap();
        assert_eq!(key.as_slice(), &fx.wg_private);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let serialized = serde_json::to_string(&assembled).unwrap();
        assert!(!serialized.contains(&B64.encode(fx.wg_private)));
        assert!(!serialized.contains(&B64.encode(fx.operator_private.as_slice())));
        assert_eq!(
            serde_json::to_value(&assembled).unwrap(),
            json!({ "file_name": RECOVERY_FILE })
        );
    }

    #[test]
    fn a_refused_assembly_writes_nothing() {
        let fx = fixture(Some(5));
        let prepared = prepare_with_key(&fx.escrow, &fx.operator_private[..], None, None).unwrap();
        let other_gateway = wg_public(&fixture(None).wg_private);
        let authorization = authorization_json(payload(6, other_gateway));
        let scratch = Scratch::new("refused");
        let target = scratch.0.join(RECOVERY_FILE);

        let refusal = assemble_to(
            &fx.escrow,
            &fx.operator_private[..],
            &prepared.request.contents,
            &authorization,
            &target,
        )
        .unwrap_err();

        assert_eq!(refusal, RecoveryRefusalView::ForeignGateway);
        assert!(!target.exists());
    }

    #[test]
    fn assemble_maps_a_foreign_authorization_to_its_refusal_code() {
        let fx = fixture(Some(5));
        let prepared = prepare_with_key(&fx.escrow, &fx.operator_private[..], None, None).unwrap();
        let other_gateway = wg_public(&fixture(None).wg_private);
        let authorization = authorization_json(payload(6, other_gateway));

        let refusal = assemble_frame(
            &fx.escrow,
            &fx.operator_private[..],
            &prepared.request.contents,
            &authorization,
        )
        .unwrap_err();

        assert_eq!(refusal, RecoveryRefusalView::ForeignGateway);
        assert_eq!(
            serde_json::to_value(&refusal).unwrap(),
            json!({ "refusal": "foreign_gateway" })
        );
    }

    #[test]
    fn assemble_maps_another_request_to_request_mismatch() {
        let fx = fixture(Some(5));
        // The operator prepared the request for counter 6; the publisher signed 7.
        let prepared =
            prepare_with_key(&fx.escrow, &fx.operator_private[..], Some(6), None).unwrap();
        let authorization = authorization_json(payload(7, wg_public(&fx.wg_private)));

        let refusal = assemble_frame(
            &fx.escrow,
            &fx.operator_private[..],
            &prepared.request.contents,
            &authorization,
        )
        .unwrap_err();

        assert_eq!(refusal, RecoveryRefusalView::RequestMismatch);
        assert_eq!(
            serde_json::to_value(&refusal).unwrap(),
            json!({ "refusal": "request_mismatch" })
        );
    }

    #[test]
    fn unparseable_json_maps_to_its_refusal_code() {
        let fx = fixture(Some(5));
        let prepared = prepare_with_key(&fx.escrow, &fx.operator_private[..], None, None).unwrap();
        let authorization = authorization_json(payload(6, wg_public(&fx.wg_private)));

        assert_eq!(
            assemble_frame(
                &fx.escrow,
                &fx.operator_private[..],
                "not json",
                &authorization
            )
            .unwrap_err(),
            RecoveryRefusalView::RequestMalformed
        );
        assert_eq!(
            assemble_frame(
                &fx.escrow,
                &fx.operator_private[..],
                &prepared.request.contents,
                "not json"
            )
            .unwrap_err(),
            RecoveryRefusalView::AuthorizationInvalid
        );
    }

    #[test]
    fn an_explicit_counter_and_pcr_digest_are_preserved_in_the_public_request() {
        let fx = fixture(None);
        let digest = [0x42; 32];
        let decoded = decode_pcr_digest(Some(format!(" {}\n", hex::encode(digest)))).unwrap();
        let prepared = prepare_with_key(&fx.escrow, &fx.operator_private[..], Some(9), decoded)
            .expect("prepare with an explicit counter");
        assert_eq!(prepared.counter, 9);
        assert_eq!(prepared.counter_source, CounterOrigin::Given);
        let body: WireGuardRecoveryPayload =
            serde_json::from_str(&prepared.request.contents).expect("public request");
        assert_eq!(body.counter, 9);
        assert_eq!(body.gateway_public_key, wg_public(&fx.wg_private));
        assert_eq!(body.expected_pcr_digest, Some(digest));
        assert_eq!(decode_pcr_digest(None).unwrap(), None);
        assert_eq!(
            decode_pcr_digest(Some(hex::encode([0; 31]))).unwrap_err(),
            RecoveryRefusalView::RequestMalformed
        );
    }

    #[test]
    fn assembly_reports_a_write_failure_without_replacing_the_destination() {
        let fx = fixture(Some(5));
        let prepared = prepare_with_key(&fx.escrow, &fx.operator_private[..], None, None).unwrap();
        let authorization = authorization_json(payload(6, wg_public(&fx.wg_private)));
        let scratch = Scratch::new("write-refused");
        let target = scratch.0.join(RECOVERY_FILE);
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("keep"), b"existing contents").unwrap();

        let refusal = assemble_to(
            &fx.escrow,
            &fx.operator_private[..],
            &prepared.request.contents,
            &authorization,
            &target,
        )
        .unwrap_err();

        assert_eq!(refusal, RecoveryRefusalView::FrameMalformed);
        assert_eq!(
            std::fs::read(target.join("keep")).unwrap(),
            b"existing contents"
        );
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);
    }

    #[test]
    fn an_invalid_pcr_digest_is_a_malformed_request() {
        assert_eq!(
            decode_pcr_digest(Some("not hex".to_string())).unwrap_err(),
            RecoveryRefusalView::RequestMalformed
        );
    }

    #[test]
    fn an_operator_key_must_be_base64_of_the_key_length() {
        let key = B64.encode([7u8; KEY_LEN]);
        assert_eq!(
            decode_operator_key(&format!("  {key}\n"))
                .unwrap()
                .as_slice(),
            &[7u8; KEY_LEN]
        );
        assert_eq!(
            decode_operator_key(&B64.encode([7u8; KEY_LEN - 1])).unwrap_err(),
            RecoveryRefusalView::EscrowUnreadable
        );
        assert_eq!(
            decode_operator_key("not base64!").unwrap_err(),
            RecoveryRefusalView::EscrowUnreadable
        );
    }

    #[test]
    fn an_escrow_must_be_base64() {
        assert_eq!(
            decode_escrow("not base64!").unwrap_err(),
            RecoveryRefusalView::EscrowUnreadable
        );
    }

    #[test]
    fn every_recovery_error_has_a_refusal_code() {
        let errors = [
            RecoveryError::EscrowUnreadable,
            RecoveryError::LegacyEscrow,
            RecoveryError::EscrowInconsistent,
            RecoveryError::CounterUnknown,
            RecoveryError::AuthorizationInvalid,
            RecoveryError::ForeignGateway,
            RecoveryError::RequestMismatch,
            RecoveryError::FrameMalformed,
        ];
        for error in errors {
            let code = code_of(&error);
            let view = RecoveryRefusalView::from(error);
            assert_eq!(
                serde_json::to_value(&view).unwrap(),
                json!({ "refusal": code })
            );
        }
    }

    #[test]
    fn every_refusal_view_has_a_closed_code() {
        let views = [
            (RecoveryRefusalView::EscrowUnreadable, "escrow_unreadable"),
            (RecoveryRefusalView::LegacyEscrow, "legacy_escrow"),
            (
                RecoveryRefusalView::EscrowInconsistent,
                "escrow_inconsistent",
            ),
            (RecoveryRefusalView::CounterUnknown, "counter_unknown"),
            (
                RecoveryRefusalView::AuthorizationInvalid,
                "authorization_invalid",
            ),
            (RecoveryRefusalView::ForeignGateway, "foreign_gateway"),
            (RecoveryRefusalView::RequestMismatch, "request_mismatch"),
            (RecoveryRefusalView::FrameMalformed, "frame_malformed"),
            (RecoveryRefusalView::RequestMalformed, "request_malformed"),
            (
                RecoveryRefusalView::PlatformUnsupported,
                "platform_unsupported",
            ),
        ];
        for (view, code) in views {
            assert_eq!(
                serde_json::to_value(&view).unwrap(),
                json!({ "refusal": code })
            );
        }
    }
}
