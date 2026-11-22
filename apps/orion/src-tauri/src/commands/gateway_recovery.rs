//! Offline recovery of a gateway's WireGuard identity, run from the operator's
//! workstation: the ceremony of `helios escrow`, through the same offline core
//! (`helios_escrow::recovery`).
//!
//! The commands run in the unprivileged UI process. They need neither
//! elevation nor an open operator vault: they read only what the operator
//! hands over. Refusals cross as closed codes; no key and no free text does.

use aether::sig::{SignedWireGuardRecovery, WireGuardRecoveryPayload};
use base64::Engine as _;
use helios_escrow::recovery::{self, CounterSource, RecoveryError};
use helios_escrow::KEY_LEN;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::operator::{ArtifactEncoding, OperatorArtifact};

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

/// Opens the escrow and prepares the request the publisher signs.
///
/// `counter` is optional: without it, the escrow's counter plus one is used.
/// `expected_pcr_digest` is 64 hex digits when given.
#[tauri::command]
pub(crate) async fn gateway_recovery_prepare(
    escrow_b64: String,
    escrow_private_key: String,
    counter: Option<u64>,
    expected_pcr_digest: Option<String>,
) -> Result<RecoveryPrepared, RecoveryRefusalView> {
    let escrow = decode_escrow(&escrow_b64)?;
    let operator_key = decode_operator_key(&escrow_private_key)?;
    let digest = decode_pcr_digest(expected_pcr_digest)?;
    prepare_recovery(&escrow, &operator_key, counter, digest)
}

/// Verifies the publisher's authorization against the escrow and returns the
/// recovery frame, as `wg-key.recovery`, base64 encoded for the window.
///
/// `request` is the JSON text of the prepared request; `authorization` is the
/// JSON the publisher returned.
#[tauri::command]
pub(crate) async fn gateway_recovery_assemble(
    escrow_b64: String,
    escrow_private_key: String,
    request: String,
    authorization: String,
) -> Result<OperatorArtifact, RecoveryRefusalView> {
    let escrow = decode_escrow(&escrow_b64)?;
    let operator_key = decode_operator_key(&escrow_private_key)?;
    assemble_recovery(&escrow, &operator_key, &request, &authorization)
}

fn prepare_recovery(
    escrow: &[u8],
    operator_key: &[u8],
    counter: Option<u64>,
    expected_pcr_digest: Option<[u8; 32]>,
) -> Result<RecoveryPrepared, RecoveryRefusalView> {
    let request = recovery::prepare(escrow, operator_key, counter, expected_pcr_digest)?;
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

fn assemble_recovery(
    escrow: &[u8],
    operator_key: &[u8],
    request: &str,
    authorization: &str,
) -> Result<OperatorArtifact, RecoveryRefusalView> {
    let request: WireGuardRecoveryPayload =
        serde_json::from_str(request).map_err(|_| RecoveryRefusalView::FrameMalformed)?;
    let authorization: SignedWireGuardRecovery = serde_json::from_str(authorization)
        .map_err(|_| RecoveryRefusalView::AuthorizationInvalid)?;
    let frame = recovery::assemble(escrow, operator_key, &request, &authorization)?;
    Ok(OperatorArtifact {
        file_name: RECOVERY_FILE.to_string(),
        contents: B64.encode(frame.as_slice()),
        encoding: ArtifactEncoding::Base64,
        fingerprint: None,
    })
}

fn decode_escrow(text: &str) -> Result<Vec<u8>, RecoveryRefusalView> {
    B64.decode(text.trim())
        .map_err(|_| RecoveryRefusalView::EscrowUnreadable)
}

/// Reads the operator's escrow private key, as `helios escrow keygen` writes it.
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

fn decode_pcr_digest(text: Option<String>) -> Result<Option<[u8; 32]>, RecoveryRefusalView> {
    text.map(|text| {
        hex::decode(text.trim())
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or(RecoveryRefusalView::FrameMalformed)
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

        let prepared = prepare_recovery(&fx.escrow, &fx.operator_private[..], None, None).unwrap();

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
        let prepared = prepare_recovery(&fx.escrow, &fx.operator_private[..], None, None).unwrap();
        let authorization = authorization_json(payload(6, wg_public(&fx.wg_private)));

        let artifact = assemble_recovery(
            &fx.escrow,
            &fx.operator_private[..],
            &prepared.request.contents,
            &authorization,
        )
        .unwrap();

        assert_eq!(artifact.file_name, RECOVERY_FILE);
        assert_eq!(artifact.encoding, ArtifactEncoding::Base64);
        let frame = B64.decode(&artifact.contents).unwrap();
        let (_, key) = recovery::decode_recovery_frame(&frame).unwrap();
        assert_eq!(key.as_slice(), &fx.wg_private);
    }

    #[test]
    fn assemble_maps_a_foreign_authorization_to_its_refusal_code() {
        let fx = fixture(Some(5));
        let prepared = prepare_recovery(&fx.escrow, &fx.operator_private[..], None, None).unwrap();
        let other_gateway = wg_public(&fixture(None).wg_private);
        let authorization = authorization_json(payload(6, other_gateway));

        let refusal = assemble_recovery(
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
            prepare_recovery(&fx.escrow, &fx.operator_private[..], Some(6), None).unwrap();
        let authorization = authorization_json(payload(7, wg_public(&fx.wg_private)));

        let refusal = assemble_recovery(
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
        let prepared = prepare_recovery(&fx.escrow, &fx.operator_private[..], None, None).unwrap();
        let authorization = authorization_json(payload(6, wg_public(&fx.wg_private)));

        assert_eq!(
            assemble_recovery(
                &fx.escrow,
                &fx.operator_private[..],
                "not json",
                &authorization
            )
            .unwrap_err(),
            RecoveryRefusalView::FrameMalformed
        );
        assert_eq!(
            assemble_recovery(
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
}
