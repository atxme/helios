//! Offline recovery of the WireGuard identity, held by the operator.
//!
//! The gateway cannot ask for its own recovery: its key is lost and so is its
//! tunnel. This module is the one ceremony that both the `helios escrow` CLI
//! and Orion call, and it works only on files the operator holds: the escrow
//! `wg-key.escrow`, the operator private key, and the publisher authorization.
//!
//! 1. [`prepare`] opens the escrow and returns the public request to sign: the
//!    counter and the gateway public key. The WireGuard private key is never
//!    returned.
//! 2. The publisher signs that request (`helios-publisher wg-recovery`).
//! 3. [`assemble`] opens the escrow again with the authorization, verifies it
//!    under the compiled publisher keyring, and returns the recovery frame
//!    `wg-key.recovery` expects. Reopening the escrow avoids any intermediate
//!    file holding the private key in clear between the two steps, which may
//!    be days apart.
//!
//! The frame has the same shape as `helios-tpm`'s firmware restore frame: a
//! big-endian `u32` length, the authorization as JSON, then the 32 raw bytes
//! of the WireGuard private key. Key material lives in `Zeroizing` buffers.

use aether::sig::{
    verify_wireguard_recovery, SignedWireGuardRecovery, WireGuardRecoveryError,
    WireGuardRecoveryPayload, PUBLISHER_KEYS,
};
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::{open_as_operator, EscrowMetadata, KEY_LEN};

/// Upper bound on a recovery frame, read before any parsing.
pub const MAX_RECOVERY_FRAME: usize = 65_536;
/// Length prefix plus the raw private key, around the JSON authorization.
const FRAME_OVERHEAD: usize = 4 + KEY_LEN;

/// Where the counter of a request comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterSource {
    /// Given explicitly by the operator.
    Given,
    /// Read from the escrow, plus one: a recovery always follows a consumed
    /// ticket (spec §5.2).
    EscrowAfterTicket,
}

/// Public request the publisher signs. Carries no private key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRequest {
    pub payload: WireGuardRecoveryPayload,
    pub counter_source: CounterSource,
    /// Same key as `payload.gateway_public_key`, in base64 for display.
    pub gateway_public_key_b64: String,
}

/// Closed set of refusals of the offline recovery ceremony.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecoveryError {
    #[error("the escrow cannot be opened with this operator key")]
    EscrowUnreadable,
    #[error("HESC v1 escrow: it records no counter and no gateway key, so no request can be signed from it")]
    LegacyEscrow,
    #[error(
        "the escrow is inconsistent: its WireGuard key does not derive its recorded public key"
    )]
    EscrowInconsistent,
    #[error("no counter: pass it explicitly, the escrow recorded none")]
    CounterUnknown,
    #[error("the recovery authorization is not validly signed under the publisher keys")]
    AuthorizationInvalid,
    #[error("the recovery authorization is for another gateway")]
    ForeignGateway,
    #[error("the recovery frame is malformed")]
    FrameMalformed,
}

/// Opens the escrow and prepares the public request to sign.
///
/// `counter` overrides the counter of the escrow; without it, the escrow's
/// counter plus one is used, because a recovery follows a consumed ticket.
pub fn prepare(
    escrow: &[u8],
    operator_private_key: &[u8],
    counter: Option<u64>,
    expected_pcr_digest: Option<[u8; 32]>,
) -> Result<RecoveryRequest, RecoveryError> {
    let (_, metadata) = open_checked(escrow, operator_private_key)?;

    let (counter, counter_source) = match (counter, metadata.counter) {
        (Some(counter), _) => (counter, CounterSource::Given),
        (None, Some(escrowed)) => (
            escrowed
                .checked_add(1)
                .ok_or(RecoveryError::CounterUnknown)?,
            CounterSource::EscrowAfterTicket,
        ),
        (None, None) => return Err(RecoveryError::CounterUnknown),
    };

    Ok(RecoveryRequest {
        payload: WireGuardRecoveryPayload {
            counter,
            gateway_public_key: metadata.gateway_public_key,
            expected_pcr_digest,
        },
        counter_source,
        gateway_public_key_b64: base64::engine::general_purpose::STANDARD
            .encode(metadata.gateway_public_key),
    })
}

/// Verifies the signed authorization against the escrow and returns the
/// recovery frame, holding the WireGuard private key in a zeroizing buffer.
pub fn assemble(
    escrow: &[u8],
    operator_private_key: &[u8],
    authorization: &SignedWireGuardRecovery,
) -> Result<Zeroizing<Vec<u8>>, RecoveryError> {
    let (wg_key, metadata) = open_checked(escrow, operator_private_key)?;

    verify_wireguard_recovery(authorization, PUBLISHER_KEYS, &wg_key).map_err(
        |error| match error {
            WireGuardRecoveryError::Signature(_) => RecoveryError::AuthorizationInvalid,
            WireGuardRecoveryError::ForeignKey => RecoveryError::ForeignGateway,
        },
    )?;
    if authorization.payload.gateway_public_key != metadata.gateway_public_key {
        return Err(RecoveryError::ForeignGateway);
    }

    encode_recovery_frame(authorization, &wg_key)
}

/// Serializes a recovery frame: `u32` big-endian length, JSON authorization,
/// then the 32 raw bytes of the WireGuard private key.
pub fn encode_recovery_frame(
    authorization: &SignedWireGuardRecovery,
    private_key: &[u8; KEY_LEN],
) -> Result<Zeroizing<Vec<u8>>, RecoveryError> {
    let json = serde_json::to_vec(authorization).map_err(|_| RecoveryError::FrameMalformed)?;
    if json.len() > MAX_RECOVERY_FRAME - FRAME_OVERHEAD {
        return Err(RecoveryError::FrameMalformed);
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(FRAME_OVERHEAD + json.len()));
    frame.extend_from_slice(&(json.len() as u32).to_be_bytes());
    frame.extend_from_slice(&json);
    frame.extend_from_slice(private_key);
    Ok(frame)
}

/// Parses a recovery frame. The key is returned unverified: verification
/// against the publisher keys happens in [`assemble`] and on the gateway.
pub fn decode_recovery_frame(
    frame: &[u8],
) -> Result<(SignedWireGuardRecovery, Zeroizing<[u8; KEY_LEN]>), RecoveryError> {
    if frame.len() < FRAME_OVERHEAD || frame.len() > MAX_RECOVERY_FRAME {
        return Err(RecoveryError::FrameMalformed);
    }
    let length = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if length > MAX_RECOVERY_FRAME - FRAME_OVERHEAD || frame.len() != 4 + length + KEY_LEN {
        return Err(RecoveryError::FrameMalformed);
    }
    let authorization =
        serde_json::from_slice(&frame[4..4 + length]).map_err(|_| RecoveryError::FrameMalformed)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&frame[4 + length..]);
    Ok((authorization, key))
}

/// Opens an escrow and checks what both steps need: a HESC v2 header, and a
/// WireGuard key that derives the recorded public key.
fn open_checked(
    escrow: &[u8],
    operator_private_key: &[u8],
) -> Result<(Zeroizing<[u8; KEY_LEN]>, EscrowMetadata), RecoveryError> {
    let opened = open_as_operator(operator_private_key, escrow)
        .map_err(|_| RecoveryError::EscrowUnreadable)?;
    let metadata = opened.metadata.ok_or(RecoveryError::LegacyEscrow)?;

    let text =
        std::str::from_utf8(&opened.plaintext).map_err(|_| RecoveryError::EscrowInconsistent)?;
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .map_err(|_| RecoveryError::EscrowInconsistent)?,
    );
    if decoded.len() != KEY_LEN {
        return Err(RecoveryError::EscrowInconsistent);
    }
    let mut wg_key = Zeroizing::new([0u8; KEY_LEN]);
    wg_key.copy_from_slice(&decoded);

    let secret = x25519_dalek::StaticSecret::from(*wg_key);
    let derived = x25519_dalek::PublicKey::from(&secret);
    if derived.as_bytes() != &metadata.gateway_public_key {
        return Err(RecoveryError::EscrowInconsistent);
    }
    Ok((wg_key, metadata))
}

#[cfg(test)]
mod tests {
    use aether::sig::{PublisherSigner, WireGuardRecoveryPayload};

    use super::*;
    use crate::{generate_operator_keypair, seal_secret_to_operator, seal_to_operator};

    // Development seeds of `helios-tpm::boot_controller`: they match the
    // development `PUBLISHER_KEYS` compiled into `aether`, so the signatures
    // produced here verify through the real keyring.
    const DEV_ED_SEED: [u8; 32] = *b"helios-sign-ed25519-dev-seed-001";
    const DEV_ML_SEED: [u8; 32] = *b"helios-sign-mldsa65-dev-seed-001";

    fn publisher() -> PublisherSigner {
        PublisherSigner::from_seed_material(1, &DEV_ED_SEED, &DEV_ML_SEED).unwrap()
    }

    fn wg_public(private: &[u8; 32]) -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(*private);
        *x25519_dalek::PublicKey::from(&secret).as_bytes()
    }

    /// A WireGuard private key as `heliosd` holds it, and its escrow sealed
    /// to the operator with the counter read at the last nominal start.
    fn escrow_of(
        wg_private: &[u8; 32],
        operator_public: &[u8; 32],
        counter: Option<u64>,
    ) -> Vec<u8> {
        let plaintext = base64::engine::general_purpose::STANDARD.encode(wg_private);
        let metadata = EscrowMetadata {
            counter,
            gateway_public_key: wg_public(wg_private),
        };
        seal_to_operator(operator_public, plaintext.as_bytes(), &metadata).unwrap()
    }

    fn wg_private() -> [u8; 32] {
        let mut key = [0u8; 32];
        aether::random::fill_secret(&mut key).unwrap();
        key
    }

    fn authorization(
        counter: u64,
        gateway_public_key: [u8; 32],
    ) -> aether::sig::SignedWireGuardRecovery {
        publisher()
            .sign(WireGuardRecoveryPayload {
                counter,
                gateway_public_key,
                expected_pcr_digest: None,
            })
            .unwrap()
    }

    #[test]
    fn prepare_uses_the_given_counter() {
        let (operator_private, operator_public) = generate_operator_keypair().unwrap();
        let wg = wg_private();
        let escrow = escrow_of(&wg, &operator_public, Some(5));

        let request = prepare(&escrow, operator_private.as_slice(), Some(9), None).unwrap();
        assert_eq!(request.payload.counter, 9);
        assert_eq!(request.counter_source, CounterSource::Given);
        assert_eq!(request.payload.gateway_public_key, wg_public(&wg));
        assert_eq!(
            request.gateway_public_key_b64,
            base64::engine::general_purpose::STANDARD.encode(wg_public(&wg))
        );
    }

    #[test]
    fn prepare_defaults_to_the_counter_after_a_ticket() {
        let (operator_private, operator_public) = generate_operator_keypair().unwrap();
        let wg = wg_private();
        let escrow = escrow_of(&wg, &operator_public, Some(5));

        let request = prepare(&escrow, operator_private.as_slice(), None, None).unwrap();
        assert_eq!(request.payload.counter, 6);
        assert_eq!(request.counter_source, CounterSource::EscrowAfterTicket);
    }

    #[test]
    fn prepare_refuses_a_legacy_escrow() {
        let (operator_private, operator_public) = generate_operator_keypair().unwrap();
        let wg = wg_private();
        let plaintext = base64::engine::general_purpose::STANDARD.encode(wg);
        let legacy = seal_secret_to_operator(&operator_public, plaintext.as_bytes()).unwrap();

        assert!(matches!(
            prepare(&legacy, operator_private.as_slice(), Some(1), None),
            Err(RecoveryError::LegacyEscrow)
        ));
    }

    #[test]
    fn prepare_without_any_counter_is_refused() {
        let (operator_private, operator_public) = generate_operator_keypair().unwrap();
        let escrow = escrow_of(&wg_private(), &operator_public, None);

        assert!(matches!(
            prepare(&escrow, operator_private.as_slice(), None, None),
            Err(RecoveryError::CounterUnknown)
        ));
    }

    #[test]
    fn prepare_refuses_an_escrow_whose_key_does_not_match_its_header() {
        let (operator_private, operator_public) = generate_operator_keypair().unwrap();
        let wg = wg_private();
        let other = wg_private();
        let plaintext = base64::engine::general_purpose::STANDARD.encode(other);
        let metadata = EscrowMetadata {
            counter: Some(5),
            gateway_public_key: wg_public(&wg),
        };
        let escrow = seal_to_operator(&operator_public, plaintext.as_bytes(), &metadata).unwrap();

        assert!(matches!(
            prepare(&escrow, operator_private.as_slice(), None, None),
            Err(RecoveryError::EscrowInconsistent)
        ));
    }

    #[test]
    fn assemble_produces_a_frame_that_decodes_to_the_key() {
        let (operator_private, operator_public) = generate_operator_keypair().unwrap();
        let wg = wg_private();
        let escrow = escrow_of(&wg, &operator_public, Some(5));
        let auth = authorization(6, wg_public(&wg));

        let frame = assemble(&escrow, operator_private.as_slice(), &auth).unwrap();
        let (decoded, key) = decode_recovery_frame(&frame).unwrap();
        assert_eq!(decoded, auth);
        assert_eq!(key.as_slice(), &wg);
    }

    #[test]
    fn assemble_refuses_an_authorization_for_another_gateway() {
        let (operator_private, operator_public) = generate_operator_keypair().unwrap();
        let wg = wg_private();
        let escrow = escrow_of(&wg, &operator_public, Some(5));
        let other_gateway = wg_public(&wg_private());
        let auth = authorization(6, other_gateway);

        assert!(matches!(
            assemble(&escrow, operator_private.as_slice(), &auth),
            Err(RecoveryError::ForeignGateway)
        ));
    }

    #[test]
    fn assemble_refuses_a_single_signature() {
        let (operator_private, operator_public) = generate_operator_keypair().unwrap();
        let wg = wg_private();
        let escrow = escrow_of(&wg, &operator_public, Some(5));
        let mut auth = authorization(6, wg_public(&wg));
        auth.signatures
            .retain(|entry| entry.alg == aether::sig::AlgId::Ed25519.as_str());

        assert!(matches!(
            assemble(&escrow, operator_private.as_slice(), &auth),
            Err(RecoveryError::AuthorizationInvalid)
        ));
    }

    #[test]
    fn decode_refuses_truncated_and_oversized_frames() {
        let (operator_private, operator_public) = generate_operator_keypair().unwrap();
        let wg = wg_private();
        let escrow = escrow_of(&wg, &operator_public, Some(5));
        let auth = authorization(6, wg_public(&wg));
        let frame = assemble(&escrow, operator_private.as_slice(), &auth).unwrap();

        assert!(matches!(
            decode_recovery_frame(&frame[..frame.len() - 1]),
            Err(RecoveryError::FrameMalformed)
        ));
        assert!(matches!(
            decode_recovery_frame(&frame[..10]),
            Err(RecoveryError::FrameMalformed)
        ));
        assert!(matches!(
            decode_recovery_frame(&vec![0u8; MAX_RECOVERY_FRAME + 1]),
            Err(RecoveryError::FrameMalformed)
        ));
    }
}
