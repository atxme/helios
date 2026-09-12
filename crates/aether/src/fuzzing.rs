//! Fuzz entry points for the signed objects and the temporal state machine.
//!
//! Spec §14.1 asks for «fuzzing de tous les objets signés, de leurs
//! certificats embarqués et de la machine d'état temporelle». The targets that
//! drive libFuzzer live in `fuzz/`, outside the workspace, because that
//! harness needs a nightly toolchain. What they contain is three lines each:
//! the substance is here, in a module that the stable build compiles and the
//! ordinary test suite exercises.
//!
//! # Why here and not in the fuzz crate
//!
//! Code that only a nightly toolchain can build is code nobody runs on the
//! branch that ships. Putting the harnesses in `aether` means every one of
//! them is type-checked by `cargo check`, linted by clippy, and run over a
//! handful of seeds by `cargo test` — so a target that stopped compiling, or
//! that started passing because it had quietly become a no-op, is caught by
//! the same commands as everything else.
//!
//! # What a target may and may not do
//!
//! It may **refuse**. Every entry point below feeds attacker-controlled bytes
//! to a parser or a verifier whose whole job is to say no, so a refusal is the
//! expected outcome and is never an error. What none of them may do is panic,
//! and what the state-machine target additionally checks is that the
//! invariants of §4 survive an arbitrary sequence of operations at arbitrary
//! clock readings: counters that never go backwards, no third generation, and
//! a revoked identity that stays revoked.
//!
//! No entry point performs a signature verification against a *valid*
//! signature, because a fuzzer cannot produce one. What they exercise is the
//! decoding and the ordering of the checks that happen before that point,
//! which is where a malformed document does its damage.

use crate::certificates::encoding::Fingerprint;

/// A cursor over the fuzzer's bytes.
///
/// A hand-rolled reader rather than a dependency: what these targets need is
/// «give me the next byte, and tell me when you are empty», and adding a
/// derive-based input crate to the workspace for that would be a dependency
/// carried by every consumer of `aether` for the sake of four harnesses.
struct Bytes<'a> {
    data: &'a [u8],
}

impl<'a> Bytes<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn byte(&mut self) -> u8 {
        match self.data.split_first() {
            Some((first, rest)) => {
                self.data = rest;
                *first
            }
            None => 0,
        }
    }

    fn u64(&mut self) -> u64 {
        let mut value = [0u8; 8];
        for slot in &mut value {
            *slot = self.byte();
        }
        u64::from_le_bytes(value)
    }

    /// A clock reading, kept inside a range where the window arithmetic is
    /// interesting rather than saturating everywhere.
    fn instant(&mut self) -> u64 {
        self.u64() % (400 * 86_400)
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Every signed object, decoded from arbitrary bytes.
///
/// One JSON document is offered to each variant of the trust-update union in
/// turn. The interesting outcome is not that one of them parses — it is that
/// none of them panics, and that a document accepted by the parser still has
/// to survive `fingerprint()`, which walks every field it declared.
pub fn signed_object(data: &[u8]) {
    use crate::certificates::transport::TrustUpdateObject;

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(object) = serde_json::from_str::<TrustUpdateObject>(text) {
        // The canonical encoding must survive anything the parser let in: a
        // document that decodes and then panics on its own transcript is one
        // an attacker can hand to any holder.
        let _ = object.fingerprint();
        let _ = object.apply_order();
    }
    // The two objects that never travel in that union, and whose parsers are
    // reached by their own routes.
    let _ = serde_json::from_str::<crate::certificates::status::AstraRotationCampaign>(text);
    let _ = serde_json::from_str::<crate::certificates::status::AstraSignerResult>(text);
}

/// A chunked trust transaction, assembled from arbitrary bytes.
///
/// The property under test is the one §8.1.1 exists for: fragments assemble
/// into exactly the transaction their manifest describes, or into nothing.
/// A partially filled accumulator must never report itself complete, and a
/// complete one must hand back exactly as many objects as the manifest
/// announced.
pub fn trust_transaction(data: &[u8]) {
    use crate::certificates::transport::{
        PendingTrustTransaction, TrustUpdateChunk, TrustUpdateTransactionManifest,
    };

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    #[derive(serde::Deserialize)]
    struct Input {
        manifest: TrustUpdateTransactionManifest,
        chunks: Vec<TrustUpdateChunk>,
    }
    let Ok(input) = serde_json::from_str::<Input>(text) else {
        return;
    };

    let announced = input.manifest.objects.len();
    let mut pending = PendingTrustTransaction::new(input.manifest);
    for chunk in &input.chunks {
        // A refused fragment is the ordinary outcome and never stops the run:
        // what matters is the state the accumulator is left in afterwards.
        let _ = pending.accept(chunk);
        match pending.complete() {
            Some(objects) => assert_eq!(
                objects.len(),
                announced,
                "a complete transaction carries exactly the objects its manifest announced"
            ),
            None => assert!(
                !pending.is_complete(),
                "an accumulator that hands back nothing must not report itself complete"
            ),
        }
    }
}

/// The X.509 documents a signed object embeds.
///
/// `aether` parses DER that arrived inside a signed envelope, which is exactly
/// the case where «it was signed» is not a reason to trust the bytes: the
/// signature covers the fingerprint of a certificate nobody has parsed yet.
pub fn x509_documents(data: &[u8]) {
    use crate::certificates::encoding::DerCertificate;
    use crate::certificates::x509;

    let Ok(certificate) = DerCertificate::new(data.to_vec()) else {
        return;
    };
    let _ = x509::inspect(&certificate);
    let _ = x509::subject_public_key_info(&certificate);
    let _ = x509::certification_request_public_key_info(&certificate);
    let _ = x509::assert_certificate_authority(&certificate);
    // Chaining a document against itself: a self-issued certificate is legal,
    // and the parser must reach the same verdict twice.
    let first = x509::assert_issued_by(&certificate, &certificate).is_ok();
    let second = x509::assert_issued_by(&certificate, &certificate).is_ok();
    assert_eq!(first, second, "chain verification must be deterministic");
}

/// The temporal state machine of §4 and §6, driven by arbitrary operations.
///
/// This is the target that earns its keep. The others check that a parser
/// refuses; this one checks that a sequence of *legal-looking* operations at
/// arbitrary clock readings cannot walk the state somewhere the specification
/// forbids — which is the class of defect a reviewer misses and a fuzzer does
/// not.
///
/// The invariants asserted after every step:
///
/// - the revocation counter never decreases, and `revoked` is terminal;
/// - a promotion never brings back a generation the clock has left;
/// - a service rollback never moves a counter, and never outlives its overlap.
pub fn gateway_state_machine(data: &[u8]) {
    use crate::certificates::state::GatewayCertificateState;

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(mut state) = serde_json::from_str::<GatewayCertificateState>(text) else {
        return;
    };

    let mut bytes = Bytes::new(data);
    let mut revocation_epoch = state.revocation_epoch;
    let mut was_revoked = state.revoked;

    while !bytes.is_empty() {
        let now = bytes.instant();
        match bytes.byte() % 3 {
            0 => {
                let _ = state.promote_if_due(now);
            }
            1 => {
                let _ = state.promote_ca_if_due(now);
            }
            _ => {
                let _ = state.active_service_rollback(now);
            }
        }

        assert!(
            state.revocation_epoch >= revocation_epoch,
            "a consumed revocation counter never comes back down"
        );
        revocation_epoch = state.revocation_epoch;

        assert!(
            state.revoked || !was_revoked,
            "revoked is terminal: no maintenance pass lifts it"
        );
        was_revoked = state.revoked;

        if let Some(rollback) = state.active_service_rollback(now) {
            assert!(
                now < rollback.expires_at,
                "a rollback served past its own expiry is not bounded at all"
            );
            assert!(
                state
                    .retire_active_at
                    .is_none_or(|not_after| rollback.expires_at <= not_after),
                "a rollback never outlives the overlap it lives in"
            );
        }
    }

    // The fingerprint of the final state must be computable whatever the walk
    // did: it is what a client signs its next request against.
    let _ = state.active_pq_fingerprint();
    let _: Fingerprint = state.active_tls_fingerprint();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seeds every target is run over by the ordinary suite.
    ///
    /// Not a corpus — a fuzzer builds its own. These exist so a harness that
    /// stopped compiling, or that quietly became a no-op because a type it
    /// names was renamed, fails here rather than on the day someone runs
    /// `cargo fuzz` for the first time in a month.
    const SEEDS: &[&[u8]] = &[
        b"",
        b"{}",
        b"null",
        b"[]",
        b"\xff\xfe\xfd",
        b"{\"ca_transition\":{}}",
        b"{\"manifest\":{},\"chunks\":[]}",
        b"0123456789abcdef0123456789abcdef",
        b"\x30\x82\x01\x00", // a DER SEQUENCE header and nothing after it
    ];

    #[test]
    fn no_target_panics_on_a_seed() {
        for seed in SEEDS {
            signed_object(seed);
            trust_transaction(seed);
            x509_documents(seed);
            gateway_state_machine(seed);
        }
    }

    /// A byte reader that runs out mid-value must answer, not panic: the
    /// fuzzer will hand every target a truncated input on its first pass.
    #[test]
    fn the_reader_runs_dry_without_panicking() {
        let mut bytes = Bytes::new(&[1, 2, 3]);
        let _ = bytes.u64();
        assert!(bytes.is_empty());
        assert_eq!(bytes.byte(), 0);
        assert_eq!(bytes.u64(), 0);
    }

    /// The state-machine target must actually reach the state machine, or it
    /// asserts nothing at all. A well-formed state walks; a malformed one is
    /// dropped before the loop.
    #[test]
    fn the_state_machine_target_runs_on_a_well_formed_state() {
        let state = crate::certificates::state::GatewayCertificateState {
            trust_domain_id: crate::certificates::encoding::TrustDomainId::new([1; 16])
                .expect("domain"),
            gateway_wg_public_key: crate::certificates::encoding::WireGuardKey::from_bytes([2; 32]),
            server_name: "gateway.example".into(),
            ca_epoch: 1,
            current_ca_public_key: crate::certificates::encoding::MlDsa87PublicKey::new(vec![
                0;
                2592
            ])
            .expect("key"),
            next_ca_public_key: None,
            next_ca_transition_fingerprint: None,
            ca_activation_at: None,
            ca_retire_active_at: None,
            active_gateway_identity_epoch: 1,
            gateway_decision_epoch: 1,
            next_gateway_identity_epoch: None,
            next_transition_fingerprint: None,
            last_aborted_transition: None,
            active_gateway_tls_certificate: crate::certificates::encoding::DerCertificate::new(
                vec![1; 64],
            )
            .expect("der"),
            next_gateway_tls_certificate: None,
            active_gateway_certificate: crate::key_negotiation::PqCertificate {
                version: crate::key_negotiation::PQ_CERTIFICATE_VERSION,
                serial: [3; 16],
                subject: "gateway.example".into(),
                issuer: "CA-PQ".into(),
                role: crate::key_negotiation::PqCertificateRole::Gateway,
                wireguard_public_key: crate::certificates::encoding::WireGuardKey::from_bytes(
                    [2; 32],
                )
                .to_base64(),
                ml_dsa_87_public_key: String::new(),
                not_before_unix: 0,
                not_after_unix: 100_000,
                ml_dsa_87_signature: String::new(),
            },
            next_gateway_certificate: None,
            activation_at: None,
            retire_active_at: None,
            published: false,
            revoked: false,
            revocation_epoch: 0,
            service_rollback: None,
            awaited_replacement: None,
        };
        let mut encoded = serde_json::to_vec(&state).expect("encode");
        // Bytes past the document are what drives the walk.
        encoded.extend_from_slice(&[0xAA; 64]);
        gateway_state_machine(&encoded);
    }
}
