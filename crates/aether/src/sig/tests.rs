use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use fips204::{
    ml_dsa_65::KG,
    traits::{KeyGen, SerDes, Signer},
};

use super::*;

const ED_SEED: [u8; 32] = *b"helios-sign-ed25519-test-seed001";
const ML_SEED: [u8; 32] = *b"helios-sign-mldsa65-test-seed001";

fn signed(payload: ResealPayload, key_epoch: u32) -> (SignedResealTicket, PublisherPublicKeys) {
    let ed = Ed25519KeyPair::from_seed_unchecked(&ED_SEED).unwrap();
    let (ml_public, ml_private) = KG::keygen_from_seed(&ML_SEED);
    let keys = PublisherPublicKeys {
        key_epoch,
        ed25519: ed.public_key().as_ref().try_into().unwrap(),
        ml_dsa_65: ml_public.into_bytes(),
    };
    let message = signing_bytes(&payload, key_epoch);
    let ed_signature = ed.sign(&message);
    let ml_signature = ml_private
        .try_sign_with_seed(&[7u8; 32], &message, &[])
        .unwrap();
    (
        SignedEnvelope {
            payload,
            key_epoch,
            signatures: vec![
                ArtifactSignature {
                    alg: "ed25519".into(),
                    sig: STANDARD.encode(ed_signature.as_ref()),
                },
                ArtifactSignature {
                    alg: "ml-dsa-65".into(),
                    sig: STANDARD.encode(ml_signature),
                },
            ],
        },
        keys,
    )
}

fn entry(path: &str) -> BundleEntry {
    BundleEntry {
        path: path.to_string(),
        size: 10,
        sha256: [1u8; 32],
        executable: false,
    }
}

fn bundle(files: Vec<BundleEntry>) -> BundlePayload {
    BundlePayload {
        product: "helios".into(),
        channel: "testing".into(),
        release_sequence: 1,
        version: "0.1.0".into(),
        git_commit: "abcdef".into(),
        target: "x86_64-unknown-linux-gnu".into(),
        minimum_installer_version: 1,
        files,
    }
}

/// An absolute or ascending path would write outside the destination:
/// this is an arbitrary write disguised as an installation.
#[test]
fn a_bundle_path_outside_the_root_is_rejected() {
    for path in [
        "/etc/systemd/system/heliosd.service",
        "../../etc/passwd",
        "bin/../../../root/.ssh/authorized_keys",
        "./heliosd",
        "C:/heliosd",
        "bin\\heliosd",
        "",
    ] {
        assert!(
            matches!(
                bundle(vec![entry(path)]).validate(),
                Err(BundleError::Path(_))
            ),
            "path wrongly accepted: {path:?}"
        );
    }
}

#[test]
fn an_unsorted_or_duplicated_list_is_rejected() {
    assert!(matches!(
        bundle(vec![entry("b"), entry("a")]).validate(),
        Err(BundleError::Order(_))
    ));
    assert!(matches!(
        bundle(vec![entry("a"), entry("a")]).validate(),
        Err(BundleError::Order(_))
    ));
    assert_eq!(bundle(vec![]).validate(), Err(BundleError::Empty));
    assert_eq!(bundle(vec![entry("a"), entry("b/c")]).validate(), Ok(()));
}

/// The domain separates artifacts: a bundle's signature must not be
/// usable as a binary release signature (ADR-002 §3).
#[test]
fn the_bundle_domain_is_distinct_from_other_artifacts() {
    let bytes = signing_bytes(&bundle(vec![entry("heliosd")]), 1);
    assert!(bytes.starts_with(b"helios-bundle-v1"));
    assert_ne!(BundlePayload::DOMAIN, BinaryReleasePayload::DOMAIN);
    assert_ne!(BundlePayload::DOMAIN, ResealPayload::DOMAIN);
}

/// Every content field must enter the signed bytes: a file whose digest
/// or executable bit could change without invalidating the signature
/// would not be protected at all.
#[test]
fn any_content_alteration_changes_the_signed_bytes() {
    let reference = signing_bytes(&bundle(vec![entry("heliosd")]), 1);

    let mut different_digest = entry("heliosd");
    different_digest.sha256 = [2u8; 32];
    let mut different_size = entry("heliosd");
    different_size.size = 11;
    let mut different_mode = entry("heliosd");
    different_mode.executable = true;

    for modified in [
        different_digest,
        different_size,
        different_mode,
        entry("autre"),
    ] {
        assert_ne!(
            signing_bytes(&bundle(vec![modified]), 1),
            reference,
            "a content modification did not change the signed bytes"
        );
    }
    assert_ne!(
        signing_bytes(&bundle(vec![entry("heliosd")]), 2),
        reference,
        "the key epoch must be signed (ADR-002 amendment 3)"
    );
}

#[test]
fn both_valid_signatures_are_required() {
    let (envelope, keys) = signed(
        ResealPayload {
            version: 3,
            expected_pcr_digest: None,
        },
        1,
    );
    assert_eq!(envelope.verify(&[keys]), Ok(()));

    for algorithm in REQUIRED_ALGS {
        let mut missing = envelope.clone();
        missing
            .signatures
            .retain(|entry| entry.alg != algorithm.as_str());
        assert_eq!(
            missing.verify(&[keys]),
            Err(SignatureError::MissingRequiredAlgorithm(*algorithm))
        );
    }
}

#[test]
fn a_known_but_invalid_signature_is_a_rejection() {
    let (envelope, keys) = signed(
        ResealPayload {
            version: 3,
            expected_pcr_digest: None,
        },
        1,
    );
    for algorithm in REQUIRED_ALGS {
        let mut corrupted = envelope.clone();
        let entry = corrupted
            .signatures
            .iter_mut()
            .find(|entry| entry.alg == algorithm.as_str())
            .unwrap();
        let mut bytes = STANDARD.decode(&entry.sig).unwrap();
        bytes[0] ^= 1;
        entry.sig = STANDARD.encode(bytes);
        assert_eq!(
            corrupted.verify(&[keys]),
            Err(SignatureError::InvalidSignature(*algorithm))
        );
    }
}

#[test]
fn unknown_algorithm_ignored_but_known_duplicate_rejected() {
    let (mut envelope, keys) = signed(
        ResealPayload {
            version: 1,
            expected_pcr_digest: None,
        },
        1,
    );
    envelope.signatures.push(ArtifactSignature {
        alg: "slh-dsa-128s-futur".into(),
        sig: "not even base64".into(),
    });
    assert_eq!(envelope.verify(&[keys]), Ok(()));

    envelope.signatures.push(envelope.signatures[0].clone());
    assert_eq!(
        envelope.verify(&[keys]),
        Err(SignatureError::DuplicateAlgorithm(AlgId::Ed25519))
    );
}

#[test]
fn binary_manifest_has_a_strict_canonical_encoding() {
    let payload = BinaryReleasePayload {
        product: "heliosd".into(),
        channel: "testing".into(),
        release_sequence: 42,
        version: "1.2.3".into(),
        git_commit: "0123456789abcdef".into(),
        target: "x86_64-unknown-linux-gnu".into(),
        features: vec!["embed-ui".into(), "netlink".into()],
        binary_size: 1234,
        sha256: [7; 32],
        minimum_installer_version: 1,
    };
    let bytes = signing_bytes(&payload, 3);
    assert!(bytes.starts_with(BinaryReleasePayload::DOMAIN));

    let json = serde_json::to_vec(&payload).unwrap();
    let decoded: BinaryReleasePayload = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, payload);

    let mut value = serde_json::to_value(&payload).unwrap();
    value["champ_inconnu"] = serde_json::json!(true);
    assert!(serde_json::from_value::<BinaryReleasePayload>(value).is_err());
}

#[test]
fn unknown_epoch_and_epoch_rewriting_are_rejected() {
    let (mut envelope, keys) = signed(
        ResealPayload {
            version: 1,
            expected_pcr_digest: None,
        },
        1,
    );
    assert_eq!(
        envelope.verify(&[]),
        Err(SignatureError::UnknownKeyEpoch(1))
    );

    envelope.key_epoch = 2;
    let same_keys_other_epoch = PublisherPublicKeys {
        key_epoch: 2,
        ..keys
    };
    assert_eq!(
        envelope.verify(&[same_keys_other_epoch]),
        Err(SignatureError::InvalidSignature(AlgId::Ed25519))
    );
}

#[test]
fn payload_mutation_is_rejected() {
    let (mut envelope, keys) = signed(
        ResealPayload {
            version: 1,
            expected_pcr_digest: Some([4u8; 32]),
        },
        1,
    );
    envelope.payload.version = 2;
    assert!(matches!(
        envelope.verify(&[keys]),
        Err(SignatureError::InvalidSignature(_))
    ));
}

#[test]
fn domain_and_format_version_are_part_of_the_signature() {
    #[derive(Clone)]
    struct OtherArtifact(ResealPayload);

    impl ArtifactPayload for OtherArtifact {
        const DOMAIN: &'static [u8] = b"helios-wg-recovery-v1";
        const FORMAT_VERSION: u32 = 1;

        fn encode_canonical(&self, output: &mut Vec<u8>) {
            self.0.encode_canonical(output);
        }
    }

    let (ticket, keys) = signed(
        ResealPayload {
            version: 1,
            expected_pcr_digest: None,
        },
        1,
    );
    let wrong_context = SignedEnvelope {
        payload: OtherArtifact(ticket.payload),
        key_epoch: ticket.key_epoch,
        signatures: ticket.signatures,
    };
    assert!(matches!(
        wrong_context.verify(&[keys]),
        Err(SignatureError::InvalidSignature(_))
    ));
}

#[test]
fn ed25519_rejects_non_canonical_encodings_and_weak_points() {
    let message = b"proof of the AWS-LC strict path";
    let ed = Ed25519KeyPair::from_seed_unchecked(&ED_SEED).unwrap();
    let signature = ed.sign(message);
    assert!(Ed25519Suite::verify(
        ed.public_key().as_ref(),
        message,
        signature.as_ref()
    ));

    // S = subgroup order (non-canonical, S < L is required).
    let mut non_canonical_s: [u8; 64] = signature.as_ref().try_into().unwrap();
    non_canonical_s[32..].copy_from_slice(&[
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]);
    assert!(!Ed25519Suite::verify(
        ed.public_key().as_ref(),
        message,
        &non_canonical_s
    ));

    // Public key and R at the identity point: a non-strict verification
    // could accept this trivial forgery with S = 0.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut weak_signature = [0u8; 64];
    weak_signature[0] = 1;
    assert!(!Ed25519Suite::verify(&identity, message, &weak_signature));
}

#[test]
fn reordered_json_does_not_change_the_canonical_bytes() {
    let first: SignedResealTicket = serde_json::from_str(
        r#"{"payload":{"version":9,"expected_pcr_digest":null},"key_epoch":1,"signatures":[]}"#,
    )
    .unwrap();
    let second: SignedResealTicket = serde_json::from_str(
        r#"{"signatures":[],"key_epoch":1,"payload":{"expected_pcr_digest":null,"version":9}}"#,
    )
    .unwrap();
    assert_eq!(
        signing_bytes(&first.payload, first.key_epoch),
        signing_bytes(&second.payload, second.key_epoch)
    );
}

#[test]
fn invalid_base64_encoding_and_empty_signature_are_fail_closed() {
    let (envelope, keys) = signed(
        ResealPayload {
            version: 5,
            expected_pcr_digest: None,
        },
        1,
    );

    let mut invalid_base64 = envelope.clone();
    invalid_base64.signatures[0].sig = "%%%".into();
    assert_eq!(
        invalid_base64.verify(&[keys]),
        Err(SignatureError::InvalidEncoding(AlgId::Ed25519))
    );

    let mut empty = envelope;
    empty.signatures[1].sig.clear();
    assert_eq!(
        empty.verify(&[keys]),
        Err(SignatureError::InvalidSignature(AlgId::MlDsa65))
    );
}

#[test]
fn json_rejects_any_unauthenticated_field() {
    for json in [
        r#"{"payload":{"version":9,"expected_pcr_digest":null},"key_epoch":1,"signatures":[],"selector":"attaquant"}"#,
        r#"{"payload":{"version":9,"expected_pcr_digest":null,"ignored":true},"key_epoch":1,"signatures":[]}"#,
        r#"{"payload":{"version":9,"expected_pcr_digest":null},"key_epoch":1,"signatures":[{"alg":"ed25519","sig":"AA==","extra":1}]}"#,
    ] {
        assert!(serde_json::from_str::<SignedResealTicket>(json).is_err());
    }
}

#[test]
fn fingerprint_identifies_both_halves_of_the_keyring() {
    let (_, keys) = signed(
        ResealPayload {
            version: 1,
            expected_pcr_digest: None,
        },
        7,
    );
    assert_eq!(keys.fingerprint(), keys.fingerprint());
    assert_eq!(keys.fingerprint().len(), 32);

    let mut changed_ed = keys;
    changed_ed.ed25519[0] ^= 1;
    assert_ne!(keys.fingerprint(), changed_ed.fingerprint());

    let mut changed_ml = keys;
    changed_ml.ml_dsa_65[0] ^= 1;
    assert_ne!(keys.fingerprint(), changed_ml.fingerprint());
}

#[test]
fn firmware_authorization_is_bound_to_every_context_field_and_its_own_domain() {
    let payload = FirmwareRecoveryPayload {
        version: 3,
        sealed_blob_anchor: [1; 32],
        secret_commitment: [2; 32],
        device_id: "5bc922b7bd1adb5b6f99592611404036bd9f42d0".into(),
        target_version: "2023".into(),
    };
    let message = signing_bytes(&payload, 1);
    let mut changed = payload.clone();
    changed.version += 1;
    assert_ne!(message, signing_bytes(&changed, 1));
    changed = payload.clone();
    changed.sealed_blob_anchor[0] ^= 1;
    assert_ne!(message, signing_bytes(&changed, 1));
    changed = payload.clone();
    changed.secret_commitment[0] ^= 1;
    assert_ne!(message, signing_bytes(&changed, 1));
    changed = payload.clone();
    changed.device_id.replace_range(..1, "0");
    assert_ne!(message, signing_bytes(&changed, 1));
    changed = payload.clone();
    changed.target_version = "2024".into();
    assert_ne!(message, signing_bytes(&changed, 1));
    assert_ne!(message, signing_bytes(&payload, 2));
    assert_ne!(FirmwareRecoveryPayload::DOMAIN, ResealPayload::DOMAIN);
    let mut json = serde_json::to_value(&payload).unwrap();
    json["secret"] = serde_json::json!("not allowed");
    assert!(serde_json::from_value::<FirmwareRecoveryPayload>(json).is_err());
    changed.target_version = "--force".into();
    assert!(changed.validate().is_err());
    changed = payload;
    changed.version = 0;
    assert!(changed.validate().is_err());
}
