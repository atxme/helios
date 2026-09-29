use super::*;
use crate::certificates::encoding::{generate_ml_dsa_87_keypair, sign_ml_dsa_87};
use crate::certificates::window::TransitionWindow;
use zeroize::Zeroizing;

/// The bound is not a round number picked by feel: it has to clear what a
/// commit and its grant actually weigh, base64 included.
#[test]
fn the_stage_commit_bound_clears_what_the_pair_carries() {
    const ML_DSA_87_SIGNATURE: usize = 4627;
    const ML_DSA_87_PUBLIC_KEY: usize = 2592;
    // Two on the commit, one on the grant, one on the PQ leaf, one on the
    // stage receipt, one on the delegation.
    let signatures = 6 * ML_DSA_87_SIGNATURE;
    // The PQ leaf's key, and the delegated issuer's.
    let keys = 2 * ML_DSA_87_PUBLIC_KEY;
    // The client TLS leaf and the delegated intermediate, generously.
    let certificates = 2 * 2_048;
    let base64 = (signatures + keys + certificates).div_ceil(3) * 4;
    assert!(
        MAX_STAGE_COMMIT_REQUEST_BYTES > base64,
        "the bound must hold the signed material: {base64} bytes of base64"
    );
    assert!(
        MAX_TRUST_UPDATE_REQUEST_BYTES < base64,
        "if a trust update body could hold it, this constant would be pointless"
    );
}

struct Keys {
    private: Zeroizing<Vec<u8>>,
    public: MlDsa87PublicKey,
}

fn keys() -> Keys {
    let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
    Keys { private, public }
}

fn domain() -> TrustDomainId {
    TrustDomainId::new([5; 16]).expect("domain")
}

fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([1; 32])
}

fn client_key() -> WireGuardKey {
    WireGuardKey::from_bytes([2; 32])
}

/// A cheap object to fill a transaction with: a CA transition whose
/// signatures are never verified by the manifest itself.
fn ca_object(seed: u8) -> TrustUpdateObject {
    let next = keys();
    TrustUpdateObject::CaTransition(Box::new(CaTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        current_ca_epoch: u64::from(seed),
        next_ca_epoch: u64::from(seed) + 1,
        current_ca_fingerprint: Fingerprint::of(&[seed]),
        next_ca_public_key: next.public.clone(),
        next_ca_fingerprint: next.public.authority_fingerprint(),
        window: TransitionWindow::new(1_000, 2_000, 3_000).unwrap(),
        current_ca_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        next_ca_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
    }))
}

fn manifest(
    authority: &Keys,
    objects: &[TrustUpdateObject],
    chunk_count: u16,
) -> TrustUpdateTransactionManifest {
    let refs = objects
        .iter()
        .map(|object| TrustUpdateObjectRef {
            apply_order: object.apply_order(),
            object_fingerprint: object.fingerprint().expect("fingerprint"),
            prerequisite_bitmap: 0,
        })
        .collect();
    let mut manifest = TrustUpdateTransactionManifest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        transaction_id: Id16::new([6; 16]).expect("id"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        base_state_fingerprint: Fingerprint::of(b"base state"),
        created_at: 1_000,
        expires_at: 5_000,
        minimum_activation_at: 9_000,
        chunk_count,
        objects: refs,
        manifest_authority_kind: ManifestAuthority::AstraServiceKey,
        manifest_authority_epoch: 1,
        signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
    };
    manifest.signature = sign_ml_dsa_87(&authority.private, &manifest.signing_bytes()).unwrap();
    manifest
}

fn verify_manifest(
    manifest: &TrustUpdateTransactionManifest,
    authority: &Keys,
    now: u64,
) -> Result<(), CertificateError> {
    manifest.verify(
        &authority.public,
        1,
        &domain(),
        &gateway_key(),
        &client_key(),
        &Fingerprint::of(b"base state"),
        now,
    )
}

/// The builder and the verifier are one contract: what it emits has to
/// pass every check the receiver runs, reassemble in order, and land on
/// the exact base state the client signed.
#[test]
fn a_built_transaction_verifies_and_reassembles_whole() {
    use super::signing::{build_transaction, TransactionPlan};

    let authority = keys();
    let base = Fingerprint::of(b"orion local state");
    let objects = vec![ca_object(1), ca_object(2), ca_object(3)];
    let plan = TransactionPlan {
        transaction_id: Id16::new([5; 16]).expect("id"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        base_state_fingerprint: base,
        created_at: 1_000,
        expires_at: 8_000,
        minimum_activation_at: 9_000,
        authority_epoch: 1,
        authority_private_key: &authority.private,
    };
    // A budget under two objects, so the split is exercised rather than
    // assumed: a single-chunk transaction proves nothing about ranges.
    let one_object = serde_json::to_vec(&objects[0]).expect("encode").len();
    let (manifest, chunks) =
        build_transaction(objects.clone(), &plan, one_object + 1).expect("built");

    assert!(chunks.len() > 1, "the budget must have split this set");
    assert_eq!(manifest.chunk_count as usize, chunks.len());
    manifest
        .verify(
            &authority.public,
            1,
            &domain(),
            &gateway_key(),
            &client_key(),
            &base,
            1_100,
        )
        .expect("the receiver accepts what the builder emitted");

    let mut pending = PendingTrustTransaction::new(manifest);
    for chunk in &chunks {
        pending.accept(chunk).expect("fragment");
    }
    assert!(pending.is_complete());
    assert_eq!(pending.complete().expect("complete"), objects);
}

/// The base state is the compare-and-swap token. A transaction built for
/// one snapshot must not apply to another, even one object for object.
#[test]
fn a_built_transaction_is_refused_against_another_base_state() {
    use super::signing::{build_transaction, TransactionPlan};

    let authority = keys();
    let plan = TransactionPlan {
        transaction_id: Id16::new([5; 16]).expect("id"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        base_state_fingerprint: Fingerprint::of(b"the state it was built for"),
        created_at: 1_000,
        expires_at: 8_000,
        minimum_activation_at: 9_000,
        authority_epoch: 1,
        authority_private_key: &authority.private,
    };
    let (manifest, _) = build_transaction(vec![ca_object(1)], &plan, 64 * 1024).expect("built");
    assert!(matches!(
        manifest.verify(
            &authority.public,
            1,
            &domain(),
            &gateway_key(),
            &client_key(),
            &Fingerprint::of(b"the state it moved to"),
            1_100,
        ),
        Err(CertificateError::InvalidTransaction("base state moved"))
    ));
}

/// A fragment carries whole objects. One that fits in no fragment is
/// refused here rather than emitted as a transaction nobody can read.
#[test]
fn an_object_that_fits_in_no_fragment_is_refused() {
    use super::signing::{build_transaction, TransactionPlan};

    let authority = keys();
    let plan = TransactionPlan {
        transaction_id: Id16::new([5; 16]).expect("id"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        base_state_fingerprint: Fingerprint::of(b"base"),
        created_at: 1_000,
        expires_at: 8_000,
        minimum_activation_at: 9_000,
        authority_epoch: 1,
        authority_private_key: &authority.private,
    };
    assert!(matches!(
        build_transaction(vec![ca_object(1)], &plan, 16),
        Err(CertificateError::InvalidTransaction("object too large"))
    ));
    assert!(matches!(
        build_transaction(Vec::new(), &plan, 64 * 1024),
        Err(CertificateError::InvalidTransaction("empty transaction"))
    ));
}

/// The opaque CAS token is part of the client's signature. A gateway may
/// relay it, but cannot retarget the future manifest to another local
/// state without invalidating the request first.
/// A client leaf issued by an authority the verifier does not hold, bound
/// to `client_key()` and valid over `1..=u64::MAX`.
#[cfg(feature = "key-negotiation-signing")]
fn client_leaf(
    subject: &str,
    subject_public: &MlDsa87PublicKey,
    issuer_private: &[u8],
    not_after: u64,
) -> crate::key_negotiation::PqCertificate {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    crate::key_negotiation::issue_pq_certificate(
        crate::key_negotiation::PqCertificate {
            version: crate::key_negotiation::PQ_CERTIFICATE_VERSION,
            serial: [4; 16],
            subject: subject.into(),
            issuer: "operator-ca".into(),
            role: crate::key_negotiation::PqCertificateRole::Client,
            wireguard_public_key: client_key().to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
            not_before_unix: 1,
            not_after_unix: not_after,
            ml_dsa_87_signature: String::new(),
        },
        issuer_private,
    )
    .expect("client leaf")
}

/// A request signed by that leaf, naming its own fingerprint.
#[cfg(feature = "key-negotiation-signing")]
fn signed_request(
    leaf: &crate::key_negotiation::PqCertificate,
    leaf_private: &[u8],
) -> AuthenticatedTrustUpdateRequest {
    let request = TrustUpdateRequest {
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        request_id: Id16::new([3; 16]).expect("request"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        ca_epoch: 1,
        ca_tls_epoch: 2,
        astra_service_key_epoch: 3,
        issuer_epoch: 4,
        active_gateway_identity_epoch: 5,
        gateway_decision_epoch: 6,
        client_identity_generation: 7,
        active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"gateway tls"),
        active_gateway_certificate_fingerprint: Fingerprint::of(b"gateway pq"),
        active_client_tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
        active_client_pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
        client_pq_certificate_fingerprint: pq_certificate_fingerprint(leaf).expect("presented"),
        base_state_fingerprint: Fingerprint::of(b"local state"),
    };
    let signature = sign_ml_dsa_87(leaf_private, &request.signing_bytes()).expect("signature");
    AuthenticatedTrustUpdateRequest {
        request,
        certificate: leaf.clone(),
        ml_dsa_87_signature: signature,
    }
}

/// A client's **first** leaf is issued by the operator CA, an authority a
/// domain registry does not carry — and must not learn from the request it
/// is checking. No issuer set can authenticate it, so Astra refused every
/// peer that had never renewed: on a fresh domain, every peer.
///
/// The leaf it recorded at admission answers what the issuer set cannot,
/// and answers it more narrowly: one certificate rather than every
/// certificate that authority ever signed.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn a_first_generation_leaf_verifies_against_the_recorded_one_and_under_no_issuer() {
    let operator_ca = keys();
    let leaf_keys = keys();
    let leaf = client_leaf("poste", &leaf_keys.public, &operator_ca.private, u64::MAX);
    let authenticated = signed_request(&leaf, &leaf_keys.private);
    let acceptable = [pq_certificate_fingerprint(&leaf).expect("presented")];
    let domain_anchor = keys();

    assert_eq!(
        authenticated.verify(
            &[&domain_anchor.public],
            &domain(),
            &gateway_key(),
            &client_key(),
            &acceptable,
            100,
        ),
        Err(CertificateError::UnauthorizedIssuer),
        "the operator CA is not an authority this registry holds"
    );
    authenticated
        .verify_against_recorded_leaf(
            &leaf,
            &domain(),
            &gateway_key(),
            &client_key(),
            &acceptable,
            100,
        )
        .expect("the leaf Astra recorded at admission");
}

/// Identity, not resemblance: another leaf for the same peer, issued by
/// the same authority, is refused.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn a_leaf_other_than_the_recorded_one_is_refused() {
    let operator_ca = keys();
    let leaf_keys = keys();
    let leaf = client_leaf("poste", &leaf_keys.public, &operator_ca.private, u64::MAX);
    let other = client_leaf("autre", &leaf_keys.public, &operator_ca.private, u64::MAX);
    let authenticated = signed_request(&leaf, &leaf_keys.private);
    let acceptable = [pq_certificate_fingerprint(&leaf).expect("presented")];

    assert_eq!(
        authenticated.verify_against_recorded_leaf(
            &other,
            &domain(),
            &gateway_key(),
            &client_key(),
            &acceptable,
            100,
        ),
        Err(CertificateError::UnauthorizedIssuer)
    );
}

/// Recorded is not eternal. Identity replaces the issuer check, never the
/// clock: a peer whose leaf has expired renews through §7.5, not here.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn a_recorded_leaf_past_its_validity_is_refused() {
    let operator_ca = keys();
    let leaf_keys = keys();
    let leaf = client_leaf("poste", &leaf_keys.public, &operator_ca.private, 50);
    let authenticated = signed_request(&leaf, &leaf_keys.private);
    let acceptable = [pq_certificate_fingerprint(&leaf).expect("presented")];

    assert_eq!(
        authenticated.verify_against_recorded_leaf(
            &leaf,
            &domain(),
            &gateway_key(),
            &client_key(),
            &acceptable,
            100,
        ),
        Err(CertificateError::OutsideValidityPeriod)
    );
}

#[test]
fn the_base_state_fingerprint_is_bound_into_the_client_request() {
    let signer = keys();
    let mut request = TrustUpdateRequest {
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        request_id: Id16::new([3; 16]).expect("request"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        ca_epoch: 1,
        ca_tls_epoch: 2,
        astra_service_key_epoch: 3,
        issuer_epoch: 4,
        active_gateway_identity_epoch: 5,
        gateway_decision_epoch: 6,
        client_identity_generation: 7,
        active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"gateway tls"),
        active_gateway_certificate_fingerprint: Fingerprint::of(b"gateway pq"),
        active_client_tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
        active_client_pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
        client_pq_certificate_fingerprint: Fingerprint::of(b"presented pq"),
        base_state_fingerprint: Fingerprint::of(b"local state"),
    };
    let signature = sign_ml_dsa_87(&signer.private, &request.signing_bytes()).expect("signature");
    verify_ml_dsa_87(&signer.public, &request.signing_bytes(), &signature)
        .expect("original request");

    request.base_state_fingerprint = Fingerprint::of(b"another local state");
    assert!(verify_ml_dsa_87(&signer.public, &request.signing_bytes(), &signature).is_err());
}

/// Nothing is visible until every chunk has landed — the property the
/// whole chunking design exists for.
#[test]
fn a_transaction_stays_invisible_until_its_last_chunk_arrives() {
    let authority = keys();
    let objects = vec![ca_object(1), ca_object(2)];
    let manifest = manifest(&authority, &objects, 2);
    assert!(verify_manifest(&manifest, &authority, 1_100).is_ok());

    let mut pending = PendingTrustTransaction::new(manifest.clone());
    let first = TrustUpdateChunk {
        manifest_fingerprint: manifest.fingerprint(),
        chunk_index: 0,
        chunk_count: 2,
        first_object_index: 0,
        objects: vec![objects[0].clone()],
    };
    pending.accept(&first).expect("first chunk");
    assert!(!pending.is_complete());
    assert!(pending.complete().is_none());

    let second = TrustUpdateChunk {
        manifest_fingerprint: manifest.fingerprint(),
        chunk_index: 1,
        chunk_count: 2,
        first_object_index: 1,
        objects: vec![objects[1].clone()],
    };
    pending.accept(&second).expect("second chunk");
    assert_eq!(pending.complete().expect("complete").len(), 2);
}

/// A replayed chunk is a no-op; the same index with other bytes is not.
#[test]
fn an_identical_chunk_is_idempotent_and_a_differing_one_is_a_conflict() {
    let authority = keys();
    let objects = vec![ca_object(1)];
    let manifest = manifest(&authority, &objects, 1);
    let mut pending = PendingTrustTransaction::new(manifest.clone());
    let chunk = TrustUpdateChunk {
        manifest_fingerprint: manifest.fingerprint(),
        chunk_index: 0,
        chunk_count: 1,
        first_object_index: 0,
        objects: vec![objects[0].clone()],
    };
    pending.accept(&chunk).expect("first");
    pending.accept(&chunk).expect("replay is a no-op");

    let forged = TrustUpdateChunk {
        objects: vec![ca_object(9)],
        ..chunk
    };
    assert!(matches!(
        pending.accept(&forged),
        Err(CertificateError::FingerprintMismatch("transaction object"))
    ));
}

/// A fragment may cover more of the range than the split announced. The
/// transaction is still not complete until every announced fragment has
/// arrived — the count is signed, and it says how the decision was split.
#[test]
fn one_fragment_filling_every_slot_does_not_complete_a_two_chunk_transaction() {
    let authority = keys();
    let objects = vec![ca_object(1), ca_object(2)];
    let manifest = manifest(&authority, &objects, 2);
    let mut pending = PendingTrustTransaction::new(manifest.clone());

    let whole = TrustUpdateChunk {
        manifest_fingerprint: manifest.fingerprint(),
        chunk_index: 0,
        chunk_count: 2,
        first_object_index: 0,
        objects: objects.clone(),
    };
    pending.accept(&whole).expect("oversized first fragment");
    assert!(
        !pending.is_complete(),
        "every object is present, but the announced second fragment is not"
    );
    assert!(pending.complete().is_none());

    let second = TrustUpdateChunk {
        manifest_fingerprint: manifest.fingerprint(),
        chunk_index: 1,
        chunk_count: 2,
        first_object_index: 1,
        objects: vec![objects[1].clone()],
    };
    pending.accept(&second).expect("second fragment");
    assert_eq!(pending.complete().expect("complete").len(), 2);
}

#[test]
fn a_chunk_belonging_to_another_manifest_is_refused() {
    let authority = keys();
    let objects = vec![ca_object(1)];
    let manifest = manifest(&authority, &objects, 1);
    let mut pending = PendingTrustTransaction::new(manifest);
    let stray = TrustUpdateChunk {
        manifest_fingerprint: Fingerprint::of(b"another manifest"),
        chunk_index: 0,
        chunk_count: 1,
        first_object_index: 0,
        objects: vec![objects[0].clone()],
    };
    assert!(matches!(
        pending.accept(&stray),
        Err(CertificateError::InvalidTransaction("foreign chunk"))
    ));
}

/// A manifest built against a snapshot that has since moved would decide
/// from a state that no longer exists.
#[test]
fn a_manifest_whose_base_state_moved_is_refused() {
    let authority = keys();
    let manifest = manifest(&authority, &[ca_object(1)], 1);
    assert!(matches!(
        manifest.verify(
            &authority.public,
            1,
            &domain(),
            &gateway_key(),
            &client_key(),
            &Fingerprint::of(b"moved"),
            1_100
        ),
        Err(CertificateError::InvalidTransaction("base state moved"))
    ));
}

#[test]
fn a_transaction_past_its_earliest_activation_is_refused() {
    let authority = keys();
    let mut manifest = manifest(&authority, &[ca_object(1)], 1);
    manifest.minimum_activation_at = 3_000;
    manifest.signature = sign_ml_dsa_87(&authority.private, &manifest.signing_bytes()).unwrap();

    assert!(verify_manifest(&manifest, &authority, 2_999).is_ok());
    assert!(matches!(
        verify_manifest(&manifest, &authority, 3_000),
        Err(CertificateError::InvalidTransaction(
            "minimum activation reached"
        ))
    ));
    // And past `expires_at` the transaction is simply gone.
    assert!(matches!(
        verify_manifest(&manifest, &authority, 5_000),
        Err(CertificateError::InvalidLease)
    ));
}

/// The service key coordinates an anchor object but does not authorize it:
/// the object's own `CA-PQ` signatures remain independently mandatory.
#[test]
fn the_astra_service_key_can_coordinate_an_anchor_object() {
    let authority = keys();
    let manifest = manifest(&authority, &[ca_object(1)], 1);
    assert!(verify_manifest(&manifest, &authority, 1_100).is_ok());
}

/// `CA-PQ` signs transition objects and offline documents, never a
/// personalized online envelope.
#[test]
fn the_ca_pq_manifest_authority_is_reserved_online() {
    let authority = keys();
    let mut manifest = manifest(&authority, &[ca_object(1)], 1);
    manifest.manifest_authority_kind = ManifestAuthority::CaPq;
    manifest.signature = sign_ml_dsa_87(&authority.private, &manifest.signing_bytes()).unwrap();
    assert!(matches!(
        verify_manifest(&manifest, &authority, 1_100),
        Err(CertificateError::UnauthorizedIssuer)
    ));
}

/// A prerequisite may only point backwards: a forward bit is a cycle.
#[test]
fn a_forward_prerequisite_is_refused() {
    let authority = keys();
    let objects = vec![ca_object(1), ca_object(2)];
    let mut manifest = manifest(&authority, &objects, 1);
    manifest.objects[0].prerequisite_bitmap = 0b10;
    manifest.signature = sign_ml_dsa_87(&authority.private, &manifest.signing_bytes()).unwrap();
    assert!(matches!(
        verify_manifest(&manifest, &authority, 1_100),
        Err(CertificateError::InvalidTransaction("prerequisite bitmap"))
    ));
}

#[test]
fn an_offline_document_verifies_only_under_the_locally_trusted_anchor() {
    let ca = keys();
    let mut document = OrionTrustUpdateDocument {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        objects: vec![ca_object(1)],
        ca_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
    };
    document.ca_signature =
        sign_ml_dsa_87(&ca.private, &document.signing_bytes().unwrap()).unwrap();
    assert!(document.verify(&ca.public, &domain()).is_ok());

    let stranger = keys();
    assert!(matches!(
        document.verify(&stranger.public, &domain()),
        Err(CertificateError::InvalidSignature)
    ));
    assert!(matches!(
        document.verify(&ca.public, &TrustDomainId::new([9; 16]).unwrap()),
        Err(CertificateError::TrustDomainMismatch)
    ));
}

/// At no instant may the trust store hold three anchors.
#[test]
fn an_offline_document_carrying_two_ca_transitions_is_refused() {
    let ca = keys();
    let mut document = OrionTrustUpdateDocument {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        objects: vec![ca_object(1), ca_object(2)],
        ca_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
    };
    document.ca_signature =
        sign_ml_dsa_87(&ca.private, &document.signing_bytes().unwrap()).unwrap();
    assert!(matches!(
        document.verify(&ca.public, &domain()),
        Err(CertificateError::InvalidTransaction("two CA transitions"))
    ));
}
