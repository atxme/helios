//! Seeding the bounded trust state from the enrolment document and the sealed
//! identity: what the active generation is read from, which operator
//! credentials travel with it, and which profiles are refused or named.

use aether::certificates::encoding::{DerCertificate, WireGuardKey};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::certificate_renewal::{open_or_seed, RenewalError};
use crate::test_domain::*;

/// A profile plus a sealed identity is enough to seed the bounded state.
///
/// Nothing is fetched and nothing is invented: the anchors come from the
/// document the operator signed for, and the active generation's own
/// fingerprints come from the certificates in the protected store.
#[test]
fn a_profile_and_its_identity_seed_the_trust_store() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let settings = settings(&domain);
    let bundle = bundle(&domain);
    let path = directory.path().join("trust.json");

    let store = open_or_seed(&path, &settings, &bundle).expect("seeded");
    let state = store.state();
    assert_eq!(state.trust_domain_id, domain_id());
    assert_eq!(state.client_wg_public_key, client_key());
    assert_eq!(state.gateway.gateway_wg_public_key, gateway_key());
    assert_eq!(state.gateway.server_name, SERVER_NAME);
    assert_eq!(state.certificates.active.generation, 4);
    assert_eq!(
        state.certificates.active.pq_certificate_fingerprint,
        aether::certificates::gateway::pq_certificate_fingerprint(&domain.active_client_leaf)
            .expect("fingerprint"),
        "the active generation is the certificate the store actually holds"
    );
    assert_eq!(
        state.client_tls_ca.active_client_tls_ca_certificate,
        domain.tls_ca_der
    );
    assert!(path.exists(), "seeding writes, so a restart resumes");
}

/// Once the file exists it is the record: it may hold a staged generation
/// or a revocation the static profile never heard of.
#[test]
fn an_existing_store_is_not_reseeded_from_the_profile() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut settings = settings(&domain);
    let bundle = bundle(&domain);
    let path = directory.path().join("trust.json");
    open_or_seed(&path, &settings, &bundle).expect("seeded");

    // The operator re-emits a document claiming a generation that has
    // already been superseded locally.
    settings.trust.as_mut().expect("trust").client_generation = 1;
    let store = open_or_seed(&path, &settings, &bundle).expect("reopened");
    assert_eq!(
        store.state().certificates.active.generation,
        4,
        "the store is the record, not the document"
    );
}

/// Conversion into a numbered generation is a triple correspondence
/// (spec §14.1): the chain, the fingerprints and the local keys. Each of
/// the three is read from the material the machine already holds — the
/// sealed bundle and the operator's trust block — and never from the
/// document alone, which is why they are asserted together here.
#[test]
fn the_seeded_generation_matches_the_chain_the_fingerprints_and_the_local_key() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let settings = settings(&domain);
    let bundle = bundle(&domain);
    let path = directory.path().join("trust.json");

    let store = open_or_seed(&path, &settings, &bundle).expect("seeded");
    let state = store.state();
    let active = &state.certificates.active;
    let trust = settings.trust.as_ref().expect("trust");

    // The chain: the leaf the bundle carries, not a fingerprint the
    // profile asserts about it.
    let chain_leaf = DerCertificate::new(
        STANDARD
            .decode(bundle.certificate_chain.first().expect("chain").trim())
            .expect("chain leaf base64"),
    )
    .expect("chain leaf der");
    assert_eq!(active.tls_certificate_fingerprint, chain_leaf.fingerprint());

    // The fingerprints: the anchor the operator pinned, and the PQ leaf
    // the protected store holds.
    assert_eq!(
        active.tls_ca_certificate_fingerprint,
        domain.tls_ca_der.fingerprint()
    );
    assert_eq!(
        active.pq_certificate_fingerprint,
        aether::certificates::gateway::pq_certificate_fingerprint(&domain.active_client_leaf)
            .expect("pq fingerprint")
    );
    assert_eq!(active.generation, trust.client_generation);
    assert_eq!(active.ca_tls_epoch, trust.ca_tls_epoch);
    assert_eq!(active.not_before, domain.active_client_leaf.not_before_unix);
    assert_eq!(active.not_after, domain.active_client_leaf.not_after_unix);

    // The local key: read off the certificate the gateway admitted, so a
    // profile naming another key cannot seed a state around it.
    assert_eq!(
        state.client_wg_public_key,
        WireGuardKey::parse(&domain.active_client_leaf.wireguard_public_key).expect("key")
    );
}

/// A COSE ES256 public key, as an authenticator publishes one.
///
/// Built here rather than faked: the binding's own verification parses
/// this field, so a placeholder would make the test pass on a shape the
/// real exchange refuses.
fn cose_es256_key() -> Vec<u8> {
    let mut key = vec![
        0xA5, // map(5)
        0x01, 0x02, // 1 (kty)  : 2   — EC2
        0x03, 0x26, // 3 (alg)  : -7  — ES256
        0x20, 0x01, // -1 (crv) : 1   — P-256
        0x21, 0x58, 0x20, // -2 (x) : bstr(32)
    ];
    key.extend_from_slice(&[3u8; 32]);
    key.extend_from_slice(&[0x22, 0x58, 0x20]); // -3 (y) : bstr(32)
    key.extend_from_slice(&[5u8; 32]);
    key
}

/// A binding the domain's `CA-PQ` signed, carried by the enrolment.
fn signed_binding(
    domain: &Domain,
    credential_id: Vec<u8>,
) -> aether::certificates::approval::AstraCredentialBinding {
    aether::certificates::approval::AstraCredentialBinding {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        credential_id,
        credential_public_key: cose_es256_key(),
        aaguid: [0; 16],
        trust_domain_id: crate::test_domain::domain_id(),
        gateway_wg_public_key: crate::test_domain::gateway_key(),
        state: aether::certificates::approval::CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: 1,
        ca_epoch: 1,
        created_at: NOW,
        ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&domain.ca_pq_private)
    .expect("signed under CA-PQ")
}

/// Recovering an expired identity begins by naming the credential that
/// will approve it, and a client with no tunnel cannot go and ask. The
/// enrolment therefore carries the list, and the seed adopts it.
#[test]
fn the_operator_credentials_travel_with_the_enrolment() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut settings = settings(&domain);
    settings
        .trust
        .as_mut()
        .expect("trust")
        .astra_credential_bindings = vec![signed_binding(&domain, vec![0xAB, 0xCD])];
    let bundle = bundle(&domain);
    let path = directory.path().join("trust.json");
    let store = open_or_seed(&path, &settings, &bundle).expect("seeded");
    let bindings = &store.state().astra.credential_bindings;
    assert_eq!(bindings.len(), 1, "the credential the enrolment carried");
    assert!(
        bindings
            .values()
            .any(|binding| binding.state
                == aether::certificates::approval::CredentialState::Active),
        "an active row is what a recovery may name"
    );
}

/// The document that carried the bindings proves nothing by itself: each
/// one is verified under the anchor of this profile, and a row signed by
/// another authority is refused rather than adopted.
#[test]
fn a_credential_binding_signed_by_another_anchor_is_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let stranger = crate::test_domain::domain();
    let mut settings = settings(&domain);
    settings
        .trust
        .as_mut()
        .expect("trust")
        .astra_credential_bindings = vec![signed_binding(&stranger, vec![0xAB, 0xCD])];
    let bundle = bundle(&domain);
    let path = directory.path().join("trust.json");
    assert!(
        open_or_seed(&path, &settings, &bundle).is_err(),
        "a row the domain never signed is not adopted"
    );
    assert!(!path.exists(), "a refused seed writes nothing");
}

/// A machine left off past its own expiry is exactly what §7.5 recovers,
/// and it reaches that path through a store it does not have yet. Seeding
/// therefore describes the expired leaf instead of refusing it — the
/// refusal that used to live here made the recovery unreachable.
#[test]
fn an_expired_active_leaf_is_seeded_so_the_recovery_can_read_it() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let settings = settings(&domain);
    let bundle = bundle(&domain);
    let path = directory.path().join("trust.json");
    let expired_at = NOW + 20 * 86_400;
    let store = open_or_seed(&path, &settings, &bundle).expect("seeded");
    assert!(
        path.exists(),
        "the store the recovery opens must be written"
    );
    assert!(
        store.state().certificates.active.not_after <= expired_at,
        "the seeded state describes the expired leaf rather than hiding it"
    );
}

/// A profile enrolled before §19 carries no trust block, and the refusal
/// is that — not a store that could not be written.
#[test]
fn a_profile_without_trust_material_is_named() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut settings = settings(&domain);
    settings.trust = None;
    assert!(matches!(
        open_or_seed(
            &directory.path().join("trust.json"),
            &settings,
            &bundle(&domain)
        ),
        Err(RenewalError::TrustMaterialMissing)
    ));
}

/// The gateway identity epochs are read from the enrolment block.
///
/// They cannot be learned any other way. An identity transition only moves a
/// store from the decision it already holds to the next one, so a store seeded
/// at `0` against a registry that starts at `1` (§13.1) is behind on the
/// trust-update comparison for the life of the profile, and the gateway
/// answers `503` to every poll it makes. The values here are deliberately not
/// `1`: a seed that read a constant would pass against the fixture's own.
#[test]
fn the_gateway_identity_epochs_come_from_the_enrolment_block() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut settings = settings(&domain);
    let bundle = bundle(&domain);
    {
        let trust = settings.trust.as_mut().expect("trust block");
        trust.active_gateway_identity_epoch = 3;
        trust.gateway_decision_epoch = 4;
    }
    let path = directory.path().join("trust.json");

    let store = open_or_seed(&path, &settings, &bundle).expect("seeded");
    let gateway = &store.state().gateway;
    assert_eq!(gateway.active_gateway_identity_epoch, 3);
    assert_eq!(gateway.gateway_decision_epoch, 4);
}

#[test]
fn the_verified_operator_registry_survives_a_reload_and_has_public_inventory() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut settings = settings(&domain);
    settings
        .trust
        .as_mut()
        .expect("trust")
        .astra_credential_bindings = vec![signed_binding(&domain, vec![0xAB, 0xCD])];
    let path = directory.path().join("trust.json");
    let store = open_or_seed(&path, &settings, &bundle(&domain)).expect("seed");
    assert!(store.state().credential_registry.is_some());
    let reloaded = crate::certificates::TrustStore::load(&path)
        .expect("load")
        .expect("exists");
    let inventory =
        crate::certificate_inventory::operator_inventory(reloaded.state()).expect("verified");
    assert_eq!(
        inventory.detail,
        crate::certificate_inventory::OperatorCredentialDetail::Verified
    );
    assert_eq!(inventory.credentials.len(), 1);
    assert_eq!(
        inventory.credentials[0].state,
        aether::certificates::approval::CredentialState::Active
    );
    let encoded = serde_json::to_string(&inventory).expect("JSON");
    assert!(!encoded.contains("credential_public_key"));
    assert!(!encoded.contains("credential_id"));
    assert!(!encoded.contains("ca_pq_signature"));
}

#[test]
fn the_previous_trust_shape_migrates_without_losing_security_state() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut settings = settings(&domain);
    settings
        .trust
        .as_mut()
        .expect("trust")
        .astra_credential_bindings = vec![signed_binding(&domain, vec![1, 2])];
    let path = directory.path().join("trust.json");
    let original = open_or_seed(&path, &settings, &bundle(&domain)).expect("seed");
    let mut document = serde_json::to_value(original.state()).expect("JSON");
    document
        .as_object_mut()
        .expect("object")
        .remove("credential_registry");
    std::fs::write(&path, serde_json::to_vec(&document).expect("JSON")).expect("write fixture");
    let migrated = open_or_seed(&path, &settings, &bundle(&domain)).expect("migration");
    assert_eq!(migrated.state(), original.state());
    assert_eq!(
        migrated.base_state_fingerprint().expect("fingerprint"),
        original.base_state_fingerprint().expect("fingerprint")
    );
}

#[test]
fn duplicated_enrolment_credentials_are_refused_before_persistence() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut settings = settings(&domain);
    let binding = signed_binding(&domain, vec![1, 2]);
    settings
        .trust
        .as_mut()
        .expect("trust")
        .astra_credential_bindings = vec![binding.clone(), binding];
    let path = directory.path().join("trust.json");
    assert!(open_or_seed(&path, &settings, &bundle(&domain)).is_err());
    assert!(!path.exists());
}

#[test]
fn a_later_registry_cannot_hide_a_previously_retained_credential() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut settings = settings(&domain);
    settings
        .trust
        .as_mut()
        .expect("trust")
        .astra_credential_bindings = vec![
        signed_binding(&domain, vec![1]),
        signed_binding(&domain, vec![2]),
    ];
    let path = directory.path().join("trust.json");
    let mut store = open_or_seed(&path, &settings, &bundle(&domain)).expect("seed");
    let before = store.state().clone();
    let mut omitted = before.credential_registry.clone().expect("registry");
    omitted.credential_registry_epoch += 1;
    omitted.bindings.truncate(1);
    omitted.bindings[0].credential_registry_epoch = omitted.credential_registry_epoch;
    omitted.bindings[0] = omitted.bindings[0]
        .clone()
        .sign(&domain.ca_pq_private)
        .expect("sign");
    assert!(store.install_credential_registry(&omitted).is_err());
    assert_eq!(store.state(), &before);
}

#[test]
fn registry_installation_refuses_rollback_forgery_and_same_epoch_conflicts() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut settings = settings(&domain);
    settings
        .trust
        .as_mut()
        .expect("trust")
        .astra_credential_bindings = vec![signed_binding(&domain, vec![1, 2])];
    let path = directory.path().join("trust.json");
    let mut store = open_or_seed(&path, &settings, &bundle(&domain)).expect("seed");
    let before = std::fs::read(&path).expect("read");
    let original = store.state().credential_registry.clone().expect("registry");
    assert_eq!(
        store
            .install_credential_registry(&original)
            .expect("idempotent"),
        aether::certificates::state::InstallOutcome::AlreadyPresent
    );
    let mut rollback = original.clone();
    rollback.credential_registry_epoch = 0;
    assert!(store.install_credential_registry(&rollback).is_err());
    let mut forged = original.clone();
    forged.bindings[0].state = aether::certificates::approval::CredentialState::Revoked;
    assert!(store.install_credential_registry(&forged).is_err());
    let mut conflict = original.clone();
    conflict.bindings[0].created_at += 1;
    conflict.bindings[0] = conflict.bindings[0]
        .clone()
        .sign(&domain.ca_pq_private)
        .expect("sign");
    assert!(store.install_credential_registry(&conflict).is_err());
    assert_eq!(store.state().credential_registry.as_ref(), Some(&original));
    assert_eq!(std::fs::read(&path).expect("read"), before);
}

#[test]
fn a_registry_write_failure_keeps_the_live_snapshot_unchanged() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let settings = settings(&domain);
    let path = directory.path().join("trust.json");
    let seeded = open_or_seed(&path, &settings, &bundle(&domain)).expect("seed");
    let mut store = crate::certificates::TrustStore::new(
        directory.path().to_path_buf(),
        seeded.state().clone(),
    );
    let before = store.state().clone();
    let registry = aether::certificates::approval::CredentialRegistry {
        trust_domain_id: before.trust_domain_id,
        gateway_wg_public_key: before.gateway.gateway_wg_public_key,
        ca_epoch: before.gateway.ca_epoch,
        credential_registry_epoch: 1,
        bindings: vec![signed_binding(&domain, vec![1, 2])],
    };
    assert!(store.install_credential_registry(&registry).is_err());
    assert_eq!(store.state(), &before);
}

#[test]
fn a_later_signed_registry_cannot_restore_a_revoked_credential() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut settings = settings(&domain);
    settings
        .trust
        .as_mut()
        .expect("trust")
        .astra_credential_bindings = vec![signed_binding(&domain, vec![1, 2])];
    let path = directory.path().join("trust.json");
    let mut store = open_or_seed(&path, &settings, &bundle(&domain)).expect("seed");
    let mut revoked = store.state().credential_registry.clone().expect("registry");
    revoked.credential_registry_epoch = 2;
    revoked.bindings[0].credential_registry_epoch = 2;
    revoked.bindings[0].credential_epoch = 2;
    revoked.bindings[0].state = aether::certificates::approval::CredentialState::Revoked;
    revoked.bindings[0] = revoked.bindings[0]
        .clone()
        .sign(&domain.ca_pq_private)
        .expect("sign");
    store.install_credential_registry(&revoked).expect("revoke");
    let before = store.state().clone();
    let disk = std::fs::read(&path).expect("read");
    let mut revived = revoked;
    revived.credential_registry_epoch = 3;
    revived.bindings[0].credential_registry_epoch = 3;
    revived.bindings[0].credential_epoch = 3;
    revived.bindings[0].state = aether::certificates::approval::CredentialState::Active;
    revived.bindings[0] = revived.bindings[0]
        .clone()
        .sign(&domain.ca_pq_private)
        .expect("sign");
    assert!(store.install_credential_registry(&revived).is_err());
    assert_eq!(store.state(), &before);
    assert_eq!(std::fs::read(&path).expect("read"), disk);
}

#[test]
fn oversized_registries_and_forged_inventory_are_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut settings = settings(&domain);
    settings
        .trust
        .as_mut()
        .expect("trust")
        .astra_credential_bindings = vec![signed_binding(&domain, vec![1, 2])];
    let path = directory.path().join("trust.json");
    let mut store = open_or_seed(&path, &settings, &bundle(&domain)).expect("seed");
    let before = store.state().clone();
    let mut oversized = before.credential_registry.clone().expect("registry");
    oversized.bindings = vec![
        oversized.bindings[0].clone();
        aether::certificates::approval::MAX_CREDENTIAL_BINDINGS + 1
    ];
    assert!(store.install_credential_registry(&oversized).is_err());
    assert_eq!(store.state(), &before);
    let mut forged = before;
    forged
        .credential_registry
        .as_mut()
        .expect("registry")
        .bindings[0]
        .state = aether::certificates::approval::CredentialState::Lost;
    assert!(crate::certificate_inventory::operator_inventory(&forged).is_err());
}

#[test]
fn inventory_refuses_a_truncated_snapshot_even_when_remaining_rows_verify() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let mut settings = settings(&domain);
    settings
        .trust
        .as_mut()
        .expect("trust")
        .astra_credential_bindings = vec![
        signed_binding(&domain, vec![1]),
        signed_binding(&domain, vec![2]),
    ];
    let path = directory.path().join("trust.json");
    let store = open_or_seed(&path, &settings, &bundle(&domain)).expect("seed");
    let mut state = store.state().clone();
    state
        .credential_registry
        .as_mut()
        .expect("registry")
        .bindings
        .truncate(1);
    assert!(crate::certificate_inventory::operator_inventory(&state).is_err());
}

#[test]
fn an_oversized_trust_file_is_refused_before_deserialization() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("trust.json");
    std::fs::File::create(&path)
        .expect("file")
        .set_len(crate::certificates::MAX_TRUST_STORE_BYTES + 1)
        .expect("sparse file");
    assert!(matches!(crate::certificates::TrustStore::load(&path),
        Err(crate::certificates::TrustError::Corrupt(reason)) if reason.contains("size bound")));
}
