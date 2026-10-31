//! The gateway bootstrap Orion's operator ceremony runs, against simulated
//! keys.
//!
//! The request is the public file the gateway exports; the plan refuses what
//! is predictable before any key is asked anything, and the gesture writes in
//! one order — the relay's identity, the leaf, then whatever the domain still
//! lacks — so a failure late in it never takes back what came before.

mod support;

use std::path::{Path, PathBuf};

use aether::certificates::approval::CredentialState;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, MlDsa87PublicKey, MlDsa87Signature, TrustDomainId, WireGuardKey,
};
use aether::certificates::gateway::GatewayBootstrapRequest;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use aether::key_negotiation::{PqCertificate, PqCertificateRole};
use astra_operator::authenticator::Opened;
use astra_operator::bootstrap::{
    bootstrap_plan, bootstrap_with, path_beside, BootstrapPlan, Bootstrapped,
    MAX_BOOTSTRAP_REQUEST_BYTES,
};
use astra_operator::gestures::{NewAuthority, NewKey};
use astra_operator::vault::SlotRole;
use astra_operator::vault_gestures::{add_key_with, create_first_key, finalize_with, SetupRefusal};
use astra_operator::{credentials, handoff, signing, store};
use support::{FakeKey, PIN, RP_ID};

const NOW: u64 = 1_800_000_000;
const AUTHORITY_URL: &str = "https://astra.helios.test/";
const SERVER_NAME: &str = "gateway.helios.test";
const GATEWAY: [u8; 32] = [0x11; 32];

fn request() -> NewAuthority {
    NewAuthority {
        rp_id: RP_ID.into(),
        trust_domain_id: TrustDomainId::new([0x2A; 16]).expect("domain"),
        label: "YubiKey du bureau".into(),
        role: SlotRole::Primary,
    }
}

fn vault_path(directory: &tempfile::TempDir) -> PathBuf {
    directory.path().join("authority-vault.json")
}

/// The refusal an error carries, when it carries one.
fn refusal<T>(result: anyhow::Result<T>) -> Option<SetupRefusal> {
    result
        .err()
        .and_then(|error| error.downcast_ref::<SetupRefusal>().copied())
}

fn create(path: &Path, key: &FakeKey) -> Opened {
    create_first_key(path, &request(), AUTHORITY_URL, key, PIN, NOW).expect("the domain is created")
}

fn add(path: &Path, opening: &Opened, key: &FakeKey, label: &str) -> ([u8; 16], Opened) {
    let added = add_key_with(
        path,
        opening,
        key,
        &NewKey {
            label: label.into(),
            role: SlotRole::Recovery,
        },
        PIN,
        NOW,
    )
    .expect("the key is added");
    (added.slot_id, added.opening)
}

/// A domain with two keys and a relay that names no gateway yet.
fn fresh_domain(path: &Path, key1: &FakeKey, key2: &FakeKey) -> (Opened, Opened) {
    let first = create(path, key1);
    let (_, second) = add(path, &first, key2, "YubiKey du sac");
    (first, second)
}

/// Records a gateway on the relay, as an earlier adoption would have.
fn record_gateway(path: &Path, gateway: WireGuardKey, server_name: &str) {
    let relay_path = handoff::path_beside(path);
    let mut relay = handoff::load(&relay_path).expect("relay");
    relay.gateway_wg_public_key = Some(gateway.to_base64());
    relay.server_name = Some(server_name.into());
    handoff::save(&relay_path, &relay).expect("relay saved");
}

/// Forgets the gateway on the relay, as a hand-edited or stale relay would.
fn clear_gateway(path: &Path) {
    let relay_path = handoff::path_beside(path);
    let mut relay = handoff::load(&relay_path).expect("relay");
    relay.gateway_wg_public_key = None;
    relay.server_name = None;
    handoff::save(&relay_path, &relay).expect("relay saved");
}

/// Signs the credential document from the vault and the relay, with `states`
/// overriding the rows they name.
fn emit_document(path: &Path, opening: &Opened, states: &[(Vec<u8>, CredentialState)]) {
    let vault = store::load(path).expect("vault");
    let identity = handoff::identity_of(&relay(path)).expect("identity");
    let registry_path = credentials::path_beside(path);
    let previous = credentials::load(&registry_path).expect("previous");
    let registry = signing::sign_credential_bindings(
        &vault,
        opening,
        &identity,
        previous.as_ref(),
        states,
        NOW,
    )
    .expect("document signed");
    credentials::save(&registry_path, &registry).expect("document saved");
}

fn relay(path: &Path) -> handoff::DomainHandoff {
    handoff::load(&handoff::path_beside(path)).expect("relay")
}

/// The request the gateway exports, signed by its own key.
fn gateway_request(server_name: &str, gateway: WireGuardKey) -> GatewayBootstrapRequest {
    let (private, public) = generate_ml_dsa_87_keypair().expect("gateway key");
    GatewayBootstrapRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        gateway_wg_public_key: gateway,
        server_name: server_name.into(),
        ml_dsa_87_public_key: public,
        key_possession_proof: MlDsa87Signature::placeholder(),
    }
    .sign(&private)
    .expect("bootstrap request")
}

fn json_of(request: &GatewayBootstrapRequest) -> String {
    serde_json::to_string_pretty(request).expect("request JSON")
}

fn leaf_beside(path: &Path) -> PqCertificate {
    let bytes = std::fs::read(path_beside(path)).expect("leaf written");
    serde_json::from_slice(&bytes).expect("leaf JSON")
}

/// Whether `leaf` verifies under the domain's `CA-PQ` for this gateway.
fn verifies(path: &Path, leaf: &PqCertificate, server_name: &str, gateway: WireGuardKey) -> bool {
    let ca_pq = MlDsa87PublicKey::parse(relay(path).ca_pq_public_key.trim()).expect("anchor");
    leaf.verify(
        ca_pq.as_bytes(),
        PqCertificateRole::Gateway,
        Some(server_name),
        &gateway.to_base64(),
        NOW,
    )
    .is_ok()
}

/// What sits in the domain's folder, name and bytes, to show nothing moved.
fn folder(path: &Path) -> Vec<(String, Vec<u8>)> {
    let mut entries: Vec<(String, Vec<u8>)> = std::fs::read_dir(path.parent().expect("folder"))
        .expect("folder readable")
        .map(|entry| {
            let entry = entry.expect("entry");
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).unwrap_or_default(),
            )
        })
        .collect();
    entries.sort();
    entries
}

fn credential_of(path: &Path, slot_id: &[u8; 16]) -> Vec<u8> {
    store::load(path)
        .expect("vault")
        .slot(slot_id)
        .expect("slot")
        .credential_id()
        .expect("credential")
}

#[test]
fn a_fresh_domain_is_bootstrapped_and_finalized_in_one_gesture() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let (first, second) = fresh_domain(&path, &key1, &key2);
    let gateway = WireGuardKey::from_bytes(GATEWAY);
    let request = gateway_request(SERVER_NAME, gateway);

    let plan = bootstrap_plan(&path, &json_of(&request)).expect("a plan");
    assert_eq!(plan.request, request);
    assert!(plan.records_identity);
    assert!(plan.issues_ca_tls);
    assert!(plan.issues_credentials);

    let Bootstrapped {
        leaf_json,
        leaf_fingerprint,
        finalized,
    } = bootstrap_with(&path, &plan, &first, &second, NOW).expect("bootstrapped");

    assert_eq!(key1.assertions(), 1, "one press to create, none here");
    assert_eq!(key2.assertions(), 1, "one press to enrol, none here");
    let relay = relay(&path);
    assert_eq!(
        relay.gateway_wg_public_key.as_deref(),
        Some(gateway.to_base64().as_str())
    );
    assert_eq!(relay.server_name.as_deref(), Some(SERVER_NAME));
    let leaf = leaf_beside(&path);
    assert!(verifies(&path, &leaf, SERVER_NAME, gateway));
    assert_eq!(
        serde_json::from_str::<PqCertificate>(&leaf_json).expect("leaf JSON"),
        leaf
    );
    assert_eq!(
        leaf_fingerprint,
        aether::certificates::gateway::pq_certificate_fingerprint(&leaf)
            .expect("fingerprint")
            .to_string()
    );
    assert_eq!(leaf.not_before_unix, NOW - 300);
    assert_eq!(leaf.not_after_unix, NOW + 365 * 86_400);
    let finalized = finalized.expect("the domain was finished");
    assert!(finalized.ca_tls_pem.is_some());
    assert!(finalized.credentials_epoch.is_some());
    assert!(relay.ca_tls_certificate.is_some());
}

#[test]
fn a_file_that_is_not_a_bootstrap_request_is_refused_before_any_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let (first, _) = fresh_domain(&path, &key1, &key2);
    let before = folder(&path);

    let leaf = {
        let vault = store::load(&path).expect("vault");
        let request = gateway_request(SERVER_NAME, WireGuardKey::from_bytes(GATEWAY));
        signing::issue_gateway_bootstrap_certificate(
            &vault,
            &first,
            &MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim()).expect("anchor"),
            &signing::GatewayBootstrapDecision {
                request: &request,
                leaf_validity: (NOW - 60, NOW + 86_400),
                serial: [9; 16],
            },
        )
        .expect("a leaf")
    };
    let mut altered = gateway_request(SERVER_NAME, WireGuardKey::from_bytes(GATEWAY));
    altered.server_name = "other.helios.test".into();
    let mut oversized = json_of(&gateway_request(
        SERVER_NAME,
        WireGuardKey::from_bytes(GATEWAY),
    ));
    oversized.push_str(&" ".repeat(MAX_BOOTSTRAP_REQUEST_BYTES + 1 - oversized.len()));
    assert_eq!(oversized.len(), MAX_BOOTSTRAP_REQUEST_BYTES + 1);

    for (what, text) in [
        ("empty", String::new()),
        ("empty object", "{}".to_string()),
        ("a leaf", serde_json::to_string(&leaf).expect("leaf JSON")),
        ("altered after signing", json_of(&altered)),
        ("oversized", oversized),
    ] {
        assert_eq!(
            bootstrap_plan(&path, &text).err(),
            Some(SetupRefusal::BootstrapRequestInvalid),
            "{what}"
        );
    }
    assert_eq!(folder(&path), before);
}

#[test]
fn another_gateway_is_refused_before_any_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let (first, second) = fresh_domain(&path, &key1, &key2);
    let gateway_a = WireGuardKey::from_bytes(GATEWAY);
    let gateway_b = WireGuardKey::from_bytes([0x22; 32]);
    record_gateway(&path, gateway_a, SERVER_NAME);
    let before = folder(&path);

    for request in [
        gateway_request("other.helios.test", gateway_b),
        gateway_request("other.helios.test", gateway_a),
        gateway_request(SERVER_NAME, gateway_b),
    ] {
        assert_eq!(
            bootstrap_plan(&path, &json_of(&request)).err(),
            Some(SetupRefusal::OtherGateway),
            "{request:?}"
        );
        // The gesture checks again, whatever plan it is handed.
        let forged = BootstrapPlan {
            request,
            records_identity: true,
            issues_ca_tls: true,
            issues_credentials: true,
        };
        assert_eq!(
            refusal(bootstrap_with(&path, &forged, &first, &second, NOW)),
            Some(SetupRefusal::OtherGateway)
        );
        assert_eq!(folder(&path), before);
    }

    // The relay forgot the gateway, the document it signed did not.
    emit_document(&path, &first, &[]);
    clear_gateway(&path);
    let before = folder(&path);
    assert_eq!(
        bootstrap_plan(&path, &json_of(&gateway_request(SERVER_NAME, gateway_b))).err(),
        Some(SetupRefusal::OtherGateway)
    );
    assert_eq!(folder(&path), before);

    // The gateway the document is bound to is still this domain's.
    let plan = bootstrap_plan(&path, &json_of(&gateway_request(SERVER_NAME, gateway_a)))
        .expect("the document's gateway");
    assert!(plan.records_identity);
    assert!(plan.issues_ca_tls);
    assert!(!plan.issues_credentials);
    assert_eq!(key1.assertions(), 1);
    assert_eq!(key2.assertions(), 1);
}

/// A document in place that no longer verifies is not taken on trust, nor
/// replaced: restoring it is the operator's call.
#[test]
fn a_document_that_does_not_verify_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let (first, _) = fresh_domain(&path, &key1, &key2);
    let gateway = WireGuardKey::from_bytes(GATEWAY);
    record_gateway(&path, gateway, SERVER_NAME);
    emit_document(&path, &first, &[]);
    clear_gateway(&path);
    let registry_path = credentials::path_beside(&path);
    let mut altered = credentials::load(&registry_path)
        .expect("readable")
        .expect("present");
    altered.bindings[0].state = CredentialState::Lost;
    credentials::save(&registry_path, &altered).expect("altered document");

    assert_eq!(
        bootstrap_plan(&path, &json_of(&gateway_request(SERVER_NAME, gateway))).err(),
        Some(SetupRefusal::GatewayIdentityMissing)
    );
}

#[test]
fn fewer_than_two_usable_keys_are_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2, key3) = (FakeKey::new(1), FakeKey::new(2), FakeKey::new(3));
    let first = create(&path, &key1);
    let gateway = WireGuardKey::from_bytes(GATEWAY);
    let request = json_of(&gateway_request(SERVER_NAME, gateway));

    assert_eq!(
        bootstrap_plan(&path, &request).err(),
        Some(SetupRefusal::MinimumKeys)
    );

    let (slot2, _) = add(&path, &first, &key2, "YubiKey du sac");
    let (slot3, _) = add(&path, &first, &key3, "YubiKey perdue");
    record_gateway(&path, gateway, SERVER_NAME);
    emit_document(
        &path,
        &first,
        &[
            (credential_of(&path, &slot2), CredentialState::Revoked),
            (credential_of(&path, &slot3), CredentialState::Revoked),
        ],
    );
    let before = folder(&path);

    assert_eq!(
        bootstrap_plan(&path, &request).err(),
        Some(SetupRefusal::MinimumKeys)
    );
    assert_eq!(folder(&path), before);
}

/// A key the document revokes is no signer, even with another key that is.
#[test]
fn a_revoked_key_cannot_approve() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2, key3) = (FakeKey::new(1), FakeKey::new(2), FakeKey::new(3));
    let first = create(&path, &key1);
    add(&path, &first, &key2, "YubiKey du sac");
    let (slot3, third) = add(&path, &first, &key3, "YubiKey perdue");
    let gateway = WireGuardKey::from_bytes(GATEWAY);
    record_gateway(&path, gateway, SERVER_NAME);
    emit_document(
        &path,
        &first,
        &[(credential_of(&path, &slot3), CredentialState::Revoked)],
    );
    let plan = bootstrap_plan(&path, &json_of(&gateway_request(SERVER_NAME, gateway)))
        .expect("two keys remain");
    let before = folder(&path);

    assert_eq!(
        refusal(bootstrap_with(&path, &plan, &first, &third, NOW)),
        Some(SetupRefusal::SignerRevoked)
    );
    assert_eq!(
        refusal(bootstrap_with(&path, &plan, &third, &first, NOW)),
        Some(SetupRefusal::SignerRevoked)
    );
    assert_eq!(folder(&path), before);
}

#[test]
fn the_same_key_cannot_approve_twice() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let (first, _) = fresh_domain(&path, &key1, &key2);
    let plan = bootstrap_plan(
        &path,
        &json_of(&gateway_request(
            SERVER_NAME,
            WireGuardKey::from_bytes(GATEWAY),
        )),
    )
    .expect("a plan");

    let before = folder(&path);

    let error = bootstrap_with(&path, &plan, &first, &first, NOW).expect_err("one key twice");
    // The bootstrap's own check, not only the scope policy's.
    assert_eq!(
        error.to_string(),
        "le même credential a été présenté deux fois : l'amorçage en exige deux distincts"
    );
    assert_eq!(folder(&path), before);
    let relay = relay(&path);
    assert!(relay.gateway_wg_public_key.is_none());
    assert!(relay.server_name.is_none());
    assert!(!path_beside(&path).exists());
}

/// What the press would write must be what the manifest showed: a domain that
/// moved in between is refused before anything is written.
#[test]
fn a_domain_that_changed_since_the_plan_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let (first, second) = fresh_domain(&path, &key1, &key2);
    let gateway = WireGuardKey::from_bytes(GATEWAY);
    record_gateway(&path, gateway, SERVER_NAME);
    finalize_with(&path, &first, NOW).expect("the domain is finished");
    let plan =
        bootstrap_plan(&path, &json_of(&gateway_request(SERVER_NAME, gateway))).expect("a plan");
    assert!(!plan.issues_ca_tls);

    let relay_path = handoff::path_beside(&path);
    let mut moved = relay(&path);
    moved.ca_tls_certificate = None;
    handoff::save(&relay_path, &moved).expect("relay saved");
    let before = folder(&path);

    assert_eq!(
        refusal(bootstrap_with(&path, &plan, &first, &second, NOW)),
        Some(SetupRefusal::PlanChanged)
    );
    assert_eq!(folder(&path), before);
    assert!(!path_beside(&path).exists());
}

/// An anchor that does not parse is refused before any key, as a vault that
/// does not load is.
#[test]
fn a_vault_whose_anchor_does_not_parse_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    fresh_domain(&path, &key1, &key2);
    let mut vault: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("vault bytes")).expect("vault JSON");
    vault["ca_pq_public_key"] = serde_json::Value::String("bm9wZQ==".into());
    std::fs::write(&path, serde_json::to_vec(&vault).expect("vault JSON")).expect("vault written");
    // The vault itself still loads: it is the anchor that refuses.
    store::load(&path).expect("the vault loads");
    let before = folder(&path);

    assert_eq!(
        bootstrap_plan(
            &path,
            &json_of(&gateway_request(
                SERVER_NAME,
                WireGuardKey::from_bytes(GATEWAY)
            ))
        )
        .err(),
        Some(SetupRefusal::LocationUnavailable)
    );
    assert_eq!(folder(&path), before);
}

#[test]
fn bootstrapping_again_issues_a_leaf_and_nothing_else() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let (first, second) = fresh_domain(&path, &key1, &key2);
    let gateway = WireGuardKey::from_bytes(GATEWAY);
    let request = json_of(&gateway_request(SERVER_NAME, gateway));
    let plan = bootstrap_plan(&path, &request).expect("a plan");
    bootstrap_with(&path, &plan, &first, &second, NOW).expect("first bootstrap");
    let first_leaf = leaf_beside(&path);
    let ca_tls = relay(&path).ca_tls_certificate;
    let document = std::fs::read(credentials::path_beside(&path)).expect("document");

    let again = bootstrap_plan(&path, &request).expect("the same gateway again");
    assert!(!again.records_identity);
    assert!(!again.issues_ca_tls);
    assert!(!again.issues_credentials);
    let bootstrapped = bootstrap_with(&path, &again, &first, &second, NOW).expect("again");

    assert!(bootstrapped.finalized.is_none());
    let second_leaf = leaf_beside(&path);
    assert_ne!(second_leaf.serial, first_leaf.serial);
    assert!(verifies(&path, &second_leaf, SERVER_NAME, gateway));
    assert_eq!(relay(&path).ca_tls_certificate, ca_tls);
    assert_eq!(
        std::fs::read(credentials::path_beside(&path)).expect("document"),
        document
    );
}

/// The leaf is written before the domain is finished: a finalization that
/// fails leaves the leaf in place, and « Finaliser le domaine » resumes.
///
/// The document's write is made to fail by a symbolic link where it goes: the
/// document reads as absent through a dangling link, and the private writer
/// refuses to replace a link. Unix only, where a test may create one.
#[cfg(unix)]
#[test]
fn a_failed_finalization_keeps_the_leaf() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    let (first, second) = fresh_domain(&path, &key1, &key2);
    let gateway = WireGuardKey::from_bytes(GATEWAY);
    std::os::unix::fs::symlink(
        directory.path().join("nowhere.json"),
        credentials::path_beside(&path),
    )
    .expect("link in the document's place");
    let plan =
        bootstrap_plan(&path, &json_of(&gateway_request(SERVER_NAME, gateway))).expect("a plan");
    assert!(plan.issues_credentials);

    bootstrap_with(&path, &plan, &first, &second, NOW).expect_err("the document cannot be written");

    let leaf = leaf_beside(&path);
    assert!(verifies(&path, &leaf, SERVER_NAME, gateway));
    assert_eq!(
        relay(&path).gateway_wg_public_key.as_deref(),
        Some(gateway.to_base64().as_str())
    );
}
