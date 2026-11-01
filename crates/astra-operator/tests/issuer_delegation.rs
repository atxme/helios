//! The issuer delegation of §9.5, planned and signed against simulated keys.
//!
//! Only the CTAP2 boundary is simulated (see [`support::FakeKey`]): the vault,
//! the anchors, the X.509 issuance and the campaign coverage are the
//! production code. What these tests pin is the order §6.3 asks for: every
//! refusal a file, a campaign or the relay makes predictable is reached before
//! any key is asked anything.

mod support;

use std::path::{Path, PathBuf};

use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87PublicKey, TrustDomainId, WireGuardKey,
};
use aether::certificates::operator_session::CampaignManifest;
use aether::certificates::status::{
    AstraRotationCampaign, CampaignScope, CampaignTarget, CertificateKind,
};
use aether::certificates::x509::certification_request_public_key_info;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};
use astra_operator::authenticator::{
    Approval, ApprovedOpening, Authenticator, AuthenticatorError, CredentialSubject, Opened,
    Registration,
};
use astra_operator::gestures::{self, NewAuthority, NewKey};
use astra_operator::operations::issuer::{
    self, IssuerRefusal, DELEGATION_DAYS, LEAF_DAYS, MAX_DELEGATION_REQUEST_BYTES,
};
use astra_operator::signing::IssuerDelegationRequest;
use astra_operator::vault::SlotRole;
use astra_operator::vault_gestures::{add_key_with, create_first_key, finalize_with};
use astra_operator::{handoff, store};
use base64::Engine as _;
use support::{FakeKey, PIN, RP_ID};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const AUTHORITY_URL: &str = "https://astra.helios.test/";
const SERVER_NAME: &str = "gateway.helios.test";

fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([0x11; 32])
}

fn domain() -> TrustDomainId {
    TrustDomainId::new([0x2A; 16]).expect("domain")
}

/// A domain with its two keys, the gateway recorded on the relay, and the
/// origin the creation pins. Returns the first key's opening.
fn domain_with_two_keys(path: &Path, key1: &FakeKey, key2: &FakeKey) -> Opened {
    let first = create_first_key(
        path,
        &NewAuthority {
            rp_id: RP_ID.into(),
            trust_domain_id: domain(),
            label: "YubiKey du bureau".into(),
            role: SlotRole::Primary,
        },
        AUTHORITY_URL,
        key1,
        PIN,
        NOW,
    )
    .expect("the domain is created");
    add_key_with(
        path,
        &first,
        key2,
        &NewKey {
            label: "YubiKey du sac".into(),
            role: SlotRole::Recovery,
        },
        PIN,
        NOW,
    )
    .expect("the second key is added");
    let relay_path = handoff::path_beside(path);
    let mut relay = handoff::load(&relay_path).expect("relay");
    relay.gateway_wg_public_key = Some(gateway_key().to_base64());
    relay.server_name = Some(SERVER_NAME.into());
    handoff::save(&relay_path, &relay).expect("relay saved");
    first
}

/// The same domain, finished: `CA-TLS` on the relay, credential document
/// beside the vault.
fn finished_domain(path: &Path, key1: &FakeKey, key2: &FakeKey) -> Opened {
    let first = domain_with_two_keys(path, key1, key2);
    finalize_with(path, &first, NOW).expect("the domain is finished");
    first
}

fn vault_path(directory: &tempfile::TempDir) -> PathBuf {
    directory.path().join("authority-vault.json")
}

fn set_origin(path: &Path, origin: Option<&str>) {
    let relay_path = handoff::path_beside(path);
    let mut relay = handoff::load(&relay_path).expect("relay");
    relay.astra_authority_url = origin.map(str::to_string);
    handoff::save(&relay_path, &relay).expect("relay saved");
}

/// What `astra issuer request` writes: fresh issuer keys, their public halves.
struct Delegation {
    request: IssuerDelegationRequest,
    pq_fingerprint: Fingerprint,
    spki_fingerprint: Fingerprint,
}

fn delegation(epoch: u64) -> Delegation {
    let (_, issuer_public) = generate_ml_dsa_87_keypair().expect("issuer keypair");
    let issuer_tls_key = rcgen::KeyPair::generate().expect("issuer TLS key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("astra delegated issuer {epoch}"),
    );
    let csr = params
        .serialize_request(&issuer_tls_key)
        .expect("PKCS#10")
        .der()
        .to_vec();
    let spki = certification_request_public_key_info(
        &aether::certificates::encoding::DerCertificate::new(csr.clone()).expect("der"),
    )
    .expect("csr spki");
    Delegation {
        request: IssuerDelegationRequest {
            trust_domain_id: domain().to_hex(),
            issuer_epoch: epoch,
            pq_issuer_public_key: issuer_public.to_base64(),
            tls_intermediate_csr: base64::engine::general_purpose::STANDARD.encode(&csr),
        },
        pq_fingerprint: Fingerprint::of(issuer_public.as_bytes()),
        spki_fingerprint: Fingerprint::of(&spki),
    }
}

fn json(request: &IssuerDelegationRequest) -> String {
    serde_json::to_string_pretty(request).expect("request")
}

/// The campaign `astra issuer request --reason --requested-by` opens for one
/// delegation request: the epoch and both public halves, pinned.
fn campaign_for(delegation: &Delegation, scope: CampaignScope) -> AstraRotationCampaign {
    AstraRotationCampaign {
        format_version: CERTIFICATE_FORMAT_VERSION,
        campaign_id: Id16::new([9; 16]).expect("id"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        created_at: NOW,
        expires_at: NOW + 300,
        scope,
        targets: vec![CampaignTarget {
            certificate_kind: CertificateKind::AstraIssuer,
            identity_key: gateway_key(),
            epoch: delegation.request.issuer_epoch,
            generation: delegation.request.issuer_epoch,
            active_tls_certificate_fingerprint: delegation.spki_fingerprint,
            active_pq_certificate_fingerprint: delegation.pq_fingerprint,
        }],
        reason: "délégation trimestrielle".into(),
        requested_by: "operator".into(),
        policy_fingerprint: aether::certificates::approval::AstraIssuancePolicy::standard(
            domain(),
            gateway_key(),
            SERVER_NAME.into(),
        )
        .fingerprint()
        .expect("policy"),
        required_credentials: scope.required_credentials(),
    }
}

#[test]
fn an_offline_delegation_is_planned_and_signed() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    finished_domain(&path, &key1, &key2);
    set_origin(&path, None);
    let delegation = delegation(1);
    let presses = key1.assertions();

    let plan = issuer::plan(&path, &json(&delegation.request), None, NOW).expect("planned");
    assert_eq!(key1.assertions(), presses, "planning asks no key anything");

    let manifest = &plan.manifest;
    assert_eq!(manifest.campaign, None);
    assert_eq!(manifest.trust_domain_id, domain());
    assert_eq!(manifest.issuer_epoch, 1);
    assert_eq!(manifest.not_before, NOW);
    assert_eq!(manifest.not_after - manifest.not_before, 30 * DAY);
    assert_eq!(DELEGATION_DAYS, 30);
    assert_eq!(manifest.maximum_leaf_lifetime_secs, LEAF_DAYS * DAY);
    assert_eq!(LEAF_DAYS, 90);
    assert_eq!(
        manifest.allowed_usages,
        vec!["admitted_client_leaf_renewal"]
    );
    assert_eq!(
        manifest.pq_public_key_fingerprint,
        delegation.pq_fingerprint
    );
    assert_eq!(
        manifest.tls_public_key_info_fingerprint,
        delegation.spki_fingerprint
    );
    assert_eq!(plan.request, delegation.request);
    assert_eq!(plan.bounds.not_before, manifest.not_before);
    assert_eq!(plan.bounds.not_after, manifest.not_after);
    assert_eq!(
        plan.bounds.maximum_leaf_lifetime_secs,
        manifest.maximum_leaf_lifetime_secs
    );

    let vault = store::load(&path).expect("vault");
    let opened = gestures::open_with_authorized_key(&key1, &vault, PIN).expect("opens");
    let authorization = issuer::sign_offline(&path, &plan, &opened, NOW).expect("signed");

    // What was shown is what was signed.
    assert_eq!(authorization.issuer_epoch, manifest.issuer_epoch);
    assert_eq!(authorization.not_before, manifest.not_before);
    assert_eq!(authorization.not_after, manifest.not_after);
    assert_eq!(
        authorization.maximum_leaf_lifetime_secs,
        manifest.maximum_leaf_lifetime_secs
    );
    assert_eq!(
        authorization.policy_fingerprint,
        manifest.policy_fingerprint
    );
    assert_eq!(
        Fingerprint::of(authorization.pq_issuer_public_key.as_bytes()),
        manifest.pq_public_key_fingerprint
    );

    let relay = handoff::load(&handoff::path_beside(&path)).expect("relay");
    let identity = handoff::identity_of(&relay).expect("identity");
    authorization
        .verify(
            &MlDsa87PublicKey::parse(&relay.ca_pq_public_key).expect("anchor"),
            &identity.trust_domain_id,
            identity.ca_epoch,
            identity.ca_tls_epoch,
            &identity.gateway_wg_public_key,
            &identity.server_name,
            NOW,
        )
        .expect("the delegation verifies under the relay's CA-PQ");
}

#[test]
fn a_file_that_is_not_a_delegation_request_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    finished_domain(&path, &key1, &key2);
    set_origin(&path, None);

    let (_, leaf_key) = generate_ml_dsa_87_keypair().expect("leaf key");
    let leaf = serde_json::to_string(&PqCertificate {
        version: PQ_CERTIFICATE_VERSION,
        serial: [9; 16],
        subject: SERVER_NAME.into(),
        issuer: "helios-ca-pq".into(),
        role: PqCertificateRole::Gateway,
        wireguard_public_key: gateway_key().to_base64(),
        ml_dsa_87_public_key: leaf_key.to_base64(),
        not_before_unix: NOW,
        not_after_unix: NOW + DAY,
        ml_dsa_87_signature: String::new(),
    })
    .expect("leaf");

    // A valid request, padded past the bound: the size is refused before the
    // contents are read.
    let valid = json(&delegation(1).request);
    let oversized = format!(
        "{valid}{}",
        " ".repeat(MAX_DELEGATION_REQUEST_BYTES + 1 - valid.len())
    );
    assert_eq!(oversized.len(), MAX_DELEGATION_REQUEST_BYTES + 1);

    let mut bad_csr = delegation(1).request;
    bad_csr.tls_intermediate_csr = base64::engine::general_purpose::STANDARD.encode(b"no CSR");
    let mut bad_pq = delegation(1).request;
    bad_pq.pq_issuer_public_key = "bm9wZQ==".into();

    for (what, text) in [
        ("empty", String::new()),
        ("empty object", "{}".to_string()),
        ("a leaf", leaf),
        ("oversized", oversized),
        ("undecodable CSR", json(&bad_csr)),
        ("unreadable PQ key", json(&bad_pq)),
    ] {
        assert_eq!(
            issuer::plan(&path, &text, None, NOW).err(),
            Some(IssuerRefusal::RequestInvalid),
            "{what}"
        );
    }
    assert!(issuer::plan(&path, &valid, None, NOW).is_ok());
}

#[test]
fn a_substituted_request_is_refused_before_any_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    finished_domain(&path, &key1, &key2);
    let named = delegation(1);
    let campaign = campaign_for(&named, CampaignScope::IssuerDelegation);

    let plan = issuer::plan(&path, &json(&named.request), Some(&campaign), NOW)
        .expect("the request the campaign names");
    assert_eq!(
        plan.manifest.campaign,
        Some(CampaignManifest {
            campaign: Box::new(campaign.clone()),
            fingerprint: campaign.fingerprint(),
        })
    );

    // Another PQ key, the same CSR.
    let mut other_key = named.request.clone();
    other_key.pq_issuer_public_key = delegation(1).request.pq_issuer_public_key;
    // Another TLS key, the same PQ key.
    let mut other_csr = named.request.clone();
    other_csr.tls_intermediate_csr = delegation(1).request.tls_intermediate_csr;
    // Another epoch, the same keys.
    let mut other_epoch = named.request.clone();
    other_epoch.issuer_epoch = 2;
    // Another domain, the same material.
    let mut other_domain = named.request.clone();
    other_domain.trust_domain_id = TrustDomainId::new([0x33; 16]).expect("domain").to_hex();

    let presses = (key1.assertions(), key2.assertions());
    for (what, request) in [
        ("PQ key", other_key),
        ("CSR", other_csr),
        ("epoch", other_epoch),
        ("domain", other_domain),
    ] {
        assert_eq!(
            issuer::plan(&path, &json(&request), Some(&campaign), NOW).err(),
            Some(IssuerRefusal::RequestMismatch),
            "{what}"
        );
    }
    assert_eq!((key1.assertions(), key2.assertions()), presses);
}

#[test]
fn a_campaign_of_another_family_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    finished_domain(&path, &key1, &key2);
    let named = delegation(1);
    let campaign = campaign_for(&named, CampaignScope::OrionProfile);

    assert_eq!(
        issuer::plan(&path, &json(&named.request), Some(&campaign), NOW).err(),
        Some(IssuerRefusal::NotADelegation)
    );
}

#[test]
fn an_offline_delegation_is_refused_when_the_relay_names_an_origin() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    finished_domain(&path, &key1, &key2);
    let request = delegation(1).request;

    assert_eq!(
        issuer::plan(&path, &json(&request), None, NOW).err(),
        Some(IssuerRefusal::OriginRecorded)
    );

    // The gesture settles it again: an origin recorded after the plan was
    // shown refuses the signature, whatever the interface displayed.
    set_origin(&path, None);
    let plan = issuer::plan(&path, &json(&request), None, NOW).expect("planned");
    set_origin(&path, Some(AUTHORITY_URL));
    let vault = store::load(&path).expect("vault");
    let opened = gestures::open_with_authorized_key(&key1, &vault, PIN).expect("opens");
    let error = issuer::sign_offline(&path, &plan, &opened, NOW).expect_err("refused");
    assert_eq!(
        error.downcast_ref::<IssuerRefusal>(),
        Some(&IssuerRefusal::OriginRecorded)
    );
}

#[test]
fn a_domain_without_ca_tls_cannot_delegate() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    domain_with_two_keys(&path, &key1, &key2);
    set_origin(&path, None);

    assert_eq!(
        issuer::plan(&path, &json(&delegation(1).request), None, NOW).err(),
        Some(IssuerRefusal::CaTlsMissing)
    );
}

/// A token that ignores the allow-list it is handed and answers for a
/// credential of its own choosing.
struct IgnoresAllowList(FakeKey);

impl Authenticator for IgnoresAllowList {
    fn register(
        &self,
        rp_id: &str,
        subject: &CredentialSubject,
        exclude: &[Vec<u8>],
        pin: &str,
    ) -> Result<Registration, AuthenticatorError> {
        self.0.register(rp_id, subject, exclude, pin)
    }

    fn derive(
        &self,
        rp_id: &str,
        _credentials: &[Vec<u8>],
        salt: &[u8; 32],
        pin: &str,
    ) -> Result<Opened, AuthenticatorError> {
        self.0.derive(rp_id, &self.0.credential_ids(), salt, pin)
    }

    fn approve(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        client_data_json: &[u8],
        pin: &str,
    ) -> Result<Approval, AuthenticatorError> {
        self.0.approve(rp_id, credentials, client_data_json, pin)
    }

    fn approve_and_derive(
        &self,
        rp_id: &str,
        credentials: &[Vec<u8>],
        client_data_json: &[u8],
        salt: &[u8; 32],
        pin: &str,
    ) -> Result<ApprovedOpening, AuthenticatorError> {
        self.0
            .approve_and_derive(rp_id, credentials, client_data_json, salt, pin)
    }
}

#[test]
fn only_the_approving_credential_can_open_the_vault() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&directory);
    let (key1, key2) = (FakeKey::new(1), FakeKey::new(2));
    domain_with_two_keys(&path, &key1, &key2);
    let vault = store::load(&path).expect("vault");
    let approving = key1.credential_ids().remove(0);

    assert!(
        gestures::open_with_credential(&key2, &vault, &approving, PIN).is_err(),
        "the other key of the vault holds nothing it may answer for"
    );
    assert!(
        gestures::open_with_credential(&IgnoresAllowList(key2), &vault, &approving, PIN).is_err(),
        "a key answering for a credential it was not offered is refused"
    );
    let presses = key1.assertions();
    assert!(
        gestures::open_with_credential(&key1, &vault, &[0xEE; 64], PIN).is_err(),
        "a credential the vault does not hold"
    );
    assert_eq!(key1.assertions(), presses, "refused before the press");

    let opened =
        gestures::open_with_credential(&key1, &vault, &approving, PIN).expect("the approving key");
    assert_eq!(opened.credential_id, approving);
    gestures::prove_anchors_open(&vault, &opened).expect("and it opens the anchors");
}
