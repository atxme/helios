//! The signing gestures, against simulated security keys and real anchors.
//!
//! Only the CTAP2 boundary is simulated (see [`support::FakeKey`]): the vault,
//! the ML-DSA-87 anchors, the X.509 issuance and the WebAuthn verifier are the
//! production code, and every object produced here is checked with the same
//! function its consumer runs.
//!
//! What these tests are for is the pair of properties §14.1 rests on: an
//! ordinary renewal obtains an operator's touch and **does not open the
//! vault**, while every other gesture does open it and produces something
//! `CA-PQ` signed.

mod support;

use aether::certificates::approval::{
    AstraCredentialApprovalRequest, AstraIssuancePolicy, AstraRenewalApproval, CredentialState,
    MAX_APPROVAL_LIFETIME_SECS,
};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey,
    MlDsa87Signature, TrustDomainId, WireGuardKey,
};
use aether::certificates::revocation::{RevocationReason, RevocationScope};
use aether::certificates::status::{
    AstraRotationCampaign, CampaignScope, CampaignTarget, CertificateKind,
};
use aether::certificates::window::TransitionWindow;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use astra::vault::{AuthorityVault, SlotRole};
use astra_signer::authenticator::Opened;
use astra_signer::authority::{
    self, DelegationBounds, DomainIdentity, IssuerDelegationRequest, MAX_CA_TLS_LIFETIME_SECS,
};
use astra_signer::credentials::CredentialRegistry;
use astra_signer::gestures::{
    add_key, create_authority, open_with_authorized_key, NewAuthority, NewKey,
};
use base64::Engine as _;
use support::{FakeKey, ORIGIN, PIN, RP_ID};

const NOW: u64 = 1_800_000_000;
const SERVER_NAME: &str = "gateway.helios.test";

fn domain() -> TrustDomainId {
    TrustDomainId::new([0x2A; 16]).expect("domain")
}

fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([0x11; 32])
}

fn identity() -> DomainIdentity {
    DomainIdentity {
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
    }
}

/// A vault holding two enrolled keys — the shape §2.4 calls bootstrapped.
fn bootstrapped(first: &FakeKey, second: &FakeKey) -> AuthorityVault {
    let mut vault = create_authority(
        first,
        &NewAuthority {
            rp_id: RP_ID.into(),
            trust_domain_id: domain(),
            label: "YubiKey du bureau".into(),
            role: SlotRole::Primary,
        },
        PIN,
        NOW,
    )
    .expect("create")
    .vault;
    let opened = open_with_authorized_key(first, &vault, PIN).expect("opens");
    add_key(
        second,
        &mut vault,
        &opened,
        &NewKey {
            label: "YubiKey de récupération".into(),
            role: SlotRole::Recovery,
        },
        PIN,
        NOW,
    )
    .expect("enrols");
    vault
}

fn open(key: &FakeKey, vault: &AuthorityVault) -> Opened {
    open_with_authorized_key(key, vault, PIN).expect("opens")
}

fn ca_pq_public_key(vault: &AuthorityVault) -> MlDsa87PublicKey {
    MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim()).expect("public anchor")
}

fn bindings(vault: &AuthorityVault, opening: &Opened) -> CredentialRegistry {
    authority::sign_credential_bindings(vault, opening, &identity(), None, &[], NOW)
        .expect("bindings")
}

/// The `CA-TLS` this companion self-signs is a real CA: it certifies, and it
/// certifies under the key the vault has held since the domain was created.
#[test]
fn the_self_signed_ca_tls_certifies_under_the_vaults_own_key() {
    let first = FakeKey::new(1);
    let second = FakeKey::new(2);
    let vault = bootstrapped(&first, &second);
    let opening = open(&first, &vault);

    let certificate = authority::issue_ca_tls(
        &vault,
        &opening,
        &identity(),
        NOW,
        NOW + MAX_CA_TLS_LIFETIME_SECS,
    )
    .expect("CA-TLS issues");

    let (_, parsed) =
        x509_parser::parse_x509_certificate(certificate.as_bytes()).expect("the DER parses");
    assert!(parsed.is_ca(), "a CA-TLS that cannot certify signs nothing");
    assert!(
        parsed.verify_signature(None).is_ok(),
        "self-signed under its own key"
    );

    // A window longer than the ceiling is refused by name rather than clamped:
    // a fleet-wide pin must not silently outlive what §9.4 allows.
    assert!(authority::issue_ca_tls(
        &vault,
        &opening,
        &identity(),
        NOW,
        NOW + MAX_CA_TLS_LIFETIME_SECS + 1,
    )
    .is_err());
}

#[test]
fn an_emergency_revocation_is_signed_by_the_master_anchor() {
    let first = FakeKey::new(1);
    let second = FakeKey::new(2);
    let vault = bootstrapped(&first, &second);
    let opening = open(&first, &vault);
    let decision = authority::RevocationDecision {
        scope: RevocationScope::Client,
        identity_key: WireGuardKey::from_bytes([7; 32]),
        server_name: None,
        revocation_epoch: 1,
        revoked_tls: Some((Fingerprint::of(b"tls leaf"), NOW + 86_400)),
        revoked_pq: Some((Fingerprint::of(b"pq leaf"), NOW + 86_400)),
        effective_at: NOW,
        reason: RevocationReason::KeyCompromise,
    };

    let revocation = authority::sign_revocation(
        &vault,
        &opening,
        &identity(),
        &ca_pq_public_key(&vault),
        &decision,
        0,
    )
    .expect("revocation signs");
    revocation
        .verify(&ca_pq_public_key(&vault), &domain(), 1, 0)
        .expect("and verifies under the pinned anchor");
}

/// A delegation binds the issuer's two halves under `CA-PQ`, and verifies
/// under the anchor that signed it — the check its consumers run.
#[test]
fn a_delegation_verifies_under_the_anchor_that_signed_it() {
    let first = FakeKey::new(1);
    let second = FakeKey::new(2);
    let vault = bootstrapped(&first, &second);
    let opening = open(&first, &vault);
    let identity = identity();
    // The CA has to outlive the delegation it covers: an intermediate whose
    // issuer expires first is refused by name rather than served.
    let ca_tls =
        authority::issue_ca_tls(&vault, &opening, &identity, NOW, NOW + 365 * 86_400).unwrap();

    let (_, issuer_public) = generate_ml_dsa_87_keypair().expect("issuer keypair");
    let issuer_tls_key = rcgen::KeyPair::generate().expect("issuer TLS key");
    let mut csr_params = rcgen::CertificateParams::new(vec![SERVER_NAME.into()]).expect("params");
    csr_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Astra delegated issuer");
    let csr = csr_params
        .serialize_request(&issuer_tls_key)
        .expect("PKCS#10");

    let request = IssuerDelegationRequest {
        trust_domain_id: identity.trust_domain_id.to_hex(),
        issuer_epoch: 1,
        pq_issuer_public_key: issuer_public.to_base64(),
        tls_intermediate_csr: base64::engine::general_purpose::STANDARD.encode(csr.der()),
    };
    let bounds = DelegationBounds {
        maximum_leaf_lifetime_secs: 90 * 86_400,
        not_before: NOW,
        not_after: NOW + 30 * 86_400,
    };

    let authorization =
        authority::authorize_issuer(&vault, &opening, &identity, &ca_tls, &request, &bounds, NOW)
            .expect("the delegation signs");
    authorization
        .verify(
            &ca_pq_public_key(&vault),
            &identity.trust_domain_id,
            identity.ca_epoch,
            identity.ca_tls_epoch,
            &identity.gateway_wg_public_key,
            &identity.server_name,
            NOW,
        )
        .expect("and verifies where it lands");

    // A request naming another domain is refused before the vault is opened
    // for it: a delegation signed under the wrong anchor verifies nowhere, and
    // finding that out at the gateway is finding it out too late.
    let mut foreign = request.clone();
    foreign.trust_domain_id = TrustDomainId::new([0x33; 16]).unwrap().to_hex();
    assert!(authority::authorize_issuer(
        &vault, &opening, &identity, &ca_tls, &foreign, &bounds, NOW
    )
    .is_err());
}

/// Bindings are rebuilt from the key-slot table, never edited: one row per
/// slot present, and a withdrawn credential keeps a `revoked` row.
#[test]
fn bindings_describe_the_slot_table_and_nothing_else() {
    let first = FakeKey::new(1);
    let second = FakeKey::new(2);
    let mut vault = bootstrapped(&first, &second);
    let opening = open(&first, &vault);
    let identity = identity();

    // A third key, so the one withdrawn below is not the last recovery — the
    // vault refuses that, and rightly.
    let third = FakeKey::new(3);
    add_key(
        &third,
        &mut vault,
        &opening,
        &NewKey {
            label: "YubiKey du sac".into(),
            role: SlotRole::Recovery,
        },
        PIN,
        NOW,
    )
    .expect("enrols");
    let opening = open(&first, &vault);

    let registry = bindings(&vault, &opening);
    assert_eq!(registry.bindings.len(), 3);
    assert_eq!(registry.credential_registry_epoch, 1);
    for binding in &registry.bindings {
        assert_eq!(binding.state, CredentialState::Active);
        binding
            .verify(
                &ca_pq_public_key(&vault),
                &identity.trust_domain_id,
                &identity.gateway_wg_public_key,
                identity.ca_epoch,
                0,
            )
            .expect("each row verifies under CA-PQ");
    }

    // Withdraw the second key, then re-sign: the row stays, and says `revoked`
    // rather than disappearing — «absent from a document» is not a decision a
    // consumer can act on.
    let withdrawn = third.credential_ids().first().cloned().expect("credential");
    let slot = vault
        .slots
        .iter()
        .find(|slot| slot.credential_id().unwrap() == withdrawn)
        .map(|slot| slot.slot_id)
        .expect("the slot is there");
    astra_signer::gestures::remove_key(&mut vault, &opening, &slot).expect("removes");

    let opening = open(&first, &vault);
    let next = authority::sign_credential_bindings(
        &vault,
        &opening,
        &identity,
        Some(&registry),
        &[],
        NOW + 1,
    )
    .expect("re-signs");
    assert_eq!(next.credential_registry_epoch, 2);
    assert_eq!(next.bindings.len(), 3);
    assert_eq!(
        next.binding(&withdrawn).expect("the row stays").state,
        CredentialState::Revoked
    );

    // Epochs and terminal rows are learned only from a registry authenticated
    // under the current anchor.  Trusting its clear header here would let a
    // modified file get re-signed by the master authority.
    let mut tampered = registry.clone();
    tampered.bindings[0].created_at += 1;
    assert!(authority::sign_credential_bindings(
        &vault,
        &opening,
        &identity,
        Some(&tampered),
        &[],
        NOW + 2,
    )
    .is_err());
}

fn service_key() -> (zeroize::Zeroizing<Vec<u8>>, MlDsa87PublicKey) {
    generate_ml_dsa_87_keypair().expect("service keypair")
}

fn approval_request(
    registry: &CredentialRegistry,
    service_private_key: &[u8],
) -> AstraCredentialApprovalRequest {
    AstraCredentialApprovalRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        operation_id: Id16::new([0x07; 16]).expect("operation"),
        request_fingerprint: Fingerprint::of(b"the client rotation request"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: WireGuardKey::from_bytes([0x44; 32]),
        active_generation: 3,
        requested_generation: 4,
        credential_registry_epoch: registry.credential_registry_epoch,
        webauthn_rp_id: RP_ID.into(),
        webauthn_origin: ORIGIN.into(),
        allowed_credential_ids: registry
            .approvable()
            .into_iter()
            .map(|binding| binding.credential_id.clone())
            .collect(),
        required_credentials: 1,
        created_at: NOW,
        expires_at: NOW + MAX_APPROVAL_LIFETIME_SECS,
        astra_service_key_epoch: 2,
        astra_signature: MlDsa87Signature::placeholder(),
    }
    .sign(service_private_key)
    .expect("Astra signs its request")
}

/// The one rule of §14.1, checked as a fact rather than as a comment: an
/// ordinary renewal is approved with **no vault at all** in hand, and the
/// assertion it produces is bound to that exact request.
#[test]
fn an_ordinary_renewal_approves_without_opening_the_vault() {
    let first = FakeKey::new(1);
    let second = FakeKey::new(2);
    let vault = bootstrapped(&first, &second);
    let opening = open(&first, &vault);
    let identity = identity();
    let registry = bindings(&vault, &opening);
    let (service_private, service_public) = service_key();
    let request = approval_request(&registry, &service_private);

    let approval = helios_fido::approve_renewal(
        &first,
        &request,
        &service_public,
        2,
        &identity,
        &ca_pq_public_key(&vault),
        &registry,
        RP_ID,
        Some(3),
        PIN,
        NOW,
    )
    .expect("the operator approves");

    // Astra countersigns what the companion could not: everything else in the
    // object was produced and verified above.
    let approval = approval
        .sign(&service_private)
        .expect("Astra fills its signature");
    approval
        .verify(
            &request,
            &ca_pq_public_key(&vault),
            &service_public,
            2,
            &identity.trust_domain_id,
            identity.ca_epoch,
            0,
            NOW,
        )
        .expect("and the approval verifies at the consumer");
    assert!(
        approval.expires_at <= NOW + MAX_APPROVAL_LIFETIME_SECS,
        "five minutes at most (spec §2.4)"
    );

    // A token nobody enrolled holds no credential this request names, so it
    // answers nothing — the allow-list is the intersection, not the union.
    let stranger = FakeKey::new(9);
    assert!(helios_fido::approve_renewal(
        &stranger,
        &request,
        &service_public,
        2,
        &identity,
        &ca_pq_public_key(&vault),
        &registry,
        RP_ID,
        Some(3),
        PIN,
        NOW,
    )
    .is_err());
}

/// An assertion answers one request. Re-presented against another, the
/// challenge no longer matches and the verifier says so.
#[test]
fn an_approval_does_not_travel_to_a_second_request() {
    let first = FakeKey::new(1);
    let second = FakeKey::new(2);
    let vault = bootstrapped(&first, &second);
    let opening = open(&first, &vault);
    let registry = bindings(&vault, &opening);
    let (service_private, service_public) = service_key();

    let request = approval_request(&registry, &service_private);
    let mut other = request.clone();
    other.requested_generation = 5;
    let other = other.sign(&service_private).expect("signs");

    let approval = helios_fido::approve_renewal(
        &first,
        &request,
        &service_public,
        2,
        &identity(),
        &ca_pq_public_key(&vault),
        &registry,
        RP_ID,
        Some(3),
        PIN,
        NOW,
    )
    .expect("approves the first")
    .sign(&service_private)
    .expect("countersigned");

    // The object carries the first request's fingerprints, so presenting it
    // beside the second is caught before a signature is even checked.
    let carried = AstraRenewalApproval {
        operation_id: other.operation_id,
        ..approval
    };
    assert!(carried
        .verify(
            &other,
            &ca_pq_public_key(&vault),
            &service_public,
            2,
            &domain(),
            1,
            0,
            NOW,
        )
        .is_err());
}

fn campaign(registry: &CredentialRegistry) -> AstraRotationCampaign {
    let _ = registry;
    AstraRotationCampaign {
        format_version: CERTIFICATE_FORMAT_VERSION,
        campaign_id: Id16::new([0x09; 16]).expect("campaign"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        created_at: NOW,
        expires_at: NOW + 3_600,
        scope: CampaignScope::TrustAuthorities,
        targets: vec![CampaignTarget {
            certificate_kind: CertificateKind::CaPq,
            identity_key: gateway_key(),
            epoch: 1,
            generation: 1,
            active_tls_certificate_fingerprint: Fingerprint::of(b"tls"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"pq"),
        }],
        reason: "rotation planifiée".into(),
        requested_by: "opérateur".into(),
        policy_fingerprint: AstraIssuancePolicy::standard(
            domain(),
            gateway_key(),
            SERVER_NAME.into(),
        )
        .fingerprint()
        .expect("policy"),
        required_credentials: CampaignScope::TrustAuthorities.required_credentials(),
    }
}

/// A `TrustAuthorities` campaign takes two **distinct** credentials, and two
/// touches of one token is the case the check exists for.
#[test]
fn a_two_credential_campaign_refuses_two_touches_of_one_token() {
    let first = FakeKey::new(1);
    let second = FakeKey::new(2);
    let vault = bootstrapped(&first, &second);
    let opening = open(&first, &vault);
    let registry = bindings(&vault, &opening);
    let campaign = campaign(&registry);

    let approval = authority::approve_campaign(
        &[&first, &second],
        &campaign,
        &registry,
        &identity(),
        &ca_pq_public_key(&vault),
        RP_ID,
        ORIGIN,
        &[PIN, PIN],
        NOW,
    )
    .expect("two distinct keys approve");
    assert_eq!(approval.approvals.len(), 2);
    campaign
        .assert_unchanged(&approval.campaign_fingerprint)
        .expect("the campaign has not moved");

    assert!(authority::approve_campaign(
        &[&first, &first],
        &campaign,
        &registry,
        &identity(),
        &ca_pq_public_key(&vault),
        RP_ID,
        ORIGIN,
        &[PIN, PIN],
        NOW,
    )
    .is_err());

    // A target added after the approval changes the fingerprint, which is what
    // the operator actually touched for.
    let mut moved = campaign.clone();
    moved.targets.push(CampaignTarget {
        certificate_kind: CertificateKind::ClientPq,
        identity_key: WireGuardKey::from_bytes([0x55; 32]),
        epoch: 1,
        generation: 1,
        active_tls_certificate_fingerprint: Fingerprint::of(b"other tls"),
        active_pq_certificate_fingerprint: Fingerprint::of(b"other pq"),
    });
    assert!(moved
        .assert_unchanged(&approval.campaign_fingerprint)
        .is_err());
}

/// A `CA-PQ` rotation moves the anchor and leaves every key-slot where it was:
/// both keys open the vault after, and the bindings come back under the new
/// anchor rather than under the one just replaced.
#[test]
fn rotating_the_anchor_leaves_every_key_slot_working() {
    let first = FakeKey::new(1);
    let second = FakeKey::new(2);
    let mut vault = bootstrapped(&first, &second);
    let identity = identity();
    let registry = bindings(&vault, &open(&first, &vault));
    let previous_anchor = ca_pq_public_key(&vault);

    let first_opening = open(&first, &vault);
    let second_opening = open(&second, &vault);
    let window = TransitionWindow::new(NOW, NOW + 3_600, NOW + 7_200).expect("window");
    let rotated = authority::rotate_ca_pq(
        &mut vault,
        &[&first_opening, &second_opening],
        &identity,
        Some(&registry),
        window,
        NOW,
    )
    .expect("the anchor rotates");

    assert_ne!(rotated.next_ca_public_key, previous_anchor);
    assert_eq!(ca_pq_public_key(&vault), rotated.next_ca_public_key);
    rotated
        .transition
        .verify(
            &previous_anchor,
            &identity.trust_domain_id,
            identity.ca_epoch,
        )
        .expect("both signatures answer their own question");

    // The slot table did not move, and the re-signed bindings verify under the
    // new anchor at the new epoch.
    assert_eq!(vault.slots.len(), 2);
    for key in [&first, &second] {
        let opening = open(key, &vault);
        astra_signer::gestures::prove_anchors_open(&vault, &opening).expect("still opens");
    }
    for binding in &rotated.bindings.bindings {
        binding
            .verify(
                &rotated.next_ca_public_key,
                &identity.trust_domain_id,
                &identity.gateway_wg_public_key,
                identity.ca_epoch + 1,
                0,
            )
            .expect("re-signed under the successor");
    }

    // One credential is not a rotation: §2.4 requires two, and two objects.
    let third = FakeKey::new(3);
    let fourth = FakeKey::new(4);
    let mut other = bootstrapped(&third, &fourth);
    let only = open(&third, &other);
    assert!(authority::rotate_ca_pq(&mut other, &[&only], &identity, None, window, NOW,).is_err());
}

/// The signing gestures must fit the stack the binary reserves, like the
/// enrolment ones: ML-DSA-87 keeps its working state there, and Windows hands
/// a main thread exactly one megabyte.
#[test]
fn the_signing_gestures_fit_the_stack_the_binary_reserves() {
    let done = std::thread::Builder::new()
        .stack_size(astra_signer::WORK_STACK_BYTES)
        .spawn(|| {
            let first = FakeKey::new(1);
            let second = FakeKey::new(2);
            let vault = bootstrapped(&first, &second);
            let opening = open(&first, &vault);
            let registry = bindings(&vault, &opening);
            let (service_private, service_public) = service_key();
            let request = approval_request(&registry, &service_private);
            helios_fido::approve_renewal(
                &first,
                &request,
                &service_public,
                2,
                &identity(),
                &ca_pq_public_key(&vault),
                &registry,
                RP_ID,
                Some(3),
                PIN,
                NOW,
            )
            .expect("approves");
            let _: DerCertificate =
                authority::issue_ca_tls(&vault, &opening, &identity(), NOW, NOW + 86_400)
                    .expect("issues");
        })
        .expect("spawn")
        .join();
    assert!(done.is_ok(), "the gestures completed within the stack");
}
