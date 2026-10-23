//! The enrollment gestures of §15.2, against simulated security keys and real
//! anchors.
//!
//! What matters here is the order: an invitation exists only once it is in the
//! registry, an invitation is consumed before anything is issued for it, and a
//! document is signed only around the leaves its invitation actually received.

mod support;

use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Id16, MlDsa87PublicKey, MlDsa87Signature,
    WireGuardKey,
};
use aether::certificates::gateway::GatewayBootstrapRequest;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use aether::key_negotiation::{
    wireguard_proof, EnrollmentDocument, EnrollmentInvitation, EnrollmentRequest, PqCertificate,
    PqCertificateRole, ENROLLMENT_DOCUMENT_FORMAT, ENROLLMENT_DOCUMENT_VERSION,
    ENROLLMENT_FORMAT_VERSION, ENROLLMENT_PROTOCOL_VERSION,
};
use astra_operator::authenticator::Opened;
use astra_operator::enrollment::{InvitationRegistry, InvitationState};
use astra_operator::gestures::{
    add_key, create_authority, open_with_authorized_key, NewAuthority, NewKey,
};
use astra_operator::signing::{self, DomainIdentity, InvitationDraft, IssuedLeaves};
use astra_operator::vault::{AuthorityVault, SlotRole, SlotSecret};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use support::{FakeKey, PIN, RP_ID};
use zeroize::Zeroizing;

const NOW: u64 = 1_800_000_000;
const SERVER_NAME: &str = "gateway.helios.test";
const LEAF_VALIDITY: (u64, u64) = (NOW, NOW + 365 * 86_400);

fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([0x11; 32])
}

fn identity() -> DomainIdentity {
    DomainIdentity {
        trust_domain_id: aether::certificates::encoding::TrustDomainId::new([0x2A; 16])
            .expect("domain"),
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
    }
}

struct Domain {
    first: FakeKey,
    second: FakeKey,
    vault: AuthorityVault,
    ca_tls: DerCertificate,
    gateway_leaf: PqCertificate,
    _directory: tempfile::TempDir,
    registry: InvitationRegistry,
}

impl Domain {
    fn new() -> Self {
        let first = FakeKey::new(1);
        let second = FakeKey::new(2);
        let mut vault = create_authority(
            &first,
            &NewAuthority {
                rp_id: RP_ID.into(),
                trust_domain_id: identity().trust_domain_id,
                label: "YubiKey du bureau".into(),
                role: SlotRole::Primary,
            },
            PIN,
            NOW,
        )
        .expect("create")
        .vault;
        let opened = open_with_authorized_key(&first, &vault, PIN).expect("opens");
        add_key(
            &second,
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
        let ca_tls =
            signing::issue_ca_tls(&vault, &opened, &identity(), NOW, NOW + 10 * 365 * 86_400)
                .expect("CA-TLS");
        let gateway_leaf = gateway_leaf(&vault, &opened);
        let directory = tempfile::tempdir().expect("tempdir");
        let registry = InvitationRegistry::at(directory.path().join("enrollment-invitations"));
        Self {
            first,
            second,
            vault,
            ca_tls,
            gateway_leaf,
            _directory: directory,
            registry,
        }
    }

    fn open(&self) -> Opened {
        open_with_authorized_key(&self.first, &self.vault, PIN).expect("opens")
    }

    fn open_second(&self) -> Opened {
        open_with_authorized_key(&self.second, &self.vault, PIN).expect("opens")
    }

    fn ca_pq(&self) -> MlDsa87PublicKey {
        MlDsa87PublicKey::parse(self.vault.ca_pq_public_key.trim()).expect("anchor")
    }

    fn draft(&self, allow_readmission: bool) -> InvitationDraft<'_> {
        InvitationDraft {
            gateway_certificate: &self.gateway_leaf,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME,
            not_before_unix: NOW,
            not_after_unix: NOW + 3_600,
            allow_readmission,
        }
    }

    fn invite(&self) -> EnrollmentInvitation {
        let opening = self.open();
        signing::sign_invitation(
            &self.vault,
            &[&opening],
            &self.draft(false),
            &self.registry,
            NOW,
        )
        .expect("invitation")
    }

    fn accept(&self, request: &EnrollmentRequest) -> IssuedLeaves {
        signing::accept_request(
            &self.vault,
            &self.open(),
            &self.registry,
            &self.ca_tls,
            request,
            LEAF_VALIDITY,
            NOW,
        )
        .expect("accepted")
    }
}

fn gateway_leaf(vault: &AuthorityVault, opening: &Opened) -> PqCertificate {
    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().expect("gateway key");
    let request = GatewayBootstrapRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        ml_dsa_87_public_key: gateway_public,
        key_possession_proof: MlDsa87Signature::placeholder(),
    }
    .sign(&gateway_private)
    .expect("bootstrap request");
    signing::issue_gateway_bootstrap_certificate(
        vault,
        opening,
        &MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim()).expect("anchor"),
        &signing::GatewayBootstrapDecision {
            request: &request,
            leaf_validity: LEAF_VALIDITY,
            serial: [9; 16],
        },
    )
    .expect("gateway leaf")
}

struct Client {
    request: EnrollmentRequest,
}

fn request(invitation: &EnrollmentInvitation, name: &str) -> Client {
    let keys = aether::wg::generate_keypair().expect("wg");
    let private: Zeroizing<[u8; 32]> = Zeroizing::new(
        STANDARD
            .decode(keys.private_key.expose())
            .expect("base64")
            .try_into()
            .expect("32 bytes"),
    );
    let (ml_dsa_private, ml_dsa_public) = generate_ml_dsa_87_keypair().expect("ml-dsa");
    let csr = aether::certificates::x509::client_rotation_csr(name).expect("csr");
    let mut request = EnrollmentRequest {
        format_version: ENROLLMENT_FORMAT_VERSION,
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: invitation.invitation_id,
        invitation_fingerprint: invitation.fingerprint(),
        request_id: Id16::new([0x5C; 16]).expect("id"),
        timestamp_unix: NOW,
        requested_name: name.into(),
        client_wg_public_key: WireGuardKey::parse(&keys.public_key).expect("public"),
        tls_csr: csr.csr,
        client_ml_dsa_87_public_key: ml_dsa_public,
        wireguard_proof: [0; 32],
        client_signature: MlDsa87Signature::placeholder(),
    };
    request.wireguard_proof = wireguard_proof(&private, invitation, &request).expect("proof");
    Client {
        request: request.sign(&ml_dsa_private).expect("signed"),
    }
}

fn document(
    domain: &Domain,
    invitation: &EnrollmentInvitation,
    request: &EnrollmentRequest,
    leaves: &IssuedLeaves,
) -> EnrollmentDocument {
    let profile = serde_json::json!({
        "name": "laptop-alice",
        "type": "helios_key_negotiation",
        "endpoint": "gateway.helios.test:51820",
        "peer_public_key": invitation.gateway_wg_public_key.to_base64(),
        "key_negotiation": {
            "server_name": SERVER_NAME,
            "gateway_pq_certificate": serde_json::to_string(&domain.gateway_leaf).expect("json"),
            "trust": { "ca_pq_public_key": domain.ca_pq().to_base64() },
        },
    });
    let serde_json::Value::Object(profile) = profile else {
        panic!("object");
    };
    EnrollmentDocument {
        format: ENROLLMENT_DOCUMENT_FORMAT.into(),
        format_version: ENROLLMENT_DOCUMENT_VERSION,
        invitation_id: invitation.invitation_id,
        request_id: request.request_id,
        request_fingerprint: request.fingerprint(),
        operator_ca_fingerprint: domain.ca_pq().authority_fingerprint(),
        issued_at_unix: NOW,
        profile,
        client_tls_certificate: leaves.tls_certificate.clone(),
        client_pq_certificate: serde_json::to_string(&leaves.pq_certificate).expect("json"),
        operator_signature: None,
    }
}

#[test]
fn an_invitation_is_recorded_before_it_is_returned() {
    let domain = Domain::new();
    let invitation = domain.invite();
    let record = domain
        .registry
        .load(&invitation.invitation_id)
        .expect("recorded");
    assert_eq!(record.invitation, invitation);
    assert_eq!(record.state, InvitationState::Issued);
    invitation
        .verify(&domain.ca_pq(), NOW)
        .expect("signed by CA-PQ");
    assert_eq!(
        invitation.gateway_certificate_fingerprint,
        aether::certificates::gateway::pq_certificate_fingerprint(&domain.gateway_leaf)
            .expect("fingerprint")
    );
}

#[test]
fn readmission_invitations_need_two_distinct_credentials() {
    let domain = Domain::new();
    let first = domain.open();
    let draft = domain.draft(true);
    assert!(
        signing::sign_invitation(&domain.vault, &[&first], &draft, &domain.registry, NOW).is_err()
    );
    let again = domain.open();
    assert!(signing::sign_invitation(
        &domain.vault,
        &[&first, &again],
        &draft,
        &domain.registry,
        NOW
    )
    .is_err());
    let second = domain.open_second();
    let invitation = signing::sign_invitation(
        &domain.vault,
        &[&first, &second],
        &draft,
        &domain.registry,
        NOW,
    )
    .expect("two keys");
    assert!(invitation.allow_readmission);
}

#[test]
fn an_invitation_for_a_gateway_leaf_not_signed_by_ca_pq_is_refused() {
    let domain = Domain::new();
    let (private, _) = generate_ml_dsa_87_keypair().expect("other");
    let mut forged = domain.gateway_leaf.clone();
    forged.ml_dsa_87_signature = String::new();
    let forged = aether::key_negotiation::issue_pq_certificate(forged, &private).expect("forged");
    let opening = domain.open();
    let draft = InvitationDraft {
        gateway_certificate: &forged,
        ..domain.draft(false)
    };
    assert!(
        signing::sign_invitation(&domain.vault, &[&opening], &draft, &domain.registry, NOW)
            .is_err()
    );
}

#[test]
fn accept_consumes_before_issuing() {
    let domain = Domain::new();
    let invitation = domain.invite();
    let client = request(&invitation, "laptop-alice");
    let opening = domain.open();
    // The right credential, the wrong secret: the vault refuses to open.
    let broken = Opened {
        credential_id: opening.credential_id.clone(),
        secret: SlotSecret::new(vec![0; 32]),
    };
    assert!(signing::accept_request(
        &domain.vault,
        &broken,
        &domain.registry,
        &domain.ca_tls,
        &client.request,
        LEAF_VALIDITY,
        NOW,
    )
    .is_err());
    assert!(matches!(
        domain
            .registry
            .load(&invitation.invitation_id)
            .expect("record")
            .state,
        InvitationState::Consumed { issued: None, .. }
    ));
    assert!(signing::accept_request(
        &domain.vault,
        &opening,
        &domain.registry,
        &domain.ca_tls,
        &client.request,
        LEAF_VALIDITY,
        NOW,
    )
    .is_err());
}

#[test]
fn accepted_leaves_certify_the_request_keys() {
    let domain = Domain::new();
    let invitation = domain.invite();
    let client = request(&invitation, "laptop-alice");
    let leaves = domain.accept(&client.request);

    aether::certificates::x509::assert_csr_matches(
        &client.request.tls_csr,
        &leaves.tls_certificate,
    )
    .expect("TLS leaf certifies the CSR key");
    aether::certificates::x509::assert_client_leaf(&leaves.tls_certificate, NOW, NOW + 86_400)
        .expect("a client leaf");
    leaves
        .pq_certificate
        .verify(
            domain.ca_pq().as_bytes(),
            PqCertificateRole::Client,
            Some("laptop-alice"),
            &client.request.client_wg_public_key.to_base64(),
            NOW,
        )
        .expect("PQ leaf under CA-PQ");
    assert_eq!(
        leaves.pq_certificate.ml_dsa_87_public_key,
        client.request.client_ml_dsa_87_public_key.to_base64()
    );
    assert!(matches!(
        domain
            .registry
            .load(&invitation.invitation_id)
            .expect("record")
            .state,
        InvitationState::Consumed {
            issued: Some(_),
            ..
        }
    ));
}

#[test]
fn a_signed_document_verifies_under_ca_pq() {
    let domain = Domain::new();
    let invitation = domain.invite();
    let client = request(&invitation, "laptop-alice");
    let leaves = domain.accept(&client.request);
    let draft = document(&domain, &invitation, &client.request, &leaves);
    let signed = signing::sign_document(&domain.vault, &domain.open(), &domain.registry, draft)
        .expect("signed");
    signed.verify(&domain.ca_pq()).expect("verifies");
}

#[test]
fn a_document_for_leaves_this_invitation_did_not_receive_is_refused() {
    let domain = Domain::new();
    let invitation = domain.invite();
    let client = request(&invitation, "laptop-alice");
    let leaves = domain.accept(&client.request);

    let other_invitation = domain.invite();
    let other = request(&other_invitation, "laptop-bob");
    let other_leaves = domain.accept(&other.request);

    let mut draft = document(&domain, &invitation, &client.request, &leaves);
    draft.client_pq_certificate =
        serde_json::to_string(&other_leaves.pq_certificate).expect("json");
    assert!(
        signing::sign_document(&domain.vault, &domain.open(), &domain.registry, draft).is_err()
    );

    let mut draft = document(&domain, &invitation, &client.request, &leaves);
    draft.client_tls_certificate = other_leaves.tls_certificate.clone();
    assert!(
        signing::sign_document(&domain.vault, &domain.open(), &domain.registry, draft).is_err()
    );

    let mut draft = document(&domain, &invitation, &client.request, &leaves);
    draft.request_fingerprint = other.request.fingerprint();
    assert!(
        signing::sign_document(&domain.vault, &domain.open(), &domain.registry, draft).is_err()
    );
}

#[test]
fn a_document_before_any_leaf_is_refused() {
    let domain = Domain::new();
    let invitation = domain.invite();
    let client = request(&invitation, "laptop-alice");
    let unissued = IssuedLeaves {
        tls_certificate: domain.ca_tls.clone(),
        pq_certificate: domain.gateway_leaf.clone(),
    };
    let draft = document(&domain, &invitation, &client.request, &unissued);
    assert!(
        signing::sign_document(&domain.vault, &domain.open(), &domain.registry, draft).is_err()
    );
}

#[test]
fn a_document_whose_trust_block_names_another_ca_is_refused() {
    let domain = Domain::new();
    let invitation = domain.invite();
    let client = request(&invitation, "laptop-alice");
    let leaves = domain.accept(&client.request);
    let mut draft = document(&domain, &invitation, &client.request, &leaves);
    let (_, other) = generate_ml_dsa_87_keypair().expect("other");
    draft.profile["key_negotiation"]["trust"]["ca_pq_public_key"] =
        serde_json::json!(other.to_base64());
    assert!(
        signing::sign_document(&domain.vault, &domain.open(), &domain.registry, draft).is_err()
    );
}

#[test]
fn a_document_naming_another_gateway_is_refused() {
    let domain = Domain::new();
    let invitation = domain.invite();
    let client = request(&invitation, "laptop-alice");
    let leaves = domain.accept(&client.request);

    let mut draft = document(&domain, &invitation, &client.request, &leaves);
    draft.profile["peer_public_key"] =
        serde_json::json!(WireGuardKey::from_bytes([0x22; 32]).to_base64());
    assert!(
        signing::sign_document(&domain.vault, &domain.open(), &domain.registry, draft).is_err()
    );

    let mut draft = document(&domain, &invitation, &client.request, &leaves);
    draft.profile["key_negotiation"]["server_name"] = serde_json::json!("other.helios.test");
    assert!(
        signing::sign_document(&domain.vault, &domain.open(), &domain.registry, draft).is_err()
    );

    let mut draft = document(&domain, &invitation, &client.request, &leaves);
    draft.profile["key_negotiation"]["gateway_pq_certificate"] =
        serde_json::json!(serde_json::to_string(&leaves.pq_certificate).expect("json"));
    assert!(
        signing::sign_document(&domain.vault, &domain.open(), &domain.registry, draft).is_err()
    );
}
