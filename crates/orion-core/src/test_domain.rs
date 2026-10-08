//! The client-side domain fixture every certificate test is built on.
//!
//! One place decides what «a domain» is for these tests: the anchor, the
//! gateway leaf, the client generation in service, the CA-TLS and the profile
//! that names them. Three modules need exactly this — renewal, trust update
//! and expired recovery — and three copies of it would drift the moment one of
//! them learned a new field, with the divergence showing up as a test that
//! passes against a domain no other test describes.
//!
//! Everything here is `#[cfg(test)]`. No release build sees it.

use aether::certificates::client::ClientCertificateGeneration;
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, MlDsa87PublicKey, TrustDomainId,
    WireGuardKey,
};
use aether::certificates::state::{
    AstraProfile, ClientCertificateState, ClientTlsCaState, GatewayCertificateState, TrustLedger,
};
use aether::key_negotiation::{
    issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use zeroize::Zeroizing;

use crate::certificates::TrustStore;
use crate::config::{KeyNegotiationSettings, TrustMaterial};
use crate::identity_store::ClientIdentityBundle;

pub(crate) const NOW: u64 = 1_700_000_000;
pub(crate) const SERVER_NAME: &str = "gateway.example";
pub(crate) const SUBJECT: &str = "poste-windows";

/// Every private key the fixture has to hold, because every one of them
/// signs something the client verifies.
pub(crate) struct Domain {
    pub(crate) ca_pq_private: Zeroizing<Vec<u8>>,
    pub(crate) ca_pq_public: MlDsa87PublicKey,
    pub(crate) gateway_pq_private: Zeroizing<Vec<u8>>,
    pub(crate) gateway_leaf: PqCertificate,
    pub(crate) active_client_private: Zeroizing<Vec<u8>>,
    pub(crate) active_client_leaf: PqCertificate,
    pub(crate) active_client_tls: DerCertificate,
    pub(crate) tls_ca: rcgen::Certificate,
    pub(crate) tls_ca_key: KeyPair,
    pub(crate) tls_ca_der: DerCertificate,
    pub(crate) service_public: MlDsa87PublicKey,
}

pub(crate) fn client_key() -> WireGuardKey {
    WireGuardKey::from_bytes([2; 32])
}

pub(crate) fn gateway_key() -> WireGuardKey {
    WireGuardKey::from_bytes([9; 32])
}

pub(crate) fn domain_id() -> TrustDomainId {
    TrustDomainId::new([1; 16]).expect("domain")
}

pub(crate) fn name(common: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common);
    name
}

pub(crate) fn seconds_since_epoch(unix: u64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(unix as i64).expect("timestamp")
}

pub(crate) fn domain() -> Domain {
    let (ca_pq_private, ca_pq_public) = generate_ml_dsa_87_keypair().expect("CA-PQ");
    let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("service");
    drop(service_private);

    let (gateway_pq_private, gateway_pq_public) =
        generate_ml_dsa_87_keypair().expect("gateway leaf");
    let gateway_leaf = issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [1; 16],
            subject: SERVER_NAME.into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: gateway_key().to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(gateway_pq_public.as_bytes()),
            not_before_unix: NOW - 3_600,
            not_after_unix: NOW + 10 * 86_400,
            ml_dsa_87_signature: String::new(),
        },
        &ca_pq_private,
    )
    .expect("gateway leaf");

    let (active_client_private, active_client_public) =
        generate_ml_dsa_87_keypair().expect("active client");
    let active_client_leaf = issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [2; 16],
            subject: SUBJECT.into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Client,
            wireguard_public_key: client_key().to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(active_client_public.as_bytes()),
            not_before_unix: NOW - 3_600,
            not_after_unix: NOW + 10 * 86_400,
            ml_dsa_87_signature: String::new(),
        },
        &ca_pq_private,
    )
    .expect("active client leaf");

    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name = name("CA-TLS cliente");
    params.not_before = seconds_since_epoch(NOW - 86_400);
    params.not_after = seconds_since_epoch(NOW + 365 * 86_400);
    let tls_ca_key = KeyPair::generate().expect("CA-TLS key");
    let tls_ca = params.self_signed(&tls_ca_key).expect("CA-TLS");
    let tls_ca_der = DerCertificate::new(tls_ca.der().to_vec()).expect("der");

    // The leaf the machine is currently connecting with. Issued by the
    // same CA-TLS, because that is what an admitted client holds.
    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("params");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    leaf_params.distinguished_name = name(SUBJECT);
    leaf_params.not_before = seconds_since_epoch(NOW - 3_600);
    leaf_params.not_after = seconds_since_epoch(NOW + 10 * 86_400);
    let active_client_tls = DerCertificate::new(
        leaf_params
            .signed_by(
                &KeyPair::generate().expect("leaf key"),
                &Issuer::from_ca_cert_der(tls_ca.der(), &tls_ca_key).expect("CA-TLS issuer"),
            )
            .expect("client leaf")
            .der()
            .to_vec(),
    )
    .expect("der");

    Domain {
        ca_pq_private,
        ca_pq_public,
        gateway_pq_private,
        gateway_leaf,
        active_client_private,
        active_client_leaf,
        active_client_tls,
        tls_ca,
        tls_ca_key,
        tls_ca_der,
        service_public,
    }
}

pub(crate) fn active_generation(domain: &Domain) -> ClientCertificateGeneration {
    ClientCertificateGeneration {
        generation: 4,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: domain.tls_ca_der.fingerprint(),
        tls_certificate_fingerprint: Fingerprint::of(b"active client tls"),
        pq_certificate_fingerprint: aether::certificates::gateway::pq_certificate_fingerprint(
            &domain.active_client_leaf,
        )
        .expect("active pq fingerprint"),
        not_before: NOW - 3_600,
        not_after: NOW + 10 * 86_400,
    }
}

pub(crate) fn store(directory: &std::path::Path, domain: &Domain) -> TrustStore {
    TrustStore::new(
        directory.join("trust.json"),
        crate::certificates::TrustState {
            trust_domain_id: domain_id(),
            client_wg_public_key: client_key(),
            gateway: GatewayCertificateState {
                trust_domain_id: domain_id(),
                gateway_wg_public_key: gateway_key(),
                server_name: SERVER_NAME.into(),
                ca_epoch: 1,
                current_ca_public_key: domain.ca_pq_public.clone(),
                next_ca_public_key: None,
                next_ca_transition_fingerprint: None,
                ca_activation_at: None,
                ca_retire_active_at: None,
                active_gateway_identity_epoch: 1,
                gateway_decision_epoch: 1,
                next_gateway_identity_epoch: None,
                next_transition_fingerprint: None,
                last_aborted_transition: None,
                active_gateway_tls_certificate: DerCertificate::new(vec![1; 64]).expect("der"),
                next_gateway_tls_certificate: None,
                active_gateway_certificate: domain.gateway_leaf.clone(),
                next_gateway_certificate: None,
                activation_at: None,
                retire_active_at: None,
                published: false,
                revoked: false,
                revocation_epoch: 0,
                service_rollback: None,
                awaited_replacement: None,
            },
            client_tls_ca: ClientTlsCaState {
                ca_tls_epoch: 1,
                active_client_tls_ca_certificate: domain.tls_ca_der.clone(),
                next_client_tls_ca_certificate: None,
                next_transition_fingerprint: None,
                activation_at: None,
                retire_active_at: None,
            },
            astra: AstraProfile {
                authority_url: "https://astra.example".into(),
                webauthn_rp_id: "astra.example".into(),
                astra_policy_fingerprint: aether::certificates::approval::AstraPolicyPin::new(
                    Fingerprint::of(b"policy"),
                )
                .expect("policy pin"),
                credential_registry_epoch: 1,
                credential_bindings: Default::default(),
                active_astra_service_public_key: domain.service_public.clone(),
                next_astra_service_public_key: None,
                next_service_key_transition_fingerprint: None,
                astra_service_key_epoch: 1,
                service_key_activation_at: None,
                service_key_retire_active_at: None,
                service_key_revocation_epoch: 0,
                last_emergency_replacement_fingerprint: None,
            },
            issuer_epoch: 1,
            issuer: None,
            certificates: ClientCertificateState::new(active_generation(domain)),
            staged_gateway_transition: None,
            ledger: TrustLedger::default(),
        },
    )
}

/// A profile as `helios profile emit` writes one since §19.
pub(crate) fn settings(domain: &Domain) -> KeyNegotiationSettings {
    KeyNegotiationSettings {
        mode: aether::key_negotiation::ProtectionMode::MlKem,
        minimum_mode: aether::key_negotiation::ProtectionMode::MlKem,
        endpoint: "gateway.example:51821".into(),
        server_name: SERVER_NAME.into(),
        gateway_ca_der: STANDARD.encode(vec![1u8; 64]),
        gateway_pq_certificate: STANDARD
            .encode(serde_json::to_vec(&domain.gateway_leaf).expect("gateway leaf")),
        identity: SUBJECT.into(),
        trust: Some(TrustMaterial {
            trust_domain_id: domain_id().to_hex(),
            ca_epoch: 1,
            ca_pq_public_key: domain.ca_pq_public.to_base64(),
            ca_tls_epoch: 1,
            client_tls_ca_der: STANDARD.encode(domain.tls_ca_der.as_bytes()),
            client_generation: 4,
            astra_authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: Fingerprint::of(b"policy").to_hex(),
            credential_registry_epoch: 1,
            astra_credential_bindings: Vec::new(),
            astra_service_key_epoch: 1,
            astra_service_public_key: domain.service_public.to_base64(),
            active_gateway_identity_epoch: 1,
            gateway_decision_epoch: 1,
        }),
    }
}

/// The sealed identity as it exists on an enrolled machine — read here
/// straight from the fixture, because DPAPI seals nothing outside Windows.
pub(crate) fn bundle(domain: &Domain) -> ClientIdentityBundle {
    ClientIdentityBundle {
        identity: SUBJECT.into(),
        certificate_chain: vec![STANDARD.encode(domain.active_client_tls.as_bytes())],
        private_key: STANDARD.encode(vec![7u8; 64]),
        pq_certificate: STANDARD
            .encode(serde_json::to_vec(&domain.active_client_leaf).expect("client leaf")),
        pq_private_key: STANDARD.encode(domain.active_client_private.as_slice()),
    }
}

pub(crate) fn bundle_for_client_key(domain: &Domain, client: WireGuardKey) -> ClientIdentityBundle {
    let mut leaf = domain.active_client_leaf.clone();
    leaf.wireguard_public_key = client.to_base64();
    leaf.ml_dsa_87_signature.clear();
    let leaf = issue_pq_certificate(leaf, &domain.ca_pq_private).expect("client leaf");
    ClientIdentityBundle {
        pq_certificate: STANDARD.encode(serde_json::to_vec(&leaf).expect("client leaf encoding")),
        ..bundle(domain)
    }
}
