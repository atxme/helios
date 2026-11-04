use super::*;
use aether::certificates::encoding::generate_ml_dsa_87_keypair;
use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

mod delegation;

fn certificate() -> PqCertificate {
    PqCertificate {
        version: PQ_CERTIFICATE_VERSION,
        serial: [1; 16],
        subject: "orion".into(),
        issuer: "CA-PQ".into(),
        role: PqCertificateRole::Client,
        wireguard_public_key: WireGuardKey::from_bytes([2; 32]).to_base64(),
        ml_dsa_87_public_key: String::new(),
        not_before_unix: 0,
        not_after_unix: 100_000,
        ml_dsa_87_signature: String::new(),
    }
}

fn generation(index: u64) -> ClientCertificateGeneration {
    ClientCertificateGeneration {
        generation: index,
        ca_tls_epoch: 1,
        tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
        tls_certificate_fingerprint: Fingerprint::of(&[index as u8, 1]),
        pq_certificate_fingerprint: Fingerprint::of(&[index as u8, 2]),
        not_before: 0,
        not_after: 100_000,
    }
}

fn registry() -> (AstraRegistry, tempfile::TempDir) {
    let directory = tempfile::tempdir().expect("temp dir");
    let (_, ca) = generate_ml_dsa_87_keypair().expect("keygen");
    let (_, service) = generate_ml_dsa_87_keypair().expect("keygen");
    let state = AstraState {
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
        server_name: "gateway.example".into(),
        authority_url: "https://astra.example".into(),
        webauthn_rp_id: "astra.example".into(),
        astra_policy_fingerprint: AstraPolicyPin::new(Fingerprint::of(b"policy"))
            .expect("policy pin"),
        credential_registry_epoch: 1,
        ca_epoch: 1,
        ca_public_key: ca,
        ca_rotation: None,
        ca_tls_epoch: 1,
        ca_tls_fingerprint: Some(Fingerprint::of(b"client tls ca")),
        ca_tls_rotation: None,
        astra_service_key_epoch: 1,
        astra_service_public_key: service,
        issuer: None,
        transitions: Vec::new(),
        promoted_credentials: None,
        peers: BTreeMap::new(),
        status_epochs: BTreeMap::new(),
        audit: AuditChain::default(),
    };
    let mut registry = AstraRegistry::new(directory.path().join("astra.json"), state);
    registry
        .admit(
            PeerRecord {
                name: "workstation".into(),
                client_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                active: generation(4),
                active_pq_certificate: certificate(),
                pending: None,
                revoked: false,
                revocation_epoch: 0,
                admission_pq_ca: None,
            },
            1_000,
        )
        .expect("admission");
    (registry, directory)
}

fn rotation(stage: u8, expires_at: u64) -> PendingRotation {
    PendingRotation {
        stage_id: Id16::new([stage; 16]).expect("stage"),
        request_fingerprint: Fingerprint::of(b"request"),
        candidate: generation(5),
        window: TransitionWindow::new(1_000, 50_000, 60_000).expect("window"),
        stage_expires_at: expires_at,
        granted: false,
    }
}

fn served(index: u64) -> PeerRecord {
    PeerRecord {
        name: "workstation".into(),
        client_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        active: generation(index),
        active_pq_certificate: certificate(),
        pending: None,
        revoked: false,
        revocation_epoch: 0,
        admission_pq_ca: None,
    }
}

mod challenges;
mod peer_lifecycle;
mod persistence;
mod transitions;
