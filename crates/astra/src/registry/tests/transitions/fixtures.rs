//! Fixtures shared by transition-family tests.

use super::*;

pub(super) struct Anchored {
    pub(super) registry: AstraRegistry,
    pub(super) ca_private: zeroize::Zeroizing<Vec<u8>>,
    pub(super) ca_public: MlDsa87PublicKey,
    pub(super) _directory: tempfile::TempDir,
}

pub(super) fn anchored() -> Anchored {
    let directory = tempfile::tempdir().expect("temp dir");
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
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
        ca_public_key: ca_public.clone(),
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
    Anchored {
        registry: AstraRegistry::new(directory.path().join("astra.json"), state),
        ca_private,
        ca_public,
        _directory: directory,
    }
}

fn campaign_id() -> Id16 {
    Id16::new([7; 16]).expect("id")
}

/// The approved text an acceptance is checked against.
///
/// Only the gateway-identity arms read its rows; every other object
/// carries the state it is verified against, or is verified against an
/// anchor this registry pins. Which is exactly the asymmetry: the
/// gateway's own leaves live nowhere here.
pub(super) fn campaign(
    scope: aether::certificates::status::CampaignScope,
    targets: Vec<aether::certificates::status::CampaignTarget>,
) -> aether::certificates::status::AstraRotationCampaign {
    aether::certificates::status::AstraRotationCampaign {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        campaign_id: campaign_id(),
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
        server_name: "gateway.example".into(),
        created_at: 1_000,
        expires_at: 1_300,
        scope,
        targets,
        reason: "rotation".into(),
        requested_by: "operator".into(),
        policy_fingerprint: Fingerprint::of(b"policy"),
        required_credentials: scope.required_credentials(),
    }
}

pub(super) fn anchor_campaign() -> aether::certificates::status::AstraRotationCampaign {
    campaign(
        aether::certificates::status::CampaignScope::TrustAuthorities,
        Vec::new(),
    )
}
