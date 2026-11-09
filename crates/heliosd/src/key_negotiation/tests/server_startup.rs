//! Startup refuses stale or incomplete gateway identities before unsealing.

use super::super::*;
use super::fixtures::*;
use aether::certificates::{
    encoding::{DerCertificate, TrustDomainId, WireGuardKey},
    state::GatewayCertificateState,
};

const BEFORE_ACTIVATION: u64 = 199;
const ACTIVATION: u64 = 200;
const RETIRE_ACTIVE_AT: u64 = 300;

fn gateway_state() -> GatewayCertificateState {
    let (_, ca_public_key) = generate_ml_dsa_87_keypair().expect("CA key");
    let fixture = pq_fixture();
    GatewayCertificateState {
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain id"),
        gateway_wg_public_key: WireGuardKey::parse(GATEWAY_KEY).expect("gateway WireGuard key"),
        server_name: "gateway.example".into(),
        ca_epoch: 1,
        current_ca_public_key: aether::certificates::encoding::MlDsa87PublicKey::new(ca_public_key)
            .expect("CA public key"),
        next_ca_public_key: None,
        next_ca_transition_fingerprint: None,
        ca_activation_at: None,
        ca_retire_active_at: None,
        active_gateway_identity_epoch: 1,
        gateway_decision_epoch: 1,
        next_gateway_identity_epoch: None,
        next_transition_fingerprint: None,
        last_aborted_transition: None,
        active_gateway_tls_certificate: DerCertificate::new(vec![1; 64]).expect("TLS leaf"),
        next_gateway_tls_certificate: None,
        active_gateway_certificate: fixture.gateway_certificate,
        next_gateway_certificate: None,
        activation_at: None,
        retire_active_at: None,
        published: false,
        revoked: false,
        revocation_epoch: 0,
        service_rollback: None,
        awaited_replacement: None,
    }
}

fn startup_error(gateway: &GatewayCertificateState, now: u64) -> String {
    match load_served_identity(None, false, GATEWAY_KEY, Some(gateway), now) {
        Ok(_) => panic!("invalid identity state must fail before opening sealed material"),
        Err(error) => format!("{error:#}"),
    }
}

#[test]
fn startup_refuses_a_revoked_gateway_identity_before_unsealing_or_reading_identity_files() {
    let mut gateway = gateway_state();
    gateway.revoked = true;

    let error = startup_error(&gateway, ACTIVATION);

    assert!(error.contains("identity is revoked"), "{error}");
    assert!(!error.contains("TPM secret unavailable"), "{error}");
}

#[test]
fn startup_refuses_an_unpublished_candidate_at_activation_before_unsealing() {
    let mut gateway = gateway_state();
    gateway.next_gateway_identity_epoch = Some(2);
    gateway.activation_at = Some(ACTIVATION);
    gateway.retire_active_at = Some(RETIRE_ACTIVE_AT);
    gateway.published = false;

    let error = startup_error(&gateway, ACTIVATION);

    assert!(error.contains("before publication"), "{error}");
    assert!(!error.contains("TPM secret unavailable"), "{error}");
}

#[test]
fn startup_refuses_an_unpromoted_identity_at_the_end_of_its_overlap() {
    let mut gateway = gateway_state();
    gateway.next_gateway_identity_epoch = Some(2);
    gateway.activation_at = Some(ACTIVATION);
    gateway.retire_active_at = Some(RETIRE_ACTIVE_AT);
    gateway.published = true;

    let error = startup_error(&gateway, RETIRE_ACTIVE_AT);

    assert!(error.contains("without being promoted"), "{error}");
    assert!(!error.contains("TPM secret unavailable"), "{error}");
}

#[test]
fn startup_uses_the_active_identity_before_a_published_candidate_activates() {
    let mut gateway = gateway_state();
    gateway.next_gateway_identity_epoch = Some(2);
    gateway.activation_at = Some(ACTIVATION);
    gateway.retire_active_at = Some(RETIRE_ACTIVE_AT);
    gateway.published = true;

    assert_eq!(
        served_identity_slot(Some(&gateway), BEFORE_ACTIVATION).expect("active slot"),
        ServedIdentitySlot::Active
    );
}

async fn start_with_network(network: NetworkConfig) -> Result<Option<Arc<GatewayHandler>>> {
    let (psk_tx, _psk_rx) = mpsc::channel(1);
    let (handshake_tx, _handshake_rx) = mpsc::channel(1);
    start(
        Arc::new(RwLock::new(network)),
        psk_tx,
        handshake_tx,
        Arc::new(RwLock::new(Vec::new())),
        None,
        &BootDecision::Disabled,
        false,
    )
    .await
}

#[tokio::test]
async fn absent_port_returns_without_loading_an_invalid_gateway_key() {
    let network = NetworkConfig {
        wg_private_key: SecretString::new("not a WireGuard private key"),
        ..NetworkConfig::default()
    };
    assert_eq!(network.key_negotiation_port, None);

    let service = start_with_network(network)
        .await
        .expect("disabled negotiation must not require identity material");

    assert!(service.is_none(), "an absent port starts no service");
}

#[tokio::test]
async fn invalid_gateway_key_refuses_start_with_an_identity_error() {
    let network = NetworkConfig {
        key_negotiation_port: Some(0),
        wg_private_key: SecretString::new("not a WireGuard private key"),
        ..NetworkConfig::default()
    };

    let error = match start_with_network(network).await {
        Ok(_) => panic!("an invalid gateway identity must refuse startup"),
        Err(error) => error,
    };

    assert!(
        format!("{error:#}").contains("gateway WireGuard identity is unavailable"),
        "the refusal must identify the invalid gateway key: {error:#}"
    );
}
