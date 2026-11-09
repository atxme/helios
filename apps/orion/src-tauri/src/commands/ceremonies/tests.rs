use super::*;
use orion_engine::ProfileView;

const REFUSAL: &str = "Connectez d'abord le profil de la gateway, avec un pair administrateur : \
                       l'admission passe par le tunnel.";

fn profile(name: &str, heliosd_url: Option<&str>) -> ProfileView {
    ProfileView {
        name: name.into(),
        endpoint: "vpn.example.net:51820".into(),
        peer_public_key: String::new(),
        address: None,
        address_v6: None,
        allowed_ips: String::new(),
        persistent_keepalive: 25,
        heliosd_url: heliosd_url.map(str::to_string),
        ssh_target: None,
        key_negotiation: None,
        profile_type: "classic".into(),
        public_key: None,
        has_private_key: false,
        has_static_psk: false,
        ipv6_uncaptured_full_tunnel: false,
    }
}

fn gateway_url(state: &str, view: &ConfigView) -> Result<String, String> {
    gateway_profile(state, view).map(|(url, _)| url)
}

fn view(selected: Option<&str>, profiles: Vec<ProfileView>) -> ConfigView {
    ConfigView {
        profiles,
        selected: selected.map(str::to_string),
        vault_error: None,
    }
}

#[test]
fn no_connected_profile_means_no_gateway_url() {
    let gateway = profile("gateway", Some("http://100.64.0.1:8080"));
    let selected = view(Some("gateway"), vec![gateway.clone()]);

    // Only an established tunnel carries the admission.
    for state in [
        "down",
        "connecting",
        "failed",
        "captive_portal",
        "",
        "garbage",
    ] {
        assert_eq!(
            gateway_url(state, &selected),
            Err(REFUSAL.to_string()),
            "{state}"
        );
    }
    // No selection, a selection that names nothing, and a profile without a
    // control-plane address are each a refusal too.
    assert_eq!(
        gateway_url("up", &view(None, vec![gateway.clone()])),
        Err(REFUSAL.to_string())
    );
    assert_eq!(
        gateway_url("up", &view(Some("other"), vec![gateway.clone()])),
        Err(REFUSAL.to_string())
    );
    assert_eq!(
        gateway_url("up", &view(Some("bare"), vec![profile("bare", None)])),
        Err(REFUSAL.to_string())
    );
    assert_eq!(
        gateway_url(
            "up",
            &view(Some("blank"), vec![profile("blank", Some(" "))])
        ),
        Err(REFUSAL.to_string())
    );
}

#[test]
fn a_connected_profile_gives_its_gateway_url() {
    let selected = view(
        Some("gateway"),
        vec![
            profile("other", Some("http://100.64.0.9:8080")),
            profile("gateway", Some("http://100.64.0.1:8080")),
        ],
    );
    assert_eq!(
        gateway_url("up", &selected),
        Ok("http://100.64.0.1:8080".to_string())
    );
}

fn status(
    gesture: aether::certificates::operator_session::GestureState,
) -> aether::certificates::operator_session::OperatorStatus {
    use aether::certificates::operator_session::{OperationKind, OperatorStatus, RemoteState};
    OperatorStatus::new(
        aether::certificates::encoding::Id16::new([6; 16]).expect("id"),
        3,
        OperationKind::AddKey,
        RemoteState::AwaitingOperator,
        gesture,
    )
}

/// A key-less write waits for the open ceremony to end: that ceremony read
/// the vault before its key and writes it after.
#[test]
fn a_key_less_write_waits_for_the_open_ceremony() {
    use aether::certificates::operator_session::{GestureState, KeyPurpose};

    assert_eq!(no_open_ceremony(None), Ok(()));
    for ended in [
        GestureState::Done,
        GestureState::Cancelled,
        GestureState::Failed,
    ] {
        assert_eq!(no_open_ceremony(Some(&status(ended))), Ok(()), "{ended:?}");
    }
    for open in [
        GestureState::Verifying,
        GestureState::AwaitingKey {
            index: 1,
            of: 2,
            purpose: KeyPurpose::OpenVault,
        },
        GestureState::ProcessingKey { index: 1, of: 2 },
        GestureState::Signing,
    ] {
        assert_eq!(
            no_open_ceremony(Some(&status(open))),
            Err(CEREMONY_OPEN.to_string()),
            "{open:?}"
        );
    }
}

fn gateway_leaf(subject: &str, key: &str) -> aether::key_negotiation::PqCertificate {
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};
    PqCertificate {
        version: PQ_CERTIFICATE_VERSION,
        serial: [9; 16],
        subject: subject.into(),
        issuer: "helios-ca-pq".into(),
        role: PqCertificateRole::Gateway,
        wireguard_public_key: key.into(),
        ml_dsa_87_public_key: String::new(),
        not_before_unix: 0,
        not_after_unix: 1,
        ml_dsa_87_signature: String::new(),
    }
}

fn answered(server_name: &str, key: &str) -> orion_core::enrollment_draft::GatewayMaterial {
    orion_core::enrollment_draft::GatewayMaterial {
        server_name: server_name.into(),
        gateway_ca_der: String::new(),
        gateway_pq_certificate: String::new(),
        wireguard_public_key: key.into(),
        pq_certificate_sha256: String::new(),
        negotiation_port: None,
    }
}

/// The leaf adopted is the tunnel's gateway: its key, the key the gateway
/// answers with and the connected profile's peer key are one, compared as
/// keys and not as strings.
#[test]
fn only_the_tunnel_gateway_is_adopted() {
    use aether::certificates::encoding::WireGuardKey;

    let tunnel = WireGuardKey::from_bytes([0x11; 32]).to_base64();
    let other = WireGuardKey::from_bytes([0x22; 32]).to_base64();
    let name = "gateway.example";
    let refused = Err("la gateway qui répond n'est pas celle du profil connecté".to_string());

    assert_eq!(
        check_tunnel_leaf(
            &gateway_leaf(name, &tunnel),
            &answered(name, &format!(" {tunnel} ")),
            &format!("{tunnel}\n"),
        ),
        Ok(())
    );
    // Another gateway behind the tunnel, a leaf for another gateway, another
    // name, a key that does not parse.
    assert_eq!(
        check_tunnel_leaf(
            &gateway_leaf(name, &other),
            &answered(name, &other),
            &tunnel
        ),
        refused
    );
    assert_eq!(
        check_tunnel_leaf(
            &gateway_leaf(name, &other),
            &answered(name, &tunnel),
            &tunnel
        ),
        refused
    );
    assert_eq!(
        check_tunnel_leaf(
            &gateway_leaf("other.example", &tunnel),
            &answered(name, &tunnel),
            &tunnel
        ),
        refused
    );
    assert_eq!(
        check_tunnel_leaf(
            &gateway_leaf(name, "garbage"),
            &answered(name, "garbage"),
            "garbage"
        ),
        refused
    );
}

#[test]
fn own_key_comes_from_the_domain_profile() {
    use crate::operator::peers::own_key_of;

    let mut domain = profile("domaine", Some("http://100.64.0.1:8080"));
    domain.public_key = Some(" OWNKEY= ".into());
    let mut other = profile("autre", Some("http://100.64.9.1:8080"));
    other.public_key = Some("OTHERKEY=".into());

    assert_eq!(
        own_key_of(&view(Some("domaine"), vec![other.clone(), domain.clone()])).as_deref(),
        Some("OWNKEY="),
        "the selected profile's public half, trimmed"
    );
    assert_eq!(
        own_key_of(&view(None, vec![domain.clone(), other.clone()])),
        None,
        "no selected profile, no key"
    );
    domain.public_key = None;
    assert_eq!(own_key_of(&view(Some("domaine"), vec![domain])), None);
}
