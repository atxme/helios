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
