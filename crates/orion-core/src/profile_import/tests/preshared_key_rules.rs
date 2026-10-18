//! Which pre-shared key each protection mode admits, at import and before the
//! data plane.

use aether::key_negotiation::ProtectionMode;

use super::fixtures::{complete_profile, gateway_settings};
use crate::profile_import::inspect_profile;
use crate::ClientProfile;

/// The three modes don't take the same profile material, and the fault
/// is a relation between two fields — the block carries it as a whole.
#[test]
fn a_psk_that_contradicts_the_mode_is_reported_on_the_block() {
    let profile = ClientProfile {
        preshared_key: Some("cHNr".into()),
        key_negotiation: Some(gateway_settings(ProtectionMode::MlKem)),
        ..complete_profile()
    };
    let message = inspect_profile(&profile)
        .key_negotiation
        .expect("a PSK is only valid in static mode");
    assert!(message.contains("PSK statique"), "message : {message}");

    let sound = ClientProfile {
        key_negotiation: Some(gateway_settings(ProtectionMode::MlKem)),
        ..complete_profile()
    };
    assert_eq!(inspect_profile(&sound).key_negotiation, None);
}

/// The PSK that ML-KEM just produced is not the PSK this rule forbids.
///
/// Both sit in the same slot, and telling them apart is the difference
/// between a negotiation that commits and one that cannot: `up()`
/// validates the profile it mounts, and that profile carries the freshly
/// negotiated secret. Judging it as a static PSK made every ML-KEM
/// connection fail — three attempts, then «un PSK de profil n'est valable
/// qu'avec le mode PSK statique», on a profile the user never touched.
#[test]
fn a_negotiated_psk_does_not_contradict_the_ml_kem_mode() {
    let mounted = ClientProfile {
        preshared_key: Some("cHNr".into()),
        preshared_key_is_negotiated: true,
        key_negotiation: Some(gateway_settings(ProtectionMode::MlKem)),
        ..complete_profile()
    };
    assert!(
        mounted.validate().is_ok(),
        "the profile handed to up() after a negotiation must be mountable: {:?}",
        mounted.validate().unwrap_err()
    );

    // The same secret, declared static: still refused, and that check is
    // the one worth keeping.
    let configured = ClientProfile {
        preshared_key_is_negotiated: false,
        ..mounted
    };
    assert!(configured.validate().is_err());
}

/// An ML-KEM profile must never reach the data plane without its PSK.
///
/// `validate()` accepts that shape on purpose — it is the profile's state
/// at rest, before any negotiation. What must not accept it is `up()`:
/// mounting there would bring WireGuard up on the static key pair alone.
/// The handshake would succeed, the state would go `Up`, and the
/// post-quantum protection the profile announces would simply be absent,
/// with nothing on screen saying so.
#[test]
fn an_ml_kem_profile_without_its_negotiated_psk_never_reaches_the_data_plane() {
    let at_rest = ClientProfile {
        key_negotiation: Some(gateway_settings(ProtectionMode::MlKem)),
        ..complete_profile()
    };
    assert!(
        at_rest.validate().is_ok(),
        "au repos, un profil ML-KEM n'a légitimement pas encore de PSK"
    );

    let refused = at_rest
        .validate_for_data_plane()
        .expect_err("le plan de données doit refuser un mode ML-KEM sans PSK négocié");
    assert!(
        refused.to_string().contains("sans PSK négocié"),
        "message obtenu : {refused}"
    );

    // A static PSK is not a substitute: it is the operator's out-of-band
    // value, and its presence would mean the negotiation never happened.
    let smuggled = ClientProfile {
        preshared_key: Some("cHNrLXN0YXRpcXVl".into()),
        preshared_key_is_negotiated: false,
        ..ClientProfile {
            key_negotiation: Some(gateway_settings(ProtectionMode::MlKem)),
            ..complete_profile()
        }
    };
    assert!(
        smuggled.validate_for_data_plane().is_err(),
        "un PSK statique ne peut pas tenir lieu de PSK négocié"
    );

    // And what the negotiation actually hands to `up()` passes.
    let negotiated = ClientProfile {
        preshared_key: Some("cHNrLW5lZ29jaWU=".into()),
        preshared_key_is_negotiated: true,
        key_negotiation: Some(gateway_settings(ProtectionMode::MlKem)),
        ..complete_profile()
    };
    assert!(
        negotiated.validate_for_data_plane().is_ok(),
        "le profil éphémère issu de la négociation doit être montable : {:?}",
        negotiated.validate_for_data_plane().unwrap_err()
    );
}

/// The other mode keeps its existing contract unchanged.
#[test]
fn the_data_plane_rule_only_constrains_ml_kem() {
    let static_psk = ClientProfile {
        preshared_key: Some("cHNrLXN0YXRpcXVl".into()),
        key_negotiation: Some(gateway_settings(ProtectionMode::StaticPsk)),
        ..complete_profile()
    };
    assert!(static_psk.validate_for_data_plane().is_ok());

    // A profile with no negotiation block at all is untouched by the rule.
    assert!(complete_profile().validate_for_data_plane().is_ok());
}
