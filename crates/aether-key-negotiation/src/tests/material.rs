use super::fixtures::{
    commitment, simple_request, test_now, CLIENT_WG_KEY, GATEWAY_CERT_FINGERPRINT, GATEWAY_WG_KEY,
    TEST_CHALLENGE, TEST_SERVER_NAME,
};
use aether::key_negotiation::{
    KeyNegotiationRequest, ProtectionMode, KEY_NEGOTIATION_VERSION, SERVER_CHALLENGE_LEN,
};
use aether::pq::{Kem, MlKem1024Kem};
use base64::Engine as _;

use crate::{prepare_key_material, PublicError, DEFAULT_CONFIRMATION_TIMEOUT};

#[test]
fn all_modes_prepare_exactly_one_wireguard_slot_state() {
    let static_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);

    let base = KeyNegotiationRequest {
        protocol_version: KEY_NEGOTIATION_VERSION,
        server_challenge: TEST_CHALLENGE,
        transaction_id: [1; 16],
        mode: ProtectionMode::StaticPsk,
        client_wg_public_key: CLIENT_WG_KEY.into(),
        gateway_wg_public_key: GATEWAY_WG_KEY.into(),
        server_name: TEST_SERVER_NAME.into(),
        gateway_certificate_fingerprint: GATEWAY_CERT_FINGERPRINT.into(),
        client_nonce: [2; 16],
        timestamp_unix: test_now(),
        kem_public_key: None,
        static_psk_commitment: None,
    };
    let mut static_request = base.clone();
    static_request.static_psk_commitment = Some(commitment(&static_psk, &static_request));
    let prepared = prepare_key_material(
        &static_request,
        GATEWAY_WG_KEY,
        [3; 16],
        Some(&static_psk),
        DEFAULT_CONFIRMATION_TIMEOUT,
    )
    .unwrap();
    assert_eq!(prepared.psk.unwrap().expose(), static_psk);

    let (_secret_key, public_key) = MlKem1024Kem::generate().unwrap();
    let mut kem_request = base;
    kem_request.mode = ProtectionMode::MlKem;
    kem_request.kem_public_key = Some(public_key);
    let prepared = prepare_key_material(
        &kem_request,
        GATEWAY_WG_KEY,
        [3; 16],
        None,
        DEFAULT_CONFIRMATION_TIMEOUT,
    )
    .unwrap();
    assert!(prepared.psk.is_some());
    assert!(prepared.response.kem_ciphertext.is_some());
}
/// L'engagement prouve la possession **pour cette transaction** : celui
/// d'un autre PSK ne passe pas, et rien dans le refus ne dit lequel des
/// deux cas — pas de PSK configuré, ou mauvais PSK — s'est produit.
#[test]
fn static_mode_rejects_another_psk_commitment() {
    let configured = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let other = base64::engine::general_purpose::STANDARD.encode([8u8; 32]);
    let mut request = simple_request([1; 16]);
    request.mode = ProtectionMode::StaticPsk;
    request.static_psk_commitment = Some(commitment(&other, &request));
    assert!(matches!(
        prepare_key_material(
            &request,
            GATEWAY_WG_KEY,
            [3; 16],
            Some(&configured),
            DEFAULT_CONFIRMATION_TIMEOUT
        ),
        Err(PublicError::Rejected)
    ));

    // Le bon PSK, lui, passe — sinon le test ci-dessus ne prouverait rien.
    request.static_psk_commitment = Some(commitment(&configured, &request));
    assert!(prepare_key_material(
        &request,
        GATEWAY_WG_KEY,
        [3; 16],
        Some(&configured),
        DEFAULT_CONFIRMATION_TIMEOUT
    )
    .is_ok());
}

/// Deux transactions, le **même** PSK : deux engagements différents. C'est
/// ce qui remplace l'empreinte stable de la v4, corrélable d'une session à
/// l'autre par un simple observateur du port public.
#[test]
fn the_same_static_psk_commits_differently_each_transaction() {
    let psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let first = simple_request([1; 16]);
    let mut second = simple_request([2; 16]);
    second.server_challenge = [6; SERVER_CHALLENGE_LEN];
    assert_ne!(commitment(&psk, &first), commitment(&psk, &second));
}
