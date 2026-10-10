use super::*;
use crate::pq::{Kem, MlKem1024Kem};

const CLIENT_WG_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const GATEWAY_WG_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const SERVER_NAME: &str = "gateway.example";
const GATEWAY_FINGERPRINT: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

/// Horloge des tests : les requêtes doivent être fraîches pour passer le
/// contrôle secondaire de fraîcheur.
fn test_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn challenge() -> [u8; SERVER_CHALLENGE_LEN] {
    [5; SERVER_CHALLENGE_LEN]
}

/// The static PSK the test fixtures commit to.
fn test_static_psk() -> String {
    STANDARD.encode([7u8; STATIC_PSK_LEN])
}

/// A request carrying whatever its mode requires.
///
/// `static_psk` is the default of these tests because it is the cheapest
/// mode that a v5 decoder actually accepts: `classic` is refused outright
/// since the mode stopped being negotiable, and `ml_kem` costs a keypair
/// on every call.
fn request(mode: ProtectionMode) -> KeyNegotiationRequest {
    let transaction_id = [1; KEY_NEGOTIATION_NONCE_LEN];
    let client_nonce = [2; KEY_NEGOTIATION_NONCE_LEN];
    let static_psk_commitment = (mode == ProtectionMode::StaticPsk).then(|| {
        static_psk_commitment(
            &test_static_psk(),
            &transaction_id,
            &client_nonce,
            &challenge(),
            CLIENT_WG_KEY,
            GATEWAY_WG_KEY,
        )
        .unwrap()
    });
    let kem_public_key = (mode == ProtectionMode::MlKem).then(|| {
        use crate::pq::Kem as _;
        crate::pq::MlKem1024Kem::generate().unwrap().1
    });
    KeyNegotiationRequest {
        protocol_version: KEY_NEGOTIATION_VERSION,
        server_challenge: challenge(),
        transaction_id,
        mode,
        client_wg_public_key: CLIENT_WG_KEY.into(),
        gateway_wg_public_key: GATEWAY_WG_KEY.into(),
        server_name: SERVER_NAME.into(),
        gateway_certificate_fingerprint: GATEWAY_FINGERPRINT.into(),
        client_nonce,
        timestamp_unix: test_now(),
        kem_public_key,
        static_psk_commitment,
    }
}

fn response(request: &KeyNegotiationRequest, mode: ProtectionMode) -> KeyNegotiationResponse {
    KeyNegotiationResponse {
        protocol_version: KEY_NEGOTIATION_VERSION,
        transaction_id: request.transaction_id,
        server_challenge: request.server_challenge,
        selected_mode: mode,
        gateway_wg_public_key: GATEWAY_WG_KEY.into(),
        client_wg_public_key: request.client_wg_public_key.clone(),
        gateway_nonce: [3; KEY_NEGOTIATION_NONCE_LEN],
        kem_ciphertext: None,
        confirmation_timeout_secs: 45,
        psk_lifetime_secs: match mode {
            ProtectionMode::StaticPsk => 0,
            _ => NEGOTIATED_PSK_LIFETIME_SECS,
        },
    }
}

#[test]
fn an_announced_psk_lifetime_must_match_the_mode() {
    let request = request(ProtectionMode::MlKem);

    let mut honest = response(&request, ProtectionMode::MlKem);
    // `ml_kem` also requires a ciphertext; supplying one keeps this test
    // focused on the lifetime rather than tripping over an earlier check.
    honest.kem_ciphertext = Some(vec![0; crate::pq::CIPHERTEXT_LEN]);
    assert_eq!(honest.psk_lifetime_secs, NEGOTIATED_PSK_LIFETIME_SECS);
    assert!(honest.validate_for(&request, GATEWAY_WG_KEY).is_ok());

    // A gateway advertising a deadline it does not enforce: the client
    // would plan its renewal around a lie and lose the tunnel at a moment
    // neither end announced.
    let mut lying = response(&request, ProtectionMode::MlKem);
    lying.kem_ciphertext = Some(vec![0; crate::pq::CIPHERTEXT_LEN]);
    lying.psk_lifetime_secs = 60;
    assert!(matches!(
        lying.validate_for(&request, GATEWAY_WG_KEY),
        Err(KeyNegotiationError::PskLifetimeMismatch { .. })
    ));

    // A static PSK expires never, and saying otherwise is equally wrong:
    // it would have the client renegotiate for a value only the operator
    // can change.
    let static_request = self::request(ProtectionMode::StaticPsk);
    let mut expiring = response(&static_request, ProtectionMode::StaticPsk);
    assert_eq!(expiring.psk_lifetime_secs, 0);
    expiring.psk_lifetime_secs = NEGOTIATED_PSK_LIFETIME_SECS;
    assert!(matches!(
        expiring.validate_for(&static_request, GATEWAY_WG_KEY),
        Err(KeyNegotiationError::PskLifetimeMismatch { .. })
    ));
}

#[test]
fn a_request_outside_the_clock_window_is_refused() {
    let now = test_now();
    let fresh = KeyNegotiationRequest {
        timestamp_unix: now,
        ..request(ProtectionMode::StaticPsk)
    };
    assert!(fresh.assert_fresh(now).is_ok());

    // Aux bornes exactes : accepté, la tolérance est inclusive.
    assert!(fresh
        .assert_fresh(now + MAX_REQUEST_CLOCK_SKEW_SECS)
        .is_ok());
    assert!(fresh
        .assert_fresh(now - MAX_REQUEST_CLOCK_SKEW_SECS)
        .is_ok());

    for drift in [
        MAX_REQUEST_CLOCK_SKEW_SECS + 1,
        MAX_REQUEST_CLOCK_SKEW_SECS + 3600,
    ] {
        assert!(matches!(
            fresh.assert_fresh(now + drift),
            Err(KeyNegotiationError::StaleRequest { .. })
        ));
        assert!(matches!(
            fresh.assert_fresh(now - drift),
            Err(KeyNegotiationError::StaleRequest { .. })
        ));
    }

    let undated = KeyNegotiationRequest {
        timestamp_unix: 0,
        ..request(ProtectionMode::StaticPsk)
    };
    assert_eq!(
        undated.validate(),
        Err(KeyNegotiationError::MissingTimestamp)
    );
}

/// Le challenge entre dans le sel : une transcription rejouée sous un
/// challenge différent ne peut pas produire le même PSK.
#[test]
fn the_challenge_and_the_timestamp_are_bound_into_the_derived_psk() {
    let (secret_key, public_key) = MlKem1024Kem::generate().unwrap();
    let mut plain = request(ProtectionMode::MlKem);
    plain.kem_public_key = Some(public_key);
    let (ciphertext, gateway_secret) =
        MlKem1024Kem::encapsulate(plain.kem_public_key.as_ref().unwrap()).unwrap();
    let mut answer = response(&plain, ProtectionMode::MlKem);
    answer.kem_ciphertext = Some(ciphertext.clone());

    let client_secret = MlKem1024Kem::decapsulate(&secret_key, &ciphertext).unwrap();
    let reference = derive_negotiated_psk(&gateway_secret, &plain, &answer).unwrap();
    assert_eq!(
        *reference,
        *derive_negotiated_psk(&client_secret, &plain, &answer).unwrap(),
        "les deux bouts doivent dériver le même PSK"
    );
    assert_eq!(reference.len(), 32, "un slot PresharedKey fait 32 octets");

    let mut other_challenge = plain.clone();
    other_challenge.server_challenge[0] ^= 1;
    let mut rebound = answer.clone();
    rebound.server_challenge = other_challenge.server_challenge;
    assert_ne!(
        *reference,
        *derive_negotiated_psk(&gateway_secret, &other_challenge, &rebound).unwrap(),
        "changer le challenge doit changer le PSK"
    );

    let replayed = KeyNegotiationRequest {
        timestamp_unix: plain.timestamp_unix + 1,
        ..plain.clone()
    };
    assert_ne!(
        *reference,
        *derive_negotiated_psk(&gateway_secret, &replayed, &answer).unwrap(),
        "changer l'horodatage doit changer le PSK"
    );
}

/// Le nom du serveur entre dans `info` : deux gateways partageant la même
/// CA ne dérivent pas le même secret d'une transcription identique.
#[test]
fn the_server_name_is_bound_into_the_derived_psk() {
    let (_, public_key) = MlKem1024Kem::generate().unwrap();
    let mut plain = request(ProtectionMode::MlKem);
    plain.kem_public_key = Some(public_key);
    let (ciphertext, secret) =
        MlKem1024Kem::encapsulate(plain.kem_public_key.as_ref().unwrap()).unwrap();
    let mut answer = response(&plain, ProtectionMode::MlKem);
    answer.kem_ciphertext = Some(ciphertext);

    let reference = derive_negotiated_psk(&secret, &plain, &answer).unwrap();
    let elsewhere = KeyNegotiationRequest {
        server_name: "other.example".into(),
        ..plain
    };
    assert_ne!(
        *reference,
        *derive_negotiated_psk(&secret, &elsewhere, &answer).unwrap()
    );
}

#[test]
fn each_mode_rejects_material_from_another_mode() {
    // `classic` is refused before its material is even looked at: it is
    // not a mode with the wrong contents, it is not a v5 mode.
    let mut classic = request(ProtectionMode::Classic);
    assert_eq!(
        classic.validate(),
        Err(KeyNegotiationError::ClassicNotNegotiable)
    );
    classic.static_psk_commitment = Some("a".repeat(64));
    assert_eq!(
        classic.validate(),
        Err(KeyNegotiationError::ClassicNotNegotiable),
        "adding material must not turn a retired mode into a negotiable one"
    );

    let mut static_psk = request(ProtectionMode::StaticPsk);
    static_psk.kem_public_key = Some(vec![0; crate::pq::PUBLIC_KEY_LEN]);
    assert_eq!(
        static_psk.validate(),
        Err(KeyNegotiationError::UnexpectedModeMaterial)
    );

    let mut ml_kem = request(ProtectionMode::MlKem);
    ml_kem.static_psk_commitment = Some("a".repeat(64));
    assert_eq!(
        ml_kem.validate(),
        Err(KeyNegotiationError::UnexpectedModeMaterial)
    );
}

#[test]
fn a_request_naming_another_gateway_is_refused() {
    let plain = request(ProtectionMode::StaticPsk);
    plain
        .assert_addressed_to(GATEWAY_WG_KEY, SERVER_NAME, GATEWAY_FINGERPRINT)
        .unwrap();

    // Chacun des trois champs, seul, suffit à disqualifier la requête.
    assert_eq!(
        plain.assert_addressed_to(CLIENT_WG_KEY, SERVER_NAME, GATEWAY_FINGERPRINT),
        Err(KeyNegotiationError::GatewayIdentityMismatch)
    );
    assert_eq!(
        plain.assert_addressed_to(GATEWAY_WG_KEY, "other.example", GATEWAY_FINGERPRINT),
        Err(KeyNegotiationError::GatewayIdentityMismatch)
    );
    assert_eq!(
        plain.assert_addressed_to(GATEWAY_WG_KEY, SERVER_NAME, &"2".repeat(64)),
        Err(KeyNegotiationError::GatewayIdentityMismatch)
    );
}

#[test]
fn response_refuses_mode_downgrade_transaction_and_challenge_replay() {
    let mut plain = request(ProtectionMode::MlKem);
    plain.kem_public_key = Some(vec![0; crate::pq::PUBLIC_KEY_LEN]);

    let mut answer = response(&plain, ProtectionMode::StaticPsk);
    assert_eq!(
        answer.validate_for(&plain, GATEWAY_WG_KEY),
        Err(KeyNegotiationError::ModeDowngrade)
    );

    answer.selected_mode = ProtectionMode::MlKem;
    answer.kem_ciphertext = Some(vec![0; crate::pq::CIPHERTEXT_LEN]);
    answer.transaction_id = [9; KEY_NEGOTIATION_NONCE_LEN];
    assert_eq!(
        answer.validate_for(&plain, GATEWAY_WG_KEY),
        Err(KeyNegotiationError::TransactionMismatch)
    );

    answer.transaction_id = plain.transaction_id;
    answer.server_challenge[0] ^= 1;
    assert_eq!(
        answer.validate_for(&plain, GATEWAY_WG_KEY),
        Err(KeyNegotiationError::ChallengeMismatch)
    );
}

/// Une valeur signée n'est pas une valeur de confiance : la borne est
/// locale, et sortir de la plage est un refus, pas un rognage.
#[test]
fn a_confirmation_timeout_outside_the_local_range_is_refused() {
    let plain = request(ProtectionMode::StaticPsk);
    for accepted in [MIN_CONFIRMATION_TIMEOUT_SECS, MAX_CONFIRMATION_TIMEOUT_SECS] {
        let answer = KeyNegotiationResponse {
            confirmation_timeout_secs: accepted,
            ..response(&plain, ProtectionMode::StaticPsk)
        };
        answer.validate_for(&plain, GATEWAY_WG_KEY).unwrap();
    }

    for refused in [0, MAX_CONFIRMATION_TIMEOUT_SECS + 1, 86_400] {
        let answer = KeyNegotiationResponse {
            confirmation_timeout_secs: refused,
            ..response(&plain, ProtectionMode::StaticPsk)
        };
        assert!(matches!(
            answer.validate_for(&plain, GATEWAY_WG_KEY),
            Err(KeyNegotiationError::ConfirmationTimeoutOutOfRange { .. })
        ));
    }
}

/// L'engagement remplace une empreinte stable : deux négociations avec le
/// **même** PSK ne produisent pas la même valeur, donc rien à corréler.
#[test]
fn the_static_psk_commitment_differs_across_transactions() {
    let psk = STANDARD.encode([7u8; STATIC_PSK_LEN]);
    let first = static_psk_commitment(
        &psk,
        &[1; KEY_NEGOTIATION_NONCE_LEN],
        &[2; KEY_NEGOTIATION_NONCE_LEN],
        &challenge(),
        CLIENT_WG_KEY,
        GATEWAY_WG_KEY,
    )
    .unwrap();
    assert_eq!(first.len(), 64);
    assert!(!first.contains(&psk));

    // Chaque composante du contexte, changée seule, change l'engagement.
    let other_transaction = static_psk_commitment(
        &psk,
        &[9; KEY_NEGOTIATION_NONCE_LEN],
        &[2; KEY_NEGOTIATION_NONCE_LEN],
        &challenge(),
        CLIENT_WG_KEY,
        GATEWAY_WG_KEY,
    )
    .unwrap();
    let other_challenge = static_psk_commitment(
        &psk,
        &[1; KEY_NEGOTIATION_NONCE_LEN],
        &[2; KEY_NEGOTIATION_NONCE_LEN],
        &[6; SERVER_CHALLENGE_LEN],
        CLIENT_WG_KEY,
        GATEWAY_WG_KEY,
    )
    .unwrap();
    let other_gateway = static_psk_commitment(
        &psk,
        &[1; KEY_NEGOTIATION_NONCE_LEN],
        &[2; KEY_NEGOTIATION_NONCE_LEN],
        &challenge(),
        CLIENT_WG_KEY,
        CLIENT_WG_KEY,
    )
    .unwrap();
    for different in [&other_transaction, &other_challenge, &other_gateway] {
        assert_ne!(&first, different);
    }

    // Le même contexte et le même PSK se recalculent à l'identique : c'est
    // ce qui permet à la gateway de vérifier.
    assert!(commitments_match(
        &first,
        &static_psk_commitment(
            &psk,
            &[1; KEY_NEGOTIATION_NONCE_LEN],
            &[2; KEY_NEGOTIATION_NONCE_LEN],
            &challenge(),
            CLIENT_WG_KEY,
            GATEWAY_WG_KEY,
        )
        .unwrap()
    ));
    assert!(!commitments_match(&first, &other_transaction));
}

/// Un PSK statique fait exactement 32 octets : ni 31, ni 33, ni une phrase.
#[test]
fn a_static_psk_is_exactly_thirty_two_bytes() {
    validate_static_psk(&STANDARD.encode([7u8; STATIC_PSK_LEN])).unwrap();
    for wrong in [
        STANDARD.encode([7u8; 31]),
        STANDARD.encode([7u8; 33]),
        STANDARD.encode(b"correct horse battery staple"),
        "not-base64!".to_string(),
        String::new(),
    ] {
        assert_eq!(
            validate_static_psk(&wrong).map(|_| ()),
            Err(KeyNegotiationError::InvalidStaticPsk),
            "{wrong} ne doit pas passer pour un PSK"
        );
    }
}

#[test]
fn unknown_fields_are_rejected() {
    let json = format!(
        r#"{{
                "protocol_version":5,
                "server_challenge":[{challenge}],
                "transaction_id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "mode":"classic",
                "client_wg_public_key":"{CLIENT_WG_KEY}",
                "gateway_wg_public_key":"{GATEWAY_WG_KEY}",
                "server_name":"{SERVER_NAME}",
                "gateway_certificate_fingerprint":"{GATEWAY_FINGERPRINT}",
                "client_nonce":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "timestamp_unix":1,
                "kem_public_key":null,
                "static_psk_commitment":null,
                "ignored":"downgrade"
            }}"#,
        challenge = vec!["5"; SERVER_CHALLENGE_LEN].join(",")
    );
    assert!(serde_json::from_str::<KeyNegotiationRequest>(&json).is_err());
}

#[test]
fn protection_floor_is_monotone() {
    assert!(ProtectionMode::MlKem.satisfies(ProtectionMode::Classic));
    assert!(ProtectionMode::MlKem.satisfies(ProtectionMode::StaticPsk));
    assert!(ProtectionMode::MlKem.satisfies(ProtectionMode::MlKem));
    assert!(!ProtectionMode::Classic.satisfies(ProtectionMode::StaticPsk));
    assert!(!ProtectionMode::Classic.satisfies(ProtectionMode::MlKem));
    assert!(!ProtectionMode::StaticPsk.satisfies(ProtectionMode::MlKem));
}

#[cfg(feature = "key-negotiation-signing")]
fn pq_certificate(
    role: PqCertificateRole,
    subject: &str,
    wireguard_key: &str,
    subject_public_key: &[u8],
    issuer_private_key: &[u8],
) -> PqCertificate {
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [7; 16],
            subject: subject.into(),
            issuer: "test-ca".into(),
            role,
            wireguard_public_key: wireguard_key.into(),
            ml_dsa_87_public_key: STANDARD.encode(subject_public_key),
            not_before_unix: 1,
            not_after_unix: u64::MAX,
            ml_dsa_87_signature: String::new(),
        },
        issuer_private_key,
    )
    .unwrap()
}

/// The leaf a gateway with no trust domain serves: the issuer **is** the
/// subject, so the pinned bytes are the whole of the trust.
///
/// [`pq_certificate`] always writes `test-ca` as the issuer, which is
/// right for a client leaf and wrong for this one: a certificate that
/// names an authority it was not signed by is not a shape any gateway
/// serves, and a fixture that carries it hides which of the two paths a
/// verification took.
#[cfg(feature = "key-negotiation-signing")]
fn self_signed_gateway_certificate(
    subject: &str,
    wireguard_key: &str,
    subject_public_key: &[u8],
    subject_private_key: &[u8],
) -> PqCertificate {
    issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [9; 16],
            subject: subject.into(),
            issuer: subject.into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: wireguard_key.into(),
            ml_dsa_87_public_key: STANDARD.encode(subject_public_key),
            not_before_unix: 1,
            not_after_unix: u64::MAX,
            ml_dsa_87_signature: String::new(),
        },
        subject_private_key,
    )
    .unwrap()
}

/// A `CA-PQ` signature is refused when its external context is not the
/// one of §8, however valid the arithmetic is.
///
/// The transcript prefix cannot catch this: the bytes signed here are
/// exactly the ones a conforming issuer signs. Only the context differs —
/// empty in the first case, another type's in the second — and that is the
/// whole point of carrying it outside `M`.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn a_certificate_signed_outside_its_context_is_refused() {
    use fips204::{ml_dsa_87::PrivateKey, traits::Signer as _};

    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let (_, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    certificate
        .verify(
            &ca_public,
            PqCertificateRole::Client,
            Some("orion"),
            CLIENT_WG_KEY,
            test_now(),
        )
        .expect("the conforming context verifies");

    let transcript = pq_certificate_signing_bytes(&certificate).unwrap();
    let issuer = PrivateKey::try_from_bytes(
        <[u8; ml_dsa_87::SK_LEN]>::try_from(ca_private.as_slice()).unwrap(),
    )
    .unwrap();
    for context in [b"".as_slice(), PQ_REQUEST_DOMAIN] {
        let mut forged = certificate.clone();
        forged.ml_dsa_87_signature =
            STANDARD.encode(issuer.try_sign(&transcript, context).unwrap());
        assert_eq!(
            forged.verify(
                &ca_public,
                PqCertificateRole::Client,
                Some("orion"),
                CLIENT_WG_KEY,
                test_now(),
            ),
            Err(KeyNegotiationError::InvalidPqCertificateSignature)
        );
    }
}

/// Le pire cas ML-DSA-87 doit tenir sous la borne de trame — vérifié, pas
/// déduit d'un calcul au dos d'une enveloppe.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn the_worst_case_frame_fits_the_bound() {
    let (ca_private, _) = generate_ml_dsa_87_keypair().unwrap();
    let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    let mut plain = request(ProtectionMode::MlKem);
    plain.kem_public_key = Some(vec![0xff; crate::pq::PUBLIC_KEY_LEN]);
    let authenticated =
        authenticate_request(plain, certificate, client_private.as_slice()).unwrap();
    let encoded = serde_json::to_vec(&authenticated).unwrap();
    assert!(
        encoded.len() < MAX_KEY_NEGOTIATION_MESSAGE_BYTES,
        "la requête ml_kem pèse {} octets, borne {MAX_KEY_NEGOTIATION_MESSAGE_BYTES}",
        encoded.len()
    );
}

#[cfg(feature = "key-negotiation-signing")]
#[test]
fn editing_the_timestamp_breaks_pq_authentication() {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    let fingerprint = certificate.fingerprint().unwrap();
    let mut authenticated = authenticate_request(
        request(ProtectionMode::StaticPsk),
        certificate,
        client_private.as_slice(),
    )
    .unwrap();
    authenticated
        .verify(&ca_public, &fingerprint, test_now())
        .unwrap();

    authenticated.request.timestamp_unix += 1;
    assert_eq!(
        authenticated.verify(&ca_public, &fingerprint, test_now()),
        Err(KeyNegotiationError::InvalidPqProtocolSignature)
    );
}

/// A renewed leaf is signed by the delegated issuer, not by the anchor
/// the first generation chained to.
///
/// A gateway holding one issuer would refuse every client it has itself
/// renewed — at the end of the overlap, on a machine whose only way to ask
/// about it was the tunnel it can no longer open.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn a_leaf_signed_by_the_second_issuer_is_accepted() {
    let (anchor_private, anchor_public) = generate_ml_dsa_87_keypair().unwrap();
    let (delegated_private, delegated_public) = generate_ml_dsa_87_keypair().unwrap();
    let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        delegated_private.as_slice(),
    );
    let fingerprint = certificate.fingerprint().unwrap();
    let authenticated = authenticate_request(
        request(ProtectionMode::StaticPsk),
        certificate,
        client_private.as_slice(),
    )
    .unwrap();

    // The anchor alone refuses it, which is the whole reason the set
    // exists.
    assert!(authenticated
        .verify(&anchor_public, &fingerprint, test_now())
        .is_err());
    authenticated
        .verify_against(
            &[&anchor_public, &delegated_public],
            &[&fingerprint],
            test_now(),
        )
        .unwrap();
    let _ = anchor_private;
}

/// The fingerprint decides before any signature is verified.
///
/// Each issuer trial is an ML-DSA-87 verification; the digest is a hash.
/// A caller presenting a leaf this gateway never issued must buy the hash
/// and nothing more, however many issuers the domain admits.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn a_fingerprint_that_is_not_admitted_is_refused_before_any_issuer_is_tried() {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    let authenticated = authenticate_request(
        request(ProtectionMode::StaticPsk),
        certificate,
        client_private.as_slice(),
    )
    .unwrap();

    assert_eq!(
        authenticated.verify_against(&[&ca_public], &["00".repeat(32).as_str()], test_now()),
        Err(KeyNegotiationError::PqCertificateFingerprintMismatch)
    );
}

/// An unknown peer must not be an unauthenticated one: empty sets refuse.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn empty_issuer_and_fingerprint_sets_refuse_everything() {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    let fingerprint = certificate.fingerprint().unwrap();
    let authenticated = authenticate_request(
        request(ProtectionMode::StaticPsk),
        certificate,
        client_private.as_slice(),
    )
    .unwrap();

    assert_eq!(
        authenticated.verify_against(&[&ca_public], &[], test_now()),
        Err(KeyNegotiationError::PqCertificateFingerprintMismatch)
    );
    assert!(authenticated
        .verify_against(&[], &[&fingerprint], test_now())
        .is_err());
}

/// La liaison à la gateway est **signée** : la retoucher pour viser une
/// autre gateway invalide la requête avant toute pose de slot.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn retargeting_a_request_to_another_gateway_breaks_its_signature() {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    let fingerprint = certificate.fingerprint().unwrap();
    let authenticated = authenticate_request(
        request(ProtectionMode::StaticPsk),
        certificate,
        client_private.as_slice(),
    )
    .unwrap();
    authenticated
        .verify(&ca_public, &fingerprint, test_now())
        .unwrap();

    for retarget in [
        |r: &mut KeyNegotiationRequest| r.server_name = "other.example".into(),
        |r: &mut KeyNegotiationRequest| r.gateway_wg_public_key = CLIENT_WG_KEY.into(),
        |r: &mut KeyNegotiationRequest| r.gateway_certificate_fingerprint = "2".repeat(64),
    ] {
        let mut tampered = authenticated.clone();
        retarget(&mut tampered.request);
        assert_eq!(
            tampered.verify(&ca_public, &fingerprint, test_now()),
            Err(KeyNegotiationError::InvalidPqProtocolSignature)
        );
    }
}

/// Le challenge est signé : le remplacer par un autre, même valide
/// ailleurs, invalide la requête.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn substituting_the_challenge_breaks_pq_authentication() {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    let fingerprint = certificate.fingerprint().unwrap();
    let mut authenticated = authenticate_request(
        request(ProtectionMode::StaticPsk),
        certificate,
        client_private.as_slice(),
    )
    .unwrap();
    authenticated.request.server_challenge[0] ^= 1;
    assert_eq!(
        authenticated.verify(&ca_public, &fingerprint, test_now()),
        Err(KeyNegotiationError::InvalidPqProtocolSignature)
    );
}

#[cfg(feature = "key-negotiation-signing")]
#[test]
fn substituting_the_ml_kem_public_key_breaks_pq_authentication() {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    let fingerprint = certificate.fingerprint().unwrap();
    let mut plain = request(ProtectionMode::MlKem);
    plain.kem_public_key = Some(vec![3; crate::pq::PUBLIC_KEY_LEN]);
    let mut authenticated =
        authenticate_request(plain, certificate, client_private.as_slice()).unwrap();
    authenticated
        .verify(&ca_public, &fingerprint, test_now())
        .unwrap();

    authenticated.request.kem_public_key.as_mut().unwrap()[0] ^= 1;
    assert_eq!(
        authenticated.verify(&ca_public, &fingerprint, test_now()),
        Err(KeyNegotiationError::InvalidPqProtocolSignature)
    );
}

#[cfg(feature = "key-negotiation-signing")]
#[test]
fn substituting_the_ml_kem_ciphertext_breaks_gateway_authentication() {
    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = self_signed_gateway_certificate(
        SERVER_NAME,
        GATEWAY_WG_KEY,
        &gateway_public,
        gateway_private.as_slice(),
    );
    let mut plain = request(ProtectionMode::MlKem);
    plain.kem_public_key = Some(vec![4; crate::pq::PUBLIC_KEY_LEN]);
    let mut answer = response(&plain, ProtectionMode::MlKem);
    answer.kem_ciphertext = Some(vec![5; crate::pq::CIPHERTEXT_LEN]);
    let mut authenticated =
        authenticate_response(answer, certificate.clone(), gateway_private.as_slice()).unwrap();
    authenticated
        .verify(&plain, &certificate, SERVER_NAME, GATEWAY_WG_KEY, None, 100)
        .unwrap();

    authenticated.response.kem_ciphertext.as_mut().unwrap()[0] ^= 1;
    assert_eq!(
        authenticated.verify(&plain, &certificate, SERVER_NAME, GATEWAY_WG_KEY, None, 100),
        Err(KeyNegotiationError::InvalidPqProtocolSignature)
    );
}

/// The shape a gateway serves once it carries a trust domain (ADR-008
/// §13.1). Checking this leaf against its own subject key is what
/// `verify_self_signed` does, and it fails on every such gateway — which
/// is to say on every gateway an authority exists for.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn a_ca_issued_gateway_leaf_verifies_under_the_domain_anchor() {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Gateway,
        SERVER_NAME,
        GATEWAY_WG_KEY,
        &gateway_public,
        ca_private.as_slice(),
    );
    let mut plain = request(ProtectionMode::MlKem);
    plain.kem_public_key = Some(vec![4; crate::pq::PUBLIC_KEY_LEN]);
    let mut answer = response(&plain, ProtectionMode::MlKem);
    answer.kem_ciphertext = Some(vec![5; crate::pq::CIPHERTEXT_LEN]);
    let authenticated =
        authenticate_response(answer, certificate.clone(), gateway_private.as_slice()).unwrap();

    authenticated
        .verify(
            &plain,
            &certificate,
            SERVER_NAME,
            GATEWAY_WG_KEY,
            Some(ca_public.as_slice()),
            100,
        )
        .unwrap();
}

/// Refused, rather than checked against itself. A peer that holds no
/// anchor has nothing to verify a delegated leaf with, and falling back to
/// the subject key would accept any leaf naming any authority.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn a_ca_issued_gateway_leaf_is_refused_without_an_anchor() {
    let (ca_private, _) = generate_ml_dsa_87_keypair().unwrap();
    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Gateway,
        SERVER_NAME,
        GATEWAY_WG_KEY,
        &gateway_public,
        ca_private.as_slice(),
    );
    let mut plain = request(ProtectionMode::MlKem);
    plain.kem_public_key = Some(vec![4; crate::pq::PUBLIC_KEY_LEN]);
    let mut answer = response(&plain, ProtectionMode::MlKem);
    answer.kem_ciphertext = Some(vec![5; crate::pq::CIPHERTEXT_LEN]);
    let authenticated =
        authenticate_response(answer, certificate.clone(), gateway_private.as_slice()).unwrap();

    assert_eq!(
        authenticated.verify(&plain, &certificate, SERVER_NAME, GATEWAY_WG_KEY, None, 100),
        Err(KeyNegotiationError::MissingPqCertificateAnchor)
    );
}

/// Another domain's anchor is not this domain's. The fingerprint of the
/// pinned leaf still matches, so only the issuer signature separates the
/// two — which is exactly what must be checked.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn a_ca_issued_gateway_leaf_is_refused_under_a_foreign_anchor() {
    let (ca_private, _) = generate_ml_dsa_87_keypair().unwrap();
    let (_, foreign_public) = generate_ml_dsa_87_keypair().unwrap();
    let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Gateway,
        SERVER_NAME,
        GATEWAY_WG_KEY,
        &gateway_public,
        ca_private.as_slice(),
    );
    let mut plain = request(ProtectionMode::MlKem);
    plain.kem_public_key = Some(vec![4; crate::pq::PUBLIC_KEY_LEN]);
    let mut answer = response(&plain, ProtectionMode::MlKem);
    answer.kem_ciphertext = Some(vec![5; crate::pq::CIPHERTEXT_LEN]);
    let authenticated =
        authenticate_response(answer, certificate.clone(), gateway_private.as_slice()).unwrap();

    assert_eq!(
        authenticated.verify(
            &plain,
            &certificate,
            SERVER_NAME,
            GATEWAY_WG_KEY,
            Some(foreign_public.as_slice()),
            100,
        ),
        Err(KeyNegotiationError::InvalidPqCertificateSignature)
    );
}

/// The in-tunnel `release` is authenticated like a request, and its
/// signature domain differs from the removed QUIC message: the same
/// command cannot be replayed from one transport to the other.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn an_in_tunnel_release_is_authenticated_and_bound_to_its_transaction() {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let (client_private, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let client_certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    let fingerprint = client_certificate.fingerprint().unwrap();

    let release = PskRelease {
        protocol_version: KEY_NEGOTIATION_VERSION,
        installed_transaction_id: [4; KEY_NEGOTIATION_NONCE_LEN],
        client_wg_public_key: CLIENT_WG_KEY.into(),
        gateway_wg_public_key: GATEWAY_WG_KEY.into(),
    };
    let mut authenticated = authenticate_release(
        release.clone(),
        client_certificate.clone(),
        client_private.as_slice(),
    )
    .unwrap();
    authenticated
        .verify(&ca_public, &fingerprint, test_now())
        .unwrap();

    // The domain binds the transport: a signature produced over the old
    // public QUIC message bytes is invalid here.
    let mut public_domain_bytes = pq_release_signing_bytes(&release, &client_certificate)
        .unwrap()
        .split_off(PQ_IN_TUNNEL_RELEASE_DOMAIN.len());
    const PUBLIC_RELEASE_DOMAIN: &[u8] = b"helios-key-negotiation-pq-release-v5";
    let mut rebuilt = PUBLIC_RELEASE_DOMAIN.to_vec();
    rebuilt.append(&mut public_domain_bytes);
    // The retired public message is not merely invalid when presented to
    // the in-tunnel verifier: its context is absent from the exhaustive v5
    // registry, so no conforming signing path can mint it anymore.
    assert_eq!(
        sign_ml_dsa_87(client_private.as_slice(), PUBLIC_RELEASE_DOMAIN, &rebuilt),
        Err(KeyNegotiationError::InvalidPqProtocolSignature)
    );

    // Redirecting a release to another transaction breaks its signature.
    authenticated.release.installed_transaction_id[0] ^= 1;
    assert_eq!(
        authenticated.verify(&ca_public, &fingerprint, test_now()),
        Err(KeyNegotiationError::InvalidPqProtocolSignature)
    );
}

/// §8.4 byte for byte: three 32-byte binary values, without a length prefix
/// or base64/hexadecimal text.
///
/// This check is deliberately explicit: the four neighboring messages sign
/// the textual form with a `u32` length, and nothing else prevents this one
/// from being aligned with them by imitation. The assertion makes the
/// difference visible rather than merely plausible.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn the_in_tunnel_release_signs_decoded_thirty_two_byte_values() {
    let (ca_private, _) = generate_ml_dsa_87_keypair().unwrap();
    let (_, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    let release = PskRelease {
        protocol_version: KEY_NEGOTIATION_VERSION,
        installed_transaction_id: [4; KEY_NEGOTIATION_NONCE_LEN],
        client_wg_public_key: CLIENT_WG_KEY.into(),
        gateway_wg_public_key: GATEWAY_WG_KEY.into(),
    };

    let mut expected = Vec::new();
    expected.extend_from_slice(PQ_IN_TUNNEL_RELEASE_DOMAIN);
    expected.extend_from_slice(&KEY_NEGOTIATION_VERSION.to_be_bytes());
    expected.extend_from_slice(&[4; KEY_NEGOTIATION_NONCE_LEN]);
    expected.extend_from_slice(&STANDARD.decode(CLIENT_WG_KEY).unwrap());
    expected.extend_from_slice(&STANDARD.decode(GATEWAY_WG_KEY).unwrap());
    expected.extend_from_slice(&hex::decode(certificate.fingerprint().unwrap()).unwrap());

    assert_eq!(
        pq_release_signing_bytes(&release, &certificate).unwrap(),
        expected
    );
    assert_eq!(
        expected.len(),
        PQ_IN_TUNNEL_RELEASE_DOMAIN.len() + 2 + KEY_NEGOTIATION_NONCE_LEN + 3 * 32
    );
}

/// A key with an invalid length is rejected before signing rather than
/// encoded as-is; this is the counterpart of decoding.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn a_release_naming_an_undecodable_key_cannot_be_signed() {
    let (ca_private, _) = generate_ml_dsa_87_keypair().unwrap();
    let (_, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    let release = PskRelease {
        protocol_version: KEY_NEGOTIATION_VERSION,
        installed_transaction_id: [4; KEY_NEGOTIATION_NONCE_LEN],
        client_wg_public_key: "AAAA".into(),
        gateway_wg_public_key: GATEWAY_WG_KEY.into(),
    };
    assert_eq!(
        pq_release_signing_bytes(&release, &certificate),
        Err(KeyNegotiationError::InvalidWireGuardKey)
    );
}

/// Un certificat v1 (ML-DSA-65) n'est pas lu comme un certificat v5 : la
/// migration réémet, elle ne tolère pas.
#[cfg(feature = "key-negotiation-signing")]
#[test]
fn a_version_one_certificate_is_refused() {
    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().unwrap();
    let (_, client_public) = generate_ml_dsa_87_keypair().unwrap();
    let mut certificate = pq_certificate(
        PqCertificateRole::Client,
        "orion",
        CLIENT_WG_KEY,
        &client_public,
        ca_private.as_slice(),
    );
    certificate.version = 1;
    assert_eq!(
        certificate.verify(
            &ca_public,
            PqCertificateRole::Client,
            None,
            CLIENT_WG_KEY,
            test_now()
        ),
        Err(KeyNegotiationError::InvalidPqCertificate)
    );
}

/// Negotiation values both ends compute independently, from constant inputs,
/// and the values they must keep.
///
/// The gateway and Orion each derive the WireGuard PSK from the ML-KEM secret
/// and the transcript, each compute the static-PSK commitment, and each name a
/// PQ leaf by its fingerprint. A tunnel comes up only if both sides agree to
/// the byte. Every other test here compares two values produced by the same
/// code, so a refactor that moved a byte of a transcript — splitting this
/// module included — would pass them all. A change of these values breaks
/// interoperability with deployed peers and needs new domains.
#[test]
fn the_negotiation_values_are_pinned() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let pattern =
        |seed: u8| -> [u8; 32] { std::array::from_fn(|i| seed.wrapping_add(i as u8 * 7)) };
    let client_key = STANDARD.encode(pattern(1));
    let gateway_key = STANDARD.encode(pattern(2));

    let certificate = PqCertificate {
        version: PQ_CERTIFICATE_VERSION,
        serial: [3; KEY_NEGOTIATION_NONCE_LEN],
        subject: "gateway.example".into(),
        issuer: "CA-PQ".into(),
        role: PqCertificateRole::Gateway,
        wireguard_public_key: gateway_key.clone(),
        ml_dsa_87_public_key: STANDARD.encode([4; ML_DSA_87_PUBLIC_KEY_LEN]),
        not_before_unix: 0,
        not_after_unix: 100_000,
        ml_dsa_87_signature: STANDARD.encode([5; ML_DSA_87_SIGNATURE_LEN]),
    };

    let commitment = static_psk_commitment(
        &STANDARD.encode(pattern(6)),
        &[7; KEY_NEGOTIATION_NONCE_LEN],
        &[8; KEY_NEGOTIATION_NONCE_LEN],
        &[9; SERVER_CHALLENGE_LEN],
        &client_key,
        &gateway_key,
    )
    .expect("a well-formed static PSK has a commitment");

    let request = KeyNegotiationRequest {
        protocol_version: KEY_NEGOTIATION_VERSION,
        server_challenge: [9; SERVER_CHALLENGE_LEN],
        transaction_id: [7; KEY_NEGOTIATION_NONCE_LEN],
        mode: ProtectionMode::MlKem,
        client_wg_public_key: client_key.clone(),
        gateway_wg_public_key: gateway_key.clone(),
        server_name: "gateway.example".into(),
        gateway_certificate_fingerprint: certificate.fingerprint().expect("fingerprint"),
        client_nonce: [8; KEY_NEGOTIATION_NONCE_LEN],
        timestamp_unix: 1_000,
        kem_public_key: Some(vec![12; crate::pq::PUBLIC_KEY_LEN]),
        static_psk_commitment: None,
    };
    let response = KeyNegotiationResponse {
        protocol_version: KEY_NEGOTIATION_VERSION,
        transaction_id: [7; KEY_NEGOTIATION_NONCE_LEN],
        server_challenge: [9; SERVER_CHALLENGE_LEN],
        selected_mode: ProtectionMode::MlKem,
        gateway_wg_public_key: gateway_key.clone(),
        client_wg_public_key: client_key.clone(),
        gateway_nonce: [10; KEY_NEGOTIATION_NONCE_LEN],
        kem_ciphertext: Some(vec![13; crate::pq::CIPHERTEXT_LEN]),
        confirmation_timeout_secs: 30,
        psk_lifetime_secs: NEGOTIATED_PSK_LIFETIME_SECS,
    };
    let psk = derive_negotiated_psk(&Zeroizing::new(pattern(11)), &request, &response)
        .expect("a consistent ML-KEM transcript derives a PSK");

    assert_eq!(
        [
            certificate.fingerprint().expect("fingerprint"),
            commitment,
            STANDARD.encode(*psk),
        ],
        [
            "83dd514cedec29d8fdc92dc7a6c7439ece2b95d3c804da563ffbea8ef2b29c26",
            "4e713cdfb69656e29b1ad1f93ef657f71a3791b5a79b5e09b3886bd0335de0e5",
            "c3RJcdp39JblINzZ/EnxzMlVv6YzUkHVeZhvG0RHWtw=",
        ]
    );
}

#[test]
fn renewal_thresholds_sit_at_eighty_percent_of_each_bound() {
    assert_eq!(NEGOTIATED_PSK_BYTE_LIMIT, 100 * 1024 * 1024 * 1024);
    assert_eq!(
        psk_renewal_after_secs(),
        69_120,
        "19 h 12 of a 24 h lifetime"
    );
    assert_eq!(
        psk_renewal_after_bytes(),
        85_899_345_920,
        "80 GiB of 100 GiB"
    );
    assert!(psk_renewal_after_secs() < u64::from(NEGOTIATED_PSK_LIFETIME_SECS));
    assert!(psk_renewal_after_bytes() < NEGOTIATED_PSK_BYTE_LIMIT);
}
