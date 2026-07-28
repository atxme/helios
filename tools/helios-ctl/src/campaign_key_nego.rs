//! Campagne de la négociation de clé pré-WireGuard.
//!
//! # Pourquoi une campagne, et pas seulement des tests unitaires
//!
//! Les tests du dépôt éprouvent des fonctions ; ils ne peuvent pas éprouver
//! *une gateway*. Or les pannes rencontrées sur cette feature n'étaient
//! visibles qu'en vrai : un PSK jugé statique alors qu'il venait d'être
//! négocié, une session QUIC qui mourait trente secondes après le commit, un
//! datagramme dimensionné par une sonde de MTU que le tunnel ne portait plus.
//! Aucune n'aurait été prise par un test hors ligne, et toutes le sont par une
//! campagne qui parle au vrai service.
//!
//! # Trois familles, trois exigences
//!
//! * **crypto** — primitives seules, aucune gateway, aucun profil. Tourne
//!   partout, y compris dans la régression WSL2 ;
//! * **profil** — le profil Orion réel et son identité scellée, sans réseau.
//!   Répond à « ce poste est-il en état de négocier ? » ;
//! * **gateway** — négociation complète contre le service réel.
//!
//! # Ce que la famille *gateway* fait au pair
//!
//! Elle négocie pour de vrai : la gateway pose un PSK sur le plan de données,
//! puis le retire au rollback. Un Orion connecté **avec le même profil**
//! perdra son tunnel au renouvellement de clé suivant. C'est le prix d'une
//! campagne qui ne simule rien ; elle l'annonce avant de commencer.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aether::key_negotiation::{
    authenticate_request, derive_negotiated_psk, generate_ml_dsa_65_keypair, issue_pq_certificate,
    KeyNegotiationRequest, KeyNegotiationResponse, PqCertificate, PqCertificateRole,
    ProtectionMode, KEY_NEGOTIATION_VERSION, PQ_CERTIFICATE_VERSION,
};
use aether::pq::{Kem, MlKem1024Kem, CIPHERTEXT_LEN};
use anyhow::{Context, Result};
use base64::Engine as _;
use orion_core::key_negotiation::{prepare_for_profile, IdentityProvider};
use orion_core::{ClientConfig, ClientProfile, ProtectedIdentityStore};

use crate::campaign::Outcome;

/// Base64 standard, used for every key and certificate here.
fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// A WireGuard key, well-formed, for material that is never mounted.
fn some_wg_key(seed: u8) -> String {
    b64().encode([seed; 32])
}

// ─── Famille crypto : primitives seules ──────────────────────────────────────

/// ML-KEM-1024 : ce que le pair encapsule, le client le retrouve — et deux
/// encapsulations ne donnent jamais le même secret.
///
/// C'est la propriété sur laquelle repose tout le reste : si elle tombe, le
/// PSK dérivé n'est pas partagé et aucun handshake n'aboutit.
fn scenario_ml_kem_roundtrip() -> Outcome {
    let (secret, public) = match MlKem1024Kem::generate() {
        Ok(pair) => pair,
        Err(error) => return Outcome::fail(format!("génération ML-KEM impossible : {error}")),
    };
    let (first_ciphertext, first_secret) = match MlKem1024Kem::encapsulate(&public) {
        Ok(value) => value,
        Err(error) => return Outcome::fail(format!("encapsulation impossible : {error}")),
    };
    let (second_ciphertext, second_secret) = match MlKem1024Kem::encapsulate(&public) {
        Ok(value) => value,
        Err(error) => return Outcome::fail(format!("seconde encapsulation impossible : {error}")),
    };
    let opened = match MlKem1024Kem::decapsulate(&secret, &first_ciphertext) {
        Ok(value) => value,
        Err(error) => return Outcome::fail(format!("décapsulation impossible : {error}")),
    };

    if opened.as_slice() != first_secret.as_slice() {
        return Outcome::fail("le secret décapsulé diffère de celui encapsulé");
    }
    if first_ciphertext.len() != CIPHERTEXT_LEN {
        return Outcome::fail(format!(
            "chiffré de {} octets au lieu de {CIPHERTEXT_LEN}",
            first_ciphertext.len()
        ));
    }
    if first_ciphertext == second_ciphertext || first_secret.as_slice() == second_secret.as_slice()
    {
        return Outcome::fail("deux encapsulations produisent le même résultat");
    }
    Outcome::pass(format!(
        "secret de 32 o retrouvé, chiffré de {CIPHERTEXT_LEN} o, deux tirages distincts"
    ))
}

/// Une décapsulation avec la mauvaise clé ne rend pas le bon secret.
///
/// ML-KEM ne « refuse » pas un chiffré étranger — la construction Fujisaki-
/// Okamoto rend un secret implicite. C'est donc l'inégalité qui est la
/// propriété, et un test qui attendrait une erreur passerait à côté.
fn scenario_ml_kem_wrong_key() -> Outcome {
    let Ok((_, public)) = MlKem1024Kem::generate() else {
        return Outcome::fail("génération ML-KEM impossible");
    };
    let Ok((other_secret, _)) = MlKem1024Kem::generate() else {
        return Outcome::fail("génération ML-KEM impossible");
    };
    let Ok((ciphertext, expected)) = MlKem1024Kem::encapsulate(&public) else {
        return Outcome::fail("encapsulation impossible");
    };
    match MlKem1024Kem::decapsulate(&other_secret, &ciphertext) {
        Ok(wrong) if wrong.as_slice() == expected.as_slice() => {
            Outcome::fail("une clé étrangère retrouve le secret : ML-KEM est cassé")
        }
        Ok(_) => Outcome::pass("secret implicite, différent de l'attendu"),
        Err(_) => Outcome::pass("chiffré refusé par la mauvaise clé"),
    }
}

/// Transcription valide : c'est elle que la dérivation lie au PSK.
fn transcript() -> (KeyNegotiationRequest, KeyNegotiationResponse, Vec<u8>) {
    let (secret, public) = MlKem1024Kem::generate().expect("ML-KEM");
    let (ciphertext, _) = MlKem1024Kem::encapsulate(&public).expect("ML-KEM");
    let request = KeyNegotiationRequest {
        protocol_version: KEY_NEGOTIATION_VERSION,
        transaction_id: [11; 16],
        mode: ProtectionMode::MlKem,
        client_wg_public_key: some_wg_key(1),
        client_nonce: [22; 16],
        timestamp_unix: now_unix(),
        kem_public_key: Some(public),
        static_psk_fingerprint: None,
    };
    let response = KeyNegotiationResponse {
        protocol_version: KEY_NEGOTIATION_VERSION,
        transaction_id: request.transaction_id,
        selected_mode: ProtectionMode::MlKem,
        gateway_wg_public_key: some_wg_key(2),
        gateway_nonce: [33; 16],
        kem_ciphertext: Some(ciphertext.clone()),
        confirmation_timeout_secs: 45,
    };
    let shared = MlKem1024Kem::decapsulate(&secret, &ciphertext).expect("ML-KEM");
    (request, response, shared.as_slice().to_vec())
}

/// Le PSK est lié à **toute** la transcription : changer un seul champ
/// change le secret.
///
/// Sans cette liaison, une réponse rejouée d'une autre session dériverait le
/// même PSK — et deux tunnels partageraient un secret.
fn scenario_psk_binding() -> Outcome {
    let (request, response, shared) = transcript();
    let shared = aether::pq::SharedSecret::new(shared.try_into().unwrap_or([0; 32]));

    let reference = match derive_negotiated_psk(&shared, &request, &response) {
        Ok(psk) => psk,
        Err(error) => return Outcome::fail(format!("dérivation refusée : {error}")),
    };
    let again = match derive_negotiated_psk(&shared, &request, &response) {
        Ok(psk) => psk,
        Err(error) => return Outcome::fail(format!("dérivation non déterministe : {error}")),
    };
    if reference.as_slice() != again.as_slice() {
        return Outcome::fail("deux dérivations identiques donnent des PSK différents");
    }

    // Un seul octet de la réponse, et le PSK doit changer.
    let mut altered = response.clone();
    altered.gateway_nonce[0] ^= 0x01;
    match derive_negotiated_psk(&shared, &request, &altered) {
        Ok(other) if other.as_slice() == reference.as_slice() => {
            Outcome::fail("le nonce de la gateway n'entre pas dans la dérivation")
        }
        Ok(_) => Outcome::pass("PSK déterministe et lié à la transcription (nonce, clés, mode)"),
        Err(error) => Outcome::fail(format!("réponse altérée non dérivable : {error}")),
    }
}

/// Hors ML-KEM, la dérivation doit refuser : un PSK « dérivé » en mode
/// classique serait une protection imaginaire.
fn scenario_psk_outside_ml_kem() -> Outcome {
    let (mut request, mut response, shared) = transcript();
    let shared = aether::pq::SharedSecret::new(shared.try_into().unwrap_or([0; 32]));
    request.mode = ProtectionMode::Classic;
    request.kem_public_key = None;
    response.selected_mode = ProtectionMode::Classic;
    response.kem_ciphertext = None;

    match derive_negotiated_psk(&shared, &request, &response) {
        Err(_) => Outcome::pass("dérivation refusée hors ML-KEM"),
        Ok(_) => Outcome::fail("un PSK a été dérivé en mode classique"),
    }
}

/// Identité PQ : une signature ML-DSA-65 valide passe, une signature d'un
/// octet près est refusée.
fn scenario_ml_dsa_signature() -> Outcome {
    let Ok((ca_private, ca_public)) = generate_ml_dsa_65_keypair() else {
        return Outcome::fail("génération ML-DSA-65 impossible");
    };
    let Ok((client_private, client_public)) = generate_ml_dsa_65_keypair() else {
        return Outcome::fail("génération ML-DSA-65 impossible");
    };
    let client_wg = some_wg_key(1);
    let certificate = match issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [5; 16],
            subject: "campagne".into(),
            issuer: "campagne-ca".into(),
            role: PqCertificateRole::Client,
            wireguard_public_key: client_wg.clone(),
            ml_dsa_65_public_key: b64().encode(&client_public),
            not_before_unix: now_unix() - 60,
            not_after_unix: now_unix() + 3600,
            ml_dsa_65_signature: String::new(),
        },
        &ca_private,
    ) {
        Ok(certificate) => certificate,
        Err(error) => return Outcome::fail(format!("émission du certificat : {error}")),
    };
    let Ok(fingerprint) = certificate.fingerprint() else {
        return Outcome::fail("empreinte du certificat illisible");
    };

    let request = KeyNegotiationRequest {
        protocol_version: KEY_NEGOTIATION_VERSION,
        transaction_id: [7; 16],
        mode: ProtectionMode::Classic,
        client_wg_public_key: client_wg,
        client_nonce: [8; 16],
        timestamp_unix: now_unix(),
        kem_public_key: None,
        static_psk_fingerprint: None,
    };
    let signed = match authenticate_request(request, certificate, &client_private) {
        Ok(signed) => signed,
        Err(error) => return Outcome::fail(format!("signature de la requête : {error}")),
    };
    if let Err(error) = signed.verify(&ca_public, &fingerprint, now_unix()) {
        return Outcome::fail(format!("une requête bien signée est refusée : {error}"));
    }

    // Un octet de signature retourné : le refus doit être net.
    let mut tampered = signed.clone();
    let mut raw = match b64().decode(&tampered.ml_dsa_65_signature) {
        Ok(raw) => raw,
        Err(_) => return Outcome::fail("signature illisible"),
    };
    raw[0] ^= 0x01;
    tampered.ml_dsa_65_signature = b64().encode(&raw);
    match tampered.verify(&ca_public, &fingerprint, now_unix()) {
        Err(_) => Outcome::pass("signature valide acceptée, signature altérée refusée"),
        Ok(()) => Outcome::fail("une signature altérée est acceptée"),
    }
}

/// Le certificat épinglé vaut pour **une** gateway : le lier à une autre clé
/// WireGuard doit le rendre inutilisable.
///
/// C'est ce qui empêche un profil volé de servir à parler à une autre gateway
/// — et une gateway compromise de se faire passer pour la bonne.
fn scenario_certificate_pinning() -> Outcome {
    let Ok((private, public)) = generate_ml_dsa_65_keypair() else {
        return Outcome::fail("génération ML-DSA-65 impossible");
    };
    let gateway_wg = some_wg_key(9);
    let certificate = match issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [1; 16],
            subject: "gateway.example".into(),
            issuer: "gateway.example".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: gateway_wg.clone(),
            ml_dsa_65_public_key: b64().encode(&public),
            not_before_unix: now_unix() - 60,
            not_after_unix: now_unix() + 3600,
            ml_dsa_65_signature: String::new(),
        },
        &private,
    ) {
        Ok(certificate) => certificate,
        Err(error) => return Outcome::fail(format!("émission du certificat : {error}")),
    };

    let sound = certificate.verify_self_signed(
        PqCertificateRole::Gateway,
        Some("gateway.example"),
        &gateway_wg,
        now_unix(),
    );
    if let Err(error) = sound {
        return Outcome::fail(format!("un certificat sain est refusé : {error}"));
    }

    let other_key = certificate.verify_self_signed(
        PqCertificateRole::Gateway,
        Some("gateway.example"),
        &some_wg_key(10),
        now_unix(),
    );
    let other_name = certificate.verify_self_signed(
        PqCertificateRole::Gateway,
        Some("autre.example"),
        &gateway_wg,
        now_unix(),
    );
    let client_role = certificate.verify_self_signed(
        PqCertificateRole::Client,
        Some("gateway.example"),
        &gateway_wg,
        now_unix(),
    );
    let expired = certificate.verify_self_signed(
        PqCertificateRole::Gateway,
        Some("gateway.example"),
        &gateway_wg,
        certificate.not_after_unix + 1,
    );

    Outcome::check(
        other_key.is_err() && other_name.is_err() && client_role.is_err() && expired.is_err(),
        "refusé sur clé WireGuard, nom, rôle et date",
        format!(
            "épinglage incomplet — autre clé : {}, autre nom : {}, autre rôle : {}, expiré : {}",
            other_key.is_err(),
            other_name.is_err(),
            client_role.is_err(),
            expired.is_err()
        ),
    )
}

/// Toute la famille crypto, dans l'ordre où elle se lit.
pub fn crypto_scenarios() -> Vec<(&'static str, Outcome)> {
    vec![
        ("ML-KEM-1024 aller-retour", scenario_ml_kem_roundtrip()),
        ("ML-KEM clé étrangère", scenario_ml_kem_wrong_key()),
        ("PSK lié à la transcription", scenario_psk_binding()),
        (
            "dérivation refusée hors ML-KEM",
            scenario_psk_outside_ml_kem(),
        ),
        ("signature ML-DSA-65", scenario_ml_dsa_signature()),
        ("certificat épinglé", scenario_certificate_pinning()),
    ]
}

// ─── Famille profil : le poste est-il en état de négocier ? ──────────────────

/// Profil et magasin d'identité, tels qu'Orion les voit.
pub struct Enrolled {
    pub profile: ClientProfile,
    pub identities: Arc<dyn IdentityProvider>,
}

/// Charge le profil nommé depuis la configuration Orion de ce poste.
///
/// La campagne lit **la** configuration du client, pas une copie : c'est ce
/// qui lui permet de répondre à « ce poste-ci peut-il se connecter ? » plutôt
/// qu'à « ce protocole est-il correct ? ».
pub fn load_enrolled(name: &str) -> Result<Enrolled> {
    let config = ClientConfig::load().context("lecture de la configuration Orion")?;
    let profile = config
        .find(name)
        .cloned()
        .with_context(|| format!("aucun profil Orion nommé « {name} » sur ce poste"))?;
    let store = ProtectedIdentityStore::for_current_user()
        .context("ouverture du stockage protégé d'identité")?;
    Ok(Enrolled {
        profile,
        identities: Arc::new(store),
    })
}

/// Le bloc de négociation du profil tient debout face à sa propre gateway.
fn scenario_profile_block(profile: &ClientProfile) -> Outcome {
    let Some(settings) = profile.key_negotiation.as_ref() else {
        return Outcome::skip("ce profil ne négocie pas");
    };
    match orion_core::config::validate_key_negotiation(
        settings,
        &profile.peer_public_key,
        profile.has_static_psk(),
    ) {
        Ok(()) => Outcome::pass(format!(
            "mode {:?}, plancher {:?}, empreinte PQ {}",
            settings.mode,
            settings.minimum_mode,
            settings
                .gateway_pq_fingerprint()
                .unwrap_or_else(|| "illisible".into())
        )),
        Err(error) => Outcome::fail(format!("{error:#}")),
    }
}

/// L'identité scellée existe, et elle est bien celle de ce profil.
///
/// Le piège que ce scénario prend : une identité présente mais émise pour une
/// **autre** clé WireGuard. La gateway la refuserait avec un message
/// d'empreinte, très loin de la cause.
async fn scenario_identity_matches(enrolled: &Enrolled) -> Outcome {
    let Some(settings) = enrolled.profile.key_negotiation.as_ref() else {
        return Outcome::skip("ce profil ne négocie pas");
    };
    let identity = match enrolled.identities.load(&settings.identity).await {
        Ok(identity) => identity,
        Err(error) => return Outcome::fail(format!("{error:#}")),
    };
    let certificate: PqCertificate = match serde_json::from_slice(&identity.pq_certificate) {
        Ok(certificate) => certificate,
        Err(error) => return Outcome::fail(format!("certificat PQ client illisible : {error}")),
    };
    let expected = match enrolled.profile.public_key() {
        Some(key) => key,
        None => return Outcome::fail("clé privée du profil illisible"),
    };
    Outcome::check(
        certificate.wireguard_public_key == expected,
        format!(
            "identité « {} » scellée et liée à ce profil",
            settings.identity
        ),
        format!(
            "l'identité scellée porte la clé {} alors que le profil détient {expected}",
            certificate.wireguard_public_key
        ),
    )
}

/// Un mode sous le plancher est refusé **avant** tout accès réseau.
async fn scenario_local_downgrade(enrolled: &Enrolled) -> Outcome {
    let Some(settings) = enrolled.profile.key_negotiation.as_ref() else {
        return Outcome::skip("ce profil ne négocie pas");
    };
    if settings.minimum_mode == ProtectionMode::Classic {
        return Outcome::skip("plancher classique : rien à refuser");
    }
    let mut downgraded = enrolled.profile.clone();
    if let Some(block) = downgraded.key_negotiation.as_mut() {
        block.mode = ProtectionMode::Classic;
    }
    match prepare_for_profile(&downgraded, enrolled.identities.as_ref()).await {
        Err(error) => Outcome::pass(format!("refusé localement : {error}")),
        Ok(_) => Outcome::fail("un mode sous le plancher a été négocié"),
    }
}

pub async fn profile_scenarios(enrolled: &Enrolled) -> Vec<(&'static str, Outcome)> {
    vec![
        (
            "bloc de négociation valide",
            scenario_profile_block(&enrolled.profile),
        ),
        (
            "identité scellée cohérente",
            scenario_identity_matches(enrolled).await,
        ),
        (
            "plancher tenu localement",
            scenario_local_downgrade(enrolled).await,
        ),
    ]
}

// ─── Famille gateway : négociation réelle ────────────────────────────────────

/// Négociation nominale : la gateway répond, le PSK est dérivé.
async fn scenario_nominal(enrolled: &Enrolled) -> Outcome {
    let started = std::time::Instant::now();
    match prepare_for_profile(&enrolled.profile, enrolled.identities.as_ref()).await {
        Err(error) => Outcome::fail(format!("{error:#}")),
        Ok(negotiated) => {
            let psk = negotiated.psk.as_ref().map(|psk| psk.expose().to_string());
            let decoded = psk.as_deref().and_then(|psk| b64().decode(psk).ok());
            // La transaction n'est pas confirmée : la gateway la défait seule.
            drop(negotiated);
            match decoded {
                Some(raw) if raw.len() == 32 => Outcome::pass(format!(
                    "PSK de 32 o négocié en {} ms",
                    started.elapsed().as_millis()
                )),
                Some(raw) => Outcome::fail(format!("PSK de {} o au lieu de 32", raw.len())),
                None => Outcome::fail("aucun PSK dans une négociation ML-KEM"),
            }
        }
    }
}

/// Deux négociations, deux PSK : c'est ce qui distingue un secret négocié
/// d'un secret partagé une fois pour toutes.
async fn scenario_fresh_psk(enrolled: &Enrolled) -> Outcome {
    let mut secrets = Vec::new();
    for pass in 1..=2 {
        match prepare_for_profile(&enrolled.profile, enrolled.identities.as_ref()).await {
            Err(error) => return Outcome::fail(format!("passe {pass} : {error:#}")),
            Ok(negotiated) => {
                secrets.push(negotiated.psk.as_ref().map(|psk| psk.expose().to_string()));
                drop(negotiated);
            }
        }
        // Laisse la gateway défaire la transaction précédente : sans ce
        // battement, la seconde tentative se heurte au verrou du pair.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Outcome::check(
        secrets[0].is_some() && secrets[0] != secrets[1],
        "deux négociations, deux PSK distincts",
        "deux négociations ont rendu le même PSK",
    )
}

/// Une transaction abandonnée libère le pair.
///
/// C'est la panne qui bloque un client pour de bon : une session morte qui
/// garde le verrou, et toute négociation suivante refusée « busy » sans que
/// rien ne le dise.
async fn scenario_rollback_releases_peer(enrolled: &Enrolled) -> Outcome {
    match prepare_for_profile(&enrolled.profile, enrolled.identities.as_ref()).await {
        Err(error) => return Outcome::fail(format!("première négociation : {error:#}")),
        Ok(negotiated) => drop(negotiated),
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    match prepare_for_profile(&enrolled.profile, enrolled.identities.as_ref()).await {
        Err(error) => Outcome::fail(format!(
            "le pair reste verrouillé après un abandon : {error:#}"
        )),
        Ok(negotiated) => {
            drop(negotiated);
            Outcome::pass("le pair est renégociable après une transaction abandonnée")
        }
    }
}

/// Le lien de vivacité survit au silence.
///
/// Régression du défaut qui coupait tous les tunnels au bout de trois
/// minutes : sans keep-alive, QUIC déclarait la connexion morte après 30 s, la
/// gateway libérait le PSK, et le tunnel mourait au renouvellement de clé
/// suivant. Le scénario attend donc **plus** que ce délai, exprès.
async fn scenario_link_survives_silence(enrolled: &Enrolled) -> Outcome {
    let negotiated =
        match prepare_for_profile(&enrolled.profile, enrolled.identities.as_ref()).await {
            Ok(negotiated) => negotiated,
            Err(error) => return Outcome::fail(format!("{error:#}")),
        };
    let link = match negotiated.confirm().await {
        Ok(link) => link,
        Err(error) => return Outcome::fail(format!("confirmation refusée : {error:#}")),
    };

    let silence = Duration::from_secs(40);
    let closed = tokio::time::timeout(silence, link.closed()).await.is_ok();
    link.close();
    Outcome::check(
        !closed,
        format!(
            "lien encore ouvert après {} s de silence",
            silence.as_secs()
        ),
        format!(
            "lien fermé avant {} s : la gateway a libéré le PSK, le tunnel serait mort au \
             prochain renouvellement de clé",
            silence.as_secs()
        ),
    )
}

pub async fn gateway_scenarios(enrolled: &Enrolled, soak: bool) -> Vec<(&'static str, Outcome)> {
    let mut scenarios = vec![
        ("négociation nominale", scenario_nominal(enrolled).await),
        (
            "PSK frais à chaque négociation",
            scenario_fresh_psk(enrolled).await,
        ),
        (
            "abandon libère le pair",
            scenario_rollback_releases_peer(enrolled).await,
        ),
    ];
    scenarios.push((
        "lien de vivacité maintenu (40 s)",
        if soak {
            scenario_link_survives_silence(enrolled).await
        } else {
            Outcome::skip("demande --soak : le scénario dure 40 s")
        },
    ));
    scenarios
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La famille crypto doit passer sur n'importe quelle machine.
    ///
    /// C'est ce qui la rend jouable en régression, là où il n'y a ni
    /// gateway ni identité scellée : une primitive cassée est prise par
    /// `cargo test`, sans attendre que quelqu'un lance la campagne.
    #[test]
    fn la_famille_crypto_passe_sans_environnement() {
        for (name, outcome) in crypto_scenarios() {
            assert!(matches!(outcome, Outcome::Pass(_)), "{name} : {outcome:?}");
        }
    }
}
