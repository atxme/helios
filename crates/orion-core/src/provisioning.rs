//! Provisioning côté client : obtenir le PSK post-quantique auprès de la gateway.
//!
//! # Quand cela tourne
//!
//! **Uniquement une fois le tunnel classique monté**, comme la télémétrie. La
//! cinématique de l'ADR-001 :
//!
//! ```text
//! 1. Tunnel WireGuard classique (Curve25519) monté -> état Connecting,
//!    kill-switch engagé, aucun trafic utilisateur.
//! 2. CE MODULE : requête de provisioning vers la gateway, DANS le tunnel.
//!    -> échange ML-KEM -> PSK dérivé des deux côtés.
//! 3. PSK installé -> le handshake suivant réussit -> Up.
//! ```
//!
//! # Pourquoi pas de TLS ici
//!
//! Le canal vit **à l'intérieur** du tunnel WireGuard, qui fournit déjà la
//! confidentialité *et* l'authentification mutuelle : chaque bout connaît la clé
//! publique statique de l'autre (`peer_public_key` côté client, table de pairs
//! côté gateway). Une couche TLS supplémentaire n'ajouterait ni l'une ni
//! l'autre.
//!
//! Et même si le tunnel classique était rompu plus tard par un adversaire
//! quantique, cela ne compromettrait pas le PSK : l'attaquant ne verrait que la
//! clé publique ML-KEM et le ciphertext — exactement ce que voit l'observateur
//! passif d'un échange ML-KEM mené en clair, ce à quoi ML-KEM résiste par
//! construction.
//!
//! # Ce que ce module ne fait pas
//!
//! Il n'enrôle pas un client inconnu. Si la gateway ne connaît pas encore la clé
//! publique WireGuard du client, le tunnel classique ne monte pas et ce code
//! n'est jamais atteint. L'admission est hors bande (voir
//! `helios_provisioning`).

use std::time::Duration;

use aether::enroll::{
    derive_psk, EnrollError, ProvisionRequest, ProvisionResponse, PROTOCOL_VERSION,
};
use aether::pq::{Kem, MlKem768Kem};

use crate::config::ClientProfile;

/// Délai max d'une requête de provisioning.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Résultat d'un provisioning réussi.
#[derive(Debug)]
pub struct ProvisionOutcome {
    /// PSK post-quantique, en base64, prêt pour le slot `PresharedKey`.
    pub preshared_key: String,
    /// VIP attribuée par la gateway (CIDR).
    pub address: String,
    /// Clé publique WireGuard de la gateway, telle qu'elle se déclare.
    pub gateway_public_key: String,
    /// Durée de validité annoncée du PSK.
    pub lifetime: Duration,
}

/// Erreurs du provisioning côté client.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("le profil n'est pas exploitable : {0}")]
    Profile(String),
    #[error("canal de provisioning injoignable : {0}")]
    Transport(String),
    #[error("la gateway a refusé le provisioning (HTTP {status}) : {body}")]
    Rejected { status: u16, body: String },
    #[error("réponse de provisioning illisible : {0}")]
    BadResponse(String),
    #[error(transparent)]
    Protocol(#[from] EnrollError),
    #[error("échange ML-KEM impossible : {0}")]
    Kem(String),
    /// La gateway ne s'annonce pas avec la clé publique attendue par le profil.
    #[error("identité de gateway inattendue : le profil attend `{expected}`, la gateway annonce `{announced}`")]
    GatewayIdentityMismatch { expected: String, announced: String },
}

/// Construit la requête et la paire ML-KEM éphémère associée.
///
/// La paire est **éphémère par session** : le secret ne survit pas au
/// provisioning, ce qui borne l'impact d'une compromission ultérieure du client.
fn build_request(
    profile: &ClientProfile,
) -> Result<(<MlKem768Kem as Kem>::SecretKey, [u8; 16], ProvisionRequest), ProvisionError> {
    let (secret_key, kem_public_key) =
        MlKem768Kem::generate().map_err(|e| ProvisionError::Kem(e.to_string()))?;

    let client_nonce = fresh_nonce();
    let request = ProvisionRequest {
        protocol_version: PROTOCOL_VERSION,
        client_wg_public_key: profile.wg_public_key()?,
        kem_public_key,
        client_nonce,
    };
    Ok((secret_key, client_nonce, request))
}

/// Dérive le PSK depuis la réponse de la gateway.
///
/// Séparé du transport pour être testable sans réseau — c'est ici que vit toute
/// la logique cryptographique.
pub fn finish(
    profile: &ClientProfile,
    secret_key: &<MlKem768Kem as Kem>::SecretKey,
    client_nonce: &[u8; 16],
    response: &ProvisionResponse,
) -> Result<ProvisionOutcome, ProvisionError> {
    response.validate()?;

    // La gateway doit être celle que le profil attend. Sans cette vérification,
    // une gateway compromise pourrait se substituer et négocier un PSK avec nous
    // — même si le tunnel WireGuard rend déjà ce scénario très improbable.
    if response.gateway_wg_public_key != profile.peer_public_key {
        return Err(ProvisionError::GatewayIdentityMismatch {
            expected: profile.peer_public_key.clone(),
            announced: response.gateway_wg_public_key.clone(),
        });
    }

    let kem_secret = MlKem768Kem::decapsulate(secret_key, &response.kem_ciphertext)
        .map_err(|e| ProvisionError::Kem(e.to_string()))?;

    let psk = derive_psk(
        &kem_secret,
        client_nonce,
        &response.gateway_nonce,
        &profile.wg_public_key()?,
        &response.gateway_wg_public_key,
    )?;

    Ok(ProvisionOutcome {
        preshared_key: aether::enroll::psk_to_base64(&psk),
        address: response.assigned_address.clone(),
        gateway_public_key: response.gateway_wg_public_key.clone(),
        lifetime: Duration::from_secs(u64::from(response.psk_lifetime_secs)),
    })
}

/// Exécute un provisioning complet contre la gateway.
///
/// `gateway_url` est l'URL interne, joignable **uniquement dans le tunnel**
/// (ex. `http://100.64.0.1:8080`).
pub async fn provision(
    profile: &ClientProfile,
    gateway_url: &str,
) -> Result<ProvisionOutcome, ProvisionError> {
    let (secret_key, client_nonce, request) = build_request(profile)?;

    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| ProvisionError::Transport(e.to_string()))?;

    let url = format!("{}/api/provision", gateway_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .json(&request)
        .send()
        .await
        .map_err(|e| ProvisionError::Transport(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ProvisionError::Rejected {
            status: status.as_u16(),
            body,
        });
    }

    let response: ProvisionResponse = resp
        .json()
        .await
        .map_err(|e| ProvisionError::BadResponse(e.to_string()))?;

    finish(profile, &secret_key, &client_nonce, &response)
}

/// Tire un nonce de session depuis le CSPRNG du système.
fn fresh_nonce() -> [u8; 16] {
    use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
    let mut nonce = [0u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .expect("CSPRNG système indisponible — impossible de provisionner sûrement");
    nonce
}

impl ClientProfile {
    /// Clé publique WireGuard du client, dérivée de sa clé privée.
    ///
    /// C'est l'identité que la gateway connaît. On la recalcule plutôt que de la
    /// stocker : impossible qu'elle diverge de la clé privée réellement utilisée.
    pub fn wg_public_key(&self) -> Result<String, ProvisionError> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(self.private_key.trim())
            .map_err(|e| ProvisionError::Profile(format!("clé privée illisible : {e}")))?;
        let raw: [u8; 32] = raw
            .try_into()
            .map_err(|_| ProvisionError::Profile("clé privée de longueur invalide".into()))?;

        // Curve25519 : clé publique = base * clé privée (clampée).
        let secret = x25519_dalek::StaticSecret::from(raw);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(base64::engine::general_purpose::STANDARD.encode(public.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::enroll::NONCE_LEN;

    const CLIENT_PRIV: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const GATEWAY_PUB: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn profile() -> ClientProfile {
        ClientProfile {
            name: "test".into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: CLIENT_PRIV.into(),
            peer_public_key: GATEWAY_PUB.into(),
            ..ClientProfile::default()
        }
    }

    #[test]
    fn la_cle_publique_derive_de_la_cle_privee() {
        let pk = profile().wg_public_key().unwrap();
        assert_eq!(pk.len(), 44, "clé Curve25519 en base64");
        // Déterministe : deux appels donnent la même identité.
        assert_eq!(pk, profile().wg_public_key().unwrap());
    }

    #[test]
    fn cle_privee_invalide_rejetee() {
        let mut p = profile();
        p.private_key = "pas-du-base64".into();
        assert!(matches!(p.wg_public_key(), Err(ProvisionError::Profile(_))));
    }

    /// Le tour complet côté client, sans réseau : on simule la gateway avec la
    /// vraie crypto ML-KEM et on vérifie que le PSK dérivé est exploitable.
    #[test]
    fn provisioning_complet_produit_un_psk_utilisable() {
        let profile = profile();
        let (secret_key, client_nonce, request) = build_request(&profile).unwrap();
        request.validate().unwrap();

        // ── Gateway simulée ──
        let gateway_nonce = [7u8; NONCE_LEN];
        let (ciphertext, kem_secret) = MlKem768Kem::encapsulate(&request.kem_public_key).unwrap();
        let expected_psk = derive_psk(
            &kem_secret,
            &client_nonce,
            &gateway_nonce,
            &request.client_wg_public_key,
            GATEWAY_PUB,
        )
        .unwrap();

        let response = ProvisionResponse {
            protocol_version: PROTOCOL_VERSION,
            kem_ciphertext: ciphertext,
            gateway_nonce,
            assigned_address: "100.64.1.2/32".into(),
            gateway_wg_public_key: GATEWAY_PUB.into(),
            psk_lifetime_secs: 3600,
        };

        // ── Retour côté client ──
        let outcome = finish(&profile, &secret_key, &client_nonce, &response).unwrap();
        assert_eq!(
            outcome.preshared_key,
            aether::enroll::psk_to_base64(&expected_psk),
            "le client doit dériver exactement le PSK que la gateway a calculé"
        );
        assert_eq!(outcome.address, "100.64.1.2/32");
        assert_eq!(outcome.lifetime, Duration::from_secs(3600));
    }

    /// Une gateway qui n'est pas celle du profil doit être rejetée.
    #[test]
    fn gateway_inattendue_refusee() {
        let profile = profile();
        let (secret_key, client_nonce, request) = build_request(&profile).unwrap();
        let (ciphertext, _) = MlKem768Kem::encapsulate(&request.kem_public_key).unwrap();

        let response = ProvisionResponse {
            protocol_version: PROTOCOL_VERSION,
            kem_ciphertext: ciphertext,
            gateway_nonce: [0; NONCE_LEN],
            assigned_address: "100.64.1.2/32".into(),
            // Une autre identité que celle attendue par le profil.
            gateway_wg_public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into(),
            psk_lifetime_secs: 3600,
        };

        assert!(matches!(
            finish(&profile, &secret_key, &client_nonce, &response),
            Err(ProvisionError::GatewayIdentityMismatch { .. })
        ));
    }

    #[test]
    fn ciphertext_malforme_rejete() {
        let profile = profile();
        let (secret_key, client_nonce, _) = build_request(&profile).unwrap();
        let response = ProvisionResponse {
            protocol_version: PROTOCOL_VERSION,
            kem_ciphertext: vec![0u8; 10],
            gateway_nonce: [0; NONCE_LEN],
            assigned_address: "100.64.1.2/32".into(),
            gateway_wg_public_key: GATEWAY_PUB.into(),
            psk_lifetime_secs: 3600,
        };
        assert!(finish(&profile, &secret_key, &client_nonce, &response).is_err());
    }

    #[test]
    fn deux_sessions_utilisent_des_paires_kem_distinctes() {
        let p = profile();
        let (_, n1, r1) = build_request(&p).unwrap();
        let (_, n2, r2) = build_request(&p).unwrap();
        assert_ne!(
            r1.kem_public_key, r2.kem_public_key,
            "paire éphémère par session"
        );
        assert_ne!(n1, n2, "nonce frais par session");
    }
}
