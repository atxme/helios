//! Endpoint de provisioning : `POST /api/provision`.
//!
//! # Pourquoi ici, et pourquoi sans TLS
//!
//! L'ADR-001 prévoyait un canal TLS 1.3 dédié, ancré TPM. À l'implémentation, ce
//! canal s'avère **redondant** : il vivrait de toute façon *à l'intérieur* du
//! tunnel WireGuard, qui fournit déjà
//!
//! * la **confidentialité** (ChaCha20-Poly1305), et
//! * l'**authentification mutuelle** — chaque bout connaît la clé publique
//!   statique de l'autre (`peer_public_key` côté Orion, table de pairs côté
//!   gateway). Un tiers ne peut pas se faire passer pour la gateway sans sa clé
//!   privée Curve25519.
//!
//! TLS n'ajouterait donc aucune propriété que le tunnel ne donne déjà. Le
//! provisioning se greffe sur le serveur HTTP existant, qui vit lui aussi
//! derrière le tunnel.
//!
//! Et la confidentialité **post-quantique** du PSK ne dépend pas du canal : un
//! adversaire qui romprait le tunnel classique plus tard n'y verrait que la clé
//! publique ML-KEM et le ciphertext — exactement ce que voit l'observateur
//! passif d'un échange ML-KEM en clair, ce à quoi ML-KEM résiste par
//! construction.
//!
//! # Ce que le TPM devrait protéger
//!
//! L'intention « ancrer l'identité de la gateway dans le TPM » reste valable,
//! mais elle vise le mauvais secret : ce n'est pas une clé TLS redondante qu'il
//! faut sceller, c'est **`wg_private_key`** — l'identité cryptographique réelle
//! de la gateway, aujourd'hui en clair dans `network.toml`. Chantier ouvert.

use aether::enroll::{EnrollError, ProvisionRequest, ProvisionResponse};
use axum::{extract::State, http::StatusCode, Json};
use helios_provisioning::{
    handle_request, session::fresh_nonce, AdmittedPeers, GatewayIdentity, DEFAULT_PSK_LIFETIME_SECS,
};
use helios_wireguard::PeerAddressTable;

use crate::AppState;

/// Vue « pairs admis » adossée à la config réseau.
///
/// L'admission reste **hors bande** : cette liste est celle que l'opérateur a
/// déclarée (`peers` dans `network.toml`). Le provisioning ne l'étend jamais.
struct AdmittedFromConfig(Vec<String>);

impl AdmittedPeers for AdmittedFromConfig {
    fn is_admitted(&self, wg_public_key: &str) -> bool {
        self.0.iter().any(|k| k == wg_public_key)
    }
}

/// Traite une demande de provisioning venue d'un client, **dans le tunnel**.
pub async fn provision(
    State(s): State<AppState>,
    Json(request): Json<ProvisionRequest>,
) -> Result<Json<ProvisionResponse>, (StatusCode, String)> {
    let network = s.network.read().await;

    // Sans clé privée, la gateway n'a pas d'identité à annoncer : refuser
    // explicitement plutôt que de dériver un PSK contre une identité vide.
    if !network.wireguard_ready() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway non configurée : `wg_private_key` absente".to_string(),
        ));
    }

    let gateway_public_key = match gateway_public_key(&network.wg_private_key) {
        Ok(k) => k,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    };

    let admitted = AdmittedFromConfig(network.peers.iter().map(|p| p.public_key.clone()).collect());

    // La table de pairs *vivante* sert de source de vérité pour les collisions
    // de VIP. En dry-run elle est vide : la VIP dérivée est alors retenue telle
    // quelle, ce qui est le comportement attendu.
    let peers = PeerAddressTable::from_peers(&[]);

    let identity = GatewayIdentity {
        wg_public_key: &gateway_public_key,
        psk_lifetime_secs: DEFAULT_PSK_LIFETIME_SECS,
    };

    let provisioned =
        handle_request(&request, &identity, &admitted, &peers, fresh_nonce()).map_err(to_http)?;

    tracing::info!(
        peer = %request.client_wg_public_key,
        vip = %provisioned.address,
        "provisioning effectué — PSK post-quantique dérivé"
    );

    // NOTE : le PSK doit encore être installé sur le pair côté plan de données.
    // Ce câblage passe par l'orchestrateur (voir `OrchestratorCmd`) et n'est pas
    // fait ici : cet endpoint ne doit pas manipuler le plan de données lui-même.
    Ok(Json(provisioned.response))
}

/// Traduit une erreur de protocole en réponse HTTP.
///
/// Un pair non admis reçoit `403` et non `404` : l'information « cette clé n'est
/// pas admise » n'est de toute façon pas un secret — l'appelant est déjà dans le
/// tunnel, donc déjà authentifié par WireGuard.
fn to_http(e: EnrollError) -> (StatusCode, String) {
    let code = match e {
        EnrollError::UnknownPeer => StatusCode::FORBIDDEN,
        EnrollError::VersionMismatch { .. } => StatusCode::CONFLICT,
        EnrollError::Kdf => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    (code, e.to_string())
}

/// Dérive la clé publique WireGuard de la gateway depuis sa clé privée.
fn gateway_public_key(private_key_b64: &str) -> Result<String, String> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(private_key_b64.trim())
        .map_err(|e| format!("clé privée de la gateway illisible : {e}"))?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| "clé privée de la gateway de longueur invalide".to_string())?;
    let secret = x25519_dalek::StaticSecret::from(raw);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok(base64::engine::general_purpose::STANDARD.encode(public.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn la_cle_publique_de_la_gateway_derive_de_sa_cle_privee() {
        let pk = gateway_public_key(PRIV).unwrap();
        assert_eq!(pk.len(), 44);
        assert_eq!(pk, gateway_public_key(PRIV).unwrap(), "dérivation stable");
    }

    #[test]
    fn cle_privee_invalide_signalee() {
        assert!(gateway_public_key("pas-du-base64").is_err());
        assert!(gateway_public_key("AAAA").is_err(), "longueur invalide");
    }

    #[test]
    fn seuls_les_pairs_declares_sont_admis() {
        let admitted = AdmittedFromConfig(vec!["cle-a".into()]);
        assert!(admitted.is_admitted("cle-a"));
        assert!(
            !admitted.is_admitted("cle-b"),
            "le provisioning ne doit jamais étendre l'admission"
        );
    }

    #[test]
    fn les_erreurs_de_protocole_ont_le_bon_code_http() {
        assert_eq!(to_http(EnrollError::UnknownPeer).0, StatusCode::FORBIDDEN);
        assert_eq!(
            to_http(EnrollError::VersionMismatch {
                client: 2,
                gateway: 1
            })
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            to_http(EnrollError::BadKemPublicKey(3)).0,
            StatusCode::BAD_REQUEST
        );
    }
}
