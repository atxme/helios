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

use std::time::Duration;

use aether::enroll::{EnrollError, ProvisionRequest, ProvisionResponse};
use aether::{InstallPskRequest, SecretString};
use axum::{extract::State, http::StatusCode, Extension, Json};
use helios_provisioning::{
    handle_request, session::fresh_nonce, AdmittedPeers, GatewayIdentity, Provisioned,
    DEFAULT_PSK_LIFETIME_SECS,
};
use helios_wireguard::PeerAddressTable;
use tokio::sync::oneshot;

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
    caller: Option<Extension<crate::auth::Caller>>,
    Json(request): Json<ProvisionRequest>,
) -> Result<Json<ProvisionResponse>, (StatusCode, String)> {
    match caller {
        Some(Extension(caller)) if caller.dev_loopback => {}
        Some(Extension(caller))
            if caller.public_key.as_deref() == Some(request.client_wg_public_key.as_str()) => {}
        Some(_) => {
            return Err((
                StatusCode::FORBIDDEN,
                "la clé demandée n’appartient pas au pair WireGuard appelant".into(),
            ));
        }
        None if s.dry_run => {}
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "identité WireGuard absente".into(),
            ));
        }
    }
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

    // La config n'est plus nécessaire, et l'orchestrateur va vouloir l'écrire :
    // relâcher le verrou en lecture avant de lui passer la main.
    drop(network);

    // Le PSK est posé sur le plan de données AVANT d'être annoncé au client.
    // WireGuard n'a qu'un seul slot PSK par pair : un PSK installé d'un seul
    // côté fait échouer tous les handshakes suivants — et le canal de contrôle
    // qui permettrait de se rattraper vit précisément dans ce tunnel.
    install_psk(&s, &request.client_wg_public_key, &provisioned).await?;

    tracing::info!(
        peer = %request.client_wg_public_key,
        vip = %provisioned.address,
        "provisioning effectué — PSK post-quantique dérivé et installé"
    );

    Ok(Json(provisioned.response))
}

/// Délai d'attente de l'acquittement de l'orchestrateur.
///
/// Généreux au regard d'un `sync_peers` local, mais borné : un client bloqué
/// indéfiniment ne saurait pas s'il doit installer le PSK ou non.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Demande à l'orchestrateur de poser le PSK, et attend sa confirmation.
///
/// Toute défaillance — canal saturé, orchestrateur arrêté, plan de données en
/// erreur, délai dépassé — se traduit par un échec de la requête. C'est
/// délibérément fail-closed : mieux vaut un provisioning refusé, qui laisse le
/// tunnel classique intact, qu'un PSK orphelin qui tue le tunnel.
async fn install_psk(
    s: &AppState,
    client_public_key: &str,
    provisioned: &Provisioned,
) -> Result<(), (StatusCode, String)> {
    let (reply_tx, reply_rx) = oneshot::channel();

    let request = InstallPskRequest {
        public_key: client_public_key.to_string(),
        address: format!("{}/32", provisioned.address),
        psk: SecretString::new(aether::enroll::psk_to_base64(&provisioned.psk)),
        reply: reply_tx,
    };

    s.psk_tx.send(request).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "orchestrateur indisponible : PSK non installé".to_string(),
        )
    })?;

    match tokio::time::timeout(INSTALL_TIMEOUT, reply_rx).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(e))) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("installation du PSK refusée : {e}"),
        )),
        Ok(Err(_)) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "orchestrateur arrêté avant d'acquitter le PSK".to_string(),
        )),
        Err(_) => Err((
            StatusCode::GATEWAY_TIMEOUT,
            "délai dépassé à l'installation du PSK".to_string(),
        )),
    }
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
    // Un provisioning refusé se voit dans le journal : c'est le seul endroit où
    // une tentative d'enrôlement laisse une trace, le refus WireGuard d'un pair
    // inconnu restant invisible depuis l'espace utilisateur.
    tracing::warn!(status = %code, "provisioning refusé : {e}");
    (code, e.to_string())
}

/// Dérive la clé publique WireGuard de la gateway depuis sa clé privée.
fn gateway_public_key(private_key_b64: &str) -> Result<String, String> {
    aether::wg::public_from_private(private_key_b64)
        .map_err(|e| format!("clé privée de la gateway illisible : {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::enroll::{derive_psk, ProvisionRequest, NONCE_LEN, PROTOCOL_VERSION};
    use aether::pq::{Kem, MlKem768Kem};
    use aether::{NetworkConfig, TunnelState};
    use std::sync::Arc;
    use tokio::sync::{broadcast, mpsc, RwLock};

    const PRIV: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const CLIENT_PRIV: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    /// Clé publique du client, telle que la gateway la connaît par l'admission.
    fn client_public_key() -> String {
        use base64::Engine as _;
        let raw: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(CLIENT_PRIV)
            .unwrap()
            .try_into()
            .unwrap();
        let secret = x25519_dalek::StaticSecret::from(raw);
        base64::engine::general_purpose::STANDARD
            .encode(x25519_dalek::PublicKey::from(&secret).as_bytes())
    }

    /// `AppState` gréé pour le provisioning, avec le canal PSK rendu au test :
    /// c'est lui qui décide d'acquitter ou non, donc qui joue l'orchestrateur.
    fn state_provisionnable() -> (AppState, mpsc::Receiver<InstallPskRequest>) {
        let network = NetworkConfig {
            wg_private_key: PRIV.into(),
            wg_address: "100.64.0.1/10".into(),
            peers: vec![aether::WgPeer {
                name: "poste".into(),
                public_key: client_public_key(),
                address: "100.64.1.2/32".into(),
                admin: false,
                preshared_key: None,
            }],
            ..NetworkConfig::default()
        };
        let policy = network.firewall_policy();
        let (event_tx, _) = broadcast::channel(8);
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);
        let (psk_tx, psk_rx) = mpsc::channel(8);
        let state = AppState::new(
            Arc::new(RwLock::new(network)),
            true,
            Arc::new(RwLock::new(TunnelState::Connecting)),
            event_tx,
            cmd_tx,
            psk_tx,
            Arc::new(RwLock::new(policy)),
        );
        (state, psk_rx)
    }

    /// Construit une vraie requête de provisioning, comme le ferait Orion.
    fn requete_client() -> (
        <MlKem768Kem as Kem>::SecretKey,
        [u8; NONCE_LEN],
        ProvisionRequest,
    ) {
        let (dk, ek) = MlKem768Kem::generate().unwrap();
        let nonce = [42u8; NONCE_LEN];
        (
            dk,
            nonce,
            ProvisionRequest {
                protocol_version: PROTOCOL_VERSION,
                client_wg_public_key: client_public_key(),
                kem_public_key: ek,
                client_nonce: nonce,
            },
        )
    }

    /// Le tour complet : le PSK annoncé au client est exactement celui que la
    /// gateway a demandé d'installer, et l'installation précède la réponse.
    #[tokio::test]
    async fn le_psk_est_installe_avant_d_etre_annonce_et_les_deux_bouts_concordent() {
        let (state, mut psk_rx) = state_provisionnable();
        let (dk, client_nonce, request) = requete_client();

        // L'orchestrateur simulé : il acquitte et retient ce qu'on lui a demandé.
        let orchestrateur = tokio::spawn(async move {
            let demande = psk_rx.recv().await.expect("une demande doit arriver");
            let psk = demande.psk.expose().to_string();
            let address = demande.address.clone();
            demande.reply.send(Ok(())).unwrap();
            (psk, address)
        });

        let response = provision(State(state), None, Json(request))
            .await
            .expect("le provisioning doit aboutir")
            .0;

        let (psk_installe, address) = orchestrateur.await.unwrap();
        // La VIP transmise est celle que l'IPAM dérive de la clé publique, et
        // c'est bien celle annoncée au client : les deux doivent concorder.
        assert_eq!(
            address, response.assigned_address,
            "la VIP posée doit être celle annoncée au client"
        );

        // Côté client : décapsulation et dérivation indépendantes.
        let kem_secret = MlKem768Kem::decapsulate(&dk, &response.kem_ciphertext).unwrap();
        let psk_client = derive_psk(
            &kem_secret,
            &client_nonce,
            &response.gateway_nonce,
            &client_public_key(),
            &response.gateway_wg_public_key,
        )
        .unwrap();

        assert_eq!(
            aether::enroll::psk_to_base64(&psk_client),
            psk_installe,
            "le PSK posé sur la gateway doit être celui que le client dérive, \
             sinon tous les handshakes suivants échoueraient"
        );
    }

    /// Fail-closed : si la gateway ne peut pas poser le PSK, elle ne l'annonce
    /// pas. Le client reste en tunnel classique plutôt que de poser un PSK
    /// orphelin qui tuerait le tunnel — et avec lui le canal de rattrapage.
    #[tokio::test]
    async fn un_psk_non_installe_n_est_jamais_annonce_au_client() {
        let (state, mut psk_rx) = state_provisionnable();
        let (_dk, _nonce, request) = requete_client();

        // L'orchestrateur refuse la pose.
        tokio::spawn(async move {
            let demande = psk_rx.recv().await.unwrap();
            demande
                .reply
                .send(Err("plan de données indisponible".into()))
                .unwrap();
        });

        let erreur = provision(State(state), None, Json(request))
            .await
            .expect_err("un PSK non posé doit faire échouer la requête");

        assert_eq!(erreur.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn la_cle_demandee_doit_appartenir_au_pair_appelant() {
        let (state, _psk_rx) = state_provisionnable();
        let (_dk, _nonce, request) = requete_client();
        let caller = crate::auth::Caller {
            source: "100.64.1.3".parse().unwrap(),
            name: "autre-pair".into(),
            public_key: Some("cle-d-un-autre-pair".into()),
            admin: false,
            dev_loopback: false,
        };
        let error = provision(State(state), Some(Extension(caller)), Json(request))
            .await
            .unwrap_err();
        assert_eq!(error.0, StatusCode::FORBIDDEN);
    }

    /// Orchestrateur arrêté : même exigence, par un autre chemin.
    #[tokio::test]
    async fn orchestrateur_absent_fait_echouer_le_provisioning() {
        let (state, psk_rx) = state_provisionnable();
        drop(psk_rx);
        let (_dk, _nonce, request) = requete_client();

        let erreur = provision(State(state), None, Json(request))
            .await
            .expect_err("sans orchestrateur, aucun PSK ne doit être annoncé");

        assert_eq!(erreur.0, StatusCode::SERVICE_UNAVAILABLE);
    }

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
