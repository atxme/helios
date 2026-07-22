use aether::{NetworkConfig, OrchestratorCmd};
use axum::{extract::State, http::StatusCode, Json};
use helios_firewall::ruleset;
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Serialize)]
pub struct StatusResponse {
    pub state: String,
    pub version: &'static str,
    pub wan_iface: String,
    pub lan_ifaces: Vec<String>,
    pub wg_peers: Vec<String>,
    pub allow_ssh_from: Vec<String>,
    pub peers: Vec<PeerSummary>,
    pub wg_iface: String,
    pub wg_listen_port: Option<u16>,
    pub dry_run: bool,
    pub split_tunnel_cidrs: Vec<String>,
    pub mss_clamp: Option<u16>,
    pub captive_portal_gateway: Option<String>,
}

/// Un pair WireGuard autorisé, tel qu'exposé à l'IHM.
/// La clé publique est publique par nature ; le PSK n'est jamais exposé,
/// on n'en publie que la présence.
#[derive(Serialize, Clone)]
pub struct PeerSummary {
    pub name: String,
    pub public_key: String,
    pub address: String,
    pub post_quantum: bool,
    pub admin: bool,
}

/// Vue publique de la configuration réseau.
///
/// Elle est volontairement distincte de [`NetworkConfig`] : une régression de
/// sérialisation ne peut donc pas réintroduire la clé privée WireGuard ni les
/// PSK dans `GET /api/network`.
#[derive(Serialize)]
pub struct NetworkConfigView {
    pub wan_iface: String,
    pub lan_ifaces: Vec<String>,
    pub allow_ssh_from: Vec<String>,
    pub admin_iface: Option<String>,
    pub split_tunnel_cidrs: Vec<String>,
    pub wg_iface: String,
    pub wg_private_key_configured: bool,
    /// Clé publique WireGuard de la gateway — publique par nature, c'est la
    /// valeur `peer_public_key` des profils clients. `None` tant qu'aucune
    /// identité n'est résolue. La dériver ici évite que l'opérateur doive la
    /// recopier depuis le terminal où il a lancé `heliosd init-identity`.
    pub wg_public_key: Option<String>,
    pub wg_address: String,
    pub wg_listen_port: u16,
    pub peers: Vec<NetworkPeerView>,
    pub static_peer_addrs: Vec<String>,
    pub escrow_public_key: Option<String>,
}

#[derive(Serialize)]
pub struct NetworkPeerView {
    pub name: String,
    pub public_key: String,
    pub address: String,
    pub preshared_key_configured: bool,
    pub admin: bool,
}

impl From<&NetworkConfig> for NetworkConfigView {
    fn from(config: &NetworkConfig) -> Self {
        Self {
            wan_iface: config.wan_iface.clone(),
            lan_ifaces: config.lan_ifaces.clone(),
            allow_ssh_from: config.allow_ssh_from.clone(),
            admin_iface: config.admin_iface.clone(),
            split_tunnel_cidrs: config.split_tunnel_cidrs.clone(),
            wg_iface: config.wg_iface.clone(),
            wg_private_key_configured: !config.wg_private_key.trim().is_empty(),
            wg_public_key: aether::wg::public_from_private(&config.wg_private_key).ok(),
            wg_address: config.wg_address.clone(),
            wg_listen_port: config.wg_listen_port,
            peers: config
                .peers
                .iter()
                .map(|peer| NetworkPeerView {
                    name: peer.name.clone(),
                    public_key: peer.public_key.clone(),
                    address: peer.address.clone(),
                    preshared_key_configured: peer.preshared_key.is_some(),
                    admin: peer.admin,
                })
                .collect(),
            static_peer_addrs: config.static_peer_addrs.clone(),
            escrow_public_key: config.escrow_public_key.clone(),
        }
    }
}

#[derive(Serialize)]
pub struct CmdResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CmdResponse {
    fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
        }
    }
}

#[derive(Serialize)]
pub struct FirewallRulesResponse {
    pub rules: String,
    pub default_verdict: String,
    pub dry_run: bool,
}

#[derive(Deserialize)]
pub struct ApplyRulesRequest {
    pub rules: String,
}

#[derive(Deserialize)]
pub struct SplitTunnelRequest {
    pub cidrs: Vec<String>,
}

#[derive(Deserialize)]
pub struct GatewayKeyRequest {
    /// Nouvelle clé privée Curve25519 de la gateway, en base64.
    pub private_key: String,
}

/// Remplace la clé privée WireGuard de la gateway et la rescelle.
///
/// **Joignable uniquement à travers le tunnel** : comme toute cette API, le
/// pare-feu la restreint à `admin_iface`. Une rotation d'identité ne doit pas
/// pouvoir être tentée depuis l'Internet.
///
/// Le secret de scellement TPM ne transite pas par ce crate : on se contente de
/// valider la forme et de transmettre à l'orchestrateur, seul détenteur du
/// secret. Ici on refuse tôt ce qui est manifestement invalide, pour ne pas
/// faire voyager une clé absurde jusqu'au TPM.
pub async fn gateway_key_set(
    State(s): State<AppState>,
    Json(body): Json<GatewayKeyRequest>,
) -> Result<Json<CmdResponse>, (StatusCode, String)> {
    use base64::Engine as _;

    let key = body.private_key.trim();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("clé non décodable : {e}")))?;
    if raw.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "clé de {} octets au lieu de 32 — ce n'est pas une clé Curve25519",
                raw.len()
            ),
        ));
    }

    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::UpdateGatewayKey(key.to_string()))
        .await
        .is_ok();
    Ok(Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    }))
}

pub async fn status(State(s): State<AppState>) -> Json<StatusResponse> {
    let state = s.tunnel_state.read().await;
    let policy = s.policy.read().await;
    let network = s.network.read().await;

    let peers: Vec<PeerSummary> = network
        .peers
        .iter()
        .map(|p| PeerSummary {
            name: p.name.clone(),
            public_key: p.public_key.clone(),
            address: p.address.clone(),
            post_quantum: p.preshared_key.is_some(),
            admin: p.admin,
        })
        .collect();

    Json(StatusResponse {
        state: state.as_str().to_string(),
        version: env!("CARGO_PKG_VERSION"),
        wan_iface: network.wan_iface.clone(),
        lan_ifaces: network.lan_ifaces.clone(),
        wg_peers: network.wg_peers(),
        allow_ssh_from: network.allow_ssh_from.clone(),
        peers,
        wg_iface: network.wg_iface.clone(),
        wg_listen_port: policy.wg_listen_port,
        dry_run: s.dry_run,
        split_tunnel_cidrs: policy.split_tunnel_cidrs.clone(),
        mss_clamp: policy.mss_clamp,
        captive_portal_gateway: policy.captive_portal_gateway.clone(),
    })
}

/// Retourne la configuration réseau courante sans aucun secret.
pub async fn network_get(State(s): State<AppState>) -> Json<NetworkConfigView> {
    let network = s.network.read().await;
    Json(NetworkConfigView::from(&*network))
}

/// Recharge la configuration réseau à chaud (JSON).
/// Persiste sur disque et envoie `LoadNetworkConfig` à l'orchestrateur.
pub async fn network_set(
    State(s): State<AppState>,
    Json(mut new_config): Json<NetworkConfig>,
) -> Result<Json<CmdResponse>, (StatusCode, String)> {
    // `GET /api/network` n'expose ni la clé privée ni les PSK : une
    // configuration relue puis repostée par l'IHM revient donc nécessairement
    // sans eux. Les reprendre de la configuration en vigueur évite qu'un simple
    // changement d'interface LAN efface l'identité résolue depuis le coffre
    // scellé et tous les PSK négociés — la gateway resterait montée, puis tous
    // les handshakes échoueraient sans que rien ne relie la panne au réglage
    // qui l'a causée.
    {
        let courant = s.network.read().await;
        if new_config.wg_private_key.trim().is_empty() {
            new_config
                .wg_private_key
                .clone_from(&courant.wg_private_key);
        }
        for peer in &mut new_config.peers {
            if peer.preshared_key.is_none() {
                peer.preshared_key = courant
                    .peers
                    .iter()
                    .find(|connu| connu.public_key == peer.public_key)
                    .and_then(|connu| connu.preshared_key.clone());
            }
        }
    }
    apply_network(&s, new_config).await?;
    Ok(Json(CmdResponse::ok()))
}

#[derive(Deserialize)]
pub struct PeerAdmitRequest {
    /// Nom convivial, unique sur la gateway.
    pub name: String,
    /// Clé publique Curve25519 du client, en base64.
    pub public_key: String,
    /// Autorise ce pair à muter le plan de contrôle et les mises à jour.
    #[serde(default)]
    pub admin: bool,
}

#[derive(Deserialize)]
pub struct PeerRevokeRequest {
    pub name: String,
}

/// Admet un pair et lui attribue sa VIP (ADR-004 §4).
///
/// # Pourquoi une route dédiée plutôt qu'un `POST /api/network`
///
/// `GET /api/network` renvoie une vue sciemment expurgée : ni clé privée, ni
/// PSK. Un outil qui relirait cette vue, y ajouterait un pair et la reposterait
/// écraserait la configuration **sans les PSK des autres pairs**. Or un slot
/// PSK renseigné d'un seul côté fait échouer tous les handshakes du pair
/// concerné, sans canal de rattrapage : l'opérateur se couperait de son parc en
/// croyant ajouter un client. La mutation doit donc être ciblée et jouée ici,
/// là où la configuration complète est connue.
pub async fn peer_admit(
    State(s): State<AppState>,
    Json(body): Json<PeerAdmitRequest>,
) -> Result<Json<PeerSummary>, (StatusCode, String)> {
    let mut updated = s.network.read().await.clone();
    let peer = helios_provisioning::admit(&mut updated, &body.name, &body.public_key, body.admin)
        .map_err(admission_status)?;
    apply_network(&s, updated).await?;

    tracing::info!(peer = %peer.name, vip = %peer.address, admin = peer.admin, "pair admis");
    Ok(Json(PeerSummary {
        name: peer.name,
        public_key: peer.public_key,
        address: peer.address,
        post_quantum: peer.preshared_key.is_some(),
        admin: peer.admin,
    }))
}

/// Retire un pair de l'admission.
///
/// Ce n'est pas une révocation cryptographique : le pair tombe à son prochain
/// handshake, il n'existe pas de liste de révocation (ADR-004).
pub async fn peer_revoke(
    State(s): State<AppState>,
    Json(body): Json<PeerRevokeRequest>,
) -> Result<Json<PeerSummary>, (StatusCode, String)> {
    let mut updated = s.network.read().await.clone();
    let peer = helios_provisioning::revoke(&mut updated, &body.name).map_err(admission_status)?;
    apply_network(&s, updated).await?;

    tracing::warn!(peer = %peer.name, "pair retiré de l'admission");
    Ok(Json(PeerSummary {
        name: peer.name,
        public_key: peer.public_key,
        address: peer.address,
        post_quantum: peer.preshared_key.is_some(),
        admin: peer.admin,
    }))
}

/// Persiste une configuration mutée puis la transmet à l'orchestrateur.
///
/// La copie écrite sur disque est privée des secrets que la configuration en
/// mémoire porte :
///
/// * les PSK post-quantiques, **toujours** : ils se renégocient à l'enrôlement,
///   et un PSK sur disque survivrait à la rotation censée le remplacer ;
/// * la clé privée WireGuard, **hors dry-run** : elle vient du coffre scellé
///   TPM, et la réécrire dans `network.toml` la remettrait en clair sur le
///   disque, exactement ce que le scellement existe pour empêcher.
///
/// L'exception dry-run est explicite et non contournable autrement : sans TPM,
/// le coffre n'existe pas et `network.toml` est le **seul** endroit où
/// l'identité de la gateway puisse vivre. L'effacer ferait perdre son identité
/// à un daemon `--dev` au premier ajout de pair, sans qu'aucun message ne relie
/// la panne à l'admission qui l'a causée.
///
/// L'orchestrateur, lui, reçoit la configuration complète : c'est elle qui
/// monte l'interface et pose les pairs.
async fn apply_network(
    s: &AppState,
    updated: aether::NetworkConfig,
) -> Result<(), (StatusCode, String)> {
    let mut on_disk = updated.clone();
    if !s.dry_run {
        on_disk.wg_private_key.clear();
    }
    for peer in &mut on_disk.peers {
        peer.preshared_key = None;
    }
    on_disk
        .save()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    s.cmd_tx
        .send(OrchestratorCmd::LoadNetworkConfig(Box::new(updated)))
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "orchestrateur injoignable".to_string(),
            )
        })
}

/// Traduit un refus d'admission en code HTTP : chaque cause a le sien, pour que
/// l'appelant distingue une erreur de saisie d'un conflit d'état.
fn admission_status(error: helios_provisioning::AdmissionError) -> (StatusCode, String) {
    use helios_provisioning::AdmissionError as E;
    let code = match &error {
        E::EmptyName | E::Key(_) => StatusCode::BAD_REQUEST,
        E::NameTaken(_) | E::KeyTaken(_) => StatusCode::CONFLICT,
        E::Unknown(_) => StatusCode::NOT_FOUND,
        E::Ipam(_) => StatusCode::INSUFFICIENT_STORAGE,
    };
    (code, error.to_string())
}

pub async fn tunnel_start(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::Connect).await.is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    })
}

pub async fn tunnel_stop(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s.cmd_tx.send(OrchestratorCmd::Disconnect).await.is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    })
}

pub async fn firewall_rules_get(State(s): State<AppState>) -> Json<FirewallRulesResponse> {
    let state = *s.tunnel_state.read().await;
    let policy = s.policy.read().await;
    let rs = ruleset::render(&policy, state);

    let verdict_str = match rs.default_verdict {
        ruleset::Verdict::Drop => "drop",
        ruleset::Verdict::Accept => "accept",
    };

    // Rendu fidèle à ce que le backend Netlink applique réellement : trois
    // chaînes à hook, chacune avec sa politique par défaut.
    let mut lines = vec!["table inet helios {".to_string()];
    for kind in [
        ruleset::ChainKind::Input,
        ruleset::ChainKind::Forward,
        ruleset::ChainKind::Output,
    ] {
        let name = kind.as_str();
        lines.push(format!("  chain {name} {{"));
        lines.push(format!(
            "    type filter hook {name} priority filter; policy {verdict_str};"
        ));
        for rule in rs.chain(kind) {
            match &rule.note {
                Some(note) => lines.push(format!("    {rule}  # {note}")),
                None => lines.push(format!("    {rule}")),
            }
        }
        lines.push("  }".to_string());
    }
    if let Some(mss) = rs.mss_clamp {
        lines.push(format!(
            "  # MSS clamping demandé ({mss}) — non appliqué par le backend Netlink"
        ));
    }
    lines.push("}".to_string());

    Json(FirewallRulesResponse {
        rules: lines.join("\n"),
        default_verdict: verdict_str.to_string(),
        dry_run: s.dry_run,
    })
}

pub async fn firewall_rules_apply(
    State(s): State<AppState>,
    Json(body): Json<ApplyRulesRequest>,
) -> Json<CmdResponse> {
    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::ApplyFirewallRules(body.rules))
        .await
        .is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    })
}

pub async fn captive_portal_release(State(s): State<AppState>) -> Json<CmdResponse> {
    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::AcknowledgeCaptivePortal)
        .await
        .is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    })
}

pub async fn split_tunnel_set(
    State(s): State<AppState>,
    Json(body): Json<SplitTunnelRequest>,
) -> Json<CmdResponse> {
    let ok = s
        .cmd_tx
        .send(OrchestratorCmd::SetSplitTunnel(body.cidrs))
        .await
        .is_ok();
    Json(if ok {
        CmdResponse::ok()
    } else {
        CmdResponse::err("orchestrateur injoignable")
    })
}

/// Ancre de confiance éditeur, telle que compilée dans **ce** binaire (ADR-002).
///
/// Tout ce qui est ici est une constante de compilation, pas un état runtime :
/// c'est précisément le propos de l'ADR — la racine de confiance ne se
/// reconfigure pas à chaud, elle se remplace par une mise à jour firmware.
/// L'IHM l'affiche pour qu'un opérateur puisse vérifier *quel* trousseau le
/// binaire déployé porte réellement.
#[derive(Serialize)]
pub struct TrustResponse {
    /// Algorithmes dont une signature valide est exigée — jamais « au moins un ».
    pub required_algs: Vec<&'static str>,
    /// Époques de clés éditeur reconnues.
    pub publisher_keys: Vec<PublisherKeySummary>,
    /// `true` = trousseau de développement. Interdit en release par le build script.
    pub development_keys: bool,
    /// Domaine de séparation du billet de rescellement, et sa version de format.
    pub reseal_domain: String,
    pub reseal_format_version: u32,
}

/// Une époque du trousseau éditeur. Les clés publiques ne sont pas exposées
/// entières : l'IHM n'en a pas l'usage, une empreinte suffit à les comparer.
#[derive(Serialize)]
pub struct PublisherKeySummary {
    pub key_epoch: u32,
    pub fingerprint: String,
}

pub async fn trust() -> Json<TrustResponse> {
    use aether::sig::{ArtifactPayload as _, ResealPayload};

    Json(TrustResponse {
        required_algs: aether::sig::REQUIRED_ALGS
            .iter()
            .map(|alg| alg.as_str())
            .collect(),
        publisher_keys: aether::sig::PUBLISHER_KEYS
            .iter()
            .map(|keys| PublisherKeySummary {
                key_epoch: keys.key_epoch,
                fingerprint: keys.fingerprint(),
            })
            .collect(),
        development_keys: aether::sig::USING_DEVELOPMENT_PUBLISHER_KEYS,
        reseal_domain: String::from_utf8_lossy(ResealPayload::DOMAIN).into_owned(),
        reseal_format_version: ResealPayload::FORMAT_VERSION,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aether::{NetworkConfig, OrchestratorCmd, TunnelState, WgPeer};
    use axum::extract::State;
    use tokio::sync::{broadcast, mpsc, RwLock};

    use super::*;

    const PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const PEER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    fn network() -> NetworkConfig {
        NetworkConfig {
            wan_iface: "eth0".into(),
            lan_ifaces: vec!["lan0".into()],
            admin_iface: Some("helios0".into()),
            wg_private_key: PRIVATE_KEY.into(),
            wg_address: "100.64.0.1/10".into(),
            wg_listen_port: 51820,
            peers: vec![WgPeer {
                name: "poste-test".into(),
                public_key: PEER_KEY.into(),
                address: "100.64.1.2/32".into(),
                admin: true,
                preshared_key: Some("secret-pq-ne-doit-pas-sortir".into()),
            }],
            ..NetworkConfig::default()
        }
    }

    fn app_state(state: TunnelState) -> (AppState, mpsc::Receiver<OrchestratorCmd>) {
        let network = network();
        let (event_tx, _) = broadcast::channel(8);
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let policy = network.firewall_policy();
        (
            AppState::new(
                Arc::new(RwLock::new(network)),
                true,
                Arc::new(RwLock::new(state)),
                event_tx,
                cmd_tx,
                // Ces tests ne touchent pas au provisioning : un canal jamais
                // servi suffit.
                mpsc::channel(1).0,
                Arc::new(RwLock::new(policy)),
            ),
            cmd_rx,
        )
    }

    #[tokio::test]
    async fn status_expose_les_donnees_utiles_sans_le_psk() {
        let (app, _cmd_rx) = app_state(TunnelState::Up);

        let response = status(State(app)).await.0;

        assert_eq!(response.state, "up");
        assert_eq!(response.wg_listen_port, Some(51820));
        assert_eq!(response.peers.len(), 1);
        assert_eq!(response.peers[0].name, "poste-test");
        assert!(response.peers[0].post_quantum);
        let payload = serde_json::to_string(&response).unwrap();
        assert!(!payload.contains("secret-pq-ne-doit-pas-sortir"));
    }

    #[tokio::test]
    async fn configuration_lue_ne_serialize_jamais_les_secrets() {
        let (app, _cmd_rx) = app_state(TunnelState::Up);

        let response = network_get(State(app)).await.0;
        let payload = serde_json::to_string(&response).unwrap();

        assert!(response.wg_private_key_configured);
        assert!(response.peers[0].preshared_key_configured);
        assert!(!payload.contains(PRIVATE_KEY));
        assert!(!payload.contains("secret-pq-ne-doit-pas-sortir"));
        assert!(!payload.contains("wg_private_key\""));
        assert!(!payload.contains("preshared_key\""));
    }

    #[tokio::test]
    async fn trust_publie_l_hybride_exige_et_jamais_de_cle_entiere() {
        let response = trust().await.0;

        // L'IHM doit pouvoir affirmer « les deux, sinon rejet » : si un jour
        // quelqu'un retire ML-DSA de REQUIRED_ALGS, ce test tombe.
        assert_eq!(response.required_algs, vec!["ed25519", "ml-dsa-65"]);
        assert!(!response.publisher_keys.is_empty());
        assert_eq!(response.reseal_domain, "helios-tpm-reseal-v2");

        // Une empreinte tronquée à 128 bits, pas la clé.
        let payload = serde_json::to_string(&response).unwrap();
        for keys in aether::sig::PUBLISHER_KEYS {
            assert_eq!(keys.fingerprint().len(), 32);
            use base64::Engine as _;
            let encoded = base64::engine::general_purpose::STANDARD.encode(keys.ml_dsa_65);
            assert!(!payload.contains(&encoded));
        }
    }

    #[tokio::test]
    async fn routes_de_commande_transmettent_l_intention_exacte() {
        let (app, mut cmd_rx) = app_state(TunnelState::Down);

        assert!(tunnel_start(State(app.clone())).await.0.ok);
        assert!(matches!(
            cmd_rx.recv().await,
            Some(OrchestratorCmd::Connect)
        ));

        assert!(
            split_tunnel_set(
                State(app.clone()),
                Json(SplitTunnelRequest {
                    cidrs: vec!["10.0.0.0/8".into()]
                }),
            )
            .await
            .0
            .ok
        );
        match cmd_rx.recv().await {
            Some(OrchestratorCmd::SetSplitTunnel(cidrs)) => assert_eq!(cidrs, ["10.0.0.0/8"]),
            other => panic!("commande inattendue : {other:?}"),
        }

        assert!(tunnel_stop(State(app)).await.0.ok);
        assert!(matches!(
            cmd_rx.recv().await,
            Some(OrchestratorCmd::Disconnect)
        ));
    }

    #[tokio::test]
    async fn rendu_pare_feu_reste_fail_closed_hors_tunnel_actif() {
        let (app, _cmd_rx) = app_state(TunnelState::Down);

        let response = firewall_rules_get(State(app)).await.0;

        assert_eq!(response.default_verdict, "drop");
        assert!(response.rules.contains("udp dport 51820 accept"));
        assert!(!response.rules.contains("secret-pq-ne-doit-pas-sortir"));
    }

    #[tokio::test]
    async fn erreur_explicite_si_orchestrateur_absent() {
        let (app, cmd_rx) = app_state(TunnelState::Down);
        drop(cmd_rx);

        let response = tunnel_start(State(app)).await.0;

        assert!(!response.ok);
        assert_eq!(response.error.as_deref(), Some("orchestrateur injoignable"));
    }
}
