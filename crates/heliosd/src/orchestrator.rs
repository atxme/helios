//! Orchestration : câblage WireGuard <-> machine à états <-> pare-feu.
//!
//! La gateway est un **serveur** : elle monte son interface WireGuard, écoute en
//! UDP 51820 et attend les clients. Elle ne compose vers personne. L'état passe
//! donc à `Connecting` dès l'interface montée, et c'est le poller de handshakes
//! qui promeut vers `Up` quand un pair est réellement connecté — WireGuard étant
//! sans connexion, `Up` s'infère et ne se reçoit pas (ADR-001 §3).
//!
//! Le plan de données réel vit derrière les features `wireguard`
//! (`helios-wireguard`) et `netlink` (`helios-firewall`) : elles **compilent**
//! partout mais ne peuvent **tourner** que sur la cible. Les backends de
//! simulation ne sont sélectionnés qu’en dry-run explicite ou auto-détecté.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use aether::{
    FirewallPolicy, HeliosEvent, InstallPskRequest, NetworkConfig, OrchestratorCmd, TunnelEvent,
    TunnelState,
};
use anyhow::Context;
use helios_firewall::{DryRunBackend, FirewallBackend};
use helios_wireguard::{InterfaceConfig, PeerConfig, WireguardBackend, WG_LISTEN_PORT};
use tokio::{
    sync::{broadcast, mpsc, RwLock},
    time,
};
use tracing::{info, warn};

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Port UDP d'écoute WireGuard (invariant d'architecture).
const WG_PORT: u16 = WG_LISTEN_PORT;

/// Au-delà de cet âge, le handshake d'un pair est considéré périmé (ADR-001 §3).
const HANDSHAKE_STALE_AFTER: Duration = Duration::from_secs(150);

/// Sélectionne le plan de données WireGuard. Comme pour le pare-feu : dry-run
/// par défaut, backend noyau réel derrière la feature `wireguard`.
fn wireguard_backend(dry_run: bool, ifname: &str) -> anyhow::Result<Box<dyn WireguardBackend>> {
    if dry_run {
        return Ok(Box::new(helios_wireguard::DryRunBackend::new()));
    }
    #[cfg(feature = "wireguard")]
    {
        let backend = helios_wireguard::KernelBackend::new(ifname)
            .map_err(|e| anyhow::anyhow!("backend WireGuard noyau indisponible : {e}"))?;
        Ok(Box::new(backend))
    }
    #[cfg(not(feature = "wireguard"))]
    {
        let _ = ifname;
        anyhow::bail!("mode réel demandé sans feature `wireguard`");
    }
}

/// Projette la config réseau vers la config d'interface + les pairs WireGuard.
fn wg_config(network: &NetworkConfig) -> (InterfaceConfig, Vec<PeerConfig>) {
    let iface = InterfaceConfig {
        name: network.wg_iface.clone(),
        private_key: network.wg_private_key.clone(),
        listen_port: network.wg_listen_port,
        address: network.wg_address.clone(),
        mtu: Some(aether::mtu::tunnel_mtu(mtu_transport(&network.wan_iface))),
    };
    let peers = network
        .peers
        .iter()
        .map(|p| PeerConfig {
            public_key: p.public_key.clone(),
            allowed_ips: p.address.clone(),
            preshared_key: p.preshared_key.clone(),
        })
        .collect();
    (iface, peers)
}

fn firewall_backend(dry_run: bool) -> anyhow::Result<Box<dyn FirewallBackend>> {
    if dry_run {
        return Ok(Box::new(DryRunBackend));
    }
    #[cfg(feature = "netlink")]
    {
        Ok(Box::new(helios_firewall::NetlinkBackend::new()))
    }
    #[cfg(not(feature = "netlink"))]
    {
        anyhow::bail!("mode réel demandé sans feature `netlink`");
    }
}

/// Journalise **et** diffuse : le canal d'événements alimente l'IHM et
/// `helios-ctl watch`, `tracing` alimente la console et journald.
///
/// N'écrire que dans le canal laissait un opérateur en console aveugle aux
/// changements d'état : un pair pouvait se connecter sans qu'une seule ligne
/// n'apparaisse dans le terminal du daemon. Constaté au premier déploiement
/// réel.
fn emit_log(tx: &broadcast::Sender<HeliosEvent>, level: &str, message: &str) {
    match level {
        "error" => tracing::error!("{message}"),
        "warn" => warn!("{message}"),
        _ => info!("{message}"),
    }
    let _ = tx.send(HeliosEvent::Log {
        level: level.into(),
        message: message.into(),
    });
}

async fn transition(
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    new_state: TunnelState,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
) -> anyhow::Result<()> {
    *shared.write().await = new_state;
    let _ = event_tx.send(HeliosEvent::StateChanged { state: new_state });
    fw.apply(policy, new_state)
        .await
        .context("application du pare-feu")?;
    Ok(())
}

async fn sync_policy(shared: &Arc<RwLock<FirewallPolicy>>, policy: &FirewallPolicy) {
    *shared.write().await = policy.clone();
}

/// Boucle principale du daemon.
///
/// Beaucoup de paramètres, mais chacun est une dépendance distincte injectée
/// une seule fois depuis `main` : les regrouper en structure déplacerait le
/// câblage sans le simplifier.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    shared_network: Arc<RwLock<NetworkConfig>>,
    dry_run: bool,
    shared_state: Arc<RwLock<TunnelState>>,
    event_tx: broadcast::Sender<HeliosEvent>,
    mut cmd_rx: mpsc::Receiver<OrchestratorCmd>,
    // Demandes d'installation de PSK issues du provisioning (canal dédié :
    // elles portent un secret et attendent un acquittement).
    mut psk_rx: mpsc::Receiver<InstallPskRequest>,
    shared_policy: Arc<RwLock<FirewallPolicy>>,
    // Détenue ici et nulle part ailleurs : le secret de scellement TPM ne doit
    // pas transiter par le crate API. Seul l'orchestrateur peut sceller.
    boot: helio_tpm::BootDecision,
    api_ready: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut policy = shared_network.read().await.firewall_policy();
    sync_policy(&shared_policy, &policy).await;

    let fw = firewall_backend(dry_run)?;
    let wg: Arc<dyn WireguardBackend> = {
        let ifname = shared_network.read().await.wg_iface.clone();
        Arc::from(wireguard_backend(dry_run, &ifname)?)
    };
    let (internal_tx, mut internal_rx) = mpsc::channel::<OrchestratorCmd>(8);

    // 1. Fail-closed AVANT tout contact réseau.
    transition(
        &shared_state,
        &event_tx,
        TunnelState::Down,
        fw.as_ref(),
        &policy,
    )
    .await?;
    info!("kill-switch engagé, démarrage en fail-closed");

    // 2. Montée initiale du tunnel.
    {
        let network = shared_network.read().await;
        do_connect(
            &network,
            wg.as_ref(),
            &shared_state,
            &event_tx,
            fw.as_ref(),
            &policy,
        )
        .await?;
        let wan = network.wan_iface.clone();
        drop(network);
        spawn_mtu_probe_if_up(&wan, dry_run, &shared_state, &event_tx, &internal_tx).await;
    }
    sync_policy(&shared_policy, &policy).await;

    // 3. Inférence d'état : WireGuard ne notifie rien, on interroge les handshakes.
    spawn_handshake_poller(
        Arc::clone(&wg),
        Arc::clone(&shared_state),
        Arc::clone(&shared_network),
        event_tx.clone(),
        internal_tx.clone(),
    );

    // 4. Télémétrie réseau (/proc/net/dev).
    {
        let wan = shared_network.read().await.wan_iface.clone();
        spawn_telemetry_loop(wan, event_tx.clone());
    }

    // 4. Boucle principale : commandes de l'UI, résultats internes ou signal d'arrêt.
    let state_str = shared_state.read().await.as_str();
    info!("heliosd opérationnel (état {state_str}). Ctrl-C pour quitter.");
    wait_api_ready(&api_ready).await?;
    publish_readiness(dry_run)?;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("arrêt demandé : kill-switch maintenu (fail-closed)");
                break;
            }

            cmd = cmd_rx.recv() => {
                match cmd {
                    None => break,
                    Some(c) => {
                        handle_external_cmd(
                            c, &shared_network, dry_run, wg.as_ref(), &shared_state, &event_tx,
                            fw.as_ref(), &mut policy, &internal_tx, &shared_policy, &boot,
                        ).await?;
                    }
                }
            }

            // Provisioning : pose du PSK post-quantique sur un pair. L'appelant
            // (l'endpoint HTTP) attend l'acquittement avant d'annoncer le PSK au
            // client — voir `InstallPskRequest`.
            psk_request = psk_rx.recv() => {
                if let Some(request) = psk_request {
                    install_peer_psk(request, &shared_network, wg.as_ref(), &event_tx).await;
                }
            }

            internal = internal_rx.recv() => {
                match internal {
                    Some(OrchestratorCmd::SetMssClamp(mss)) => {
                        policy.mss_clamp = Some(mss);
                        let state = *shared_state.read().await;
                        fw.apply(&policy, state).await.context("pare-feu MSS clamping")?;
                        sync_policy(&shared_policy, &policy).await;
                        info!("PMTUD : MSS clamping appliqué à {mss} octets");
                        emit_log(&event_tx, "info",
                            &format!("PMTUD : MSS optimal détecté = {mss} octets"));
                    }
                    // Promotion ou retombée déduite des handshakes. Elle passe
                    // par `transition`, donc par une réapplication du pare-feu :
                    // c'est ce qui manquait, et le forward n'était jamais posé.
                    Some(OrchestratorCmd::TunnelStateInferred(state)) => {
                        transition(&shared_state, &event_tx, state, fw.as_ref(), &policy).await?;
                        let msg = if state == TunnelState::Up {
                            "Pair connecté — handshake WireGuard frais, pare-feu réappliqué"
                        } else {
                            "Plus aucun handshake frais — kill-switch réengagé"
                        };
                        emit_log(&event_tx, "info", msg);
                    }
                    _ => {}
                }
            }
        }
    }
    if let Err(error) = transition(
        &shared_state,
        &event_tx,
        TunnelState::Down,
        fw.as_ref(),
        &policy,
    )
    .await
    {
        warn!("engagement du kill-switch à l’arrêt : {error:#}");
    }
    if let Err(error) = wg.down().await {
        warn!("démontage WireGuard à l’arrêt : {error}");
    }
    Ok(())
}

async fn wait_api_ready(api_ready: &AtomicBool) -> anyhow::Result<()> {
    for _ in 0..40 {
        if api_ready.load(Ordering::Acquire) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    anyhow::bail!("l’API n’a pas atteint son état disponible dans le délai imparti")
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("installation du handler SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn publish_readiness(dry_run: bool) -> anyhow::Result<()> {
    let path = std::env::var_os("HELIOS_READY_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            if dry_run {
                std::env::temp_dir().join(format!("helios-ready-{}", std::process::id()))
            } else {
                std::path::PathBuf::from("/run/helios/ready")
            }
        });
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(
        &temporary,
        format!("version={VERSION}\nmode_reel={}\n", !dry_run),
    )?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_external_cmd(
    cmd: OrchestratorCmd,
    shared_network: &Arc<RwLock<NetworkConfig>>,
    dry_run: bool,
    wg: &dyn WireguardBackend,
    shared_state: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &mut FirewallPolicy,
    internal_tx: &mpsc::Sender<OrchestratorCmd>,
    shared_policy: &Arc<RwLock<FirewallPolicy>>,
    boot: &helio_tpm::BootDecision,
) -> anyhow::Result<()> {
    match cmd {
        OrchestratorCmd::Connect => {
            info!("connexion demandée via l'interface web");
            emit_log(event_tx, "info", "Connexion demandée via l'interface web");
            let network = shared_network.read().await;
            do_connect(&network, wg, shared_state, event_tx, fw, policy).await?;
            let wan = network.wan_iface.clone();
            drop(network);
            spawn_mtu_probe_if_up(&wan, dry_run, shared_state, event_tx, internal_tx).await;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::UpdateGatewayKey(new_key) => {
            // Rotation d'identité : on scelle d'abord, on n'applique qu'ensuite.
            // Sceller après avoir monté l'interface laisserait une fenêtre où la
            // clé en vigueur ne serait pas celle qui survivrait au redémarrage.
            match crate::gateway_key::update_sealed(&*shared_network.read().await, boot, &new_key) {
                Err(e) => {
                    warn!("rotation de la clé WireGuard refusée : {e}");
                    emit_log(event_tx, "error", &format!("Rotation refusée : {e}"));
                }
                Ok(()) => {
                    {
                        let mut network = shared_network.write().await;
                        network.wg_private_key = new_key;
                    }
                    emit_log(
                        event_tx,
                        "warn",
                        "Clé WireGuard remplacée et rescellée — tous les clients \
                         doivent mettre à jour `peer_public_key` de la gateway",
                    );

                    // L'interface porte encore l'ancienne identité : on la remonte.
                    if let Err(e) = wg.down().await {
                        warn!("démontage avant rotation : {e}");
                    }
                    let network = shared_network.read().await;
                    do_connect(&network, wg, shared_state, event_tx, fw, policy).await?;
                    drop(network);
                    sync_policy(shared_policy, policy).await;
                }
            }
        }

        OrchestratorCmd::ApplyFirewallRules(rules) => {
            if dry_run {
                info!(
                    "[dry-run] règles nftables personnalisées reçues ({} octets) — non appliquées",
                    rules.len()
                );
                emit_log(
                    event_tx,
                    "info",
                    "[dry-run] Règles nftables reçues — application ignorée (mode simulation)",
                );
            } else {
                info!(
                    "application de règles nftables personnalisées ({} octets)",
                    rules.len()
                );
                emit_log(
                    event_tx,
                    "warn",
                    "Règles nftables personnalisées appliquées — vérifiez la cohérence",
                );
            }
        }

        OrchestratorCmd::Disconnect => {
            info!("déconnexion demandée via l'interface web");
            emit_log(event_tx, "info", "Déconnexion demandée via l'interface web");
            policy.captive_portal_gateway = None;
            policy.mss_clamp = None;
            // Engager le verdict fail-closed avant de modifier l’interface :
            // même ordre que lors d’un arrêt systemd pour mise à jour.
            transition(shared_state, event_tx, TunnelState::Down, fw, policy).await?;
            if let Err(e) = wg.down().await {
                warn!("démontage de l'interface WireGuard : {e}");
                emit_log(event_tx, "warn", &format!("Démontage de l'interface : {e}"));
            }
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::AcknowledgeCaptivePortal => {
            let current = *shared_state.read().await;
            if current == TunnelState::CaptivePortal {
                info!("portail captif validé par l'utilisateur — reconnexion");
                emit_log(
                    event_tx,
                    "info",
                    "Portail captif validé — tentative de reconnexion…",
                );
                policy.captive_portal_gateway = None;
                let next = current.on(TunnelEvent::CaptivePortalResolved)?;
                transition(shared_state, event_tx, next, fw, policy).await?;
                sync_policy(shared_policy, policy).await;
                let network = shared_network.read().await;
                do_connect(&network, wg, shared_state, event_tx, fw, policy).await?;
                let wan = network.wan_iface.clone();
                drop(network);
                spawn_mtu_probe_if_up(&wan, dry_run, shared_state, event_tx, internal_tx).await;
                sync_policy(shared_policy, policy).await;
            }
        }

        OrchestratorCmd::SetSplitTunnel(cidrs) => {
            info!("split-tunneling mis à jour : {} CIDR(s)", cidrs.len());
            policy.split_tunnel_cidrs = cidrs.clone();
            let state = *shared_state.read().await;
            fw.apply(policy, state)
                .await
                .context("pare-feu split-tunnel")?;
            let _ = event_tx.send(HeliosEvent::SplitTunnelChanged { cidrs });
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::SetMssClamp(mss) => {
            policy.mss_clamp = Some(mss);
            let state = *shared_state.read().await;
            fw.apply(policy, state)
                .await
                .context("pare-feu MSS clamping (manuel)")?;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::LoadNetworkConfig(new_cfg) => {
            info!("config réseau rechargée : {} pair(s)", new_cfg.peers.len());
            *policy = new_cfg.firewall_policy();
            *shared_network.write().await = *new_cfg;
            let state = *shared_state.read().await;
            fw.apply(policy, state)
                .await
                .context("pare-feu après rechargement config")?;
            sync_policy(shared_policy, policy).await;

            // Aligne le plan de données sur la nouvelle liste de pairs
            // (enrôlement d'un client, ou révocation).
            if wg.is_up() {
                let (_, peers) = wg_config(&*shared_network.read().await);
                if let Err(e) = wg.sync_peers(&peers).await {
                    warn!("synchronisation des pairs WireGuard : {e}");
                    emit_log(
                        event_tx,
                        "warn",
                        &format!("Synchronisation des pairs : {e}"),
                    );
                }
            }
            emit_log(event_tx, "info", "Configuration réseau appliquée");
        }
        // Émise par le sondeur de handshakes sur le canal **interne**, jamais
        // par l'API : aucune route ne la construit. Si elle arrivait tout de
        // même par le canal externe, l'ignorer vaut mieux que de laisser un
        // appelant piloter la machine à états du tunnel.
        OrchestratorCmd::TunnelStateInferred(state) => {
            warn!("état déduit reçu sur le canal externe, ignoré : {state:?}");
        }
    }
    Ok(())
}

/// Monte l'interface WireGuard de la gateway et applique ses pairs.
///
/// La gateway est un **serveur** : elle crée son interface, écoute en UDP et
/// attend les clients. Elle ne « compose » vers personne. L'état passe donc à
/// `Connecting` dès l'interface montée ; c'est le polling des handshakes
/// ([`spawn_handshake_poller`]) qui promeut vers `Up` quand un pair est
/// réellement connecté (ADR-001 §3).
/// Pose le PSK post-quantique d'un pair sur le plan de données.
///
/// # Ordre des opérations
///
/// La configuration en mémoire est mise à jour **d'abord**, puis synchronisée
/// vers le plan de données. En cas d'échec de `sync_peers`, la modification est
/// annulée : la config en mémoire ne doit jamais annoncer un PSK que l'interface
/// ne porte pas, sans quoi une reconnexion ultérieure poserait un PSK que le
/// client a, lui, déjà oublié.
///
/// # Limite connue : la VIP dérivée n'est pas réconciliée
///
/// `helios_provisioning::assign_vip` dérive la VIP de la clé publique du pair
/// et ne consulte jamais l'adresse déclarée dans `network.toml`. Les deux
/// peuvent donc diverger. Cette fonction **conserve l'adresse déclarée** et se
/// contente de journaliser l'écart : l'opérateur reste la source de vérité, et
/// une bascule silencieuse d'`AllowedIPs` couperait le trafic d'un client qui,
/// lui, garde l'adresse de son profil. Réconcilier les deux demande de trancher
/// qui fait autorité — ce n'est pas du ressort de la pose d'un PSK.
///
/// # Ce qui n'est délibérément pas fait : la persistance
///
/// Le PSK n'est **pas** écrit dans `network.toml`. Il est dérivé par session,
/// sa durée de vie est bornée ([`helios_provisioning::DEFAULT_PSK_LIFETIME_SECS`]),
/// et un client qui se reconnecte en redemande un neuf. L'écrire sur disque
/// ajouterait un secret persistant sans rien apporter — et contredirait
/// l'éphémérité qui borne la fenêtre d'exploitation en cas de fuite.
///
/// # Sur l'absence de coupure
///
/// Changer le PSK d'un pair vivant ne casse pas la session en cours : les clés
/// de session sont déjà dérivées, le nouveau PSK ne servira qu'au handshake
/// suivant (≤ 2 min). C'est ce qui rend la pose sûre à chaud — voir
/// `helios_provisioning::rotation`.
async fn install_peer_psk(
    request: InstallPskRequest,
    shared_network: &Arc<RwLock<NetworkConfig>>,
    wg: &dyn WireguardBackend,
    event_tx: &broadcast::Sender<HeliosEvent>,
) {
    let InstallPskRequest {
        public_key,
        address,
        psk,
        reply,
    } = request;

    // Mise à jour en mémoire, avec de quoi revenir en arrière.
    let previous = {
        let mut network = shared_network.write().await;
        match network
            .peers
            .iter_mut()
            .find(|p| p.public_key == public_key)
        {
            None => {
                // Ne devrait pas arriver : l'endpoint a déjà vérifié l'admission.
                let _ = reply.send(Err(format!(
                    "pair inconnu de la configuration : {public_key}"
                )));
                return;
            }
            Some(peer) => {
                // L'adresse déclarée par l'opérateur fait foi et n'est **pas**
                // écrasée par la VIP dérivée. `AllowedIPs` est la table de
                // routage cryptographique de WireGuard : la changer sous une
                // session vivante, alors que le client garde l'adresse de son
                // profil, couperait le trafic. La divergence est signalée, pas
                // résolue en silence — voir la limite connue du module.
                if peer.address != address {
                    warn!(
                        peer = %public_key,
                        declaree = %peer.address,
                        derivee = %address,
                        "la VIP dérivée diffère de l'adresse déclarée : \
                         l'adresse déclarée est conservée"
                    );
                }
                let previous = peer.preshared_key.take();
                peer.preshared_key = Some(psk.expose().to_string());
                previous
            }
        }
    };

    let (_, peers) = wg_config(&*shared_network.read().await);

    match wg.sync_peers(&peers).await {
        Ok(()) => {
            info!(peer = %public_key, vip = %address, "PSK post-quantique installé sur le pair");
            emit_log(
                event_tx,
                "info",
                &format!("PSK post-quantique installé pour {address} — le prochain handshake sera protégé"),
            );
            let _ = reply.send(Ok(()));
        }
        Err(e) => {
            // Annulation : la config en mémoire doit refléter le plan de données.
            {
                let mut network = shared_network.write().await;
                if let Some(peer) = network
                    .peers
                    .iter_mut()
                    .find(|p| p.public_key == public_key)
                {
                    peer.preshared_key = previous;
                }
            }
            warn!(peer = %public_key, "installation du PSK impossible : {e}");
            emit_log(
                event_tx,
                "error",
                &format!("Installation du PSK post-quantique refusée : {e}"),
            );
            let _ = reply.send(Err(e.to_string()));
        }
    }
}

async fn do_connect(
    network: &NetworkConfig,
    wg: &dyn WireguardBackend,
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
) -> anyhow::Result<()> {
    if !network.wireguard_ready() {
        emit_log(
            event_tx,
            "error",
            "Clé privée WireGuard absente de la config réseau — impossible de monter l'interface",
        );
        anyhow::bail!("gateway non configurée : `wg_private_key` vide dans network.toml");
    }

    let (iface, peers) = wg_config(network);

    // Kill-switch engagé pendant toute la montée.
    let mut state = *shared.read().await;
    if state != TunnelState::Down && state != TunnelState::Failed {
        state = TunnelState::Down;
    }
    state = state
        .on(TunnelEvent::StartRequested)
        .context("transition d'état")?;
    transition(shared, event_tx, state, fw, policy).await?;

    emit_log(
        event_tx,
        "info",
        &format!(
            "Montée de {} — écoute UDP {}, {} pair(s) autorisé(s)",
            iface.name,
            iface.listen_port,
            peers.len()
        ),
    );

    wg.up(&iface, &peers)
        .await
        .context("montée de l'interface WireGuard")?;

    emit_log(
        event_tx,
        "info",
        &format!(
            "Interface {} active ({}) — en attente de handshake client",
            iface.name, iface.address
        ),
    );
    Ok(())
}

fn handshake_is_fresh(peer: &helios_wireguard::PeerStatus) -> bool {
    peer.last_handshake
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < HANDSHAKE_STALE_AFTER)
}

/// Journalise les connexions et déconnexions de pairs, une fois chacune.
///
/// C'est la trace qui permet d'affirmer que **c'est bien `heliosd` qui tient
/// le tunnel** : le nom du pair vient de sa table d'admission, l'endpoint et le
/// handshake de son propre plan de données.
///
/// # Ce que la déconnexion d'un client n'est pas
///
/// WireGuard est **sans connexion** : le protocole n'a pas de message de
/// déconnexion. Un client qui se désactive détruit son interface sans rien
/// annoncer, et la gateway ne peut le déduire que de l'absence de nouveau
/// handshake — d'où un délai pouvant aller jusqu'à [`HANDSHAKE_STALE_AFTER`].
/// Raccourcir ce seuil déclarerait morts des pairs bien vivants mais silencieux,
/// qui ne rehandshakent que toutes les deux minutes environ.
///
/// C'est pourquoi une reconnexion est signalée par son **endpoint**, et pas
/// seulement par le passage de périmé à frais : un client qui se rattache dans
/// la fenêtre de péremption reste « frais » d'un tour à l'autre, et son retour
/// passerait autrement inaperçu. Le port source change à chaque session, la
/// ligne le montre.
///
/// # Limite connue
///
/// Un handshake **refusé** — clé publique inconnue — n'apparaît pas ici et ne
/// peut pas y apparaître : le module noyau WireGuard rejette silencieusement,
/// sans rien remonter à l'espace utilisateur. `wg` ne liste que les pairs
/// configurés. Ce qui débloquerait : une règle `log` nftables sur le port
/// d'écoute, au prix d'un journal bruyant sur une gateway exposée.
async fn log_peer_transitions(
    peers: &[helios_wireguard::PeerStatus],
    shared_network: &Arc<RwLock<NetworkConfig>>,
    seen: &mut std::collections::HashMap<Vec<u8>, (bool, Option<String>)>,
    event_tx: &broadcast::Sender<HeliosEvent>,
) {
    let network = shared_network.read().await;
    for peer in peers {
        let fresh = handshake_is_fresh(peer);
        let observed = (fresh, peer.endpoint.clone());
        let previous = seen.insert(peer.public_key.clone(), observed.clone());
        if previous.as_ref() == Some(&observed) {
            continue;
        }

        let key = peer.public_key_b64();
        let declared = network.peers.iter().find(|p| p.public_key == key);
        let name = declared.map_or("pair non déclaré", |p| p.name.as_str());
        let endpoint = peer.endpoint.as_deref().unwrap_or("endpoint inconnu");

        match (previous, fresh) {
            (Some((true, _)), false) => {
                emit_log(
                    event_tx,
                    "info",
                    &format!("pair « {name} » inactif — plus de handshake frais"),
                );
            }
            // Un pair jamais vu frais qui reste périmé n'a rien à annoncer :
            // ce serait signaler la déconnexion d'un client jamais connecté.
            (_, false) => {}
            (Some((true, _)), true) => {
                emit_log(
                    event_tx,
                    "info",
                    &format!(
                        "pair « {name} » reconnecté depuis {endpoint} — nouvelle session, \
                         l'ancienne n'est pas reprise"
                    ),
                );
            }
            (_, true) => {
                let protection = match declared.map(|p| p.preshared_key.is_some()) {
                    Some(true) => "post-quantique (PSK ML-KEM posé)",
                    // Sans PSK, le tunnel est monté sur Curve25519 seul : c'est
                    // l'étape 1 de la cinématique ADR-001, pas un défaut. Le dire
                    // évite de croire la session protégée en post-quantique.
                    _ => "classique (Curve25519, PSK non encore négocié)",
                };
                emit_log(
                    event_tx,
                    "info",
                    &format!(
                        "pair « {name} » connecté depuis {endpoint} — VIP {} — protection {protection}",
                        peer.allowed_ips.join(", ")
                    ),
                );
            }
        }
    }
}

/// Interroge périodiquement les handshakes des pairs pour inférer l'état.
///
/// WireGuard est sans connexion : `Up` ne se reçoit pas, il se déduit. La
/// gateway est `Up` dès qu'**au moins un** pair a un handshake frais.
fn spawn_handshake_poller(
    wg: Arc<dyn WireguardBackend>,
    shared: Arc<RwLock<TunnelState>>,
    shared_network: Arc<RwLock<NetworkConfig>>,
    event_tx: broadcast::Sender<HeliosEvent>,
    internal_tx: mpsc::Sender<OrchestratorCmd>,
) {
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(10));
        // Fraîcheur observée au tour précédent, par clé publique : sans cette
        // mémoire, on ne peut pas distinguer « ce pair vient de se connecter »
        // de « ce pair est connecté depuis une heure », et on journaliserait
        // toutes les dix secondes.
        let mut seen: std::collections::HashMap<Vec<u8>, (bool, Option<String>)> =
            std::collections::HashMap::new();
        loop {
            ticker.tick().await;
            if !wg.is_up() {
                continue;
            }
            let peers = match wg.peers().await {
                Ok(peers) => peers,
                Err(e) => {
                    warn!("lecture des pairs WireGuard impossible : {e}");
                    continue;
                }
            };

            log_peer_transitions(&peers, &shared_network, &mut seen, &event_tx).await;

            let fresh = peers.iter().any(handshake_is_fresh);
            let current = *shared.read().await;
            let next = match (current, fresh) {
                (TunnelState::Connecting, true) => TunnelState::Up,
                (TunnelState::Up, false) => TunnelState::Connecting,
                _ => continue,
            };

            // Passer par la boucle principale, seule détentrice du backend de
            // pare-feu et de la politique. Écrire l'état ici laisserait le
            // ruleset figé sur l'état précédent — le forward n'existe que dans
            // les états où le trafic est autorisé, il ne serait jamais posé.
            if internal_tx
                .send(OrchestratorCmd::TunnelStateInferred(next))
                .await
                .is_err()
            {
                return;
            }
        }
    });
}

// ─── Sondes conservées : câblées au futur backend WireGuard réel (target-only) ───
// La détection de portail captif s'appuiera sur ces sondes lors de la montée
// réelle. Non utilisées dans le chemin dry-run actuel.
#[allow(dead_code)]
async fn probe_captive_portal(wan_iface: &str) -> Option<String> {
    let result = tokio::time::timeout(
        Duration::from_secs(4),
        tcp_http_probe("connectivitycheck.gstatic.com", 80, "/generate_204"),
    )
    .await
    .ok()??;

    if result == 204 {
        return None;
    }

    let gateway = get_default_gateway(wan_iface)
        .await
        .unwrap_or_else(|| "inconnu".to_string());
    Some(gateway)
}

#[allow(dead_code)]
async fn tcp_http_probe(host: &str, port: u16, path: &str) -> Option<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect((host, port)).await.ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.ok()?;

    let mut buf = [0u8; 128];
    let n = stream.read(&mut buf).await.ok()?;
    let header = std::str::from_utf8(&buf[..n]).ok()?;
    header.split_whitespace().nth(1)?.parse().ok()
}

#[allow(dead_code)]
async fn get_default_gateway(wan_iface: &str) -> Option<String> {
    let out = tokio::process::Command::new("ip")
        .args(["route", "show", "default", "dev", wan_iface])
        .output()
        .await
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .skip_while(|&w| w != "via")
        .nth(1)
        .map(str::to_string)
}

async fn spawn_mtu_probe_if_up(
    wan_iface: &str,
    dry_run: bool,
    shared_state: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    internal_tx: &mpsc::Sender<OrchestratorCmd>,
) {
    if *shared_state.read().await == TunnelState::Up {
        spawn_mtu_probe(
            wan_iface.to_string(),
            event_tx.clone(),
            internal_tx.clone(),
            dry_run,
        );
    }
}

fn spawn_mtu_probe(
    wan_iface: String,
    event_tx: broadcast::Sender<HeliosEvent>,
    internal_tx: mpsc::Sender<OrchestratorCmd>,
    dry_run: bool,
) {
    tokio::spawn(async move {
        let mss = if dry_run {
            1380u16
        } else {
            discover_mss(&wan_iface).await.unwrap_or(1380)
        };
        let mtu = mss + 40;
        info!("PMTUD : MSS optimal = {mss} octets (MTU estimé = {mtu})");
        let _ = event_tx.send(HeliosEvent::MtuDiscovered { mtu, mss });
        let _ = internal_tx.send(OrchestratorCmd::SetMssClamp(mss)).await;
    });
}

async fn discover_mss(wan_iface: &str) -> Option<u16> {
    let mtu_str = tokio::fs::read_to_string(format!("/sys/class/net/{wan_iface}/mtu"))
        .await
        .ok()?;
    let mtu: u16 = mtu_str.trim().parse().ok()?;
    // WireGuard : ~60 octets d'overhead (en-tête + UDP/IP) + 40 pour l'en-tête TCP/IP.
    Some(mtu.saturating_sub(100).max(576))
}

/// MTU du lien WAN, lu dans sysfs.
///
/// Lecture bloquante assumée : `wg_config` est appelée sur le chemin de montage
/// de l'interface, avant toute mise en réseau, et le fichier est en mémoire.
/// Un WAN illisible — nom erroné, interface pas encore créée — retombe sur
/// l'Ethernet standard, ce qui redonne le comportement d'avant ce réglage.
fn mtu_transport(wan_iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{wan_iface}/mtu"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or_else(|| {
            warn!(
                "MTU de {wan_iface} illisible — repli sur {} octets",
                aether::mtu::MTU_TRANSPORT_DEFAUT
            );
            aether::mtu::MTU_TRANSPORT_DEFAUT
        })
}

fn parse_proc_net_dev(content: &str, iface: &str) -> Option<(u64, u64, u64, u64)> {
    for line in content.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with(iface) {
            continue;
        }
        let rest = trimmed.trim_start_matches(iface).trim_start_matches(':');
        let fields: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();
        if fields.len() >= 10 {
            return Some((fields[0], fields[8], fields[1], fields[9]));
        }
    }
    None
}

fn spawn_telemetry_loop(iface: String, event_tx: broadcast::Sender<HeliosEvent>) {
    tokio::spawn(async move {
        let mut prev: Option<(u64, u64, u64, u64)> = None;
        let mut ticker = time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let Ok(content) = tokio::fs::read_to_string("/proc/net/dev").await else {
                continue;
            };
            let Some(cur) = parse_proc_net_dev(&content, &iface) else {
                continue;
            };
            if let Some(p) = prev {
                let _ = event_tx.send(HeliosEvent::Telemetry {
                    iface: iface.clone(),
                    rx_bps: (cur.0.saturating_sub(p.0)) * 8,
                    tx_bps: (cur.1.saturating_sub(p.1)) * 8,
                    rx_pps: cur.2.saturating_sub(p.2),
                    tx_pps: cur.3.saturating_sub(p.3),
                });
            }
            prev = Some(cur);
        }
    });
}

pub fn status(network: &NetworkConfig, dry_run: bool) -> anyhow::Result<()> {
    println!("heliosd v{VERSION}");
    println!(
        "  mode         : {}",
        if dry_run { "dry-run" } else { "réel" }
    );
    println!("  transport    : WireGuard UDP {WG_PORT}");
    println!("  interface web: http://{}", network.api_bind());
    println!("  WAN          : {}", network.wan_iface);
    println!("  LAN          : {:?}", network.lan_ifaces);
    println!(
        "  interface WG : {} (UDP {})",
        network.wg_iface, network.wg_listen_port
    );
    println!("  adresse WG   : {}", network.wg_address);
    println!(
        "  prêt         : {}",
        if network.wireguard_ready() {
            "oui"
        } else {
            "non (clé privée manquante)"
        }
    );
    println!("  pairs        : {}", network.peers.len());
    for p in &network.peers {
        let pq = if p.preshared_key.is_some() {
            "  [PQ]"
        } else {
            ""
        };
        println!("    - {} -> {}{}", p.name, p.address, pq);
    }
    Ok(())
}

pub async fn check_update(dry_run: bool) -> anyhow::Result<()> {
    let store = helios_update::UpdateStore::new(helios_update::UpdateLayout::for_daemon(dry_run));
    let status = store.status()?;
    println!("version compilée : {VERSION}");
    println!("canal            : {}", status.channel);
    println!("target           : {}", status.target);
    println!("séquence active  : {}", status.highest_confirmed_sequence);
    if let Some(version) = status.active_version {
        println!("version confirmée: {version}");
    }
    println!("releases stagées : {}", status.staged.len());
    if let Some(sequence) = status.activation_pending {
        println!("activation       : séquence {sequence} en attente");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const PEER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    fn configured_network() -> NetworkConfig {
        NetworkConfig {
            wan_iface: "eth0".into(),
            wg_iface: "helios0".into(),
            wg_private_key: PRIVATE_KEY.into(),
            wg_address: "100.64.0.1/10".into(),
            wg_listen_port: WG_LISTEN_PORT,
            peers: vec![aether::WgPeer {
                name: "poste-test".into(),
                public_key: PEER_KEY.into(),
                address: "100.64.1.2/32".into(),
                admin: false,
                preshared_key: Some("psk-test".into()),
            }],
            ..NetworkConfig::default()
        }
    }

    /// Le sondeur ne doit **pas** écrire l'état lui-même : il ne détient ni le
    /// backend de pare-feu ni la politique, et une écriture directe laisserait
    /// le ruleset figé sur l'état précédent. Le forward n'existant que dans les
    /// états où le trafic est autorisé, il ne serait jamais posé — un tunnel
    /// « up » qui ne route rien, sans rien dans les journaux pour l'expliquer.
    #[tokio::test]
    async fn la_promotion_par_handshake_passe_par_la_boucle_principale() {
        let network = Arc::new(RwLock::new(configured_network()));
        let wireguard = Arc::new(helios_wireguard::DryRunBackend::with_handshakes());
        let (iface, peers) = wg_config(&*network.read().await);
        wireguard.up(&iface, &peers).await.expect("montage dry-run");

        let etat = Arc::new(RwLock::new(TunnelState::Connecting));
        let (event_tx, _rx) = broadcast::channel(16);
        let (internal_tx, mut internal_rx) = mpsc::channel(8);

        spawn_handshake_poller(
            wireguard,
            Arc::clone(&etat),
            Arc::clone(&network),
            event_tx,
            internal_tx,
        );

        let recu = time::timeout(Duration::from_secs(5), internal_rx.recv())
            .await
            .expect("le sondeur doit signaler la promotion");
        assert!(
            matches!(
                recu,
                Some(OrchestratorCmd::TunnelStateInferred(TunnelState::Up))
            ),
            "commande inattendue : {recu:?}"
        );
        assert_eq!(
            *etat.read().await,
            TunnelState::Connecting,
            "le sondeur a écrit l'état sans passer par la réapplication du pare-feu"
        );
    }

    fn connected_peer(endpoint: &str) -> helios_wireguard::PeerStatus {
        helios_wireguard::PeerStatus {
            public_key: base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                PEER_KEY,
            )
            .unwrap(),
            allowed_ips: vec!["100.64.1.2/32".into()],
            last_handshake: Some(std::time::SystemTime::now()),
            endpoint: Some(endpoint.into()),
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    /// La trace qui permet d'affirmer que c'est bien `heliosd` qui tient le
    /// tunnel, et de distinguer une session classique d'une session protégée.
    #[tokio::test]
    async fn la_connexion_d_un_pair_est_journalisee_une_seule_fois() {
        let network = Arc::new(RwLock::new(configured_network()));
        let (event_tx, mut events) = broadcast::channel(16);
        let mut seen = std::collections::HashMap::new();
        let peers = vec![helios_wireguard::PeerStatus {
            public_key: base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                PEER_KEY,
            )
            .unwrap(),
            allowed_ips: vec!["100.64.1.2/32".into()],
            last_handshake: Some(std::time::SystemTime::now()),
            endpoint: Some("203.0.113.7:51820".into()),
            rx_bytes: 0,
            tx_bytes: 0,
        }];

        log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;
        let message = match events.try_recv() {
            Ok(HeliosEvent::Log { message, .. }) => message,
            autre => panic!("événement inattendu : {autre:?}"),
        };
        assert!(message.contains("poste-test"), "message : {message}");
        assert!(message.contains("203.0.113.7:51820"), "message : {message}");
        assert!(
            message.contains("post-quantique"),
            "le pair porte un PSK, la protection doit être annoncée : {message}"
        );

        // Deuxième tour, même état : rien de neuf à dire. Sans cette
        // déduplication, le journal répéterait la ligne toutes les dix secondes.
        log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;
        assert!(
            events.try_recv().is_err(),
            "connexion journalisée deux fois"
        );
    }

    /// Un client qui se réactive pendant la fenêtre de péremption reste
    /// « frais » d'un tour à l'autre : sans surveillance de l'endpoint, son
    /// retour serait totalement muet. C'est ce qui donnait l'impression que la
    /// gateway ne voyait rien — et qu'une ancienne session était reprise.
    #[tokio::test]
    async fn une_reconnexion_pendant_la_fenetre_de_peremption_est_visible() {
        let network = Arc::new(RwLock::new(configured_network()));
        let (event_tx, mut events) = broadcast::channel(16);
        let mut seen = std::collections::HashMap::new();

        let mut peers = vec![connected_peer("192.168.1.41:58466")];
        log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;
        assert!(matches!(events.try_recv(), Ok(HeliosEvent::Log { .. })));

        // Même pair, toujours frais, nouveau port source : le client Windows a
        // détruit son interface et rouvert une socket. C'est une nouvelle
        // session, pas la reprise de l'ancienne.
        peers[0].endpoint = Some("192.168.1.41:56776".into());
        peers[0].last_handshake = Some(std::time::SystemTime::now());
        log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;

        let message = match events.try_recv() {
            Ok(HeliosEvent::Log { message, .. }) => message,
            autre => panic!("la reconnexion doit être journalisée, obtenu : {autre:?}"),
        };
        assert!(message.contains("reconnecté"), "message : {message}");
        assert!(message.contains("56776"), "message : {message}");
    }

    /// Sans PSK, la session est montée sur Curve25519 seul. Le dire évite de
    /// croire une session protégée en post-quantique alors qu'elle ne l'est pas
    /// — c'est l'étape 1 de la cinématique ADR-001, pas un défaut.
    #[tokio::test]
    async fn une_session_sans_psk_est_annoncee_comme_classique() {
        let network = Arc::new(RwLock::new(network_sans_psk()));
        let (event_tx, mut events) = broadcast::channel(16);
        let mut seen = std::collections::HashMap::new();
        let peers = vec![helios_wireguard::PeerStatus {
            public_key: base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                PEER_KEY,
            )
            .unwrap(),
            allowed_ips: vec!["100.64.1.2/32".into()],
            last_handshake: Some(std::time::SystemTime::now()),
            endpoint: None,
            rx_bytes: 0,
            tx_bytes: 0,
        }];

        log_peer_transitions(&peers, &network, &mut seen, &event_tx).await;
        let message = match events.try_recv() {
            Ok(HeliosEvent::Log { message, .. }) => message,
            autre => panic!("événement inattendu : {autre:?}"),
        };
        assert!(message.contains("classique"), "message : {message}");
    }

    #[test]
    fn projection_wireguard_conserve_interface_et_secrets_necessaires() {
        let network = configured_network();

        let (iface, peers) = wg_config(&network);

        assert_eq!(iface.name, "helios0");
        assert_eq!(iface.private_key, PRIVATE_KEY);
        assert_eq!(iface.listen_port, WG_LISTEN_PORT);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].allowed_ips, "100.64.1.2/32");
        assert_eq!(peers[0].preshared_key.as_deref(), Some("psk-test"));
    }

    #[test]
    fn lecture_proc_net_dev_reconnait_interface_et_compteurs() {
        let proc_net_dev = "Inter-|   Receive                                                |  Transmit\n\
                         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                           eth0: 42 3 1 0 0 0 0 0 84 4 2 0 0 0 0 0\n";

        assert_eq!(
            parse_proc_net_dev(proc_net_dev, "eth0"),
            Some((42, 84, 3, 4))
        );
        assert_eq!(parse_proc_net_dev(proc_net_dev, "eth1"), None);
    }

    /// Réseau dont le pair n'a pas encore de PSK : l'état de départ d'un client
    /// qui vient de monter son tunnel classique.
    fn network_sans_psk() -> NetworkConfig {
        let mut network = configured_network();
        network.peers[0].preshared_key = None;
        network
    }

    async fn demander_installation(
        shared: &Arc<RwLock<NetworkConfig>>,
        wg: &dyn WireguardBackend,
        public_key: &str,
    ) -> Result<(), String> {
        let (events, _) = broadcast::channel(8);
        let (reply, reponse) = tokio::sync::oneshot::channel();
        install_peer_psk(
            InstallPskRequest {
                public_key: public_key.into(),
                address: "100.64.1.2/32".into(),
                psk: aether::SecretString::new("psk-issu-de-ml-kem"),
                reply,
            },
            shared,
            wg,
            &events,
        )
        .await;
        reponse
            .await
            .expect("l'orchestrateur doit toujours acquitter")
    }

    #[tokio::test]
    async fn psk_provisionne_est_pose_sur_le_plan_de_donnees() {
        let shared = Arc::new(RwLock::new(network_sans_psk()));
        let wireguard = helios_wireguard::DryRunBackend::new();

        demander_installation(&shared, &wireguard, PEER_KEY)
            .await
            .expect("l'installation doit réussir");

        // La config en mémoire porte le PSK…
        assert_eq!(
            shared.read().await.peers[0].preshared_key.as_deref(),
            Some("psk-issu-de-ml-kem")
        );
        // …et le plan de données aussi : c'est lui qui protège réellement.
        let peers = wireguard.peers().await.unwrap();
        assert_eq!(peers.len(), 1, "le pair doit être présent sur l'interface");
    }

    /// Si le plan de données refuse, la config en mémoire ne doit pas rester en
    /// avance sur lui : elle annoncerait un PSK que l'interface ne porte pas, et
    /// une reconnexion ultérieure le poserait alors que le client l'a oublié.
    #[tokio::test]
    async fn echec_du_plan_de_donnees_annule_le_psk_en_memoire() {
        let shared = Arc::new(RwLock::new(network_sans_psk()));
        let wireguard = helios_wireguard::DryRunBackend::failing_sync();

        let resultat = demander_installation(&shared, &wireguard, PEER_KEY).await;

        assert!(resultat.is_err(), "l'échec doit remonter à l'appelant");
        assert_eq!(
            shared.read().await.peers[0].preshared_key,
            None,
            "INVARIANTE VIOLÉE : la config garde un PSK que le plan de données \
             a refusé — le prochain handshake échouerait sans explication"
        );
    }

    /// L'ancien PSK doit être restauré, pas simplement effacé : une rotation
    /// ratée ne doit pas dégrader un pair qui était déjà protégé.
    #[tokio::test]
    async fn echec_de_rotation_restaure_le_psk_precedent() {
        // `configured_network` part avec un PSK déjà en place.
        let shared = Arc::new(RwLock::new(configured_network()));
        let wireguard = helios_wireguard::DryRunBackend::failing_sync();

        let resultat = demander_installation(&shared, &wireguard, PEER_KEY).await;

        assert!(resultat.is_err());
        assert_eq!(
            shared.read().await.peers[0].preshared_key.as_deref(),
            Some("psk-test"),
            "une rotation ratée doit rendre le pair à son état antérieur"
        );
    }

    /// L'endpoint vérifie déjà l'admission, mais l'orchestrateur ne doit pas
    /// s'en remettre à un appelant : un pair absent de la config est refusé.
    #[tokio::test]
    async fn pair_absent_de_la_configuration_est_refuse() {
        let shared = Arc::new(RwLock::new(network_sans_psk()));
        let wireguard = helios_wireguard::DryRunBackend::new();

        let resultat = demander_installation(
            &shared,
            &wireguard,
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        )
        .await;

        assert!(
            resultat.is_err(),
            "un pair non déclaré ne doit pas être posé"
        );
        assert_eq!(
            shared.read().await.peers[0].preshared_key,
            None,
            "le pair légitime ne doit pas avoir été touché"
        );
    }

    #[tokio::test]
    async fn connexion_dry_run_reste_bloquee_jusqu_au_handshake() {
        let network = configured_network();
        let state = Arc::new(RwLock::new(TunnelState::Down));
        let (events, _) = broadcast::channel(8);
        let firewall = DryRunBackend;
        let wireguard = helios_wireguard::DryRunBackend::new();

        do_connect(
            &network,
            &wireguard,
            &state,
            &events,
            &firewall,
            &network.firewall_policy(),
        )
        .await
        .unwrap();

        assert!(wireguard.is_up());
        assert_eq!(*state.read().await, TunnelState::Connecting);
        assert!(state.read().await.kill_switch_engaged());
    }

    #[tokio::test]
    async fn deconnexion_demonte_wireguard_et_reengage_le_kill_switch() {
        let network = configured_network();
        let shared_network = Arc::new(RwLock::new(network.clone()));
        let state = Arc::new(RwLock::new(TunnelState::Up));
        let policy = Arc::new(RwLock::new(network.firewall_policy()));
        let (events, _) = broadcast::channel(8);
        let (internal_tx, _internal_rx) = mpsc::channel(1);
        let firewall = DryRunBackend;
        let wireguard = helios_wireguard::DryRunBackend::new();
        let (iface, peers) = wg_config(&network);
        wireguard.up(&iface, &peers).await.unwrap();
        let mut current_policy = network.firewall_policy();
        current_policy.mss_clamp = Some(1380);

        handle_external_cmd(
            OrchestratorCmd::Disconnect,
            &shared_network,
            true,
            &wireguard,
            &state,
            &events,
            &firewall,
            &mut current_policy,
            &internal_tx,
            &policy,
            // TPM désactivé : ce test ne fait pas de rotation de clé.
            &helio_tpm::BootDecision::Disabled,
        )
        .await
        .unwrap();

        assert!(!wireguard.is_up());
        assert_eq!(*state.read().await, TunnelState::Down);
        assert!(state.read().await.kill_switch_engaged());
        assert_eq!(policy.read().await.mss_clamp, None);
    }
}
