//! `heliosd` — daemon orchestrateur du plan de contrôle.

mod gateway_key;
mod orchestrator;

use std::sync::Arc;

use aether::{
    HeliosEvent, InstallPskRequest, NetworkConfig, OrchestratorCmd, TunnelState, API_BIND_LOOPBACK,
};
use anyhow::Context;
use clap::{Parser, Subcommand};
use helio_tpm::{BootController, BootDecision, TpmSettings};
use helios_api::AppState;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Nombre d'essais de mise en écoute de l'API avant abandon.
///
/// L'adresse d'écoute appartient à l'interface WireGuard, créée par
/// l'orchestrateur après le lancement du serveur : les premiers essais échouent
/// nécessairement. La borne évite une boucle infinie si l'adresse ne vient
/// jamais — une configuration erronée doit rester visible, pas être masquée par
/// des tentatives silencieuses.
const API_BIND_TENTATIVES: u32 = 20;

/// Attente entre deux essais de mise en écoute de l'API.
const API_BIND_DELAI: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Parser)]
#[command(name = "heliosd", version, about = "Gateway VPN WireGuard Helios")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Lance le daemon (kill-switch + orchestration + interface web).
    Run {
        /// Mode développement : simule WireGuard, nftables et TPM.
        /// Activé automatiquement sur WSL2 si WireGuard noyau est absent.
        #[arg(long)]
        dev: bool,
    },
    /// Affiche la configuration résolue et l'état du système.
    Status,
    /// Vérifie la disponibilité d'une mise à jour.
    CheckUpdate,
    /// Provisionne le coffre TPM au premier déploiement.
    ///
    /// À jouer **une seule fois**, à l'installation, avec accès console. Sur le
    /// terrain, un coffre absent est une anomalie de sécurité : le démarrage
    /// nominal refuse donc de provisionner de lui-même, et cette commande est le
    /// seul chemin explicite pour le faire.
    ProvisionTpm,
    /// Crée l'identité WireGuard de la gateway et la scelle (ADR-004 §3).
    ///
    /// À jouer après `provision-tpm`, avec accès console. La clé privée est
    /// générée en mémoire et scellée sans jamais toucher le disque en clair ;
    /// seule la clé publique est affichée, à remettre aux clients.
    InitIdentity {
        /// Remplace une identité déjà scellée. **Tous les clients devront
        /// mettre à jour `peer_public_key`** : ce n'est pas une reprise, c'est
        /// un changement d'identité de la gateway.
        #[arg(long)]
        rotate: bool,
    },
    /// Admission locale des clients, avec accès console.
    ///
    /// Sert au bootstrap du premier pair administrateur — sans lui, aucune
    /// mutation distante n'est autorisée (ADR-003 §3) — et au dépannage. Le
    /// chemin nominal ensuite est `helios-ctl peer`, à travers le tunnel.
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
}

#[derive(Subcommand)]
enum PeerCommand {
    /// Admet un client et lui attribue sa VIP.
    Add {
        /// Nom convivial, unique sur la gateway.
        #[arg(long)]
        name: String,
        /// Clé publique Curve25519 du client, en base64.
        #[arg(long)]
        public_key: String,
        /// Autorise ce pair à muter le plan de contrôle et les mises à jour.
        #[arg(long)]
        admin: bool,
    },
    /// Liste les pairs admis.
    List,
    /// Retire un pair de l'admission.
    Remove {
        #[arg(long)]
        name: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let network = NetworkConfig::load().context("chargement de la config réseau")?;

    match cli.command {
        Command::Run { dev } => {
            let dry_run = resolve_dry_run(dev);
            run(network, dry_run).await
        }
        Command::Status => {
            let dry_run = resolve_dry_run(false);
            orchestrator::status(&network, dry_run)
        }
        Command::CheckUpdate => {
            let dry_run = resolve_dry_run(false);
            orchestrator::check_update(dry_run).await
        }
        Command::ProvisionTpm => provision_tpm(),
        Command::InitIdentity { rotate } => init_identity(&network, rotate),
        Command::Peer { command } => peer_command(network, command),
    }
}

/// Crée et scelle l'identité WireGuard de la gateway.
///
/// Le déscellement passe par le même `BootController` que le démarrage
/// nominal : si l'intégrité de la chaîne de démarrage n'est pas confirmée, il
/// n'y a pas de secret, donc pas de scellement — et pas d'identité créée à
/// moitié.
fn init_identity(network: &NetworkConfig, rotate: bool) -> anyhow::Result<()> {
    let tpm = TpmSettings::default();
    let boot = BootController::unlock(&tpm).map_err(|e| {
        anyhow::anyhow!(
            "déscellement TPM échoué : {e}. Provisionner le coffre d'abord \
             (`heliosd provision-tpm`)."
        )
    })?;

    let public_key = gateway_key::initialize(network, &boot, rotate)
        .map_err(|e| anyhow::anyhow!("initialisation de l'identité impossible : {e}"))?;

    println!("{public_key}");
    info!(
        "clé publique de la gateway ci-dessus — c'est la valeur `peer_public_key` \
         des profils clients. La clé privée reste scellée et n'est jamais affichée."
    );
    Ok(())
}

/// Admission locale : lit, modifie et réécrit `network.toml`.
///
/// Le daemon garde sa configuration en mémoire : une modification par ce chemin
/// ne prend effet qu'au prochain démarrage. C'est assumé — cette commande vise
/// le bootstrap et le dépannage console, pas l'exploitation courante, qui passe
/// par l'API (`helios-ctl peer`).
fn peer_command(mut network: NetworkConfig, command: PeerCommand) -> anyhow::Result<()> {
    match command {
        PeerCommand::List => {
            if network.peers.is_empty() {
                println!("aucun pair admis");
                return Ok(());
            }
            for peer in &network.peers {
                let role = if peer.admin { " [admin]" } else { "" };
                let pq = if peer.preshared_key.is_some() {
                    " [PQ]"
                } else {
                    ""
                };
                println!(
                    "{}\t{}\t{}{role}{pq}",
                    peer.name, peer.address, peer.public_key
                );
            }
            Ok(())
        }
        PeerCommand::Add {
            name,
            public_key,
            admin,
        } => {
            let peer = helios_provisioning::admit(&mut network, &name, &public_key, admin)
                .map_err(|e| anyhow::anyhow!("admission refusée : {e}"))?;
            network
                .save()
                .context("écriture de la configuration réseau")?;
            println!("{}\t{}", peer.name, peer.address);
            info!("pair admis — la modification prendra effet au prochain démarrage de heliosd");
            Ok(())
        }
        PeerCommand::Remove { name } => {
            let peer = helios_provisioning::revoke(&mut network, &name)
                .map_err(|e| anyhow::anyhow!("révocation refusée : {e}"))?;
            network
                .save()
                .context("écriture de la configuration réseau")?;
            println!("{} retiré", peer.name);
            warn!(
                "le pair tombera à son prochain handshake ; aucune révocation \
                 cryptographique n'existe (ADR-004)"
            );
            Ok(())
        }
    }
}

/// Scelle un secret neuf dans le TPM, au premier déploiement seulement.
///
/// `TpmSettings::default()` porte `allow_provisioning = false` : c'est
/// délibéré, un coffre absent sur le terrain signale qu'on a pu l'effacer pour
/// forcer un faux premier boot. Le démarrage nominal doit donc s'arrêter là.
///
/// Il faut malgré tout un chemin pour le premier scellement, sans quoi une
/// gateway compilée avec la feature `tpm` ne peut jamais démarrer. Cette
/// commande est ce chemin : explicite, distincte du démarrage, et refusant
/// d'écraser un coffre existant — un écrasement détruirait l'identité de la
/// gateway sans possibilité de retour.
fn provision_tpm() -> anyhow::Result<()> {
    let mut tpm = TpmSettings::default();

    if !tpm.enabled {
        anyhow::bail!(
            "binaire compilé sans la feature `tpm` : aucun scellement possible. \
             Recompiler avec --features tpm sur la cible."
        );
    }

    if std::path::Path::new(&tpm.sealed_blob_path).exists() {
        anyhow::bail!(
            "un coffre existe déjà dans {} — refus d'écraser. Le supprimer ferait \
             perdre l'identité scellée de la gateway.",
            tpm.sealed_blob_path
        );
    }

    tpm.allow_provisioning = true;
    match BootController::unlock(&tpm).map_err(|e| anyhow::anyhow!("scellement échoué : {e}"))? {
        BootDecision::Provisioned(_) => {
            info!(
                "coffre TPM provisionné dans {} — lié aux PCR {:?} de la banque {}",
                tpm.sealed_blob_path, tpm.pcr_selection, tpm.pcr_bank
            );
            info!(
                "démarrer heliosd : la clé WireGuard en clair de network.toml sera \
                 scellée automatiquement, après quoi `wg_private_key` peut en être retiré"
            );
            Ok(())
        }
        autre => anyhow::bail!("provisionnement attendu, obtenu : {autre:?}"),
    }
}

/// Détermine si on est sous WSL2 (noyau Microsoft).
fn is_wsl2() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| v.to_ascii_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

/// Vérifie si le module WireGuard noyau est chargé.
fn wireguard_module_present() -> bool {
    std::path::Path::new("/sys/module/wireguard").exists()
}

/// Résout le mode dry-run : explicite (`--dev`) ou auto-détecté (WSL2 sans WireGuard).
fn resolve_dry_run(explicit_dev: bool) -> bool {
    if explicit_dev {
        info!("mode --dev activé : simulation WireGuard, nftables et TPM");
        return true;
    }
    if is_wsl2() && !wireguard_module_present() {
        warn!(
            "WSL2 détecté sans module WireGuard — bascule automatique en mode dev \
             (simulation sans crypto)"
        );
        return true;
    }
    false
}

async fn run(network: NetworkConfig, dry_run: bool) -> anyhow::Result<()> {
    // Validation d'intégrité TPM — AVANT tout réseau.
    let tpm = TpmSettings::default();
    let boot = BootController::unlock(&tpm)
        .map_err(|e| anyhow::anyhow!("déscellement TPM échoué — arrêt : {e}"))?;
    match &boot {
        BootDecision::Disabled => {}
        BootDecision::Bypassed => warn!("intégrité TPM non vérifiée (enforce=false)"),
        BootDecision::Unsealed(_) => info!("intégrité du démarrage confirmée (TPM)"),
        BootDecision::Provisioned(_) => warn!("premier boot : provisionnement TOFU effectué"),
        BootDecision::Resealed(_) => warn!("rescellement post-OTA effectué (billet valide)"),
    }
    // La clé privée WireGuard vient du coffre scellé TPM, pas de network.toml.
    // Voir `gateway_key` : en clair sur disque, elle suffirait à usurper la
    // gateway. La config n'en porte plus qu'un éventuel repli hérité.
    let mut network = network;
    let resolved = gateway_key::resolve(&network, &boot);
    match resolved.origin {
        gateway_key::KeyOrigin::Sealed => {}
        gateway_key::KeyOrigin::Recovered => warn!(
            "identité restaurée depuis le séquestre après un changement de PCR — \
             vérifier que le fichier de récupération a bien été effacé"
        ),
        gateway_key::KeyOrigin::PlaintextConfig => warn!(
            "identité de la gateway en clair sur disque — sceller la clé puis retirer \
             `wg_private_key` de network.toml"
        ),
        gateway_key::KeyOrigin::Missing => warn!(
            "aucune clé privée WireGuard : la gateway démarre en fail-closed sans \
             monter d'interface. Fournir une clé (POST /api/gateway/wireguard-key)."
        ),
    }
    network.wg_private_key = resolved.private_key;

    let (event_tx, _) = broadcast::channel::<HeliosEvent>(256);
    let (cmd_tx, cmd_rx) = mpsc::channel::<OrchestratorCmd>(32);
    // Canal dédié au provisioning : il porte un secret et attend un
    // acquittement, contrairement au flux d'ordres d'IHM.
    let (psk_tx, psk_rx) = mpsc::channel::<InstallPskRequest>(8);
    let tunnel_state = Arc::new(RwLock::new(TunnelState::Down));
    let shared_network = Arc::new(RwLock::new(network));
    let shared_policy = Arc::new(RwLock::new(shared_network.read().await.firewall_policy()));

    // L'API écoute sur l'adresse du tunnel : c'est par là que les clients Orion
    // atteignent le provisioning et la télémétrie. Le filtrage reste assuré par
    // le pare-feu (`admin_iface`), pas par l'adresse de bind.
    // Une simulation ne crée pas réellement l'adresse WireGuard. Elle écoute
    // donc uniquement en local, ce qui rend le test manuel possible sans
    // exposer l'API de développement sur le réseau de la machine.
    let api_bind = if dry_run {
        API_BIND_LOOPBACK.to_string()
    } else {
        shared_network.read().await.api_bind()
    };
    info!("interface web sur http://{api_bind}");

    let state = AppState::new(
        Arc::clone(&shared_network),
        dry_run,
        Arc::clone(&tunnel_state),
        event_tx.clone(),
        cmd_tx,
        psk_tx,
        Arc::clone(&shared_policy),
    );
    let api_ready = Arc::clone(&state.api_ready);
    tokio::spawn(async move {
        // Hors simulation, l'API écoute sur l'adresse WireGuard — que
        // l'orchestrateur, démarré juste après, n'a pas encore assignée à
        // l'interface. Le premier `bind` échoue donc en « Cannot assign
        // requested address », et sans réessai la gateway tournait pour de
        // bon sans API : ni provisioning, ni télémétrie, pour une course
        // perdue de quelques dizaines de millisecondes.
        for tentative in 1..=API_BIND_TENTATIVES {
            match helios_api::serve(state.clone(), &api_bind).await {
                Ok(()) => return,
                Err(e) if tentative < API_BIND_TENTATIVES => {
                    warn!(
                        "serveur API indisponible (tentative {tentative}/{API_BIND_TENTATIVES}), \
                         nouvel essai : {e:#}"
                    );
                    tokio::time::sleep(API_BIND_DELAI).await;
                }
                Err(e) => {
                    tracing::error!(
                        "serveur API abandonné après {API_BIND_TENTATIVES} tentatives : {e:#}"
                    );
                }
            }
        }
    });

    orchestrator::run(
        shared_network,
        dry_run,
        tunnel_state,
        event_tx,
        cmd_rx,
        psk_rx,
        shared_policy,
        boot,
        api_ready,
    )
    .await
}
