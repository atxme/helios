//! `heliosd` — control plane orchestrator daemon.

mod gateway_key;
mod key_negotiation;
mod orchestrator;
mod static_psk;

use std::sync::Arc;

use aether::{
    HeliosEvent, InstallPskRequest, NetworkConfig, OrchestratorCmd, TunnelState, API_BIND_LOOPBACK,
};
use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use helio_tpm::{BootController, BootDecision, TpmSettings};
use helios_api::AppState;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// Number of API listen attempts before giving up.
///
/// The listening address belongs to the WireGuard interface, created by the
/// orchestrator after the server starts: the first attempts necessarily
/// fail. The bound avoids an infinite loop if the address never comes —
/// a misconfiguration must stay visible, not be masked by silent retries.
const API_BIND_ATTEMPTS: u32 = 20;

/// Wait between two API listen attempts.
const API_BIND_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Parser)]
#[command(name = "heliosd", version, about = "Gateway VPN WireGuard Helios")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Launches the daemon (kill-switch + orchestration + web interface).
    Run {
        /// Development mode: simulates WireGuard, nftables and TPM.
        /// Enabled automatically on WSL2 if the kernel WireGuard module is
        /// absent.
        #[arg(long)]
        dev: bool,
    },
    /// Displays the resolved configuration and system state.
    Status,
    /// Checks whether an update is available.
    CheckUpdate,
    /// Provisions the TPM vault on first deployment.
    ///
    /// To be run **only once**, at install time, with console access. In the
    /// field, an absent vault is a security anomaly: nominal startup
    /// therefore refuses to provision on its own, and this command is the
    /// only explicit path to do so.
    ProvisionTpm,
    /// Creates the gateway's WireGuard identity and seals it (ADR-004 §3).
    ///
    /// To be run after `provision-tpm`, with console access. The private key
    /// is generated in memory and sealed without ever touching the disk in
    /// the clear; only the public key is displayed, to hand to clients.
    InitIdentity {
        /// Replaces an already-sealed identity. **All clients will have to
        /// update `peer_public_key`**: this is not a recovery, it is a
        /// change of the gateway's identity.
        #[arg(long)]
        rotate: bool,
    },
    /// Creates and seals the gateway's key-negotiation TLS identity.
    InitKeyNegotiation {
        /// DNS name or IP address clients use to authenticate this gateway.
        #[arg(long)]
        server_name: String,
        /// DER certificate of the CA authorized to issue Orion certificates.
        #[arg(long)]
        client_ca: std::path::PathBuf,
        /// Raw ML-DSA-65 public key of the CA issuing Orion PQ certificates.
        #[arg(long)]
        client_pq_ca: std::path::PathBuf,
        /// Explicitly replaces the existing identity and public certificates.
        #[arg(long)]
        rotate: bool,
    },
    /// Local client admission, with console access.
    ///
    /// Used to bootstrap the first administrator peer — without it, no
    /// remote mutation is authorized (ADR-003 §3) — and for troubleshooting.
    /// The nominal path afterwards is `helios-ctl peer`, through the tunnel.
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
}

#[derive(Subcommand)]
enum PeerCommand {
    /// Admits a client and assigns it its VIP.
    Add {
        /// Friendly name, unique on the gateway.
        #[arg(long)]
        name: String,
        /// Client's Curve25519 public key, in base64.
        #[arg(long)]
        public_key: String,
        /// Authorizes this peer to mutate the control plane and updates.
        #[arg(long)]
        admin: bool,
        /// SHA-256 fingerprint of the client's key-negotiation certificate.
        #[arg(long)]
        key_negotiation_certificate_sha256: Option<String>,
        /// SHA-256 fingerprint of the client's ML-DSA-65 certificate.
        #[arg(long)]
        key_negotiation_pq_certificate_sha256: Option<String>,
        /// Refuses future negotiations below this protection level.
        #[arg(long, value_enum)]
        minimum_mode: Option<NegotiationMode>,
    },
    /// Lists admitted peers.
    List,
    /// Removes a peer from admission.
    Remove {
        #[arg(long)]
        name: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum NegotiationMode {
    Classic,
    StaticPsk,
    MlKem,
}

impl From<NegotiationMode> for aether::key_negotiation::ProtectionMode {
    fn from(value: NegotiationMode) -> Self {
        match value {
            NegotiationMode::Classic => Self::Classic,
            NegotiationMode::StaticPsk => Self::StaticPsk,
            NegotiationMode::MlKem => Self::MlKem,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let network = NetworkConfig::load().context("loading the network config")?;

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
        Command::InitKeyNegotiation {
            server_name,
            client_ca,
            client_pq_ca,
            rotate,
        } => init_key_negotiation(&network, &server_name, &client_ca, &client_pq_ca, rotate),
        Command::Peer { command } => peer_command(network, command),
    }
}

fn init_key_negotiation(
    network: &NetworkConfig,
    server_name: &str,
    client_ca: &std::path::Path,
    client_pq_ca: &std::path::Path,
    rotate: bool,
) -> anyhow::Result<()> {
    let boot = BootController::unlock(&TpmSettings::default())
        .context("unlocking the TPM vault for key-negotiation identity creation")?;
    let resolved = gateway_key::resolve(network, &boot);
    let gateway_wg_public_key = aether::wg::public_from_private(&resolved.private_key)
        .context("gateway WireGuard identity is unavailable")?;
    let result = key_negotiation::initialize(
        server_name,
        &gateway_wg_public_key,
        client_ca,
        client_pq_ca,
        &boot,
        rotate,
    )?;
    println!("certificate: {}", result.certificate_path.display());
    println!("sha256: {}", result.certificate_sha256);
    println!("PQ certificate: {}", result.pq_certificate_path.display());
    println!("PQ sha256: {}", result.pq_certificate_sha256);
    info!("key-negotiation TLS and PQ private keys generated on the gateway and sealed");
    Ok(())
}

/// Creates and seals the gateway's WireGuard identity.
///
/// Unsealing goes through the same `BootController` as nominal startup: if
/// the boot chain's integrity is not confirmed, there is no secret, hence no
/// sealing — and no half-created identity.
fn init_identity(network: &NetworkConfig, rotate: bool) -> anyhow::Result<()> {
    let tpm = TpmSettings::default();
    let boot = BootController::unlock(&tpm).map_err(|e| {
        anyhow::anyhow!(
            "TPM unsealing failed: {e}. Provision the vault first \
             (`heliosd provision-tpm`)."
        )
    })?;

    let public_key = gateway_key::initialize(network, &boot, rotate)
        .map_err(|e| anyhow::anyhow!("could not initialize the identity: {e}"))?;

    println!("{public_key}");
    info!(
        "gateway's public key above — this is the `peer_public_key` value \
         for client profiles. The private key stays sealed and is never displayed."
    );
    Ok(())
}

/// Local admission: reads, modifies and rewrites `network.toml`.
///
/// This command runs in its own process and only knows the file. A running
/// daemon picks the change up on its own — it watches `network.toml`
/// (`orchestrator::spawn_network_config_watcher`) and re-applies it without a
/// restart. Admitting a peer therefore no longer costs the connection of
/// every peer already admitted.
///
/// The secrets are not in the file, and must not be: the daemon restores its
/// sealed private key and its negotiated PSKs from memory when it reloads.
fn peer_command(mut network: NetworkConfig, command: PeerCommand) -> anyhow::Result<()> {
    match command {
        PeerCommand::List => {
            if network.peers.is_empty() {
                println!("no admitted peers");
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
            key_negotiation_certificate_sha256,
            key_negotiation_pq_certificate_sha256,
            minimum_mode,
        } => {
            let minimum_mode = minimum_mode.map(Into::into).unwrap_or_else(|| {
                if key_negotiation_pq_certificate_sha256.is_some() {
                    aether::key_negotiation::ProtectionMode::MlKem
                } else {
                    aether::key_negotiation::ProtectionMode::Classic
                }
            });
            let peer = helios_provisioning::admit_with_key_negotiation(
                &mut network,
                &name,
                &public_key,
                admin,
                key_negotiation_certificate_sha256.as_deref(),
                key_negotiation_pq_certificate_sha256.as_deref(),
                minimum_mode,
            )
            .map_err(|e| anyhow::anyhow!("admission refused: {e}"))?;
            network
                .save()
                .context("writing the network configuration")?;
            println!("{}\t{}", peer.name, peer.address);
            info!("peer admitted — a running heliosd applies it within seconds, without restart");
            Ok(())
        }
        PeerCommand::Remove { name } => {
            let peer = helios_provisioning::revoke(&mut network, &name)
                .map_err(|e| anyhow::anyhow!("revocation refused: {e}"))?;
            // The peer leaves the table too. Leaving its PSK behind would keep
            // a shared secret alive for an identity nobody admits any more —
            // and would make it slide back onto that public key if it were
            // ever re-admitted.
            let table = static_psk::default_path();
            let identity = network.wg_private_key.trim().to_string();
            if !identity.is_empty() {
                match static_psk::load(&table, &identity) {
                    Ok(mut map) => {
                        if map.remove(&peer.public_key) {
                            static_psk::store(&table, &identity, &map).map_err(|e| {
                                anyhow::anyhow!("writing the static PSK table: {e}")
                            })?;
                            info!("static PSK removed with the peer");
                        }
                    }
                    // Not fatal: the peer is revoked either way, and refusing
                    // here would leave it admitted because a table we cannot
                    // read might hold a secret for it.
                    Err(error) => warn!(%error, "static PSK table unreadable — entry not removed"),
                }
            }
            network
                .save()
                .context("writing the network configuration")?;
            println!("{} removed", peer.name);
            warn!(
                "the peer will drop at its next handshake; no cryptographic \
                 revocation exists (ADR-004)"
            );
            Ok(())
        }
    }
}

/// Seals a fresh secret into the TPM, on first deployment only.
///
/// `TpmSettings::default()` carries `allow_provisioning = false`: this is
/// deliberate, an absent vault in the field signals it may have been erased
/// to force a fake first boot. Nominal startup must therefore stop there.
///
/// A path for the first sealing is nonetheless needed, without which a
/// gateway built with the `tpm` feature could never start. This command is
/// that path: explicit, distinct from startup, and refusing to overwrite an
/// existing vault — an overwrite would destroy the gateway's identity with
/// no way back.
fn provision_tpm() -> anyhow::Result<()> {
    let mut tpm = TpmSettings::default();

    if !tpm.enabled {
        anyhow::bail!(
            "binary built without the `tpm` feature: no sealing possible. \
             Rebuild with --features tpm on the target."
        );
    }

    if std::path::Path::new(&tpm.sealed_blob_path).exists() {
        anyhow::bail!(
            "a vault already exists in {} — refusing to overwrite it. Deleting it \
             would lose the gateway's sealed identity.",
            tpm.sealed_blob_path
        );
    }

    tpm.allow_provisioning = true;
    match BootController::unlock(&tpm).map_err(|e| anyhow::anyhow!("sealing failed: {e}"))? {
        BootDecision::Provisioned(_) => {
            info!(
                "TPM vault provisioned in {} — bound to PCR {:?} of bank {}",
                tpm.sealed_blob_path, tpm.pcr_selection, tpm.pcr_bank
            );
            info!(
                "start heliosd: the plaintext WireGuard key from network.toml will be \
                 sealed automatically, after which `wg_private_key` can be removed from it"
            );
            Ok(())
        }
        other => anyhow::bail!("expected provisioning, got: {other:?}"),
    }
}

/// Determines whether we are under WSL2 (Microsoft kernel).
fn is_wsl2() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| v.to_ascii_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

/// Checks whether the kernel WireGuard module is loaded.
fn wireguard_module_present() -> bool {
    std::path::Path::new("/sys/module/wireguard").exists()
}

/// Resolves dry-run mode: explicit (`--dev`) or auto-detected (WSL2 without WireGuard).
fn resolve_dry_run(explicit_dev: bool) -> bool {
    if explicit_dev {
        info!("--dev mode enabled: simulating WireGuard, nftables and TPM");
        return true;
    }
    if is_wsl2() && !wireguard_module_present() {
        warn!(
            "WSL2 detected without the WireGuard module — automatically switching \
             to dev mode (simulation without crypto)"
        );
        return true;
    }
    false
}

/// Makes the process non-dumpable, **before** the first key is loaded.
///
/// `LimitCORE=0` in the unit covers the service started by systemd; this covers
/// every other way `heliosd` is launched, and it also removes the ptrace
/// attachability that `PR_SET_DUMPABLE=1` grants to same-uid processes.
///
/// Fatal outside `--dev`: a daemon that cannot make itself non-dumpable would
/// hold the gateway identity in a process anyone of the same user can dump, and
/// that is not a warning-level fact (ADR-006 §6).
#[cfg(unix)]
fn forbid_core_dumps(dry_run: bool) -> anyhow::Result<()> {
    // SAFETY: `prctl` with PR_SET_DUMPABLE takes an int and touches only this
    // process's own attributes.
    let applied = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    if applied != 0 {
        let cause = std::io::Error::last_os_error();
        if dry_run {
            warn!("PR_SET_DUMPABLE refused ({cause}) — tolerated in --dev only");
            return Ok(());
        }
        anyhow::bail!("PR_SET_DUMPABLE refused: {cause}");
    }
    // Reading it back rather than trusting the return code: the value is what
    // the kernel will actually honour on a crash.
    let effective = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
    anyhow::ensure!(
        effective == 0,
        "PR_SET_DUMPABLE accepted but PR_GET_DUMPABLE reports {effective}"
    );
    Ok(())
}

#[cfg(not(unix))]
fn forbid_core_dumps(_dry_run: bool) -> anyhow::Result<()> {
    Ok(())
}

async fn run(network: NetworkConfig, dry_run: bool) -> anyhow::Result<()> {
    // Before the TPM unseal below, which is where the first key appears.
    forbid_core_dumps(dry_run)?;

    // The guard that used to stand here — refusing to start when
    // `key_negotiation_port` was set on a binary built without the feature —
    // no longer has a case to catch: every heliosd serves that port. The
    // setting alone decides whether it opens.

    // TPM integrity validation — BEFORE any network access.
    let tpm = TpmSettings::default();
    let boot = BootController::unlock(&tpm)
        .map_err(|e| anyhow::anyhow!("TPM unsealing failed — stopping: {e}"))?;
    match &boot {
        BootDecision::Disabled => {}
        BootDecision::Bypassed => warn!("TPM integrity not verified (enforce=false)"),
        BootDecision::Unsealed(_) => info!("boot integrity confirmed (TPM)"),
        BootDecision::Provisioned(_) => warn!("first boot: TOFU provisioning performed"),
        BootDecision::Resealed(_) => warn!("post-OTA resealing performed (valid ticket)"),
    }
    // The WireGuard private key comes from the sealed TPM vault, not from
    // network.toml. See `gateway_key`: in the clear on disk, it would be
    // enough to impersonate the gateway. The config now only carries a
    // possible legacy fallback.
    let mut network = network;
    let resolved = gateway_key::resolve(&network, &boot);
    match resolved.origin {
        gateway_key::KeyOrigin::Sealed => {}
        gateway_key::KeyOrigin::Recovered => warn!(
            "identity restored from escrow after a PCR change — \
             check that the recovery file was indeed erased"
        ),
        gateway_key::KeyOrigin::PlaintextConfig => warn!(
            "gateway identity in the clear on disk — seal the key then remove \
             `wg_private_key` from network.toml"
        ),
        gateway_key::KeyOrigin::Missing => warn!(
            "no WireGuard private key: the gateway starts fail-closed without \
             bringing up an interface. Provide a key (POST /api/gateway/wireguard-key)."
        ),
    }
    network.wg_private_key = resolved.private_key;

    // Static PSKs move out of `network.toml` and into the sealed table
    // (ADR-006 §4). The value is moved, not dropped: the running config is
    // refilled from the table, because the data plane reads it and a peer
    // without its PSK fails every handshake with no recovery channel.
    //
    // Not fatal when it cannot be read: `Undecipherable` means the identity
    // changed without the table being re-wrapped, and the ADR forbids both
    // starting without the PSK and falling back to classic mode. So the
    // affected peers keep no PSK and stay unable to handshake, which is the
    // fail-closed outcome — announced loudly rather than silently degraded.
    if !network.wg_private_key.trim().is_empty() {
        let table = static_psk::default_path();
        let identity = network.wg_private_key.clone();
        match static_psk::adopt_from_config(&mut network, &table, &identity) {
            Ok(0) => {}
            Ok(adopted) => warn!(
                adopted,
                "PSK statiques repris de network.toml vers la table scellée — \
                 retirer `preshared_key` du fichier"
            ),
            Err(error) => error!(
                %error,
                "table des PSK statiques inutilisable — les pairs concernés resteront \
                 sans PSK et ne pourront pas établir de handshake"
            ),
        }
    }

    let (event_tx, _) = broadcast::channel::<HeliosEvent>(256);
    let (cmd_tx, cmd_rx) = mpsc::channel::<OrchestratorCmd>(32);
    // Dedicated provisioning channel: it carries a secret and awaits an
    // acknowledgment, unlike the UI order flow.
    let (psk_tx, psk_rx) = mpsc::channel::<InstallPskRequest>(8);
    let tunnel_state = Arc::new(RwLock::new(TunnelState::Down));
    let shared_network = Arc::new(RwLock::new(network));
    let shared_policy = Arc::new(RwLock::new(shared_network.read().await.firewall_policy()));

    key_negotiation::start(Arc::clone(&shared_network), psk_tx.clone(), &boot, dry_run).await?;

    // The API listens on the tunnel's address: this is how Orion clients
    // reach provisioning and telemetry. Filtering is still enforced by the
    // firewall (`admin_iface`), not by the bind address.
    // A simulation does not actually create the WireGuard address. It
    // therefore only listens locally, which makes manual testing possible
    // without exposing the development API on the machine's network.
    let api_bind = if dry_run {
        API_BIND_LOOPBACK.to_string()
    } else {
        shared_network.read().await.api_bind()
    };
    info!("web interface on http://{api_bind}");

    #[allow(unused_mut)]
    let mut state = AppState::new(
        Arc::clone(&shared_network),
        dry_run,
        Arc::clone(&tunnel_state),
        event_tx.clone(),
        cmd_tx,
        psk_tx,
        Arc::clone(&shared_policy),
    );
    // Published for the operator tooling: `helios-ctl` builds a complete
    // Orion profile from the gateway rather than making the operator copy
    // certificates out of /var/lib/helios by hand.
    if let Some(material) = key_negotiation::public_material()? {
        state = state.with_key_negotiation(material);
    }
    let api_ready = Arc::clone(&state.api_ready);
    tokio::spawn(async move {
        // Outside simulation, the API listens on the WireGuard address —
        // which the orchestrator, started right after, has not yet assigned
        // to the interface. The first `bind` therefore fails with "Cannot
        // assign requested address", and without a retry the gateway would
        // run for good without an API: no provisioning, no telemetry, for a
        // race lost by a few dozen milliseconds.
        for attempt in 1..=API_BIND_ATTEMPTS {
            match helios_api::serve(state.clone(), &api_bind).await {
                Ok(()) => return,
                Err(e) if attempt < API_BIND_ATTEMPTS => {
                    warn!(
                        "API server unavailable (attempt {attempt}/{API_BIND_ATTEMPTS}), \
                         retrying: {e:#}"
                    );
                    tokio::time::sleep(API_BIND_DELAY).await;
                }
                Err(e) => {
                    tracing::error!(
                        "API server given up after {API_BIND_ATTEMPTS} attempts: {e:#}"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_parses_every_offline_command_and_rejects_unknown_modes() {
        assert!(matches!(
            Cli::try_parse_from(["heliosd", "run", "--dev"])
                .unwrap()
                .command,
            Command::Run { dev: true }
        ));
        assert!(matches!(
            Cli::try_parse_from(["heliosd", "status"]).unwrap().command,
            Command::Status
        ));
        assert!(matches!(
            Cli::try_parse_from(["heliosd", "check-update"])
                .unwrap()
                .command,
            Command::CheckUpdate
        ));
        assert!(matches!(
            Cli::try_parse_from(["heliosd", "provision-tpm"])
                .unwrap()
                .command,
            Command::ProvisionTpm
        ));
        assert!(matches!(
            Cli::try_parse_from(["heliosd", "init-identity", "--rotate"])
                .unwrap()
                .command,
            Command::InitIdentity { rotate: true }
        ));
        assert!(Cli::try_parse_from([
            "heliosd",
            "peer",
            "add",
            "--name",
            "portable",
            "--public-key",
            "public",
            "--minimum-mode",
            "unknown"
        ])
        .is_err());
    }

    #[test]
    fn peer_commands_keep_all_security_parameters() {
        let cli = Cli::try_parse_from([
            "heliosd",
            "peer",
            "add",
            "--name",
            "admin",
            "--public-key",
            "public",
            "--admin",
            "--key-negotiation-certificate-sha256",
            "tls",
            "--key-negotiation-pq-certificate-sha256",
            "pq",
            "--minimum-mode",
            "ml-kem",
        ])
        .unwrap();

        match cli.command {
            Command::Peer {
                command:
                    PeerCommand::Add {
                        name,
                        public_key,
                        admin,
                        key_negotiation_certificate_sha256,
                        key_negotiation_pq_certificate_sha256,
                        minimum_mode,
                    },
            } => {
                assert_eq!(name, "admin");
                assert_eq!(public_key, "public");
                assert!(admin);
                assert_eq!(key_negotiation_certificate_sha256.as_deref(), Some("tls"));
                assert_eq!(key_negotiation_pq_certificate_sha256.as_deref(), Some("pq"));
                assert!(matches!(minimum_mode, Some(NegotiationMode::MlKem)));
            }
            _ => panic!("unexpected command"),
        }

        assert!(matches!(
            Cli::try_parse_from(["heliosd", "peer", "list"])
                .unwrap()
                .command,
            Command::Peer {
                command: PeerCommand::List
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["heliosd", "peer", "remove", "--name", "portable"])
                .unwrap()
                .command,
            Command::Peer {
                command: PeerCommand::Remove { name }
            } if name == "portable"
        ));
    }

    #[test]
    fn negotiation_mode_conversion_is_exhaustive() {
        use aether::key_negotiation::ProtectionMode;

        assert_eq!(
            ProtectionMode::from(NegotiationMode::Classic),
            ProtectionMode::Classic
        );
        assert_eq!(
            ProtectionMode::from(NegotiationMode::StaticPsk),
            ProtectionMode::StaticPsk
        );
        assert_eq!(
            ProtectionMode::from(NegotiationMode::MlKem),
            ProtectionMode::MlKem
        );
    }

    #[test]
    fn explicit_development_mode_always_wins_auto_detection() {
        assert!(resolve_dry_run(true));
    }

    #[test]
    fn listing_peers_is_safe_for_empty_and_populated_configuration() {
        peer_command(NetworkConfig::default(), PeerCommand::List).unwrap();
        let network = NetworkConfig {
            peers: vec![aether::WgPeer {
                name: "portable".into(),
                public_key: "public".into(),
                address: "100.64.1.2/32".into(),
                admin: true,
                preshared_key: Some("secret".into()),
                key_negotiation_certificate_sha256: None,
                key_negotiation_pq_certificate_sha256: None,
                minimum_key_negotiation_mode: aether::key_negotiation::ProtectionMode::Classic,
            }],
            ..NetworkConfig::default()
        };
        peer_command(network, PeerCommand::List).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn process_is_made_non_dumpable_before_loading_secrets() {
        forbid_core_dumps(false).expect("this process must control its dumpability");
        // SAFETY: PR_GET_DUMPABLE has no pointer argument and only reads the
        // current test process attribute.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, 0);
    }
}
