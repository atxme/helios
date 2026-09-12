//! `heliosd` — control plane orchestrator daemon.

mod astra_channel;
mod certificates;
mod gateway_key;
mod gateway_rotation;
mod key_negotiation;
mod orchestrator;
mod static_psk;
mod uplink;
mod vip_routing;

use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use aether::{
    HeliosEvent, InstallPskRequest, NetworkConfig, ObserveHandshakeRequest, OrchestratorCmd,
    TunnelState, API_BIND_LOOPBACK,
};
use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use helios_api::AppState;
use helios_tpm::{BootController, BootDecision, TpmSettings};
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
/// Cadence at which the raw speedtest keeps trying to bind, past the burst.
///
/// Thirty seconds: slow enough that a lasting conflict costs nothing, quick
/// enough that freeing the port brings the service back before an operator has
/// finished reading why it was gone.
const RAW_SPEEDTEST_RETRY: std::time::Duration = std::time::Duration::from_secs(30);

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
        /// Unsafe maintenance mode: real WireGuard/TPM, but remove and keep
        /// absent only the Helios nftables table. Never selected implicitly.
        #[arg(long, conflicts_with = "dev")]
        unsafe_disable_firewall: bool,
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
    /// Creates this gateway's certificate registry (ADR-008).
    ///
    /// The counterpart of `astra bootstrap`, on this side of the wire. Until
    /// it is run the registry is absent, and an absent registry is **not** an
    /// empty one: the in-tunnel lifecycle routes stay closed and the gateway
    /// says so at startup.
    ///
    /// It opens no vault and generates no key. Every value it writes is
    /// public — the leaves this gateway already serves, read from disk, and
    /// the anchors it is told to trust. It therefore runs on a gateway whose
    /// TPM is unavailable, which is exactly when one wants to inspect it.
    InitTrustDomain {
        /// Trust domain identifier, 32 hex characters — printed by
        /// `astra-signer init`.
        #[arg(long)]
        trust_domain_id: String,
        /// Public `CA-PQ` key, base64 — printed by `astra-signer init`. The
        /// anchor of the domain, and the only one this gateway ever trusts.
        #[arg(long)]
        ca_public_key: String,
        /// Gateway PQ leaf returned by the offline `astra-signer
        /// issue-gateway-bootstrap` ceremony.
        #[arg(long)]
        gateway_certificate: std::path::PathBuf,
        /// Astra's service public key, base64 — printed by `astra bootstrap`.
        /// It signs statuses and receipts; it certifies nothing.
        #[arg(long)]
        astra_service_public_key: String,
        /// Public URL of the Astra endpoint.
        #[arg(long)]
        authority_url: String,
        /// WebAuthn RP ID of the domain. The same value given to
        /// `astra-signer init --rp-id` and to `astra bootstrap`.
        #[arg(long)]
        webauthn_rp_id: String,
        /// DER of the client `CA-TLS` **the domain** serves, self-signed from
        /// the authority vault by `astra-signer issue-ca-tls` and carried by
        /// the domain hand-off as `ca_tls_certificate`.
        ///
        /// This is not the operator CA that admits clients. That one lives on
        /// this gateway as a file and decides who may open an mTLS session;
        /// this one is the anchor a **renewed** leaf chains to, through Astra's
        /// delegated intermediate. Seeding the registry with the operator CA
        /// instead puts the admission authority where the domain anchor
        /// belongs, and every staging is then refused with «the candidate TLS
        /// leaf chains to no client CA this gateway holds» — a §9.4 rotation
        /// cannot repair it, because a transition can only move away from an
        /// anchor the gateway already holds.
        #[arg(long)]
        client_tls_ca: Option<std::path::PathBuf>,
    },
    /// Repairs registries created before `init-trust-domain --client-tls-ca`.
    ///
    /// The affected release stored the operator admission CA as the domain
    /// anchor. This command accepts only that exact untouched epoch-1 shape,
    /// replaces it atomically with the supplied self-signed domain CA-TLS and
    /// keeps every peer identity and queued signed distribution.
    ///
    /// **For a stopped daemon.** A running process owns the registry in memory
    /// and could overwrite an offline repair with its previous state.
    RepairClientTlsCaBootstrap {
        /// DER of the domain's original client CA-TLS, as carried by the
        /// operator hand-off. The operator admission CA is read from the
        /// gateway's served key-negotiation identity and must match the bad
        /// anchor exactly.
        #[arg(long)]
        client_tls_ca: std::path::PathBuf,
    },
    /// Prepares this gateway's next identity and exports its request (§5).
    ///
    /// Step 1 and 2 of §11.1, and the only two that happen on the gateway
    /// before an operator ceremony: the next ML-DSA-87 key is generated and
    /// sealed **beside** the identity in service — never over it, which keeps
    /// serving tunnels throughout — and a `GatewayCertificateRequest` carrying
    /// only public halves is written out.
    ///
    /// The request proves possession of the new key and, on an ordinary
    /// renewal, continuity from the leaf in service. It authorises nothing:
    /// only `CA-PQ` issues, from a vault this machine must never hold. Carry
    /// the file to the operator companion and bring back a signed
    /// `GatewayIdentityTransition`.
    ///
    /// Re-running is a resumption, not a second attempt: an unexpired request
    /// for the same epoch is returned unchanged, and one that has outlived the
    /// 24 hours of §5 is re-signed over the **same** sealed key.
    ///
    /// **For a stopped daemon.** A running `heliosd` owns the certificate
    /// registry in memory and persists it on its own mutations, so a write
    /// made here can be overwritten by the next one it makes. With the daemon
    /// up, the console's *Certificats* screen drives the same gesture through
    /// the process that holds the lock.
    PrepareGatewayCertificate {
        /// Also replace the TLS leaf, self-signed and pinned like the active
        /// one. Left out, the renewal moves the PQ half alone — §6.1 makes
        /// each leaf independently optional.
        #[arg(long)]
        rotate_tls: bool,
        /// Discard the sealed candidate and generate a fresh key.
        ///
        /// Not needed to refresh an expired request. Use it when the candidate
        /// itself must be replaced — the previous one is destroyed, and the
        /// epoch it was prepared for stays available.
        #[arg(long)]
        new_key: bool,
        /// Build the request without a continuity signature (§5 recovery).
        ///
        /// Only after an explicit local procedure establishing that the active
        /// private key is gone. The field is then absent rather than
        /// unverified, and the transition that answers must carry the
        /// `key_recovery` reason.
        #[arg(long)]
        key_recovery: bool,
    },
    /// Installs the signed transition that answers the request (§11.1 5).
    ///
    /// Step 5, and the first thing the gateway does with what comes back from
    /// the ceremony. The transition is verified against the anchors this
    /// gateway already pins — `CA-PQ`, its epoch, the stable WireGuard
    /// identity, the server name and the two leaves in service — and refused
    /// unless the private half of every leaf it installs is sealed here.
    ///
    /// **The identity served does not change.** Staging is a decision about
    /// `activation_at`; until then the active leaf keeps mounting tunnels, and
    /// the switch needs the restart of §11.1 step 7.
    ///
    /// **For a stopped daemon**, like `prepare-gateway-certificate`. The
    /// console applies the same document through the process that owns the
    /// registry.
    InstallGatewayTransition {
        /// Signed `GatewayIdentityTransition`, as JSON.
        transition: PathBuf,
    },
    /// Cancels a staged, unpublished transition (§6.3).
    ///
    /// Accepted only while the transition is staged, has distributed no byte
    /// and `activation_at` is still ahead — on the local clock as well as in
    /// the document, so backdating the abort reopens nothing. The candidate
    /// identity is destroyed and the epoch stays consumed: a fleet must never
    /// have to choose between two decisions numbered the same.
    ///
    /// **For a stopped daemon**, like the two commands above.
    AbortGatewayTransition {
        /// Signed `GatewayTransitionAbort`, as JSON.
        abort: PathBuf,
    },
    /// Installs a signed rotation of the domain anchor `CA-PQ` (§9.1).
    ///
    /// The anchor everything else hangs from. The outgoing `CA-PQ` authorises
    /// its successor and the successor proves its own key — one signature
    /// would not be enough — and both verify from `activation_at` until the
    /// outgoing one is retired at `not_after`. The epoch moves only then.
    ///
    /// **For a stopped daemon.** A running one takes the same document on the
    /// Certificates screen, which writes through the process that holds the
    /// registry.
    InstallCaTransition {
        /// Signed `CaTransition`, as JSON.
        transition: PathBuf,
    },
    /// Installs a signed rotation of the client `CA-TLS` (§9.4).
    ///
    /// The anchor that authenticates the mTLS transport before any PQ
    /// signature is checked. Both chains are accepted during the overlap, and
    /// the outgoing one retires at `not_after` — a rotation without that
    /// overlap would cut every client that has not yet been re-issued.
    ///
    /// **For a stopped daemon**, like the gateway identity commands.
    InstallClientTlsCa {
        /// Signed `ClientTlsCaTransition`, as JSON.
        transition: PathBuf,
    },
    /// Records Astra's delegated issuer, and the policy it names.
    ///
    /// Until the amendment of 6 September 2026 a scheduled renewal asked for
    /// one operator credential per request. Dropping it widens what the
    /// delegated issuer may do unattended, so the policy fingerprint changed
    /// with it and no binary upgrade reinterprets the old one — the gateway
    /// would refuse every automatic renewal instead.
    ///
    /// The evidence that moves it is an `AstraIssuerAuthorization` signed by
    /// this domain's `CA-PQ` and naming the current policy: the out-of-band
    /// confirmation §2.4 asks for, in the form the operator's security keys
    /// already produce. A registry pinned to anything but the superseded
    /// policy is left untouched.
    ///
    /// **For a stopped daemon**, like the other registry commands.
    InstallAstraIssuer {
        /// Signed `AstraIssuerAuthorization`, as JSON.
        delegation: PathBuf,
    },
    /// Records the domain's operator credentials, so an enrolment can carry
    /// them (spec §19, §7.5).
    ///
    /// The document is the one `astra-signer bindings` emits beside the vault,
    /// and `deploy.sh` already copies it to Astra. This installs the same
    /// bytes here, because the enrolment block is the only thing a client
    /// reads before it has a tunnel — and recovering an expired identity
    /// begins by naming the credential that will approve it.
    ///
    /// Nothing secret crosses: the rows are public and each carries its own
    /// `CA-PQ` signature, which this registry checks under the anchor it
    /// already holds.
    ///
    /// **Run it with `heliosd` stopped.** A running daemon holds the registry
    /// in memory and rewrites it whole at the first decision it records, so an
    /// edit made beside it is undone without a word at the next peer
    /// admission — which is usually the very next thing a deployment does.
    InstallAstraCredentials {
        /// `CA-PQ`-signed credential registry, as JSON.
        credentials: PathBuf,
    },
    /// Prints the trust block a client's profile must carry (spec §19).
    ///
    /// Read from the certificate registry in one pass, and printed as the
    /// JSON an Orion profile embeds verbatim. Eleven public values: anchors,
    /// epochs, the Astra origin and the generation this peer is at. None is
    /// secret, and none is meant to be retyped — a value pasted wrong here
    /// fails months later, at 80 % of a leaf's life, on a client with no
    /// fallback.
    ///
    /// Exists beside the API route because an enrolment happens **before** the
    /// client has a tunnel, and `provision-client.sh` reaches this gateway over
    /// SSH rather than over the admin API.
    ShowTrustEnrolment {
        /// The peer's WireGuard public key, base64, as it was admitted.
        #[arg(long)]
        public_key: String,
    },
    /// Creates this gateway's end of the private Astra veth channel (§8.3).
    ///
    /// It generates a transport identity — a service identity, unrelated to
    /// `CA-PQ` and to every client — and pins Astra's, byte for byte. It seals
    /// nothing and unseals nothing, so it runs on a gateway whose TPM is
    /// unavailable, like `init-trust-domain`.
    ///
    /// Without it the private listener stays closed, and the gateway keeps
    /// working: an authority is an addition, not a prerequisite.
    InitAstraChannel {
        /// Address of the gateway's end of the veth, with its port. Never a
        /// wildcard: this API belongs on one interface with no default route.
        #[arg(long)]
        bind: std::net::SocketAddr,
        /// Astra's transport certificate, DER — printed by
        /// `astra init-channel`. The only client identity this listener will
        /// ever accept.
        #[arg(long)]
        astra_certificate: std::path::PathBuf,
        /// Address of Astra's own private listener, on the same veth.
        ///
        /// The direction this gateway dials, to relay a client renewal
        /// (spec §8.1.2). Absent, the four renewal routes answer `503` and the
        /// staging half keeps working — an authority that only receives is a
        /// supported deployment.
        #[arg(long)]
        authority: Option<std::net::SocketAddr>,
        /// Astra's **authority** certificate, DER — printed by
        /// `astra init-channel` beside its transport one. The only server
        /// identity this gateway will dial.
        #[arg(long)]
        astra_authority_certificate: Option<std::path::PathBuf>,
        /// Replaces an existing identity. **Astra must be re-pinned**: it
        /// holds these exact bytes, and changing them without telling it stops
        /// the two from talking.
        #[arg(long)]
        rotate: bool,
    },
    /// Prints what `wan_iface = "auto"` resolves to, and why.
    ///
    /// Read-only. Every candidate the kernel exposes, its medium, its carrier
    /// and its default-route metric — so a surprising choice is one command
    /// away from being explained.
    ShowUplink,
    /// Prints the key-negotiation identity this gateway serves.
    ///
    /// Read-only, public, and it unseals nothing: the two values a deployment
    /// needs — the server name clients pin and the WireGuard identity — are
    /// read out of the served PQ leaf rather than retyped.
    ShowIdentity,
    /// Local client admission, with console access.
    ///
    /// Used to bootstrap the first administrator peer — without it, no
    /// remote mutation is authorized (ADR-003 §3) — and for troubleshooting.
    /// The nominal path afterwards is `helios-ctl peer`, through the tunnel.
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
    /// TPM update window: surviving an OS upgrade that moves the PCRs.
    Tpm {
        #[command(subcommand)]
        command: TpmCommand,
    },
}

#[derive(Subcommand)]
enum TpmCommand {
    /// Arms an update window before an OS upgrade that will reboot.
    ///
    /// Run it on the running gateway, **before** `apt upgrade` or before the
    /// reboot that follows one. It carries the current TPM secret across a
    /// single reboot, so the gateway comes back with its vaults intact even
    /// though PCR 4 has moved — no reseal ticket, no escrow, no client to
    /// re-enroll.
    ///
    /// It is deliberately local (console or SSH), not an API route: the API
    /// lives behind the very tunnel this operation exists to preserve.
    PrepareUpdate {
        /// Reboots immediately after arming, which is what makes the window
        /// last seconds instead of minutes.
        #[arg(long)]
        reboot: bool,
    },
    /// Revokes an armed window. Idempotent, and safe at any time.
    CancelUpdate,
    /// Revokes a window that outlived its duration. Driven by a timer.
    ///
    /// The non-secret marker exposes the same deadline as the protected NV
    /// payload, so expiry can overwrite that payload without releasing it.
    ExpireWindow,
    /// Reports whether a window is armed on this TPM.
    UpdateStatus,
    /// Reports whether a window could be armed **now**, without arming one.
    ///
    /// Same precondition as `prepare-update`, answered before an upgrade
    /// touches the disk. Asking afterwards is asking too late: the kernel has
    /// already moved and the next reboot loses the vaults.
    UpdateReadiness,
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
        /// The client's TLS leaf itself, DER.
        ///
        /// A gateway holding a trust domain records the **leaves**, not their
        /// digests: it verifies signatures made by them. Without the two
        /// files, this peer would connect and never be able to renew, so the
        /// admission is refused rather than left to be discovered at 80 % of a
        /// leaf's life.
        #[arg(long)]
        certificate: Option<PathBuf>,
        /// The client's ML-DSA-87 leaf, its JSON document.
        #[arg(long)]
        pq_certificate: Option<PathBuf>,
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

    // Logs go to **stderr**, never stdout: several subcommands answer on stdout
    // and are read by a machine — `tpm update-status` returns `armed`/`none` to
    // `helios-ctl update`, `peer add` returns the assigned VIP. A log line
    // interleaved there is not noise, it is a wrong answer. systemd captures
    // both streams, so the journal is unchanged.
    //
    // `tss_esapi` is held at `warn` by default: at `info` it narrates opening
    // and closing a TPM context, three lines for every command, which buried
    // what the command itself had to say. Its warnings and errors still come
    // through, and `RUST_LOG` overrides the whole thing when a TPM problem is
    // what one is actually chasing.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,tss_esapi=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    // The randomness pipeline is named before anything draws from it. Both
    // specifications require the banner (§4.3, §2.3.2), and an unusable
    // provider is a start-up error rather than a refusal the first client to
    // negotiate discovers.
    // Settled before the first HTTP client: two rustls providers are compiled
    // in, so an unnamed one is a panic rather than a choice.
    helios_api::internal::install_process_default_provider();

    let drbg = aether::random::configure().context("resolving the DRBG provider")?;
    info!(%drbg, "randomness provider");

    match cli.command {
        Command::Run {
            dev,
            unsafe_disable_firewall,
        } => {
            let network = NetworkConfig::load().context("loading the network config")?;
            let dry_run = resolve_dry_run(dev);
            let firewall_mode = if unsafe_disable_firewall {
                orchestrator::FirewallMode::DisabledForMaintenance
            } else {
                orchestrator::FirewallMode::Enforced
            };
            run(network, dry_run, firewall_mode).await
        }
        Command::Status => {
            let mut network = NetworkConfig::load().context("loading the network config")?;
            // Resolved here too: `status` is what an operator reads to see what
            // the daemon will do, and printing the marker instead of the
            // interface would answer a different question. A failure is not
            // fatal — a diagnostic command must still print the rest.
            if let Err(error) = resolve_uplink(&mut network) {
                warn!(%error, "WAN interface unresolved");
            }
            let dry_run = resolve_dry_run(false);
            orchestrator::status(&network, dry_run)
        }
        Command::CheckUpdate => {
            let dry_run = resolve_dry_run(false);
            orchestrator::check_update(dry_run).await
        }
        Command::ProvisionTpm => provision_tpm(),
        Command::InitIdentity { rotate } => {
            let network = NetworkConfig::load().context("loading the network config")?;
            init_identity(&network, rotate)
        }
        Command::InitKeyNegotiation {
            server_name,
            client_ca,
            client_pq_ca,
            rotate,
        } => {
            let network = NetworkConfig::load().context("loading the network config")?;
            init_key_negotiation(&network, &server_name, &client_ca, &client_pq_ca, rotate)
        }
        Command::ShowTrustEnrolment { public_key } => show_trust_enrolment(&public_key),
        Command::PrepareGatewayCertificate {
            rotate_tls,
            new_key,
            key_recovery,
        } => prepare_gateway_certificate(rotate_tls, new_key, key_recovery),
        Command::InstallGatewayTransition { transition } => install_gateway_transition(&transition),
        Command::AbortGatewayTransition { abort } => abort_gateway_transition(&abort),
        Command::InstallCaTransition { transition } => install_ca_transition(&transition),
        Command::InstallClientTlsCa { transition } => install_client_tls_ca(&transition),
        Command::InstallAstraIssuer { delegation } => install_astra_issuer(&delegation),
        Command::InstallAstraCredentials { credentials } => install_astra_credentials(&credentials),
        Command::InitTrustDomain {
            trust_domain_id,
            ca_public_key,
            gateway_certificate,
            astra_service_public_key,
            authority_url,
            webauthn_rp_id,
            client_tls_ca,
        } => init_trust_domain(
            &trust_domain_id,
            &ca_public_key,
            &gateway_certificate,
            &astra_service_public_key,
            &authority_url,
            &webauthn_rp_id,
            client_tls_ca.as_deref(),
        ),
        Command::RepairClientTlsCaBootstrap { client_tls_ca } => {
            repair_client_tls_ca_bootstrap(&client_tls_ca)
        }
        Command::InitAstraChannel {
            bind,
            astra_certificate,
            authority,
            astra_authority_certificate,
            rotate,
        } => init_astra_channel(
            bind,
            &astra_certificate,
            authority,
            astra_authority_certificate.as_deref(),
            rotate,
        ),
        Command::ShowUplink => show_uplink(),
        Command::ShowIdentity => show_identity(),
        Command::Peer { command } => {
            let network = NetworkConfig::load().context("loading the network config")?;
            peer_command(network, command)
        }
        Command::Tpm { command } => tpm_command(command),
    }
}

/// Drives the update window (see `helios_tpm::update_window`).
fn tpm_command(command: TpmCommand) -> anyhow::Result<()> {
    let tpm = TpmSettings::default();
    match command {
        TpmCommand::PrepareUpdate { reboot } => prepare_update(&tpm, reboot),
        TpmCommand::CancelUpdate => {
            BootController::cancel_update_window(&tpm).context("revoking the update window")?;
            info!("update window revoked");
            Ok(())
        }
        TpmCommand::ExpireWindow => expire_update_window(&tpm),
        TpmCommand::UpdateStatus => {
            match BootController::update_window_armed(&tpm).context("reading the window state")? {
                true => println!("armed"),
                false => println!("none"),
            }
            Ok(())
        }
        TpmCommand::UpdateReadiness => update_readiness(&tpm),
    }
}

/// Answers whether `prepare-update` would succeed, without arming anything.
///
/// Three answers on stdout, because they lead to three different operations:
///
/// - `ready` — the boot unsealed nominally, a window can carry that verdict;
/// - `disabled` — nothing is sealed to the PCRs, so an OS upgrade has no
///   secret to lose and needs no window;
/// - `unavailable` — the TPM answers but this boot is not a nominal unseal
///   (bypassed, provisioned, resealed). The reason is logged, on stderr.
///
/// An unreachable TPM is none of the three: the command fails, and the caller
/// must treat that as a refusal rather than as an absent window. That
/// distinction is the whole point of asking *before* upgrading — after
/// `apt upgrade` there is no answer left that saves the vaults.
///
/// The probe runs the **same** unlock as arming, deliberately: a prediction
/// made by a different path would be a different question. It inherits that
/// path's effects — on a boot whose PCRs have already moved it can consume a
/// reseal ticket, exactly as `prepare-update` would have.
fn update_readiness(tpm: &TpmSettings) -> anyhow::Result<()> {
    let boot = unlock_tpm_for_offline_command(tpm).context("unlocking the TPM vault")?;
    match boot {
        BootDecision::Unsealed(_) => println!("ready"),
        BootDecision::Disabled => println!("disabled"),
        other => {
            warn!(
                "the current boot is {other:?}, not a nominal unseal — no update \
                 window can be armed from it"
            );
            println!("unavailable");
        }
    }
    Ok(())
}

/// Revokes an armed window whose explicit marker deadline has passed.
fn expire_update_window(tpm: &TpmSettings) -> anyhow::Result<()> {
    if !BootController::expire_update_window(tpm).context("expiring the update window")? {
        return Ok(());
    }
    warn!(
        "update window expired without a reboot — revoked. Arm a new one when the \
         upgrade is actually ready."
    );
    Ok(())
}

/// Arms the window, then optionally reboots.
///
/// Arming requires a **nominal** unseal here and now: the window carries an
/// integrity verdict across a reboot, it does not create one. A gateway that
/// is already running on a resealed or bypassed secret is refused, loudly,
/// rather than propagating a state the boot chain never vouched for.
fn prepare_update(tpm: &TpmSettings, reboot: bool) -> anyhow::Result<()> {
    let boot = unlock_tpm_for_offline_command(tpm).context("unlocking the TPM vault")?;
    if !matches!(boot, BootDecision::Unsealed(_)) {
        anyhow::bail!(
            "the current boot is {boot:?}, not a nominal unseal — an update window \
             may only be armed from a boot whose integrity the TPM confirmed"
        );
    }

    let deadline = BootController::arm_update_window(tpm, &boot)
        .map_err(|e| anyhow::anyhow!("arming the update window: {e}"))?;

    warn!(
        deadline,
        "update window armed — it expires on its own, and any boot that unseals \
         nominally revokes it. Reboot now, or run `heliosd tpm cancel-update`."
    );
    if !reboot {
        println!("window armed until unix {deadline} — reboot before then");
        return Ok(());
    }

    println!("window armed until unix {deadline} — rebooting");
    let status = std::process::Command::new("systemctl")
        .arg("reboot")
        .status()
        .context("invoking systemctl reboot")?;
    anyhow::ensure!(
        status.success(),
        "systemctl reboot failed ({status}) — the window stays armed; reboot by hand \
         or run `heliosd tpm cancel-update`"
    );
    Ok(())
}

fn init_key_negotiation(
    network: &NetworkConfig,
    server_name: &str,
    client_ca: &std::path::Path,
    client_pq_ca: &std::path::Path,
    rotate: bool,
) -> anyhow::Result<()> {
    let boot = unlock_tpm_for_offline_command(&TpmSettings::default())
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
    println!(
        "gateway bootstrap request: {}",
        result.bootstrap_request_path.display()
    );
    println!(
        "request fingerprint: {}",
        result.bootstrap_request_fingerprint
    );
    info!("key-negotiation TLS and PQ private keys generated on the gateway and sealed");
    Ok(())
}

/// Prepares the next gateway identity and prints where its request landed.
fn prepare_gateway_certificate(
    rotate_tls: bool,
    new_key: bool,
    key_recovery: bool,
) -> anyhow::Result<()> {
    let boot = unlock_tpm_for_offline_command(&TpmSettings::default())
        .context("unlocking the TPM vault to seal the candidate gateway identity")?;
    let now_unix = now_unix()?;
    let registry = gateway_rotation::open_registry_for_command()?;
    let prepared = gateway_rotation::prepare_request(
        &registry,
        boot.secret(),
        false,
        rotate_tls,
        new_key,
        key_recovery,
        now_unix,
    )?;

    println!("request: {}", prepared.path.display());
    println!("epoch: {}", prepared.request.gateway_identity_epoch);
    println!("request id: {}", prepared.request.request_id.to_hex());
    println!("fingerprint: {}", prepared.request.fingerprint().to_hex());
    println!(
        "expires at: {}",
        aether::display_time::format_paris_timestamp(prepared.request.expires_at)
    );
    match &prepared.tls_certificate {
        Some(certificate) => println!("candidate TLS leaf: {}", certificate.fingerprint().to_hex()),
        None => println!("candidate TLS leaf: unchanged"),
    }
    if prepared.reused {
        info!("the request already prepared for this epoch is still valid and was reused");
    } else if key_recovery {
        warn!(
            "request built without a continuity signature: the transition answering it must \
             carry the key_recovery reason"
        );
    }
    Ok(())
}

fn install_gateway_transition(source: &Path) -> anyhow::Result<()> {
    let now_unix = now_unix()?;
    let mut registry = gateway_rotation::open_registry_for_command()?;
    let transition = gateway_rotation::read_signed_document(source, "transition")?;
    let staged = gateway_rotation::install_transition(&mut registry, transition, now_unix)?;
    let transition = &staged.transition;

    println!("epoch: {}", transition.gateway_identity_epoch);
    println!("fingerprint: {}", transition.fingerprint()?.to_hex());
    println!("reason: {:?}", transition.reason);
    println!(
        "not before: {}",
        aether::display_time::format_paris_timestamp(transition.window.not_before)
    );
    println!(
        "activation at: {}",
        aether::display_time::format_paris_timestamp(transition.window.activation_at)
    );
    println!(
        "not after: {}",
        aether::display_time::format_paris_timestamp(transition.window.not_after)
    );
    match &transition.next_gateway_certificate {
        Some(certificate) => println!(
            "next PQ leaf: {}",
            aether::certificates::gateway::pq_certificate_fingerprint(certificate)?.to_hex()
        ),
        None => println!("next PQ leaf: unchanged"),
    }
    match &transition.next_gateway_tls_certificate {
        Some(certificate) => println!("next TLS leaf: {}", certificate.fingerprint().to_hex()),
        None => println!("next TLS leaf: unchanged"),
    }
    println!("document: {}", staged.path.display());

    if staged.already_present {
        info!("this transition was already staged; nothing moved");
    } else {
        info!(
            "transition staged: the identity in service is unchanged until activation_at, and \
             heliosd must be restarted at that instant to serve the next one"
        );
    }
    Ok(())
}

fn abort_gateway_transition(source: &Path) -> anyhow::Result<()> {
    let now_unix = now_unix()?;
    let mut registry = gateway_rotation::open_registry_for_command()?;
    let abort = gateway_rotation::read_signed_document(source, "abort")?;
    let aborted = gateway_rotation::abort_transition(&mut registry, abort, now_unix)?;

    println!("epoch: {}", aborted.abort.gateway_identity_epoch);
    println!("aborted at: {}", aborted.abort.aborted_at);
    println!("reason: {:?}", aborted.abort.reason);
    println!(
        "cancelled transition: {}",
        aborted.abort.gateway_transition_fingerprint.to_hex()
    );

    if aborted.already_present {
        info!("this abort had already been applied; nothing moved");
    } else {
        warn!(
            "transition cancelled and the candidate identity destroyed: epoch {} stays consumed, \
             the next attempt starts one decision higher",
            aborted.abort.gateway_identity_epoch
        );
    }
    Ok(())
}

fn install_ca_transition(source: &Path) -> anyhow::Result<()> {
    use aether::certificates::state::InstallOutcome;

    let now_unix = now_unix()?;
    let mut registry = gateway_rotation::open_registry_for_command()?;
    let transition: aether::certificates::authority::CaTransition =
        gateway_rotation::read_signed_document(source, "CA-PQ transition")?;
    let outcome = registry
        .install_ca_transition(&transition, now_unix)
        .context("installing the CA-PQ rotation")?;

    println!(
        "epoch: {} → {}",
        transition.current_ca_epoch, transition.next_ca_epoch
    );
    println!("next anchor: {}", transition.next_ca_fingerprint.to_hex());
    println!(
        "activation at: {}",
        aether::display_time::format_paris_timestamp(transition.window.activation_at)
    );
    println!(
        "not after: {}",
        aether::display_time::format_paris_timestamp(transition.window.not_after)
    );
    match outcome {
        InstallOutcome::AlreadyPresent => info!("this rotation was already installed"),
        InstallOutcome::Installed => warn!(
            "CA-PQ rotation staged: both anchors verify from activation_at, and the outgoing one              is retired at not_after. Every client must have received this transition before that              date — one that has not is repaired by an operator, not by a late delivery"
        ),
    }
    Ok(())
}

/// Records the domain's operator credentials, for the enrolment to carry.
fn install_astra_credentials(source: &Path) -> anyhow::Result<()> {
    let mut registry = gateway_rotation::open_registry_for_command()?;
    let credentials: aether::certificates::approval::CredentialRegistry =
        gateway_rotation::read_signed_document(source, "Astra credential registry")?;
    let installed = registry
        .install_astra_credentials(&credentials)
        .context("recording the Astra operator credentials")?;

    println!("registry epoch: {}", credentials.credential_registry_epoch);
    println!("rows installed: {installed}");
    if installed == 0 {
        info!("this registry already holds every row of that document");
    }
    Ok(())
}

/// Records the delegation the authority issues under, and its policy.
///
/// Both halves matter and neither is optional: without the delegation the
/// negotiation port cannot authenticate a renewed leaf, and without the policy
/// the authority refuses to issue one unattended. Prints the pin it ends on
/// either way, because "nothing changed" and "it was already right" are the
/// same silence otherwise.
fn install_astra_issuer(source: &Path) -> anyhow::Result<()> {
    use aether::certificates::approval::PolicyMigration;

    let now_unix = now_unix()?;
    let mut registry = gateway_rotation::open_registry_for_command()?;
    let delegation: aether::certificates::authority::AstraIssuerAuthorization =
        gateway_rotation::read_signed_document(source, "Astra issuer authorization")?;
    let migration = registry
        .install_astra_issuer(&delegation, now_unix)
        .context("adopting the current Astra issuance policy")?;

    println!("issuer epoch: {}", delegation.issuer_epoch);
    match migration {
        PolicyMigration::AlreadyCurrent => {
            println!("policy pin: unchanged");
            info!("the delegation is recorded; this registry already pinned the policy it names");
        }
        PolicyMigration::Adopted(pin) => {
            println!("policy pin: {}", pin.fingerprint().to_hex());
            info!(
                "issuance policy adopted: scheduled renewal of an active identity no longer asks                  for an operator credential on this gateway"
            );
        }
    }
    Ok(())
}

fn install_client_tls_ca(source: &Path) -> anyhow::Result<()> {
    use aether::certificates::state::InstallOutcome;

    let now_unix = now_unix()?;
    let mut registry = gateway_rotation::open_registry_for_command()?;
    let transition: aether::certificates::authority::ClientTlsCaTransition =
        gateway_rotation::read_signed_document(source, "client TLS CA transition")?;
    let outcome = registry
        .install_client_tls_ca_transition(&transition, now_unix)
        .context("installing the client TLS CA rotation")?;

    println!(
        "epoch: {} → {}",
        transition.current_ca_tls_epoch, transition.next_ca_tls_epoch
    );
    println!(
        "next anchor: {}",
        transition
            .next_client_tls_ca_certificate
            .fingerprint()
            .to_hex()
    );
    println!(
        "activation at: {}",
        aether::display_time::format_paris_timestamp(transition.window.activation_at)
    );
    println!(
        "not after: {}",
        aether::display_time::format_paris_timestamp(transition.window.not_after)
    );
    match outcome {
        InstallOutcome::AlreadyPresent => info!("this rotation was already installed"),
        InstallOutcome::Installed => info!(
            "client TLS CA rotation staged: both chains are accepted from activation_at, and the \
             outgoing anchor retires at not_after"
        ),
    }
    Ok(())
}

fn now_unix() -> anyhow::Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock predates the Unix epoch")?
        .as_secs())
}

/// Resolves `wan_iface = "auto"` against the kernel, once.
///
/// Substituted into the in-memory configuration, so everything downstream —
/// the firewall policy, the hot reload, the API view — sees a real interface
/// name rather than a marker. The file keeps `auto`: it describes the
/// operator's intent, not the machine's current cabling.
fn resolve_uplink(network: &mut NetworkConfig) -> anyhow::Result<()> {
    if !network.wan_iface_is_auto() {
        return Ok(());
    }
    let selection = uplink::resolve().context("choosing the WAN interface")?;
    for warning in &selection.warnings {
        warn!("{warning}");
    }
    info!(
        interfaces = %selection.interfaces.join(", "),
        preferred = %selection.preferred(),
        reason = %selection.reason,
        "WAN interfaces enumerated from the kernel — all of them are permitted"
    );
    network.wan_ifaces = selection.interfaces;
    Ok(())
}

/// Prints what `wan_iface = "auto"` would choose, and why.
fn show_uplink() -> anyhow::Result<()> {
    let facts = uplink::observe(
        std::path::Path::new("/sys/class/net"),
        std::path::Path::new("/proc"),
    )
    .context("reading the kernel's network state")?;
    for interface in facts.iter().filter(|facts| facts.physical) {
        println!(
            "{:<12} {:<9} carrier={} default_route={}",
            interface.name,
            if interface.wireless {
                "wireless"
            } else {
                "wired"
            },
            u8::from(interface.carrier),
            match interface.default_route_metric {
                Some(metric) => format!("metric {metric}"),
                None => "none".to_string(),
            }
        );
    }
    println!();
    match uplink::select(&facts) {
        Ok(selection) => {
            for warning in &selection.warnings {
                println!("attention : {warning}");
            }
            println!("permises : {}", selection.interfaces.join(", "));
            println!(
                "préférée : {} — {}",
                selection.preferred(),
                selection.reason
            );
        }
        Err(error) => println!("aucune interface retenue : {error}"),
    }
    Ok(())
}

/// Prints the served key-negotiation identity, for a deployment to read.
///
/// One value per line, `clé=valeur`, because the consumer is a shell script:
/// a script that has to parse JSON over SSH parses it with `sed`, and a `sed`
/// pattern over a certificate is a defect waiting for a field to move.
fn show_identity() -> anyhow::Result<()> {
    if let Some(served) = key_negotiation::served_identity()? {
        println!("server_name={}", served.pq_certificate.subject);
        println!(
            "wireguard_public_key={}",
            served.pq_certificate.wireguard_public_key
        );
        println!(
            "pq_certificate_not_after={}",
            served.pq_certificate.not_after_unix
        );
    } else if let Some(request) = key_negotiation::gateway_bootstrap_request()? {
        request
            .verify()
            .context("verifying the gateway bootstrap request")?;
        println!("server_name={}", request.server_name);
        println!(
            "wireguard_public_key={}",
            request.gateway_wg_public_key.to_base64()
        );
        println!("bootstrap_request_fingerprint={}", request.fingerprint());
    } else {
        anyhow::bail!(
            "this gateway has no key-negotiation identity: run `heliosd init-key-negotiation`"
        );
    }
    Ok(())
}

/// Creates the gateway's end of the private Astra channel (spec §8.3).
///
/// Prints its certificate in the same `clé=valeur` shape `show-identity` uses,
/// and for the same reason: the consumer is `deploy.sh` over SSH, and a script
/// that has to parse JSON parses it with `sed`.
fn init_astra_channel(
    bind: std::net::SocketAddr,
    astra_certificate: &std::path::Path,
    authority: Option<std::net::SocketAddr>,
    astra_authority_certificate: Option<&std::path::Path>,
    rotate: bool,
) -> anyhow::Result<()> {
    let identities = astra_channel::initialize(
        bind,
        astra_certificate,
        authority,
        astra_authority_certificate,
        rotate,
    )?;
    println!("bind={bind}");
    println!(
        "gateway_channel_certificate={}",
        identities.served.to_base64()
    );
    println!(
        "gateway_channel_fingerprint={}",
        identities.served.fingerprint()
    );
    if let Some(client) = &identities.client {
        println!("gateway_client_certificate={}", client.to_base64());
        println!("gateway_client_fingerprint={}", client.fingerprint());
    }
    println!();
    println!(
        "hand the certificates above to Astra: it pins these exact bytes and accepts no other \
         gateway — the served one to dial this listener, the client one to accept this gateway \
         on its own"
    );
    Ok(())
}

/// Creates the gateway's certificate registry.
///
/// # Where each value comes from, and why not from an argument
///
/// The server name and the gateway's WireGuard identity are read out of the PQ
/// leaf already on disk, never retyped: the registry has to describe the
/// identity this gateway actually serves. An operator who mistyped either
/// would produce a registry that disagrees with the certificate every client
/// pins — and the disagreement would only surface at the first staging, as a
/// refusal naming neither.
///
/// The anchors, by contrast, *must* come from the operator: `CA-PQ` is born on
/// their machine inside `astra-signer`, and the Astra service key inside the
/// container. Neither is derivable here, and confirming them out of band is
/// the point (ADR-008 §3).
/// Prints one peer's §19 trust block, as an Orion profile embeds it.
///
/// JSON on stdout and nothing else, so a script can capture it into a file:
/// `provision-client.sh` carries it beside the two gateway certificates it
/// already copies. The same block the admin API serves, from the same reading
/// of the same registry — a second shape here would be a second thing to keep
/// equal by hand.
fn show_trust_enrolment(public_key: &str) -> anyhow::Result<()> {
    use aether::certificates::encoding::WireGuardKey;
    use helios_provisioning::certificates::CertificateRegistry;

    let path = CertificateRegistry::path();
    let registry = CertificateRegistry::load(&path)
        .with_context(|| format!("reading {}", path.display()))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "this gateway has no trust domain: run `heliosd init-trust-domain` first. An \
                 absent registry is not an empty one — the lifecycle routes stay closed."
            )
        })?;
    let key = WireGuardKey::parse(public_key.trim())
        .map_err(|error| anyhow::anyhow!("invalid WireGuard public key: {error}"))?;
    let peer = registry.peer(&key).ok_or_else(|| {
        anyhow::anyhow!(
            "no such peer in the certificate registry — admit it first, with `heliosd peer add` \
             or `helios-ctl peer add`"
        )
    })?;
    let view = certificates::enrolment_view(registry.state(), peer);
    println!(
        "{}",
        serde_json::to_string_pretty(&view).context("encoding the trust block")?
    );
    Ok(())
}

/// The client `CA-TLS` a fresh registry records as generation 1.
///
/// The domain's own anchor when the deployment supplies it, and the operator
/// admission CA otherwise. The fallback exists because a domain may be
/// bootstrapped before `astra-signer issue-ca-tls` has run, but it is never
/// silent: a registry seeded with the admission CA stages no renewal — the
/// candidate leaf chains to Astra's delegated intermediate, which is signed by
/// the domain anchor — and §9.4 cannot repair it afterwards, because a
/// transition can only move away from an anchor the gateway already holds.
fn domain_client_tls_ca(
    supplied: Option<&std::path::Path>,
    served: aether::certificates::encoding::DerCertificate,
) -> anyhow::Result<aether::certificates::encoding::DerCertificate> {
    let Some(path) = supplied else {
        warn!(
            fingerprint = %served.fingerprint(),
            "no --client-tls-ca given: the registry records the operator admission CA as the \
             domain anchor. Renewals will not stage until the domain's own CA-TLS is the active \
             one, and a §9.4 rotation cannot install it — it can only move away from an anchor \
             this gateway already holds"
        );
        return Ok(served);
    };
    let der = std::fs::read(path)
        .with_context(|| format!("reading the domain client CA-TLS in {}", path.display()))?;
    let certificate = aether::certificates::encoding::DerCertificate::new(der)
        .context("the domain client CA-TLS is not a readable certificate")?;
    info!(
        fingerprint = %certificate.fingerprint(),
        "client CA-TLS of the domain recorded as generation 1"
    );
    Ok(certificate)
}

/// Applies the one-time, fail-closed correction for the legacy CA-TLS seed.
fn repair_client_tls_ca_bootstrap(client_tls_ca: &std::path::Path) -> anyhow::Result<()> {
    use aether::certificates::encoding::DerCertificate;
    use helios_provisioning::certificates::{BootstrapRepairOutcome, CertificateRegistry};

    let domain_ca = DerCertificate::new(
        std::fs::read(client_tls_ca)
            .with_context(|| format!("reading {}", client_tls_ca.display()))?,
    )
    .context("the supplied domain client CA-TLS is not a readable certificate")?;
    let served = key_negotiation::served_identity()?.ok_or_else(|| {
        anyhow::anyhow!(
            "the gateway has no served key-negotiation identity from which to read the operator \
             admission CA"
        )
    })?;
    let path = CertificateRegistry::path();
    let mut registry = CertificateRegistry::load(&path)
        .with_context(|| format!("reading {}", path.display()))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "this gateway has no certificate registry; use init-trust-domain for a new domain"
            )
        })?;
    let admission_fingerprint = served.client_tls_ca.fingerprint();
    let domain_fingerprint = domain_ca.fingerprint();
    let outcome = registry
        .repair_legacy_client_tls_ca_bootstrap(&served.client_tls_ca, &domain_ca)
        .context("repairing the legacy client CA-TLS bootstrap")?;

    match outcome {
        BootstrapRepairOutcome::Repaired => println!(
            "client CA-TLS bootstrap repaired atomically: {admission_fingerprint} -> \
             {domain_fingerprint}"
        ),
        BootstrapRepairOutcome::AlreadyCorrect => {
            println!("client CA-TLS bootstrap already current; nothing changed")
        }
        BootstrapRepairOutcome::LaterEpoch => {
            println!("client CA-TLS bootstrap repair not applicable after epoch 1; nothing changed")
        }
    }
    Ok(())
}

fn init_trust_domain(
    trust_domain_id: &str,
    ca_public_key: &str,
    gateway_certificate: &std::path::Path,
    astra_service_public_key: &str,
    authority_url: &str,
    webauthn_rp_id: &str,
    client_tls_ca: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use aether::certificates::encoding::{MlDsa87PublicKey, TrustDomainId, WireGuardKey};
    use aether::certificates::state::{
        AstraProfile, ClientTlsCaState, GatewayCertificateState, TrustLedger,
    };
    use helios_provisioning::certificates::{CertificateRegistry, RegistryState};

    let trust_domain_id =
        TrustDomainId::parse_hex(trust_domain_id).context("reading the trust domain identifier")?;
    let ca_public_key =
        MlDsa87PublicKey::parse(ca_public_key).context("reading the CA-PQ public key")?;
    let astra_service_public_key = MlDsa87PublicKey::parse(astra_service_public_key)
        .context("reading the Astra service public key")?;

    let path = CertificateRegistry::path();
    anyhow::ensure!(
        !path.exists(),
        "a certificate registry already exists at {}; init-trust-domain only creates a domain",
        path.display()
    );
    key_negotiation::install_gateway_bootstrap_certificate(
        gateway_certificate,
        &ca_public_key,
        now_unix()?,
    )?;
    let Some(served) = key_negotiation::served_identity()? else {
        anyhow::bail!(
            "this gateway has no key-negotiation identity yet: run `heliosd \
             init-key-negotiation`, complete the CA-PQ ceremony, then retry"
        );
    };
    let gateway_wg_public_key = WireGuardKey::parse(&served.pq_certificate.wireguard_public_key)
        .context("reading the WireGuard identity out of the served PQ leaf")?;
    let server_name = served.pq_certificate.subject.clone();
    let astra_policy_fingerprint = aether::certificates::AstraIssuancePolicy::standard(
        trust_domain_id,
        gateway_wg_public_key,
        server_name.clone(),
    )
    .pin()
    .context("building the pinned Astra issuance policy")?;

    let domain_client_tls_ca = domain_client_tls_ca(client_tls_ca, served.client_tls_ca)?;
    let state = RegistryState {
        trust_domain_id,
        gateway: GatewayCertificateState {
            trust_domain_id,
            gateway_wg_public_key,
            server_name: server_name.clone(),
            ca_epoch: 1,
            current_ca_public_key: ca_public_key.clone(),
            next_ca_public_key: None,
            next_ca_transition_fingerprint: None,
            ca_activation_at: None,
            ca_retire_active_at: None,
            active_gateway_identity_epoch: 1,
            gateway_decision_epoch: 1,
            next_gateway_identity_epoch: None,
            next_transition_fingerprint: None,
            last_aborted_transition: None,
            active_gateway_tls_certificate: served.tls_certificate,
            next_gateway_tls_certificate: None,
            active_gateway_certificate: served.pq_certificate,
            next_gateway_certificate: None,
            activation_at: None,
            retire_active_at: None,
            published: false,
            revoked: false,
            revocation_epoch: 0,
            service_rollback: None,
            awaited_replacement: None,
        },
        client_tls_ca: ClientTlsCaState {
            ca_tls_epoch: 1,
            active_client_tls_ca_certificate: domain_client_tls_ca,
            next_client_tls_ca_certificate: None,
            next_transition_fingerprint: None,
            activation_at: None,
            retire_active_at: None,
        },
        astra: AstraProfile {
            authority_url: authority_url.to_string(),
            webauthn_rp_id: webauthn_rp_id.to_string(),
            astra_policy_fingerprint,
            credential_registry_epoch: 1,
            credential_bindings: Default::default(),
            active_astra_service_public_key: astra_service_public_key,
            next_astra_service_public_key: None,
            next_service_key_transition_fingerprint: None,
            astra_service_key_epoch: 1,
            service_key_activation_at: None,
            service_key_retire_active_at: None,
            service_key_revocation_epoch: 0,
            last_emergency_replacement_fingerprint: None,
        },
        issuer: None,
        // Peers are not seeded from `network.toml`: admission records
        // fingerprints, and the registry needs the leaves themselves — it has
        // to *verify* signatures made by them, not merely compare. Each peer
        // enters at its first staging.
        peers: Default::default(),
        ledger: TrustLedger::default(),
    };

    let registry = CertificateRegistry::bootstrap(path.clone(), state)
        .context("creating the certificate registry")?;

    println!("registry         : {}", path.display());
    println!("trust domain     : {}", registry.state().trust_domain_id);
    println!("server name      : {server_name}");
    println!(
        "gateway          : {}",
        registry.state().gateway.gateway_wg_public_key
    );
    println!(
        "CA-PQ fingerprint: {}",
        ca_public_key.authority_fingerprint()
    );
    println!(
        "Astra policy pin : {}",
        registry
            .state()
            .astra
            .astra_policy_fingerprint
            .fingerprint()
    );
    println!(
        "gateway TLS      : {}",
        registry.state().gateway.active_tls_fingerprint()
    );
    println!(
        "gateway PQ       : {}",
        registry.state().gateway.active_pq_fingerprint()?
    );
    println!();
    println!(
        "no delegated issuer yet: ordinary renewals stay refused until an \
         `AstraIssuerAuthorization` is signed and installed in Astra"
    );
    println!("restart heliosd to open the in-tunnel lifecycle routes");
    Ok(())
}

/// Creates and seals the gateway's WireGuard identity.
///
/// Unsealing goes through the same `BootController` as nominal startup: if
/// the boot chain's integrity is not confirmed, there is no secret, hence no
/// sealing — and no half-created identity.
fn init_identity(network: &NetworkConfig, rotate: bool) -> anyhow::Result<()> {
    let tpm = TpmSettings::default();
    let boot = unlock_tpm_for_offline_command(&tpm).map_err(|e| {
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
            certificate,
            pq_certificate,
            minimum_mode,
        } => {
            // Read and checked before `network.toml` moves: an admission whose
            // certificates cannot be queued must not leave a peer admitted
            // with no certificate generation.
            let queued = queue_console_admission(
                &name,
                &public_key,
                certificate.as_deref(),
                pq_certificate.as_deref(),
            )?;
            let minimum_mode = admission_floor(
                minimum_mode,
                key_negotiation_pq_certificate_sha256.is_some(),
            );
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
            if let Some(queued) = queued {
                certificates::queue_admission(
                    &helios_provisioning::certificates::CertificateRegistry::path(),
                    &queued,
                )
                .context("queueing the peer's first certificate generation")?;
            }
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

/// Prepares the console's half of an admission into the certificate registry.
///
/// Returns `None` when this gateway has no trust domain: there is nothing to
/// record, and admission keeps working exactly as it did before ADR-008.
///
/// When it does have one, both certificates are required. The registry needs
/// the objects — it verifies signatures made by them — and a peer admitted
/// without them holds no generation, therefore no trust block, therefore a
/// profile that connects and can never renew. That is refused here rather than
/// discovered months later.
fn queue_console_admission(
    name: &str,
    public_key: &str,
    certificate: Option<&Path>,
    pq_certificate: Option<&Path>,
) -> anyhow::Result<Option<certificates::QueuedAdmission>> {
    use base64::Engine as _;

    if !helios_provisioning::certificates::CertificateRegistry::path().exists() {
        return Ok(None);
    }
    let (Some(certificate), Some(pq_certificate)) = (certificate, pq_certificate) else {
        anyhow::bail!(
            "this gateway holds a trust domain, so `peer add` also takes the client's two \
             certificates: --certificate <orion-client-cert.der> --pq-certificate \
             <orion-client-pq-cert.json>. Without them the peer connects but can never renew."
        );
    };
    let encoder = base64::engine::general_purpose::STANDARD;
    let tls =
        std::fs::read(certificate).with_context(|| format!("reading {}", certificate.display()))?;
    let pq = std::fs::read(pq_certificate)
        .with_context(|| format!("reading {}", pq_certificate.display()))?;
    Ok(Some(certificates::QueuedAdmission {
        name: name.to_string(),
        client_wg_public_key: public_key.trim().to_string(),
        tls_certificate: encoder.encode(tls),
        pq_certificate: encoder.encode(pq),
    }))
}

/// Derives the safe default without hiding an explicit operator floor.
fn admission_floor(
    explicit: Option<NegotiationMode>,
    has_pq_certificate: bool,
) -> aether::key_negotiation::ProtectionMode {
    explicit.map(Into::into).unwrap_or_else(|| {
        if has_pq_certificate {
            aether::key_negotiation::ProtectionMode::MlKem
        } else {
            aether::key_negotiation::ProtectionMode::Classic
        }
    })
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

    validate_provisioning_request(&tpm)?;

    tpm.allow_provisioning = true;
    match unlock_tpm_for_offline_command(&tpm)
        .map_err(|e| anyhow::anyhow!("sealing failed: {e}"))?
    {
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

/// Refuses unsafe provisioning requests before opening the TPM device.
fn validate_provisioning_request(tpm: &TpmSettings) -> anyhow::Result<()> {
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
    Ok(())
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

/// Applies process-memory protection before an offline command can create or
/// unseal the TPM root secret.
fn unlock_tpm_for_offline_command(tpm: &TpmSettings) -> anyhow::Result<BootDecision> {
    forbid_core_dumps(false)?;
    BootController::unlock(tpm).map_err(anyhow::Error::new)
}

#[cfg(not(unix))]
fn forbid_core_dumps(_dry_run: bool) -> anyhow::Result<()> {
    Ok(())
}

async fn run(
    mut network: NetworkConfig,
    dry_run: bool,
    firewall_mode: orchestrator::FirewallMode,
) -> anyhow::Result<()> {
    // Before the TPM unseal below, which is where the first key appears.
    forbid_core_dumps(dry_run)?;

    // The uplink, before any ruleset is built: every egress rule and the
    // masquerade are bound to this name, and resolving it later would mean
    // building the kill-switch around an interface we had not chosen yet.
    resolve_uplink(&mut network)?;

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
        // Not a warning, unlike the line above it: the window preserved the
        // secret, so the vaults open and nothing has to be re-supplied. The
        // two decisions look alike and mean opposite things.
        BootDecision::WindowResealed(_) => info!(
            "update window consumed: the PCRs moved (OS upgrade) and the same secret \
             was resealed on the new state — vaults intact"
        ),
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
                 `preshared_key` retiré du fichier"
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
    // Read-only counterpart, for the one decision that cannot use the
    // ten-second peer snapshot: proving a WireGuard handshake at the commit.
    let (handshake_tx, handshake_rx) = mpsc::channel::<ObserveHandshakeRequest>(8);
    let tunnel_state = Arc::new(RwLock::new(TunnelState::Down));
    let shared_network = Arc::new(RwLock::new(network));
    let shared_policy = Arc::new(RwLock::new(shared_network.read().await.firewall_policy()));

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
    let raw_speedtest_bind = if dry_run {
        format!("127.0.0.1:{}", aether::SPEEDTEST_PORT)
    } else {
        shared_network.read().await.speedtest_bind()
    };
    info!("web interface on http://{api_bind}");
    info!("raw speedtest on {raw_speedtest_bind} (WireGuard TCP/UDP)");

    #[allow(unused_mut)]
    let mut state = AppState::new(
        Arc::clone(&shared_network),
        dry_run,
        Arc::clone(&tunnel_state),
        event_tx.clone(),
        cmd_tx,
        psk_tx.clone(),
        Arc::clone(&shared_policy),
    );
    // The sealing posture, as two non-secret facts. `boot` itself is moved
    // into the orchestrator below — it holds the unlock secret, and only the
    // orchestrator may seal.
    state = state.with_tpm(boot.kind(), boot.preserved_vaults());
    // Started here rather than earlier because the reclamation loop reads the
    // same data-plane snapshot the console does, and that snapshot is owned
    // by `AppState`. Polling the backend a second time would risk the two
    // readers disagreeing on whether a peer is still there — and the whole
    // point of v5's liveness is that there is one answer, read where the
    // traffic is.
    // Opened once, and shared. The negotiation *reads* it — a caller resolved
    // by the fingerprint mTLS proved has to be looked up in the thing that
    // recorded the last rotation, not in a file written at admission — while
    // the lifecycle service below is its single writer. Two `CertificateRegistry`
    // values over one path would be two writers of one slot.
    let registry = match certificates::open_registry(
        &helios_provisioning::certificates::CertificateRegistry::path(),
    ) {
        Ok(registry) => registry,
        Err(error) => {
            error!(
                %error,
                "certificate registry unusable — the in-tunnel lifecycle routes stay closed and \
                 the negotiation falls back to the pins of network.toml"
            );
            None
        }
    };
    if let Some(registry) = &registry {
        let mut registry = registry.lock().await;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock predates the Unix epoch")?
            .as_secs();
        if gateway_rotation::maintain_gateway_identity(&mut registry, boot.secret(), now_unix)
            .context("reconciling the scheduled gateway identity before startup")?
        {
            info!("gateway identity promoted and sealed slots synchronized");
        }
    }
    if let Some(handler) = key_negotiation::start(
        Arc::clone(&shared_network),
        psk_tx.clone(),
        handshake_tx,
        Arc::clone(&state.peer_runtime),
        registry.clone(),
        &boot,
        dry_run,
    )
    .await?
    {
        // The certificate lifecycle, when this gateway has a trust domain. It
        // signs its receipts through the negotiation handler — the same leaf
        // the client already pins, unsealed once — and it is the single owner
        // of the registry: a second one would give one slot two writers.
        // Built before the service, and shared with it: the same veth client
        // serves the four renewal routes and the trust-update producer, and a
        // second one would open a second connection to say the same thing.
        let authority = astra_channel::relay().map(Arc::new);
        let gateway_identity_secret = boot.secret().cloned();
        match registry.map(|registry| {
            let service = certificates::CertificateService::new(
                registry,
                Arc::clone(&handler) as Arc<dyn certificates::StageReceiptSigner>,
            )
            .with_gateway_identity_secret(gateway_identity_secret);
            Arc::new(match &authority {
                Some(relay) => service.with_authority(
                    Arc::clone(relay) as Arc<dyn helios_api::internal::TrustUpdatePreparer>
                ),
                None => service,
            })
        }) {
            Some(service) => {
                info!("certificate lifecycle ready");
                certificates::spawn_maintenance(Arc::clone(&service));
                // Admissions made on the console, in another process: it may
                // only leave the two public leaves in an inbox, because this
                // task is the single owner of the registry. Drained here, and
                // at every start — an admission made while the daemon was down
                // is recorded when it comes back.
                certificates::spawn_admission_drain(
                    Arc::clone(&service),
                    helios_provisioning::certificates::CertificateRegistry::path(),
                );
                // The private veth listener, on its own socket. Never a path
                // on the administration API: two listeners make "Astra may
                // not admit a peer" a fact about which socket the packet
                // arrived on, rather than about middleware ordering.
                astra_channel::spawn(
                    Arc::clone(&service) as Arc<dyn helios_api::internal::AstraChannelHandler>
                );
                // And the other direction: the four in-tunnel renewal routes
                // relay into Astra's own listener. Separate from the trust
                // update on purpose — a gateway may hold a registry and have
                // no way to dial the authority, and in that state the
                // trust-update route must keep working while the renewal
                // routes report the authority unreachable.
                if let Some(relay) = authority {
                    // The same relay on both surfaces: one veth client, two
                    // stores at the far end. The operator routes sit behind
                    // `require_admin` rather than `require_peer` (spec §8.5),
                    // which is what keeps a campaign out of reach of an
                    // ordinary admitted peer.
                    state = state.with_operator_campaign(Arc::clone(&relay)
                        as Arc<dyn helios_api::certificates::OperatorCampaignRelay>);
                    state = state.with_client_renewal(relay);
                }
                // The same service, on two surfaces: the lifecycle screen
                // reads through `trust_update`, and its four gestures go
                // through `gateway_identity`. One instance, because both
                // mutate the registry this task owns.
                state = state.with_gateway_identity(Arc::clone(&service)
                    as Arc<dyn helios_api::certificates::GatewayIdentityHandler>);
                state = state.with_trust_update(service);
            }
            None => info!(
                "no certificate registry: the trust domain is not bootstrapped, and the \
                 in-tunnel lifecycle routes stay closed"
            ),
        }
        // The in-tunnel `release` (spec §7.5) reaches the same state machine
        // as the public negotiation, through the same per-peer serializer.
        // A second instance here would give one slot two writers.
        state = state.with_psk_release(handler);
    }
    // Published for the operator tooling: `helios-ctl` builds a complete
    // Orion profile from the gateway rather than making the operator copy
    // certificates out of /var/lib/helios by hand.
    if let Some(material) = key_negotiation::public_material()? {
        state = state.with_key_negotiation(material);
    }
    let api_ready = Arc::clone(&state.api_ready);
    // The console reads the data plane through this snapshot; only the
    // orchestrator's poller writes it.
    let peer_runtime = Arc::clone(&state.peer_runtime);
    let api_state = state.clone();
    tokio::spawn(async move {
        // Outside simulation, the API listens on the WireGuard address —
        // which the orchestrator, started right after, has not yet assigned
        // to the interface. The first `bind` therefore fails with "Cannot
        // assign requested address", and without a retry the gateway would
        // run for good without an API: no provisioning, no telemetry, for a
        // race lost by a few dozen milliseconds.
        for attempt in 1..=API_BIND_ATTEMPTS {
            match helios_api::serve(api_state.clone(), &api_bind).await {
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

    let raw_speedtest_state = state.clone();
    let raw_speedtest_shutdown = Arc::new(AtomicBool::new(false));
    let raw_speedtest_task_shutdown = Arc::clone(&raw_speedtest_shutdown);
    tokio::spawn(async move {
        // It never gives up, and that is the point. The tunnel address appears
        // when WireGuard comes up, so the first binds legitimately fail — that
        // is what the fast burst is for. But the port can also be held by
        // **another program**, and that is not transient: `iperf3` listening on
        // a wildcard listener wins the port and keeps it, and a gateway that
        // stopped trying after ten seconds served no speedtest until someone
        // restarted the daemon. Worse, it said so once, in a line long gone by
        // the time a client reports « connexion fermée par l'hôte ».
        //
        // So after the burst it keeps retrying slowly, and logs only when the
        // situation *changes* — a conflict that persists for a day is one line,
        // not a hundred and seventy thousand.
        let mut attempt: u32 = 0;
        let mut reported: Option<String> = None;
        loop {
            attempt = attempt.saturating_add(1);
            match helios_api::speedtest::serve_raw(
                raw_speedtest_state.clone(),
                &raw_speedtest_bind,
                Arc::clone(&raw_speedtest_task_shutdown),
            )
            .await
            {
                Ok(()) => return,
                Err(error) => {
                    let reason = format!("{error:#}");
                    if attempt < API_BIND_ATTEMPTS {
                        warn!(
                            "raw speedtest unavailable (attempt {attempt}/{API_BIND_ATTEMPTS}), \
                             retrying: {reason}"
                        );
                        tokio::time::sleep(API_BIND_DELAY).await;
                        continue;
                    }
                    if reported.as_deref() != Some(reason.as_str()) {
                        tracing::error!(
                            bind = %raw_speedtest_bind,
                            "raw speedtest still unavailable after {attempt} attempts: {reason}. \
                             A client asking for a speedtest will be told the service is absent. \
                             If the address is in use, another program holds this port — \
                             `ss -lntup | grep {port}` names it, iperf3 on 0.0.0.0 being the \
                             usual one. Retrying every {retry}s.",
                            port = aether::speedtest::SPEEDTEST_PORT,
                            retry = RAW_SPEEDTEST_RETRY.as_secs(),
                        );
                        reported = Some(reason);
                    }
                    tokio::time::sleep(RAW_SPEEDTEST_RETRY).await;
                }
            }
        }
    });

    let result = orchestrator::run(
        shared_network,
        dry_run,
        firewall_mode,
        tunnel_state,
        event_tx,
        cmd_rx,
        psk_rx,
        handshake_rx,
        shared_policy,
        peer_runtime,
        boot,
        api_ready,
    )
    .await;
    raw_speedtest_shutdown.store(true, Ordering::Release);
    result
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
            Command::Run {
                dev: true,
                unsafe_disable_firewall: false
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["heliosd", "run", "--unsafe-disable-firewall"])
                .unwrap()
                .command,
            Command::Run {
                dev: false,
                unsafe_disable_firewall: true
            }
        ));
        assert!(
            Cli::try_parse_from(["heliosd", "run", "--dev", "--unsafe-disable-firewall"]).is_err()
        );
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
            Cli::try_parse_from(["heliosd", "tpm", "prepare-update", "--reboot"])
                .unwrap()
                .command,
            Command::Tpm {
                command: TpmCommand::PrepareUpdate { reboot: true }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["heliosd", "tpm", "expire-window"])
                .unwrap()
                .command,
            Command::Tpm {
                command: TpmCommand::ExpireWindow
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["heliosd", "init-identity", "--rotate"])
                .unwrap()
                .command,
            Command::InitIdentity { rotate: true }
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "heliosd",
                "init-trust-domain",
                "--trust-domain-id",
                "00112233445566778899aabbccddeeff",
                "--ca-public-key",
                "ca",
                "--gateway-certificate",
                "/tmp/gateway.json",
                "--astra-service-public-key",
                "service",
                "--authority-url",
                "https://astra.example",
                "--webauthn-rp-id",
                "astra.example",
            ])
            .unwrap()
            .command,
            Command::InitTrustDomain {
                gateway_certificate,
                ..
            } if gateway_certificate == std::path::Path::new("/tmp/gateway.json")
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "heliosd",
                "repair-client-tls-ca-bootstrap",
                "--client-tls-ca",
                "/tmp/domain-ca.der",
            ])
            .unwrap()
            .command,
            Command::RepairClientTlsCaBootstrap { client_tls_ca }
                if client_tls_ca == std::path::Path::new("/tmp/domain-ca.der")
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
                        certificate: None,
                        pq_certificate: None,
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
    fn admission_floor_defaults_to_the_strongest_available_identity() {
        use aether::key_negotiation::ProtectionMode;

        assert_eq!(admission_floor(None, false), ProtectionMode::Classic);
        assert_eq!(admission_floor(None, true), ProtectionMode::MlKem);
        assert_eq!(
            admission_floor(Some(NegotiationMode::StaticPsk), true),
            ProtectionMode::StaticPsk,
            "an explicit floor must not be replaced by inference"
        );
    }

    #[test]
    fn explicit_development_mode_always_wins_auto_detection() {
        assert!(resolve_dry_run(true));
    }

    #[test]
    fn automatic_development_mode_matches_the_detected_kernel() {
        assert_eq!(
            resolve_dry_run(false),
            is_wsl2() && !wireguard_module_present()
        );
    }

    #[test]
    fn provisioning_refuses_a_disabled_tpm_and_an_existing_vault() {
        let disabled = TpmSettings {
            enabled: false,
            ..TpmSettings::default()
        };
        assert!(validate_provisioning_request(&disabled)
            .unwrap_err()
            .to_string()
            .contains("without the `tpm` feature"));

        let directory = std::env::temp_dir().join(format!(
            "helios-provisioning-guard-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let blob = directory.join("sealed.key");
        std::fs::write(&blob, b"existing vault").unwrap();
        let existing = TpmSettings {
            enabled: true,
            sealed_blob_path: blob.to_string_lossy().into_owned(),
            ..TpmSettings::default()
        };
        assert!(validate_provisioning_request(&existing)
            .unwrap_err()
            .to_string()
            .contains("refusing to overwrite"));

        std::fs::remove_dir_all(directory).unwrap();
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
                persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
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

#[cfg(test)]
mod trust_domain_seeding_tests {
    use super::domain_client_tls_ca;
    use aether::certificates::encoding::DerCertificate;

    fn certificate(byte: u8) -> DerCertificate {
        DerCertificate::new(vec![0x30, 0x03, 0x02, 0x01, byte]).expect("certificate")
    }

    /// The domain's own anchor wins over the admission CA that was served.
    ///
    /// This is the whole point of the option: `served.client_tls_ca` is the
    /// operator CA that decides who may open an mTLS session, and recording it
    /// as the domain anchor is what made every staging refuse the candidate
    /// leaf — which chains to Astra's delegated intermediate, signed by the
    /// domain's CA-TLS and by nothing else.
    #[test]
    fn a_supplied_domain_anchor_replaces_the_admission_ca() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("domain-client-ca-tls.der");
        let domain = certificate(7);
        std::fs::write(&path, domain.as_bytes()).expect("writing the anchor");

        let seeded = domain_client_tls_ca(Some(&path), certificate(1)).expect("seeding");
        assert_eq!(
            seeded, domain,
            "the registry records what the domain serves"
        );
    }

    /// Without the option, the served CA is kept — a bootstrap before
    /// `issue-ca-tls` must not fail — and the caller is warned it will not
    /// stage a renewal.
    #[test]
    fn without_the_option_the_served_ca_is_kept() {
        let served = certificate(1);
        let seeded = domain_client_tls_ca(None, served.clone()).expect("seeding");
        assert_eq!(seeded, served);
    }

    /// A file that is not a certificate is named, not recorded.
    #[test]
    fn a_file_that_is_not_a_certificate_is_refused() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("pas-un-certificat.der");
        std::fs::write(&path, b"").expect("writing");
        assert!(domain_client_tls_ca(Some(&path), certificate(1)).is_err());

        let absent = directory.path().join("absent.der");
        assert!(domain_client_tls_ca(Some(&absent), certificate(1)).is_err());
    }
}
