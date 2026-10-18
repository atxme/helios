//! `heliosd` — control plane orchestrator daemon.

mod astra_channel;
mod certificates;
mod commands;
mod daemon;
mod gateway_key;
mod gateway_rotation;
mod key_negotiation;
mod orchestrator;
mod process_guards;
mod static_psk;
mod uplink;
mod vip_routing;

use std::path::PathBuf;

use aether::NetworkConfig;
use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::commands::identity::{
    init_astra_channel, init_identity, init_key_negotiation, show_identity,
};
use crate::commands::ipv6_prefix::init_ipv6_prefix;
use crate::commands::peer::peer_command;
use crate::commands::tpm::{provision_tpm, tpm_command};
use crate::commands::trust::{
    abort_gateway_transition, init_trust_domain, install_astra_credentials, install_astra_issuer,
    install_ca_transition, install_client_tls_ca, install_gateway_transition,
    prepare_gateway_certificate, repair_client_tls_ca_bootstrap, show_trust_enrolment,
};
use crate::commands::wan::{resolve_uplink, show_uplink};
use crate::daemon::run;
use crate::process_guards::resolve_dry_run;

#[cfg(test)]
pub(crate) static NETWORK_CONFIG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn with_network_config_test<T>(path: &std::path::Path, body: impl FnOnce() -> T) -> T {
    let _guard = NETWORK_CONFIG_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    struct Restore(Option<std::ffi::OsString>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                std::env::set_var("HELIOS_NETWORK_CONFIG", previous);
            } else {
                std::env::remove_var("HELIOS_NETWORK_CONFIG");
            }
        }
    }
    let restore = Restore(std::env::var_os("HELIOS_NETWORK_CONFIG"));
    std::env::set_var("HELIOS_NETWORK_CONFIG", path);
    let result = body();
    drop(restore);
    result
}

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
    /// Generates and persists the gateway's IPv6 ULA tunnel prefix.
    ///
    /// Run explicitly with the daemon stopped. The prefix is stable after it
    /// is written; changing it renumbers every IPv6 peer address.
    InitIpv6Prefix,
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
    /// The nominal path afterwards is `helios peer`, through the tunnel.
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
pub(crate) enum TpmCommand {
    /// Reports whether this binary uses TPM sealing, without opening the TPM.
    SealingStatus,
    /// Exports an encrypted root backup for planned firmware maintenance.
    ExportFirmware {
        #[arg(long)]
        operator_public_key: String,
        #[arg(long)]
        device: String,
        #[arg(long)]
        target_version: String,
    },
    /// Verifies a firmware authorization supplied as JSON on stdin.
    FirmwarePreflight,
    /// Restores the existing root from a bounded SSH stdin frame.
    RestoreFirmware,
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
pub(crate) enum PeerCommand {
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
pub(crate) enum NegotiationMode {
    StaticPsk,
    MlKem,
}

impl From<NegotiationMode> for aether::key_negotiation::ProtectionMode {
    fn from(value: NegotiationMode) -> Self {
        match value {
            NegotiationMode::StaticPsk => Self::StaticPsk,
            NegotiationMode::MlKem => Self::MlKem,
        }
    }
}

/// Rewrites the pre-v5 `minimum_key_negotiation_mode = "classic"` values of
/// `network.toml`, logging each peer that changed.
fn migrate_legacy_key_negotiation_floors() -> anyhow::Result<()> {
    for migration in NetworkConfig::migrate_legacy_classic_floor()
        .context("migrating the legacy classic key-negotiation floors")?
    {
        let state = match migration.floor {
            None => "plain WireGuard, no negotiation",
            Some(_) => "floor raised to ml_kem",
        };
        warn!(
            peer = %migration.peer,
            state,
            "rewrote the legacy classic key-negotiation floor in network.toml"
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Logs go to **stderr**, never stdout: several subcommands answer on stdout
    // and are read by a machine — `tpm update-status` returns `armed`/`none` to
    // `helios update`, `peer add` returns the assigned VIP. A log line
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
    ::astra_channel::install_process_default_provider();

    let drbg = aether::random::configure().context("resolving the DRBG provider")?;
    info!(%drbg, "randomness provider");

    match cli.command {
        Command::Run {
            dev,
            unsafe_disable_firewall,
        } => {
            // Before the first load: the typed load refuses a legacy `classic`
            // floor, so it is rewritten here, and a failure stops the daemon.
            migrate_legacy_key_negotiation_floors()?;
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
        Command::InitIpv6Prefix => init_ipv6_prefix(),
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
            ProtectionMode::from(NegotiationMode::StaticPsk),
            ProtectionMode::StaticPsk
        );
        assert_eq!(
            ProtectionMode::from(NegotiationMode::MlKem),
            ProtectionMode::MlKem
        );
    }
}
