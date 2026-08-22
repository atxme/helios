//! `astra` — the authority coordinator daemon.
//!
//! Three commands, and the separation between them is the ADR-008 boundary:
//!
//! - `bootstrap` creates the registry of a trust domain. It never creates
//!   `CA-PQ`: the anchor is produced by the operator companion and confirmed
//!   out of band, and Astra only ever learns its **public** half.
//! - `run` serves the public HTTPS endpoint.
//! - `status` prints what the authority currently believes, including the head
//!   of the audit chain — the value an operator records so a restore can be
//!   told apart from a fork.
//! - `issuer request` / `issuer install` prepare the delegated issuer and take
//!   back the delegation the companion signed. Two commands and not one,
//!   because the signature happens on another machine, at a security key: the
//!   private halves are born here and never travel, and what crosses is a
//!   public request one way and a `CA-PQ`-signed authorization the other.
//!
//! # Limite connue
//!
//! `run` binds plain HTTP and expects a TLS terminator in front of it — a
//! reverse proxy, or the container's own ingress. Terminating TLS here would
//! mean holding a Web PKI key beside the delegated issuer, and the endpoint's
//! transport certificate is explicitly **not** what authenticates Astra: the
//! pinned ML-DSA-87 service key is (spec §9.6). Deployments that expose
//! `astra_port` directly must place a terminator in the same container.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, MlDsa87PublicKey, TrustDomainId, WireGuardKey,
};
use anyhow::{Context, Result};
use astra::registry::{AstraRegistry, AstraState, ChallengeStore};
use astra::service::{AstraService, SourceBudget, MAX_LIVE_CHALLENGES};
use astra::{AuditEvent, DelegatedIssuer};
use clap::{Parser, Subcommand};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const DEFAULT_STATE_DIR: &str = "/var/lib/astra";
const REGISTRY_FILE: &str = "registry.json";
const SERVICE_KEY_FILE: &str = "service-key.bin";
/// Private material of one delegation, addressed by its epoch.
///
/// Epoch-addressed rather than fixed: `issuer request` writes the keys of the
/// **next** delegation while the current one is still signing, and the
/// registry names the epoch that is installed. An interrupted authorization
/// therefore leaves an unreferenced pair of files and a working issuer, rather
/// than a live delegation whose keys were overwritten by a candidate nobody
/// signed.
fn issuer_pq_key_path(state_dir: &Path, issuer_epoch: u64) -> PathBuf {
    state_dir.join(format!("issuer-pq-key-{issuer_epoch}.bin"))
}

fn issuer_tls_key_path(state_dir: &Path, issuer_epoch: u64) -> PathBuf {
    state_dir.join(format!("issuer-tls-key-{issuer_epoch}.der"))
}
const OPERATIONS_FILE: &str = "client-renewal-operations.json";
/// The signed credential decisions of the domain, as the companion emits them.
///
/// Copied into Astra's state volume by an operator (spec §8.2 would carry it,
/// and answers `501`). It holds no secret: every row is public and signed by
/// `CA-PQ`, which is why it can travel by hand at all.
const CREDENTIALS_FILE: &str = "astra-credentials.json";
/// Largest credential document read, in bytes.
const MAX_CREDENTIALS_BYTES: u64 = 1024 * 1024;
/// The encrypted authority vault, as the companion wrote it.
///
/// Astra transports and backs it up; it does not open it, and nothing in this
/// container can — the key-slots unwrap under a FIDO2 `hmac-secret` output
/// that never leaves the operator's token. Copied in by an operator, exactly
/// like the credential document.
const VAULT_FILE: &str = "authority-vault.json";
/// Largest vault file read, in bytes.
///
/// The same ceiling the companion applies to its own copy: a file larger than
/// this is not a vault with more key-slots, it is a mistake or a wedge.
const MAX_VAULT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "astra",
    version,
    about = "Coordinateur d'autorité Helios (ADR-008)"
)]
struct Cli {
    /// State directory. Holds the registry, the audit chain and the sealed
    /// service key — never a master key.
    #[arg(long, env = "ASTRA_STATE_DIR", default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Creates the registry of a trust domain.
    Bootstrap {
        /// Public `CA-PQ` key, base64. Confirmed out of band — this is the
        /// only anchor Astra ever trusts, and it is never created here.
        #[arg(long)]
        ca_public_key: String,
        #[arg(long)]
        trust_domain_id: String,
        #[arg(long)]
        gateway_wireguard_public_key: String,
        #[arg(long)]
        server_name: String,
        #[arg(long)]
        authority_url: String,
        #[arg(long)]
        webauthn_rp_id: String,
    },
    /// Creates Astra's transport identity for the private veth channel (§8.3).
    ///
    /// It generates a service identity — unrelated to `CA-PQ`, to the service
    /// key and to every client — and prints its certificate. `heliosd
    /// init-astra-channel` pins those exact bytes.
    InitChannel {
        /// Replaces an existing identity. **The gateway must be re-pinned**:
        /// it holds these exact bytes and accepts no other client.
        #[arg(long)]
        rotate: bool,
    },
    /// Serves the public endpoint.
    Run {
        #[arg(long, default_value = "127.0.0.1:8443")]
        bind: SocketAddr,
        /// Head of the audit chain recorded by the operator. Given, a restore
        /// that forked away from it is refused instead of continued; a suffix
        /// made only of legacy read-only status publications is tolerated.
        #[arg(long)]
        expected_audit_head: Option<String>,
        /// Address of the gateway's private lifecycle listener, on the veth.
        ///
        /// Absent, the private channel stays closed and Astra serves its
        /// public endpoint alone — a supported state, and the one every
        /// deployment starts in.
        #[arg(long, env = "ASTRA_GATEWAY_CHANNEL")]
        gateway_channel: Option<SocketAddr>,
        /// The gateway's transport certificate, DER base64 — printed by
        /// `heliosd init-astra-channel`. The only server identity Astra will
        /// accept on that address, byte for byte.
        #[arg(long, env = "ASTRA_GATEWAY_CERTIFICATE")]
        gateway_certificate: Option<String>,
        /// Address Astra's own private listener binds, on the veth.
        ///
        /// This is the direction the **gateway** dials: it relays a client's
        /// renewal into it (spec §8.1.2). Absent, the four renewal routes have
        /// nothing behind them and the gateway answers `503` — the same
        /// supported state as a deployment with no authority at all.
        #[arg(long, env = "ASTRA_PRIVATE_BIND")]
        private_bind: Option<SocketAddr>,
        /// The gateway's **client** transport certificate, DER base64 —
        /// printed by `heliosd init-astra-channel`. The only client identity
        /// this listener accepts, byte for byte.
        #[arg(long, env = "ASTRA_GATEWAY_CLIENT_CERTIFICATE")]
        gateway_client_certificate: Option<String>,
    },
    /// Prepares the delegated issuer, and installs the delegation once signed.
    Issuer {
        #[command(subcommand)]
        command: IssuerCommand,
    },
    /// Opens a manual rotation campaign for an operator to approve (§7.6).
    Campaign {
        #[command(subcommand)]
        command: CampaignCommand,
    },
    /// Prints the authority's state and the head of its audit chain.
    Status {
        /// Previously recorded head. A suffix made only of legacy status
        /// publications is accepted while all authority decisions remain
        /// subject to the normal fork check.
        #[arg(long)]
        expected_audit_head: Option<String>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum CampaignScopeArg {
    /// The fleet's client leaves. Rotates no authority.
    FleetLeafs,
    /// The `CA-PQ` anchor. Two operator credentials, and the companion signs.
    TrustAuthorities,
}

#[derive(Subcommand)]
enum CampaignCommand {
    /// Resolves a campaign over the current fleet and deposits it.
    ///
    /// # Why a local command and not a public route
    ///
    /// §11.6 has an interface ask Astra to resolve a campaign over the
    /// **current** targets and generations. On the public origin that would be
    /// an unauthenticated route answering every caller with the domain's
    /// inventory, and the authentication such a route would need is not
    /// settled anywhere. So the resolution happens here, on the machine that
    /// already runs Astra, and the result is deposited for the running service
    /// to adopt — the shape `heliosd peer add` uses for the same reason.
    ///
    /// What it prints is an opaque operation identifier. Everything else — the
    /// capability tokens, the campaign itself — the companion fetches from the
    /// endpoint under that identifier.
    Open {
        /// What the campaign covers.
        #[arg(long, value_enum)]
        scope: CampaignScopeArg,
        /// Free text shown to the operator before the touch.
        #[arg(long)]
        reason: String,
        /// Who asked for it. Shown to the operator, and audited.
        #[arg(long)]
        requested_by: String,
        /// How long the operator has, in seconds.
        #[arg(long, default_value_t = 300)]
        window_secs: u64,
    },
}

#[derive(Subcommand)]
enum IssuerCommand {
    /// Generates the next delegation's private material and prints its request.
    ///
    /// The request is public: an ML-DSA-87 public key and a PKCS#10 request
    /// for the TLS intermediate. It goes to the operator's machine, where
    /// `astra-signer authorize-issuer` signs it under `CA-PQ` at a security
    /// key. Nothing here can sign anything until that authorization comes
    /// back — the keys exist, and no object names them.
    Request {
        /// Where to write the request, in addition to standard output.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Installs the `AstraIssuerAuthorization` the companion signed.
    ///
    /// Verified under the anchor the registry pins, against the pinned
    /// issuance policy, and against the private keys already on disk — three
    /// checks that come from three different places, which is the only reason
    /// installing is not simply believing a file.
    Install {
        /// The signed authorization, in JSON. Standard input when absent.
        #[arg(long)]
        authorization: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    // Logs on **stderr**, so standard output carries only what a command
    // produces. `issuer request` is piped out of the container by the
    // deployment, and a start-up banner interleaved with its JSON would make
    // the handover depend on the log level.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Named before anything draws from it, and fatal when unusable
    // (ROTATION-CERTIFICATS §2.3.2).
    // Settled before the first HTTP client: two rustls providers are compiled
    // in, so an unnamed one is a panic rather than a choice.
    helios_api::internal::install_process_default_provider();

    let drbg = aether::random::configure().context("resolving the DRBG provider")?;
    tracing::info!(%drbg, "randomness provider");

    let cli = Cli::parse();
    match cli.command {
        Command::Bootstrap {
            ca_public_key,
            trust_domain_id,
            gateway_wireguard_public_key,
            server_name,
            authority_url,
            webauthn_rp_id,
        } => bootstrap(
            &cli.state_dir,
            &ca_public_key,
            &trust_domain_id,
            &gateway_wireguard_public_key,
            &server_name,
            &authority_url,
            &webauthn_rp_id,
        ),
        Command::InitChannel { rotate } => init_channel(&cli.state_dir, rotate),
        Command::Run {
            bind,
            expected_audit_head,
            gateway_channel,
            gateway_certificate,
            private_bind,
            gateway_client_certificate,
        } => run(
            &cli.state_dir,
            bind,
            expected_audit_head.as_deref(),
            gateway_channel,
            gateway_certificate.as_deref(),
            private_bind,
            gateway_client_certificate.as_deref(),
        ),
        Command::Issuer { command } => match command {
            IssuerCommand::Request { out } => issuer_request(&cli.state_dir, out.as_deref()),
            IssuerCommand::Install { authorization } => {
                issuer_install(&cli.state_dir, authorization.as_deref())
            }
        },
        Command::Campaign { command } => match command {
            CampaignCommand::Open {
                scope,
                reason,
                requested_by,
                window_secs,
            } => campaign_open(&cli.state_dir, scope, &reason, &requested_by, window_secs),
        },
        Command::Status {
            expected_audit_head,
        } => status(&cli.state_dir, expected_audit_head.as_deref()),
    }
}

fn bootstrap(
    state_dir: &Path,
    ca_public_key: &str,
    trust_domain_id: &str,
    gateway_wireguard_public_key: &str,
    server_name: &str,
    authority_url: &str,
    webauthn_rp_id: &str,
) -> Result<()> {
    let registry_path = state_dir.join(REGISTRY_FILE);
    anyhow::ensure!(
        !registry_path.exists(),
        "a registry already exists at {}: bootstrapping over it would start a second history \
         for the same domain",
        registry_path.display()
    );
    aether::private_file::create_private_dir(state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;

    let ca_public_key =
        MlDsa87PublicKey::parse(ca_public_key).context("reading the CA-PQ public key")?;
    let trust_domain_id =
        TrustDomainId::parse_hex(trust_domain_id).context("reading the trust domain identifier")?;
    let gateway_wg_public_key = WireGuardKey::parse(gateway_wireguard_public_key)
        .context("reading the gateway WireGuard public key")?;
    let astra_policy_fingerprint = aether::certificates::AstraIssuancePolicy::standard(
        trust_domain_id,
        gateway_wg_public_key,
        server_name.to_string(),
    )
    .pin()
    .context("building the pinned Astra issuance policy")?;

    // The service key is Astra's own voice — it signs statuses and operation
    // receipts. It is not an issuer and it certifies nothing.
    let (service_private_key, service_public_key) =
        generate_ml_dsa_87_keypair().context("generating the Astra service key")?;
    aether::private_file::write_private_atomic(
        &state_dir.join(SERVICE_KEY_FILE),
        &service_private_key,
    )
    .context("sealing the Astra service key")?;

    let state_trust_domain = trust_domain_id;
    let state = AstraState {
        trust_domain_id,
        gateway_wg_public_key,
        server_name: server_name.to_string(),
        authority_url: authority_url.to_string(),
        webauthn_rp_id: webauthn_rp_id.to_string(),
        astra_policy_fingerprint,
        credential_registry_epoch: 1,
        ca_epoch: 1,
        ca_public_key,
        ca_tls_epoch: 1,
        astra_service_key_epoch: 1,
        astra_service_public_key: service_public_key.clone(),
        issuer: None,
        transitions: Vec::new(),
        peers: Default::default(),
        status_epochs: Default::default(),
        audit: Default::default(),
    };
    let mut registry = AstraRegistry::new(registry_path.clone(), state);
    registry.record(AuditEvent::DomainBootstrapped, now_unix())?;

    println!("registry            : {}", registry_path.display());
    // The base64 key, not only its fingerprint: `heliosd init-trust-domain`
    // pins the key itself, and a fingerprint is not something an operator can
    // hand it. Printing only the digest left the value they need unreachable.
    println!("service key         : {}", service_public_key.to_base64());
    println!(
        "service fingerprint : {}",
        service_public_key.authority_fingerprint()
    );
    println!("audit head          : {}", registry.audit_head());
    println!(
        "policy fingerprint  : {}",
        registry.state().astra_policy_fingerprint.fingerprint()
    );
    println!();
    println!(
        "record the audit head above: a restore that ends elsewhere is a fork, and `astra run \
         --expected-audit-head` is what refuses it"
    );
    println!(
        "then, on the gateway: `heliosd init-trust-domain --trust-domain-id {} --ca-public-key \
         <CA-PQ> --astra-service-public-key <service key above> --authority-url {} \
         --webauthn-rp-id {}`",
        state_trust_domain, authority_url, webauthn_rp_id
    );
    Ok(())
}

/// Creates Astra's end of the private channel, and prints its certificate.
///
/// One value per line, `clé=valeur`, because the consumer is `deploy.sh` over
/// SSH: a script that has to parse JSON parses it with `sed`, and a `sed`
/// pattern over a certificate is a defect waiting for a field to move.
fn init_channel(state_dir: &Path, rotate: bool) -> Result<()> {
    let identities = astra::gateway::initialize_pair(state_dir, rotate)
        .context("creating the Astra transport identities")?;
    println!(
        "astra_channel_certificate={}",
        identities.client.to_base64()
    );
    println!(
        "astra_channel_fingerprint={}",
        identities.client.fingerprint()
    );
    println!(
        "astra_authority_certificate={}",
        identities.authority.to_base64()
    );
    println!(
        "astra_authority_fingerprint={}",
        identities.authority.fingerprint()
    );
    println!();
    println!(
        "then, on the gateway: `heliosd init-astra-channel --bind <veth address:port> \
         --astra-certificate <astra_channel_certificate> --authority <astra veth address:port> \
         --astra-authority-certificate <astra_authority_certificate>`"
    );
    Ok(())
}

/// Opens the private channel to the gateway, when this deployment has one.
///
/// The pin is checked here, at startup, rather than at the first rotation: an
/// unusable pairing found at deployment costs a command, and the same pairing
/// found at 80 % of a leaf's life costs a night. It performs no network I/O —
/// the gateway may legitimately come up after the authority does.
fn open_gateway_channel(
    state_dir: &Path,
    address: Option<SocketAddr>,
    certificate: Option<&str>,
) -> Result<Option<astra::gateway::GatewayChannel>> {
    let (Some(address), Some(certificate)) = (address, certificate) else {
        if address.is_some() != certificate.is_some() {
            // Half a pairing is an operator error, not a deployment choice: it
            // means someone meant to have a channel and will not.
            anyhow::bail!(
                "the private gateway channel needs both its address and the gateway's pinned \
                 certificate; only one was given"
            );
        }
        tracing::info!(
            "no private gateway channel configured: Astra serves its public endpoint alone, and \
             stages nothing on the gateway"
        );
        return Ok(None);
    };
    let pinned = aether::certificates::encoding::DerCertificate::parse(certificate)
        .map_err(|error| anyhow::anyhow!("the pinned gateway certificate: {error}"))?;
    let channel = astra::gateway::GatewayChannel::open(state_dir, address, &pinned)
        .map_err(|error| anyhow::anyhow!("opening the private gateway channel: {error}"))?;
    tracing::info!(
        gateway = %channel.address(),
        pinned_gateway_sha256 = %pinned.fingerprint(),
        "private gateway channel ready"
    );
    Ok(Some(channel))
}

fn run(
    state_dir: &Path,
    bind: SocketAddr,
    expected_audit_head: Option<&str>,
    gateway_channel: Option<SocketAddr>,
    gateway_certificate: Option<&str>,
    private_bind: Option<SocketAddr>,
    gateway_client_certificate: Option<&str>,
) -> Result<()> {
    // Before the registry is touched: a mispinned channel is a deployment
    // error, and reporting it after "Astra ready" buries it under a success.
    let gateway = open_gateway_channel(state_dir, gateway_channel, gateway_certificate)?;
    let expected = expected_audit_head
        .map(Fingerprint::parse_hex)
        .transpose()
        .context("reading the expected audit head")?;
    let registry =
        AstraRegistry::load_allowing_status_tail(&state_dir.join(REGISTRY_FILE), expected.as_ref())
            .context("loading the Astra registry")?;
    let service_private_key = Zeroizing::new(
        std::fs::read(state_dir.join(SERVICE_KEY_FILE)).context("reading the Astra service key")?,
    );

    tracing::info!(
        domain = %registry.state().trust_domain_id,
        gateway = %registry.state().gateway_wg_public_key,
        audit_head = %registry.audit_head(),
        peers = registry.state().peers.len(),
        "Astra ready"
    );

    let issuer = load_issuer(state_dir, &registry)?;
    let (approval_credential_ids, approval_credential_registry_epoch, approval_credential_registry) =
        load_approval_credentials(state_dir, &registry)?;
    let service_public_key = registry.state().astra_service_public_key.clone();
    let operations =
        astra::operations::OperationStore::load(&state_dir.join(OPERATIONS_FILE), now_unix())
            .context("loading the client renewal operations")?;
    let encrypted_vault = load_encrypted_vault(state_dir)?;
    let service = Arc::new(AstraService {
        registry: Mutex::new(registry),
        issuer,
        challenges: Mutex::new(ChallengeStore::with_capacity(MAX_LIVE_CHALLENGES)),
        budgets: Mutex::new(SourceBudget::default()),
        service_private_key,
        service_public_key,
        operations: Mutex::new(operations),
        capabilities: Mutex::new(
            aether::certificates::capability::CapabilityTokens::new()
                .context("drawing the capability key")?,
        ),
        approval_credential_ids,
        approval_credential_registry_epoch,
        approval_credential_registry,
        signing: Mutex::new(astra::signing::SigningOperationStore::new()),
        encrypted_vault,
        gateway,
    });

    // Built before the runtime, and fatal when unusable: a listener whose pin
    // does not load is an operator error, and finding it at the first renewal
    // is finding it at the one moment there is no fallback.
    let private = private_listener(state_dir, private_bind, gateway_client_certificate)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the Astra runtime")?;
    runtime.block_on(async move {
        if let Some((bind, config)) = private {
            // Its own task, and its failure is never the public endpoint's:
            // a gateway that cannot relay a renewal is a degraded authority,
            // not a dead one.
            let router = astra::renewal::router::router(service.clone());
            tokio::spawn(async move {
                if let Err(error) = helios_api::internal::serve(
                    bind,
                    config,
                    router,
                    helios_api::internal::ASTRA_INTERNAL_PREFIX,
                )
                .await
                {
                    tracing::error!(
                        %bind, %error,
                        "the private renewal listener never came up; the gateway will answer 503 \
                         to every client renewal"
                    );
                }
            });
        }
        spawn_campaign_drain(service.clone(), state_dir.to_path_buf());
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .with_context(|| format!("binding {bind}"))?;
        tracing::info!(%bind, "Astra public endpoint listening");
        axum::serve(
            listener,
            astra::service::router(service).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .context("serving the Astra public endpoint")
    })
}

/// Adopts the campaigns a local operator command deposited.
///
/// The store lives in this process, in memory; `astra campaign open` runs in
/// another one. This is the same arrangement `heliosd` uses for console
/// admissions, and for the same reason: one owner of the state, and a second
/// process that may only leave something for it.
///
/// A deposit that does not verify is **removed**, not retried. It sat between
/// two processes on disk, and re-reading it every two seconds until its window
/// closes would turn one bad file into a log the operator has to scroll past.
fn spawn_campaign_drain(service: Arc<AstraService>, state_dir: PathBuf) {
    tokio::spawn(async move {
        let directory = state_dir.join(astra::signing::CAMPAIGN_INBOX_DIR);
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            astra::signing::INBOX_POLL_INTERVAL_SECS,
        ));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            // Anchor transitions that can no longer authorize anything, on the
            // same tick. A bounded store that only ever grows refuses the next
            // rotation, and it would refuse it during a ceremony.
            match service
                .registry
                .lock()
                .await
                .forget_expired_transitions(now_unix())
            {
                Ok(0) => {}
                Ok(dropped) => tracing::info!(
                    dropped,
                    "anchor transitions past their window forgotten: a peer that never collected \
                     one is repaired by an operator, not by a late delivery"
                ),
                Err(error) => tracing::error!(
                    %error,
                    "could not sweep the expired anchor transitions"
                ),
            }
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                    continue;
                }
                match adopt_campaign_file(&service, &path).await {
                    Ok(operation_id) => tracing::info!(
                        %operation_id,
                        "manual campaign adopted; the companion may fetch it"
                    ),
                    Err(error) => tracing::error!(
                        file = %path.display(),
                        %error,
                        "manual campaign refused: nothing was opened, and the operator has to \
                         run `astra campaign open` again"
                    ),
                }
                let _ = std::fs::remove_file(&path);
            }
        }
    });
}

/// Reads one deposit and opens the operation it describes.
async fn adopt_campaign_file(
    service: &Arc<AstraService>,
    path: &Path,
) -> Result<aether::certificates::encoding::Id16> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > astra::signing::MAX_INBOX_ENTRY_BYTES {
        anyhow::bail!("{} bytes: this is not a campaign", metadata.len());
    }
    let bytes = std::fs::read(path)?;
    let deposit: astra::signing::CampaignDeposit =
        serde_json::from_slice(&bytes).context("decoding the campaign")?;
    let (service_public_key, service_key_epoch, authority_url) = {
        let registry = service.registry.lock().await;
        let state = registry.state();
        (
            state.astra_service_public_key.clone(),
            state.astra_service_key_epoch,
            state.authority_url.clone(),
        )
    };
    let mut store = service.signing.lock().await;
    astra::signing::adopt_deposit(
        &mut store,
        deposit,
        &service_public_key,
        service_key_epoch,
        &authority_url,
        now_unix(),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))
}

/// Astra's own listener on the veth, when this deployment has one.
///
/// It pins the gateway's **client** certificate — a second identity from the
/// one Astra pins for dialling, because the two roles are pinned by different
/// peers under different names. Half a pairing is refused rather than served
/// one-sided: an address without a pin would accept any client that reached
/// the veth, which is precisely what the pin exists to prevent.
fn private_listener(
    state_dir: &Path,
    bind: Option<SocketAddr>,
    gateway_client_certificate: Option<&str>,
) -> Result<Option<(SocketAddr, rustls::ServerConfig)>> {
    let (Some(bind), Some(certificate)) = (bind, gateway_client_certificate) else {
        if bind.is_some() != gateway_client_certificate.is_some() {
            anyhow::bail!(
                "the private renewal listener needs both its bind address and the gateway's \
                 pinned client certificate; only one was given"
            );
        }
        tracing::info!(
            "no private renewal listener configured: the gateway relays no client renewal, and \
             answers 503 on its four renewal routes"
        );
        return Ok(None);
    };
    anyhow::ensure!(
        !bind.ip().is_unspecified(),
        "the private renewal listener is configured to bind {bind}, which publishes the authority \
         on every interface; name Astra's veth address"
    );
    let pinned = aether::certificates::encoding::DerCertificate::parse(certificate)
        .map_err(|error| anyhow::anyhow!("the pinned gateway client certificate: {error}"))?;
    let identity = astra::gateway::authority_identity(state_dir)
        .map_err(|error| anyhow::anyhow!("reading the authority transport identity: {error}"))?;
    let config = helios_api::internal::server_config(&identity, &pinned)
        .map_err(|error| anyhow::anyhow!("building the private renewal listener: {error}"))?;
    tracing::info!(
        %bind,
        pinned_gateway_client_sha256 = %pinned.fingerprint(),
        "private renewal listener ready"
    );
    Ok(Some((bind, config)))
}

/// The credentials an ordinary renewal may be approved by.
///
/// The document is **verified** here, under the `CA-PQ` the registry already
/// pins and at the registry's own epoch — never trusted for being on disk. A
/// file an operator copied to the wrong host, or one left behind by a previous
/// domain, would otherwise put credential identifiers into a signed approval
/// request that no key can answer.
///
/// Only `active` rows are kept. Naming a lost or revoked credential would ask
/// an operator for a touch the verifier then refuses — a ceremony spent on a
/// refusal, at the one moment there is nobody to ask twice.
///
/// A missing document is not fatal: the authority still serves statuses and
/// still holds the channel. Every ordinary renewal is then refused by name,
/// which is what an incomplete install should look like.
/// What the credential document yields at start-up.
///
/// The identifiers, the epoch they came from, and the document itself — the
/// last because whoever runs an approval verifies it under `CA-PQ`, and an
/// allow-list this process merely asserted would be an allow-list a compromised
/// Astra chooses.
type ApprovalCredentials = (
    Vec<Vec<u8>>,
    u64,
    Option<Box<aether::certificates::approval::CredentialRegistry>>,
);

/// Reads the encrypted vault, if an operator has copied one into the volume.
///
/// The bytes are kept exactly as written and never parsed: Astra serves them
/// to a companion that holds the key-slots, and a value it had opinions about
/// would be a value it could substitute. Its fingerprint is what the signed
/// `AstraSignerRequest` names, so a wrong file is refused by the companion —
/// not by this read.
///
/// Absent is a supported state, and the ordinary one: only a campaign that
/// rotates an anchor needs it. Saying so at start-up beats discovering it in
/// the middle of a ceremony.
fn load_encrypted_vault(state_dir: &Path) -> Result<Option<Vec<u8>>> {
    let path = state_dir.join(VAULT_FILE);
    let Ok(metadata) = std::fs::metadata(&path) else {
        tracing::info!(
            path = %path.display(),
            "no encrypted vault in the state volume: campaigns that rotate an anchor are refused \
             by name; every other scope is unaffected"
        );
        return Ok(None);
    };
    if metadata.len() > MAX_VAULT_BYTES {
        anyhow::bail!(
            "{} is {} bytes, over the {MAX_VAULT_BYTES}-byte ceiling: this is not a vault",
            path.display(),
            metadata.len()
        );
    }
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let fingerprint = aether::certificates::encoding::Fingerprint::of(&bytes);
    tracing::info!(
        path = %path.display(),
        vault_sha256 = %fingerprint,
        bytes = bytes.len(),
        "encrypted vault held for the companion — this process cannot open it"
    );
    Ok(Some(bytes))
}

fn load_approval_credentials(
    state_dir: &Path,
    registry: &AstraRegistry,
) -> Result<ApprovalCredentials> {
    let path = state_dir.join(CREDENTIALS_FILE);
    let Ok(metadata) = std::fs::metadata(&path) else {
        tracing::warn!(
            path = %path.display(),
            "no credential document: no operator credential can approve a renewal, so every \
             ordinary rotation will be refused until `astra-signer bindings` is copied here"
        );
        return Ok((Vec::new(), registry.state().credential_registry_epoch, None));
    };
    if metadata.len() > MAX_CREDENTIALS_BYTES {
        anyhow::bail!(
            "{} weighs {} bytes: that is not a credential document",
            path.display(),
            metadata.len()
        );
    }
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let document: aether::certificates::approval::CredentialRegistry =
        serde_json::from_slice(&bytes)
            .with_context(|| format!("reading the credential document {}", path.display()))?;

    let state = registry.state();
    document
        .verify(
            &state.ca_public_key,
            &state.trust_domain_id,
            &state.gateway_wg_public_key,
            state.ca_epoch,
            state.credential_registry_epoch,
        )
        .with_context(|| format!("verifying the credential document {}", path.display()))?;

    let approvable: Vec<Vec<u8>> = document
        .approvable()
        .into_iter()
        .map(|binding| binding.credential_id.clone())
        .collect();
    tracing::info!(
        credentials = approvable.len(),
        rows = document.bindings.len(),
        registry_epoch = document.credential_registry_epoch,
        "credential document loaded"
    );
    let epoch = document.credential_registry_epoch;
    Ok((approvable, epoch, Some(Box::new(document))))
}

/// Builds the delegated issuer, when the domain has one **and** its private
/// material is on disk.
///
/// The three parts are independent on purpose: the authorization is public and
/// travels in the registry, while the two private keys are generated and
/// sealed locally. A registry that names a delegation whose keys are missing is
/// an incomplete install, and it is reported as such — an issuer silently
/// forced to `None` would refuse every ordinary renewal with no explanation,
/// at 80 % of a leaf's life.
fn load_issuer(state_dir: &Path, registry: &AstraRegistry) -> Result<Option<DelegatedIssuer>> {
    let Some(installed) = registry.state().issuer.as_ref() else {
        tracing::warn!(
            "no delegated issuer in the registry: ordinary renewals stay refused until \
             `AstraIssuerAuthorization` is signed by the operator companion"
        );
        return Ok(None);
    };
    let pq_key = issuer_pq_key_path(state_dir, installed.issuer_epoch);
    let tls_key = issuer_tls_key_path(state_dir, installed.issuer_epoch);
    if !pq_key.exists() || !tls_key.exists() {
        tracing::error!(
            issuer_epoch = installed.issuer_epoch,
            pq_key = %pq_key.display(),
            tls_key = %tls_key.display(),
            "the registry names a delegated issuer but its private material is missing: \
             ordinary renewals will be refused"
        );
        return Ok(None);
    }
    let pq_private_key =
        Zeroizing::new(std::fs::read(&pq_key).context("reading the delegated issuer PQ key")?);
    let tls_private_key =
        Zeroizing::new(std::fs::read(&tls_key).context("reading the delegated issuer TLS key")?);
    registry
        .state()
        .astra_policy_fingerprint
        .assert_authorizes(&installed.authorization)
        .context("the delegated issuer does not match the pinned Astra policy")?;
    // Present is not the same as correct: the keys and the delegation come
    // from two different places, and a mismatch would only show up at the
    // first renewal.
    let issuer = DelegatedIssuer::load(
        installed.authorization.clone(),
        pq_private_key,
        tls_private_key,
    )
    .context("checking the delegated issuer's private material against the registry")?;
    tracing::info!(
        issuer_epoch = installed.issuer_epoch,
        not_after = installed.authorization.not_after,
        "delegated issuer loaded"
    );
    Ok(Some(issuer))
}

/// Draws the next delegation's private keys and prints its public request.
///
/// Nothing is installed and nothing is announced: the registry is only read,
/// for the epoch to advance from. Until an authorization comes back, these two
/// files are a key pair no signed object names — which is exactly the state an
/// interrupted ceremony should leave behind.
/// A non-zero 16-byte identifier from the approved DRBG (spec §2.3.2).
fn fresh_id() -> Result<aether::certificates::encoding::Id16> {
    let bytes = aether::random::public_bytes::<16>()
        .map_err(|error| anyhow::anyhow!("drawing an identifier: {error}"))?;
    aether::certificates::encoding::Id16::new(bytes)
        .map_err(|error| anyhow::anyhow!("drawing an identifier: {error}"))
}

/// Resolves a campaign over the fleet as it stands, and deposits it (§7.6).
///
/// Every target is pinned to the generation and the **exact** fingerprints the
/// registry holds right now. That is what makes the operator's touch an
/// approval of a specific set rather than of a list evaluated later: a target
/// that moves in between changes the campaign fingerprint, and
/// `assert_unchanged` refuses it instead of quietly recomputing.
///
/// A revoked peer is not a target. `revoked` is terminal — no credential lifts
/// it — so including one would put an object in the campaign that every
/// downstream step must then refuse, and would make the count the operator
/// reads on their screen wrong.
fn campaign_open(
    state_dir: &Path,
    scope: CampaignScopeArg,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
) -> Result<()> {
    use aether::certificates::status::{
        AstraRotationCampaign, AstraSignerRequest, CampaignScope, CampaignTarget, CertificateKind,
        MAX_CAMPAIGN_TARGETS,
    };

    if reason.trim().is_empty() || requested_by.trim().is_empty() {
        anyhow::bail!("--reason and --requested-by are what the operator reads before the touch");
    }
    // The specification bounds the campaign window at five minutes: the
    // approval is a challenge, and a challenge with a long life is a challenge
    // worth capturing.
    if window_secs == 0 || window_secs > 300 {
        anyhow::bail!("--window-secs must be between 1 and 300");
    }

    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let state = registry.state();
    let scope = match scope {
        CampaignScopeArg::FleetLeafs => CampaignScope::FleetLeafs,
        CampaignScopeArg::TrustAuthorities => CampaignScope::TrustAuthorities,
    };

    let targets: Vec<CampaignTarget> = match scope {
        // One target, and it is the anchor as this registry holds it right
        // now. The companion compares it to the anchor its own vault holds:
        // two authorities that disagree about which `CA-PQ` is current must
        // not be reconciled by a rotation, they must stop.
        CampaignScope::TrustAuthorities => {
            let anchor = state.ca_public_key.authority_fingerprint();
            vec![CampaignTarget {
                certificate_kind: CertificateKind::CaPq,
                identity_key: state.gateway_wg_public_key,
                epoch: state.ca_epoch,
                generation: state.ca_epoch,
                active_tls_certificate_fingerprint: anchor,
                active_pq_certificate_fingerprint: anchor,
            }]
        }
        _ => state
            .peers
            .values()
            .filter(|peer| !peer.revoked)
            .map(|peer| CampaignTarget {
                certificate_kind: CertificateKind::ClientPq,
                identity_key: peer.client_wg_public_key,
                epoch: state.ca_epoch,
                generation: peer.active.generation,
                active_tls_certificate_fingerprint: peer.active.tls_certificate_fingerprint,
                active_pq_certificate_fingerprint: peer.active.pq_certificate_fingerprint,
            })
            .collect(),
    };
    if targets.is_empty() {
        anyhow::bail!(
            "no admitted peer in this registry: there is nothing for an operator to approve"
        );
    }
    if scope.rotates_authority() && load_encrypted_vault(state_dir)?.is_none() {
        // The companion needs the vault to open `CA-PQ`, and it fetches it
        // from here. Opening the campaign anyway would spend an operator's
        // window on a ceremony that cannot reach a private key.
        anyhow::bail!(
            "this state volume holds no encrypted vault: an authority campaign has nothing for \
             the companion to open, and `CA-PQ` would never sign"
        );
    }
    if targets.len() > MAX_CAMPAIGN_TARGETS {
        anyhow::bail!(
            "{} targets, over the {MAX_CAMPAIGN_TARGETS} ceiling of §8.2",
            targets.len()
        );
    }

    let now = now_unix();
    let expires_at = now
        .checked_add(window_secs)
        .context("campaign window overflow")?;
    let campaign = AstraRotationCampaign {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        campaign_id: fresh_id()?,
        trust_domain_id: state.trust_domain_id,
        gateway_wg_public_key: state.gateway_wg_public_key,
        server_name: state.server_name.clone(),
        created_at: now,
        expires_at,
        scope,
        targets,
        reason: reason.trim().to_string(),
        requested_by: requested_by.trim().to_string(),
        // The pin the domain was bootstrapped with, not one computed here: a
        // campaign carrying a policy it derived itself would be a campaign
        // that chose the policy it is checked against (§2.4).
        policy_fingerprint: *state.astra_policy_fingerprint.fingerprint(),
        required_credentials: scope.required_credentials(),
    };
    campaign.validate(now).map_err(|error| {
        anyhow::anyhow!("the resolved campaign is not one an operator may be shown: {error}")
    })?;

    let service_private_key = Zeroizing::new(
        std::fs::read(state_dir.join(SERVICE_KEY_FILE)).context("reading the Astra service key")?,
    );
    // The vault fingerprint is part of the signed request, so a scope that
    // needs no vault still names one. All-zero would be a value the companion
    // could be pointed at; the vault actually held is the honest answer, and
    // `SigningOperation::vault_fingerprint` is what decides whether a token is
    // ever minted for it.
    let vault_fingerprint = load_encrypted_vault(state_dir)?
        .map(|bytes| Fingerprint::of(&bytes))
        .unwrap_or_else(|| Fingerprint::of(b"no encrypted vault in this state volume"));
    let signer_request = AstraSignerRequest {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        operation_id: fresh_id()?,
        campaign_fingerprint: campaign.fingerprint(),
        authority_url: state.authority_url.clone(),
        encrypted_vault_fingerprint: vault_fingerprint,
        required_credentials: campaign.required_credentials,
        created_at: now,
        expires_at,
        astra_service_key_epoch: state.astra_service_key_epoch,
        astra_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(&service_private_key)
    .map_err(|error| anyhow::anyhow!("signing the companion request: {error}"))?;

    let operation_id = signer_request.operation_id;
    let deposit = astra::signing::CampaignDeposit {
        campaign: Box::new(campaign),
        signer_request: Box::new(signer_request),
    };
    let directory = state_dir.join(astra::signing::CAMPAIGN_INBOX_DIR);
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("creating {}", directory.display()))?;
    let path = directory.join(format!("{}.json", operation_id.to_hex()));
    let temporary = directory.join(format!("{}.tmp", operation_id.to_hex()));
    std::fs::write(
        &temporary,
        serde_json::to_vec(&deposit).context("encoding the campaign")?,
    )
    .with_context(|| format!("writing {}", temporary.display()))?;
    // Renamed into place, so the drain never reads a half-written campaign and
    // refuses a deposit that was merely still being made.
    std::fs::rename(&temporary, &path).with_context(|| format!("publishing {}", path.display()))?;

    println!("{}", operation_id.to_hex());
    eprintln!(
        "campagne déposée : {} cible(s), {} credential(s), fenêtre de {window_secs} s",
        deposit.campaign.targets.len(),
        deposit.campaign.required_credentials
    );
    eprintln!("empreinte de campagne : {}", deposit.campaign.fingerprint());
    eprintln!(
        "approuver depuis le poste opérateur :\n  astra-signer approve-campaign \\\n    \
         --authority-url {} \\\n    --operation-id {}",
        deposit.signer_request.authority_url,
        operation_id.to_hex()
    );
    eprintln!(
        "limite connue : l'approbation sera enregistrée, et rien ne l'applique encore. Produire \
         les objets signés et les déposer sur le veth est le lot suivant — cette commande sert à \
         éprouver la cérémonie, pas à faire tourner un parc."
    );
    Ok(())
}

fn issuer_request(state_dir: &Path, out: Option<&Path>) -> Result<()> {
    use base64::Engine as _;

    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let state = registry.state();
    let issuer_epoch = state
        .issuer
        .as_ref()
        .map(|installed| installed.issuer_epoch)
        .unwrap_or(0)
        .checked_add(1)
        .context("issuer epoch overflow")?;

    let (pq_private_key, pq_public_key) =
        generate_ml_dsa_87_keypair().context("generating the delegated issuer ML-DSA-87 key")?;
    let tls_key = rcgen::KeyPair::generate().context("generating the delegated issuer TLS key")?;

    // Subject only. Validity, `basicConstraints` and key usage are the
    // issuer's decision and are set by the companion when it signs — a PKCS#10
    // request that carried them would be asking for what it is not entitled to
    // choose.
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .context("building the intermediate request")?;
    let mut name = rcgen::DistinguishedName::new();
    name.push(
        rcgen::DnType::CommonName,
        format!("astra delegated issuer {issuer_epoch}"),
    );
    params.distinguished_name = name;
    let csr = params
        .serialize_request(&tls_key)
        .context("serializing the intermediate request")?;

    // The private halves first: a request whose keys were not written would
    // name a public key nobody can ever sign with, and the operator would only
    // discover it after a security-key ceremony.
    aether::private_file::write_private_atomic(
        &issuer_pq_key_path(state_dir, issuer_epoch),
        &pq_private_key,
    )
    .context("sealing the delegated issuer ML-DSA-87 key")?;
    aether::private_file::write_private_atomic(
        &issuer_tls_key_path(state_dir, issuer_epoch),
        &tls_key.serialize_der(),
    )
    .context("sealing the delegated issuer TLS key")?;

    let request = astra::issuer::IssuerDelegationRequest {
        trust_domain_id: state.trust_domain_id.to_hex(),
        issuer_epoch,
        pq_issuer_public_key: pq_public_key.to_base64(),
        tls_intermediate_csr: base64::engine::general_purpose::STANDARD.encode(csr.der()),
    };
    let encoded = serde_json::to_vec_pretty(&request).context("encoding the delegation request")?;
    if let Some(out) = out {
        std::fs::write(out, &encoded).with_context(|| format!("writing {}", out.display()))?;
        eprintln!("delegation request : {}", out.display());
    }
    eprintln!("issuer epoch       : {issuer_epoch}");
    eprintln!(
        "sign it with `astra-signer authorize-issuer --request <file> --out <file>`, then feed \
         the result back to `astra issuer install`"
    );
    // On standard output, alone, so a deployment script can pipe it out of the
    // container without a shared volume.
    println!("{}", String::from_utf8_lossy(&encoded));
    Ok(())
}

/// Installs a signed delegation, after checking it three ways.
///
/// The anchor the registry pins, the policy it computed at bootstrap, and the
/// private keys already on disk. The three come from three different places on
/// purpose: a file that satisfies all of them is one this authority can
/// actually issue with, and the alternative is announcing a delegation whose
/// first use fails at 80 % of a client's leaf.
fn issuer_install(state_dir: &Path, authorization: Option<&Path>) -> Result<()> {
    let encoded = match authorization {
        Some(path) => std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        None => {
            use std::io::Read as _;
            let mut buffer = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buffer)
                .context("reading the authorization from standard input")?;
            buffer
        }
    };
    let authorization: aether::certificates::authority::AstraIssuerAuthorization =
        serde_json::from_slice(&encoded).context("reading the issuer authorization")?;

    let mut registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let now = now_unix();
    {
        let state = registry.state();
        authorization
            .verify(
                &state.ca_public_key,
                &state.trust_domain_id,
                state.ca_epoch,
                state.ca_tls_epoch,
                &state.gateway_wg_public_key,
                &state.server_name,
                now,
            )
            .context("verifying the issuer authorization under this domain's anchor")?;
        state
            .astra_policy_fingerprint
            .assert_authorizes(&authorization)
            .context("the delegation does not match the pinned Astra issuance policy")?;
    }

    let issuer_epoch = authorization.issuer_epoch;
    let pq_key = issuer_pq_key_path(state_dir, issuer_epoch);
    let tls_key = issuer_tls_key_path(state_dir, issuer_epoch);
    anyhow::ensure!(
        pq_key.exists() && tls_key.exists(),
        "no private material for issuer epoch {issuer_epoch} in {}: this authorization answers a \
         request another state directory made, or `astra issuer request` was never run here",
        state_dir.display()
    );
    let pq_private_key =
        Zeroizing::new(std::fs::read(&pq_key).context("reading the delegated issuer PQ key")?);
    let tls_private_key =
        Zeroizing::new(std::fs::read(&tls_key).context("reading the delegated issuer TLS key")?);
    // Possession, before anything is recorded: this is the check that refuses
    // a delegation signed around somebody else's public key.
    DelegatedIssuer::load(authorization.clone(), pq_private_key, tls_private_key)
        .context("checking the delegation against the private material on disk")?;

    let not_after = authorization.not_after;
    registry
        .install_issuer(
            aether::certificates::state::AstraIssuerState {
                issuer_epoch,
                authorization,
                state: aether::certificates::state::IssuerLifecycle::Active,
            },
            now,
        )
        .context("recording the delegation")?;

    println!("issuer epoch     : {issuer_epoch}");
    println!("delegation until : {not_after}");
    println!("audit head       : {}", registry.audit_head());
    println!(
        "restart Astra to load it: the delegation is read at start-up, beside the private keys \
         it names"
    );
    Ok(())
}

fn status(state_dir: &Path, expected_audit_head: Option<&str>) -> Result<()> {
    let expected = expected_audit_head
        .map(Fingerprint::parse_hex)
        .transpose()
        .context("reading the expected audit head")?;
    let registry =
        AstraRegistry::load_allowing_status_tail(&state_dir.join(REGISTRY_FILE), expected.as_ref())
            .context("loading the Astra registry")?;
    let state = registry.state();
    println!("trust domain     : {}", state.trust_domain_id);
    println!("gateway          : {}", state.gateway_wg_public_key);
    println!("server name      : {}", state.server_name);
    println!("CA-PQ epoch      : {}", state.ca_epoch);
    println!(
        "CA-PQ fingerprint: {}",
        state.ca_public_key.authority_fingerprint()
    );
    println!("service key epoch: {}", state.astra_service_key_epoch);
    println!(
        "service key      : {}",
        state.astra_service_public_key.to_base64()
    );
    println!(
        "delegated issuer : {}",
        match &state.issuer {
            Some(issuer) => format!("epoch {}", issuer.issuer_epoch),
            None => "absent".to_string(),
        }
    );
    println!("audit head       : {}", registry.audit_head());
    println!("peers            : {}", state.peers.len());

    let now = now_unix();
    for peer in state.peers.values() {
        let urgency = astra::planner::urgency(&peer.active, now)
            .map(|urgency| format!("{urgency:?}"))
            .unwrap_or_else(|_| "unreadable".to_string());
        println!(
            "  {} — génération {} — {}{}",
            peer.name,
            peer.active.generation,
            urgency,
            if peer.revoked { " — révoqué" } else { "" }
        );
    }
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}
