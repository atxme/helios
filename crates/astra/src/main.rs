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
const ISSUER_PQ_KEY_FILE: &str = "issuer-pq-key.bin";
const ISSUER_TLS_KEY_FILE: &str = "issuer-tls-key.der";
const OPERATIONS_FILE: &str = "client-renewal-operations.json";
/// The signed credential decisions of the domain, as the companion emits them.
///
/// Copied into Astra's state volume by an operator (spec §8.2 would carry it,
/// and answers `501`). It holds no secret: every row is public and signed by
/// `CA-PQ`, which is why it can travel by hand at all.
const CREDENTIALS_FILE: &str = "astra-credentials.json";
/// Largest credential document read, in bytes.
const MAX_CREDENTIALS_BYTES: u64 = 1024 * 1024;

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
        /// that forked away from it is refused instead of continued.
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
    /// Prints the authority's state and the head of its audit chain.
    Status,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
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
        Command::Status => status(&cli.state_dir),
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
    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), expected.as_ref())
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
    let (approval_credential_ids, approval_credential_registry_epoch) =
        load_approval_credentials(state_dir, &registry)?;
    let service_public_key = registry.state().astra_service_public_key.clone();
    let operations =
        astra::operations::OperationStore::load(&state_dir.join(OPERATIONS_FILE), now_unix())
            .context("loading the client renewal operations")?;
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
fn load_approval_credentials(
    state_dir: &Path,
    registry: &AstraRegistry,
) -> Result<(Vec<Vec<u8>>, u64)> {
    let path = state_dir.join(CREDENTIALS_FILE);
    let Ok(metadata) = std::fs::metadata(&path) else {
        tracing::warn!(
            path = %path.display(),
            "no credential document: no operator credential can approve a renewal, so every \
             ordinary rotation will be refused until `astra-signer bindings` is copied here"
        );
        return Ok((Vec::new(), registry.state().credential_registry_epoch));
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
    Ok((approvable, document.credential_registry_epoch))
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
    let pq_key = state_dir.join(ISSUER_PQ_KEY_FILE);
    let tls_key = state_dir.join(ISSUER_TLS_KEY_FILE);
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

fn status(state_dir: &Path) -> Result<()> {
    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
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
