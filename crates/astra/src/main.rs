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
    /// Serves the public endpoint.
    Run {
        #[arg(long, default_value = "127.0.0.1:8443")]
        bind: SocketAddr,
        /// Head of the audit chain recorded by the operator. Given, a restore
        /// that forked away from it is refused instead of continued.
        #[arg(long)]
        expected_audit_head: Option<String>,
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
        Command::Run {
            bind,
            expected_audit_head,
        } => run(&cli.state_dir, bind, expected_audit_head.as_deref()),
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

    // The service key is Astra's own voice — it signs statuses and operation
    // receipts. It is not an issuer and it certifies nothing.
    let (service_private_key, service_public_key) =
        generate_ml_dsa_87_keypair().context("generating the Astra service key")?;
    aether::private_file::write_private_atomic(
        &state_dir.join(SERVICE_KEY_FILE),
        &service_private_key,
    )
    .context("sealing the Astra service key")?;

    let state = AstraState {
        trust_domain_id,
        gateway_wg_public_key,
        server_name: server_name.to_string(),
        authority_url: authority_url.to_string(),
        webauthn_rp_id: webauthn_rp_id.to_string(),
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

    println!("registry: {}", registry_path.display());
    println!(
        "service key: {}",
        service_public_key.authority_fingerprint()
    );
    println!("audit head: {}", registry.audit_head());
    println!(
        "record the audit head above: a restore that ends elsewhere is a fork, and `astra run \
         --expected-audit-head` is what refuses it"
    );
    Ok(())
}

fn run(state_dir: &Path, bind: SocketAddr, expected_audit_head: Option<&str>) -> Result<()> {
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
    let service = Arc::new(AstraService {
        registry: Mutex::new(registry),
        issuer,
        challenges: Mutex::new(ChallengeStore::with_capacity(MAX_LIVE_CHALLENGES)),
        budgets: Mutex::new(SourceBudget::default()),
        service_private_key,
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the Astra runtime")?;
    runtime.block_on(async move {
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
    tracing::info!(
        issuer_epoch = installed.issuer_epoch,
        not_after = installed.authorization.not_after,
        "delegated issuer loaded"
    );
    Ok(Some(DelegatedIssuer::new(
        installed.authorization.clone(),
        pq_private_key,
        tls_private_key,
    )))
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
