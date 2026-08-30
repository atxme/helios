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
/// The gateway leaf in service, exported for the operator companion.
///
/// Public by construction, and rewritten on every campaign: the companion has
/// to verify the §5 request's continuity signature under the key that is
/// actually serving, and it holds no copy of it.
const GATEWAY_ACTIVE_CERTIFICATE_FILE: &str = "gateway-active-certificate.json";
const SERVICE_KEY_FILE: &str = "service-key.bin";
/// Private material of one delegation, addressed by its epoch.
///
/// Epoch-addressed rather than fixed: `issuer request` writes the keys of the
/// **next** delegation while the current one is still signing, and the
/// registry names the epoch that is installed. An interrupted authorization
/// therefore leaves an unreferenced pair of files and a working issuer, rather
/// than a live delegation whose keys were overwritten by a candidate nobody
/// signed.
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
        /// SHA-256 of the client `CA-TLS` in service, hex — printed by
        /// `astra-signer issue-ca-tls` and by `heliosd show-trust-enrolment`.
        ///
        /// Optional, and named rather than inferred: without it this authority
        /// pins the epoch of that anchor without pinning the anchor, and a
        /// `CA-TLS` transition can only be checked against a value the object
        /// itself carries — which checks nothing. Absent, the rotation of §9.4
        /// is refused by name until `astra pin-ca-tls` records it.
        #[arg(long)]
        ca_tls_fingerprint: Option<String>,
    },
    /// Records the client `CA-TLS` this domain serves, once (§9.4).
    ///
    /// For a domain bootstrapped before that anchor was pinned. It refuses to
    /// overwrite one already recorded: replacing a pinned anchor is a
    /// rotation, and a rotation is signed.
    PinCaTls {
        /// SHA-256 of the certificate in service, hex. Confirmed out of band.
        #[arg(long)]
        fingerprint: String,
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
    /// Drives the full certificate chain, one campaign at a time (§7.6).
    Chain {
        #[command(subcommand)]
        command: ChainCommand,
    },
    /// Opens an emergency identity revocation for the companion to sign.
    Revocation {
        #[command(subcommand)]
        command: RevocationCommand,
    },
    /// Opens a campaign about the gateway's own identity (spec §6, §11.1).
    GatewayIdentity {
        #[command(subcommand)]
        command: GatewayIdentityCommand,
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
enum ChainCommand {
    /// Resolves the chain and deposits its first campaign.
    ///
    /// # Why four campaigns and not one
    ///
    /// `full_certificate_chain` covers the issuer, the client TLS anchor, the
    /// gateway identity and the fleet's leaves — four **families** of signed
    /// object. `CampaignFamily` is total on purpose: every family refuses the
    /// other three in both directions, so no scope added later inherits an
    /// authorization by omission. A campaign carrying a *set* of families
    /// would turn each of those guards into a subset check, which is the shape
    /// that model exists to remove. So the chain is a plan of four ordinary
    /// campaigns, each with its own family and its own operator touch, and not
    /// a single wider one.
    ///
    /// §7.6 also bounds a campaign window at five minutes, so the later steps
    /// could not be resolved up front in any case: each is resolved against
    /// the registry as it stands when its turn comes.
    Open {
        /// Free text shown to the operator before every touch of this chain.
        #[arg(long)]
        reason: String,
        /// Who asked for it. Shown to the operator, and audited.
        #[arg(long)]
        requested_by: String,
        /// How long the operator has for each step, in seconds.
        #[arg(long, default_value_t = 300)]
        window_secs: u64,
        /// Where to write the delegation request of the first step.
        #[arg(long)]
        issuer_request_out: Option<PathBuf>,
    },
    /// Deposits the next campaign, once the previous one has taken effect.
    ///
    /// «Taken effect» is read from this registry, not from an approval: the
    /// plan lives in the state volume and the operations live in the running
    /// service's memory. Observing the effect is also the stronger question —
    /// a step whose approval was taken but whose object never landed has not
    /// moved the domain, and resolving the next campaign against it would
    /// freeze a state nobody reached.
    Next {
        /// Address of the gateway's private lifecycle listener, on the veth.
        ///
        /// Required only when the chain reaches its gateway-identity step:
        /// that campaign is resolved from the leaves the daemon actually
        /// serves, which this registry has never held.
        #[arg(long, env = "ASTRA_GATEWAY_CHANNEL")]
        gateway_channel: Option<SocketAddr>,
        /// The gateway's transport certificate, DER base64 — the same value
        /// `astra run` is given.
        #[arg(long, env = "ASTRA_GATEWAY_CERTIFICATE")]
        gateway_certificate: Option<String>,
        /// Where to write the delegation request, on the issuer step.
        #[arg(long)]
        issuer_request_out: Option<PathBuf>,
    },
    /// Prints where the chain stands.
    Status,
    /// Drops the plan. Campaigns already approved keep their effect.
    Abandon,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum RevocationScopeArg {
    /// This gateway's own leaves.
    Gateway,
    /// One admitted client's leaves.
    Client,
}

#[derive(Subcommand)]
enum RevocationCommand {
    /// Resolves one active identity into a short-lived signing campaign.
    Open {
        #[arg(long, value_enum)]
        scope: RevocationScopeArg,
        /// Client WireGuard public key. Required for `client`, refused for
        /// `gateway`.
        #[arg(long)]
        peer: Option<String>,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        requested_by: String,
        #[arg(long, default_value_t = 300)]
        window_secs: u64,
        /// Address of the gateway's private lifecycle listener, on the veth.
        ///
        /// Required for `--scope gateway`: this registry holds no gateway
        /// leaf, so their fingerprints and signed expiries are read from the
        /// daemon that serves them.
        #[arg(long, env = "ASTRA_GATEWAY_CHANNEL")]
        gateway_channel: Option<SocketAddr>,
        /// The gateway's transport certificate, DER base64.
        #[arg(long, env = "ASTRA_GATEWAY_CERTIFICATE")]
        gateway_certificate: Option<String>,
    },
}

#[derive(Subcommand)]
enum GatewayIdentityCommand {
    /// Freezes the gateway identity in service into a signing campaign.
    ///
    /// # Why the state is read from the gateway and not from here
    ///
    /// Astra records which generation each **client** is at; it has never held
    /// the gateway's own leaves, and §11.1 step 3 needs their exact
    /// fingerprints. They are therefore read live over the private channel,
    /// from the daemon that serves them. A value retyped by an operator would
    /// produce a campaign the companion signs and the gateway then refuses —
    /// at the one moment a renewal is already under way.
    ///
    /// # Why one command for a renewal and for an abort
    ///
    /// Both decide the same identity at the same decision epoch, so both
    /// freeze the same row. Which decision is being taken is not a property of
    /// the campaign but of the object signed under it, and the companion
    /// displays that in full before the touch. A second scope would give the
    /// gateway identity two families that each accept the other's objects.
    Open {
        #[arg(long)]
        reason: String,
        #[arg(long)]
        requested_by: String,
        #[arg(long, default_value_t = 300)]
        window_secs: u64,
        /// Address of the gateway's private lifecycle listener, on the veth.
        #[arg(long, env = "ASTRA_GATEWAY_CHANNEL")]
        gateway_channel: SocketAddr,
        /// The gateway's transport certificate, DER base64 — the same value
        /// `astra run` is given.
        #[arg(long, env = "ASTRA_GATEWAY_CERTIFICATE")]
        gateway_certificate: String,
    },
    /// Laisse partir la transition déjà signée (§11.1 étape 6).
    ///
    /// Le dernier instant où un avortement est encore légitime est *avant*
    /// cette commande. Après, un client peut détenir la décision, repartir
    /// hors ligne et promouvoir seul à `not_after` : annuler sur la seule
    /// gateway laisserait deux vérités dans le parc.
    ///
    /// Rejouable : la marque est persistée avant le relais, et une seconde
    /// exécution termine un relais que la première n'a pas pu confirmer.
    Publish {
        /// L'époque de la transition à publier.
        #[arg(long)]
        epoch: u64,
        #[arg(long, env = "ASTRA_GATEWAY_CHANNEL")]
        gateway_channel: SocketAddr,
        #[arg(long, env = "ASTRA_GATEWAY_CERTIFICATE")]
        gateway_certificate: String,
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
        /// Free text shown to the operator before the touch.
        ///
        /// With `--requested-by`, the request is also deposited as an
        /// `issuer_delegation` campaign (§7.6): the companion then fetches it
        /// over the §8.2 transport, reads the exact material it is about to
        /// certify, and deposits the delegation back here. Without the two,
        /// the request is only written to a file, and the companion signs it
        /// with nothing tying it to this authority.
        ///
        /// Not a `campaign open --scope` variant, because the target of this
        /// campaign does not exist until this command creates it: the epoch,
        /// the ML-DSA-87 key and the PKCS#10 request are produced here, beside
        /// the private halves they name.
        #[arg(long, requires = "requested_by")]
        reason: Option<String>,
        /// Who asked for it. Shown to the operator, and audited.
        #[arg(long, requires = "reason")]
        requested_by: Option<String>,
        /// How long the operator has, in seconds.
        #[arg(long, default_value_t = 300)]
        window_secs: u64,
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
            ca_tls_fingerprint,
        } => bootstrap(
            &cli.state_dir,
            &ca_public_key,
            &trust_domain_id,
            &gateway_wireguard_public_key,
            &server_name,
            &authority_url,
            &webauthn_rp_id,
            ca_tls_fingerprint.as_deref(),
        ),
        Command::PinCaTls { fingerprint } => pin_ca_tls(&cli.state_dir, &fingerprint),
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
            IssuerCommand::Request {
                out,
                reason,
                requested_by,
                window_secs,
            } => issuer_request(
                &cli.state_dir,
                out.as_deref(),
                reason.as_deref().zip(requested_by.as_deref()),
                window_secs,
            )
            .map(|_| ()),
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
        Command::Chain { command } => match command {
            ChainCommand::Open {
                reason,
                requested_by,
                window_secs,
                issuer_request_out,
            } => chain_open(
                &cli.state_dir,
                &reason,
                &requested_by,
                window_secs,
                issuer_request_out.as_deref(),
            ),
            ChainCommand::Next {
                gateway_channel,
                gateway_certificate,
                issuer_request_out,
            } => chain_next(
                &cli.state_dir,
                gateway_channel,
                gateway_certificate.as_deref(),
                issuer_request_out.as_deref(),
            ),
            ChainCommand::Status => chain_status(&cli.state_dir),
            ChainCommand::Abandon => chain_abandon(&cli.state_dir),
        },
        Command::Revocation { command } => match command {
            RevocationCommand::Open {
                scope,
                peer,
                reason,
                requested_by,
                window_secs,
                gateway_channel,
                gateway_certificate,
            } => revocation_open(
                &cli.state_dir,
                scope,
                peer.as_deref(),
                &reason,
                &requested_by,
                window_secs,
                gateway_channel,
                gateway_certificate.as_deref(),
            ),
        },
        Command::GatewayIdentity { command } => match command {
            GatewayIdentityCommand::Open {
                reason,
                requested_by,
                window_secs,
                gateway_channel,
                gateway_certificate,
            } => gateway_identity_open(
                &cli.state_dir,
                &reason,
                &requested_by,
                window_secs,
                gateway_channel,
                &gateway_certificate,
            )
            .map(|_| ()),
            GatewayIdentityCommand::Publish {
                epoch,
                gateway_channel,
                gateway_certificate,
            } => gateway_identity_publish(
                &cli.state_dir,
                epoch,
                gateway_channel,
                &gateway_certificate,
            ),
        },
        Command::Status {
            expected_audit_head,
        } => status(&cli.state_dir, expected_audit_head.as_deref()),
    }
}

#[allow(clippy::too_many_arguments)]
fn bootstrap(
    state_dir: &Path,
    ca_public_key: &str,
    trust_domain_id: &str,
    gateway_wireguard_public_key: &str,
    server_name: &str,
    authority_url: &str,
    webauthn_rp_id: &str,
    ca_tls_fingerprint: Option<&str>,
) -> Result<()> {
    let ca_tls_fingerprint = ca_tls_fingerprint
        .map(parse_fingerprint)
        .transpose()
        .context("--ca-tls-fingerprint")?;
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
        ca_rotation: None,
        ca_tls_epoch: 1,
        ca_tls_fingerprint,
        ca_tls_rotation: None,
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
/// Records the client `CA-TLS` in service, once (spec §9.4).
fn pin_ca_tls(state_dir: &Path, fingerprint: &str) -> Result<()> {
    let fingerprint = parse_fingerprint(fingerprint).context("--fingerprint")?;
    let mut registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;

    if let Some(held) = registry.state().ca_tls_fingerprint {
        if held.matches(&fingerprint) {
            eprintln!("cette ancre CA-TLS est déjà épinglée ; rien n'a changé");
            return Ok(());
        }
        anyhow::bail!(
            "another CA-TLS anchor is already pinned here. Replacing a pinned anchor is a \
             rotation, and a rotation is signed: `astra campaign open --scope trust-authorities` \
             then `astra-signer rotate-ca-tls`"
        );
    }
    registry.pin_client_tls_ca(fingerprint, now_unix())?;
    println!("{fingerprint}");
    eprintln!("ancre CA-TLS épinglée : la rotation du §9.4 est désormais vérifiable ici");
    Ok(())
}

/// Reads a SHA-256 an operator confirmed out of band.
fn parse_fingerprint(value: &str) -> Result<aether::certificates::encoding::Fingerprint> {
    aether::certificates::encoding::Fingerprint::parse_hex(value.trim())
        .map_err(|error| anyhow::anyhow!("{error}"))
}

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
        state_dir: state_dir.to_path_buf(),
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
        recoveries: Mutex::new(astra::recovery::RecoveryStore::new()),
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
/// Absent is a supported state, and the ordinary one: only a ceremony that
/// makes a master key sign needs it. Saying so at start-up beats discovering
/// it in the middle of a ceremony.
fn load_encrypted_vault(state_dir: &Path) -> Result<Option<Vec<u8>>> {
    let path = state_dir.join(VAULT_FILE);
    let Ok(metadata) = std::fs::metadata(&path) else {
        tracing::info!(
            path = %path.display(),
            "no encrypted vault in the state volume: anchor rotations and revocations are \
             refused by name; every other scope is unaffected"
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
    let pq_key = astra::issuer::pq_key_path(state_dir, installed.issuer_epoch);
    let tls_key = astra::issuer::tls_key_path(state_dir, installed.issuer_epoch);
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

/// Writes a resolved campaign and its service-signed companion request into
/// the inbox consumed by the running Astra service.
/// Freezes the gateway identity in service into a revocation campaign (§10.1).
///
/// # Why this one dials the gateway too
///
/// A client revocation resolves from this registry, which records every
/// admitted generation. The gateway's own leaves were never recorded here —
/// Astra transcribes admissions, it does not hold the identity every client
/// pins — so their fingerprints and, above all, their **signed expiries** come
/// from the daemon that serves them. §10.1 makes each expiry exact: a value
/// retyped or inferred produces an object every recipient refuses, during the
/// incident that motivated it.
fn gateway_revocation_open(
    state_dir: &Path,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
    gateway_channel: SocketAddr,
    gateway_certificate: &str,
) -> Result<()> {
    use aether::certificates::status::{
        AstraRotationCampaign, CampaignScope, CampaignTarget, CertificateKind,
    };

    if load_encrypted_vault(state_dir)?.is_none() {
        anyhow::bail!("this state volume has no encrypted vault for the companion to open");
    }
    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let state = registry.state();

    let identity = read_gateway_identity(state_dir, gateway_channel, gateway_certificate)?;
    let pq_not_after = identity.pq_certificate.not_after_unix;
    let tls_not_after = identity.tls_certificate_not_after;

    // The counter is the gateway's own axis (§4.2), and this registry does not
    // hold it either. It is the decision epoch the daemon reports, advanced by
    // one — the same rule a client revocation follows on its own axis.
    let target = CampaignTarget {
        certificate_kind: CertificateKind::GatewayPq,
        identity_key: state.gateway_wg_public_key,
        epoch: identity.gateway_decision_epoch,
        generation: identity.active_gateway_identity_epoch,
        active_tls_certificate_fingerprint: identity.tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: identity.pq_certificate_fingerprint,
    };
    let now = now_unix();
    let expires_at = now
        .checked_add(window_secs)
        .context("revocation campaign window overflow")?;
    let campaign = AstraRotationCampaign {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        campaign_id: fresh_id()?,
        trust_domain_id: state.trust_domain_id,
        gateway_wg_public_key: state.gateway_wg_public_key,
        server_name: state.server_name.clone(),
        created_at: now,
        expires_at,
        scope: CampaignScope::EmergencyRevocation,
        targets: vec![target],
        reason: reason.trim().to_string(),
        requested_by: requested_by.trim().to_string(),
        policy_fingerprint: *state.astra_policy_fingerprint.fingerprint(),
        required_credentials: CampaignScope::EmergencyRevocation.required_credentials(),
    };
    campaign.validate(now).map_err(|error| {
        anyhow::anyhow!("the resolved revocation cannot be shown to an operator: {error}")
    })?;

    let next_epoch = identity
        .gateway_decision_epoch
        .checked_add(1)
        .context("gateway revocation counter overflow")?;
    let deposit = deposit_campaign(state_dir, state, campaign, now, expires_at)?;
    let operation_id = deposit.signer_request.operation_id;
    println!("{}", operation_id.to_hex());
    eprintln!("révocation gateway déposée : compteur {next_epoch}, fenêtre de {window_secs} s");
    eprintln!(
        "feuille PQ  : {} · expire {pq_not_after}",
        identity.pq_certificate_fingerprint
    );
    eprintln!(
        "feuille TLS : {} · expire {tls_not_after}",
        identity.tls_certificate_fingerprint
    );
    eprintln!("empreinte de campagne : {}", deposit.campaign.fingerprint());
    eprintln!(
        "terminal : la gateway ne négociera plus. Signer depuis le poste opérateur :\n  \
         astra-signer revoke --scope gateway --authority-url {} --operation-id {} \
         --pq-not-after {pq_not_after} --tls-not-after {tls_not_after}",
        deposit.signer_request.authority_url,
        operation_id.to_hex()
    );
    Ok(())
}

/// Reads the identity the daemon **serves**, over the private channel.
fn read_gateway_identity(
    state_dir: &Path,
    gateway_channel: SocketAddr,
    gateway_certificate: &str,
) -> Result<helios_api::internal::GatewayIdentityView> {
    let pinned = aether::certificates::encoding::DerCertificate::parse(gateway_certificate)
        .map_err(|error| anyhow::anyhow!("--gateway-certificate: {error}"))?;
    let channel = astra::gateway::GatewayChannel::open(state_dir, gateway_channel, &pinned)
        .map_err(|error| anyhow::anyhow!("opening the private gateway channel: {error}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting a runtime for the private channel")?;
    runtime
        .block_on(channel.gateway_identity())
        .context("reading the identity the gateway serves")
}

/// Freezes the gateway identity in service into a signing campaign (§11.1 3).
fn gateway_identity_open(
    state_dir: &Path,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
    gateway_channel: SocketAddr,
    gateway_certificate: &str,
) -> Result<DepositedCampaign> {
    use aether::certificates::status::{CampaignScope, CampaignTarget, CertificateKind};

    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let state = registry.state();

    let identity = read_gateway_identity(state_dir, gateway_channel, gateway_certificate)?;

    // The daemon answers with the leaf it actually presents. A campaign built
    // from anything else would freeze a state no client has ever pinned.
    let target = CampaignTarget {
        certificate_kind: CertificateKind::GatewayPq,
        identity_key: state.gateway_wg_public_key,
        epoch: identity.gateway_decision_epoch,
        generation: identity.active_gateway_identity_epoch,
        active_tls_certificate_fingerprint: identity.tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: identity.pq_certificate_fingerprint,
    };

    // Exported because the companion cannot verify the §5 request's
    // continuity signature without the leaf in service, and it holds no copy
    // of it. Public material: the same leaf every admitted client pins.
    let served_path = state_dir.join(GATEWAY_ACTIVE_CERTIFICATE_FILE);
    std::fs::write(
        &served_path,
        serde_json::to_vec_pretty(&identity.pq_certificate)
            .context("encoding the gateway leaf in service")?,
    )
    .with_context(|| format!("writing {}", served_path.display()))?;

    let decision_epoch = identity.gateway_decision_epoch;
    let next_epoch = decision_epoch
        .checked_add(1)
        .context("gateway decision epoch overflow")?;
    let deposited = open_campaign(
        state_dir,
        state,
        CampaignScope::GatewayIdentity,
        vec![target],
        reason,
        requested_by,
        window_secs,
    )?;
    let operation_id = deposited.operation_id;
    println!("{}", operation_id.to_hex());
    eprintln!("campagne gateway déposée : décision {decision_epoch}, fenêtre de {window_secs} s");
    eprintln!(
        "feuille PQ en service : {}",
        identity.pq_certificate_fingerprint
    );
    eprintln!(
        "feuille TLS en service : {}",
        identity.tls_certificate_fingerprint
    );
    eprintln!("empreinte de campagne : {}", deposited.fingerprint);
    eprintln!("feuille en service exportée : {}", served_path.display());
    eprintln!(
        "renouveler depuis le poste opérateur (époque {next_epoch}) :\n  astra-signer \
         sign-gateway-transition --authority-url {} --operation-id {} --request <demande.json> \
         --active-certificate <{}> --out <transition.json>",
        state.authority_url,
        operation_id.to_hex(),
        GATEWAY_ACTIVE_CERTIFICATE_FILE
    );
    eprintln!(
        "ou annuler la transition déjà en attente :\n  astra-signer abort-gateway-transition \
         --authority-url {} --operation-id {} --transition <transition.json> \
         --out <avortement.json>",
        state.authority_url,
        operation_id.to_hex()
    );
    Ok(deposited)
}

/// Lets a signed transition leave the authority (spec §11.1 step 6).
fn gateway_identity_publish(
    state_dir: &Path,
    epoch: u64,
    gateway_channel: SocketAddr,
    gateway_certificate: &str,
) -> Result<()> {
    let mut registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let pinned = aether::certificates::encoding::DerCertificate::parse(gateway_certificate)
        .map_err(|error| anyhow::anyhow!("--gateway-certificate: {error}"))?;
    let channel = astra::gateway::GatewayChannel::open(state_dir, gateway_channel, &pinned)
        .map_err(|error| anyhow::anyhow!("opening the private gateway channel: {error}"))?;

    // Persisted first, and irreversibly. A marker written after the relay
    // would leave a gateway that has closed its abort window while this
    // authority still believes the decision cancellable — and §6.3 makes the
    // gateway's belief the one clients act on.
    let transition = registry
        .publish_gateway_transition(epoch, now_unix())
        .context("no unaborted gateway transition is stored at this epoch")?;
    let fingerprint = transition
        .fingerprint()
        .context("fingerprinting the published transition")?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting a runtime for the private channel")?;
    runtime
        .block_on(channel.gateway_transition_published(
            &helios_api::internal::GatewayTransitionPublished {
                gateway_identity_epoch: epoch,
                transition_fingerprint: fingerprint,
            },
        ))
        .context(
            "the publication is recorded here but the gateway did not confirm it; re-run this \
             command",
        )?;

    println!("{}", fingerprint);
    eprintln!(
        "transition publiée : époque {epoch}, activation {}",
        transition.window.activation_at
    );
    eprintln!("l'avortement n'est plus légitime ; la distribution aux clients est ouverte");
    Ok(())
}

fn deposit_campaign(
    state_dir: &Path,
    state: &astra::registry::AstraState,
    campaign: aether::certificates::status::AstraRotationCampaign,
    now: u64,
    expires_at: u64,
) -> Result<astra::signing::CampaignDeposit> {
    use aether::certificates::status::AstraSignerRequest;

    let service_private_key = Zeroizing::new(
        std::fs::read(state_dir.join(SERVICE_KEY_FILE)).context("reading the Astra service key")?,
    );
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
    std::fs::rename(&temporary, &path).with_context(|| format!("publishing {}", path.display()))?;
    Ok(deposit)
}

/// Resolves one admitted client into an emergency revocation campaign.
#[allow(clippy::too_many_arguments)]
fn revocation_open(
    state_dir: &Path,
    scope: RevocationScopeArg,
    peer: Option<&str>,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
    gateway_channel: Option<SocketAddr>,
    gateway_certificate: Option<&str>,
) -> Result<()> {
    use aether::certificates::status::{
        AstraRotationCampaign, CampaignScope, CampaignTarget, CertificateKind,
    };

    if reason.trim().is_empty() || requested_by.trim().is_empty() {
        anyhow::bail!("--reason and --requested-by are what the operator reads before the touch");
    }
    if window_secs == 0 || window_secs > 300 {
        anyhow::bail!("--window-secs must be between 1 and 300");
    }
    if scope == RevocationScopeArg::Gateway {
        anyhow::ensure!(peer.is_none(), "--peer is refused for --scope gateway");
        return gateway_revocation_open(
            state_dir,
            reason,
            requested_by,
            window_secs,
            gateway_channel.context(
                "--gateway-channel is required for --scope gateway: this registry holds no \
                 gateway leaf, and §10.1 needs the exact expiry each one carries",
            )?,
            gateway_certificate.context("--gateway-certificate is required for --scope gateway")?,
        );
    }
    let peer = peer.context("--peer is required for --scope client")?;
    let client_wg_public_key =
        WireGuardKey::parse(peer).context("reading the client's WireGuard public key")?;

    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let state = registry.state();
    let record = state
        .peers
        .get(&client_wg_public_key.to_base64())
        .context("this registry has no admitted identity for --peer")?;
    if record.revoked {
        anyhow::bail!(
            "{} is already revoked at epoch {}; revoked is terminal",
            record.name,
            record.revocation_epoch
        );
    }
    if load_encrypted_vault(state_dir)?.is_none() {
        anyhow::bail!("this state volume has no encrypted vault for the companion to open");
    }

    let target = CampaignTarget {
        certificate_kind: CertificateKind::ClientPq,
        identity_key: record.client_wg_public_key,
        epoch: record.revocation_epoch,
        generation: record.active.generation,
        active_tls_certificate_fingerprint: record.active.tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: record.active.pq_certificate_fingerprint,
    };
    let now = now_unix();
    let expires_at = now
        .checked_add(window_secs)
        .context("revocation campaign window overflow")?;
    let campaign = AstraRotationCampaign {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        campaign_id: fresh_id()?,
        trust_domain_id: state.trust_domain_id,
        gateway_wg_public_key: state.gateway_wg_public_key,
        server_name: state.server_name.clone(),
        created_at: now,
        expires_at,
        scope: CampaignScope::EmergencyRevocation,
        targets: vec![target],
        reason: reason.trim().to_string(),
        requested_by: requested_by.trim().to_string(),
        policy_fingerprint: *state.astra_policy_fingerprint.fingerprint(),
        required_credentials: CampaignScope::EmergencyRevocation.required_credentials(),
    };
    campaign.validate(now).map_err(|error| {
        anyhow::anyhow!("the resolved revocation cannot be shown to an operator: {error}")
    })?;

    let peer_name = record.name.clone();
    let generation = record.active.generation;
    let not_after = record.active.not_after;
    let next_epoch = record
        .revocation_epoch
        .checked_add(1)
        .context("revocation counter overflow")?;
    let deposit = deposit_campaign(state_dir, state, campaign, now, expires_at)?;
    let operation_id = deposit.signer_request.operation_id;
    println!("{}", operation_id.to_hex());
    eprintln!(
        "révocation déposée : {peer_name}, génération {generation}, compteur {next_epoch}, fenêtre de {window_secs} s"
    );
    eprintln!("empreinte de campagne : {}", deposit.campaign.fingerprint());
    eprintln!(
        "signer depuis le poste opérateur :\n  astra-signer revoke --authority-url {} \
         --operation-id {} --not-after {not_after}",
        deposit.signer_request.authority_url,
        operation_id.to_hex()
    );
    Ok(())
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
    use aether::certificates::status::{CampaignScope, CampaignTarget, CertificateKind};

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
            let mut targets = vec![CampaignTarget {
                certificate_kind: CertificateKind::CaPq,
                identity_key: state.gateway_wg_public_key,
                epoch: state.ca_epoch,
                generation: state.ca_epoch,
                active_tls_certificate_fingerprint: anchor,
                active_pq_certificate_fingerprint: anchor,
            }];
            // The client TLS anchor is a second row, not a second campaign:
            // §7.6 puts both under `trust_authorities`, and the companion
            // signs whichever the ceremony is for. A domain that never pinned
            // that anchor simply offers no row for it — the rotation is then
            // refused where the pin is missing, not here.
            if let Some(row) = client_tls_ca_row(state) {
                targets.push(row);
            }
            targets
        }
        _ => fleet_leaf_rows(state),
    };
    if targets.is_empty() {
        anyhow::bail!(
            "no admitted peer in this registry: there is nothing for an operator to approve"
        );
    }

    let deposited = open_campaign(
        state_dir,
        state,
        scope,
        targets,
        reason,
        requested_by,
        window_secs,
    )?;

    println!("{}", deposited.operation_id.to_hex());
    eprintln!(
        "campagne déposée : {} credential(s), fenêtre de {window_secs} s",
        scope.required_credentials()
    );
    eprintln!("empreinte de campagne : {}", deposited.fingerprint);
    eprintln!(
        "approuver depuis le poste opérateur :\n  astra-signer approve-campaign \\\n    \
         --authority-url {} \\\n    --operation-id {}",
        state.authority_url,
        deposited.operation_id.to_hex()
    );
    Ok(())
}

/// The client `CA-TLS` row, when this domain pins that anchor at all.
///
/// Shared between `campaign open --scope trust-authorities`, which offers it
/// beside `CA-PQ`, and the chain of §7.6, which offers it **alone** — the
/// chain covers «émetteur, CA TLS, gateway et leafs clientes, mais pas
/// `CA-PQ`», and leaving the anchor row out is what carries that exclusion:
/// `covers_authority_object` matches on the certificate kind, so a campaign
/// with no `CA-PQ` row refuses a `CA-PQ` transition by construction rather
/// than by a check somebody has to remember.
fn client_tls_ca_row(
    state: &astra::registry::AstraState,
) -> Option<aether::certificates::status::CampaignTarget> {
    use aether::certificates::status::{CampaignTarget, CertificateKind};
    state
        .ca_tls_fingerprint
        .map(|client_tls_ca| CampaignTarget {
            certificate_kind: CertificateKind::CaTls,
            identity_key: state.gateway_wg_public_key,
            epoch: state.ca_tls_epoch,
            generation: state.ca_tls_epoch,
            active_tls_certificate_fingerprint: client_tls_ca,
            active_pq_certificate_fingerprint: client_tls_ca,
        })
}

/// One row per admitted peer, pinned to the generation it is actually at.
///
/// A revoked peer is not a target. `revoked` is terminal — no credential lifts
/// it — so including one would put an object in the campaign that every
/// downstream step must then refuse, and would make the count the operator
/// reads on their screen wrong.
fn fleet_leaf_rows(
    state: &astra::registry::AstraState,
) -> Vec<aether::certificates::status::CampaignTarget> {
    use aether::certificates::status::{CampaignTarget, CertificateKind};
    state
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
        .collect()
}

fn issuer_request(
    state_dir: &Path,
    out: Option<&Path>,
    campaign: Option<(&str, &str)>,
    window_secs: u64,
) -> Result<Option<DepositedCampaign>> {
    use base64::Engine as _;

    if campaign.is_some() && (window_secs == 0 || window_secs > 300) {
        anyhow::bail!("--window-secs must be between 1 and 300");
    }

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
        &astra::issuer::pq_key_path(state_dir, issuer_epoch),
        &pq_private_key,
    )
    .context("sealing the delegated issuer ML-DSA-87 key")?;
    aether::private_file::write_private_atomic(
        &astra::issuer::tls_key_path(state_dir, issuer_epoch),
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

    let deposited = match campaign {
        Some((reason, requested_by)) => {
            let deposited = deposit_issuer_campaign(
                state_dir,
                state,
                &request,
                reason,
                requested_by,
                window_secs,
            )?;
            eprintln!(
                "sign it from the operator machine:\n  astra-signer authorize-issuer \\\n    \
                 --authority-url {} \\\n    --operation-id {}",
                state.authority_url,
                deposited.operation_id.to_hex()
            );
            eprintln!(
                "the delegation is recorded here as soon as the companion deposits it; restart \
                 Astra to issue under it"
            );
            Some(deposited)
        }
        None => {
            eprintln!(
            "hors campagne      : `astra-signer authorize-issuer --request <file> --out <file>`, \
             puis `astra issuer install`. Rien ne rattache alors cette demande à cette autorité : \
             l'opérateur signe le fichier qu'on lui présente. Passer --reason et --requested-by \
             pour la cérémonie du §8.2."
            );
            None
        }
    };
    // On standard output, alone, so a deployment script can pipe it out of the
    // container without a shared volume.
    println!("{}", String::from_utf8_lossy(&encoded));
    Ok(deposited)
}

/// What a resolved campaign left for the running service to adopt.
#[derive(Debug, Clone, Copy)]
struct DepositedCampaign {
    operation_id: aether::certificates::encoding::Id16,
    campaign_id: aether::certificates::encoding::Id16,
    fingerprint: Fingerprint,
}

/// Builds one campaign over targets a caller resolved, and deposits it.
///
/// The targets are the caller's business, because each scope reads a different
/// source: the fleet from this registry, the gateway from the daemon that
/// serves it, the delegation from the request that was just produced. What is
/// the same for all of them — the window bound of §7.6, the vault the
/// companion must be able to open, the policy pin, the structural validation
/// and the deposit itself — lives here, so that a scope added later cannot
/// acquire its own version of any of it.
fn open_campaign(
    state_dir: &Path,
    state: &astra::registry::AstraState,
    scope: aether::certificates::status::CampaignScope,
    targets: Vec<aether::certificates::status::CampaignTarget>,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
) -> Result<DepositedCampaign> {
    use aether::certificates::status::{AstraRotationCampaign, MAX_CAMPAIGN_TARGETS};

    if reason.trim().is_empty() || requested_by.trim().is_empty() {
        anyhow::bail!("--reason and --requested-by are what the operator reads before the touch");
    }
    // The specification bounds the campaign window at five minutes: the
    // approval is a challenge, and a challenge with a long life is a challenge
    // worth capturing.
    if window_secs == 0 || window_secs > 300 {
        anyhow::bail!("--window-secs must be between 1 and 300");
    }
    if targets.is_empty() {
        anyhow::bail!(
            "this campaign resolves to no target: there is nothing for an operator to approve"
        );
    }
    if targets.len() > MAX_CAMPAIGN_TARGETS {
        anyhow::bail!(
            "{} targets, over the {MAX_CAMPAIGN_TARGETS} ceiling of §8.2",
            targets.len()
        );
    }
    if scope.opens_vault() && load_encrypted_vault(state_dir)?.is_none() {
        // The companion needs the vault to open `CA-PQ`, and it fetches it
        // from here. Opening the campaign anyway would spend an operator's
        // window on a ceremony that cannot reach a private key.
        anyhow::bail!(
            "this state volume holds no encrypted vault: this campaign has nothing for the \
             companion to open, and `CA-PQ` would never sign"
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

    let campaign_id = campaign.campaign_id;
    let deposit = deposit_campaign(state_dir, state, campaign, now, expires_at)?;
    Ok(DepositedCampaign {
        operation_id: deposit.signer_request.operation_id,
        campaign_id,
        fingerprint: deposit.campaign.fingerprint(),
    })
}

fn chain_plan_path(state_dir: &Path) -> PathBuf {
    state_dir.join(astra::chain::CHAIN_PLAN_FILE)
}

fn load_chain_plan(state_dir: &Path) -> Result<astra::chain::ChainPlan> {
    let path = chain_plan_path(state_dir);
    let raw = std::fs::read(&path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => anyhow::anyhow!(
            "no certificate chain is open in {}: `astra chain open` starts one",
            state_dir.display()
        ),
        _ => anyhow::Error::new(error).context(format!("reading {}", path.display())),
    })?;
    let plan: astra::chain::ChainPlan =
        serde_json::from_slice(&raw).with_context(|| format!("decoding {}", path.display()))?;
    plan.validate()?;
    Ok(plan)
}

/// Writes the plan where a crash leaves either the old one or the new one.
///
/// The plan is what keeps the four campaigns in order, so a half-written file
/// would leave the chain unable to say which step it is on — and the next
/// command would resolve a campaign against a domain it cannot describe.
fn save_chain_plan(state_dir: &Path, plan: &astra::chain::ChainPlan) -> Result<()> {
    let path = chain_plan_path(state_dir);
    let temporary = path.with_extension("tmp");
    std::fs::write(
        &temporary,
        serde_json::to_vec_pretty(plan).context("encoding the certificate chain plan")?,
    )
    .with_context(|| format!("writing {}", temporary.display()))?;
    std::fs::rename(&temporary, &path).with_context(|| format!("publishing {}", path.display()))
}

/// Deposits the campaign of the step the plan currently points at.
fn chain_deposit_current(
    state_dir: &Path,
    plan: &mut astra::chain::ChainPlan,
    gateway_channel: Option<SocketAddr>,
    gateway_certificate: Option<&str>,
    issuer_request_out: Option<&Path>,
) -> Result<()> {
    use aether::certificates::status::CampaignScope;

    let Some(step) = plan.pending() else {
        return Err(astra::chain::ChainError::Finished.into());
    };
    let scope = step.scope;
    let (reason, requested_by, window_secs) = (
        plan.reason.clone(),
        plan.requested_by.clone(),
        plan.window_secs,
    );

    let deposited = match scope {
        // The delegation's target does not exist until this call creates it:
        // the epoch, the ML-DSA-87 key and the PKCS#10 request are produced
        // here, beside the private halves they name.
        CampaignScope::IssuerDelegation => issuer_request(
            state_dir,
            issuer_request_out,
            Some((reason.as_str(), requested_by.as_str())),
            window_secs,
        )?
        .context("the issuer step deposited no campaign")?,
        // Read live from the daemon that serves the leaves: this registry has
        // never held them, and a retyped value would produce a campaign the
        // companion signs and the gateway then refuses.
        CampaignScope::GatewayIdentity => {
            let channel = gateway_channel.context(
                "--gateway-channel is required for the gateway identity step: the campaign is \
                 resolved from the leaves the daemon actually serves",
            )?;
            let certificate = gateway_certificate
                .context("--gateway-certificate is required for the gateway identity step")?;
            gateway_identity_open(
                state_dir,
                &reason,
                &requested_by,
                window_secs,
                channel,
                certificate,
            )?
        }
        scope => {
            let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
                .context("loading the Astra registry")?;
            let state = registry.state();
            let targets = match scope {
                // The chain covers the client TLS anchor and **not** `CA-PQ`
                // (§7.6). Leaving the `CA-PQ` row out is what carries that
                // exclusion: `covers_authority_object` matches on the
                // certificate kind, so this campaign refuses a `CA-PQ`
                // transition by construction.
                CampaignScope::TrustAuthorities => {
                    client_tls_ca_row(state).map(|row| vec![row]).context(
                        "this domain pins no client TLS anchor: `astra pin-ca-tls` records it \
                         once, and a rotation cannot be checked without it",
                    )?
                }
                _ => fleet_leaf_rows(state),
            };
            if targets.is_empty() {
                anyhow::bail!(
                    "no admitted peer in this registry: the fleet step has nothing for an \
                     operator to approve"
                );
            }
            let deposited = open_campaign(
                state_dir,
                state,
                scope,
                targets,
                &reason,
                &requested_by,
                window_secs,
            )?;
            println!("{}", deposited.operation_id.to_hex());
            eprintln!("empreinte de campagne : {}", deposited.fingerprint);
            eprintln!(
                "approuver depuis le poste opérateur :\n  astra-signer approve-campaign \\\n    \
                 --authority-url {} \\\n    --operation-id {}",
                state.authority_url,
                deposited.operation_id.to_hex()
            );
            deposited
        }
    };

    plan.record_deposit(
        deposited.operation_id,
        deposited.campaign_id,
        deposited.fingerprint,
        now_unix(),
    )?;
    save_chain_plan(state_dir, plan)
}

fn print_chain_plan(plan: &astra::chain::ChainPlan) {
    eprintln!("chaîne           : {}", plan.chain_id.to_hex());
    eprintln!("motif            : {}", plan.reason);
    eprintln!("demandée par     : {}", plan.requested_by);
    for (index, step) in plan.steps.iter().enumerate() {
        let mark = match index.cmp(&plan.current) {
            std::cmp::Ordering::Less => "fait",
            std::cmp::Ordering::Equal => "en cours",
            std::cmp::Ordering::Greater => "à venir",
        };
        eprintln!(
            "  {}. {:<26} {:<9} {} credential(s){}",
            index + 1,
            step.label(),
            mark,
            step.scope.required_credentials(),
            match step.operation_id {
                Some(id) => format!(" — opération {}", id.to_hex()),
                None => String::new(),
            }
        );
    }
}

fn chain_open(
    state_dir: &Path,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
    issuer_request_out: Option<&Path>,
) -> Result<()> {
    let path = chain_plan_path(state_dir);
    if path.exists() {
        let existing = load_chain_plan(state_dir)?;
        anyhow::bail!(
            "a certificate chain is already open in {} with {} step(s) left: finish it with \
             `astra chain next`, or drop it with `astra chain abandon`",
            state_dir.display(),
            existing.remaining()
        );
    }

    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let mut plan = astra::chain::ChainPlan::resolve(
        fresh_id()?,
        registry.state(),
        reason.trim().to_string(),
        requested_by.trim().to_string(),
        window_secs,
        now_unix(),
    );
    drop(registry);

    chain_deposit_current(state_dir, &mut plan, None, None, issuer_request_out)?;
    eprintln!(
        "chaîne ouverte : quatre campagnes, quatre touchers. `astra chain next` dépose la \
         suivante une fois celle-ci prise en compte."
    );
    print_chain_plan(&plan);
    Ok(())
}

fn chain_next(
    state_dir: &Path,
    gateway_channel: Option<SocketAddr>,
    gateway_certificate: Option<&str>,
    issuer_request_out: Option<&Path>,
) -> Result<()> {
    let mut plan = load_chain_plan(state_dir)?;
    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    plan.assert_current_landed(registry.state())?;
    drop(registry);

    plan.advance();
    if plan.pending().is_none() {
        std::fs::remove_file(chain_plan_path(state_dir))
            .with_context(|| format!("removing {}", chain_plan_path(state_dir).display()))?;
        eprintln!(
            "chaîne terminée. La dernière étape autorise des rotations clientes : chaque pair la \
             dépense en revenant, dans la fenêtre de campagne, et l'autorité ne l'observe pas."
        );
        return Ok(());
    }
    save_chain_plan(state_dir, &plan)?;
    chain_deposit_current(
        state_dir,
        &mut plan,
        gateway_channel,
        gateway_certificate,
        issuer_request_out,
    )?;
    print_chain_plan(&plan);
    Ok(())
}

fn chain_status(state_dir: &Path) -> Result<()> {
    let plan = load_chain_plan(state_dir)?;
    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    print_chain_plan(&plan);
    match plan.assert_current_landed(registry.state()) {
        Ok(()) => eprintln!("étape en cours   : prête pour `astra chain next`"),
        Err(error) => eprintln!("étape en cours   : {error}"),
    }
    Ok(())
}

fn chain_abandon(state_dir: &Path) -> Result<()> {
    let plan = load_chain_plan(state_dir)?;
    std::fs::remove_file(chain_plan_path(state_dir))
        .with_context(|| format!("removing {}", chain_plan_path(state_dir).display()))?;
    eprintln!(
        "chaîne {} abandonnée après {} étape(s). Ce qui a déjà été approuvé garde son effet : \
         une campagne dépensée ne se reprend pas.",
        plan.chain_id.to_hex(),
        plan.current
    );
    Ok(())
}

/// Resolves one delegation request into a signing campaign and deposits it.
///
/// The campaign pins the **exact material** that will be certified: the
/// epoch, the ML-DSA-87 public key, and the `SubjectPublicKeyInfo` the PKCS#10
/// request proved possession of. That is what the operator reads before the
/// touch, and what refuses a substituted request afterwards — the request
/// itself carries no signature, so nothing else could.
fn deposit_issuer_campaign(
    state_dir: &Path,
    state: &astra::registry::AstraState,
    request: &astra::issuer::IssuerDelegationRequest,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
) -> Result<DepositedCampaign> {
    use aether::certificates::status::{CampaignScope, CampaignTarget, CertificateKind};
    use base64::Engine as _;

    let csr = aether::certificates::encoding::DerCertificate::new(
        base64::engine::general_purpose::STANDARD
            .decode(request.tls_intermediate_csr.trim())
            .context("decoding the intermediate request")?,
    )
    .context("reading the intermediate request")?;
    let public_key_info =
        aether::certificates::x509::certification_request_public_key_info(&csr)
            .context("reading the public key the intermediate request proves possession of")?;
    let pq_issuer_public_key = aether::certificates::encoding::MlDsa87PublicKey::parse(
        request.pq_issuer_public_key.trim(),
    )
    .context("reading the delegated issuer's ML-DSA-87 key")?;

    let deposited = open_campaign(
        state_dir,
        state,
        CampaignScope::IssuerDelegation,
        vec![CampaignTarget {
            certificate_kind: CertificateKind::AstraIssuer,
            identity_key: state.gateway_wg_public_key,
            epoch: request.issuer_epoch,
            generation: request.issuer_epoch,
            active_tls_certificate_fingerprint: Fingerprint::of(&public_key_info),
            active_pq_certificate_fingerprint: Fingerprint::of(pq_issuer_public_key.as_bytes()),
        }],
        reason,
        requested_by,
        window_secs,
    )?;
    // Standard error, unlike `campaign open`: on this command standard output
    // already belongs to the delegation request, which a deployment script
    // pipes out of the container. Two things there would give the script
    // neither.
    eprintln!("operation         : {}", deposited.operation_id.to_hex());
    eprintln!("empreinte de campagne : {}", deposited.fingerprint);
    Ok(deposited)
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
    let not_after = authorization.not_after;
    let issuer_epoch = authorization.issuer_epoch;
    astra::issuer::adopt(
        &mut registry,
        authorization,
        &astra::issuer::pq_key_path(state_dir, issuer_epoch),
        &astra::issuer::tls_key_path(state_dir, issuer_epoch),
        now,
    )
    .with_context(|| {
        format!(
            "installing the delegation of issuer epoch {issuer_epoch} from {}",
            state_dir.display()
        )
    })?;

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
