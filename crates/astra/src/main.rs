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

mod campaign_deposit;
mod commands;
mod daemon;
mod private_channel;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::commands::{
    bootstrap, campaign_open, chain_abandon, chain_next, chain_open, chain_status,
    gateway_identity_open, gateway_identity_publish, issuer_install, issuer_request, pin_ca_tls,
    revocation_open, status,
};
use crate::daemon::run;
use crate::private_channel::init_channel;

const DEFAULT_STATE_DIR: &str = "/var/lib/astra";
pub(crate) const REGISTRY_FILE: &str = "registry.json";
pub(crate) const SERVICE_KEY_FILE: &str = "service-key.bin";

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
pub(crate) enum CampaignScopeArg {
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
pub(crate) enum RevocationScopeArg {
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
    astra_channel::install_process_default_provider();

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

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}
