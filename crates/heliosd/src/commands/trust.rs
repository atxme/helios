//! The certificate registry, edited with the daemon stopped.
//!
//! Creating the trust domain, preparing and installing the documents an
//! operator ceremony signs, rotating the anchors, and reading a peer's
//! enrolment block back out. Every function here opens the registry file
//! itself, which is why each one says it is for a stopped daemon.

use std::path::Path;

use aether::certificates::encoding::WireGuardKey;
use aether::key_negotiation::{encode_enrolment_export_file, EnrollmentExport, PqCertificate};
use aether::{NetworkConfig, WgPeer};
use anyhow::Context;
use helios_provisioning::certificates::CertificateRegistry;
use helios_tpm::TpmSettings;
use tracing::{info, warn};

use crate::commands::tpm::unlock_tpm_for_offline_command;
use crate::{certificates, gateway_rotation, key_negotiation};

/// Prepares the next gateway identity and prints where its request landed.
pub(crate) fn prepare_gateway_certificate(
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

pub(crate) fn install_gateway_transition(source: &Path) -> anyhow::Result<()> {
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

pub(crate) fn abort_gateway_transition(source: &Path) -> anyhow::Result<()> {
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

pub(crate) fn install_ca_transition(source: &Path) -> anyhow::Result<()> {
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
pub(crate) fn install_astra_credentials(source: &Path) -> anyhow::Result<()> {
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
pub(crate) fn install_astra_issuer(source: &Path) -> anyhow::Result<()> {
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

pub(crate) fn install_client_tls_ca(source: &Path) -> anyhow::Result<()> {
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

/// Writes the public file an Orion enrolment is signed from, for a first
/// administrator whose workstation has no tunnel yet.
///
/// The same values the online routes serve, read from the same files and the
/// same registry: `GET /api/key-negotiation`, the network view and the §19
/// trust block of the peer. Printed on stdout and nothing else, so it can be
/// captured into a file. Public material only.
pub(crate) fn export_enrolment(public_key: &str) -> anyhow::Result<()> {
    let network = NetworkConfig::load().context("loading the network config")?;
    admitted_in_network(&network, public_key)?;
    let material = key_negotiation::public_material()?.ok_or_else(|| {
        anyhow::anyhow!(
            "this gateway has no key-negotiation material — run `heliosd init-key-negotiation`"
        )
    })?;
    let registry = load_trust_domain(&CertificateRegistry::path())?;
    let export = enrolment_export(
        &network,
        &material.certificate_der,
        &material.pq_certificate_json,
        &registry,
        public_key,
    )?;
    println!("{}", encode_enrolment_export_file(&export));
    Ok(())
}

/// Builds the export of one admitted peer from values already read.
///
/// Pure: no file is opened here, so every refusal is testable on its own. The
/// gateway's identity is read out of the PQ leaf on disk, never retyped, and
/// the leaf must name the WireGuard identity the sealed key derives to —
/// otherwise every client would pin a certificate that cannot be served.
pub(crate) fn enrolment_export(
    network: &NetworkConfig,
    certificate_der: &[u8],
    pq_certificate_json: &[u8],
    registry: &CertificateRegistry,
    public_key: &str,
) -> anyhow::Result<EnrollmentExport> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let peer = admitted_in_network(network, public_key)?;
    let trust = trust_enrolment_view(registry, public_key)?;
    let leaf: PqCertificate = serde_json::from_slice(pq_certificate_json)
        .map_err(|_| anyhow::anyhow!("the gateway PQ certificate on disk is unreadable"))?;
    let fingerprint = leaf
        .fingerprint()
        .map_err(|_| anyhow::anyhow!("the gateway PQ certificate cannot be fingerprinted"))?;
    let private = network.wg_private_key.expose();
    if !private.is_empty() {
        if let Ok(public) = aether::wg::public_from_private(private) {
            if public != leaf.wireguard_public_key.trim() {
                anyhow::bail!(
                    "the negotiation certificate is bound to another WireGuard identity — run \
                     `heliosd init-key-negotiation --rotate`"
                );
            }
        }
    }
    Ok(EnrollmentExport {
        server_name: leaf.subject.clone(),
        gateway_ca_der: STANDARD.encode(certificate_der),
        gateway_pq_certificate: STANDARD.encode(pq_certificate_json),
        pq_certificate_sha256: fingerprint,
        wireguard_public_key: leaf.wireguard_public_key.clone(),
        negotiation_port: network.key_negotiation_port,
        gateway_wg_address: network.wg_address.clone(),
        peer_public_key: peer.public_key.clone(),
        address: peer.address.clone(),
        address_v6: peer.address_v6.map(aether::net::format_vip_v6),
        trust: serde_json::to_value(&trust).context("encoding the trust block")?,
    })
}

fn parse_wireguard_key(public_key: &str) -> anyhow::Result<WireGuardKey> {
    WireGuardKey::parse(public_key.trim())
        .map_err(|error| anyhow::anyhow!("invalid WireGuard public key: {error}"))
}

/// The peer as `network.toml` admits it, the first refusal of an export.
fn admitted_in_network<'a>(
    network: &'a NetworkConfig,
    public_key: &str,
) -> anyhow::Result<&'a WgPeer> {
    let key = parse_wireguard_key(public_key)?;
    network
        .peers
        .iter()
        .find(|peer| peer.public_key.trim() == key.to_base64())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no such peer in network.toml — admit it first, with `heliosd peer add`"
            )
        })
}

fn load_trust_domain(path: &Path) -> anyhow::Result<CertificateRegistry> {
    CertificateRegistry::load(path)
        .with_context(|| format!("reading {}", path.display()))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "this gateway has no trust domain: run `heliosd init-trust-domain` first. An \
                 absent registry is not an empty one — the lifecycle routes stay closed."
            )
        })
}

fn trust_enrolment_view(
    registry: &CertificateRegistry,
    public_key: &str,
) -> anyhow::Result<helios_api::certificates::TrustEnrolmentView> {
    let key = parse_wireguard_key(public_key)?;
    let peer = registry.peer(&key).ok_or_else(|| {
        anyhow::anyhow!(
            "no such peer in the certificate registry — admit it first, with `heliosd peer add` \
             or `helios peer add`"
        )
    })?;
    Ok(certificates::enrolment_view(registry.state(), peer))
}

/// The client `CA-TLS` a fresh registry records as generation 1.
///
/// The domain's own anchor when the deployment supplies it, and the operator
/// admission CA otherwise. The fallback exists because a domain may be
/// bootstrapped before the domain's CA-TLS is issued in Orion, but it is never
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
pub(crate) fn repair_client_tls_ca_bootstrap(
    client_tls_ca: &std::path::Path,
) -> anyhow::Result<()> {
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
/// their machine inside Orion, and the Astra service key inside the
/// container. Neither is derivable here, and confirming them out of band is
/// the point (ADR-008 §3).
pub(crate) fn init_trust_domain(
    trust_domain_id: &str,
    ca_public_key: &str,
    gateway_certificate: &std::path::Path,
    astra_service_public_key: &str,
    authority_url: &str,
    webauthn_rp_id: &str,
    client_tls_ca: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use aether::certificates::encoding::{MlDsa87PublicKey, TrustDomainId};
    use helios_provisioning::certificates::CertificateRegistry;

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
    let state = initial_trust_domain_state(
        trust_domain_id,
        ca_public_key.clone(),
        astra_service_public_key,
        ServedIdentityMaterials {
            tls_certificate: served.tls_certificate,
            pq_certificate: served.pq_certificate,
            client_tls_ca: served.client_tls_ca,
        },
        authority_url,
        webauthn_rp_id,
        client_tls_ca,
    )?;
    let server_name = state.gateway.server_name.clone();

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

struct ServedIdentityMaterials {
    tls_certificate: aether::certificates::encoding::DerCertificate,
    pq_certificate: aether::key_negotiation::PqCertificate,
    client_tls_ca: aether::certificates::encoding::DerCertificate,
}

fn initial_trust_domain_state(
    trust_domain_id: aether::certificates::encoding::TrustDomainId,
    ca_public_key: aether::certificates::encoding::MlDsa87PublicKey,
    astra_service_public_key: aether::certificates::encoding::MlDsa87PublicKey,
    served: ServedIdentityMaterials,
    authority_url: &str,
    webauthn_rp_id: &str,
    client_tls_ca: Option<&std::path::Path>,
) -> anyhow::Result<helios_provisioning::certificates::RegistryState> {
    use aether::certificates::encoding::WireGuardKey;
    use aether::certificates::state::{
        AstraProfile, ClientTlsCaState, GatewayCertificateState, TrustLedger,
    };
    use helios_provisioning::certificates::RegistryState;

    let ServedIdentityMaterials {
        tls_certificate,
        pq_certificate,
        client_tls_ca: served_client_tls_ca,
    } = served;
    let gateway_wg_public_key = WireGuardKey::parse(&pq_certificate.wireguard_public_key)
        .context("reading the WireGuard identity out of the served PQ leaf")?;
    let server_name = pq_certificate.subject.clone();
    let astra_policy_fingerprint = aether::certificates::AstraIssuancePolicy::standard(
        trust_domain_id,
        gateway_wg_public_key,
        server_name.clone(),
    )
    .pin()
    .context("building the pinned Astra issuance policy")?;
    let domain_client_tls_ca = domain_client_tls_ca(client_tls_ca, served_client_tls_ca)?;

    Ok(RegistryState {
        trust_domain_id,
        gateway: GatewayCertificateState {
            trust_domain_id,
            gateway_wg_public_key,
            server_name,
            ca_epoch: 1,
            current_ca_public_key: ca_public_key,
            next_ca_public_key: None,
            next_ca_transition_fingerprint: None,
            ca_activation_at: None,
            ca_retire_active_at: None,
            active_gateway_identity_epoch: 1,
            gateway_decision_epoch: 1,
            next_gateway_identity_epoch: None,
            next_transition_fingerprint: None,
            last_aborted_transition: None,
            active_gateway_tls_certificate: tls_certificate,
            next_gateway_tls_certificate: None,
            active_gateway_certificate: pq_certificate,
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
            astra_service_key_epoch: 1,
            active_astra_service_public_key: astra_service_public_key,
            next_astra_service_public_key: None,
            next_service_key_transition_fingerprint: None,
            service_key_activation_at: None,
            service_key_retire_active_at: None,
            service_key_revocation_epoch: 0,
            last_emergency_replacement_fingerprint: None,
        },
        issuer: None,
        // Peers enter through admission, when their certificate fingerprints
        // and signed leaves can be recorded together.
        peers: Default::default(),
        ledger: TrustLedger::default(),
    })
}

#[cfg(test)]
mod trust_domain_seeding_tests {
    use super::{
        domain_client_tls_ca, enrolment_export, initial_trust_domain_state, load_trust_domain,
        trust_enrolment_view,
    };
    use crate::certificates::enrolment_view;
    use aether::certificates::client::ClientCertificateGeneration;
    use aether::certificates::encoding::{
        generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, TrustDomainId, WireGuardKey,
    };
    use aether::certificates::state::ClientCertificateState;
    use aether::key_negotiation::{decode_enrolment_export_file, encode_enrolment_export_file};
    use helios_provisioning::certificates::{CertificateRegistry, PeerCertificates};

    const AUTHORITY_URL: &str = "https://astra.example";
    const RP_ID: &str = "astra.example";

    fn certificate(byte: u8) -> DerCertificate {
        DerCertificate::new(vec![0x30, 0x03, 0x02, 0x01, byte]).expect("certificate")
    }

    fn gateway_identity(wg_public_key: &str) -> super::ServedIdentityMaterials {
        use aether::key_negotiation::{issue_pq_certificate, PqCertificate, PqCertificateRole};
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let (ca_private, _) = generate_ml_dsa_87_keypair().expect("CA keypair");
        let (_, subject_public) = generate_ml_dsa_87_keypair().expect("leaf keypair");
        let pq_certificate = issue_pq_certificate(
            PqCertificate {
                version: aether::key_negotiation::PQ_CERTIFICATE_VERSION,
                serial: [1; 16],
                subject: "gateway.example".into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Gateway,
                wireguard_public_key: wg_public_key.into(),
                ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
                not_before_unix: 0,
                not_after_unix: 1_000_000,
                ml_dsa_87_signature: String::new(),
            },
            &ca_private,
        )
        .expect("issue gateway leaf");
        super::ServedIdentityMaterials {
            tls_certificate: certificate(2),
            pq_certificate,
            client_tls_ca: certificate(1),
        }
    }

    fn initial_state(
        served: super::ServedIdentityMaterials,
    ) -> helios_provisioning::certificates::RegistryState {
        let (_, ca_public) = generate_ml_dsa_87_keypair().expect("CA keypair");
        let (_, service_public) = generate_ml_dsa_87_keypair().expect("service keypair");
        initial_trust_domain_state(
            TrustDomainId::new([8; 16]).expect("trust domain"),
            ca_public,
            service_public,
            served,
            AUTHORITY_URL,
            RP_ID,
            None,
        )
        .expect("initial registry state")
    }

    fn registry_with_peer() -> (CertificateRegistry, tempfile::TempDir, WireGuardKey) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let peer_key = WireGuardKey::from_bytes([3; 32]);
        let mut state = initial_state(gateway_identity(&key(9).to_base64()));
        // A genuine anchor: the trust block carries it, and Orion parses it.
        state.client_tls_ca.active_client_tls_ca_certificate =
            aether::certificates::test_x509::client_material("workstation").authority;
        state.peers.insert(
            peer_key.to_base64(),
            PeerCertificates {
                name: "workstation".into(),
                state: ClientCertificateState::new(ClientCertificateGeneration {
                    generation: 7,
                    ca_tls_epoch: 1,
                    tls_ca_certificate_fingerprint: Fingerprint::of(b"client CA"),
                    tls_certificate_fingerprint: Fingerprint::of(b"client TLS"),
                    pq_certificate_fingerprint: Fingerprint::of(b"client PQ"),
                    not_before: 100,
                    not_after: 10_000,
                }),
                active_pq_certificate: state.gateway.active_gateway_certificate.clone(),
                staged_pq_certificate: None,
                distribution: None,
            },
        );
        let registry =
            CertificateRegistry::bootstrap(directory.path().join("certificates.json"), state)
                .expect("registry");
        (registry, directory, peer_key)
    }

    fn key(seed: u8) -> WireGuardKey {
        WireGuardKey::from_bytes([seed; 32])
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

    #[test]
    fn initial_registry_state_uses_the_served_identity_and_starts_closed() {
        let wg = key(9);
        let served = gateway_identity(&wg.to_base64());
        let active_tls = served.tls_certificate.clone();
        let active_pq = served.pq_certificate.clone();
        let state = initial_state(served);

        assert_eq!(
            state.trust_domain_id,
            TrustDomainId::new([8; 16]).expect("domain")
        );
        assert_eq!(state.gateway.gateway_wg_public_key, wg);
        assert_eq!(state.gateway.server_name, "gateway.example");
        assert_eq!(state.gateway.active_gateway_tls_certificate, active_tls);
        assert_eq!(state.gateway.active_gateway_certificate, active_pq);
        assert_eq!(state.gateway.ca_epoch, 1);
        assert_eq!(state.gateway.active_gateway_identity_epoch, 1);
        assert_eq!(state.gateway.gateway_decision_epoch, 1);
        assert!(state.gateway.next_gateway_certificate.is_none());
        assert!(state.gateway.next_gateway_tls_certificate.is_none());
        assert_eq!(state.client_tls_ca.ca_tls_epoch, 1);
        assert_eq!(
            state.client_tls_ca.active_client_tls_ca_certificate,
            certificate(1)
        );
        assert_eq!(state.astra.authority_url, AUTHORITY_URL);
        assert_eq!(state.astra.webauthn_rp_id, RP_ID);
        assert_eq!(state.astra.astra_service_key_epoch, 1);
        let expected_policy = aether::certificates::AstraIssuancePolicy::standard(
            state.trust_domain_id,
            wg,
            "gateway.example".into(),
        )
        .pin()
        .expect("policy pin");
        assert_eq!(
            state.astra.astra_policy_fingerprint.fingerprint(),
            expected_policy.fingerprint()
        );
        assert!(state.issuer.is_none());
        assert!(state.peers.is_empty());
    }

    #[test]
    fn invalid_bootstrap_arguments_are_named_before_gateway_files_are_read() {
        let (_, ca_public) = generate_ml_dsa_87_keypair().expect("CA keypair");
        let (_, service_public) = generate_ml_dsa_87_keypair().expect("service keypair");
        let valid_domain = TrustDomainId::new([8; 16]).expect("domain").to_hex();
        let certificate_path = std::path::Path::new("not-read-before-argument-validation");

        let invalid_domain = super::init_trust_domain(
            "not-a-domain-id",
            &ca_public.to_base64(),
            certificate_path,
            &service_public.to_base64(),
            AUTHORITY_URL,
            RP_ID,
            None,
        )
        .expect_err("invalid trust domain identifier is rejected");
        assert!(format!("{invalid_domain:#}").contains("reading the trust domain identifier"));

        let invalid_ca = super::init_trust_domain(
            &valid_domain,
            "%%%",
            certificate_path,
            &service_public.to_base64(),
            AUTHORITY_URL,
            RP_ID,
            None,
        )
        .expect_err("invalid CA-PQ key is rejected");
        assert!(format!("{invalid_ca:#}").contains("reading the CA-PQ public key"));

        let invalid_service = super::init_trust_domain(
            &valid_domain,
            &ca_public.to_base64(),
            certificate_path,
            "%%%",
            AUTHORITY_URL,
            RP_ID,
            None,
        )
        .expect_err("invalid Astra key is rejected");
        assert!(format!("{invalid_service:#}").contains("reading the Astra service public key"));
    }

    #[test]
    fn invalid_served_wireguard_identity_fails_before_client_ca_file_read() {
        let mut served = gateway_identity(&key(9).to_base64());
        served.pq_certificate.wireguard_public_key = "not-a-wireguard-key".into();
        let (_, ca_public) = generate_ml_dsa_87_keypair().expect("CA keypair");
        let (_, service_public) = generate_ml_dsa_87_keypair().expect("service keypair");
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing_ca = directory.path().join("missing.der");

        let error = initial_trust_domain_state(
            TrustDomainId::new([8; 16]).expect("trust domain"),
            ca_public,
            service_public,
            served,
            AUTHORITY_URL,
            RP_ID,
            Some(&missing_ca),
        )
        .expect_err("the identity in the served leaf is authoritative");

        assert!(error
            .to_string()
            .contains("WireGuard identity out of the served PQ leaf"));
        assert!(!format!("{error:#}").contains("reading the domain client CA-TLS"));
    }

    #[test]
    fn invalid_policy_identity_fails_before_client_ca_file_read() {
        let mut served = gateway_identity(&key(9).to_base64());
        served.pq_certificate.subject = "not a server name".into();
        let (_, ca_public) = generate_ml_dsa_87_keypair().expect("CA keypair");
        let (_, service_public) = generate_ml_dsa_87_keypair().expect("service keypair");
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing_ca = directory.path().join("missing.der");

        let error = initial_trust_domain_state(
            TrustDomainId::new([8; 16]).expect("trust domain"),
            ca_public,
            service_public,
            served,
            AUTHORITY_URL,
            RP_ID,
            Some(&missing_ca),
        )
        .expect_err("the issuance policy must be valid before seeding");

        assert!(format!("{error:#}").contains("building the pinned Astra issuance policy"));
        assert!(!format!("{error:#}").contains("reading the domain client CA-TLS"));
    }

    #[test]
    fn trust_enrolment_rejects_bad_and_unadmitted_keys_and_trims_valid_keys() {
        let (registry, _directory, peer_key) = registry_with_peer();

        let invalid = trust_enrolment_view(&registry, "%%%")
            .expect_err("invalid keys are refused before peer lookup");
        assert!(invalid.to_string().contains("invalid WireGuard public key"));

        let absent = trust_enrolment_view(&registry, &key(4).to_base64())
            .expect_err("unadmitted peers have no trust block");
        assert!(absent
            .to_string()
            .contains("no such peer in the certificate registry"));

        let view = trust_enrolment_view(&registry, &format!("  {}\n", peer_key.to_base64()))
            .expect("the command trims the key it receives");
        assert_eq!(
            view.trust_domain_id,
            registry.state().trust_domain_id.to_hex()
        );
        assert_eq!(view.client_generation, 7);
        assert_eq!(view.astra_authority_url, AUTHORITY_URL);
        assert_eq!(view.webauthn_rp_id, RP_ID);
    }

    /// A network that admits `public_key`, with the gateway's private key as
    /// `wg_private` (empty when the identity is sealed in the TPM vault).
    fn network_admitting(public_key: &str, wg_private: &str) -> aether::NetworkConfig {
        let mut network = aether::NetworkConfig::default();
        network.peers.push(aether::WgPeer {
            name: "workstation".into(),
            public_key: public_key.into(),
            address: "100.64.1.2/32".into(),
            address_v6: Some("fd00::2".parse().expect("VIP")),
            admin: false,
            preshared_key: None,
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: None,
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        });
        network.key_negotiation_port = Some(4443);
        network.wg_private_key = aether::SecretString::new(wg_private);
        network
    }

    /// The bytes the negotiation files hold: the TLS DER and the PQ leaf, as
    /// `served_identity` reads them from disk.
    fn negotiation_files(registry: &CertificateRegistry) -> (Vec<u8>, Vec<u8>) {
        let leaf = &registry.state().gateway.active_gateway_certificate;
        (
            certificate(2).as_bytes().to_vec(),
            serde_json::to_vec(leaf).expect("encoding the leaf"),
        )
    }

    #[test]
    fn export_carries_what_the_online_routes_serve() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let (registry, _directory, peer_key) = registry_with_peer();
        let network = network_admitting(&peer_key.to_base64(), "");
        let (certificate_der, pq_json) = negotiation_files(&registry);

        let export = enrolment_export(
            &network,
            &certificate_der,
            &pq_json,
            &registry,
            &peer_key.to_base64(),
        )
        .expect("an admitted peer has an export");

        let leaf = &registry.state().gateway.active_gateway_certificate;
        assert_eq!(export.server_name, leaf.subject);
        assert_eq!(
            export.pq_certificate_sha256,
            leaf.fingerprint().expect("fingerprint")
        );
        assert_eq!(export.wireguard_public_key, leaf.wireguard_public_key);
        assert_eq!(
            STANDARD.decode(&export.gateway_ca_der).expect("base64"),
            certificate_der
        );
        assert_eq!(
            STANDARD
                .decode(&export.gateway_pq_certificate)
                .expect("base64"),
            pq_json
        );
        assert_eq!(export.negotiation_port, Some(4443));
        assert_eq!(export.gateway_wg_address, network.wg_address);
        assert_eq!(export.peer_public_key, peer_key.to_base64());
        assert_eq!(export.address, "100.64.1.2/32");
        assert_eq!(export.address_v6.as_deref(), Some("fd00::2/128"));
        assert_eq!(
            export.trust,
            serde_json::to_value(enrolment_view(
                registry.state(),
                registry.peer(&peer_key).expect("peer")
            ))
            .expect("encoding the trust block")
        );
    }

    #[test]
    fn an_export_is_one_orion_reads() {
        let (registry, _directory, peer_key) = registry_with_peer();
        let network = network_admitting(&peer_key.to_base64(), "");
        let (certificate_der, pq_json) = negotiation_files(&registry);
        let export = enrolment_export(
            &network,
            &certificate_der,
            &pq_json,
            &registry,
            &peer_key.to_base64(),
        )
        .expect("export");

        let text = encode_enrolment_export_file(&export);
        let read = decode_enrolment_export_file(&text).expect("the file reads back");
        let (material, admission) =
            orion_core::gateway_admin::material_from_export(&read).expect("Orion reads the export");

        assert_eq!(
            material.server_name,
            registry.state().gateway.active_gateway_certificate.subject
        );
        assert_eq!(admission.address, "100.64.1.2/32");
        admission
            .trust
            .expect("the trust block is present")
            .validate()
            .expect("Orion accepts the trust block");
    }

    #[test]
    fn export_refuses_a_peer_not_in_network_toml() {
        let (registry, _directory, peer_key) = registry_with_peer();
        let network = aether::NetworkConfig::default();
        let (certificate_der, pq_json) = negotiation_files(&registry);

        let error = enrolment_export(
            &network,
            &certificate_der,
            &pq_json,
            &registry,
            &peer_key.to_base64(),
        )
        .expect_err("a peer absent from network.toml has no export");

        let message = error.to_string();
        assert!(
            message.contains("no such peer in network.toml"),
            "{message}"
        );
        assert!(message.contains("heliosd peer add"), "{message}");
    }

    #[test]
    fn export_refuses_a_peer_the_registry_does_not_hold() {
        let (registry, _directory, _peer_key) = registry_with_peer();
        let absent = key(4).to_base64();
        let network = network_admitting(&absent, "");
        let (certificate_der, pq_json) = negotiation_files(&registry);

        let error = enrolment_export(&network, &certificate_der, &pq_json, &registry, &absent)
            .expect_err("a peer absent from the registry has no export");

        assert!(error
            .to_string()
            .contains("no such peer in the certificate registry"));
    }

    #[test]
    fn export_refuses_without_a_trust_domain() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let error = load_trust_domain(&directory.path().join("certificates.json"))
            .expect_err("an absent registry is not an empty one");

        let message = error.to_string();
        assert!(message.contains("init-trust-domain"), "{message}");
        assert!(
            message.contains("absent registry is not an empty one"),
            "{message}"
        );
    }

    #[test]
    fn export_refuses_an_unreadable_key() {
        let (registry, _directory, peer_key) = registry_with_peer();
        let network = network_admitting(&peer_key.to_base64(), "");
        let (certificate_der, pq_json) = negotiation_files(&registry);

        let error = enrolment_export(&network, &certificate_der, &pq_json, &registry, "%%%")
            .expect_err("an unreadable key is refused before any lookup");

        assert!(error.to_string().contains("invalid WireGuard public key"));
    }

    #[test]
    fn export_refuses_a_leaf_bound_to_another_identity() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let (registry, _directory, peer_key) = registry_with_peer();
        // A private key whose public half is not the leaf's WireGuard key.
        let other_private = STANDARD.encode([5u8; 32]);
        let network = network_admitting(&peer_key.to_base64(), &other_private);
        let (certificate_der, pq_json) = negotiation_files(&registry);

        let error = enrolment_export(
            &network,
            &certificate_der,
            &pq_json,
            &registry,
            &peer_key.to_base64(),
        )
        .expect_err("a leaf bound to another identity is never exported");

        let message = error.to_string();
        assert!(
            message.contains("bound to another WireGuard identity"),
            "{message}"
        );
        assert!(
            message.contains("init-key-negotiation --rotate"),
            "{message}"
        );
    }

    #[test]
    fn export_ignores_a_sealed_identity() {
        let (registry, _directory, peer_key) = registry_with_peer();
        let network = network_admitting(&peer_key.to_base64(), "");
        let (certificate_der, pq_json) = negotiation_files(&registry);

        enrolment_export(
            &network,
            &certificate_der,
            &pq_json,
            &registry,
            &peer_key.to_base64(),
        )
        .expect("with the identity sealed there is nothing to compare, and the export is made");
    }
}
