//! The certificate registry, edited with the daemon stopped.
//!
//! Creating the trust domain, preparing and installing the documents an
//! operator ceremony signs, rotating the anchors, and reading a peer's
//! enrolment block back out. Every function here opens the registry file
//! itself, which is why each one says it is for a stopped daemon.

use std::path::Path;

use anyhow::Context;
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
pub(crate) fn show_trust_enrolment(public_key: &str) -> anyhow::Result<()> {
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
             or `helios peer add`"
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

pub(crate) fn init_trust_domain(
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
