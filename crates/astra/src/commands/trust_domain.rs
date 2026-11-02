//! The anchors this authority was bootstrapped with, and what it believes.
//!
//! `bootstrap` creates the registry of a trust domain, `pin-ca-tls` completes
//! it with the one anchor §9.4 needs and bootstrap may have left unnamed, and
//! `status` prints what the authority currently holds. None of the three opens
//! a campaign or contacts the gateway. `bootstrap` writes a volume no service
//! can be running on, and takes its lock to be sure; `pin-ca-tls` is a write
//! of the console, which follows that lock (§5.9); `status` reads
//! `registry.json`, with the service running or not.

use std::path::Path;

use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, MlDsa87PublicKey, TrustDomainId, WireGuardKey,
};
use anyhow::{Context, Result};
use astra::door::{DoorOutcome, DoorRequest, VolumeLock};
use astra::registry::{AstraRegistry, AstraState};
use astra::AuditEvent;

use crate::{console, now_unix, REGISTRY_FILE, SERVICE_KEY_FILE};

#[allow(clippy::too_many_arguments)]
pub(crate) fn bootstrap(
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
    // Held until the registry is written: bootstrapping a volume another
    // process writes is the corruption the lock exists to prevent (§5.9).
    let _volume = VolumeLock::try_acquire(state_dir)
        .with_context(|| {
            format!(
                "locking {}",
                state_dir.join(astra::door::VOLUME_LOCK_FILE).display()
            )
        })?
        .with_context(|| {
            format!(
                "un autre processus tient {} : rien n'a été amorcé",
                state_dir.display()
            )
        })?;

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

/// Records the client `CA-TLS` in service, once (spec §9.4).
///
/// Pinning the anchor already held changes nothing and is not a refusal;
/// another anchor is refused, because replacing a pinned anchor is a signed
/// rotation.
pub(crate) fn pin_ca_tls(state_dir: &Path, fingerprint: &str) -> Result<()> {
    let fingerprint = parse_fingerprint(fingerprint).context("--fingerprint")?;
    let outcome = console::write(
        state_dir,
        DoorRequest::PinCaTls { fingerprint },
        |registry| {
            let pinned = astra::door::write::pin_ca_tls(registry, fingerprint, now_unix())?;
            Ok(pinned.into())
        },
    )?;
    let DoorOutcome::Pinned { changed, .. } = outcome else {
        return Err(console::unexpected(&outcome));
    };
    if !changed {
        eprintln!("cette ancre CA-TLS est déjà épinglée ; rien n'a changé");
        return Ok(());
    }
    println!("{fingerprint}");
    eprintln!("ancre CA-TLS épinglée : la rotation du §9.4 est désormais vérifiable ici");
    Ok(())
}

/// Reads a SHA-256 an operator confirmed out of band.
fn parse_fingerprint(value: &str) -> Result<aether::certificates::encoding::Fingerprint> {
    aether::certificates::encoding::Fingerprint::parse_hex(value.trim())
        .map_err(|error| anyhow::anyhow!("{error}"))
}

pub(crate) fn status(state_dir: &Path, expected_audit_head: Option<&str>) -> Result<()> {
    let expected = expected_audit_head
        .map(Fingerprint::parse_hex)
        .transpose()
        .context("reading the expected audit head")?;
    let registry = AstraRegistry::load_allowing_unattended_tail(
        &state_dir.join(REGISTRY_FILE),
        expected.as_ref(),
    )
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
