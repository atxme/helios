//! The delegated issuer: prepare it here, have it signed there, install it.
//!
//! Two commands and not one, because the signature happens on another machine
//! at a security key: the private halves are born here and never travel, and
//! what crosses is a public request one way and a `CA-PQ`-signed authorization
//! the other.

use std::path::Path;

use aether::certificates::encoding::{generate_ml_dsa_87_keypair, Fingerprint};
use anyhow::{Context, Result};
use astra::registry::AstraRegistry;

use crate::campaign_deposit::{open_campaign, DepositedCampaign};
use crate::{now_unix, REGISTRY_FILE};

/// Draws the next delegation's private keys and prints its public request.
///
/// Nothing is installed and nothing is announced: the registry is only read,
/// for the epoch to advance from. Until an authorization comes back, these two
/// files are a key pair no signed object names — which is exactly the state an
/// interrupted ceremony should leave behind.
pub(crate) fn issuer_request(
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
pub(crate) fn issuer_install(state_dir: &Path, authorization: Option<&Path>) -> Result<()> {
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
