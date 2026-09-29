//! Issuing `CA-TLS` and delegating Astra's issuer.

use super::*;

pub(crate) fn issue_ca_tls(
    path: &Path,
    days: u64,
    out: Option<&Path>,
    transport: Transport,
) -> Result<()> {
    let vault = store::load(path)?;
    let mut handoff = handoff::DomainHandoff::beside(path, &vault)?;
    if handoff.ca_tls_certificate.is_some() {
        bail!(
            "ce domaine porte déjà une CA-TLS à l'époque {} : `issue-ca-tls` initialise l'ancre, \
             il ne la remplace pas ; employer la transition CA-TLS du §9.4",
            handoff.ca_tls_epoch.unwrap_or(1)
        );
    }
    let identity = handoff::identity_of(&handoff)?;
    let not_before = now_unix();
    let not_after = not_before
        .checked_add(days.checked_mul(DAY_SECS).context("durée hors bornes")?)
        .context("durée hors bornes")?;

    let opening = open_vault(
        &vault,
        transport,
        "Auto-signature de CA-TLS. Brancher une clé autorisée, puis appuyer sur Entrée.",
    )?;
    let certificate = authority::issue_ca_tls(&vault, &opening, &identity, not_before, not_after)?;

    // The epoch moves with the certificate, in the same write: a hand-off
    // naming one epoch and carrying another would have every later delegation
    // refused at the gateway, under a signature that is perfectly valid.
    handoff.ca_tls_epoch = Some(identity.ca_tls_epoch);
    handoff.ca_tls_certificate = Some(certificate.to_base64());
    handoff::save(&handoff::path_beside(path), &handoff)?;
    if let Some(out) = out {
        std::fs::write(out, pem_of(&certificate))
            .with_context(|| format!("écriture de {}", out.display()))?;
        println!("certificat PEM   : {}", out.display());
    }

    println!(
        "relais           : {}",
        handoff::path_beside(path).display()
    );
    println!("époque CA-TLS    : {}", identity.ca_tls_epoch);
    println!("valide de        : {}", horodatage(not_before));
    println!("valide jusqu'à   : {}", horodatage(not_after));
    println!(
        "cette CA est épinglée par la gateway : la remplacer coupe tous les clients déjà \
         admis, et c'est la rotation du §9.4 qui la remplace"
    );
    Ok(())
}

/// Signs one bounded delegation to Astra's online issuer (spec §9.5).
///
/// # Why the campaign is the ordinary path
///
/// An [`IssuerDelegationRequest`] carries no signature. Read from a file, it
/// authorizes whoever handed the operator that file: substitute the ML-DSA-87
/// key, and the delegation certifies a key its holder chose. The campaign is
/// what closes that — it is signed by the authority's service key, it pins the
/// epoch and both public halves, and the operator reads them before the touch.
/// The offline form survives for a domain with no reachable origin, and says
/// so rather than pretending the two are equivalent.
#[allow(clippy::too_many_arguments)]
pub(crate) fn authorize_issuer(
    path: &Path,
    request_path: &Path,
    out: Option<&Path>,
    online: Option<(&str, &str)>,
    days: u64,
    leaf_days: u64,
    origin: Option<&str>,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::status::CampaignFamily;

    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_tls = DerCertificate::parse(handoff.require(
        handoff.ca_tls_certificate.as_ref(),
        "le certificat CA-TLS",
        "issue-ca-tls",
    )?)?;
    let campaign_context = match online {
        Some((authority_url, operation_id)) => {
            let operation = Id16::parse_hex(operation_id)
                .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
            let client = astra_operator::origin::Origin::new(authority_url)?;
            let request_document = origin_client_fetch(&client, &operation)?;
            handoff::verify_campaign_request(
                &handoff,
                &vault,
                &request_document,
                authority_url,
                now_unix(),
            )?;
            let campaign = request_document.campaign.as_ref().clone();
            if !matches!(campaign.scope.family(), CampaignFamily::IssuerDelegation) {
                bail!(
                    "cette opération n'autorise pas de délégation d'émetteur. Rien n'a été signé."
                );
            }
            Some((client, request_document, campaign))
        }
        None => None,
    };

    let request: IssuerDelegationRequest = documents::read(request_path)?;

    // The campaign pins the exact material, so a substituted request is
    // refused here — before the vault opens, and before the operator is asked
    // for anything.
    if let Some((_, _, campaign)) = &campaign_context {
        let csr = DerCertificate::new(
            <base64::engine::general_purpose::GeneralPurpose as base64::Engine>::decode(
                &base64::engine::general_purpose::STANDARD,
                request.tls_intermediate_csr.trim(),
            )
            .context("décodage de la demande d'intermédiaire")?,
        )?;
        let public_key_info =
            aether::certificates::x509::certification_request_public_key_info(&csr)?;
        let pq = MlDsa87PublicKey::parse(request.pq_issuer_public_key.trim())?;
        campaign
            .covers_issuer_delegation(
                identity.trust_domain_id,
                request.issuer_epoch,
                &aether::certificates::encoding::Fingerprint::of(pq.as_bytes()),
                &aether::certificates::encoding::Fingerprint::of(&public_key_info),
            )
            .context(
                "la demande de délégation n'est pas celle que la campagne nomme : époque ou clé \
                 substituée. Rien n'a été signé.",
            )?;
    }

    let not_before = now_unix();
    let bounds = DelegationBounds {
        maximum_leaf_lifetime_secs: leaf_days
            .checked_mul(DAY_SECS)
            .context("durée hors bornes")?,
        not_before,
        not_after: not_before
            .checked_add(days.checked_mul(DAY_SECS).context("durée hors bornes")?)
            .context("durée hors bornes")?,
    };

    println!("émetteur délégué : époque {}", request.issuer_epoch);
    println!("domaine          : {}", request.trust_domain_id);
    println!("gateway          : {}", identity.gateway_wg_public_key);
    println!("leaf au plus     : {leaf_days} jours");
    println!("délégation       : {days} jours");
    match &campaign_context {
        Some((_, _, campaign)) => {
            println!("campagne         : {}", campaign.campaign_id.to_hex());
            println!("empreinte        : {}", campaign.fingerprint());
            println!("motif            : {}", campaign.reason);
            println!("demandée par     : {}", campaign.requested_by);
        }
        None => println!(
            "hors campagne    : rien ne rattache cette demande à une autorité ; elle vaut ce que \
             vaut le fichier"
        ),
    }

    let authorization = match &campaign_context {
        Some((_, _, campaign)) => {
            let origin = origin
                .map(str::to_string)
                .unwrap_or_else(|| format!("https://{}", vault.rp_id));
            let registry =
                credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "aucun document de credentials : l'émettre par `astra-signer bindings`"
                    )
                })?;
            let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
            eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
            wait_for_operator()?;
            let key = authenticator::connect(transport)?;
            let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;
            let approval = authority::approve_campaign(
                &[key.as_ref()],
                campaign,
                &registry,
                &identity,
                &ca_pq_public_key,
                &vault.rp_id,
                &origin,
                &[pin.as_str()],
                now_unix(),
            )?;
            let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
            let authorization = authority::authorize_issuer(
                &vault,
                &opening,
                &identity,
                &ca_tls,
                &request,
                &bounds,
                now_unix(),
            )?;
            (Some(approval), authorization)
        }
        None => {
            let opening = open_vault(
                &vault,
                transport,
                "Signature de la délégation. Brancher une clé autorisée, puis appuyer sur Entrée.",
            )?;
            let authorization = authority::authorize_issuer(
                &vault,
                &opening,
                &identity,
                &ca_tls,
                &request,
                &bounds,
                now_unix(),
            )?;
            (None, authorization)
        }
    };
    let (approval, authorization) = authorization;

    if let Some(out) = out {
        documents::write(out, &authorization)?;
        println!("autorisation     : {}", out.display());
    }
    match (&campaign_context, approval) {
        (Some((client, request_document, _)), Some(approval)) => {
            let mut result = campaign_result(&approval, Vec::new(), None);
            result.issuer_authorization = Some(Box::new(authorization));
            let state = client.submit(
                &request_document.operation_id,
                &request_document.result_token,
                &result,
            )?;
            println!("état             : {state:?}");
            println!(
                "la délégation est enregistrée par l'autorité ; redémarrer Astra pour émettre \
                 sous elle"
            );
        }
        _ => println!("à reporter sur l'autorité : astra issuer install --authorization <fichier>"),
    }
    println!(
        "cette délégation n'autorise qu'un renouvellement de leaf cliente admise, et rien \
         d'autre : ni gateway, ni CA, ni pair inconnu"
    );
    Ok(())
}

/// The PEM form of a certificate, for the tools that read one.
fn pem_of(certificate: &DerCertificate) -> String {
    let body = certificate.to_base64();
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}
