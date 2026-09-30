//! The gateway's identity: bootstrap, transition, abort, rollback, and the
//! deposit of the signed decision.

use super::*;

/// Issues the first gateway leaf without inventing an online Astra campaign.
pub(crate) fn issue_gateway_bootstrap(
    path: &Path,
    request_path: &Path,
    out: &Path,
    validity_days: u64,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::gateway::GatewayBootstrapRequest;
    use aether::certificates::status::CampaignScope;

    let vault = store::load(path)?;
    let mut handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let request: GatewayBootstrapRequest =
        read_json(request_path, "la demande d'amorçage gateway")?;
    request.verify()?;
    // The gateway this domain serves, recorded once rather than retyped.
    //
    // This ceremony is the first thing that learns it, from a request the
    // gateway signed with its own sealed key, and every later command needs
    // it: `issue-ca-tls` pins the issuance policy over exactly these two
    // values. Leaving them out of the hand-off is what forces an operator to
    // pass `astra-signer domain --gateway-wg-public-key ...` by hand between
    // two steps that both already hold the value.
    //
    // Recorded, never replaced: ADR-008 binds a trust domain to one gateway,
    // so a request naming another one is a mistake to stop on, not a second
    // identity to adopt.
    let gateway_key = request.gateway_wg_public_key.to_base64();
    for (held, found, what) in [
        (
            handoff.gateway_wg_public_key.as_deref(),
            gateway_key.as_str(),
            "la clé publique WireGuard",
        ),
        (
            handoff.server_name.as_deref(),
            request.server_name.as_str(),
            "le nom de service",
        ),
    ] {
        if let Some(held) = held {
            if held != found {
                bail!(
                    "ce relais nomme déjà une autre gateway : {what} y vaut « {held} », la \
                     demande porte « {found} ». Un domaine de confiance sert une gateway et une \
                     seule."
                );
            }
        }
    }
    handoff.gateway_wg_public_key = Some(gateway_key);
    handoff.server_name = Some(request.server_name.clone());
    handoff::save(&handoff::path_beside(path), &handoff)?;
    let now = now_unix();
    let validity = validity_days
        .checked_mul(DAY_SECS)
        .and_then(|seconds| now.checked_add(seconds))
        .context("durée de validité hors bornes")?;

    let scope = CampaignScope::GatewayBootstrap;
    println!("amorçage gateway : émission de l'époque 1 sous CA-PQ");
    println!("gateway          : {}", request.server_name);
    println!(
        "identité         : {}",
        request.gateway_wg_public_key.to_base64()
    );
    println!("demande          : {}", request.fingerprint());
    println!("valide jusqu'à   : {}", horodatage(validity));
    println!(
        "credentials      : {} actifs distincts (admission sans continuité)",
        scope.required_credentials()
    );
    println!("transport        : fichiers uniquement ; Astra n'a encore aucun registre");

    let first = connect_authorized_key(
        &vault,
        transport,
        "Brancher le PREMIER credential autorisé, puis appuyer sur Entrée.",
    )?;
    eprintln!();
    let second = connect_authorized_key(
        &vault,
        transport,
        "Débrancher celui-ci, brancher le SECOND credential autorisé, puis Entrée.",
    )?;
    gestures::require_scope_credentials(scope, &[&first.opened, &second.opened])?;
    // Both credentials must open the current vault, not merely resolve to a
    // slot. This is the bootstrap trial ADR-008 requires before first use.
    gestures::prove_anchors_open(&vault, &first.opened)?;
    gestures::prove_anchors_open(&vault, &second.opened)?;

    let certificate = signing::issue_gateway_bootstrap_certificate(
        &vault,
        &first.opened,
        &ca_pq_public_key,
        &signing::GatewayBootstrapDecision {
            request: &request,
            leaf_validity: (now.saturating_sub(300), validity),
            serial: random_id()?,
        },
    )?;
    let encoded = serde_json::to_vec_pretty(&certificate).context("encodage de la feuille")?;
    std::fs::write(out, encoded).with_context(|| format!("écriture de {}", out.display()))?;
    println!("feuille écrite   : {}", out.display());
    println!("empreinte        : {}", certificate.fingerprint()?);
    Ok(())
}

/// Everything the gateway ceremony reads from the operator's command line.
pub(crate) struct GatewayTransitionInputs<'a> {
    pub(crate) request: &'a Path,
    pub(crate) active_certificate: Option<&'a Path>,
    pub(crate) tls_certificate: Option<&'a Path>,
    pub(crate) out: &'a Path,
    pub(crate) validity_days: u64,
    pub(crate) prepare_days: u64,
    pub(crate) overlap_days: u64,
    pub(crate) key_recovery: bool,
    pub(crate) emergency_replacement: bool,
}

/// Issues the next gateway leaf and signs its transition (spec §11.1 step 4).
pub(crate) fn sign_gateway_transition(
    path: &Path,
    channel: astra_operator::campaign::Campaign,
    operation_id: &str,
    origin: Option<&str>,
    inputs: GatewayTransitionInputs<'_>,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::gateway::{Continuity, GatewayCertificateRequest};
    use aether::certificates::status::CampaignFamily;

    let operation = Id16::parse_hex(operation_id)
        .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;

    let expected_url = handoff::expected_authority_url(&handoff, &channel)?;
    println!("transport        : {}", channel.description());
    let request_document = channel.fetch(&operation)?;
    handoff::verify_campaign_request(
        &handoff,
        &vault,
        &request_document,
        &expected_url,
        now_unix(),
    )?;
    let campaign = request_document.campaign.as_ref().clone();
    if !matches!(campaign.scope.family(), CampaignFamily::GatewayIdentity) {
        bail!("cette opération ne décide pas l'identité gateway. Rien n'a été signé.");
    }
    let target = match campaign.targets.as_slice() {
        [only] => only,
        targets => bail!(
            "une décision gateway nomme exactement une identité, {} présentes. Rien n'a été signé.",
            targets.len()
        ),
    };

    let request: GatewayCertificateRequest = read_json(inputs.request, "la demande gateway")?;
    let epoch = target
        .epoch
        .checked_add(1)
        .context("époque de décision hors bornes")?;
    if request.gateway_identity_epoch != epoch {
        bail!(
            "la demande porte l'époque {} et cette campagne autorise la {epoch}. Rien n'a été \
             signé.",
            request.gateway_identity_epoch
        );
    }
    let now = now_unix();

    // The continuity signature proves the request comes from the identity in
    // place. It cannot be checked without that identity's public key, which
    // this companion does not hold — `astra gateway-identity open` exports it
    // from the daemon that serves it.
    let continuity_key = match inputs.active_certificate {
        Some(source) => {
            let served: aether::key_negotiation::PqCertificate =
                read_json(source, "la feuille en service")?;
            let fingerprint = aether::certificates::gateway::pq_certificate_fingerprint(&served)?;
            if !target
                .active_pq_certificate_fingerprint
                .matches(&fingerprint)
            {
                bail!(
                    "la feuille fournie n'est pas celle que la campagne épingle. Rien n'a été \
                     signé."
                );
            }
            Some(MlDsa87PublicKey::parse(&served.ml_dsa_87_public_key)?)
        }
        None if inputs.key_recovery => None,
        None => bail!(
            "--active-certificate est requis : sans la feuille en service, la continuité du §5 \
             n'est pas vérifiable. Une demande sans continuité exige --key-recovery."
        ),
    };
    request.verify(
        match continuity_key.as_ref() {
            Some(key) => Continuity::Required(key),
            None => Continuity::WaivedForKeyRecovery,
        },
        &identity.trust_domain_id,
        target.epoch,
        &campaign.gateway_wg_public_key,
        &campaign.server_name,
        now,
    )?;

    let next_tls = inputs
        .tls_certificate
        .map(|source| -> Result<DerCertificate> {
            let der = std::fs::read(source)
                .with_context(|| format!("lecture de {}", source.display()))?;
            Ok(DerCertificate::new(der)?)
        })
        .transpose()?;

    let day =
        |days: u64| -> Result<u64> { days.checked_mul(DAY_SECS).context("durée hors bornes") };
    let activation_at = now
        .checked_add(day(inputs.prepare_days)?)
        .context("durée hors bornes")?;
    let window = TransitionWindow::new(
        now,
        activation_at,
        activation_at
            .checked_add(day(inputs.overlap_days)?)
            .context("durée hors bornes")?,
    )?;
    let leaf_validity = (
        now,
        now.checked_add(day(inputs.validity_days)?)
            .context("durée hors bornes")?,
    );

    println!("opération        : {}", operation.to_hex());
    println!("gateway          : {}", campaign.server_name);
    println!(
        "identité         : {}",
        campaign.gateway_wg_public_key.to_base64()
    );
    println!("époque           : {} → {epoch}", target.epoch);
    println!(
        "feuille PQ       : {}",
        target.active_pq_certificate_fingerprint
    );
    println!(
        "feuille TLS      : {}",
        target.active_tls_certificate_fingerprint
    );
    println!(
        "TLS remplacée    : {}",
        match &next_tls {
            Some(certificate) => certificate.fingerprint().to_hex(),
            None => "inchangée".to_string(),
        }
    );
    println!(
        "continuité       : {}",
        if continuity_key.is_some() {
            "vérifiée"
        } else {
            "levée (récupération de clé)"
        }
    );
    println!("activation       : {}", horodatage(activation_at));
    println!("retrait          : {}", horodatage(window.not_after));
    println!("motif            : {}", campaign.reason);
    println!("demandée par     : {}", campaign.requested_by);
    println!("empreinte        : {}", campaign.fingerprint());
    println!("effet            : aucun avant activation_at ; heliosd redémarre à cet instant");

    let origin = origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", vault.rp_id));
    eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;

    let approval = signing::approve_campaign(
        &[key.as_ref()],
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        &[pin.as_str()],
        now,
    )?;
    let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    let decision = signing::GatewayTransitionDecision {
        gateway_identity_epoch: epoch,
        gateway_wg_public_key: campaign.gateway_wg_public_key,
        server_name: campaign.server_name.clone(),
        active_tls_fingerprint: target.active_tls_certificate_fingerprint,
        active_pq_fingerprint: target.active_pq_certificate_fingerprint,
        next_pq_public_key: request.new_ml_dsa_87_public_key.clone(),
        next_tls_certificate: next_tls,
        window,
        leaf_validity,
        reason: match (inputs.emergency_replacement, inputs.key_recovery) {
            (true, _) => aether::certificates::authority::RotationReason::EmergencyReplacement,
            (false, true) => aether::certificates::authority::RotationReason::KeyRecovery,
            (false, false) => aether::certificates::authority::RotationReason::Scheduled,
        },
        serial: random_id()?,
    };
    let transition = signing::sign_gateway_transition(
        &vault,
        &opening,
        &identity,
        &ca_pq_public_key,
        &decision,
    )?;
    campaign
        .covers_gateway_transition(&transition)
        .context("la décision signée ne correspond pas à la campagne approuvée")?;

    deposit_gateway_decision(
        &channel,
        &request_document,
        &approval,
        aether::certificates::transport::TrustUpdateObject::GatewayIdentityTransition(Box::new(
            transition,
        )),
        inputs.out,
        "transition",
    )
}

/// Signs the cancellation of a staged gateway transition (spec §6.3).
#[allow(clippy::too_many_arguments)]
pub(crate) fn abort_gateway_transition(
    path: &Path,
    channel: astra_operator::campaign::Campaign,
    operation_id: &str,
    origin: Option<&str>,
    transition_path: &Path,
    out: &Path,
    reason: aether::certificates::gateway::AbortReason,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::gateway::GatewayIdentityTransition;
    use aether::certificates::status::CampaignFamily;

    let operation = Id16::parse_hex(operation_id)
        .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;

    let expected_url = handoff::expected_authority_url(&handoff, &channel)?;
    println!("transport        : {}", channel.description());
    let request_document = channel.fetch(&operation)?;
    handoff::verify_campaign_request(
        &handoff,
        &vault,
        &request_document,
        &expected_url,
        now_unix(),
    )?;
    let campaign = request_document.campaign.as_ref().clone();
    if !matches!(campaign.scope.family(), CampaignFamily::GatewayIdentity) {
        bail!("cette opération ne décide pas l'identité gateway. Rien n'a été signé.");
    }
    let target = match campaign.targets.as_slice() {
        [only] => only,
        targets => bail!(
            "une décision gateway nomme exactement une identité, {} présentes. Rien n'a été signé.",
            targets.len()
        ),
    };

    let transition: GatewayIdentityTransition =
        read_json(transition_path, "la transition à annuler")?;
    if transition.gateway_identity_epoch != target.epoch {
        bail!(
            "cette campagne porte la décision {} et la transition fournie la {}. Rien n'a été \
             signé.",
            target.epoch,
            transition.gateway_identity_epoch
        );
    }
    let now = now_unix();
    if now >= transition.window.activation_at {
        bail!(
            "activation_at est atteint : la transition est en recouvrement et ne s'annule plus \
             (§6.3). Promouvoir, puis préparer une nouvelle transition."
        );
    }

    println!("opération        : {}", operation.to_hex());
    println!("gateway          : {}", campaign.server_name);
    println!("époque annulée   : {}", transition.gateway_identity_epoch);
    println!("transition       : {}", transition.fingerprint()?);
    println!(
        "activation prévue: {}",
        horodatage(transition.window.activation_at)
    );
    println!("motif            : {reason:?}");
    println!("demandé par      : {}", campaign.requested_by);
    println!("empreinte        : {}", campaign.fingerprint());
    println!(
        "effet            : l'époque reste consommée ; la suivante repart une décision plus haut"
    );

    let origin = origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", vault.rp_id));
    eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;

    let approval = signing::approve_campaign(
        &[key.as_ref()],
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        &[pin.as_str()],
        now,
    )?;
    let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    let abort = signing::sign_gateway_abort(
        &vault,
        &opening,
        &identity,
        &ca_pq_public_key,
        &signing::GatewayAbortDecision {
            transition: &transition,
            reason,
            campaign_fingerprint: campaign.fingerprint(),
            aborted_at: now,
        },
    )?;
    campaign
        .covers_gateway_abort(&abort)
        .context("l'avortement signé ne correspond pas à la campagne approuvée")?;

    deposit_gateway_decision(
        &channel,
        &request_document,
        &approval,
        aether::certificates::transport::TrustUpdateObject::GatewayTransitionAbort(Box::new(abort)),
        out,
        "avortement",
    )
}

/// Signs the temporary selection of the outgoing gateway leaf (spec §11.1
/// step 8).
///
/// # Why this one opens no Astra operation
///
/// Every other gateway gesture goes through the authority because it produces
/// a `TrustUpdateObject` the domain distributes. A rollback produces none: it
/// moves no counter, removes no slot, and no client ever sees it — §4.4 calls
/// it a service rollback precisely to say that. The authority's own guard
/// agrees, and by construction: a gateway-identity campaign result must carry
/// exactly one trust-update object, so depositing this would mean inventing a
/// distributable form of a decision that must never be distributed.
///
/// So the campaign is resolved here, from the signed transition itself —
/// §11.6 keeps that resolution local anyway — displayed in full, and attested
/// by one authorized key before `CA-PQ` signs. The record of the gesture is
/// the gateway's, which is where the selection takes effect.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_gateway_rollback(
    path: &Path,
    transition_path: &Path,
    out: &Path,
    hours: u64,
    reason: &str,
    requested_by: &str,
    origin: Option<&str>,
    transport: Transport,
) -> Result<()> {
    use aether::certificates::gateway::GatewayIdentityTransition;
    use aether::certificates::status::{
        AstraRotationCampaign, CampaignScope, CampaignTarget, CertificateKind,
    };

    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;

    let transition: GatewayIdentityTransition =
        read_json(transition_path, "la transition en recouvrement")?;
    if transition.gateway_wg_public_key != identity.gateway_wg_public_key {
        bail!("cette transition vise une autre gateway. Rien n'a été signé.");
    }
    let now = now_unix();
    if now < transition.window.activation_at {
        bail!(
            "activation_at n'est pas atteint : l'ancienne identité est encore celle qui sert, il              n'y a rien à retrouver. Pour annuler la transition, `abort-gateway-transition`              (§6.3)."
        );
    }
    if now >= transition.window.not_after {
        bail!(
            "le recouvrement est terminé : après not_after, ramener l'ancienne feuille serait un              rollback d'état, pas un rollback de service (§4.4)."
        );
    }
    let expires_at = hours
        .checked_mul(3_600)
        .and_then(|seconds| now.checked_add(seconds))
        .context("durée hors bornes")?
        .min(transition.window.not_after);

    // Resolved from the transition `CA-PQ` signed, never from a command line:
    // a campaign whose target an operator typed would describe a decision the
    // domain never took.
    let campaign = AstraRotationCampaign {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        campaign_id: Id16::new(aether::random::public_bytes::<16>()?)
            .map_err(|error| anyhow::anyhow!("identifiant de campagne : {error}"))?,
        trust_domain_id: identity.trust_domain_id,
        gateway_wg_public_key: identity.gateway_wg_public_key,
        server_name: identity.server_name.clone(),
        created_at: now,
        expires_at,
        scope: CampaignScope::GatewayIdentity,
        targets: vec![CampaignTarget {
            certificate_kind: CertificateKind::GatewayTls,
            identity_key: identity.gateway_wg_public_key,
            epoch: transition.gateway_identity_epoch,
            generation: transition.gateway_identity_epoch,
            active_tls_certificate_fingerprint: transition
                .active_gateway_tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: transition.active_gateway_certificate_fingerprint,
        }],
        reason: reason.to_string(),
        requested_by: requested_by.to_string(),
        policy_fingerprint: identity.policy()?.fingerprint()?,
        required_credentials: CampaignScope::GatewayIdentity.required_credentials(),
    };

    println!("rollback de service : la gateway resert l'ancienne feuille.");
    println!("gateway          : {}", identity.server_name);
    println!("époque en cours  : {}", transition.gateway_identity_epoch);
    println!("transition       : {}", transition.fingerprint()?);
    println!(
        "feuille resservie: {}",
        transition.active_gateway_tls_certificate_fingerprint
    );
    println!("expire à         : {}", horodatage(expires_at));
    println!(
        "fin du recouvr.  : {}",
        horodatage(transition.window.not_after)
    );
    println!("motif            : {reason}");
    println!("demandé par      : {requested_by}");
    println!("empreinte        : {}", campaign.fingerprint());
    println!(
        "effet            : aucun compteur ne bouge, le slot suivant reste scellé et sa          promotion a lieu à not_after comme prévu"
    );

    let origin = origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", vault.rp_id));
    eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;

    // The assertion attests the text above, not merely the vault: §7.6 binds a
    // rollback to a YubiKey campaign, and an unenrolled key is refused here
    // against the credential document `CA-PQ` signed.
    let approval = signing::approve_campaign(
        &[key.as_ref()],
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        &[pin.as_str()],
        now,
    )?;
    let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    let authorization = signing::sign_service_rollback(
        &vault,
        &opening,
        &identity,
        &ca_pq_public_key,
        &signing::ServiceRollbackDecision {
            transition: &transition,
            campaign_fingerprint: approval.campaign_fingerprint,
            expires_at,
        },
        now,
    )?;

    let encoded =
        serde_json::to_vec_pretty(&authorization).context("encodage de l'autorisation")?;
    std::fs::write(out, &encoded).with_context(|| format!("écriture de {}", out.display()))?;
    println!("autorisation écrite : {}", out.display());
    println!(
        "à reporter sur la gateway : console Certificats, ou POST \
         /api/certificates/gateway-transition/rollback"
    );
    println!(
        "puis redémarrer heliosd : la feuille en service est déscellée au démarrage et tenue \
         pour la vie du processus"
    );
    Ok(())
}

/// Writes the signed decision out, then deposits it.
///
/// The file first. The operator carries it to the gateway, and a deposit that
/// fails after `CA-PQ` has signed must not also lose the object — the
/// alternative is a second ceremony for a decision that already exists.
fn deposit_gateway_decision(
    client: &astra_operator::campaign::Campaign,
    request: &astra_operator::origin::CampaignRequest,
    approval: &aether::certificates::status::CampaignApproval,
    object: aether::certificates::transport::TrustUpdateObject,
    out: &Path,
    what: &str,
) -> Result<()> {
    let encoded = document_nu(&object)?;
    std::fs::write(out, &encoded).with_context(|| format!("écriture de {}", out.display()))?;
    println!("{what} écrit : {}", out.display());

    let result = campaign_result(approval, vec![object], None);
    let state = client.submit(&request.operation_id, &request.result_token, &result)?;
    println!("état             : {state:?}");
    println!();
    println!("à reporter sur la gateway, en deux temps :");
    println!("  1. copier {} sur la gateway", out.display());
    println!(
        "  2. y lancer : heliosd {} <le fichier copié>",
        if what == "transition" {
            "install-gateway-transition"
        } else {
            "abort-gateway-transition"
        }
    );
    Ok(())
}

/// The signed object as `heliosd` reads it: bare, without the routing envelope.
///
/// [`TrustUpdateObject`] is internally tagged, and that tag is how Astra's
/// registry tells one decision from another. The `heliosd install-*` readers
/// take one concrete type and refuse an unknown `kind` field, so a file
/// carrying the envelope is a file the command this companion prints cannot
/// parse. The envelope still travels to the authority; only the operator's
/// copy is unwrapped.
pub(crate) fn document_nu(
    object: &aether::certificates::transport::TrustUpdateObject,
) -> Result<Vec<u8>> {
    use aether::certificates::transport::TrustUpdateObject as Objet;

    let encoded = match object {
        Objet::GatewayIdentityTransition(transition) => serde_json::to_vec_pretty(transition),
        Objet::GatewayTransitionAbort(abort) => serde_json::to_vec_pretty(abort),
        Objet::CaTransition(transition) => serde_json::to_vec_pretty(transition),
        Objet::ClientTlsCaTransition(transition) => serde_json::to_vec_pretty(transition),
        // No `heliosd install-*` command reads the remaining variants from a
        // file; they reach the gateway through the distribution channel. The
        // envelope is kept rather than guessed at, so a future reader sees the
        // type it was given instead of an unlabelled body.
        other => serde_json::to_vec_pretty(other),
    };
    encoded.context("encodage de la décision signée")
}
