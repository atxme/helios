//! Rotating the client TLS CA: the transition, its resumption and its
//! promotion.

use super::*;

/// Rotates the client `CA-TLS` under an approved authority campaign (§9.4).
///
/// # Why this one has no offline form
///
/// `rotate-ca-pq` can run without an authority because the operator's vault
/// **is** the `CA-PQ` authority: it holds the outgoing key and can vouch for
/// its successor alone. The client TLS anchor is different — the object that
/// installs it is authorised by `CA-PQ`, and what says *which* anchor is
/// current is the domain's registry, not this vault. A rotation resolved from
/// the vault alone could name an anchor the fleet retired months ago.
pub(crate) fn rotate_ca_tls(
    path: &Path,
    channel: astra_operator::campaign::Campaign,
    operation_id: &str,
    origin: Option<&str>,
    out: &Path,
    (prepare_days, overlap_days, validity_days): (u64, u64, u64),
    transport: Transport,
) -> Result<()> {
    use aether::certificates::transport::TrustUpdateObject;

    astra_operator::rotation_journal::ensure_none_in_flight(path)?;
    let operation = Id16::parse_hex(operation_id)
        .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
    let mut vault = store::load(path)?;
    // One window at a time, and one *finished* window at a time. A second
    // ceremony opened over an outstanding deposit would spend a second
    // campaign approval on a domain that has not accepted the first, and the
    // two rotations would then name each other's outgoing anchor.
    let prepared_path = prepared::path_beside(path);
    if let Some(outstanding) = prepared::load(&prepared_path)? {
        bail!(
            "une rotation CA-TLS est déjà préparée vers l'époque {} ({}) : {}. Rien n'a été signé.",
            outstanding.next_ca_tls_epoch,
            if outstanding.submitted {
                "déposée, en attente de promotion"
            } else {
                "jamais déposée"
            },
            if outstanding.submitted {
                "la mener à son terme par `astra-signer promote-ca-tls`"
            } else {
                "la déposer par `astra-signer resume-rotation`"
            }
        );
    }
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let active_certificate = DerCertificate::parse(handoff.require(
        handoff.ca_tls_certificate.as_ref(),
        "le certificat CA-TLS en service",
        "--ca-tls-certificate",
    )?)?;
    let registry = credentials::load(&credentials::path_beside(path))?.ok_or_else(|| {
        anyhow::anyhow!("aucun document de credentials : l'émettre par `astra-signer bindings`")
    })?;

    let expected_url = handoff::expected_authority_url(&handoff, &channel)?;
    println!("transport        : {}", channel.description());
    let request = channel.fetch(&operation)?;
    handoff::verify_campaign_request(&handoff, &vault, &request, &expected_url, now_unix())?;
    let campaign = request.campaign.as_ref().clone();
    if !campaign.scope.rotates_authority() {
        bail!("cette campagne ne fait tourner aucune ancre. Rien n'a été signé.");
    }

    let now = now_unix();
    let day =
        |days: u64| -> Result<u64> { days.checked_mul(DAY_SECS).context("durée hors bornes") };
    let activation_at = now
        .checked_add(day(prepare_days)?)
        .context("délai hors bornes")?;
    let window = TransitionWindow::new(
        now,
        activation_at,
        activation_at
            .checked_add(day(overlap_days)?)
            .context("délai hors bornes")?,
    )?;
    let validity = (
        now,
        now.checked_add(day(validity_days)?)
            .context("durée hors bornes")?,
    );

    println!("rotation de CA-TLS: l'ancre du transport mTLS client change.");
    println!("opération        : {}", operation.to_hex());
    println!(
        "époque           : {} → {}",
        identity.ca_tls_epoch,
        identity.ca_tls_epoch + 1
    );
    println!("ancre sortante   : {}", active_certificate.fingerprint());
    println!("activation       : {}", horodatage(activation_at));
    println!("retrait          : {}", horodatage(window.not_after));
    println!("motif            : {}", campaign.reason);
    println!("demandée par     : {}", campaign.requested_by);
    println!("empreinte        : {}", campaign.fingerprint());
    println!(
        "effet            : pendant le recouvrement les deux chaînes sont acceptées ; après \
         not_after, une leaf émise sous l'ancienne ne monte plus de tunnel"
    );

    let origin = origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", vault.rp_id));
    let mut approval = signing::CampaignApprovalSession::new(
        &campaign,
        &registry,
        &identity,
        &ca_pq_public_key,
        &vault.rp_id,
        &origin,
        now,
    )?;

    // Approve with each key while it is still plugged in. Windows WebAuthn
    // handles are platform selectors, not handles tied to the physical token
    // present when `connect` ran; delaying both assertions until after the
    // swap makes the second token answer the first slot and leaves the first
    // token requested forever by the narrowed allow-list.
    let first = connect_authorized_key(
        &vault,
        transport,
        "Brancher la PREMIÈRE clé autorisée, puis appuyer sur Entrée.",
    )?;
    let offered = approval.offered_credentials();
    let assertion = first.key.approve(
        approval.webauthn_rp_id(),
        &offered,
        approval.client_data_json(),
        &first.pin,
    )?;
    approval.accept_for(assertion, Some(&first.opened.credential_id), now_unix())?;
    eprintln!();
    let second = connect_authorized_key(
        &vault,
        transport,
        "Débrancher celle-ci, brancher la SECONDE clé autorisée, puis Entrée.",
    )?;
    let offered = approval.offered_credentials();
    let assertion = second.key.approve(
        approval.webauthn_rp_id(),
        &offered,
        approval.client_data_json(),
        &second.pin,
    )?;
    approval.accept_for(assertion, Some(&second.opened.credential_id), now_unix())?;
    let approval = approval.finish(now_unix())?;

    let rotated = signing::rotate_ca_tls(
        &mut vault,
        &first.opened,
        &identity,
        &active_certificate,
        window,
        validity,
    )?;
    let transition_document = rotated.transition.clone();
    let object = TrustUpdateObject::ClientTlsCaTransition(Box::new(rotated.transition));
    campaign
        .covers_authority_object(&object)
        .context("la transition signée ne correspond pas à la campagne approuvée")?;

    // Signed, verified, and covered by the approval. Only now does anything
    // durable move, and the vault moves first: it is the one file on this
    // machine built to hold the successor's private half.
    store::save(path, &vault)?;

    let result = campaign_result(&approval, vec![object.clone()], None);
    let record = prepared::PreparedRotation {
        kind: prepared::PreparedKind::CaTls,
        operation_id: request.operation_id.to_hex(),
        result_token: Some(request.result_token.clone()),
        result,
        transition_path: out.display().to_string(),
        next_ca_tls_epoch: identity.ca_tls_epoch + 1,
        next_ca_tls_certificate: rotated.next_certificate.to_base64(),
        activation_at: window.activation_at,
        not_after: window.not_after,
        submitted: false,
        prepared_at: now,
        // The same public campaign summary the terminal printed above. A
        // window survives its ceremony by days, and whatever resumes it — this
        // binary or the Orion companion — must be able to name what was
        // approved without re-fetching a campaign that is already closed.
        manifest: Some(prepared::manifest_of(
            &campaign,
            &identity,
            &active_certificate,
            window,
        )?),
        adopted: false,
    };
    // Written before the deposit is attempted, and holding the exact bytes of
    // it. A crash after this point is a replay; a crash before it is a
    // ceremony that changed nothing anyone else can see.
    prepared::save(&prepared_path, &record)?;

    // The bare transition, not the tagged `TrustUpdateObject` envelope. The
    // envelope is what Astra's registry consumes; this file is what
    // `heliosd install-client-tls-ca` reads, and that reader refuses an
    // unknown `kind` field — so writing the envelope produced a file the very
    // command printed below could not parse.
    let encoded =
        serde_json::to_vec_pretty(&transition_document).context("encodage de la transition")?;
    std::fs::write(out, &encoded).with_context(|| format!("écriture de {}", out.display()))?;
    println!("transition écrite: {}", out.display());
    println!(
        "ancre entrante   : {}",
        rotated.next_certificate.fingerprint()
    );

    submit_prepared(&channel, &prepared_path, record)?;
    // The file is on *this* machine; the command runs on the gateway. Naming
    // the local path inside the remote command printed an instruction that
    // could not work — the operator has to copy the file across first.
    println!();
    println!("à reporter sur la gateway, en deux temps :");
    println!("  1. copier {} sur la gateway", out.display());
    println!("  2. y lancer : heliosd install-client-tls-ca <le fichier copié>");
    println!(
        "puis, à partir du {} : astra-signer promote-ca-tls",
        horodatage(window.not_after)
    );
    println!(
        "  (l'époque CA-TLS reste à {} pendant tout le recouvrement)",
        identity.ca_tls_epoch
    );
    Ok(())
}

/// Deposits a prepared rotation and records that it landed.
///
/// The record is updated **after** the authority accepts, never before: a
/// machine that marked it submitted and then failed to send would have lost
/// the only trace that anything still had to be sent.
fn submit_prepared(
    client: &astra_operator::campaign::Campaign,
    prepared_path: &Path,
    mut record: prepared::PreparedRotation,
) -> Result<()> {
    let operation = Id16::parse_hex(&record.operation_id)
        .map_err(|error| anyhow::anyhow!("rotation préparée illisible : {error}"))?;
    let token = record
        .result_token
        .as_deref()
        .context("cette rotation préparée ne porte aucun jeton de dépôt : elle ne se rejoue pas")?;
    let state = client.submit(&operation, token, &record.result)?;
    record.submitted = true;
    prepared::save(prepared_path, &record)?;
    println!("état             : {state:?}");
    Ok(())
}

/// Replays the deposit of a rotation the ceremony already committed to (§8.2).
pub(crate) fn resume_rotation(
    path: &Path,
    channel: astra_operator::campaign::Campaign,
) -> Result<()> {
    let prepared_path = prepared::path_beside(path);
    let Some(record) = prepared::load(&prepared_path)? else {
        println!("aucune rotation préparée : rien à reprendre.");
        return Ok(());
    };
    if record.submitted {
        println!(
            "la rotation vers l'époque {} est déjà déposée. La poursuivre par `astra-signer \
             promote-ca-tls` à partir de {}.",
            record.next_ca_tls_epoch,
            horodatage(record.activation_at)
        );
        return Ok(());
    }
    println!(
        "reprise du dépôt : rotation CA-TLS vers l'époque {}, préparée à {}.",
        record.next_ca_tls_epoch,
        horodatage(record.prepared_at)
    );
    println!("transition       : {}", record.transition_path);
    // No security key. The decision was approved when it was signed; this
    // sends bytes that already exist.
    println!("transport        : {}", channel.description());
    submit_prepared(&channel, &prepared_path, record)
}

/// The rotation `promote-ca-tls` would act on, read before any key is asked for.
pub(crate) fn record_to_promote(prepared_path: &Path) -> Result<prepared::PreparedRotation> {
    let Some(record) = prepared::load(prepared_path)? else {
        bail!("aucune rotation CA-TLS en cours : rien à promouvoir.");
    };
    if !record.submitted {
        bail!(
            "la rotation vers l'époque {} n'a jamais été déposée : la promouvoir ici ferait \
             émettre sous une ancre que le domaine ignore. La déposer par `astra-signer \
             resume-rotation`.",
            record.next_ca_tls_epoch
        );
    }
    Ok(record)
}

/// Advances the open `CA-TLS` window by one step (§9.2).
pub(crate) fn promote_ca_tls(path: &Path, transport: Transport) -> Result<()> {
    use astra_operator::vault::CaTlsAdvance;

    // That rotation has not reached the gateway: promoting would destroy the
    // outgoing key while the gateway never installed its successor.
    astra_operator::rotation_journal::ensure_none_in_flight(path)?;
    let mut vault = store::load(path)?;
    let prepared_path = prepared::path_beside(path);
    let record = record_to_promote(&prepared_path)?;

    let now = now_unix();
    println!("rotation CA-TLS  : époque {}.", record.next_ca_tls_epoch);
    println!("activation parc  : {}", horodatage(record.activation_at));
    println!("retrait          : {}", horodatage(record.not_after));

    // One key: this executes a decision two credentials already approved. It
    // opens the vault, it does not authorise anything new.
    let opened = connect_authorized_key(
        &vault,
        transport,
        "Brancher une clé autorisée, puis appuyer sur Entrée.",
    )?;
    let opening = gestures::open_with_authorized_key(opened.key.as_ref(), &vault, &opened.pin)?;
    let advance = signing::advance_ca_tls(&mut vault, &opening, now)?;

    match &advance {
        CaTlsAdvance::Idle => {
            bail!(
                "le coffre ne porte aucune fenêtre CA-TLS ouverte alors qu'une rotation est \
                 enregistrée : les deux fichiers ne décrivent pas le même coffre."
            );
        }
        CaTlsAdvance::Awaiting { at } => {
            println!(
                "rien à faire : l'ancre sortante émet jusqu'à {at}. C'est le recouvrement — la \
                 gateway exige encore la génération {} et refuserait la suivante.",
                record.next_ca_tls_epoch - 1
            );
        }
        CaTlsAdvance::Rotated {
            certificate_fingerprint,
            destroyed_fingerprint,
        } => {
            store::save(path, &vault)?;
            // The hand-off moves with the vault, and only now: every issuance
            // command resolves its anchor and its generation from it, and the
            // gateway advances its own `ca_tls_epoch` at this same second.
            let mut handoff = handoff::DomainHandoff::beside(path, &vault)?;
            handoff.ca_tls_epoch = Some(record.next_ca_tls_epoch);
            handoff.ca_tls_certificate = Some(record.next_ca_tls_certificate.clone());
            handoff::save(&handoff::path_beside(path), &handoff)?;
            prepared::clear(&prepared_path)?;
            println!("ancre en service : {certificate_fingerprint}");
            println!("époque CA-TLS    : {}", record.next_ca_tls_epoch);
            println!("clé privée détruite : {destroyed_fingerprint}");
            println!("fenêtre refermée : une nouvelle rotation peut être ouverte.");
        }
    }
    Ok(())
}
