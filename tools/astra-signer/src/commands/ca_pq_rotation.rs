//! Rotating the `CA-PQ` anchor, and the journal that makes an interrupted
//! rotation resumable.

use super::*;

// Prepared before any of the four files of a CA-PQ rotation is replaced.
//
// A filesystem cannot atomically rename four unrelated destinations. This
// private journal makes the operation replayable instead: after it exists,
// every destination is an idempotent projection of these exact bytes. A crash
// can therefore leave an old or new value at each path, never an unrecoverable
// rotation whose outgoing private key vanished before its public transition was
// written.
//
// The format lives in `rotation_journal`, which also adopts such a file into
// Orion's journal: an unapplied vault must not depend on which of the two resumes
// it.
use astra_operator::rotation_journal::{
    self, LegacyCaPqJournal as CaPqRotationJournal, LEGACY_CA_PQ_JOURNAL_VERSION,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn rotate_ca_pq(
    path: &Path,
    out: &Path,
    prepare_days: u64,
    overlap_days: u64,
    authority_url: Option<&str>,
    operation_id: Option<&str>,
    origin: Option<&str>,
    transport: Transport,
) -> Result<()> {
    rotation_journal::ensure_ca_pq_may_run(path)?;
    let output_path = absolute_path(out)?;
    let journal_path = rotation_journal::legacy_ca_pq_path_beside(path);
    if journal_path.exists() {
        let journal: CaPqRotationJournal =
            documents::read(&journal_path).context("reprise de la rotation CA-PQ préparée")?;
        if journal.output_path != output_path {
            bail!(
                "une rotation CA-PQ interrompue doit être reprise avec --out {}",
                journal.output_path.display()
            );
        }
        journal.validate()?;
        apply_ca_pq_rotation(path, &journal)?;
        // The adoption first: a stop between the two leaves this file, from which
        // this command and an adoption both still recover.
        rotation_journal::clear(&rotation_journal::path_beside(path))?;
        std::fs::remove_file(&journal_path)
            .with_context(|| format!("suppression de {}", journal_path.display()))?;
        print_ca_pq_rotation(&journal);
        println!("reprise           : rotation préparée terminée sans nouvelle cérémonie");
        return Ok(());
    }

    let mut vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;
    let current_ca_public_key = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())?;
    let now = now_unix();
    let activation_at = now
        .checked_add(
            prepare_days
                .checked_mul(DAY_SECS)
                .context("délai hors bornes")?,
        )
        .context("délai hors bornes")?;
    let window = TransitionWindow::new(
        now,
        activation_at,
        activation_at
            .checked_add(
                overlap_days
                    .checked_mul(DAY_SECS)
                    .context("délai hors bornes")?,
            )
            .context("délai hors bornes")?,
    )?;

    let online = match (authority_url, operation_id) {
        (Some(url), Some(id)) => {
            let operation =
                Id16::parse_hex(id).map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
            let client = astra_operator::origin::Origin::new(url)?;
            let request = origin_client_fetch(&client, &operation)?;
            handoff::verify_campaign_request(&handoff, &vault, &request, url, now_unix())?;
            let campaign = request.campaign.as_ref().clone();
            if !campaign.scope.rotates_authority() {
                bail!(
                    "cette campagne ne fait tourner aucune ancre : elle s'approuve par \
                     `astra-signer approve-campaign`. Rien n'a été signé."
                );
            }
            // The campaign was resolved from Astra's registry. If it names
            // another anchor than the one this vault holds, the two halves of
            // the domain disagree about what is current — and a rotation is
            // the last thing that should reconcile them.
            campaign
                .covers_authority_object(&anchor_probe(&identity, &current_ca_public_key, window)?)
                .context(
                    "la campagne ne nomme pas l'ancre que ce coffre détient : l'autorité et le \
                     compagnon ne décrivent pas le même domaine",
                )?;
            Some((client, request, campaign))
        }
        (None, None) => None,
        _ => bail!("--authority-url et --operation-id vont ensemble"),
    };

    println!(
        "rotation de CA-PQ : l'ancre du domaine change. Tout objet signé sous l'ancienne cesse \
         de vérifier au bout du recouvrement."
    );
    println!("préparation      : {prepare_days} jour(s)");
    println!("recouvrement     : {overlap_days} jour(s)");
    if let Some((_, _, campaign)) = &online {
        println!("campagne         : {}", campaign.campaign_id.to_hex());
        println!("empreinte        : {}", campaign.fingerprint());
        println!("motif            : {}", campaign.reason);
        println!("demandée par     : {}", campaign.requested_by);
    } else {
        println!(
            "hors campagne    : la transition sera écrite dans un fichier, et aucune autorité ne \
             la distribuera"
        );
    }

    let registry_path = credentials::path_beside(path);
    let previous = credentials::load(&registry_path)?;
    let approval_origin = origin
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://{}", vault.rp_id));
    let mut approval_session = match &online {
        Some((_, _, campaign)) => {
            let registry = previous.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "aucun document de credentials : l'émettre par `astra-signer bindings` avant \
                     d'exécuter une campagne d'autorité"
                )
            })?;
            Some(signing::CampaignApprovalSession::new(
                campaign,
                registry,
                &identity,
                &current_ca_public_key,
                &vault.rp_id,
                &approval_origin,
                now,
            )?)
        }
        None => None,
    };

    // Two distinct keys, plugged one after the other. Both are proven to open
    // the vault before anything is generated: an operator whose second key
    // does not work should find out now, and not after the anchor has moved.
    //
    // Each key stays connected for both of its jobs — the campaign assertion
    // and the key-slot opening. Asking for four plug cycles where two suffice
    // is how a ceremony gets abandoned halfway.
    let first = connect_authorized_key(
        &vault,
        transport,
        "Brancher la PREMIÈRE clé autorisée, puis appuyer sur Entrée.",
    )?;
    if let Some(session) = approval_session.as_mut() {
        let offered = session.offered_credentials();
        let assertion = first.key.approve(
            session.webauthn_rp_id(),
            &offered,
            session.client_data_json(),
            &first.pin,
        )?;
        session.accept_for(assertion, Some(&first.opened.credential_id), now_unix())?;
    }
    eprintln!();
    let second = connect_authorized_key(
        &vault,
        transport,
        "Débrancher celle-ci, brancher la SECONDE clé autorisée, puis Entrée.",
    )?;
    if let Some(session) = approval_session.as_mut() {
        let offered = session.offered_credentials();
        let assertion = second.key.approve(
            session.webauthn_rp_id(),
            &offered,
            session.client_data_json(),
            &second.pin,
        )?;
        session.accept_for(assertion, Some(&second.opened.credential_id), now_unix())?;
    }

    // The approval is taken **before** the anchor moves, under the credential
    // document the outgoing anchor signed — which is also the one Astra holds.
    let approval = approval_session
        .map(|session| session.finish(now_unix()))
        .transpose()?;

    let rotated = signing::rotate_ca_pq(
        &mut vault,
        &[&first.opened, &second.opened],
        &identity,
        previous.as_ref(),
        window,
        now,
    )?;
    let mut next_handoff = handoff;
    next_handoff.adopt(&vault)?;
    next_handoff.ca_epoch = Some(identity.ca_epoch + 1);
    let journal = CaPqRotationJournal {
        format_version: LEGACY_CA_PQ_JOURNAL_VERSION,
        output_path,
        current_ca_public_key,
        vault,
        bindings: rotated.bindings,
        transition: rotated.transition,
        handoff: next_handoff,
    };
    journal.validate()?;

    if let (Some((client, request, _)), Some(approval)) = (&online, &approval) {
        let result = campaign_result(
            approval,
            vec![
                aether::certificates::transport::TrustUpdateObject::CaTransition(Box::new(
                    journal.transition.clone(),
                )),
            ],
            Some(Box::new(journal.bindings.clone())),
        );
        let state = client.submit(&request.operation_id, &request.result_token, &result)?;
        println!("opération        : {}", request.operation_id.to_hex());
        println!("état             : {state:?}");
    }

    documents::write(&journal_path, &journal)
        .context("préparation durable de la rotation CA-PQ")?;
    apply_ca_pq_rotation(path, &journal)?;
    std::fs::remove_file(&journal_path)
        .with_context(|| format!("suppression de {}", journal_path.display()))?;

    print_ca_pq_rotation(&journal);
    println!("les key-slots n'ont pas bougé : chaque clé qui ouvrait le coffre l'ouvre encore");
    if online.is_some() {
        println!(
            "l'autorité distribue la transition aux pairs qui reviennent avant l'activation ; \
             au-delà, un pair en retard se répare par l'opérateur"
        );
    }
    Ok(())
}

/// The object a campaign target is compared against, before anything signs.
///
/// A placeholder transition carrying the outgoing epoch and fingerprint: what
/// [`AstraRotationCampaign::covers_authority_object`](aether::certificates::status::AstraRotationCampaign::covers_authority_object) reads is exactly those
/// two values, so comparing here costs no signature and answers the only
/// question that matters before a key is touched — does the authority name the
/// anchor this vault holds.
fn anchor_probe(
    identity: &signing::DomainIdentity,
    current: &MlDsa87PublicKey,
    window: TransitionWindow,
) -> Result<aether::certificates::transport::TrustUpdateObject> {
    use aether::certificates::authority::CaTransition;

    Ok(
        aether::certificates::transport::TrustUpdateObject::CaTransition(Box::new(CaTransition {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: identity.trust_domain_id,
            current_ca_epoch: identity.ca_epoch,
            next_ca_epoch: identity.ca_epoch + 1,
            current_ca_fingerprint: current.authority_fingerprint(),
            next_ca_public_key: current.clone(),
            next_ca_fingerprint: current.authority_fingerprint(),
            window,
            current_ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            next_ca_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        })),
    )
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("lecture du répertoire courant")?
            .join(path))
    }
}

fn apply_ca_pq_rotation(vault_path: &Path, journal: &CaPqRotationJournal) -> Result<()> {
    // Every write is itself atomic. The journal remains until all four have
    // landed, so any prefix of this sequence is safely replayed.
    store::save(vault_path, &journal.vault)?;
    credentials::save(&credentials::path_beside(vault_path), &journal.bindings)?;
    documents::write(&journal.output_path, &journal.transition)?;
    handoff::save(&handoff::path_beside(vault_path), &journal.handoff)?;
    Ok(())
}

fn print_ca_pq_rotation(journal: &CaPqRotationJournal) {
    println!("transition       : {}", journal.output_path.display());
    println!("époque CA-PQ     : {}", journal.transition.next_ca_epoch);
    println!(
        "CA-PQ (publique) : {}",
        journal.transition.next_ca_public_key.to_base64()
    );
    println!(
        "CA-PQ empreinte  : {}",
        journal
            .transition
            .next_ca_public_key
            .authority_fingerprint()
    );
    println!(
        "credentials      : époque {}",
        journal.bindings.credential_registry_epoch
    );
}
