//! `enroll`: the operator half of NEGOCIATION-DE-CLE-V5 §15.2.

use super::*;

use aether::key_negotiation::{
    decode_request_file, encode_invitation_file, EnrollmentDocument, PqCertificate,
};
use astra_operator::enrollment::{InvitationRegistry, InvitationState};

pub(crate) fn enroll(path: &Path, command: EnrollCommand, transport: Transport) -> Result<()> {
    let registry = InvitationRegistry::default_location()?;
    match command {
        EnrollCommand::Invite {
            gateway_certificate,
            valid_for_hours,
            allow_readmission,
            out,
        } => invite(
            path,
            &registry,
            &gateway_certificate,
            valid_for_hours,
            allow_readmission,
            &out,
            transport,
        ),
        EnrollCommand::Accept {
            request,
            validity_days,
            out_dir,
        } => accept(
            path,
            &registry,
            &request,
            validity_days,
            &out_dir,
            transport,
        ),
        EnrollCommand::SignDocument { draft, out } => {
            sign_document(path, &registry, &draft, &out, transport)
        }
        EnrollCommand::List => list_invitations(&registry),
        EnrollCommand::Revoke { invitation_id } => {
            let id = Id16::parse_hex(invitation_id.trim())
                .context("identifiant d'invitation : 32 caractères hexadécimaux attendus")?;
            registry.revoke(&id, now_unix())?;
            println!("invitation {id} révoquée ; sa clé de preuve est détruite");
            Ok(())
        }
    }
}

fn invite(
    path: &Path,
    registry: &InvitationRegistry,
    gateway_certificate: &Path,
    valid_for_hours: u64,
    allow_readmission: bool,
    out: &Path,
    transport: Transport,
) -> Result<()> {
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let (Some(gateway_key), Some(server_name)) = (
        handoff.gateway_wg_public_key.as_deref(),
        handoff.server_name.as_deref(),
    ) else {
        bail!(
            "le relais de domaine ne nomme encore aucune gateway : lancer d'abord \
             `astra-signer issue-gateway-bootstrap`"
        );
    };
    let gateway_wg_public_key = WireGuardKey::parse(gateway_key)?;
    let certificate: PqCertificate = read_json(gateway_certificate, "la feuille PQ de la gateway")?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&handoff.ca_pq_public_key)?;
    let now = now_unix();
    let not_after = now
        .checked_add(valid_for_hours.saturating_mul(3_600))
        .context("durée de validité hors bornes")?;
    let required = signing::enrollment_credentials(allow_readmission);

    println!("invitation d'enrôlement sous CA-PQ");
    println!("gateway          : {server_name}");
    println!("identité         : {gateway_key}");
    println!("expire           : {}", horodatage(not_after));
    println!(
        "réadmission      : {}",
        if allow_readmission {
            "autorisée (deux credentials distincts)"
        } else {
            "refusée"
        }
    );

    let first = connect_authorized_key(
        &vault,
        transport,
        "Brancher un credential autorisé, puis appuyer sur Entrée.",
    )?;
    let second = if required == 2 {
        eprintln!();
        Some(connect_authorized_key(
            &vault,
            transport,
            "Débrancher celui-ci, brancher le SECOND credential autorisé, puis Entrée.",
        )?)
    } else {
        None
    };
    let mut openings = vec![&first.opened];
    if let Some(second) = &second {
        openings.push(&second.opened);
    }
    let invitation = signing::sign_invitation(
        &vault,
        &openings,
        &signing::InvitationDraft {
            gateway_certificate: &certificate,
            gateway_wg_public_key,
            server_name,
            not_before_unix: now,
            not_after_unix: not_after,
            allow_readmission,
        },
        registry,
        now,
    )?;
    write_private(out, encode_invitation_file(&invitation).as_bytes())?;
    println!("invitation       : {}", invitation.invitation_id);
    println!("écrite           : {}", out.display());
    println!();
    println!("Empreinte CA-PQ à faire confirmer par le client, hors bande :");
    println!(
        "  {}",
        grouped_hex(&ca_pq_public_key.authority_fingerprint().to_hex())
    );
    Ok(())
}

fn accept(
    path: &Path,
    registry: &InvitationRegistry,
    request_path: &Path,
    validity_days: u64,
    out_dir: &Path,
    transport: Transport,
) -> Result<()> {
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let ca_tls_certificate = handoff
        .ca_tls_certificate
        .as_deref()
        .map(DerCertificate::parse)
        .transpose()?
        .context(
            "aucun CA-TLS dans le relais de domaine : lancer d'abord `astra-signer issue-ca-tls`",
        )?;
    let text = read_text(request_path)?;
    let request = decode_request_file(&text).with_context(|| {
        format!(
            "{} n'est pas une demande d'enrôlement",
            request_path.display()
        )
    })?;
    let now = now_unix();
    let not_after = validity_days
        .checked_mul(DAY_SECS)
        .and_then(|seconds| now.checked_add(seconds))
        .context("durée de validité hors bornes")?;

    println!("demande d'enrôlement");
    println!("invitation       : {}", request.invitation_id);
    println!("demande          : {}", request.fingerprint());
    println!("nom demandé      : {}", request.requested_name);
    println!("clé WireGuard    : {}", request.client_wg_public_key);
    println!("feuilles jusqu'à : {}", horodatage(not_after));

    let key = connect_authorized_key(
        &vault,
        transport,
        "Brancher un credential autorisé, puis appuyer sur Entrée.",
    )?;
    let leaves = signing::accept_request(
        &vault,
        &key.opened,
        registry,
        &ca_tls_certificate,
        &request,
        (now.saturating_sub(300), not_after),
        now,
    )?;

    aether::private_file::create_private_dir(out_dir)
        .with_context(|| format!("création de {}", out_dir.display()))?;
    let stem = request.request_id.to_hex();
    let tls_path = out_dir.join(format!("{stem}-client-cert.der"));
    let pq_path = out_dir.join(format!("{stem}-client-pq-cert.json"));
    write_private(&tls_path, leaves.tls_certificate.as_bytes())?;
    let pq = serde_json::to_vec_pretty(&leaves.pq_certificate).context("encodage de la feuille")?;
    write_private(&pq_path, &pq)?;
    println!("feuille TLS      : {}", tls_path.display());
    println!("feuille PQ       : {}", pq_path.display());
    println!();
    println!("Admettre le pair sur la gateway :");
    println!(
        "  heliosd peer add --name {} --public-key {} --certificate {} --pq-certificate {} \
         --minimum-mode ml-kem",
        shell_word(&request.requested_name),
        request.client_wg_public_key,
        shell_word(&tls_path.display().to_string()),
        shell_word(&pq_path.display().to_string()),
    );
    println!("puis préparer le document : helios enroll document --request …");
    Ok(())
}

fn sign_document(
    path: &Path,
    registry: &InvitationRegistry,
    draft_path: &Path,
    out: &Path,
    transport: Transport,
) -> Result<()> {
    let vault = store::load(path)?;
    let draft = EnrollmentDocument::parse(&read_text(draft_path)?).with_context(|| {
        format!(
            "{} n'est pas un brouillon de document v5",
            draft_path.display()
        )
    })?;
    println!("document .orion v5");
    println!("invitation       : {}", draft.invitation_id);
    println!("demande          : {}", draft.request_fingerprint);
    let key = connect_authorized_key(
        &vault,
        transport,
        "Brancher un credential autorisé, puis appuyer sur Entrée.",
    )?;
    let signed = signing::sign_document(&vault, &key.opened, registry, draft)?;
    write_private(out, signed.to_json()?.as_bytes())?;
    println!("écrit            : {}", out.display());
    Ok(())
}

fn list_invitations(registry: &InvitationRegistry) -> Result<()> {
    let records = registry.list(now_unix())?;
    if records.is_empty() {
        println!("aucune invitation dans {}", registry.directory().display());
        return Ok(());
    }
    for record in records {
        let detail = match &record.state {
            InvitationState::Consumed {
                client_wg_public_key,
                ..
            } => format!(" par {client_wg_public_key}"),
            _ => String::new(),
        };
        println!(
            "{}  {:<10}  expire {}  {}{detail}",
            record.invitation.invitation_id,
            record.state.label(),
            horodatage(record.invitation.not_after_unix),
            record.invitation.server_name,
        );
    }
    Ok(())
}

fn read_text(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    String::from_utf8(bytes).with_context(|| format!("{} n'est pas de l'UTF-8", path.display()))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    aether::private_file::write_private_atomic(path, bytes)
        .with_context(|| format!("écriture de {}", path.display()))
}

/// A hexadecimal fingerprint in groups of four, as it is read aloud.
pub(crate) fn grouped_hex(hex: &str) -> String {
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// One POSIX shell word, quoted only when it needs to be.
pub(crate) fn shell_word(value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:+,@".contains(c));
    if plain {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}
