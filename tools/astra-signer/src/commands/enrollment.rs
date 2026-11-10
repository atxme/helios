//! `enroll`: the operator half of NEGOCIATION-DE-CLE-V5 §15.2.

use super::*;

use aether::key_negotiation::{
    decode_request_file, encode_invitation_file, EnrollmentDocument, PqCertificate,
};
use astra_operator::admission::admission_command_line;
use astra_operator::enrollment::{InvitationRegistry, InvitationState};
use astra_operator::overview::grouped_hex;

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
        "  {}",
        admission_command_line(
            &request.requested_name,
            &request.client_wg_public_key.to_string(),
            &tls_path.display().to_string(),
            &pq_path.display().to_string(),
        )
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

/// Reads a request or a draft as Orion reads its documents: a file re-saved by
/// PowerShell on the client's machine arrives in UTF-16.
fn read_text(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    aether::transit_text::decode_transit_text(&bytes)
        .with_context(|| format!("{} n'est pas un texte lisible", path.display()))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    aether::private_file::write_private_atomic(path, bytes)
        .with_context(|| format!("écriture de {}", path.display()))
}

#[cfg(test)]
mod transit_text_tests {
    use super::read_text;

    #[test]
    fn request_reader_accepts_utf16_little_and_big_endian_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let little = directory.path().join("request-le.json");
        let big = directory.path().join("request-be.json");
        let text = "{\"requested_name\":\"étoile\"}";
        let units: Vec<u16> = text.encode_utf16().collect();
        let mut le_bytes = vec![0xFF, 0xFE];
        let mut be_bytes = vec![0xFE, 0xFF];
        for unit in units {
            le_bytes.extend_from_slice(&unit.to_le_bytes());
            be_bytes.extend_from_slice(&unit.to_be_bytes());
        }
        std::fs::write(&little, le_bytes).expect("write little endian text");
        std::fs::write(&big, be_bytes).expect("write big endian text");

        assert_eq!(read_text(&little).expect("decode UTF-16LE"), text);
        assert_eq!(read_text(&big).expect("decode UTF-16BE"), text);
    }

    #[test]
    fn request_reader_rejects_odd_and_invalid_utf16_before_document_parsing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let odd = directory.path().join("odd.json");
        let invalid = directory.path().join("invalid.json");
        std::fs::write(&odd, [0xFF, 0xFE, 0x7B]).expect("write odd UTF-16");
        std::fs::write(&invalid, [0xFF, 0xFE, 0x00, 0xD8]).expect("write unpaired surrogate");

        assert!(read_text(&odd).is_err());
        assert!(read_text(&invalid).is_err());
    }
}

#[cfg(test)]
mod private_output_tests {
    use super::{read_text, write_private};

    #[test]
    fn private_writer_creates_and_replaces_the_complete_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("invitation.json");

        write_private(&path, b"first complete document").expect("initial private write");
        assert_eq!(
            std::fs::read(&path).expect("read initial document"),
            b"first complete document"
        );
        write_private(&path, b"second complete document").expect("replace private file");
        assert_eq!(
            std::fs::read(&path).expect("read replacement"),
            b"second complete document"
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("list output directory")
                .count(),
            1,
            "temporary files are removed after publication"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("output metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode, 0o600,
                "enrollment output must be private from creation"
            );
        }
    }

    #[test]
    fn private_writer_rejects_symlinks_and_missing_parent_without_losing_existing_data() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target.json");
        std::fs::write(&target, b"preserve this").expect("write target");

        #[cfg(unix)]
        {
            let link = directory.path().join("link.json");
            std::os::unix::fs::symlink(&target, &link).expect("create symlink");
            assert!(write_private(&link, b"must not follow symlink").is_err());
            assert_eq!(
                std::fs::read(&target).expect("read target"),
                b"preserve this"
            );
            assert!(std::fs::symlink_metadata(&link)
                .expect("inspect link")
                .file_type()
                .is_symlink());
        }

        let missing_parent = directory.path().join("missing").join("output.json");
        assert!(write_private(&missing_parent, b"no parent").is_err());
        assert_eq!(
            std::fs::read(&target).expect("read target"),
            b"preserve this"
        );
        #[cfg(unix)]
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("list output directory")
                .count(),
            2,
            "failed writes leave no staging file"
        );
        #[cfg(not(unix))]
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("list output directory")
                .count(),
            1,
            "failed writes leave no staging file"
        );
    }

    #[test]
    fn request_reader_reports_missing_and_non_text_files_with_path_context() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing = directory.path().join("missing.request");
        let invalid = directory.path().join("invalid.request");
        std::fs::write(&invalid, [0xFF, 0xFE, 0x00, 0xD8]).expect("write invalid UTF-16");

        let missing_error = read_text(&missing).expect_err("missing requests are refused");
        assert!(format!("{missing_error:#}").contains("missing.request"));
        let invalid_error = read_text(&invalid).expect_err("invalid UTF-16 is refused");
        assert!(format!("{invalid_error:#}").contains("invalid.request"));
    }
}
