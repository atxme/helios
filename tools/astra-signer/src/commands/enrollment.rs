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

#[cfg(test)]
mod command_preflight_tests {
    use super::*;
    use aether::certificates::encoding::{DerCertificate, TrustDomainId, WireGuardKey};
    use aether::key_negotiation::{
        encode_request_file, EnrollmentRequest, ENROLLMENT_FORMAT_VERSION,
        ENROLLMENT_PROTOCOL_VERSION,
    };
    use astra_operator::vault::{
        AuthoritySecrets, AuthorityVault, SlotEnrolment, SlotRole, SlotSecret,
    };
    use base64::Engine as _;

    struct Fixture {
        _directory: tempfile::TempDir,
        vault_path: PathBuf,
        registry: InvitationRegistry,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("temporary directory");
            let vault_path = directory.path().join("authority-vault.json");
            let (pq_private, pq_public) =
                aether::certificates::encoding::generate_ml_dsa_87_keypair()
                    .expect("CA-PQ keypair");
            let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
            let trust_domain_id = TrustDomainId::new([0x31; 16]).expect("domain id");
            let vault = AuthorityVault::create(
                trust_domain_id,
                "astra.example",
                astra_operator::vault::draw_salt().expect("vault salt"),
                &AuthoritySecrets {
                    ca_pq_private_key: encode(&pq_private),
                    ca_pq_public_key: pq_public.to_base64(),
                    ca_tls_private_key: encode(b"test-only TLS private key"),
                    retained_ca_tls: None,
                    retained_outgoing_ca_pq: None,
                },
                SlotEnrolment {
                    role: SlotRole::Primary,
                    label: "test slot".into(),
                    credential_id: vec![0x51; 32],
                    credential_public_key: vec![0xa5, 0x01],
                    aaguid: [0; 16],
                    enrolled_at: 1,
                },
                &SlotSecret::new(vec![0x61; 32]),
                1,
            )
            .expect("test vault");
            astra_operator::store::save(&vault_path, &vault).expect("save vault");
            let registry = InvitationRegistry::at(directory.path().join("invitations"));
            Self {
                _directory: directory,
                vault_path,
                registry,
            }
        }

        fn write_handoff(&self, gateway: bool, ca_tls: bool) {
            let vault = store::load(&self.vault_path).expect("load vault");
            let mut handoff = handoff::DomainHandoff::of(&vault).expect("handoff");
            if gateway {
                handoff.gateway_wg_public_key =
                    Some(WireGuardKey::from_bytes([0x42; 32]).to_base64());
                handoff.server_name = Some("gateway.example".into());
            }
            if ca_tls {
                handoff.ca_tls_certificate = Some(
                    DerCertificate::new(vec![0x30, 0x00])
                        .expect("CA-TLS bytes")
                        .to_base64(),
                );
            }
            handoff::save(&handoff::path_beside(&self.vault_path), &handoff).expect("save handoff");
        }

        fn request_file(&self) -> PathBuf {
            let (_, public) = aether::certificates::encoding::generate_ml_dsa_87_keypair()
                .expect("client public key");
            let request = EnrollmentRequest {
                format_version: ENROLLMENT_FORMAT_VERSION,
                protocol_version: ENROLLMENT_PROTOCOL_VERSION,
                invitation_id: Id16::new([0x61; 16]).expect("invitation id"),
                invitation_fingerprint: aether::certificates::encoding::Fingerprint::of(
                    b"invitation",
                ),
                request_id: Id16::new([0x62; 16]).expect("request id"),
                timestamp_unix: 1,
                requested_name: "client.example".into(),
                client_wg_public_key: WireGuardKey::from_bytes([0x71; 32]),
                tls_csr: DerCertificate::new(vec![0x30, 0x00]).expect("CSR bytes"),
                client_ml_dsa_87_public_key: public,
                wireguard_proof: [0x73; 32],
                client_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            };
            let path = self._directory.path().join("request.helios-request");
            std::fs::write(&path, encode_request_file(&request)).expect("write request");
            path
        }

        fn out_dir(&self) -> PathBuf {
            self._directory.path().join("leaves")
        }
    }

    #[test]
    fn invite_refuses_an_uninitialized_gateway_before_reading_its_certificate() {
        let fixture = Fixture::new();
        let missing_certificate = fixture._directory.path().join("missing-certificate.json");
        let out = fixture._directory.path().join("invitation.helios-invite");

        let error = invite(
            &fixture.vault_path,
            &fixture.registry,
            &missing_certificate,
            1,
            false,
            &out,
            Transport::Hid,
        )
        .expect_err("domain without a gateway");

        assert!(format!("{error:#}").contains("ne nomme encore aucune gateway"));
        assert!(!out.exists());
        assert!(!fixture.registry.directory().exists());
    }

    #[test]
    fn invite_rejects_a_malformed_gateway_leaf_before_key_access_or_registry_write() {
        let fixture = Fixture::new();
        fixture.write_handoff(true, false);
        let certificate = fixture._directory.path().join("gateway-pq.json");
        let out = fixture._directory.path().join("invitation.helios-invite");
        std::fs::write(&certificate, b"{not-json").expect("write malformed leaf");

        let error = invite(
            &fixture.vault_path,
            &fixture.registry,
            &certificate,
            1,
            false,
            &out,
            Transport::Hid,
        )
        .expect_err("invalid gateway leaf");

        assert!(format!("{error:#}").contains("gateway-pq.json"));
        assert!(!out.exists());
        assert!(!fixture.registry.directory().exists());
    }

    #[test]
    fn accept_requires_a_client_ca_before_reading_or_emitting_anything() {
        let fixture = Fixture::new();
        let missing_request = fixture._directory.path().join("missing-request");

        let error = accept(
            &fixture.vault_path,
            &fixture.registry,
            &missing_request,
            30,
            &fixture.out_dir(),
            Transport::Hid,
        )
        .expect_err("missing CA-TLS anchor");

        assert!(format!("{error:#}").contains("aucun CA-TLS dans le relais"));
        assert!(!format!("{error:#}").contains("missing-request"));
        assert!(!fixture.out_dir().exists());
    }

    #[test]
    fn accept_rejects_invalid_transit_text_before_key_access() {
        let fixture = Fixture::new();
        fixture.write_handoff(false, true);
        let request = fixture._directory.path().join("invalid-request");
        std::fs::write(&request, [0xFF, 0xFE, 0x00, 0xD8]).expect("write invalid UTF-16");

        let error = accept(
            &fixture.vault_path,
            &fixture.registry,
            &request,
            30,
            &fixture.out_dir(),
            Transport::Hid,
        )
        .expect_err("invalid request text");

        assert!(format!("{error:#}").contains("n'est pas un texte lisible"));
        assert!(format!("{error:#}").contains("invalid-request"));
        assert!(!fixture.out_dir().exists());
    }

    #[test]
    fn accept_rejects_unrepresentable_validity_after_parsing_public_request_but_before_key() {
        let fixture = Fixture::new();
        fixture.write_handoff(false, true);
        let request = fixture.request_file();

        let error = accept(
            &fixture.vault_path,
            &fixture.registry,
            &request,
            u64::MAX,
            &fixture.out_dir(),
            Transport::Hid,
        )
        .expect_err("unrepresentable leaf validity");

        assert!(error.to_string().contains("durée de validité hors bornes"));
        assert!(!fixture.out_dir().exists());
    }

    #[test]
    fn sign_document_rejects_invalid_drafts_before_operator_key_access() {
        let fixture = Fixture::new();
        let draft = fixture._directory.path().join("invalid-draft.orion");
        let out = fixture._directory.path().join("signed.orion");
        std::fs::write(&draft, b"not a v5 enrollment document").expect("write draft");

        let error = sign_document(
            &fixture.vault_path,
            &fixture.registry,
            &draft,
            &out,
            Transport::Hid,
        )
        .expect_err("malformed document draft");

        assert!(format!("{error:#}").contains("n'est pas un brouillon de document v5"));
        assert!(!out.exists());
    }

    #[test]
    fn listing_an_empty_operator_registry_is_a_valid_noop() {
        let fixture = Fixture::new();

        list_invitations(&fixture.registry).expect("empty registry listing");

        assert!(!fixture.registry.directory().exists());
    }
}
