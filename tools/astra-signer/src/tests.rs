use super::*;
use aether::certificates::authority::ClientTlsCaTransition;
use aether::certificates::encoding::{
    DerCertificate, Fingerprint, MlDsa87Signature, TrustDomainId,
};
use aether::certificates::transport::TrustUpdateObject;
use aether::certificates::window::TransitionWindow;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;

fn transition() -> ClientTlsCaTransition {
    ClientTlsCaTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        current_ca_tls_epoch: 1,
        next_ca_tls_epoch: 2,
        active_client_tls_ca_fingerprint: Fingerprint::of(b"ancre sortante"),
        next_client_tls_ca_certificate: DerCertificate::new(vec![0x30, 0x03, 0x02, 0x01, 0x00])
            .expect("certificate"),
        window: TransitionWindow {
            not_before: 10,
            activation_at: 20,
            not_after: 30,
        },
        ca_pq_signature: MlDsa87Signature::new(vec![7; 4627]).expect("signature"),
    }
}

/// The operator's copy is what `heliosd install-*` reads, so it carries no
/// routing envelope.
///
/// The tag `TrustUpdateObject` adds is how Astra's registry tells one
/// decision from another; the gateway readers take one concrete type and
/// refuse an unknown `kind`. Writing the envelope produced a file the very
/// command this companion printed could not parse — which is the failure
/// this test exists to keep from coming back.
#[test]
fn the_file_written_for_the_gateway_carries_no_routing_envelope() {
    let object = TrustUpdateObject::ClientTlsCaTransition(Box::new(transition()));
    let encoded = document_nu(&object).expect("encoding");

    let value: serde_json::Value = serde_json::from_slice(&encoded).expect("readable JSON");
    assert!(
        value.get("kind").is_none(),
        "the gateway reader refuses an unknown `kind` field"
    );
    let parsed: ClientTlsCaTransition =
        serde_json::from_slice(&encoded).expect("the gateway must be able to read this file");
    assert_eq!(parsed.next_ca_tls_epoch, 2);
}

/// A rotation window is a date an operator diaries, not a raw counter.
#[test]
fn a_window_bound_is_printed_as_a_date() {
    assert_eq!(horodatage(1_791_792_171), "2026-10-12 10:02 CEST");
    // Out of range is named rather than silently rendered as an epoch.
    assert!(horodatage(u64::MAX).contains("hors plage"));
}

/// The five enrollment gestures parse as an operator types them, and an
/// invitation cannot outlive the 24 hours §15.2 allows.
#[test]
fn enroll_subcommands_parse() {
    use clap::Parser as _;

    for line in [
        "astra-signer enroll invite --gateway-certificate gw.json --out a.helios-invite",
        "astra-signer enroll invite --gateway-certificate gw.json --valid-for-hours 2 \
         --allow-readmission --out a.helios-invite",
        "astra-signer enroll accept --request a.helios-request --out-dir leaves",
        "astra-signer enroll sign-document --draft draft.json --out a.orion",
        "astra-signer enroll list",
        "astra-signer enroll revoke 01010101010101010101010101010101",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_ok(), "{line}");
    }
    for refused in [
        "astra-signer enroll invite --gateway-certificate gw.json --valid-for-hours 25 --out a",
        "astra-signer enroll invite --gateway-certificate gw.json --valid-for-hours 0 --out a",
        "astra-signer enroll accept --request a.helios-request",
    ] {
        let words: Vec<&str> = refused.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_err(), "{refused}");
    }
}

/// A rotation Orion is carrying to the gateway has a journal beside the vault,
/// and a second one signed over it would name the same outgoing anchor. Refused
/// before anything else is read, so a damaged journal refuses as well.
#[test]
fn neither_rotation_opens_over_a_rotation_journal() {
    let directory = tempfile::tempdir().expect("dir");
    let vault = directory.path().join("authority-vault.json");
    let out = directory.path().join("transition.json");
    std::fs::write(
        astra_operator::rotation_journal::path_beside(&vault),
        b"illisible",
    )
    .expect("journal");

    let ca_pq = commands::rotate_ca_pq(&vault, &out, 7, 30, None, None, None, Transport::default())
        .expect_err("refused");
    assert!(
        format!("{ca_pq:#}").contains("rotation est en cours"),
        "{ca_pq:#}"
    );

    let channel = astra_operator::campaign::Campaign::select(None, Some("http://127.0.0.1:9"))
        .expect("channel");
    let ca_tls = commands::rotate_ca_tls(
        &vault,
        channel,
        &"0".repeat(32),
        None,
        &out,
        (7, 30, 1825),
        Transport::default(),
    )
    .expect_err("refused");
    assert!(
        format!("{ca_tls:#}").contains("rotation est en cours"),
        "{ca_tls:#}"
    );
}

/// What Orion leaves beside the vault once a client TLS rotation has landed: the
/// deposit is behind it, so no token.
fn record_left_by_orion(path: &Path) -> astra_operator::prepared::PreparedRotation {
    use aether::certificates::encoding::Id16;
    use aether::certificates::status::{AstraSignerResult, CampaignApproval};

    let record = astra_operator::prepared::PreparedRotation {
        kind: astra_operator::prepared::PreparedKind::CaTls,
        operation_id: "01".repeat(16),
        result_token: None,
        result: AstraSignerResult {
            format_version: CERTIFICATE_FORMAT_VERSION,
            approval: Box::new(CampaignApproval {
                campaign_id: Id16::new([3; 16]).expect("id"),
                campaign_fingerprint: Fingerprint::of(b"campagne"),
                required_credentials: 2,
                approved_at: 9,
                approvals: Vec::new(),
            }),
            objects: Vec::new(),
            credential_registry: None,
            issuer_authorization: None,
        },
        transition_path: String::new(),
        next_ca_tls_epoch: 2,
        next_ca_tls_certificate: "REVS".into(),
        activation_at: 100,
        not_after: 200,
        submitted: true,
        prepared_at: 10,
        manifest: None,
        adopted: true,
    };
    astra_operator::prepared::save(path, &record).expect("record");
    record
}

/// The command reads what Orion left, and goes on to ask for a key.
#[test]
fn promote_reads_the_record_orion_leaves() {
    let directory = tempfile::tempdir().expect("dir");
    let path = astra_operator::prepared::path_beside(&directory.path().join("vault.json"));
    let record = record_left_by_orion(&path);

    assert_eq!(commands::record_to_promote(&path).expect("read"), record);
}

/// A journal in flight is a rotation that has not reached the gateway: promoting
/// would destroy the outgoing key while it never installed the successor. Refused
/// by presence and before any key, with the record and the file as they were.
#[test]
fn promote_is_refused_while_a_rotation_journal_is_in_flight() {
    let directory = tempfile::tempdir().expect("dir");
    let vault = directory.path().join("vault.json");
    let record_path = astra_operator::prepared::path_beside(&vault);
    let record = record_left_by_orion(&record_path);
    let journal = astra_operator::rotation_journal::path_beside(&vault);
    std::fs::write(&journal, b"illisible").expect("journal");

    let refused = commands::promote_ca_tls(&vault, Transport::default()).expect_err("refused");

    assert!(
        format!("{refused:#}").contains("une rotation est en cours"),
        "{refused:#}"
    );
    assert_eq!(
        astra_operator::prepared::load(&record_path).expect("read"),
        Some(record)
    );
    assert_eq!(std::fs::read(&journal).expect("journal"), b"illisible");
}

/// Nothing to deposit again, so nothing to ask of the channel, which is out of
/// reach here. A record that does want a deposit and holds no token says so.
#[test]
fn resume_has_nothing_to_replay_from_a_record_with_no_token() {
    let directory = tempfile::tempdir().expect("dir");
    let vault = directory.path().join("vault.json");
    let path = astra_operator::prepared::path_beside(&vault);
    let record = record_left_by_orion(&path);
    let channel = || {
        astra_operator::campaign::Campaign::select(None, Some("http://127.0.0.1:9"))
            .expect("channel")
    };
    commands::resume_rotation(&vault, channel()).expect("already deposited");

    astra_operator::prepared::save(
        &path,
        &astra_operator::prepared::PreparedRotation {
            submitted: false,
            ..record
        },
    )
    .expect("record");
    let refused = commands::resume_rotation(&vault, channel()).expect_err("refused");
    assert!(format!("{refused:#}").contains("jeton"), "{refused:#}");
}

/// A real rotation, signed with slot secrets in place of a security key: this
/// binary's own journal, in the format the operator library adopts.
fn interrupted_ca_pq_rotation(
    directory: &Path,
) -> (
    PathBuf,
    PathBuf,
    astra_operator::rotation_journal::LegacyCaPqJournal,
) {
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, WireGuardKey};
    use astra_operator::vault::{draw_salt, AuthoritySecrets, SlotEnrolment, SlotSecret};
    use base64::Engine as _;

    let domain = TrustDomainId::new([1; 16]).expect("domain");
    let (private, public) = generate_ml_dsa_87_keypair().expect("keys");
    let encoder = base64::engine::general_purpose::STANDARD;
    let secrets = AuthoritySecrets {
        ca_pq_private_key: encoder.encode(&*private),
        ca_pq_public_key: public.to_base64(),
        ca_tls_private_key: encoder.encode(b"tls"),
        retained_ca_tls: None,
    };
    let enrolment = |seed: u8, role| SlotEnrolment {
        role,
        label: format!("clé {seed}"),
        credential_id: vec![seed; 64],
        // An Ed25519 COSE key: the registry parses it, nothing here verifies with it.
        credential_public_key: [
            &[0xA4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20][..],
            &[seed; 32],
        ]
        .concat(),
        aaguid: [seed; 16],
        enrolled_at: 1_000,
    };
    let secret = |seed: u8| SlotSecret::new(vec![seed; 32]);
    let mut vault = AuthorityVault::create(
        domain,
        "astra.helios.test",
        draw_salt().expect("salt"),
        &secrets,
        enrolment(1, SlotRole::Primary),
        &secret(1),
        1_000,
    )
    .expect("vault");
    vault
        .add_slot(
            &[1; 64],
            &secret(1),
            enrolment(2, SlotRole::Recovery),
            &secret(2),
        )
        .expect("second slot");

    let path = directory.join("authority-vault.json");
    store::save(&path, &vault).expect("vault");
    let mut relay = handoff::DomainHandoff::of(&vault).expect("relay");
    relay.gateway_wg_public_key = Some(WireGuardKey::from_bytes([9; 32]).to_base64());
    relay.server_name = Some("gateway.helios.test".into());
    handoff::save(&handoff::path_beside(&path), &relay).expect("relay");
    let identity = handoff::identity_of(&relay).expect("identity");

    let first = Opened {
        credential_id: vec![1; 64],
        secret: secret(1),
    };
    let second = Opened {
        credential_id: vec![2; 64],
        secret: secret(2),
    };
    let window = TransitionWindow::new(2_000, 3_000, 4_000).expect("window");
    let rotated = signing::rotate_ca_pq(
        &mut vault,
        &[&first, &second],
        &identity,
        None,
        window,
        2_000,
    )
    .expect("rotated");
    relay.adopt(&vault).expect("adopt");
    relay.ca_epoch = Some(identity.ca_epoch + 1);
    let out = directory.join("transition.json");
    let journal = astra_operator::rotation_journal::LegacyCaPqJournal {
        format_version: astra_operator::rotation_journal::LEGACY_CA_PQ_JOURNAL_VERSION,
        output_path: out.clone(),
        current_ca_public_key: public,
        vault,
        bindings: rotated.bindings,
        transition: rotated.transition,
        handoff: relay,
    };
    documents::write(
        &astra_operator::rotation_journal::legacy_ca_pq_path_beside(&path),
        &journal,
    )
    .expect("journal");
    (path, out, journal)
}

fn resume_ca_pq(path: &Path, out: &Path) -> Result<()> {
    commands::rotate_ca_pq(path, out, 7, 30, None, None, None, Transport::default())
}

/// The way back for an offline rotation, which Orion refuses: while Astra has
/// not confirmed the adoption, the command that wrote the file may finish it, and
/// it leaves neither file behind.
#[test]
fn the_ca_pq_command_finishes_a_rotation_astra_has_not_confirmed() {
    let directory = tempfile::tempdir().expect("dir");
    let (path, out, journal) = interrupted_ca_pq_rotation(directory.path());
    let journal_path = astra_operator::rotation_journal::path_beside(&path);
    let legacy_path = astra_operator::rotation_journal::legacy_ca_pq_path_beside(&path);
    astra_operator::rotation_journal::adopt_legacy(&path)
        .expect("adopted")
        .expect("a journal");
    assert!(journal_path.exists());

    resume_ca_pq(&path, &out).expect("resumed");

    assert!(!journal_path.exists());
    assert!(!legacy_path.exists());
    assert!(out.exists());
    assert_eq!(store::load(&path).expect("vault"), journal.vault);
}

/// Past the apply the journal carries the rotation, and the command stays out.
#[test]
fn the_ca_pq_command_refuses_a_journal_astra_has_confirmed() {
    let directory = tempfile::tempdir().expect("dir");
    let (path, out, journal) = interrupted_ca_pq_rotation(directory.path());
    let legacy_path = astra_operator::rotation_journal::legacy_ca_pq_path_beside(&path);
    let mut adopted = astra_operator::rotation_journal::adopt_legacy(&path)
        .expect("adopted")
        .expect("a journal");
    astra_operator::rotation_journal::apply_local(&path, &mut adopted).expect("applied");
    documents::write(&legacy_path, &journal).expect("left behind by a stop");

    let refusal = resume_ca_pq(&path, &out).expect_err("refused");

    assert!(
        format!("{refusal:#}").contains("rotation est en cours"),
        "{refusal:#}"
    );
    assert!(!out.exists());
}

/// The exception is for that command alone: the CA-TLS one still refuses.
#[test]
fn the_ca_tls_command_refuses_an_unconfirmed_adoption_too() {
    let directory = tempfile::tempdir().expect("dir");
    let (path, out, _) = interrupted_ca_pq_rotation(directory.path());
    astra_operator::rotation_journal::adopt_legacy(&path)
        .expect("adopted")
        .expect("a journal");
    let channel = astra_operator::campaign::Campaign::select(None, Some("http://127.0.0.1:9"))
        .expect("channel");

    let refusal = commands::rotate_ca_tls(
        &path,
        channel,
        &"0".repeat(32),
        None,
        &out,
        (7, 30, 1825),
        Transport::default(),
    )
    .expect_err("refused");

    assert!(
        format!("{refusal:#}").contains("rotation est en cours"),
        "{refusal:#}"
    );
}

/// `apply_local` overwrites the vault with the one signed before the journal: a key
/// added, removed or marked meanwhile would be undone, and a removed key would get
/// its access back. Refused by presence, before any key, with the vault as it was.
#[test]
fn key_slot_gestures_are_refused_while_a_rotation_journal_is_in_flight() {
    let directory = tempfile::tempdir().expect("dir");
    let vault = directory.path().join("authority-vault.json");
    std::fs::write(&vault, b"coffre").expect("vault");
    std::fs::write(
        astra_operator::rotation_journal::path_beside(&vault),
        b"illisible",
    )
    .expect("journal");
    let slot = "00".repeat(16);

    let refusals = [
        commands::enrol(
            &vault,
            "clé",
            astra_operator::vault::SlotRole::Recovery,
            Transport::default(),
        ),
        commands::remove(&vault, &slot, Transport::default()),
        commands::bindings(
            &vault,
            std::slice::from_ref(&slot),
            &[],
            Transport::default(),
        ),
        commands::bindings(
            &vault,
            &[],
            std::slice::from_ref(&slot),
            Transport::default(),
        ),
    ];

    for refused in refusals {
        let refused = refused.expect_err("refused");
        assert!(
            format!("{refused:#}").contains("une rotation est en cours"),
            "{refused:#}"
        );
    }
    assert_eq!(std::fs::read(&vault).expect("vault"), b"coffre");
}
