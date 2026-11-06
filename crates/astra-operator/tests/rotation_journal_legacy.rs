//! Adopting what `astra-signer` left behind, from what its ceremonies write.
//!
//! Only the CTAP2 boundary is simulated: the vault, the two rotations and every
//! signature are the production code, and each record is built field by field
//! the way `rotate_ca_pq` and `rotate_ca_tls` of `astra-signer` build it. A
//! record that a test made up would prove only that the test agrees with itself.

mod support;

use std::path::{Path, PathBuf};

use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey,
};
use aether::certificates::operator_ipc::AstraCaTlsManifest;
use aether::certificates::status::{AstraSignerResult, CampaignApproval};
use aether::certificates::transport::{OperatorAuthorityStatus, TrustUpdateObject};
use aether::certificates::window::TransitionWindow;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use astra_operator::authenticator::Opened;
use astra_operator::gestures::{self, NewAuthority, NewKey};
use astra_operator::prepared::{self, PreparedKind, PreparedRotation};
use astra_operator::rotation_journal::{
    self, GatewayAnchor, JournalStage, LegacyCaPqJournal, ResumeFacts, ResumeStep, RotationKind,
    RotationTransition, LEGACY_CA_PQ_JOURNAL_VERSION,
};
use astra_operator::vault::{AuthorityVault, SlotRole};
use astra_operator::vault_gestures::{add_key_with, create_first_key, finalize_with};
use astra_operator::{credentials, documents, handoff, signing, store};
use support::{FakeKey, PIN, RP_ID};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const ACTIVATION: u64 = NOW + 7 * DAY;
const NOT_AFTER: u64 = ACTIVATION + 30 * DAY;
const AUTHORITY_URL: &str = "https://astra.helios.test/";

fn window() -> TransitionWindow {
    TransitionWindow::new(NOW, ACTIVATION, NOT_AFTER).expect("window")
}

/// A finished domain with its two keys open, as a rotation starts from.
struct Domain {
    _directory: tempfile::TempDir,
    path: PathBuf,
    first: Opened,
    second: Opened,
}

fn domain() -> Domain {
    let directory = tempfile::tempdir().expect("dir");
    let path = directory.path().join("authority-vault.json");
    let key1 = FakeKey::new(1);
    let key2 = FakeKey::new(2);
    let first = create_first_key(
        &path,
        &NewAuthority {
            rp_id: RP_ID.into(),
            trust_domain_id: aether::certificates::encoding::TrustDomainId::new([0x2A; 16])
                .expect("domain"),
            label: "YubiKey du bureau".into(),
            role: SlotRole::Primary,
        },
        AUTHORITY_URL,
        &key1,
        PIN,
        NOW,
    )
    .expect("the domain is created");
    add_key_with(
        &path,
        &first,
        &key2,
        &NewKey {
            label: "YubiKey du sac".into(),
            role: SlotRole::Recovery,
        },
        PIN,
        NOW,
    )
    .expect("the second key is added");
    let relay_path = handoff::path_beside(&path);
    let mut relay = handoff::load(&relay_path).expect("relay");
    relay.gateway_wg_public_key =
        Some(aether::certificates::encoding::WireGuardKey::from_bytes([0x11; 32]).to_base64());
    relay.server_name = Some("gateway.helios.test".into());
    handoff::save(&relay_path, &relay).expect("relay saved");
    finalize_with(&path, &first, NOW).expect("the domain is finished");
    let vault = store::load(&path).expect("vault");
    let second = gestures::open_with_authorized_key(&key2, &vault, PIN).expect("second key");
    Domain {
        _directory: directory,
        path,
        first,
        second,
    }
}

/// What `rotate_ca_pq` of `astra-signer` writes, with a deposit behind it or,
/// with no `--authority-url`, none: the file is the same either way.
fn legacy_ca_pq(domain: &Domain) -> LegacyCaPqJournal {
    let mut vault = store::load(&domain.path).expect("vault");
    let relay = handoff::DomainHandoff::beside(&domain.path, &vault).expect("relay");
    let identity = handoff::identity_of(&relay).expect("identity");
    let current_ca_public_key =
        MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim()).expect("anchor");
    let previous = credentials::load(&credentials::path_beside(&domain.path)).expect("document");
    let rotated = signing::rotate_ca_pq(
        &mut vault,
        &[&domain.first, &domain.second],
        &identity,
        previous.as_ref(),
        window(),
        NOW,
    )
    .expect("rotated");
    let mut next_handoff = relay;
    next_handoff.adopt(&vault).expect("adopt");
    next_handoff.ca_epoch = Some(identity.ca_epoch + 1);
    LegacyCaPqJournal {
        format_version: LEGACY_CA_PQ_JOURNAL_VERSION,
        output_path: PathBuf::from("/tmp/transition-ca-pq.json"),
        current_ca_public_key,
        vault,
        bindings: rotated.bindings,
        transition: rotated.transition,
        handoff: next_handoff,
    }
}

fn write_legacy_ca_pq(path: &Path, journal: &LegacyCaPqJournal) -> PathBuf {
    let legacy_path = rotation_journal::legacy_ca_pq_path_beside(path);
    documents::write(&legacy_path, journal).expect("written");
    legacy_path
}

/// What `rotate_ca_tls` of `astra-signer` leaves: the vault already moved, and
/// the record written before the deposit is attempted.
fn legacy_prepared(domain: &Domain, submitted: bool) -> (PreparedRotation, AuthorityVault) {
    let mut vault = store::load(&domain.path).expect("vault");
    let relay = handoff::DomainHandoff::beside(&domain.path, &vault).expect("relay");
    let identity = handoff::identity_of(&relay).expect("identity");
    let active = DerCertificate::parse(relay.ca_tls_certificate.as_ref().expect("CA-TLS"))
        .expect("certificate");
    let rotated = signing::rotate_ca_tls(
        &mut vault,
        &domain.first,
        &identity,
        &active,
        window(),
        (NOW, NOW + 1825 * DAY),
    )
    .expect("rotated");
    store::save(&domain.path, &vault).expect("the vault moves first");
    let record = PreparedRotation {
        kind: PreparedKind::CaTls,
        operation_id: Id16::new([4; 16]).expect("id").to_hex(),
        result_token: "jeton-de-depot".into(),
        result: AstraSignerResult {
            format_version: CERTIFICATE_FORMAT_VERSION,
            approval: Box::new(CampaignApproval {
                campaign_id: Id16::new([5; 16]).expect("id"),
                campaign_fingerprint: Fingerprint::of(b"campagne"),
                required_credentials: 2,
                approved_at: NOW,
                approvals: Vec::new(),
            }),
            objects: vec![TrustUpdateObject::ClientTlsCaTransition(Box::new(
                rotated.transition,
            ))],
            credential_registry: None,
            issuer_authorization: None,
        },
        transition_path: "/tmp/transition-ca-tls.json".into(),
        next_ca_tls_epoch: identity.ca_tls_epoch + 1,
        next_ca_tls_certificate: rotated.next_certificate.to_base64(),
        activation_at: ACTIVATION,
        not_after: NOT_AFTER,
        submitted,
        prepared_at: NOW,
        adopted: false,
        manifest: Some(AstraCaTlsManifest {
            reason: "remplacement".into(),
            requested_by: "opératrice".into(),
            fingerprint: "ab".repeat(32),
            current_ca_tls_epoch: identity.ca_tls_epoch,
            next_ca_tls_epoch: identity.ca_tls_epoch + 1,
            activation_at: ACTIVATION,
            not_after: NOT_AFTER,
            outgoing_anchor_fingerprint: active.fingerprint().to_hex(),
            affected_ca: "client_tls".into(),
            target_count: 1,
        }),
    };
    prepared::save(&prepared::path_beside(&domain.path), &record).expect("record");
    (record, vault)
}

fn facts(now: u64) -> ResumeFacts {
    ResumeFacts {
        now,
        deposit_refused: false,
        authority: None,
        gateway_next: GatewayAnchor::NotRead,
    }
}

fn with_authority(status: OperatorAuthorityStatus) -> ResumeFacts {
    ResumeFacts {
        authority: Some(status),
        ..facts(NOW)
    }
}

fn nothing_in_flight() -> OperatorAuthorityStatus {
    OperatorAuthorityStatus {
        ca_epoch: 1,
        ca_fingerprint: Fingerprint::of(b"ca en service"),
        next_ca_fingerprint: None,
        ca_tls_epoch: 1,
        ca_tls_fingerprint: Some(Fingerprint::of(b"ca tls en service")),
        next_ca_tls_fingerprint: None,
        issuer: None,
        vault_copy_fingerprint: None,
        credential_registry_epoch: None,
    }
}

/// The format on disk is what operators hold, so its field names are a contract
/// the move into this crate must not have touched.
#[test]
fn the_legacy_ca_pq_format_keeps_its_field_names() {
    let domain = domain();
    let legacy = legacy_ca_pq(&domain);
    let value = serde_json::to_value(&legacy).expect("value");
    let mut names: Vec<&str> = value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "bindings",
            "current_ca_public_key",
            "format_version",
            "handoff",
            "output_path",
            "transition",
            "vault"
        ]
    );
    assert_eq!(
        rotation_journal::LEGACY_CA_PQ_JOURNAL_FILE,
        "ca-pq-rotation.pending.json"
    );
}

/// Adopted, and nothing has moved: the file cannot say whether a deposit went
/// out, so until Astra answers, the vault and the file stay as they are.
#[test]
fn a_legacy_ca_pq_journal_waits_for_astra_with_its_vault_still_to_apply() {
    let domain = domain();
    let legacy = legacy_ca_pq(&domain);
    let next_anchor = legacy.transition.next_ca_public_key.authority_fingerprint();
    let legacy_path = write_legacy_ca_pq(&domain.path, &legacy);
    let vault_before = std::fs::read(&domain.path).expect("vault");

    let journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");

    assert_eq!(journal.kind, RotationKind::CaPq);
    assert_eq!(journal.stage, JournalStage::Accepted);
    assert_eq!(
        journal.deposit, None,
        "this format holds no token or result"
    );
    assert_eq!(journal.next_anchor_fingerprint, next_anchor);
    assert_eq!(
        (journal.activation_at, journal.not_after),
        (ACTIVATION, NOT_AFTER)
    );
    assert!(matches!(journal.transition, RotationTransition::CaPq(_)));
    assert_eq!(std::fs::read(&domain.path).expect("vault"), vault_before);
    assert!(legacy_path.exists(), "it stays until Astra confirms");
    let journal_path = rotation_journal::path_beside(&domain.path);
    assert_eq!(
        rotation_journal::load(&journal_path)
            .expect("load")
            .as_ref(),
        Some(&journal)
    );
    assert_eq!(
        rotation_journal::next_step(&journal, &facts(NOW)),
        ResumeStep::ReadAuthority
    );
}

/// `rotate-ca-pq` with no `--authority-url`: Astra never heard of it, and the
/// vault must not move, nor the gateway stage what Astra would keep refusing.
#[test]
fn an_offline_record_astra_does_not_hold_conflicts_and_moves_nothing() {
    let domain = domain();
    let legacy = legacy_ca_pq(&domain);
    let legacy_path = write_legacy_ca_pq(&domain.path, &legacy);
    let vault_before = std::fs::read(&domain.path).expect("vault");
    let relay_before = std::fs::read(handoff::path_beside(&domain.path)).expect("relay");

    let journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");

    for status in [
        nothing_in_flight(),
        OperatorAuthorityStatus {
            next_ca_fingerprint: Some(Fingerprint::of(b"une autre")),
            ..nothing_in_flight()
        },
    ] {
        assert_eq!(
            rotation_journal::next_step(&journal, &with_authority(status)),
            ResumeStep::DomainConflict
        );
    }
    assert_eq!(std::fs::read(&domain.path).expect("vault"), vault_before);
    assert_eq!(
        std::fs::read(handoff::path_beside(&domain.path)).expect("relay"),
        relay_before
    );
    assert!(legacy_path.exists());
}

/// The vault already moved: a stop inside `astra-signer` after its first write.
/// Adopted all the same, and still not discarded when Astra does not hold it.
#[test]
fn an_offline_record_whose_vault_already_moved_is_not_discarded() {
    let domain = domain();
    let legacy = legacy_ca_pq(&domain);
    store::save(&domain.path, &legacy.vault).expect("the vault moved");
    write_legacy_ca_pq(&domain.path, &legacy);

    let journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");

    assert_eq!(
        rotation_journal::next_step(&journal, &with_authority(nothing_in_flight())),
        ResumeStep::DomainConflict
    );
}

/// Astra holds it, as next or already as current: the deposit went through. The
/// file goes only here, once the journal has taken over from it.
#[test]
fn a_legacy_ca_pq_journal_astra_holds_applies_and_only_then_lets_the_file_go() {
    let next_in_flight = |anchor| OperatorAuthorityStatus {
        next_ca_fingerprint: Some(anchor),
        ..nothing_in_flight()
    };
    let promoted = |anchor| OperatorAuthorityStatus {
        ca_fingerprint: anchor,
        ..nothing_in_flight()
    };
    let statuses: [&dyn Fn(Fingerprint) -> OperatorAuthorityStatus; 2] =
        [&next_in_flight, &promoted];
    for status_of in statuses {
        let domain = domain();
        let legacy = legacy_ca_pq(&domain);
        let next_vault = legacy.vault.clone();
        let next_handoff = legacy.handoff.clone();
        let next_bindings = legacy.bindings.clone();
        let legacy_path = write_legacy_ca_pq(&domain.path, &legacy);

        let mut journal = rotation_journal::adopt_legacy(&domain.path)
            .expect("adopted")
            .expect("a journal");
        let status = status_of(journal.next_anchor_fingerprint);
        assert_eq!(
            rotation_journal::next_step(&journal, &with_authority(status)),
            ResumeStep::ApplyLocal
        );

        rotation_journal::apply_local(&domain.path, &mut journal).expect("applied");

        assert!(!legacy_path.exists());
        assert_eq!(store::load(&domain.path).expect("vault"), next_vault);
        assert_eq!(
            handoff::load(&handoff::path_beside(&domain.path)).expect("relay"),
            next_handoff
        );
        assert_eq!(
            credentials::load(&credentials::path_beside(&domain.path)).expect("document"),
            Some(next_bindings)
        );
        assert_eq!(journal.next, None);
        let elsewhere = GatewayAnchor::Named(Fingerprint::of(b"ancre en service"));
        assert_eq!(
            rotation_journal::next_step(
                &journal,
                &ResumeFacts {
                    gateway_next: elsewhere,
                    ..facts(NOW)
                }
            ),
            ResumeStep::Install
        );
    }
}

/// A file for a vault this machine does not hold is someone else's rotation, or
/// a restored backup: applying it would replace the vault with a stranger.
#[test]
fn a_legacy_ca_pq_journal_for_a_vault_holding_neither_key_is_refused() {
    let domain = domain();
    let legacy = legacy_ca_pq(&domain);
    let legacy_path = write_legacy_ca_pq(&domain.path, &legacy);
    let mut stranger = store::load(&domain.path).expect("vault");
    let (_, unrelated) = generate_ml_dsa_87_keypair().expect("keys");
    stranger.ca_pq_public_key = unrelated.to_base64();
    store::save(&domain.path, &stranger).expect("vault");

    assert!(rotation_journal::adopt_legacy(&domain.path).is_err());

    assert!(legacy_path.exists());
    assert_eq!(store::load(&domain.path).expect("vault"), stranger);
    assert_eq!(
        rotation_journal::load(&rotation_journal::path_beside(&domain.path)).expect("load"),
        None
    );
}

/// The CLI may finish what it started while nothing has confirmed the adoption,
/// and not after: past the apply, the journal is carrying the rotation alone.
#[test]
fn the_ca_pq_command_may_resume_only_until_astra_confirmed() {
    let domain = domain();
    let legacy = legacy_ca_pq(&domain);
    let legacy_path = write_legacy_ca_pq(&domain.path, &legacy);
    let mut journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");
    rotation_journal::ensure_ca_pq_may_run(&domain.path).expect("unconfirmed");

    rotation_journal::apply_local(&domain.path, &mut journal).expect("applied");
    write_legacy_ca_pq(&domain.path, &legacy);

    assert!(rotation_journal::ensure_ca_pq_may_run(&domain.path).is_err());
    assert!(legacy_path.exists());
}

/// The signatures are checked as `astra-signer` checks them when it resumes.
#[test]
fn a_legacy_ca_pq_journal_that_does_not_verify_stays_where_it_is() {
    let domain = domain();
    let mut legacy = legacy_ca_pq(&domain);
    legacy.handoff.ca_epoch = Some(99);
    let legacy_path = write_legacy_ca_pq(&domain.path, &legacy);

    assert!(rotation_journal::adopt_legacy(&domain.path).is_err());

    assert!(legacy_path.exists());
    assert_eq!(
        rotation_journal::load(&rotation_journal::path_beside(&domain.path)).expect("load"),
        None
    );
}

/// A stop between saving the journal and removing the old file: the journal may
/// be further along by the next attempt, and must not be pulled back.
#[test]
fn adopting_again_after_a_stop_keeps_the_journal_further_along() {
    let domain = domain();
    let legacy = legacy_ca_pq(&domain);
    let legacy_path = write_legacy_ca_pq(&domain.path, &legacy);
    let mut journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");
    rotation_journal::apply_local(&domain.path, &mut journal).expect("applied");

    write_legacy_ca_pq(&domain.path, &legacy);
    let again = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");

    assert_eq!(again.stage, JournalStage::Applied);
    assert!(!legacy_path.exists());
}

/// Two different rotations: not this code's to choose, and nothing is lost.
#[test]
fn a_legacy_ca_pq_journal_against_another_journal_is_refused_with_both_intact() {
    let domain = domain();
    let legacy = legacy_ca_pq(&domain);
    let legacy_path = write_legacy_ca_pq(&domain.path, &legacy);
    let first = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");

    let other = legacy_ca_pq(&domain);
    assert_ne!(
        other.transition.next_ca_fingerprint,
        first.next_anchor_fingerprint
    );
    write_legacy_ca_pq(&domain.path, &other);

    assert!(rotation_journal::adopt_legacy(&domain.path).is_err());
    assert!(legacy_path.exists());
    assert_eq!(
        rotation_journal::load(&rotation_journal::path_beside(&domain.path)).expect("load"),
        Some(first)
    );
}

#[test]
fn a_submitted_prepared_record_is_accepted_with_no_next() {
    let domain = domain();
    let (record, vault) = legacy_prepared(&domain, true);

    let mut journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");

    assert_eq!(journal.kind, RotationKind::CaTls);
    assert_eq!(journal.stage, JournalStage::Accepted);
    assert_eq!(journal.next, None, "the vault already moved");
    let deposit = journal.deposit.as_ref().expect("the deposit is kept");
    assert_eq!(deposit.operation_id.to_hex(), record.operation_id);
    assert_eq!(deposit.result_token, record.result_token);
    assert_eq!(deposit.result, record.result);
    assert_eq!(journal.signed_at, NOW);
    assert_eq!(
        (journal.activation_at, journal.not_after),
        (ACTIVATION, NOT_AFTER)
    );

    let vault_bytes = std::fs::read(&domain.path).expect("vault");
    assert_eq!(
        rotation_journal::next_step(&journal, &facts(NOW)),
        ResumeStep::ApplyLocal
    );
    rotation_journal::apply_local(&domain.path, &mut journal).expect("applied");
    assert_eq!(journal.stage, JournalStage::Applied);
    assert_eq!(std::fs::read(&domain.path).expect("vault"), vault_bytes);
    assert_eq!(store::load(&domain.path).expect("vault"), vault);
}

/// `promote-ca-tls` reads this record until `not_after`, and it alone names the
/// incoming certificate for the relay. It stays, marked, and is adopted once:
/// outliving its window, it would otherwise read as a permanent "Délai dépassé".
#[test]
fn a_prepared_record_is_adopted_once_and_stays_for_the_promotion() {
    let domain = domain();
    let (record, _) = legacy_prepared(&domain, true);
    let prepared_path = prepared::path_beside(&domain.path);
    let journal_path = rotation_journal::path_beside(&domain.path);

    rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");
    let kept = prepared::load(&prepared_path).expect("load").expect("kept");
    assert!(kept.adopted);
    assert_eq!(
        PreparedRotation {
            adopted: false,
            ..kept
        },
        record
    );

    rotation_journal::clear(&journal_path).expect("clear");
    assert_eq!(
        rotation_journal::adopt_legacy(&domain.path).expect("adopted"),
        None,
        "its journal has ended, and no new one holds the token again"
    );
    assert_eq!(rotation_journal::load(&journal_path).expect("load"), None);
    assert!(prepared::load(&prepared_path).expect("load").is_some());
}

/// A stop between saving the journal and marking the record: the next look
/// finishes the marking, so the record is still adopted only once.
#[test]
fn a_stop_before_the_marker_does_not_adopt_the_record_twice() {
    let domain = domain();
    let (record, _) = legacy_prepared(&domain, true);
    let prepared_path = prepared::path_beside(&domain.path);
    let journal_path = rotation_journal::path_beside(&domain.path);
    let journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");
    prepared::save(&prepared_path, &record).expect("the marker never landed");

    assert_eq!(
        rotation_journal::adopt_legacy(&domain.path).expect("adopted"),
        Some(journal)
    );
    assert!(
        prepared::load(&prepared_path)
            .expect("load")
            .expect("kept")
            .adopted
    );

    rotation_journal::clear(&journal_path).expect("clear");
    assert_eq!(
        rotation_journal::adopt_legacy(&domain.path).expect("adopted"),
        None
    );
}

/// Orion carries the deposit, and `promote-ca-tls` must not then say it never
/// happened: the command stays the recourse for this rotation.
#[test]
fn recording_acceptance_tells_the_prepared_record() {
    let domain = domain();
    legacy_prepared(&domain, false);
    let prepared_path = prepared::path_beside(&domain.path);
    let mut journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");
    assert!(
        !prepared::load(&prepared_path)
            .expect("load")
            .expect("kept")
            .submitted
    );

    rotation_journal::record_accepted(&domain.path, &mut journal).expect("recorded");

    assert_eq!(journal.stage, JournalStage::Accepted);
    let kept = prepared::load(&prepared_path).expect("load").expect("kept");
    assert!(kept.submitted);
    assert!(kept.adopted);
    assert_eq!(
        rotation_journal::load(&rotation_journal::path_beside(&domain.path)).expect("load"),
        Some(journal)
    );
}

/// A record of another operation says nothing about this one.
#[test]
fn recording_acceptance_leaves_another_record_alone() {
    let domain = domain();
    let (mut record, _) = legacy_prepared(&domain, false);
    let mut journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");
    record.operation_id = Id16::new([9; 16]).expect("id").to_hex();
    let prepared_path = prepared::path_beside(&domain.path);
    prepared::save(&prepared_path, &record).expect("record");

    rotation_journal::record_accepted(&domain.path, &mut journal).expect("recorded");

    assert_eq!(prepared::load(&prepared_path).expect("load"), Some(record));
}

#[test]
fn an_unsubmitted_prepared_record_replays_its_deposit_while_the_campaign_lives() {
    let domain = domain();
    legacy_prepared(&domain, false);

    let journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");

    assert_eq!(journal.stage, JournalStage::Signed);
    assert_eq!(journal.next, None);
    assert!(journal.deposit.is_some());
    assert_eq!(
        rotation_journal::next_step(&journal, &facts(NOW + 1)),
        ResumeStep::Deposit
    );
    assert_eq!(
        rotation_journal::next_step(&journal, &facts(NOW + 300)),
        ResumeStep::ReadAuthority
    );
}

/// Its vault already moved. Astra knowing nothing of it is therefore the domain
/// contradicting this machine, and clearing the record would hide that.
#[test]
fn a_prepared_record_is_never_discarded() {
    let domain = domain();
    legacy_prepared(&domain, false);
    let journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");
    let dead = |status| ResumeFacts {
        authority: Some(status),
        ..facts(NOW + 300)
    };

    assert_eq!(
        rotation_journal::next_step(&journal, &dead(nothing_in_flight())),
        ResumeStep::DomainConflict
    );
    assert_eq!(
        rotation_journal::next_step(
            &journal,
            &dead(OperatorAuthorityStatus {
                next_ca_tls_fingerprint: Some(Fingerprint::of(b"une autre")),
                ..nothing_in_flight()
            })
        ),
        ResumeStep::DomainConflict
    );
    assert_eq!(
        rotation_journal::next_step(
            &journal,
            &dead(OperatorAuthorityStatus {
                next_ca_tls_fingerprint: Some(journal.next_anchor_fingerprint),
                ..nothing_in_flight()
            })
        ),
        ResumeStep::ApplyLocal
    );
}

/// A record that contradicts the transition it carries names nothing certain.
#[test]
fn a_prepared_record_that_contradicts_itself_is_refused() {
    let domain = domain();
    let (mut record, _) = legacy_prepared(&domain, true);
    record.next_ca_tls_certificate = "REVS".into();
    prepared::save(&prepared::path_beside(&domain.path), &record).expect("record");

    assert!(rotation_journal::adopt_legacy(&domain.path).is_err());
    assert_eq!(
        rotation_journal::load(&rotation_journal::path_beside(&domain.path)).expect("load"),
        None
    );
}

/// `rotate-ca-pq` never looked at the prepared record, so both can exist. The
/// vault not yet applied goes first; the other keeps its turn.
#[test]
fn the_unapplied_ca_pq_vault_goes_before_a_prepared_record() {
    let domain = domain();
    let (record, _) = legacy_prepared(&domain, true);
    let legacy = legacy_ca_pq(&domain);
    write_legacy_ca_pq(&domain.path, &legacy);
    let journal_path = rotation_journal::path_beside(&domain.path);

    let journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");
    assert_eq!(journal.kind, RotationKind::CaPq);
    assert_eq!(
        prepared::load(&prepared::path_beside(&domain.path)).expect("load"),
        Some(record)
    );

    // With a journal in place, the record waits and does not overwrite it.
    let same = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");
    assert_eq!(same, journal);

    // The CA-PQ journal ends through its apply, which lets its file go.
    let mut journal = journal;
    rotation_journal::apply_local(&domain.path, &mut journal).expect("applied");
    rotation_journal::clear(&journal_path).expect("clear");
    let after = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");
    assert_eq!(after.kind, RotationKind::CaTls);
}

/// A second look returns the journal in place, not a second adoption.
#[test]
fn adopting_again_returns_the_journal_in_place() {
    let domain = domain();
    let legacy = legacy_ca_pq(&domain);
    write_legacy_ca_pq(&domain.path, &legacy);
    let journal = rotation_journal::adopt_legacy(&domain.path)
        .expect("adopted")
        .expect("a journal");
    assert_eq!(
        rotation_journal::adopt_legacy(&domain.path).expect("adopted"),
        Some(journal)
    );
}
