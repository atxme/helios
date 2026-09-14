//! Which store file belongs to which admitted identity: the scoped path, the
//! migration of a machine-wide legacy store, and the refusal of a store
//! describing another domain or another client key.

use aether::certificates::encoding::WireGuardKey;

use crate::certificate_renewal::trust_store::identity_trust_store_path;
use crate::certificate_renewal::{open_identity_store, open_or_seed, RenewalError};
use crate::certificates::TrustStore;
use crate::test_domain::*;

/// A machine can hold several Orion identities, including several peers
/// admitted in the same trust domain. Their pending generations and
/// revocation ledgers must never share a file.
#[test]
fn trust_store_paths_are_scoped_by_domain_and_client_key() {
    let directory = tempfile::tempdir().expect("temp dir");
    let first = identity_trust_store_path(directory.path(), &domain_id(), &client_key());
    let second = identity_trust_store_path(
        directory.path(),
        &domain_id(),
        &WireGuardKey::from_bytes([3; 32]),
    );

    assert_ne!(first, second);
    let filename = first
        .file_name()
        .and_then(|name| name.to_str())
        .expect("UTF-8 filename");
    assert!(filename.starts_with(&format!("trust-{}-", domain_id().to_hex())));
    assert!(filename.ends_with(".json"));
    assert!(filename
        .trim_end_matches(".json")
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'));
}

/// Upgrade keeps every decision already recorded in the machine-wide
/// store. It copies that state under the identity-scoped name and retains
/// the old file as a recoverable snapshot.
#[test]
fn a_matching_legacy_store_is_copied_without_being_deleted() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let settings = settings(&domain);
    let bundle = bundle(&domain);
    let legacy_path = directory.path().join("trust.json");
    let legacy = store(directory.path(), &domain);
    legacy.save().expect("legacy saved");

    let migrated =
        open_identity_store(directory.path(), &settings, &bundle).expect("legacy imported");
    let scoped_path = identity_trust_store_path(directory.path(), &domain_id(), &client_key());

    assert!(
        legacy_path.exists(),
        "migration retains the legacy snapshot"
    );
    assert!(scoped_path.exists(), "migration writes the scoped store");
    assert_eq!(migrated.state(), legacy.state());
}

/// A legacy store for another peer is not an error and is not overwritten:
/// the newly loaded profile receives an independent state file.
#[test]
fn another_clients_legacy_store_does_not_block_a_new_profile() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let settings = settings(&domain);
    let legacy = store(directory.path(), &domain);
    legacy.save().expect("legacy saved");
    let other_key = WireGuardKey::from_bytes([3; 32]);
    let other_bundle = bundle_for_client_key(&domain, other_key);

    let opened = open_identity_store(directory.path(), &settings, &other_bundle)
        .expect("independent store seeded");
    let scoped_path = identity_trust_store_path(directory.path(), &domain_id(), &other_key);

    assert_eq!(opened.state().client_wg_public_key, other_key);
    assert!(scoped_path.exists());
    let preserved = TrustStore::load(&directory.path().join("trust.json"))
        .expect("legacy readable")
        .expect("legacy retained");
    assert_eq!(preserved.state().client_wg_public_key, client_key());
}

/// A store belonging to another domain is refused, never replaced: it
/// carries decisions an overwrite would drop in silence.
#[test]
fn a_store_describing_another_domain_is_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let settings = settings(&domain);
    let bundle = bundle(&domain);
    let path = directory.path().join("trust.json");
    open_or_seed(&path, &settings, &bundle).expect("seeded");

    let mut stranger = settings.clone();
    stranger.trust.as_mut().expect("trust").trust_domain_id = "ab".repeat(16);
    assert!(matches!(
        open_or_seed(&path, &stranger, &bundle),
        Err(RenewalError::ForeignTrustStore { .. })
    ));
}

/// A store belonging to another admitted peer of the **same** domain is
/// refused too. The domain check alone would let one machine's second
/// profile adopt the first one's generations, and the renewal would then
/// prove continuity for an identity it does not hold the key of.
#[test]
fn a_store_describing_another_client_key_is_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let domain = domain();
    let settings = settings(&domain);
    let path = directory.path().join("trust.json");
    open_or_seed(&path, &settings, &bundle(&domain)).expect("seeded");

    let stranger = bundle_for_client_key(&domain, WireGuardKey::from_bytes([3; 32]));
    assert!(matches!(
        open_or_seed(&path, &settings, &stranger),
        Err(RenewalError::ForeignTrustStore { .. })
    ));
}
