use super::*;
use crate::vault::keys::KEY_LEN;

/// A provider with a fixed root, so the store is testable without a TPM.
///
/// Test-only on purpose: shipping such a provider would be the software
/// fallback ADR-006 forbids.
struct FixedRoot([u8; KEY_LEN]);

impl RootKeyProvider for FixedRoot {
    fn root_key(&self) -> Result<DeviceRootKey, VaultError> {
        Ok(DeviceRootKey::from_unwrapped(Zeroizing::new(self.0)))
    }
    fn hardware_backed(&self) -> bool {
        false
    }
}

/// Counts how many times the root was actually unwrapped.
///
/// Stands in for the TPM, whose every unwrap is an RSA decrypt costing
/// roughly 250 ms on real hardware — and which some chips rate-limit into
/// an anti-hammering lockout.
#[derive(Default)]
struct CountingRoot(std::sync::atomic::AtomicUsize);

impl RootKeyProvider for CountingRoot {
    fn root_key(&self) -> Result<DeviceRootKey, VaultError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(DeviceRootKey::from_unwrapped(Zeroizing::new(
            [4u8; KEY_LEN],
        )))
    }
    fn hardware_backed(&self) -> bool {
        true
    }
}

/// The root is unwrapped **once**, however many operations follow.
///
/// Uncached, one connection cost six TPM unwraps — posture, migration,
/// load, `rotation_required`, save, selection — each around 250 ms, on a
/// device that is rate-limited by design.
#[test]
fn the_installation_root_is_unwrapped_once_per_store() {
    let dir = std::env::temp_dir().join(format!(
        "orion-store-root-cache-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let counter = Arc::new(CountingRoot::default());
    struct Shared(Arc<CountingRoot>);
    impl RootKeyProvider for Shared {
        fn root_key(&self) -> Result<DeviceRootKey, VaultError> {
            self.0.root_key()
        }
        fn hardware_backed(&self) -> bool {
            self.0.hardware_backed()
        }
    }
    let store = ProfileStore::new(dir.clone(), Box::new(Shared(Arc::clone(&counter))));

    // The sequence a single connection actually performs.
    assert!(store.probe_hardware_root());
    store.save_profile(&profile("poste")).unwrap();
    let _ = store.load().unwrap();
    let _ = store.rotation_required().unwrap();
    let _ = store.posture();
    store.select("poste").unwrap();

    assert_eq!(
        counter.0.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "le TPM ne doit être sollicité qu'une fois par processus"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn store(name: &str) -> (std::path::PathBuf, ProfileStore) {
    let dir = std::env::temp_dir().join(format!(
        "orion-store-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = ProfileStore::new(dir.clone(), Box::new(FixedRoot([4u8; KEY_LEN])));
    (dir, store)
}

fn profile(name: &str) -> ClientProfile {
    let pair = aether::wg::generate_keypair().unwrap();
    let gateway = aether::wg::generate_keypair().unwrap();
    ClientProfile {
        name: name.into(),
        endpoint: "203.0.113.10:51820".into(),
        private_key: pair.private_key.duplicate(),
        peer_public_key: gateway.public_key,
        address: Some("100.64.1.2/32".into()),
        ..ClientProfile::default()
    }
}

/// The bootstrap names the slot the store was given: an auditor reads the key
/// actually in use, not the one this file was first written for.
#[test]
fn the_bootstrap_names_the_slot_in_use() {
    let (dir, store) = store("bootstrap-slot");
    let store = store.with_key_slot("Helios Orion device root v2 S-1-5-21-1-2-3-1001".to_string());
    store.save_profile(&profile("poste")).unwrap();
    let raw = std::fs::read_to_string(dir.join(BOOTSTRAP_FILE)).unwrap();
    let bootstrap: Bootstrap = toml::from_str(&raw).unwrap();
    assert_eq!(
        bootstrap.key_slot,
        "Helios Orion device root v2 S-1-5-21-1-2-3-1001"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A refusal and a deliberate downgrade must not look alike.
///
/// Off Windows `hardware_backed()` is false either way, so the flag is the
/// only thing that distinguishes "this machine has no TPM" from "the
/// operator chose to do without one". Reporting the first as the second
/// would credit them with a decision they never made — and would hide the
/// real one where it was actually taken.
#[test]
fn the_posture_separates_a_missing_tpm_from_a_waived_one() {
    let (dir, strict) = store("posture-strict");
    let posture = strict.posture();
    assert!(
        !posture.software_keystore,
        "no flag set: the absence of hardware is a refusal, not a downgrade"
    );

    let waived = ProfileStore::new(dir.clone(), Box::new(FixedRoot([4u8; KEY_LEN])))
        .allowing_software_keystore(true);
    let posture = waived.posture();
    assert!(posture.software_keystore);
    assert!(
        !posture.hardware_backed,
        "waiving the requirement must never produce a hardware claim"
    );
    assert!(!posture.is_clean());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Off Windows the volume posture is `Indeterminate`, which refuses. The
/// waiver is the only thing that lets a secret be written — and it must not
/// pretend the disk became encrypted.
#[test]
fn the_volume_waiver_permits_writing_without_claiming_protection() {
    let (dir, strict) = store("volume-strict");
    assert!(
        strict.may_write_secrets().is_err(),
        "une posture indéterminable doit refuser, pas passer"
    );
    assert!(!strict.posture().unencrypted_volume_waived);

    let waived = ProfileStore::new(dir.clone(), Box::new(FixedRoot([4u8; KEY_LEN])))
        .allowing_unencrypted_volume(true);
    assert!(
        waived.may_write_secrets().is_ok(),
        "la dérogation doit lever le refus"
    );

    let posture = waived.posture();
    assert!(
        posture.unencrypted_volume_waived,
        "la dérogation doit être visible"
    );
    assert!(
        !posture.volume_protected,
        "lever l'exigence ne chiffre pas le disque"
    );
    assert!(!posture.is_clean());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The interface can obtain informed consent after startup. The choice
/// takes effect for the pending save and survives the next launch.
#[test]
fn the_volume_waiver_can_be_persisted_and_applied_live() {
    let (dir, store) = store("volume-live-waiver");
    assert!(store.may_write_secrets().is_err());
    super::super::LocalSettings {
        danger_allow_software_keystore: true,
        danger_allow_unencrypted_volume: false,
    }
    .save(&dir)
    .unwrap();

    store.persist_unencrypted_volume_waiver().unwrap();

    assert!(store.may_write_secrets().is_ok());
    assert!(store.posture().unencrypted_volume_waived);
    let saved = super::super::LocalSettings::load(&dir).0;
    assert!(saved.danger_allow_unencrypted_volume);
    assert!(
        saved.danger_allow_software_keystore,
        "persisting one choice must preserve the other"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The bootstrap records the choice, not the outcome: it is what an
/// auditor reads to know whether the downgrade was deliberate.
#[test]
fn the_bootstrap_records_whether_the_downgrade_was_chosen() {
    let (dir, store) = store("bootstrap-flag");
    store.save_profile(&profile("poste")).unwrap();
    let raw = std::fs::read_to_string(dir.join(BOOTSTRAP_FILE)).unwrap();
    let bootstrap: Bootstrap = toml::from_str(&raw).unwrap();
    assert!(
        !bootstrap.software_keystore,
        "no flag set: the bootstrap must not claim a waiver"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_profile_round_trips_through_the_store() {
    let (dir, store) = store("roundtrip");
    let original = profile("poste");
    store.save_profile(&original).unwrap();

    let loaded = store.load().unwrap();
    assert_eq!(loaded.profiles.len(), 1);
    assert_eq!(loaded.profiles[0].private_key, original.private_key);
    assert_eq!(loaded.selected.as_deref(), Some("poste"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The vault is the durable enforcement point for the profile variant.
///
/// The shell normally refuses this before I/O, but imports and future
/// callers must not be able to bypass the rule by writing directly. The
/// original blob must remain readable after the refusal.
#[test]
fn a_sealed_profile_cannot_change_security_kind_in_place() {
    use crate::config::ProfileKind;

    let (dir, store) = store("immutable-kind");
    let classic = profile("poste");
    store.save_profile(&classic).unwrap();

    let mut helios = classic.duplicate();
    helios.profile_type = Some(ProfileKind::HeliosKeyNegotiation);
    helios.key_negotiation = Some(negotiation());
    let error = store.save_profile(&helios).unwrap_err();
    assert!(matches!(error, VaultError::ProfileKindChanged { .. }));

    let loaded = store.load().unwrap();
    assert_eq!(loaded.find("poste").unwrap().kind(), ProfileKind::Classic);
    assert!(loaded.find("poste").unwrap().key_negotiation.is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The property the whole lot exists for.
#[test]
fn no_secret_reaches_any_file_in_the_store() {
    let (dir, store) = store("no-secret");
    let original = profile("poste");
    store.save_profile(&original).unwrap();

    let mut checked = 0;
    for entry in walk(&dir) {
        let bytes = std::fs::read(&entry).unwrap();
        assert!(
            !bytes
                .windows(original.private_key.expose().len())
                .any(|w| w == original.private_key.expose().as_bytes()),
            "the private key appears in {}",
            entry.display()
        );
        checked += 1;
    }
    assert!(checked >= 3, "expected bootstrap, registry and manifest");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_bootstrap_carries_no_secret_and_is_readable() {
    let (dir, store) = store("bootstrap");
    store.save_profile(&profile("poste")).unwrap();
    let raw = std::fs::read_to_string(dir.join(BOOTSTRAP_FILE)).unwrap();
    let bootstrap: Bootstrap = toml::from_str(&raw).unwrap();
    assert_eq!(bootstrap.version, BOOTSTRAP_VERSION);
    assert_eq!(bootstrap.install_id.len(), 32);
    assert!(
        !raw.contains("private"),
        "the bootstrap must stay secret-free"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn removing_a_profile_removes_its_manifest() {
    let (dir, store) = store("remove");
    store.save_profile(&profile("poste")).unwrap();
    store.save_profile(&profile("portable")).unwrap();
    store.remove_profile("poste").unwrap();

    let loaded = store.load().unwrap();
    assert_eq!(loaded.profiles.len(), 1);
    assert_eq!(loaded.profiles[0].name, "portable");
    let manifests = std::fs::read_dir(dir.join(PROFILES_DIR)).unwrap().count();
    assert_eq!(manifests, 1, "the removed manifest is still on disk");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn selection_survives_a_reload() {
    let (dir, store) = store("select");
    store.save_profile(&profile("poste")).unwrap();
    store.save_profile(&profile("portable")).unwrap();
    store.select("portable").unwrap();
    assert_eq!(store.load().unwrap().selected.as_deref(), Some("portable"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Raising a floor must not resurrect the plaintext file.
///
/// This is the shape of the defect the shell carried: a committed
/// negotiation raised `minimum_mode`, and the raise was persisted with
/// `ClientConfig::save` — which writes `profiles.toml`, in this very
/// directory, with the private key in the clear. The whole vault was
/// undone by the ordinary success path, once per connection.
///
/// The test drives the store the way the shell now does, and then asserts
/// on the directory: no legacy file, and the secret nowhere in it.
#[test]
fn raising_a_floor_writes_no_plaintext_file() {
    use aether::key_negotiation::ProtectionMode;

    let (dir, store) = store("floor-raise");
    let mut profile = profile("poste");
    profile.key_negotiation = Some(negotiation());
    store.save_profile(&profile).unwrap();

    // What the negotiation sink does after a committed ML-KEM exchange.
    if let Some(settings) = profile.key_negotiation.as_mut() {
        settings.minimum_mode = ProtectionMode::MlKem;
    }
    store.save_profile(&profile).unwrap();

    assert!(
        !store.legacy_present(),
        "une montée de plancher a recréé {}",
        LEGACY_FILE
    );
    let secret = profile.private_key.expose().as_bytes();
    for path in walk(&dir) {
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(secret.len()).any(|window| window == secret),
            "la clé privée apparaît dans {}",
            path.display()
        );
    }

    // And the raise is genuinely persisted, sealed.
    let reloaded = store.load().unwrap();
    assert_eq!(
        reloaded
            .find("poste")
            .unwrap()
            .key_negotiation
            .as_ref()
            .unwrap()
            .minimum_mode,
        ProtectionMode::MlKem
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rewriting with a new WireGuard key is a rotation: the generation rises.
#[test]
fn a_key_rotation_raises_the_generation() {
    let (dir, store) = store("generation");
    let mut original = profile("poste");
    store.save_profile(&original).unwrap();

    original.private_key = aether::wg::generate_keypair().unwrap().private_key;
    store.save_profile(&original).unwrap();

    let root = store.root().unwrap();
    let entry = store.load_registry(&root).unwrap();
    assert_eq!(entry.find_by_name("poste").unwrap().generation.0, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Key negotiation block whose anchor and floor a test can move.
fn negotiation() -> crate::config::KeyNegotiationSettings {
    use aether::key_negotiation::ProtectionMode;
    crate::config::KeyNegotiationSettings {
        mode: ProtectionMode::MlKem,
        minimum_mode: ProtectionMode::StaticPsk,
        endpoint: "203.0.113.10:51821".into(),
        server_name: "gw.example".into(),
        gateway_ca_der: "Q0EtT1JJR0lORQ==".into(),
        gateway_pq_certificate: "Q0VSVC1PUklHSU5F".into(),
        identity: "poste".into(),
        trust: None,
    }
}

/// ADR-006 §2 names four triggers, not one.
///
/// Before the security digest entered the registry, only a WireGuard key
/// rotation moved the counter. Swapping the pinned trust anchor or lowering
/// the stored floor left it still — so a restored manifest carrying the old
/// anchor passed the registry's freshness check untouched. Each case here
/// is one of those triggers, exercised on its own.
#[test]
fn every_security_change_raises_the_generation() {
    use aether::key_negotiation::ProtectionMode;

    type Change = fn(&mut ClientProfile);
    let cases: [(&str, Change); 4] = [
        ("clé WireGuard", |profile| {
            profile.private_key = aether::wg::generate_keypair().unwrap().private_key;
        }),
        ("PSK statique", |profile| {
            profile.preshared_key = Some("cHNrLXJlbXBsYWNhbnQtMzItb2N0ZXRz".into());
        }),
        ("ancre de confiance", |profile| {
            if let Some(settings) = profile.key_negotiation.as_mut() {
                settings.gateway_ca_der = "Q0EtUkVNUExBQ0FOVEU=".into();
            }
        }),
        ("plancher", |profile| {
            if let Some(settings) = profile.key_negotiation.as_mut() {
                settings.minimum_mode = ProtectionMode::MlKem;
            }
        }),
    ];

    for (label, apply) in cases {
        let (dir, store) = store(&format!("generation-{}", label.replace(' ', "-")));
        let mut original = profile("poste");
        original.key_negotiation = Some(negotiation());
        store.save_profile(&original).unwrap();

        apply(&mut original);
        store.save_profile(&original).unwrap();

        let root = store.root().unwrap();
        assert_eq!(
            store
                .load_registry(&root)
                .unwrap()
                .find_by_name("poste")
                .unwrap()
                .generation
                .0,
            2,
            "un changement de {label} doit être un événement de sécurité"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The registry witnesses the change without ever holding the secret.
#[test]
fn the_registry_records_a_digest_and_never_the_psk() {
    let (dir, store) = store("digest-no-secret");
    let mut original = profile("poste");
    original.preshared_key = Some("cHNrLXNlY3JldC1xdWktbmUtc29ydC1wYXM=".into());
    store.save_profile(&original).unwrap();

    let root = store.root().unwrap();
    let entry = store
        .load_registry(&root)
        .unwrap()
        .find_by_name("poste")
        .unwrap()
        .clone();
    assert_ne!(entry.security_digest, [0u8; 32], "digest non calculé");

    let psk = original
        .preshared_key
        .as_ref()
        .map(aether::SecretString::expose)
        .unwrap()
        .as_bytes();
    for path in walk(&dir) {
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(psk.len()).any(|window| window == psk),
            "le PSK apparaît dans {}",
            path.display()
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saving_without_changing_the_key_keeps_the_generation() {
    let (dir, store) = store("stable-generation");
    let mut original = profile("poste");
    store.save_profile(&original).unwrap();
    original.endpoint = "198.51.100.7:51820".into();
    store.save_profile(&original).unwrap();

    let root = store.root().unwrap();
    assert_eq!(
        store
            .load_registry(&root)
            .unwrap()
            .find_by_name("poste")
            .unwrap()
            .generation
            .0,
        1,
        "an ordinary edit is not a security event"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A sealed IPv4-only full tunnel stays exactly what it was, until edited.
///
/// `::/0` joined the default after profiles were already sealed with
/// `0.0.0.0/0` alone. Those are warned about, never rewritten: not on load,
/// not when saved back for an unrelated reason. Only an edit of the list
/// itself changes it.
#[test]
fn a_stored_ipv4_only_full_tunnel_survives_load_and_save_unchanged() {
    let (dir, store) = store("ipv4-only");
    let legacy = ClientProfile {
        allowed_ips: "0.0.0.0/0".into(),
        ..profile("poste")
    };
    store.save_profile(&legacy).unwrap();

    let loaded = store.load().unwrap().profiles.remove(0);
    assert_eq!(loaded.allowed_ips, "0.0.0.0/0");
    assert!(loaded.ipv6_uncaptured_full_tunnel());

    // Saved back with another field edited: the list is left alone.
    let mut edited = loaded;
    edited.endpoint = "198.51.100.7:51820".into();
    store.save_profile(&edited).unwrap();
    let reloaded = store.load().unwrap().profiles.remove(0);
    assert_eq!(reloaded.endpoint, "198.51.100.7:51820");
    assert_eq!(reloaded.allowed_ips, "0.0.0.0/0");

    // The user's own edit is the only thing that widens it.
    let mut widened = reloaded;
    widened.allowed_ips = crate::DEFAULT_ALLOWED_IPS.into();
    store.save_profile(&widened).unwrap();
    let reloaded = store.load().unwrap().profiles.remove(0);
    assert_eq!(reloaded.allowed_ips, "0.0.0.0/0, ::/0");
    assert!(!reloaded.ipv6_uncaptured_full_tunnel());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A sealed IPv4-only profile stays IPv4-only through load and save: the
/// IPv6 address is never invented. One that carries it keeps it, and only an
/// edit removes it (`ADRESSAGE-IPV6.md` §8).
#[test]
fn the_ipv6_address_round_trips_through_the_store_only_when_present() {
    let (dir, store) = store("address-v6");
    store.save_profile(&profile("ipv4")).unwrap();
    store
        .save_profile(&ClientProfile {
            address_v6: Some("fd3c:91a2:7e04::2/128".into()),
            ..profile("dual")
        })
        .unwrap();

    let loaded = store.load().unwrap();
    let ipv4 = loaded.find("ipv4").unwrap().duplicate();
    let dual = loaded.find("dual").unwrap().duplicate();
    assert_eq!(ipv4.address.as_deref(), Some("100.64.1.2/32"));
    assert_eq!(ipv4.address_v6, None, "absent, not invented");
    assert_eq!(dual.address_v6.as_deref(), Some("fd3c:91a2:7e04::2/128"));

    // Saved back for an unrelated edit: both stay what they were.
    let mut edited = ipv4;
    edited.endpoint = "198.51.100.7:51820".into();
    store.save_profile(&edited).unwrap();
    let mut edited = dual;
    edited.endpoint = "198.51.100.7:51820".into();
    store.save_profile(&edited).unwrap();
    let reloaded = store.load().unwrap();
    assert_eq!(reloaded.find("ipv4").unwrap().address_v6, None);
    assert_eq!(
        reloaded.find("dual").unwrap().address_v6.as_deref(),
        Some("fd3c:91a2:7e04::2/128")
    );

    // The user's edit is what removes it.
    let mut cleared = reloaded.find("dual").unwrap().duplicate();
    cleared.address_v6 = None;
    store.save_profile(&cleared).unwrap();
    assert_eq!(store.load().unwrap().find("dual").unwrap().address_v6, None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_legacy_file_is_migrated_and_removed() {
    let (dir, store) = store("migration");
    let legacy = ClientConfig {
        profiles: vec![profile("poste")],
        selected: Some("poste".into()),
        locked: Vec::new(),
    };
    let secret = legacy.profiles[0].private_key.duplicate();
    std::fs::write(
        dir.join(LEGACY_FILE),
        legacy.encode_legacy_fixture().unwrap(),
    )
    .unwrap();

    assert!(store.legacy_present());
    let report = store.migrate_legacy().unwrap();
    assert_eq!(report.migrated, vec!["poste".to_string()]);
    assert!(!store.legacy_present(), "the plaintext file must be gone");

    let loaded = store.load().unwrap();
    assert_eq!(loaded.profiles[0].private_key, secret);
    assert_eq!(loaded.selected.as_deref(), Some("poste"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Sealing the file does not recall the copies already in backups.
#[test]
fn a_migrated_profile_stays_blocked_until_its_key_is_rotated() {
    let (dir, store) = store("rotation");
    let original = profile("poste");
    let legacy = ClientConfig {
        profiles: vec![original.duplicate()],
        selected: None,
        locked: Vec::new(),
    };
    std::fs::write(
        dir.join(LEGACY_FILE),
        legacy.encode_legacy_fixture().unwrap(),
    )
    .unwrap();
    store.migrate_legacy().unwrap();

    assert_eq!(
        store.rotation_required().unwrap(),
        vec!["poste".to_string()]
    );

    // Re-saving the same key changes nothing: the compromised key is still
    // the one in use.
    store.save_profile(&original).unwrap();
    assert_eq!(
        store.rotation_required().unwrap(),
        vec!["poste".to_string()]
    );

    // A new key closes it.
    let mut rotated = original.duplicate();
    rotated.private_key = aether::wg::generate_keypair().unwrap().private_key;
    store.save_profile(&rotated).unwrap();
    assert!(
        store.rotation_required().unwrap().is_empty(),
        "a rotated key must clear the migration flag"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn migrating_twice_is_harmless() {
    let (dir, store) = store("idempotent");
    let legacy = ClientConfig {
        profiles: vec![profile("poste")],
        selected: None,
        locked: Vec::new(),
    };
    std::fs::write(
        dir.join(LEGACY_FILE),
        legacy.encode_legacy_fixture().unwrap(),
    )
    .unwrap();
    store.migrate_legacy().unwrap();
    let second = store.migrate_legacy().unwrap();
    assert!(second.migrated.is_empty());
    assert_eq!(store.load().unwrap().profiles.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Another installation's root opens nothing — the point of the binding.
#[test]
fn another_installation_cannot_read_the_store() {
    let (dir, store) = store("foreign");
    store.save_profile(&profile("poste")).unwrap();

    let foreign = ProfileStore::new(dir.clone(), Box::new(FixedRoot([9u8; KEY_LEN])));
    assert!(foreign.load().is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Putting an older manifest back must be refused, not silently accepted.
#[test]
fn an_older_manifest_is_refused() {
    let (dir, store) = store("rollback");
    let mut original = profile("poste");
    store.save_profile(&original).unwrap();
    let root = store.root().unwrap();
    let id = store
        .load_registry(&root)
        .unwrap()
        .find_by_name("poste")
        .unwrap()
        .id;
    let old_blob = std::fs::read(store.manifest_path(id)).unwrap();

    // Rotate: generation 2, registry updated.
    original.private_key = aether::wg::generate_keypair().unwrap().private_key;
    store.save_profile(&original).unwrap();

    // Put the generation-1 blob back. Its context no longer matches the
    // registry's public key, and even a matching one would be caught by
    // the generation check.
    std::fs::write(store.manifest_path(id), &old_blob).unwrap();
    assert!(
        store.load().is_err(),
        "a restored older manifest must not load"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path);
        }
    }
    found
}

const PASSPHRASE: &str = "cheval agrafe batterie correcte orion";

/// Sets the lock watch on, as the engine does once its notifications run.
fn watched(store: ProfileStore) -> ProfileStore {
    store.set_lock_watch(true);
    store
}

fn id_of(store: &ProfileStore, name: &str) -> ProfileId {
    let root = store.root().unwrap();
    store
        .load_registry(&root)
        .unwrap()
        .find_by_name(name)
        .unwrap()
        .id
}

/// The passphrase the switch tests move a profile on to.
const NEW_PASSPHRASE: &str = "pommier glacé soleil rouge nuage vingt";

/// The `kdf` byte of a sealed container: `aether_vault`'s `HKDF_SHA256`, the
/// identifier of a `nomade` manifest. A service manifest carries `RAW` (0).
const HKDF_KDF_ID: u8 = 3;
const RAW_KDF_ID: u8 = 0;

/// Creates a `nomade` profile through the gesture, then forgets its key, so
/// that the test starts from a locked profile.
fn enrol(store: &ProfileStore, name: &str) -> ClientProfile {
    let profile = profile(name);
    // The gesture needs the lock watch; the caller's setting is restored.
    let watch = store.lock_watch_active();
    store.set_lock_watch(true);
    store
        .save_new_nomad_profile(&profile, PASSPHRASE)
        .expect("enrol nomad");
    store.set_lock_watch(watch);
    store.forget_unlocked();
    profile
}

/// A store on an existing directory, as a fresh process would open it.
fn reopen(dir: &std::path::Path) -> ProfileStore {
    ProfileStore::new(dir.to_path_buf(), Box::new(FixedRoot([4u8; KEY_LEN])))
}

/// Every file under `dir` with its bytes: a byte-identical comparison of the store.
fn snapshot(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut files: Vec<_> = walk(dir)
        .into_iter()
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    files.sort();
    files
}

fn generation_of(store: &ProfileStore, name: &str) -> u64 {
    let root = store.root().unwrap();
    store
        .load_registry(&root)
        .unwrap()
        .find_by_name(name)
        .unwrap()
        .generation
        .0
}

fn salt_of(store: &ProfileStore, name: &str) -> [u8; crate::vault::nomad::SALT_LEN] {
    match store.mode_of(name).unwrap().unwrap() {
        ProfileMode::Nomad { salt, .. } => salt,
        ProfileMode::Service => panic!("{name} is a service profile"),
    }
}

#[test]
fn load_keeps_a_nomad_profile_locked() {
    let (dir, store) = store("nomad-locked");
    store.save_profile(&profile("poste")).unwrap();
    let portable = enrol(&store, "portable");
    let manifest = store.manifest_path(id_of(&store, "portable"));

    // Garbage in place of the sealed manifest: a load that opened it would fail.
    std::fs::write(&manifest, b"never opened by load").unwrap();
    let loaded = store
        .load()
        .expect("a locked profile does not need its manifest");

    assert_eq!(loaded.profiles.len(), 1);
    assert_eq!(loaded.profiles[0].name, "poste");
    assert!(loaded.find("portable").is_none());
    assert_eq!(loaded.locked.len(), 1);
    assert_eq!(loaded.locked[0].name, "portable");
    assert_eq!(
        loaded.locked[0].gateway_public_key,
        portable.peer_public_key
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unlock_opens_it_and_load_then_returns_it() {
    let (dir, store) = store("nomad-unlock");
    let store = watched(store);
    let original = enrol(&store, "portable");

    store.unlock("portable", PASSPHRASE).unwrap();
    assert!(store.is_unlocked("portable"));

    let loaded = store.load().unwrap();
    assert!(loaded.locked.is_empty());
    let portable = loaded.find("portable").expect("unlocked profile loaded");
    assert_eq!(portable.private_key, original.private_key);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_wrong_passphrase_is_refused_and_leaves_it_locked() {
    let (dir, store) = store("nomad-wrong");
    let store = watched(store);
    enrol(&store, "portable");

    let error = store
        .unlock("portable", "une autre passphrase assez longue")
        .unwrap_err();
    assert!(matches!(error, VaultError::WrongPassphrase), "got {error}");
    assert!(!store.is_unlocked("portable"));
    assert_eq!(store.load().unwrap().locked.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unlock_is_refused_without_the_lock_watch() {
    let (dir, store) = store("nomad-no-watch");
    enrol(&store, "portable");

    let error = store.unlock("portable", PASSPHRASE).unwrap_err();
    assert!(
        matches!(error, VaultError::LockWatchUnavailable),
        "got {error}"
    );
    assert!(!store.is_unlocked("portable"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_lock_during_unlock_discards_the_key() {
    let (dir, mut store) = store("nomad-race");
    store.set_lock_watch(true);
    enrol(&store, "portable");
    store.between_derivation_and_store = Some(Box::new(|store: &ProfileStore| {
        store.forget_unlocked();
    }));

    let error = store.unlock("portable", PASSPHRASE).unwrap_err();
    assert!(
        matches!(&error, VaultError::ProfileLocked(name) if name == "portable"),
        "got {error}"
    );
    assert!(!store.is_unlocked("portable"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn forget_unlocked_locks_every_nomad_profile_again() {
    let (dir, store) = store("nomad-forget");
    let store = watched(store);
    enrol(&store, "portable");
    enrol(&store, "bureau");
    store.unlock("portable", PASSPHRASE).unwrap();
    store.unlock("bureau", PASSPHRASE).unwrap();
    assert!(store.load().unwrap().locked.is_empty());

    store.forget_unlocked();

    assert!(!store.is_unlocked("portable"));
    assert!(!store.is_unlocked("bureau"));
    let loaded = store.load().unwrap();
    assert!(loaded.profiles.is_empty());
    assert_eq!(loaded.locked.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_locked_nomad_profile_is_never_written() {
    let (dir, store) = store("nomad-no-write");
    let original = enrol(&store, "portable");
    let manifest = store.manifest_path(id_of(&store, "portable"));
    let before = std::fs::read(&manifest).unwrap();

    let mut edited = original.duplicate();
    edited.endpoint = "198.51.100.7:51820".into();
    let error = store.save_profile(&edited).unwrap_err();

    assert!(
        matches!(&error, VaultError::ProfileLocked(name) if name == "portable"),
        "got {error}"
    );
    assert_eq!(std::fs::read(&manifest).unwrap(), before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saving_an_unlocked_nomad_profile_keeps_it_nomad() {
    let (dir, store) = store("nomad-save-held");
    let store = watched(store);
    let original = enrol(&store, "portable");
    store.unlock("portable", PASSPHRASE).unwrap();

    let mut edited = original.duplicate();
    edited.endpoint = "198.51.100.7:51820".into();
    store.save_profile(&edited).unwrap();

    assert!(store
        .mode_of("portable")
        .unwrap()
        .is_some_and(|mode| mode.is_nomad()));
    let root = store.root().unwrap();
    assert_eq!(
        store
            .load_registry(&root)
            .unwrap()
            .find_by_name("portable")
            .unwrap()
            .generation
            .0,
        1,
        "an ordinary edit is not a security event, whatever the mode"
    );
    store.forget_unlocked();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.locked.len(),
        1,
        "the edit must not have sealed it as service"
    );
    assert!(loaded.profiles.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saving_over_a_locked_nomad_name_is_refused() {
    let (dir, store) = store("nomad-name");
    enrol(&store, "portable");

    let error = store.save_profile(&profile("portable")).unwrap_err();
    assert!(
        matches!(&error, VaultError::ProfileLocked(name) if name == "portable"),
        "got {error}"
    );
    assert_eq!(
        store.mode_of("portable").unwrap().map(|m| m.is_nomad()),
        Some(true)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn select_and_remove_need_no_passphrase() {
    let (dir, store) = store("nomad-select-remove");
    store.save_profile(&profile("poste")).unwrap();
    enrol(&store, "portable");

    store.select("portable").unwrap();
    assert_eq!(store.load().unwrap().selected.as_deref(), Some("portable"));

    store.remove_profile("portable").unwrap();
    let loaded = store.load().unwrap();
    assert!(loaded.locked.is_empty());
    assert_eq!(loaded.profiles.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn trailing_spaces_and_nfd_open_the_profile() {
    let (dir, store) = store("nomad-normalise");
    let store = watched(store);
    let profile = profile("portable");
    store
        .save_new_nomad_profile(&profile, "rivière calme montagne bleue vingt")
        .unwrap();
    store.forget_unlocked();

    store
        .unlock("portable", "  rivie\u{0300}re calme montagne bleue vingt  ")
        .expect("the same passphrase, typed differently, opens it");
    assert!(store.is_unlocked("portable"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_next_manifest_above_the_registry_is_deleted() {
    let (dir, store) = store("next-above");
    store.save_profile(&profile("poste")).unwrap();
    let id = id_of(&store, "poste");
    let current = store.manifest_path(id);
    let current_bytes = std::fs::read(&current).unwrap();
    let next = store.next_manifest_path(id, SecurityGeneration(2));
    std::fs::write(&next, b"a half-written step, never opened").unwrap();

    let loaded = store.load().expect("the stray file is removed, not opened");

    assert_eq!(loaded.profiles.len(), 1);
    assert!(!next.exists(), "a step above the registry is a leftover");
    assert_eq!(std::fs::read(&current).unwrap(), current_bytes);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_next_manifest_at_the_registry_generation_is_promoted() {
    let (dir, store) = store("next-promoted");
    store.save_profile(&profile("poste")).unwrap();
    let id = id_of(&store, "poste");
    let current = store.manifest_path(id);
    let bytes = std::fs::read(&current).unwrap();
    let next = store.next_manifest_path(id, SecurityGeneration(1));
    std::fs::rename(&current, &next).unwrap();

    let loaded = store.load().unwrap();

    assert_eq!(loaded.profiles.len(), 1, "the promoted manifest opens");
    assert!(!next.exists());
    assert_eq!(std::fs::read(&current).unwrap(), bytes);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_migration_cannot_seal_over_a_nomad_profile() {
    let (dir, store) = store("nomad-migration");
    let portable = enrol(&store, "portable");
    let manifest = store.manifest_path(id_of(&store, "portable"));
    let before = std::fs::read(&manifest).unwrap();
    let legacy = ClientConfig {
        profiles: vec![portable.duplicate()],
        selected: None,
        locked: Vec::new(),
    };
    std::fs::write(
        dir.join(LEGACY_FILE),
        legacy.encode_legacy_fixture().unwrap(),
    )
    .unwrap();

    let error = store.migrate_legacy().unwrap_err();

    assert!(
        matches!(&error, VaultError::ProfileLocked(name) if name == "portable"),
        "got {error}"
    );
    assert_eq!(std::fs::read(&manifest).unwrap(), before);
    assert!(store.legacy_present(), "the legacy file is kept on refusal");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn service_to_nomad_then_load_is_locked_after_forget() {
    let (dir, store) = store("switch-to-nomad");
    let store = watched(store);
    let original = profile("poste");
    store.save_profile(&original).unwrap();
    let id = id_of(&store, "poste");

    store.make_nomad("poste", NEW_PASSPHRASE).unwrap();
    assert!(store.is_unlocked("poste"), "the switch leaves its key held");
    store.forget_unlocked();

    let loaded = store.load().unwrap();
    assert!(loaded.profiles.is_empty());
    assert_eq!(loaded.locked.len(), 1);
    assert_eq!(loaded.locked[0].name, "poste");
    let blob = std::fs::read(store.manifest_path(id)).unwrap();
    assert_eq!(
        blob[5], HKDF_KDF_ID,
        "the old service path holds a nomad blob"
    );

    store.unlock("poste", NEW_PASSPHRASE).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(
        loaded.find("poste").unwrap().private_key,
        original.private_key
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn changing_the_passphrase_refuses_the_old_one() {
    let (dir, store) = store("switch-change");
    let store = watched(store);
    enrol(&store, "portable");
    let salt_before = salt_of(&store, "portable");

    store.unlock("portable", PASSPHRASE).unwrap();
    store.make_nomad("portable", NEW_PASSPHRASE).unwrap();
    store.forget_unlocked();

    assert_ne!(salt_of(&store, "portable"), salt_before, "a new salt");
    let error = store.unlock("portable", PASSPHRASE).unwrap_err();
    assert!(matches!(error, VaultError::WrongPassphrase), "got {error}");
    store.unlock("portable", NEW_PASSPHRASE).unwrap();
    assert!(store.is_unlocked("portable"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn back_to_service_opens_without_passphrase() {
    let (dir, store) = store("switch-to-service");
    let store = watched(store);
    let original = enrol(&store, "portable");
    store.unlock("portable", PASSPHRASE).unwrap();

    store.make_service("portable").unwrap();

    assert!(!store.is_unlocked("portable"), "the key is forgotten");
    assert!(store
        .mode_of("portable")
        .unwrap()
        .is_some_and(|mode| !mode.is_nomad()));
    // A fresh process, with no passphrase anywhere, opens it.
    let loaded = reopen(&dir).load().unwrap();
    assert!(loaded.locked.is_empty());
    assert_eq!(
        loaded.find("portable").unwrap().private_key,
        original.private_key
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn each_switch_raises_the_generation() {
    let (dir, store) = store("switch-generation");
    store.set_lock_watch(true);
    store.save_profile(&profile("poste")).unwrap();
    assert_eq!(generation_of(&store, "poste"), 1);

    store.make_nomad("poste", NEW_PASSPHRASE).unwrap();
    assert_eq!(generation_of(&store, "poste"), 2);

    store.make_nomad("poste", PASSPHRASE).unwrap();
    assert_eq!(
        generation_of(&store, "poste"),
        3,
        "a passphrase change counts"
    );

    store.make_service("poste").unwrap();
    assert_eq!(generation_of(&store, "poste"), 4);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_locked_nomad_profile_cannot_switch_and_nothing_changes() {
    let (dir, store) = store("switch-locked");
    let store = watched(store);
    enrol(&store, "portable");
    let before = snapshot(&dir);

    let error = store.make_service("portable").unwrap_err();
    assert!(
        matches!(&error, VaultError::ProfileLocked(name) if name == "portable"),
        "got {error}"
    );
    let error = store.make_nomad("portable", NEW_PASSPHRASE).unwrap_err();
    assert!(
        matches!(&error, VaultError::ProfileLocked(name) if name == "portable"),
        "got {error}"
    );
    assert_eq!(snapshot(&dir), before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_weak_new_passphrase_is_refused_and_nothing_changes() {
    use crate::vault::passphrase::PassphraseError;

    let (dir, store) = store("switch-weak");
    store.set_lock_watch(true);
    store.save_profile(&profile("poste")).unwrap();
    let before = snapshot(&dir);

    let error = store.make_nomad("poste", "motdepasse").unwrap_err();
    assert!(
        matches!(
            error,
            VaultError::NewPassphraseRefused(PassphraseError::TooCommon)
        ),
        "got {error}"
    );
    assert_eq!(snapshot(&dir), before, "a refused switch writes nothing");

    let error = store
        .save_new_nomad_profile(&profile("portable"), "motdepasse")
        .unwrap_err();
    assert!(
        matches!(
            error,
            VaultError::NewPassphraseRefused(PassphraseError::TooCommon)
        ),
        "got {error}"
    );
    assert_eq!(snapshot(&dir), before, "a refused enrolment writes nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_new_nomad_profile_never_touches_disk_as_service() {
    let (dir, store) = store("switch-new-nomad");
    store.set_lock_watch(true);
    store
        .save_new_nomad_profile(&profile("portable"), PASSPHRASE)
        .unwrap();
    let id = id_of(&store, "portable");
    let blob = std::fs::read(store.manifest_path(id)).unwrap();

    assert_eq!(blob[5], HKDF_KDF_ID);
    assert_ne!(blob[5], RAW_KDF_ID);
    let root = store.root().unwrap();
    let entry = store
        .load_registry(&root)
        .unwrap()
        .find(id)
        .unwrap()
        .clone();
    assert!(
        open_manifest(
            &root,
            id,
            &entry.client_public_key,
            &entry.gateway_public_key,
            &blob,
            ManifestKey::Service,
        )
        .is_err(),
        "the installation root alone must not open it"
    );
    assert!(store.is_unlocked("portable"), "the key stays held");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_new_passphrase_for_an_existing_name_is_refused_with_the_switch_named() {
    let (dir, store) = store("switch-exists");
    store.set_lock_watch(true);
    store.save_profile(&profile("poste")).unwrap();
    let before = snapshot(&dir);

    let error = store
        .save_new_nomad_profile(&profile("poste"), PASSPHRASE)
        .unwrap_err();
    assert!(
        matches!(&error, VaultError::ProfileExists(name) if name == "poste"),
        "got {error}"
    );
    assert_eq!(snapshot(&dir), before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_crash_after_each_write_leaves_an_openable_profile() {
    for (index, stop) in [
        SwitchStep::Staged,
        SwitchStep::Registered,
        SwitchStep::Renamed,
    ]
    .into_iter()
    .enumerate()
    {
        let (dir, mut store) = store(&format!("switch-crash-{index}"));
        store.set_lock_watch(true);
        store.save_profile(&profile("poste")).unwrap();
        let id = id_of(&store, "poste");
        store.stop_switch_after = Some(stop);

        let error = store.make_nomad("poste", NEW_PASSPHRASE).unwrap_err();
        assert!(matches!(error, VaultError::Io { .. }), "got {error}");

        // A fresh process settles the interrupted step, then opens the profile.
        let reopened = watched(reopen(&dir));
        let loaded = reopened.load().unwrap();
        assert!(
            !reopened
                .next_manifest_path(id, SecurityGeneration(2))
                .exists(),
            "{stop:?}: the step is settled by the load"
        );
        match stop {
            SwitchStep::Staged => {
                assert_eq!(loaded.profiles.len(), 1, "{stop:?}: still service");
                assert!(loaded.locked.is_empty());
            }
            SwitchStep::Registered | SwitchStep::Renamed => {
                assert!(loaded.profiles.is_empty(), "{stop:?}: now nomade");
                assert_eq!(loaded.locked.len(), 1);
                reopened.unlock("poste", NEW_PASSPHRASE).unwrap();
                assert_eq!(reopened.load().unwrap().profiles.len(), 1);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn a_tightened_policy_still_opens_an_existing_profile() {
    let (dir, store) = store("switch-tightened");
    let store = watched(store);
    // `accept` now refuses this passphrase; the profile predates the rule.
    let weak = "motdepasse";
    let salt = crate::vault::nomad::new_salt().unwrap();
    let key = PassphraseKey::derive(weak, &salt).unwrap();
    let epoch = store.lock_epoch.load(std::sync::atomic::Ordering::Acquire);
    store
        .create_nomad(&profile("portable"), salt, key, epoch)
        .unwrap();
    store.forget_unlocked();

    store.unlock("portable", weak).unwrap();
    assert!(store.is_unlocked("portable"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_lock_during_a_new_nomad_enrolment_leaves_it_locked() {
    let (dir, mut store) = store("enrol-lock-race");
    store.set_lock_watch(true);
    store.between_derivation_and_store = Some(Box::new(|store: &ProfileStore| {
        store.forget_unlocked();
    }));

    store
        .save_new_nomad_profile(&profile("portable"), PASSPHRASE)
        .expect("the profile is written even when a lock lands");
    assert!(!store.is_unlocked("portable"), "the lock wins");
    assert_eq!(
        store.mode_of("portable").unwrap().map(|m| m.is_nomad()),
        Some(true)
    );
    let loaded = store.load().unwrap();
    assert_eq!(loaded.locked.len(), 1);
    assert!(loaded.profiles.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_lock_during_a_switch_leaves_the_profile_locked() {
    let (dir, mut store) = store("switch-lock-race");
    store.set_lock_watch(true);
    store.save_profile(&profile("poste")).unwrap();
    // The switch holds the unlocked map for its whole run, so a real lock
    // waits for it. This hook only bumps the epoch, as a lock that already
    // happened would have, and the switch must not keep the key.
    store.between_derivation_and_store = Some(Box::new(|store: &ProfileStore| {
        store
            .lock_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }));

    store
        .make_nomad("poste", NEW_PASSPHRASE)
        .expect("the switch is written even when a lock lands");
    assert!(!store.is_unlocked("poste"), "the lock wins");
    let loaded = store.load().unwrap();
    assert_eq!(loaded.locked.len(), 1);
    assert!(loaded.profiles.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_new_nomad_profile_without_the_lock_watch_is_refused_and_nothing_changes() {
    let (dir, store) = store("enrol-no-watch");
    store.save_profile(&profile("poste")).unwrap();
    let before = snapshot(&dir);

    let error = store
        .save_new_nomad_profile(&profile("portable"), PASSPHRASE)
        .unwrap_err();
    assert!(
        matches!(error, VaultError::LockWatchUnavailable),
        "got {error}"
    );
    assert!(!store.is_unlocked("portable"));
    assert_eq!(snapshot(&dir), before, "refused before any write");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_switch_without_the_lock_watch_is_refused_and_nothing_changes() {
    let (dir, store) = store("switch-no-watch");
    store.save_profile(&profile("poste")).unwrap();
    let before = snapshot(&dir);

    let error = store.make_nomad("poste", NEW_PASSPHRASE).unwrap_err();
    assert!(
        matches!(error, VaultError::LockWatchUnavailable),
        "got {error}"
    );
    assert!(!store.is_unlocked("poste"));
    assert_eq!(snapshot(&dir), before, "refused before any write");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A selection that runs while a switch is under way must not be lost, nor
/// must it put the switched profile back to its old mode. The hook runs inside
/// the switch, after the registry was read; the selection starts there on its
/// own thread. Unserialised, it wrote its registry copy at once and the
/// switch then overwrote it from an older one.
#[test]
fn a_selection_during_a_switch_waits_and_loses_nothing() {
    let (dir, mut store) = store("switch-select-race");
    store.set_lock_watch(true);
    store.save_profile(&profile("poste")).unwrap();
    store.save_profile(&profile("autre")).unwrap();
    store.select("poste").unwrap();

    let slot: Arc<Mutex<Option<std::sync::Weak<ProfileStore>>>> = Arc::new(Mutex::new(None));
    let selector: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> = Arc::new(Mutex::new(None));
    let (hook_slot, hook_selector) = (Arc::clone(&slot), Arc::clone(&selector));
    store.between_derivation_and_store = Some(Box::new(move |_store: &ProfileStore| {
        let shared = hook_slot
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .expect("the store is alive");
        *hook_selector.lock().unwrap() = Some(std::thread::spawn(move || {
            shared.select("autre").expect("the selection is written");
        }));
        // Long enough for an unserialised selection to finish first.
        std::thread::sleep(std::time::Duration::from_millis(300));
    }));
    let store = Arc::new(store);
    *slot.lock().unwrap() = Some(Arc::downgrade(&store));

    store
        .make_nomad("poste", NEW_PASSPHRASE)
        .expect("the switch is written");
    selector
        .lock()
        .unwrap()
        .take()
        .expect("the selection started")
        .join()
        .unwrap();

    let root = store.root().unwrap();
    let registry = store.load_registry(&root).unwrap();
    let poste = registry.find_by_name("poste").unwrap();
    assert!(poste.mode.is_nomad(), "the switch is not undone");
    assert_eq!(
        registry.selected,
        Some(registry.find_by_name("autre").unwrap().id),
        "the selection is not lost"
    );
    store.forget_unlocked();
    assert_eq!(store.load().expect("the vault still loads").locked.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
