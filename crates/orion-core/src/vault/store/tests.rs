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
        minimum_mode: ProtectionMode::Classic,
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
