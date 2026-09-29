use super::*;

fn test_directory(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "orion-identity-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

fn bundle() -> ClientIdentityBundle {
    let encoder = base64::engine::general_purpose::STANDARD;
    ClientIdentityBundle {
        identity: "orion-portable".into(),
        certificate_chain: vec![encoder.encode([0x30, 0x82, 0x01, 0x00])],
        private_key: encoder.encode([0x30, 0x81, 0x87, 0x02]),
        pq_certificate: encoder.encode(br#"{"version":1}"#),
        pq_private_key: encoder.encode([7u8; 64]),
    }
}

/// A bundle that only failed at connection time would leave the user with
/// a profile that looks imported and never connects.
#[test]
fn an_undecodable_bundle_is_refused_before_sealing() {
    for broken in [
        ClientIdentityBundle {
            identity: "  ".into(),
            ..bundle()
        },
        ClientIdentityBundle {
            certificate_chain: Vec::new(),
            ..bundle()
        },
        ClientIdentityBundle {
            certificate_chain: vec![String::new()],
            ..bundle()
        },
        ClientIdentityBundle {
            certificate_chain: vec!["not base64".into()],
            ..bundle()
        },
        ClientIdentityBundle {
            private_key: "pas du base64 !".into(),
            ..bundle()
        },
        ClientIdentityBundle {
            private_key: String::new(),
            ..bundle()
        },
        ClientIdentityBundle {
            pq_certificate: String::new(),
            ..bundle()
        },
        ClientIdentityBundle {
            pq_private_key: String::new(),
            ..bundle()
        },
        ClientIdentityBundle {
            pq_private_key: "not base64".into(),
            ..bundle()
        },
        // Decodable base64, but not the JSON document a PQ certificate is.
        ClientIdentityBundle {
            pq_certificate: base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]),
            ..bundle()
        },
    ] {
        assert!(broken.validate().is_err(), "{broken:?} should be refused");
    }
    assert!(bundle().validate().is_ok());
}

#[test]
fn debug_never_prints_private_material() {
    let bundle = bundle();
    let rendered = format!("{bundle:?}");

    assert!(rendered.contains("orion-portable"));
    assert!(rendered.contains("private_key: \"***\""));
    assert!(rendered.contains("pq_private_key: \"***\""));
    assert!(!rendered.contains(&bundle.private_key));
    assert!(!rendered.contains(&bundle.pq_private_key));
}

#[test]
fn serialized_bundles_reject_unknown_fields() {
    let mut value = serde_json::to_value(bundle()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), serde_json::Value::Bool(true));

    assert!(serde_json::from_value::<ClientIdentityBundle>(value).is_err());
}

/// The identity name comes from an operator-written document: it must not
/// be able to designate a file outside the store.
#[test]
fn an_identity_name_cannot_escape_the_store_directory() {
    let store = ProtectedIdentityStore::at(PathBuf::from("/var/lib/orion"));

    for hostile in ["../../etc/passwd", "..", "a/b", r"..\\windows"] {
        // Refusing outright is just as good as sanitizing: nothing is
        // written either way. What must never happen is a path that
        // leaves the store directory.
        if let Ok(path) = store.path_of(hostile) {
            assert_eq!(
                path.parent(),
                Some(Path::new("/var/lib/orion")),
                "{hostile} escaped the store"
            );
            assert!(!path.to_string_lossy().contains(".."));
        }
    }
    assert_eq!(
        store.path_of("orion-portable").unwrap(),
        Path::new("/var/lib/orion/orion-portable.identity")
    );
    assert!(store.path_of("...").is_err());

    let long = "a".repeat(128);
    let path = store.path_of(&long).unwrap();
    assert_eq!(
        path.file_stem().unwrap().to_string_lossy().len(),
        96,
        "identity filenames are bounded"
    );
}

#[test]
fn contains_only_accepts_a_regular_identity_file() {
    let directory = test_directory("contains");
    std::fs::create_dir_all(&directory).unwrap();
    let store = ProtectedIdentityStore::at(directory.clone());
    let path = store.path_of("portable").unwrap();

    assert!(!store.contains("portable"));
    std::fs::create_dir(&path).unwrap();
    assert!(
        !store.contains("portable"),
        "a directory is not a sealed identity"
    );
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(&path, b"sealed").unwrap();
    assert!(store.contains("portable"));

    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn bounded_reads_distinguish_the_limit_from_an_oversized_blob() {
    let directory = test_directory("bounded");
    std::fs::create_dir_all(&directory).unwrap();
    let exact = directory.join("exact.identity");
    let oversized = directory.join("oversized.identity");
    std::fs::write(&exact, vec![0x5a; MAX_SEALED_BYTES]).unwrap();
    std::fs::write(&oversized, vec![0x5a; MAX_SEALED_BYTES + 1]).unwrap();

    assert_eq!(read_bounded(&exact).unwrap().len(), MAX_SEALED_BYTES);
    let error = read_bounded(&oversized).expect_err("oversized identity must be refused");
    assert!(error.to_string().contains("anormalement volumineuse"));
    assert!(read_bounded(&directory.join("missing.identity")).is_err());

    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn promotion_keeps_the_outgoing_bundle_until_the_overlap_ends() {
    let outgoing = bundle();
    let mut incoming = outgoing.clone();
    incoming.pq_private_key = base64::engine::general_purpose::STANDARD.encode([9u8; 64]);
    let mut record = ProtectedIdentityRecord::new(outgoing.clone());

    assert!(record
        .promote(incoming.clone(), 2_000, 3_000)
        .expect("promoted"));
    assert_eq!(record.current, incoming);
    assert_eq!(
        record.previous.as_ref().map(|slot| &slot.bundle),
        Some(&outgoing)
    );
    assert_eq!(
        record.previous_status(2_000).map(|status| status.phase),
        Some(PreviousIdentityPhase::Available)
    );

    record
        .select_previous(2_100)
        .expect("selected during overlap");
    assert_eq!(record.served_at(2_100), &outgoing);
    assert_eq!(
        record.previous_status(2_100).map(|status| status.selected),
        Some(true)
    );

    assert_ne!(record.served_at(3_000), &outgoing);
    assert!(record.select_previous(3_000).is_err());
    assert!(record.retire_previous(3_000));
    assert!(record.previous.is_none());
    assert!(!record.serve_previous);
    let retired_record = serde_json::to_string(&record).expect("serialized tombstone");
    assert!(!retired_record.contains(&outgoing.pq_private_key));
    assert_eq!(
        record.previous_status(3_001).map(|status| status.phase),
        Some(PreviousIdentityPhase::Expired)
    );
}

#[test]
fn replaying_promotion_preserves_an_explicit_service_rollback() {
    let outgoing = bundle();
    let mut incoming = outgoing.clone();
    incoming.pq_private_key = base64::engine::general_purpose::STANDARD.encode([9u8; 64]);
    let mut record = ProtectedIdentityRecord::new(outgoing.clone());
    record
        .promote(incoming.clone(), 2_000, 3_000)
        .expect("promoted");
    record.select_previous(2_100).expect("selected");

    assert!(!record
        .promote(incoming, 2_000, 3_000)
        .expect("idempotent promotion"));
    assert_eq!(record.served_at(2_200), &outgoing);
}

#[test]
fn a_second_previous_slot_is_refused_while_the_first_is_live() {
    let outgoing = bundle();
    let mut first = outgoing.clone();
    first.pq_private_key = base64::engine::general_purpose::STANDARD.encode([8u8; 64]);
    let mut second = outgoing.clone();
    second.pq_private_key = base64::engine::general_purpose::STANDARD.encode([9u8; 64]);
    let mut record = ProtectedIdentityRecord::new(outgoing);
    record.promote(first, 2_000, 3_000).expect("first");

    assert!(record.promote(second, 2_500, 4_000).is_err());
}

#[test]
fn loading_an_absent_identity_reports_its_name() {
    let store = ProtectedIdentityStore::at(test_directory("missing"));
    let error = store.load("workstation").expect_err("identity is absent");
    assert!(
        error.downcast_ref::<IdentityStoreError>().is_some_and(
            |error| matches!(error, IdentityStoreError::NotFound(name) if name == "workstation")
        ),
        "unexpected error: {error}"
    );
}

/// Exercises the actual Windows account boundary rather than the
/// non-Windows refusal compiled on the Linux runner.
#[cfg(windows)]
#[test]
fn dpapi_sealing_round_trips_and_hides_the_plaintext() {
    let plaintext = b"orion identity private material";
    let sealed = seal(plaintext).expect("DPAPI must seal for the current test account");

    assert_ne!(sealed, plaintext);
    assert!(
        !sealed
            .windows(plaintext.len())
            .any(|window| window == plaintext),
        "the DPAPI envelope must not contain the plaintext"
    );
    assert_eq!(unseal(&sealed).unwrap().as_slice(), plaintext);
}

/// Covers validation, DPAPI, the atomic replacement and decoding as one
/// operation on the platform Orion actually ships for.
#[cfg(windows)]
#[test]
fn protected_store_round_trips_and_replaces_an_identity() {
    let directory = test_directory("windows-round-trip");
    let store = ProtectedIdentityStore::at(directory.clone());
    let first = bundle();

    let path = store.store(&first).unwrap();
    let ciphertext = std::fs::read(&path).unwrap();
    assert!(!ciphertext
        .windows(first.private_key.len())
        .any(|window| { window == first.private_key.as_bytes() }));
    assert!(store.contains(&first.identity));
    let loaded = store.load(&first.identity).unwrap();
    assert_eq!(loaded.private_key, first.private_key);
    assert_eq!(loaded.pq_private_key, first.pq_private_key);

    let mut replacement = first;
    replacement.pq_private_key = base64::engine::general_purpose::STANDARD.encode([9u8; 64]);
    store.store(&replacement).unwrap();
    assert_eq!(
        store.load(&replacement.identity).unwrap().pq_private_key,
        replacement.pq_private_key
    );
    assert!(std::fs::read_dir(&directory).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));

    std::fs::remove_dir_all(directory).unwrap();
}

/// DPAPI authentication must turn a modified blob into an explicit
/// decryption failure, never partially decoded identity material.
#[cfg(windows)]
#[test]
fn a_tampered_identity_blob_is_refused() {
    let directory = test_directory("windows-tamper");
    let store = ProtectedIdentityStore::at(directory.clone());
    let identity = bundle();
    let path = store.store(&identity).unwrap();
    let mut sealed = std::fs::read(&path).unwrap();
    let last = sealed.last_mut().expect("DPAPI produced a non-empty blob");
    *last ^= 0x80;
    std::fs::write(&path, sealed).unwrap();

    let error = store
        .load(&identity.identity)
        .expect_err("modified DPAPI material must not open");
    assert!(
        error
            .downcast_ref::<IdentityStoreError>()
            .is_some_and(|error| matches!(error, IdentityStoreError::Unseal(_))),
        "unexpected error: {error}"
    );

    std::fs::remove_dir_all(directory).unwrap();
}

/// The refusal must be explicit rather than a silent plaintext fallback:
/// a screen promising a protected store must not be served by a file
/// anyone can read.
#[cfg(not(windows))]
#[test]
fn sealing_fails_loudly_where_no_protected_store_exists() {
    let error = seal(b"secret").expect_err("no protected store outside Windows");
    assert!(
        error
            .downcast_ref::<IdentityStoreError>()
            .is_some_and(|e| matches!(e, IdentityStoreError::UnsupportedPlatform)),
        "unexpected error: {error}"
    );
    assert!(unseal(b"secret").is_err());
}

/// Storing must not write anything when the platform cannot seal: a
/// plaintext bundle left behind would be worse than no import at all.
#[cfg(not(windows))]
#[test]
fn a_refused_seal_leaves_no_file_behind() {
    let directory = test_directory("refused-seal");
    let store = ProtectedIdentityStore::at(directory.clone());

    assert!(store.store(&bundle()).is_err());
    assert!(!store.contains("orion-portable"));
    assert!(
        std::fs::read_dir(&directory).is_err(),
        "nothing must have been created"
    );
}
