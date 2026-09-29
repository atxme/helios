use super::*;

const KEY: [u8; KEY_LEN] = [7u8; KEY_LEN];
const DOMAIN: &str = "orion.profile";

fn key_unlock() -> Unlock<'static> {
    Unlock::Key(&KEY)
}

fn context(id: &str) -> Context {
    Context::new().field("profile_id", id.as_bytes())
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aether-vault-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("test directory");
    dir
}

#[test]
fn a_sealed_secret_comes_back_identical() {
    let secret = b"cHJpdmF0ZS1rZXktYmFzZTY0";
    let ctx = context("alice");
    let blob = seal(DOMAIN, &ctx, &key_unlock(), secret).expect("seal");
    assert!(
        !blob.windows(secret.len()).any(|w| w == secret),
        "the sealed blob still contains the plaintext"
    );
    assert_eq!(
        open(DOMAIN, &ctx, &key_unlock(), &blob)
            .expect("open")
            .as_slice(),
        secret
    );
}

#[test]
fn two_seals_of_the_same_secret_differ() {
    let ctx = context("alice");
    let a = seal(DOMAIN, &ctx, &key_unlock(), b"same").expect("seal a");
    let b = seal(DOMAIN, &ctx, &key_unlock(), b"same").expect("seal b");
    assert_ne!(a, b);
}

/// The property `object_context` exists for: under a shared root key, two
/// blobs of the same kind must not be interchangeable.
#[test]
fn a_blob_of_another_object_is_refused() {
    let blob = seal(DOMAIN, &context("alice"), &key_unlock(), b"secret").expect("seal");
    assert!(matches!(
        open(DOMAIN, &context("bob"), &key_unlock(), &blob),
        Err(VaultError::ContextMismatch)
    ));
}

/// Length prefixing is what makes the context unambiguous: without it,
/// `("ab","c")` and `("a","bc")` would be the same bytes.
#[test]
fn context_fields_cannot_be_confused_by_concatenation() {
    let a = Context::new().field("k", b"ab").field("l", b"c");
    let b = Context::new().field("k", b"a").field("l", b"bc");
    assert_ne!(a.as_bytes(), b.as_bytes());

    let blob = seal(DOMAIN, &a, &key_unlock(), b"secret").expect("seal");
    assert!(matches!(
        open(DOMAIN, &b, &key_unlock(), &blob),
        Err(VaultError::ContextMismatch)
    ));
}

#[test]
fn context_field_order_matters() {
    let a = Context::new().field("x", b"1").field("y", b"2");
    let b = Context::new().field("y", b"2").field("x", b"1");
    assert_ne!(a.as_bytes(), b.as_bytes());
}

#[test]
fn a_context_rewritten_in_the_blob_fails_the_tag() {
    let mut blob = seal(DOMAIN, &context("aaaaa"), &key_unlock(), b"secret").expect("seal");
    let at = FIXED_HEADER_LEN + DOMAIN.len();
    let ctx = context("aaaaa");
    let replacement = context("bbbbb");
    assert_eq!(ctx.as_bytes().len(), replacement.as_bytes().len());
    blob[at..at + replacement.as_bytes().len()].copy_from_slice(replacement.as_bytes());
    assert!(matches!(
        open(DOMAIN, &replacement, &key_unlock(), &blob),
        Err(VaultError::Undecipherable)
    ));
}

#[test]
fn peek_context_reads_the_declared_context() {
    let ctx = context("alice");
    let blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
    assert_eq!(peek_context(&blob).expect("peek"), ctx.as_bytes());
}

#[test]
fn a_wrong_key_is_refused() {
    let ctx = context("alice");
    let blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
    let other = [8u8; KEY_LEN];
    assert!(matches!(
        open(DOMAIN, &ctx, &Unlock::Key(&other), &blob),
        Err(VaultError::Undecipherable)
    ));
}

#[test]
fn a_substituted_domain_is_refused() {
    let ctx = context("alice");
    let blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
    assert!(matches!(
        open("helios.gateway.wg-key", &ctx, &key_unlock(), &blob),
        Err(VaultError::DomainMismatch { .. })
    ));
}

#[test]
fn an_unknown_version_is_refused_not_guessed() {
    let ctx = context("alice");
    let mut blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
    blob[4] = 99;
    assert!(matches!(
        open(DOMAIN, &ctx, &key_unlock(), &blob),
        Err(VaultError::UnsupportedVersion(99))
    ));
}

/// The withdrawn identifier must never be silently reinterpreted.
///
/// This is the whole point of burning it: a vault written when `1` meant
/// SHA-256 fails with a message saying so, instead of being handed to
/// SHA-512 and producing an `Undecipherable` that looks like corruption.
#[test]
fn the_burned_kdf_is_refused_and_named() {
    let ctx = context("alice");
    let mut blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
    blob[5] = kdf::BURNED_PBKDF2_HMAC_SHA256;
    let error = open(DOMAIN, &ctx, &key_unlock(), &blob).unwrap_err();
    assert!(
        matches!(error, VaultError::BurnedKdf(1)),
        "obtained: {error}"
    );
}

/// No live identifier may collide with the burned one.
#[test]
fn no_live_kdf_reuses_the_burned_identifier() {
    assert_ne!(kdf::RAW, kdf::BURNED_PBKDF2_HMAC_SHA256);
    assert_ne!(kdf::PBKDF2_HMAC_SHA512, kdf::BURNED_PBKDF2_HMAC_SHA256);
    assert_ne!(kdf::HKDF_SHA256, kdf::BURNED_PBKDF2_HMAC_SHA256);
    assert_eq!(
        Unlock::Passphrase("x").id(),
        kdf::PBKDF2_HMAC_SHA512,
        "the passphrase path must not write the burned identifier"
    );
}

#[test]
fn an_unknown_kdf_is_refused() {
    let ctx = context("alice");
    let mut blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
    blob[5] = 42;
    assert!(matches!(
        open(DOMAIN, &ctx, &key_unlock(), &blob),
        Err(VaultError::UnsupportedKdf(42))
    ));
}

#[test]
fn bad_magic_is_refused() {
    let ctx = context("alice");
    let mut blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
    blob[0] = b'X';
    assert!(matches!(
        open(DOMAIN, &ctx, &key_unlock(), &blob),
        Err(VaultError::BadMagic)
    ));
}

#[test]
fn a_lying_context_length_does_not_panic() {
    let ctx = context("alice");
    let mut blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
    blob[7] = 0xff;
    blob[8] = 0xff;
    let error = open(DOMAIN, &ctx, &key_unlock(), &blob).unwrap_err();
    assert!(
        matches!(error, VaultError::ContextTooLong | VaultError::Truncated(_)),
        "obtained: {error}"
    );
}

#[test]
fn a_lying_domain_length_does_not_panic() {
    let ctx = context("alice");
    let mut blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
    blob[6] = 255;
    assert!(matches!(
        open(DOMAIN, &ctx, &key_unlock(), &blob),
        Err(VaultError::Truncated(_))
    ));
}

#[test]
fn every_truncation_is_refused_without_panicking() {
    let ctx = context("alice");
    let blob = seal(DOMAIN, &ctx, &key_unlock(), b"a reasonably long secret").expect("seal");
    for cut in 0..blob.len() {
        open(DOMAIN, &ctx, &key_unlock(), &blob[..cut])
            .expect_err("a truncated vault must never open");
    }
}

/// Header, context, ciphertext and tag in one sweep. Would catch an AAD
/// that stopped covering a field.
#[test]
fn flipping_any_byte_is_refused() {
    let ctx = context("alice");
    let blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret payload").expect("seal");
    for index in 0..blob.len() {
        let mut altered = blob.clone();
        altered[index] ^= 0xff;
        assert!(
            open(DOMAIN, &ctx, &key_unlock(), &altered).is_err(),
            "byte {index} altered and the vault still opened"
        );
    }
}

#[test]
fn a_vault_over_the_bound_is_refused_before_parsing() {
    let oversized = vec![0u8; MAX_VAULT_BYTES + 1];
    assert!(matches!(
        open(DOMAIN, &context("alice"), &key_unlock(), &oversized),
        Err(VaultError::TooLarge(_))
    ));
}

/// `seal` must not produce what `open` would reject: discovering that at
/// read time would mean a secret written and lost.
#[test]
fn seal_refuses_what_open_could_not_read() {
    let plaintext = vec![0u8; MAX_VAULT_BYTES];
    assert!(matches!(
        seal(DOMAIN, &context("alice"), &key_unlock(), &plaintext),
        Err(VaultError::TooLarge(_))
    ));
}

#[test]
fn a_context_over_the_bound_is_refused() {
    let ctx = Context::new().field("blob", &vec![0u8; MAX_CONTEXT_BYTES]);
    assert!(matches!(
        seal(DOMAIN, &ctx, &key_unlock(), b"secret"),
        Err(VaultError::ContextTooLong)
    ));
}

#[test]
fn a_domain_over_the_bound_is_refused() {
    let domain = "d".repeat(MAX_DOMAIN_BYTES + 1);
    assert!(matches!(
        seal(&domain, &context("alice"), &key_unlock(), b"secret"),
        Err(VaultError::DomainTooLong)
    ));
}

#[test]
fn an_empty_secret_round_trips() {
    let ctx = context("alice");
    let blob = seal(DOMAIN, &ctx, &key_unlock(), b"").expect("seal");
    assert!(open(DOMAIN, &ctx, &key_unlock(), &blob)
        .expect("open")
        .is_empty());
}

#[test]
fn a_passphrase_round_trips() {
    let unlock = Unlock::Passphrase("correcte batterie agrafe cheval quinze");
    let ctx = context("alice");
    let blob = seal(DOMAIN, &ctx, &unlock, b"secret").expect("seal");
    assert_eq!(
        open(DOMAIN, &ctx, &unlock, &blob).expect("open").as_slice(),
        b"secret"
    );
}

#[test]
fn a_wrong_passphrase_is_refused() {
    let ctx = context("alice");
    let blob = seal(DOMAIN, &ctx, &Unlock::Passphrase("bonne"), b"secret").expect("seal");
    assert!(matches!(
        open(DOMAIN, &ctx, &Unlock::Passphrase("mauvaise"), &blob),
        Err(VaultError::Undecipherable)
    ));
}

#[test]
fn the_unlock_method_must_match() {
    let ctx = context("alice");
    let blob = seal(DOMAIN, &ctx, &Unlock::Passphrase("phrase"), b"secret").expect("seal");
    assert!(matches!(
        open(DOMAIN, &ctx, &key_unlock(), &blob),
        Err(VaultError::UnlockMismatch)
    ));
}

/// Pins the PRF **and** the iteration count.
///
/// Every other passphrase test would pass unchanged if the KDF silently
/// became SHA-256, or if the count were lowered — seal and open would
/// simply agree with each other. This vector does not: it is
/// `PBKDF2-HMAC-SHA-512(passphrase, salt, 600 000, 32)` computed
/// independently. ADR-006 §3 requires the `kdf` identifier to bind the
/// whole parameter set; this is what makes that binding real.
#[test]
fn the_passphrase_kdf_matches_its_reference_vector() {
    let salt: [u8; SALT_LEN] = std::array::from_fn(|i| i as u8);
    let expected = hex_to_bytes("4047acfe6d63e30a1f0f135f1c1c2c1d581492cdd2697405c8d7bdd1070eb0a0");
    let derived = derive_key_material(
        &Unlock::Passphrase("correcte batterie agrafe cheval quinze"),
        &salt,
    )
    .expect("derive");
    assert_eq!(
        derived.as_ref(),
        expected.as_slice(),
        "the passphrase KDF is no longer PBKDF2-HMAC-SHA-512 at {PBKDF2_ITERATIONS} iterations"
    );

    // And the SHA-256 output of the same inputs, so a swap is caught with
    // a message naming the culprit rather than a bare mismatch.
    let sha256 = hex_to_bytes("8773d7bfacbcb6bb09182f5328c73f1db9e866aa949aff13a02cb615397e38b6");
    assert_ne!(
        derived.as_ref(),
        sha256.as_slice(),
        "the KDF fell back to SHA-256"
    );
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

const PSK_MAP_INFO: &[u8] = b"helios/static-psk-map/v1";

fn derived_unlock(ikm: &[u8]) -> Unlock<'_> {
    Unlock::Derived {
        ikm,
        info: PSK_MAP_INFO,
    }
}

#[test]
fn a_derived_key_round_trips() {
    let ikm = [9u8; 32];
    let ctx = context("gateway");
    let blob = seal(DOMAIN, &ctx, &derived_unlock(&ikm), b"table").expect("seal");
    assert_eq!(
        open(DOMAIN, &ctx, &derived_unlock(&ikm), &blob)
            .expect("open")
            .as_slice(),
        b"table"
    );
}

/// The property ADR-006 §4 relies on: the vault lives and dies with the
/// key material it was derived from. Another identity opens nothing.
#[test]
fn another_input_keying_material_opens_nothing() {
    let ctx = context("gateway");
    let blob = seal(DOMAIN, &ctx, &derived_unlock(&[9u8; 32]), b"table").expect("seal");
    assert!(matches!(
        open(DOMAIN, &ctx, &derived_unlock(&[8u8; 32]), &blob),
        Err(VaultError::Undecipherable)
    ));
}

/// `info` separates uses: the same material under another label is another
/// key, so a PSK table cannot be opened as anything else.
#[test]
fn another_info_label_opens_nothing() {
    let ikm = [9u8; 32];
    let ctx = context("gateway");
    let blob = seal(DOMAIN, &ctx, &derived_unlock(&ikm), b"table").expect("seal");
    let other = Unlock::Derived {
        ikm: &ikm,
        info: b"helios/autre-usage/v1",
    };
    assert!(matches!(
        open(DOMAIN, &ctx, &other, &blob),
        Err(VaultError::Undecipherable)
    ));
}

/// Two seals of the same material must not share a key: the container's
/// fresh salt is what makes re-sealing safe.
#[test]
fn two_derived_seals_use_different_salts() {
    let ikm = [9u8; 32];
    let ctx = context("gateway");
    let a = seal(DOMAIN, &ctx, &derived_unlock(&ikm), b"table").expect("seal a");
    let b = seal(DOMAIN, &ctx, &derived_unlock(&ikm), b"table").expect("seal b");
    let salt_at = FIXED_HEADER_LEN + DOMAIN.len() + ctx.as_bytes().len();
    assert_ne!(
        a[salt_at..salt_at + SALT_LEN],
        b[salt_at..salt_at + SALT_LEN]
    );
}

#[test]
fn a_derived_vault_is_not_openable_with_a_raw_key() {
    let ctx = context("gateway");
    let blob = seal(DOMAIN, &ctx, &derived_unlock(&[9u8; 32]), b"table").expect("seal");
    assert!(matches!(
        open(DOMAIN, &ctx, &key_unlock(), &blob),
        Err(VaultError::UnlockMismatch)
    ));
}

/// Pins the PRF, the salt placement and the `info` handling against an
/// implementation written outside this crate. A round trip would agree
/// with itself under any consistent KDF.
#[test]
fn the_derived_kdf_matches_its_reference_vector() {
    let salt: [u8; SALT_LEN] = std::array::from_fn(|i| i as u8);
    let derived = derive_key_material(&derived_unlock(&[9u8; 32]), &salt).expect("derive");
    assert_eq!(
        derived.as_ref(),
        hex_to_bytes("78934c37a46e3380f05143199ac623e8acc02236d6ccc24528d5a6210a8804e1").as_slice(),
        "the derived KDF is no longer HKDF-SHA-256 over the container salt"
    );
}

#[test]
fn two_passphrase_seals_use_different_salts() {
    let unlock = Unlock::Passphrase("phrase");
    let ctx = context("alice");
    let a = seal(DOMAIN, &ctx, &unlock, b"secret").expect("seal a");
    let b = seal(DOMAIN, &ctx, &unlock, b"secret").expect("seal b");
    let salt_at = FIXED_HEADER_LEN + DOMAIN.len() + ctx.as_bytes().len();
    assert_ne!(
        a[salt_at..salt_at + SALT_LEN],
        b[salt_at..salt_at + SALT_LEN]
    );
}

#[test]
fn a_file_round_trips() {
    let dir = tmp_dir("file");
    let path = dir.join("vault.hvlt");
    let ctx = context("alice");
    let blob = seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal");
    std::fs::write(&path, &blob).unwrap();
    assert_eq!(
        open_file(&path, DOMAIN, &ctx, &key_unlock())
            .expect("open_file")
            .as_slice(),
        b"secret"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The bound must live in the **file reader**, not only in the in-memory
/// parser. A sparse file costs nothing to create and everything to read:
/// checking after a `std::fs::read` is a bound that already lost.
#[test]
fn a_sparse_file_over_the_bound_is_refused_without_reading_it() {
    let dir = tmp_dir("sparse");
    let path = dir.join("huge.hvlt");
    let file = File::create(&path).unwrap();
    // Two gigabytes that occupy no blocks. A `read_to_end` here would try
    // to allocate all of it.
    file.set_len(2 * 1024 * 1024 * 1024).unwrap();
    drop(file);

    assert!(matches!(
        open_file(&path, DOMAIN, &context("alice"), &key_unlock()),
        Err(VaultError::TooLarge(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The bound belongs to the **reader**, so a caller that peeks before it
/// opens gets it too. `static_psk` is exactly that caller: it cannot name
/// its context before reading the blob, so it must not be forced back onto
/// `std::fs::read` to do so.
#[test]
fn the_bounded_reader_refuses_a_sparse_file_on_its_own() {
    let dir = tmp_dir("bounded-reader");
    let path = dir.join("huge.hvlt");
    let file = File::create(&path).unwrap();
    file.set_len(2 * 1024 * 1024 * 1024).unwrap();
    drop(file);

    assert!(matches!(
        read_file_bounded(&path),
        Err(VaultError::TooLarge(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_bounded_reader_returns_a_blob_the_parser_accepts() {
    let dir = tmp_dir("bounded-roundtrip");
    let path = dir.join("vault.hvlt");
    let ctx = context("alice");
    std::fs::write(
        &path,
        seal(DOMAIN, &ctx, &key_unlock(), b"secret").expect("seal"),
    )
    .unwrap();

    let blob = read_file_bounded(&path).expect("read");
    assert_eq!(peek_context(&blob).expect("peek"), ctx.as_bytes());
    assert_eq!(
        open(DOMAIN, &ctx, &key_unlock(), &blob)
            .expect("open")
            .as_slice(),
        b"secret"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_file_reports_its_path() {
    let dir = tmp_dir("missing");
    let path = dir.join("absent.hvlt");
    assert!(matches!(
        open_file(&path, DOMAIN, &context("alice"), &key_unlock()),
        Err(VaultError::Io { .. })
    ));
    let _ = std::fs::remove_dir_all(&dir);
}
