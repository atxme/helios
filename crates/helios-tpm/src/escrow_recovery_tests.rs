use helios_escrow::{generate_operator_keypair, open_as_operator, seal_to_operator};

use crate::{Context, SealedKeystore, SecretKey, DOMAIN_GATEWAY_WG_KEY};

fn ctx() -> Context {
    Context::new().field("wg_public_key", b"cle-publique-de-test")
}

/// The full recovery scenario belongs to the TPM integration boundary: it
/// proves that an escrowed value can be resealed after the TPM secret changes.
#[test]
fn full_recovery_after_a_pcr_change() {
    let dir = std::env::temp_dir().join(format!("helios-escrow-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = SealedKeystore::new(dir.join("wg-key.sealed"), DOMAIN_GATEWAY_WG_KEY);

    let wg_key = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let (operator_private, operator_public) = generate_operator_keypair().unwrap();

    let secret_before = SecretKey::from_bytes([1u8; 32]);
    store.store(&secret_before, &ctx(), wg_key).unwrap();
    let escrow_blob = seal_to_operator(&operator_public, wg_key).unwrap();
    assert_eq!(
        store.load(&secret_before, &ctx()).unwrap().as_slice(),
        wg_key
    );

    let secret_after = SecretKey::from_bytes([2u8; 32]);
    assert!(
        store.load(&secret_after, &ctx()).is_err(),
        "the vault must be unreadable with the new secret"
    );

    let recovered = open_as_operator(operator_private.as_slice(), &escrow_blob).unwrap();
    assert_eq!(recovered.as_slice(), wg_key, "identity recovered");

    store.store(&secret_after, &ctx(), &recovered).unwrap();
    assert_eq!(
        store.load(&secret_after, &ctx()).unwrap().as_slice(),
        wg_key
    );

    let _ = std::fs::remove_dir_all(&dir);
}
