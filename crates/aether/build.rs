use std::{collections::HashSet, env, fs, path::PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;

const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1_952;

fn main() {
    println!("cargo:rerun-if-env-changed=HELIOS_PUBLISHER_KEYRING_PATH");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let configured = env::var_os("HELIOS_PUBLISHER_KEYRING_PATH").map(PathBuf::from);
    let implicit_development_keys = configured.is_none();
    let keyring_path =
        configured.unwrap_or_else(|| manifest_dir.join("publisher-keyring.dev.json"));

    println!("cargo:rerun-if-changed={}", keyring_path.display());
    let json = fs::read_to_string(&keyring_path).unwrap_or_else(|e| {
        panic!(
            "lecture du trousseau éditeur {} impossible : {e}",
            keyring_path.display()
        )
    });
    let entries = serde_json::from_str::<Value>(&json)
        .unwrap_or_else(|e| panic!("trousseau éditeur JSON invalide : {e}"));
    let entries = entries
        .as_array()
        .unwrap_or_else(|| panic!("le trousseau éditeur doit être un tableau JSON"));
    let declared_development_keys = entries.iter().any(|entry| {
        entry
            .get("development")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    });
    let using_development_keys = implicit_development_keys || declared_development_keys;
    if using_development_keys && env::var("PROFILE").as_deref() == Ok("release") {
        panic!(
            "le trousseau éditeur de développement est interdit en release ; \
             fournir HELIOS_PUBLISHER_KEYRING_PATH vers un trousseau de production"
        );
    }
    assert!(
        !entries.is_empty(),
        "le trousseau éditeur ne peut pas être vide"
    );

    let mut epochs = HashSet::new();
    let mut generated = String::from("pub const PUBLISHER_KEYS: &[PublisherPublicKeys] = &[\n");
    for entry in entries {
        let epoch = entry
            .get("key_epoch")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or_else(|| panic!("key_epoch absent ou hors plage u32"));
        assert!(epochs.insert(epoch), "key_epoch {epoch} dupliquée");

        let ed25519 = decode_key(entry, "ed25519", ED25519_PUBLIC_KEY_LEN, epoch);
        let ml_dsa_65 = decode_key(entry, "ml-dsa-65", ML_DSA_65_PUBLIC_KEY_LEN, epoch);

        generated.push_str("    PublisherPublicKeys {\n");
        generated.push_str(&format!("        key_epoch: {epoch},\n"));
        generated.push_str(&format!("        ed25519: {},\n", rust_array(&ed25519)));
        generated.push_str(&format!("        ml_dsa_65: {},\n", rust_array(&ml_dsa_65)));
        generated.push_str("    },\n");
    }
    generated.push_str("];\n");
    generated.push_str(&format!(
        "pub const USING_DEVELOPMENT_PUBLISHER_KEYS: bool = {using_development_keys};\n"
    ));

    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("publisher_keyring.rs");
    fs::write(output, generated).expect("écriture du trousseau éditeur généré");
}

fn decode_key(entry: &Value, field: &str, expected_len: usize, epoch: u32) -> Vec<u8> {
    let encoded = entry
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("clé {field} absente pour l'époque {epoch}"));
    let bytes = STANDARD
        .decode(encoded)
        .unwrap_or_else(|e| panic!("clé {field} base64 invalide pour l'époque {epoch} : {e}"));
    assert_eq!(
        bytes.len(),
        expected_len,
        "clé {field} de longueur invalide pour l'époque {epoch}"
    );
    bytes
}

fn rust_array(bytes: &[u8]) -> String {
    let mut output = String::from("[");
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str(&byte.to_string());
    }
    output.push(']');
    output
}
