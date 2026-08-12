//! Where the encrypted vault sits on an operator's machine.
//!
//! The file is the vault, and the vault is already encrypted: what is on disk
//! is a sealed body and a table of public identifiers. The private write is
//! defence in depth rather than the protection — losing this file costs an
//! operator nothing beyond a copy, and losing *every* copy costs them the
//! trust domain, so it is meant to be backed up.
//!
//! # Refusing to overwrite
//!
//! [`save_new`] fails on an existing path. Creating a second vault over a
//! first one destroys the only object that opens the anchors, and no
//! authenticator recovers from that: the master key it wrapped is gone. Every
//! other write goes through [`save`], which an operator reaches only after
//! opening the vault they are about to replace.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use astra::vault::AuthorityVault;

/// Largest vault file read, in bytes.
///
/// The body holds two private keys and the table at most [`MAX_SLOTS`] rows;
/// a megabyte is far above that, and refuses a file that would drive an
/// allocation before a single field is parsed.
///
/// [`MAX_SLOTS`]: astra::vault::MAX_SLOTS
const MAX_VAULT_BYTES: u64 = 1024 * 1024;

/// Default location of the vault, per platform.
///
/// `%APPDATA%` on Windows, `~/.helios` elsewhere — the same place the rest of
/// the operator tooling keeps its material.
pub fn default_path() -> Result<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .context("APPDATA is not set: pass --vault explicitly")?
    } else {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME is not set: pass --vault explicitly")?
            .join(".helios")
    };
    Ok(base.join("astra").join("authority-vault.json"))
}

pub fn load(path: &Path) -> Result<AuthorityVault> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("aucun coffre d'autorité à {}", path.display()))?;
    if metadata.len() > MAX_VAULT_BYTES {
        bail!(
            "{} pèse {} octets : ce n'est pas un coffre d'autorité",
            path.display(),
            metadata.len()
        );
    }
    let bytes = std::fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("lecture du coffre {}", path.display()))
}

/// Writes a vault that must not already exist.
pub fn save_new(path: &Path, vault: &AuthorityVault) -> Result<()> {
    if path.exists() {
        bail!(
            "un coffre existe déjà à {} : en créer un second par-dessus détruirait le seul objet \
             qui ouvre les ancres actuelles",
            path.display()
        );
    }
    save(path, vault)
}

/// Replaces the vault, atomically and privately.
pub fn save(path: &Path, vault: &AuthorityVault) -> Result<()> {
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent)
            .with_context(|| format!("création de {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(vault).context("sérialisation du coffre")?;
    aether::private_file::write_private_atomic(path, &bytes)
        .with_context(|| format!("écriture de {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra::vault::{AuthorityVault, SlotEnrolment, SlotRole, SlotSecret};

    fn vault() -> AuthorityVault {
        AuthorityVault::create(
            aether::certificates::encoding::TrustDomainId::new([7; 16]).expect("domain"),
            "astra.example",
            astra::vault::draw_salt().expect("salt"),
            &astra::vault::AuthoritySecrets {
                ca_pq_private_key: "cHE=".into(),
                ca_pq_public_key: "cHViCg==".into(),
                ca_tls_private_key: "dGxz".into(),
            },
            SlotEnrolment {
                role: SlotRole::Primary,
                label: "clé".into(),
                credential_id: vec![1; 64],
                enrolled_at: 10,
            },
            &SlotSecret::new(vec![1; 32]),
            10,
        )
        .expect("create")
    }

    /// A vault survives a round trip through the file, byte for byte: the
    /// sealed body is base64 in JSON, and a lossy encoding would be found only
    /// at the next unlock.
    #[test]
    fn a_vault_round_trips_through_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("vault.json");
        let original = vault();
        save_new(&path, &original).expect("save");
        assert_eq!(load(&path).expect("load"), original);
    }

    /// Creating a second vault over the first destroys the only object that
    /// opens the anchors. The refusal is the whole point of `save_new`.
    #[test]
    fn a_second_vault_never_lands_on_the_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.json");
        save_new(&path, &vault()).expect("save");
        assert!(save_new(&path, &vault()).is_err());
        // And the replacement path, which an operator reaches only after
        // opening what they are replacing, still works.
        save(&path, &vault()).expect("save over");
    }

    /// A file too large to be a vault is refused before it is parsed.
    #[test]
    fn an_oversized_file_is_not_a_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.json");
        std::fs::write(&path, vec![b'x'; (MAX_VAULT_BYTES + 1) as usize]).expect("write");
        assert!(load(&path).is_err());
    }
}
