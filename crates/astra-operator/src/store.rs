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

use crate::vault::AuthorityVault;
use anyhow::{bail, Context, Result};

/// Largest vault file read, in bytes.
///
/// The body holds two private keys and the table at most [`MAX_SLOTS`] rows;
/// a megabyte is far above that, and refuses a file that would drive an
/// allocation before a single field is parsed.
///
/// [`MAX_SLOTS`]: crate::vault::MAX_SLOTS
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

/// Writes a vault that must not already exist, at revision one.
pub fn save_new(path: &Path, vault: &AuthorityVault) -> Result<()> {
    if path.exists() {
        bail!(
            "un coffre existe déjà à {} : en créer un second par-dessus détruirait le seul objet \
             qui ouvre les ancres actuelles",
            path.display()
        );
    }
    write(
        path,
        &AuthorityVault {
            revision: 1,
            ..vault.clone()
        },
    )
}

/// Replaces the vault, atomically and privately.
///
/// The copy written is one revision past the newer of the value given and the
/// file on disk, so a stale value cannot land behind the vault it replaces. The
/// value given is left as it was.
pub fn save(path: &Path, vault: &AuthorityVault) -> Result<()> {
    let revision = vault.revision.max(revision_on_disk(path)).saturating_add(1);
    write(
        path,
        &AuthorityVault {
            revision,
            ..vault.clone()
        },
    )
}

/// The revision of the vault at `path`, read without a key: zero when there is
/// no file, or one that cannot be read as a vault.
///
/// It reads the one field and ignores the rest, so it needs no authenticator and
/// reports the counter even for a vault this machine cannot open.
pub fn revision_on_disk(path: &Path) -> u64 {
    #[derive(serde::Deserialize)]
    struct Header {
        #[serde(default)]
        revision: u64,
    }
    let Ok(metadata) = std::fs::metadata(path) else {
        return 0;
    };
    if metadata.len() > MAX_VAULT_BYTES {
        return 0;
    }
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Header>(&bytes).ok())
        .map_or(0, |header| header.revision)
}

fn write(path: &Path, vault: &AuthorityVault) -> Result<()> {
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
    use crate::vault::{AuthorityVault, SlotEnrolment, SlotRole, SlotSecret};

    fn vault() -> AuthorityVault {
        AuthorityVault::create(
            aether::certificates::encoding::TrustDomainId::new([7; 16]).expect("domain"),
            "astra.example",
            crate::vault::draw_salt().expect("salt"),
            &crate::vault::AuthoritySecrets {
                ca_pq_private_key: "cHE=".into(),
                ca_pq_public_key: "cHViCg==".into(),
                ca_tls_private_key: "dGxz".into(),
                retained_ca_tls: None,
                retained_outgoing_ca_pq: None,
            },
            SlotEnrolment {
                role: SlotRole::Primary,
                label: "clé".into(),
                credential_id: vec![1; 64],
                credential_public_key: vec![0xa5, 0x01],
                aaguid: [0; 16],
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
        // The file holds the revision `save_new` gives it, and nothing else differs.
        let written = AuthorityVault {
            revision: 1,
            ..original
        };
        assert_eq!(load(&path).expect("load"), written);
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

    /// A vault written before the revision existed reads as revision zero, and
    /// the first write through [`save`] moves it to one.
    #[test]
    fn an_old_vault_reads_at_zero_and_is_rewritten_at_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.json");
        let mut value = serde_json::to_value(vault()).expect("value");
        value.as_object_mut().expect("object").remove("revision");
        std::fs::write(&path, serde_json::to_vec_pretty(&value).expect("bytes")).expect("write");
        assert_eq!(load(&path).expect("load").revision, 0);
        save(&path, &vault()).expect("save");
        assert_eq!(load(&path).expect("load").revision, 1);
    }

    /// Two saves from the same in-memory value do not write the same revision:
    /// each one counts on from what is on disk, so a copy that was held back
    /// and then written is always the newer one.
    #[test]
    fn two_saves_from_the_same_value_count_on() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.json");
        let value = vault();
        save_new(&path, &value).expect("save new");
        assert_eq!(revision_on_disk(&path), 1);
        save(&path, &value).expect("first save");
        assert_eq!(revision_on_disk(&path), 2);
        save(&path, &value).expect("second save");
        assert_eq!(revision_on_disk(&path), 3);
    }

    /// A stale value written over a newer file lands above the file it replaces,
    /// never at or below it.
    #[test]
    fn a_vault_at_zero_written_over_one_at_n_lands_above() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.json");
        save_new(&path, &vault()).expect("save new");
        for _ in 0..4 {
            save(&path, &vault()).expect("save");
        }
        assert_eq!(revision_on_disk(&path), 5);
        save(&path, &vault()).expect("save over");
        assert_eq!(revision_on_disk(&path), 6);
    }

    /// A vault at revision zero carries no revision field, so a file written
    /// before the field existed is byte-compatible with the one written now.
    #[test]
    fn an_old_vault_round_trips_without_the_field() {
        let bytes = serde_json::to_vec_pretty(&vault()).expect("bytes");
        assert!(!String::from_utf8_lossy(&bytes).contains("\"revision\""));
    }

    /// The revision is outside the sealed context: bumping it must not change
    /// what the credentials open.
    #[test]
    fn the_revision_does_not_change_opening() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.json");
        let value = vault();
        save_new(&path, &value).expect("save new");
        save(&path, &value).expect("save");
        let loaded = load(&path).expect("load");
        let secret = SlotSecret::new(vec![1; 32]);
        assert_eq!(
            loaded.open(&[1; 64], &secret).expect("opens"),
            value.open(&[1; 64], &secret).expect("opens in memory")
        );
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
