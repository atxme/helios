//! The signed documents the companion reads and writes, as local files.
//!
//! # Why files rather than the routes of §8.2
//!
//! The specification has the companion fetch its request, the encrypted vault
//! and the slot to post its result into, over three capability-token routes.
//! Astra answers all three with `501` today (`crates/astra/src/service.rs`), so
//! there is nothing to call: a HTTP client written against them could not be
//! exercised, and an untestable network path in the one program that holds
//! `CA-PQ` in the clear is not a trade worth making.
//!
//! What is written instead is exactly the same objects, read from and written
//! to paths an operator names. The verification is identical — it is the
//! objects that carry the signatures, not the transport — so wiring the routes
//! later replaces the two functions below and nothing else.
//!
//! # Limite connue
//!
//! Ce module ne récupère donc rien tout seul et ne dépose rien tout seul :
//! l'opérateur copie les documents. Ce qui débloque : les routes du §8.2
//! servies par Astra, et les jetons de capacité que
//! `aether::certificates::capability` sait déjà émettre et vérifier.

use std::path::Path;

use anyhow::{bail, Context, Result};

/// Largest lifecycle document read, in bytes.
///
/// A staging authorization carries two certificates and several ML-DSA-87
/// signatures of roughly 4.6 KiB each; a campaign carries up to its own bound
/// of targets. A megabyte is far above either and refuses a file that would
/// drive an allocation before a single field is parsed.
pub const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;

/// Reads one strict JSON document, bounded before it is parsed.
pub fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("aucun document à {}", path.display()))?;
    if metadata.len() > MAX_DOCUMENT_BYTES {
        bail!(
            "{} pèse {} octets : ce n'est pas un document de cycle de vie",
            path.display(),
            metadata.len()
        );
    }
    let bytes = std::fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("lecture de {}", path.display()))
}

/// Writes one document, privately and atomically.
///
/// Private even though every one of them is public: the directory beside the
/// vault is private, and a file written world-readable into it would be the
/// one exception an operator has to remember.
pub fn write<T: serde::Serialize>(path: &Path, document: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent)
            .with_context(|| format!("création de {}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(document).context("sérialisation du document")?;
    bytes.push(b'\n');
    aether::private_file::write_private_atomic(path, &bytes)
        .with_context(|| format!("écriture de {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Document {
        value: String,
    }

    #[test]
    fn a_document_round_trips_through_the_file() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("nested").join("document.json");
        let original = Document {
            value: "délégation".into(),
        };
        write(&path, &original).expect("write");
        assert_eq!(read::<Document>(&path).expect("read"), original);
    }

    /// A file too large to be a lifecycle document is refused before it is
    /// parsed, so nothing allocates on a size an attacker chose.
    #[test]
    fn an_oversized_file_is_refused_before_it_is_parsed() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("document.json");
        std::fs::write(&path, vec![b'x'; (MAX_DOCUMENT_BYTES + 1) as usize]).expect("write");
        assert!(read::<Document>(&path).is_err());
    }

    /// Unknown members are refused rather than ignored: a document with a
    /// field this build does not understand is a document from another
    /// version, and signing around it would sign around a misreading.
    #[test]
    fn an_unknown_member_is_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("document.json");
        std::fs::write(&path, br#"{"value":"x","extra":1}"#).expect("write");
        assert!(read::<Document>(&path).is_err());
    }

    /// A duplicated member is refused rather than resolved by "the last one
    /// wins" (spec §14.1).
    ///
    /// Two values under one name is a document with two readings: an operator
    /// approving what a viewer shows them, and a verifier signing what the
    /// parser kept, would not be looking at the same object.
    #[test]
    fn a_duplicated_member_is_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("document.json");
        std::fs::write(&path, br#"{"value":"first","value":"second"}"#).expect("write");
        assert!(read::<Document>(&path).is_err());
    }
}
