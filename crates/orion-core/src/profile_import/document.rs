//! Admission of an exchange document: what is read from disk, which parser
//! the name selects, and what the result still lacks.

use std::{fs::File, io::Read, path::Path};

use anyhow::{Context, Result};

use aether::key_negotiation::EnrollmentDocument;

use crate::enrollment::EnrollmentOutcome;
use crate::{ClientConfig, ClientProfile};

use super::json::parse_json;
use super::validate_imported_profile;
use super::wg_quick::parse_wg_quick;

/// Maximum size of an imported profile. A normal profile fits in a few KB.
pub const MAX_PROFILE_IMPORT_BYTES: usize = 64 * 1024;

/// A decoded document: the profile, and the signed envelope it came in.
///
/// No document carries a secret any more. A v5 document is signed under the
/// operator's `CA-PQ` and answers a request this machine made; the private
/// keys it is completed with never left the pending enrollment
/// (NEGOCIATION-DE-CLE-V5 §15.3).
#[derive(Debug)]
pub struct ProfileImport {
    pub profile: ClientProfile,
    /// Present for a signed v5 document, which nothing may display before
    /// [`crate::enrollment::complete_enrollment`] has verified it.
    pub enrollment: Option<EnrollmentDocument>,
    /// What the document said that Orion read but does **not** apply.
    ///
    /// Distinct from [`CompletedImport::incomplete`], which is about a field
    /// left to fill. These are fields that were *understood and dropped* — a
    /// `DNS` line, an `MTU` — and dropping one silently changes the tunnel's
    /// behaviour without changing anything the user can see.
    pub notices: Vec<String>,
}

/// A decoded document, completed against the local configuration.
///
/// The private key is reported missing rather than raised as an error: the
/// rest of the document is sound and worth showing — endpoint, virtual
/// address, pinned certificate — and a screen that displays it lets the user
/// paste the key or re-enroll. Refusing outright left them with nothing to
/// look at and no idea which key was expected.
#[derive(Debug)]
pub struct CompletedImport {
    pub profile: ClientProfile,
    /// What the document said that Orion read but does not apply.
    ///
    /// Carried through from [`ProfileImport::notices`]: the completion step
    /// changes nothing about them, and dropping them here would undo the
    /// point of reading them at all.
    pub notices: Vec<String>,
    /// User-facing explanation when no local profile holds the private half.
    /// The profile is then handed over with an empty `private_key`, and
    /// stays unconnectable until it is filled in.
    pub private_key_missing: Option<String>,
    /// Why the document is not yet connectable, when something **other** than
    /// the private key is missing.
    ///
    /// Same reasoning as the field above, generalised: an operator sends what
    /// they know, and a document without an endpoint or without a pinned
    /// gateway key is still worth showing. Refusing to import it returned the
    /// user to a file picker with a sentence, instead of to a form with one
    /// field left to fill.
    pub incomplete: Option<String>,
}

impl CompletedImport {
    /// The import of a signed document, once
    /// [`crate::enrollment::complete_enrollment`] has decided.
    ///
    /// Never completed from a local profile or a staged key: the only key a
    /// v5 document admits is the one generated with its request.
    pub fn from_enrollment(outcome: EnrollmentOutcome, notices: Vec<String>) -> Self {
        let (profile, private_key_missing) = match outcome {
            EnrollmentOutcome::Completed { profile } => (profile, None),
            EnrollmentOutcome::Unmatched { profile, expected } => (profile, Some(expected)),
        };
        let incomplete = advisory(&profile);
        Self {
            profile,
            notices,
            private_key_missing,
            incomplete,
        }
    }
}

/// Suffixes of an Orion document.
///
/// `.orion` is **ours**: it is what `helios enroll` writes and what Windows
/// associates with Orion. Leaving it out made its recognition rest entirely on
/// the first character, so the slightest disturbance at the head of the file —
/// a byte-order mark from a copy through PowerShell, a stray blank line —
/// produced «format inconnu» about the very extension the tool distributes.
///
/// `.orionprofile` is the suffix distributed until August 2026. Nothing writes
/// it anymore; it stays readable because a document on an operator's disk
/// outlives the client that reads it, and refusing what Orion itself wrote last
/// month would send the user back through an enrolment for a rename.
const ORION_SUFFIXES: &[&str] = &[".orion", ".orionprofile", ".json"];

/// Decodes an imported profile without writing it to disk.
///
/// The file suffix picks the parser; for a suffix-less file, the first
/// meaningful character lets us recognize JSON or wg-quick.
pub fn parse_profile_import(contents: &str, file_name: &str) -> Result<ProfileImport> {
    if contents.len() > MAX_PROFILE_IMPORT_BYTES {
        anyhow::bail!(
            "fichier trop volumineux (maximum {} Kio)",
            MAX_PROFILE_IMPORT_BYTES / 1024
        );
    }

    let lower_name = file_name.to_ascii_lowercase();
    let trimmed = contents.trim_start_matches('\u{feff}').trim_start();
    let named_orion = ORION_SUFFIXES
        .iter()
        .any(|suffix| lower_name.ends_with(suffix));
    let (profile, enrollment, notices) = if named_orion || trimmed.starts_with('{') {
        let parsed = parse_json(trimmed)?;
        (parsed.profile, parsed.enrollment, Vec::new())
    } else if lower_name.ends_with(".conf") || trimmed.starts_with('[') {
        let parsed = parse_wg_quick(trimmed, file_name)?;
        (parsed.profile, None, parsed.notices)
    } else {
        anyhow::bail!(
            "format inconnu : « {file_name} » ne commence ni par « {{ » (document Orion) ni par « [ » (profil WireGuard) — {}",
            describe_head(trimmed)
        );
    };

    let profile = validate_imported_profile(profile)?;
    Ok(ProfileImport {
        profile,
        enrollment,
        notices,
    })
}

/// Reads a profile from a path without ever allocating more than the import
/// limit. The check applies to bytes actually read: a size derived from
/// metadata wouldn't suffice against a file modified during reading.
pub fn read_profile_import_path(path: &Path) -> Result<ProfileImport> {
    let file = File::open(path).with_context(|| format!("ouverture de {}", path.display()))?;
    let mut bytes = Vec::with_capacity(MAX_PROFILE_IMPORT_BYTES.min(4096));
    file.take((MAX_PROFILE_IMPORT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("lecture de {}", path.display()))?;
    if bytes.len() > MAX_PROFILE_IMPORT_BYTES {
        anyhow::bail!(
            "fichier trop volumineux (maximum {} Kio)",
            MAX_PROFILE_IMPORT_BYTES / 1024
        );
    }
    let contents = decode_document(&bytes)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("le nom du profil n'est pas représentable en UTF-8")?;
    parse_profile_import(&contents, file_name)
}

/// Decodes a document whatever byte-order mark it carries.
///
/// A profile is a file a human carries from one machine to another, and that
/// trip re-encodes it: Windows PowerShell's `Out-File` writes UTF-16LE by
/// default, Notepad long prefixed UTF-8 with a BOM. Refusing those would be
/// technically defensible and practically useless — the document is intact,
/// only its clothing changed. What is **not** accepted is anything else: a
/// silent lossy conversion would turn a base64 key into a key that no longer
/// decodes, and the failure would surface much later, as a handshake that
/// never happens.
///
/// The frontend does the same thing on the file-picker path, where the bytes
/// never reach Rust (`apps/orion/src/profileDocument.ts`). The two must
/// accept the same files: an import that works by double-click and fails
/// through the button is impossible to explain to the person doing it.
pub(crate) fn decode_document(bytes: &[u8]) -> Result<String> {
    use aether::transit_text::{decode_transit_text, TransitTextError};

    decode_transit_text(bytes).map_err(|error| {
        anyhow::anyhow!(match error {
            TransitTextError::TruncatedUtf16 => {
                "le profil est encodé en UTF-16 mais tronqué (nombre impair d'octets)"
            }
            TransitTextError::InvalidUtf16 => "le profil n'est pas un texte UTF-16 valide",
            TransitTextError::InvalidUtf8 => "le profil n'est pas encodé en UTF-8",
        })
    })
}

/// Says what the document starts with, for a format error.
///
/// «format inconnu» alone leaves the user re-reading a file that looks right
/// to them. Quoting the head is what distinguishes an empty file from an
/// HTML error page saved by mistake, or from a text mangled by an encoding
/// conversion.
fn describe_head(trimmed: &str) -> String {
    if trimmed.is_empty() {
        return "le fichier est vide".to_string();
    }
    // U+FFFD is what a UTF-8 decoder leaves behind when handed UTF-16: the
    // document is intact, its encoding is not the expected one.
    if trimmed.starts_with('\u{fffd}') || trimmed.contains('\0') {
        return "le fichier n'est pas du texte UTF-8 : le réenregistrer en UTF-8, ou le recopier \
                sans passer par un éditeur"
            .to_string();
    }
    let head: String = trimmed
        .chars()
        .take(24)
        .flat_map(char::escape_debug)
        .collect();
    format!("il commence par « {head} »")
}

/// Completes a classic invitation document from the local profile of the
/// same name.
///
/// Both file-picker and system-association imports call this function. No
/// private key is ever fabricated here: a new one would break the admission
/// the gateway already granted to the original public key. A signed v5
/// document is completed by [`crate::enrollment::complete_enrollment`] instead, from the
/// pending enrollment that holds its keys.
pub fn complete_profile_import(
    mut profile: ClientProfile,
    config: &ClientConfig,
    notices: Vec<String>,
) -> Result<CompletedImport> {
    if !profile.private_key.is_empty() {
        let incomplete = advisory(&profile);
        return Ok(CompletedImport {
            profile,
            notices,
            private_key_missing: None,
            incomplete,
        });
    }

    let local = config
        .find(&profile.name)
        .filter(|candidate| !candidate.private_key.is_empty());

    let Some(existing) = local else {
        // The message names the gesture, not just the gap: the field is
        // « Importer une clé privée », in the identity block of this very
        // screen.
        let missing = format!(
            "ce document est une invitation : il ne porte pas de clé privée, et aucun profil local « {} » n'en fournit une. \
             Utiliser « Importer une clé privée », ou demander un profil complet à l'opérateur.",
            profile.name
        );
        let incomplete = advisory(&profile);
        return Ok(CompletedImport {
            profile,
            notices,
            private_key_missing: Some(missing),
            incomplete,
        });
    };

    profile.private_key = existing.private_key.duplicate();
    let incomplete = advisory(&profile);
    Ok(CompletedImport {
        profile,
        notices,
        private_key_missing: None,
        incomplete,
    })
}

/// What still stands between this profile and a tunnel, if anything.
///
/// The rules [`ClientProfile::validate`] enforces, **reported** instead of
/// raised. A document is imported for the user to look at and finish; the
/// refusal belongs at the moment they press Connect, not at the moment they
/// open a file.
///
/// The virtual address is checked here and not in `validate`, because the two
/// answer different questions. `validate` asks whether the *core* may mount
/// this profile, and the dry-run backend mounts perfectly well without a VIP;
/// this asks whether the **document** is finished, and a real tunnel needs one.
/// Folding it into `validate` would refuse simulations that have every right
/// to run.
fn advisory(profile: &ClientProfile) -> Option<String> {
    if let Err(error) = profile.validate() {
        return Some(format!("{error:#}"));
    }
    if profile
        .address
        .as_deref()
        .is_none_or(|address| address.trim().is_empty())
    {
        return Some(
            "l'adresse virtuelle est absente : elle est attribuée par la gateway à l'admission"
                .into(),
        );
    }
    None
}
