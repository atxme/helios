//! Import of Orion profiles from an exchange document.
//!
//! Two formats are accepted: versioned Orion JSON, intended for Helios tools,
//! and the single-peer `wg-quick` format. Import persists nothing: it
//! produces a validated [`ClientProfile`] that the UI presents as a draft.

use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use anyhow::{Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use aether::key_negotiation::ProtectionMode;

use crate::{
    config::validate_key_negotiation, identity_store::ClientIdentityBundle, ClientConfig,
    ClientProfile, KeyNegotiationSettings, DEFAULT_ALLOWED_IPS, DEFAULT_KEEPALIVE_SECS,
};

/// Stable identifier of the JSON document exchangeable with Orion.
pub const PROFILE_IMPORT_FORMAT: &str = "orion-profile";
/// Current version of the JSON document exchangeable with Orion.
pub const PROFILE_IMPORT_VERSION: u16 = 1;
/// Maximum size of an imported profile. A normal profile fits in a few KB.
pub const MAX_PROFILE_IMPORT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonEnvelope {
    #[serde(rename = "format")]
    _format: String,
    #[serde(rename = "version")]
    _version: u16,
    profile: JsonProfile,
}

#[derive(Deserialize)]
struct JsonHeader {
    format: String,
    version: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonProfile {
    /// The one required field: it is the key the profile is stored under.
    name: String,
    /// `default`, like everything below it.
    ///
    /// An operator hands out what they know, and a document is allowed to be
    /// partial. Refusing to **parse** one returned the user to a file picker
    /// with a sentence, when the useful outcome is a form with one field left
    /// to fill. [`complete_profile_import`] names what is missing, and
    /// [`ClientProfile::validate`] is what refuses a tunnel — parsing only
    /// decides whether the document is intelligible.
    #[serde(default)]
    endpoint: String,
    /// Absent in an invitation profile: the operator doesn't hold the
    /// client's private key and therefore has nothing to send back
    /// (ADR-004 §6). [`complete_profile_import`] then takes it from the local
    /// profile holding the admitted key, or from a key just generated.
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    peer_public_key: String,
    #[serde(default)]
    preshared_key: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    allowed_ips: Option<String>,
    #[serde(default)]
    persistent_keepalive: Option<u16>,
    #[serde(default)]
    heliosd_url: Option<String>,
    #[serde(default)]
    ssh_target: Option<String>,
    /// Public key-negotiation material distributed with the profile.
    ///
    /// The client's own certificate and private key never travel here: they
    /// go into the machine's protected identity store, and the document only
    /// names the entry to look up.
    #[serde(default)]
    key_negotiation: Option<JsonKeyNegotiation>,
    /// Client identity, when the operator ships it with the profile.
    ///
    /// **Never lands in [`ClientProfile`]**: it goes to the machine's
    /// protected store and the profile keeps only the entry name. A
    /// document carrying it is a secret and must be destroyed after import.
    #[serde(default)]
    key_negotiation_identity: Option<ClientIdentityBundle>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonKeyNegotiation {
    mode: ProtectionMode,
    #[serde(default)]
    minimum_mode: Option<ProtectionMode>,
    endpoint: String,
    server_name: String,
    gateway_ca_der: String,
    gateway_pq_certificate: String,
    identity: String,
}

impl From<JsonKeyNegotiation> for KeyNegotiationSettings {
    fn from(value: JsonKeyNegotiation) -> Self {
        Self {
            mode: value.mode,
            // An absent floor is not "no floor": a document asking for ML-KEM
            // that would accept a classic negotiation tomorrow protects
            // nothing. The floor therefore starts at the mode the operator
            // chose, and an explicit floor is honored as-is — including a
            // contradictory one, which import then rejects rather than
            // silently repairs.
            minimum_mode: value.minimum_mode.unwrap_or(value.mode),
            endpoint: value.endpoint,
            server_name: value.server_name,
            gateway_ca_der: value.gateway_ca_der,
            gateway_pq_certificate: value.gateway_pq_certificate,
            identity: value.identity,
        }
    }
}

impl From<JsonProfile> for ClientProfile {
    fn from(profile: JsonProfile) -> Self {
        Self {
            name: profile.name,
            endpoint: profile.endpoint,
            private_key: profile.private_key,
            peer_public_key: profile.peer_public_key,
            preshared_key: profile.preshared_key,
            address: profile.address,
            allowed_ips: profile
                .allowed_ips
                .unwrap_or_else(|| DEFAULT_ALLOWED_IPS.to_string()),
            persistent_keepalive: profile
                .persistent_keepalive
                .unwrap_or(DEFAULT_KEEPALIVE_SECS),
            heliosd_url: profile.heliosd_url,
            ssh_target: profile.ssh_target,
            key_negotiation: profile.key_negotiation.map(KeyNegotiationSettings::from),
            // A document is a configuration: any PSK it carries was shared
            // out of band, never negotiated.
            preshared_key_is_negotiated: false,
        }
    }
}

/// A decoded document: the profile, and the identity that came with it.
///
/// The two are returned separately because they have opposite destinies —
/// the profile is persisted in `profiles.toml`, the identity is sealed into
/// the protected store and the plaintext is dropped. Returning one value that
/// mixed them would make it far too easy to write the secret to disk.
#[derive(Debug)]
pub struct ProfileImport {
    pub profile: ClientProfile,
    /// Present only when the operator shipped the identity in the document.
    pub identity: Option<ClientIdentityBundle>,
}

impl ProfileImport {
    /// WireGuard public key the gateway admitted for this document.
    ///
    /// Read from the client PQ certificate that travels with the identity:
    /// admission is bound to **that** key, so it is what says which local
    /// private key completes an invitation. The profile name never proved
    /// anything — the same client is routinely named differently on the
    /// operator's side and on the user's machine.
    ///
    /// `None` when the document ships no identity, or when its certificate
    /// carries no key: completion then falls back to the name.
    pub fn admitted_public_key(&self) -> Option<String> {
        let identity = self.identity.as_ref()?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(identity.pq_certificate.trim())
            .ok()?;
        let certificate: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        let key = certificate.get("wireguard_public_key")?.as_str()?.trim();
        (!key.is_empty()).then(|| key.to_string())
    }
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

/// Suffixes of an Orion document.
///
/// `.orionprofile` is **ours**: it is what `helios-ctl enroll` writes and what
/// Windows associates with Orion. Leaving it out made its recognition rest
/// entirely on the first character, so the slightest disturbance at the head
/// of the file — a byte-order mark from a copy through PowerShell, a stray
/// blank line — produced «format inconnu» about the very extension the tool
/// distributes.
const ORION_SUFFIXES: &[&str] = &[".orionprofile", ".json"];

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
    // wg-quick has no notion of a client identity: only the Orion document
    // can carry one.
    let (profile, identity) = if named_orion || trimmed.starts_with('{') {
        parse_json(trimmed)?
    } else if lower_name.ends_with(".conf") || trimmed.starts_with('[') {
        (parse_wg_quick(trimmed, file_name)?, None)
    } else {
        anyhow::bail!(
            "format inconnu : « {file_name} » ne commence ni par « {{ » (document Orion) ni par « [ » (profil WireGuard) — {}",
            describe_head(trimmed)
        );
    };

    let profile = validate_imported_profile(profile)?;
    if let Some(identity) = &identity {
        identity.validate()?;
        // A document shipping an identity for an entry the profile does not
        // name would seal a secret nothing would ever read.
        let expected = profile
            .key_negotiation
            .as_ref()
            .map(|settings| settings.identity.trim());
        if expected != Some(identity.identity.trim()) {
            anyhow::bail!(
                "l'identité fournie (« {} ») ne correspond pas à celle que le profil désigne",
                identity.identity
            );
        }
    }
    Ok(ProfileImport { profile, identity })
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
fn decode_document(bytes: &[u8]) -> Result<String> {
    fn from_utf16(bytes: &[u8], little_endian: bool) -> Result<String> {
        if !bytes.len().is_multiple_of(2) {
            anyhow::bail!("le profil est encodé en UTF-16 mais tronqué (nombre impair d'octets)");
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| {
                if little_endian {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            })
            .collect();
        String::from_utf16(&units).context("le profil n'est pas un texte UTF-16 valide")
    }

    match bytes {
        [0xFF, 0xFE, rest @ ..] => from_utf16(rest, true),
        [0xFE, 0xFF, rest @ ..] => from_utf16(rest, false),
        [0xEF, 0xBB, 0xBF, rest @ ..] => {
            String::from_utf8(rest.to_vec()).context("le profil n'est pas encodé en UTF-8")
        }
        _ => String::from_utf8(bytes.to_vec()).context("le profil n'est pas encodé en UTF-8"),
    }
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

/// Completes an invitation document from the local profile that holds the
/// admitted key.
///
/// Both file-picker and system-association imports call this function. No
/// private key is ever fabricated here: a new one would break the admission
/// the gateway already granted to the original public key.
///
/// `admitted_public_key` — see [`ProfileImport::admitted_public_key`] — is
/// what designates the local profile. It is matched by **key**, not by name:
/// `helios-ctl enroll --public-key` is normally run for a client that already
/// exists locally under another name, and the name rule alone refused those
/// documents. When the document names no key, the name stays the only
/// available criterion.
pub fn complete_profile_import(
    mut profile: ClientProfile,
    config: &ClientConfig,
    admitted_public_key: Option<&str>,
) -> Result<CompletedImport> {
    if !profile.private_key.is_empty() {
        let incomplete = advisory(&profile);
        return Ok(CompletedImport {
            profile,
            private_key_missing: None,
            incomplete,
        });
    }

    let local = match admitted_public_key {
        // A same-name profile holding *another* key is not a match: it was
        // never admitted, and its tunnel would fail at the first handshake
        // without saying why.
        Some(admitted) => config
            .profiles
            .iter()
            .find(|candidate| candidate.public_key().as_deref() == Some(admitted)),
        None => config
            .find(&profile.name)
            .filter(|candidate| !candidate.private_key.trim().is_empty()),
    };

    let Some(existing) = local else {
        // The message names the gesture, not just the gap. It used to end on
        // "coller la clé privée correspondante" with nothing saying where —
        // the field is « Importer une clé privée », in the identity block of
        // this very screen.
        let missing = match admitted_public_key {
            Some(admitted) => format!(
                "ce document est une invitation : il ne porte pas de clé privée, et aucune clé de ce poste ne correspond à la clé admise « {admitted} ». \
                 Utiliser « Importer une clé privée » si vous détenez la moitié privée de cette clé, ou demander un profil complet à l'opérateur."
            ),
            None => format!(
                "ce document est une invitation : il ne porte pas de clé privée, et aucun profil local « {} » n'en fournit une. \
                 Utiliser « Importer une clé privée », ou demander un profil complet à l'opérateur.",
                profile.name
            ),
        };
        let incomplete = advisory(&profile);
        return Ok(CompletedImport {
            profile,
            private_key_missing: Some(missing),
            incomplete,
        });
    };

    profile.private_key = existing.private_key.clone();
    let incomplete = advisory(&profile);
    Ok(CompletedImport {
        profile,
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

fn parse_json(contents: &str) -> Result<(ClientProfile, Option<ClientIdentityBundle>)> {
    // Reading the header first guarantees an intelligible version error even
    // if a future version entirely changes the shape of `profile`.
    let header: JsonHeader =
        serde_json::from_str(contents).context("document JSON Orion invalide")?;
    if header.format != PROFILE_IMPORT_FORMAT {
        anyhow::bail!(
            "format JSON non reconnu : « {} » au lieu de « {PROFILE_IMPORT_FORMAT} »",
            header.format
        );
    }
    if header.version != PROFILE_IMPORT_VERSION {
        anyhow::bail!(
            "version de profil Orion non prise en charge : {} (version attendue : {PROFILE_IMPORT_VERSION})",
            header.version
        );
    }
    let envelope: JsonEnvelope =
        serde_json::from_str(contents).context("document JSON Orion invalide")?;
    let mut profile = envelope.profile;
    // Taken out before the conversion: `ClientProfile` has no field for it,
    // and that is the property worth keeping — the secret cannot reach
    // `profiles.toml` by way of a struct update.
    let identity = profile.key_negotiation_identity.take();
    Ok((profile.into(), identity))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WgSection {
    Interface,
    Peer,
}

fn parse_wg_quick(contents: &str, file_name: &str) -> Result<ClientProfile> {
    let mut section = None;
    let mut interface = HashMap::new();
    let mut peer = HashMap::new();
    let mut interface_count = 0_u8;
    let mut peer_count = 0_u8;

    for (index, raw_line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            section = match line[1..line.len() - 1].trim().to_ascii_lowercase().as_str() {
                "interface" => {
                    interface_count += 1;
                    if interface_count > 1 {
                        anyhow::bail!(
                            "ligne {line_number} : une seule section [Interface] est autorisée"
                        );
                    }
                    Some(WgSection::Interface)
                }
                "peer" => {
                    peer_count += 1;
                    if peer_count > 1 {
                        anyhow::bail!(
                            "ligne {line_number} : Orion accepte un seul pair par profil"
                        );
                    }
                    Some(WgSection::Peer)
                }
                other => anyhow::bail!("ligne {line_number} : section [{other}] inconnue"),
            };
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            anyhow::bail!("ligne {line_number} : propriété WireGuard mal formée");
        };
        let key = raw_key.trim().to_ascii_lowercase();
        let value = raw_value.trim().to_string();
        let fields = match section {
            Some(WgSection::Interface) => &mut interface,
            Some(WgSection::Peer) => &mut peer,
            None => {
                anyhow::bail!("ligne {line_number} : propriété placée avant [Interface] ou [Peer]")
            }
        };
        if fields.insert(key.clone(), value).is_some() {
            anyhow::bail!("ligne {line_number} : propriété {key} déclarée plusieurs fois");
        }
    }

    if peer_count == 0 {
        anyhow::bail!("section [Peer] absente du fichier WireGuard");
    }
    if interface_count == 0 {
        anyhow::bail!("section [Interface] absente du fichier WireGuard");
    }
    reject_unsupported_fields(&interface, &["privatekey", "address"], "[Interface]")?;
    reject_unsupported_fields(
        &peer,
        &[
            "publickey",
            "presharedkey",
            "allowedips",
            "endpoint",
            "persistentkeepalive",
        ],
        "[Peer]",
    )?;

    let keepalive = match peer.get("persistentkeepalive") {
        Some(raw) => raw
            .parse::<u16>()
            .context("PersistentKeepalive doit être un entier entre 0 et 65535")?,
        None => DEFAULT_KEEPALIVE_SECS,
    };

    Ok(ClientProfile {
        name: profile_name_from_file(file_name),
        endpoint: required_field(&peer, "endpoint", "Endpoint")?,
        private_key: required_field(&interface, "privatekey", "PrivateKey")?,
        peer_public_key: required_field(&peer, "publickey", "PublicKey")?,
        preshared_key: peer.get("presharedkey").cloned(),
        address: interface.get("address").cloned(),
        allowed_ips: peer
            .get("allowedips")
            .cloned()
            .unwrap_or_else(|| DEFAULT_ALLOWED_IPS.to_string()),
        persistent_keepalive: keepalive,
        heliosd_url: None,
        ssh_target: None,
        key_negotiation: None,
        preshared_key_is_negotiated: false,
    })
}

fn reject_unsupported_fields(
    fields: &HashMap<String, String>,
    supported: &[&str],
    section: &str,
) -> Result<()> {
    if let Some(field) = fields
        .keys()
        .find(|field| !supported.contains(&field.as_str()))
    {
        anyhow::bail!(
            "propriété {field} de {section} non prise en charge par Orion ; la retirer modifierait le comportement du profil"
        );
    }
    Ok(())
}

fn required_field(
    fields: &HashMap<String, String>,
    normalized_name: &str,
    display_name: &str,
) -> Result<String> {
    fields
        .get(normalized_name)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .with_context(|| format!("propriété {display_name} requise"))
}

fn profile_name_from_file(file_name: &str) -> String {
    let basename = file_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(file_name)
        .trim();
    let stem = basename.rsplit_once('.').map_or(basename, |(stem, _)| stem);
    if stem.trim().is_empty() {
        "profil-importé".to_string()
    } else {
        stem.trim().to_string()
    }
}

/// Field-by-field diagnostic of a profile being edited.
///
/// `None` = nothing to report. Each field is independent of the others.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileIssues {
    pub name: Option<String>,
    pub endpoint: Option<String>,
    pub private_key: Option<String>,
    pub peer_public_key: Option<String>,
    pub preshared_key: Option<String>,
    pub address: Option<String>,
    pub allowed_ips: Option<String>,
    pub persistent_keepalive: Option<String>,
    pub heliosd_url: Option<String>,
    pub ssh_target: Option<String>,
    /// Fault of the key-negotiation block as a whole.
    ///
    /// Deliberately a single message rather than one per sub-field: what
    /// makes the block wrong is almost always a relation — a mode below the
    /// floor, a PSK that contradicts the mode, a certificate pinned to
    /// another gateway. Reporting the fault on one sub-field would designate
    /// the wrong culprit.
    pub key_negotiation: Option<String>,
}

impl ProfileIssues {
    /// `true` if at least one field is faulty.
    pub fn any(&self) -> bool {
        *self != Self::default()
    }
}

/// Reports **all** faulty fields of a profile being edited.
///
/// Unlike [`parse_profile_import`], which refuses a document at the first
/// fault, this inspection doesn't stop: the UI must be able to highlight
/// every field in one pass, rather than discovering one at a time on each
/// save attempt.
///
/// **An empty field is not reported.** While typing, "not filled in yet" is
/// not "impossible" — marking a fresh profile red would be noise.
/// Completeness is judged elsewhere, at connection time.
///
/// The validators are the same as import's: that's deliberate. Two rule sets,
/// one for import and one for editing, would eventually diverge and the UI
/// would accept values the core refuses.
pub fn inspect_profile(profile: &ClientProfile) -> ProfileIssues {
    /// Only validates if the value is filled in.
    fn when_filled(value: &str, check: impl Fn(&str) -> Result<()>) -> Option<String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        check(trimmed).err().map(|error| error.to_string())
    }

    ProfileIssues {
        name: None,
        endpoint: when_filled(&profile.endpoint, validate_endpoint),
        private_key: when_filled(&profile.private_key, |value| {
            validate_wg_key(value, "clé privée")
        }),
        peer_public_key: when_filled(&profile.peer_public_key, |value| {
            validate_wg_key(value, "clé publique de la gateway")
        }),
        preshared_key: profile
            .preshared_key
            .as_deref()
            .and_then(|value| when_filled(value, |value| validate_wg_key(value, "PSK"))),
        address: profile.address.as_deref().and_then(|value| {
            when_filled(value, |value| validate_cidr(value, "adresse virtuelle"))
        }),
        allowed_ips: when_filled(&profile.allowed_ips, |value| {
            validate_cidr_list(value, "trafic capté")
        }),
        // Zero is not "empty": it's a value, and it disables keepalive while
        // a client behind NAT depends on it.
        persistent_keepalive: (profile.persistent_keepalive == 0)
            .then(|| "le keepalive doit être supérieur à zéro".to_string()),
        ssh_target: profile
            .ssh_target
            .as_deref()
            .and_then(|value| when_filled(value, validate_ssh_target)),
        heliosd_url: profile
            .heliosd_url
            .as_deref()
            .and_then(|value| when_filled(value, validate_heliosd_url)),
        // The block is only judged once the gateway key it is pinned to is
        // readable: without it, every certificate would look wrong while the
        // profile is merely incomplete.
        key_negotiation: profile.key_negotiation.as_ref().and_then(|settings| {
            when_filled(&profile.peer_public_key, |peer_public_key| {
                validate_key_negotiation(settings, peer_public_key, profile.has_preshared_key())
            })
        }),
    }
}

fn validate_imported_profile(mut profile: ClientProfile) -> Result<ClientProfile> {
    profile.name = profile.name.trim().to_string();
    profile.endpoint = profile.endpoint.trim().to_string();
    profile.private_key = profile.private_key.trim().to_string();
    profile.peer_public_key = profile.peer_public_key.trim().to_string();
    // Normalized rather than merely trimmed: a `wg-quick` file writes
    // `a/n,b/m` and the screen writes `a/n, b/m`. Same list, two spellings,
    // and a profile that came back from disk spelled differently from how it
    // was saved would show "unsaved changes" on every load.
    profile.allowed_ips = normalize_cidr_list(&profile.allowed_ips);
    profile.preshared_key = non_empty(profile.preshared_key);
    profile.address = non_empty(profile.address);
    profile.heliosd_url = non_empty(profile.heliosd_url);
    profile.ssh_target = non_empty(profile.ssh_target);

    if profile.name.is_empty() {
        anyhow::bail!("le nom du profil est requis");
    }
    // Absent fields are tolerated; **malformed** ones are not. The distinction
    // is the whole rule here: a document that leaves a field out is a partial
    // document the user finishes on screen, whereas a truncated key or an
    // endpoint typed as a URL is an error that would otherwise surface much
    // later, as a tunnel that never mounts.
    if !profile.endpoint.is_empty() {
        validate_endpoint(&profile.endpoint)?;
    }
    // An invitation profile arrives without a private key: the operator
    // never held the client's, which is precisely what makes this mode safe.
    if !profile.private_key.is_empty() {
        validate_wg_key(&profile.private_key, "clé privée du client")?;
    }
    if !profile.peer_public_key.is_empty() {
        validate_wg_key(&profile.peer_public_key, "clé publique de la gateway")?;
    }
    if let Some(psk) = &profile.preshared_key {
        validate_wg_key(psk, "PresharedKey")?;
    }
    if profile.allowed_ips.is_empty() {
        anyhow::bail!("AllowedIPs ne peut pas être vide");
    }
    // Absent is tolerated, malformed is not — the VIP is assigned by the
    // gateway at admission, so an invitation legitimately arrives without one.
    if let Some(address) = profile.address.as_deref() {
        validate_cidr(address, "adresse virtuelle")?;
    }
    validate_cidr_list(&profile.allowed_ips, "AllowedIPs")?;
    if profile.persistent_keepalive == 0 {
        anyhow::bail!("PersistentKeepalive doit être supérieur à zéro");
    }
    if let Some(url) = &profile.heliosd_url {
        validate_heliosd_url(url)?;
    }
    if let Some(target) = &profile.ssh_target {
        validate_ssh_target(target)?;
    }
    // Taken out of the profile: the block is validated against the peer key
    // and the PSK of the very profile that carries it.
    if let Some(mut settings) = profile.key_negotiation.take() {
        settings.endpoint = settings.endpoint.trim().to_string();
        settings.server_name = settings.server_name.trim().to_string();
        settings.gateway_ca_der = settings.gateway_ca_der.trim().to_string();
        settings.gateway_pq_certificate = settings.gateway_pq_certificate.trim().to_string();
        settings.identity = settings.identity.trim().to_string();
        validate_endpoint(&settings.endpoint).context("endpoint de négociation de clé invalide")?;
        validate_key_negotiation(
            &settings,
            &profile.peer_public_key,
            profile.has_preshared_key(),
        )?;
        profile.key_negotiation = Some(settings);
    }
    Ok(profile)
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

/// Length of a WireGuard key: 32 raw bytes…
const WG_KEY_BYTES: usize = 32;
/// …i.e. exactly 44 characters once base64-encoded.
const WG_KEY_BASE64_LEN: usize = 44;

/// Validates a base64-encoded Curve25519 key.
///
/// The messages say what's expected, not just that it's refused: "base64
/// expected" doesn't help anyone see that a character is missing at the end
/// of a truncated copy-paste. The observed length is given so it can be
/// compared at a glance to the expected 44 characters.
fn validate_wg_key(value: &str, label: &str) -> Result<()> {
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) else {
        anyhow::bail!(
            "{label} : caractères invalides. Une clé WireGuard fait {WG_KEY_BASE64_LEN} caractères base64 (A–Z, a–z, 0–9, + et /) et se termine par « = »."
        );
    };
    if decoded.len() != WG_KEY_BYTES {
        anyhow::bail!(
            "{label} : {} caractères au lieu de {WG_KEY_BASE64_LEN}. Une clé WireGuard fait {WG_KEY_BYTES} octets et se termine par « = » — vérifier que le copier-coller est complet.",
            value.chars().count()
        );
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    if endpoint.contains("://") {
        anyhow::bail!("Endpoint doit être une adresse UDP IP/FQDN:port, pas une URL");
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        anyhow::bail!("Endpoint invalide : port UDP absent");
    };
    if host.trim_matches(['[', ']']).is_empty() {
        anyhow::bail!("Endpoint invalide : hôte absent");
    }
    if host.chars().any(char::is_whitespace) {
        anyhow::bail!("Endpoint invalide : l'hôte contient un espace");
    }
    if host.starts_with('[') != host.ends_with(']') {
        anyhow::bail!("Endpoint invalide : adresse IPv6 mal délimitée");
    }
    let port = port
        .parse::<u16>()
        .context("Endpoint invalide : port UDP non numérique")?;
    if port == 0 {
        anyhow::bail!("Endpoint invalide : le port UDP doit être supérieur à zéro");
    }
    validate_endpoint_host(host)
}

/// Validates an endpoint's host: IPv6 literal in brackets, IPv4 address, or
/// hostname.
///
/// The case that motivates this function: `86.229.1286` is **neither** a
/// valid IPv4 (1286 exceeds 255) **nor** a legitimate hostname — RFC 1123
/// forbids a last label from being entirely numeric, precisely so the two
/// can't be confused. Without this rule, a mistyped IPv4 passes for a domain
/// name and the defect only shows up at the first handshake, as a failing
/// DNS resolution.
fn validate_endpoint_host(host: &str) -> Result<()> {
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner
            .parse::<Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| anyhow::anyhow!("Endpoint invalide : adresse IPv6 illisible"));
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }

    if host.len() > 253 {
        anyhow::bail!("Endpoint invalide : nom d'hôte trop long");
    }
    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            anyhow::bail!("Endpoint invalide : nom d'hôte mal formé");
        }
        if label.len() > 63 {
            anyhow::bail!("Endpoint invalide : partie de nom d'hôte trop longue");
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            anyhow::bail!("Endpoint invalide : caractère interdit dans le nom d'hôte");
        }
        if label.starts_with('-') || label.ends_with('-') {
            anyhow::bail!("Endpoint invalide : nom d'hôte mal formé");
        }
    }
    if labels
        .last()
        .is_some_and(|label| label.chars().all(|c| c.is_ascii_digit()))
    {
        anyhow::bail!("Endpoint invalide : adresse IP mal formée");
    }
    Ok(())
}

/// Splits a comma-separated prefix list into its trimmed, non-empty entries.
///
/// One place, because four call sites read this field — validation, import,
/// the screen and the backend that builds the peer — and a list they parsed
/// differently would let the UI approve a route WireGuard never installs.
pub fn split_cidr_list(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// Validates a list of prefixes: `AllowedIPs` is one, an address is not.
///
/// # Why several
///
/// `AllowedIPs` is WireGuard's cryptographic routing table, and a split
/// tunnel usually needs more than one entry — the VPN network *and* the
/// remote LAN, say, which have no common supernet short of `0.0.0.0/0`.
/// Accepting a single prefix forced the choice between them, or the whole
/// Internet. A `wg-quick` file, where a comma-separated list is the ordinary
/// form, was refused for the same reason.
///
/// Each entry is validated on its own and named in the message: "the third is
/// wrong" is what turns a rejected list into a fixed one.
/// Validates an SSH destination: `user@host`, `host`, optionally `:port`.
///
/// # An allow-list, and why it has to be one
///
/// This value ends up as an **argument of a spawned process**. Every other
/// field of a profile is data the client interprets itself; this one crosses
/// into the operating system. A profile document arrives from outside — an
/// operator's file, an email attachment, a double-clicked download — so the
/// question is not whether the string looks reasonable but whether anything
/// it could contain can mean something to a shell.
///
/// Hence an allow-list of characters rather than a deny-list of dangerous
/// ones: letters, digits, `.`, `-`, `_`, one optional `@`, one optional `:`
/// followed by digits. No space, no quote, no `;`, `&`, `|`, `$`, backtick,
/// newline, and no leading `-` that an argument parser would read as a flag.
/// A deny-list is a promise to have thought of every metacharacter of every
/// shell the launcher might one day use; this is a promise about what is
/// allowed, which stays true when the launcher changes.
pub fn validate_ssh_target(value: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("destination SSH vide");
    }
    if value.len() > 255 {
        anyhow::bail!("destination SSH trop longue");
    }
    let (user_host, port) = match value.rsplit_once(':') {
        Some((rest, port)) => (rest, Some(port)),
        None => (value, None),
    };
    if let Some(port) = port {
        let port: u16 = port
            .parse()
            .context("destination SSH invalide : port non numérique")?;
        if port == 0 {
            anyhow::bail!("destination SSH invalide : port nul");
        }
    }
    let host = match user_host.split_once('@') {
        Some((user, host)) => {
            if user.is_empty() {
                anyhow::bail!("destination SSH invalide : nom d'utilisateur vide");
            }
            if !user
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            {
                anyhow::bail!(
                    "destination SSH invalide : le nom d'utilisateur n'accepte que lettres, \
                     chiffres, point, tiret et souligné"
                );
            }
            host
        }
        None => user_host,
    };
    if host.is_empty() {
        anyhow::bail!("destination SSH invalide : hôte vide");
    }
    if host.contains('@') {
        anyhow::bail!("destination SSH invalide : un seul « @ » est attendu");
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        anyhow::bail!(
            "destination SSH invalide : l'hôte n'accepte que lettres, chiffres, point, \
             tiret et souligné — ni espace ni caractère de shell"
        );
    }
    // A leading dash would be read as an option by `ssh` itself, whatever the
    // launcher does with quoting.
    if value.starts_with('-') || host.starts_with('-') {
        anyhow::bail!("destination SSH invalide : elle ne peut pas commencer par « - »");
    }
    Ok(())
}

/// Public entry point for tooling that emits a profile document.
///
/// `helios-ctl` validates the operator's `--allowed-ips` **before** admitting
/// a peer, so a mistyped prefix is a refusal rather than an admission with no
/// usable profile behind it.
pub fn validate_allowed_ips(value: &str) -> Result<()> {
    validate_cidr_list(value, "trafic capté")
}

fn validate_cidr_list(value: &str, label: &str) -> Result<()> {
    let entries = split_cidr_list(value);
    if entries.is_empty() {
        anyhow::bail!("{label} invalide : au moins un préfixe est requis");
    }
    for (index, entry) in entries.iter().enumerate() {
        validate_cidr(entry, label).with_context(|| {
            if entries.len() > 1 {
                format!("{label} : préfixe {} sur {}", index + 1, entries.len())
            } else {
                label.to_string()
            }
        })?;
    }
    // Duplicates are refused rather than silently collapsed. WireGuard would
    // take the list as it comes, so a prefix written twice is not an ambiguity
    // to arbitrate — it is a list the user has lost track of, and the second
    // occurrence is usually a typo for something else.
    for (index, entry) in entries.iter().enumerate() {
        if entries[..index].contains(entry) {
            anyhow::bail!("{label} invalide : le préfixe {entry} apparaît deux fois");
        }
    }
    Ok(())
}

/// Rewrites a prefix list in one canonical form: `a/n, b/m`.
///
/// The screen, the stored profile and the peer built from it must agree
/// character for character — otherwise a profile saved as `a/n,b/m` and
/// redisplayed as `a/n, b/m` reads as an unsaved change on every load.
pub fn normalize_cidr_list(value: &str) -> String {
    split_cidr_list(value).join(", ")
}

fn validate_cidr(value: &str, label: &str) -> Result<()> {
    let Some((address, prefix)) = value.split_once('/') else {
        anyhow::bail!("{label} invalide : notation CIDR attendue");
    };
    let address = address
        .parse::<IpAddr>()
        .with_context(|| format!("{label} invalide : adresse IP illisible"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("{label} invalide : préfixe non numérique"))?;
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        anyhow::bail!("{label} invalide : préfixe supérieur à {max_prefix}");
    }
    Ok(())
}

fn validate_heliosd_url(url: &str) -> Result<()> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .context("URL Helios interne invalide : schéma http:// ou https:// attendu")?;
    if rest.is_empty() || rest.chars().any(char::is_whitespace) {
        anyhow::bail!("URL Helios interne invalide");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_PRIVATE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const GATEWAY_PUBLIC: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    /// Temporary directory of the calling test.
    ///
    /// Named after the process **and** the thread: the suite runs in
    /// parallel, and two tests writing `portable.orionprofile` in one shared
    /// directory would delete each other's file.
    fn temp_directory(prefix: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "{prefix}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn complete_profile() -> ClientProfile {
        ClientProfile {
            name: "poste".into(),
            endpoint: "vpn.example.net:51820".into(),
            private_key: CLIENT_PRIVATE.into(),
            peer_public_key: GATEWAY_PUBLIC.into(),
            address: Some("100.64.1.2/32".into()),
            allowed_ips: "0.0.0.0/0".into(),
            persistent_keepalive: 25,
            ..ClientProfile::default()
        }
    }

    /// A mistyped IPv4 must not pass for a domain name.
    ///
    /// `86.229.1286` is the real case: 1286 exceeds 255, but the string
    /// remains syntactically acceptable as a sequence of labels. Without the
    /// RFC 1123 rule on the numeric last label, the defect only showed up at
    /// the first handshake, as a failing DNS resolution.
    #[test]
    fn a_malformed_ip_address_does_not_pass_for_a_hostname() {
        for accepted in [
            "86.229.12.86:51820",
            "vpn.example.net:51820",
            "gateway:51820",
            "[2a01:cb1e:101d:4b5c::1]:51820",
        ] {
            let profile = ClientProfile {
                endpoint: accepted.into(),
                ..complete_profile()
            };
            assert_eq!(
                inspect_profile(&profile).endpoint,
                None,
                "{accepted} should have been accepted"
            );
        }

        for refused in [
            "86.229.1286:51820",
            "256.1.1.1:51820",
            "10.0.0:51820",
            "[zz::1]:51820",
            "-mauvais.example.net:51820",
            "vpn..example.net:51820",
        ] {
            let profile = ClientProfile {
                endpoint: refused.into(),
                ..complete_profile()
            };
            assert!(
                inspect_profile(&profile).endpoint.is_some(),
                "{refused} should have been refused"
            );
        }
    }

    /// The message must say **what's expected**, not just that it's refused.
    /// "base64 expected" doesn't help see that a copy-paste was truncated;
    /// the observed length against the expected 44 characters does.
    #[test]
    fn the_message_for_an_invalid_key_gives_the_expected_length() {
        let truncated = &CLIENT_PRIVATE[..CLIENT_PRIVATE.len() - 4];
        let profile = ClientProfile {
            private_key: truncated.into(),
            ..complete_profile()
        };
        let message = inspect_profile(&profile)
            .private_key
            .expect("a truncated key must be refused");
        assert!(message.contains("44"), "message: {message}");
        assert!(message.contains("clé privée"), "message: {message}");

        let profile = ClientProfile {
            peer_public_key: "not base64 at all!".into(),
            ..complete_profile()
        };
        let message = inspect_profile(&profile)
            .peer_public_key
            .expect("forbidden characters must be refused");
        assert!(message.contains("44"), "message: {message}");
    }

    #[test]
    fn a_valid_profile_reports_no_field() {
        assert!(!inspect_profile(&complete_profile()).any());
    }

    /// While typing, "not filled in yet" is not "impossible": marking a
    /// fresh profile red would be noise.
    #[test]
    fn empty_fields_are_not_reported() {
        let issues = inspect_profile(&ClientProfile::default());
        assert_eq!(issues.endpoint, None);
        assert_eq!(issues.private_key, None);
        assert_eq!(issues.peer_public_key, None);
        assert_eq!(issues.address, None);
    }

    /// `AllowedIPs` is a list, and a split tunnel is why.
    ///
    /// One prefix used to be the limit, so reaching both the VPN network and
    /// a remote LAN — which share no supernet short of `0.0.0.0/0` — meant
    /// choosing one or routing the whole Internet.
    #[test]
    fn allowed_ips_accepts_several_prefixes_and_names_the_faulty_one() {
        let several = ClientProfile {
            allowed_ips: "100.64.0.0/10, 192.168.1.0/24, fd00::/8".into(),
            ..complete_profile()
        };
        assert_eq!(inspect_profile(&several).allowed_ips, None);
        assert!(validate_imported_profile(several).is_ok());

        // Spelling is normalized on the way in: the screen writes one form,
        // a `wg-quick` file another, and a profile reloaded in a spelling it
        // was not saved in reads as modified.
        let unspaced = ClientProfile {
            allowed_ips: "100.64.0.0/10,192.168.1.0/24".into(),
            ..complete_profile()
        };
        assert_eq!(
            validate_imported_profile(unspaced)
                .expect("import")
                .allowed_ips,
            "100.64.0.0/10, 192.168.1.0/24"
        );

        // A faulty entry names its position: "the second is wrong" is what
        // turns a rejected list into a fixed one.
        let faulty = ClientProfile {
            allowed_ips: "100.64.0.0/10, 192.168.1.0/33".into(),
            ..complete_profile()
        };
        let reported = inspect_profile(&faulty)
            .allowed_ips
            .expect("the faulty prefix is reported");
        assert!(reported.contains("préfixe 2 sur 2"), "{reported}");

        // A prefix written twice is a list its author has lost track of.
        let duplicated = ClientProfile {
            allowed_ips: "10.0.0.0/8, 10.0.0.0/8".into(),
            ..complete_profile()
        };
        assert!(inspect_profile(&duplicated).allowed_ips.is_some());

        // And an empty list still cannot mount a tunnel that captures nothing.
        let empty = ClientProfile {
            allowed_ips: " , ".into(),
            ..complete_profile()
        };
        assert!(validate_imported_profile(empty).is_err());
    }

    /// The allow-list holds against everything a shell could read as syntax.
    ///
    /// This field becomes an argument of a spawned process, so the test is
    /// written as a refusal list rather than an acceptance one: what matters
    /// is not that `user@host` works, it is that nothing else does.
    #[test]
    fn an_ssh_target_refuses_everything_a_shell_could_read() {
        for accepted in [
            "christophe@100.64.0.1",
            "100.64.0.1",
            "gateway.example.net",
            "root@gw-01.internal:2222",
            "a_b.c-d@host_1.example",
        ] {
            assert!(
                validate_ssh_target(accepted).is_ok(),
                "`{accepted}` should be accepted"
            );
        }

        for refused in [
            "",
            "   ",
            // Command substitution and chaining, in every spelling.
            "user@host; rm -rf /",
            "user@host && calc.exe",
            "user@host | more",
            "user@$(whoami)",
            "user@`hostname`",
            "user@host\nsecond",
            // Quoting and expansion.
            "user@host'",
            "user@\"host\"",
            "user@${env:PATH}",
            // Argument injection into `ssh` itself: `-o` would set options,
            // and no amount of quoting by the launcher would stop it.
            "-oProxyCommand=calc",
            "-lroot",
            // Shape faults.
            "user@@host",
            "@host",
            "user@",
            "user@host:0",
            "user@host:notaport",
            "user @host",
        ] {
            assert!(
                validate_ssh_target(refused).is_err(),
                "`{refused}` should be refused"
            );
        }
    }

    /// A document carrying a hostile destination is refused as a whole.
    ///
    /// The launcher is not the only gate, and must not be the first: a
    /// profile that would never be safe to launch has no business being
    /// stored, displayed as valid, or handed to another machine.
    #[test]
    fn a_document_with_a_hostile_ssh_target_does_not_import() {
        let hostile = ClientProfile {
            ssh_target: Some("user@host; calc.exe".into()),
            ..complete_profile()
        };
        assert!(inspect_profile(&hostile).ssh_target.is_some());
        assert!(validate_imported_profile(hostile).is_err());

        let sound = ClientProfile {
            ssh_target: Some("  christophe@100.64.0.1  ".into()),
            ..complete_profile()
        };
        assert_eq!(inspect_profile(&sound).ssh_target, None);
        assert_eq!(
            validate_imported_profile(sound).expect("import").ssh_target,
            Some("christophe@100.64.0.1".into()),
            "trimmed on the way in, so the launcher never sees padding"
        );
    }

    /// The point of inspection versus import: it doesn't stop at the first
    /// fault, otherwise the UI would discover one per attempt.
    #[test]
    fn all_faulty_fields_are_reported_in_one_pass() {
        let profile = ClientProfile {
            endpoint: "https://vpn.example.net".into(),
            private_key: "not-base64".into(),
            peer_public_key: "AAAA".into(),
            address: Some("100.64.1.2".into()),
            allowed_ips: "0.0.0.0/33".into(),
            persistent_keepalive: 0,
            heliosd_url: Some("100.64.0.1:8080".into()),
            ..complete_profile()
        };
        let issues = inspect_profile(&profile);

        assert!(issues.any());
        for (field, value) in [
            ("endpoint", &issues.endpoint),
            ("private_key", &issues.private_key),
            ("peer_public_key", &issues.peer_public_key),
            ("address", &issues.address),
            ("allowed_ips", &issues.allowed_ips),
            ("persistent_keepalive", &issues.persistent_keepalive),
            ("heliosd_url", &issues.heliosd_url),
        ] {
            assert!(value.is_some(), "{field} should have been reported");
        }
    }

    /// Zero is not "empty": it's a value, and it cuts off the keepalive a
    /// client behind NAT depends on.
    #[test]
    fn a_zero_keepalive_is_reported_while_an_absent_psk_is_not() {
        let profile = ClientProfile {
            persistent_keepalive: 0,
            preshared_key: None,
            ..complete_profile()
        };
        let issues = inspect_profile(&profile);
        assert!(issues.persistent_keepalive.is_some());
        assert_eq!(issues.preshared_key, None);
    }

    /// Gateway material as the operator distributes it: public certificate,
    /// public CA, and the name of the protected store entry — never the
    /// client's own private key.
    fn gateway_settings(mode: ProtectionMode) -> KeyNegotiationSettings {
        use aether::key_negotiation::{
            generate_ml_dsa_65_keypair, issue_pq_certificate, PqCertificate, PqCertificateRole,
            PQ_CERTIFICATE_VERSION,
        };
        use base64::engine::general_purpose::STANDARD;

        let (private_key, public_key) = generate_ml_dsa_65_keypair().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [7u8; 16],
                subject: "vpn.example.net".into(),
                issuer: "vpn.example.net".into(),
                role: PqCertificateRole::Gateway,
                wireguard_public_key: GATEWAY_PUBLIC.into(),
                ml_dsa_65_public_key: STANDARD.encode(&public_key),
                not_before_unix: now - 60,
                not_after_unix: now + 3600,
                ml_dsa_65_signature: String::new(),
            },
            &private_key,
        )
        .unwrap();

        KeyNegotiationSettings {
            mode,
            minimum_mode: mode,
            endpoint: "vpn.example.net:51821".into(),
            server_name: "vpn.example.net".into(),
            gateway_ca_der: STANDARD.encode([0x30, 0x82, 0x01, 0x00]),
            gateway_pq_certificate: STANDARD.encode(serde_json::to_vec(&certificate).unwrap()),
            identity: "orion-portable".into(),
        }
    }

    fn document_with(settings: serde_json::Value) -> String {
        serde_json::json!({
            "format": PROFILE_IMPORT_FORMAT,
            "version": PROFILE_IMPORT_VERSION,
            "profile": {
                "name": "portable",
                "endpoint": "vpn.example.net:51820",
                "private_key": CLIENT_PRIVATE,
                "peer_public_key": GATEWAY_PUBLIC,
                "address": "100.64.1.2/32",
                "key_negotiation": settings,
            }
        })
        .to_string()
    }

    /// The operator document is the vehicle for the negotiation settings:
    /// without it, the screen would have nothing to display and the user
    /// would have to retype a certificate by hand.
    #[test]
    fn imports_the_key_negotiation_block_of_an_operator_document() {
        let settings = gateway_settings(ProtectionMode::MlKem);
        let raw = document_with(serde_json::to_value(&settings).unwrap());

        let profile = parse_profile_import(&raw, "portable.json").unwrap().profile;
        let imported = profile.key_negotiation.expect("block expected");
        assert_eq!(imported.mode, ProtectionMode::MlKem);
        assert_eq!(imported.minimum_mode, ProtectionMode::MlKem);
        assert_eq!(imported.endpoint, "vpn.example.net:51821");
        assert!(imported.gateway_pq_fingerprint().is_some());
    }

    /// An absent floor is not "no floor": accepting a classic negotiation
    /// tomorrow would void the mode chosen today.
    #[test]
    fn an_imported_block_without_a_floor_takes_its_selected_mode_as_floor() {
        let mut settings = serde_json::to_value(gateway_settings(ProtectionMode::MlKem)).unwrap();
        settings
            .as_object_mut()
            .unwrap()
            .remove("minimum_mode")
            .expect("the fixture carries a floor");

        let profile = parse_profile_import(&document_with(settings), "portable.json")
            .unwrap()
            .profile;
        assert_eq!(
            profile.key_negotiation.unwrap().minimum_mode,
            ProtectionMode::MlKem
        );
    }

    /// A document that asks for less than its own floor is contradictory:
    /// import refuses it rather than silently picking a side.
    #[test]
    fn a_mode_below_the_declared_floor_is_refused_at_import() {
        let mut settings = gateway_settings(ProtectionMode::Classic);
        settings.minimum_mode = ProtectionMode::MlKem;
        let raw = document_with(serde_json::to_value(&settings).unwrap());

        let error = parse_profile_import(&raw, "portable.json")
            .expect_err("a mode below the floor must be refused")
            .to_string();
        assert!(error.contains("plancher"), "message : {error}");
    }

    /// A certificate pinned to another gateway must not pass for this one:
    /// it's the only check that ties the imported material to the peer key
    /// the profile is about to talk to.
    #[test]
    fn a_certificate_pinned_to_another_gateway_is_refused() {
        let settings = gateway_settings(ProtectionMode::MlKem);
        let mut document: serde_json::Value =
            serde_json::from_str(&document_with(serde_json::to_value(&settings).unwrap())).unwrap();
        document["profile"]["peer_public_key"] =
            serde_json::Value::String(CLIENT_PRIVATE.to_string());

        assert!(parse_profile_import(&document.to_string(), "portable.json").is_err());
    }

    /// The three modes don't take the same profile material, and the fault
    /// is a relation between two fields — the block carries it as a whole.
    #[test]
    fn a_psk_that_contradicts_the_mode_is_reported_on_the_block() {
        let profile = ClientProfile {
            preshared_key: Some("cHNr".into()),
            key_negotiation: Some(gateway_settings(ProtectionMode::MlKem)),
            ..complete_profile()
        };
        let message = inspect_profile(&profile)
            .key_negotiation
            .expect("a PSK is only valid in static mode");
        assert!(message.contains("PSK statique"), "message : {message}");

        let sound = ClientProfile {
            key_negotiation: Some(gateway_settings(ProtectionMode::MlKem)),
            ..complete_profile()
        };
        assert_eq!(inspect_profile(&sound).key_negotiation, None);
    }

    /// The PSK that ML-KEM just produced is not the PSK this rule forbids.
    ///
    /// Both sit in the same slot, and telling them apart is the difference
    /// between a negotiation that commits and one that cannot: `up()`
    /// validates the profile it mounts, and that profile carries the freshly
    /// negotiated secret. Judging it as a static PSK made every ML-KEM
    /// connection fail — three attempts, then «un PSK de profil n'est valable
    /// qu'avec le mode PSK statique», on a profile the user never touched.
    #[test]
    fn a_negotiated_psk_does_not_contradict_the_ml_kem_mode() {
        let mounted = ClientProfile {
            preshared_key: Some("cHNr".into()),
            preshared_key_is_negotiated: true,
            key_negotiation: Some(gateway_settings(ProtectionMode::MlKem)),
            ..complete_profile()
        };
        assert!(
            mounted.validate().is_ok(),
            "the profile handed to up() after a negotiation must be mountable: {:?}",
            mounted.validate().unwrap_err()
        );

        // The same secret, declared static: still refused, and that check is
        // the one worth keeping.
        let configured = ClientProfile {
            preshared_key_is_negotiated: false,
            ..mounted
        };
        assert!(configured.validate().is_err());
    }

    /// An ML-KEM profile must never reach the data plane without its PSK.
    ///
    /// `validate()` accepts that shape on purpose — it is the profile's state
    /// at rest, before any negotiation. What must not accept it is `up()`:
    /// mounting there would bring WireGuard up on the static key pair alone.
    /// The handshake would succeed, the state would go `Up`, and the
    /// post-quantum protection the profile announces would simply be absent,
    /// with nothing on screen saying so.
    #[test]
    fn an_ml_kem_profile_without_its_negotiated_psk_never_reaches_the_data_plane() {
        let at_rest = ClientProfile {
            key_negotiation: Some(gateway_settings(ProtectionMode::MlKem)),
            ..complete_profile()
        };
        assert!(
            at_rest.validate().is_ok(),
            "au repos, un profil ML-KEM n'a légitimement pas encore de PSK"
        );

        let refused = at_rest
            .validate_for_data_plane()
            .expect_err("le plan de données doit refuser un mode ML-KEM sans PSK négocié");
        assert!(
            refused.to_string().contains("sans PSK négocié"),
            "message obtenu : {refused}"
        );

        // A static PSK is not a substitute: it is the operator's out-of-band
        // value, and its presence would mean the negotiation never happened.
        let smuggled = ClientProfile {
            preshared_key: Some("cHNrLXN0YXRpcXVl".into()),
            preshared_key_is_negotiated: false,
            ..ClientProfile {
                key_negotiation: Some(gateway_settings(ProtectionMode::MlKem)),
                ..complete_profile()
            }
        };
        assert!(
            smuggled.validate_for_data_plane().is_err(),
            "un PSK statique ne peut pas tenir lieu de PSK négocié"
        );

        // And what the negotiation actually hands to `up()` passes.
        let negotiated = ClientProfile {
            preshared_key: Some("cHNrLW5lZ29jaWU=".into()),
            preshared_key_is_negotiated: true,
            key_negotiation: Some(gateway_settings(ProtectionMode::MlKem)),
            ..complete_profile()
        };
        assert!(
            negotiated.validate_for_data_plane().is_ok(),
            "le profil éphémère issu de la négociation doit être montable : {:?}",
            negotiated.validate_for_data_plane().unwrap_err()
        );
    }

    /// The other two modes keep their existing contract unchanged.
    #[test]
    fn the_data_plane_rule_only_constrains_ml_kem() {
        let classic = ClientProfile {
            key_negotiation: Some(gateway_settings(ProtectionMode::Classic)),
            ..complete_profile()
        };
        assert!(classic.validate_for_data_plane().is_ok());

        let static_psk = ClientProfile {
            preshared_key: Some("cHNrLXN0YXRpcXVl".into()),
            key_negotiation: Some(gateway_settings(ProtectionMode::StaticPsk)),
            ..complete_profile()
        };
        assert!(static_psk.validate_for_data_plane().is_ok());

        // A profile with no negotiation block at all is untouched by the rule.
        assert!(complete_profile().validate_for_data_plane().is_ok());
    }

    /// A document may leave fields out; it is loaded, not refused.
    ///
    /// The operator sends what they know. Refusing to *parse* an invitation
    /// with no endpoint returned the user to a file picker with a sentence,
    /// instead of to a form with one field left to fill. `validate` is what
    /// decides whether a tunnel may mount — parsing only decides whether the
    /// document is intelligible.
    #[test]
    fn a_partial_document_is_loaded_and_its_gap_named() {
        let document = serde_json::json!({
            "format": "orion-profile",
            "version": 1,
            "profile": { "name": "poste" },
        })
        .to_string();

        let imported = parse_profile_import(&document, "poste.orionprofile")
            .expect("un document partiel doit se lire");
        assert_eq!(imported.profile.name, "poste");
        // The defaults are applied rather than left empty.
        assert_eq!(imported.profile.allowed_ips, DEFAULT_ALLOWED_IPS);
        assert_eq!(
            imported.profile.persistent_keepalive,
            DEFAULT_KEEPALIVE_SECS
        );

        let completed = complete_profile_import(imported.profile, &ClientConfig::default(), None)
            .expect("l'import ne refuse pas un document incomplet");
        assert!(
            completed.private_key_missing.is_some(),
            "l'absence de clé privée doit être nommée"
        );
        assert!(
            completed.incomplete.is_some(),
            "ce qui reste à compléter doit être nommé, pas tu"
        );
    }

    /// A complete document reports nothing to fill in.
    #[test]
    fn a_complete_document_reports_no_gap() {
        let pair = aether::wg::generate_keypair().expect("keypair");
        let profile = ClientProfile {
            private_key: pair.private_key.expose().to_string(),
            ..complete_profile()
        };
        let completed =
            complete_profile_import(profile, &ClientConfig::default(), None).expect("import");
        assert!(completed.private_key_missing.is_none());
        assert!(
            completed.incomplete.is_none(),
            "obtenu : {:?}",
            completed.incomplete
        );
    }

    fn identity_bundle(name: &str) -> serde_json::Value {
        use base64::engine::general_purpose::STANDARD;

        serde_json::json!({
            "identity": name,
            "certificate_chain": [STANDARD.encode([0x30, 0x82, 0x01, 0x00])],
            "private_key": STANDARD.encode([0x30, 0x81, 0x87, 0x02]),
            "pq_certificate": STANDARD.encode(br#"{"version":1}"#),
            "pq_private_key": STANDARD.encode([7u8; 64]),
        })
    }

    /// The identity travels with the profile so the user has **one** file to
    /// import — but it must come back separately, because the two have
    /// opposite destinies: one is persisted, the other is sealed.
    #[test]
    fn the_shipped_identity_is_returned_apart_from_the_profile() {
        let settings = gateway_settings(ProtectionMode::MlKem);
        let mut document: serde_json::Value =
            serde_json::from_str(&document_with(serde_json::to_value(&settings).unwrap())).unwrap();
        document["profile"]["key_negotiation_identity"] = identity_bundle(&settings.identity);

        let imported = parse_profile_import(&document.to_string(), "portable.json").unwrap();
        let identity = imported.identity.expect("identity expected");
        assert_eq!(identity.identity, settings.identity);

        // The decisive property: nothing of the secret can reach the profile,
        // hence nothing can reach `profiles.toml`.
        let persisted = toml::to_string(&imported.profile).unwrap();
        assert!(!persisted.contains("pq_private_key"), "{persisted}");
        assert!(
            !persisted.contains(&identity.pq_private_key),
            "the PQ private key must not be persistable"
        );
    }

    /// Adding negotiation to a profile that already exists must not disturb
    /// its WireGuard identity.
    ///
    /// This is the ordinary upgrade path: a client enrolled long ago is
    /// re-enrolled from its **public** key, so the document carries no
    /// private key and completion takes the local one. Regenerating a key
    /// here would silently break an admission the gateway already holds.
    #[test]
    fn enrolling_an_existing_profile_keeps_its_wireguard_identity() {
        let settings = gateway_settings(ProtectionMode::MlKem);
        let mut document: serde_json::Value =
            serde_json::from_str(&document_with(serde_json::to_value(&settings).unwrap())).unwrap();
        // Invitation form: `helios-ctl enroll --public-key <clé existante>`.
        document["profile"]["private_key"] = serde_json::Value::String(String::new());

        let imported = parse_profile_import(&document.to_string(), "portable.json").unwrap();
        assert!(imported.profile.private_key.is_empty());

        let mut config = ClientConfig::default();
        config.upsert(ClientProfile {
            name: "portable".into(),
            private_key: CLIENT_PRIVATE.into(),
            ..complete_profile()
        });

        let completed = complete_profile_import(imported.profile, &config, None)
            .unwrap()
            .profile;
        assert_eq!(completed.private_key, CLIENT_PRIVATE);
        assert!(
            completed.key_negotiation.is_some(),
            "the negotiation block must survive completion"
        );
    }

    /// The decisive case of an enrolled client: the operator names it
    /// `poste-windows`, the machine kept it under another name, and the
    /// admitted key is the same on both sides. Matching by name refused the
    /// document; matching by key is what makes it importable.
    #[test]
    fn an_invitation_is_completed_by_the_admitted_key_whatever_the_name() {
        use base64::engine::general_purpose::STANDARD;

        let admitted = ClientProfile {
            private_key: CLIENT_PRIVATE.into(),
            ..complete_profile()
        }
        .public_key()
        .unwrap();

        let settings = gateway_settings(ProtectionMode::MlKem);
        let mut document: serde_json::Value =
            serde_json::from_str(&document_with(serde_json::to_value(&settings).unwrap())).unwrap();
        document["profile"]["private_key"] = serde_json::Value::String(String::new());
        let mut bundle = identity_bundle(&settings.identity);
        bundle["pq_certificate"] = serde_json::Value::String(STANDARD.encode(
            serde_json::json!({ "version": 1, "wireguard_public_key": admitted }).to_string(),
        ));
        document["profile"]["key_negotiation_identity"] = bundle;

        let imported =
            parse_profile_import(&document.to_string(), "portable.orionprofile").unwrap();
        assert_eq!(imported.admitted_public_key().as_deref(), Some(&*admitted));

        let mut config = ClientConfig::default();
        config.upsert(ClientProfile {
            // Same client, other name: the situation the name rule refused.
            name: "poste-de-christophe".into(),
            private_key: CLIENT_PRIVATE.into(),
            ..complete_profile()
        });

        let admitted_key = imported.admitted_public_key();
        let completed =
            complete_profile_import(imported.profile, &config, admitted_key.as_deref()).unwrap();
        assert_eq!(completed.private_key_missing, None);
        assert_eq!(completed.profile.private_key, CLIENT_PRIVATE);
        assert_eq!(completed.profile.name, "portable");
    }

    /// A same-name profile holding **another** key is not a match: it was
    /// never admitted, and using it would produce a tunnel that handshakes
    /// with nobody.
    #[test]
    fn a_local_profile_holding_another_key_does_not_complete_an_invitation() {
        let invitation = ClientProfile {
            private_key: String::new(),
            ..complete_profile()
        };
        let mut config = ClientConfig::default();
        config.upsert(ClientProfile {
            private_key: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=".into(),
            ..complete_profile()
        });

        let completed =
            complete_profile_import(invitation, &config, Some("une-autre-clé-publique")).unwrap();
        let message = completed
            .private_key_missing
            .expect("an unadmitted local key must not complete the document");
        assert!(message.contains("une-autre-clé-publique"), "{message}");
        assert!(completed.profile.private_key.is_empty());
    }

    /// An identity sealed under a name the profile never looks up would be a
    /// secret stored for nothing.
    #[test]
    fn an_identity_naming_another_entry_is_refused() {
        let settings = gateway_settings(ProtectionMode::MlKem);
        let mut document: serde_json::Value =
            serde_json::from_str(&document_with(serde_json::to_value(&settings).unwrap())).unwrap();
        document["profile"]["key_negotiation_identity"] = identity_bundle("un-autre-poste");

        let error = parse_profile_import(&document.to_string(), "portable.json")
            .expect_err("mismatched identity must be refused")
            .to_string();
        assert!(error.contains("un-autre-poste"), "message : {error}");
    }

    #[test]
    fn imports_versioned_json_with_defaults() {
        let raw = format!(
            r#"{{
                "format": "orion-profile",
                "version": 1,
                "profile": {{
                    "name": " portable ",
                    "endpoint": "vpn.example.net:51820",
                    "private_key": "{CLIENT_PRIVATE}",
                    "peer_public_key": "{GATEWAY_PUBLIC}",
                    "address": "100.64.1.2/32",
                    "heliosd_url": "http://100.64.0.1:8080"
                }}
            }}"#
        );

        let profile = parse_profile_import(&raw, "portable.json").unwrap().profile;
        assert_eq!(profile.name, "portable");
        assert_eq!(profile.allowed_ips, DEFAULT_ALLOWED_IPS);
        assert_eq!(profile.persistent_keepalive, DEFAULT_KEEPALIVE_SECS);
        assert_eq!(profile.address.as_deref(), Some("100.64.1.2/32"));
    }

    /// Invitation profile (ADR-004 §6): the operator admits the public key
    /// the client sent, and returns everything **except** the private key,
    /// which it never held. The UI takes it back from the local profile of
    /// the same name.
    #[test]
    fn imports_an_invitation_without_a_private_key() {
        let raw = format!(
            r#"{{
                "format": "orion-profile",
                "version": 1,
                "profile": {{
                    "name": "portable",
                    "endpoint": "vpn.example.net:51820",
                    "peer_public_key": "{GATEWAY_PUBLIC}",
                    "address": "100.64.1.2/32"
                }}
            }}"#
        );

        let profile = parse_profile_import(&raw, "portable.json").unwrap().profile;
        assert!(
            profile.private_key.is_empty(),
            "the invitation must carry no private key"
        );
        assert_eq!(profile.peer_public_key, GATEWAY_PUBLIC);
        assert_eq!(profile.address.as_deref(), Some("100.64.1.2/32"));
        assert!(
            profile.validate().is_err(),
            "an invitation alone must not be presented as connectable"
        );
    }

    #[test]
    fn completes_an_invitation_with_the_local_key_of_the_same_name() {
        let invitation = ClientProfile {
            name: "portable".into(),
            endpoint: "vpn.example.net:51820".into(),
            peer_public_key: GATEWAY_PUBLIC.into(),
            address: Some("100.64.1.2/32".into()),
            ..ClientProfile::default()
        };
        let config = ClientConfig {
            profiles: vec![ClientProfile {
                name: "portable".into(),
                private_key: CLIENT_PRIVATE.into(),
                ..ClientProfile::default()
            }],
            selected: None,
        };

        let completed = complete_profile_import(invitation, &config, None).unwrap();
        assert_eq!(completed.private_key_missing, None);
        assert_eq!(completed.profile.private_key, CLIENT_PRIVATE);
    }

    #[test]
    fn reports_an_invitation_without_a_matching_local_key() {
        let invitation = ClientProfile {
            name: "portable".into(),
            endpoint: "vpn.example.net:51820".into(),
            peer_public_key: GATEWAY_PUBLIC.into(),
            address: Some("100.64.1.2/32".into()),
            ..ClientProfile::default()
        };

        // Reported, not raised: the draft stays visible so the user sees
        // which endpoint and which address were issued, and can paste the
        // key rather than being told to start over.
        let completed =
            complete_profile_import(invitation, &ClientConfig::default(), None).unwrap();
        let message = completed
            .private_key_missing
            .expect("the absence of a key must be reported");
        assert!(message.contains("aucun profil local"), "{message}");
        assert!(completed.profile.private_key.is_empty());
        assert_eq!(completed.profile.name, "portable");
    }

    /// Tolerating the absence of a private key must not tolerate a truncated
    /// key: that's not an invitation, it's a corruption.
    #[test]
    fn a_private_key_present_but_malformed_stays_refused() {
        let raw = r#"{
            "format": "orion-profile",
            "version": 1,
            "profile": {
                "name": "portable",
                "endpoint": "vpn.example.net:51820",
                "private_key": "AAAA",
                "peer_public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                "address": "100.64.1.2/32"
            }
        }"#;
        let error = parse_profile_import(raw, "portable.json").unwrap_err();
        assert!(error.to_string().contains("clé privée"), "message: {error}");
    }

    /// `wg-quick` has no notion of invitation: a file without `PrivateKey`
    /// is an incomplete file, and saying so early avoids a tunnel that never
    /// mounts without explanation.
    #[test]
    fn wg_quick_without_a_private_key_stays_refused() {
        let raw = format!(
            r#"
                [Interface]
                Address = 100.64.1.2/32

                [Peer]
                PublicKey = {GATEWAY_PUBLIC}
                Endpoint = vpn.example.net:51820
            "#
        );
        let error = parse_profile_import(&raw, "portable.conf").unwrap_err();
        assert!(error.to_string().contains("PrivateKey"), "message: {error}");
    }

    #[test]
    fn imports_wg_quick_with_one_peer() {
        let raw = format!(
            r#"
                # profile issued by the administrator
                [Interface]
                PrivateKey = {CLIENT_PRIVATE}
                Address = 100.64.1.2/32

                [Peer]
                PublicKey = {GATEWAY_PUBLIC}
                AllowedIPs = 0.0.0.0/0
                Endpoint = 203.0.113.10:51820
                PersistentKeepalive = 25
            "#
        );

        let profile = parse_profile_import(&raw, r"C:\Profils\site-labo.conf")
            .unwrap()
            .profile;
        assert_eq!(profile.name, "site-labo");
        assert_eq!(profile.endpoint, "203.0.113.10:51820");
        assert_eq!(profile.private_key, CLIENT_PRIVATE);
        assert_eq!(profile.peer_public_key, GATEWAY_PUBLIC);
        assert_eq!(profile.persistent_keepalive, 25);
    }

    #[test]
    fn refuses_unknown_json_or_unexpected_field() {
        let wrong_version = r#"{
            "format": "orion-profile",
            "version": 2,
            "profile": {}
        }"#;
        assert!(parse_profile_import(wrong_version, "profile.json")
            .unwrap_err()
            .to_string()
            .contains("version"));

        let unknown_field = format!(
            r#"{{
                "format": "orion-profile",
                "version": 1,
                "profile": {{
                    "name": "site",
                    "endpoint": "vpn.example.net:51820",
                    "private_key": "{CLIENT_PRIVATE}",
                    "peer_public_key": "{GATEWAY_PUBLIC}",
                    "dns": "100.64.0.1"
                }}
            }}"#
        );
        assert!(parse_profile_import(&unknown_field, "profile.json").is_err());
    }

    #[test]
    fn refuses_multiple_peers_and_unapplied_options() {
        let multiple = format!(
            "[Interface]\nPrivateKey={CLIENT_PRIVATE}\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820\n[Peer]\nPublicKey={GATEWAY_PUBLIC}"
        );
        assert!(parse_profile_import(&multiple, "multi.conf")
            .unwrap_err()
            .to_string()
            .contains("un seul pair"));

        let dns = format!(
            "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nDNS=100.64.0.1\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
        );
        assert!(parse_profile_import(&dns, "dns.conf")
            .unwrap_err()
            .to_string()
            .contains("dns"));
    }

    #[test]
    fn refuses_invalid_keys_and_endpoint() {
        let bad_key = format!(
            "[Interface]\nPrivateKey=short\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
        );
        assert!(parse_profile_import(&bad_key, "invalid.conf").is_err());

        let url = format!(
            "[Interface]\nPrivateKey={CLIENT_PRIVATE}\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=https://vpn.example.net"
        );
        assert!(parse_profile_import(&url, "url.conf")
            .unwrap_err()
            .to_string()
            .contains("pas une URL"));
    }

    /// Absent is tolerated; **malformed** is refused.
    ///
    /// The document used to be rejected for a missing virtual address, which
    /// an invitation legitimately lacks — the VIP is assigned by the gateway
    /// at admission. What must still be refused is an address that is present
    /// and wrong: absent, the user fills it in; wrong, it produces a tunnel
    /// that never routes and nothing says why.
    #[test]
    fn an_absent_address_is_tolerated_but_a_malformed_one_is_not() {
        let no_address = format!(
            "[Interface]\nPrivateKey={CLIENT_PRIVATE}\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
        );
        let imported = parse_profile_import(&no_address, "no-address.conf")
            .expect("une invitation sans VIP doit se charger");
        assert_eq!(imported.profile.address, None);
        // …and the gap is named rather than passed over in silence.
        let completed =
            complete_profile_import(imported.profile, &ClientConfig::default(), None).unwrap();
        assert!(completed
            .incomplete
            .expect("le manque doit être nommé")
            .contains("adresse"));

        let bad_address = format!(
            "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=pas-un-cidr\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820"
        );
        assert!(parse_profile_import(&bad_address, "bad-address.conf").is_err());
    }

    #[test]
    fn refuses_an_unroutable_profile() {
        let no_keepalive = format!(
            "[Interface]\nPrivateKey={CLIENT_PRIVATE}\nAddress=100.64.1.2/32\n[Peer]\nPublicKey={GATEWAY_PUBLIC}\nEndpoint=host:51820\nPersistentKeepalive=0"
        );
        assert!(parse_profile_import(&no_keepalive, "no-keepalive.conf")
            .unwrap_err()
            .to_string()
            .contains("supérieur à zéro"));
    }

    /// `.orionprofile` is the extension the tooling distributes: recognizing
    /// it must not depend on the first character surviving the trip.
    #[test]
    fn the_orionprofile_suffix_selects_the_orion_parser() {
        let raw = format!(
            r#"{{
                "format": "orion-profile",
                "version": 1,
                "profile": {{
                    "name": "portable",
                    "endpoint": "vpn.example.net:51820",
                    "private_key": "{CLIENT_PRIVATE}",
                    "peer_public_key": "{GATEWAY_PUBLIC}",
                    "address": "100.64.1.2/32"
                }}
            }}"#
        );

        // Leading blank lines: the head no longer decides, the suffix does.
        let padded = format!("\n\n{raw}");
        assert_eq!(
            parse_profile_import(&padded, "poste-windows.orionprofile")
                .unwrap()
                .profile
                .name,
            "portable"
        );
        assert_eq!(
            parse_profile_import(&raw, "POSTE-WINDOWS.ORIONPROFILE")
                .unwrap()
                .profile
                .name,
            "portable"
        );
    }

    /// A document is carried by hand from one machine to another, and that
    /// trip re-encodes it: PowerShell's `Out-File` writes UTF-16LE, Notepad
    /// long prefixed UTF-8 with a BOM. The content is intact; refusing it
    /// only strands the user.
    #[test]
    fn reads_a_document_whatever_byte_order_mark_it_carries() {
        let raw = format!(
            r#"{{"format":"orion-profile","version":1,"profile":{{"name":"portable","endpoint":"vpn.example.net:51820","private_key":"{CLIENT_PRIVATE}","peer_public_key":"{GATEWAY_PUBLIC}","address":"100.64.1.2/32"}}}}"#
        );

        let utf16le: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(raw.encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        let utf16be: Vec<u8> = [0xFE, 0xFF]
            .into_iter()
            .chain(raw.encode_utf16().flat_map(u16::to_be_bytes))
            .collect();
        let utf8_bom: Vec<u8> = [0xEF, 0xBB, 0xBF].into_iter().chain(raw.bytes()).collect();

        for (label, bytes) in [
            ("UTF-8", raw.clone().into_bytes()),
            ("UTF-8 + BOM", utf8_bom),
            ("UTF-16LE", utf16le),
            ("UTF-16BE", utf16be),
        ] {
            let directory = temp_directory("orion-import-encoding");
            let path = directory.join("portable.orionprofile");
            std::fs::write(&path, &bytes).unwrap();
            let imported = read_profile_import_path(&path)
                .unwrap_or_else(|error| panic!("{label} should have been read: {error:#}"));
            assert_eq!(imported.profile.name, "portable", "{label}");
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    /// «format inconnu» alone leaves the user re-reading a file that looks
    /// right to them: the message must say what was actually seen.
    #[test]
    fn an_unrecognized_document_says_what_it_starts_with() {
        let empty = parse_profile_import("   ", "profil.txt")
            .unwrap_err()
            .to_string();
        assert!(empty.contains("vide"), "message : {empty}");

        let html = parse_profile_import("<!DOCTYPE html>", "profil.txt")
            .unwrap_err()
            .to_string();
        assert!(html.contains("<!DOCTYPE html>"), "message : {html}");
        assert!(html.contains("profil.txt"), "message : {html}");

        // What a UTF-8 decoder leaves when handed UTF-16: the encoding is
        // named, because "unknown format" would send the user looking for a
        // fault in a document that has none.
        let mangled = parse_profile_import("\u{fffd}\u{fffd}{\0", "profil.txt")
            .unwrap_err()
            .to_string();
        assert!(mangled.contains("UTF-8"), "message : {mangled}");
    }

    #[test]
    fn refuses_an_oversized_document() {
        let raw = " ".repeat(MAX_PROFILE_IMPORT_BYTES + 1);
        assert!(parse_profile_import(&raw, "big.json")
            .unwrap_err()
            .to_string()
            .contains("trop volumineux"));
    }

    #[test]
    fn reading_by_path_reuses_the_parser_and_the_limit() {
        let directory = temp_directory("orion-import-path");
        let profile_path = directory.join("portable.orionprofile");
        let raw = format!(
            r#"{{
                "format": "orion-profile",
                "version": 1,
                "profile": {{
                    "name": "portable",
                    "endpoint": "vpn.example.net:51820",
                    "private_key": "{CLIENT_PRIVATE}",
                    "peer_public_key": "{GATEWAY_PUBLIC}",
                    "address": "100.64.1.2/32"
                }}
            }}"#
        );
        std::fs::write(&profile_path, raw).unwrap();
        assert_eq!(
            read_profile_import_path(&profile_path)
                .unwrap()
                .profile
                .name,
            "portable"
        );

        let oversized_path = directory.join("too-big.orionprofile");
        std::fs::write(&oversized_path, vec![b' '; MAX_PROFILE_IMPORT_BYTES + 1]).unwrap();
        assert!(read_profile_import_path(&oversized_path)
            .unwrap_err()
            .to_string()
            .contains("trop volumineux"));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
