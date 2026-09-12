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
    /// What this document claims to be (spec §19).
    ///
    /// Absent in a document written before the field existed; the kind is
    /// then inferred from the negotiation block, which is the behaviour this
    /// field exists to stop relying on.
    ///
    /// Spelled `type` in the document, as the specification writes it.
    /// `profile_type` stays accepted as an alias: the field was read under
    /// that name before, and a document already written must not stop being
    /// intelligible over a spelling.
    #[serde(default, rename = "type", alias = "profile_type")]
    profile_type: Option<ProfileKind>,
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
    /// Trust material of spec §19. Absent in a document written before it.
    #[serde(default)]
    trust: Option<crate::config::TrustMaterial>,
}

/// The §19 discriminant, defined with the profile model it belongs to.
///
/// Re-exported here because a document is where it is first read.
pub use crate::config::ProfileKind;

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
            trust: value.trust,
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
            profile_type: profile.profile_type,
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
    /// What the document said that Orion read but does **not** apply.
    ///
    /// Distinct from [`CompletedImport::incomplete`], which is about a field
    /// left to fill. These are fields that were *understood and dropped* — a
    /// `DNS` line, an `MTU` — and dropping one silently changes the tunnel's
    /// behaviour without changing anything the user can see.
    pub notices: Vec<String>,
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

/// Suffixes of an Orion document.
///
/// `.orion` is **ours**: it is what `helios-ctl enroll` writes and what Windows
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
    // wg-quick has no notion of a client identity: only the Orion document
    // can carry one.
    let (profile, identity, notices) = if named_orion || trimmed.starts_with('{') {
        let (profile, identity) = parse_json(trimmed)?;
        (profile, identity, Vec::new())
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
    Ok(ProfileImport {
        profile,
        identity,
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
fn decode_document(bytes: &[u8]) -> Result<String> {
    fn from_utf16(bytes: &[u8], little_endian: bool) -> Result<String> {
        if !bytes.len().is_multiple_of(2) {
            anyhow::bail!("le profil est encodé en UTF-16 mais tronqué (nombre impair d'octets)");
        }
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                if little_endian {
                    u16::from_le_bytes(*pair)
                } else {
                    u16::from_be_bytes(*pair)
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
            notices,
            private_key_missing: Some(missing),
            incomplete,
        });
    };

    profile.private_key = existing.private_key.clone();
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

    // The discriminant of spec §19, checked against what the document
    // actually carries. A claim and a content that disagree is the case the
    // field exists for: inferring from the block would have accepted both
    // silently, and one of the two is a profile that mounts a tunnel with no
    // pre-WireGuard authentication.
    let declared = profile.profile_type;
    let has_block = profile.key_negotiation.is_some();
    match (declared, has_block) {
        (Some(ProfileKind::HeliosKeyNegotiation), false) => anyhow::bail!(
            "ce document se déclare « helios_key_negotiation » mais ne porte pas de bloc de \
             négociation : un profil Helios sans négociation monterait un tunnel sans \
             authentification avant WireGuard"
        ),
        (Some(ProfileKind::Classic), true) => anyhow::bail!(
            "ce document se déclare « classic » mais porte un bloc de négociation : l'un des \
             deux est faux, et deviner lequel reviendrait à choisir un niveau de protection à \
             la place de l'opérateur"
        ),
        // No claim: inferred, as documents written before §19 have always
        // been read. The inference happens **here**, once, and is written into
        // the profile below — so a document that predates the field still ends
        // up with a recorded kind, and nothing downstream ever guesses again.
        _ => {}
    }

    if let Some(trust) = profile
        .key_negotiation
        .as_ref()
        .and_then(|block| block.trust.as_ref())
    {
        trust
            .validate()
            .context("matériel de confiance du document")?;
    }
    let mut profile: ClientProfile = profile.into();
    // Mandatory after import (spec §19): from here on the profile carries its
    // own answer, declared by the document or resolved from it at this single
    // point.
    profile.profile_type = Some(profile.kind());
    Ok((profile, identity))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WgSection {
    Interface,
    Peer,
}

/// A wg-quick file, read into a profile plus what was dropped along the way.
struct WgQuickImport {
    profile: ClientProfile,
    notices: Vec<String>,
}

/// wg-quick properties Orion reads and applies.
const WG_APPLIED_INTERFACE: &[&str] = &["privatekey", "address"];
const WG_APPLIED_PEER: &[&str] = &[
    "publickey",
    "presharedkey",
    "allowedips",
    "endpoint",
    "persistentkeepalive",
];

/// Properties Orion understands, does not apply, and **says so**.
///
/// Refusing the file over these was the wrong trade: they appear in almost
/// every configuration a provider hands out, and a client that cannot open a
/// normal WireGuard file is not a WireGuard client. Dropping them silently is
/// the other wrong trade — a `DNS` line that vanishes takes name resolution
/// with it, and the user sees a tunnel that works and a browser that does not.
///
/// So each one is imported as a notice naming the consequence.
fn wg_unapplied_notice(field: &str, value: &str) -> Option<String> {
    let value = value.trim();
    Some(match field {
        // Orion does not tunnel DNS at all — the same documented limit the
        // gateway's ruleset carries. Naming it here is the only chance the
        // user has to learn it before the queries leave in the clear.
        "dns" => format!(
            "DNS = {value} : Orion n'applique pas de serveur DNS et ne tunnelise pas les \
             requêtes de résolution ; elles sortiront hors du tunnel."
        ),
        "mtu" => format!(
            "MTU = {value} : Orion laisse l'adaptateur choisir son MTU. Un chemin qui exigeait \
             cette valeur peut fragmenter."
        ),
        "table" => {
            format!("Table = {value} : Orion pose ses routes lui-même, à partir du trafic capté.")
        }
        "listenport" => {
            format!("ListenPort = {value} : Orion laisse le système attribuer le port source.")
        }
        "fwmark" => format!("FwMark = {value} : Orion ne marque pas ses paquets."),
        _ => return None,
    })
}

/// Properties Orion refuses, because they run something.
///
/// A `PostUp` is a shell command the configuration depends on — a firewall
/// rule, a route, a resolver swap. Orion will not execute it, and importing
/// the file **without** it would produce a tunnel the author never described.
/// This is the one class where refusing is right: the alternative is a profile
/// that looks identical and behaves differently.
fn wg_executable_field(field: &str) -> bool {
    matches!(
        field,
        "preup" | "postup" | "predown" | "postdown" | "saveconfig"
    )
}

fn parse_wg_quick(contents: &str, file_name: &str) -> Result<WgQuickImport> {
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
    let mut notices = Vec::new();
    classify_wg_fields(
        &interface,
        WG_APPLIED_INTERFACE,
        "[Interface]",
        &mut notices,
    )?;
    classify_wg_fields(&peer, WG_APPLIED_PEER, "[Peer]", &mut notices)?;

    let keepalive = match peer.get("persistentkeepalive") {
        Some(raw) => raw
            .parse::<u16>()
            .context("PersistentKeepalive doit être un entier entre 0 et 65535")?,
        None => DEFAULT_KEEPALIVE_SECS,
    };

    let profile = ClientProfile {
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
        // A wg-quick file **is** the classic shape: it has no way to express a
        // Helios negotiation, so the discriminant is a fact here, not a guess.
        profile_type: Some(ProfileKind::Classic),
        ssh_target: None,
        key_negotiation: None,
        preshared_key_is_negotiated: false,
    };
    Ok(WgQuickImport { profile, notices })
}

/// Sorts a section's properties into applied, reported and refused.
///
/// The three classes are the whole point. An allowlist alone refused ordinary
/// files; no list at all would drop, without a word, lines the tunnel's
/// behaviour depends on.
fn classify_wg_fields(
    fields: &HashMap<String, String>,
    applied: &[&str],
    section: &str,
    notices: &mut Vec<String>,
) -> Result<()> {
    // Sorted, so two imports of one file report the same thing in the same
    // order: a notice list that shuffled between runs reads as new problems.
    let mut names: Vec<&String> = fields.keys().collect();
    names.sort();
    for field in names {
        if applied.contains(&field.as_str()) {
            continue;
        }
        if wg_executable_field(field) {
            anyhow::bail!(
                "propriété {field} de {section} : Orion n'exécute aucune commande d'un fichier \
                 importé, et l'importer sans elle produirait un tunnel différent de celui que ce \
                 fichier décrit. La retirer du fichier, en connaissance de cause, permet l'import."
            );
        }
        match wg_unapplied_notice(field, &fields[field]) {
            Some(notice) => notices.push(notice),
            // A property nobody here knows about could mean anything, and
            // guessing which half of the trade it falls on is how a silent
            // behaviour change gets shipped.
            None => anyhow::bail!(
                "propriété {field} de {section} inconnue d'Orion ; la retirer modifierait \
                 peut-être le comportement du profil"
            ),
        }
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
mod tests;
