//! The versioned Orion JSON document, as it is written and as it is read.

use anyhow::{Context, Result};
use serde::Deserialize;

use aether::key_negotiation::{EnrollmentDocument, ProtectionMode, ENROLLMENT_DOCUMENT_VERSION};

use crate::{ClientProfile, KeyNegotiationSettings, DEFAULT_ALLOWED_IPS, DEFAULT_KEEPALIVE_SECS};

use super::ProfileKind;

/// Stable identifier of the JSON document exchangeable with Orion.
pub const PROFILE_IMPORT_FORMAT: &str = "orion-profile";
/// Current version of the JSON document exchangeable with Orion.
pub const PROFILE_IMPORT_VERSION: u16 = 1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonEnvelope {
    #[serde(rename = "format")]
    _format: String,
    #[serde(rename = "version")]
    _version: u16,
    profile: JsonProfile,
}

/// The two generations of the document share a format name and differ in
/// how they spell the version: `version` in v1, `format_version` in the
/// signed v5 document of NEGOCIATION-DE-CLE-V5 §15.3.
#[derive(Deserialize)]
struct JsonHeader {
    format: String,
    #[serde(default)]
    version: Option<u16>,
    #[serde(default)]
    format_version: Option<u16>,
}

/// What the refusal of an unsigned Helios document says: the procedure that
/// replaces it, not only the fact that it is refused.
const UNSIGNED_HELIOS_DOCUMENT: &str = "document Helios non signé : ce format portait les clés \
     privées du poste ou admettait une clé sans preuve de possession. Demander une invitation \
     d'enrôlement v5 à l'opérateur";

/// A decoded JSON document: the profile, and the signed envelope it came in
/// when it is a v5 document.
pub(super) struct ParsedJson {
    pub(super) profile: ClientProfile,
    /// Present for a v5 document. Its signature is **not** checked here: the
    /// key it verifies under is the one pinned by the pending enrollment, and
    /// only [`crate::enrollment::complete_enrollment`] holds it.
    pub(super) enrollment: Option<EnrollmentDocument>,
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
    /// to fill. [`complete_profile_import`](super::complete_profile_import) names what is missing, and
    /// [`ClientProfile::validate`] is what refuses a tunnel — parsing only
    /// decides whether the document is intelligible.
    #[serde(default)]
    endpoint: String,
    /// Absent in an invitation profile: the operator doesn't hold the
    /// client's private key and therefore has nothing to send back
    /// (ADR-004 §6). [`complete_profile_import`](super::complete_profile_import) then takes it from the local
    /// profile holding the admitted key, or from a key just generated.
    #[serde(default)]
    private_key: aether::SecretString,
    #[serde(default)]
    peer_public_key: String,
    #[serde(default)]
    preshared_key: Option<aether::SecretString>,
    #[serde(default)]
    address: Option<String>,
    /// IPv6 VIP, `…/128`, present only when the gateway assigned one
    /// (`ADRESSAGE-IPV6.md` §7.2).
    ///
    /// The envelope is `deny_unknown_fields`, so an Orion older than this
    /// field refuses a document carrying it — an explicit refusal, which is
    /// why `helios` writes the key only for a peer that has one.
    #[serde(default)]
    address_v6: Option<String>,
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
    /// Trust material of spec §19. Absent in a document written before it.
    #[serde(default)]
    trust: Option<crate::config::TrustMaterial>,
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
            // Named once the document is matched with a pending enrollment:
            // the identity is sealed by this machine, never named by the
            // operator.
            identity: String::new(),
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
            address_v6: profile.address_v6,
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

pub(super) fn parse_json(contents: &str) -> Result<ParsedJson> {
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
    match (header.version, header.format_version) {
        (Some(PROFILE_IMPORT_VERSION), None) => parse_v1(contents),
        (None, Some(ENROLLMENT_DOCUMENT_VERSION)) => parse_v5(contents),
        (version, format_version) => anyhow::bail!(
            "version de profil Orion non prise en charge : {} (versions attendues : \
             {PROFILE_IMPORT_VERSION}, ou {ENROLLMENT_DOCUMENT_VERSION} pour un document signé)",
            version
                .or(format_version)
                .map_or_else(|| "absente".to_string(), |version| version.to_string())
        ),
    }
}

/// The v1 document, which only a classic WireGuard profile may still use.
fn parse_v1(contents: &str) -> Result<ParsedJson> {
    // Decided on the raw value, before the typed parse: the fields that made
    // a v1 document Helios no longer exist in [`JsonProfile`], and a refusal
    // on an unknown field would not say what to do instead.
    let raw: serde_json::Value =
        serde_json::from_str(contents).context("document JSON Orion invalide")?;
    if let Some(profile) = raw.get("profile").and_then(serde_json::Value::as_object) {
        let declared_helios = profile
            .get("type")
            .or_else(|| profile.get("profile_type"))
            .and_then(serde_json::Value::as_str)
            == Some("helios_key_negotiation");
        if declared_helios
            || profile.contains_key("key_negotiation")
            || profile.contains_key("key_negotiation_identity")
        {
            anyhow::bail!("{UNSIGNED_HELIOS_DOCUMENT}");
        }
    }
    let envelope: JsonEnvelope =
        serde_json::from_str(contents).context("document JSON Orion invalide")?;
    Ok(ParsedJson {
        profile: into_client_profile(envelope.profile)?,
        enrollment: None,
    })
}

/// The signed v5 document (NEGOCIATION-DE-CLE-V5 §15.3).
///
/// Its profile carries no secret at all: the private keys never left the
/// machine, and the identity is named here from the request it answers.
fn parse_v5(contents: &str) -> Result<ParsedJson> {
    let document = EnrollmentDocument::parse(contents)
        .map_err(|error| anyhow::anyhow!("document Orion signé illisible : {error}"))?;
    let profile: JsonProfile =
        serde_json::from_value(serde_json::Value::Object(document.profile.clone()))
            .context("profil du document signé invalide")?;
    if !profile.private_key.is_empty() {
        anyhow::bail!(
            "un document signé ne porte jamais de clé privée : celle de ce poste n'a pas quitté \
             la machine"
        );
    }
    if profile.preshared_key.is_some() {
        anyhow::bail!("un document signé ne porte pas de PresharedKey : il est négocié par ML-KEM");
    }
    if profile.key_negotiation.as_ref().is_some_and(|block| {
        block.mode != ProtectionMode::MlKem
            || block
                .minimum_mode
                .is_some_and(|floor| floor != ProtectionMode::MlKem)
    }) {
        anyhow::bail!("un document signé n'admet que le mode ML-KEM, plancher compris");
    }
    // After the shared checks, so a document declaring Helios without a block
    // is refused with the §19 message that names the contradiction.
    let mut profile = into_client_profile(profile)?;
    let Some(settings) = profile.key_negotiation.as_mut() else {
        anyhow::bail!("un document signé porte toujours un bloc de négociation de clé");
    };
    settings.identity = crate::enrollment::identity_name(&document.request_id);
    Ok(ParsedJson {
        profile,
        enrollment: Some(document),
    })
}

/// The checks both generations share, and the conversion to the profile.
fn into_client_profile(profile: JsonProfile) -> Result<ClientProfile> {
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
    Ok(profile)
}
