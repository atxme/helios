//! The versioned Orion JSON document, as it is written and as it is read.

use anyhow::{Context, Result};
use serde::Deserialize;

use aether::key_negotiation::ProtectionMode;

use crate::{
    identity_store::ClientIdentityBundle, ClientProfile, KeyNegotiationSettings,
    DEFAULT_ALLOWED_IPS, DEFAULT_KEEPALIVE_SECS,
};

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
    private_key: String,
    #[serde(default)]
    peer_public_key: String,
    #[serde(default)]
    preshared_key: Option<String>,
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

pub(super) fn parse_json(contents: &str) -> Result<(ClientProfile, Option<ClientIdentityBundle>)> {
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
