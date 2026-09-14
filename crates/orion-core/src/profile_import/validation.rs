//! Profile-level validation: the field rules applied to a whole profile,
//! fatally on import and as a report while editing.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{config::validate_key_negotiation, ClientProfile};

// Named by the documentation of `inspect_profile` below, and by nothing
// else: an intra-doc link only resolves in the scope it is written in.
#[allow(unused_imports)]
use super::parse_profile_import;

use super::field_rules::{
    normalize_cidr_list, validate_cidr, validate_cidr_list, validate_endpoint,
    validate_heliosd_url, validate_ssh_target, validate_wg_key,
};

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

pub(super) fn validate_imported_profile(mut profile: ClientProfile) -> Result<ClientProfile> {
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
