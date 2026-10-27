//! The public half of an enrollment v5 document, assembled from what an
//! operator has: the client's request and leaves, and the gateway's public
//! material.
//!
//! Shared by Orion and `helios enroll document` so both build the very same
//! draft. The draft carries no secret and no signature: it is signed
//! afterwards under `CA-PQ`.

use aether::certificates::encoding::{DerCertificate, MlDsa87PublicKey};
use aether::key_negotiation::{
    EnrollmentDocument, EnrollmentRequest, PqCertificate, PqCertificateRole, ProtectionMode,
    ENROLLMENT_DOCUMENT_FORMAT, ENROLLMENT_DOCUMENT_VERSION,
};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::Serialize;

use crate::{verify_pinned_gateway_certificate, ProfileKind, TrustMaterial};

/// Gateway-side material a profile pins, however it was obtained.
pub struct GatewayMaterial {
    pub server_name: String,
    pub gateway_ca_der: String,
    pub gateway_pq_certificate: String,
    pub wireguard_public_key: String,
    pub pq_certificate_sha256: String,
    pub negotiation_port: Option<u16>,
}

/// What the gateway says about the admitted peer, however it was read.
pub struct Admission {
    pub address: String,
    pub address_v6: Option<String>,
    pub heliosd_url: Option<String>,
    pub trust: Option<TrustMaterial>,
}

/// The inputs of a draft, once every file and the gateway have been read.
pub struct DraftInput<'a> {
    pub request: &'a EnrollmentRequest,
    pub tls_certificate: DerCertificate,
    pub pq_certificate: &'a PqCertificate,
    pub material: &'a GatewayMaterial,
    pub admission: Admission,
    pub endpoint: &'a str,
    pub negotiation_endpoint: String,
    pub allowed_ips: Option<&'a str>,
    pub ssh_target: Option<&'a str>,
    pub now_unix: u64,
}

/// The leaves must certify the keys the request names, and nothing else.
pub fn check_leaves(
    request: &EnrollmentRequest,
    tls_certificate: &DerCertificate,
    pq_certificate: &PqCertificate,
) -> Result<()> {
    aether::certificates::x509::assert_csr_matches(&request.tls_csr, tls_certificate)
        .map_err(|error| anyhow::anyhow!("the TLS leaf does not certify the request: {error}"))?;
    if pq_certificate.role != PqCertificateRole::Client {
        bail!("the PQ leaf is not a client leaf");
    }
    let wireguard = request.client_wg_public_key.to_base64();
    if pq_certificate.wireguard_public_key != wireguard {
        bail!(
            "the PQ leaf certifies the WireGuard key {}, while the request names {wireguard}",
            pq_certificate.wireguard_public_key
        );
    }
    let ml_dsa = request.client_ml_dsa_87_public_key.to_base64();
    if pq_certificate.ml_dsa_87_public_key != ml_dsa {
        bail!("the PQ leaf certifies another ML-DSA-87 key than the request's");
    }
    Ok(())
}

pub fn build_draft(draft: DraftInput<'_>) -> Result<EnrollmentDocument> {
    let Some(trust) = draft.admission.trust else {
        bail!(
            "cette gateway n'a pas de domaine de confiance : `astra-signer init` puis \
             `heliosd init-trust-domain`. Un document v5 est signé sous la CA-PQ que ce domaine \
             épingle."
        );
    };
    let ca_pq_public_key = MlDsa87PublicKey::parse(&trust.ca_pq_public_key)
        .context("the trust block names an unreadable CA-PQ key")?;
    draft
        .pq_certificate
        .verify(
            ca_pq_public_key.as_bytes(),
            PqCertificateRole::Client,
            Some(&draft.request.requested_name),
            &draft.request.client_wg_public_key.to_base64(),
            draft.now_unix,
        )
        .map_err(|error| {
            anyhow::anyhow!("the PQ leaf does not verify under this domain's CA-PQ: {error}")
        })?;

    // The one place the pinned gateway leaf is verified, under the authority
    // that issued it — the trust block's `CA-PQ`.
    let gateway_certificate: PqCertificate = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(&draft.material.gateway_pq_certificate)
            .context("the gateway PQ certificate is not valid base64")?,
    )
    .context("the gateway PQ certificate is not a readable JSON document")?;
    verify_pinned_gateway_certificate(
        &gateway_certificate,
        &draft.material.server_name,
        &draft.material.wireguard_public_key,
        Some(&trust),
        draft.now_unix,
    )
    .context("the gateway PQ certificate does not verify — copied incompletely, or expired")?;

    let public = public_profile(&Profile {
        name: &draft.request.requested_name,
        endpoint: draft.endpoint,
        private_key: None,
        peer_public_key: &draft.material.wireguard_public_key,
        address: &draft.admission.address,
        address_v6: draft.admission.address_v6.as_deref(),
        allowed_ips: draft.allowed_ips,
        ssh_target: draft.ssh_target,
        heliosd_url: draft.admission.heliosd_url,
        key_negotiation: Some(KeyNegotiation {
            mode: ProtectionMode::MlKem,
            minimum_mode: ProtectionMode::MlKem,
            endpoint: draft.negotiation_endpoint,
            server_name: draft.material.server_name.clone(),
            gateway_ca_der: draft.material.gateway_ca_der.clone(),
            gateway_pq_certificate: draft.material.gateway_pq_certificate.clone(),
            trust: Some(trust),
        }),
    })?;
    Ok(EnrollmentDocument {
        format: ENROLLMENT_DOCUMENT_FORMAT.into(),
        format_version: ENROLLMENT_DOCUMENT_VERSION,
        invitation_id: draft.request.invitation_id,
        request_id: draft.request.request_id,
        request_fingerprint: draft.request.fingerprint(),
        operator_ca_fingerprint: ca_pq_public_key.authority_fingerprint(),
        issued_at_unix: draft.now_unix,
        profile: public,
        client_tls_certificate: draft.tls_certificate,
        client_pq_certificate: base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_vec(draft.pq_certificate).context("encoding the client PQ leaf")?,
        ),
        operator_signature: None,
    })
}

/// Endpoint of the negotiation service, as the client will dial it.
///
/// Derived from the tunnel endpoint by default: the two services live on the
/// same host, and asking the operator to retype the address is one more place
/// to get it wrong. The port comes from the gateway, never from a guess — a
/// hardcoded 51821 would silently be wrong on a gateway that moved it.
pub fn resolve_negotiation_endpoint(
    endpoint: &str,
    explicit: Option<&str>,
    port: Option<u16>,
) -> Result<String> {
    if let Some(explicit) = explicit {
        return Ok(explicit.trim().to_string());
    }
    let port = port.context(
        "the gateway publishes no key-negotiation port — set `key_negotiation_port` in \
         network.toml, or pass --negotiation-endpoint",
    )?;
    let host = endpoint
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(endpoint);
    Ok(format!("{host}:{port}"))
}

/// The profile, plus the §19 discriminant `helios profile` derives for it.
///
/// Kept out of [`Profile`] on purpose: the kind is not something a caller
/// chooses beside the negotiation block, it is what the presence of that block
/// *means*. Deriving it at the single point that renders a document makes the
/// two impossible to contradict — which is the failure the field exists to
/// stop, and it would be a poor joke to reintroduce it in the emitter.
#[derive(Serialize)]
pub struct TaggedProfile<'a> {
    #[serde(rename = "type")]
    profile_type: ProfileKind,
    #[serde(flatten)]
    inner: PublicProfile<'a>,
}

/// The `private_key` field is omitted in invitation mode: `orion-core` treats
/// it as absent, not empty, and completes it from the local profile.
pub struct Profile<'a> {
    pub name: &'a str,
    pub endpoint: &'a str,
    pub private_key: Option<&'a str>,
    pub peer_public_key: &'a str,
    pub address: &'a str,
    /// IPv6 VIP, `…/128`, written **only** when the peer has one
    /// (`ADRESSAGE-IPV6.md` §7.2).
    ///
    /// The document is `deny_unknown_fields`: an Orion older than the field
    /// refuses any profile carrying the key, even empty or `null`. Omitting it
    /// for a peer without IPv6 is what keeps the profile of a gateway without
    /// IPv6 readable by every Orion.
    pub address_v6: Option<&'a str>,
    /// Traffic the client routes into the tunnel — one or more CIDR prefixes,
    /// comma-separated.
    ///
    /// Omitted rather than defaulted, because the two are not the same thing:
    /// an absent field lets `orion-core` apply its default full tunnel,
    /// `0.0.0.0/0, ::/0`, which stays the right answer when the operator has
    /// said nothing. Only
    /// a split tunnel needs stating, and it is stated **here** so a fleet gets
    /// it from the document rather than from each user retyping prefixes into
    /// the Advanced panel.
    pub allowed_ips: Option<&'a str>,
    /// SSH destination inside the tunnel, `user@host`. Omitted = no terminal.
    pub ssh_target: Option<&'a str>,
    pub heliosd_url: Option<String>,
    /// Public negotiation settings. Absent when the gateway serves none:
    /// the profile then falls back to the legacy path, whose first handshake
    /// is unprotected.
    pub key_negotiation: Option<KeyNegotiation>,
}

/// The serializable half of an emitted profile contains public fields only.
#[derive(Serialize)]
struct PublicProfile<'a> {
    name: &'a str,
    endpoint: &'a str,
    peer_public_key: &'a str,
    address: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_v6: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_ips: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    heliosd_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_negotiation: Option<&'a KeyNegotiation>,
}

/// Public negotiation block, as `orion-core` reads it back.
#[derive(Serialize)]
pub struct KeyNegotiation {
    pub mode: ProtectionMode,
    /// Written explicitly even though `orion-core` would default it to
    /// `mode`: a floor that is visible in the document is one an operator can
    /// audit without knowing the defaulting rule.
    pub minimum_mode: ProtectionMode,
    pub endpoint: String,
    pub server_name: String,
    pub gateway_ca_der: String,
    pub gateway_pq_certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustMaterial>,
}

/// The profile with its §19 discriminant, derived from the negotiation block.
pub fn tagged<'a>(profile: &'a Profile<'a>) -> TaggedProfile<'a> {
    TaggedProfile {
        profile_type: if profile.key_negotiation.is_some() {
            ProfileKind::HeliosKeyNegotiation
        } else {
            ProfileKind::Classic
        },
        inner: PublicProfile {
            name: profile.name,
            endpoint: profile.endpoint,
            peer_public_key: profile.peer_public_key,
            address: profile.address,
            address_v6: profile.address_v6,
            allowed_ips: profile.allowed_ips,
            ssh_target: profile.ssh_target,
            heliosd_url: profile.heliosd_url.as_deref(),
            key_negotiation: profile.key_negotiation.as_ref(),
        },
    }
}

/// The public fields of a profile, as the v5 document carries them.
///
/// No private key can reach it: [`PublicProfile`] has no field for one.
pub fn public_profile(profile: &Profile<'_>) -> Result<serde_json::Map<String, serde_json::Value>> {
    match serde_json::to_value(tagged(profile)).context("serializing the public profile fields")? {
        serde_json::Value::Object(map) => Ok(map),
        _ => bail!("the public profile did not serialize as an object — this is a tooling bug"),
    }
}

#[cfg(test)]
mod tests;
