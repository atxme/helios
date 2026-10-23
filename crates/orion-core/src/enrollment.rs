//! The client half of enrollment v5 (NEGOCIATION-DE-CLE-V5 §15).
//!
//! Orion imports an invitation, shows the fingerprint of the `CA-PQ` key it
//! names, and does **nothing** until the user has typed back the fingerprint
//! read out of band. Then, and only then, it generates its three key pairs —
//! WireGuard, TLS, ML-DSA-87 — signs a request bound to the invitation, and
//! seals everything as a *pending enrollment* in the protected store. The
//! request file is produced only once that seal is on disk: a request whose
//! keys were lost could be accepted, and the document that answers it would
//! admit a peer nobody can connect as.
//!
//! The pending record is the only place the three private keys exist until
//! the signed `.orion` comes back and `complete_enrollment` turns it into
//! an identity.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use aether::certificates::encoding::{Fingerprint, Id16, MlDsa87Signature};
use aether::key_negotiation::{
    decode_invitation_file, encode_request_file, wireguard_proof, EnrollmentInvitation,
    EnrollmentRequest, ENROLLMENT_FORMAT_VERSION, ENROLLMENT_PROTOCOL_VERSION,
};
use aether::{secret::json::SecretJson, SecretString};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::ProtectedIdentityStore;

/// Prefix of a pending enrollment's sealed record.
const PENDING_PREFIX: &str = "pending-enrollment-";
/// Version of the sealed pending record.
const PENDING_FORMAT_VERSION: u16 = 1;
/// Bound on the plaintext of a pending record: two signed objects and three
/// keys, about 20 KiB.
const MAX_PENDING_BYTES: usize = 128 * 1024;

/// What the screen shows of an invitation before anything is trusted.
#[derive(Debug, Clone)]
pub struct InvitationPreview {
    pub invitation: EnrollmentInvitation,
    /// SHA-256 fingerprint of the `CA-PQ` key, hexadecimal in groups of four:
    /// what the user compares with what the operator reads out.
    pub ca_fingerprint: String,
    pub server_name: String,
    pub expires_at_unix: u64,
}

/// Reads a `.helios-invite`, as raw bytes in whatever encoding it travelled.
///
/// Shape and window only. The signature is **not** checked here, and cannot
/// be: the key it would be checked under is exactly what the user has not
/// confirmed yet.
pub fn preview_invitation(bytes: &[u8], now_unix: u64) -> Result<InvitationPreview> {
    let text = crate::profile_import::decode_document(bytes)?;
    let invitation = decode_invitation_file(&text)
        .map_err(|error| anyhow::anyhow!("invitation d'enrôlement illisible : {error}"))?;
    if now_unix > invitation.not_after_unix {
        bail!("cette invitation a expiré : en demander une nouvelle à l'opérateur");
    }
    Ok(InvitationPreview {
        ca_fingerprint: format_fingerprint(
            &invitation.operator_ca_public_key.authority_fingerprint(),
        ),
        server_name: invitation.server_name.clone(),
        expires_at_unix: invitation.not_after_unix,
        invitation,
    })
}

/// A fingerprint in groups of four hexadecimal digits.
pub fn format_fingerprint(fingerprint: &Fingerprint) -> String {
    fingerprint
        .to_hex()
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A pending enrollment, as the screen lists it. Carries no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingEnrollment {
    pub invitation_id: Id16,
    pub request_id: Id16,
    pub requested_name: String,
    pub server_name: String,
    pub created_at_unix: u64,
    /// After this instant the operator can no longer accept the request.
    pub invitation_expires_at_unix: u64,
}

/// The sealed content of a pending enrollment.
///
/// Deliberately neither `Serialize` nor `Debug`-derived: it holds the three
/// private keys, and is written only by [`Self::encode`] into the protected
/// store.
pub(crate) struct PendingSecrets {
    pub(crate) created_at_unix: u64,
    pub(crate) invitation: EnrollmentInvitation,
    pub(crate) request: EnrollmentRequest,
    /// WireGuard private key, base64.
    pub(crate) wg_private_key: SecretString,
    /// TLS private key, PKCS#8 DER.
    pub(crate) tls_private_key_der: Zeroizing<Vec<u8>>,
    /// ML-DSA-87 private key.
    pub(crate) ml_dsa_private_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for PendingSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingSecrets")
            .field("request_id", &self.request.request_id)
            .field("invitation_id", &self.invitation.invitation_id)
            .field("wg_private_key", &"***")
            .field("tls_private_key_der", &"***")
            .field("ml_dsa_private_key", &"***")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRecord {
    format_version: u16,
    created_at_unix: u64,
    invitation: EnrollmentInvitation,
    request: EnrollmentRequest,
    wg_private_key: SecretString,
    tls_private_key: SecretString,
    ml_dsa_private_key: SecretString,
}

impl PendingSecrets {
    pub(crate) fn summary(&self) -> PendingEnrollment {
        PendingEnrollment {
            invitation_id: self.invitation.invitation_id,
            request_id: self.request.request_id,
            requested_name: self.request.requested_name.clone(),
            server_name: self.invitation.server_name.clone(),
            created_at_unix: self.created_at_unix,
            invitation_expires_at_unix: self.invitation.not_after_unix,
        }
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = SecretJson::new(MAX_PENDING_BYTES);
        out.append(b"{\"format_version\":")?;
        out.public(&PENDING_FORMAT_VERSION)?;
        out.append(b",\"created_at_unix\":")?;
        out.public(&self.created_at_unix)?;
        out.append(b",\"invitation\":")?;
        out.public(&self.invitation)?;
        out.append(b",\"request\":")?;
        out.public(&self.request)?;
        out.append(b",\"wg_private_key\":")?;
        out.secret(&self.wg_private_key)?;
        out.append(b",\"tls_private_key\":")?;
        out.secret_str(&Zeroizing::new(
            STANDARD.encode(self.tls_private_key_der.as_slice()),
        ))?;
        out.append(b",\"ml_dsa_private_key\":")?;
        out.secret_str(&Zeroizing::new(
            STANDARD.encode(self.ml_dsa_private_key.as_slice()),
        ))?;
        out.append(b"}")?;
        Ok(out.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let record: PendingRecord =
            serde_json::from_slice(bytes).context("demande d'enrôlement en attente illisible")?;
        if record.format_version != PENDING_FORMAT_VERSION {
            bail!(
                "demande d'enrôlement en attente au format {} : version inconnue",
                record.format_version
            );
        }
        let decode = |value: &SecretString, what: &str| -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(
                STANDARD
                    .decode(value.expose())
                    .with_context(|| format!("{what} : base64 illisible"))?,
            ))
        };
        Ok(Self {
            tls_private_key_der: decode(&record.tls_private_key, "clé privée TLS")?,
            ml_dsa_private_key: decode(&record.ml_dsa_private_key, "clé privée ML-DSA")?,
            created_at_unix: record.created_at_unix,
            invitation: record.invitation,
            request: record.request,
            wg_private_key: record.wg_private_key,
        })
    }
}

fn pending_name(request_id: &Id16) -> String {
    format!("{PENDING_PREFIX}{}", request_id.to_hex())
}

/// Builds the request once the user has confirmed the `CA-PQ` fingerprint.
///
/// The order is §15.2's: confirmation first, then the invitation's signature
/// under the key just confirmed, and only then are any keys generated. A
/// mismatch anywhere before generation leaves nothing behind.
pub(crate) fn prepare_request(
    invitation: &EnrollmentInvitation,
    confirmed_ca_fingerprint: &str,
    requested_name: &str,
    now_unix: u64,
) -> Result<PendingSecrets> {
    let typed: String = confirmed_ca_fingerprint
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    let expected = invitation.operator_ca_public_key.authority_fingerprint();
    if typed != expected.to_hex() {
        bail!(
            "l'empreinte saisie ne correspond pas à celle de l'invitation ({}) : ne pas poursuivre \
             sans l'avoir vérifiée auprès de l'opérateur",
            format_fingerprint(&expected)
        );
    }
    invitation
        .verify(&invitation.operator_ca_public_key, now_unix)
        .map_err(|error| anyhow::anyhow!("invitation refusée : {error}"))?;

    let requested_name = requested_name.trim();
    let wg = aether::wg::generate_keypair().context("génération de la clé WireGuard")?;
    let wg_private: Zeroizing<[u8; 32]> = Zeroizing::new(
        STANDARD
            .decode(wg.private_key.expose())
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .context("clé WireGuard générée illisible")?,
    );
    let (ml_dsa_private_key, ml_dsa_public_key) =
        aether::certificates::encoding::generate_ml_dsa_87_keypair()
            .context("génération de la clé ML-DSA-87")?;
    let csr = aether::certificates::x509::client_rotation_csr(requested_name)
        .context("génération de la clé TLS")?;
    let request_id = Id16::new(
        aether::random::public_bytes().map_err(|_| anyhow::anyhow!("aléa indisponible"))?,
    )
    .context("identifiant de demande")?;

    let mut request = EnrollmentRequest {
        format_version: ENROLLMENT_FORMAT_VERSION,
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: invitation.invitation_id,
        invitation_fingerprint: invitation.fingerprint(),
        request_id,
        timestamp_unix: now_unix,
        requested_name: requested_name.to_string(),
        client_wg_public_key: aether::certificates::encoding::WireGuardKey::parse(&wg.public_key)?,
        tls_csr: csr.csr,
        client_ml_dsa_87_public_key: ml_dsa_public_key,
        wireguard_proof: [0; 32],
        client_signature: MlDsa87Signature::placeholder(),
    };
    request
        .validate()
        .map_err(|error| anyhow::anyhow!("nom de pair refusé : {error}"))?;
    request.wireguard_proof = wireguard_proof(&wg_private, invitation, &request)
        .map_err(|error| anyhow::anyhow!("preuve WireGuard : {error}"))?;
    let request = request
        .sign(&ml_dsa_private_key)
        .map_err(|error| anyhow::anyhow!("signature de la demande : {error}"))?;
    request
        .verify(invitation)
        .map_err(|error| anyhow::anyhow!("demande incohérente : {error}"))?;

    Ok(PendingSecrets {
        created_at_unix: now_unix,
        invitation: invitation.clone(),
        request,
        wg_private_key: wg.private_key,
        tls_private_key_der: csr.private_key_der,
        ml_dsa_private_key,
    })
}

/// Generates the keys, seals them, and only then returns the request file.
pub fn begin_enrollment(
    store: &ProtectedIdentityStore,
    invitation: &EnrollmentInvitation,
    confirmed_ca_fingerprint: &str,
    requested_name: &str,
    now_unix: u64,
) -> Result<(PendingEnrollment, String)> {
    let pending = prepare_request(
        invitation,
        confirmed_ca_fingerprint,
        requested_name,
        now_unix,
    )?;
    let encoded = pending.encode()?;
    store.seal_named(&pending_name(&pending.request.request_id), &encoded)?;
    Ok((pending.summary(), encode_request_file(&pending.request)))
}

/// Every pending enrollment on this machine, oldest first.
pub fn pending_enrollments(store: &ProtectedIdentityStore) -> Result<Vec<PendingEnrollment>> {
    let mut pending = Vec::new();
    for name in store.names_with_prefix(PENDING_PREFIX)? {
        let secrets = PendingSecrets::decode(&store.open_named(&name)?)?;
        if pending_name(&secrets.request.request_id) != name {
            bail!("la demande en attente « {name} » ne porte pas son propre identifiant");
        }
        pending.push(secrets.summary());
    }
    pending.sort_by_key(|entry| entry.created_at_unix);
    Ok(pending)
}

/// Abandons a pending enrollment: its three private keys are destroyed.
pub fn discard_enrollment(store: &ProtectedIdentityStore, request_id: &Id16) -> Result<()> {
    store.remove_named(&pending_name(request_id))
}

#[cfg(test)]
pub(crate) mod tests;
