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

use aether::certificates::encoding::{Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature};
use aether::key_negotiation::{
    decode_invitation_file, encode_request_file, wireguard_proof, EnrollmentDocument,
    EnrollmentInvitation, EnrollmentRequest, PqCertificate, PqCertificateRole,
    ENROLLMENT_FORMAT_VERSION, ENROLLMENT_PROTOCOL_VERSION,
};
use aether::{secret::json::SecretJson, SecretString};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::{ClientIdentityBundle, ClientProfile, IdentityStoreError, ProtectedIdentityStore};

/// Prefix of the identity an enrollment seals.
const IDENTITY_PREFIX: &str = "enrollment-";
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The request file, as [`begin_enrollment`] first returned it.
    pub(crate) fn request_file(&self) -> String {
        encode_request_file(&self.request)
    }

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

/// Name of the identity sealed for the request `request_id`.
///
/// Derived from the request rather than chosen by the operator: the document
/// names no identity, and two enrollments of one machine never collide.
pub(crate) fn identity_name(request_id: &Id16) -> String {
    format!("{IDENTITY_PREFIX}{}", request_id.to_hex())
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
    Ok((pending.summary(), pending.request_file()))
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

/// The `.helios-request` of a pending enrollment, written again.
///
/// The request is public and is all that leaves the record: a download that
/// failed, or a dialog closed too early, must not cost a second request on
/// the same invitation.
pub fn pending_request_file(store: &ProtectedIdentityStore, request_id: &Id16) -> Result<String> {
    Ok(open_pending(store, request_id)?.request_file())
}

/// Destroys the pending record of the enrollment that sealed `identity`.
///
/// Called once a profile naming that identity is saved: its WireGuard private
/// key is then in the profile store, and the record holds nothing that is
/// still needed. An identity no enrollment produced has no record to destroy.
pub fn settle_enrollment(store: &ProtectedIdentityStore, identity: &str) -> Result<()> {
    match identity.strip_prefix(IDENTITY_PREFIX) {
        Some(request) => store.remove_named(&format!("{PENDING_PREFIX}{request}")),
        None => Ok(()),
    }
}

/// Opens one pending enrollment, private keys included.
pub(crate) fn open_pending(
    store: &ProtectedIdentityStore,
    request_id: &Id16,
) -> Result<PendingSecrets> {
    let secrets = PendingSecrets::decode(&store.open_named(&pending_name(request_id))?)?;
    if &secrets.request.request_id != request_id {
        bail!("la demande en attente {request_id} a été altérée");
    }
    Ok(secrets)
}

/// What importing a signed document did.
#[derive(Debug)]
pub enum EnrollmentOutcome {
    /// The identity is sealed, the pending record destroyed, and the profile
    /// carries the WireGuard private key generated with the request.
    Completed { profile: ClientProfile },
    /// No pending enrollment on this machine answers the document. The
    /// profile is a draft with no private key; `expected` says which key the
    /// document was issued for.
    Unmatched {
        profile: ClientProfile,
        expected: String,
    },
}

/// The pure half of [`complete_enrollment`]: every check of §15.3, and the
/// identity it yields. Nothing is written.
#[derive(Debug)]
pub(crate) enum DocumentMatch {
    Matched {
        profile: ClientProfile,
        bundle: ClientIdentityBundle,
    },
    Unmatched {
        profile: ClientProfile,
        expected: String,
    },
}

fn decode_pq_leaf(value: &str) -> Result<PqCertificate> {
    let json = STANDARD
        .decode(value.trim())
        .context("feuille PQ du document : base64 illisible")?;
    serde_json::from_slice(&json).context("feuille PQ du document illisible")
}

/// Checks a signed document against the pending enrollment it answers, in
/// the order of NEGOCIATION-DE-CLE-V5 §15.3.
///
/// The `CA-PQ` key is the one pinned when the user confirmed the invitation,
/// never the one the document names. Every mismatch is refused before
/// anything is sealed, and names both values.
pub(crate) fn match_document(
    pending: Option<&PendingSecrets>,
    document: &EnrollmentDocument,
    mut profile: ClientProfile,
    now_unix: u64,
) -> Result<DocumentMatch> {
    let Some(pending) = pending else {
        // Not trusted, and not trustable: the key that would verify it is
        // exactly what this machine does not hold. The draft has no private
        // key and cannot connect, and names no identity: the request id it
        // was parsed with is public, and the identity sealed under that name
        // must never be paired with anchors nobody verified.
        if let Some(block) = profile.key_negotiation.as_mut() {
            block.identity.clear();
        }
        // Read only to name the key: an unreadable leaf changes the wording,
        // not the verdict.
        let certified = match decode_pq_leaf(&document.client_pq_certificate) {
            Ok(leaf) => format!("clé WireGuard certifiée « {} »", leaf.wireguard_public_key),
            Err(_) => "feuille PQ du document illisible".to_string(),
        };
        return Ok(DocumentMatch::Unmatched {
            expected: format!(
                "aucune demande d'enrôlement en attente sur ce poste ne correspond à ce document \
                 ({certified}) : il a été préparé pour un autre poste, ou la demande a été \
                 abandonnée"
            ),
            profile,
        });
    };
    let client_leaf = decode_pq_leaf(&document.client_pq_certificate)?;
    let invitation = &pending.invitation;
    let request = &pending.request;
    let pinned = &invitation.operator_ca_public_key;

    if document.operator_ca_fingerprint != pinned.authority_fingerprint() {
        bail!(
            "document signé sous la CA-PQ {}, alors que l'invitation confirmée épingle {}",
            format_fingerprint(&document.operator_ca_fingerprint),
            format_fingerprint(&pinned.authority_fingerprint())
        );
    }
    if document.invitation_id != invitation.invitation_id
        || document.request_id != request.request_id
    {
        bail!(
            "le document répond à l'invitation {} / demande {}, pas à {} / {}",
            document.invitation_id,
            document.request_id,
            invitation.invitation_id,
            request.request_id
        );
    }
    document
        .verify(pinned)
        .map_err(|error| anyhow::anyhow!("signature du document refusée : {error}"))?;
    if document.request_fingerprint != request.fingerprint() {
        bail!(
            "le document certifie la demande {}, alors que celle de ce poste est {}",
            document.request_fingerprint,
            request.fingerprint()
        );
    }
    aether::certificates::x509::assert_csr_matches(
        &request.tls_csr,
        &document.client_tls_certificate,
    )
    .map_err(|error| {
        anyhow::anyhow!("la feuille TLS ne certifie pas la clé de ce poste : {error}")
    })?;
    client_leaf
        .verify(
            pinned.as_bytes(),
            PqCertificateRole::Client,
            Some(&request.requested_name),
            &request.client_wg_public_key.to_base64(),
            now_unix,
        )
        .map_err(|error| anyhow::anyhow!("feuille PQ cliente refusée : {error}"))?;
    let local_ml_dsa = request.client_ml_dsa_87_public_key.to_base64();
    if client_leaf.ml_dsa_87_public_key != local_ml_dsa {
        bail!(
            "la feuille PQ certifie la clé ML-DSA {}, alors que celle de ce poste est {local_ml_dsa}",
            client_leaf.ml_dsa_87_public_key
        );
    }

    let gateway_key = invitation.gateway_wg_public_key.to_base64();
    if profile.peer_public_key.trim() != gateway_key {
        bail!(
            "le profil désigne la gateway {}, alors que l'invitation confirmée nomme {gateway_key}",
            profile.peer_public_key
        );
    }
    let settings = profile
        .key_negotiation
        .as_mut()
        .context("un document signé porte toujours un bloc de négociation de clé")?;
    if settings.server_name.trim() != invitation.server_name {
        bail!(
            "le profil désigne le serveur « {} », alors que l'invitation confirmée nomme « {} »",
            settings.server_name,
            invitation.server_name
        );
    }
    let gateway_leaf = aether::certificates::gateway::pq_certificate_fingerprint(
        &settings.gateway_pq_certificate()?,
    )?;
    if gateway_leaf != invitation.gateway_certificate_fingerprint {
        bail!(
            "le profil épingle la feuille gateway {gateway_leaf}, alors que l'invitation confirmée \
             nomme {}",
            invitation.gateway_certificate_fingerprint
        );
    }
    let trust_ca = settings
        .trust
        .as_ref()
        .context("un document signé porte toujours son matériel de confiance")
        .and_then(|trust| {
            MlDsa87PublicKey::parse(&trust.ca_pq_public_key)
                .context("clé CA-PQ du matériel de confiance illisible")
        })?;
    if &trust_ca != pinned {
        bail!(
            "le matériel de confiance épingle la CA-PQ {}, alors que l'invitation confirmée nomme {}",
            format_fingerprint(&trust_ca.authority_fingerprint()),
            format_fingerprint(&pinned.authority_fingerprint())
        );
    }

    let name = identity_name(&request.request_id);
    settings.identity = name.clone();
    profile.private_key = pending.wg_private_key.duplicate();
    let bundle = ClientIdentityBundle {
        identity: name,
        certificate_chain: vec![document.client_tls_certificate.to_base64()],
        private_key: STANDARD
            .encode(pending.tls_private_key_der.as_slice())
            .into(),
        pq_certificate: document.client_pq_certificate.clone(),
        pq_private_key: STANDARD
            .encode(pending.ml_dsa_private_key.as_slice())
            .into(),
    };
    Ok(DocumentMatch::Matched { profile, bundle })
}

/// Completes an enrollment from its signed document.
///
/// The identity is sealed and the pending record **kept**: the WireGuard
/// private key is not part of the sealed bundle, and until the profile that
/// carries it is saved the pending record is its only durable copy. Importing
/// the same document again, after a restart or a refused save, completes it
/// again; [`settle_enrollment`] destroys the record once the profile is saved.
pub fn complete_enrollment(
    store: &ProtectedIdentityStore,
    document: &EnrollmentDocument,
    profile: ClientProfile,
    now_unix: u64,
) -> Result<EnrollmentOutcome> {
    let pending = match open_pending(store, &document.request_id) {
        Ok(pending) => Some(pending),
        Err(error)
            if matches!(
                error.downcast_ref::<IdentityStoreError>(),
                Some(IdentityStoreError::NotFound(_))
            ) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    match match_document(pending.as_ref(), document, profile, now_unix)? {
        DocumentMatch::Unmatched { profile, expected } => {
            Ok(EnrollmentOutcome::Unmatched { profile, expected })
        }
        DocumentMatch::Matched { profile, bundle } => {
            store.store(&bundle)?;
            Ok(EnrollmentOutcome::Completed { profile })
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
