//! Distribution of trust updates — spec §8.
//!
//! Three carriers, one rule: **an object is authorized by what the receiver
//! already trusts, never by the envelope that delivered it.**
//!
//! - inside the tunnel, `POST /api/key-negotiation/trust-update`, authenticated
//!   by the peer's own WireGuard source address and its PQ certificate;
//! - a chunked transaction, when the answer does not fit in 64 KiB;
//! - an offline `orion-trust-update` document, for a client that cannot reach
//!   Astra at all.
//!
//! # Why chunking does not weaken atomicity
//!
//! The 64 KiB ceiling splits the **transport**, not the decision. Every chunk
//! belongs to one signed manifest; chunks land in a pending area invisible to
//! the active and next slots; and when the set is complete, Orion verifies
//! each object in the order `CA-PQ -> CA-TLS -> Astra service key -> gateway
//! -> client`, re-compares the live snapshot, and publishes everything in a
//! single local write. A cut between two chunks leaves nothing behind — the
//! alternative, applying objects as they arrive, produces a trust store that
//! trusts the new CA and still pins the old gateway.
//!
//! # Why the in-tunnel request carries no challenge and no timestamp
//!
//! The transport already refuses replayed packets, and the request is signed
//! over the generations and fingerprints the client currently holds. Replaying
//! it can only ever ask for the same state again. Adding a challenge would buy
//! nothing and would cost a round trip on the one path that must work while a
//! client is racing an expiry.

use serde::{Deserialize, Serialize};

use crate::key_negotiation::PqCertificate;

use super::{
    authority::{
        AstraIssuerAuthorization, AstraServiceKeyTransition, CaTransition, ClientTlsCaTransition,
        EmergencyAstraServiceKeyReplacement,
    },
    client::{ClientCertificateRotationGrant, ClientCertificateStageAuthorization},
    encoding::{
        verify_ml_dsa_87, CanonicalBytes, Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature,
        SignedTranscript, TrustDomainId, WireGuardKey,
    },
    gateway::{pq_certificate_fingerprint, GatewayIdentityTransition, GatewayTransitionAbort},
    revocation::EmergencyCertificateRevocation,
    status::AstraCertificateStatus,
    CertificateError, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};

const TRUST_UPDATE_REQUEST_DOMAIN: &[u8] = b"helios-in-tunnel-trust-update-request-v5";
const TRANSACTION_MANIFEST_DOMAIN: &[u8] = b"helios-trust-update-transaction-manifest-v5";
const TRANSACTION_CHUNK_DOMAIN: &[u8] = b"helios-trust-update-chunk-v5";
const OFFLINE_DOCUMENT_DOMAIN: &[u8] = b"helios-orion-trust-update-document-v5";

/// Largest request body read before deserialization (spec §8.1).
pub const MAX_TRUST_UPDATE_REQUEST_BYTES: usize = 32 * 1024;
/// Largest response body produced (spec §8.1).
pub const MAX_TRUST_UPDATE_RESPONSE_BYTES: usize = 64 * 1024;
/// Largest single object. Beyond this an object is refused at issuance rather
/// than fragmented: a partial object has no signature of its own.
pub const MAX_TRUST_UPDATE_OBJECT_BYTES: usize = 60 * 1024;
/// Largest number of objects in one transaction (spec §8.1).
pub const MAX_TRUST_UPDATE_OBJECTS: usize = 64;

/// Request an admitted Orion sends inside the tunnel (spec §8.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustUpdateRequest {
    pub protocol_version: u16,
    pub request_id: Id16,
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub client_wg_public_key: WireGuardKey,
    pub ca_epoch: u64,
    pub ca_tls_epoch: u64,
    pub astra_service_key_epoch: u64,
    pub issuer_epoch: u64,
    pub active_gateway_identity_epoch: u64,
    pub gateway_decision_epoch: u64,
    pub client_identity_generation: u64,
    pub active_gateway_tls_certificate_fingerprint: Fingerprint,
    pub active_gateway_certificate_fingerprint: Fingerprint,
    pub active_client_tls_certificate_fingerprint: Fingerprint,
    pub active_client_pq_certificate_fingerprint: Fingerprint,
    /// Fingerprint of the PQ certificate carried alongside this request.
    pub client_pq_certificate_fingerprint: Fingerprint,
}

impl TrustUpdateRequest {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(TRUST_UPDATE_REQUEST_DOMAIN);
        bytes
            .u16(self.protocol_version)
            .id(&self.request_id)
            .id(&self.trust_domain_id)
            .key(&self.gateway_wg_public_key)
            .key(&self.client_wg_public_key)
            .u64(self.ca_epoch)
            .u64(self.ca_tls_epoch)
            .u64(self.astra_service_key_epoch)
            .u64(self.issuer_epoch)
            .u64(self.active_gateway_identity_epoch)
            .u64(self.gateway_decision_epoch)
            .u64(self.client_identity_generation)
            .fingerprint(&self.active_gateway_tls_certificate_fingerprint)
            .fingerprint(&self.active_gateway_certificate_fingerprint)
            .fingerprint(&self.active_client_tls_certificate_fingerprint)
            .fingerprint(&self.active_client_pq_certificate_fingerprint)
            .fingerprint(&self.client_pq_certificate_fingerprint);
        bytes.finish_signed()
    }
}

/// The request plus the certificate and signature that authenticate it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedTrustUpdateRequest {
    pub request: TrustUpdateRequest,
    pub certificate: PqCertificate,
    pub ml_dsa_87_signature: MlDsa87Signature,
}

impl AuthenticatedTrustUpdateRequest {
    /// Verifies what the gateway can check from the message itself.
    ///
    /// The caller has already resolved the **source address** to its single
    /// admitted peer, exactly like every other authenticated route: the body's
    /// `client_wg_public_key` is compared against that resolution and is never
    /// a lookup key. This function then proves the message was produced by the
    /// PQ identity of a generation that peer is currently allowed to present.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        issuers: &[&MlDsa87PublicKey],
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        resolved_client_wg_public_key: &WireGuardKey,
        acceptable_pq_fingerprints: &[Fingerprint],
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if self.request.protocol_version != CERTIFICATE_PROTOCOL_VERSION {
            return Err(CertificateError::UnsupportedProtocolVersion {
                received: self.request.protocol_version,
                supported: CERTIFICATE_PROTOCOL_VERSION,
            });
        }
        if self.request.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.request.gateway_wg_public_key != *gateway_wg_public_key {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.request.client_wg_public_key != *resolved_client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        // The leaf may chain to `CA-PQ` **or** to the delegated Astra issuer:
        // an ordinary renewal produces the second, and a route that only tried
        // the anchor would refuse every client that had ever renewed.
        crate::certificates::client::verify_client_leaf_under_any(
            &self.certificate,
            issuers,
            resolved_client_wg_public_key,
            now_unix,
        )?;
        let presented = pq_certificate_fingerprint(&self.certificate)?;
        if !self
            .request
            .client_pq_certificate_fingerprint
            .matches(&presented)
        {
            return Err(CertificateError::FingerprintMismatch("client PQ leaf"));
        }
        // "Acceptable at this instant" is the caller's business: the active
        // generation always, the next one only from its `activation_at`.
        if !acceptable_pq_fingerprints
            .iter()
            .any(|acceptable| acceptable.matches(&presented))
        {
            return Err(CertificateError::FingerprintMismatch("client generation"));
        }
        let public_key = MlDsa87PublicKey::parse(&self.certificate.ml_dsa_87_public_key)?;
        verify_ml_dsa_87(
            &public_key,
            &self.request.signing_bytes(),
            &self.ml_dsa_87_signature,
        )
    }
}

/// Every object a trust transaction can carry.
///
/// The tag is what makes the apply order checkable without parsing each
/// variant twice, and the order itself is the dependency order of spec §8.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TrustUpdateObject {
    CaTransition(Box<CaTransition>),
    ClientTlsCaTransition(Box<ClientTlsCaTransition>),
    AstraServiceKeyTransition(Box<AstraServiceKeyTransition>),
    AstraServiceKeyEmergencyReplacement(Box<EmergencyAstraServiceKeyReplacement>),
    AstraIssuerAuthorization(Box<AstraIssuerAuthorization>),
    GatewayIdentityTransition(Box<GatewayIdentityTransition>),
    GatewayTransitionAbort(Box<GatewayTransitionAbort>),
    ClientCertificateStageAuthorization(Box<ClientCertificateStageAuthorization>),
    ClientCertificateRotationGrant(Box<ClientCertificateRotationGrant>),
    CertificateRevocation(Box<EmergencyCertificateRevocation>),
    CertificateStatus(Box<AstraCertificateStatus>),
}

impl TrustUpdateObject {
    /// Rank in the apply order `CA-PQ -> CA-TLS -> Astra -> gateway -> client`.
    pub const fn apply_order(&self) -> u8 {
        match self {
            Self::CaTransition(_) => 0,
            Self::ClientTlsCaTransition(_) => 1,
            Self::AstraServiceKeyTransition(_)
            | Self::AstraServiceKeyEmergencyReplacement(_)
            | Self::AstraIssuerAuthorization(_) => 2,
            Self::GatewayIdentityTransition(_) | Self::GatewayTransitionAbort(_) => 3,
            Self::ClientCertificateStageAuthorization(_)
            | Self::ClientCertificateRotationGrant(_) => 4,
            // A revocation dominates everything, so it is applied first among
            // equals at the end: it can only ever remove.
            Self::CertificateRevocation(_) => 5,
            Self::CertificateStatus(_) => 6,
        }
    }

    /// Canonical fingerprint of the object, signatures included.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        Ok(match self {
            Self::CaTransition(object) => object.fingerprint(),
            Self::ClientTlsCaTransition(object) => object.fingerprint(),
            Self::AstraServiceKeyTransition(object) => object.fingerprint(),
            Self::AstraServiceKeyEmergencyReplacement(object) => object.fingerprint(),
            Self::AstraIssuerAuthorization(object) => object.fingerprint(),
            Self::GatewayIdentityTransition(object) => object.fingerprint()?,
            Self::GatewayTransitionAbort(object) => object.fingerprint(),
            Self::ClientCertificateStageAuthorization(object) => object.fingerprint()?,
            Self::ClientCertificateRotationGrant(object) => object.fingerprint()?,
            Self::CertificateRevocation(object) => object.fingerprint(),
            Self::CertificateStatus(object) => {
                Fingerprint::of(&serde_json::to_vec(object).unwrap_or_default())
            }
        })
    }
}

/// Which authority signed a transaction manifest (spec §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestAuthority {
    /// Any transaction touching a CA, the service key or the gateway identity.
    CaPq,
    /// A transaction limited to an ordinary client renewal.
    AstraServiceKey,
}

impl ManifestAuthority {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::CaPq => 0,
            Self::AstraServiceKey => 1,
        }
    }

    /// Whether this authority may sign a manifest containing `objects`.
    ///
    /// The service key covers client-scoped objects only. A manifest that
    /// moves an anchor while being authorized by the online key would hand a
    /// compromised Astra the fleet.
    fn covers(self, objects: &[TrustUpdateObjectRef]) -> bool {
        match self {
            Self::CaPq => true,
            Self::AstraServiceKey => objects.iter().all(|object| object.apply_order >= 4),
        }
    }
}

/// One entry of a manifest: what the object is, and what it depends on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustUpdateObjectRef {
    /// Apply-order rank of the object, as [`TrustUpdateObject::apply_order`].
    pub apply_order: u8,
    pub object_fingerprint: Fingerprint,
    /// Bits of objects that must be applied first. Only lower indices.
    pub prerequisite_bitmap: u64,
}

/// The single signed decision a chunked transaction carries (spec §8.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustUpdateTransactionManifest {
    pub format_version: u16,
    pub protocol_version: u16,
    pub transaction_id: Id16,
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub client_wg_public_key: WireGuardKey,
    /// SHA-256 of the receiver's complete state when the manifest was built.
    pub base_state_fingerprint: Fingerprint,
    pub created_at: u64,
    pub expires_at: u64,
    /// Earliest activation among the objects: past it, the transaction is
    /// refused rather than applied late.
    pub minimum_activation_at: u64,
    pub chunk_count: u16,
    pub objects: Vec<TrustUpdateObjectRef>,
    pub manifest_authority_kind: ManifestAuthority,
    pub manifest_authority_epoch: u64,
    pub signature: MlDsa87Signature,
}

impl TrustUpdateTransactionManifest {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(TRANSACTION_MANIFEST_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.transaction_id)
            .id(&self.trust_domain_id)
            .key(&self.gateway_wg_public_key)
            .key(&self.client_wg_public_key)
            .fingerprint(&self.base_state_fingerprint)
            .u64(self.created_at)
            .u64(self.expires_at)
            .u64(self.minimum_activation_at)
            .u16(self.chunk_count)
            .u16(self.objects.len() as u16);
        for object in &self.objects {
            bytes
                .u8(object.apply_order)
                .fingerprint(&object.object_fingerprint)
                .u64(object.prerequisite_bitmap);
        }
        bytes
            .u8(self.manifest_authority_kind.domain_byte())
            .u64(self.manifest_authority_epoch);
        bytes.finish_signed()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes.length_prefixed(self.signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Verifies the manifest under an authority already trusted locally.
    ///
    /// `base_state` is the fingerprint of the receiver's **live** state. A
    /// manifest built against a different one is refused outright: applying it
    /// would mean deciding from a snapshot that has since moved.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        authority_key: &MlDsa87PublicKey,
        authority_epoch: u64,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        client_wg_public_key: &WireGuardKey,
        base_state: &Fingerprint,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.protocol_version != CERTIFICATE_PROTOCOL_VERSION {
            return Err(CertificateError::UnsupportedProtocolVersion {
                received: self.protocol_version,
                supported: CERTIFICATE_PROTOCOL_VERSION,
            });
        }
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.client_wg_public_key != *client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        if !self.base_state_fingerprint.matches(base_state) {
            return Err(CertificateError::InvalidTransaction("base state moved"));
        }
        if self.objects.is_empty() || self.chunk_count == 0 {
            return Err(CertificateError::InvalidTransaction("empty transaction"));
        }
        if self.objects.len() > MAX_TRUST_UPDATE_OBJECTS {
            return Err(CertificateError::TooManyObjects);
        }
        if self.expires_at <= self.created_at || now_unix >= self.expires_at {
            return Err(CertificateError::InvalidLease);
        }
        // Past the earliest activation, the transaction can no longer be
        // committed: an object that should already be in force must not be
        // installed as if it were still in the future.
        if now_unix >= self.minimum_activation_at {
            return Err(CertificateError::InvalidTransaction(
                "minimum activation reached",
            ));
        }
        if self.manifest_authority_epoch != authority_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if !self.manifest_authority_kind.covers(&self.objects) {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        for (index, object) in self.objects.iter().enumerate() {
            if index > 0 && object.apply_order < self.objects[index - 1].apply_order {
                return Err(CertificateError::InvalidTransaction("apply order"));
            }
            // A prerequisite may only point backwards, and never outside the
            // list: a forward or out-of-range bit is a cycle or a dangling
            // dependency dressed as an ordering constraint.
            let allowed = if index == 0 {
                0
            } else {
                u64::MAX >> (64 - index)
            };
            if object.prerequisite_bitmap & !allowed != 0 {
                return Err(CertificateError::InvalidTransaction("prerequisite bitmap"));
            }
        }
        verify_ml_dsa_87(authority_key, &self.signing_bytes(), &self.signature)
    }
}

/// One fragment of a transaction. Carries whole objects, never partial ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustUpdateChunk {
    pub manifest_fingerprint: Fingerprint,
    pub chunk_index: u16,
    pub chunk_count: u16,
    pub first_object_index: u16,
    pub objects: Vec<TrustUpdateObject>,
}

impl TrustUpdateChunk {
    /// Canonical identity of the fragment, for idempotent replay.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        let mut bytes = CanonicalBytes::new(TRANSACTION_CHUNK_DOMAIN);
        bytes
            .fingerprint(&self.manifest_fingerprint)
            .u16(self.chunk_index)
            .u16(self.chunk_count)
            .u16(self.first_object_index)
            .u16(self.objects.len() as u16);
        for object in &self.objects {
            bytes.fingerprint(&object.fingerprint()?);
        }
        Ok(Fingerprint::of(&bytes.finish()))
    }

    /// Checks the fragment against the manifest that owns it.
    ///
    /// Every contained object has its fingerprint recomputed and compared to
    /// the manifest entry at its exact index. A chunk therefore cannot deliver
    /// an object the manifest did not name, nor deliver it at the wrong place
    /// in the apply order.
    pub fn verify_against(
        &self,
        manifest: &TrustUpdateTransactionManifest,
    ) -> Result<(), CertificateError> {
        if !self.manifest_fingerprint.matches(&manifest.fingerprint()) {
            return Err(CertificateError::InvalidTransaction("foreign chunk"));
        }
        if self.chunk_count != manifest.chunk_count || self.chunk_index >= self.chunk_count {
            return Err(CertificateError::InvalidTransaction("chunk index"));
        }
        if self.objects.is_empty() {
            return Err(CertificateError::InvalidTransaction("empty chunk"));
        }
        let first = usize::from(self.first_object_index);
        let last = first
            .checked_add(self.objects.len())
            .ok_or(CertificateError::TooManyObjects)?;
        if last > manifest.objects.len() {
            return Err(CertificateError::InvalidTransaction("chunk range"));
        }
        for (offset, object) in self.objects.iter().enumerate() {
            let expected = &manifest.objects[first + offset];
            if !object.fingerprint()?.matches(&expected.object_fingerprint) {
                return Err(CertificateError::FingerprintMismatch("transaction object"));
            }
            if object.apply_order() != expected.apply_order {
                return Err(CertificateError::InvalidTransaction("apply order"));
            }
        }
        Ok(())
    }
}

/// Accumulator for a transaction being received, invisible to the trust store.
///
/// It holds no authority of its own: nothing here is trusted until
/// [`Self::complete`] returns the whole ordered set and the caller has
/// verified each object against the anchors it already has.
#[derive(Debug)]
pub struct PendingTrustTransaction {
    manifest: TrustUpdateTransactionManifest,
    manifest_fingerprint: Fingerprint,
    slots: Vec<Option<TrustUpdateObject>>,
    /// Fingerprint of the fragment accepted at each index.
    ///
    /// Object slots alone are not enough: two fragments claiming the same
    /// `chunk_index` over different ranges would both be accepted, and between
    /// them they could fill the transaction without the sender ever having
    /// emitted that split. A chunk index names one fragment, for good.
    chunks: Vec<Option<Fingerprint>>,
}

impl PendingTrustTransaction {
    pub fn new(manifest: TrustUpdateTransactionManifest) -> Self {
        let slots = vec![None; manifest.objects.len()];
        let chunks = vec![None; usize::from(manifest.chunk_count)];
        let manifest_fingerprint = manifest.fingerprint();
        Self {
            manifest,
            manifest_fingerprint,
            slots,
            chunks,
        }
    }

    pub fn manifest(&self) -> &TrustUpdateTransactionManifest {
        &self.manifest
    }

    pub fn manifest_fingerprint(&self) -> Fingerprint {
        self.manifest_fingerprint
    }

    /// Accepts a chunk. Replaying an identical one is a no-op; the same index
    /// carrying different bytes is a conflict.
    pub fn accept(&mut self, chunk: &TrustUpdateChunk) -> Result<(), CertificateError> {
        chunk.verify_against(&self.manifest)?;

        // One fragment per index. A second one carrying different bytes at the
        // same index is a conflict, not a second delivery — otherwise two
        // partial splits could be combined into a transaction the sender never
        // produced.
        let index = usize::from(chunk.chunk_index);
        let fingerprint = chunk.fingerprint()?;
        match self.chunks.get_mut(index) {
            Some(Some(seen)) if !seen.matches(&fingerprint) => {
                return Err(CertificateError::InvalidTransaction("chunk conflict"))
            }
            Some(slot @ None) => *slot = Some(fingerprint),
            Some(Some(_)) => {}
            None => return Err(CertificateError::InvalidTransaction("chunk index")),
        }

        let first = usize::from(chunk.first_object_index);
        for (offset, object) in chunk.objects.iter().enumerate() {
            let slot = &mut self.slots[first + offset];
            match slot {
                Some(existing) if existing != object => {
                    return Err(CertificateError::InvalidTransaction("chunk conflict"))
                }
                Some(_) => {}
                None => *slot = Some(object.clone()),
            }
        }
        Ok(())
    }

    /// Every object slot filled **and** every announced fragment received.
    ///
    /// Both, not either. A manifest declaring two chunks can have all its
    /// object slots filled by chunk 0 alone — nothing forbids a fragment from
    /// covering the whole range — and a transaction committed on that basis is
    /// one the sender never emitted. The chunk count is part of the signed
    /// manifest, so it is a statement about how the decision was split, not a
    /// transport detail.
    pub fn is_complete(&self) -> bool {
        self.slots.iter().all(Option::is_some) && self.chunks.iter().all(Option::is_some)
    }

    /// The full ordered object list, or nothing at all.
    ///
    /// The caller applies these in one local write after verifying each of
    /// them; there is no partial success to expose.
    pub fn complete(&self) -> Option<Vec<TrustUpdateObject>> {
        if !self.is_complete() {
            return None;
        }
        Some(self.slots.iter().flatten().cloned().collect())
    }

    /// Whether the transaction may still be committed at `now_unix`.
    pub fn is_usable_at(&self, now_unix: u64) -> bool {
        now_unix < self.manifest.expires_at && now_unix < self.manifest.minimum_activation_at
    }
}

/// Offline trust update, carried by any untrusted channel (spec §8.4).
///
/// # A deliberate divergence, and why it is stronger
///
/// The specification describes a `CA-PQ` signature over the JCS form of the
/// document. This implementation signs the same fields in the canonical binary
/// encoding used by every other object here, derived from the **parsed**
/// document. That yields the properties JCS was asked for — one representation
/// per document, unknown members refused, duplicate members refused — without
/// a second canonicalization to get wrong: `deny_unknown_fields` rejects an
/// unknown member, serde rejects a duplicate one, and any re-encoding that
/// parses to the same document verifies identically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrionTrustUpdateDocument {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    /// At most one transition of each family, per spec §8.4.
    pub objects: Vec<TrustUpdateObject>,
    pub ca_signature: MlDsa87Signature,
}

impl OrionTrustUpdateDocument {
    fn signing_bytes(&self) -> Result<SignedTranscript, CertificateError> {
        let mut bytes = CanonicalBytes::new(OFFLINE_DOCUMENT_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .u16(self.objects.len() as u16);
        for object in &self.objects {
            bytes
                .u8(object.apply_order())
                .fingerprint(&object.fingerprint()?);
        }
        Ok(bytes.finish_signed())
    }

    /// Verifies the document under the CA active at the **start** of the
    /// import, taken from the local profile and never from the document.
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
    ) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.objects.is_empty() {
            return Err(CertificateError::EmptyTransition);
        }
        if self.objects.len() > MAX_TRUST_UPDATE_OBJECTS {
            return Err(CertificateError::TooManyObjects);
        }
        // One CA transition per document: a document carrying two would ask
        // the trust store to hold three anchors at once.
        let ca_transitions = self
            .objects
            .iter()
            .filter(|object| matches!(object, TrustUpdateObject::CaTransition(_)))
            .count();
        if ca_transitions > 1 {
            return Err(CertificateError::InvalidTransaction("two CA transitions"));
        }
        for pair in self.objects.windows(2) {
            if pair[1].apply_order() < pair[0].apply_order() {
                return Err(CertificateError::InvalidTransaction("apply order"));
            }
        }
        verify_ml_dsa_87(ca_pq, &self.signing_bytes()?, &self.ca_signature)
    }
}

/// Signing side of the transport objects (see `authority::signing`).
#[cfg(feature = "key-negotiation-signing")]
mod signing {
    use super::*;
    use crate::certificates::encoding::sign_ml_dsa_87;
    use crate::key_negotiation::PqCertificate;

    impl TrustUpdateRequest {
        /// Authenticates the request with the client's current PQ identity.
        pub fn authenticate(
            self,
            certificate: PqCertificate,
            client_pq_private_key: &[u8],
        ) -> Result<AuthenticatedTrustUpdateRequest, CertificateError> {
            let signature = sign_ml_dsa_87(client_pq_private_key, &self.signing_bytes())?;
            Ok(AuthenticatedTrustUpdateRequest {
                request: self,
                certificate,
                ml_dsa_87_signature: signature,
            })
        }
    }

    impl TrustUpdateTransactionManifest {
        pub fn sign(mut self, authority_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.signature = sign_ml_dsa_87(authority_private_key, &self.signing_bytes())?;
            Ok(self)
        }
    }

    impl OrionTrustUpdateDocument {
        pub fn sign(mut self, ca_pq_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.ca_signature = sign_ml_dsa_87(ca_pq_private_key, &self.signing_bytes()?)?;
            Ok(self)
        }
    }
}

#[cfg(all(test, feature = "key-negotiation-signing"))]
mod tests {
    use super::*;
    use crate::certificates::encoding::{generate_ml_dsa_87_keypair, sign_ml_dsa_87};
    use crate::certificates::window::TransitionWindow;
    use zeroize::Zeroizing;

    struct Keys {
        private: Zeroizing<Vec<u8>>,
        public: MlDsa87PublicKey,
    }

    fn keys() -> Keys {
        let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
        Keys { private, public }
    }

    fn domain() -> TrustDomainId {
        TrustDomainId::new([5; 16]).expect("domain")
    }

    fn gateway_key() -> WireGuardKey {
        WireGuardKey::from_bytes([1; 32])
    }

    fn client_key() -> WireGuardKey {
        WireGuardKey::from_bytes([2; 32])
    }

    /// A cheap object to fill a transaction with: a CA transition whose
    /// signatures are never verified by the manifest itself.
    fn ca_object(seed: u8) -> TrustUpdateObject {
        let next = keys();
        TrustUpdateObject::CaTransition(Box::new(CaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            current_ca_epoch: u64::from(seed),
            next_ca_epoch: u64::from(seed) + 1,
            current_ca_fingerprint: Fingerprint::of(&[seed]),
            next_ca_public_key: next.public.clone(),
            next_ca_fingerprint: next.public.authority_fingerprint(),
            window: TransitionWindow::new(1_000, 2_000, 3_000).unwrap(),
            current_ca_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
            next_ca_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        }))
    }

    fn manifest(
        authority: &Keys,
        objects: &[TrustUpdateObject],
        chunk_count: u16,
    ) -> TrustUpdateTransactionManifest {
        let refs = objects
            .iter()
            .map(|object| TrustUpdateObjectRef {
                apply_order: object.apply_order(),
                object_fingerprint: object.fingerprint().expect("fingerprint"),
                prerequisite_bitmap: 0,
            })
            .collect();
        let mut manifest = TrustUpdateTransactionManifest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            transaction_id: Id16::new([6; 16]).expect("id"),
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            base_state_fingerprint: Fingerprint::of(b"base state"),
            created_at: 1_000,
            expires_at: 5_000,
            minimum_activation_at: 9_000,
            chunk_count,
            objects: refs,
            manifest_authority_kind: ManifestAuthority::CaPq,
            manifest_authority_epoch: 1,
            signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        };
        manifest.signature = sign_ml_dsa_87(&authority.private, &manifest.signing_bytes()).unwrap();
        manifest
    }

    fn verify_manifest(
        manifest: &TrustUpdateTransactionManifest,
        authority: &Keys,
        now: u64,
    ) -> Result<(), CertificateError> {
        manifest.verify(
            &authority.public,
            1,
            &domain(),
            &gateway_key(),
            &client_key(),
            &Fingerprint::of(b"base state"),
            now,
        )
    }

    /// Nothing is visible until every chunk has landed — the property the
    /// whole chunking design exists for.
    #[test]
    fn a_transaction_stays_invisible_until_its_last_chunk_arrives() {
        let authority = keys();
        let objects = vec![ca_object(1), ca_object(2)];
        let manifest = manifest(&authority, &objects, 2);
        assert!(verify_manifest(&manifest, &authority, 1_100).is_ok());

        let mut pending = PendingTrustTransaction::new(manifest.clone());
        let first = TrustUpdateChunk {
            manifest_fingerprint: manifest.fingerprint(),
            chunk_index: 0,
            chunk_count: 2,
            first_object_index: 0,
            objects: vec![objects[0].clone()],
        };
        pending.accept(&first).expect("first chunk");
        assert!(!pending.is_complete());
        assert!(pending.complete().is_none());

        let second = TrustUpdateChunk {
            manifest_fingerprint: manifest.fingerprint(),
            chunk_index: 1,
            chunk_count: 2,
            first_object_index: 1,
            objects: vec![objects[1].clone()],
        };
        pending.accept(&second).expect("second chunk");
        assert_eq!(pending.complete().expect("complete").len(), 2);
    }

    /// A replayed chunk is a no-op; the same index with other bytes is not.
    #[test]
    fn an_identical_chunk_is_idempotent_and_a_differing_one_is_a_conflict() {
        let authority = keys();
        let objects = vec![ca_object(1)];
        let manifest = manifest(&authority, &objects, 1);
        let mut pending = PendingTrustTransaction::new(manifest.clone());
        let chunk = TrustUpdateChunk {
            manifest_fingerprint: manifest.fingerprint(),
            chunk_index: 0,
            chunk_count: 1,
            first_object_index: 0,
            objects: vec![objects[0].clone()],
        };
        pending.accept(&chunk).expect("first");
        pending.accept(&chunk).expect("replay is a no-op");

        let forged = TrustUpdateChunk {
            objects: vec![ca_object(9)],
            ..chunk
        };
        assert!(matches!(
            pending.accept(&forged),
            Err(CertificateError::FingerprintMismatch("transaction object"))
        ));
    }

    /// A fragment may cover more of the range than the split announced. The
    /// transaction is still not complete until every announced fragment has
    /// arrived — the count is signed, and it says how the decision was split.
    #[test]
    fn one_fragment_filling_every_slot_does_not_complete_a_two_chunk_transaction() {
        let authority = keys();
        let objects = vec![ca_object(1), ca_object(2)];
        let manifest = manifest(&authority, &objects, 2);
        let mut pending = PendingTrustTransaction::new(manifest.clone());

        let whole = TrustUpdateChunk {
            manifest_fingerprint: manifest.fingerprint(),
            chunk_index: 0,
            chunk_count: 2,
            first_object_index: 0,
            objects: objects.clone(),
        };
        pending.accept(&whole).expect("oversized first fragment");
        assert!(
            !pending.is_complete(),
            "every object is present, but the announced second fragment is not"
        );
        assert!(pending.complete().is_none());

        let second = TrustUpdateChunk {
            manifest_fingerprint: manifest.fingerprint(),
            chunk_index: 1,
            chunk_count: 2,
            first_object_index: 1,
            objects: vec![objects[1].clone()],
        };
        pending.accept(&second).expect("second fragment");
        assert_eq!(pending.complete().expect("complete").len(), 2);
    }

    #[test]
    fn a_chunk_belonging_to_another_manifest_is_refused() {
        let authority = keys();
        let objects = vec![ca_object(1)];
        let manifest = manifest(&authority, &objects, 1);
        let mut pending = PendingTrustTransaction::new(manifest);
        let stray = TrustUpdateChunk {
            manifest_fingerprint: Fingerprint::of(b"another manifest"),
            chunk_index: 0,
            chunk_count: 1,
            first_object_index: 0,
            objects: vec![objects[0].clone()],
        };
        assert!(matches!(
            pending.accept(&stray),
            Err(CertificateError::InvalidTransaction("foreign chunk"))
        ));
    }

    /// A manifest built against a snapshot that has since moved would decide
    /// from a state that no longer exists.
    #[test]
    fn a_manifest_whose_base_state_moved_is_refused() {
        let authority = keys();
        let manifest = manifest(&authority, &[ca_object(1)], 1);
        assert!(matches!(
            manifest.verify(
                &authority.public,
                1,
                &domain(),
                &gateway_key(),
                &client_key(),
                &Fingerprint::of(b"moved"),
                1_100
            ),
            Err(CertificateError::InvalidTransaction("base state moved"))
        ));
    }

    #[test]
    fn a_transaction_past_its_earliest_activation_is_refused() {
        let authority = keys();
        let mut manifest = manifest(&authority, &[ca_object(1)], 1);
        manifest.minimum_activation_at = 3_000;
        manifest.signature = sign_ml_dsa_87(&authority.private, &manifest.signing_bytes()).unwrap();

        assert!(verify_manifest(&manifest, &authority, 2_999).is_ok());
        assert!(matches!(
            verify_manifest(&manifest, &authority, 3_000),
            Err(CertificateError::InvalidTransaction(
                "minimum activation reached"
            ))
        ));
        // And past `expires_at` the transaction is simply gone.
        assert!(matches!(
            verify_manifest(&manifest, &authority, 5_000),
            Err(CertificateError::InvalidLease)
        ));
    }

    /// The online service key may not authorize a manifest that moves an
    /// anchor: that is exactly the power the delegation exists to withhold.
    #[test]
    fn the_astra_service_key_cannot_sign_an_anchor_moving_manifest() {
        let authority = keys();
        let mut manifest = manifest(&authority, &[ca_object(1)], 1);
        manifest.manifest_authority_kind = ManifestAuthority::AstraServiceKey;
        manifest.signature = sign_ml_dsa_87(&authority.private, &manifest.signing_bytes()).unwrap();
        assert!(matches!(
            verify_manifest(&manifest, &authority, 1_100),
            Err(CertificateError::UnauthorizedIssuer)
        ));
    }

    /// A prerequisite may only point backwards: a forward bit is a cycle.
    #[test]
    fn a_forward_prerequisite_is_refused() {
        let authority = keys();
        let objects = vec![ca_object(1), ca_object(2)];
        let mut manifest = manifest(&authority, &objects, 1);
        manifest.objects[0].prerequisite_bitmap = 0b10;
        manifest.signature = sign_ml_dsa_87(&authority.private, &manifest.signing_bytes()).unwrap();
        assert!(matches!(
            verify_manifest(&manifest, &authority, 1_100),
            Err(CertificateError::InvalidTransaction("prerequisite bitmap"))
        ));
    }

    #[test]
    fn an_offline_document_verifies_only_under_the_locally_trusted_anchor() {
        let ca = keys();
        let mut document = OrionTrustUpdateDocument {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            objects: vec![ca_object(1)],
            ca_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        };
        document.ca_signature =
            sign_ml_dsa_87(&ca.private, &document.signing_bytes().unwrap()).unwrap();
        assert!(document.verify(&ca.public, &domain()).is_ok());

        let stranger = keys();
        assert!(matches!(
            document.verify(&stranger.public, &domain()),
            Err(CertificateError::InvalidSignature)
        ));
        assert!(matches!(
            document.verify(&ca.public, &TrustDomainId::new([9; 16]).unwrap()),
            Err(CertificateError::TrustDomainMismatch)
        ));
    }

    /// At no instant may the trust store hold three anchors.
    #[test]
    fn an_offline_document_carrying_two_ca_transitions_is_refused() {
        let ca = keys();
        let mut document = OrionTrustUpdateDocument {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            objects: vec![ca_object(1), ca_object(2)],
            ca_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        };
        document.ca_signature =
            sign_ml_dsa_87(&ca.private, &document.signing_bytes().unwrap()).unwrap();
        assert!(matches!(
            document.verify(&ca.public, &domain()),
            Err(CertificateError::InvalidTransaction("two CA transitions"))
        ));
    }
}

// ---------------------------------------------------------------------------
// The relayed renewal, as Orion sees it (spec §8.1.2).
// ---------------------------------------------------------------------------
//
// These three live here rather than in `helios-api` because both ends parse
// them: the gateway serves them on the four in-tunnel routes, and Orion reads
// them off the wire. A second definition on the client side is a wire contract
// that two crates would have to be kept equal by hand, and the way that fails
// is silent — a field added on one side is simply dropped by the other, or
// refused by `deny_unknown_fields` with nothing naming which field.
//
// The private-link envelopes stay in `helios-api`: `caller_wg_public_key` is
// the gateway's own resolution of the peer, so an Orion has no business
// holding a type that carries it.

/// Where a renewal operation stands, as the authority reports it (spec §8.2).
///
/// Deliberately not [`super::status::CertificateStatus`]: that
/// enum describes a **certificate**, and until an operator has approved
/// anything there is no candidate certificate to describe. This describes the
/// operation, which is what `awaiting_operator` is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientRenewalOperationState {
    /// Prepared past the 80 % threshold and waiting for a hardware credential.
    /// Nothing is issued and no candidate exists.
    AwaitingOperator,
    /// The operator approval is persisted and Astra is issuing or replaying
    /// the exact staging authorization towards the gateway. A restart resumes
    /// this state under the same operation identifier.
    PendingGrant,
    /// The gateway persisted the candidate and signed its receipt; the grant
    /// is available and the client has yet to commit it.
    PendingCommit,
    /// The operation ended without a grant. No further assertion is accepted
    /// under this identifier — the client opens a new one.
    Failed,
}

/// What the authority answers about one operation.
///
/// The two capability tokens are minted for **this** read and live five
/// minutes at most (spec §8.2). The client that owns the operation hands them
/// to the companion; they confer nothing outside that operation, that manifest
/// and that scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientRenewalOperationView {
    pub operation_id: Id16,
    pub state: ClientRenewalOperationState,
    pub client_wg_public_key: WireGuardKey,
    pub request_fingerprint: Fingerprint,
    /// SHA-256 of the signed approval request the companion will be shown —
    /// the manifest the capability tokens are bound to.
    pub operation_manifest_fingerprint: Fingerprint,
    pub created_at: u64,
    pub expires_at: u64,
    /// Bearer token for the companion's read route, absent once the operation
    /// no longer accepts one.
    pub signer_request_token: Option<String>,
    /// Bearer token for the companion's submission route. Reusing it for the
    /// identical result is idempotent; another body under the operation is a
    /// conflict decided by Astra's persisted operation record.
    pub signer_result_token: Option<String>,
    /// Present only in [`ClientRenewalOperationState::PendingCommit`].
    pub grant: Option<Box<super::client::ClientCertificateRotationGrant>>,
}

/// What the companion fetches, and everything it needs in order to answer.
///
/// No private material: the approval request is signed by the Astra service
/// key the companion already pins, and the WebAuthn challenge is **derived**
/// from it rather than carried beside it — which is what stops an assertion
/// from being moved to another operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientRenewalSignerRequest {
    pub operation_id: Id16,
    pub approval_request: Box<super::approval::AstraCredentialApprovalRequest>,
    /// The `CA-PQ`-signed credential registry the allow-list comes from.
    ///
    /// Carried rather than assumed, because whoever runs the ceremony has to
    /// verify it under an anchor **it already holds**. The operator companion
    /// keeps its own copy beside the vault; Orion has none, and asking it to
    /// trust an allow-list on the authority's word would let a compromised
    /// authority name a credential of its choosing. Under `CA-PQ` it cannot.
    pub credential_registry: Box<super::approval::CredentialRegistry>,
    pub authority_url: String,
    pub webauthn_rp_id: String,
}
