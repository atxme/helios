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
//! over the generations and fingerprints the client currently holds, plus the
//! opaque fingerprint of its complete local trust state. Replaying it can only
//! ever ask for the same compare-and-swap decision again. Adding a challenge
//! would buy nothing and would cost a round trip on the one path that must work
//! while a client is racing an expiry.

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
    status::{AstraCertificateStatus, AstraRotationCampaign, AstraSignerRequest, CampaignScope},
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
/// Largest `StageCommitRequest` body read before deserialization (spec §7.3).
///
/// A bound of its own, because the commit route does not carry a trust update
/// and the two have nothing in common but the word "request". What it carries
/// is a commit with two ML-DSA-87 signatures, and a grant holding a third,
/// a PQ leaf, a TLS leaf, a stage receipt, and — whenever a delegated issuer
/// signed the generation, which is the ordinary case — a whole
/// `AstraIssuerAuthorization` with its own key and signature.
///
/// An ML-DSA-87 signature is 4627 bytes and a public key 2592, before base64
/// inflates them by a third. The 32 KiB sized for a trust update covers none
/// of that: the route rejected every real commit with 413, and the shape it
/// was measuring had never actually been sent.
pub const MAX_STAGE_COMMIT_REQUEST_BYTES: usize = 128 * 1024;

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
    /// SHA-256 of the sender's complete live trust state.
    ///
    /// The authority treats this as an opaque compare-and-swap token: it
    /// copies it into the transaction manifest, and the receiver recomputes it
    /// before commit. The authority never needs the local tombstones, pending
    /// slots or status counters that formed its preimage (spec §8.1.1).
    pub base_state_fingerprint: Fingerprint,
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
            .fingerprint(&self.client_pq_certificate_fingerprint)
            .fingerprint(&self.base_state_fingerprint);
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
        self.verify_preconditions(
            trust_domain_id,
            gateway_wg_public_key,
            resolved_client_wg_public_key,
        )?;
        // The leaf may chain to `CA-PQ` **or** to the delegated Astra issuer:
        // an ordinary renewal produces the second, and a route that only tried
        // the anchor would refuse every client that had ever renewed.
        crate::certificates::client::verify_client_leaf_under_any(
            &self.certificate,
            issuers,
            resolved_client_wg_public_key,
            now_unix,
        )?;
        self.verify_bound(resolved_client_wg_public_key, acceptable_pq_fingerprints)
    }

    /// The same verification, for a verifier that recorded the peer's leaf
    /// rather than the authority that issued it.
    ///
    /// Astra is that verifier. A first-generation leaf is issued by the
    /// operator CA, which its registry does not carry and must not learn from
    /// the request; the leaf it stored at admission answers the question an
    /// issuer set cannot.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_against_recorded_leaf(
        &self,
        recorded_leaf: &crate::key_negotiation::PqCertificate,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        resolved_client_wg_public_key: &WireGuardKey,
        acceptable_pq_fingerprints: &[Fingerprint],
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        self.verify_preconditions(
            trust_domain_id,
            gateway_wg_public_key,
            resolved_client_wg_public_key,
        )?;
        crate::certificates::client::verify_client_leaf_against_recorded(
            &self.certificate,
            recorded_leaf,
            resolved_client_wg_public_key,
            now_unix,
        )?;
        self.verify_bound(resolved_client_wg_public_key, acceptable_pq_fingerprints)
    }

    /// Everything both entry points check before the leaf is authenticated.
    fn verify_preconditions(
        &self,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        resolved_client_wg_public_key: &WireGuardKey,
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
        Ok(())
    }

    /// Everything both entry points check once the leaf is authenticated.
    fn verify_bound(
        &self,
        _resolved_client_wg_public_key: &WireGuardKey,
        acceptable_pq_fingerprints: &[Fingerprint],
    ) -> Result<(), CertificateError> {
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
    /// Reserved wire value. Online manifests carrying it are refused.
    ///
    /// `CA-PQ` authorizes the transition objects themselves; making it also
    /// sign one personalized envelope per client would require the offline
    /// companion for every recipient without granting any additional trust.
    CaPq,
    /// The online coordinator of every in-tunnel manifest.
    ///
    /// This signature binds target, base state, ordering and atomic grouping.
    /// Every contained object still verifies under its own normative
    /// authority, including `CA-PQ` where required.
    AstraServiceKey,
}

impl ManifestAuthority {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::CaPq => 0,
            Self::AstraServiceKey => 1,
        }
    }

    /// Whether this authority may sign an online manifest.
    fn covers(self, _objects: &[TrustUpdateObjectRef]) -> bool {
        match self {
            Self::CaPq => false,
            Self::AstraServiceKey => true,
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
///
/// Public, unlike its siblings: besides the inherent `sign` methods, it holds
/// the transaction **builder**, which the authority calls by name.
#[cfg(feature = "key-negotiation-signing")]
pub mod signing {
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

    /// What one transaction is addressed to and bounded by.
    ///
    /// A struct rather than nine positional arguments: every field here is a
    /// `u64` or a fingerprint, and a builder that took them in a row would let
    /// two of them be swapped without the compiler noticing — on the one
    /// object whose whole job is to say *which* peer and *which* base state.
    pub struct TransactionPlan<'a> {
        pub transaction_id: Id16,
        pub trust_domain_id: TrustDomainId,
        pub gateway_wg_public_key: WireGuardKey,
        pub client_wg_public_key: WireGuardKey,
        /// The opaque compare-and-swap token the client signed (§0.6).
        pub base_state_fingerprint: Fingerprint,
        pub created_at: u64,
        pub expires_at: u64,
        pub minimum_activation_at: u64,
        pub authority_epoch: u64,
        pub authority_private_key: &'a [u8],
    }

    /// Builds and signs one chunked transaction from an ordered object set.
    ///
    /// # Why this lives beside the verifier
    ///
    /// Every rule the receiver enforces is a rule the producer has to satisfy:
    /// the apply order, the object index each chunk starts at, the chunk count
    /// as a *signed statement about the split*, and the fingerprint each entry
    /// pins. Written on the other side of the wire they would be two readings
    /// of one contract, and the drift would only appear as a client refusing a
    /// transaction nobody could explain.
    ///
    /// The objects are sorted by apply order, stably: §8.1 orders the phases,
    /// and within a phase the caller's order is a decision this must not
    /// silently change.
    ///
    /// Chunks are cut by serialized size against `chunk_budget_bytes`, because
    /// what bounds a fragment is the response it has to fit in, not a count of
    /// objects — one gateway identity transition is worth many revocations.
    /// An object that does not fit alone is refused rather than split: a
    /// fragment carries whole objects, and there is no reassembly below that
    /// level.
    pub fn build_transaction(
        mut objects: Vec<TrustUpdateObject>,
        plan: &TransactionPlan<'_>,
        chunk_budget_bytes: usize,
    ) -> Result<(TrustUpdateTransactionManifest, Vec<TrustUpdateChunk>), CertificateError> {
        if objects.is_empty() {
            return Err(CertificateError::InvalidTransaction("empty transaction"));
        }
        if objects.len() > MAX_TRUST_UPDATE_OBJECTS {
            return Err(CertificateError::TooManyObjects);
        }
        objects.sort_by_key(TrustUpdateObject::apply_order);

        // The ranges first: the chunk count is signed, so it has to be known
        // before the manifest exists — and the manifest fingerprint has to
        // exist before any chunk can name it.
        let mut ranges: Vec<(u16, u16)> = Vec::new();
        let mut start = 0usize;
        let mut used = 0usize;
        for (index, object) in objects.iter().enumerate() {
            let size = serde_json::to_vec(object)
                .map_err(|_| CertificateError::InvalidTransaction("object encoding"))?
                .len();
            if size > chunk_budget_bytes {
                return Err(CertificateError::InvalidTransaction("object too large"));
            }
            if index > start && used + size > chunk_budget_bytes {
                ranges.push((start as u16, (index - start) as u16));
                start = index;
                used = 0;
            }
            used += size;
        }
        ranges.push((start as u16, (objects.len() - start) as u16));
        let chunk_count = u16::try_from(ranges.len())
            .map_err(|_| CertificateError::InvalidTransaction("chunk count"))?;

        let mut refs = Vec::with_capacity(objects.len());
        for object in &objects {
            refs.push(TrustUpdateObjectRef {
                apply_order: object.apply_order(),
                object_fingerprint: object.fingerprint()?,
                // Every earlier index, which is exactly what the apply order
                // means once the set is sorted: an object depends on
                // everything the receiver must already have installed.
                prerequisite_bitmap: prerequisites(refs.len()),
            });
        }

        let manifest = TrustUpdateTransactionManifest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            transaction_id: plan.transaction_id,
            trust_domain_id: plan.trust_domain_id,
            gateway_wg_public_key: plan.gateway_wg_public_key,
            client_wg_public_key: plan.client_wg_public_key,
            base_state_fingerprint: plan.base_state_fingerprint,
            created_at: plan.created_at,
            expires_at: plan.expires_at,
            minimum_activation_at: plan.minimum_activation_at,
            chunk_count,
            objects: refs,
            // §0.6: every online manifest is coordinated by the service key.
            // The objects keep their own normative signatures.
            manifest_authority_kind: ManifestAuthority::AstraServiceKey,
            manifest_authority_epoch: plan.authority_epoch,
            signature: MlDsa87Signature::placeholder(),
        }
        .sign(plan.authority_private_key)?;

        let manifest_fingerprint = manifest.fingerprint();
        let chunks = ranges
            .into_iter()
            .enumerate()
            .map(|(index, (first, len))| TrustUpdateChunk {
                manifest_fingerprint,
                chunk_index: index as u16,
                chunk_count,
                first_object_index: first,
                objects: objects[usize::from(first)..usize::from(first) + usize::from(len)]
                    .to_vec(),
            })
            .collect();
        Ok((manifest, chunks))
    }

    /// Every index strictly below `index`, as a bitmap.
    ///
    /// Saturating at 64 rather than wrapping: the object ceiling is
    /// [`MAX_TRUST_UPDATE_OBJECTS`], so the shift never overflows in practice,
    /// and a silent wrap would claim an object depends on nothing.
    const fn prerequisites(index: usize) -> u64 {
        if index >= 64 {
            u64::MAX
        } else {
            (1u64 << index) - 1
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

    /// The bound is not a round number picked by feel: it has to clear what a
    /// commit and its grant actually weigh, base64 included.
    #[test]
    fn the_stage_commit_bound_clears_what_the_pair_carries() {
        const ML_DSA_87_SIGNATURE: usize = 4627;
        const ML_DSA_87_PUBLIC_KEY: usize = 2592;
        // Two on the commit, one on the grant, one on the PQ leaf, one on the
        // stage receipt, one on the delegation.
        let signatures = 6 * ML_DSA_87_SIGNATURE;
        // The PQ leaf's key, and the delegated issuer's.
        let keys = 2 * ML_DSA_87_PUBLIC_KEY;
        // The client TLS leaf and the delegated intermediate, generously.
        let certificates = 2 * 2_048;
        let base64 = (signatures + keys + certificates).div_ceil(3) * 4;
        assert!(
            MAX_STAGE_COMMIT_REQUEST_BYTES > base64,
            "the bound must hold the signed material: {base64} bytes of base64"
        );
        assert!(
            MAX_TRUST_UPDATE_REQUEST_BYTES < base64,
            "if a trust update body could hold it, this constant would be pointless"
        );
    }

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
            manifest_authority_kind: ManifestAuthority::AstraServiceKey,
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

    /// The builder and the verifier are one contract: what it emits has to
    /// pass every check the receiver runs, reassemble in order, and land on
    /// the exact base state the client signed.
    #[test]
    fn a_built_transaction_verifies_and_reassembles_whole() {
        use super::signing::{build_transaction, TransactionPlan};

        let authority = keys();
        let base = Fingerprint::of(b"orion local state");
        let objects = vec![ca_object(1), ca_object(2), ca_object(3)];
        let plan = TransactionPlan {
            transaction_id: Id16::new([5; 16]).expect("id"),
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            base_state_fingerprint: base,
            created_at: 1_000,
            expires_at: 8_000,
            minimum_activation_at: 9_000,
            authority_epoch: 1,
            authority_private_key: &authority.private,
        };
        // A budget under two objects, so the split is exercised rather than
        // assumed: a single-chunk transaction proves nothing about ranges.
        let one_object = serde_json::to_vec(&objects[0]).expect("encode").len();
        let (manifest, chunks) =
            build_transaction(objects.clone(), &plan, one_object + 1).expect("built");

        assert!(chunks.len() > 1, "the budget must have split this set");
        assert_eq!(manifest.chunk_count as usize, chunks.len());
        manifest
            .verify(
                &authority.public,
                1,
                &domain(),
                &gateway_key(),
                &client_key(),
                &base,
                1_100,
            )
            .expect("the receiver accepts what the builder emitted");

        let mut pending = PendingTrustTransaction::new(manifest);
        for chunk in &chunks {
            pending.accept(chunk).expect("fragment");
        }
        assert!(pending.is_complete());
        assert_eq!(pending.complete().expect("complete"), objects);
    }

    /// The base state is the compare-and-swap token. A transaction built for
    /// one snapshot must not apply to another, even one object for object.
    #[test]
    fn a_built_transaction_is_refused_against_another_base_state() {
        use super::signing::{build_transaction, TransactionPlan};

        let authority = keys();
        let plan = TransactionPlan {
            transaction_id: Id16::new([5; 16]).expect("id"),
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            base_state_fingerprint: Fingerprint::of(b"the state it was built for"),
            created_at: 1_000,
            expires_at: 8_000,
            minimum_activation_at: 9_000,
            authority_epoch: 1,
            authority_private_key: &authority.private,
        };
        let (manifest, _) = build_transaction(vec![ca_object(1)], &plan, 64 * 1024).expect("built");
        assert!(matches!(
            manifest.verify(
                &authority.public,
                1,
                &domain(),
                &gateway_key(),
                &client_key(),
                &Fingerprint::of(b"the state it moved to"),
                1_100,
            ),
            Err(CertificateError::InvalidTransaction("base state moved"))
        ));
    }

    /// A fragment carries whole objects. One that fits in no fragment is
    /// refused here rather than emitted as a transaction nobody can read.
    #[test]
    fn an_object_that_fits_in_no_fragment_is_refused() {
        use super::signing::{build_transaction, TransactionPlan};

        let authority = keys();
        let plan = TransactionPlan {
            transaction_id: Id16::new([5; 16]).expect("id"),
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            base_state_fingerprint: Fingerprint::of(b"base"),
            created_at: 1_000,
            expires_at: 8_000,
            minimum_activation_at: 9_000,
            authority_epoch: 1,
            authority_private_key: &authority.private,
        };
        assert!(matches!(
            build_transaction(vec![ca_object(1)], &plan, 16),
            Err(CertificateError::InvalidTransaction("object too large"))
        ));
        assert!(matches!(
            build_transaction(Vec::new(), &plan, 64 * 1024),
            Err(CertificateError::InvalidTransaction("empty transaction"))
        ));
    }

    /// The opaque CAS token is part of the client's signature. A gateway may
    /// relay it, but cannot retarget the future manifest to another local
    /// state without invalidating the request first.
    /// A client leaf issued by an authority the verifier does not hold, bound
    /// to `client_key()` and valid over `1..=u64::MAX`.
    #[cfg(feature = "key-negotiation-signing")]
    fn client_leaf(
        subject: &str,
        subject_public: &MlDsa87PublicKey,
        issuer_private: &[u8],
        not_after: u64,
    ) -> crate::key_negotiation::PqCertificate {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        crate::key_negotiation::issue_pq_certificate(
            crate::key_negotiation::PqCertificate {
                version: crate::key_negotiation::PQ_CERTIFICATE_VERSION,
                serial: [4; 16],
                subject: subject.into(),
                issuer: "operator-ca".into(),
                role: crate::key_negotiation::PqCertificateRole::Client,
                wireguard_public_key: client_key().to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
                not_before_unix: 1,
                not_after_unix: not_after,
                ml_dsa_87_signature: String::new(),
            },
            issuer_private,
        )
        .expect("client leaf")
    }

    /// A request signed by that leaf, naming its own fingerprint.
    #[cfg(feature = "key-negotiation-signing")]
    fn signed_request(
        leaf: &crate::key_negotiation::PqCertificate,
        leaf_private: &[u8],
    ) -> AuthenticatedTrustUpdateRequest {
        let request = TrustUpdateRequest {
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            request_id: Id16::new([3; 16]).expect("request"),
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            ca_epoch: 1,
            ca_tls_epoch: 2,
            astra_service_key_epoch: 3,
            issuer_epoch: 4,
            active_gateway_identity_epoch: 5,
            gateway_decision_epoch: 6,
            client_identity_generation: 7,
            active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"gateway tls"),
            active_gateway_certificate_fingerprint: Fingerprint::of(b"gateway pq"),
            active_client_tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
            active_client_pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
            client_pq_certificate_fingerprint: pq_certificate_fingerprint(leaf).expect("presented"),
            base_state_fingerprint: Fingerprint::of(b"local state"),
        };
        let signature = sign_ml_dsa_87(leaf_private, &request.signing_bytes()).expect("signature");
        AuthenticatedTrustUpdateRequest {
            request,
            certificate: leaf.clone(),
            ml_dsa_87_signature: signature,
        }
    }

    /// A client's **first** leaf is issued by the operator CA, an authority a
    /// domain registry does not carry — and must not learn from the request it
    /// is checking. No issuer set can authenticate it, so Astra refused every
    /// peer that had never renewed: on a fresh domain, every peer.
    ///
    /// The leaf it recorded at admission answers what the issuer set cannot,
    /// and answers it more narrowly: one certificate rather than every
    /// certificate that authority ever signed.
    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn a_first_generation_leaf_verifies_against_the_recorded_one_and_under_no_issuer() {
        let operator_ca = keys();
        let leaf_keys = keys();
        let leaf = client_leaf("poste", &leaf_keys.public, &operator_ca.private, u64::MAX);
        let authenticated = signed_request(&leaf, &leaf_keys.private);
        let acceptable = [pq_certificate_fingerprint(&leaf).expect("presented")];
        let domain_anchor = keys();

        assert_eq!(
            authenticated.verify(
                &[&domain_anchor.public],
                &domain(),
                &gateway_key(),
                &client_key(),
                &acceptable,
                100,
            ),
            Err(CertificateError::UnauthorizedIssuer),
            "the operator CA is not an authority this registry holds"
        );
        authenticated
            .verify_against_recorded_leaf(
                &leaf,
                &domain(),
                &gateway_key(),
                &client_key(),
                &acceptable,
                100,
            )
            .expect("the leaf Astra recorded at admission");
    }

    /// Identity, not resemblance: another leaf for the same peer, issued by
    /// the same authority, is refused.
    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn a_leaf_other_than_the_recorded_one_is_refused() {
        let operator_ca = keys();
        let leaf_keys = keys();
        let leaf = client_leaf("poste", &leaf_keys.public, &operator_ca.private, u64::MAX);
        let other = client_leaf("autre", &leaf_keys.public, &operator_ca.private, u64::MAX);
        let authenticated = signed_request(&leaf, &leaf_keys.private);
        let acceptable = [pq_certificate_fingerprint(&leaf).expect("presented")];

        assert_eq!(
            authenticated.verify_against_recorded_leaf(
                &other,
                &domain(),
                &gateway_key(),
                &client_key(),
                &acceptable,
                100,
            ),
            Err(CertificateError::UnauthorizedIssuer)
        );
    }

    /// Recorded is not eternal. Identity replaces the issuer check, never the
    /// clock: a peer whose leaf has expired renews through §7.5, not here.
    #[cfg(feature = "key-negotiation-signing")]
    #[test]
    fn a_recorded_leaf_past_its_validity_is_refused() {
        let operator_ca = keys();
        let leaf_keys = keys();
        let leaf = client_leaf("poste", &leaf_keys.public, &operator_ca.private, 50);
        let authenticated = signed_request(&leaf, &leaf_keys.private);
        let acceptable = [pq_certificate_fingerprint(&leaf).expect("presented")];

        assert_eq!(
            authenticated.verify_against_recorded_leaf(
                &leaf,
                &domain(),
                &gateway_key(),
                &client_key(),
                &acceptable,
                100,
            ),
            Err(CertificateError::OutsideValidityPeriod)
        );
    }

    #[test]
    fn the_base_state_fingerprint_is_bound_into_the_client_request() {
        let signer = keys();
        let mut request = TrustUpdateRequest {
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            request_id: Id16::new([3; 16]).expect("request"),
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            ca_epoch: 1,
            ca_tls_epoch: 2,
            astra_service_key_epoch: 3,
            issuer_epoch: 4,
            active_gateway_identity_epoch: 5,
            gateway_decision_epoch: 6,
            client_identity_generation: 7,
            active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"gateway tls"),
            active_gateway_certificate_fingerprint: Fingerprint::of(b"gateway pq"),
            active_client_tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
            active_client_pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
            client_pq_certificate_fingerprint: Fingerprint::of(b"presented pq"),
            base_state_fingerprint: Fingerprint::of(b"local state"),
        };
        let signature =
            sign_ml_dsa_87(&signer.private, &request.signing_bytes()).expect("signature");
        verify_ml_dsa_87(&signer.public, &request.signing_bytes(), &signature)
            .expect("original request");

        request.base_state_fingerprint = Fingerprint::of(b"another local state");
        assert!(verify_ml_dsa_87(&signer.public, &request.signing_bytes(), &signature).is_err());
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

    /// The service key coordinates an anchor object but does not authorize it:
    /// the object's own `CA-PQ` signatures remain independently mandatory.
    #[test]
    fn the_astra_service_key_can_coordinate_an_anchor_object() {
        let authority = keys();
        let manifest = manifest(&authority, &[ca_object(1)], 1);
        assert!(verify_manifest(&manifest, &authority, 1_100).is_ok());
    }

    /// `CA-PQ` signs transition objects and offline documents, never a
    /// personalized online envelope.
    #[test]
    fn the_ca_pq_manifest_authority_is_reserved_online() {
        let authority = keys();
        let mut manifest = manifest(&authority, &[ca_object(1)], 1);
        manifest.manifest_authority_kind = ManifestAuthority::CaPq;
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

// ---------------------------------------------------------------------------
// The operator ceremony surface (spec §8.2 out of tunnel, §8.5 inside it).
// ---------------------------------------------------------------------------

/// Where an operator operation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningOperationState {
    /// Open, and waiting for the companion's assertions.
    AwaitingOperator,
    /// The assertions arrived and verified.
    ///
    /// # What an approval authorizes, and what still does not act on one
    ///
    /// A campaign covering **client leaves** is applied: when a covered peer
    /// sends its rotation request, `astra::renewal::open` finds this
    /// operation through `SigningOperationStore::approved_for_client`, opens
    /// an operation already approved, and issues without asking anyone a
    /// second time. It also overrides the 80 % threshold, which is what a
    /// manual campaign is for.
    ///
    /// # Limite connue : une campagne n'atteint que les clients qui reviennent
    ///
    /// A client leaf cannot be rotated without the client: it holds the private
    /// key and writes the CSR. So a campaign authorizes rotations, and each
    /// peer's own request is what spends that authorization — inside the
    /// campaign window, which `astra campaign open` caps at 300 seconds (§7.6).
    /// A peer that is offline for those five minutes is simply not renewed, and
    /// the operator opens another campaign. Reaching an absent fleet would mean
    /// an authorization that outlives the text its operator read, which is the
    /// property §7.6 exists to hold.
    ///
    /// # What an authority campaign produces instead
    ///
    /// [`super::status::CampaignScope::TrustAuthorities`] makes `CA-PQ` sign, which happens
    /// in the companion and nowhere else. Such a campaign is therefore
    /// approved **and** answered in one deposit: the result carries the signed
    /// transition objects, and the registry stores them before this state is
    /// reached (§0.6). Nothing here reads it as a per-client authorization —
    /// `AstraRotationCampaign::covers_client` refuses an authority campaign
    /// outright rather than approximating one.
    Approved,
}

/// What a caller learns about an operation it holds the identifier of.
///
/// Unsigned, exactly like [`ClientRenewalOperationView`]
/// and for the same reason: everything here that decides anything is
/// re-derivable from the signed `AstraSignerRequest` the companion fetches and
/// verifies under the service key it already pins. A view is how an interface
/// follows progress, never how it concludes that a signature succeeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningOperationView {
    pub operation_id: Id16,
    pub state: SigningOperationState,
    pub scope: CampaignScope,
    pub target_count: usize,
    pub required_credentials: u8,
    /// SHA-256 of the canonical campaign — the value the operator reads on the
    /// companion's screen, and the challenge their key answers.
    pub campaign_fingerprint: Fingerprint,
    pub created_at: u64,
    pub expires_at: u64,
    /// Bearer token for the companion's read route, absent once the operation
    /// no longer accepts one.
    pub signer_request_token: Option<String>,
    /// Bearer token for the encrypted vault, present only for a scope that
    /// makes an anchor sign.
    pub vault_token: Option<String>,
    /// Bearer token for the companion's submission route.
    pub signer_result_token: Option<String>,
}

/// What the companion fetches before it asks for a touch.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorSignerRequestResponse {
    pub signer_request: Box<AstraSignerRequest>,
    /// The campaign itself, because the companion must display its scope, its
    /// target count and their exact current fingerprints — and must recompute
    /// the challenge from it rather than be handed one.
    pub campaign: Box<AstraRotationCampaign>,
    /// The allow-list, signed by `CA-PQ`.
    ///
    /// It travels because whoever runs the ceremony verifies it under the
    /// anchor themselves: an allow-list this service merely asserted would let
    /// a compromised Astra name a credential nobody enrolled.
    pub credential_registry: Box<super::approval::CredentialRegistry>,
    pub webauthn_rp_id: String,
    pub webauthn_origin: String,
}

/// Where a §7.5 recovery stands.
///
/// Four states and no more. A recovery has no approval to wait for *and* a
/// staging to wait for: the same ceremony that approves it signs the staging,
/// because both need `CA-PQ` and `CA-PQ` is opened once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiredRecoveryState {
    /// The request verified. Nothing exists yet but the operator's decision.
    AwaitingOperator,
    /// The gateway persisted the candidate and signed a receipt.
    Staged,
    /// The grant is available; the client may install and commit.
    Granted,
    /// The client's commit reached the gateway. Terminal.
    Committed,
}

/// What the authority answers about one recovery.
///
/// # Why there is no capability token here
///
/// Everything this view carries is public: two expired leaves, a CSR, a public
/// key, a receipt and a grant. The private halves never leave the client, and
/// the one secret in the whole exchange — `CA-PQ` — never leaves the vault.
/// A token would be protecting material that is already published by the
/// objects it appears in, while adding a second thing to keep alive across a
/// ceremony that already has a five-minute window.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiredRecoveryOperationView {
    pub operation_id: Id16,
    pub state: ExpiredRecoveryState,
    pub client_wg_public_key: WireGuardKey,
    pub request_fingerprint: Fingerprint,
    pub created_at: u64,
    pub expires_at: u64,
    /// The request itself, for the companion that has to display it.
    pub request: Option<Box<super::client::ExpiredCertificateRecoveryRequest>>,
    /// Present from [`ExpiredRecoveryState::Staged`]: what the companion signs
    /// the grant against.
    pub receipt: Option<Box<super::client::GatewayCertificateStageReceipt>>,
    /// The leaf the gateway **serves**, read back over the private channel.
    ///
    /// A receipt is signed by what the daemon actually presents, and the
    /// companion has no way to reach the gateway itself. It is not asked to
    /// believe this copy: the leaf names a WireGuard key, and the companion
    /// compares it to the gateway its own domain hand-off pins before it
    /// verifies anything under it.
    pub gateway_pq_certificate: Option<Box<crate::key_negotiation::PqCertificate>>,
    /// Present from [`ExpiredRecoveryState::Granted`]: what the client installs.
    pub grant: Option<Box<super::client::ClientCertificateRotationGrant>>,
}

/// What the companion deposits after the one ceremony (spec §7.5).
///
/// The authorization and the approval travel together because one touch
/// produced both: the assertion answers the recovery challenge, and the PRF
/// output of that same assertion opens the key-slot that signs the
/// authorization. Splitting them would let a caller present an authorization
/// with no operator answer, or an answer with nothing it authorized.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiredRecoveryAuthorizationDeposit {
    pub authorization: Box<super::client::ClientCertificateStageAuthorization>,
    pub evidence: Box<super::approval::ExpiredRecoveryApprovalEvidence>,
}

/// The grant the companion signs once the gateway's receipt exists.
///
/// A recovery staging is `IssuerKind::Master`, so its grant is signed by
/// `CA-PQ` too — the delegated issuer may not vouch for an operation it was
/// never allowed to authorize. That is why the vault stays open across one
/// veth round trip, and why it is one command rather than two.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiredRecoveryGrantDeposit {
    pub grant: Box<super::client::ClientCertificateRotationGrant>,
}

/// The client's commit, relayed because it has no tunnel to send it through.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiredRecoveryCommitDeposit {
    pub commit: Box<super::client::ClientCertificateStageCommit>,
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
