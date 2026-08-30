//! Astra's signed state: status, campaigns, companion requests and the
//! bounded service rollback — spec §2.4, §7.6 and §8.2.
//!
//! # A status is freshness, never validity
//!
//! [`AstraCertificateStatus`] takes its shape from OCSP and stops exactly
//! where OCSP does: it says whether Astra considers a certificate revoked,
//! superseded or due for renewal. It never makes a leaf acceptable outside
//! `not_before..not_after`. Orion verifies the signature and the monotonicity,
//! then computes validity itself — a signed `active` on an expired leaf is a
//! statement about the registry, not a permission.
//!
//! Monotonicity is lexicographic on `(astra_service_key_epoch, status_epoch)`.
//! The key epoch is compared first, which is what stops a compromised service
//! key from publishing `status_epoch = u64::MAX` and freezing its own target
//! forever: as soon as the key transition is persisted, every status under the
//! old epoch is older, whatever number it carries.
//!
//! # A campaign is approved as a whole
//!
//! [`AstraRotationCampaign::fingerprint`] covers the SHA-256 of the complete
//! canonical campaign: every target, its key, its epoch, its generation and
//! its exact current fingerprints. Astra refuses a target added, removed or
//! modified afterwards — the difference between "renew these eleven leaves"
//! and "renew whatever this list holds when I get to it".
//!
//! # What a hardware credential does here, and what it never does
//!
//! It **never signs anything this module verifies.** No field in the whole
//! certificate lifecycle holds anything but an `MlDsa87Signature`, and a
//! YubiKey signs no ML-DSA — it has RSA, P-256/P-384 and Ed25519, nothing
//! post-quantum.
//!
//! Its job is authentication and key derivation: presence plus user
//! verification release a CTAP2 `hmac-secret` output, that output unwraps a
//! key-slot of the authority vault, and the anchors inside it produce the
//! ML-DSA-87 signature. The campaign fingerprint is what `astra-signer`
//! **displays** before asking for the touch, and what the resulting `CA-PQ`
//! signature is bound to.
//!
//! `required_credentials` follows from that: two is not a threshold anyone
//! verifies, it is two key-slots the companion must see opened before it will
//! sign — an operational barrier against a mistake and against one stolen key
//! used with an honest companion (ADR-008 §4, which says so in as many
//! words).

use serde::{Deserialize, Serialize};

use super::{
    encoding::{
        verify_ml_dsa_87, CanonicalBytes, Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature,
        SignedTranscript, TrustDomainId, WireGuardKey,
    },
    CertificateError, CERTIFICATE_FORMAT_VERSION,
};

const STATUS_DOMAIN: &[u8] = b"helios-astra-certificate-status-v5";
const STATUS_QUERY_DOMAIN: &[u8] = b"helios-astra-certificate-status-query-v5";
const CAMPAIGN_APPROVAL_DOMAIN: &[u8] = b"helios-astra-rotation-campaign-approval-v5";
const SIGNER_REQUEST_DOMAIN: &[u8] = b"helios-astra-signer-request-v5";
const SERVICE_ROLLBACK_DOMAIN: &[u8] = b"helios-certificate-service-rollback-authorization-v5";

/// Largest campaign Astra will resolve, sign or apply (spec §8.2).
pub const MAX_CAMPAIGN_TARGETS: usize = 256;

/// Largest number of transition objects one campaign result may carry.
///
/// [`CampaignScope::TrustAuthorities`] names two anchors, so two is the whole
/// domain of the honest case. The ceiling is four to leave room for a scope
/// that later names more, and low enough that a result cannot be a delivery
/// vehicle for an object set nobody read.
pub const MAX_CAMPAIGN_OBJECTS: usize = 4;

/// Which family a certified target belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateKind {
    GatewayTls,
    GatewayPq,
    ClientTls,
    ClientPq,
    CaPq,
    CaTls,
    AstraIssuer,
    AstraServiceKey,
}

impl CertificateKind {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::GatewayTls => 0,
            Self::GatewayPq => 1,
            Self::ClientTls => 2,
            Self::ClientPq => 3,
            Self::CaPq => 4,
            Self::CaTls => 5,
            Self::AstraIssuer => 6,
            Self::AstraServiceKey => 7,
        }
    }
}

/// Lifecycle state of one certified target, as the interfaces display it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Active,
    RenewalDue,
    PendingGrant,
    PendingCommit,
    Staged,
    Published,
    Aborted,
    Overlap,
    Expired,
    Revoked,
    /// A client renewal is open and waiting for an operator's key, before any
    /// candidate certificate exists (spec §8.2).
    ///
    /// It describes the **active** leaf, not a candidate: at this point there
    /// is none. `pending_grant` and `pending_commit` describe the candidate,
    /// once there is one.
    AwaitingOperator,
    /// The mutation that has just made this generation the active one.
    ///
    /// A later status with no new mutation describes it as `active` again, so
    /// this is an event and not a resting state.
    ///
    /// # Limite connue : accepté, jamais émis
    ///
    /// Nothing in this repository produces it. Saying "this generation was
    /// promoted **just now**" needs a per-target record of the last mutation,
    /// and Astra keeps a monotonic status counter rather than a mutation
    /// journal — the counter says a change happened, not which one or when.
    /// It stays in the enum because a decoder must accept every state the
    /// specification's family table names: refusing one the authority is
    /// entitled to send would be refusing a legitimate answer. Emitting it
    /// needs Astra to record the promotion it observes at admission
    /// synchronisation.
    Promoted,
}

impl CertificateStatus {
    /// Byte in the signed transcript.
    ///
    /// The two states added after the first ten are **appended** rather than
    /// slotted into the specification's reading order. The number is what the
    /// ML-DSA-87 signature covers, so renumbering an existing state would
    /// silently change what every already-signed status said.
    const fn domain_byte(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::RenewalDue => 1,
            Self::PendingGrant => 2,
            Self::PendingCommit => 3,
            Self::Staged => 4,
            Self::Published => 5,
            Self::Aborted => 6,
            Self::Overlap => 7,
            Self::Expired => 8,
            Self::Revoked => 9,
            Self::AwaitingOperator => 10,
            Self::Promoted => 11,
        }
    }

    /// Whether this state forbids every rotation, recovery and rollback.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked)
    }

    /// Whether a family may be in this state at all (spec §8.2).
    ///
    /// # Why this is a refusal and not a display rule
    ///
    /// The specification is explicit: «il n'existe pas un enum libre commun à
    /// toutes les familles», and «le décodeur **doit** refuser une combinaison
    /// absente de ce tableau». A flat enum lets a signed status say
    /// `astra_issuer: pending_commit` — a sentence with no meaning, which
    /// every consumer would then have to interpret. Interpreting it is how two
    /// interfaces end up disagreeing about what the authority said.
    ///
    /// The subsets follow the shape of each lifecycle. Only a client leaf has
    /// an operator-approved renewal, so only it may be `awaiting_operator`,
    /// `pending_grant` or `pending_commit`. Only the gateway identity has a
    /// staged transition that can be published or aborted. The anchors stage
    /// and overlap but are never published or aborted, because nothing
    /// announces them separately. The delegated issuer has no overlap at all:
    /// it is replaced, not rotated through one.
    pub const fn permitted_for(self, kind: CertificateKind) -> bool {
        match kind {
            CertificateKind::ClientTls | CertificateKind::ClientPq => matches!(
                self,
                Self::Active
                    | Self::RenewalDue
                    | Self::AwaitingOperator
                    | Self::PendingGrant
                    | Self::PendingCommit
                    | Self::Overlap
                    | Self::Promoted
                    | Self::Expired
                    | Self::Revoked
            ),
            CertificateKind::GatewayTls | CertificateKind::GatewayPq => matches!(
                self,
                Self::Active
                    | Self::RenewalDue
                    | Self::Staged
                    | Self::Published
                    | Self::Aborted
                    | Self::Overlap
                    | Self::Promoted
                    | Self::Expired
                    | Self::Revoked
            ),
            CertificateKind::CaPq | CertificateKind::CaTls | CertificateKind::AstraServiceKey => {
                matches!(
                    self,
                    Self::Active
                        | Self::RenewalDue
                        | Self::Staged
                        | Self::Overlap
                        | Self::Promoted
                        | Self::Expired
                        | Self::Revoked
                )
            }
            CertificateKind::AstraIssuer => matches!(
                self,
                Self::Active | Self::RenewalDue | Self::Expired | Self::Revoked
            ),
        }
    }
}

/// Signed freshness statement about one certificate (spec §8.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraCertificateStatus {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub certificate_fingerprint: Fingerprint,
    pub certificate_kind: CertificateKind,
    pub generation: u64,
    pub status: CertificateStatus,
    pub suggested_window_start: u64,
    pub suggested_window_end: u64,
    pub produced_at: u64,
    pub next_update: u64,
    pub status_epoch: u64,
    pub astra_service_key_epoch: u64,
    pub astra_signature: MlDsa87Signature,
}

impl AstraCertificateStatus {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(STATUS_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .fingerprint(&self.certificate_fingerprint)
            .u8(self.certificate_kind.domain_byte())
            .u64(self.generation)
            .u8(self.status.domain_byte())
            .u64(self.suggested_window_start)
            .u64(self.suggested_window_end)
            .u64(self.produced_at)
            .u64(self.next_update)
            .u64(self.status_epoch)
            .u64(self.astra_service_key_epoch);
        bytes.finish_signed()
    }

    /// Ordering key: the service key epoch dominates the status epoch.
    pub fn ordering_key(&self) -> (u64, u64) {
        (self.astra_service_key_epoch, self.status_epoch)
    }

    /// Verifies signature, binding and monotonicity.
    ///
    /// `service_key` must be the one whose epoch this status names — the
    /// caller resolves active or next from its own pinned pair, so a status
    /// cannot select the key that verifies it.
    pub fn verify(
        &self,
        service_key: &MlDsa87PublicKey,
        service_key_epoch: u64,
        trust_domain_id: &TrustDomainId,
        certificate_fingerprint: &Fingerprint,
        last_seen: Option<(u64, u64)>,
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
        // Before the signature, because it costs a match and the signature
        // costs an ML-DSA-87 verification — and because a combination the
        // table does not hold is a sentence with no meaning, whoever signed
        // it. §8.2 makes this a decoder obligation, not a display rule.
        if !self.status.permitted_for(self.certificate_kind) {
            return Err(CertificateError::UnsupportedStatus {
                kind: self.certificate_kind,
                status: self.status,
            });
        }
        if self.astra_service_key_epoch != service_key_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if !self
            .certificate_fingerprint
            .matches(certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("status target"));
        }
        if let Some(previous) = last_seen {
            if self.ordering_key() < previous {
                return Err(CertificateError::GenerationRollback {
                    current: previous.1,
                    proposed: self.status_epoch,
                });
            }
        }
        verify_ml_dsa_87(service_key, &self.signing_bytes(), &self.astra_signature)
    }

    /// Clamps the suggested renewal window to what the client computed itself.
    ///
    /// Astra may bring the window **forward** — an incident campaign — but it
    /// can never push the start past the local `renewal_at`, nor the end past
    /// the expiry. A gateway that could delay renewals could manufacture the
    /// very expiry the planner exists to prevent.
    pub fn clamped_window(&self, local_renewal_at: u64, local_not_after: u64) -> (u64, u64) {
        (
            self.suggested_window_start.min(local_renewal_at),
            self.suggested_window_end.min(local_not_after),
        )
    }
}

/// Bytes an out-of-tunnel status query signs (spec §8.2).
///
/// No status is ever indexable by fingerprint alone: the requester must prove
/// possession of the PQ key of the exact identity it asks about. Knowing a
/// fingerprint seen on the wire therefore reveals neither generation, nor
/// window, nor rotation schedule.
#[allow(clippy::too_many_arguments)]
pub fn status_query_signing_bytes(
    trust_domain_id: &TrustDomainId,
    astra_challenge: &[u8; 32],
    request_id: &Id16,
    gateway_wg_public_key: &WireGuardKey,
    client_wg_public_key: &WireGuardKey,
    certificate_fingerprint: &Fingerprint,
) -> SignedTranscript {
    let mut bytes = CanonicalBytes::new(STATUS_QUERY_DOMAIN);
    bytes
        .id(trust_domain_id)
        .raw(astra_challenge)
        .id(request_id)
        .key(gateway_wg_public_key)
        .key(client_wg_public_key)
        .fingerprint(certificate_fingerprint);
    bytes.finish_signed()
}

/// What a manual campaign covers (spec §7.6).
///
/// The names are the ones the interfaces must show. No short label may
/// conflate [`Self::TrustAuthorities`] with an ordinary renewal: it rotates
/// `CA-PQ`, and it is the one scope that requires two operator credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignScope {
    /// One Orion profile.
    OrionProfile,
    /// Every Helios profile present on one device.
    OrionDevice,
    /// The fleet's client leaves. Rotates no authority.
    FleetLeafs,
    /// Issuer, TLS CA, gateway and client leaves — but not `CA-PQ`.
    FullCertificateChain,
    /// `CA-PQ` and `CA-TLS`. Two operator credentials.
    TrustAuthorities,
    /// Emergency withdrawal of one identity's active leaves (spec §10).
    EmergencyRevocation,
    /// The gateway's own identity: one transition, or its abort (spec §6).
    GatewayIdentity,
    /// Astra's delegated issuer: one bounded delegation (spec §9.5).
    IssuerDelegation,
}

/// Which family of signed objects a scope may produce.
///
/// # Why a family and not a set of booleans
///
/// Every predicate below reads as «may this scope do X». Asked one at a time,
/// they answer independently, and a scope added later inherits whatever the
/// negative form of a question happens to allow — the exact shape that once
/// let a revocation scope through a guard written as «not an authority». A
/// family is total: a new scope cannot be written without naming which
/// objects it authorizes, and every other family refuses it by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignFamily {
    /// Client leaves. The companion signs no trust-update object at all.
    ClientLeaves,
    /// Anchor transitions: `CA-PQ` and the client TLS CA.
    Authorities,
    /// The gateway's own identity, and the abort that cancels it (spec §6).
    GatewayIdentity,
    /// Emergency withdrawal of active leaves (spec §10).
    Revocation,
    /// The bounded delegation Astra issues under (spec §9.5).
    ///
    /// Its own family because the object it authorizes is not a
    /// [`super::transport::TrustUpdateObject`] at all: a delegation is
    /// consumed by the authority that issues under it and verified by the
    /// holders against the anchor they already pin, so it is never
    /// distributed as a trust update. Folding it into any of the three above
    /// would let a campaign for one of them deliver it, or the reverse.
    IssuerDelegation,
}

impl CampaignScope {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::OrionProfile => 0,
            Self::OrionDevice => 1,
            Self::FleetLeafs => 2,
            Self::FullCertificateChain => 3,
            Self::TrustAuthorities => 4,
            Self::EmergencyRevocation => 5,
            Self::GatewayIdentity => 6,
            Self::IssuerDelegation => 7,
        }
    }

    /// The one family of objects this scope authorizes.
    pub const fn family(self) -> CampaignFamily {
        match self {
            Self::OrionProfile
            | Self::OrionDevice
            | Self::FleetLeafs
            | Self::FullCertificateChain => CampaignFamily::ClientLeaves,
            Self::TrustAuthorities => CampaignFamily::Authorities,
            Self::EmergencyRevocation => CampaignFamily::Revocation,
            Self::GatewayIdentity => CampaignFamily::GatewayIdentity,
            Self::IssuerDelegation => CampaignFamily::IssuerDelegation,
        }
    }

    /// Operator credentials this scope requires (spec §7.6, ADR-008 §4).
    pub const fn required_credentials(self) -> u8 {
        match self {
            Self::TrustAuthorities => 2,
            _ => 1,
        }
    }

    /// Whether the scope rotates an anchor of the domain.
    pub const fn rotates_authority(self) -> bool {
        matches!(self, Self::TrustAuthorities)
    }

    /// Whether this scope authorizes renewing a client leaf.
    pub const fn authorizes_client_rotation(self) -> bool {
        matches!(
            self,
            Self::OrionProfile | Self::OrionDevice | Self::FleetLeafs | Self::FullCertificateChain
        )
    }

    /// Whether the companion must open the master vault for this scope.
    ///
    /// Not the same question as «does it replace an anchor». A revocation and
    /// a gateway transition are both signed **by** `CA-PQ` without replacing
    /// it, and a single predicate for the two questions would refuse the vault
    /// to a ceremony that cannot proceed without it.
    pub const fn opens_vault(self) -> bool {
        !matches!(self.family(), CampaignFamily::ClientLeaves)
    }

    /// Whether this scope withdraws leaves instead of renewing them.
    pub const fn revokes(self) -> bool {
        matches!(self, Self::EmergencyRevocation)
    }
}

/// One certified object a campaign will act on, pinned to its current state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignTarget {
    pub certificate_kind: CertificateKind,
    pub identity_key: WireGuardKey,
    pub epoch: u64,
    pub generation: u64,
    pub active_tls_certificate_fingerprint: Fingerprint,
    pub active_pq_certificate_fingerprint: Fingerprint,
}

/// A manual rotation campaign, frozen at approval time (spec §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraRotationCampaign {
    pub format_version: u16,
    pub campaign_id: Id16,
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub scope: CampaignScope,
    pub targets: Vec<CampaignTarget>,
    pub reason: String,
    pub requested_by: String,
    pub policy_fingerprint: Fingerprint,
    pub required_credentials: u8,
}

impl AstraRotationCampaign {
    /// The canonical form the companion displays before asking for a touch.
    fn approval_bytes(&self) -> Vec<u8> {
        let mut bytes = CanonicalBytes::new(CAMPAIGN_APPROVAL_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.campaign_id)
            .id(&self.trust_domain_id)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .u64(self.created_at)
            .u64(self.expires_at)
            .u8(self.scope.domain_byte())
            .u64(self.targets.len() as u64);
        for target in &self.targets {
            bytes
                .u8(target.certificate_kind.domain_byte())
                .key(&target.identity_key)
                .u64(target.epoch)
                .u64(target.generation)
                .fingerprint(&target.active_tls_certificate_fingerprint)
                .fingerprint(&target.active_pq_certificate_fingerprint);
        }
        bytes
            .text(&self.reason)
            .text(&self.requested_by)
            .fingerprint(&self.policy_fingerprint)
            .u8(self.required_credentials);
        bytes.finish()
    }

    /// SHA-256 of the canonical campaign — the value the `CA-PQ` signature is
    /// bound to, and the one an operator reads on the companion's screen.
    ///
    /// Order is part of it: reordering the targets changes the fingerprint, so
    /// an approval cannot be reused for the same set applied differently.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.approval_bytes())
    }

    /// Structural checks, before an operator is asked for anything.
    pub fn validate(&self, now_unix: u64) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.targets.is_empty() {
            return Err(CertificateError::EmptyTransition);
        }
        if self.targets.len() > MAX_CAMPAIGN_TARGETS {
            return Err(CertificateError::TooManyObjects);
        }
        if self.scope.revokes() && self.targets.len() != 1 {
            return Err(CertificateError::CampaignMismatch);
        }
        if self.expires_at <= self.created_at || now_unix >= self.expires_at {
            return Err(CertificateError::InvalidLease);
        }
        // The policy is not advisory: a campaign that asks for fewer
        // credentials than its scope demands is refused rather than upgraded,
        // because the operator approved *this* text.
        if self.required_credentials != self.scope.required_credentials() {
            return Err(CertificateError::InsufficientApprovals {
                required: self.scope.required_credentials(),
                provided: self.required_credentials,
            });
        }
        // One decision per object. Two rows naming the same certificate would
        // make «what did the operator approve for this identity» a question of
        // iteration order, and `covers_client` below answers it by finding a
        // row — the first one it meets would silently win over a second that
        // pins other fingerprints.
        for (index, target) in self.targets.iter().enumerate() {
            if self.targets[..index].iter().any(|earlier| {
                earlier.certificate_kind == target.certificate_kind
                    && earlier.identity_key == target.identity_key
            }) {
                return Err(CertificateError::DuplicateFingerprint);
            }
        }
        Ok(())
    }

    /// The row that authorizes rotating one admitted client's generation.
    ///
    /// # Why the whole current state, and not just the key
    ///
    /// A campaign is frozen at approval: §7.6 makes the operator approve the
    /// targets *and their current fingerprints*. So a row only authorizes the
    /// rotation it described — the same identity one generation later is a
    /// different rotation, and re-using the approval for it would let one
    /// touch renew a peer indefinitely, once per generation, for as long as
    /// nobody noticed.
    ///
    /// A client generation is a TLS leaf and a PQ leaf that rotate together,
    /// so either kind names it and both fingerprints are pinned in both rows.
    /// A scope that rotates an anchor is refused outright: `trust_authorities`
    /// is a two-credential decision about `CA-PQ`, and reading it as a
    /// per-client authorization would spend it on something the operator was
    /// not shown.
    pub fn covers_client(
        &self,
        client_wg_public_key: &WireGuardKey,
        active_generation: u64,
        active_tls_certificate_fingerprint: &Fingerprint,
        active_pq_certificate_fingerprint: &Fingerprint,
    ) -> Result<(), CertificateError> {
        if !self.scope.authorizes_client_rotation() {
            return Err(CertificateError::IssuerScopeViolation(
                "this campaign does not authorize a client rotation",
            ));
        }
        let covered = self.targets.iter().any(|target| {
            matches!(
                target.certificate_kind,
                CertificateKind::ClientTls | CertificateKind::ClientPq
            ) && target.identity_key == *client_wg_public_key
                && target.generation == active_generation
                && target
                    .active_tls_certificate_fingerprint
                    .matches(active_tls_certificate_fingerprint)
                && target
                    .active_pq_certificate_fingerprint
                    .matches(active_pq_certificate_fingerprint)
        });
        if covered {
            Ok(())
        } else {
            Err(CertificateError::CampaignMismatch)
        }
    }

    /// Whether this campaign authorized one anchor transition (spec §0.6).
    ///
    /// The mirror of [`Self::covers_client`], and its opposite in both
    /// directions: only a scope that rotates an anchor may produce one of
    /// these, and the two object kinds accepted are exactly the two anchors
    /// [`CampaignScope::TrustAuthorities`] names — `CA-PQ` and `CA-TLS`.
    /// Anything else is refused rather than stored: an object nobody was shown
    /// would be an object the operator's touch did not approve.
    ///
    /// What is compared is the **outgoing** state, target by target, exactly
    /// as `covers_client` compares a client's. A transition leaving another
    /// epoch, or another anchor, is not the one the campaign named — even when
    /// its own signatures verify, because a valid object produced for a
    /// different starting point walks the domain somewhere nobody approved.
    pub fn covers_authority_object(
        &self,
        object: &super::transport::TrustUpdateObject,
    ) -> Result<(), CertificateError> {
        use super::transport::TrustUpdateObject;

        if !self.scope.rotates_authority() {
            return Err(CertificateError::IssuerScopeViolation(
                "only an authority campaign produces a transition object",
            ));
        }
        let (kind, trust_domain_id, epoch, current_fingerprint) = match object {
            TrustUpdateObject::CaTransition(transition) => (
                CertificateKind::CaPq,
                transition.trust_domain_id,
                transition.current_ca_epoch,
                transition.current_ca_fingerprint,
            ),
            TrustUpdateObject::ClientTlsCaTransition(transition) => (
                CertificateKind::CaTls,
                transition.trust_domain_id,
                transition.current_ca_tls_epoch,
                transition.active_client_tls_ca_fingerprint,
            ),
            _ => {
                return Err(CertificateError::IssuerScopeViolation(
                    "this object is not an anchor transition",
                ))
            }
        };
        if trust_domain_id != self.trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        let covered = self.targets.iter().any(|target| {
            target.certificate_kind == kind
                && target.identity_key == self.gateway_wg_public_key
                && target.epoch == epoch
                && target
                    .active_pq_certificate_fingerprint
                    .matches(&current_fingerprint)
        });
        if covered {
            Ok(())
        } else {
            Err(CertificateError::CampaignMismatch)
        }
    }

    /// Verifies that an emergency revocation names the exact identity state
    /// frozen into this campaign.
    pub fn covers_revocation(
        &self,
        revocation: &super::revocation::EmergencyCertificateRevocation,
    ) -> Result<(), CertificateError> {
        use super::revocation::RevocationScope;

        if !self.scope.revokes() {
            return Err(CertificateError::IssuerScopeViolation(
                "only a revocation campaign produces a revocation",
            ));
        }
        if revocation.trust_domain_id != self.trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        let (tls_kind, pq_kind) = match revocation.scope {
            RevocationScope::Gateway => (CertificateKind::GatewayTls, CertificateKind::GatewayPq),
            RevocationScope::Client => (CertificateKind::ClientTls, CertificateKind::ClientPq),
        };
        let covered = self.targets.iter().any(|target| {
            (target.certificate_kind == tls_kind || target.certificate_kind == pq_kind)
                && target.identity_key == revocation.identity_key
                && target
                    .epoch
                    .checked_add(1)
                    .is_some_and(|next| next == revocation.revocation_epoch)
                && revocation
                    .revoked_tls_fingerprint
                    .is_none_or(|fingerprint| {
                        target
                            .active_tls_certificate_fingerprint
                            .matches(&fingerprint)
                    })
                && revocation.revoked_pq_fingerprint.is_none_or(|fingerprint| {
                    target
                        .active_pq_certificate_fingerprint
                        .matches(&fingerprint)
                })
        });
        if covered {
            Ok(())
        } else {
            Err(CertificateError::CampaignMismatch)
        }
    }

    /// Verifies that a gateway transition moves the identity this campaign
    /// froze, one decision forward (spec §6.1, §11.1 step 3).
    ///
    /// The row pins the two leaves in service, so the transition is bound to
    /// the state the operator was shown. What the campaign deliberately does
    /// **not** pin is the leaf being installed: it does not exist when the
    /// campaign is opened, and `CA-PQ` is what certifies it. A substituted
    /// next leaf is refused at the gateway instead, which alone knows whether
    /// it holds the matching private half.
    pub fn covers_gateway_transition(
        &self,
        transition: &super::gateway::GatewayIdentityTransition,
    ) -> Result<(), CertificateError> {
        let row = self.gateway_row(
            transition.trust_domain_id,
            &transition.gateway_wg_public_key,
            &transition.server_name,
            // One decision forward: the row names the last decision this
            // domain took, and a transition is the next one.
            transition
                .gateway_identity_epoch
                .checked_sub(1)
                .ok_or(CertificateError::CampaignMismatch)?,
        )?;
        let matches_state = row
            .active_tls_certificate_fingerprint
            .matches(&transition.active_gateway_tls_certificate_fingerprint)
            && row
                .active_pq_certificate_fingerprint
                .matches(&transition.active_gateway_certificate_fingerprint);
        if matches_state {
            Ok(())
        } else {
            Err(CertificateError::CampaignMismatch)
        }
    }

    /// Verifies that an abort cancels a transition of the identity this
    /// campaign froze (spec §6.3).
    ///
    /// # Why the epoch relation is not the transition's
    ///
    /// An abort campaign is opened **after** the transition was staged, when
    /// the decision epoch already *is* the epoch being cancelled. Reusing the
    /// «one forward» rule here would refuse every abort, and accepting either
    /// relation would let one approved row authorise two different decisions.
    ///
    /// # Why the leaves in service are not compared
    ///
    /// An abort names no leaf. It names the exact document it cancels, by
    /// fingerprint, under `CA-PQ` — which is narrower than the pair of active
    /// leaves would be, since a transition is unique where a leaf pair is
    /// shared by every decision taken while it is in service. The fingerprints
    /// on the row are still what the operator reads before the touch.
    pub fn covers_gateway_abort(
        &self,
        abort: &super::gateway::GatewayTransitionAbort,
    ) -> Result<(), CertificateError> {
        self.gateway_row(
            abort.trust_domain_id,
            &abort.gateway_wg_public_key,
            &abort.server_name,
            abort.gateway_identity_epoch,
        )
        .map(|_| ())
    }

    /// The row authorizing a decision about the gateway's own identity.
    fn gateway_row(
        &self,
        trust_domain_id: TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        decision_epoch: u64,
    ) -> Result<&CampaignTarget, CertificateError> {
        if !matches!(self.scope.family(), CampaignFamily::GatewayIdentity) {
            return Err(CertificateError::IssuerScopeViolation(
                "only a gateway-identity campaign decides the gateway identity",
            ));
        }
        if trust_domain_id != self.trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        // Named twice, because a client pins both: an object for another
        // gateway carried under this approval would be a decision the operator
        // never read.
        if gateway_wg_public_key != &self.gateway_wg_public_key || server_name != self.server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        self.targets
            .iter()
            .find(|target| {
                (target.certificate_kind == CertificateKind::GatewayPq
                    || target.certificate_kind == CertificateKind::GatewayTls)
                    && target.identity_key == self.gateway_wg_public_key
                    && target.epoch == decision_epoch
            })
            .ok_or(CertificateError::CampaignMismatch)
    }

    /// The row authorizing one bounded delegation to Astra's issuer (§9.5).
    ///
    /// # Why the keys and not only the epoch
    ///
    /// A delegation request carries no signature of its own: it is a domain
    /// identifier, an epoch, an ML-DSA-87 public key and a PKCS#10 request,
    /// produced beside private halves that never leave the authority's state
    /// volume. Signed on its own, it would authorize whoever handed the
    /// operator a file. So what the campaign pins — and what the operator
    /// therefore reads before the touch — is the **exact material** that will
    /// be certified: substituting either half changes a fingerprint here and
    /// the approval no longer covers the request.
    ///
    /// The epoch must match for the reason
    /// [`crate::certificates::state::AstraIssuerState`] exists: a delegation
    /// reinstalled at a spent epoch would bring a withdrawn intermediate back
    /// under a signature that still verifies.
    pub fn covers_issuer_delegation(
        &self,
        trust_domain_id: TrustDomainId,
        issuer_epoch: u64,
        pq_issuer_public_key_fingerprint: &Fingerprint,
        tls_public_key_info_fingerprint: &Fingerprint,
    ) -> Result<(), CertificateError> {
        if !matches!(self.scope.family(), CampaignFamily::IssuerDelegation) {
            return Err(CertificateError::IssuerScopeViolation(
                "only an issuer-delegation campaign authorizes a delegation",
            ));
        }
        if trust_domain_id != self.trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        let covered = self.targets.iter().any(|target| {
            target.certificate_kind == CertificateKind::AstraIssuer
                && target.identity_key == self.gateway_wg_public_key
                && target.epoch == issuer_epoch
                && target
                    .active_pq_certificate_fingerprint
                    .matches(pq_issuer_public_key_fingerprint)
                && target
                    .active_tls_certificate_fingerprint
                    .matches(tls_public_key_info_fingerprint)
        });
        if covered {
            Ok(())
        } else {
            Err(CertificateError::CampaignMismatch)
        }
    }

    /// Refuses a campaign whose targets moved after approval (spec §7.6).
    pub fn assert_unchanged(
        &self,
        approved_fingerprint: &Fingerprint,
    ) -> Result<(), CertificateError> {
        if !self.fingerprint().matches(approved_fingerprint) {
            return Err(CertificateError::CampaignMismatch);
        }
        Ok(())
    }
}

/// One credential's answer to a campaign challenge, and the row it answered
/// under.
///
/// The binding is named rather than embedded: the verifier holds the credential
/// registry already, signed by `CA-PQ`, and an approval that carried its own
/// row would be an approval that chose the key it is checked against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAssertion {
    pub credential_id: Vec<u8>,
    pub credential_fingerprint: Fingerprint,
    pub assertion: super::webauthn::WebAuthnAssertion,
    pub assertion_fingerprint: Fingerprint,
}

/// What the companion returns for a manual campaign (spec §7.6).
///
/// # Why it lives here and not beside the gesture that produces it
///
/// It is a wire type: the companion writes it, Astra reads it, and the two run
/// on different machines and in different processes. A shape defined in the
/// companion would make Astra depend on the one program in the repository that
/// holds `CA-PQ` in the clear, which is the dependency ADR-008 §4 exists to
/// forbid.
///
/// It carries **no** PRF output, no unlock key and no private key — only
/// assertions, which are public by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignApproval {
    pub campaign_id: Id16,
    pub campaign_fingerprint: Fingerprint,
    pub required_credentials: u8,
    pub approved_at: u64,
    pub approvals: Vec<CredentialAssertion>,
}

impl CampaignApproval {
    /// Everything this document is, as bytes, for idempotency comparison.
    ///
    /// §8.2 makes a replayed result idempotent and any divergence on the same
    /// identifier a conflict, and "identical" has to mean the exact bytes: two
    /// approvals differing only in which credential answered first are two
    /// different decisions by two different people.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        let encoded =
            serde_json::to_vec(self).map_err(|_| CertificateError::InvalidAssertion("encoding"))?;
        Ok(Fingerprint::of(&encoded))
    }

    /// Re-derives every claim against material the verifier already holds.
    ///
    /// Nothing here is taken from the approval: the challenge is recomputed
    /// from the campaign, each credential's public key comes from the registry
    /// row `CA-PQ` signed, and the relying party and origin come from the
    /// domain. An approval that supplied any of those would be an approval of
    /// nothing.
    ///
    /// Distinct credentials are required, and that is the point of a two-key
    /// scope: two touches of one token read as two people and are one.
    pub fn verify(
        &self,
        campaign: &AstraRotationCampaign,
        registry: &super::approval::CredentialRegistry,
        webauthn_rp_id: &str,
        webauthn_origin: &str,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        use super::webauthn::{verify_assertion, AssertionExpectation};

        campaign.validate(now_unix)?;
        if self.campaign_id != campaign.campaign_id {
            return Err(CertificateError::CampaignMismatch);
        }
        // The targets must not have moved since the operator read them.
        campaign.assert_unchanged(&self.campaign_fingerprint)?;
        // The count the *campaign* demands, never the count the approval
        // announces: a document that carried its own threshold would set it.
        let required = usize::from(campaign.required_credentials);
        if self.required_credentials != campaign.required_credentials
            || self.approvals.len() != required
        {
            return Err(CertificateError::InsufficientApprovals {
                required: campaign.required_credentials,
                provided: u8::try_from(self.approvals.len()).unwrap_or(u8::MAX),
            });
        }

        let challenge = campaign.fingerprint();
        for (index, approval) in self.approvals.iter().enumerate() {
            if self.approvals[..index]
                .iter()
                .any(|earlier| earlier.credential_id == approval.credential_id)
            {
                return Err(CertificateError::DuplicateApproval);
            }
            let binding = registry
                .binding(&approval.credential_id)
                .ok_or(CertificateError::UnknownCredential)?;
            if binding.state != super::approval::CredentialState::Active {
                return Err(CertificateError::UnknownCredential);
            }
            if !binding
                .fingerprint()
                .matches(&approval.credential_fingerprint)
            {
                return Err(CertificateError::InvalidAssertion("credential binding"));
            }
            if !approval
                .assertion
                .fingerprint()
                .matches(&approval.assertion_fingerprint)
            {
                return Err(CertificateError::InvalidAssertion("assertion fingerprint"));
            }
            verify_assertion(
                &approval.assertion,
                &binding.credential_public_key,
                &AssertionExpectation {
                    relying_party_id: webauthn_rp_id,
                    origin: webauthn_origin,
                    challenge: &challenge,
                },
            )?;
        }
        Ok(())
    }
}

/// What the companion deposits once a campaign has been approved (spec §0.6).
///
/// # Why the objects travel with the approval and not after it
///
/// §0.6 has the companion open the vault and return the transition objects
/// **once**, bound to the campaign. Delivering them in a second call would
/// leave a window in which Astra holds an approval that authorizes objects it
/// does not have — and no way to tell that state apart from a campaign whose
/// operator walked away. One deposit, one decision: either the whole result
/// verifies, or the campaign is still awaiting its operator.
///
/// # What is *not* here
///
/// No private key, no PRF output, no vault. The objects carry their own
/// `CA-PQ` signatures, produced inside the companion and never reproducible by
/// the online authority — which is precisely why Astra may persist and
/// redistribute them without ever being able to forge one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraSignerResult {
    pub format_version: u16,
    pub approval: Box<CampaignApproval>,
    /// The transition objects this campaign authorized, signed by `CA-PQ`.
    ///
    /// Empty for a campaign that rotates no anchor: a fleet campaign is an
    /// authorization to renew leaves, and the leaves are issued online by the
    /// delegated issuer as each client comes back.
    #[serde(default)]
    pub objects: Vec<super::transport::TrustUpdateObject>,
    /// Credential bindings re-signed under the anchor being installed.
    ///
    /// Present exactly when an object replaces `CA-PQ`. Leaving it out would
    /// hand the domain a successor anchor and a registry of operator
    /// credentials that only the anchor it replaces can verify — every future
    /// approval would then fail, on the one path that repairs anything.
    #[serde(default)]
    pub credential_registry: Option<Box<super::approval::CredentialRegistry>>,
    /// The bounded delegation an issuer campaign authorized (spec §9.5).
    ///
    /// Present exactly when the campaign's family is
    /// [`CampaignFamily::IssuerDelegation`], and absent everywhere else. It
    /// travels beside `objects` rather than inside them because it is not a
    /// trust update: no holder ever receives it, the authority issues under
    /// it, and everyone else verifies it against the anchor they already pin.
    #[serde(default)]
    pub issuer_authorization: Option<Box<super::authority::AstraIssuerAuthorization>>,
}

impl AstraSignerResult {
    /// Everything this document is, as bytes, for the idempotency rule of §8.2.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        let encoded =
            serde_json::to_vec(self).map_err(|_| CertificateError::InvalidAssertion("encoding"))?;
        Ok(Fingerprint::of(&encoded))
    }

    /// Checks the shape of the result against the campaign it answers.
    ///
    /// Shape only: every signature inside is verified by its own object's
    /// `verify`, against anchors the reader holds. What this decides is
    /// narrower and cannot be decided there — that each object belongs to this
    /// campaign, that no object arrives twice, and that a result carrying a
    /// successor anchor carries the credential registry that survives it.
    pub fn validate(&self, campaign: &AstraRotationCampaign) -> Result<(), CertificateError> {
        use super::transport::TrustUpdateObject;

        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        self.approval
            .campaign_fingerprint
            .matches(&campaign.fingerprint())
            .then_some(())
            .ok_or(CertificateError::CampaignMismatch)?;
        if self.objects.len() > MAX_CAMPAIGN_OBJECTS {
            return Err(CertificateError::CampaignMismatch);
        }
        // One decision per ceremony for the two families that decide about a
        // single identity. A batch would make «which of these did the operator
        // approve» a question about ordering.
        if matches!(
            campaign.scope.family(),
            CampaignFamily::Revocation | CampaignFamily::GatewayIdentity
        ) && self.objects.len() != 1
        {
            return Err(CertificateError::CampaignMismatch);
        }
        // Total the other way too: exactly one family delivers a delegation,
        // and it delivers nothing else. Checked before the object loop, so a
        // delegation smuggled beside an anchor transition is refused by the
        // family rather than by whichever arm of the loop happened to run.
        match (campaign.scope.family(), &self.issuer_authorization) {
            (CampaignFamily::IssuerDelegation, Some(authorization)) => {
                if !self.objects.is_empty() || self.credential_registry.is_some() {
                    return Err(CertificateError::IssuerScopeViolation(
                        "an issuer campaign authorizes a delegation and nothing else",
                    ));
                }
                return campaign.covers_issuer_delegation(
                    authorization.trust_domain_id,
                    authorization.issuer_epoch,
                    &Fingerprint::of(authorization.pq_issuer_public_key.as_bytes()),
                    &Fingerprint::of(&super::x509::subject_public_key_info(
                        &authorization.tls_intermediate_certificate,
                    )?),
                );
            }
            (CampaignFamily::IssuerDelegation, None) => {
                return Err(CertificateError::EmptyTransition);
            }
            (_, Some(_)) => {
                return Err(CertificateError::IssuerScopeViolation(
                    "only an issuer campaign delivers a delegation",
                ));
            }
            (_, None) => {}
        }
        if matches!(campaign.scope.family(), CampaignFamily::ClientLeaves) {
            // An ordinary leaf campaign has nothing for the companion to
            // sign. Accepting objects here would let it deliver a trust
            // mutation that the operator was never shown.
            return if self.objects.is_empty() && self.credential_registry.is_none() {
                Ok(())
            } else {
                Err(CertificateError::IssuerScopeViolation(
                    "this campaign authorizes no trust-update object",
                ))
            };
        }
        if self.objects.is_empty() {
            return Err(CertificateError::EmptyTransition);
        }

        let mut seen: Vec<Fingerprint> = Vec::with_capacity(self.objects.len());
        let mut replaces_ca_pq = false;
        for object in &self.objects {
            // Total in both directions: every family names the objects it
            // authorizes, and everything else falls into one refusal. A family
            // added later cannot inherit another's authorization by omission.
            match (campaign.scope.family(), object) {
                (
                    CampaignFamily::Revocation,
                    TrustUpdateObject::CertificateRevocation(revocation),
                ) => campaign.covers_revocation(revocation)?,
                (
                    CampaignFamily::Authorities,
                    TrustUpdateObject::CaTransition(_)
                    | TrustUpdateObject::ClientTlsCaTransition(_),
                ) => campaign.covers_authority_object(object)?,
                (
                    CampaignFamily::GatewayIdentity,
                    TrustUpdateObject::GatewayIdentityTransition(transition),
                ) => campaign.covers_gateway_transition(transition)?,
                (
                    CampaignFamily::GatewayIdentity,
                    TrustUpdateObject::GatewayTransitionAbort(abort),
                ) => campaign.covers_gateway_abort(abort)?,
                _ => {
                    return Err(CertificateError::IssuerScopeViolation(
                        "this object does not belong to the family its campaign approved",
                    ))
                }
            }
            let fingerprint = object.fingerprint()?;
            if seen.iter().any(|earlier| earlier.matches(&fingerprint)) {
                return Err(CertificateError::DuplicateFingerprint);
            }
            seen.push(fingerprint);
            replaces_ca_pq |= matches!(object, TrustUpdateObject::CaTransition(_));
        }
        match (replaces_ca_pq, self.credential_registry.is_some()) {
            (true, true) | (false, false) => Ok(()),
            (true, false) => Err(CertificateError::InvalidCredentialBinding(
                "a CA-PQ transition must carry the registry re-signed under its successor",
            )),
            (false, true) => Err(CertificateError::InvalidCredentialBinding(
                "no object replaces CA-PQ, so nothing re-signs the registry",
            )),
        }
    }
}

/// What Astra hands to the local signing companion (spec §2.4).
///
/// It carries no private material and no vault: only the identifiers the
/// companion needs to fetch, verify and display the operation itself. The
/// interface that launches the companion never sees more than the authority
/// URL and an opaque `operation_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraSignerRequest {
    pub format_version: u16,
    pub operation_id: Id16,
    pub campaign_fingerprint: Fingerprint,
    pub authority_url: String,
    pub encrypted_vault_fingerprint: Fingerprint,
    pub required_credentials: u8,
    pub created_at: u64,
    pub expires_at: u64,
    pub astra_service_key_epoch: u64,
    pub astra_signature: MlDsa87Signature,
}

impl AstraSignerRequest {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(SIGNER_REQUEST_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.operation_id)
            .fingerprint(&self.campaign_fingerprint)
            .text(&self.authority_url)
            .fingerprint(&self.encrypted_vault_fingerprint)
            .u8(self.required_credentials)
            .u64(self.created_at)
            .u64(self.expires_at)
            .u64(self.astra_service_key_epoch);
        bytes.finish_signed()
    }

    /// Verified by the companion under the service key **it already pins**.
    ///
    /// A companion that learned the service key from the request it is about
    /// to trust would authenticate nothing.
    pub fn verify(
        &self,
        service_key: &MlDsa87PublicKey,
        service_key_epoch: u64,
        authority_url: &str,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.astra_service_key_epoch != service_key_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if self.authority_url != authority_url {
            return Err(CertificateError::CampaignMismatch);
        }
        if self.expires_at <= self.created_at || now_unix >= self.expires_at {
            return Err(CertificateError::InvalidLease);
        }
        if self.required_credentials == 0 {
            return Err(CertificateError::InsufficientApprovals {
                required: 1,
                provided: 0,
            });
        }
        verify_ml_dsa_87(service_key, &self.signing_bytes(), &self.astra_signature)
    }
}

/// Temporary selection of the outgoing identity during an overlap (spec §4.4).
///
/// It changes no counter and removes no slot. It is refused outside an
/// existing overlap, and it expires at `not_after` at the latest — a rollback
/// cannot outlive the transition it rolls back within.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateServiceRollbackAuthorization {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    /// Transition whose overlap this rollback lives inside.
    pub transition_fingerprint: Fingerprint,
    /// Fingerprint of the slot to serve — always the outgoing one.
    pub selected_certificate_fingerprint: Fingerprint,
    pub campaign_fingerprint: Fingerprint,
    pub expires_at: u64,
    pub ca_signature: MlDsa87Signature,
}

impl CertificateServiceRollbackAuthorization {
    /// Everything this document is, as bytes.
    ///
    /// The gateway stores it so that carrying the same authorization twice is
    /// a replay, while a different one — a later expiry, another slot — is a
    /// second decision rather than a silent extension of the first.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        let encoded =
            serde_json::to_vec(self).map_err(|_| CertificateError::InvalidAssertion("encoding"))?;
        Ok(Fingerprint::of(&encoded))
    }

    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(SERVICE_ROLLBACK_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .fingerprint(&self.transition_fingerprint)
            .fingerprint(&self.selected_certificate_fingerprint)
            .fingerprint(&self.campaign_fingerprint)
            .u64(self.expires_at);
        bytes.finish_signed()
    }

    /// Verifies the authorization against the overlap it claims to be inside.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        transition_fingerprint: &Fingerprint,
        active_fingerprint: &Fingerprint,
        overlap_not_after: u64,
        now_unix: u64,
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
        if self.ca_epoch != ca_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key || self.server_name != server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if !self.transition_fingerprint.matches(transition_fingerprint) {
            return Err(CertificateError::FingerprintMismatch("transition"));
        }
        // Only the outgoing slot can be selected. A rollback that could name
        // an arbitrary fingerprint would be a downgrade primitive.
        if !self
            .selected_certificate_fingerprint
            .matches(active_fingerprint)
        {
            return Err(CertificateError::RollbackUnavailable);
        }
        if self.expires_at > overlap_not_after || now_unix >= self.expires_at {
            return Err(CertificateError::RollbackUnavailable);
        }
        verify_ml_dsa_87(ca_pq, &self.signing_bytes(), &self.ca_signature)
    }
}

/// Signing side of the Astra objects (see `authority::signing`).
#[cfg(feature = "key-negotiation-signing")]
mod signing {
    use super::*;
    use crate::certificates::encoding::sign_ml_dsa_87;

    impl AstraCertificateStatus {
        pub fn sign(mut self, service_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.astra_signature = sign_ml_dsa_87(service_private_key, &self.signing_bytes())?;
            Ok(self)
        }
    }

    impl AstraSignerRequest {
        pub fn sign(mut self, service_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.astra_signature = sign_ml_dsa_87(service_private_key, &self.signing_bytes())?;
            Ok(self)
        }
    }

    impl CertificateServiceRollbackAuthorization {
        pub fn sign(mut self, ca_pq_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.ca_signature = sign_ml_dsa_87(ca_pq_private_key, &self.signing_bytes())?;
            Ok(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every state the specification names, so a new one cannot be added to
    /// the enum and quietly left out of the family table.
    const EVERY_STATUS: [CertificateStatus; 12] = [
        CertificateStatus::Active,
        CertificateStatus::RenewalDue,
        CertificateStatus::AwaitingOperator,
        CertificateStatus::PendingGrant,
        CertificateStatus::PendingCommit,
        CertificateStatus::Staged,
        CertificateStatus::Published,
        CertificateStatus::Aborted,
        CertificateStatus::Overlap,
        CertificateStatus::Promoted,
        CertificateStatus::Expired,
        CertificateStatus::Revoked,
    ];

    fn domain() -> TrustDomainId {
        TrustDomainId::new([1; 16]).expect("domain")
    }

    fn target(seed: u8) -> CampaignTarget {
        CampaignTarget {
            certificate_kind: CertificateKind::ClientPq,
            identity_key: WireGuardKey::from_bytes([seed; 32]),
            epoch: 1,
            generation: 3,
            active_tls_certificate_fingerprint: Fingerprint::of(&[seed, 1]),
            active_pq_certificate_fingerprint: Fingerprint::of(&[seed, 2]),
        }
    }

    fn campaign(scope: CampaignScope, targets: Vec<CampaignTarget>) -> AstraRotationCampaign {
        AstraRotationCampaign {
            format_version: CERTIFICATE_FORMAT_VERSION,
            campaign_id: Id16::new([7; 16]).expect("id"),
            trust_domain_id: domain(),
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            server_name: "gateway.example".into(),
            created_at: 1_000,
            expires_at: 1_300,
            scope,
            targets,
            reason: "rotation trimestrielle".into(),
            requested_by: "operator".into(),
            policy_fingerprint: Fingerprint::of(b"policy"),
            required_credentials: scope.required_credentials(),
        }
    }

    /// The §0.6 half: what a campaign that touches an anchor may produce.
    ///
    /// Gated on the signing feature only because a valid ML-DSA-87 public key
    /// has to be generated to build a transition at all; everything asserted
    /// below is pure decision logic that a verifier-only build also runs.
    #[cfg(feature = "key-negotiation-signing")]
    mod authority_objects {
        use super::*;
        use crate::certificates::encoding::generate_ml_dsa_87_keypair;

        /// The anchor as a campaign names it: the gateway key, the outgoing epoch
        /// and the outgoing fingerprint, exactly as `astra campaign open` resolves
        /// them.
        fn anchor_target(
            kind: CertificateKind,
            epoch: u64,
            current: Fingerprint,
        ) -> CampaignTarget {
            CampaignTarget {
                certificate_kind: kind,
                identity_key: WireGuardKey::from_bytes([2; 32]),
                epoch,
                generation: epoch,
                active_tls_certificate_fingerprint: current,
                active_pq_certificate_fingerprint: current,
            }
        }

        fn ca_transition(
            current_epoch: u64,
            current: Fingerprint,
        ) -> crate::certificates::transport::TrustUpdateObject {
            use crate::certificates::authority::CaTransition;
            use crate::certificates::window::TransitionWindow;

            crate::certificates::transport::TrustUpdateObject::CaTransition(Box::new(
                CaTransition {
                    format_version: CERTIFICATE_FORMAT_VERSION,
                    trust_domain_id: domain(),
                    current_ca_epoch: current_epoch,
                    next_ca_epoch: current_epoch + 1,
                    current_ca_fingerprint: current,
                    next_ca_public_key: generate_ml_dsa_87_keypair().expect("keygen").1,
                    next_ca_fingerprint: Fingerprint::of(b"next anchor"),
                    window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
                    current_ca_signature: MlDsa87Signature::placeholder(),
                    next_ca_signature: MlDsa87Signature::placeholder(),
                },
            ))
        }

        fn registry() -> Box<crate::certificates::approval::CredentialRegistry> {
            Box::new(crate::certificates::approval::CredentialRegistry {
                trust_domain_id: domain(),
                gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                ca_epoch: 2,
                credential_registry_epoch: 2,
                bindings: Vec::new(),
            })
        }

        fn signer_result(
            campaign: &AstraRotationCampaign,
            objects: Vec<crate::certificates::transport::TrustUpdateObject>,
            credential_registry: Option<Box<crate::certificates::approval::CredentialRegistry>>,
        ) -> AstraSignerResult {
            AstraSignerResult {
                format_version: CERTIFICATE_FORMAT_VERSION,
                approval: Box::new(CampaignApproval {
                    campaign_id: campaign.campaign_id,
                    campaign_fingerprint: campaign.fingerprint(),
                    required_credentials: campaign.required_credentials,
                    approved_at: 1_100,
                    approvals: Vec::new(),
                }),
                objects,
                credential_registry,
                issuer_authorization: None,
            }
        }

        /// A delegation, and the exact material it will certify (spec §9.5).
        mod issuer_delegation {
            use super::*;
            use crate::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};
            use crate::certificates::encoding::{DerCertificate, MlDsa87Signature};

            /// A self-signed certificate, standing in for the intermediate the
            /// companion issues. What matters below is its public key: it is
            /// the value the campaign pinned before the touch.
            fn intermediate() -> DerCertificate {
                let key = rcgen::KeyPair::generate().expect("key");
                let mut params =
                    rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
                DerCertificate::new(
                    params
                        .self_signed(&key)
                        .expect("intermediate")
                        .der()
                        .to_vec(),
                )
                .expect("der")
            }

            fn pq_key() -> crate::certificates::encoding::MlDsa87PublicKey {
                let (_, public_key) = crate::ml_dsa::generate_keypair().expect("keypair");
                crate::certificates::encoding::MlDsa87PublicKey::new(public_key).expect("key")
            }

            fn authorization(
                issuer_epoch: u64,
                pq_issuer_public_key: crate::certificates::encoding::MlDsa87PublicKey,
                tls_intermediate_certificate: DerCertificate,
            ) -> Box<AstraIssuerAuthorization> {
                Box::new(AstraIssuerAuthorization {
                    format_version: CERTIFICATE_FORMAT_VERSION,
                    trust_domain_id: domain(),
                    ca_epoch: 1,
                    ca_tls_epoch: 1,
                    gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                    server_name: "gateway.example".into(),
                    issuer_epoch,
                    pq_issuer_public_key,
                    tls_intermediate_certificate,
                    allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
                    maximum_leaf_lifetime_secs: 90 * 86_400,
                    policy_fingerprint: Fingerprint::of(b"policy"),
                    not_before: 1_000,
                    not_after: 2_000,
                    ca_pq_signature: MlDsa87Signature::placeholder(),
                })
            }

            fn issuer_campaign(
                issuer_epoch: u64,
                pq: &crate::certificates::encoding::MlDsa87PublicKey,
                intermediate: &DerCertificate,
            ) -> AstraRotationCampaign {
                super::super::campaign(
                    CampaignScope::IssuerDelegation,
                    vec![CampaignTarget {
                        certificate_kind: CertificateKind::AstraIssuer,
                        identity_key: WireGuardKey::from_bytes([2; 32]),
                        epoch: issuer_epoch,
                        generation: 0,
                        active_tls_certificate_fingerprint: Fingerprint::of(
                            &crate::certificates::x509::subject_public_key_info(intermediate)
                                .expect("spki"),
                        ),
                        active_pq_certificate_fingerprint: Fingerprint::of(pq.as_bytes()),
                    }],
                )
            }

            fn result(
                campaign: &AstraRotationCampaign,
                authorization: Option<Box<AstraIssuerAuthorization>>,
            ) -> AstraSignerResult {
                let mut result = signer_result(campaign, Vec::new(), None);
                result.issuer_authorization = authorization;
                result
            }

            /// The delegation request carries no signature of its own, so the
            /// campaign is what binds it. Either half substituted, and the
            /// approval no longer covers what would be certified.
            #[test]
            fn a_delegation_is_covered_by_the_exact_material_the_operator_read() {
                let pq = pq_key();
                let tls = intermediate();
                let campaign = issuer_campaign(2, &pq, &tls);

                result(&campaign, Some(authorization(2, pq.clone(), tls.clone())))
                    .validate(&campaign)
                    .expect("the delegation the campaign named");

                // Another PQ issuer key, under the same touch.
                assert!(matches!(
                    result(&campaign, Some(authorization(2, pq_key(), tls.clone())))
                        .validate(&campaign),
                    Err(CertificateError::CampaignMismatch)
                ));
                // Another intermediate, therefore another certified key.
                assert!(matches!(
                    result(
                        &campaign,
                        Some(authorization(2, pq.clone(), intermediate()))
                    )
                    .validate(&campaign),
                    Err(CertificateError::CampaignMismatch)
                ));
                // A spent epoch: the walk-back `install_issuer` refuses, caught
                // before a signature is ever produced for it.
                assert!(matches!(
                    result(&campaign, Some(authorization(1, pq, tls))).validate(&campaign),
                    Err(CertificateError::CampaignMismatch)
                ));
            }

            /// Total in both directions, like every other family.
            #[test]
            fn a_delegation_belongs_to_its_family_and_to_no_other() {
                let pq = pq_key();
                let tls = intermediate();
                let campaign = issuer_campaign(2, &pq, &tls);

                // An issuer campaign with nothing to install is not a
                // ceremony that succeeded quietly.
                assert!(matches!(
                    result(&campaign, None).validate(&campaign),
                    Err(CertificateError::EmptyTransition)
                ));

                // No other family delivers one.
                let fleet = super::super::campaign(CampaignScope::FleetLeafs, vec![target(3)]);
                assert!(matches!(
                    result(&fleet, Some(authorization(2, pq.clone(), tls.clone())))
                        .validate(&fleet),
                    Err(CertificateError::IssuerScopeViolation(_))
                ));

                // And an issuer campaign delivers nothing else: no trust
                // update, and no re-signed credential registry.
                let mut smuggled = result(&campaign, Some(authorization(2, pq, tls)));
                smuggled.credential_registry = Some(registry());
                assert!(matches!(
                    smuggled.validate(&campaign),
                    Err(CertificateError::IssuerScopeViolation(_))
                ));
            }

            /// One credential, and the vault opens: the companion issues the
            /// intermediate under `CA-TLS` and signs under `CA-PQ`. It rotates
            /// no anchor, so it is not the two-credential decision of §0.2.
            #[test]
            fn an_issuer_campaign_is_a_one_credential_vault_ceremony() {
                let scope = CampaignScope::IssuerDelegation;
                assert_eq!(scope.required_credentials(), 1);
                assert!(scope.opens_vault());
                assert!(!scope.rotates_authority());
                assert!(!scope.authorizes_client_rotation());
                assert!(!scope.revokes());
            }
        }

        /// The whole point of §0.6: an object the operator's campaign named, and
        /// nothing else, is what the companion may deposit.
        #[test]
        fn an_authority_campaign_covers_the_anchor_state_its_operator_read() {
            let current = Fingerprint::of(b"anchor of epoch 1");
            let campaign = campaign(
                CampaignScope::TrustAuthorities,
                vec![anchor_target(CertificateKind::CaPq, 1, current)],
            );
            assert!(campaign
                .covers_authority_object(&ca_transition(1, current))
                .is_ok());

            // A transition that leaves another epoch verifies under its own
            // anchor and still walks the domain somewhere nobody approved.
            assert!(matches!(
                campaign.covers_authority_object(&ca_transition(2, current)),
                Err(CertificateError::CampaignMismatch)
            ));
            // Same epoch, another outgoing anchor: not the object that was read.
            assert!(matches!(
                campaign.covers_authority_object(&ca_transition(1, Fingerprint::of(b"elsewhere"))),
                Err(CertificateError::CampaignMismatch)
            ));
        }

        /// A one-credential campaign must never be a delivery vehicle for an
        /// anchor transition — that is the whole difference between the two
        /// families of §7.2.
        #[test]
        fn a_fleet_campaign_produces_no_transition_object() {
            let campaign = campaign(CampaignScope::FleetLeafs, vec![target(3)]);
            assert!(matches!(
                campaign.covers_authority_object(&ca_transition(1, Fingerprint::of(b"anchor"))),
                Err(CertificateError::IssuerScopeViolation(_))
            ));

            let result = signer_result(&campaign, Vec::new(), None);
            assert!(result.validate(&campaign).is_ok());

            let smuggled = signer_result(
                &campaign,
                vec![ca_transition(1, Fingerprint::of(b"anchor"))],
                None,
            );
            assert!(matches!(
                smuggled.validate(&campaign),
                Err(CertificateError::IssuerScopeViolation(_))
            ));
        }

        /// A successor anchor and a credential registry only the anchor it
        /// replaces can verify would leave the domain unable to approve anything
        /// again — on the one path that repairs a domain.
        #[test]
        fn a_ca_pq_transition_carries_the_registry_that_survives_it() {
            let current = Fingerprint::of(b"anchor of epoch 1");
            let campaign = campaign(
                CampaignScope::TrustAuthorities,
                vec![anchor_target(CertificateKind::CaPq, 1, current)],
            );

            let complete =
                signer_result(&campaign, vec![ca_transition(1, current)], Some(registry()));
            assert!(complete.validate(&campaign).is_ok());

            let orphaned = signer_result(&campaign, vec![ca_transition(1, current)], None);
            assert!(matches!(
                orphaned.validate(&campaign),
                Err(CertificateError::InvalidCredentialBinding(_))
            ));
        }

        /// An empty authority result is not «nothing to do»: the operator touched
        /// their key for a text that named an anchor, and no object came back.
        #[test]
        fn an_authority_campaign_with_no_object_is_refused() {
            let current = Fingerprint::of(b"anchor of epoch 1");
            let campaign = campaign(
                CampaignScope::TrustAuthorities,
                vec![anchor_target(CertificateKind::CaPq, 1, current)],
            );
            assert!(matches!(
                signer_result(&campaign, Vec::new(), None).validate(&campaign),
                Err(CertificateError::EmptyTransition)
            ));
        }

        /// Two rows naming one object would make «what did the operator approve»
        /// a question of iteration order, and the ceiling stops a result from
        /// being a bulk channel.
        #[test]
        fn a_result_names_each_object_once_and_stays_under_the_ceiling() {
            let current = Fingerprint::of(b"anchor of epoch 1");
            let campaign = campaign(
                CampaignScope::TrustAuthorities,
                vec![anchor_target(CertificateKind::CaPq, 1, current)],
            );
            // The same object twice, not two objects that merely look alike:
            // each call draws a fresh successor key, and two successors are
            // two decisions rather than one repeated.
            let object = ca_transition(1, current);
            let twice = signer_result(
                &campaign,
                vec![object.clone(), object.clone()],
                Some(registry()),
            );
            assert!(matches!(
                twice.validate(&campaign),
                Err(CertificateError::DuplicateFingerprint)
            ));

            let flood = signer_result(
                &campaign,
                (0..=MAX_CAMPAIGN_OBJECTS).map(|_| object.clone()).collect(),
                Some(registry()),
            );
            assert!(matches!(
                flood.validate(&campaign),
                Err(CertificateError::CampaignMismatch)
            ));
        }

        /// The result answers the campaign it was fetched for, and Astra compares
        /// that before reading a single object.
        #[test]
        fn a_result_answering_another_campaign_is_refused() {
            let current = Fingerprint::of(b"anchor of epoch 1");
            let campaign = campaign(
                CampaignScope::TrustAuthorities,
                vec![anchor_target(CertificateKind::CaPq, 1, current)],
            );
            let mut elsewhere = campaign.clone();
            elsewhere.reason = "un autre texte".into();
            let result = signer_result(
                &elsewhere,
                vec![ca_transition(1, current)],
                Some(registry()),
            );
            assert!(matches!(
                result.validate(&campaign),
                Err(CertificateError::CampaignMismatch)
            ));
        }

        fn gateway_target(epoch: u64, tls: Fingerprint, pq: Fingerprint) -> CampaignTarget {
            CampaignTarget {
                certificate_kind: CertificateKind::GatewayPq,
                identity_key: WireGuardKey::from_bytes([2; 32]),
                epoch,
                generation: epoch,
                active_tls_certificate_fingerprint: tls,
                active_pq_certificate_fingerprint: pq,
            }
        }

        fn gateway_transition(
            epoch: u64,
            tls: Fingerprint,
            pq: Fingerprint,
        ) -> crate::certificates::transport::TrustUpdateObject {
            use crate::certificates::authority::RotationReason;
            use crate::certificates::gateway::GatewayIdentityTransition;
            use crate::certificates::window::TransitionWindow;

            crate::certificates::transport::TrustUpdateObject::GatewayIdentityTransition(Box::new(
                GatewayIdentityTransition {
                    format_version: CERTIFICATE_FORMAT_VERSION,
                    protocol_version: crate::certificates::CERTIFICATE_PROTOCOL_VERSION,
                    trust_domain_id: domain(),
                    ca_epoch: 1,
                    gateway_identity_epoch: epoch,
                    gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                    server_name: "gateway.example".into(),
                    active_gateway_tls_certificate_fingerprint: tls,
                    next_gateway_tls_certificate: None,
                    active_gateway_certificate_fingerprint: pq,
                    next_gateway_certificate: None,
                    window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
                    reason: RotationReason::Scheduled,
                    ca_signature: MlDsa87Signature::placeholder(),
                },
            ))
        }

        fn gateway_abort(epoch: u64) -> crate::certificates::transport::TrustUpdateObject {
            use crate::certificates::gateway::{AbortReason, GatewayTransitionAbort};

            crate::certificates::transport::TrustUpdateObject::GatewayTransitionAbort(Box::new(
                GatewayTransitionAbort {
                    format_version: CERTIFICATE_FORMAT_VERSION,
                    protocol_version: crate::certificates::CERTIFICATE_PROTOCOL_VERSION,
                    trust_domain_id: domain(),
                    ca_epoch: 1,
                    gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                    server_name: "gateway.example".into(),
                    gateway_identity_epoch: epoch,
                    gateway_transition_fingerprint: Fingerprint::of(b"the staged transition"),
                    aborted_at: 1_500,
                    reason: AbortReason::OperatorCancelled,
                    campaign_fingerprint: Fingerprint::of(b"campaign"),
                    ca_signature: MlDsa87Signature::placeholder(),
                },
            ))
        }

        /// §11.1 step 3: the campaign freezes the identity in service, and the
        /// transition it authorizes is the next decision on that exact state.
        #[test]
        fn a_gateway_campaign_covers_the_identity_state_its_operator_read() {
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let campaign = campaign(
                CampaignScope::GatewayIdentity,
                vec![gateway_target(4, tls, pq)],
            );

            let result = signer_result(&campaign, vec![gateway_transition(5, tls, pq)], None);
            result.validate(&campaign).expect("the approved decision");

            // Two decisions forward: an epoch nobody was shown.
            let skipped = signer_result(&campaign, vec![gateway_transition(6, tls, pq)], None);
            assert!(matches!(
                skipped.validate(&campaign),
                Err(CertificateError::CampaignMismatch)
            ));
            // The same epoch over another leaf in service: a decision taken
            // against a state the operator never read.
            let elsewhere = signer_result(
                &campaign,
                vec![gateway_transition(5, tls, Fingerprint::of(b"another leaf"))],
                None,
            );
            assert!(matches!(
                elsewhere.validate(&campaign),
                Err(CertificateError::CampaignMismatch)
            ));
        }

        /// The asymmetry that would silently refuse every abort: a transition
        /// is one decision forward, an abort is *at* the decision it cancels.
        #[test]
        fn an_abort_is_covered_at_the_epoch_it_cancels() {
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let campaign = campaign(
                CampaignScope::GatewayIdentity,
                vec![gateway_target(5, tls, pq)],
            );

            let result = signer_result(&campaign, vec![gateway_abort(5)], None);
            result.validate(&campaign).expect("the staged epoch");

            let forward = signer_result(&campaign, vec![gateway_abort(6)], None);
            assert!(matches!(
                forward.validate(&campaign),
                Err(CertificateError::CampaignMismatch)
            ));
        }

        /// Four families, and each refuses the other three.
        #[test]
        fn a_gateway_decision_belongs_to_no_other_family() {
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let transition = gateway_transition(5, tls, pq);

            for scope in [
                CampaignScope::TrustAuthorities,
                CampaignScope::EmergencyRevocation,
                CampaignScope::FleetLeafs,
            ] {
                let campaign = campaign(scope, vec![gateway_target(4, tls, pq)]);
                let smuggled = signer_result(&campaign, vec![transition.clone()], None);
                assert!(
                    matches!(
                        smuggled.validate(&campaign),
                        Err(CertificateError::IssuerScopeViolation(_))
                    ),
                    "{scope:?} accepted a gateway transition"
                );
            }

            // And the reverse: a gateway campaign is not a delivery vehicle
            // for an anchor rotation.
            let campaign = campaign(
                CampaignScope::GatewayIdentity,
                vec![gateway_target(4, tls, pq)],
            );
            let anchor = signer_result(&campaign, vec![ca_transition(1, tls)], Some(registry()));
            assert!(matches!(
                anchor.validate(&campaign),
                Err(CertificateError::IssuerScopeViolation(_))
            ));
        }

        /// One touch, one decision about the identity every client pins.
        #[test]
        fn a_gateway_campaign_carries_exactly_one_decision() {
            let tls = Fingerprint::of(b"gateway tls in service");
            let pq = Fingerprint::of(b"gateway pq in service");
            let campaign = campaign(
                CampaignScope::GatewayIdentity,
                vec![gateway_target(4, tls, pq)],
            );

            let twice = signer_result(
                &campaign,
                vec![
                    gateway_transition(5, tls, pq),
                    gateway_transition(5, tls, pq),
                ],
                None,
            );
            assert!(matches!(
                twice.validate(&campaign),
                Err(CertificateError::CampaignMismatch)
            ));

            let empty = signer_result(&campaign, Vec::new(), None);
            assert!(matches!(
                empty.validate(&campaign),
                Err(CertificateError::CampaignMismatch)
            ));
        }

        /// A gateway renewal is signed by `CA-PQ` without replacing it, so it
        /// opens the vault while rotating no authority at all.
        #[test]
        fn a_gateway_campaign_opens_the_vault_without_rotating_an_anchor() {
            assert!(CampaignScope::GatewayIdentity.opens_vault());
            assert!(!CampaignScope::GatewayIdentity.rotates_authority());
            assert!(!CampaignScope::GatewayIdentity.revokes());
            assert!(!CampaignScope::GatewayIdentity.authorizes_client_rotation());
            assert_eq!(CampaignScope::GatewayIdentity.required_credentials(), 1);
        }
    }

    fn revocation(
        identity_key: WireGuardKey,
        tls: Option<Fingerprint>,
        pq: Option<Fingerprint>,
    ) -> super::super::revocation::EmergencyCertificateRevocation {
        use super::super::revocation::{
            EmergencyCertificateRevocation, RevocationReason, RevocationScope,
        };

        EmergencyCertificateRevocation {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            scope: RevocationScope::Client,
            identity_key,
            server_name: None,
            revocation_epoch: 2,
            revoked_tls_fingerprint: tls,
            revoked_tls_not_after: tls.map(|_| 9_000),
            revoked_pq_fingerprint: pq,
            revoked_pq_not_after: pq.map(|_| 9_000),
            effective_at: 1_100,
            reason: RevocationReason::KeyCompromise,
            replacement_transition_fingerprint: None,
            ca_signature: MlDsa87Signature::placeholder(),
        }
    }

    #[test]
    fn a_revocation_campaign_covers_only_the_identity_state_shown_to_the_operator() {
        let target = target(1);
        let campaign = campaign(CampaignScope::EmergencyRevocation, vec![target.clone()]);
        let decision = revocation(
            target.identity_key,
            Some(target.active_tls_certificate_fingerprint),
            Some(target.active_pq_certificate_fingerprint),
        );
        campaign
            .covers_revocation(&decision)
            .expect("the exact frozen identity");

        let substituted = revocation(
            target.identity_key,
            None,
            Some(Fingerprint::of(b"a leaf the operator was not shown")),
        );
        assert!(matches!(
            campaign.covers_revocation(&substituted),
            Err(CertificateError::CampaignMismatch)
        ));
    }

    #[test]
    fn a_revocation_campaign_neither_renews_a_client_nor_carries_an_anchor() {
        let target = target(1);
        let campaign = campaign(CampaignScope::EmergencyRevocation, vec![target.clone()]);
        assert!(campaign
            .covers_client(
                &target.identity_key,
                target.generation,
                &target.active_tls_certificate_fingerprint,
                &target.active_pq_certificate_fingerprint,
            )
            .is_err());
        assert!(campaign
            .covers_authority_object(
                &crate::certificates::transport::TrustUpdateObject::CertificateRevocation(
                    Box::new(revocation(
                        target.identity_key,
                        None,
                        Some(target.active_pq_certificate_fingerprint),
                    )),
                )
            )
            .is_err());
    }

    #[test]
    fn a_revocation_result_carries_exactly_one_revocation_and_no_registry() {
        let target = target(1);
        let campaign = campaign(CampaignScope::EmergencyRevocation, vec![target.clone()]);
        let object = crate::certificates::transport::TrustUpdateObject::CertificateRevocation(
            Box::new(revocation(
                target.identity_key,
                Some(target.active_tls_certificate_fingerprint),
                Some(target.active_pq_certificate_fingerprint),
            )),
        );
        let result = AstraSignerResult {
            format_version: CERTIFICATE_FORMAT_VERSION,
            approval: Box::new(CampaignApproval {
                campaign_id: campaign.campaign_id,
                campaign_fingerprint: campaign.fingerprint(),
                required_credentials: 1,
                approved_at: 1_100,
                approvals: Vec::new(),
            }),
            objects: vec![object.clone()],
            credential_registry: None,
            issuer_authorization: None,
        };
        result.validate(&campaign).expect("one signed decision");

        let mut twice = result.clone();
        twice.objects.push(object);
        assert!(twice.validate(&campaign).is_err());
        let mut with_registry = result;
        with_registry.credential_registry = Some(Box::new(
            crate::certificates::approval::CredentialRegistry {
                trust_domain_id: domain(),
                gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                ca_epoch: 1,
                credential_registry_epoch: 1,
                bindings: Vec::new(),
            },
        ));
        assert!(with_registry.validate(&campaign).is_err());
    }

    /// Rotating the authorities is the one scope that needs two credentials,
    /// and no short label may make it look like an ordinary renewal.
    #[test]
    fn only_a_trust_authority_campaign_requires_two_credentials() {
        assert_eq!(CampaignScope::FleetLeafs.required_credentials(), 1);
        assert_eq!(
            CampaignScope::FullCertificateChain.required_credentials(),
            1
        );
        assert_eq!(CampaignScope::TrustAuthorities.required_credentials(), 2);
        assert!(CampaignScope::TrustAuthorities.rotates_authority());
        assert!(!CampaignScope::FullCertificateChain.rotates_authority());
    }

    #[test]
    fn a_campaign_asking_for_fewer_credentials_than_its_scope_is_refused() {
        let mut campaign = campaign(CampaignScope::TrustAuthorities, vec![target(1)]);
        campaign.required_credentials = 1;
        assert!(matches!(
            campaign.validate(1_100),
            Err(CertificateError::InsufficientApprovals {
                required: 2,
                provided: 1
            })
        ));
    }

    /// Two rows for the same object make «what was approved» an iteration
    /// order, and `covers_client` would answer with whichever it met first.
    #[test]
    fn a_campaign_naming_the_same_object_twice_is_refused() {
        let twice = campaign(CampaignScope::FleetLeafs, vec![target(1), target(1)]);
        assert!(matches!(
            twice.validate(1_100),
            Err(CertificateError::DuplicateFingerprint)
        ));

        // Same identity, other family: two different objects, both allowed.
        let mut tls = target(1);
        tls.certificate_kind = CertificateKind::ClientTls;
        let pair = campaign(CampaignScope::FleetLeafs, vec![target(1), tls]);
        pair.validate(1_100).expect("two families of one identity");
    }

    /// The row authorizes the rotation it described, and no later one.
    #[test]
    fn a_campaign_covers_the_state_its_operator_read_and_no_other() {
        let campaign = campaign(CampaignScope::FleetLeafs, vec![target(1), target(2)]);
        let key = WireGuardKey::from_bytes([1; 32]);
        let tls = Fingerprint::of(&[1, 1]);
        let pq = Fingerprint::of(&[1, 2]);
        campaign
            .covers_client(&key, 3, &tls, &pq)
            .expect("the approved target");

        // The same identity, one generation on: a different rotation, and the
        // touch that approved the first must not authorize it. Without this a
        // single approval renews a peer for as long as nobody looks.
        assert!(matches!(
            campaign.covers_client(&key, 4, &tls, &pq),
            Err(CertificateError::CampaignMismatch)
        ));
        // A leaf that moved under the operator between reading and approving.
        assert!(matches!(
            campaign.covers_client(&key, 3, &Fingerprint::of(b"other"), &pq),
            Err(CertificateError::CampaignMismatch)
        ));
        assert!(matches!(
            campaign.covers_client(&key, 3, &tls, &Fingerprint::of(b"other")),
            Err(CertificateError::CampaignMismatch)
        ));
        // An identity the campaign never named.
        assert!(matches!(
            campaign.covers_client(&WireGuardKey::from_bytes([9; 32]), 3, &tls, &pq),
            Err(CertificateError::CampaignMismatch)
        ));
    }

    /// A generation is a TLS leaf and a PQ leaf together, so either row names
    /// it — both pin both fingerprints.
    #[test]
    fn either_client_family_names_the_generation() {
        let mut tls = target(1);
        tls.certificate_kind = CertificateKind::ClientTls;
        let campaign = campaign(CampaignScope::FleetLeafs, vec![tls]);
        campaign
            .covers_client(
                &WireGuardKey::from_bytes([1; 32]),
                3,
                &Fingerprint::of(&[1, 1]),
                &Fingerprint::of(&[1, 2]),
            )
            .expect("a TLS row names the same generation");
    }

    /// A gateway row is not a client row, whatever its fingerprints say.
    #[test]
    fn a_gateway_target_does_not_authorize_a_client_rotation() {
        let mut gateway = target(1);
        gateway.certificate_kind = CertificateKind::GatewayPq;
        let campaign = campaign(CampaignScope::FleetLeafs, vec![gateway]);
        assert!(matches!(
            campaign.covers_client(
                &WireGuardKey::from_bytes([1; 32]),
                3,
                &Fingerprint::of(&[1, 1]),
                &Fingerprint::of(&[1, 2]),
            ),
            Err(CertificateError::CampaignMismatch)
        ));
    }

    /// Two credentials approved a decision about `CA-PQ`. Spending it on a
    /// client leaf would apply a text the operator was never shown.
    #[test]
    fn an_authority_campaign_never_authorizes_a_client_rotation() {
        let campaign = campaign(CampaignScope::TrustAuthorities, vec![target(1)]);
        assert!(matches!(
            campaign.covers_client(
                &WireGuardKey::from_bytes([1; 32]),
                3,
                &Fingerprint::of(&[1, 1]),
                &Fingerprint::of(&[1, 2]),
            ),
            Err(CertificateError::IssuerScopeViolation(_))
        ));
    }

    /// Adding, removing or reordering a target after approval must be visible.
    #[test]
    fn any_change_to_the_target_list_invalidates_the_approval() {
        let campaign = campaign(CampaignScope::FleetLeafs, vec![target(1), target(2)]);
        campaign.validate(1_100).expect("valid campaign");
        let approved = campaign.fingerprint();
        assert!(campaign.assert_unchanged(&approved).is_ok());

        let added = super::AstraRotationCampaign {
            targets: vec![target(1), target(2), target(3)],
            ..campaign.clone()
        };
        assert!(matches!(
            added.assert_unchanged(&approved),
            Err(CertificateError::CampaignMismatch)
        ));

        let reordered = super::AstraRotationCampaign {
            targets: vec![target(2), target(1)],
            ..campaign.clone()
        };
        assert!(matches!(
            reordered.assert_unchanged(&approved),
            Err(CertificateError::CampaignMismatch)
        ));

        let mut modified = campaign.clone();
        modified.targets[0].generation = 4;
        assert!(matches!(
            modified.assert_unchanged(&approved),
            Err(CertificateError::CampaignMismatch)
        ));
    }

    #[test]
    fn an_empty_or_oversized_campaign_is_refused() {
        let empty = campaign(CampaignScope::FleetLeafs, Vec::new());
        assert!(matches!(
            empty.validate(1_100),
            Err(CertificateError::EmptyTransition)
        ));

        let targets = (0..=MAX_CAMPAIGN_TARGETS)
            .map(|index| target((index % 251) as u8))
            .collect();
        let oversized = campaign(CampaignScope::FleetLeafs, targets);
        assert!(matches!(
            oversized.validate(1_100),
            Err(CertificateError::TooManyObjects)
        ));
    }

    /// The service key epoch is compared first, so a compromised key cannot
    /// freeze its target by publishing `status_epoch = u64::MAX`.
    #[test]
    fn a_maximal_status_epoch_under_the_old_key_loses_to_the_next_key() {
        let frozen = (3u64, u64::MAX);
        let successor = (4u64, 1u64);
        assert!(successor > frozen);
    }

    #[test]
    fn a_status_window_can_be_brought_forward_but_never_pushed_back() {
        let status = AstraCertificateStatus {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            certificate_fingerprint: Fingerprint::of(b"leaf"),
            certificate_kind: CertificateKind::ClientPq,
            generation: 3,
            status: CertificateStatus::RenewalDue,
            suggested_window_start: 9_000,
            suggested_window_end: 20_000,
            produced_at: 1_000,
            next_update: 2_000,
            status_epoch: 5,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        };
        // Local calculation says renewal opens at 8 000 and the leaf dies at
        // 10 000: Astra cannot delay either bound.
        assert_eq!(status.clamped_window(8_000, 10_000), (8_000, 10_000));
        // Bringing the window forward for an incident is allowed.
        let earlier = AstraCertificateStatus {
            suggested_window_start: 5_000,
            ..status
        };
        assert_eq!(earlier.clamped_window(8_000, 10_000), (5_000, 10_000));
    }

    #[test]
    fn revoked_is_the_only_terminal_status() {
        assert!(CertificateStatus::Revoked.is_terminal());
        for status in [
            CertificateStatus::Active,
            CertificateStatus::Overlap,
            CertificateStatus::Expired,
            CertificateStatus::Aborted,
        ] {
            assert!(!status.is_terminal(), "{status:?}");
        }
    }

    /// The refusal happens in the **verifier**, not only in a display.
    ///
    /// And before the signature: the family check is a match, the signature is
    /// an ML-DSA-87 verification, and a combination the table does not hold is
    /// meaningless whoever signed it.
    #[test]
    fn a_status_outside_its_family_is_refused_before_its_signature() {
        let (_, service_key) =
            crate::certificates::encoding::generate_ml_dsa_87_keypair().expect("keygen");
        let fingerprint = Fingerprint::of(b"delegation");
        let status = AstraCertificateStatus {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            certificate_fingerprint: fingerprint,
            // A delegated issuer is replaced, never staged through a client
            // renewal: this pair is not in the table.
            certificate_kind: CertificateKind::AstraIssuer,
            generation: 3,
            status: CertificateStatus::PendingCommit,
            suggested_window_start: 9_000,
            suggested_window_end: 20_000,
            produced_at: 1_000,
            next_update: 2_000,
            status_epoch: 5,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        };

        assert!(matches!(
            status.verify(&service_key, 1, &domain(), &fingerprint, None),
            Err(CertificateError::UnsupportedStatus {
                kind: CertificateKind::AstraIssuer,
                status: CertificateStatus::PendingCommit,
            })
        ));

        // The same object in a state its family does hold gets as far as the
        // signature — which a placeholder fails. That is what says the refusal
        // above was about the family and not about the signature.
        let allowed = AstraCertificateStatus {
            status: CertificateStatus::RenewalDue,
            ..status
        };
        assert!(!matches!(
            allowed.verify(&service_key, 1, &domain(), &fingerprint, None),
            Err(CertificateError::UnsupportedStatus { .. })
        ));
    }

    /// §8.2 selects the state type by family, and the decoder **must** refuse a
    /// combination absent from its table.
    ///
    /// A flat enum lets a signed status say `astra_issuer: pending_commit` — a
    /// sentence with no meaning that every consumer would then have to
    /// interpret, and interpreting it is how two interfaces end up disagreeing
    /// about what the authority said.
    #[test]
    fn each_family_admits_only_the_states_the_table_gives_it() {
        use CertificateKind::*;
        use CertificateStatus::*;

        // The table of §8.2, transcribed. Anything outside a row is refused.
        let client: &[CertificateStatus] = &[
            Active,
            RenewalDue,
            AwaitingOperator,
            PendingGrant,
            PendingCommit,
            Overlap,
            Promoted,
            Expired,
            Revoked,
        ];
        let gateway: &[CertificateStatus] = &[
            Active, RenewalDue, Staged, Published, Aborted, Overlap, Promoted, Expired, Revoked,
        ];
        let anchors: &[CertificateStatus] = &[
            Active, RenewalDue, Staged, Overlap, Promoted, Expired, Revoked,
        ];
        let issuer: &[CertificateStatus] = &[Active, RenewalDue, Expired, Revoked];
        let table: [(CertificateKind, &[CertificateStatus]); 8] = [
            (ClientTls, client),
            (ClientPq, client),
            (GatewayTls, gateway),
            (GatewayPq, gateway),
            (CaPq, anchors),
            (CaTls, anchors),
            (AstraServiceKey, anchors),
            (AstraIssuer, issuer),
        ];

        for (kind, admitted) in table {
            for status in EVERY_STATUS {
                assert_eq!(
                    status.permitted_for(kind),
                    admitted.contains(&status),
                    "{kind:?} / {status:?}"
                );
            }
        }
    }

    /// A state no family may hold is a state nothing can express.
    #[test]
    fn no_state_is_orphaned_by_the_table() {
        use CertificateKind::*;

        let families = [
            GatewayTls,
            GatewayPq,
            ClientTls,
            ClientPq,
            CaPq,
            CaTls,
            AstraIssuer,
            AstraServiceKey,
        ];
        for status in EVERY_STATUS {
            assert!(
                families.iter().any(|kind| status.permitted_for(*kind)),
                "{status:?} belongs to no family"
            );
        }
    }

    /// Two states cannot share a transcript byte: that byte is what the
    /// signature covers, so a collision makes two statements identical.
    #[test]
    fn every_state_has_its_own_transcript_byte() {
        let mut bytes: Vec<u8> = EVERY_STATUS
            .into_iter()
            .map(CertificateStatus::domain_byte)
            .collect();
        let total = bytes.len();
        bytes.sort_unstable();
        bytes.dedup();
        assert_eq!(bytes.len(), total, "two states share a byte");
        // The ten original states keep the numbers they were signed under:
        // renumbering one would silently change what every signed status said.
        assert_eq!(CertificateStatus::Active.domain_byte(), 0);
        assert_eq!(CertificateStatus::Revoked.domain_byte(), 9);
    }

    mod campaign_approval {
        use super::*;
        use crate::certificates::approval::{
            AstraCredentialBinding, CredentialRegistry, CredentialState,
        };
        use crate::certificates::encoding::generate_ml_dsa_87_keypair;
        use crate::certificates::webauthn::test_credentials::Credential;
        use crate::certificates::webauthn::WebAuthnAssertion;
        use aws_lc_rs::digest;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        const RELYING_PARTY: &str = "astra.example";
        const ORIGIN: &str = "https://astra.example";

        fn binding(
            ca_private: &[u8],
            credential: &Credential,
            id: &[u8],
        ) -> AstraCredentialBinding {
            AstraCredentialBinding {
                format_version: CERTIFICATE_FORMAT_VERSION,
                credential_id: id.to_vec(),
                credential_public_key: credential.cose_public_key(),
                aaguid: [0; 16],
                trust_domain_id: domain(),
                gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                state: CredentialState::Active,
                credential_epoch: 1,
                credential_registry_epoch: 4,
                ca_epoch: 1,
                created_at: 500,
                ca_pq_signature: MlDsa87Signature::placeholder(),
            }
            .sign(ca_private)
            .expect("sign")
        }

        fn assertion(credential: &Credential, challenge: &Fingerprint) -> WebAuthnAssertion {
            let mut authenticator_data = Fingerprint::of(RELYING_PARTY.as_bytes())
                .as_bytes()
                .to_vec();
            // User presence and user verification.
            authenticator_data.push(0x05);
            authenticator_data.extend_from_slice(&11u32.to_be_bytes());
            let client_data_json = format!(
                r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}"}}"#,
                URL_SAFE_NO_PAD.encode(challenge.as_bytes())
            )
            .into_bytes();
            let mut message = authenticator_data.clone();
            message.extend_from_slice(digest::digest(&digest::SHA256, &client_data_json).as_ref());
            WebAuthnAssertion {
                authenticator_data,
                client_data_json,
                signature: credential.sign(&message),
            }
        }

        fn answer(
            credential: &Credential,
            binding: &AstraCredentialBinding,
            challenge: &Fingerprint,
        ) -> CredentialAssertion {
            let assertion = assertion(credential, challenge);
            CredentialAssertion {
                credential_id: binding.credential_id.clone(),
                credential_fingerprint: binding.fingerprint(),
                assertion_fingerprint: assertion.fingerprint(),
                assertion,
            }
        }

        struct Domain {
            ca_public: MlDsa87PublicKey,
            registry: CredentialRegistry,
            first: Credential,
            second: Credential,
            first_binding: AstraCredentialBinding,
            second_binding: AstraCredentialBinding,
        }

        fn domain_with_two_credentials() -> Domain {
            let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
            let first = Credential::generate();
            let second = Credential::generate();
            let first_binding = binding(&ca_private, &first, b"credential-one");
            let second_binding = binding(&ca_private, &second, b"credential-two");
            Domain {
                ca_public,
                registry: CredentialRegistry {
                    trust_domain_id: domain(),
                    gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                    ca_epoch: 1,
                    credential_registry_epoch: 4,
                    bindings: vec![first_binding.clone(), second_binding.clone()],
                },
                first,
                second,
                first_binding,
                second_binding,
            }
        }

        fn approval(
            campaign: &AstraRotationCampaign,
            answers: Vec<CredentialAssertion>,
        ) -> CampaignApproval {
            CampaignApproval {
                campaign_id: campaign.campaign_id,
                campaign_fingerprint: campaign.fingerprint(),
                required_credentials: campaign.required_credentials,
                approved_at: 1_100,
                approvals: answers,
            }
        }

        /// The evidence a delegated `manual_global` staging carries (§7.2).
        mod evidence {
            use super::*;
            use crate::certificates::approval::AstraCampaignApprovalEvidence;

            const POLICY: &[u8] = b"policy";

            fn client_key() -> WireGuardKey {
                WireGuardKey::from_bytes([1; 32])
            }

            fn evidence(
                domain: &Domain,
                campaign: AstraRotationCampaign,
            ) -> AstraCampaignApprovalEvidence {
                let challenge = campaign.fingerprint();
                let approval = approval(
                    &campaign,
                    vec![answer(&domain.first, &domain.first_binding, &challenge)],
                );
                AstraCampaignApprovalEvidence {
                    campaign,
                    approval,
                    credential_registry: domain.registry.clone(),
                    webauthn_origin: ORIGIN.into(),
                }
            }

            fn check(
                domain: &Domain,
                evidence: &AstraCampaignApprovalEvidence,
                policy: &Fingerprint,
            ) -> Result<(), CertificateError> {
                evidence.verify(
                    &domain.ca_public,
                    &super::super::domain(),
                    &WireGuardKey::from_bytes([2; 32]),
                    &client_key(),
                    3,
                    &Fingerprint::of(&[1, 1]),
                    &Fingerprint::of(&[1, 2]),
                    RELYING_PARTY,
                    policy,
                    1,
                    4,
                    1_100,
                )
            }

            #[test]
            fn a_campaign_approval_authorizes_the_target_it_named() {
                let domain = domain_with_two_credentials();
                let evidence = evidence(
                    &domain,
                    campaign(CampaignScope::FleetLeafs, vec![target(1), target(2)]),
                );
                check(&domain, &evidence, &Fingerprint::of(POLICY)).expect("covered target");
            }

            /// The fingerprint is what the staging authorization signs. An
            /// evidence blob that did not hash to it would be a second
            /// document beside the one the signature commits to.
            #[test]
            fn the_carried_fingerprint_is_the_approval_itself() {
                let domain = domain_with_two_credentials();
                let evidence = evidence(
                    &domain,
                    campaign(CampaignScope::FleetLeafs, vec![target(1)]),
                );
                assert!(evidence
                    .fingerprint()
                    .expect("fingerprint")
                    .matches(&evidence.approval.fingerprint().expect("approval")));
            }

            /// §2.4: the policy pin is confirmed out of band, and a campaign
            /// resolved under another set of rules is not this domain's.
            #[test]
            fn a_campaign_naming_another_policy_is_refused() {
                let domain = domain_with_two_credentials();
                let evidence = evidence(
                    &domain,
                    campaign(CampaignScope::FleetLeafs, vec![target(1)]),
                );
                assert!(matches!(
                    check(&domain, &evidence, &Fingerprint::of(b"another policy")),
                    Err(CertificateError::PolicyNotPinned)
                ));
            }

            /// The origin is supplied, so it is checked against the relying
            /// party the consumer pins — otherwise supplying it would be
            /// supplying the answer.
            #[test]
            fn an_origin_outside_the_pinned_relying_party_is_refused() {
                let domain = domain_with_two_credentials();
                let mut evidence = evidence(
                    &domain,
                    campaign(CampaignScope::FleetLeafs, vec![target(1)]),
                );
                evidence.webauthn_origin = "https://attacker.example".into();
                assert!(check(&domain, &evidence, &Fingerprint::of(POLICY)).is_err());
            }

            /// The registry travels along and is verified under the `CA-PQ`
            /// the consumer already holds, never believed for being present.
            #[test]
            fn a_registry_no_ca_pq_of_this_domain_signed_is_refused() {
                let domain = domain_with_two_credentials();
                let stranger = domain_with_two_credentials();
                let mut evidence = evidence(
                    &domain,
                    campaign(CampaignScope::FleetLeafs, vec![target(1)]),
                );
                evidence.credential_registry = stranger.registry.clone();
                assert!(check(&domain, &evidence, &Fingerprint::of(POLICY)).is_err());
            }

            /// A campaign for another gateway resolves credentials that verify
            /// nowhere; it is refused before any of them is looked at.
            #[test]
            fn a_campaign_for_another_gateway_is_refused() {
                let domain = domain_with_two_credentials();
                let mut wrong = campaign(CampaignScope::FleetLeafs, vec![target(1)]);
                wrong.gateway_wg_public_key = WireGuardKey::from_bytes([9; 32]);
                let evidence = evidence(&domain, wrong);
                assert!(matches!(
                    check(&domain, &evidence, &Fingerprint::of(POLICY)),
                    Err(CertificateError::GatewayIdentityMismatch)
                ));
            }

            /// The whole point of the family: a perfectly approved campaign
            /// that does not name this peer authorizes nothing for it.
            #[test]
            fn a_valid_approval_for_other_targets_authorizes_nothing_here() {
                let domain = domain_with_two_credentials();
                let evidence = evidence(
                    &domain,
                    campaign(CampaignScope::FleetLeafs, vec![target(2), target(3)]),
                );
                assert!(matches!(
                    check(&domain, &evidence, &Fingerprint::of(POLICY)),
                    Err(CertificateError::CampaignMismatch)
                ));
            }
        }

        #[test]
        fn one_credential_approves_an_ordinary_campaign() {
            let domain = domain_with_two_credentials();
            let campaign = campaign(CampaignScope::FleetLeafs, vec![target(3)]);
            let challenge = campaign.fingerprint();
            let approval = approval(
                &campaign,
                vec![answer(&domain.first, &domain.first_binding, &challenge)],
            );

            approval
                .verify(&campaign, &domain.registry, RELYING_PARTY, ORIGIN, 1_100)
                .expect("one active credential is what this scope demands");
        }

        /// Two touches of one token read as two people and are one.
        ///
        /// The whole value of a two-credential scope is that two objects were
        /// present; accepting the same identifier twice would make the count a
        /// formality.
        #[test]
        fn the_same_credential_cannot_answer_twice() {
            let domain = domain_with_two_credentials();
            let campaign = campaign(CampaignScope::TrustAuthorities, vec![target(3)]);
            let challenge = campaign.fingerprint();
            let once = answer(&domain.first, &domain.first_binding, &challenge);
            let twice = approval(&campaign, vec![once.clone(), once]);

            assert!(matches!(
                twice.verify(&campaign, &domain.registry, RELYING_PARTY, ORIGIN, 1_100),
                Err(CertificateError::DuplicateApproval)
            ));

            // Two distinct ones pass, so the refusal above is about identity
            // and not about the count.
            let distinct = approval(
                &campaign,
                vec![
                    answer(&domain.first, &domain.first_binding, &challenge),
                    answer(&domain.second, &domain.second_binding, &challenge),
                ],
            );
            distinct
                .verify(&campaign, &domain.registry, RELYING_PARTY, ORIGIN, 1_100)
                .expect("two distinct credentials");
        }

        /// A target that moved after the touch invalidates the approval.
        ///
        /// The operator approved *that* list. Recomputing the campaign around
        /// a new target and reusing the assertion would apply a decision
        /// nobody made.
        #[test]
        fn a_campaign_whose_targets_moved_is_refused() {
            let domain = domain_with_two_credentials();
            let approved = campaign(CampaignScope::FleetLeafs, vec![target(3)]);
            let challenge = approved.fingerprint();
            let approval = approval(
                &approved,
                vec![answer(&domain.first, &domain.first_binding, &challenge)],
            );

            let widened = campaign(CampaignScope::FleetLeafs, vec![target(3), target(4)]);
            assert!(matches!(
                approval.verify(&widened, &domain.registry, RELYING_PARTY, ORIGIN, 1_100),
                Err(CertificateError::CampaignMismatch)
            ));
        }

        /// The count comes from the campaign, never from the approval.
        ///
        /// A document that carried its own threshold would set it.
        #[test]
        fn an_approval_cannot_lower_the_count_its_campaign_demands() {
            let domain = domain_with_two_credentials();
            let campaign = campaign(CampaignScope::TrustAuthorities, vec![target(3)]);
            let challenge = campaign.fingerprint();
            let mut approval = approval(
                &campaign,
                vec![answer(&domain.first, &domain.first_binding, &challenge)],
            );
            approval.required_credentials = 1;

            assert!(matches!(
                approval.verify(&campaign, &domain.registry, RELYING_PARTY, ORIGIN, 1_100),
                Err(CertificateError::InsufficientApprovals { .. })
            ));
        }

        /// An assertion produced for another relying party is valid for
        /// another domain, and must not verify here.
        #[test]
        fn an_assertion_for_another_relying_party_is_refused() {
            let domain = domain_with_two_credentials();
            let campaign = campaign(CampaignScope::FleetLeafs, vec![target(3)]);
            let challenge = campaign.fingerprint();
            let approval = approval(
                &campaign,
                vec![answer(&domain.first, &domain.first_binding, &challenge)],
            );

            assert!(approval
                .verify(
                    &campaign,
                    &domain.registry,
                    "other.example",
                    "https://other.example",
                    1_100
                )
                .is_err());
        }

        /// A credential the registry does not carry approves nothing, however
        /// well-formed its assertion is.
        #[test]
        fn a_credential_outside_the_registry_is_refused() {
            let domain = domain_with_two_credentials();
            let campaign = campaign(CampaignScope::FleetLeafs, vec![target(3)]);
            let challenge = campaign.fingerprint();
            let stranger = Credential::generate();
            let mut answer = answer(&domain.first, &domain.first_binding, &challenge);
            answer.credential_id = b"credential-unknown".to_vec();
            let _ = stranger;
            let approval = approval(&campaign, vec![answer]);

            assert!(matches!(
                approval.verify(&campaign, &domain.registry, RELYING_PARTY, ORIGIN, 1_100),
                Err(CertificateError::UnknownCredential)
            ));
        }
    }
}
