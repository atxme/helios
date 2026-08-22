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
}

impl CampaignScope {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::OrionProfile => 0,
            Self::OrionDevice => 1,
            Self::FleetLeafs => 2,
            Self::FullCertificateChain => 3,
            Self::TrustAuthorities => 4,
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
        if self.scope.rotates_authority() {
            return Err(CertificateError::IssuerScopeViolation(
                "an authority campaign does not authorize a client rotation",
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
