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
        TrustDomainId, WireGuardKey,
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
}

impl CertificateStatus {
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
        }
    }

    /// Whether this state forbids every rotation, recovery and rollback.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked)
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
    fn signing_bytes(&self) -> Vec<u8> {
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
        bytes.finish()
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
) -> Vec<u8> {
    let mut bytes = CanonicalBytes::new(STATUS_QUERY_DOMAIN);
    bytes
        .id(trust_domain_id)
        .raw(astra_challenge)
        .id(request_id)
        .key(gateway_wg_public_key)
        .key(client_wg_public_key)
        .fingerprint(certificate_fingerprint);
    bytes.finish()
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
        Ok(())
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
    fn signing_bytes(&self) -> Vec<u8> {
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
        bytes.finish()
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
    fn signing_bytes(&self) -> Vec<u8> {
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
        bytes.finish()
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
}
