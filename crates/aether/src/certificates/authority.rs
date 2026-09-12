//! The authorities: `CA-PQ`, the client TLS CA, the delegated Astra issuer and
//! the Astra service key — spec §3.4 and §9.
//!
//! # Why an anchor change costs two signatures
//!
//! Every other object in this module is authorized by an anchor the verifier
//! *already* holds. [`CaTransition`] is the one object that installs a new
//! anchor, and it is therefore the one place where a naive design lets a
//! document vouch for itself. It is refused unless the trusted anchor
//! authorizes the successor **and** the successor proves possession of its own
//! key: the first signature is the continuity, the second stops an attacker
//! who obtained a continuity signature from binding it to a key they do not
//! own.
//!
//! That protects continuity, not compromise. A `CA-PQ` whose private key is in
//! the attacker's hands can choose and co-sign its own successor — spec §9.3
//! and the known limitation of the same name. The answer there is a new trust
//! domain confirmed out of band, never a smarter transition object.
//!
//! # Why the delegated issuer exists
//!
//! Astra must renew an admitted client without a human present (ADR-008 §5),
//! but an online service holding `CA-PQ` would hand a host compromise the
//! permanent authority over the fleet. [`AstraIssuerAuthorization`] is the
//! bounded middle: one gateway, one domain, one window, one usage, and only
//! generation `active + 1` of a peer that is already admitted. Every consumer
//! verifies `CA-PQ` first, then the scope, then the operational signature —
//! in that order, because checking the scope of a delegation nobody
//! authorized is checking nothing.

use serde::{Deserialize, Serialize};

use super::{
    encoding::{
        validate_server_name, verify_ml_dsa_87, CanonicalBytes, DerCertificate, Fingerprint,
        MlDsa87PublicKey, MlDsa87Signature, SignedTranscript, TrustDomainId, WireGuardKey,
    },
    window::{require_next_generation, TransitionWindow},
    CertificateError, CERTIFICATE_FORMAT_VERSION,
};

const CA_TRANSITION_DOMAIN: &[u8] = b"helios-ca-transition-v5";
const CLIENT_TLS_CA_TRANSITION_DOMAIN: &[u8] = b"helios-client-tls-ca-transition-v5";
const ISSUER_AUTHORIZATION_DOMAIN: &[u8] = b"helios-astra-issuer-authorization-v5";
const SERVICE_KEY_TRANSITION_DOMAIN: &[u8] = b"helios-astra-service-key-transition-v5";
const SERVICE_KEY_EMERGENCY_DOMAIN: &[u8] = b"helios-astra-service-key-emergency-replacement-v5";

/// Rotation of the operator anchor, `N -> N+1` (spec §9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaTransition {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub current_ca_epoch: u64,
    pub next_ca_epoch: u64,
    pub current_ca_fingerprint: Fingerprint,
    pub next_ca_public_key: MlDsa87PublicKey,
    pub next_ca_fingerprint: Fingerprint,
    pub window: TransitionWindow,
    /// Continuity, signed by the anchor the verifier already trusts.
    pub current_ca_signature: MlDsa87Signature,
    /// Possession, signed by the anchor being installed.
    pub next_ca_signature: MlDsa87Signature,
}

impl CaTransition {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(CA_TRANSITION_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .u64(self.current_ca_epoch)
            .u64(self.next_ca_epoch)
            .fingerprint(&self.current_ca_fingerprint)
            .length_prefixed(self.next_ca_public_key.as_bytes())
            .fingerprint(&self.next_ca_fingerprint)
            .u64(self.window.not_before)
            .u64(self.window.activation_at)
            .u64(self.window.not_after);
        bytes.finish_signed()
    }

    /// SHA-256 of the signed transcript followed by both signatures.
    ///
    /// Identifies the exact document, signatures included: two transitions
    /// with the same fields and different signature encodings are two
    /// documents, and the idempotent-replay rule compares this.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes
            .length_prefixed(self.current_ca_signature.as_bytes())
            .length_prefixed(self.next_ca_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Verifies the object against the anchor currently trusted locally.
    ///
    /// `trusted_ca` is read from the local trust store, **never** from the
    /// document: an object that brought both a new CA and the signature making
    /// it trustworthy would be self-authorizing.
    pub fn verify(
        &self,
        trusted_ca: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        current_ca_epoch: u64,
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
        if self.current_ca_epoch != current_ca_epoch {
            return Err(CertificateError::GenerationRollback {
                current: current_ca_epoch,
                proposed: self.current_ca_epoch,
            });
        }
        require_next_generation(self.current_ca_epoch, self.next_ca_epoch)?;
        if !self
            .current_ca_fingerprint
            .matches(&trusted_ca.authority_fingerprint())
        {
            return Err(CertificateError::FingerprintMismatch("current CA"));
        }
        if !self
            .next_ca_fingerprint
            .matches(&self.next_ca_public_key.authority_fingerprint())
        {
            return Err(CertificateError::FingerprintMismatch("next CA"));
        }
        self.window.validate()?;

        let transcript = self.signing_bytes();
        verify_ml_dsa_87(trusted_ca, &transcript, &self.current_ca_signature)?;
        verify_ml_dsa_87(
            &self.next_ca_public_key,
            &transcript,
            &self.next_ca_signature,
        )
    }
}

/// Rotation of the CA that issues client mTLS leaves (spec §9.4).
///
/// Authorized by `CA-PQ`, never by the outgoing TLS CA: the TLS anchor
/// authenticates a transport, and letting it authorize its own successor would
/// make a forged transport certificate enough to move the anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTlsCaTransition {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub current_ca_tls_epoch: u64,
    pub next_ca_tls_epoch: u64,
    pub active_client_tls_ca_fingerprint: Fingerprint,
    /// Complete DER of the incoming CA. Self-signed, which proves possession
    /// and its capacity to certify — and which never replaces `ca_pq_signature`
    /// as the authorization.
    pub next_client_tls_ca_certificate: DerCertificate,
    pub window: TransitionWindow,
    pub ca_pq_signature: MlDsa87Signature,
}

impl ClientTlsCaTransition {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(CLIENT_TLS_CA_TRANSITION_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .u64(self.current_ca_tls_epoch)
            .u64(self.next_ca_tls_epoch)
            .fingerprint(&self.active_client_tls_ca_fingerprint)
            .fingerprint(&self.next_client_tls_ca_certificate.fingerprint())
            .u64(self.window.not_before)
            .u64(self.window.activation_at)
            .u64(self.window.not_after);
        bytes.finish_signed()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes.length_prefixed(self.ca_pq_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        current_ca_tls_epoch: u64,
        active_ca_tls_fingerprint: &Fingerprint,
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
        if self.current_ca_tls_epoch != current_ca_tls_epoch {
            return Err(CertificateError::GenerationRollback {
                current: current_ca_tls_epoch,
                proposed: self.current_ca_tls_epoch,
            });
        }
        require_next_generation(self.current_ca_tls_epoch, self.next_ca_tls_epoch)?;
        if !self
            .active_client_tls_ca_fingerprint
            .matches(active_ca_tls_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch(
                "active client TLS CA",
            ));
        }
        self.window.validate()?;
        // The incoming anchor must be a real one, and prove it holds its own
        // key. A signature from `CA-PQ` says the operator meant to install
        // *this document*; it says nothing about whether the bytes inside are
        // a certificate authority at all.
        crate::certificates::x509::assert_certificate_authority(
            &self.next_client_tls_ca_certificate,
        )?;
        // And it must still be an authority for the whole window it is being
        // installed for. An anchor that expires between `activation_at` and
        // `not_after` retires in the middle of the overlap it exists to carry,
        // taking every leaf under it with it — after the outgoing anchor has
        // already been scheduled for retirement.
        crate::certificates::x509::assert_covers(
            &self.next_client_tls_ca_certificate,
            self.window.activation_at,
            self.window.not_after,
        )?;
        verify_ml_dsa_87(ca_pq, &self.signing_bytes(), &self.ca_pq_signature)
    }
}

/// The single usage a delegated issuer may ever carry (spec §3.4).
///
/// An enumeration with one variant rather than a bitmask: a delegation that
/// can express two usages is a delegation whose scope check has to be right
/// twice, and nothing in the specification asks for a second one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowedUsage {
    AdmittedClientLeafRenewal,
}

impl AllowedUsage {
    pub(crate) const fn domain_byte(self) -> u8 {
        match self {
            Self::AdmittedClientLeafRenewal => 1,
        }
    }
}

/// Bounded delegation from `CA-PQ` to the online Astra issuer (spec §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraIssuerAuthorization {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub ca_tls_epoch: u64,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub issuer_epoch: u64,
    pub pq_issuer_public_key: MlDsa87PublicKey,
    /// Client-auth-only intermediate the issuer signs TLS leaves with.
    ///
    /// Its X.509 chain up to `CA-TLS` is verified by the TLS layer that will
    /// actually use it; what the PQ signature binds here is the exact
    /// intermediate, so a delegation cannot be re-pointed at another one.
    pub tls_intermediate_certificate: DerCertificate,
    pub allowed_usage: AllowedUsage,
    pub maximum_leaf_lifetime_secs: u64,
    pub policy_fingerprint: Fingerprint,
    pub not_before: u64,
    pub not_after: u64,
    pub ca_pq_signature: MlDsa87Signature,
}

impl AstraIssuerAuthorization {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(ISSUER_AUTHORIZATION_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .u64(self.ca_tls_epoch)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .u64(self.issuer_epoch)
            .length_prefixed(self.pq_issuer_public_key.as_bytes())
            .fingerprint(&self.tls_intermediate_certificate.fingerprint())
            .u8(self.allowed_usage.domain_byte())
            .u64(self.maximum_leaf_lifetime_secs)
            .fingerprint(&self.policy_fingerprint)
            .u64(self.not_before)
            .u64(self.not_after);
        bytes.finish_signed()
    }

    /// Identifies this delegation in the objects that carry it (spec §7.2).
    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes.length_prefixed(self.ca_pq_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Verifies the delegation itself: anchor, then binding, then window.
    ///
    /// Does **not** authorize an operation — see [`Self::authorize_renewal`].
    /// Splitting the two keeps a caller from believing that a verified
    /// delegation is a permitted operation.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
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
        if self.ca_epoch != ca_epoch || self.ca_tls_epoch != ca_tls_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key || self.server_name != server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        validate_server_name(&self.server_name)?;
        if self.maximum_leaf_lifetime_secs == 0 {
            return Err(CertificateError::IssuerScopeViolation("leaf lifetime"));
        }
        // The delegated intermediate must itself be able to certify, or every
        // leaf it signs would chain to nothing.
        let intermediate = crate::certificates::x509::inspect(&self.tls_intermediate_certificate)?;
        if !intermediate.is_certificate_authority || !intermediate.can_sign_certificates {
            return Err(CertificateError::IssuerScopeViolation("TLS intermediate"));
        }
        if self.not_after <= self.not_before {
            return Err(CertificateError::InvalidValidityPeriod);
        }
        if now_unix < self.not_before || now_unix >= self.not_after {
            return Err(CertificateError::IssuerAuthorizationExpired);
        }
        // The intermediate must outlast the delegation. One that expires
        // first leaves Astra holding a signed authorization it can no longer
        // produce a usable leaf with, and the refusal lands at 80 % of a
        // client's leaf — the one moment there is no fallback.
        crate::certificates::x509::assert_covers(
            &self.tls_intermediate_certificate,
            self.not_before,
            self.not_after,
        )?;
        verify_ml_dsa_87(ca_pq, &self.signing_bytes(), &self.ca_pq_signature)
    }

    /// Checks that a client renewal falls inside this delegation.
    ///
    /// The four refusals here are the whole point of the delegation existing:
    /// a compromised online issuer can renew tomorrow's leaf of an admitted
    /// peer, and nothing else.
    pub fn authorize_renewal(
        &self,
        active_generation: u64,
        requested_generation: u64,
        leaf_lifetime_secs: u64,
        reason: RotationReason,
    ) -> Result<(), CertificateError> {
        if self.allowed_usage != AllowedUsage::AdmittedClientLeafRenewal {
            return Err(CertificateError::IssuerScopeViolation("usage"));
        }
        if !reason.is_delegable() {
            return Err(CertificateError::IssuerScopeViolation("reason"));
        }
        require_next_generation(active_generation, requested_generation)
            .map_err(|_| CertificateError::IssuerScopeViolation("generation"))?;
        if leaf_lifetime_secs == 0 || leaf_lifetime_secs > self.maximum_leaf_lifetime_secs {
            return Err(CertificateError::IssuerScopeViolation("leaf lifetime"));
        }
        Ok(())
    }
}

/// Why a certificate is being reissued (spec §6.1 and §7.2).
///
/// The reason is signed, and it decides which authority may sign: the
/// delegated Astra issuer covers only the ordinary cases. A reason is
/// therefore not a comment — it is the discriminant of an authorization rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    /// The 80 % planner, or a manual renewal of an already active identity.
    Scheduled,
    /// A manual fleet-wide campaign that changes no authority and no admission.
    ManualGlobal,
    /// The gateway lost the private key of its active leaf.
    KeyRecovery,
    /// A client came back after its leaf expired (spec §7.5).
    ExpiredRecovery,
    /// A peer is admitted again after a revocation.
    Readmission,
    /// A compromise: no overlap, and the outgoing identity is withdrawn.
    EmergencyReplacement,
}

impl RotationReason {
    pub(crate) const fn domain_byte(self) -> u8 {
        match self {
            Self::Scheduled => 0,
            Self::ManualGlobal => 1,
            Self::KeyRecovery => 2,
            Self::ExpiredRecovery => 3,
            Self::Readmission => 4,
            Self::EmergencyReplacement => 5,
        }
    }

    /// Whether the delegated Astra issuer may sign for this reason.
    ///
    /// `ManualGlobal` is delegable because it renews leaves of peers that are
    /// already admitted, under a campaign that changes neither admission, nor
    /// authority, nor policy (spec §7.2). Everything else either creates a
    /// continuity that did not exist or touches an anchor, and needs `CA-PQ`.
    pub const fn is_delegable(self) -> bool {
        matches!(self, Self::Scheduled | Self::ManualGlobal)
    }
}

/// Planned rotation of the Astra service key (spec §9.6).
///
/// Three signatures: the outgoing key proves continuity, the incoming key
/// proves possession, and `CA-PQ` authorizes. The last one is why a
/// compromised service key cannot rotate itself onto an attacker's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraServiceKeyTransition {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub current_service_key_epoch: u64,
    pub next_service_key_epoch: u64,
    pub current_service_key_fingerprint: Fingerprint,
    pub next_service_public_key: MlDsa87PublicKey,
    pub next_service_key_fingerprint: Fingerprint,
    pub window: TransitionWindow,
    pub reason: RotationReason,
    pub current_service_key_signature: MlDsa87Signature,
    pub next_service_key_signature: MlDsa87Signature,
    pub ca_pq_signature: MlDsa87Signature,
}

impl AstraServiceKeyTransition {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(SERVICE_KEY_TRANSITION_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .u64(self.current_service_key_epoch)
            .u64(self.next_service_key_epoch)
            .fingerprint(&self.current_service_key_fingerprint)
            .length_prefixed(self.next_service_public_key.as_bytes())
            .fingerprint(&self.next_service_key_fingerprint)
            .u64(self.window.not_before)
            .u64(self.window.activation_at)
            .u64(self.window.not_after)
            .u8(self.reason.domain_byte());
        bytes.finish_signed()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes
            .length_prefixed(self.current_service_key_signature.as_bytes())
            .length_prefixed(self.next_service_key_signature.as_bytes())
            .length_prefixed(self.ca_pq_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        current_service_key: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        current_service_key_epoch: u64,
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
        if self.current_service_key_epoch != current_service_key_epoch {
            return Err(CertificateError::GenerationRollback {
                current: current_service_key_epoch,
                proposed: self.current_service_key_epoch,
            });
        }
        require_next_generation(self.current_service_key_epoch, self.next_service_key_epoch)?;
        if !self
            .current_service_key_fingerprint
            .matches(&current_service_key.authority_fingerprint())
        {
            return Err(CertificateError::FingerprintMismatch("current service key"));
        }
        if !self
            .next_service_key_fingerprint
            .matches(&self.next_service_public_key.authority_fingerprint())
        {
            return Err(CertificateError::FingerprintMismatch("next service key"));
        }
        self.window.validate()?;

        let transcript = self.signing_bytes();
        verify_ml_dsa_87(
            current_service_key,
            &transcript,
            &self.current_service_key_signature,
        )?;
        verify_ml_dsa_87(
            &self.next_service_public_key,
            &transcript,
            &self.next_service_key_signature,
        )?;
        verify_ml_dsa_87(ca_pq, &transcript, &self.ca_pq_signature)
    }
}

/// Immediate replacement of a compromised Astra service key (spec §9.6).
///
/// No overlap and no signature from the outgoing key: a compromised key's
/// signature proves nothing, and requiring it would let the attacker block
/// their own eviction. `CA-PQ` authorizes, the incoming key proves itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmergencyAstraServiceKeyReplacement {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub current_service_key_epoch: u64,
    pub next_service_key_epoch: u64,
    pub revoked_service_key_fingerprint: Fingerprint,
    pub next_service_public_key: MlDsa87PublicKey,
    pub next_service_key_fingerprint: Fingerprint,
    pub revocation_epoch: u64,
    pub effective_at: u64,
    pub reason: RotationReason,
    pub next_service_key_signature: MlDsa87Signature,
    pub ca_pq_signature: MlDsa87Signature,
}

impl EmergencyAstraServiceKeyReplacement {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(SERVICE_KEY_EMERGENCY_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .u64(self.current_service_key_epoch)
            .u64(self.next_service_key_epoch)
            .fingerprint(&self.revoked_service_key_fingerprint)
            .length_prefixed(self.next_service_public_key.as_bytes())
            .fingerprint(&self.next_service_key_fingerprint)
            .u64(self.revocation_epoch)
            .u64(self.effective_at)
            .u8(self.reason.domain_byte());
        bytes.finish_signed()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes
            .length_prefixed(self.next_service_key_signature.as_bytes())
            .length_prefixed(self.ca_pq_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        current_service_key_epoch: u64,
        current_revocation_epoch: u64,
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
        if self.current_service_key_epoch != current_service_key_epoch {
            return Err(CertificateError::GenerationRollback {
                current: current_service_key_epoch,
                proposed: self.current_service_key_epoch,
            });
        }
        require_next_generation(self.current_service_key_epoch, self.next_service_key_epoch)?;
        require_next_generation(current_revocation_epoch, self.revocation_epoch)?;
        if !self
            .next_service_key_fingerprint
            .matches(&self.next_service_public_key.authority_fingerprint())
        {
            return Err(CertificateError::FingerprintMismatch("next service key"));
        }

        let transcript = self.signing_bytes();
        verify_ml_dsa_87(
            &self.next_service_public_key,
            &transcript,
            &self.next_service_key_signature,
        )?;
        verify_ml_dsa_87(ca_pq, &transcript, &self.ca_pq_signature)
    }
}

/// Signing side of the authority objects.
///
/// Separated from the types by a feature so a gateway that only ever verifies
/// links no signing implementation at all. The private keys these take live in
/// the operator companion; nothing in the workspace calls them with a key read
/// from a gateway.
#[cfg(feature = "key-negotiation-signing")]
mod signing {
    use super::*;
    use crate::certificates::encoding::sign_ml_dsa_87;

    impl CaTransition {
        /// Both signatures over the same transcript: continuity, then
        /// possession. A caller holding only one key cannot produce a valid
        /// object, which is the property [`CaTransition::verify`] enforces.
        pub fn sign(
            mut self,
            current_ca_private_key: &[u8],
            next_ca_private_key: &[u8],
        ) -> Result<Self, CertificateError> {
            let transcript = self.signing_bytes();
            self.current_ca_signature = sign_ml_dsa_87(current_ca_private_key, &transcript)?;
            self.next_ca_signature = sign_ml_dsa_87(next_ca_private_key, &transcript)?;
            Ok(self)
        }
    }

    impl ClientTlsCaTransition {
        pub fn sign(mut self, ca_pq_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.ca_pq_signature = sign_ml_dsa_87(ca_pq_private_key, &self.signing_bytes())?;
            Ok(self)
        }
    }

    impl AstraIssuerAuthorization {
        pub fn sign(mut self, ca_pq_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.ca_pq_signature = sign_ml_dsa_87(ca_pq_private_key, &self.signing_bytes())?;
            Ok(self)
        }
    }

    impl AstraServiceKeyTransition {
        pub fn sign(
            mut self,
            current_service_private_key: &[u8],
            next_service_private_key: &[u8],
            ca_pq_private_key: &[u8],
        ) -> Result<Self, CertificateError> {
            let transcript = self.signing_bytes();
            self.current_service_key_signature =
                sign_ml_dsa_87(current_service_private_key, &transcript)?;
            self.next_service_key_signature =
                sign_ml_dsa_87(next_service_private_key, &transcript)?;
            self.ca_pq_signature = sign_ml_dsa_87(ca_pq_private_key, &transcript)?;
            Ok(self)
        }
    }

    impl EmergencyAstraServiceKeyReplacement {
        /// Deliberately takes no outgoing key: a compromised one proves
        /// nothing, and requiring it would let the attacker block their own
        /// eviction.
        pub fn sign(
            mut self,
            next_service_private_key: &[u8],
            ca_pq_private_key: &[u8],
        ) -> Result<Self, CertificateError> {
            let transcript = self.signing_bytes();
            self.next_service_key_signature =
                sign_ml_dsa_87(next_service_private_key, &transcript)?;
            self.ca_pq_signature = sign_ml_dsa_87(ca_pq_private_key, &transcript)?;
            Ok(self)
        }
    }
}

#[cfg(all(test, feature = "key-negotiation-signing"))]
mod tests {
    use super::*;
    use crate::certificates::encoding::{generate_ml_dsa_87_keypair, sign_ml_dsa_87};
    use crate::certificates::window::MAX_OVERLAP_SECS;
    use zeroize::Zeroizing;

    struct Authority {
        private: Zeroizing<Vec<u8>>,
        public: MlDsa87PublicKey,
    }

    fn authority() -> Authority {
        let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
        Authority { private, public }
    }

    fn domain() -> TrustDomainId {
        TrustDomainId::new([9; 16]).expect("domain")
    }

    fn window() -> TransitionWindow {
        TransitionWindow::new(1_000, 2_000, 2_000 + MAX_OVERLAP_SECS).expect("window")
    }

    fn ca_transition(current: &Authority, next: &Authority) -> CaTransition {
        let mut transition = CaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            current_ca_epoch: 1,
            next_ca_epoch: 2,
            current_ca_fingerprint: current.public.authority_fingerprint(),
            next_ca_public_key: next.public.clone(),
            next_ca_fingerprint: next.public.authority_fingerprint(),
            window: window(),
            current_ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
            next_ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
        };
        let transcript = transition.signing_bytes();
        transition.current_ca_signature =
            sign_ml_dsa_87(&current.private, &transcript).expect("sign current");
        transition.next_ca_signature =
            sign_ml_dsa_87(&next.private, &transcript).expect("sign next");
        transition
    }

    #[test]
    fn a_ca_transition_needs_both_the_continuity_and_the_possession_signature() {
        let current = authority();
        let next = authority();
        let transition = ca_transition(&current, &next);
        assert!(transition.verify(&current.public, &domain(), 1).is_ok());

        // Continuity alone: the successor's own signature is replaced by one
        // from a key nobody authorized.
        let impostor = authority();
        let mut forged = transition.clone();
        forged.next_ca_signature =
            sign_ml_dsa_87(&impostor.private, &transition.signing_bytes()).expect("sign");
        assert!(matches!(
            forged.verify(&current.public, &domain(), 1),
            Err(CertificateError::InvalidSignature)
        ));

        // Possession alone: the document is not authorized by the trusted
        // anchor at all.
        let mut unauthorized = transition.clone();
        unauthorized.current_ca_signature =
            sign_ml_dsa_87(&impostor.private, &transition.signing_bytes()).expect("sign");
        assert!(matches!(
            unauthorized.verify(&current.public, &domain(), 1),
            Err(CertificateError::InvalidSignature)
        ));
    }

    /// The anchor comes from the local trust store. A document signed by a CA
    /// the verifier does not already hold proves nothing about the domain.
    #[test]
    fn a_ca_transition_under_an_unknown_anchor_is_refused() {
        let current = authority();
        let next = authority();
        let stranger = authority();
        let transition = ca_transition(&current, &next);
        assert!(matches!(
            transition.verify(&stranger.public, &domain(), 1),
            Err(CertificateError::FingerprintMismatch("current CA"))
        ));
    }

    #[test]
    fn a_ca_transition_refuses_a_skipped_or_reversed_epoch() {
        let current = authority();
        let next = authority();
        let transition = ca_transition(&current, &next);
        assert!(matches!(
            transition.verify(&current.public, &domain(), 2),
            Err(CertificateError::GenerationRollback { .. })
        ));
        assert!(matches!(
            transition.verify(&current.public, &domain(), 0),
            Err(CertificateError::GenerationRollback { .. })
        ));
    }

    #[test]
    fn a_ca_transition_for_another_domain_is_refused_before_any_signature() {
        let current = authority();
        let next = authority();
        let mut transition = ca_transition(&current, &next);
        transition.trust_domain_id = TrustDomainId::new([1; 16]).expect("domain");
        assert!(matches!(
            transition.verify(&current.public, &domain(), 1),
            Err(CertificateError::TrustDomainMismatch)
        ));
    }

    fn issuer_authorization(ca: &Authority, issuer: &MlDsa87PublicKey) -> AstraIssuerAuthorization {
        let mut authorization = AstraIssuerAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            server_name: "gateway.example".into(),
            issuer_epoch: 1,
            pq_issuer_public_key: issuer.clone(),
            tls_intermediate_certificate: crate::certificates::test_x509::certificate_authority(
                "astra-issuer",
            ),
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 90 * 86_400,
            policy_fingerprint: Fingerprint::of(b"policy"),
            not_before: 1_000,
            not_after: 100_000,
            ca_pq_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
        };
        authorization.ca_pq_signature =
            sign_ml_dsa_87(&ca.private, &authorization.signing_bytes()).expect("sign");
        authorization
    }

    #[test]
    fn a_delegation_is_bound_to_one_gateway_one_domain_and_one_window() {
        let ca = authority();
        let (_, issuer) = generate_ml_dsa_87_keypair().expect("keygen");
        let authorization = issuer_authorization(&ca, &issuer);
        let gateway = WireGuardKey::from_bytes([2; 32]);

        assert!(authorization
            .verify(
                &ca.public,
                &domain(),
                1,
                1,
                &gateway,
                "gateway.example",
                2_000
            )
            .is_ok());

        assert!(matches!(
            authorization.verify(
                &ca.public,
                &domain(),
                1,
                1,
                &WireGuardKey::from_bytes([7; 32]),
                "gateway.example",
                2_000
            ),
            Err(CertificateError::GatewayIdentityMismatch)
        ));
        assert!(matches!(
            authorization.verify(
                &ca.public,
                &domain(),
                1,
                1,
                &gateway,
                "other.example",
                2_000
            ),
            Err(CertificateError::GatewayIdentityMismatch)
        ));
        assert!(matches!(
            authorization.verify(
                &ca.public,
                &domain(),
                1,
                1,
                &gateway,
                "gateway.example",
                100_001
            ),
            Err(CertificateError::IssuerAuthorizationExpired)
        ));
        assert!(matches!(
            authorization.verify(
                &ca.public,
                &domain(),
                2,
                1,
                &gateway,
                "gateway.example",
                2_000
            ),
            Err(CertificateError::UnauthorizedIssuer)
        ));
    }

    /// The four refusals that make the delegation worth having: an online
    /// issuer renews tomorrow's leaf of an admitted peer, and nothing else.
    #[test]
    fn a_delegation_covers_only_the_next_generation_of_an_ordinary_renewal() {
        let ca = authority();
        let (_, issuer) = generate_ml_dsa_87_keypair().expect("keygen");
        let authorization = issuer_authorization(&ca, &issuer);

        assert!(authorization
            .authorize_renewal(4, 5, 30 * 86_400, RotationReason::Scheduled)
            .is_ok());
        assert!(authorization
            .authorize_renewal(4, 5, 30 * 86_400, RotationReason::ManualGlobal)
            .is_ok());

        for forbidden in [
            RotationReason::ExpiredRecovery,
            RotationReason::Readmission,
            RotationReason::EmergencyReplacement,
            RotationReason::KeyRecovery,
        ] {
            assert!(matches!(
                authorization.authorize_renewal(4, 5, 30 * 86_400, forbidden),
                Err(CertificateError::IssuerScopeViolation("reason"))
            ));
        }
        assert!(matches!(
            authorization.authorize_renewal(4, 6, 30 * 86_400, RotationReason::Scheduled),
            Err(CertificateError::IssuerScopeViolation("generation"))
        ));
        assert!(matches!(
            authorization.authorize_renewal(4, 5, 91 * 86_400, RotationReason::Scheduled),
            Err(CertificateError::IssuerScopeViolation("leaf lifetime"))
        ));
    }

    #[test]
    fn a_planned_service_key_rotation_needs_all_three_signatures() {
        let ca = authority();
        let current = authority();
        let next = authority();

        let mut transition = AstraServiceKeyTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            current_service_key_epoch: 3,
            next_service_key_epoch: 4,
            current_service_key_fingerprint: current.public.authority_fingerprint(),
            next_service_public_key: next.public.clone(),
            next_service_key_fingerprint: next.public.authority_fingerprint(),
            window: window(),
            reason: RotationReason::Scheduled,
            current_service_key_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
            next_service_key_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
            ca_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        };
        let transcript = transition.signing_bytes();
        transition.current_service_key_signature =
            sign_ml_dsa_87(&current.private, &transcript).unwrap();
        transition.next_service_key_signature = sign_ml_dsa_87(&next.private, &transcript).unwrap();
        transition.ca_pq_signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();

        assert!(transition
            .verify(&ca.public, &current.public, &domain(), 1, 3)
            .is_ok());

        for missing in 0..3 {
            let mut broken = transition.clone();
            let stranger = authority();
            let forged = sign_ml_dsa_87(&stranger.private, &transcript).unwrap();
            match missing {
                0 => broken.current_service_key_signature = forged,
                1 => broken.next_service_key_signature = forged,
                _ => broken.ca_pq_signature = forged,
            }
            assert!(matches!(
                broken.verify(&ca.public, &current.public, &domain(), 1, 3),
                Err(CertificateError::InvalidSignature)
            ));
        }
    }

    /// A compromised key must not be able to block its own eviction, so the
    /// emergency object carries no signature from it.
    #[test]
    fn an_emergency_replacement_needs_ca_pq_and_the_new_key_only() {
        let ca = authority();
        let next = authority();

        let mut replacement = EmergencyAstraServiceKeyReplacement {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            current_service_key_epoch: 3,
            next_service_key_epoch: 4,
            revoked_service_key_fingerprint: Fingerprint::of(b"revoked"),
            next_service_public_key: next.public.clone(),
            next_service_key_fingerprint: next.public.authority_fingerprint(),
            revocation_epoch: 1,
            effective_at: 1_000,
            reason: RotationReason::EmergencyReplacement,
            next_service_key_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
            ca_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        };
        let transcript = replacement.signing_bytes();
        replacement.next_service_key_signature =
            sign_ml_dsa_87(&next.private, &transcript).unwrap();
        replacement.ca_pq_signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();

        assert!(replacement.verify(&ca.public, &domain(), 1, 3, 0).is_ok());

        // The revocation counter advances on its own axis and cannot stand still.
        assert!(matches!(
            replacement.verify(&ca.public, &domain(), 1, 3, 1),
            Err(CertificateError::GenerationConflict { .. })
        ));

        let stranger = authority();
        let mut forged = replacement.clone();
        forged.ca_pq_signature = sign_ml_dsa_87(&stranger.private, &transcript).unwrap();
        assert!(matches!(
            forged.verify(&ca.public, &domain(), 1, 3, 0),
            Err(CertificateError::InvalidSignature)
        ));
    }
}
