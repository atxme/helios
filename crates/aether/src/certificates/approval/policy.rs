//! Astra's issuance policy, and the pin an operator confirms out of band.

use super::*;

/// The ceilings and counts an operator confirmed out of band (spec §2.4).
///
/// Not a signed object: it is a **computation**, and its result is the pin.
/// Making it signable would reintroduce the thing §2.4 refuses — a policy that
/// an anchor's signature can move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraIssuancePolicy {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub allowed_usage: AllowedUsage,
    pub maximum_leaf_lifetime_secs: u64,
    pub maximum_stage_lease_secs: u64,
    pub maximum_overlap_secs: u64,
    pub renewal_start_percent: u8,
    pub scheduled_renewal_credentials: u8,
    pub expired_recovery_credentials: u8,
    pub authority_mutation_credentials: u8,
}

impl AstraIssuancePolicy {
    /// The fixed policy profile shipped by this protocol version.
    ///
    /// Both Astra and Helios compute it independently from the gateway identity
    /// during bootstrap.  The resulting fingerprint is then displayed and
    /// carried by enrollment documents; it is never learned from a delegation.
    pub fn standard(
        trust_domain_id: TrustDomainId,
        gateway_wg_public_key: WireGuardKey,
        server_name: String,
    ) -> Self {
        Self {
            format_version: ISSUANCE_POLICY_FORMAT_VERSION,
            trust_domain_id,
            gateway_wg_public_key,
            server_name,
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 90 * 86_400,
            maximum_stage_lease_secs: MAX_STAGE_LEASE_SECS,
            maximum_overlap_secs: MAX_OVERLAP_SECS,
            renewal_start_percent: POLICY_RENEWAL_START_PERCENT,
            scheduled_renewal_credentials: AUTOMATIC_RENEWAL_CREDENTIALS,
            expired_recovery_credentials: 1,
            authority_mutation_credentials: AUTHORITY_MUTATION_CREDENTIALS,
        }
    }

    /// Every bound §2.4 fixes, refused by name rather than clamped.
    ///
    /// A policy outside these bounds has no fingerprint at all — see
    /// [`Self::fingerprint`] — so two ends can never pin a ceiling the
    /// specification does not allow and then agree with each other about it.
    pub fn validate(&self) -> Result<(), CertificateError> {
        if self.format_version != ISSUANCE_POLICY_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: ISSUANCE_POLICY_FORMAT_VERSION,
            });
        }
        validate_server_name(&self.server_name)?;
        if self.allowed_usage != AllowedUsage::AdmittedClientLeafRenewal {
            return Err(CertificateError::InvalidPolicy("allowed usage"));
        }
        if self.maximum_leaf_lifetime_secs == 0 {
            return Err(CertificateError::InvalidPolicy("leaf lifetime"));
        }
        if self.maximum_stage_lease_secs == 0
            || self.maximum_stage_lease_secs > MAX_STAGE_LEASE_SECS
        {
            return Err(CertificateError::InvalidPolicy("stage lease"));
        }
        if self.maximum_overlap_secs == 0 || self.maximum_overlap_secs > MAX_OVERLAP_SECS {
            return Err(CertificateError::InvalidPolicy("overlap"));
        }
        if self.renewal_start_percent != POLICY_RENEWAL_START_PERCENT {
            return Err(CertificateError::InvalidPolicy("renewal start"));
        }
        if self.scheduled_renewal_credentials != AUTOMATIC_RENEWAL_CREDENTIALS {
            return Err(CertificateError::InvalidPolicy(
                "scheduled renewal credentials",
            ));
        }
        if self.expired_recovery_credentials != 1 && self.expired_recovery_credentials != 2 {
            return Err(CertificateError::InvalidPolicy("recovery credentials"));
        }
        if self.authority_mutation_credentials != AUTHORITY_MUTATION_CREDENTIALS {
            return Err(CertificateError::InvalidPolicy("authority credentials"));
        }
        Ok(())
    }

    /// SHA-256 of the canonical form of §2.4, once the policy is in bounds.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        self.validate()?;
        Ok(self.fingerprint_with_scheduled_credentials(self.scheduled_renewal_credentials))
    }

    /// The canonical form, with the scheduled-renewal count supplied.
    ///
    /// Every other field comes from `self`. The count is a parameter for one
    /// reason only: [`superseded_per_request_policy_fingerprint`] has to
    /// reproduce a fingerprint whose count [`Self::validate`] now refuses, and
    /// re-typing the encoder there would be a second canonical form to keep
    /// equal to this one by hand.
    fn fingerprint_with_scheduled_credentials(&self, scheduled_credentials: u8) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(ISSUANCE_POLICY_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .u8(self.allowed_usage.domain_byte())
            .u64(self.maximum_leaf_lifetime_secs)
            .u64(self.maximum_stage_lease_secs)
            .u64(self.maximum_overlap_secs)
            .u8(self.renewal_start_percent)
            .u8(scheduled_credentials)
            .u8(self.expired_recovery_credentials)
            .u8(self.authority_mutation_credentials);
        Fingerprint::of(&bytes.finish())
    }

    /// The value a profile and a registry store.
    pub fn pin(&self) -> Result<AstraPolicyPin, CertificateError> {
        AstraPolicyPin::new(self.fingerprint()?)
    }
}

/// The fingerprint the **superseded** policy of 15 August 2026 produced.
///
/// That policy asked one operator credential per scheduled renewal. Its
/// fingerprint is no longer reachable through
/// [`AstraIssuancePolicy::fingerprint`] — [`AstraIssuancePolicy::validate`]
/// refuses the count — so it is recomputed here from the same canonical form
/// with the single byte that changed.
///
/// It exists to **recognise** a domain still pinned to it, and for nothing
/// else. No path accepts it as an authorization: a pin that equals this value
/// refuses automatic renewal until an operator has confirmed the current
/// policy out of band.
pub fn superseded_per_request_policy_fingerprint(
    trust_domain_id: TrustDomainId,
    gateway_wg_public_key: WireGuardKey,
    server_name: &str,
) -> Result<Fingerprint, CertificateError> {
    let policy = AstraIssuancePolicy::standard(
        trust_domain_id,
        gateway_wg_public_key,
        server_name.to_owned(),
    );
    // Validated on the current policy, so a domain whose *other* bounds are
    // out of specification is refused here rather than recognised as legacy.
    policy.validate()?;
    Ok(policy.fingerprint_with_scheduled_credentials(PER_REQUEST_APPROVAL_CREDENTIALS))
}

/// What [`AstraPolicyPin::adopt_automatic_renewal_policy`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMigration {
    /// The pin already names the current standard policy.
    AlreadyCurrent,
    /// The pin named the superseded policy and the delegation carries the
    /// current one. The caller persists the returned pin.
    Adopted(AstraPolicyPin),
}

/// The out-of-band pin of the issuance policy (spec §2.4).
///
/// A newtype rather than a bare [`Fingerprint`], for one reason: the zero
/// value is what an unset field deserializes to, and a pin that compares equal
/// to nothing has to be impossible to hold rather than merely unlikely. §14.1
/// asks for exactly that refusal — "profil refusé avec une empreinte de
/// politique nulle".
///
/// There is deliberately no constructor taking a signed object. The pin is
/// confirmed by a human against the `CA-PQ` fingerprint at enrolment; learning
/// it from a document would make it a delegation, which §2.4 refuses in as
/// many words.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AstraPolicyPin(Fingerprint);

impl AstraPolicyPin {
    pub fn new(fingerprint: Fingerprint) -> Result<Self, CertificateError> {
        if fingerprint.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(CertificateError::PolicyNotPinned);
        }
        Ok(Self(fingerprint))
    }

    pub const fn fingerprint(&self) -> &Fingerprint {
        &self.0
    }

    /// Compares a presented policy fingerprint against the pin.
    pub fn assert_matches(&self, presented: &Fingerprint) -> Result<(), CertificateError> {
        if !self.0.matches(presented) {
            return Err(CertificateError::FingerprintMismatch(
                "Astra issuance policy",
            ));
        }
        Ok(())
    }

    /// The §2.4 ordering: the pin decides before any delegated right is read.
    ///
    /// Calling `AstraIssuerAuthorization::verify` first would establish that
    /// `CA-PQ` signed *a* delegation — which is true of a delegation carrying
    /// any policy at all, including one that raises every ceiling.
    pub fn assert_authorizes(
        &self,
        delegation: &AstraIssuerAuthorization,
    ) -> Result<(), CertificateError> {
        self.assert_matches(&delegation.policy_fingerprint)
    }

    /// Refuses to reinterpret a pin confirmed under an older issuance policy
    /// as permission for credential-free scheduled renewal.
    ///
    /// Removing the per-request credential changes the authority represented
    /// by the policy fingerprint.  A deployment must therefore confirm the
    /// current standard policy out of band before this path is enabled; merely
    /// upgrading the binaries cannot silently broaden an older delegation.
    pub fn assert_allows_automatic_renewal(
        &self,
        trust_domain_id: TrustDomainId,
        gateway_wg_public_key: WireGuardKey,
        server_name: &str,
    ) -> Result<(), CertificateError> {
        let expected = AstraIssuancePolicy::standard(
            trust_domain_id,
            gateway_wg_public_key,
            server_name.to_owned(),
        )
        .fingerprint()?;
        self.assert_matches(&expected)
    }

    /// Moves a domain off the superseded policy, once, and only on evidence.
    ///
    /// Removing the per-request credential widens what the delegated issuer
    /// may do unattended, so the pin cannot follow a binary upgrade. What it
    /// follows instead is an [`AstraIssuerAuthorization`] carrying the current
    /// standard policy — a document `CA-PQ` signed, which is the out-of-band
    /// confirmation §2.4 asks for. **The caller must have verified that
    /// signature under its own pinned anchor before calling**: this decides
    /// which policy the document names, never whether the document is genuine.
    ///
    /// Every other shape is refused. A pin that is neither the current nor the
    /// superseded standard is left alone — it belongs to a domain this
    /// migration does not describe, and guessing would be exactly the silent
    /// broadening the amendment forbids.
    pub fn adopt_automatic_renewal_policy(
        &self,
        trust_domain_id: TrustDomainId,
        gateway_wg_public_key: WireGuardKey,
        server_name: &str,
        delegation: &AstraIssuerAuthorization,
    ) -> Result<PolicyMigration, CertificateError> {
        let current = AstraIssuancePolicy::standard(
            trust_domain_id,
            gateway_wg_public_key,
            server_name.to_owned(),
        )
        .fingerprint()?;
        if self.0.matches(&current) {
            return Ok(PolicyMigration::AlreadyCurrent);
        }
        let superseded = superseded_per_request_policy_fingerprint(
            trust_domain_id,
            gateway_wg_public_key,
            server_name,
        )?;
        if !self.0.matches(&superseded) {
            return Err(CertificateError::InvalidPolicy(
                "the pinned policy is neither the current nor the superseded standard",
            ));
        }
        if !delegation.policy_fingerprint.matches(&current) {
            return Err(CertificateError::FingerprintMismatch(
                "delegation does not carry the current issuance policy",
            ));
        }
        Ok(PolicyMigration::Adopted(AstraPolicyPin::new(current)?))
    }
}

impl std::fmt::Debug for AstraPolicyPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AstraPolicyPin({})", self.0)
    }
}

impl<'de> Deserialize<'de> for AstraPolicyPin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(Fingerprint::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}
