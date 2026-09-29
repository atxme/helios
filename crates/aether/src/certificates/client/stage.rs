//! Staging: the authority's stage authorization and the gateway's signed
//! receipt that it persisted the candidate.

use super::*;

/// Authority's permission for the gateway to hold a candidate (spec §7.2).
///
/// It carries both issued certificates, but it is **not** the grant: until the
/// gateway has persisted the candidate and signed a receipt, the client never
/// receives anything it could install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificateStageAuthorization {
    pub format_version: u16,
    pub protocol_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub ca_tls_epoch: u64,
    pub issuer_kind: IssuerKind,
    pub issuer_epoch: u64,
    /// All-zero under [`IssuerKind::Master`], where `CA-PQ` signs directly.
    pub issuer_authorization_fingerprint: Fingerprint,
    /// The delegation itself, carried so every consumer can check its scope.
    pub issuer_authorization: Option<AstraIssuerAuthorization>,
    pub stage_id: Id16,
    pub request_fingerprint: Fingerprint,
    /// Non-zero fingerprint of the exact operator approval carried below.
    pub renewal_authorization_fingerprint: Fingerprint,
    /// Complete ordinary-renewal evidence. Master-authority paths use another
    /// approval family and therefore leave this absent; their caller must
    /// verify that family before invoking this leaf-level verifier.
    pub renewal_approval: Option<AstraRenewalApprovalEvidence>,
    /// The other approval family of §7.2: the campaign that authorized this
    /// rotation, present exactly when `reason` is [`RotationReason::ManualGlobal`].
    ///
    /// Boxed because a campaign carries up to 256 targets and a credential
    /// registry, and every consumer of this authorization would otherwise
    /// carry that weight on the ordinary path where the field is empty.
    pub campaign_approval: Option<Box<AstraCampaignApprovalEvidence>>,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub client_wg_public_key: WireGuardKey,
    pub active_generation: u64,
    pub next_generation: u64,
    pub active_tls_certificate_fingerprint: Fingerprint,
    pub active_pq_certificate_fingerprint: Fingerprint,
    pub next_tls_ca_certificate_fingerprint: Fingerprint,
    pub next_tls_certificate: DerCertificate,
    pub next_pq_certificate: PqCertificate,
    pub issued_at: u64,
    pub stage_expires_at: u64,
    pub window: TransitionWindow,
    pub reason: RotationReason,
    pub signature: MlDsa87Signature,
}

impl ClientCertificateStageAuthorization {
    pub(super) fn signing_bytes(&self) -> Result<SignedTranscript, CertificateError> {
        let next_pq = pq_certificate_fingerprint(&self.next_pq_certificate)?;
        let mut bytes = CanonicalBytes::new(STAGE_AUTHORIZATION_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .u64(self.ca_tls_epoch)
            .u8(self.issuer_kind.domain_byte())
            .u64(self.issuer_epoch)
            .fingerprint(&self.issuer_authorization_fingerprint)
            .id(&self.stage_id)
            .fingerprint(&self.request_fingerprint)
            .fingerprint(&self.renewal_authorization_fingerprint)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .key(&self.client_wg_public_key)
            .u64(self.active_generation)
            .u64(self.next_generation)
            .fingerprint(&self.active_tls_certificate_fingerprint)
            .fingerprint(&self.active_pq_certificate_fingerprint)
            .fingerprint(&self.next_tls_ca_certificate_fingerprint)
            .fingerprint(&self.next_tls_certificate.fingerprint())
            .fingerprint(&next_pq)
            .u64(self.issued_at)
            .u64(self.stage_expires_at)
            .u64(self.window.not_before)
            .u64(self.window.activation_at)
            .u64(self.window.not_after)
            .u8(self.reason.domain_byte());
        Ok(bytes.finish_signed())
    }

    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        let mut bytes = CanonicalBytes::new(self.signing_bytes()?.as_bytes());
        bytes.length_prefixed(self.signature.as_bytes());
        Ok(Fingerprint::of(&bytes.finish()))
    }

    /// The candidate generation this authorization describes.
    pub fn candidate(&self) -> Result<ClientCertificateGeneration, CertificateError> {
        Ok(ClientCertificateGeneration {
            generation: self.next_generation,
            ca_tls_epoch: self.ca_tls_epoch,
            tls_ca_certificate_fingerprint: self.next_tls_ca_certificate_fingerprint,
            tls_certificate_fingerprint: self.next_tls_certificate.fingerprint(),
            pq_certificate_fingerprint: pq_certificate_fingerprint(&self.next_pq_certificate)?,
            not_before: self.next_pq_certificate.not_before_unix,
            not_after: self.next_pq_certificate.not_after_unix,
        })
    }

    /// Verifies the authorization as Helios does before persisting anything.
    ///
    /// `request_expires_at` is `Some` only where the caller holds the request
    /// itself — Astra. Helios never sees it, so it enforces the bounds it can
    /// see: the lease ceiling and `activation_at`.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        client_wg_public_key: &WireGuardKey,
        active: &ClientCertificateGeneration,
        tls_anchors: &[&DerCertificate],
        policy_pin: Option<&AstraPolicyPin>,
        request_expires_at: Option<u64>,
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
        if self.ca_epoch != ca_epoch || self.ca_tls_epoch != ca_tls_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key || self.server_name != server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.client_wg_public_key != *client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        if self
            .renewal_authorization_fingerprint
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(CertificateError::ApprovalMismatch("missing approval"));
        }
        match (self.issuer_kind, self.reason, &self.renewal_approval) {
            (IssuerKind::Astra, RotationReason::Scheduled, None)
                if self
                    .renewal_authorization_fingerprint
                    .matches(&self.request_fingerprint) =>
            {
                policy_pin
                    .ok_or(CertificateError::PolicyNotPinned)?
                    .assert_allows_automatic_renewal(
                        *trust_domain_id,
                        *gateway_wg_public_key,
                        server_name,
                    )?;
            }
            (IssuerKind::Astra, RotationReason::Scheduled, _) => {
                return Err(CertificateError::ApprovalMismatch(
                    "automatic renewal request binding",
                ));
            }
            (IssuerKind::Astra, RotationReason::ManualGlobal, None) => {}
            (IssuerKind::Astra, RotationReason::ManualGlobal, Some(_)) => {
                return Err(CertificateError::ApprovalMismatch(
                    "unexpected per-request approval",
                ));
            }
            (IssuerKind::Astra, _, _) => {
                return Err(CertificateError::UnauthorizedIssuer);
            }
            // Master-authority operations use their own approval family. It
            // must not be confused with an ordinary delegated renewal.
            (IssuerKind::Master, _, Some(_)) => {
                return Err(CertificateError::ApprovalMismatch(
                    "unexpected delegated renewal approval",
                ));
            }
            (IssuerKind::Master, _, None) => {}
        }
        if self.active_generation != active.generation {
            return Err(CertificateError::GenerationRollback {
                current: active.generation,
                proposed: self.active_generation,
            });
        }
        require_next_generation(self.active_generation, self.next_generation)?;
        if !self
            .active_tls_certificate_fingerprint
            .matches(&active.tls_certificate_fingerprint)
            || !self
                .active_pq_certificate_fingerprint
                .matches(&active.pq_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("active client"));
        }
        self.window.validate()?;

        // An expired recovery is unusable until its signed two-key commit has
        // replaced `pending_grant` with `next`, so its lease only bounds how
        // long that commit may arrive. Unlike an ordinary rotation, it does
        // not prepare a still-working identity ahead of a future cut-over:
        // activation may therefore already have been reached while the stage
        // remains pending. Keeping this exception on the signed reason makes
        // it unavailable to every delegated/ordinary authorization.
        let mut bounds = Vec::with_capacity(2);
        if self.reason != RotationReason::ExpiredRecovery {
            bounds.push(self.window.activation_at);
        }
        if let Some(expiry) = request_expires_at {
            bounds.push(expiry);
        }
        validate_lease(
            self.issued_at,
            self.stage_expires_at,
            MAX_STAGE_LEASE_SECS,
            &bounds,
        )?;
        if now_unix >= self.stage_expires_at {
            return Err(CertificateError::StageExpired);
        }

        // Resolve the issuer **before** touching the leaf: a leaf signed by the
        // delegated issuer chains to that issuer, not to `CA-PQ`, and reading
        // it under the wrong key would refuse every ordinary renewal — or, the
        // other way round, accept a leaf nobody authorized.
        let issuer_key = self.resolve_issuer(
            ca_pq,
            trust_domain_id,
            ca_epoch,
            ca_tls_epoch,
            gateway_wg_public_key,
            server_name,
            &self.next_pq_certificate,
            self.active_generation,
            self.next_generation,
            self.reason,
            policy_pin,
            now_unix,
        )?;

        // The incoming PQ leaf is read at `activation_at`, for the same reason
        // a gateway leaf is: a candidate prepared ahead of time is not valid
        // today, and it must still be valid at the end of the overlap.
        self.next_pq_certificate
            .verify(
                issuer_key.as_bytes(),
                PqCertificateRole::Client,
                None,
                &client_wg_public_key.to_base64(),
                self.window.activation_at,
            )
            .map_err(|_| CertificateError::UnauthorizedIssuer)?;
        if self.next_pq_certificate.not_after_unix < self.window.not_after {
            return Err(CertificateError::OutsideValidityPeriod);
        }
        self.verify_tls_leaf(tls_anchors)?;

        verify_ml_dsa_87(issuer_key, &self.signing_bytes()?, &self.signature)
    }

    /// The TLS half of the candidate: a real client leaf, on a real path.
    ///
    /// The PQ half has always been verified; the TLS one used to be a byte
    /// string nobody parsed. A generation is indivisible, so half of it being
    /// unchecked made the whole of it unchecked.
    fn verify_tls_leaf(&self, tls_anchors: &[&DerCertificate]) -> Result<(), CertificateError> {
        crate::certificates::x509::assert_client_leaf(
            &self.next_tls_certificate,
            self.window.activation_at,
            self.window.not_after,
        )?;
        let intermediates: Vec<&DerCertificate> = self
            .issuer_authorization
            .as_ref()
            .map(|delegation| vec![&delegation.tls_intermediate_certificate])
            .unwrap_or_default();
        // The chain is read at `activation_at`, like the leaf itself: an anchor
        // that expires before the candidate goes into service could not have
        // vouched for it there.
        crate::certificates::x509::assert_chains_to(
            &self.next_tls_certificate,
            &intermediates,
            tls_anchors,
            self.window.activation_at,
            self.window.not_after,
        )?;
        // The anchor the object *names* must be the one it actually chains to.
        if !tls_anchors.iter().any(|anchor| {
            anchor
                .fingerprint()
                .matches(&self.next_tls_ca_certificate_fingerprint)
        }) {
            return Err(CertificateError::FingerprintMismatch("client TLS CA"));
        }
        Ok(())
    }

    /// The key that signed both this object and the leaf it carries.
    ///
    /// Under [`IssuerKind::Master`] that is `CA-PQ` itself, and the delegation
    /// fields must be absent — naming two authorities at once is one authority
    /// too many. Under [`IssuerKind::Astra`] the delegation is verified
    /// against the anchor first, then its scope, and only then is its key
    /// allowed to stand for the authority.
    #[allow(clippy::too_many_arguments)]
    fn resolve_issuer<'a>(
        &'a self,
        ca_pq: &'a MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        leaf: &PqCertificate,
        active_generation: u64,
        next_generation: u64,
        reason: RotationReason,
        policy_pin: Option<&AstraPolicyPin>,
        now_unix: u64,
    ) -> Result<&'a MlDsa87PublicKey, CertificateError> {
        match self.issuer_kind {
            IssuerKind::Master => {
                if self.issuer_authorization.is_some()
                    || self.issuer_authorization_fingerprint != Fingerprint::from_bytes([0; 32])
                {
                    return Err(CertificateError::UnauthorizedIssuer);
                }
                Ok(ca_pq)
            }
            IssuerKind::Astra => {
                let delegation = self
                    .issuer_authorization
                    .as_ref()
                    .ok_or(CertificateError::UnauthorizedIssuer)?;
                policy_pin
                    .ok_or(CertificateError::PolicyNotPinned)?
                    .assert_authorizes(delegation)?;
                delegation.verify(
                    ca_pq,
                    trust_domain_id,
                    ca_epoch,
                    ca_tls_epoch,
                    gateway_wg_public_key,
                    server_name,
                    now_unix,
                )?;
                if delegation.issuer_epoch != self.issuer_epoch
                    || !self
                        .issuer_authorization_fingerprint
                        .matches(&delegation.fingerprint())
                {
                    return Err(CertificateError::UnauthorizedIssuer);
                }
                let lifetime = leaf
                    .not_after_unix
                    .checked_sub(leaf.not_before_unix)
                    .ok_or(CertificateError::InvalidValidityPeriod)?;
                delegation.authorize_renewal(
                    active_generation,
                    next_generation,
                    lifetime,
                    reason,
                )?;
                Ok(&delegation.pq_issuer_public_key)
            }
        }
    }
}

/// Proof that the gateway persisted the candidate before it was released.
///
/// Signed by the **active** gateway PQ leaf, after an atomic write and an
/// `fsync` of the file and of its directory (spec §7.3). Astra refuses to
/// build a grant without it, which is what keeps an issued client identity
/// from existing before the gateway admits it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayCertificateStageReceipt {
    pub format_version: u16,
    pub protocol_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub stage_id: Id16,
    pub stage_authorization_fingerprint: Fingerprint,
    pub request_fingerprint: Fingerprint,
    pub renewal_authorization_fingerprint: Fingerprint,
    pub gateway_wg_public_key: WireGuardKey,
    pub client_wg_public_key: WireGuardKey,
    pub active_generation: u64,
    pub staged_generation: u64,
    pub staged_tls_certificate_fingerprint: Fingerprint,
    pub staged_pq_certificate_fingerprint: Fingerprint,
    pub persisted_at: u64,
    pub stage_expires_at: u64,
    pub active_gateway_identity_epoch: u64,
    pub gateway_decision_epoch: u64,
    pub gateway_certificate_fingerprint: Fingerprint,
    pub gateway_signature: MlDsa87Signature,
}

impl GatewayCertificateStageReceipt {
    pub(super) fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(STAGE_RECEIPT_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.trust_domain_id)
            .id(&self.stage_id)
            .fingerprint(&self.stage_authorization_fingerprint)
            .fingerprint(&self.request_fingerprint)
            .fingerprint(&self.renewal_authorization_fingerprint)
            .key(&self.gateway_wg_public_key)
            .key(&self.client_wg_public_key)
            .u64(self.active_generation)
            .u64(self.staged_generation)
            .fingerprint(&self.staged_tls_certificate_fingerprint)
            .fingerprint(&self.staged_pq_certificate_fingerprint)
            .u64(self.persisted_at)
            .u64(self.stage_expires_at)
            .u64(self.active_gateway_identity_epoch)
            .u64(self.gateway_decision_epoch)
            .fingerprint(&self.gateway_certificate_fingerprint);
        bytes.finish_signed()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes.length_prefixed(self.gateway_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Verifies the receipt against the authorization it answers.
    ///
    /// Every field is compared, not merely the identifier: a receipt that
    /// named the right `stage_id` while describing another generation would be
    /// a valid signature over the wrong fact.
    pub fn verify(
        &self,
        gateway_pq_public_key: &MlDsa87PublicKey,
        gateway_certificate_fingerprint: &Fingerprint,
        authorization: &ClientCertificateStageAuthorization,
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
        if self.trust_domain_id != authorization.trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.stage_id != authorization.stage_id {
            return Err(CertificateError::UnknownStage);
        }
        if !self
            .stage_authorization_fingerprint
            .matches(&authorization.fingerprint()?)
            || !self
                .request_fingerprint
                .matches(&authorization.request_fingerprint)
            || !self
                .renewal_authorization_fingerprint
                .matches(&authorization.renewal_authorization_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("stage authorization"));
        }
        if self.gateway_wg_public_key != authorization.gateway_wg_public_key {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.client_wg_public_key != authorization.client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        if self.active_generation != authorization.active_generation
            || self.staged_generation != authorization.next_generation
        {
            return Err(CertificateError::GenerationConflict {
                generation: self.staged_generation,
            });
        }
        let candidate = authorization.candidate()?;
        if !self
            .staged_tls_certificate_fingerprint
            .matches(&candidate.tls_certificate_fingerprint)
            || !self
                .staged_pq_certificate_fingerprint
                .matches(&candidate.pq_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("staged client"));
        }
        if self.stage_expires_at != authorization.stage_expires_at {
            return Err(CertificateError::InvalidLease);
        }
        if !self
            .gateway_certificate_fingerprint
            .matches(gateway_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("gateway leaf"));
        }
        verify_ml_dsa_87(
            gateway_pq_public_key,
            &self.signing_bytes(),
            &self.gateway_signature,
        )
    }
}
