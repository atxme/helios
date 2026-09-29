//! The rotation grant: the authority releases the leaves once the gateway
//! has receipted them.

use super::*;

/// Release of the two issued leaves, against a valid receipt (spec §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificateRotationGrant {
    pub format_version: u16,
    pub protocol_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub ca_tls_epoch: u64,
    pub issuer_kind: IssuerKind,
    pub issuer_epoch: u64,
    pub issuer_authorization_fingerprint: Fingerprint,
    pub issuer_authorization: Option<AstraIssuerAuthorization>,
    pub request_fingerprint: Fingerprint,
    pub renewal_authorization_fingerprint: Fingerprint,
    pub renewal_approval: Option<AstraRenewalApprovalEvidence>,
    /// Carried onward from the authorization, so the client checks the same
    /// family the gateway did rather than trusting that it happened.
    pub campaign_approval: Option<Box<AstraCampaignApprovalEvidence>>,
    pub stage_receipt_fingerprint: Fingerprint,
    pub stage_receipt: GatewayCertificateStageReceipt,
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
    pub stage_expires_at: u64,
    pub window: TransitionWindow,
    pub reason: RotationReason,
    pub signature: MlDsa87Signature,
}

impl ClientCertificateRotationGrant {
    pub(super) fn signing_bytes(&self) -> Result<SignedTranscript, CertificateError> {
        let next_pq = pq_certificate_fingerprint(&self.next_pq_certificate)?;
        let mut bytes = CanonicalBytes::new(ROTATION_GRANT_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .u64(self.ca_tls_epoch)
            .u8(self.issuer_kind.domain_byte())
            .u64(self.issuer_epoch)
            .fingerprint(&self.issuer_authorization_fingerprint)
            .fingerprint(&self.request_fingerprint)
            .fingerprint(&self.renewal_authorization_fingerprint)
            .fingerprint(&self.stage_receipt_fingerprint)
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

    /// Verifies the grant as Orion does, before writing anything locally.
    ///
    /// The embedded receipt is verified under the gateway leaf **this client
    /// pins**: a grant is only worth what the gateway admitted, and a receipt
    /// signed by another gateway describes another fleet.
    ///
    /// On top of what [`Self::verify_for_gateway`] checks, this binds the
    /// grant to the **local** request: its fingerprint, its generations and
    /// the public key it proved possession of. Without that, a valid grant
    /// issued for another machine would be installed against private keys
    /// nobody on this one holds.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        gateway_pq_public_key: &MlDsa87PublicKey,
        gateway_certificate_fingerprint: &Fingerprint,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        client_wg_public_key: &WireGuardKey,
        request: &ClientCertificateRotationRequest,
        tls_anchors: &[&DerCertificate],
        policy_pin: Option<&AstraPolicyPin>,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        let issuer_key = self.verify_common(
            ca_pq,
            gateway_pq_public_key,
            gateway_certificate_fingerprint,
            trust_domain_id,
            ca_epoch,
            ca_tls_epoch,
            gateway_wg_public_key,
            server_name,
            client_wg_public_key,
            tls_anchors,
            policy_pin,
            now_unix,
        )?;

        // The TLS leaf must certify the key **this** client generated. A grant
        // can be perfectly signed and still install a certificate whose private
        // key nobody holds; the failure would then surface at the next mTLS
        // handshake, after the old generation was retired.
        crate::certificates::x509::assert_csr_matches(
            &request.tls_csr,
            &self.next_tls_certificate,
        )?;

        if !self.request_fingerprint.matches(&request.fingerprint()) {
            return Err(CertificateError::FingerprintMismatch("rotation request"));
        }
        if self.active_generation != request.active_generation
            || self.next_generation != request.requested_generation
        {
            return Err(CertificateError::GenerationConflict {
                generation: self.next_generation,
            });
        }
        // The leaf must certify the key the client actually generated, or the
        // candidate would be a certificate without a usable private key.
        if self.next_pq_certificate.ml_dsa_87_public_key
            != request.new_ml_dsa_87_public_key.to_base64()
        {
            return Err(CertificateError::MissingProof("new client"));
        }

        verify_ml_dsa_87(issuer_key, &self.signing_bytes()?, &self.signature)
    }

    /// Verifies the grant of a §7.5 recovery, as the client does.
    ///
    /// The same checks as [`Self::verify`], read off the recovery request
    /// instead of the rotation one — and two extra refusals that only make
    /// sense here: the grant must be `CA-PQ`'s own
    /// ([`IssuerKind::Master`]) and its reason must be
    /// [`RotationReason::ExpiredRecovery`].
    ///
    /// # Why this is a separate method and not a generic one
    ///
    /// A recovery installs a certificate for an identity every ordinary
    /// validator refuses. Sharing one entry point with the ordinary path would
    /// mean one `if` away from letting a delegated issuer's grant install a
    /// generation that reaches past a validity period. Two methods make the
    /// two paths impossible to confuse at the call site, which is where the
    /// confusion would matter.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_for_recovery(
        &self,
        ca_pq: &MlDsa87PublicKey,
        gateway_pq_public_key: &MlDsa87PublicKey,
        gateway_certificate_fingerprint: &Fingerprint,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        client_wg_public_key: &WireGuardKey,
        request: &ExpiredCertificateRecoveryRequest,
        tls_anchors: &[&DerCertificate],
        policy_pin: Option<&AstraPolicyPin>,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if self.issuer_kind != IssuerKind::Master {
            return Err(CertificateError::IssuerScopeViolation(
                "only CA-PQ grants the recovery of an expired identity",
            ));
        }
        if self.reason != RotationReason::ExpiredRecovery {
            return Err(CertificateError::IssuerScopeViolation(
                "this grant was issued for another reason",
            ));
        }
        let issuer_key = self.verify_common(
            ca_pq,
            gateway_pq_public_key,
            gateway_certificate_fingerprint,
            trust_domain_id,
            ca_epoch,
            ca_tls_epoch,
            gateway_wg_public_key,
            server_name,
            client_wg_public_key,
            tls_anchors,
            policy_pin,
            now_unix,
        )?;

        crate::certificates::x509::assert_csr_matches(
            &request.tls_csr,
            &self.next_tls_certificate,
        )?;
        if !self.request_fingerprint.matches(&request.fingerprint()) {
            return Err(CertificateError::FingerprintMismatch("recovery request"));
        }
        if self.active_generation != request.expired_generation
            || self.next_generation != request.requested_generation
        {
            return Err(CertificateError::GenerationConflict {
                generation: self.next_generation,
            });
        }
        if self.next_pq_certificate.ml_dsa_87_public_key
            != request.new_ml_dsa_87_public_key.to_base64()
        {
            return Err(CertificateError::MissingProof("new client"));
        }

        verify_ml_dsa_87(issuer_key, &self.signing_bytes()?, &self.signature)
    }

    /// Checks the issuer's signature over this grant, and nothing else.
    ///
    /// # What this is for, and what it is not
    ///
    /// A **relay** needs to know that the authority whose key it pins produced
    /// these bytes, before it stores or forwards them. It is not a substitute
    /// for [`Self::verify`] or [`Self::verify_for_gateway`]: neither the
    /// receipt, the leaves, the window, the anchors nor the generation are
    /// examined here, and a consumer that installs anything on the strength of
    /// this call alone would be installing an unverified certificate.
    ///
    /// Named so that no caller can mistake it for the whole check: the two
    /// full verifications say what they verify *for*, this one says only that
    /// it verifies a signature.
    pub fn verify_signed_by(
        &self,
        issuer_public_key: &MlDsa87PublicKey,
    ) -> Result<(), CertificateError> {
        let transcript = self.signing_bytes()?;
        verify_ml_dsa_87(issuer_public_key, &transcript, &self.signature)
    }

    /// Verifies the grant as **Helios** does, on a commit arriving in the
    /// tunnel (spec §7.3).
    ///
    /// The gateway never sees the rotation request — it only ever held the
    /// staging authorization — so it binds the grant to what it *does* know:
    /// the receipt it signed itself, the candidate it persisted, and the
    /// generation that candidate follows. Requiring the grant here is what
    /// closes the protocol: without it a client holding both private keys
    /// could commit a candidate the authority never released.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_for_gateway(
        &self,
        ca_pq: &MlDsa87PublicKey,
        gateway_pq_public_key: &MlDsa87PublicKey,
        gateway_certificate_fingerprint: &Fingerprint,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        client_wg_public_key: &WireGuardKey,
        active_generation: u64,
        candidate: &ClientCertificateGeneration,
        stage_id: &Id16,
        tls_anchors: &[&DerCertificate],
        policy_pin: Option<&AstraPolicyPin>,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        let issuer_key = self.verify_common(
            ca_pq,
            gateway_pq_public_key,
            gateway_certificate_fingerprint,
            trust_domain_id,
            ca_epoch,
            ca_tls_epoch,
            gateway_wg_public_key,
            server_name,
            client_wg_public_key,
            tls_anchors,
            policy_pin,
            now_unix,
        )?;

        if self.stage_receipt.stage_id != *stage_id {
            return Err(CertificateError::UnknownStage);
        }
        if self.active_generation != active_generation {
            return Err(CertificateError::GenerationConflict {
                generation: self.active_generation,
            });
        }
        // Every field of the candidate, not just its fingerprints: a grant
        // that released another window or another TLS anchor for the same two
        // leaves would be describing a different decision.
        if self.candidate()? != *candidate {
            return Err(CertificateError::FingerprintMismatch("staged client"));
        }

        verify_ml_dsa_87(issuer_key, &self.signing_bytes()?, &self.signature)
    }

    /// Everything both verifiers share: identities, the embedded receipt, the
    /// window, and the resolution of the issuer that signed the leaf.
    ///
    /// Returns the issuer key, so neither caller can verify the grant's own
    /// signature under a key the grant chose for itself.
    #[allow(clippy::too_many_arguments)]
    fn verify_common<'a>(
        &'a self,
        ca_pq: &'a MlDsa87PublicKey,
        gateway_pq_public_key: &MlDsa87PublicKey,
        gateway_certificate_fingerprint: &Fingerprint,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        client_wg_public_key: &WireGuardKey,
        tls_anchors: &[&DerCertificate],
        policy_pin: Option<&AstraPolicyPin>,
        now_unix: u64,
    ) -> Result<&'a MlDsa87PublicKey, CertificateError> {
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
            (IssuerKind::Master, _, Some(_)) => {
                return Err(CertificateError::ApprovalMismatch(
                    "unexpected delegated renewal approval",
                ));
            }
            (IssuerKind::Master, _, None) => {}
        }
        if !self
            .stage_receipt_fingerprint
            .matches(&self.stage_receipt.fingerprint())
        {
            return Err(CertificateError::FingerprintMismatch("stage receipt"));
        }
        if self.stage_receipt.stage_expires_at != self.stage_expires_at
            || self.stage_receipt.staged_generation != self.next_generation
            || !self
                .stage_receipt
                .request_fingerprint
                .matches(&self.request_fingerprint)
            || !self
                .stage_receipt
                .renewal_authorization_fingerprint
                .matches(&self.renewal_authorization_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("stage receipt"));
        }
        let candidate = self.candidate()?;
        if !self
            .stage_receipt
            .staged_tls_certificate_fingerprint
            .matches(&candidate.tls_certificate_fingerprint)
            || !self
                .stage_receipt
                .staged_pq_certificate_fingerprint
                .matches(&candidate.pq_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("staged client"));
        }
        verify_ml_dsa_87(
            gateway_pq_public_key,
            &self.stage_receipt.signing_bytes(),
            &self.stage_receipt.gateway_signature,
        )
        .map_err(|_| CertificateError::MissingProof("gateway receipt"))?;
        if !self
            .stage_receipt
            .gateway_certificate_fingerprint
            .matches(gateway_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("gateway leaf"));
        }

        self.window.validate()?;
        if now_unix >= self.stage_expires_at {
            return Err(CertificateError::StageExpired);
        }

        let issuer_key = self.resolve_issuer(
            ca_pq,
            trust_domain_id,
            ca_epoch,
            ca_tls_epoch,
            gateway_wg_public_key,
            server_name,
            policy_pin,
            now_unix,
        )?;
        self.next_pq_certificate
            .verify(
                issuer_key.as_bytes(),
                PqCertificateRole::Client,
                None,
                &client_wg_public_key.to_base64(),
                self.window.activation_at,
            )
            .map_err(|_| CertificateError::UnauthorizedIssuer)?;
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
        crate::certificates::x509::assert_chains_to(
            &self.next_tls_certificate,
            &intermediates,
            tls_anchors,
            self.window.activation_at,
            self.window.not_after,
        )?;
        if !tls_anchors.iter().any(|anchor| {
            anchor
                .fingerprint()
                .matches(&self.next_tls_ca_certificate_fingerprint)
        }) {
            return Err(CertificateError::FingerprintMismatch("client TLS CA"));
        }
        Ok(issuer_key)
    }

    /// Same rule as [`ClientCertificateStageAuthorization::resolve_issuer`]:
    /// the delegated issuer stands for the authority only after `CA-PQ` has
    /// authorized it and its scope has been checked.
    #[allow(clippy::too_many_arguments)]
    fn resolve_issuer<'a>(
        &'a self,
        ca_pq: &'a MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
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
                let lifetime = self
                    .next_pq_certificate
                    .not_after_unix
                    .checked_sub(self.next_pq_certificate.not_before_unix)
                    .ok_or(CertificateError::InvalidValidityPeriod)?;
                delegation.authorize_renewal(
                    self.active_generation,
                    self.next_generation,
                    lifetime,
                    self.reason,
                )?;
                Ok(&delegation.pq_issuer_public_key)
            }
        }
    }
}
