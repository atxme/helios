//! The legacy per-request renewal approval: the request, Astra's approval
//! and the evidence a stage or grant carries.

use super::*;

/// What Astra asks an operator to approve, before any certificate exists.
///
/// It is signed by the Astra service key so the companion can display fields
/// it did not choose, and it fixes the WebAuthn challenge as the hash of its
/// own canonical form — which is what makes the resulting assertion unmovable
/// to another peer, generation or deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraCredentialApprovalRequest {
    pub format_version: u16,
    pub operation_id: Id16,
    /// SHA-256 of the client rotation request of §7.1, signatures included.
    pub request_fingerprint: Fingerprint,
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub client_wg_public_key: WireGuardKey,
    pub active_generation: u64,
    pub requested_generation: u64,
    pub credential_registry_epoch: u64,
    pub webauthn_rp_id: String,
    pub webauthn_origin: String,
    pub allowed_credential_ids: Vec<Vec<u8>>,
    pub required_credentials: u8,
    pub created_at: u64,
    pub expires_at: u64,
    pub astra_service_key_epoch: u64,
    pub astra_signature: MlDsa87Signature,
}

impl AstraCredentialApprovalRequest {
    /// The field sequence §2.4 fixes for the challenge, reused by the
    /// signature so the two can never describe different operations.
    fn body(&self, bytes: &mut CanonicalBytes) {
        bytes
            .u16(self.format_version)
            .id(&self.operation_id)
            .fingerprint(&self.request_fingerprint)
            .id(&self.trust_domain_id)
            .key(&self.gateway_wg_public_key)
            .key(&self.client_wg_public_key)
            .u64(self.active_generation)
            .u64(self.requested_generation)
            .u64(self.credential_registry_epoch)
            .text(&self.webauthn_rp_id)
            .text(&self.webauthn_origin);
        for credential_id in &self.allowed_credential_ids {
            bytes.length_prefixed(credential_id);
        }
        bytes.u64(self.created_at).u64(self.expires_at);
    }

    /// The WebAuthn challenge of §2.4: SHA-256 of the canonical request.
    ///
    /// Not an ML-DSA context and not signed by anyone — it is the 32 bytes the
    /// authenticator answers, and the reason an assertion cannot be carried to
    /// a second operation.
    pub fn challenge(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(CLIENT_RENEWAL_APPROVAL_DOMAIN);
        self.body(&mut bytes);
        Fingerprint::of(&bytes.finish())
    }

    pub(super) fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(CREDENTIAL_APPROVAL_REQUEST_DOMAIN);
        self.body(&mut bytes);
        bytes
            .u8(self.required_credentials)
            .u64(self.astra_service_key_epoch);
        bytes.finish_signed()
    }

    /// Identifies this request, signature included, for the approval chain.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes.length_prefixed(self.astra_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Verified under the service key the consumer **already pins**.
    ///
    /// `active_generation` is the consumer's own persisted generation, not a
    /// value read from the request: an approval request that named its own
    /// starting point could ask an operator to approve a renewal of a
    /// generation that is no longer current.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        service_key: &MlDsa87PublicKey,
        service_key_epoch: u64,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        client_wg_public_key: &WireGuardKey,
        webauthn_rp_id: &str,
        active_generation: u64,
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
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.client_wg_public_key != *client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        // The relying party identifier is pinned in the profile and survives a
        // rotation of Astra's public TLS certificate, so it is compared rather
        // than learned (spec §2.4).
        if self.webauthn_rp_id != webauthn_rp_id {
            return Err(CertificateError::InvalidServerName);
        }
        validate_server_name(&self.webauthn_rp_id)?;
        validate_https_origin(&self.webauthn_origin, &self.webauthn_rp_id)?;
        if self.active_generation != active_generation {
            return Err(CertificateError::GenerationRollback {
                current: active_generation,
                proposed: self.active_generation,
            });
        }
        require_next_generation(self.active_generation, self.requested_generation)?;
        if self.required_credentials != PER_REQUEST_APPROVAL_CREDENTIALS {
            return Err(CertificateError::InsufficientApprovals {
                required: PER_REQUEST_APPROVAL_CREDENTIALS,
                provided: self.required_credentials,
            });
        }
        self.validate_credential_list()?;
        if self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_APPROVAL_LIFETIME_SECS
        {
            return Err(CertificateError::InvalidLease);
        }
        if now_unix >= self.expires_at {
            return Err(CertificateError::StageExpired);
        }
        verify_ml_dsa_87(service_key, &self.signing_bytes(), &self.astra_signature)
    }

    fn validate_credential_list(&self) -> Result<(), CertificateError> {
        if self.allowed_credential_ids.is_empty()
            || self.allowed_credential_ids.len() > MAX_ALLOWED_CREDENTIALS
        {
            return Err(CertificateError::UnknownCredential);
        }
        for (index, credential_id) in self.allowed_credential_ids.iter().enumerate() {
            if credential_id.is_empty()
                || credential_id.len() > crate::certificates::client::MAX_CREDENTIAL_ID_BYTES
            {
                return Err(CertificateError::UnknownCredential);
            }
            // A repeated identifier would let the same credential fill two
            // slots of a list whose length is the only thing bounding how many
            // tokens an operation may be answered by.
            if self.allowed_credential_ids[..index].contains(credential_id) {
                return Err(CertificateError::UnknownCredential);
            }
        }
        Ok(())
    }

    fn allows(&self, credential_id: &[u8]) -> bool {
        self.allowed_credential_ids
            .iter()
            .any(|allowed| allowed.as_slice() == credential_id)
    }
}

/// The approval Astra persists once an assertion answered the challenge.
///
/// It travels to Helios with the staging authorization and its fingerprint
/// enters both the stage and the grant, which is what makes it impossible to
/// issue a leaf that no operator approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraRenewalApproval {
    pub format_version: u16,
    pub operation_id: Id16,
    /// Fingerprint of the client rotation request of spec §7.1.
    ///
    /// This deliberately has the same meaning as
    /// [`AstraCredentialApprovalRequest::request_fingerprint`].  The signed
    /// approval-request document has its own fingerprint below; conflating the
    /// two made two interoperable implementations impossible.
    pub request_fingerprint: Fingerprint,
    /// Fingerprint of the signed [`AstraCredentialApprovalRequest`] whose
    /// WebAuthn challenge was answered.
    pub approval_request_fingerprint: Fingerprint,
    /// The `CA-PQ`-signed binding of the credential that answered, carried
    /// whole so no consumer has to ask Astra's registry what it means.
    pub credential_binding: AstraCredentialBinding,
    pub credential_fingerprint: Fingerprint,
    pub assertion_fingerprint: Fingerprint,
    pub webauthn_assertion: WebAuthnAssertion,
    pub approved_at: u64,
    pub expires_at: u64,
    pub astra_service_key_epoch: u64,
    pub astra_signature: MlDsa87Signature,
}

impl AstraRenewalApproval {
    pub(super) fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(RENEWAL_APPROVAL_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.operation_id)
            .fingerprint(&self.request_fingerprint)
            .fingerprint(&self.approval_request_fingerprint)
            .fingerprint(&self.credential_fingerprint)
            .fingerprint(&self.assertion_fingerprint)
            .u64(self.approved_at)
            .u64(self.expires_at)
            .u64(self.astra_service_key_epoch);
        bytes.finish_signed()
    }

    /// The `renewal_authorization_fingerprint` of the stage and of the grant.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes.length_prefixed(self.astra_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// The three independent proofs, then Astra's own signature.
    ///
    /// The order is the argument of this module: the binding is checked under
    /// the anchor, the assertion under the credential's own key, and the
    /// challenge is re-derived from the request — all before Astra's signature
    /// is looked at, so that no step can be satisfied by Astra's assertion
    /// that it happened.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        request: &AstraCredentialApprovalRequest,
        ca_pq: &MlDsa87PublicKey,
        service_key: &MlDsa87PublicKey,
        service_key_epoch: u64,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        minimum_registry_epoch: u64,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        self.verify_operator_evidence(
            request,
            ca_pq,
            service_key_epoch,
            trust_domain_id,
            ca_epoch,
            minimum_registry_epoch,
            now_unix,
        )?;
        verify_ml_dsa_87(service_key, &self.signing_bytes(), &self.astra_signature)
    }

    /// Verifies what the offline companion produced, before Astra signs it.
    ///
    /// The companion deliberately cannot create `astra_signature`.  Astra
    /// must therefore establish the request binding, the `CA-PQ` credential
    /// binding and the WebAuthn assertion first, then countersign that proven
    /// fact.  Calling [`Self::verify`] on the placeholder would reject every
    /// legitimate approval; signing first would make the online key sign
    /// attacker-chosen invalid evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_operator_evidence(
        &self,
        request: &AstraCredentialApprovalRequest,
        ca_pq: &MlDsa87PublicKey,
        service_key_epoch: u64,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        minimum_registry_epoch: u64,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.operation_id != request.operation_id {
            return Err(CertificateError::ApprovalMismatch("operation"));
        }
        // The binding to the exact request: the amendment of 15 August 2026
        // makes this the difference between an approval and a licence.
        if !self
            .request_fingerprint
            .matches(&request.request_fingerprint)
        {
            return Err(CertificateError::ApprovalMismatch("request fingerprint"));
        }
        if !self
            .approval_request_fingerprint
            .matches(&request.fingerprint())
        {
            return Err(CertificateError::ApprovalMismatch(
                "approval request fingerprint",
            ));
        }
        if self.astra_service_key_epoch != service_key_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        // `approved_at <= expires_at <= min(request.expires_at, approved_at +
        // 300)`, read under the consumer's clock rather than Astra's.
        if self.expires_at < self.approved_at
            || self.expires_at > request.expires_at
            || self
                .expires_at
                .checked_sub(self.approved_at)
                .ok_or(CertificateError::ArithmeticOverflow)?
                > MAX_APPROVAL_LIFETIME_SECS
        {
            return Err(CertificateError::InvalidLease);
        }
        if now_unix >= self.expires_at {
            return Err(CertificateError::StageExpired);
        }

        if !self
            .credential_fingerprint
            .matches(&self.credential_binding.fingerprint())
        {
            return Err(CertificateError::ApprovalMismatch("credential binding"));
        }
        self.credential_binding.verify(
            ca_pq,
            trust_domain_id,
            &request.gateway_wg_public_key,
            ca_epoch,
            minimum_registry_epoch,
        )?;
        self.credential_binding.assert_can_approve()?;
        // The registry epoch the operator was shown must not be older than the
        // one the request named, or a credential revoked between the two would
        // still approve.
        if self.credential_binding.credential_registry_epoch < request.credential_registry_epoch {
            return Err(CertificateError::GenerationRollback {
                current: request.credential_registry_epoch,
                proposed: self.credential_binding.credential_registry_epoch,
            });
        }
        if !request.allows(&self.credential_binding.credential_id) {
            return Err(CertificateError::UnknownCredential);
        }

        if !self
            .assertion_fingerprint
            .matches(&self.webauthn_assertion.fingerprint())
        {
            return Err(CertificateError::ApprovalMismatch("assertion"));
        }
        let challenge = request.challenge();
        verify_assertion(
            &self.webauthn_assertion,
            &self.credential_binding.credential_public_key,
            &AssertionExpectation {
                relying_party_id: &request.webauthn_rp_id,
                origin: &request.webauthn_origin,
                challenge: &challenge,
            },
        )?;

        Ok(())
    }
}

/// The complete evidence transported with a delegated client renewal.
///
/// A fingerprint alone cannot be checked by Helios or Orion: both consumers
/// need the service-signed request to reconstruct the WebAuthn challenge and
/// the approval carrying the assertion and the CA-PQ-signed credential
/// binding.  Keeping the pair in one strict object prevents a route or a
/// persistence layer from accidentally forwarding only the convenient half.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraRenewalApprovalEvidence {
    pub approval_request: AstraCredentialApprovalRequest,
    pub approval: AstraRenewalApproval,
}

impl AstraRenewalApprovalEvidence {
    /// The value carried as `renewal_authorization_fingerprint` by stage, receipt
    /// and grant.
    pub fn fingerprint(&self) -> Fingerprint {
        self.approval.fingerprint()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        expected_rotation_request: &Fingerprint,
        ca_pq: &MlDsa87PublicKey,
        service_key: &MlDsa87PublicKey,
        service_key_epoch: u64,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        client_wg_public_key: &WireGuardKey,
        webauthn_rp_id: &str,
        active_generation: u64,
        ca_epoch: u64,
        minimum_registry_epoch: u64,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if !self
            .approval_request
            .request_fingerprint
            .matches(expected_rotation_request)
        {
            return Err(CertificateError::ApprovalMismatch(
                "rotation request fingerprint",
            ));
        }
        self.approval_request.verify(
            service_key,
            service_key_epoch,
            trust_domain_id,
            gateway_wg_public_key,
            client_wg_public_key,
            webauthn_rp_id,
            active_generation,
            now_unix,
        )?;
        self.approval.verify(
            &self.approval_request,
            ca_pq,
            service_key,
            service_key_epoch,
            trust_domain_id,
            ca_epoch,
            minimum_registry_epoch,
            now_unix,
        )
    }
}
