//! The approval of an expired-certificate recovery, and its evidence.

use super::*;

/// The operator authorization behind one delegated client rotation (§7.2).
///
/// # Why the reason and the evidence are one value
///
/// A staging authorization carries both a `reason` and an approval object,
/// and only two of their combinations mean anything: `scheduled` with an
/// ordinary renewal approval, `manual_global` with a campaign approval. Passed
/// as two arguments they can disagree, and a disagreement here is a rotation
/// authorized by a document that never described it. Passed as one value they
/// cannot: the reason is *derived* from the family, at the only place that
/// One operator credential's answer to a §7.5 recovery challenge.
///
/// # Why this is a third family and not a variant of the other two
///
/// A recovery is the one operation that reaches past a validity period. Its
/// challenge therefore has its own hash domain, so an assertion taken for an
/// ordinary renewal — which the operator was shown as a routine rotation —
/// can never be replayed as authorization to revive an expired identity. The
/// two documents are not interchangeable, and making them one type is how they
/// would become so.
///
/// It is also **not** what makes the staging legitimate: a recovery staging is
/// signed by `CA-PQ` itself (`IssuerKind::Master`), inside the companion, and
/// that signature is the operator's decision. This document is what lets Astra
/// check, before relaying anything, that the touch answered *this* request —
/// and what consumes the challenge so a second relay finds nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiredRecoveryApproval {
    /// Fingerprint of the [`crate::certificates::client::ExpiredCertificateRecoveryRequest`].
    pub request_fingerprint: Fingerprint,
    /// The nonce Astra issued and will consume.
    pub astra_challenge: [u8; 32],
    pub approved_at: u64,
    pub expires_at: u64,
    pub credential_id: Vec<u8>,
    pub credential_fingerprint: Fingerprint,
    pub assertion_fingerprint: Fingerprint,
    pub webauthn_assertion: WebAuthnAssertion,
}

impl ExpiredRecoveryApproval {
    /// The 32 bytes the authenticator answers (spec §7.5).
    ///
    /// The request, the nonce and the deadline. Binding all three is what
    /// stops an assertion from surviving its window or naming another request:
    /// change any of them and the authenticator's signature covers a challenge
    /// nobody will recompute.
    pub fn challenge(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(EXPIRED_RECOVERY_APPROVAL_DOMAIN);
        bytes
            .fingerprint(&self.request_fingerprint)
            .raw(&self.astra_challenge)
            .u64(self.expires_at);
        Fingerprint::of(&bytes.finish())
    }

    /// Identifies the exact document, assertion included.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        let encoded =
            serde_json::to_vec(self).map_err(|_| CertificateError::InvalidAssertion("encoding"))?;
        Ok(Fingerprint::of(&encoded))
    }
}

/// A recovery approval and everything needed to check it (spec §7.5).
///
/// The registry travels for the same reason it does with a campaign: the
/// credential's public key comes from a row `CA-PQ` signed, and no consumer of
/// a recovery holds Astra's document. The origin travels for the same reason
/// too, and is admissible only as an HTTPS origin of the **pinned** relying
/// party — a supplied origin must never be a supplied answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiredRecoveryApprovalEvidence {
    pub approval: ExpiredRecoveryApproval,
    pub credential_registry: CredentialRegistry,
    pub webauthn_origin: String,
}

impl ExpiredRecoveryApprovalEvidence {
    /// The value carried as `renewal_authorization_fingerprint`.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        self.approval.fingerprint()
    }

    /// Re-derives every claim against material the consumer already holds.
    ///
    /// The request fingerprint and the nonce come from the caller, never from
    /// the document: an approval that named the request it answers would be an
    /// approval of whatever it chose.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        expected_request_fingerprint: &Fingerprint,
        expected_challenge: &[u8; 32],
        webauthn_rp_id: &str,
        ca_epoch: u64,
        minimum_registry_epoch: u64,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if !self
            .approval
            .request_fingerprint
            .matches(expected_request_fingerprint)
        {
            return Err(CertificateError::ApprovalMismatch(
                "recovery request fingerprint",
            ));
        }
        if self.approval.astra_challenge != *expected_challenge
            || self.approval.astra_challenge.iter().all(|byte| *byte == 0)
        {
            return Err(CertificateError::InvalidChallenge);
        }
        if self.approval.expires_at <= self.approval.approved_at
            || self.approval.expires_at - self.approval.approved_at > MAX_APPROVAL_LIFETIME_SECS
            || now_unix >= self.approval.expires_at
        {
            return Err(CertificateError::InvalidLease);
        }
        self.credential_registry.verify(
            ca_pq,
            trust_domain_id,
            gateway_wg_public_key,
            ca_epoch,
            minimum_registry_epoch,
        )?;
        validate_https_origin(&self.webauthn_origin, webauthn_rp_id)?;

        // `approvable` and not `binding`: §7.5 requires an **active** operator
        // credential. A lost or revoked one that still resolves would let a
        // withdrawn key revive an expired identity, which is the one operation
        // that reaches past a validity period.
        let binding = self
            .credential_registry
            .approvable()
            .into_iter()
            .find(|binding| binding.credential_id == self.approval.credential_id)
            .ok_or(CertificateError::UnknownCredential)?;
        if !binding
            .fingerprint()
            .matches(&self.approval.credential_fingerprint)
        {
            return Err(CertificateError::InvalidCredentialBinding(
                "credential fingerprint",
            ));
        }
        if !self
            .approval
            .webauthn_assertion
            .fingerprint()
            .matches(&self.approval.assertion_fingerprint)
        {
            return Err(CertificateError::InvalidAssertion("assertion fingerprint"));
        }
        let challenge = self.approval.challenge();
        verify_assertion(
            &self.approval.webauthn_assertion,
            &binding.credential_public_key,
            &AssertionExpectation {
                relying_party_id: webauthn_rp_id,
                origin: &self.webauthn_origin,
                challenge: &challenge,
            },
        )
    }
}
