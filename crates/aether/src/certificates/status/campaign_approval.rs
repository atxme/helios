//! The approval of a campaign: the assertions of the operator's credentials.

use super::*;

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
    pub assertion: crate::certificates::webauthn::WebAuthnAssertion,
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
        registry: &crate::certificates::approval::CredentialRegistry,
        webauthn_rp_id: &str,
        webauthn_origin: &str,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        use crate::certificates::webauthn::{verify_assertion, AssertionExpectation};

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
            if binding.state != crate::certificates::approval::CredentialState::Active {
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
