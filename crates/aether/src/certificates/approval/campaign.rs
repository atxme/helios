//! The approval evidence of an operator campaign.

use super::*;

/// The complete evidence transported with a campaign-authorized rotation.
///
/// The other approval family of §7.2. An ordinary renewal is approved once,
/// for one request that already exists; a campaign is approved once for a set
/// of targets, before any of their rotation requests are written. So the
/// document a consumer has to check is not the same one, and neither is the
/// thing it binds to: [`AstraRenewalApprovalEvidence`] binds to a request
/// fingerprint, this binds to the target's *current state*.
///
/// # Why the registry travels with it
///
/// [`CampaignApproval::verify`] resolves each credential against a
/// `CA-PQ`-signed [`CredentialRegistry`]. Helios holds the per-credential
/// decisions it has already accepted, not that document, so the document comes
/// along and is verified under the `CA-PQ` the consumer already pins — never
/// believed for being present. The rows are then what the assertions are
/// checked against, and the caller applies them to its own state afterwards,
/// where `supersedes` refuses a revival.
///
/// # Why the origin travels with it, and the relying party does not
///
/// The relying party is domain state: the consumer pins it and compares. The
/// origin is not carried anywhere the consumer can reach, so it comes with the
/// evidence — and is admissible only if it is an HTTPS origin *of that pinned
/// relying party*, which is what stops a supplied origin from being a supplied
/// answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraCampaignApprovalEvidence {
    pub campaign: crate::certificates::status::AstraRotationCampaign,
    pub approval: crate::certificates::status::CampaignApproval,
    pub credential_registry: CredentialRegistry,
    pub webauthn_origin: String,
}

impl AstraCampaignApprovalEvidence {
    /// The value carried as `renewal_authorization_fingerprint` (spec §7.2).
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        self.approval.fingerprint()
    }

    /// Re-derives every claim against material the consumer already holds.
    ///
    /// `now_unix` is the instant the *authorization* was signed, not the
    /// instant it is read: a campaign carries a five-minute window, and it is
    /// the staging lease — not the campaign — that bounds replay afterwards.
    /// This mirrors what the ordinary family already does.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        client_wg_public_key: &WireGuardKey,
        active_generation: u64,
        active_tls_certificate_fingerprint: &Fingerprint,
        active_pq_certificate_fingerprint: &Fingerprint,
        webauthn_rp_id: &str,
        astra_policy_fingerprint: &Fingerprint,
        ca_epoch: u64,
        minimum_registry_epoch: u64,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        // The domain, before anything is read from the campaign: a campaign
        // for another gateway would resolve credentials that verify nowhere.
        if self.campaign.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.campaign.gateway_wg_public_key != *gateway_wg_public_key {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        // §2.4: the policy pin is confirmed out of band and no CA-PQ signature
        // replaces it. A campaign naming another policy was resolved against
        // another set of rules.
        if !self
            .campaign
            .policy_fingerprint
            .matches(astra_policy_fingerprint)
        {
            return Err(CertificateError::PolicyNotPinned);
        }
        self.credential_registry.verify(
            ca_pq,
            trust_domain_id,
            gateway_wg_public_key,
            ca_epoch,
            minimum_registry_epoch,
        )?;
        // Supplied, therefore checked against something that was not: an
        // origin that does not belong to the pinned relying party is refused
        // before any assertion is looked at.
        validate_https_origin(&self.webauthn_origin, webauthn_rp_id)?;
        self.approval.verify(
            &self.campaign,
            &self.credential_registry,
            webauthn_rp_id,
            &self.webauthn_origin,
            now_unix,
        )?;
        // Last, and the reason this family exists at all: the operator
        // approved *this* identity at *this* state.
        self.campaign.covers_client(
            client_wg_public_key,
            active_generation,
            active_tls_certificate_fingerprint,
            active_pq_certificate_fingerprint,
        )
    }
}
