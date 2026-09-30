//! Approving a campaign with security keys — the one gesture here that never
//! opens the vault.

use super::*;

/// Approves a manual campaign, at as many distinct credentials as its scope
/// demands (spec §7.6).
///
/// `keys` are plugged one at a time, and the gesture refuses two answers from
/// the same credential: `TrustAuthorities` asking for two touches of one token
/// would be a policy that reads as two people and is one.
///
/// The challenge is the campaign fingerprint, which covers every target **and
/// their order** — so an approval cannot be reused for the same set applied
/// differently, and a target added afterwards is refused by
/// [`AstraRotationCampaign::assert_unchanged`].
#[allow(clippy::too_many_arguments)]
pub fn approve_campaign(
    keys: &[&dyn Authenticator],
    campaign: &AstraRotationCampaign,
    bindings: &CredentialRegistry,
    identity: &DomainIdentity,
    ca_pq_public_key: &MlDsa87PublicKey,
    webauthn_rp_id: &str,
    webauthn_origin: &str,
    pins: &[&str],
    now_unix: u64,
) -> Result<CampaignApproval> {
    let mut session = CampaignApprovalSession::new(
        campaign,
        bindings,
        identity,
        ca_pq_public_key,
        webauthn_rp_id,
        webauthn_origin,
        now_unix,
    )?;
    if keys.len() != session.required() || pins.len() != session.required() {
        return Err(GestureError::Anchors(format!(
            "cette campagne exige {} credential(s) distinct(s), {} clé(s) fournie(s)",
            session.required(),
            keys.len()
        )));
    }
    for (key, pin) in keys.iter().zip(pins) {
        let offered = session.offered_credentials();
        let approval = key.approve(
            session.webauthn_rp_id(),
            &offered,
            session.client_data_json(),
            pin,
        )?;
        session.accept(approval, now_unix)?;
    }
    session.finish(now_unix)
}

/// A campaign approval collected one physical key at a time.
///
/// Platform WebAuthn handles select the authenticator that is plugged in when
/// `approve` runs. Keeping a list of handles and using it after the operator
/// swapped keys therefore does not preserve physical-key identity. This
/// session exposes the shrinking allow-list so callers can approve each key
/// while that key is still connected, then move to the next one.
pub struct CampaignApprovalSession {
    campaign_id: aether::certificates::encoding::Id16,
    fingerprint: Fingerprint,
    required_credentials: u8,
    expires_at: u64,
    webauthn_rp_id: String,
    webauthn_origin: String,
    client_data_json: Vec<u8>,
    offered: Vec<AstraCredentialBinding>,
    approvals: Vec<CredentialAssertion>,
}

impl CampaignApprovalSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        campaign: &AstraRotationCampaign,
        bindings: &CredentialRegistry,
        identity: &DomainIdentity,
        ca_pq_public_key: &MlDsa87PublicKey,
        webauthn_rp_id: &str,
        webauthn_origin: &str,
        now_unix: u64,
    ) -> Result<Self> {
        campaign.validate(now_unix)?;
        bindings.verify(
            ca_pq_public_key,
            &identity.trust_domain_id,
            &identity.gateway_wg_public_key,
            identity.ca_epoch,
            bindings.credential_registry_epoch,
        )?;
        if campaign.trust_domain_id != identity.trust_domain_id
            || campaign.gateway_wg_public_key != identity.gateway_wg_public_key
        {
            return Err(GestureError::Anchors(
                "cette campagne vise un autre domaine ou une autre gateway".into(),
            ));
        }
        // The pin decides before any target is read (spec §2.4).
        identity
            .policy()?
            .pin()?
            .assert_matches(&campaign.policy_fingerprint)?;
        validate_https_origin(webauthn_origin, webauthn_rp_id)?;

        let fingerprint = campaign.fingerprint();
        let client_data_json = client_data(&fingerprint, webauthn_origin);
        let offered: Vec<AstraCredentialBinding> =
            bindings.approvable().into_iter().cloned().collect();
        let required = usize::from(campaign.required_credentials);
        if offered.len() < required {
            return Err(GestureError::Anchors(format!(
                "{required} credential(s) actifs sont exigés, {} enregistré(s)",
                offered.len()
            )));
        }

        Ok(Self {
            campaign_id: campaign.campaign_id,
            fingerprint,
            required_credentials: campaign.required_credentials,
            expires_at: campaign.expires_at,
            webauthn_rp_id: webauthn_rp_id.to_string(),
            webauthn_origin: webauthn_origin.to_string(),
            client_data_json,
            offered,
            approvals: Vec::with_capacity(required),
        })
    }

    pub fn required(&self) -> usize {
        usize::from(self.required_credentials)
    }

    pub fn webauthn_rp_id(&self) -> &str {
        &self.webauthn_rp_id
    }

    pub fn client_data_json(&self) -> &[u8] {
        &self.client_data_json
    }

    pub fn offered_credentials(&self) -> Vec<Vec<u8>> {
        self.offered
            .iter()
            .map(|binding| binding.credential_id.clone())
            .filter(|id| {
                !self
                    .approvals
                    .iter()
                    .any(|approval| approval.credential_id == *id)
            })
            .collect()
    }

    pub fn accept(&mut self, approval: Approval, now_unix: u64) -> Result<()> {
        self.accept_for(approval, None, now_unix)
    }

    /// Accepts an assertion and, when the caller already opened a vault slot,
    /// binds it to that same physical credential.
    pub fn accept_for(
        &mut self,
        approval: Approval,
        expected_credential_id: Option<&[u8]>,
        now_unix: u64,
    ) -> Result<()> {
        if now_unix >= self.expires_at {
            return Err(GestureError::Anchors(
                "la campagne a expiré pendant la cérémonie ; aucune transition ne sera signée"
                    .into(),
            ));
        }
        if self.approvals.len() >= self.required() {
            return Err(GestureError::Anchors(
                "cette campagne a déjà reçu toutes ses confirmations".into(),
            ));
        }
        if expected_credential_id.is_some_and(|expected| expected != approval.credential_id) {
            return Err(GestureError::Anchors(
                "la clé qui approuve n'est pas celle qui vient d'ouvrir le coffre ; recommencer avec une seule clé branchée"
                    .into(),
            ));
        }
        if self
            .approvals
            .iter()
            .any(|previous| previous.credential_id == approval.credential_id)
        {
            return Err(GestureError::Anchors(
                "la même clé a répondu deux fois : deux confirmations exigent deux objets \
                 distincts"
                    .into(),
            ));
        }
        let binding = self
            .offered
            .iter()
            .find(|binding| binding.credential_id == approval.credential_id)
            .ok_or_else(|| {
                GestureError::Anchors("la clé a répondu pour un credential non proposé".into())
            })?;
        verify_assertion(
            &approval.assertion,
            &binding.credential_public_key,
            &AssertionExpectation {
                relying_party_id: &self.webauthn_rp_id,
                origin: &self.webauthn_origin,
                challenge: &self.fingerprint,
            },
        )?;
        self.approvals.push(CredentialAssertion {
            credential_id: approval.credential_id,
            credential_fingerprint: binding.fingerprint(),
            assertion_fingerprint: approval.assertion.fingerprint(),
            assertion: approval.assertion,
        });
        Ok(())
    }

    pub fn finish(self, now_unix: u64) -> Result<CampaignApproval> {
        if now_unix >= self.expires_at {
            return Err(GestureError::Anchors(
                "la campagne a expiré pendant la cérémonie ; aucune transition ne sera signée"
                    .into(),
            ));
        }
        if self.approvals.len() != self.required() {
            return Err(GestureError::Anchors(format!(
                "cette campagne exige {} credential(s) distinct(s), {} confirmation(s) reçue(s)",
                self.required(),
                self.approvals.len()
            )));
        }
        Ok(CampaignApproval {
            campaign_id: self.campaign_id,
            campaign_fingerprint: self.fingerprint,
            required_credentials: self.required_credentials,
            approved_at: now_unix,
            approvals: self.approvals,
        })
    }
}
