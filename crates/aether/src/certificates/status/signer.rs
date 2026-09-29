//! What the companion receives and returns: the signer request and the
//! signer result.

use super::*;

/// What the companion deposits once a campaign has been approved (spec §0.6).
///
/// # Why the objects travel with the approval and not after it
///
/// §0.6 has the companion open the vault and return the transition objects
/// **once**, bound to the campaign. Delivering them in a second call would
/// leave a window in which Astra holds an approval that authorizes objects it
/// does not have — and no way to tell that state apart from a campaign whose
/// operator walked away. One deposit, one decision: either the whole result
/// verifies, or the campaign is still awaiting its operator.
///
/// # What is *not* here
///
/// No private key, no PRF output, no vault. The objects carry their own
/// `CA-PQ` signatures, produced inside the companion and never reproducible by
/// the online authority — which is precisely why Astra may persist and
/// redistribute them without ever being able to forge one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraSignerResult {
    pub format_version: u16,
    pub approval: Box<CampaignApproval>,
    /// The transition objects this campaign authorized, signed by `CA-PQ`.
    ///
    /// Empty for a campaign that rotates no anchor: a fleet campaign is an
    /// authorization to renew leaves, and the leaves are issued online by the
    /// delegated issuer as each client comes back.
    #[serde(default)]
    pub objects: Vec<crate::certificates::transport::TrustUpdateObject>,
    /// Credential bindings re-signed under the anchor being installed.
    ///
    /// Present exactly when an object replaces `CA-PQ`. Leaving it out would
    /// hand the domain a successor anchor and a registry of operator
    /// credentials that only the anchor it replaces can verify — every future
    /// approval would then fail, on the one path that repairs anything.
    #[serde(default)]
    pub credential_registry: Option<Box<crate::certificates::approval::CredentialRegistry>>,
    /// The bounded delegation an issuer campaign authorized (spec §9.5).
    ///
    /// Present exactly when the campaign's family is
    /// [`CampaignFamily::IssuerDelegation`], and absent everywhere else. It
    /// travels beside `objects` rather than inside them because it is not a
    /// trust update: no holder ever receives it, the authority issues under
    /// it, and everyone else verifies it against the anchor they already pin.
    #[serde(default)]
    pub issuer_authorization: Option<Box<crate::certificates::authority::AstraIssuerAuthorization>>,
}

impl AstraSignerResult {
    /// Everything this document is, as bytes, for the idempotency rule of §8.2.
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        let encoded =
            serde_json::to_vec(self).map_err(|_| CertificateError::InvalidAssertion("encoding"))?;
        Ok(Fingerprint::of(&encoded))
    }

    /// Checks the shape of the result against the campaign it answers.
    ///
    /// Shape only: every signature inside is verified by its own object's
    /// `verify`, against anchors the reader holds. What this decides is
    /// narrower and cannot be decided there — that each object belongs to this
    /// campaign, that no object arrives twice, and that a result carrying a
    /// successor anchor carries the credential registry that survives it.
    pub fn validate(&self, campaign: &AstraRotationCampaign) -> Result<(), CertificateError> {
        use crate::certificates::transport::TrustUpdateObject;

        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        self.approval
            .campaign_fingerprint
            .matches(&campaign.fingerprint())
            .then_some(())
            .ok_or(CertificateError::CampaignMismatch)?;
        if self.objects.len() > MAX_CAMPAIGN_OBJECTS {
            return Err(CertificateError::CampaignMismatch);
        }
        // One decision per ceremony for the two families that decide about a
        // single identity. A batch would make «which of these did the operator
        // approve» a question about ordering.
        if matches!(
            campaign.scope.family(),
            CampaignFamily::Revocation | CampaignFamily::GatewayIdentity
        ) && self.objects.len() != 1
        {
            return Err(CertificateError::CampaignMismatch);
        }
        // Total the other way too: exactly one family delivers a delegation,
        // and it delivers nothing else. Checked before the object loop, so a
        // delegation smuggled beside an anchor transition is refused by the
        // family rather than by whichever arm of the loop happened to run.
        match (campaign.scope.family(), &self.issuer_authorization) {
            (CampaignFamily::IssuerDelegation, Some(authorization)) => {
                if !self.objects.is_empty() || self.credential_registry.is_some() {
                    return Err(CertificateError::IssuerScopeViolation(
                        "an issuer campaign authorizes a delegation and nothing else",
                    ));
                }
                return campaign.covers_issuer_delegation(
                    authorization.trust_domain_id,
                    authorization.issuer_epoch,
                    &Fingerprint::of(authorization.pq_issuer_public_key.as_bytes()),
                    &Fingerprint::of(&crate::certificates::x509::subject_public_key_info(
                        &authorization.tls_intermediate_certificate,
                    )?),
                );
            }
            (CampaignFamily::IssuerDelegation, None) => {
                return Err(CertificateError::EmptyTransition);
            }
            (_, Some(_)) => {
                return Err(CertificateError::IssuerScopeViolation(
                    "only an issuer campaign delivers a delegation",
                ));
            }
            (_, None) => {}
        }
        if matches!(campaign.scope.family(), CampaignFamily::ClientLeaves) {
            // An ordinary leaf campaign has nothing for the companion to
            // sign. Accepting objects here would let it deliver a trust
            // mutation that the operator was never shown.
            return if self.objects.is_empty() && self.credential_registry.is_none() {
                Ok(())
            } else {
                Err(CertificateError::IssuerScopeViolation(
                    "this campaign authorizes no trust-update object",
                ))
            };
        }
        if self.objects.is_empty() {
            return Err(CertificateError::EmptyTransition);
        }

        let mut seen: Vec<Fingerprint> = Vec::with_capacity(self.objects.len());
        let mut replaces_ca_pq = false;
        for object in &self.objects {
            // Total in both directions: every family names the objects it
            // authorizes, and everything else falls into one refusal. A family
            // added later cannot inherit another's authorization by omission.
            match (campaign.scope.family(), object) {
                (
                    CampaignFamily::Revocation,
                    TrustUpdateObject::CertificateRevocation(revocation),
                ) => campaign.covers_revocation(revocation)?,
                (
                    CampaignFamily::Authorities,
                    TrustUpdateObject::CaTransition(_)
                    | TrustUpdateObject::ClientTlsCaTransition(_),
                ) => campaign.covers_authority_object(object)?,
                (
                    CampaignFamily::GatewayIdentity,
                    TrustUpdateObject::GatewayIdentityTransition(transition),
                ) => campaign.covers_gateway_transition(transition)?,
                (
                    CampaignFamily::GatewayIdentity,
                    TrustUpdateObject::GatewayTransitionAbort(abort),
                ) => campaign.covers_gateway_abort(abort)?,
                _ => {
                    return Err(CertificateError::IssuerScopeViolation(
                        "this object does not belong to the family its campaign approved",
                    ))
                }
            }
            let fingerprint = object.fingerprint()?;
            if seen.iter().any(|earlier| earlier.matches(&fingerprint)) {
                return Err(CertificateError::DuplicateFingerprint);
            }
            seen.push(fingerprint);
            replaces_ca_pq |= matches!(object, TrustUpdateObject::CaTransition(_));
        }
        match (replaces_ca_pq, self.credential_registry.is_some()) {
            (true, true) | (false, false) => Ok(()),
            (true, false) => Err(CertificateError::InvalidCredentialBinding(
                "a CA-PQ transition must carry the registry re-signed under its successor",
            )),
            (false, true) => Err(CertificateError::InvalidCredentialBinding(
                "no object replaces CA-PQ, so nothing re-signs the registry",
            )),
        }
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
    pub(super) fn signing_bytes(&self) -> SignedTranscript {
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
        bytes.finish_signed()
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
