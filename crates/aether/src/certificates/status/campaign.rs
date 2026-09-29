//! Operator campaigns: their scope, their targets and the fingerprint an
//! operator approves as a whole.

use super::*;

/// What a manual campaign covers (spec §7.6).
///
/// The names are the ones the interfaces must show. No short label may
/// conflate [`Self::TrustAuthorities`] or [`Self::GatewayBootstrap`] with an
/// ordinary renewal: both require two operator credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignScope {
    /// One Orion profile.
    OrionProfile,
    /// Every Helios profile present on one device.
    OrionDevice,
    /// The fleet's client leaves. Rotates no authority.
    FleetLeafs,
    /// Issuer, TLS CA, gateway and client leaves — but not `CA-PQ`.
    FullCertificateChain,
    /// `CA-PQ` and `CA-TLS`. Two operator credentials.
    TrustAuthorities,
    /// Emergency withdrawal of one identity's active leaves (spec §10).
    EmergencyRevocation,
    /// The gateway's own identity: one transition, or its abort (spec §6).
    GatewayIdentity,
    /// Astra's delegated issuer: one bounded delegation (spec §9.5).
    IssuerDelegation,
    /// Initial gateway leaf, issued offline before Astra has a registry (§13.1).
    GatewayBootstrap,
}

/// Which family of signed objects a scope may produce.
///
/// # Why a family and not a set of booleans
///
/// Every predicate below reads as «may this scope do X». Asked one at a time,
/// they answer independently, and a scope added later inherits whatever the
/// negative form of a question happens to allow — the exact shape that once
/// let a revocation scope through a guard written as «not an authority». A
/// family is total: a new scope cannot be written without naming which
/// objects it authorizes, and every other family refuses it by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignFamily {
    /// Client leaves. The companion signs no trust-update object at all.
    ClientLeaves,
    /// Anchor transitions: `CA-PQ` and the client TLS CA.
    Authorities,
    /// The gateway's own identity, and the abort that cancels it (spec §6).
    GatewayIdentity,
    /// Emergency withdrawal of active leaves (spec §10).
    Revocation,
    /// The bounded delegation Astra issues under (spec §9.5).
    ///
    /// Its own family because the object it authorizes is not a
    /// [`crate::certificates::transport::TrustUpdateObject`] at all: a delegation is
    /// consumed by the authority that issues under it and verified by the
    /// holders against the anchor they already pin, so it is never
    /// distributed as a trust update. Folding it into any of the three above
    /// would let a campaign for one of them deliver it, or the reverse.
    IssuerDelegation,
    /// Initial admission of a gateway with no outgoing identity.
    GatewayBootstrap,
}

impl CampaignScope {
    pub(super) const fn domain_byte(self) -> u8 {
        match self {
            Self::OrionProfile => 0,
            Self::OrionDevice => 1,
            Self::FleetLeafs => 2,
            Self::FullCertificateChain => 3,
            Self::TrustAuthorities => 4,
            Self::EmergencyRevocation => 5,
            Self::GatewayIdentity => 6,
            Self::IssuerDelegation => 7,
            Self::GatewayBootstrap => 8,
        }
    }

    /// The one family of objects this scope authorizes.
    pub const fn family(self) -> CampaignFamily {
        match self {
            Self::OrionProfile
            | Self::OrionDevice
            | Self::FleetLeafs
            | Self::FullCertificateChain => CampaignFamily::ClientLeaves,
            Self::TrustAuthorities => CampaignFamily::Authorities,
            Self::EmergencyRevocation => CampaignFamily::Revocation,
            Self::GatewayIdentity => CampaignFamily::GatewayIdentity,
            Self::IssuerDelegation => CampaignFamily::IssuerDelegation,
            Self::GatewayBootstrap => CampaignFamily::GatewayBootstrap,
        }
    }

    /// Operator credentials this scope requires (spec §7.6, ADR-008 §4).
    pub const fn required_credentials(self) -> u8 {
        match self {
            Self::TrustAuthorities | Self::GatewayBootstrap => 2,
            _ => 1,
        }
    }

    /// Whether the scope rotates an anchor of the domain.
    pub const fn rotates_authority(self) -> bool {
        matches!(self, Self::TrustAuthorities)
    }

    /// Whether this scope authorizes renewing a client leaf.
    pub const fn authorizes_client_rotation(self) -> bool {
        matches!(
            self,
            Self::OrionProfile | Self::OrionDevice | Self::FleetLeafs | Self::FullCertificateChain
        )
    }

    /// Whether the companion must open the master vault for this scope.
    ///
    /// Not the same question as «does it replace an anchor». A revocation and
    /// a gateway transition are both signed **by** `CA-PQ` without replacing
    /// it, and a single predicate for the two questions would refuse the vault
    /// to a ceremony that cannot proceed without it.
    pub const fn opens_vault(self) -> bool {
        !matches!(self.family(), CampaignFamily::ClientLeaves)
    }

    /// Whether this scope withdraws leaves instead of renewing them.
    pub const fn revokes(self) -> bool {
        matches!(self, Self::EmergencyRevocation)
    }
}

/// One certified object a campaign will act on, pinned to its current state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignTarget {
    pub certificate_kind: CertificateKind,
    pub identity_key: WireGuardKey,
    pub epoch: u64,
    pub generation: u64,
    pub active_tls_certificate_fingerprint: Fingerprint,
    pub active_pq_certificate_fingerprint: Fingerprint,
}

/// A manual rotation campaign, frozen at approval time (spec §7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraRotationCampaign {
    pub format_version: u16,
    pub campaign_id: Id16,
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub scope: CampaignScope,
    pub targets: Vec<CampaignTarget>,
    pub reason: String,
    pub requested_by: String,
    pub policy_fingerprint: Fingerprint,
    pub required_credentials: u8,
}

impl AstraRotationCampaign {
    /// The canonical form the companion displays before asking for a touch.
    fn approval_bytes(&self) -> Vec<u8> {
        let mut bytes = CanonicalBytes::new(CAMPAIGN_APPROVAL_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.campaign_id)
            .id(&self.trust_domain_id)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .u64(self.created_at)
            .u64(self.expires_at)
            .u8(self.scope.domain_byte())
            .u64(self.targets.len() as u64);
        for target in &self.targets {
            bytes
                .u8(target.certificate_kind.domain_byte())
                .key(&target.identity_key)
                .u64(target.epoch)
                .u64(target.generation)
                .fingerprint(&target.active_tls_certificate_fingerprint)
                .fingerprint(&target.active_pq_certificate_fingerprint);
        }
        bytes
            .text(&self.reason)
            .text(&self.requested_by)
            .fingerprint(&self.policy_fingerprint)
            .u8(self.required_credentials);
        bytes.finish()
    }

    /// SHA-256 of the canonical campaign — the value the `CA-PQ` signature is
    /// bound to, and the one an operator reads on the companion's screen.
    ///
    /// Order is part of it: reordering the targets changes the fingerprint, so
    /// an approval cannot be reused for the same set applied differently.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.approval_bytes())
    }

    /// Structural checks, before an operator is asked for anything.
    pub fn validate(&self, now_unix: u64) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        // The chain is a **plan**, never one campaign (spec §7.6, §12.2). It
        // covers the issuer, the client TLS anchor, the gateway identity and
        // the fleet's leaves — four families — and `CampaignFamily` is total
        // so that no scope inherits another's authorization by omission. A
        // single campaign bearing this scope would have to claim one of the
        // four, and whichever it claimed would be an authorization for three
        // things the operator was never shown. It is refused here rather than
        // merely left unproduced: «nothing builds one» is a fact about today's
        // callers, and this is a rule about the document.
        if matches!(self.scope, CampaignScope::FullCertificateChain) {
            return Err(CertificateError::IssuerScopeViolation(
                "the full certificate chain is an ordered plan of campaigns, not one campaign",
            ));
        }
        if self.targets.is_empty() {
            return Err(CertificateError::EmptyTransition);
        }
        if matches!(self.scope, CampaignScope::GatewayBootstrap) {
            return Err(CertificateError::IssuerScopeViolation(
                "gateway bootstrap is an offline credential policy, not an Astra campaign",
            ));
        }
        if self.targets.len() > MAX_CAMPAIGN_TARGETS {
            return Err(CertificateError::TooManyObjects);
        }
        if self.scope.revokes() && self.targets.len() != 1 {
            return Err(CertificateError::CampaignMismatch);
        }
        if self.expires_at <= self.created_at || now_unix >= self.expires_at {
            return Err(CertificateError::InvalidLease);
        }
        // The policy is not advisory: a campaign that asks for fewer
        // credentials than its scope demands is refused rather than upgraded,
        // because the operator approved *this* text.
        if self.required_credentials != self.scope.required_credentials() {
            return Err(CertificateError::InsufficientApprovals {
                required: self.scope.required_credentials(),
                provided: self.required_credentials,
            });
        }
        // One decision per object. Two rows naming the same certificate would
        // make «what did the operator approve for this identity» a question of
        // iteration order, and `covers_client` below answers it by finding a
        // row — the first one it meets would silently win over a second that
        // pins other fingerprints.
        for (index, target) in self.targets.iter().enumerate() {
            if self.targets[..index].iter().any(|earlier| {
                earlier.certificate_kind == target.certificate_kind
                    && earlier.identity_key == target.identity_key
            }) {
                return Err(CertificateError::DuplicateFingerprint);
            }
        }
        Ok(())
    }

    /// The row that authorizes rotating one admitted client's generation.
    ///
    /// # Why the whole current state, and not just the key
    ///
    /// A campaign is frozen at approval: §7.6 makes the operator approve the
    /// targets *and their current fingerprints*. So a row only authorizes the
    /// rotation it described — the same identity one generation later is a
    /// different rotation, and re-using the approval for it would let one
    /// touch renew a peer indefinitely, once per generation, for as long as
    /// nobody noticed.
    ///
    /// A client generation is a TLS leaf and a PQ leaf that rotate together,
    /// so either kind names it and both fingerprints are pinned in both rows.
    /// A scope that rotates an anchor is refused outright: `trust_authorities`
    /// is a two-credential decision about `CA-PQ`, and reading it as a
    /// per-client authorization would spend it on something the operator was
    /// not shown.
    pub fn covers_client(
        &self,
        client_wg_public_key: &WireGuardKey,
        active_generation: u64,
        active_tls_certificate_fingerprint: &Fingerprint,
        active_pq_certificate_fingerprint: &Fingerprint,
    ) -> Result<(), CertificateError> {
        if !self.scope.authorizes_client_rotation() {
            return Err(CertificateError::IssuerScopeViolation(
                "this campaign does not authorize a client rotation",
            ));
        }
        let covered = self.targets.iter().any(|target| {
            matches!(
                target.certificate_kind,
                CertificateKind::ClientTls | CertificateKind::ClientPq
            ) && target.identity_key == *client_wg_public_key
                && target.generation == active_generation
                && target
                    .active_tls_certificate_fingerprint
                    .matches(active_tls_certificate_fingerprint)
                && target
                    .active_pq_certificate_fingerprint
                    .matches(active_pq_certificate_fingerprint)
        });
        if covered {
            Ok(())
        } else {
            Err(CertificateError::CampaignMismatch)
        }
    }

    /// Whether this campaign authorized one anchor transition (spec §0.6).
    ///
    /// The mirror of [`Self::covers_client`], and its opposite in both
    /// directions: only a scope that rotates an anchor may produce one of
    /// these, and the two object kinds accepted are exactly the two anchors
    /// [`CampaignScope::TrustAuthorities`] names — `CA-PQ` and `CA-TLS`.
    /// Anything else is refused rather than stored: an object nobody was shown
    /// would be an object the operator's touch did not approve.
    ///
    /// What is compared is the **outgoing** state, target by target, exactly
    /// as `covers_client` compares a client's. A transition leaving another
    /// epoch, or another anchor, is not the one the campaign named — even when
    /// its own signatures verify, because a valid object produced for a
    /// different starting point walks the domain somewhere nobody approved.
    pub fn covers_authority_object(
        &self,
        object: &crate::certificates::transport::TrustUpdateObject,
    ) -> Result<(), CertificateError> {
        use crate::certificates::transport::TrustUpdateObject;

        if !self.scope.rotates_authority() {
            return Err(CertificateError::IssuerScopeViolation(
                "only an authority campaign produces a transition object",
            ));
        }
        let (kind, trust_domain_id, epoch, current_fingerprint) = match object {
            TrustUpdateObject::CaTransition(transition) => (
                CertificateKind::CaPq,
                transition.trust_domain_id,
                transition.current_ca_epoch,
                transition.current_ca_fingerprint,
            ),
            TrustUpdateObject::ClientTlsCaTransition(transition) => (
                CertificateKind::CaTls,
                transition.trust_domain_id,
                transition.current_ca_tls_epoch,
                transition.active_client_tls_ca_fingerprint,
            ),
            _ => {
                return Err(CertificateError::IssuerScopeViolation(
                    "this object is not an anchor transition",
                ))
            }
        };
        if trust_domain_id != self.trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        let covered = self.targets.iter().any(|target| {
            target.certificate_kind == kind
                && target.identity_key == self.gateway_wg_public_key
                && target.epoch == epoch
                && target
                    .active_pq_certificate_fingerprint
                    .matches(&current_fingerprint)
        });
        if covered {
            Ok(())
        } else {
            Err(CertificateError::CampaignMismatch)
        }
    }

    /// Verifies that an emergency revocation names the exact identity state
    /// frozen into this campaign.
    pub fn covers_revocation(
        &self,
        revocation: &crate::certificates::revocation::EmergencyCertificateRevocation,
    ) -> Result<(), CertificateError> {
        use crate::certificates::revocation::RevocationScope;

        if !self.scope.revokes() {
            return Err(CertificateError::IssuerScopeViolation(
                "only a revocation campaign produces a revocation",
            ));
        }
        if revocation.trust_domain_id != self.trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        let (tls_kind, pq_kind) = match revocation.scope {
            RevocationScope::Gateway => (CertificateKind::GatewayTls, CertificateKind::GatewayPq),
            RevocationScope::Client => (CertificateKind::ClientTls, CertificateKind::ClientPq),
        };
        let covered = self.targets.iter().any(|target| {
            (target.certificate_kind == tls_kind || target.certificate_kind == pq_kind)
                && target.identity_key == revocation.identity_key
                && target
                    .epoch
                    .checked_add(1)
                    .is_some_and(|next| next == revocation.revocation_epoch)
                && revocation
                    .revoked_tls_fingerprint
                    .is_none_or(|fingerprint| {
                        target
                            .active_tls_certificate_fingerprint
                            .matches(&fingerprint)
                    })
                && revocation.revoked_pq_fingerprint.is_none_or(|fingerprint| {
                    target
                        .active_pq_certificate_fingerprint
                        .matches(&fingerprint)
                })
        });
        if covered {
            Ok(())
        } else {
            Err(CertificateError::CampaignMismatch)
        }
    }

    /// Verifies that a gateway transition moves the identity this campaign
    /// froze, one decision forward (spec §6.1, §11.1 step 3).
    ///
    /// The row pins the two leaves in service, so the transition is bound to
    /// the state the operator was shown. What the campaign deliberately does
    /// **not** pin is the leaf being installed: it does not exist when the
    /// campaign is opened, and `CA-PQ` is what certifies it. A substituted
    /// next leaf is refused at the gateway instead, which alone knows whether
    /// it holds the matching private half.
    pub fn covers_gateway_transition(
        &self,
        transition: &crate::certificates::gateway::GatewayIdentityTransition,
    ) -> Result<(), CertificateError> {
        let row = self.gateway_row(
            transition.trust_domain_id,
            &transition.gateway_wg_public_key,
            &transition.server_name,
            // One decision forward: the row names the last decision this
            // domain took, and a transition is the next one.
            transition
                .gateway_identity_epoch
                .checked_sub(1)
                .ok_or(CertificateError::CampaignMismatch)?,
        )?;
        let matches_state = row
            .active_tls_certificate_fingerprint
            .matches(&transition.active_gateway_tls_certificate_fingerprint)
            && row
                .active_pq_certificate_fingerprint
                .matches(&transition.active_gateway_certificate_fingerprint);
        if matches_state {
            Ok(())
        } else {
            Err(CertificateError::CampaignMismatch)
        }
    }

    /// Verifies that an abort cancels a transition of the identity this
    /// campaign froze (spec §6.3).
    ///
    /// # Why the epoch relation is not the transition's
    ///
    /// An abort campaign is opened **after** the transition was staged, when
    /// the decision epoch already *is* the epoch being cancelled. Reusing the
    /// «one forward» rule here would refuse every abort, and accepting either
    /// relation would let one approved row authorise two different decisions.
    ///
    /// # Why the leaves in service are not compared
    ///
    /// An abort names no leaf. It names the exact document it cancels, by
    /// fingerprint, under `CA-PQ` — which is narrower than the pair of active
    /// leaves would be, since a transition is unique where a leaf pair is
    /// shared by every decision taken while it is in service. The fingerprints
    /// on the row are still what the operator reads before the touch.
    pub fn covers_gateway_abort(
        &self,
        abort: &crate::certificates::gateway::GatewayTransitionAbort,
    ) -> Result<(), CertificateError> {
        self.gateway_row(
            abort.trust_domain_id,
            &abort.gateway_wg_public_key,
            &abort.server_name,
            abort.gateway_identity_epoch,
        )
        .map(|_| ())
    }

    /// The row authorizing a decision about the gateway's own identity.
    fn gateway_row(
        &self,
        trust_domain_id: TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        decision_epoch: u64,
    ) -> Result<&CampaignTarget, CertificateError> {
        if !matches!(self.scope.family(), CampaignFamily::GatewayIdentity) {
            return Err(CertificateError::IssuerScopeViolation(
                "only a gateway-identity campaign decides the gateway identity",
            ));
        }
        if trust_domain_id != self.trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        // Named twice, because a client pins both: an object for another
        // gateway carried under this approval would be a decision the operator
        // never read.
        if gateway_wg_public_key != &self.gateway_wg_public_key || server_name != self.server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        self.targets
            .iter()
            .find(|target| {
                (target.certificate_kind == CertificateKind::GatewayPq
                    || target.certificate_kind == CertificateKind::GatewayTls)
                    && target.identity_key == self.gateway_wg_public_key
                    && target.epoch == decision_epoch
            })
            .ok_or(CertificateError::CampaignMismatch)
    }

    /// The row authorizing one bounded delegation to Astra's issuer (§9.5).
    ///
    /// # Why the keys and not only the epoch
    ///
    /// A delegation request carries no signature of its own: it is a domain
    /// identifier, an epoch, an ML-DSA-87 public key and a PKCS#10 request,
    /// produced beside private halves that never leave the authority's state
    /// volume. Signed on its own, it would authorize whoever handed the
    /// operator a file. So what the campaign pins — and what the operator
    /// therefore reads before the touch — is the **exact material** that will
    /// be certified: substituting either half changes a fingerprint here and
    /// the approval no longer covers the request.
    ///
    /// The epoch must match for the reason
    /// [`crate::certificates::state::AstraIssuerState`] exists: a delegation
    /// reinstalled at a spent epoch would bring a withdrawn intermediate back
    /// under a signature that still verifies.
    pub fn covers_issuer_delegation(
        &self,
        trust_domain_id: TrustDomainId,
        issuer_epoch: u64,
        pq_issuer_public_key_fingerprint: &Fingerprint,
        tls_public_key_info_fingerprint: &Fingerprint,
    ) -> Result<(), CertificateError> {
        if !matches!(self.scope.family(), CampaignFamily::IssuerDelegation) {
            return Err(CertificateError::IssuerScopeViolation(
                "only an issuer-delegation campaign authorizes a delegation",
            ));
        }
        if trust_domain_id != self.trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        let covered = self.targets.iter().any(|target| {
            target.certificate_kind == CertificateKind::AstraIssuer
                && target.identity_key == self.gateway_wg_public_key
                && target.epoch == issuer_epoch
                && target
                    .active_pq_certificate_fingerprint
                    .matches(pq_issuer_public_key_fingerprint)
                && target
                    .active_tls_certificate_fingerprint
                    .matches(tls_public_key_info_fingerprint)
        });
        if covered {
            Ok(())
        } else {
            Err(CertificateError::CampaignMismatch)
        }
    }

    /// Refuses a campaign whose targets moved after approval (spec §7.6).
    pub fn assert_unchanged(
        &self,
        approved_fingerprint: &Fingerprint,
    ) -> Result<(), CertificateError> {
        if !self.fingerprint().matches(approved_fingerprint) {
            return Err(CertificateError::CampaignMismatch);
        }
        Ok(())
    }
}
