//! The full certificate chain, as an ordered plan of ordinary campaigns.
//!
//! `CampaignScope::FullCertificateChain` (spec §7.6) names one action covering
//! «émetteur, CA TLS, gateway et leafs clientes — mais pas `CA-PQ`». It is the
//! one scope no ceremony resolved, and the reason is structural rather than
//! missing work: those four things belong to **four different families**, and
//! [`aether::certificates::status::CampaignFamily`] is deliberately total —
//! every family refuses the other three in both directions, so that a scope
//! added later cannot inherit an authorization by omission.
//!
//! # Why a sequence and not one wider campaign
//!
//! Widening a campaign to carry a *set* of families would turn every guard
//! written as «this family and not the other three» into «this subset», and a
//! subset filled in wrongly is exactly the shape that model was written to
//! remove. So the chain is not a new kind of campaign. It is a **plan**: four
//! ordinary campaigns, in order, each with its own family, its own targets and
//! its own operator touch. Nothing in the approval path changes, and nothing
//! in it has to be relaxed.
//!
//! The price is four touches instead of one. That is the honest price of the
//! ordering: §7.6 bounds a campaign window at five minutes, so the later steps
//! could not be resolved up front anyway — each one is resolved against the
//! registry as it stands when its turn comes, which is also what makes the
//! operator's screen describe the domain they are actually about to change.
//!
//! # What «done» means for a step
//!
//! Not «the operator approved it». The plan lives in the state volume and
//! outlives the operations, which live in the service's memory for five
//! minutes at most — and asking whether an approval arrived would be the
//! weaker question anyway.
//! What [`ChainStep::completed_by`] checks is the **effect**: the issuer epoch
//! moved, the client TLS anchor has a successor, the gateway decision was
//! stored. A step whose approval was taken but whose object never landed is
//! not done, and the plan says so rather than walking past it.
//!
//! The last step, the fleet's client leaves, has no registry effect by
//! construction: a campaign authorizes rotations and each peer spends that
//! authorization when it comes back (§7.6). It therefore closes the plan when
//! it is opened, and the limit is the one that scope already carries.

use aether::certificates::{
    encoding::{Fingerprint, Id16},
    status::CampaignScope,
    CERTIFICATE_FORMAT_VERSION,
};

/// Where the chain plan lives in the state volume.
pub const CHAIN_PLAN_FILE: &str = "certificate-chain-plan.json";

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("no certificate chain is open in this state volume")]
    NoPlan,
    #[error("a certificate chain is already open: {0} steps remain")]
    AlreadyOpen(usize),
    #[error(
        "step {step} ({scope}) has not taken effect yet: {expected}. Approve it before advancing, \
         or abandon the chain."
    )]
    StepIncomplete {
        step: usize,
        scope: &'static str,
        expected: String,
    },
    #[error("this chain is finished; nothing remains to deposit")]
    Finished,
    #[error("unsupported chain plan format {received}, this build writes {supported}")]
    UnsupportedFormatVersion { received: u16, supported: u16 },
}

/// What the registry must show before a step counts as done.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ChainEffect {
    /// The delegated issuer's epoch must have moved past this value.
    IssuerEpochAbove { issuer_epoch: u64 },
    /// A client `CA-TLS` successor must be held, or the anchor already moved.
    ClientTlsCaSucceeds { ca_tls_epoch: u64 },
    /// A gateway identity decision must have been stored for this campaign.
    GatewayDecisionStored { campaign_id: Id16 },
    /// Nothing to observe here: the authorization is spent by the peers.
    ///
    /// Deliberately not «always true dressed as a check». It names the one
    /// step whose effect this authority cannot see, so that reading the plan
    /// tells an operator which promise it is not making.
    SpentByPeers,
}

impl ChainEffect {
    /// What an operator is told to look for, when a step has not landed.
    pub fn expected(&self) -> String {
        match self {
            Self::IssuerEpochAbove { issuer_epoch } => {
                format!("the delegated issuer is still at epoch {issuer_epoch}")
            }
            Self::ClientTlsCaSucceeds { ca_tls_epoch } => {
                format!("the client TLS anchor is still alone at epoch {ca_tls_epoch}")
            }
            Self::GatewayDecisionStored { campaign_id } => format!(
                "no gateway identity decision was stored for campaign {}",
                campaign_id.to_hex()
            ),
            Self::SpentByPeers => "nothing is observed for this step".to_string(),
        }
    }
}

/// One campaign of the chain, and the evidence that it landed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainStep {
    pub scope: CampaignScope,
    pub effect: ChainEffect,
    /// Filled when the step's campaign was deposited.
    pub operation_id: Option<Id16>,
    pub campaign_fingerprint: Option<Fingerprint>,
    pub deposited_at: Option<u64>,
}

impl ChainStep {
    fn new(scope: CampaignScope, effect: ChainEffect) -> Self {
        Self {
            scope,
            effect,
            operation_id: None,
            campaign_fingerprint: None,
            deposited_at: None,
        }
    }

    /// A short name for the operator's screen and for a refusal's text.
    pub const fn label(&self) -> &'static str {
        match self.scope {
            CampaignScope::IssuerDelegation => "issuer_delegation",
            CampaignScope::TrustAuthorities => "trust_authorities (CA-TLS)",
            CampaignScope::GatewayIdentity => "gateway_identity",
            CampaignScope::FleetLeafs => "fleet_leafs",
            CampaignScope::OrionProfile => "orion_profile",
            CampaignScope::OrionDevice => "orion_device",
            CampaignScope::FullCertificateChain => "full_certificate_chain",
            CampaignScope::EmergencyRevocation => "emergency_revocation",
            CampaignScope::GatewayBootstrap => "gateway_bootstrap",
        }
    }

    /// Whether the registry shows this step's effect.
    pub fn completed_by(&self, state: &crate::registry::AstraState) -> bool {
        match &self.effect {
            ChainEffect::IssuerEpochAbove { issuer_epoch } => state
                .issuer
                .as_ref()
                .is_some_and(|installed| installed.issuer_epoch > *issuer_epoch),
            ChainEffect::ClientTlsCaSucceeds { ca_tls_epoch } => {
                state.ca_tls_rotation.is_some() || state.ca_tls_epoch > *ca_tls_epoch
            }
            ChainEffect::GatewayDecisionStored { campaign_id } => {
                use aether::certificates::transport::TrustUpdateObject;
                state.transitions.iter().any(|stored| {
                    stored.campaign_id == *campaign_id
                        && matches!(
                            stored.object,
                            TrustUpdateObject::GatewayIdentityTransition(_)
                                | TrustUpdateObject::GatewayTransitionAbort(_)
                        )
                })
            }
            ChainEffect::SpentByPeers => true,
        }
    }
}

/// The ordered plan, as it is written beside the registry.
///
/// The order is the one §12.2 names and is not a preference: the delegated
/// issuer is what signs client leaves, the client TLS anchor is what those
/// leaves chain to, and the gateway identity is what every client pins. Doing
/// the leaves first would renew them under an issuer and an anchor about to be
/// replaced, and each peer would come back a second time.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainPlan {
    pub format_version: u16,
    pub chain_id: Id16,
    pub reason: String,
    pub requested_by: String,
    pub window_secs: u64,
    pub opened_at: u64,
    pub steps: Vec<ChainStep>,
    /// Index of the step awaiting deposit or completion.
    pub current: usize,
}

impl ChainPlan {
    /// Resolves the four steps against the domain as it stands right now.
    pub fn resolve(
        chain_id: Id16,
        state: &crate::registry::AstraState,
        reason: String,
        requested_by: String,
        window_secs: u64,
        opened_at: u64,
    ) -> Self {
        let issuer_epoch = state
            .issuer
            .as_ref()
            .map_or(0, |installed| installed.issuer_epoch);
        Self {
            format_version: CERTIFICATE_FORMAT_VERSION,
            chain_id,
            reason,
            requested_by,
            window_secs,
            opened_at,
            steps: vec![
                ChainStep::new(
                    CampaignScope::IssuerDelegation,
                    ChainEffect::IssuerEpochAbove { issuer_epoch },
                ),
                ChainStep::new(
                    CampaignScope::TrustAuthorities,
                    ChainEffect::ClientTlsCaSucceeds {
                        ca_tls_epoch: state.ca_tls_epoch,
                    },
                ),
                // Filled in when the step is deposited: a gateway decision is
                // recognized by the campaign that produced it, and that
                // campaign does not exist until its turn.
                ChainStep::new(
                    CampaignScope::GatewayIdentity,
                    ChainEffect::GatewayDecisionStored {
                        campaign_id: chain_id,
                    },
                ),
                ChainStep::new(CampaignScope::FleetLeafs, ChainEffect::SpentByPeers),
            ],
            current: 0,
        }
    }

    /// Structural check, before a plan read from disk is acted on.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(ChainError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        Ok(())
    }

    /// The step awaiting a deposit, or `None` when the chain is finished.
    pub fn pending(&self) -> Option<&ChainStep> {
        self.steps.get(self.current)
    }

    /// How many steps remain, the current one included.
    pub fn remaining(&self) -> usize {
        self.steps.len().saturating_sub(self.current)
    }

    /// Refuses to advance while the deposited step has not taken effect.
    ///
    /// A step that was never deposited is not «incomplete», it is the one to
    /// deposit now — which is what `open` does for the first and `next` does
    /// after each effect lands.
    pub fn assert_current_landed(
        &self,
        state: &crate::registry::AstraState,
    ) -> Result<(), ChainError> {
        let Some(step) = self.pending() else {
            return Err(ChainError::Finished);
        };
        if step.operation_id.is_none() || step.completed_by(state) {
            return Ok(());
        }
        Err(ChainError::StepIncomplete {
            step: self.current + 1,
            scope: step.label(),
            expected: step.effect.expected(),
        })
    }

    /// Records what a deposit produced for the current step.
    pub fn record_deposit(
        &mut self,
        operation_id: Id16,
        campaign_id: Id16,
        campaign_fingerprint: Fingerprint,
        now_unix: u64,
    ) -> Result<(), ChainError> {
        let index = self.current;
        let step = self.steps.get_mut(index).ok_or(ChainError::Finished)?;
        step.operation_id = Some(operation_id);
        step.campaign_fingerprint = Some(campaign_fingerprint);
        step.deposited_at = Some(now_unix);
        // The gateway step recognizes its own effect by the campaign that
        // produced it, and that identifier only exists once the campaign has
        // been resolved.
        if let ChainEffect::GatewayDecisionStored { campaign_id: slot } = &mut step.effect {
            *slot = campaign_id;
        }
        Ok(())
    }

    /// Moves past a step whose effect the registry shows.
    pub fn advance(&mut self) {
        self.current = self.current.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::{MlDsa87PublicKey, TrustDomainId, WireGuardKey};

    fn state() -> crate::registry::AstraState {
        crate::registry::AstraState {
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            server_name: "gateway.example".into(),
            authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: aether::certificates::AstraIssuancePolicy::standard(
                TrustDomainId::new([1; 16]).expect("domain"),
                WireGuardKey::from_bytes([2; 32]),
                "gateway.example".into(),
            )
            .pin()
            .expect("policy"),
            credential_registry_epoch: 1,
            ca_epoch: 1,
            ca_public_key: MlDsa87PublicKey::new(vec![0; 2592]).expect("key"),
            ca_rotation: None,
            ca_tls_epoch: 1,
            ca_tls_fingerprint: Some(Fingerprint::of(b"ca-tls")),
            ca_tls_rotation: None,
            astra_service_key_epoch: 1,
            astra_service_public_key: MlDsa87PublicKey::new(vec![1; 2592]).expect("key"),
            issuer: None,
            transitions: Vec::new(),
            peers: Default::default(),
            status_epochs: Default::default(),
            audit: Default::default(),
        }
    }

    fn plan(state: &crate::registry::AstraState) -> ChainPlan {
        ChainPlan::resolve(
            Id16::new([5; 16]).expect("id"),
            state,
            "renouvellement complet".into(),
            "operator".into(),
            300,
            1_000,
        )
    }

    /// The order is the contract: an anchor and an issuer before the leaves
    /// that chain to them, and `CA-PQ` in none of it (spec §7.6, §12.2).
    #[test]
    fn the_chain_orders_issuer_then_anchor_then_gateway_then_leaves() {
        let plan = plan(&state());
        let scopes: Vec<_> = plan.steps.iter().map(|step| step.scope).collect();
        assert_eq!(
            scopes,
            vec![
                CampaignScope::IssuerDelegation,
                CampaignScope::TrustAuthorities,
                CampaignScope::GatewayIdentity,
                CampaignScope::FleetLeafs,
            ]
        );
        // Four families, four touches, and every guard left as it was.
        let families: std::collections::BTreeSet<_> = scopes
            .iter()
            .map(|scope| format!("{:?}", scope.family()))
            .collect();
        assert_eq!(families.len(), 4);
    }

    /// A step that was deposited and never landed blocks the chain, rather
    /// than letting the next campaign be resolved against a domain that did
    /// not move.
    #[test]
    fn a_deposited_step_blocks_the_chain_until_its_effect_lands() {
        let mut state = state();
        let mut plan = plan(&state);

        // Nothing deposited yet: this is the step to deposit, not a stall.
        plan.assert_current_landed(&state).expect("first deposit");

        plan.record_deposit(
            Id16::new([6; 16]).expect("id"),
            Id16::new([7; 16]).expect("id"),
            Fingerprint::of(b"campaign"),
            1_050,
        )
        .expect("deposit recorded");
        assert!(matches!(
            plan.assert_current_landed(&state),
            Err(ChainError::StepIncomplete { step: 1, .. })
        ));

        state.issuer = Some(aether::certificates::state::AstraIssuerState {
            issuer_epoch: 1,
            authorization: issuer_authorization(),
            state: aether::certificates::state::IssuerLifecycle::Active,
        });
        plan.assert_current_landed(&state)
            .expect("the effect landed");
        plan.advance();
        assert_eq!(plan.remaining(), 3);
    }

    /// The gateway step recognizes its own decision, not any decision: a
    /// transition stored by an unrelated campaign does not close it.
    #[test]
    fn the_gateway_step_names_the_campaign_that_produced_its_decision() {
        let state = state();
        let mut plan = plan(&state);
        plan.current = 2;
        plan.record_deposit(
            Id16::new([6; 16]).expect("id"),
            Id16::new([9; 16]).expect("id"),
            Fingerprint::of(b"campaign"),
            1_100,
        )
        .expect("deposit recorded");
        let ChainEffect::GatewayDecisionStored { campaign_id } = &plan.steps[2].effect else {
            panic!("the gateway step observes a stored decision");
        };
        assert_eq!(
            campaign_id.to_hex(),
            Id16::new([9; 16]).expect("id").to_hex()
        );
    }

    /// The one step this authority cannot observe says so, instead of
    /// reporting a success it did not see.
    #[test]
    fn the_fleet_step_does_not_claim_an_effect_it_cannot_observe() {
        let state = state();
        let plan = plan(&state);
        assert!(matches!(plan.steps[3].effect, ChainEffect::SpentByPeers));
        assert!(plan.steps[3].completed_by(&state));
        assert!(plan.steps[3]
            .effect
            .expected()
            .contains("nothing is observed"));
    }

    fn issuer_authorization() -> aether::certificates::authority::AstraIssuerAuthorization {
        use aether::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};
        use aether::certificates::encoding::{DerCertificate, MlDsa87Signature};
        AstraIssuerAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            server_name: "gateway.example".into(),
            issuer_epoch: 1,
            pq_issuer_public_key: MlDsa87PublicKey::new(vec![3; 2592]).expect("key"),
            tls_intermediate_certificate: DerCertificate::new(vec![9; 64]).expect("der"),
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 100,
            policy_fingerprint: Fingerprint::of(b"policy"),
            not_before: 0,
            not_after: 100_000,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
    }
}
