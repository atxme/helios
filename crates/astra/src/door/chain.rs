//! The four-campaign certificate chain of §7.6, driven from the service.
//!
//! The chain is a plan of four ordinary campaigns, each with its own family
//! and its own operator touch (`astra::chain`), and not one wider campaign:
//! `CampaignFamily` is total on purpose, so every family refuses the other
//! three in both directions, and a campaign carrying a *set* of families would
//! turn each of those guards into a subset check. §7.6 also bounds a window at
//! five minutes, so the later steps cannot be resolved up front: each is
//! resolved against the registry as it stands when its turn comes.
//!
//! «Taken effect» is read from the registry, not from an approval: a step
//! whose approval was taken but whose object never landed has not moved the
//! domain, and resolving the next campaign against it would freeze a state
//! nobody reached.
//!
//! Every step opens through [`open::open_campaign`], so the bounds and the
//! one-live-operation-per-family rule are the ones of every other opening.
//! The plan stays in the state volume under [`crate::chain::CHAIN_PLAN_FILE`],
//! and every command on it holds [`AstraService::volume_writes`].

use std::path::PathBuf;
use std::time::Duration;

use crate::chain::{ChainError, ChainPlan};
use aether::certificates::status::CampaignScope;
use aether::certificates::transport::OperatorChainView;

use super::open::{self, Resolved};
use super::{
    resolve, DoorConnector, DoorOutcome, DoorRefusal, Opening, OpeningText, VolumeWritesHeld,
};
use crate::service::AstraService;

fn plan_path(service: &AstraService) -> PathBuf {
    service.state_dir.join(crate::chain::CHAIN_PLAN_FILE)
}

fn load_plan(service: &AstraService) -> Result<Option<ChainPlan>, DoorRefusal> {
    let path = plan_path(service);
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            tracing::error!(%error, path = %path.display(), "the door could not read the chain plan");
            return Err(DoorRefusal::Internal);
        }
    };
    let plan: ChainPlan = serde_json::from_slice(&raw).map_err(|error| {
        tracing::error!(%error, path = %path.display(), "the door could not decode the chain plan");
        DoorRefusal::Internal
    })?;
    plan.validate().map_err(|error| {
        tracing::error!(%error, path = %path.display(), "the chain plan is not usable");
        DoorRefusal::Internal
    })?;
    Ok(Some(plan))
}

/// The chain the status names: its steps, the step awaiting its effect, and
/// the campaign deposited for it. A plan that cannot be read is logged by
/// `load_plan` and reads as no chain, so the status still answers.
pub(crate) fn chain_view(service: &AstraService) -> Option<OperatorChainView> {
    let plan = load_plan(service).ok()??;
    Some(OperatorChainView {
        steps: plan.steps.iter().map(|step| step.scope).collect(),
        current: plan.current,
        operation_id: plan
            .steps
            .get(plan.current)
            .and_then(|step| step.operation_id),
    })
}

/// Writes the plan where a crash leaves either the old one or the new one.
///
/// The plan is what keeps the four campaigns in order, so a half-written file
/// would leave the chain unable to say which step it is on — and the next
/// command would resolve a campaign against a domain it cannot describe.
fn save_plan(service: &AstraService, plan: &ChainPlan) -> Result<(), DoorRefusal> {
    let path = plan_path(service);
    let temporary = path.with_extension("tmp");
    let encoded = serde_json::to_vec_pretty(plan).map_err(|error| {
        tracing::error!(%error, "the door could not encode the chain plan");
        DoorRefusal::Internal
    })?;
    std::fs::write(&temporary, encoded)
        .and_then(|()| std::fs::rename(&temporary, &path))
        .map_err(|error| {
            tracing::error!(%error, path = %path.display(), "the door could not write the chain plan");
            DoorRefusal::Internal
        })
}

fn remove_plan(service: &AstraService) -> Result<(), DoorRefusal> {
    let path = plan_path(service);
    std::fs::remove_file(&path).map_err(|error| {
        tracing::error!(%error, path = %path.display(), "the door could not remove the chain plan");
        DoorRefusal::Internal
    })
}

/// A plan error, as the refusal the console reads.
fn plan_refusal(error: ChainError) -> DoorRefusal {
    match error {
        ChainError::NoPlan => DoorRefusal::NoChain,
        ChainError::AlreadyOpen(remaining) => DoorRefusal::ChainAlreadyOpen { remaining },
        ChainError::Finished => DoorRefusal::ChainFinished,
        ChainError::StepIncomplete { .. } => DoorRefusal::ChainStepIncomplete(error.to_string()),
        ChainError::UnsupportedFormatVersion { .. } => {
            tracing::error!(%error, "the chain plan cannot be used");
            DoorRefusal::Internal
        }
    }
}

impl AstraService {
    /// Resolves the chain and opens its first campaign.
    pub(super) async fn chain_open(
        &self,
        connector: &DoorConnector,
        text: OpeningText,
        now_unix: u64,
        gateway_bound: Duration,
    ) -> Result<DoorOutcome, DoorRefusal> {
        open::check_text(&text)?;
        let volume = self.volume_writes.lock().await;
        if let Some(existing) = load_plan(self)? {
            return Err(DoorRefusal::ChainAlreadyOpen {
                remaining: existing.remaining(),
            });
        }
        let chain_id = open::fresh_id()?;
        let plan = {
            let registry = self.registry.lock().await;
            ChainPlan::resolve(
                chain_id,
                registry.state(),
                text.reason.trim().to_string(),
                text.requested_by.trim().to_string(),
                text.window_secs,
                now_unix,
            )
        };
        self.chain_deposit_current(&volume, connector, plan, now_unix, gateway_bound)
            .await
    }

    /// Opens the next campaign, once the previous one has taken effect.
    pub(super) async fn chain_next(
        &self,
        connector: &DoorConnector,
        now_unix: u64,
        gateway_bound: Duration,
    ) -> Result<DoorOutcome, DoorRefusal> {
        let volume = self.volume_writes.lock().await;
        let mut plan = load_plan(self)?.ok_or(DoorRefusal::NoChain)?;
        {
            let registry = self.registry.lock().await;
            plan.assert_current_landed(registry.state())
                .map_err(plan_refusal)?;
        }
        // Advanced in memory only, and saved with the deposit: a refused
        // deposit leaves the plan on the step it was on, so the retry asks
        // the same question again instead of walking past a step that never
        // opened.
        plan.advance();
        if plan.pending().is_none() {
            remove_plan(self)?;
            return Ok(DoorOutcome::ChainStep {
                opened: None,
                delegation_request: None,
                remaining: 0,
                plan: None,
            });
        }
        self.chain_deposit_current(&volume, connector, plan, now_unix, gateway_bound)
            .await
    }

    /// Drops the plan. Campaigns already approved keep their effect: a
    /// campaign spent does not come back.
    pub(super) async fn chain_abandon(&self) -> Result<DoorOutcome, DoorRefusal> {
        let _volume = self.volume_writes.lock().await;
        let plan = load_plan(self)?.ok_or(DoorRefusal::NoChain)?;
        remove_plan(self)?;
        Ok(DoorOutcome::ChainAbandoned { plan })
    }

    /// Opens the campaign of the step the plan currently points at, records
    /// it, and saves the plan.
    async fn chain_deposit_current(
        &self,
        volume: &VolumeWritesHeld<'_>,
        connector: &DoorConnector,
        mut plan: ChainPlan,
        now_unix: u64,
        gateway_bound: Duration,
    ) -> Result<DoorOutcome, DoorRefusal> {
        let scope = plan.pending().ok_or(DoorRefusal::ChainFinished)?.scope;
        let text = OpeningText {
            reason: plan.reason.clone(),
            requested_by: plan.requested_by.clone(),
            window_secs: plan.window_secs,
        };
        let (opening, delegation_request): (Opening, Option<String>) = match scope {
            // The delegation's target does not exist until this call creates
            // it: the epoch, the ML-DSA-87 key and the PKCS#10 request are
            // produced here, beside the private halves they name.
            CampaignScope::IssuerDelegation => {
                let (request, opening) = self
                    .open_issuer_delegation(volume, connector, text, now_unix)
                    .await?;
                (opening, Some(request))
            }
            // Read live from the daemon that serves the leaves: this registry
            // has never held them, and a retyped value would produce a
            // campaign the companion signs and the gateway then refuses.
            CampaignScope::GatewayIdentity => (
                self.open_gateway_identity(connector, text, now_unix, gateway_bound)
                    .await?,
                None,
            ),
            // The chain covers the client TLS anchor and **not** `CA-PQ`
            // (§7.6). Leaving the `CA-PQ` row out is what carries that
            // exclusion: `covers_authority_object` matches on the certificate
            // kind, so this campaign refuses a `CA-PQ` transition by
            // construction.
            CampaignScope::TrustAuthorities => (
                open::open_campaign(
                    self,
                    connector,
                    scope,
                    text,
                    |state| {
                        resolve::client_tls_ca_row(state)
                            .map(|row| Resolved::targets(vec![row]))
                            .ok_or(DoorRefusal::NoClientTlsAnchor)
                    },
                    now_unix,
                )
                .await?,
                None,
            ),
            CampaignScope::FleetLeafs => (
                open::open_campaign(
                    self,
                    connector,
                    scope,
                    text,
                    |state| Ok(Resolved::targets(resolve::fleet_leaf_rows(state))),
                    now_unix,
                )
                .await?,
                None,
            ),
            _ => {
                tracing::error!(
                    ?scope,
                    "the chain plan names a scope the chain does not open"
                );
                return Err(DoorRefusal::Internal);
            }
        };
        plan.record_deposit(
            opening.opened.operation_id,
            opening.opened.campaign_id,
            opening.opened.campaign_fingerprint,
            now_unix,
        )
        .map_err(plan_refusal)?;
        save_plan(self, &plan)?;
        Ok(DoorOutcome::ChainStep {
            opened: Some(opening),
            delegation_request,
            remaining: plan.remaining(),
            plan: Some(plan),
        })
    }
}
