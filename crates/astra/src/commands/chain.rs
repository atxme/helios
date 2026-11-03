//! The four-campaign certificate chain of §7.6, driven through the door.
//!
//! The service resolves each step, opens it and keeps the plan in the state
//! volume (`astra::door`). Each step prints what the ordinary command for its
//! campaign prints — the issuer step is `issuer request`, the gateway step is
//! `gateway-identity open`, the two others are `campaign open`'s lines — and
//! then the plan.
//!
//! `chain status` is a read, and reads the plan and the registry from disk:
//! it opens nothing, writes nothing, and works with the service stopped.

use std::path::{Path, PathBuf};

use aether::certificates::status::CampaignScope;
use anyhow::{Context, Result};
use astra::chain::ChainPlan;
use astra::door::{DoorOutcome, DoorRequest, Opening};
use astra::registry::AstraRegistry;

use super::campaign::print_approval;
use super::gateway_identity::print_gateway_identity;
use super::issuer::{print_issuer_request, RequestOut};
use crate::{console, REGISTRY_FILE};

fn chain_plan_path(state_dir: &Path) -> PathBuf {
    state_dir.join(astra::chain::CHAIN_PLAN_FILE)
}

fn load_chain_plan(state_dir: &Path) -> Result<ChainPlan> {
    let path = chain_plan_path(state_dir);
    let raw = std::fs::read(&path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => anyhow::anyhow!(
            "no certificate chain is open in {}: `astra chain open` starts one",
            state_dir.display()
        ),
        _ => anyhow::Error::new(error).context(format!("reading {}", path.display())),
    })?;
    let plan: ChainPlan =
        serde_json::from_slice(&raw).with_context(|| format!("decoding {}", path.display()))?;
    plan.validate()?;
    Ok(plan)
}

/// What the step just opened prints, by the campaign it is.
fn print_step(
    state_dir: &Path,
    plan: &ChainPlan,
    opening: &Opening,
    delegation_request: Option<&str>,
    issuer_request_out: Option<RequestOut<'_>>,
) -> Result<()> {
    match opening.opened.scope {
        CampaignScope::IssuerDelegation => print_issuer_request(
            issuer_request_out,
            delegation_request.context("the door answered the issuer step without its request")?,
            Some(opening),
        ),
        CampaignScope::GatewayIdentity => {
            print_gateway_identity(state_dir, opening, plan.window_secs)
        }
        _ => {
            println!("{}", opening.opened.operation_id.to_hex());
            print_approval(opening);
            Ok(())
        }
    }
}

fn print_chain_plan(plan: &ChainPlan) {
    eprintln!("chaîne           : {}", plan.chain_id.to_hex());
    eprintln!("motif            : {}", plan.reason);
    eprintln!("demandée par     : {}", plan.requested_by);
    for (index, step) in plan.steps.iter().enumerate() {
        let mark = match index.cmp(&plan.current) {
            std::cmp::Ordering::Less => "fait",
            std::cmp::Ordering::Equal => "en cours",
            std::cmp::Ordering::Greater => "à venir",
        };
        eprintln!(
            "  {}. {:<26} {:<9} {} credential(s){}",
            index + 1,
            step.label(),
            mark,
            step.scope.required_credentials(),
            match step.operation_id {
                Some(id) => format!(" — opération {}", id.to_hex()),
                None => String::new(),
            }
        );
    }
}

pub(crate) fn chain_open(
    state_dir: &Path,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
    issuer_request_out: Option<&Path>,
) -> Result<()> {
    let text = console::opening_text(reason, requested_by, window_secs);
    // Before the door, as `issuer request` does: the step it opens may be
    // the delegation, whose request has to land somewhere.
    let issuer_request_out = issuer_request_out.map(RequestOut::open).transpose()?;
    let outcome = console::open(state_dir, DoorRequest::ChainOpen { text })?;
    let DoorOutcome::ChainStep {
        opened: Some(opening),
        delegation_request,
        plan: Some(plan),
        ..
    } = &outcome
    else {
        return Err(console::unexpected(&outcome));
    };
    print_step(
        state_dir,
        plan,
        opening,
        delegation_request.as_deref(),
        issuer_request_out,
    )?;
    eprintln!(
        "chaîne ouverte : quatre campagnes, quatre touchers. `astra chain next` dépose la \
         suivante une fois celle-ci prise en compte."
    );
    print_chain_plan(plan);
    Ok(())
}

pub(crate) fn chain_next(state_dir: &Path, issuer_request_out: Option<&Path>) -> Result<()> {
    let issuer_request_out = issuer_request_out.map(RequestOut::open).transpose()?;
    let outcome = console::open(state_dir, DoorRequest::ChainNext {})?;
    match &outcome {
        DoorOutcome::ChainStep { opened: None, .. } => {
            eprintln!(
                "chaîne terminée. La dernière étape autorise des rotations clientes : chaque pair la \
                 dépense en revenant, dans la fenêtre de campagne, et l'autorité ne l'observe pas."
            );
            Ok(())
        }
        DoorOutcome::ChainStep {
            opened: Some(opening),
            delegation_request,
            plan: Some(plan),
            ..
        } => {
            print_step(
                state_dir,
                plan,
                opening,
                delegation_request.as_deref(),
                issuer_request_out,
            )?;
            print_chain_plan(plan);
            Ok(())
        }
        _ => Err(console::unexpected(&outcome)),
    }
}

pub(crate) fn chain_status(state_dir: &Path) -> Result<()> {
    let plan = load_chain_plan(state_dir)?;
    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    print_chain_plan(&plan);
    match plan.assert_current_landed(registry.state()) {
        Ok(()) => eprintln!("étape en cours   : prête pour `astra chain next`"),
        Err(error) => eprintln!("étape en cours   : {error}"),
    }
    Ok(())
}

pub(crate) fn chain_abandon(state_dir: &Path) -> Result<()> {
    let outcome = console::open(state_dir, DoorRequest::ChainAbandon {})?;
    let DoorOutcome::ChainAbandoned { plan } = &outcome else {
        return Err(console::unexpected(&outcome));
    };
    eprintln!(
        "chaîne {} abandonnée après {} étape(s). Ce qui a déjà été approuvé garde son effet : \
         une campagne dépensée ne se reprend pas.",
        plan.chain_id.to_hex(),
        plan.current
    );
    Ok(())
}
