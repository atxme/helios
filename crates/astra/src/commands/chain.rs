//! The four-campaign certificate chain of §7.6, and the plan that orders it.
//!
//! The chain drives the ordinary commands rather than duplicating them: the
//! issuer step is `issuer request`, the gateway step is `gateway-identity
//! open`, and the two remaining steps resolve their rows the way `campaign
//! open` does. What lives here is the plan on disk, the step it points at, and
//! the observation that the previous step has landed.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use astra::registry::AstraRegistry;

use super::campaign::{client_tls_ca_row, fleet_leaf_rows};
use super::gateway_identity::gateway_identity_open;
use super::issuer::issuer_request;
use crate::campaign_deposit::{fresh_id, open_campaign};
use crate::{now_unix, REGISTRY_FILE};

fn chain_plan_path(state_dir: &Path) -> PathBuf {
    state_dir.join(astra::chain::CHAIN_PLAN_FILE)
}

fn load_chain_plan(state_dir: &Path) -> Result<astra::chain::ChainPlan> {
    let path = chain_plan_path(state_dir);
    let raw = std::fs::read(&path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => anyhow::anyhow!(
            "no certificate chain is open in {}: `astra chain open` starts one",
            state_dir.display()
        ),
        _ => anyhow::Error::new(error).context(format!("reading {}", path.display())),
    })?;
    let plan: astra::chain::ChainPlan =
        serde_json::from_slice(&raw).with_context(|| format!("decoding {}", path.display()))?;
    plan.validate()?;
    Ok(plan)
}

/// Writes the plan where a crash leaves either the old one or the new one.
///
/// The plan is what keeps the four campaigns in order, so a half-written file
/// would leave the chain unable to say which step it is on — and the next
/// command would resolve a campaign against a domain it cannot describe.
fn save_chain_plan(state_dir: &Path, plan: &astra::chain::ChainPlan) -> Result<()> {
    let path = chain_plan_path(state_dir);
    let temporary = path.with_extension("tmp");
    std::fs::write(
        &temporary,
        serde_json::to_vec_pretty(plan).context("encoding the certificate chain plan")?,
    )
    .with_context(|| format!("writing {}", temporary.display()))?;
    std::fs::rename(&temporary, &path).with_context(|| format!("publishing {}", path.display()))
}

/// Deposits the campaign of the step the plan currently points at.
fn chain_deposit_current(
    state_dir: &Path,
    plan: &mut astra::chain::ChainPlan,
    gateway_channel: Option<SocketAddr>,
    gateway_certificate: Option<&str>,
    issuer_request_out: Option<&Path>,
) -> Result<()> {
    use aether::certificates::status::CampaignScope;

    let Some(step) = plan.pending() else {
        return Err(astra::chain::ChainError::Finished.into());
    };
    let scope = step.scope;
    let (reason, requested_by, window_secs) = (
        plan.reason.clone(),
        plan.requested_by.clone(),
        plan.window_secs,
    );

    let deposited = match scope {
        // The delegation's target does not exist until this call creates it:
        // the epoch, the ML-DSA-87 key and the PKCS#10 request are produced
        // here, beside the private halves they name.
        CampaignScope::IssuerDelegation => issuer_request(
            state_dir,
            issuer_request_out,
            Some((reason.as_str(), requested_by.as_str())),
            window_secs,
        )?
        .context("the issuer step deposited no campaign")?,
        // Read live from the daemon that serves the leaves: this registry has
        // never held them, and a retyped value would produce a campaign the
        // companion signs and the gateway then refuses.
        CampaignScope::GatewayIdentity => {
            let channel = gateway_channel.context(
                "--gateway-channel is required for the gateway identity step: the campaign is \
                 resolved from the leaves the daemon actually serves",
            )?;
            let certificate = gateway_certificate
                .context("--gateway-certificate is required for the gateway identity step")?;
            gateway_identity_open(
                state_dir,
                &reason,
                &requested_by,
                window_secs,
                channel,
                certificate,
            )?
        }
        scope => {
            let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
                .context("loading the Astra registry")?;
            let state = registry.state();
            let targets = match scope {
                // The chain covers the client TLS anchor and **not** `CA-PQ`
                // (§7.6). Leaving the `CA-PQ` row out is what carries that
                // exclusion: `covers_authority_object` matches on the
                // certificate kind, so this campaign refuses a `CA-PQ`
                // transition by construction.
                CampaignScope::TrustAuthorities => {
                    client_tls_ca_row(state).map(|row| vec![row]).context(
                        "this domain pins no client TLS anchor: `astra pin-ca-tls` records it \
                         once, and a rotation cannot be checked without it",
                    )?
                }
                _ => fleet_leaf_rows(state),
            };
            if targets.is_empty() {
                anyhow::bail!(
                    "no admitted peer in this registry: the fleet step has nothing for an \
                     operator to approve"
                );
            }
            let deposited = open_campaign(
                state_dir,
                state,
                scope,
                targets,
                &reason,
                &requested_by,
                window_secs,
            )?;
            println!("{}", deposited.operation_id.to_hex());
            eprintln!("empreinte de campagne : {}", deposited.fingerprint);
            eprintln!(
                "approuver depuis le poste opérateur :\n  astra-signer approve-campaign \\\n    \
                 --authority-url {} \\\n    --operation-id {}",
                state.authority_url,
                deposited.operation_id.to_hex()
            );
            deposited
        }
    };

    plan.record_deposit(
        deposited.operation_id,
        deposited.campaign_id,
        deposited.fingerprint,
        now_unix(),
    )?;
    save_chain_plan(state_dir, plan)
}

fn print_chain_plan(plan: &astra::chain::ChainPlan) {
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
    let path = chain_plan_path(state_dir);
    if path.exists() {
        let existing = load_chain_plan(state_dir)?;
        anyhow::bail!(
            "a certificate chain is already open in {} with {} step(s) left: finish it with \
             `astra chain next`, or drop it with `astra chain abandon`",
            state_dir.display(),
            existing.remaining()
        );
    }

    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let mut plan = astra::chain::ChainPlan::resolve(
        fresh_id()?,
        registry.state(),
        reason.trim().to_string(),
        requested_by.trim().to_string(),
        window_secs,
        now_unix(),
    );
    drop(registry);

    chain_deposit_current(state_dir, &mut plan, None, None, issuer_request_out)?;
    eprintln!(
        "chaîne ouverte : quatre campagnes, quatre touchers. `astra chain next` dépose la \
         suivante une fois celle-ci prise en compte."
    );
    print_chain_plan(&plan);
    Ok(())
}

pub(crate) fn chain_next(
    state_dir: &Path,
    gateway_channel: Option<SocketAddr>,
    gateway_certificate: Option<&str>,
    issuer_request_out: Option<&Path>,
) -> Result<()> {
    let mut plan = load_chain_plan(state_dir)?;
    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    plan.assert_current_landed(registry.state())?;
    drop(registry);

    plan.advance();
    if plan.pending().is_none() {
        std::fs::remove_file(chain_plan_path(state_dir))
            .with_context(|| format!("removing {}", chain_plan_path(state_dir).display()))?;
        eprintln!(
            "chaîne terminée. La dernière étape autorise des rotations clientes : chaque pair la \
             dépense en revenant, dans la fenêtre de campagne, et l'autorité ne l'observe pas."
        );
        return Ok(());
    }
    save_chain_plan(state_dir, &plan)?;
    chain_deposit_current(
        state_dir,
        &mut plan,
        gateway_channel,
        gateway_certificate,
        issuer_request_out,
    )?;
    print_chain_plan(&plan);
    Ok(())
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
    let plan = load_chain_plan(state_dir)?;
    std::fs::remove_file(chain_plan_path(state_dir))
        .with_context(|| format!("removing {}", chain_plan_path(state_dir).display()))?;
    eprintln!(
        "chaîne {} abandonnée après {} étape(s). Ce qui a déjà été approuvé garde son effet : \
         une campagne dépensée ne se reprend pas.",
        plan.chain_id.to_hex(),
        plan.current
    );
    Ok(())
}
