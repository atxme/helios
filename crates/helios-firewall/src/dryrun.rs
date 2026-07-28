use aether::{FirewallPolicy, Result, TunnelState};
use async_trait::async_trait;
use tracing::info;

use crate::ruleset::{render, ChainKind};
use crate::FirewallBackend;

/// Backend that logs the ruleset without touching the kernel.
///
/// This is the default backend on WSL2: it lets the orchestration logic
/// (transitions, rule rendering) be validated without nf_tables.
pub struct DryRunBackend;

#[async_trait]
impl FirewallBackend for DryRunBackend {
    async fn apply(&self, policy: &FirewallPolicy, state: TunnelState) -> Result<()> {
        let rs = render(policy, state);
        info!(
            "table inet helios (default policy: {:?}) — tunnel state {:?}",
            rs.default_verdict, state
        );
        for kind in [ChainKind::Input, ChainKind::Forward, ChainKind::Output] {
            for rule in rs.chain(kind) {
                info!("  [{}] {}", kind.as_str(), rule);
            }
        }
        if let Some(out) = &rs.masquerade_out {
            info!("  [postrouting] oifname \"{out}\" masquerade  # client Internet egress");
        }
        if let Some(mss) = rs.mss_clamp {
            info!("  (mangle) MSS clamping = {mss}");
        }
        Ok(())
    }

    async fn teardown(&self) -> Result<()> {
        info!("[dry-run] removing the inet helios table");
        Ok(())
    }
}
