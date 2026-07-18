use async_trait::async_trait;
use aether::{FirewallPolicy, Result, TunnelState};
use tracing::info;

use crate::ruleset::{render, ChainKind};
use crate::FirewallBackend;

/// Backend qui journalise le jeu de règles sans toucher au kernel.
///
/// C'est le backend par défaut sur WSL2 : il permet de valider toute la logique
/// d'orchestration (transitions, rendu de règles) sans nf_tables.
pub struct DryRunBackend;

#[async_trait]
impl FirewallBackend for DryRunBackend {
    async fn apply(&self, policy: &FirewallPolicy, state: TunnelState) -> Result<()> {
        let rs = render(policy, state);
        info!(
            "table inet helios (politique par défaut : {:?}) — état tunnel {:?}",
            rs.default_verdict, state
        );
        for kind in [ChainKind::Input, ChainKind::Forward, ChainKind::Output] {
            for rule in rs.chain(kind) {
                info!("  [{}] {}", kind.as_str(), rule);
            }
        }
        if let Some(mss) = rs.mss_clamp {
            info!("  (mangle) MSS clamping = {mss}");
        }
        Ok(())
    }

    async fn teardown(&self) -> Result<()> {
        info!("[dry-run] suppression de la table inet helios");
        Ok(())
    }
}
