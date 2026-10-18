use aether::{FirewallPolicy, Result, TunnelState};
use async_trait::async_trait;
use tracing::info;

use crate::ruleset::{render, ChainKind};
use crate::{FirewallBackend, FirewallCapabilities};

/// Backend that logs the ruleset without touching the kernel.
///
/// This is the default backend on WSL2: it lets the orchestration logic
/// (transitions, rule rendering) be validated without nf_tables.
pub struct DryRunBackend;

#[async_trait]
impl FirewallBackend for DryRunBackend {
    fn capabilities(&self) -> FirewallCapabilities {
        FirewallCapabilities { mss_clamp: true }
    }

    async fn apply(&self, policy: &FirewallPolicy, state: TunnelState) -> Result<()> {
        let rs = render(policy, state)?;
        info!(
            "table inet helios (default policy: {:?}) — tunnel state {:?}",
            rs.default_verdict, state
        );
        for kind in [
            ChainKind::Prerouting,
            ChainKind::Input,
            ChainKind::Forward,
            ChainKind::Output,
        ] {
            for rule in rs.chain(kind) {
                info!("  [{}] {}", kind.as_str(), rule);
            }
        }
        for rule in rs.masquerade_rules() {
            info!("  [postrouting] {rule}  # client Internet egress");
        }
        for (family, mss) in rs.mss_clamps() {
            info!(
                "  (mangle) TCP SYN MSS clamping = {mss} for {family:?} crossing {}",
                rs.wg_iface
            );
        }
        Ok(())
    }

    async fn teardown(&self) -> Result<()> {
        info!("[dry-run] removing the inet helios table");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::PolicyMode;

    fn policy() -> FirewallPolicy {
        FirewallPolicy {
            wan_ifaces: vec!["eth0".into()],
            lan_ifaces: vec!["eth1".into()],
            wg_peers: vec!["203.0.113.10".into()],
            wg_listen_port: Some(51820),
            key_negotiation_port: Some(51821),
            mode: PolicyMode::FailClosed,
            allow_ssh_from: vec![],
            admin_ifaces: vec![],
            allow_dhcp_on_wan: false,
            allow_client_internet: true,
            allow_tunnel_icmp: true,
            allow_gateway_egress: true,
            allow_ssh_over_tunnel: true,
            iperf_port: None,
            wg_iface: "helios0".into(),
            admin_port: Some(8080),
            admin_iface: Some("helios0".into()),
            split_tunnel_cidrs: vec![],
            mss_clamp: Some(1360),
            captive_portal_gateway: None,
            nordvpn_meshnet: None,
        }
    }

    #[tokio::test]
    async fn applies_rendered_rules_and_tears_down_without_kernel_access() {
        let backend = DryRunBackend;

        backend.apply(&policy(), TunnelState::Up).await.unwrap();
        backend.teardown().await.unwrap();
    }

    #[tokio::test]
    async fn default_kill_switch_path_applies_the_down_state() {
        DryRunBackend.engage_kill_switch(&policy()).await.unwrap();
    }
}
