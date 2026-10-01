//! The orchestrator's commands: what the API and the daemon ask of it.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_external_cmd(
    cmd: OrchestratorCmd,
    shared_network: &Arc<RwLock<NetworkConfig>>,
    dry_run: bool,
    wg: &dyn WireguardBackend,
    shared_state: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &mut FirewallPolicy,
    internal_tx: &mpsc::Sender<OrchestratorCmd>,
    shared_policy: &Arc<RwLock<FirewallPolicy>>,
    boot: &helios_tpm::BootDecision,
    shared_ipv6: &Arc<RwLock<Ipv6TunnelStatus>>,
) -> anyhow::Result<()> {
    match cmd {
        OrchestratorCmd::Connect => {
            info!("connection requested via the web interface");
            emit_log(
                event_tx,
                "info",
                "Connection requested via the web interface",
            );
            let network = shared_network.read().await;
            do_connect(
                &network,
                wg,
                shared_state,
                event_tx,
                fw,
                policy,
                dry_run,
                shared_ipv6,
            )
            .await?;
            let wan = network.primary_wan_iface().unwrap_or_default().to_string();
            drop(network);
            spawn_mtu_probe_if_up(&wan, dry_run, shared_state, event_tx, internal_tx).await;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::UpdateGatewayKey(new_key) => {
            // Identity rotation: seal first, apply only afterwards. Sealing
            // after bringing up the interface would leave a window where the
            // key in effect would not be the one that survives a restart.
            match crate::gateway_key::update_sealed(
                &*shared_network.read().await,
                boot,
                new_key.expose(),
            ) {
                Err(e) => {
                    warn!("WireGuard key rotation refused: {e}");
                    emit_log(event_tx, "error", &format!("Rotation refused: {e}"));
                }
                Ok(()) => {
                    {
                        let mut network = shared_network.write().await;
                        network.wg_private_key = new_key;
                    }
                    emit_log(
                        event_tx,
                        "warn",
                        "WireGuard key replaced and resealed — all clients \
                         must update the gateway's `peer_public_key`",
                    );

                    // The interface still carries the old identity: bring it back up.
                    if let Err(e) = wg.down().await {
                        warn!("tearing down before rotation: {e}");
                    }
                    let network = shared_network.read().await;
                    do_connect(
                        &network,
                        wg,
                        shared_state,
                        event_tx,
                        fw,
                        policy,
                        dry_run,
                        shared_ipv6,
                    )
                    .await?;
                    drop(network);
                    sync_policy(shared_policy, policy).await;
                }
            }
        }

        OrchestratorCmd::ApplyFirewallRules(rules) => {
            if dry_run {
                info!(
                    "[dry-run] custom nftables rules received ({} bytes) — not applied",
                    rules.len()
                );
                emit_log(
                    event_tx,
                    "info",
                    "[dry-run] Nftables rules received — application skipped (simulation mode)",
                );
            } else {
                info!("applying custom nftables rules ({} bytes)", rules.len());
                emit_log(
                    event_tx,
                    "warn",
                    "Custom nftables rules applied — check consistency",
                );
            }
        }

        OrchestratorCmd::Disconnect => {
            info!("disconnection requested via the web interface");
            emit_log(
                event_tx,
                "info",
                "Disconnection requested via the web interface",
            );
            policy.captive_portal_gateway = None;
            policy.mss_clamp = None;
            // Engage the fail-closed verdict before modifying the interface:
            // same order as a systemd stop for an update.
            transition(shared_state, event_tx, TunnelState::Down, fw, policy).await?;
            if let Err(e) = wg.down().await {
                warn!("tearing down the WireGuard interface: {e}");
                emit_log(
                    event_tx,
                    "warn",
                    &format!("Tearing down the interface: {e}"),
                );
            }
            unpin_peer_vips(dry_run).await;
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::AcknowledgeCaptivePortal => {
            let current = *shared_state.read().await;
            if current == TunnelState::CaptivePortal {
                info!("captive portal acknowledged by the user — reconnecting");
                emit_log(
                    event_tx,
                    "info",
                    "Captive portal acknowledged — attempting to reconnect…",
                );
                policy.captive_portal_gateway = None;
                let next = current.on(TunnelEvent::CaptivePortalResolved)?;
                transition(shared_state, event_tx, next, fw, policy).await?;
                sync_policy(shared_policy, policy).await;
                let network = shared_network.read().await;
                do_connect(
                    &network,
                    wg,
                    shared_state,
                    event_tx,
                    fw,
                    policy,
                    dry_run,
                    shared_ipv6,
                )
                .await?;
                let wan = network.primary_wan_iface().unwrap_or_default().to_string();
                drop(network);
                spawn_mtu_probe_if_up(&wan, dry_run, shared_state, event_tx, internal_tx).await;
                sync_policy(shared_policy, policy).await;
            }
        }

        OrchestratorCmd::SetSplitTunnel(cidrs) => {
            info!("split-tunneling updated: {} CIDR(s)", cidrs.len());
            policy.split_tunnel_cidrs = cidrs.clone();
            let state = *shared_state.read().await;
            fw.apply(policy, state)
                .await
                .context("firewall split-tunnel")?;
            let _ = event_tx.send(HeliosEvent::SplitTunnelChanged { cidrs });
            sync_policy(shared_policy, policy).await;
        }

        OrchestratorCmd::SetMssClamp(mss) => {
            let state = *shared_state.read().await;
            if apply_mss_clamp(fw, policy, state, mss)
                .await
                .context("firewall MSS clamping (manual)")?
            {
                sync_policy(shared_policy, policy).await;
            } else {
                warn!(
                    "manual MSS clamp {mss} ignored: the firewall backend does not support clamping"
                );
                emit_log(
                    event_tx,
                    "warn",
                    &format!(
                        "MSS clamp {mss} not accepted: firewall backend does not support clamping"
                    ),
                );
            }
        }

        OrchestratorCmd::LoadNetworkConfig(new_cfg) => {
            // Both reload paths — the API and the `network.toml` watcher —
            // converge here, so this is where a value the running data plane
            // cannot take is refused. The whole configuration is kept, not
            // only that value: see `NetworkConfig::check_hot_reload`.
            let reloadable = new_cfg.check_hot_reload(&*shared_network.read().await);
            if let Err(refusal) = reloadable {
                // `emit_log` writes the journal line as well as the event.
                emit_log(
                    event_tx,
                    "warn",
                    &format!("Network configuration not applied: {refusal}"),
                );
                return Ok(());
            }
            info!("network config reloaded: {} peer(s)", new_cfg.peers.len());
            *policy = new_cfg.firewall_policy();
            *shared_network.write().await = *new_cfg;
            let state = *shared_state.read().await;
            fw.apply(policy, state)
                .await
                .context("firewall after config reload")?;
            sync_policy(shared_policy, policy).await;

            // Aligns the data plane with the new peer list (client
            // enrollment, or revocation).
            if wg.is_up() {
                let ipv6 = shared_ipv6.read().await.clone();
                let (iface, peers) = wg_config(&*shared_network.read().await, &ipv6);
                if let Err(e) = wg.sync_peers(&peers).await {
                    warn!("WireGuard peer synchronization: {e}");
                    emit_log(event_tx, "warn", &format!("Peer synchronization: {e}"));
                }
                // An admission adds a VIP and a revocation removes one; the
                // pinned table has to follow both, or a freshly admitted
                // client is the only one still leaving through the wrong
                // tunnel — the hardest case to diagnose, since every other
                // client works.
                pin_peer_vips(dry_run, &iface, &peers, event_tx).await;
            }
            emit_log(event_tx, "info", "Network configuration applied");
        }
        // Emitted by the handshake poller on the **internal** channel, never
        // by the API: no route builds it. If it arrived through the
        // external channel anyway, ignoring it is better than letting a
        // caller drive the tunnel's state machine.
        OrchestratorCmd::TunnelStateInferred(state) => {
            warn!("inferred state received on the external channel, ignored: {state:?}");
        }
    }
    Ok(())
}
