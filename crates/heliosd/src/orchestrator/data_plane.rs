//! The data plane: the WireGuard and firewall backends, the policy and MSS
//! clamp they apply, the PSKs installed on peers and the VIPs pinned for them.

use super::*;

/// Selects the WireGuard data plane. Like for the firewall: dry-run by
/// default, real kernel backend behind the `wireguard` feature.
pub(super) fn wireguard_backend(
    dry_run: bool,
    ifname: &str,
) -> anyhow::Result<Box<dyn WireguardBackend>> {
    if dry_run {
        return Ok(Box::new(helios_wireguard::DryRunBackend::new()));
    }
    #[cfg(feature = "wireguard")]
    {
        let backend = helios_wireguard::KernelBackend::new(ifname)
            .map_err(|e| anyhow::anyhow!("kernel WireGuard backend unavailable: {e}"))?;
        Ok(Box::new(backend))
    }
    #[cfg(not(feature = "wireguard"))]
    {
        let _ = ifname;
        anyhow::bail!("real mode requested without the `wireguard` feature");
    }
}

/// Projects the network config onto the interface config + WireGuard peers.
pub(super) fn wg_config(network: &NetworkConfig) -> (InterfaceConfig, Vec<PeerConfig>) {
    let iface = InterfaceConfig {
        name: network.wg_iface.clone(),
        // A copy of the gateway identity and of every PSK: the backend trait
        // takes owned configuration, and the shared `NetworkConfig` cannot be
        // borrowed across the `await` that applies it. `Zeroizing` is what
        // bounds these copies — they die with the returned structures, at the
        // end of the bring-up or of the peer synchronization (ADR-006 §5).
        private_key: Zeroizing::new(network.wg_private_key.expose().to_owned()),
        listen_port: network.wg_listen_port,
        addresses: vec![network.wg_address.clone()],
        mtu: Some(aether::mtu::tunnel_mtu(mtu_transport(
            network.primary_wan_iface().unwrap_or_default(),
        ))),
    };
    let peers = network
        .peers
        .iter()
        .map(|p| PeerConfig {
            public_key: p.public_key.clone(),
            allowed_ips: vec![p.address.clone()],
            preshared_key: p
                .preshared_key
                .as_ref()
                .map(|psk| Zeroizing::new(psk.expose().to_owned())),
            persistent_keepalive_secs: p.persistent_keepalive_secs,
        })
        .collect();
    (iface, peers)
}

pub(super) fn firewall_backend(
    dry_run: bool,
    firewall_mode: FirewallMode,
) -> anyhow::Result<Box<dyn FirewallBackend>> {
    if dry_run {
        return Ok(Box::new(DryRunBackend));
    }
    if firewall_mode == FirewallMode::DisabledForMaintenance {
        #[cfg(feature = "netlink")]
        {
            return Ok(Box::new(helios_firewall::FirewallDisabledBackend::new()));
        }
        #[cfg(not(feature = "netlink"))]
        {
            anyhow::bail!(
                "firewall maintenance mode requested without the `netlink` feature; \
                 the daemon cannot prove that a persistent Helios table was removed"
            );
        }
    }
    #[cfg(feature = "netlink")]
    {
        Ok(Box::new(helios_firewall::NetlinkBackend::new()))
    }
    #[cfg(not(feature = "netlink"))]
    {
        anyhow::bail!("real mode requested without the `netlink` feature");
    }
}

pub(super) async fn sync_policy(shared: &Arc<RwLock<FirewallPolicy>>, policy: &FirewallPolicy) {
    *shared.write().await = policy.clone();
}

/// Accepts a discovered clamp only when the selected backend can encode it.
///
/// Applying a candidate before mutating the live policy also keeps the policy
/// aligned with the ruleset if a capable backend rejects the transaction.
pub(super) async fn apply_mss_clamp(
    fw: &dyn FirewallBackend,
    policy: &mut FirewallPolicy,
    state: TunnelState,
    mss: u16,
) -> anyhow::Result<bool> {
    if !fw.capabilities().mss_clamp {
        return Ok(false);
    }

    let mut candidate = policy.clone();
    candidate.mss_clamp = Some(mss);
    fw.apply(&candidate, state).await?;
    *policy = candidate;
    Ok(true)
}

pub(super) async fn install_peer_psk(
    request: InstallPskRequest,
    shared_network: &Arc<RwLock<NetworkConfig>>,
    wg: &dyn WireguardBackend,
    event_tx: &broadcast::Sender<HeliosEvent>,
) {
    let InstallPskRequest {
        public_key,
        address,
        psk,
        reply,
    } = request;

    // In-memory update, with what's needed to roll back.
    let previous = {
        let mut network = shared_network.write().await;
        match network
            .peers
            .iter_mut()
            .find(|p| p.public_key == public_key)
        {
            None => {
                // Should not happen: the endpoint has already verified admission.
                let _ = reply.send(Err(format!(
                    "peer unknown to the configuration: {public_key}"
                )));
                return;
            }
            Some(peer) => {
                // The declared address is authoritative and is **not**
                // overwritten by the one in the request. `AllowedIPs` is
                // WireGuard's cryptographic routing table: changing it under
                // a live session would cut off traffic.
                //
                // Both senders read `address` from this same declaration —
                // provisioning returns the persisted VIP since the unified
                // IPAM (`ADRESSAGE-IPV6.md` §3 bis.2, rule 4), and the key
                // negotiation copies `peer.address`. A difference is
                // therefore no longer a derivation disagreeing with the
                // operator; it means `network.toml` was reloaded with a new
                // address for this peer between their read and this
                // installation. Kept as a defensive check, reported rather
                // than resolved.
                if peer.address != address {
                    warn!(
                        peer = %public_key,
                        declared = %peer.address,
                        requested = %address,
                        "the PSK request names another VIP than the one now declared \
                         (configuration reloaded meanwhile): the declared address is kept"
                    );
                }
                // `previous` is a `SecretString`, so the value displaced by
                // the new one is wiped whether it is put back on rollback or
                // dropped on success — it used to be a bare `String` that
                // survived either way (ADR-006 §5).
                let previous = peer.preshared_key.take();
                peer.preshared_key = psk.as_ref().map(aether::SecretString::duplicate);
                previous
            }
        }
    };

    let (_, peers) = wg_config(&*shared_network.read().await);

    match wg.sync_peers(&peers).await {
        Ok(()) => {
            let action = if psk.is_some() {
                "installed"
            } else {
                "cleared"
            };
            info!(peer = %public_key, vip = %address, "peer PSK slot {action}");
            emit_log(
                event_tx,
                "info",
                &format!("Peer PSK slot {action} for {address}"),
            );
            let _ = reply.send(Ok(()));
        }
        Err(e) => {
            // Rollback: the in-memory config must reflect the data plane.
            {
                let mut network = shared_network.write().await;
                if let Some(peer) = network
                    .peers
                    .iter_mut()
                    .find(|p| p.public_key == public_key)
                {
                    peer.preshared_key = previous;
                }
            }
            warn!(peer = %public_key, "could not install the PSK: {e}");
            emit_log(
                event_tx,
                "error",
                &format!("Post-quantum PSK installation refused: {e}"),
            );
            let _ = reply.send(Err(e.to_string()));
        }
    }
}

/// Path to the kernel's IPv4 routing flag. Overridable for tests: the system
/// file is read-only for an ordinary user.
const IP_FORWARD_PATH: &str = "/proc/sys/net/ipv4/ip_forward";

/// Reports a disabled kernel routing flag while the config asks to route.
///
/// Without `ip_forward`, the firewall allows the traffic and the kernel
/// drops it anyway: the tunnel comes up, the rules are correct, and nothing
/// gets through. The symptom is indistinguishable from a firewall problem,
/// hence the explicit warning. It is not enabled automatically — changing a
/// global kernel setting without saying so goes beyond what the
/// configuration asked for.
fn warn_if_ip_forward_disabled(event_tx: &broadcast::Sender<HeliosEvent>) {
    let path = std::env::var("HELIOS_IP_FORWARD_PATH").unwrap_or_else(|_| IP_FORWARD_PATH.into());
    match std::fs::read_to_string(&path) {
        Ok(value) if value.trim() == "0" => emit_log(
            event_tx,
            "warn",
            "`allow_client_internet` is active but the kernel's IPv4 routing is \
             disabled: client packets will be dropped despite correct rules. \
             Fix with `sysctl -w net.ipv4.ip_forward=1`, and make it \
             permanent in /etc/sysctl.d/.",
        ),
        Ok(_) => {}
        Err(e) => emit_log(
            event_tx,
            "warn",
            &format!("kernel IPv4 routing not verifiable ({path}: {e})"),
        ),
    }
}

pub(super) async fn do_connect(
    network: &NetworkConfig,
    wg: &dyn WireguardBackend,
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
    dry_run: bool,
) -> anyhow::Result<()> {
    if !network.wireguard_ready() {
        emit_log(
            event_tx,
            "error",
            "WireGuard private key missing from the network config — cannot bring up the interface",
        );
        anyhow::bail!("gateway not configured: `wg_private_key` empty in network.toml");
    }

    if network.allow_client_internet {
        warn_if_ip_forward_disabled(event_tx);
    }

    let (iface, peers) = wg_config(network);

    // Kill-switch engaged throughout the bring-up.
    let mut state = *shared.read().await;
    if state != TunnelState::Down && state != TunnelState::Failed {
        state = TunnelState::Down;
    }
    state = state
        .on(TunnelEvent::StartRequested)
        .context("state transition")?;
    transition(shared, event_tx, state, fw, policy).await?;

    emit_log(
        event_tx,
        "info",
        &format!(
            "Bringing up {} — UDP listener {}, {} peer(s) admitted",
            iface.name,
            iface.listen_port,
            peers.len()
        ),
    );

    wg.up(&iface, &peers)
        .await
        .context("bringing up the WireGuard interface")?;

    // After the interface exists — the peer routes name it — and before the
    // state is announced: a client that handshakes in between would otherwise
    // have its first replies handed to whichever VPN owns the CGNAT range.
    pin_peer_vips(dry_run, &iface, &peers, event_tx).await;

    emit_log(
        event_tx,
        "info",
        &format!(
            "Interface {} active ({}) — waiting for client handshake",
            iface.name,
            iface.addresses.join(", ")
        ),
    );
    Ok(())
}

/// Pins the admitted peers' VIPs onto the tunnel interface.
///
/// # Why a failure is not fatal
///
/// On a gateway that has the CGNAT range to itself this changes nothing at
/// all — the main table already routes it to `helios0`. Refusing to serve
/// because a policy rule could not be written would therefore take down
/// gateways that were never at risk. The warning names the consequence
/// instead, because the symptom on the other side is invisible: packets are
/// not dropped, they leave through the wrong tunnel.
pub(super) async fn pin_peer_vips(
    dry_run: bool,
    iface: &helios_wireguard::InterfaceConfig,
    peers: &[helios_wireguard::PeerConfig],
    event_tx: &broadcast::Sender<HeliosEvent>,
) {
    if dry_run {
        return;
    }
    // The IPv4 tunnel address comes first: `wg_config` builds the list.
    let tunnel_address = iface.addresses.first().map_or("", String::as_str);
    let plan = match crate::vip_routing::plan(&iface.name, tunnel_address, peers) {
        Ok(plan) => plan,
        Err(error) => {
            warn!("peer VIP routing not planned: {error}");
            return;
        }
    };
    if let Err(error) = crate::vip_routing::apply(&plan).await {
        warn!("peer VIP routing not installed: {error}");
        emit_log(
            event_tx,
            "warn",
            &format!(
                "Client VIPs not pinned to {} ({error}). If another VPN on this host claims \
                 100.64.0.0/10, traffic to clients leaves through it and no packet is dropped \
                 to say so.",
                iface.name
            ),
        );
    }
}

/// Removes the pinning. Paired with every path that takes the interface down.
pub(super) async fn unpin_peer_vips(dry_run: bool) {
    if dry_run {
        return;
    }
    if let Err(error) = crate::vip_routing::withdraw().await {
        warn!("peer VIP routing not withdrawn: {error}");
    }
}
