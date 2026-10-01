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
///
/// The one projection every path uses — bring-up, PSK installation, reload —
/// so the interface and the peers' `AllowedIPs` can never disagree on which
/// families are installed (`ADRESSAGE-IPV6.md` §6.1). IPv6 appears only when
/// `ipv6` says the bring-up installed it: `<prefix>::1/64` after
/// `wg_address`, and each peer's `/128` after its `/32`. In every other case
/// the projection is exactly the IPv4 one of a gateway without IPv6 (§2.2).
pub(super) fn wg_config(
    network: &NetworkConfig,
    ipv6: &Ipv6TunnelStatus,
) -> (InterfaceConfig, Vec<PeerConfig>) {
    let prefix = installed_prefix(network, ipv6);
    let mut addresses = vec![network.wg_address.clone()];
    addresses.extend(prefix.map(|prefix| prefix.to_string()));
    let iface = InterfaceConfig {
        name: network.wg_iface.clone(),
        // A copy of the gateway identity and of every PSK: the backend trait
        // takes owned configuration, and the shared `NetworkConfig` cannot be
        // borrowed across the `await` that applies it. `Zeroizing` is what
        // bounds these copies — they die with the returned structures, at the
        // end of the bring-up or of the peer synchronization (ADR-006 §5).
        private_key: Zeroizing::new(network.wg_private_key.expose().to_owned()),
        listen_port: network.wg_listen_port,
        addresses,
        mtu: Some(tunnel_mtu(network)),
    };
    let peers = network
        .peers
        .iter()
        .map(|p| PeerConfig {
            public_key: p.public_key.clone(),
            allowed_ips: peer_allowed_ips(p, prefix.is_some()),
            preshared_key: p
                .preshared_key
                .as_ref()
                .map(|psk| Zeroizing::new(psk.expose().to_owned())),
            persistent_keepalive_secs: p.persistent_keepalive_secs,
        })
        .collect();
    (iface, peers)
}

/// The tunnel prefix, when the bring-up installed it.
///
/// Read from the configuration rather than carried by the status: the prefix
/// cannot change without a restart (`NetworkConfig::check_hot_reload`), so the
/// two cannot drift apart while the interface is up.
pub(super) fn installed_prefix(
    network: &NetworkConfig,
    ipv6: &Ipv6TunnelStatus,
) -> Option<TunnelPrefixV6> {
    match ipv6 {
        Ipv6TunnelStatus::Installed => network.wg_address_v6,
        Ipv6TunnelStatus::NotConfigured | Ipv6TunnelStatus::Unavailable(_) => None,
    }
}

/// A peer's `AllowedIPs`: exactly its `/32`, plus its `/128` when it has one
/// and IPv6 is installed (§6.1).
///
/// The IPv4 entry is the declared text, as before IPv6 existed: rendering it
/// again would change nothing on a validated file, and would turn a malformed
/// one into a second, earlier refusal than the data plane's. The IPv6 entry
/// is rendered from the typed host the configuration already holds.
fn peer_allowed_ips(peer: &aether::WgPeer, ipv6_installed: bool) -> Vec<String> {
    let mut allowed = vec![peer.address.clone()];
    if ipv6_installed {
        allowed.extend(peer.address_v6.map(aether::net::format_vip_v6));
    }
    allowed
}

/// MTU of the tunnel interface, derived from the primary WAN's.
pub(super) fn tunnel_mtu(network: &NetworkConfig) -> u32 {
    aether::mtu::tunnel_mtu(mtu_transport(
        network.primary_wan_iface().unwrap_or_default(),
    ))
}

/// The kernel's per-interface IPv6 settings. Overridable for tests, like
/// [`IP_FORWARD_PATH`]: an ordinary user cannot write the system files.
const IPV6_CONF_PATH: &str = "/proc/sys/net/ipv6/conf";

pub(super) fn ipv6_conf_dir() -> std::path::PathBuf {
    std::env::var_os("HELIOS_IPV6_CONF_PATH")
        .map_or_else(|| IPV6_CONF_PATH.into(), std::path::PathBuf::from)
}

/// Decides, before touching the kernel, whether the IPv6 tunnel prefix can
/// be installed (`ADRESSAGE-IPV6.md` §6.2).
///
/// `Installed` is a candidate here: the kernel can still refuse the address,
/// which [`do_connect`] handles. What can be known beforehand is refused
/// beforehand, so the common cases never reach a failed bring-up:
///
/// - a tunnel MTU below 1280, on which Linux strips IPv6 from the interface;
/// - `disable_ipv6` set for `all` or `default` — the WireGuard interface is
///   created afresh and takes `default`, and `all` overrides every interface;
/// - no IPv6 stack at all, which is what a missing `conf` directory means.
///
/// Nothing here changes a sysctl: like `warn_if_ip_forward_disabled`, it
/// reports, and the operator decides.
pub(super) fn ipv6_installability(
    network: &NetworkConfig,
    tunnel_mtu: u32,
    conf_dir: &std::path::Path,
) -> Ipv6TunnelStatus {
    if network.wg_address_v6.is_none() {
        return Ipv6TunnelStatus::NotConfigured;
    }
    if !aether::mtu::carries_ipv6(tunnel_mtu) {
        return Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::TunnelMtuTooSmall {
            tunnel_mtu,
            minimum: aether::mtu::MTU_MIN_IPV6,
        });
    }
    for scope in ["all", "default"] {
        let path = conf_dir.join(scope).join("disable_ipv6");
        match std::fs::read_to_string(&path) {
            Ok(value) if value.trim() == "0" => {}
            Ok(_) => {
                return Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::DisabledByKernel {
                    setting: format!("net.ipv6.conf.{scope}.disable_ipv6"),
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::NoKernelSupport {
                    path: path.display().to_string(),
                })
            }
            // Unreadable for another reason: the bring-up is what will tell,
            // and a refusal there is still reported, not hidden.
            Err(error) => warn!(
                "IPv6 kernel setting not verifiable ({}: {error}); trying the IPv6 address",
                path.display()
            ),
        }
    }
    Ipv6TunnelStatus::Installed
}

/// Says what the bring-up did with IPv6, on the journal and the event stream.
///
/// Silent for a gateway without a prefix: nothing about it changed (§2.2).
fn report_ipv6(
    iface: &str,
    network: &NetworkConfig,
    ipv6: &Ipv6TunnelStatus,
    event_tx: &broadcast::Sender<HeliosEvent>,
) {
    match (ipv6, network.wg_address_v6) {
        (Ipv6TunnelStatus::Installed, Some(prefix)) => emit_log(
            event_tx,
            "info",
            &format!("IPv6 tunnel address {prefix} installed on {iface}"),
        ),
        (Ipv6TunnelStatus::Unavailable(reason), _) => emit_log(
            event_tx,
            "warn",
            &format!(
                "IPv6 not installed on {iface}: {reason}. The gateway runs IPv4-only \
                 (degraded): the peers' IPv6 VIPs are left out of their AllowedIPs, and \
                 WireGuard drops their IPv6 traffic."
            ),
        ),
        _ => {}
    }
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
    shared_ipv6: &Arc<RwLock<Ipv6TunnelStatus>>,
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

    // The same families as the bring-up installed: a `sync_peers` that added
    // an IPv6 `/128` the interface does not carry would contradict it.
    let ipv6 = shared_ipv6.read().await.clone();
    let (_, peers) = wg_config(&*shared_network.read().await, &ipv6);

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

#[allow(clippy::too_many_arguments)]
pub(super) async fn do_connect(
    network: &NetworkConfig,
    wg: &dyn WireguardBackend,
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
    dry_run: bool,
    shared_ipv6: &Arc<RwLock<Ipv6TunnelStatus>>,
) -> anyhow::Result<()> {
    let candidate = ipv6_installability(network, tunnel_mtu(network), &ipv6_conf_dir());
    connect_with_ipv6(
        network,
        candidate,
        wg,
        shared,
        event_tx,
        fw,
        policy,
        dry_run,
        shared_ipv6,
    )
    .await
}

/// [`do_connect`] once the IPv6 candidate is known: what the tests drive, since
/// neither the WAN's MTU nor the kernel's settings are theirs to choose.
///
/// # A kernel that refuses the IPv6 address
///
/// The checks of [`ipv6_installability`] catch the known causes; a kernel can
/// still refuse the address for one they do not see. The specification asks
/// for an IPv4-only start in that case, not a dead gateway (§6.2), so the
/// bring-up is retried once without IPv6 — and only then:
///
/// - only a refusal from the kernel side (`WgError::Interface`) is retried. A
///   key or an address the backend refused before touching anything would be
///   refused again, and is not an IPv6 problem;
/// - the half-configured interface is taken down first. `defguard` assigns
///   the addresses before the key and the peers, so a refused address leaves
///   no peer behind; whatever a later failure did leave goes with the link.
///   If the link cannot be removed, the start fails and says why;
/// - the kill-switch stays engaged throughout, as for any bring-up;
/// - the outcome is reported as `AddressRefused`, carrying the first error
///   verbatim. If the IPv4-only attempt fails too, that failure is returned
///   with the first one in its context: the cause was not IPv6 after all.
#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_with_ipv6(
    network: &NetworkConfig,
    candidate: Ipv6TunnelStatus,
    wg: &dyn WireguardBackend,
    shared: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &FirewallPolicy,
    dry_run: bool,
    shared_ipv6: &Arc<RwLock<Ipv6TunnelStatus>>,
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

    let mut ipv6 = candidate;
    let (mut iface, mut peers) = wg_config(network, &ipv6);

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

    match wg.up(&iface, &peers).await {
        Ok(()) => {}
        Err(refusal @ WgError::Interface { .. }) if installed_prefix(network, &ipv6).is_some() => {
            let address = installed_prefix(network, &ipv6)
                .map(|prefix| prefix.to_string())
                .unwrap_or_default();
            let refusal = refusal.to_string();
            wg.down().await.with_context(|| {
                format!(
                    "bringing up {} with the IPv6 address {address} failed ({refusal}), and \
                     the half-configured interface could not be removed",
                    iface.name
                )
            })?;
            ipv6 = Ipv6TunnelStatus::Unavailable(Ipv6Unavailable::AddressRefused {
                address,
                detail: refusal.clone(),
            });
            (iface, peers) = wg_config(network, &ipv6);
            wg.up(&iface, &peers).await.with_context(|| {
                format!(
                    "bringing up the WireGuard interface without IPv6, after the attempt \
                     with it failed ({refusal})"
                )
            })?;
        }
        Err(error) => return Err(error).context("bringing up the WireGuard interface"),
    }
    *shared_ipv6.write().await = ipv6.clone();
    report_ipv6(&iface.name, network, &ipv6, event_tx);

    // After the interface exists — the peer routes name it — and before the
    // state is announced: a client that handshakes in between would otherwise
    // have its first replies handed to whichever VPN owns the CGNAT range.
    pin_peer_vips(
        dry_run,
        &iface,
        &peers,
        installed_prefix(network, &ipv6),
        event_tx,
    )
    .await;

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
///
/// The IPv6 family is pinned only when `ipv6_prefix` says the bring-up
/// installed it, and independently of the IPv4 one: a failure in one family
/// does not withhold the other.
pub(super) async fn pin_peer_vips(
    dry_run: bool,
    iface: &helios_wireguard::InterfaceConfig,
    peers: &[helios_wireguard::PeerConfig],
    ipv6_prefix: Option<TunnelPrefixV6>,
    event_tx: &broadcast::Sender<HeliosEvent>,
) {
    if dry_run {
        return;
    }
    pin_peer_vips_v4(iface, peers, event_tx).await;
    if let Some(prefix) = ipv6_prefix {
        let plan = crate::vip_routing::plan_v6(&iface.name, prefix, peers);
        if let Err(error) = crate::vip_routing::apply_v6(&plan).await {
            warn!("peer IPv6 VIP routing not installed: {error}");
            emit_log(
                event_tx,
                "warn",
                &format!(
                    "Client IPv6 VIPs not pinned to {} ({error}). If another VPN on this host \
                     routes {} through its own table, IPv6 traffic to clients leaves through it \
                     and no packet is dropped to say so.",
                    iface.name, plan.selector
                ),
            );
        }
    }
}

async fn pin_peer_vips_v4(
    iface: &helios_wireguard::InterfaceConfig,
    peers: &[helios_wireguard::PeerConfig],
    event_tx: &broadcast::Sender<HeliosEvent>,
) {
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
///
/// The IPv6 family is withdrawn only when the bring-up had installed it: a
/// gateway without IPv6 runs no `ip -6` command, on the way down either.
pub(super) async fn unpin_peer_vips(dry_run: bool, ipv6: &Ipv6TunnelStatus) {
    if dry_run {
        return;
    }
    if let Err(error) = crate::vip_routing::withdraw().await {
        warn!("peer VIP routing not withdrawn: {error}");
    }
    if *ipv6 == Ipv6TunnelStatus::Installed {
        if let Err(error) = crate::vip_routing::withdraw_v6().await {
            warn!("peer IPv6 VIP routing not withdrawn: {error}");
        }
    }
}
