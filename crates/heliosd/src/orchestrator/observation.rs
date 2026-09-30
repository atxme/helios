//! Observing peers: WireGuard handshakes and the transitions they drive.

use super::*;

/// Brings up the gateway's WireGuard interface and applies its peers.
///
/// The gateway is a **server**: it creates its interface, listens on UDP and
/// waits for clients. It never "dials" anyone. The state therefore moves to
/// `Connecting` as soon as the interface is up; it is handshake polling
/// ([`spawn_handshake_poller`]) that promotes it to `Up` when a peer is
/// actually connected (ADR-001 §3).
/// Applies a peer's post-quantum PSK onto the data plane.
///
/// # Order of operations
///
/// The in-memory configuration is updated **first**, then synchronized to
/// the data plane. On `sync_peers` failure, the modification is rolled back:
/// the in-memory config must never announce a PSK the interface does not
/// carry, otherwise a later reconnection would apply a PSK the client has
/// already forgotten.
///
/// # Known limitation: the derived VIP is not reconciled
///
/// `helios_provisioning::assign_vip` derives the VIP from the peer's public
/// key and never consults the address declared in `network.toml`. The two
/// can therefore diverge. This function **keeps the declared address** and
/// only logs the discrepancy: the operator remains the source of truth, and
/// a silent switch of `AllowedIPs` would cut off traffic for a client that
/// keeps its profile's address. Reconciling the two requires deciding who
/// has authority — that is not this PSK-application function's job.
///
/// # What is deliberately not done: persistence
///
/// The PSK is **not** written to `network.toml`. It is derived per session,
/// its lifetime is bounded ([`helios_provisioning::DEFAULT_PSK_LIFETIME_SECS`]),
/// and a client that reconnects requests a fresh one. Writing it to disk
/// would add a persistent secret for no benefit — and would contradict the
/// ephemerality that bounds the exploitation window in case of a leak.
///
/// # On the absence of disruption
///
/// Changing a live peer's PSK does not break the current session: the
/// session keys are already derived, the new PSK will only be used on the
/// next handshake (≤ 2 min). This is what makes hot application safe — see
/// `helios_provisioning::rotation`.
/// Answers one [`ObserveHandshakeRequest`] from the live data plane.
///
/// A peer absent from the backend answers `Ok(None)`, not an error: it has
/// simply never handshaken, which is a fact the caller can act on. Only a
/// backend that cannot be read at all is an `Err`, and the caller must treat
/// that as "cannot tell" rather than as "no handshake" — a commit that
/// accepted a failed read as proof would prove nothing.
pub(super) async fn observe_peer_handshake(
    request: ObserveHandshakeRequest,
    wg: &dyn WireguardBackend,
) {
    let ObserveHandshakeRequest { public_key, reply } = request;
    let answer = match wg.peers().await {
        Ok(peers) => Ok(peers
            .iter()
            .find(|peer| peer.public_key_b64() == public_key)
            .and_then(|peer| peer.last_handshake)),
        Err(error) => Err(error.to_string()),
    };
    let _ = reply.send(answer);
}

pub(super) fn handshake_is_fresh(peer: &helios_wireguard::PeerStatus) -> bool {
    peer.last_handshake
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < HANDSHAKE_STALE_AFTER)
}

/// Logs peer connections and disconnections, once each.
///
/// This is the trace that lets us assert that **it really is `heliosd`
/// holding the tunnel**: the peer's name comes from its admission table, the
/// endpoint and handshake from its own data plane.
///
/// # What a client's disconnection is not
///
/// WireGuard is **connectionless**: the protocol has no disconnect message.
/// A client that shuts down destroys its interface without announcing
/// anything, and the gateway can only infer it from the absence of a new
/// handshake — hence a delay of up to [`HANDSHAKE_STALE_AFTER`]. Shortening
/// this threshold would declare dead peers that are alive but quiet,
/// rehandshaking only roughly every two minutes.
///
/// This is why a reconnection is reported by its **endpoint**, and not only
/// by the transition from stale to fresh: a client that reattaches within
/// the staleness window stays "fresh" from one round to the next, and its
/// return would otherwise go unnoticed. The source port changes on every
/// session, the line shows it.
///
/// # Known limitation
///
/// A **rejected** handshake — unknown public key — does not appear here and
/// cannot appear here: the WireGuard kernel module silently rejects it,
/// reporting nothing to userspace. `wg` only lists configured peers. What
/// would unblock this: an nftables `log` rule on the listening port, at the
/// cost of a noisy log on an exposed gateway.
pub(super) async fn log_peer_transitions(
    peers: &[helios_wireguard::PeerStatus],
    shared_network: &Arc<RwLock<NetworkConfig>>,
    seen: &mut std::collections::HashMap<Vec<u8>, (bool, Option<String>)>,
    event_tx: &broadcast::Sender<HeliosEvent>,
) {
    let network = shared_network.read().await;
    for peer in peers {
        let fresh = handshake_is_fresh(peer);
        let observed = (fresh, peer.endpoint.clone());
        let previous = seen.insert(peer.public_key.clone(), observed.clone());
        if previous.as_ref() == Some(&observed) {
            continue;
        }

        let key = peer.public_key_b64();
        let declared = network.peers.iter().find(|p| p.public_key == key);
        let name = declared.map_or("undeclared peer", |p| p.name.as_str());
        let endpoint = peer.endpoint.as_deref().unwrap_or("unknown endpoint");

        match (previous, fresh) {
            (Some((true, _)), false) => {
                emit_log(
                    event_tx,
                    "info",
                    &format!("peer \"{name}\" inactive — its handshake has gone stale"),
                );
            }
            // A peer never seen fresh that stays stale has nothing to
            // report: that would report the disconnection of a client that
            // was never connected.
            (_, false) => {}
            (Some((true, _)), true) => {
                emit_log(
                    event_tx,
                    "info",
                    &format!(
                        "peer \"{name}\" reconnected from {endpoint} — new session, \
                         the old one is not resumed"
                    ),
                );
            }
            (_, true) => {
                let protection = match declared.map(|p| p.preshared_key.is_some()) {
                    Some(true) => "post-quantum (ML-KEM PSK applied)",
                    // Without a PSK, the tunnel is up on Curve25519 alone:
                    // this is step 1 of the ADR-001 sequence, not a flaw.
                    // Saying so avoids believing the session is
                    // post-quantum protected when it is not.
                    _ => "classic (Curve25519, PSK not yet negotiated)",
                };
                emit_log(
                    event_tx,
                    "info",
                    &format!(
                        "peer \"{name}\" connected from {endpoint} — VIP {} — protection {protection}",
                        peer.allowed_ips.join(", ")
                    ),
                );
            }
        }
    }
}

/// Periodically polls peer handshakes to infer the state.
///
/// WireGuard is connectionless: `Up` is never received, it is inferred. The
/// gateway is `Up` as soon as **at least one** peer has handshaked less than
/// [`HANDSHAKE_STALE_AFTER`] ago.
pub(super) fn spawn_handshake_poller(
    wg: Arc<dyn WireguardBackend>,
    shared: Arc<RwLock<TunnelState>>,
    shared_network: Arc<RwLock<NetworkConfig>>,
    shared_peers: Arc<RwLock<Vec<PeerStatus>>>,
    event_tx: broadcast::Sender<HeliosEvent>,
    internal_tx: mpsc::Sender<OrchestratorCmd>,
) {
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(10));
        // Freshness observed on the previous round, by public key: without
        // this memory, "this peer just connected" cannot be distinguished
        // from "this peer has been connected for an hour", and it would be
        // logged every ten seconds.
        let mut seen: std::collections::HashMap<Vec<u8>, (bool, Option<String>)> =
            std::collections::HashMap::new();
        loop {
            ticker.tick().await;
            if !wg.is_up() {
                // Emptied rather than left as it was: a console still listing
                // yesterday's peers as connected, while the interface is down,
                // is worse than one listing none.
                shared_peers.write().await.clear();
                continue;
            }
            let peers = match wg.peers().await {
                Ok(peers) => peers,
                Err(e) => {
                    warn!("could not read WireGuard peers: {e}");
                    continue;
                }
            };

            // Published before the state is inferred: the snapshot is what the
            // console reads, and it must never lag behind the state it explains.
            *shared_peers.write().await = peers.clone();

            log_peer_transitions(&peers, &shared_network, &mut seen, &event_tx).await;

            let fresh = peers.iter().any(handshake_is_fresh);
            let current = *shared.read().await;
            let next = match (current, fresh) {
                (TunnelState::Connecting, true) => TunnelState::Up,
                (TunnelState::Up, false) => TunnelState::Connecting,
                _ => continue,
            };

            // Go through the main loop, the sole holder of the firewall
            // backend and policy. Writing the state here would leave the
            // ruleset frozen on the previous state — forward only exists in
            // states where traffic is allowed, it would never be applied.
            if internal_tx
                .send(OrchestratorCmd::TunnelStateInferred(next))
                .await
                .is_err()
            {
                return;
            }
        }
    });
}
