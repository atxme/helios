//! Hot reload of `network.toml`.

use super::*;

/// Interval between two looks at `network.toml`.
///
/// A few seconds: the operator admits a peer and expects the client to be
/// able to connect right away, not to wonder whether they should restart
/// something. Nothing is read unless the file's timestamp or size moved, so
/// the cost between two admissions is one `stat` every two seconds.
const NETWORK_CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Applies `network.toml` to the running gateway when it changes on disk.
///
/// # Why watch a file rather than take an order
///
/// Admission has two paths, deliberately (ADR-004 §4): the API, for a peer
/// already connected, and the console — `heliosd peer add` — which exists
/// precisely to bootstrap a gateway *without* a tunnel. The console path runs
/// in another process: all it can do is rewrite the file. Until now the
/// change waited for the next restart, which meant cutting every connected
/// client to admit one more.
///
/// # What is reloaded, and what is not
///
/// The whole configuration is re-applied — peer table, firewall policy — by
/// the same command the API already uses ([`OrchestratorCmd::LoadNetworkConfig`]),
/// so both paths converge on one code path. **Limite connue** : what the
/// running data plane cannot change under itself is not re-applied — the
/// interface name, its listen port and the API's bind address are fixed when
/// the interface comes up. Changing those in the file still requires a
/// restart, and the daemon says so rather than pretending otherwise.
///
/// The IPv6 tunnel prefix (`wg_address_v6`) is in the same position, and
/// enforced: a file that changes it is not applied at all, with a warning,
/// until the next start ([`NetworkConfig::check_hot_reload`],
/// `ADRESSAGE-IPV6.md` §5.4). The peers' `address_v6` are part of the peer
/// table and reload live.
///
/// The secrets never live in the file: they are restored from the running
/// configuration by [`NetworkConfig::adopt_runtime_secrets_from`]. Skipping
/// that step would erase the sealed private key and every negotiated PSK on
/// the first admission — the exact accident this reload exists to avoid.
pub(super) fn spawn_network_config_watcher(
    shared_network: Arc<RwLock<NetworkConfig>>,
    cmd_tx: mpsc::Sender<OrchestratorCmd>,
) {
    /// Timestamp and size: enough to notice a rewrite without reading it.
    fn stamp(path: &std::path::Path) -> Option<(std::time::SystemTime, u64)> {
        let metadata = std::fs::metadata(path).ok()?;
        Some((metadata.modified().ok()?, metadata.len()))
    }

    tokio::spawn(async move {
        let path = NetworkConfig::path();
        let mut seen = stamp(&path);
        let mut ticker = time::interval(NETWORK_CONFIG_POLL_INTERVAL);
        loop {
            ticker.tick().await;
            let current = stamp(&path);
            if current == seen {
                continue;
            }
            seen = current;

            // `save()` writes to a temporary file then renames: a partial
            // file is never observed. A parse error therefore reports a
            // genuinely invalid file, and keeping the running configuration
            // is the only safe answer.
            let from_disk = match NetworkConfig::load() {
                Ok(config) => config,
                Err(error) => {
                    warn!(%error, "network.toml changed but is unusable; keeping the running configuration");
                    continue;
                }
            };

            let mut merged = from_disk;
            {
                let running = shared_network.read().await;
                merged.adopt_runtime_secrets_from(&running);
                // The API also rewrites the file: without this comparison,
                // every mutation through the API would be applied twice —
                // once by the route, once by this watcher.
                if merged == *running {
                    continue;
                }
                // Refused here rather than sent: the orchestrator would refuse
                // it too, after this loop had announced it as applied.
                if let Err(refusal) = merged.check_hot_reload(&running) {
                    warn!(%refusal, "network.toml changed on disk but cannot be applied live; keeping the running configuration");
                    continue;
                }
            }

            info!(
                "network.toml changed on disk: {} peer(s) applied without restart",
                merged.peers.len()
            );
            if cmd_tx
                .send(OrchestratorCmd::LoadNetworkConfig(Box::new(merged)))
                .await
                .is_err()
            {
                // The orchestrator is gone: the daemon is shutting down.
                return;
            }
        }
    });
}
