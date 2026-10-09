//! Keeping `wan_iface = "auto"` in step with the kernel.
//!
//! The set of uplinks is first resolved at startup (`commands::wan`). This
//! watches it afterwards, so that an interface without carrier at startup, or
//! an adapter plugged in later, is admitted without a restart — and one that
//! disappears or loses its carrier stops being named by the ruleset.
//!
//! # Same admission rule, same firewall path
//!
//! What is admitted is exactly what startup admits: [`uplink::select`], every
//! physical interface with carrier. A change of that set is handed to the main
//! loop as [`OrchestratorCmd::RefreshWanIfaces`], which rebuilds the whole
//! ruleset through [`commit_policy`] — compiled first, then one atomic
//! transaction, the path every hot reload already takes. Connected clients
//! see no window: the kernel swaps one complete ruleset for another.
//!
//! Only the **set** matters. The kernel reordering its preference between two
//! admitted links (a metric change) rebuilds nothing: the firewall permits
//! them all alike.
//!
//! # What is left alone
//!
//! * No usable uplink at all — every cable out — keeps the running set rather
//!   than emptying it: there is no egress to protect then, and an empty list
//!   is a policy the firewall refuses.
//! * The operator replacing `auto` by explicit names (file or API) takes the
//!   list over: the watcher notices the running list is no longer the one it
//!   last saw or applied, and stops for the life of the daemon.
//! * A set the firewall refuses is not proposed again until the kernel's set
//!   changes once more; the error is logged once.
//!
//! **Limite connue** : the telemetry loop and the startup MTU probe keep the
//! interface preferred at startup; only a reconnection reads the new
//! preference. The firewall, which is what decides whether traffic passes,
//! follows every change.

use std::collections::BTreeSet;

use super::*;
use crate::uplink;

/// Interval between two looks at `/sys/class/net`.
///
/// Same cadence as the `network.toml` watcher: a cable plugged in should
/// carry traffic before the operator wonders why it does not.
const UPLINK_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// What the watcher does after one observation of the kernel.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum UplinkStep {
    /// Nothing to send.
    Unchanged,
    /// Ask the main loop to apply this list.
    Propose(Vec<String>),
    /// The running list belongs to someone else now: stop watching.
    Relinquish,
}

/// The watcher's memory between two observations, kept apart from the timer
/// and the kernel so the decisions are exercised without either.
pub(super) struct UplinkTracker {
    /// The running list as the watcher last knew it — resolved at startup,
    /// then each list it saw applied.
    owned: Vec<String>,
    /// The last list sent, until it shows up as the running one or the
    /// kernel goes back to the running set.
    proposed: Option<Vec<String>>,
}

fn same_set(left: &[String], right: &[String]) -> bool {
    left.iter().collect::<BTreeSet<_>>() == right.iter().collect::<BTreeSet<_>>()
}

impl UplinkTracker {
    pub(super) fn new(running: Vec<String>) -> Self {
        Self {
            owned: running,
            proposed: None,
        }
    }

    /// Decides from the running list and what the kernel offers now (`None`
    /// when it offers no usable uplink at all).
    pub(super) fn step(&mut self, running: &[String], observed: Option<Vec<String>>) -> UplinkStep {
        if self
            .proposed
            .as_deref()
            .is_some_and(|proposed| same_set(proposed, running))
        {
            self.owned = running.to_vec();
            self.proposed = None;
        }
        if !same_set(running, &self.owned) {
            return UplinkStep::Relinquish;
        }
        let Some(observed) = observed else {
            return UplinkStep::Unchanged;
        };
        if same_set(&observed, running) {
            self.proposed = None;
            return UplinkStep::Unchanged;
        }
        if self
            .proposed
            .as_deref()
            .is_some_and(|proposed| same_set(proposed, &observed))
        {
            return UplinkStep::Unchanged;
        }
        self.proposed = Some(observed.clone());
        UplinkStep::Propose(observed)
    }
}

/// Watches the kernel's uplinks for a daemon started with `wan_iface = "auto"`.
pub(super) fn spawn_uplink_watcher(
    shared_network: Arc<RwLock<NetworkConfig>>,
    cmd_tx: mpsc::Sender<OrchestratorCmd>,
) {
    tokio::spawn(async move {
        let mut tracker = UplinkTracker::new(shared_network.read().await.wan_ifaces.clone());
        let mut last_error: Option<String> = None;
        let mut ticker = time::interval(UPLINK_POLL_INTERVAL);
        loop {
            ticker.tick().await;
            let observed = match uplink::resolve() {
                Ok(selection) => {
                    last_error = None;
                    Some(selection.interfaces)
                }
                Err(error) => {
                    let error = error.to_string();
                    if last_error.as_deref() != Some(error.as_str()) {
                        warn!(%error, "no usable WAN interface right now; the running set stays in force");
                        last_error = Some(error);
                    }
                    None
                }
            };
            let running = shared_network.read().await.wan_ifaces.clone();
            match tracker.step(&running, observed) {
                UplinkStep::Unchanged => {}
                UplinkStep::Relinquish => {
                    info!(
                        interfaces = %running.join(", "),
                        "WAN interfaces set explicitly since startup; uplink watching stops"
                    );
                    return;
                }
                UplinkStep::Propose(next) => {
                    let cmd = OrchestratorCmd::RefreshWanIfaces {
                        previous: running,
                        next,
                    };
                    if cmd_tx.send(cmd).await.is_err() {
                        // The orchestrator is gone: the daemon is shutting down.
                        return;
                    }
                }
            }
        }
    });
}

/// Applies a refreshed uplink list, or leaves everything as it was.
///
/// Never an error for the main loop: a refused list keeps the running ruleset,
/// which is the fail-closed outcome.
#[allow(clippy::too_many_arguments)]
pub(super) async fn refresh_wan_ifaces(
    previous: Vec<String>,
    next: Vec<String>,
    shared_network: &Arc<RwLock<NetworkConfig>>,
    shared_state: &Arc<RwLock<TunnelState>>,
    event_tx: &broadcast::Sender<HeliosEvent>,
    fw: &dyn FirewallBackend,
    policy: &mut FirewallPolicy,
    shared_policy: &Arc<RwLock<FirewallPolicy>>,
) {
    if shared_network.read().await.wan_ifaces != previous {
        info!("uplink refresh dropped: the WAN interface list changed in the meantime");
        return;
    }
    let mut candidate = policy.clone();
    candidate.wan_ifaces.clone_from(&next);
    let state = *shared_state.read().await;
    if let Err(error) = commit_policy(fw, policy, candidate, state).await {
        emit_log(
            event_tx,
            "error",
            &format!(
                "WAN interfaces {} not applied, {} stay in force: {error:#}",
                next.join(", "),
                previous.join(", ")
            ),
        );
        return;
    }
    shared_network.write().await.wan_ifaces.clone_from(&next);
    sync_policy(shared_policy, policy).await;
    emit_log(
        event_tx,
        "info",
        &format!(
            "WAN interfaces updated from the kernel: {} → {} (firewall rebuilt atomically)",
            previous.join(", "),
            next.join(", ")
        ),
    );
}
