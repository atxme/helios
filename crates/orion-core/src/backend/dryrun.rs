//! Simulation backend: mounts a "fake" WireGuard adapter.
//!
//! This is the default backend on WSL2/dev (no WireGuard stack required). It
//! faithfully models the **adapter lifecycle** — Orion's security property
//! (ADR-001 §3 bis) — so that the "never unmounted on failure" invariant is
//! actually testable without hardware or privileges.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use aether::TunnelState;
use async_trait::async_trait;

use crate::config::ClientProfile;
use crate::events::ClientEvent;

use super::{EventSink, VpnBackend};

/// Sentinel: "no handshake" (impossible as a real age).
const NO_HANDSHAKE: u64 = u64::MAX;

/// Backend simulating tunnel mounting and adapter state.
pub struct DryRunBackend {
    /// Simulated handshake delay (short in tests).
    pub negotiate_delay: Duration,
    /// `true` = `up()` fails after mounting the adapter (invariant test).
    fail_after_adapter: bool,
    /// Is the adapter mounted? Models Wintun / the WireGuard interface.
    adapter_up: AtomicBool,
    /// Simulated age of the last handshake, in seconds.
    handshake_age_secs: AtomicU64,
}

impl Default for DryRunBackend {
    fn default() -> Self {
        Self {
            negotiate_delay: Duration::from_millis(700),
            fail_after_adapter: false,
            adapter_up: AtomicBool::new(false),
            handshake_age_secs: AtomicU64::new(NO_HANDSHAKE),
        }
    }
}

impl DryRunBackend {
    /// Variant that mounts the adapter then fails at handshake — reproduces the
    /// "UDP 51820 blocked" attack scenario from ADR §3 bis.
    pub fn failing() -> Self {
        Self {
            negotiate_delay: Duration::from_millis(10),
            fail_after_adapter: true,
            ..Self::default()
        }
    }

    /// Forces the age of the last handshake (drives polling tests).
    pub fn set_handshake_age(&self, age: Option<Duration>) {
        let v = age.map(|d| d.as_secs()).unwrap_or(NO_HANDSHAKE);
        self.handshake_age_secs.store(v, Ordering::SeqCst);
    }
}

#[async_trait]
impl VpnBackend for DryRunBackend {
    async fn up(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()> {
        // The data-plane form: an ML-KEM profile must carry the negotiated PSK
        // by now, or the tunnel would come up on the static key pair alone
        // (ADR-006, ADR-005). The simulation applies the same rule as the real
        // backend on purpose — a check the dry run skipped would be a check
        // nobody exercises in the regression.
        profile.validate_for_data_plane()?;

        // 1. The adapter mounts BEFORE any network attempt: from this instant,
        //    AllowedIPs (by default 0.0.0.0/0, ::/0) captures traffic and
        //    WireGuard drops it as long as the session isn't established.
        //    Nothing it captures can leak in clear.
        self.adapter_up.store(true, Ordering::SeqCst);
        sink(ClientEvent::state(TunnelState::Connecting));
        sink(ClientEvent::log(
            "info",
            format!(
                "[dry-run] adaptateur monté ({}) — handshake vers {}",
                profile.allowed_ips, profile.endpoint
            ),
        ));

        tokio::time::sleep(self.negotiate_delay).await;

        // 2. Simulated failure: returns an error WITHOUT touching the adapter.
        if self.fail_after_adapter {
            anyhow::bail!("[dry-run] handshake impossible (UDP 51820 bloqué ?)");
        }

        self.handshake_age_secs.store(0, Ordering::SeqCst);
        sink(ClientEvent::state(TunnelState::Up));
        let pq = if profile.has_preshared_key() {
            "slot PresharedKey renseigné"
        } else {
            "slot PresharedKey vide (Curve25519 seul)"
        };
        sink(ClientEvent::log(
            "info",
            format!("[dry-run] tunnel établi — {pq}"),
        ));
        // No `Capture` verdict: there is no adapter to read back, and a
        // `Complete` here would be a verification that never happened. The
        // screen then shows the requested list without any claim about it.
        Ok(())
    }

    async fn down(&self, sink: &EventSink) -> anyhow::Result<()> {
        self.adapter_up.store(false, Ordering::SeqCst);
        self.handshake_age_secs
            .store(NO_HANDSHAKE, Ordering::SeqCst);
        sink(ClientEvent::log("info", "[dry-run] adaptateur démonté"));
        sink(ClientEvent::state(TunnelState::Down));
        Ok(())
    }

    async fn last_handshake_age(&self) -> Option<Duration> {
        match self.handshake_age_secs.load(Ordering::SeqCst) {
            NO_HANDSHAKE => None,
            secs => Some(Duration::from_secs(secs)),
        }
    }

    fn adapter_is_up(&self) -> bool {
        self.adapter_up.load(Ordering::SeqCst)
    }

    fn kind(&self) -> &'static str {
        "dry-run"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn collector() -> (EventSink, Arc<Mutex<Vec<ClientEvent>>>) {
        let log: Arc<Mutex<Vec<ClientEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let l = Arc::clone(&log);
        let sink: EventSink = Arc::new(move |ev| l.lock().unwrap().push(ev));
        (sink, log)
    }

    fn profile() -> ClientProfile {
        ClientProfile {
            name: "test".into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: "cHJpdmF0ZQ==".into(),
            peer_public_key: "cHVibGlj".into(),
            ..ClientProfile::default()
        }
    }

    fn states(log: &Arc<Mutex<Vec<ClientEvent>>>) -> Vec<TunnelState> {
        log.lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                ClientEvent::StateChanged { state } => Some(*state),
                _ => None,
            })
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn simulation_reaches_up() {
        let backend = DryRunBackend {
            negotiate_delay: Duration::from_millis(10),
            ..DryRunBackend::default()
        };
        let (sink, log) = collector();
        backend.up(&profile(), &sink).await.unwrap();

        assert_eq!(states(&log), vec![TunnelState::Connecting, TunnelState::Up]);
        assert!(backend.adapter_is_up());
    }

    #[tokio::test]
    async fn down_returns_to_down_and_unmounts() {
        let backend = DryRunBackend::default();
        let (sink, log) = collector();
        backend.up(&profile(), &sink).await.unwrap();
        backend.down(&sink).await.unwrap();

        assert_eq!(states(&log).last(), Some(&TunnelState::Down));
        assert!(!backend.adapter_is_up());
        assert!(backend.last_handshake_age().await.is_none());
    }

    /// The backend itself must not unmount on failure (ADR-001 §3 bis).
    #[tokio::test]
    async fn failure_leaves_the_adapter_mounted() {
        let backend = DryRunBackend::failing();
        let (sink, _log) = collector();
        assert!(backend.up(&profile(), &sink).await.is_err());
        assert!(
            backend.adapter_is_up(),
            "the adapter must survive a handshake failure"
        );
    }

    #[tokio::test]
    async fn invalid_profile_fails_without_mounting_the_adapter() {
        let backend = DryRunBackend::default();
        let (sink, _log) = collector();
        // Empty profile: no keys → refused before any side effect.
        assert!(backend.up(&ClientProfile::default(), &sink).await.is_err());
        assert!(!backend.adapter_is_up());
    }
}
