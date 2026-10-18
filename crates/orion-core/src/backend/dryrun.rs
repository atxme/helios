//! Simulation backend: mounts a "fake" WireGuard adapter.
//!
//! This is the default backend on WSL2/dev (no WireGuard stack required). It
//! faithfully models the **adapter lifecycle** — Orion's security property
//! (ADR-001 §3 bis) — so that the "never unmounted on failure" invariant is
//! actually testable without hardware or privileges.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use aether::{SecretString, TunnelState};
use async_trait::async_trait;

use crate::config::ClientProfile;
use crate::events::ClientEvent;

use super::{EventSink, VpnBackend};

/// Sentinel: "no handshake" (impossible as a real age).
const NO_HANDSHAKE: u64 = u64::MAX;

/// Sentinel: "transfer counter unreadable".
const NO_COUNTER: u64 = u64::MAX;

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
    /// PSKs the peer was re-registered with, in order.
    rekeyed: std::sync::Mutex<Vec<Option<SecretString>>>,
    /// `true` = every `rekey_peer` fails (rollback tests).
    fail_rekey: AtomicBool,
    /// Simulated bytes sent plus received since the peer was registered.
    transfer: AtomicU64,
}

impl Default for DryRunBackend {
    fn default() -> Self {
        Self {
            negotiate_delay: Duration::from_millis(700),
            fail_after_adapter: false,
            adapter_up: AtomicBool::new(false),
            handshake_age_secs: AtomicU64::new(NO_HANDSHAKE),
            rekeyed: std::sync::Mutex::new(Vec::new()),
            fail_rekey: AtomicBool::new(false),
            transfer: AtomicU64::new(0),
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

    /// PSKs the peer was re-registered with, in order.
    ///
    /// Each entry is an explicit copy of a secret: for tests and the
    /// simulation only, never logged.
    pub fn rekeyed_psks(&self) -> Vec<Option<SecretString>> {
        self.rekeyed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|psk| psk.as_ref().map(SecretString::duplicate))
            .collect()
    }

    /// Makes every following `rekey_peer` fail (rollback tests).
    pub fn fail_rekeys(&self, fail: bool) {
        self.fail_rekey.store(fail, Ordering::SeqCst);
    }

    /// Forces the transfer counter (`None` = unreadable).
    pub fn set_transfer_bytes(&self, bytes: Option<u64>) {
        self.transfer
            .store(bytes.unwrap_or(NO_COUNTER), Ordering::SeqCst);
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
        // Same rule as the real backend: the controller hands over a literal
        // endpoint, and a name reaching this point is a resolution skipped.
        crate::endpoint_resolution::literal_endpoint(&profile.endpoint)
            .map_err(|e| anyhow::anyhow!("endpoint `{}` invalide : {e}", profile.endpoint))?;

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

    async fn rekey_peer(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()> {
        profile.validate_for_data_plane()?;
        crate::endpoint_resolution::literal_endpoint(&profile.endpoint)
            .map_err(|e| anyhow::anyhow!("endpoint `{}` invalide : {e}", profile.endpoint))?;
        if !self.adapter_up.load(Ordering::SeqCst) {
            anyhow::bail!("[dry-run] aucun adaptateur monté : aucun pair à réinscrire");
        }
        if self.fail_rekey.load(Ordering::SeqCst) {
            anyhow::bail!("[dry-run] réinscription du pair refusée");
        }
        self.rekeyed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(profile.preshared_key.as_ref().map(SecretString::duplicate));
        self.transfer.store(0, Ordering::SeqCst);
        self.handshake_age_secs.store(0, Ordering::SeqCst);
        sink(ClientEvent::log(
            "info",
            "[dry-run] pair réinscrit — session WireGuard réinitialisée".to_string(),
        ));
        Ok(())
    }

    async fn transfer_bytes(&self) -> Option<u64> {
        match self.transfer.load(Ordering::SeqCst) {
            NO_COUNTER => None,
            bytes => Some(bytes),
        }
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

    /// The simulation refuses a name like the real backend does: the
    /// controller resolves it first, and a test that skipped that step must
    /// not pass here only to fail on a machine with WireGuard.
    #[tokio::test]
    async fn a_hostname_endpoint_is_refused_before_mounting() {
        let backend = DryRunBackend::default();
        let (sink, _log) = collector();
        let mut named = profile();
        named.endpoint = "gateway.example:51820".into();
        assert!(backend.up(&named, &sink).await.is_err());
        assert!(!backend.adapter_is_up());
    }

    #[tokio::test]
    async fn rekeying_re_registers_the_peer_and_restarts_its_counters() {
        let backend = DryRunBackend {
            negotiate_delay: Duration::ZERO,
            ..DryRunBackend::default()
        };
        let (sink, _log) = collector();
        let mut profile = profile();
        backend.up(&profile, &sink).await.unwrap();
        backend.set_transfer_bytes(Some(4096));
        backend.set_handshake_age(Some(Duration::from_secs(90)));

        profile.preshared_key = Some("cGVlcnBza3BlZXJwc2twZWVycHNrcGVlcnBzazEyMw==".into());
        backend.rekey_peer(&profile, &sink).await.unwrap();

        assert_eq!(
            backend.rekeyed_psks(),
            vec![profile.preshared_key.as_ref().map(SecretString::duplicate)]
        );
        assert_eq!(
            backend.transfer_bytes().await,
            Some(0),
            "a re-registered peer counts from zero"
        );
        assert_eq!(backend.last_handshake_age().await, Some(Duration::ZERO));
    }

    #[tokio::test]
    async fn rekeying_needs_a_mounted_adapter_and_can_be_made_to_fail() {
        let backend = DryRunBackend::default();
        let (sink, _log) = collector();
        assert!(
            backend.rekey_peer(&profile(), &sink).await.is_err(),
            "no adapter"
        );

        let backend = DryRunBackend {
            negotiate_delay: Duration::ZERO,
            ..DryRunBackend::default()
        };
        backend.up(&profile(), &sink).await.unwrap();
        backend.fail_rekeys(true);
        assert!(backend.rekey_peer(&profile(), &sink).await.is_err());
        assert!(backend.rekeyed_psks().is_empty());
    }
}
