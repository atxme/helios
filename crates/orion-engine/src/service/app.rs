//! The application family: its state, the About box, the key-negotiation
//! support and the speed test. The shell reaches them through the engine.

use std::sync::Arc;

use aether::TunnelState;
use orion_core::{ClientEvent, SpeedTestProgressSink, SpeedTestResult};

use super::EngineService;
use crate::events::EventQueue;
use crate::view::{AboutView, KeyNegotiationSupport};

/// Extension of an Orion profile, without the dot.
///
/// It is the extension the installer registers, the one `helios` writes,
/// and the one the import filter offers. One constant so those three cannot
/// drift apart.
pub const PROFILE_EXTENSION: &str = "orion";

impl EngineService {
    pub fn get_state(&self) -> String {
        self.controller.state().as_str().to_string()
    }

    pub fn backend_kind(&self) -> &'static str {
        self.controller.backend_kind()
    }

    /// Indicates whether the WireGuard adapter is still mounted. On failure, it
    /// must remain up to capture routes and prevent a clear-text leak.
    pub fn adapter_is_up(&self) -> bool {
        self.controller.adapter_is_up()
    }

    pub fn about_orion(&self) -> AboutView {
        AboutView {
            version: self.app_version.to_string(),
            backend: self.controller.backend_kind().to_string(),
            profile_extension: PROFILE_EXTENSION.to_string(),
            log_path: self
                .log_path
                .as_ref()
                .map(|path| path.display().to_string()),
        }
    }

    pub fn key_negotiation_support(&self) -> KeyNegotiationSupport {
        KeyNegotiationSupport {
            identity_store: self.controller.key_negotiation_ready(),
        }
    }

    /// Measures the raw WireGuard data path to the active gateway.
    ///
    /// This command is intentionally available only while WireGuard is `Up`: the
    /// gateway's API lives behind that tunnel, and the Rust engine targets its
    /// fixed in-tunnel address. TCP/UDP data is exchanged on a dedicated socket;
    /// this command only relays progress and keeps the expensive benchmark
    /// serialized. The transfer implementation itself lives in `orion-core`, so
    /// it remains testable without Tauri or WebView.
    ///
    /// Progress goes out as [`ClientEvent::SpeedTest`] through `events`.
    pub async fn run_speed_test(
        &self,
        mode: String,
        events: &EventQueue,
    ) -> Result<SpeedTestResult, String> {
        let _exclusive = self
            .speedtest
            .try_lock()
            .map_err(|_| "un speedtest est déjà en cours".to_string())?;
        if self.controller.state() != TunnelState::Up || !self.controller.adapter_is_up() {
            return Err("le speedtest nécessite un tunnel WireGuard connecté".into());
        }
        let mode = orion_core::SpeedTestMode::parse(&mode).map_err(|error| error.to_string())?;
        let sink = events.sink();
        let progress: SpeedTestProgressSink = Arc::new(move |progress| {
            sink(ClientEvent::SpeedTest { progress });
        });
        orion_core::run_speedtest_with_progress(
            mode,
            aether::speedtest::SPEEDTEST_DEFAULT_DURATION_SECS,
            // No override: the UI runs `full`, where the UDP quality legs take
            // their rate from the TCP throughput measured moments earlier.
            None,
            progress,
        )
        .await
        .map_err(|error| error.to_string())
    }
}
