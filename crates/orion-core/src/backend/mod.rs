//! WireGuard backend abstraction and connection controller.
//!
//! # The adapter lifecycle invariant — read before modifying
//!
//! Orion is deliberately **fail-open** (CWE-636): no firewall, no WFP
//! (ADR-001 §3 bis). Its only protection against leaking in clear is a
//! lifecycle discipline:
//!
//! > The adapter (Wintun) carries `AllowedIPs = 0.0.0.0/0, ::/0`. It is
//! > mounted on connection and **is NEVER unmounted on failure** — neither in
//! > `Connecting`, nor in `Failed`, nor after N attempts. It is removed only on
//! > **explicit disconnection** by the user or application shutdown.
//!
//! As long as the adapter holds, packets go out toward WireGuard, which
//! **drops** them if the session is dead: an attacker who blocks UDP 51820
//! only gets a denial of service. If it falls, the default route falls back to
//! the physical interface and traffic exits **in clear**.
//!
//! The drop covers what the adapter captures and nothing more. A profile
//! stored with `0.0.0.0/0` alone — the default before `::/0` joined it — sends
//! its IPv6 out of the physical interface even with the tunnel up; it is
//! flagged by [`ClientProfile::ipv6_uncaptured_full_tunnel`], never widened
//! behind the user's back.
//!
//! This is why the trait separates [`VpnBackend::up`] from
//! [`VpnBackend::down`]: `down` is only called from
//! [`VpnController::disconnect`], never on an error path. The test
//! `adapter_stays_mounted_after_failure` locks in this property.
//!
//! Only [`dryrun::DryRunBackend`] is compiled by default (testable on WSL2). The
//! real WireGuard backend (BoringTun + Wintun via `defguard_wireguard_rs`) is
//! target-only, just like the `netlink` feature on the heliosd side.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use aether::TunnelState;
use anyhow::Context as _;
use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::config::ClientProfile;
use crate::events::{ClientEvent, PskKind};

pub mod dryrun;
pub mod renewal;
#[cfg(feature = "wireguard")]
pub mod wireguard;

/// Beyond this age, the last handshake is considered stale and the state
/// falls back from `Up` to `Connecting`.
///
/// 150 s leaves margin under `REJECT_AFTER_TIME` (180 s): at 179 s we would
/// flap at the slightest jitter (ADR-001 §3).
pub const HANDSHAKE_STALE_AFTER: Duration = Duration::from_secs(150);

/// Event sink: the backend pushes its state transitions and logs here.
/// The Tauri shell provides an implementation that relays to the frontend.
pub type EventSink = Arc<dyn Fn(ClientEvent) + Send + Sync>;

/// A WireGuard stack capable of mounting/unmounting a tunnel to a gateway.
#[async_trait]
pub trait VpnBackend: Send + Sync {
    /// Mounts the adapter (the profile's `AllowedIPs`, by default
    /// `0.0.0.0/0, ::/0`) and configures the peer.
    ///
    /// **Contract**: on failure, the implementation must **not** unmount
    /// the adapter if it succeeded in creating it — letting WireGuard drop
    /// packets is better than giving back the physical route to clear traffic.
    /// Must be idempotent: calling `up` again on an already-mounted adapter
    /// reconfigures the peer without recreating it.
    ///
    /// A backend able to read back what the driver applied reports it as
    /// [`ClientEvent::Capture`] on every call. A capture narrower than the
    /// profile is reported, not returned as an error: the adapter stays
    /// mounted either way, so failing would not stop the leak, only drop
    /// what *is* captured (see `wireguard`'s module documentation).
    ///
    /// `profile.endpoint` is a **literal** `IP:port` here, chosen by
    /// [`VpnController`] from a single resolution; a backend refuses a name
    /// instead of resolving it a second time (`endpoint_resolution`).
    async fn up(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()>;

    /// Unmounts the adapter. **Called only on explicit disconnection.**
    async fn down(&self, sink: &EventSink) -> anyhow::Result<()>;

    /// Re-registers the peer from `profile`, which resets its WireGuard session.
    ///
    /// The in-tunnel PSK renewal needs a handshake **after** the new PSK is in
    /// place, and changing a peer's configuration does not reset its session:
    /// WireGuard would only rekey after 120 s of use (spec §12.3). Removing
    /// then re-adding the peer does. Costs one handshake of interruption.
    ///
    /// **Contract**: never unmounts the adapter, whatever fails.
    async fn rekey_peer(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()>;

    /// Bytes sent plus received with the peer since it was last registered,
    /// or `None` when the data plane cannot say.
    async fn transfer_bytes(&self) -> Option<u64>;

    /// Age of the last successful handshake, or `None` if none.
    /// Source of state inference (WireGuard is connectionless).
    async fn last_handshake_age(&self) -> Option<Duration>;

    /// Is the adapter currently mounted? Used to check the invariant.
    fn adapter_is_up(&self) -> bool;

    /// Human-readable backend identifier (diagnostics / UI).
    fn kind(&self) -> &'static str;
}

/// Selects the backend according to compiled features. Without a real backend
/// compiled in, falls back to dry-run simulation (WSL2/dev case).
///
/// With the `wireguard` feature, attempts the real backend; if it can't even
/// initialize (data plane absent, insufficient privileges), it **fails while
/// logging** rather than silently falling back to simulation: a user who
/// believes their traffic is encrypted when it isn't would be far worse than
/// a visible error.
pub fn default_backend() -> anyhow::Result<Arc<dyn VpnBackend>> {
    #[cfg(feature = "wireguard")]
    {
        let backend = wireguard::WireGuardBackend::new()
            .map_err(|e| anyhow::anyhow!("real WireGuard backend unavailable: {e}"))?;
        Ok(Arc::new(backend))
    }
    #[cfg(not(feature = "wireguard"))]
    Ok(Arc::new(dryrun::DryRunBackend::default()))
}

mod controller;
mod negotiation;
mod slot_renewal;

pub use controller::VpnController;
use controller::*;
use negotiation::*;
use slot_renewal::*;

#[cfg(test)]
mod tests;
