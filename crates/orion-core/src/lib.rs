//! Core logic of the Orion client.
//!
//! This crate depends on neither Tauri nor webkit: it compiles and is tested
//! everywhere, including on WSL2. It carries three things:
//!
//! 1. [`config`] — the **VPN profile**, editable and persisted locally
//!    (gateway endpoint, WireGuard keys, VIP, allowed routes and keepalive).
//! 2. [`backend`] — the `VpnBackend` that **actually mounts the tunnel** via
//!    the OS's WireGuard stack. Only `DryRunBackend` is compiled by default
//!    (testable on WSL2); real backends are behind features, like `netlink`.
//! 3. [`telemetry`] — consumption of heliosd's web API, which is only
//!    reachable **after** the tunnel is mounted (the web server lives
//!    *behind* WireGuard).
//!
//! ## Architecture invariant (never to be violated)
//!
//! A WireGuard client connects to a gateway via its **UDP endpoint**
//! (IP/FQDN), not an HTTP URL. heliosd's web server is only accessible once
//! the tunnel is established — so it is **never** used to bring up the
//! connection, only for post-connection telemetry. This is why
//! [`telemetry::run`] is only started on transition to
//! [`aether::TunnelState::Up`].

pub mod backend;
pub mod certificate_inventory;
pub mod certificates;
pub mod config;
pub mod events;
pub mod identity_store;
pub mod key_negotiation;
pub mod mtu;
pub mod net_pin;
pub mod profile_import;
pub mod provisioning;
pub mod telemetry;
pub mod vault;

pub use backend::{default_backend, EventSink, VpnBackend, VpnController, HANDSHAKE_STALE_AFTER};
pub use certificate_inventory::{CertificateFacts, CertificateInventory, CertificatePhase};
pub use config::{
    ClientConfig, ClientProfile, KeyNegotiationSettings, DEFAULT_ALLOWED_IPS,
    DEFAULT_KEEPALIVE_SECS,
};
pub use events::{ClientEvent, PskKind};
pub use identity_store::{ClientIdentityBundle, IdentityStoreError, ProtectedIdentityStore};
pub use profile_import::{
    complete_profile_import, inspect_profile, parse_profile_import, read_profile_import_path,
    CompletedImport, ProfileImport, ProfileIssues, MAX_PROFILE_IMPORT_BYTES,
};
pub use provisioning::{provision, ProvisionError, ProvisionOutcome};
