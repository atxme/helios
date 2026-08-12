//! The shared ground between Helios (the gateway) and Orion (the client):
//! common types, tunnel state machine, "fail-closed" kill-switch policy, and
//! the post-quantum ML-KEM exchange ([`pq`]).
//!
//! No dependency on a **system resource at runtime** (neither Netlink, nor
//! TPM, nor systemd): the crate is testable everywhere, WSL2 included. The
//! only exception, at compile time: [`pq`] pulls in `aws-lc-rs` (AWS-LC),
//! which builds a bit of C via the `cc` crate — like `ring`, already
//! present. This only requires a C compiler, no CMake/Go toolchain (see
//! ADR-001 §2 and the vigilance notes).

pub mod certificates;
pub mod config;
pub mod enroll;
pub mod error;
pub mod events;
pub mod key_negotiation;
pub mod locked;
pub mod mtu;
pub mod policy;
pub mod pq;
pub mod private_file;
pub mod secret;
pub mod sig;
pub mod state;
pub mod wg;

pub use config::{
    NetworkConfig, WgPeer, API_BIND_LOOPBACK, API_PORT, DEFAULT_WG_ADDRESS, DEFAULT_WG_API_URL,
};
pub use error::{HeliosError, Result};
pub use events::{HeliosEvent, InstallPskRequest, ObserveHandshakeRequest, OrchestratorCmd};
pub use policy::{FirewallPolicy, PolicyMode};
pub use pq::{Kem, MlKem1024Kem, PqError, SharedSecret};
pub use secret::SecretString;
pub use state::{TunnelEvent, TunnelState};
