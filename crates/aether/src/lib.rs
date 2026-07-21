//! Le milieu partagé par Helios (la gateway) et Orion (le client) : types
//! communs, machine à états du tunnel, politique de kill-switch « fail-closed »,
//! et l'échange post-quantique ML-KEM ([`pq`]).
//!
//! Aucune dépendance à une **ressource système au runtime** (ni Netlink, ni TPM,
//! ni systemd) : le crate se teste partout, WSL2 compris. Seule exception, à la
//! compilation : [`pq`] tire `aws-lc-rs` (AWS-LC), qui construit un peu de C via
//! le crate `cc` — comme `ring`, déjà présent. Cela n'exige qu'un compilateur C,
//! pas de toolchain CMake/Go (voir ADR-001 §2 et les notes de vigilance).

pub mod config;
pub mod enroll;
pub mod error;
pub mod events;
pub mod mtu;
pub mod policy;
pub mod pq;
pub mod secret;
pub mod sig;
pub mod state;

pub use config::{NetworkConfig, WgPeer, API_BIND_LOOPBACK, API_PORT};
pub use error::{HeliosError, Result};
pub use events::{HeliosEvent, InstallPskRequest, OrchestratorCmd};
pub use policy::{FirewallPolicy, PolicyMode};
pub use pq::{Kem, MlKem768Kem, PqError, SharedSecret};
pub use secret::SecretString;
pub use state::{TunnelEvent, TunnelState};
