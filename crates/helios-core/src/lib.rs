//! Types fondamentaux partagés par tous les composants Helios.
//!
//! Ce crate ne dépend d'aucune ressource système (ni Netlink, ni VICI, ni RAUC) :
//! il compile et se teste partout, y compris sur WSL2. C'est lui qui porte la
//! sémantique métier du projet — en particulier la machine à états du tunnel et
//! la politique de kill-switch « fail-closed ».

pub mod config;
pub mod error;
pub mod policy;
pub mod state;

pub use config::{Config, Connection};
pub use error::{HeliosError, Result};
pub use policy::{FirewallPolicy, PolicyMode};
pub use state::{TunnelEvent, TunnelState};
