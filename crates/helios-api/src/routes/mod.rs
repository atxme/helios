use std::time::SystemTime;

use aether::{
    certificates::encoding::DerCertificate,
    key_negotiation::{PqCertificate, ProtectionMode},
    net::Ipv6TunnelStatus,
    NetworkConfig, OrchestratorCmd, SecretString, WgPeer,
};
use axum::{extract::State, http::StatusCode, Json};
use helios_firewall::ruleset;
use helios_provisioning::AdmissionOutcome;
use helios_wireguard::PeerStatus;
use serde::{Deserialize, Serialize};

use crate::certificates::TrustUpdateRefusalStatus;
use crate::AppState;

mod commands;
mod firewall;
mod network;
mod peers;
mod status;

pub use commands::*;
pub use firewall::*;
pub use network::*;
pub use peers::*;
pub use status::*;

#[cfg(test)]
mod tests;
