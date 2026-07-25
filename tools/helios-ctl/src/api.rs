//! Control-plane types and calls, as exposed by the API.
//!
//! These views are deliberately **distinct** from `aether::NetworkConfig`:
//! the API redacts what it returns (no private key, no PSK), and a tool that
//! deserialized the full structure would suggest it holds fields the gateway
//! never sends.

use aether::key_negotiation::ProtectionMode;
use anyhow::{Context, Result};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Secret-free view returned by `GET /api/network`.
#[derive(Debug, Deserialize)]
pub struct NetworkConfigView {
    pub wan_iface: String,
    pub lan_ifaces: Vec<String>,
    pub allow_ssh_from: Vec<String>,
    pub admin_iface: Option<String>,
    pub wg_iface: String,
    pub wg_private_key_configured: bool,
    /// Gateway public key: the `peer_public_key` of client profiles.
    pub wg_public_key: Option<String>,
    pub wg_address: String,
    pub wg_listen_port: u16,
    pub key_negotiation_port: Option<u16>,
    pub peers: Vec<NetworkPeerView>,
}

#[derive(Debug, Deserialize)]
pub struct NetworkPeerView {
    pub name: String,
    pub public_key: String,
    pub address: String,
    pub preshared_key_configured: bool,
    pub key_negotiation_certificate_sha256: Option<String>,
    pub key_negotiation_pq_certificate_sha256: Option<String>,
    pub minimum_key_negotiation_mode: ProtectionMode,
    pub admin: bool,
}

/// Peer returned by the admission routes.
///
/// Partial view: `post_quantum` is omitted — admission never installs a PSK,
/// and showing one would suggest otherwise.
#[derive(Debug, Deserialize)]
pub struct PeerSummary {
    pub name: String,
    pub public_key: String,
    pub address: String,
    pub admin: bool,
    pub minimum_key_negotiation_mode: ProtectionMode,
}

#[derive(Debug, Deserialize)]
pub struct CmdResp {
    pub ok: bool,
    pub error: Option<String>,
}

/// Public key-negotiation material served by `GET /api/key-negotiation`.
///
/// These are the exact values an Orion profile pins. Fetching them from the
/// gateway rather than from files on the operator workstation removes the
/// failure this tooling saw most: a profile pinned to a certificate the
/// gateway has since rotated.
#[derive(Debug, Deserialize)]
pub struct KeyNegotiationView {
    pub port: Option<u16>,
    pub server_name: String,
    pub gateway_ca_der: String,
    pub gateway_pq_certificate: String,
    pub pq_certificate_sha256: String,
    pub wireguard_public_key: String,
}

/// Reads the negotiation material, or `None` if the gateway serves none.
///
/// The absence is a legitimate configuration — an older gateway, or one
/// without the feature — so it is returned rather than raised: the caller
/// decides whether it can proceed without it.
pub async fn key_negotiation(client: &Client, base: &str) -> Result<Option<KeyNegotiationView>> {
    let response = client
        .get(format!("{base}/api/key-negotiation"))
        .send()
        .await
        .context("connection refused — is heliosd reachable through the tunnel?")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let status = response.status();
    let text = response.text().await.context("unreadable response body")?;
    if !status.is_success() {
        anyhow::bail!("{} : {}", status, text.trim());
    }
    serde_json::from_str(&text)
        .map(Some)
        .context("unexpected JSON response from /api/key-negotiation")
}

pub async fn network(client: &Client, base: &str) -> Result<NetworkConfigView> {
    client
        .get(format!("{base}/api/network"))
        .send()
        .await
        .context("connection refused — is heliosd reachable through the tunnel?")?
        .json()
        .await
        .context("unexpected JSON response from /api/network")
}

/// Posts a JSON body and decodes the response, surfacing the rejection as-is.
///
/// Mutation routes reply in plain text on error: without this handling, a
/// perfectly explicit admission refusal would show up to the operator as
/// "unexpected JSON response".
pub async fn post_json<B: Serialize, T: DeserializeOwned>(
    client: &Client,
    base: &str,
    path: &str,
    body: &B,
) -> Result<T> {
    let response = client
        .post(format!("{base}{path}"))
        .json(body)
        .send()
        .await
        .context("connection refused — is heliosd reachable through the tunnel?")?;

    let status = response.status();
    let text = response.text().await.context("unreadable response body")?;
    if !status.is_success() {
        anyhow::bail!("{} : {}", status, text.trim());
    }
    serde_json::from_str(&text)
        .with_context(|| format!("unexpected JSON response from {path}: {text}"))
}
