//! Remote admission of clients, from the operator workstation.
//!
//! Nominal path of ADR-004 §4: the mutation is played by the gateway, which
//! alone holds the complete configuration. The tool neither re-reads nor
//! rewrites the configuration — a round trip from the redacted view would
//! erase the PSKs of other peers and cut off the whole fleet.

use aether::key_negotiation::ProtectionMode;
use anyhow::Result;
use reqwest::Client;
use serde::Serialize;

use crate::api::{self, PeerSummary};

#[derive(Serialize)]
struct AdmitBody<'a> {
    name: &'a str,
    public_key: &'a str,
    admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_negotiation_certificate_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_negotiation_pq_certificate_sha256: Option<&'a str>,
    minimum_key_negotiation_mode: ProtectionMode,
}

#[derive(Serialize)]
struct RevokeBody<'a> {
    name: &'a str,
}

pub struct KeyNegotiationAdmission<'a> {
    pub tls_certificate_sha256: Option<&'a str>,
    pub pq_certificate_sha256: Option<&'a str>,
    pub minimum_mode: ProtectionMode,
}

/// Admits a peer and returns the VIP the gateway derived for it.
pub async fn admit(
    client: &Client,
    base: &str,
    name: &str,
    public_key: &str,
    admin: bool,
    certificate_sha256: Option<&str>,
) -> Result<PeerSummary> {
    admit_with_policy(
        client,
        base,
        name,
        public_key,
        admin,
        KeyNegotiationAdmission {
            tls_certificate_sha256: certificate_sha256,
            pq_certificate_sha256: None,
            minimum_mode: ProtectionMode::Classic,
        },
    )
    .await
}

pub async fn admit_with_policy(
    client: &Client,
    base: &str,
    name: &str,
    public_key: &str,
    admin: bool,
    key_negotiation: KeyNegotiationAdmission<'_>,
) -> Result<PeerSummary> {
    api::post_json(
        client,
        base,
        "/api/peers",
        &AdmitBody {
            name,
            public_key,
            admin,
            key_negotiation_certificate_sha256: key_negotiation.tls_certificate_sha256,
            key_negotiation_pq_certificate_sha256: key_negotiation.pq_certificate_sha256,
            minimum_key_negotiation_mode: key_negotiation.minimum_mode,
        },
    )
    .await
}

pub async fn cmd_add(
    client: &Client,
    base: &str,
    name: &str,
    public_key: &str,
    admin: bool,
    key_negotiation: KeyNegotiationAdmission<'_>,
) -> Result<()> {
    let peer = admit_with_policy(client, base, name, public_key, admin, key_negotiation).await?;
    println!(
        "{} {} admitted → {}{}",
        crate::ok(),
        peer.name,
        peer.address,
        if peer.admin { "  [admin]" } else { "" }
    );
    println!("\n  \x1b[2mpublic key: {}\x1b[0m", peer.public_key);
    println!(
        "  \x1b[2mminimum key-negotiation mode: {:?}\x1b[0m",
        peer.minimum_key_negotiation_mode
    );
    println!("  \x1b[2mVIP derived from this key: the client will find it at enrollment.\x1b[0m");
    Ok(())
}

pub async fn cmd_revoke(client: &Client, base: &str, name: &str) -> Result<()> {
    let peer: PeerSummary =
        api::post_json(client, base, "/api/peers/revoke", &RevokeBody { name }).await?;
    println!("{} {} removed from admission", crate::ok(), peer.name);
    println!("\n  \x1b[2mThe peer will drop at its next handshake; there is no\x1b[0m");
    println!("  \x1b[2mcryptographic revocation (ADR-004).\x1b[0m");
    Ok(())
}

pub async fn cmd_list(client: &Client, base: &str) -> Result<()> {
    let view = api::network(client, base).await?;
    if view.peers.is_empty() {
        println!("\n  no admitted peers\n");
        return Ok(());
    }

    println!();
    println!("  \x1b[1mAdmitted peers\x1b[0m ({})", view.peers.len());
    println!();
    for peer in &view.peers {
        let role = if peer.admin { "  [admin]" } else { "" };
        let pq = if peer.preshared_key_configured {
            "  [PQ]"
        } else {
            ""
        };
        let certificate = if peer.key_negotiation_certificate_sha256.is_some() {
            "  [key-nego]"
        } else {
            ""
        };
        let pq_certificate = if peer.key_negotiation_pq_certificate_sha256.is_some() {
            "  [ML-DSA]"
        } else {
            ""
        };
        let key = peer.public_key.get(..12).unwrap_or(&peer.public_key);
        println!(
            "  {:<20} {:<18} {key}…{role}{pq}{certificate}{pq_certificate}  [min={:?}]",
            peer.name, peer.address, peer.minimum_key_negotiation_mode
        );
    }
    println!();
    Ok(())
}
