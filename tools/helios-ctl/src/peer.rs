//! Admission des clients à distance, depuis le poste opérateur.
//!
//! Chemin nominal de l'ADR-004 §4 : la mutation est jouée par la gateway, qui
//! seule détient la configuration complète. L'outil ne relit ni ne repose la
//! configuration — un aller-retour depuis la vue expurgée effacerait les PSK
//! des autres pairs et couperait tout le parc.

use anyhow::Result;
use reqwest::Client;
use serde::Serialize;

use crate::api::{self, PeerSummary};

#[derive(Serialize)]
struct AdmitBody<'a> {
    name: &'a str,
    public_key: &'a str,
    admin: bool,
}

#[derive(Serialize)]
struct RevokeBody<'a> {
    name: &'a str,
}

/// Admet un pair et renvoie la VIP que la gateway lui a dérivée.
pub async fn admit(
    client: &Client,
    base: &str,
    name: &str,
    public_key: &str,
    admin: bool,
) -> Result<PeerSummary> {
    api::post_json(
        client,
        base,
        "/api/peers",
        &AdmitBody {
            name,
            public_key,
            admin,
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
) -> Result<()> {
    let peer = admit(client, base, name, public_key, admin).await?;
    println!(
        "{} {} admis → {}{}",
        crate::ok(),
        peer.name,
        peer.address,
        if peer.admin { "  [admin]" } else { "" }
    );
    println!("\n  \x1b[2mclé publique : {}\x1b[0m", peer.public_key);
    println!("  \x1b[2mVIP dérivée de cette clé : le client la retrouvera à l'enrôlement.\x1b[0m");
    Ok(())
}

pub async fn cmd_revoke(client: &Client, base: &str, name: &str) -> Result<()> {
    let peer: PeerSummary =
        api::post_json(client, base, "/api/peers/revoke", &RevokeBody { name }).await?;
    println!("{} {} retiré de l'admission", crate::ok(), peer.name);
    println!("\n  \x1b[2mLe pair tombera à son prochain handshake ; il n'existe aucune\x1b[0m");
    println!("  \x1b[2mrévocation cryptographique (ADR-004).\x1b[0m");
    Ok(())
}

pub async fn cmd_list(client: &Client, base: &str) -> Result<()> {
    let view = api::network(client, base).await?;
    if view.peers.is_empty() {
        println!("\n  aucun pair admis\n");
        return Ok(());
    }

    println!();
    println!("  \x1b[1mPairs admis\x1b[0m ({})", view.peers.len());
    println!();
    for peer in &view.peers {
        let role = if peer.admin { "  [admin]" } else { "" };
        let pq = if peer.preshared_key_configured {
            "  [PQ]"
        } else {
            ""
        };
        let key = peer.public_key.get(..12).unwrap_or(&peer.public_key);
        println!("  {:<20} {:<18} {key}…{role}{pq}", peer.name, peer.address);
    }
    println!();
    Ok(())
}
