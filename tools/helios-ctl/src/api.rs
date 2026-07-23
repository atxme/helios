//! Types et appels du plan de contrôle, tels que l'API les expose.
//!
//! Ces vues sont volontairement **distinctes** de `aether::NetworkConfig` :
//! l'API rédige ce qu'elle renvoie (ni clé privée, ni PSK), et un outil qui
//! désérialiserait la structure complète laisserait croire qu'il détient des
//! champs que la gateway n'envoie jamais.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Vue sans secret renvoyée par `GET /api/network`.
#[derive(Debug, Deserialize)]
pub struct NetworkConfigView {
    pub wan_iface: String,
    pub lan_ifaces: Vec<String>,
    pub allow_ssh_from: Vec<String>,
    pub admin_iface: Option<String>,
    pub wg_iface: String,
    pub wg_private_key_configured: bool,
    /// Clé publique de la gateway : `peer_public_key` des profils clients.
    pub wg_public_key: Option<String>,
    pub wg_address: String,
    pub wg_listen_port: u16,
    pub peers: Vec<NetworkPeerView>,
}

#[derive(Debug, Deserialize)]
pub struct NetworkPeerView {
    pub name: String,
    pub public_key: String,
    pub address: String,
    pub preshared_key_configured: bool,
    pub admin: bool,
}

/// Pair renvoyé par les routes d'admission.
///
/// Vue partielle : `post_quantum` est ignoré, une admission ne pose jamais de
/// PSK et l'afficher laisserait croire le contraire.
#[derive(Debug, Deserialize)]
pub struct PeerSummary {
    pub name: String,
    pub public_key: String,
    pub address: String,
    pub admin: bool,
}

#[derive(Debug, Deserialize)]
pub struct CmdResp {
    pub ok: bool,
    pub error: Option<String>,
}

pub async fn network(client: &Client, base: &str) -> Result<NetworkConfigView> {
    client
        .get(format!("{base}/api/network"))
        .send()
        .await
        .context("connexion refusée — heliosd est-il joignable dans le tunnel ?")?
        .json()
        .await
        .context("réponse JSON inattendue de /api/network")
}

/// Poste un corps JSON et décode la réponse, en remontant le refus tel quel.
///
/// Les routes de mutation répondent en texte brut sur erreur : sans ce
/// traitement, un refus d'admission parfaitement explicite se présenterait à
/// l'opérateur comme « réponse JSON inattendue ».
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
        .context("connexion refusée — heliosd est-il joignable dans le tunnel ?")?;

    let status = response.status();
    let text = response
        .text()
        .await
        .context("corps de réponse illisible")?;
    if !status.is_success() {
        anyhow::bail!("{} : {}", status, text.trim());
    }
    serde_json::from_str(&text)
        .with_context(|| format!("réponse JSON inattendue de {path} : {text}"))
}
