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

/// Removes a peer from admission.
pub async fn revoke(client: &Client, base: &str, name: &str) -> Result<PeerSummary> {
    api::post_json(client, base, "/api/peers/revoke", &RevokeBody { name }).await
}

pub async fn cmd_revoke(client: &Client, base: &str, name: &str) -> Result<()> {
    let peer = revoke(client, base, name).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk).await.expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let header_end = header_end + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if request.len() >= header_end + content_length {
                break;
            }
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    async fn response_server(body: String) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local listener");
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("HTTP request");
            let request = read_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
            request
        });
        (format!("http://{address}"), task)
    }

    fn peer_summary(name: &str, admin: bool, mode: &str) -> String {
        serde_json::json!({
            "name": name,
            "public_key": "peer-public",
            "address": "100.64.1.2/32",
            "admin": admin,
            "minimum_key_negotiation_mode": mode
        })
        .to_string()
    }

    fn network_view(peers: serde_json::Value) -> String {
        serde_json::json!({
            "wan_iface": "eth0",
            "lan_ifaces": [],
            "allow_ssh_from": [],
            "admin_iface": "helios0",
            "wg_iface": "helios0",
            "wg_private_key_configured": true,
            "wg_public_key": "gateway-public",
            "wg_address": "100.64.0.1/10",
            "wg_listen_port": 51820,
            "key_negotiation_port": 51821,
            "peers": peers
        })
        .to_string()
    }

    #[test]
    fn admission_body_omits_absent_fingerprints_without_weakening_the_floor() {
        let body = AdmitBody {
            name: "portable",
            public_key: "public",
            admin: false,
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: ProtectionMode::Classic,
        };
        let value = serde_json::to_value(body).unwrap();

        assert_eq!(value["minimum_key_negotiation_mode"], "classic");
        assert!(value.get("key_negotiation_certificate_sha256").is_none());
        assert!(value.get("key_negotiation_pq_certificate_sha256").is_none());
    }

    #[test]
    fn admission_body_carries_both_pins_and_the_explicit_mode() {
        let body = AdmitBody {
            name: "admin",
            public_key: "public",
            admin: true,
            key_negotiation_certificate_sha256: Some("tls-pin"),
            key_negotiation_pq_certificate_sha256: Some("pq-pin"),
            minimum_key_negotiation_mode: ProtectionMode::MlKem,
        };
        let value = serde_json::to_value(body).unwrap();

        assert_eq!(value["admin"], true);
        assert_eq!(value["key_negotiation_certificate_sha256"], "tls-pin");
        assert_eq!(value["key_negotiation_pq_certificate_sha256"], "pq-pin");
        assert_eq!(value["minimum_key_negotiation_mode"], "ml_kem");
    }

    #[test]
    fn revocation_body_names_only_the_target_peer() {
        let value = serde_json::to_value(RevokeBody { name: "portable" }).unwrap();
        assert_eq!(value, serde_json::json!({ "name": "portable" }));
    }

    #[tokio::test]
    async fn admission_and_revocation_call_the_expected_routes() {
        let client = Client::new();
        let (base, server) = response_server(peer_summary("portable", false, "classic")).await;
        let admitted = admit(
            &client,
            &base,
            "portable",
            "peer-public",
            false,
            Some("tls"),
        )
        .await
        .unwrap();
        assert_eq!(admitted.name, "portable");
        assert_eq!(
            admitted.minimum_key_negotiation_mode,
            ProtectionMode::Classic
        );
        let request = server.await.unwrap();
        assert!(request.starts_with("POST /api/peers "));
        assert!(request.contains("\"key_negotiation_certificate_sha256\":\"tls\""));

        let (base, server) = response_server(peer_summary("portable", false, "classic")).await;
        let removed = revoke(&client, &base, "portable").await.unwrap();
        assert_eq!(removed.address, "100.64.1.2/32");
        let request = server.await.unwrap();
        assert!(request.starts_with("POST /api/peers/revoke "));
        assert!(request.contains("\"name\":\"portable\""));
    }

    #[tokio::test]
    async fn command_wrappers_cover_policy_and_empty_or_populated_lists() {
        let client = Client::new();
        let (base, server) = response_server(peer_summary("admin", true, "ml_kem")).await;
        cmd_add(
            &client,
            &base,
            "admin",
            "peer-public",
            true,
            KeyNegotiationAdmission {
                tls_certificate_sha256: Some("tls"),
                pq_certificate_sha256: Some("pq"),
                minimum_mode: ProtectionMode::MlKem,
            },
        )
        .await
        .unwrap();
        let request = server.await.unwrap();
        assert!(request.contains("\"minimum_key_negotiation_mode\":\"ml_kem\""));

        let (base, server) = response_server(peer_summary("admin", true, "ml_kem")).await;
        cmd_revoke(&client, &base, "admin").await.unwrap();
        server.await.unwrap();

        let (base, server) = response_server(network_view(serde_json::json!([]))).await;
        cmd_list(&client, &base).await.unwrap();
        server.await.unwrap();

        let peer = serde_json::json!({
            "name": "admin",
            "public_key": "short",
            "address": "100.64.1.2/32",
            "preshared_key_configured": true,
            "key_negotiation_certificate_sha256": "tls",
            "key_negotiation_pq_certificate_sha256": "pq",
            "minimum_key_negotiation_mode": "ml_kem",
            "admin": true
        });
        let (base, server) = response_server(network_view(serde_json::json!([peer]))).await;
        cmd_list(&client, &base).await.unwrap();
        server.await.unwrap();
    }
}
