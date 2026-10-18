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

use crate::{
    api::{self, PeerSummary},
    ui::{self, Ui},
};

#[derive(Serialize)]
struct AdmitBody<'a> {
    name: &'a str,
    public_key: &'a str,
    admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_negotiation_certificate_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_negotiation_pq_certificate_sha256: Option<&'a str>,
    /// The two leaves themselves, base64 — DER for the TLS one, the JSON
    /// document for the PQ one. The fingerprints above are what the peer table
    /// pins; these are what the certificate registry records, and a gateway
    /// holding a trust domain refuses an admission without them.
    #[serde(skip_serializing_if = "Option::is_none")]
    key_negotiation_certificate: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_negotiation_pq_certificate: Option<&'a str>,
    minimum_key_negotiation_mode: ProtectionMode,
}

#[derive(Serialize)]
struct RevokeBody<'a> {
    name: &'a str,
}

pub struct KeyNegotiationAdmission<'a> {
    pub tls_certificate_sha256: Option<&'a str>,
    pub pq_certificate_sha256: Option<&'a str>,
    /// Base64 DER of the client's TLS leaf.
    pub tls_certificate: Option<&'a str>,
    /// Base64 of the client's PQ leaf, as a JSON document.
    pub pq_certificate: Option<&'a str>,
    pub minimum_mode: ProtectionMode,
}

/// Admits a peer and returns the VIP the gateway derived for it.
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
            key_negotiation_certificate: key_negotiation.tls_certificate,
            key_negotiation_pq_certificate: key_negotiation.pq_certificate,
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
    let ui = Ui::detect();
    let mut out = ui.done(&format!("{} admitted", peer.name));
    out.push('\n');
    out.push_str(&ui.field("Address", &peer.address));
    out.push_str(&ui.field(
        "Role",
        if peer.admin {
            "administrator"
        } else {
            "client"
        },
    ));
    out.push_str(&ui.field(
        "Negotiation",
        &format!(
            "{} minimum",
            ui::protection_mode(peer.minimum_key_negotiation_mode)
        ),
    ));
    out.push_str(&ui.field("Public key", &peer.public_key));
    out.push('\n');
    out.push_str(&ui.note("The address derives from the key: the client learns it at enrollment."));
    print!("{out}");
    Ok(())
}

/// Removes a peer from admission.
pub async fn revoke(client: &Client, base: &str, name: &str) -> Result<PeerSummary> {
    api::post_json(client, base, "/api/peers/revoke", &RevokeBody { name }).await
}

pub async fn cmd_revoke(client: &Client, base: &str, name: &str) -> Result<()> {
    let peer = revoke(client, base, name).await?;
    let ui = Ui::detect();
    print!(
        "{}{}",
        ui.done(&format!("{} removed from admission", peer.name)),
        ui.note(
            "It drops at its next handshake; WireGuard has no cryptographic revocation (ADR-004)."
        )
    );
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

    #[test]
    fn admission_body_omits_absent_fingerprints_without_weakening_the_floor() {
        let body = AdmitBody {
            name: "portable",
            public_key: "public",
            admin: false,
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            key_negotiation_certificate: None,
            key_negotiation_pq_certificate: None,
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
            key_negotiation_certificate: Some("dGxz"),
            key_negotiation_pq_certificate: Some("cHE="),
            minimum_key_negotiation_mode: ProtectionMode::MlKem,
        };
        let value = serde_json::to_value(body).unwrap();

        assert_eq!(value["admin"], true);
        assert_eq!(value["key_negotiation_certificate_sha256"], "tls-pin");
        assert_eq!(value["key_negotiation_pq_certificate_sha256"], "pq-pin");
        assert_eq!(value["key_negotiation_certificate"], "dGxz");
        assert_eq!(value["key_negotiation_pq_certificate"], "cHE=");
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
        let (base, server) = response_server(peer_summary("portable", false, "ml_kem")).await;
        let admitted = admit_with_policy(
            &client,
            &base,
            "portable",
            "peer-public",
            false,
            KeyNegotiationAdmission {
                tls_certificate_sha256: Some("tls"),
                pq_certificate_sha256: Some("pq"),
                tls_certificate: None,
                pq_certificate: None,
                minimum_mode: ProtectionMode::MlKem,
            },
        )
        .await
        .unwrap();
        assert_eq!(admitted.name, "portable");
        assert_eq!(admitted.minimum_key_negotiation_mode, ProtectionMode::MlKem);
        let request = server.await.unwrap();
        assert!(request.starts_with("POST /api/peers "));
        assert!(request.contains("\"key_negotiation_certificate_sha256\":\"tls\""));
        assert!(request.contains("\"key_negotiation_pq_certificate_sha256\":\"pq\""));

        let (base, server) = response_server(peer_summary("portable", false, "classic")).await;
        let removed = revoke(&client, &base, "portable").await.unwrap();
        assert_eq!(removed.address, "100.64.1.2/32");
        let request = server.await.unwrap();
        assert!(request.starts_with("POST /api/peers/revoke "));
        assert!(request.contains("\"name\":\"portable\""));
    }

    #[tokio::test]
    async fn command_wrappers_send_the_policy_and_the_revocation() {
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
                tls_certificate: None,
                pq_certificate: None,
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
    }
}
