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
    /// Uplinks, in the gateway's order of preference: the API publishes the
    /// whole set, not a single interface.
    pub wan_ifaces: Vec<String>,
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
    decode_response(status, &text, "/api/key-negotiation").map(Some)
}

/// Trust material for one admitted peer, from
/// `GET /api/key-negotiation/trust-enrolment/<public key>` (spec §19).
///
/// The whole block, read in one call and under one lock on the gateway. An
/// epoch taken from one moment beside an anchor from another would pin a pair
/// that never existed together, and the mismatch surfaces at the first
/// renewal — 80 % into a leaf's life, on a client with no fallback.
///
/// Deserialized into `orion_core::TrustMaterial` directly: the profile writes
/// exactly what the gateway serves, and a struct in between would be a second
/// place for these eleven values to drift.
pub async fn trust_enrolment(
    client: &Client,
    base: &str,
    peer_public_key: &str,
) -> Result<Option<orion_core::TrustMaterial>> {
    let path = format!(
        "/api/key-negotiation/trust-enrolment/{}",
        urlencoding(peer_public_key)
    );
    let response = client
        .get(format!("{base}{path}"))
        .send()
        .await
        .context("connection refused — is heliosd reachable?")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        // Legitimate: a gateway whose trust domain is not bootstrapped, or a
        // peer admitted before it was. The caller decides whether it can emit
        // a profile without renewal rather than being stopped here.
        return Ok(None);
    }
    let status = response.status();
    let text = response.text().await.context("unreadable response body")?;
    decode_response(status, &text, &path).map(Some)
}

/// Percent-encodes what a WireGuard key can contain and a path segment cannot.
///
/// Base64 keys carry `+` and `/`, and `/` would silently split the segment —
/// the gateway would then look up a truncated key and answer «no such peer»,
/// which points at the admission rather than at the encoding.
fn urlencoding(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

pub async fn network(client: &Client, base: &str) -> Result<NetworkConfigView> {
    let response = client
        .get(format!("{base}/api/network"))
        .send()
        .await
        .context("connection refused — is heliosd reachable through the tunnel?")?;
    let status = response.status();
    let text = response.text().await.context("unreadable response body")?;
    decode_response(status, &text, "/api/network")
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
    decode_response(status, &text, path)
}

fn decode_response<T: DeserializeOwned>(
    status: reqwest::StatusCode,
    text: &str,
    path: &str,
) -> Result<T> {
    if !status.is_success() {
        anyhow::bail!("{} : {}", status, text.trim());
    }
    serde_json::from_str(text)
        .with_context(|| format!("unexpected JSON response from {path}: {text}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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

    async fn response_server(
        status: &str,
        body: String,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local listener");
        let address = listener.local_addr().unwrap();
        let status = status.to_string();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("HTTP request");
            let request = read_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

    #[test]
    fn response_decoding_preserves_server_rejections() {
        let error = decode_response::<CmdResp>(
            reqwest::StatusCode::CONFLICT,
            "  peer already exists \n",
            "/api/peers",
        )
        .expect_err("the HTTP rejection must be surfaced");

        assert_eq!(error.to_string(), "409 Conflict : peer already exists");
    }

    #[test]
    fn response_decoding_names_invalid_json_and_its_route() {
        let error = decode_response::<CmdResp>(
            reqwest::StatusCode::OK,
            "this is not JSON",
            "/api/tunnel/start",
        )
        .expect_err("invalid JSON must be refused");

        let message = error.to_string();
        assert!(message.contains("/api/tunnel/start"), "message: {message}");
        assert!(message.contains("this is not JSON"), "message: {message}");
    }

    #[test]
    fn command_and_network_views_decode_all_security_fields() {
        let command: CmdResp = decode_response(
            reqwest::StatusCode::OK,
            r#"{"ok":false,"error":"refused"}"#,
            "/api/tunnel/start",
        )
        .unwrap();
        assert!(!command.ok);
        assert_eq!(command.error.as_deref(), Some("refused"));

        let body = json!({
            "wan_ifaces": ["eth0"],
            "lan_ifaces": ["lan0"],
            "allow_ssh_from": ["192.0.2.0/24"],
            "admin_iface": "helios0",
            "wg_iface": "helios0",
            "wg_private_key_configured": true,
            "wg_public_key": "gateway-public",
            "wg_address": "100.64.0.1/10",
            "wg_listen_port": 51820,
            "key_negotiation_port": 51821,
            "peers": [{
                "name": "admin",
                "public_key": "peer-public",
                "address": "100.64.1.2/32",
                "preshared_key_configured": true,
                "key_negotiation_certificate_sha256": "tls",
                "key_negotiation_pq_certificate_sha256": "pq",
                "minimum_key_negotiation_mode": "ml_kem",
                "admin": true
            }]
        });
        let view: NetworkConfigView =
            decode_response(reqwest::StatusCode::OK, &body.to_string(), "/api/network").unwrap();

        assert!(view.wg_private_key_configured);
        assert_eq!(view.key_negotiation_port, Some(51821));
        assert_eq!(view.peers.len(), 1);
        assert!(view.peers[0].preshared_key_configured);
        assert!(view.peers[0].admin);
        assert_eq!(
            view.peers[0].minimum_key_negotiation_mode,
            ProtectionMode::MlKem
        );
    }

    #[test]
    fn key_negotiation_view_decodes_optional_port_and_public_material() {
        let body = json!({
            "port": null,
            "server_name": "gateway.example",
            "gateway_ca_der": "Y2E=",
            "gateway_pq_certificate": "cHE=",
            "pq_certificate_sha256": "sha256",
            "wireguard_public_key": "wg"
        });
        let view: KeyNegotiationView = decode_response(
            reqwest::StatusCode::OK,
            &body.to_string(),
            "/api/key-negotiation",
        )
        .unwrap();

        assert_eq!(view.port, None);
        assert_eq!(view.server_name, "gateway.example");
        assert_eq!(view.wireguard_public_key, "wg");
    }

    #[tokio::test]
    async fn key_negotiation_treats_404_as_absence_and_surfaces_other_errors() {
        let client = Client::new();
        let (base, server) = response_server("404 Not Found", "missing".into()).await;
        assert!(key_negotiation(&client, &base).await.unwrap().is_none());
        assert!(server
            .await
            .unwrap()
            .starts_with("GET /api/key-negotiation "));

        let (base, server) = response_server("503 Service Unavailable", "offline\n".into()).await;
        let error = key_negotiation(&client, &base)
            .await
            .expect_err("server rejection");
        assert_eq!(error.to_string(), "503 Service Unavailable : offline");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_helpers_decode_successful_get_and_post_responses() {
        let client = Client::new();
        let network_body = json!({
            "wan_ifaces": ["eth0"],
            "lan_ifaces": [],
            "allow_ssh_from": [],
            "admin_iface": null,
            "wg_iface": "helios0",
            "wg_private_key_configured": false,
            "wg_public_key": null,
            "wg_address": "100.64.0.1/10",
            "wg_listen_port": 51820,
            "key_negotiation_port": null,
            "peers": []
        })
        .to_string();
        let (base, server) = response_server("200 OK", network_body).await;
        let view = network(&client, &base).await.unwrap();
        assert_eq!(view.wg_iface, "helios0");
        assert_eq!(view.wan_ifaces, ["eth0"]);
        assert!(server.await.unwrap().starts_with("GET /api/network "));

        let (base, server) =
            response_server("200 OK", r#"{"ok":true,"error":null}"#.to_string()).await;
        let response: CmdResp = post_json(
            &client,
            &base,
            "/api/tunnel/start",
            &serde_json::json!({ "requested": true }),
        )
        .await
        .unwrap();
        assert!(response.ok);
        let request = server.await.unwrap();
        assert!(request.starts_with("POST /api/tunnel/start "));
        assert!(request
            .to_ascii_lowercase()
            .contains("content-type: application/json"));
    }
}
