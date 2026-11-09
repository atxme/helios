//! What is waiting for an operator, read from inside the tunnel.
//!
//! # Why an interface has to ask at all
//!
//! A campaign is opened by an administrator, on the gateway, and until now the
//! only way to reach it afterwards was the identifier printed by the command
//! that created it — carried by hand to whoever holds a security key. That
//! transcription is the whole of what this surface exists to remove, and
//! removing it means the operator's machine has to be able to *find* the
//! campaign rather than be told about it.
//!
//! # Where it is read, and why not from Astra
//!
//! From the gateway, in the tunnel, on the admin surface. Astra's public
//! origin serves a §7.5 recovery without a tunnel — that is the whole point of
//! §7.5 — and putting a list there would make every operation the domain is
//! about to sign readable by anyone who can reach the origin.
//!
//! Recoveries are therefore **absent** from what comes back, and their absence
//! is their access control: a recovery's only claim is the identifier the
//! expired client holds and reads out. Orion already has that identifier for
//! its own recoveries, because it opened them.
//!
//! # No credential travels
//!
//! The list carries no capability token. Tokens are minted for the caller
//! about to act on the operation they named; a list that carried them would
//! hand every reader a credential for every operation on it.

use std::time::Duration;

pub use aether::certificates::transport::{OperatorPendingList, OperatorPendingOperation};

/// How long the gateway has to answer before the tab stops waiting.
///
/// Short: this runs on a timer behind an interface, and a gateway that is not
/// answering must show as «rien en attente» rather than freeze a navigation
/// rail.
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum PendingError {
    #[error("la gateway n'a pas répondu : {0}")]
    Unreachable(String),
    #[error("la gateway a refusé ({status})")]
    Refused { status: u16 },
    #[error("la réponse de la gateway est illisible : {0}")]
    Malformed(String),
}

/// Reads everything waiting for an operator, through one gateway.
///
/// Authenticated by the tunnel itself: the route is behind `require_admin`,
/// and what identifies the caller is the WireGuard peer the request arrives
/// from. Nothing is carried in a header, so there is no credential here to
/// leak or to get wrong.
pub async fn pending(heliosd_url: &str) -> Result<OperatorPendingList, PendingError> {
    let url = route(heliosd_url);
    let http = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(|error| PendingError::Unreachable(error.to_string()))?;
    let response = http
        .get(&url)
        .send()
        .await
        .map_err(|error| PendingError::Unreachable(error.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(PendingError::Refused {
            status: status.as_u16(),
        });
    }
    response
        .json()
        .await
        .map_err(|error| PendingError::Malformed(error.to_string()))
}

/// The one route, resolved against the profile's gateway and nothing else.
///
/// Written out here rather than assembled from anything an answer supplies: a
/// path built from a remote value is a path a remote value can redirect.
fn route(heliosd_url: &str) -> String {
    format!(
        "{}/api/certificates/operator/pending",
        heliosd_url.trim_end_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn serve_once(
        status: u16,
        body: &'static [u8],
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("request");
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            loop {
                let read = stream.read(&mut chunk).await.expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).expect("ASCII HTTP request");
            let head = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(head.as_bytes())
                .await
                .expect("write headers");
            stream.write_all(body).await.expect("write body");
            request
        });
        (format!("http://{address}/"), task)
    }

    #[test]
    fn the_route_is_resolved_against_the_gateway_and_nothing_else() {
        assert_eq!(
            route("http://100.64.0.1:8080"),
            "http://100.64.0.1:8080/api/certificates/operator/pending"
        );
        assert_eq!(
            route("http://100.64.0.1:8080/"),
            "http://100.64.0.1:8080/api/certificates/operator/pending",
            "a trailing slash on the profile's gateway must not double in the path"
        );
    }

    #[tokio::test]
    async fn pending_fetches_and_decodes_the_operator_list_without_capabilities() {
        let body = br#"{"operations":[{"operation_id":"01010101010101010101010101010101","scope":"fleet_leafs","reason":"Scheduled rotation","requested_by":"admin","target_count":3,"required_credentials":1,"campaign_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","created_at":10,"expires_at":20}]}"#;
        let (url, request) = serve_once(200, body).await;
        let result = pending(&url).await.expect("pending list");
        assert_eq!(result.operations.len(), 1);
        assert_eq!(result.operations[0].reason, "Scheduled rotation");
        assert_eq!(result.operations[0].requested_by, "admin");
        assert_eq!(result.operations[0].target_count, 3);
        assert_eq!(result.operations[0].required_credentials, 1);
        let serialized = serde_json::to_value(&result).expect("serialize public list");
        assert!(serialized["operations"][0]
            .get("signer_request_token")
            .is_none());
        assert!(serialized["operations"][0].get("vault_token").is_none());
        assert!(serialized["operations"][0]
            .get("signer_result_token")
            .is_none());
        let request = request.await.expect("server task");
        let first_line = request.lines().next().expect("request line");
        assert_eq!(
            first_line,
            "GET /api/certificates/operator/pending HTTP/1.1"
        );
        assert!(!request.to_ascii_lowercase().contains("authorization:"));
    }

    #[tokio::test]
    async fn pending_accepts_an_empty_list() {
        let (url, request) = serve_once(200, br#"{"operations":[]}"#).await;
        let result = pending(&url).await.expect("empty list");
        assert!(result.operations.is_empty());
        request.await.expect("server task");
    }

    #[tokio::test]
    async fn pending_maps_non_success_statuses_to_refused() {
        for status in [401, 403, 500] {
            let (url, request) = serve_once(status, b"{}").await;
            assert!(
                matches!(pending(&url).await, Err(PendingError::Refused { status: actual }) if actual == status)
            );
            request.await.expect("server task");
        }
    }

    #[tokio::test]
    async fn pending_rejects_malformed_json_and_unknown_fields() {
        for body in [b"{".as_slice(), br#"{"operations":[],"unexpected":true}"#] {
            let (url, request) = serve_once(200, body).await;
            assert!(matches!(
                pending(&url).await,
                Err(PendingError::Malformed(_))
            ));
            request.await.expect("server task");
        }
    }

    #[tokio::test]
    async fn pending_maps_an_unparseable_gateway_url_to_unreachable() {
        assert!(matches!(
            pending("://invalid").await,
            Err(PendingError::Unreachable(_))
        ));
    }
}
