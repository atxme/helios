use super::tunnel_routed_address;
use aether::key_negotiation::{KEY_NEGOTIATION_NONCE_LEN, KEY_NEGOTIATION_VERSION};

const TUNNEL: &str = "100.64.0.0/10, 192.168.1.0/24";

fn target(url: &str) -> String {
    tunnel_routed_address(url, TUNNEL).unwrap().to_string()
}

/// The release only ever goes to a literal address the tunnel routes.
#[test]
fn a_release_target_must_be_a_literal_inside_the_tunnel() {
    assert_eq!(
        target("http://100.64.0.1:8080"),
        "http://100.64.0.1:8080/api/key-negotiation/release"
    );
    // A trailing slash is the same origin, not a second one.
    assert_eq!(
        target("http://100.64.0.1:8080/"),
        "http://100.64.0.1:8080/api/key-negotiation/release"
    );
}

/// The check has to run on the parse the request is built from.
///
/// `http://100.64.0.1:8080@evil.example` reads as an address and a port to
/// a hand-written splitter, and as userinfo followed by the host
/// `evil.example` to every RFC 3986 parser — which is the one the HTTP
/// client uses. Validating the first and contacting the second is the
/// whole bug.
#[test]
fn a_url_carrying_userinfo_is_refused() {
    for url in [
        "http://100.64.0.1:8080@evil.example",
        "http://100.64.0.1:8080@evil.example/",
        "http://user@100.64.0.1:8080",
        "http://100.64.0.1@100.64.0.1:8080",
    ] {
        let outcome = tunnel_routed_address(url, TUNNEL);
        assert!(outcome.is_err(), "{url} must be refused: {outcome:?}");
    }
}

/// A path, a query or a fragment either aims at something other than this
/// endpoint, or would push the request onto the SPA fallback — which
/// answers `200` with HTML and no handler behind it.
#[test]
fn a_url_that_is_not_a_bare_origin_is_refused() {
    for url in [
        "http://100.64.0.1:8080/ui",
        "http://100.64.0.1:8080/?a=b",
        "http://100.64.0.1:8080/#fragment",
    ] {
        let outcome = tunnel_routed_address(url, TUNNEL);
        assert!(outcome.is_err(), "{url} must be refused: {outcome:?}");
    }
}

/// A name would mean a DNS lookup, and Orion's DNS is not tunnelled: the
/// query would leave in clear and the answer could point the release
/// anywhere.
#[test]
fn a_hostname_is_refused_before_anything_is_signed() {
    assert!(tunnel_routed_address("http://gateway.example:8080", TUNNEL).is_err());
    // Including one that merely looks like an address.
    assert!(tunnel_routed_address("http://100.64.0.1.example:8080", TUNNEL).is_err());
}

/// Anything but `http`/`https` never reaches a client that speaks neither.
#[test]
fn a_foreign_scheme_is_refused() {
    assert!(tunnel_routed_address("file:///etc/passwd", TUNNEL).is_err());
    assert!(tunnel_routed_address("ftp://100.64.0.1:8080", TUNNEL).is_err());
}

/// Outside `AllowedIPs` the request leaves through the physical
/// interface, in clear, to whoever holds that address.
#[test]
fn an_address_outside_the_allowed_ips_is_refused() {
    assert!(tunnel_routed_address("http://203.0.113.9:8080", TUNNEL).is_err());
    assert!(tunnel_routed_address("http://192.168.1.44:8080", TUNNEL).is_ok());
}

// --- Transport ---
//
// What follows is not about the URL any more: the address is already
// approved, and these are the ways the request could still leave the
// tunnel or come back meaning something else.

use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// A one-shot HTTP server. Returns its origin and what it was asked for.
async fn release_server(response: String) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local listener");
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = vec![0u8; 8192];
            let read = stream.read(&mut request).await.unwrap_or(0);
            recorded.lock().unwrap().push(
                String::from_utf8_lossy(&request[..read])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string(),
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    (origin, seen)
}

/// A syntactically complete release. Nothing here verifies its signature:
/// these tests are about where the bytes go and what an answer means.
fn signed_release() -> aether::key_negotiation::AuthenticatedPskRelease {
    use aether::key_negotiation::{
        AuthenticatedPskRelease, PqCertificate, PqCertificateRole, PskRelease,
    };

    AuthenticatedPskRelease {
        release: PskRelease {
            protocol_version: KEY_NEGOTIATION_VERSION,
            installed_transaction_id: [9; KEY_NEGOTIATION_NONCE_LEN],
            client_wg_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            gateway_wg_public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
        },
        certificate: PqCertificate {
            version: aether::key_negotiation::PQ_CERTIFICATE_VERSION,
            serial: [3; KEY_NEGOTIATION_NONCE_LEN],
            subject: "orion".into(),
            issuer: "operator".into(),
            role: PqCertificateRole::Client,
            wireguard_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            ml_dsa_87_public_key: String::new(),
            not_before_unix: 0,
            not_after_unix: u64::MAX,
            ml_dsa_87_signature: String::new(),
        },
        ml_dsa_87_signature: String::new(),
    }
}

fn loopback_target(origin: &str) -> reqwest::Url {
    tunnel_routed_address(origin, "127.0.0.0/8").expect("loopback stands in for the tunnel")
}

/// `204` and only `204` is a release the gateway actually applied.
#[tokio::test]
async fn a_two_hundred_from_the_spa_fallback_is_not_a_release() {
    let body = "<!doctype html><title>Orion</title>";
    let (origin, seen) = release_server(format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
        body.len()
    ))
    .await;

    let outcome = super::post_release(loopback_target(&origin), &signed_release()).await;

    assert!(
        outcome.is_err(),
        "the static handler answers 200 without the state machine ever seeing the release"
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_two_hundred_and_four_is_accepted() {
    let (origin, seen) = release_server(
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
    )
    .await;

    super::post_release(loopback_target(&origin), &signed_release())
        .await
        .expect("204 is the one success shape");

    assert_eq!(
        seen.lock().unwrap().first().map(String::as_str),
        Some("POST /api/key-negotiation/release HTTP/1.1")
    );
}

/// A redirect lets whoever answered choose the next hop, which would undo
/// the address check: the second hop is never validated against
/// `AllowedIPs` and can sit outside the tunnel entirely.
#[tokio::test]
async fn a_redirect_is_never_followed() {
    let (elsewhere, followed) = release_server(
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
    )
    .await;
    let (origin, seen) = release_server(format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: {elsewhere}/api/key-negotiation/release\
             \r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ))
    .await;

    let outcome = super::post_release(loopback_target(&origin), &signed_release()).await;

    assert!(outcome.is_err(), "a 3xx is not a release");
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert!(
        followed.lock().unwrap().is_empty(),
        "the redirect target must never be contacted"
    );
}

/// An environment proxy would send the release to a host the profile
/// never named, in clear on the physical interface.
///
/// The variables are set for the duration of this test only. It is the
/// single test in this crate that touches them, and no other test here
/// builds an HTTP client, so nothing else can observe them.
#[tokio::test]
async fn an_environment_proxy_is_ignored() {
    let (proxy, proxied) = release_server(
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
    )
    .await;
    let (origin, seen) = release_server(
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
    )
    .await;
    std::env::set_var("HTTP_PROXY", &proxy);
    std::env::set_var("http_proxy", &proxy);

    let outcome = super::post_release(loopback_target(&origin), &signed_release()).await;

    std::env::remove_var("HTTP_PROXY");
    std::env::remove_var("http_proxy");

    outcome.expect("the request must reach the gateway directly");
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert!(
        proxied.lock().unwrap().is_empty(),
        "the release must not be handed to a proxy the profile never named"
    );
}

/// `0.0.0.0/0` is an ordinary full-tunnel entry, and its mask is the one
/// case a naive shift gets wrong.
#[test]
fn a_default_route_carries_every_address() {
    assert!(tunnel_routed_address("http://203.0.113.9:8080", "0.0.0.0/0").is_ok());
    assert!(tunnel_routed_address("http://[fd00::1]:8080", "0.0.0.0/0").is_err());
    assert_eq!(
        tunnel_routed_address("http://[fd00::1]:8080", "fd00::/8")
            .unwrap()
            .to_string(),
        "http://[fd00::1]:8080/api/key-negotiation/release"
    );
}
