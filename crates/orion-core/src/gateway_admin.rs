//! The gateway's administration routes, as the operator's Orion calls them.
//!
//! Three things travel here, all in the tunnel and none of them secret: the
//! gateway's public negotiation material, the list of keys it has admitted, and
//! the admission of one more peer. The gateway authorizes the caller by its
//! WireGuard peer, so the only credential is the tunnel itself: nothing in this
//! module holds, sends or logs a token.
//!
//! The caller supplies the HTTP client: the operator CLI reaches the gateway
//! through its local administration socket, Orion through the tunnel, and a
//! client built here would silently take the wrong road. Bodies are read
//! through a bound; a refusal keeps only the gateway's own error text, trimmed
//! of control characters and cut short.

use std::time::Duration;

use aether::certificates::encoding::DerCertificate;
use aether::key_negotiation::{PqCertificate, ProtectionMode};
use base64::Engine as _;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::enrollment_draft::{Admission, GatewayMaterial};
use crate::TrustMaterial;

/// The longest refusal reason kept, in characters.
const MAX_REASON_CHARS: usize = 200;

/// How long Orion waits for a gateway to accept a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one request may take in all, from connection to the last byte.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The largest answer read: far above any real view, far below a memory risk.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// The client every Orion gateway-admin call goes through.
///
/// Bounded twice, so a gateway that accepts the connection and then says
/// nothing cannot hold a ceremony: 10 seconds to connect and 20 in all for a
/// request. It carries no credential — the tunnel is the caller's identity.
///
/// It ignores environment proxies and follows no redirect: admin traffic must
/// stay in the tunnel, to the address the profile names and to no other.
pub fn orion_client() -> Result<Client, GatewayAdminError> {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|_| invalid("le client HTTP de l'administration ne peut pas être construit"))
}

/// A PQ leaf as it is handed over: the JSON document the gateway writes, or the
/// base64 of that document as a profile and the negotiation route carry it.
pub fn decode_pq_certificate(text: &str) -> Result<PqCertificate, GatewayAdminError> {
    let text = text.trim();
    if let Ok(certificate) = serde_json::from_str::<PqCertificate>(text) {
        return Ok(certificate);
    }
    let json = base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| invalid("la feuille PQ n'est ni un document JSON ni son encodage base64"))?;
    serde_json::from_slice(&json).map_err(|_| invalid("la feuille PQ n'est pas lisible"))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GatewayAdminError {
    /// Nothing answered: no tunnel, a wrong address, or heliosd is down.
    #[error(
        "La gateway est injoignable : vérifiez que le tunnel est monté et que heliosd répond."
    )]
    Unreachable,
    /// `401` or `403`: the gateway knows the caller is not an administrator.
    #[error(
        "La gateway refuse cette machine : le pair de ce poste doit porter le drapeau `admin`."
    )]
    Forbidden,
    /// Any other refusal: the status, and the reason the gateway gave when its
    /// answer was a readable error text.
    #[error("{}", refusal_message(*status, reason.as_deref()))]
    Refused { status: u16, reason: Option<String> },
    /// `404` on the revocation route: no admitted peer carries that name.
    #[error("Aucun poste admis ne porte ce nom sur la gateway.")]
    UnknownPeer,
    /// An answer the gateway should not have given, or a body that cannot be sent.
    #[error("Réponse de la gateway inacceptable : {0}")]
    Invalid(String),
}

/// A client to admit, as the gateway's `POST /api/peers` receives it.
///
/// `admin` is always `false` here: an operator workstation is made an
/// administrator on the gateway, never by an invitation.
#[derive(Debug, Clone, Serialize)]
pub struct PeerAdmission {
    pub name: String,
    pub public_key: String,
    pub admin: bool,
    pub minimum_key_negotiation_mode: ProtectionMode,
    /// The client's TLS leaf, DER in base64.
    pub key_negotiation_certificate: String,
    /// The client's ML-DSA-87 leaf, its JSON document in base64.
    pub key_negotiation_pq_certificate: String,
}

/// What goes on the wire: the admission and the digests of its two leaves.
///
/// The gateway refuses an admission without the digests and one whose digests
/// name other leaves, so they are derived from the leaves rather than asked of
/// the caller.
#[derive(Serialize)]
struct AdmitWire<'a> {
    #[serde(flatten)]
    admission: &'a PeerAdmission,
    key_negotiation_certificate_sha256: String,
    key_negotiation_pq_certificate_sha256: String,
}

#[derive(Deserialize)]
struct NetworkView {
    wg_public_key: Option<String>,
    wg_address: String,
    peers: Vec<PeerView>,
}

#[derive(Deserialize)]
struct PeerView {
    name: String,
    public_key: String,
    address: String,
    #[serde(default)]
    address_v6: Option<String>,
}

#[derive(Deserialize)]
struct NegotiationView {
    port: Option<u16>,
    server_name: String,
    gateway_ca_der: String,
    gateway_pq_certificate: String,
    pq_certificate_sha256: String,
    wireguard_public_key: String,
}

fn refusal_message(status: u16, reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("La gateway a refusé la demande (HTTP {status}) : {reason}"),
        None => format!("La gateway a refusé la demande (HTTP {status})."),
    }
}

/// The gateway's error text, safe to show: no control characters, bounded.
/// The gateway's mutation routes answer a refusal in plain text.
fn reason_of(body: &[u8]) -> Option<String> {
    let text: String = String::from_utf8_lossy(body)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let text: String = text.trim().chars().take(MAX_REASON_CHARS).collect();
    (!text.is_empty()).then_some(text)
}

fn status_error(status: u16, body: &[u8]) -> GatewayAdminError {
    match status {
        401 | 403 => GatewayAdminError::Forbidden,
        status => GatewayAdminError::Refused {
            status,
            reason: reason_of(body),
        },
    }
}

fn invalid(reason: &str) -> GatewayAdminError {
    GatewayAdminError::Invalid(reason.to_string())
}

fn url(base: &str, path: &str) -> String {
    format!("{}{path}", base.trim_end_matches('/'))
}

/// Sends the request and reads at most [`MAX_BODY_BYTES`] of the answer.
async fn exchange(request: reqwest::RequestBuilder) -> Result<(u16, Vec<u8>), GatewayAdminError> {
    let mut response = request
        .send()
        .await
        .map_err(|_| GatewayAdminError::Unreachable)?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GatewayAdminError::Unreachable)?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(invalid("réponse démesurée"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

/// `GET`, `404` kept apart: it is a feature the gateway does not have.
async fn get(
    client: &Client,
    base: &str,
    path: &str,
) -> Result<Option<Vec<u8>>, GatewayAdminError> {
    let (status, body) = exchange(client.get(url(base, path))).await?;
    match status {
        200..=299 => Ok(Some(body)),
        404 => Ok(None),
        status => Err(status_error(status, &body)),
    }
}

fn decode<T: serde::de::DeserializeOwned>(body: &[u8], what: &str) -> Result<T, GatewayAdminError> {
    serde_json::from_slice(body)
        .map_err(|_| GatewayAdminError::Invalid(format!("{what} illisible")))
}

/// The same address `helios enroll` writes in a profile: the gateway's tunnel
/// address on the control-plane port. Absent when the address is not IPv4.
fn heliosd_url(wg_address: &str) -> Option<String> {
    let host = wg_address.split('/').next()?.trim();
    host.parse::<std::net::Ipv4Addr>().ok()?;
    Some(format!("http://{host}:{}", aether::API_PORT))
}

/// Percent-encodes what a WireGuard key holds and a path segment cannot: `/`
/// would split the segment and the gateway would look up a truncated key.
fn path_segment(value: &str) -> String {
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

async fn network_view(client: &Client, base: &str) -> Result<NetworkView, GatewayAdminError> {
    let body = get(client, base, "/api/network")
        .await?
        .ok_or_else(|| invalid("la gateway ne publie pas sa configuration réseau"))?;
    decode(&body, "la configuration réseau")
}

/// The gateway's identity and negotiation material, with the network view that
/// proved them consistent.
async fn negotiate(
    client: &Client,
    base: &str,
) -> Result<(GatewayMaterial, NetworkView), GatewayAdminError> {
    let network = network_view(client, base).await?;
    let gateway_key = network
        .wg_public_key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| {
            invalid(
                "la gateway n'a pas encore d'identité WireGuard — lancez `heliosd init-identity` \
                 sur la gateway, depuis sa console",
            )
        })?;
    let body = get(client, base, "/api/key-negotiation")
        .await?
        .ok_or_else(|| {
            invalid(
                "la gateway ne sert aucun matériel de négociation — compilez heliosd avec la \
                 fonctionnalité `key-negotiation` et lancez `heliosd init-key-negotiation`",
            )
        })?;
    let negotiation: NegotiationView = decode(&body, "le matériel de négociation")?;
    // The gateway certificate is pinned to a WireGuard key. If that is not the
    // identity the gateway runs on, every client built from it fails its
    // pinning check, and the message would blame the client.
    if negotiation.wireguard_public_key.trim() != gateway_key {
        return Err(invalid(
            "le certificat de négociation de la gateway est lié à une autre identité WireGuard : \
             l'identité a changé sans que le certificat soit réémis — relancez \
             `heliosd init-key-negotiation --rotate`",
        ));
    }
    let material = GatewayMaterial {
        server_name: negotiation.server_name,
        gateway_ca_der: negotiation.gateway_ca_der,
        gateway_pq_certificate: negotiation.gateway_pq_certificate,
        wireguard_public_key: negotiation.wireguard_public_key,
        pq_certificate_sha256: negotiation.pq_certificate_sha256,
        negotiation_port: negotiation.port,
    };
    Ok((material, network))
}

/// The gateway's public negotiation material, for a client that has no key yet.
///
/// An invitation is issued before the client exists, so it can ask nothing
/// about a peer: only the network, the negotiation, and the check that the two
/// name the same WireGuard identity.
pub async fn gateway_negotiation(
    client: &Client,
    base: &str,
) -> Result<GatewayMaterial, GatewayAdminError> {
    negotiate(client, base).await.map(|(material, _)| material)
}

/// The material and the admission of a client the gateway already holds.
///
/// The peer must be admitted first: its address is derived by the gateway and
/// is the only thing that cannot be computed here.
pub async fn gateway_material(
    client: &Client,
    base: &str,
    client_key: &str,
) -> Result<(GatewayMaterial, Admission), GatewayAdminError> {
    let (material, network) = negotiate(client, base).await?;
    let peer = network
        .peers
        .iter()
        .find(|peer| peer.public_key.trim() == client_key)
        .ok_or_else(|| {
            GatewayAdminError::Invalid(format!(
                "aucun pair ne porte la clé {client_key} sur cette gateway : admettez-le d'abord"
            ))
        })?;
    let trust_path = format!(
        "/api/key-negotiation/trust-enrolment/{}",
        path_segment(client_key)
    );
    // `404` is legitimate: a trust domain not bootstrapped yet, or a peer
    // admitted before it was. The caller decides whether it can go on.
    let trust = match get(client, base, &trust_path).await? {
        Some(body) => Some(decode::<TrustMaterial>(&body, "le bloc de confiance")?),
        None => None,
    };
    let admission = Admission {
        address: peer.address.clone(),
        address_v6: peer
            .address_v6
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        heliosd_url: heliosd_url(&network.wg_address),
        trust,
    };
    Ok((material, admission))
}

/// A peer the gateway has admitted: the name it was admitted under, and its
/// WireGuard public key. Nothing else of the view is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmittedPeer {
    pub name: String,
    pub wg_public_key: String,
}

/// The name and public key of every peer the gateway has admitted.
pub async fn admitted_peers(
    client: &Client,
    base: &str,
) -> Result<Vec<AdmittedPeer>, GatewayAdminError> {
    let network = network_view(client, base).await?;
    Ok(network
        .peers
        .into_iter()
        .map(|peer| AdmittedPeer {
            name: peer.name.trim().to_string(),
            wg_public_key: peer.public_key.trim().to_string(),
        })
        .collect())
}

/// The body of `POST /api/peers/revoke`: the name, as the gateway holds it.
#[derive(Serialize)]
struct RevokeWire<'a> {
    name: &'a str,
}

/// Withdraws a peer's admission, by the name the gateway admitted it under.
///
/// The gateway names a peer only once (`NameTaken`), so the name is the
/// peer's identity on this route. The caller checks that it designates the
/// key it means before calling: this function does not.
pub async fn revoke_peer(client: &Client, base: &str, name: &str) -> Result<(), GatewayAdminError> {
    let body = serde_json::to_vec(&RevokeWire { name })
        .map_err(|_| invalid("la révocation n'a pas pu être encodée"))?;
    let (status, response) = exchange(
        client
            .post(url(base, "/api/peers/revoke"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body),
    )
    .await?;
    match status {
        200..=299 => Ok(()),
        404 => Err(GatewayAdminError::UnknownPeer),
        status => Err(status_error(status, &response)),
    }
}

/// The public keys of every peer the gateway has admitted.
pub async fn admitted_keys(client: &Client, base: &str) -> Result<Vec<String>, GatewayAdminError> {
    let network = network_view(client, base).await?;
    Ok(network
        .peers
        .into_iter()
        .map(|peer| peer.public_key.trim().to_string())
        .collect())
}

/// The JSON body of an admission, digests included.
fn admission_body(admission: &PeerAdmission) -> Result<Vec<u8>, GatewayAdminError> {
    let decoder = base64::engine::general_purpose::STANDARD;
    let tls = decoder
        .decode(admission.key_negotiation_certificate.trim())
        .ok()
        .and_then(|der| DerCertificate::new(der).ok())
        .ok_or_else(|| invalid("la feuille TLS du client n'est pas un DER en base64"))?;
    let pq: PqCertificate = decoder
        .decode(admission.key_negotiation_pq_certificate.trim())
        .ok()
        .and_then(|json| serde_json::from_slice(&json).ok())
        .ok_or_else(|| invalid("la feuille PQ du client n'est pas un JSON en base64"))?;
    let pq_digest = aether::certificates::gateway::pq_certificate_fingerprint(&pq)
        .map_err(|_| invalid("la feuille PQ du client n'a pas d'empreinte canonique"))?;
    serde_json::to_vec(&AdmitWire {
        admission,
        key_negotiation_certificate_sha256: tls.fingerprint().to_hex(),
        key_negotiation_pq_certificate_sha256: pq_digest.to_hex(),
    })
    .map_err(|_| invalid("l'admission n'a pas pu être encodée"))
}

/// Admits a peer. The gateway derives its address; read it back with
/// [`gateway_material`].
pub async fn admit_peer(
    client: &Client,
    base: &str,
    admission: &PeerAdmission,
) -> Result<(), GatewayAdminError> {
    let body = admission_body(admission)?;
    let (status, response) = exchange(
        client
            .post(url(base, "/api/peers"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body),
    )
    .await?;
    match status {
        200..=299 => Ok(()),
        status => Err(status_error(status, &response)),
    }
}

#[cfg(test)]
mod tests;
