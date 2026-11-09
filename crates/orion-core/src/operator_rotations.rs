//! What the rotations screen reads from the gateway, one answer at a time.
//!
//! # Why not the blocking tunnel client
//!
//! `astra-operator` has a blocking `Tunnel` for the ceremony threads, and Orion's
//! screen is read on the async runtime, on a timer. The two stay separate: this one
//! reads a **tolerant subset** of each answer, because a view that gains a field
//! must not blind a screen that only needs three of them, and it never touches a
//! key, the vault's secrets or a PIN.
//!
//! # Why an answer is a [`Reach`] and not an error
//!
//! The screen draws a line for each way a read can fail: a tunnel peer that is not
//! an administrator (`403`), an authority that is not deployed or whose private
//! channel is down (`503`), a gateway that refuses to count one more operation
//! (`429`), a gateway that does not answer. Folding them into one error would make
//! the operator guess which prerequisite to fix.
//!
//! # No credential travels
//!
//! Every route is authenticated by the tunnel itself. Nothing is sent in a header,
//! the client uses no proxy and follows no redirect, so no answer can send a later
//! request elsewhere.

use std::time::Duration;

use aether::certificates::transport::OperatorAuthorityStatus;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// How long the gateway has to answer before the screen stops waiting.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on the small answers, as the blocking tunnel client's.
const MAX_ANSWER_BYTES: usize = 256 * 1024;

/// Ceiling on the status read alone: the answer carries the credential document
/// whole. It mirrors `MAX_OPERATOR_STATUS_BYTES` in `astra-channel` (1 MiB),
/// which orion-core does not depend on, so the two are kept equal by hand. The
/// other reads keep `MAX_ANSWER_BYTES`.
const MAX_STATUS_ANSWER_BYTES: usize = 1024 * 1024;

const _: () = assert!(MAX_STATUS_ANSWER_BYTES >= 1024 * 1024);

/// Ceiling on the domain view, the one answer that grows with the fleet: a peer
/// costs a few hundred bytes there.
const MAX_DOMAIN_ANSWER_BYTES: usize = 8 * 1024 * 1024;

/// How a read ended, for the screen to draw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum Reach<T> {
    Ok(T),
    /// `403`: the tunnel peer is not an administrator of the gateway.
    NotAdmin,
    /// `503`: the gateway relays no authority.
    AstraUnavailable,
    /// No answer, or one that cannot be read or is too large.
    Unreachable,
    /// `429`: too many operations are waiting.
    Throttled,
    /// Any other status: the gateway is up and says no. A `404` is an older gateway
    /// without the route, which is not a gateway that is down.
    Refused(u16),
}

impl<T> Reach<T> {
    /// The same answer with its value transformed; a failed read stays as it was.
    pub fn map<U>(self, change: impl FnOnce(T) -> U) -> Reach<U> {
        match self {
            Self::Ok(value) => Reach::Ok(change(value)),
            Self::NotAdmin => Reach::NotAdmin,
            Self::AstraUnavailable => Reach::AstraUnavailable,
            Self::Unreachable => Reach::Unreachable,
            Self::Throttled => Reach::Throttled,
            Self::Refused(status) => Reach::Refused(status),
        }
    }

    /// The value, when the read went through.
    pub fn ok(&self) -> Option<&T> {
        match self {
            Self::Ok(value) => Some(value),
            _ => None,
        }
    }
}

/// The part of `GET /api/certificates` the screen draws from.
///
/// Its own type rather than the gateway's, which refuses a field it does not
/// know. The names are the screen's; the aliases are the view's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayDomainRead {
    /// The gateway's clock when it answered: screens must not use the operator's.
    #[serde(default)]
    pub now_unix: Option<u64>,
    #[serde(alias = "ca_pq_fingerprint")]
    pub ca_fingerprint: String,
    pub ca_epoch: u64,
    #[serde(alias = "client_tls_ca_epoch")]
    pub ca_tls_epoch: u64,
    #[serde(default)]
    pub ca_transition_pending: bool,
    #[serde(default)]
    pub ca_retire_active_at: Option<u64>,
    #[serde(default)]
    pub next_ca_fingerprint: Option<String>,
    #[serde(default)]
    pub client_tls_ca_transition_pending: bool,
    /// The peers a fleet renewal targets: revoked ones are left out, as Astra's
    /// `fleet_leaf_rows` does.
    #[serde(default)]
    pub peers: Vec<PeerExpiry>,
}

/// What the screen draws of one peer: when its certificate ends. Not its name, not
/// its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerExpiry {
    pub not_after: u64,
    #[serde(default, skip_serializing)]
    pub revoked: bool,
}

/// What Astra says of its authority state: a tolerant subset of
/// [`OperatorAuthorityStatus`], which refuses a field it does not know. Fingerprints
/// are hexadecimal text; a missing optional field reads as absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityStatusRead {
    pub ca_epoch: u64,
    pub ca_fingerprint: String,
    #[serde(default)]
    pub next_ca_fingerprint: Option<String>,
    pub ca_tls_epoch: u64,
    #[serde(default)]
    pub ca_tls_fingerprint: Option<String>,
    #[serde(default)]
    pub next_ca_tls_fingerprint: Option<String>,
    #[serde(default)]
    pub issuer: Option<IssuerRead>,
    #[serde(default)]
    pub vault_copy_fingerprint: Option<String>,
    /// `None`: Astra serves no document. Not epoch 0.
    #[serde(default)]
    pub credential_registry_epoch: Option<u64>,
    /// The workstations Astra holds as revoked, as WireGuard keys in base64.
    #[serde(default)]
    pub revoked_peers: Vec<String>,
    /// The credential document Astra serves, kept raw. Nothing here trusts it:
    /// it is verified before any decision rests on it.
    #[serde(default)]
    pub served_credentials: Option<serde_json::Value>,
}

/// The delegation, as the status reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerRead {
    pub recorded_epoch: u64,
    #[serde(default)]
    pub serving_epoch: Option<u64>,
    pub ca_epoch: u64,
    pub ca_tls_epoch: u64,
    pub not_after: u64,
}

impl From<OperatorAuthorityStatus> for AuthorityStatusRead {
    fn from(status: OperatorAuthorityStatus) -> Self {
        Self {
            ca_epoch: status.ca_epoch,
            ca_fingerprint: status.ca_fingerprint.to_hex(),
            next_ca_fingerprint: status.next_ca_fingerprint.map(|f| f.to_hex()),
            ca_tls_epoch: status.ca_tls_epoch,
            ca_tls_fingerprint: status.ca_tls_fingerprint.map(|f| f.to_hex()),
            next_ca_tls_fingerprint: status.next_ca_tls_fingerprint.map(|f| f.to_hex()),
            issuer: status.issuer.map(|issuer| IssuerRead {
                recorded_epoch: issuer.recorded_epoch,
                serving_epoch: issuer.serving_epoch,
                ca_epoch: issuer.ca_epoch,
                ca_tls_epoch: issuer.ca_tls_epoch,
                not_after: issuer.not_after,
            }),
            vault_copy_fingerprint: status.vault_copy_fingerprint.map(|f| f.to_hex()),
            credential_registry_epoch: status.credential_registry_epoch,
            revoked_peers: status
                .revoked_peers
                .iter()
                .map(|key| key.to_base64())
                .collect(),
            // A derived `Serialize` over strings and integers does not fail. Should
            // it, the screen reads no document, and nothing is trusted from it.
            served_credentials: status
                .served_credentials
                .and_then(|document| serde_json::to_value(*document).ok()),
        }
    }
}

/// One operation waiting for an operator, as the list names it. No capability token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOperationRead {
    pub operation_id: String,
    pub scope: String,
    pub reason: String,
    pub requested_by: String,
    pub target_count: u64,
    pub required_credentials: u64,
    pub campaign_fingerprint: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Deserialize)]
struct PendingListRead {
    operations: Vec<PendingOperationRead>,
}

/// Everything waiting for an operator, through one gateway.
pub async fn pending(gateway: &str) -> Reach<Vec<PendingOperationRead>> {
    read::<PendingListRead>(
        gateway,
        "/api/certificates/operator/pending",
        MAX_ANSWER_BYTES,
    )
    .await
    .map(|list| list.operations)
}

/// What Astra holds of its authority state: fingerprints, epochs, the revoked
/// peers and the credential document it serves.
pub async fn authority_status(gateway: &str) -> Reach<AuthorityStatusRead> {
    read(
        gateway,
        "/api/certificates/operator/status",
        MAX_STATUS_ANSWER_BYTES,
    )
    .await
}

/// The gateway's own view of the domain.
pub async fn domain(gateway: &str) -> Reach<GatewayDomainRead> {
    read::<GatewayDomainRead>(gateway, "/api/certificates", MAX_DOMAIN_ANSWER_BYTES)
        .await
        .map(|mut domain| {
            domain.peers.retain(|peer| !peer.revoked);
            domain
        })
}

/// One `GET`, resolved against the profile's gateway and nothing else.
///
/// The path is written out by each caller: one built from a remote value is one a
/// remote value can redirect.
async fn read<T: DeserializeOwned>(gateway: &str, path: &str, max_bytes: usize) -> Reach<T> {
    let Ok(http) = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return Reach::Unreachable;
    };
    let url = format!("{}{path}", gateway.trim_end_matches('/'));
    let Ok(mut response) = http.get(url).send().await else {
        return Reach::Unreachable;
    };
    match response.status().as_u16() {
        200..=299 => {}
        403 => return Reach::NotAdmin,
        429 => return Reach::Throttled,
        503 => return Reach::AstraUnavailable,
        other => return Reach::Refused(other),
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Reach::Unreachable;
    }
    // Counted as it arrives: a length header is a claim, and the peer is a peer.
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > max_bytes {
                    return Reach::Unreachable;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return Reach::Unreachable,
        }
    }
    serde_json::from_slice(&body).map_or(Reach::Unreachable, Reach::Ok)
}

#[cfg(test)]
mod tests;
