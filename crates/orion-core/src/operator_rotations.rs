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

use aether::certificates::transport::OperatorPendingList;
pub use aether::certificates::transport::{OperatorAuthorityStatus, OperatorPendingOperation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// How long the gateway has to answer before the screen stops waiting.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on the small answers, as the blocking tunnel client's.
const MAX_ANSWER_BYTES: usize = 256 * 1024;

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
    /// No answer, an answer of another status, or one that cannot be read.
    Unreachable,
    /// `429`: too many operations are waiting.
    Throttled,
}

impl<T> Reach<T> {
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
    #[serde(default)]
    pub peers: Vec<PeerExpiry>,
}

/// What the screen draws of one peer: when its certificate ends. Not its name, not
/// its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerExpiry {
    pub not_after: u64,
}

/// Everything waiting for an operator, through one gateway.
pub async fn pending(gateway: &str) -> Reach<Vec<OperatorPendingOperation>> {
    match read::<OperatorPendingList>(
        gateway,
        "/api/certificates/operator/pending",
        MAX_ANSWER_BYTES,
    )
    .await
    {
        Reach::Ok(list) => Reach::Ok(list.operations),
        Reach::NotAdmin => Reach::NotAdmin,
        Reach::AstraUnavailable => Reach::AstraUnavailable,
        Reach::Unreachable => Reach::Unreachable,
        Reach::Throttled => Reach::Throttled,
    }
}

/// What Astra holds of its authority state: fingerprints and epochs.
pub async fn authority_status(gateway: &str) -> Reach<OperatorAuthorityStatus> {
    read(
        gateway,
        "/api/certificates/operator/status",
        MAX_ANSWER_BYTES,
    )
    .await
}

/// The gateway's own view of the domain.
pub async fn domain(gateway: &str) -> Reach<GatewayDomainRead> {
    read(gateway, "/api/certificates", MAX_DOMAIN_ANSWER_BYTES).await
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
        _ => return Reach::Unreachable,
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
