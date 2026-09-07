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
}
