//! Gateway integration of the public key-negotiation service.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
};

use aether::{
    key_negotiation::{
        authenticate_commit, authenticate_response, generate_ml_dsa_87_keypair,
        AuthenticatedKeyNegotiationCommit, AuthenticatedKeyNegotiationConfirmation,
        AuthenticatedKeyNegotiationRequest, AuthenticatedPskRelease, PqCertificate,
        PqCertificateRole, ProtectionMode, KEY_NEGOTIATION_VERSION, SERVER_CHALLENGE_LEN,
    },
    InstallPskRequest, NetworkConfig, SecretString,
};
use aether_key_negotiation::{
    prepare_key_material, server_endpoint, GatewayIdentity, NegotiationHandler,
    PreparedNegotiation, PublicError, TlsIdentity, DEFAULT_CONFIRMATION_TIMEOUT,
};
use anyhow::{Context, Result};
use base64::Engine as _;
use helios_api::key_negotiation::PskReleaseRefusal;
use helios_tpm::{BootDecision, SealedKeystore, SecretKey};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use zeroize::Zeroizing;

/// Longest a negotiated PSK may stay posed without being renewed.
///
/// WireGuard rekeys its session keys on its own, but the PSK entering every
/// one of those derivations does not change while it is installed. A tunnel
/// left up for months would protect all of it with a single ML-KEM secret.
///
/// Orion renegotiates well before this — the deadline is the backstop, not
/// the mechanism — so a slot actually reaching it means the renewal failed,
/// which is why the reclamation names it in the journal instead of quietly
/// extending.
const MAX_PSK_LIFETIME: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

const CERTIFICATE_PATH: &str = "/var/lib/helios/key-negotiation-cert.der";
const CLIENT_CA_PATH: &str = "/var/lib/helios/key-negotiation-client-ca.der";
const PQ_CERTIFICATE_PATH: &str = "/var/lib/helios/key-negotiation-pq-cert.json";
const GATEWAY_BOOTSTRAP_REQUEST_PATH: &str =
    "/var/lib/helios/gateway-bootstrap-certificate-request.json";
/// The one ML-DSA-87 authority a client leaf is authenticated under, on the
/// public port.
///
/// `pub(crate)` because the certificate lifecycle has to ask the same question
/// before it stages a candidate: see
/// [`crate::certificates::assert_candidate_is_presentable`].
pub(crate) const CLIENT_PQ_CA_PATH: &str =
    "/var/lib/helios/key-negotiation-client-pq-ca-public.bin";
const PRIVATE_KEYSTORE_PATH: &str = "/var/lib/helios/key-negotiation-key.sealed";
/// The candidate identity of a renewal in flight (spec §6.3, `staged`).
///
/// Sealed **beside** the active one and never over it. The operator ceremony
/// that turns a request into a signed transition happens off this machine and
/// may take days; the active leaf keeps mounting tunnels for the whole of it,
/// and again through the overlap of §4.1. A candidate written over the active
/// slot would take the gateway identity out of service at the moment the
/// ceremony has not even started.
const NEXT_PRIVATE_KEYSTORE_PATH: &str = "/var/lib/helios/key-negotiation-key-next.sealed";
/// Self-signed TLS leaf of the candidate, present only when the renewal
/// replaces the TLS half too (spec §6.1: each leaf is optional).
const NEXT_CERTIFICATE_PATH: &str = "/var/lib/helios/key-negotiation-cert-next.der";

/// The candidate's sealed private material. `HELIOS_KEY_NEGO_NEXT_KEY`
/// isolates a test run exactly as `HELIOS_GATEWAY_TRANSITION` does for the
/// transition document.
fn next_private_keystore_path() -> std::path::PathBuf {
    std::env::var_os("HELIOS_KEY_NEGO_NEXT_KEY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(NEXT_PRIVATE_KEYSTORE_PATH))
}

fn next_certificate_path() -> std::path::PathBuf {
    std::env::var_os("HELIOS_KEY_NEGO_NEXT_CERT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(NEXT_CERTIFICATE_PATH))
}
const MAX_REPLAY_IDENTIFIERS: usize = 4096;

mod candidate;
mod identity;
mod protocol;
mod server;
mod transaction;

// The paths the rest of the daemon already names, unchanged by the split.
pub(crate) use candidate::{
    assert_candidate_identity_promotable, candidate_tls_certificate, discard_candidate_identity,
    promote_candidate_identity, seal_candidate_identity, sign_certificate_request,
    RequestContinuity, SealedCandidate,
};
pub use identity::{
    gateway_bootstrap_request, initialize, install_gateway_bootstrap_certificate, public_material,
    restart_due, served_identity,
};
pub use server::start;
pub use transaction::{GatewayHandler, InstalledPsk};

// What the sibling modules name of each other, through `use super::*`.
use self::{candidate::*, identity::*, transaction::*};

/// First bytes of a transaction identifier.
///
/// The client prints the same prefix: it is what lets an operator put the two
/// halves of one negotiation side by side, on two machines whose clocks are
/// never quite aligned.
fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unix_time_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock predates the Unix epoch")?
        .as_secs())
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

fn write_public_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, contents)
        .with_context(|| format!("writing {}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("atomically replacing {}", path.display()))
}

#[cfg(test)]
mod tests;
