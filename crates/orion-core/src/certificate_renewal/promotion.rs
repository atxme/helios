//! The local generation lifecycle: naming the candidate, promoting it when
//! its instant comes, and selecting the outgoing identity during the overlap.

use std::path::Path;

use aether::certificates::client::ClientCertificateGeneration;
use aether::certificates::gateway::pq_certificate_fingerprint;
use aether::certificates::CertificateError;

use crate::certificates::{TrustState, TrustStore};
use crate::identity_store::{ClientIdentityBundle, ProtectedIdentityStore};
use crate::KeyNegotiationSettings;

use super::trust_store::{client_pq_leaf, client_tls_leaf, open_identity_store};
use super::RenewalError;
use super::{committed_and_waiting, horodatage};

/// Name the candidate identity is sealed under until it activates.
///
/// A second entry rather than a replacement, and that is the whole point: the
/// active generation keeps connecting for the length of the overlap, and its
/// private keys have to stay exactly where the tunnel expects them. Sealing
/// the candidate over the top would break every handshake between the commit
/// and the activation the window schedules — an outage the renewal is
/// precisely supposed to avoid.
///
/// The suffix survives [`ProtectedIdentityStore`]'s name sanitising, which
/// keeps `-` and drops separators: it can never designate a file elsewhere.
pub fn candidate_identity_of(identity: &str) -> String {
    format!("{}-next", identity.trim())
}

/// Promotes a candidate whose activation instant has come.
///
/// Two things move together, and the order is what matters: the sealed keys
/// go into place **before** the state says the candidate is active. A crash
/// between the two leaves the store still naming the old generation, which
/// still has its keys — the renewal is retried, not lost. The reverse order
/// leaves a state pointing at a certificate whose private half is under
/// another name, and the tunnel fails at the next handshake.
///
/// Returns whether anything moved. Called from the same place that refreshes
/// the store, so a client that was offline across its own activation instant
/// catches up at the next launch rather than at the next renewal.
pub fn promote_due(
    store: &mut TrustStore,
    identities: &ProtectedIdentityStore,
    identity: &str,
    now_unix: u64,
) -> Result<bool, RenewalError> {
    let due_window = store
        .state()
        .certificates
        .next
        .as_ref()
        .zip(store.state().certificates.activation_at)
        .zip(store.state().certificates.retire_active_at)
        .map(|((_, activation_at), retire_at)| (activation_at, retire_at))
        .filter(|(activation_at, _)| now_unix >= *activation_at);
    let Some((activation_at, retire_at)) = due_window else {
        // Everything else the store promotes on its own schedule — anchors,
        // gateway identity, service key — has no local key material to move.
        let refreshed = store.refresh(now_unix)?;
        let retired = identities
            .retire_previous(identity, now_unix)
            .map_err(|error| RenewalError::Identity(error.to_string()))?;
        return Ok(refreshed || retired);
    };

    let candidate_identity = candidate_identity_of(identity);
    let candidate = identities
        .load(&candidate_identity)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let promoted = ClientIdentityBundle {
        identity: identity.trim().to_string(),
        ..candidate
    };
    let installed = identities
        .promote_with_previous(identity, &promoted, activation_at, retire_at)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let refreshed = store.refresh(now_unix)?;
    let retired = identities
        .retire_previous(identity, now_unix)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    Ok(installed || refreshed || retired)
}

/// Catches the protected service identity up before pre-WireGuard negotiation.
///
/// Trust updates and renewals already call [`promote_due`], but both normally
/// run through the tunnel. An expired recovery has no tunnel yet: if its
/// committed candidate becomes active while Orion is disconnected, waiting
/// for an in-tunnel call to promote the sealed identity is a cycle that can
/// never complete. The connection path calls this before loading its TLS/PQ
/// pair, so the first negotiation at or after `activation_at` presents the
/// generation the gateway now admits.
pub fn promote_local_identity_if_due(
    settings: &KeyNegotiationSettings,
    identities: &ProtectedIdentityStore,
    now_unix: u64,
) -> Result<bool, RenewalError> {
    if settings.trust.is_none() {
        return Ok(false);
    }
    let identity = settings.identity.trim();
    if identity.is_empty() {
        return Err(RenewalError::Identity(
            "ce profil ne nomme aucune identité protégée".into(),
        ));
    }
    let bundle = identities
        .load(identity)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let config = crate::config::ClientConfig::path()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let mut store = open_identity_store(
        config.parent().unwrap_or_else(|| Path::new(".")),
        settings,
        &bundle,
    )?;
    promote_due(&mut store, identities, identity, now_unix)
}

/// Promotes what is due and refuses an expired outgoing identity while the
/// recovered successor is still waiting for its signed activation instant.
pub(crate) fn prepare_identity_for_connection(
    settings: &KeyNegotiationSettings,
    identities: &ProtectedIdentityStore,
    now_unix: u64,
) -> Result<bool, RenewalError> {
    let promoted = promote_local_identity_if_due(settings, identities, now_unix)?;
    if settings.trust.is_none() {
        return Ok(promoted);
    }

    let identity = settings.identity.trim();
    let bundle = identities
        .load(identity)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let config = crate::config::ClientConfig::path()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let store = open_identity_store(
        config.parent().unwrap_or_else(|| Path::new(".")),
        settings,
        &bundle,
    )?;
    if now_unix >= store.state().certificates.active.not_after {
        if let Some((generation, activation_at)) =
            committed_and_waiting(&store.state().certificates, now_unix)
        {
            return Err(RenewalError::ActivationPending {
                generation,
                activation_at: horodatage(activation_at),
            });
        }
    }
    Ok(promoted)
}

/// Result of selecting the outgoing identity for service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientServiceRollback {
    pub selected_generation: u64,
    pub available_until: u64,
}

fn bundle_matches_generation(
    bundle: &ClientIdentityBundle,
    generation: &ClientCertificateGeneration,
) -> Result<(), RenewalError> {
    let tls = client_tls_leaf(bundle)?;
    let pq = client_pq_leaf(bundle)?;
    if !generation
        .tls_certificate_fingerprint
        .matches(&tls.fingerprint())
    {
        return Err(RenewalError::Certificate(
            CertificateError::FingerprintMismatch("client TLS identity"),
        ));
    }
    if !generation
        .pq_certificate_fingerprint
        .matches(&pq_certificate_fingerprint(&pq)?)
    {
        return Err(RenewalError::Certificate(
            CertificateError::FingerprintMismatch("client PQ identity"),
        ));
    }
    Ok(())
}

pub(super) fn rollback_window(
    state: &TrustState,
    now_unix: u64,
) -> Result<
    (
        ClientCertificateGeneration,
        ClientCertificateGeneration,
        u64,
    ),
    RenewalError,
> {
    let certificates = &state.certificates;
    let incoming = certificates
        .next
        .as_ref()
        .ok_or(RenewalError::RollbackUnavailable)?;
    let activation_at = certificates
        .activation_at
        .ok_or(RenewalError::RollbackUnavailable)?;
    let retire_at = certificates
        .retire_active_at
        .ok_or(RenewalError::RollbackUnavailable)?;
    if certificates.revoked || now_unix < activation_at || now_unix >= retire_at {
        return Err(RenewalError::RollbackUnavailable);
    }
    Ok((certificates.active.clone(), incoming.clone(), retire_at))
}

/// Selects the outgoing client identity during its overlap (§4.4).
///
/// This is deliberately a local service selection, not a signed trust-state
/// mutation. Both generations were already authorized by the operator-approved
/// grant and are accepted by the gateway during the overlap; a CA signature
/// cannot add authority to the client's possession of either private key. The
/// gateway case is different because a console user does not possess its
/// private keys, hence its separate `CA-PQ` rollback authorization.
///
/// The authoritative trust store is read and validated but never mutated. In
/// particular, no generation or revocation counter can move backwards, and a
/// restored protected file naming certificates outside active/next is refused
/// before the selector is written.
pub fn rollback_to_previous(
    settings: &KeyNegotiationSettings,
    now_unix: u64,
) -> Result<ClientServiceRollback, RenewalError> {
    let identity = settings.identity.trim();
    if identity.is_empty() {
        return Err(RenewalError::Identity(
            "ce profil ne nomme aucune identité protégée".into(),
        ));
    }
    let identities = ProtectedIdentityStore::for_current_user()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let snapshot = identities
        .snapshot_at(identity, now_unix)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let config = crate::config::ClientConfig::path()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let mut store = open_identity_store(
        config.parent().unwrap_or_else(|| Path::new(".")),
        settings,
        &snapshot.served,
    )?;
    promote_due(&mut store, &identities, identity, now_unix)?;

    let (outgoing, incoming, retire_at) = rollback_window(store.state(), now_unix)?;
    let selected_generation = outgoing.generation;

    identities
        .select_previous(identity, now_unix, |current, previous| {
            bundle_matches_generation(current, &incoming).map_err(anyhow::Error::from)?;
            bundle_matches_generation(previous, &outgoing).map_err(anyhow::Error::from)
        })
        .map_err(|error| RenewalError::Identity(error.to_string()))?;

    Ok(ClientServiceRollback {
        selected_generation,
        available_until: retire_at,
    })
}
