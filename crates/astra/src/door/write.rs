//! The three writes of the registry that are not openings (§5.6).
//!
//! Each is written once, here, on a `&mut AstraRegistry`, and reached by two
//! paths that never run together: the door, under the registry lock of the
//! running service, and the console with the service stopped, on a registry
//! it loaded under [`super::VolumeLock`]. The checks are the ones these writes
//! always had — an anchor pinned once and never replaced, a delegation
//! verified under the anchor, the policy and the keys on disk, a publication
//! marked before it is relayed — so which path a write arrived by decides
//! nothing about whether it is allowed.
//!
//! Every write runs through [`AstraRegistry::write_or_restore`]: one that
//! fails, its save included, leaves the registry in memory exactly as it was.
//! The service keeps that memory for its whole life, and a change the file
//! never received must not be relayed, nor persisted later by an unrelated
//! save.

use std::path::Path;

use aether::certificates::authority::AstraIssuerAuthorization;
use aether::certificates::encoding::Fingerprint;

use super::DoorRefusal;
use crate::gateway::GatewayChannel;
use crate::issuer::AdoptionError;
use crate::registry::{AstraRegistry, RegistryError};

/// Records the client `CA-TLS` in service, once (spec §9.4).
///
/// Pinning the anchor already held changes nothing and is not a refusal, so a
/// deployment may run it on every pass. Another anchor is refused: replacing a
/// pinned anchor is a rotation, and a rotation is signed.
///
/// Returns the audit head after the write.
pub fn pin_ca_tls(
    registry: &mut AstraRegistry,
    fingerprint: Fingerprint,
    now_unix: u64,
) -> Result<Fingerprint, DoorRefusal> {
    if let Some(held) = registry.state().ca_tls_fingerprint {
        return if held.matches(&fingerprint) {
            Ok(registry.audit_head())
        } else {
            Err(DoorRefusal::ClientTlsAnchorAlreadyPinned)
        };
    }
    registry
        .write_or_restore(|registry| registry.pin_client_tls_ca(fingerprint, now_unix))
        .map_err(|error| not_recorded("pin the client CA-TLS anchor", &error))?;
    Ok(registry.audit_head())
}

/// What an installed delegation is, as `issuer install` prints it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuerInstalled {
    pub issuer_epoch: u64,
    /// The delegation's own end, signed by `CA-PQ`.
    pub not_after: u64,
    pub audit_head: Fingerprint,
}

/// Installs a signed delegation, after checking it three ways.
///
/// The anchor the registry pins, the policy it computed at bootstrap, and the
/// private keys this state volume holds for its epoch: the same
/// [`crate::issuer::adopt`] the operator result of §8.2 goes through. A
/// delegation installed here is recorded, not yet used: the delegated issuer
/// is read at start-up, beside the private keys it names, so Astra issues
/// under it once restarted.
pub fn issuer_install(
    registry: &mut AstraRegistry,
    state_dir: &Path,
    authorization: AstraIssuerAuthorization,
    now_unix: u64,
) -> Result<IssuerInstalled, DoorRefusal> {
    let issuer_epoch = authorization.issuer_epoch;
    let not_after = authorization.not_after;
    registry
        .write_or_restore(|registry| {
            crate::issuer::adopt(
                registry,
                authorization,
                &crate::issuer::pq_key_path(state_dir, issuer_epoch),
                &crate::issuer::tls_key_path(state_dir, issuer_epoch),
                now_unix,
            )
        })
        .map_err(|error| match error {
            // The registry could not be written: nothing the operator sent is at
            // fault. A delegation that does not advance the epoch is a refusal of
            // the document, and stays one.
            AdoptionError::Registry(error)
                if !matches!(error, RegistryError::IssuerEpochNotAdvancing { .. }) =>
            {
                not_recorded("record the delegation", &error)
            }
            refused => DoorRefusal::DelegationRefused(refused),
        })?;
    Ok(IssuerInstalled {
        issuer_epoch,
        not_after,
        audit_head: registry.audit_head(),
    })
}

/// A gateway transition marked published, and what the gateway is told of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicationMark {
    pub epoch: u64,
    pub transition_fingerprint: Fingerprint,
    /// When the transition takes effect, from its signed window.
    pub activation_at: u64,
}

/// Marks a signed gateway transition published, durably (spec §11.1 step 6).
///
/// Persisted first, and irreversibly. A marker written after the relay would
/// leave a gateway that has closed its abort window while this authority still
/// believes the decision cancellable — and §6.3 makes the gateway's belief the
/// one clients act on. Idempotent: a mark already written is saved and
/// returned again, so a relay that failed is retried by asking for the same
/// publication, and a mark the file does not hold is never relayed.
pub fn mark_gateway_transition_published(
    registry: &mut AstraRegistry,
    epoch: u64,
    now_unix: u64,
) -> Result<PublicationMark, DoorRefusal> {
    let transition = registry
        .write_or_restore(|registry| registry.publish_gateway_transition(epoch, now_unix))
        .map_err(|error| match error {
            RegistryError::UnknownPeer => DoorRefusal::NoGatewayTransition { epoch },
            RegistryError::Transition(_) => DoorRefusal::GatewayTransitionAborted { epoch },
            other => not_published("mark the gateway transition published", &other),
        })?;
    let transition_fingerprint = transition
        .fingerprint()
        .map_err(|error| not_published("fingerprint the published transition", &error))?;
    Ok(PublicationMark {
        epoch,
        transition_fingerprint,
        activation_at: transition.window.activation_at,
    })
}

/// Tells the gateway a transition has left the authority.
///
/// `true` when the gateway confirmed it. A refusal or a silent gateway is
/// logged and answered `false`, never undone: the mark stays, and the same
/// publication asked again relays it again.
pub async fn relay_gateway_publication(channel: &GatewayChannel, mark: &PublicationMark) -> bool {
    match channel
        .gateway_transition_published(&astra_channel::GatewayTransitionPublished {
            gateway_identity_epoch: mark.epoch,
            transition_fingerprint: mark.transition_fingerprint,
        })
        .await
    {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(
                epoch = mark.epoch,
                %error,
                "the publication is recorded but the gateway did not confirm it; ask for the \
                 same publication again"
            );
            false
        }
    }
}

/// Marks a transition published, then relays it: both halves, in that order.
///
/// For a caller that owns its registry outright, the console under the volume
/// lock. The door cannot hold its registry lock across the relay, so it calls
/// the two halves itself, in the same order.
pub async fn publish_gateway_transition(
    registry: &mut AstraRegistry,
    channel: &GatewayChannel,
    epoch: u64,
    now_unix: u64,
) -> Result<(PublicationMark, bool), DoorRefusal> {
    let mark = mark_gateway_transition_published(registry, epoch, now_unix)?;
    let confirmed = relay_gateway_publication(channel, &mark).await;
    Ok((mark, confirmed))
}

fn not_recorded(what: &'static str, error: &dyn std::fmt::Display) -> DoorRefusal {
    tracing::error!(%error, "the door could not {what}");
    DoorRefusal::NotRecorded
}

fn not_published(what: &'static str, error: &dyn std::fmt::Display) -> DoorRefusal {
    tracing::error!(%error, "the door could not {what}");
    DoorRefusal::NotPublished
}
