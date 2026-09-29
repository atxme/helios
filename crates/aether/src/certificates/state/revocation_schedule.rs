//! Scheduled revocations, their tombstones and the bounds on both.

use super::*;

/// Largest number of revocations held before their effective instant.
///
/// A ceiling rather than an unbounded list: an identity can only ever be
/// revoked once, so more than a handful in flight means something is wrong,
/// and growing a bounded state on a remote party's say-so is how it stops
/// being bounded.
pub const MAX_SCHEDULED_REVOCATIONS: usize = 8;

/// Largest number of revoked fingerprints remembered at once.
///
/// Generous next to the number of slots a holder has, because a tombstone may
/// name something it never held. When it fills, [`TrustLedger::remember`]
/// refuses rather than evicting: forgetting a revocation restores the ability
/// to reinstall the leaf, and nothing later would notice.
pub const MAX_REVOCATION_TOMBSTONES: usize = 32;

/// Largest number of status-ordering entries kept.
///
/// The targets are drawn from the slots the holder already has — two anchors,
/// two gateway leaves per family, three client generations — so the map is
/// naturally bounded. The ceiling is what makes that a checked property
/// instead of an argument.
pub const MAX_TRACKED_STATUS_TARGETS: usize = 24;

/// A verified revocation waiting for its own instant (spec §10.1).
///
/// Its scope is kept, and it is the whole point: the object named either the
/// gateway or a client, and applying it to the other one would remove an
/// identity nobody revoked while leaving the compromised one in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledRevocation {
    pub scope: RevocationScope,
    pub revocation_epoch: u64,
    pub effective_at: u64,
    pub revoked_tls_fingerprint: Option<Fingerprint>,
    pub revoked_tls_not_after: Option<u64>,
    pub revoked_pq_fingerprint: Option<Fingerprint>,
    pub revoked_pq_not_after: Option<u64>,
    /// Fingerprint of the signed revocation, carried through to the tombstone.
    pub revocation_fingerprint: Option<Fingerprint>,
    /// The replacement the revocation named, carried to the state it will
    /// have to accept it from (spec §10.1).
    #[serde(default)]
    pub replacement_transition_fingerprint: Option<Fingerprint>,
}

impl ScheduledRevocation {
    /// Whether this revocation withdraws any fingerprint a client holds.
    ///
    /// Both families are checked. A revocation naming only the TLS half is a
    /// revocation: the generation is indivisible, and letting the PQ half
    /// survive would leave an identity that mTLS refuses and the negotiation
    /// still accepts.
    pub(super) fn hits_client(&self, certificates: &ClientCertificateState) -> bool {
        let occupied = certificates.occupied_fingerprints();
        [self.revoked_tls_fingerprint, self.revoked_pq_fingerprint]
            .into_iter()
            .flatten()
            .any(|revoked| occupied.iter().any(|held| held.matches(&revoked)))
    }
}

/// Which half of a generation a revoked fingerprint belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokedFamily {
    Tls,
    Pq,
}

/// A revoked fingerprint, remembered after the decision took effect (§10.2).
///
/// Applying a revocation and then forgetting the fingerprint is the subtle
/// half of the rule. Removing a leaf the holder currently has is visible and
/// easy; what matters just as much is a revocation naming a leaf the holder
/// does **not** have yet — a candidate still in flight, or a gateway leaf that
/// has not been distributed. Consumed and then dropped, the decision is gone:
/// the epoch has been spent, so the object can never be delivered again, and
/// the next transition carrying that very leaf installs it as if nothing had
/// happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationTombstone {
    pub scope: RevocationScope,
    pub family: RevokedFamily,
    pub fingerprint: Fingerprint,
    pub revocation_epoch: u64,
    /// Instant past which the revoked certificate could not have been valid.
    /// Signed into a remote revocation and read from the generation for a
    /// local `peer remove`, so it is available even if this holder never saw
    /// the certificate itself.
    pub expires_at: u64,
    /// The signed revocation this came from.
    ///
    /// `None` for a local operator decision — `peer remove` on the gateway has
    /// no signed object at all, and recording its absence is more honest than
    /// fabricating a fingerprint for it.
    pub revocation_fingerprint: Option<Fingerprint>,
}

/// Ordering key of the last status accepted for one target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusOrdering {
    pub astra_service_key_epoch: u64,
    pub status_epoch: u64,
}

impl StatusOrdering {
    pub(super) fn key(self) -> (u64, u64) {
        (self.astra_service_key_epoch, self.status_epoch)
    }
}
