//! Astra's signed certificate status: freshness, never validity.

use super::*;

/// Which family a certified target belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateKind {
    GatewayTls,
    GatewayPq,
    ClientTls,
    ClientPq,
    CaPq,
    CaTls,
    AstraIssuer,
    AstraServiceKey,
}

impl CertificateKind {
    pub(super) const fn domain_byte(self) -> u8 {
        match self {
            Self::GatewayTls => 0,
            Self::GatewayPq => 1,
            Self::ClientTls => 2,
            Self::ClientPq => 3,
            Self::CaPq => 4,
            Self::CaTls => 5,
            Self::AstraIssuer => 6,
            Self::AstraServiceKey => 7,
        }
    }
}

/// Lifecycle state of one certified target, as the interfaces display it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Active,
    RenewalDue,
    PendingGrant,
    PendingCommit,
    Staged,
    Published,
    Aborted,
    Overlap,
    Expired,
    Revoked,
    /// A client renewal is open and waiting for an operator's key, before any
    /// candidate certificate exists (spec §8.2).
    ///
    /// It describes the **active** leaf, not a candidate: at this point there
    /// is none. `pending_grant` and `pending_commit` describe the candidate,
    /// once there is one.
    AwaitingOperator,
    /// The mutation that has just made this generation the active one.
    ///
    /// A later status with no new mutation describes it as `active` again, so
    /// this is an event and not a resting state.
    ///
    /// # Limite connue : accepté, jamais émis
    ///
    /// Nothing in this repository produces it. Saying "this generation was
    /// promoted **just now**" needs a per-target record of the last mutation,
    /// and Astra keeps a monotonic status counter rather than a mutation
    /// journal — the counter says a change happened, not which one or when.
    /// It stays in the enum because a decoder must accept every state the
    /// specification's family table names: refusing one the authority is
    /// entitled to send would be refusing a legitimate answer. Emitting it
    /// needs Astra to record the promotion it observes at admission
    /// synchronisation.
    Promoted,
}

impl CertificateStatus {
    /// Byte in the signed transcript.
    ///
    /// The two states added after the first ten are **appended** rather than
    /// slotted into the specification's reading order. The number is what the
    /// ML-DSA-87 signature covers, so renumbering an existing state would
    /// silently change what every already-signed status said.
    pub(super) const fn domain_byte(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::RenewalDue => 1,
            Self::PendingGrant => 2,
            Self::PendingCommit => 3,
            Self::Staged => 4,
            Self::Published => 5,
            Self::Aborted => 6,
            Self::Overlap => 7,
            Self::Expired => 8,
            Self::Revoked => 9,
            Self::AwaitingOperator => 10,
            Self::Promoted => 11,
        }
    }

    /// Whether this state forbids every rotation, recovery and rollback.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked)
    }

    /// Whether a family may be in this state at all (spec §8.2).
    ///
    /// # Why this is a refusal and not a display rule
    ///
    /// The specification is explicit: «il n'existe pas un enum libre commun à
    /// toutes les familles», and «le décodeur **doit** refuser une combinaison
    /// absente de ce tableau». A flat enum lets a signed status say
    /// `astra_issuer: pending_commit` — a sentence with no meaning, which
    /// every consumer would then have to interpret. Interpreting it is how two
    /// interfaces end up disagreeing about what the authority said.
    ///
    /// The subsets follow the shape of each lifecycle. Only a client leaf has
    /// an operator-approved renewal, so only it may be `awaiting_operator`,
    /// `pending_grant` or `pending_commit`. Only the gateway identity has a
    /// staged transition that can be published or aborted. The anchors stage
    /// and overlap but are never published or aborted, because nothing
    /// announces them separately. The delegated issuer has no overlap at all:
    /// it is replaced, not rotated through one.
    pub const fn permitted_for(self, kind: CertificateKind) -> bool {
        match kind {
            CertificateKind::ClientTls | CertificateKind::ClientPq => matches!(
                self,
                Self::Active
                    | Self::RenewalDue
                    | Self::AwaitingOperator
                    | Self::PendingGrant
                    | Self::PendingCommit
                    | Self::Overlap
                    | Self::Promoted
                    | Self::Expired
                    | Self::Revoked
            ),
            CertificateKind::GatewayTls | CertificateKind::GatewayPq => matches!(
                self,
                Self::Active
                    | Self::RenewalDue
                    | Self::Staged
                    | Self::Published
                    | Self::Aborted
                    | Self::Overlap
                    | Self::Promoted
                    | Self::Expired
                    | Self::Revoked
            ),
            CertificateKind::CaPq | CertificateKind::CaTls | CertificateKind::AstraServiceKey => {
                matches!(
                    self,
                    Self::Active
                        | Self::RenewalDue
                        | Self::Staged
                        | Self::Overlap
                        | Self::Promoted
                        | Self::Expired
                        | Self::Revoked
                )
            }
            CertificateKind::AstraIssuer => matches!(
                self,
                Self::Active | Self::RenewalDue | Self::Expired | Self::Revoked
            ),
        }
    }
}

/// Signed freshness statement about one certificate (spec §8.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraCertificateStatus {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub certificate_fingerprint: Fingerprint,
    pub certificate_kind: CertificateKind,
    pub generation: u64,
    pub status: CertificateStatus,
    pub suggested_window_start: u64,
    pub suggested_window_end: u64,
    pub produced_at: u64,
    pub next_update: u64,
    pub status_epoch: u64,
    pub astra_service_key_epoch: u64,
    pub astra_signature: MlDsa87Signature,
}

impl AstraCertificateStatus {
    pub(super) fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(STATUS_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .fingerprint(&self.certificate_fingerprint)
            .u8(self.certificate_kind.domain_byte())
            .u64(self.generation)
            .u8(self.status.domain_byte())
            .u64(self.suggested_window_start)
            .u64(self.suggested_window_end)
            .u64(self.produced_at)
            .u64(self.next_update)
            .u64(self.status_epoch)
            .u64(self.astra_service_key_epoch);
        bytes.finish_signed()
    }

    /// Ordering key: the service key epoch dominates the status epoch.
    pub fn ordering_key(&self) -> (u64, u64) {
        (self.astra_service_key_epoch, self.status_epoch)
    }

    /// Verifies signature, binding and monotonicity.
    ///
    /// `service_key` must be the one whose epoch this status names — the
    /// caller resolves active or next from its own pinned pair, so a status
    /// cannot select the key that verifies it.
    pub fn verify(
        &self,
        service_key: &MlDsa87PublicKey,
        service_key_epoch: u64,
        trust_domain_id: &TrustDomainId,
        certificate_fingerprint: &Fingerprint,
        last_seen: Option<(u64, u64)>,
    ) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        // Before the signature, because it costs a match and the signature
        // costs an ML-DSA-87 verification — and because a combination the
        // table does not hold is a sentence with no meaning, whoever signed
        // it. §8.2 makes this a decoder obligation, not a display rule.
        if !self.status.permitted_for(self.certificate_kind) {
            return Err(CertificateError::UnsupportedStatus {
                kind: self.certificate_kind,
                status: self.status,
            });
        }
        if self.astra_service_key_epoch != service_key_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if !self
            .certificate_fingerprint
            .matches(certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("status target"));
        }
        if let Some(previous) = last_seen {
            if self.ordering_key() < previous {
                return Err(CertificateError::GenerationRollback {
                    current: previous.1,
                    proposed: self.status_epoch,
                });
            }
        }
        verify_ml_dsa_87(service_key, &self.signing_bytes(), &self.astra_signature)
    }

    /// Clamps the suggested renewal window to what the client computed itself.
    ///
    /// Astra may bring the window **forward** — an incident campaign — but it
    /// can never push the start past the local `renewal_at`, nor the end past
    /// the expiry. A gateway that could delay renewals could manufacture the
    /// very expiry the planner exists to prevent.
    pub fn clamped_window(&self, local_renewal_at: u64, local_not_after: u64) -> (u64, u64) {
        (
            self.suggested_window_start.min(local_renewal_at),
            self.suggested_window_end.min(local_not_after),
        )
    }
}

/// Bytes an out-of-tunnel status query signs (spec §8.2).
///
/// No status is ever indexable by fingerprint alone: the requester must prove
/// possession of the PQ key of the exact identity it asks about. Knowing a
/// fingerprint seen on the wire therefore reveals neither generation, nor
/// window, nor rotation schedule.
#[allow(clippy::too_many_arguments)]
pub fn status_query_signing_bytes(
    trust_domain_id: &TrustDomainId,
    astra_challenge: &[u8; 32],
    request_id: &Id16,
    gateway_wg_public_key: &WireGuardKey,
    client_wg_public_key: &WireGuardKey,
    certificate_fingerprint: &Fingerprint,
) -> SignedTranscript {
    let mut bytes = CanonicalBytes::new(STATUS_QUERY_DOMAIN);
    bytes
        .id(trust_domain_id)
        .raw(astra_challenge)
        .id(request_id)
        .key(gateway_wg_public_key)
        .key(client_wg_public_key)
        .fingerprint(certificate_fingerprint);
    bytes.finish_signed()
}
