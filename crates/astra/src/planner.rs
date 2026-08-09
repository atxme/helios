//! The renewal planner and the signed status Astra publishes.
//!
//! # A window, not a deadline
//!
//! Astra publishes a *suggested window* and Orion picks a stable instant
//! inside it. The dispersion is the client's job on purpose: a fleet that all
//! renewed at `renewal_at` would arrive together, and the one moment an
//! authority must not be saturated is the moment everybody's certificate is
//! at 80 % of its life.
//!
//! # What the authority may and may not move
//!
//! Astra can bring the window **forward** — an incident campaign — but never
//! push it back past the client's own `renewal_at`, nor past the expiry. That
//! asymmetry is enforced on the client side by
//! [`AstraCertificateStatus::clamped_window`], and mirrored here so the two
//! ends agree on what a legitimate window looks like.

use aether::certificates::{
    client::ClientCertificateGeneration,
    encoding::{Fingerprint, MlDsa87Signature, TrustDomainId},
    status::{AstraCertificateStatus, CertificateKind, CertificateStatus},
    window::{RENEWAL_CRITICAL_PERCENT, RENEWAL_OPENS_AT_PERCENT, RENEWAL_WARNING_PERCENT},
    CertificateError, CERTIFICATE_FORMAT_VERSION,
};

use crate::registry::PeerRecord;

/// How urgent a renewal is, from the authority's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalUrgency {
    /// Below 80 %: nothing to do.
    Idle,
    /// The ordinary window is open.
    Due,
    /// Past 90 %: a persistent alert.
    Warning,
    /// Past 95 %: critical, and repeated daily.
    Critical,
    /// Past `not_after`: only the recovery path of spec §7.5 remains.
    Expired,
}

/// Classifies one generation against the thresholds of spec §4.3.
pub fn urgency(
    generation: &ClientCertificateGeneration,
    now_unix: u64,
) -> Result<RenewalUrgency, CertificateError> {
    let validity = generation.validity()?;
    if now_unix >= validity.not_after {
        return Ok(RenewalUrgency::Expired);
    }
    let elapsed = validity.elapsed_percent(now_unix)?;
    Ok(if elapsed >= RENEWAL_CRITICAL_PERCENT {
        RenewalUrgency::Critical
    } else if elapsed >= RENEWAL_WARNING_PERCENT {
        RenewalUrgency::Warning
    } else if elapsed >= RENEWAL_OPENS_AT_PERCENT {
        RenewalUrgency::Due
    } else {
        RenewalUrgency::Idle
    })
}

/// The window Astra suggests for one generation.
///
/// Contained between `renewal_at` and the expiry, so it can never be read as
/// permission to renew later than the client already decided.
pub fn suggested_window(
    generation: &ClientCertificateGeneration,
) -> Result<(u64, u64), CertificateError> {
    let validity = generation.validity()?;
    Ok((validity.renewal_at()?, validity.not_after))
}

/// Builds the signed status of one peer's active identity (spec §8.2).
///
/// `status_epoch` comes from the registry's monotonic counter, and the key
/// epoch is stamped alongside it: the pair is compared lexicographically by
/// the client, which is what keeps a compromised key from freezing a target.
pub fn client_status(
    trust_domain_id: TrustDomainId,
    peer: &PeerRecord,
    status_epoch: u64,
    astra_service_key_epoch: u64,
    now_unix: u64,
    next_update: u64,
) -> Result<AstraCertificateStatus, CertificateError> {
    let (window_start, window_end) = suggested_window(&peer.active)?;
    let status = if peer.revoked {
        CertificateStatus::Revoked
    } else if let Some(rotation) = &peer.pending {
        if rotation.granted {
            CertificateStatus::PendingCommit
        } else {
            CertificateStatus::PendingGrant
        }
    } else {
        match urgency(&peer.active, now_unix)? {
            RenewalUrgency::Expired => CertificateStatus::Expired,
            RenewalUrgency::Idle => CertificateStatus::Active,
            _ => CertificateStatus::RenewalDue,
        }
    };

    Ok(AstraCertificateStatus {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id,
        certificate_fingerprint: peer.active.pq_certificate_fingerprint,
        certificate_kind: CertificateKind::ClientPq,
        generation: peer.active.generation,
        status,
        suggested_window_start: window_start,
        suggested_window_end: window_end,
        produced_at: now_unix,
        next_update,
        status_epoch,
        astra_service_key_epoch,
        astra_signature: MlDsa87Signature::placeholder(),
    })
}

/// Fingerprint of a peer's active PQ identity, for status lookups.
pub fn status_target(peer: &PeerRecord) -> Fingerprint {
    peer.active.pq_certificate_fingerprint
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PendingRotation;
    use aether::certificates::encoding::{Id16, WireGuardKey};
    use aether::certificates::window::TransitionWindow;
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

    fn generation() -> ClientCertificateGeneration {
        ClientCertificateGeneration {
            generation: 4,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(b"tls"),
            pq_certificate_fingerprint: Fingerprint::of(b"pq"),
            not_before: 0,
            not_after: 1_000,
        }
    }

    fn peer() -> PeerRecord {
        PeerRecord {
            name: "workstation".into(),
            client_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            active: generation(),
            active_pq_certificate: PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [1; 16],
                subject: "orion".into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: WireGuardKey::from_bytes([2; 32]).to_base64(),
                ml_dsa_87_public_key: String::new(),
                not_before_unix: 0,
                not_after_unix: 1_000,
                ml_dsa_87_signature: String::new(),
            },
            pending: None,
            revoked: false,
            revocation_epoch: 0,
        }
    }

    #[test]
    fn the_thresholds_of_the_specification_are_the_ones_applied() {
        let generation = generation();
        assert_eq!(urgency(&generation, 799).unwrap(), RenewalUrgency::Idle);
        assert_eq!(urgency(&generation, 800).unwrap(), RenewalUrgency::Due);
        assert_eq!(urgency(&generation, 900).unwrap(), RenewalUrgency::Warning);
        assert_eq!(urgency(&generation, 950).unwrap(), RenewalUrgency::Critical);
        assert_eq!(
            urgency(&generation, 1_000).unwrap(),
            RenewalUrgency::Expired
        );
    }

    /// The suggested window opens at the same instant the client computes and
    /// closes at the expiry — it can never license a later renewal.
    #[test]
    fn the_suggested_window_never_reaches_past_the_expiry() {
        let (start, end) = suggested_window(&generation()).expect("window");
        assert_eq!(start, 800);
        assert_eq!(end, 1_000);
    }

    /// `revoked` is terminal and wins over every other reading of the state.
    #[test]
    fn a_revoked_peer_is_reported_revoked_whatever_its_dates_say() {
        let mut peer = peer();
        peer.revoked = true;
        let status = client_status(TrustDomainId::new([1; 16]).unwrap(), &peer, 1, 1, 100, 200)
            .expect("status");
        assert_eq!(status.status, CertificateStatus::Revoked);
        assert!(status.status.is_terminal());
    }

    #[test]
    fn a_rotation_in_flight_is_reported_by_the_stage_it_reached() {
        let mut peer = peer();
        peer.pending = Some(PendingRotation {
            stage_id: Id16::new([1; 16]).unwrap(),
            request_fingerprint: Fingerprint::of(b"request"),
            candidate: generation(),
            window: TransitionWindow::new(1, 2, 3).unwrap(),
            stage_expires_at: 5_000,
            granted: false,
        });
        let domain = TrustDomainId::new([1; 16]).unwrap();
        let pending = client_status(domain, &peer, 1, 1, 100, 200).expect("status");
        assert_eq!(pending.status, CertificateStatus::PendingGrant);

        peer.pending.as_mut().unwrap().granted = true;
        let granted = client_status(domain, &peer, 2, 1, 100, 200).expect("status");
        assert_eq!(granted.status, CertificateStatus::PendingCommit);
    }

    /// An expired leaf is reported expired, and no status makes it usable
    /// again: the recovery path is the only way back.
    #[test]
    fn an_expired_identity_is_never_reported_active() {
        let status = client_status(
            TrustDomainId::new([1; 16]).unwrap(),
            &peer(),
            1,
            1,
            2_000,
            2_100,
        )
        .expect("status");
        assert_eq!(status.status, CertificateStatus::Expired);
    }
}
