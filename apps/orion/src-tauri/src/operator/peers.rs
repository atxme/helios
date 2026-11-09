//! What the *Postes* tab reads, and how the reads combine.
//!
//! Each source answers on its own: the gateway's certificates, the gateway's
//! admission, Astra's authority status and its pending campaigns, and the
//! decision waiting on this machine. A source that does not answer is an
//! [`Reach`] of its own, and it never takes another source's answer down with
//! it. Only names, public keys and dates cross to the WebView.

use aether::certificates::encoding::Id16;
use aether::certificates::status::{CampaignTarget, CertificateKind};
use orion_core::gateway_admin::{AdmittedPeer, GatewayAdminError};
use orion_core::operator_rotations::{
    AuthorityStatusRead, PeerCertificateRead, PeerCertificatesRead, PendingOperationRead, Reach,
};

/// The scope a client revocation campaign carries, as `CampaignScope` names it
/// on the wire. A gateway revocation carries the same scope, which is why the
/// targets, not the scope, tell them apart.
const EMERGENCY_REVOCATION: &str = "emergency_revocation";

/// Everything the tab shows, one source per field. Keys are WireGuard public
/// keys in base64; names and dates are the gateway's. No private key, no
/// certificate body, no token.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeersOverview {
    /// `GET /api/certificates`: every peer of the registry, revoked ones included.
    pub certificates: Reach<Vec<PeerCertificateRead>>,
    /// `GET /api/network`: the peers the gateway admits.
    pub admitted: Reach<Vec<AdmittedPeer>>,
    /// Astra's `revoked_peers`.
    pub astra_revoked: Reach<Vec<String>>,
    /// Keys named by a pending client revocation campaign.
    pub pending_revocations: Reach<Vec<String>>,
    /// This workstation's WireGuard public key, from the selected profile.
    pub own_key: Option<String>,
    /// The gateway's clock, when the gateway answered.
    pub now_unix: Option<u64>,
    /// The key named by the decision recorded on this machine, awaiting its deposit.
    pub local_pending: Option<String>,
}

/// The gateway's clock, when the certificate read answered.
pub fn clock_of(certificates: &Reach<PeerCertificatesRead>) -> Option<u64> {
    certificates.ok().and_then(|read| read.now_unix)
}

/// Combines the reads. Each source keeps its own answer: a failed source
/// shows as its own [`Reach`] and leaves the others as they were.
pub fn assemble(
    certificates: Reach<PeerCertificatesRead>,
    admitted: Reach<Vec<AdmittedPeer>>,
    astra: Reach<AuthorityStatusRead>,
    pending_revocations: Reach<Vec<String>>,
    own_key: Option<String>,
    local_pending: Option<String>,
) -> PeersOverview {
    let now_unix = clock_of(&certificates);
    PeersOverview {
        certificates: certificates.map(|read| read.peers),
        admitted,
        astra_revoked: astra.map(|status| status.revoked_peers),
        pending_revocations,
        own_key,
        now_unix,
        local_pending,
    }
}

/// The keys of the client revocations among the pending operations.
///
/// Only the `EmergencyRevocation` operations are fetched, one at a time, and a
/// target counts when it is a client identity: a gateway revocation names the
/// gateway's own leaves and contributes nothing. A failed fetch makes the whole
/// answer unreachable, never a shorter list.
pub fn pending_revocations(
    pending: Reach<Vec<PendingOperationRead>>,
    mut targets_of: impl FnMut(&Id16) -> Result<Vec<CampaignTarget>, String>,
) -> Reach<Vec<String>> {
    match pending {
        Reach::Ok(operations) => {
            let mut keys: Vec<String> = Vec::new();
            for operation in operations
                .iter()
                .filter(|operation| operation.scope == EMERGENCY_REVOCATION)
            {
                let Ok(id) = Id16::parse_hex(&operation.operation_id) else {
                    return Reach::Unreachable;
                };
                let Ok(targets) = targets_of(&id) else {
                    return Reach::Unreachable;
                };
                for target in targets {
                    if matches!(
                        target.certificate_kind,
                        CertificateKind::ClientTls | CertificateKind::ClientPq
                    ) {
                        let key = target.identity_key.to_base64();
                        if !keys.contains(&key) {
                            keys.push(key);
                        }
                    }
                }
            }
            Reach::Ok(keys)
        }
        other => other.map(|_| Vec::new()),
    }
}

/// The selected profile's WireGuard public key, when it has one. The engine
/// derives it from the stored private key and keeps the private key itself;
/// this function reads only the public half.
pub fn own_key_of(view: &orion_engine::ConfigView) -> Option<String> {
    view.selected
        .as_deref()
        .and_then(|name| view.profiles.iter().find(|profile| profile.name == name))
        .and_then(|profile| profile.public_key.as_deref())
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_string)
}

/// An admin read's error, as a [`Reach`]: the same distinctions the rotations
/// screen draws, so the two tabs say the same thing about the same gateway.
pub fn reach_of_admin<T>(result: Result<T, GatewayAdminError>) -> Reach<T> {
    match result {
        Ok(value) => Reach::Ok(value),
        Err(GatewayAdminError::Forbidden) => Reach::NotAdmin,
        Err(GatewayAdminError::Refused { status: 429, .. }) => Reach::Throttled,
        Err(GatewayAdminError::Refused { status: 503, .. }) => Reach::AstraUnavailable,
        Err(GatewayAdminError::Refused { status, .. }) => Reach::Refused(status),
        Err(GatewayAdminError::Unreachable | GatewayAdminError::Invalid(_)) => Reach::Unreachable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::{Fingerprint, WireGuardKey};

    fn key(byte: u8) -> WireGuardKey {
        WireGuardKey::from_bytes([byte; 32])
    }

    fn target(certificate_kind: CertificateKind, byte: u8) -> CampaignTarget {
        CampaignTarget {
            certificate_kind,
            identity_key: key(byte),
            epoch: 1,
            generation: 1,
            active_tls_certificate_fingerprint: Fingerprint::of(b"tls"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"pq"),
        }
    }

    fn pending_op(operation_id: &str, scope: &str) -> PendingOperationRead {
        PendingOperationRead {
            operation_id: operation_id.into(),
            scope: scope.into(),
            reason: "motif".into(),
            requested_by: "admin".into(),
            target_count: 1,
            required_credentials: 2,
            campaign_fingerprint: "ab".repeat(32),
            created_at: 1,
            expires_at: 2,
        }
    }

    fn certificates_read() -> PeerCertificatesRead {
        let peer = |name: &str, byte: u8, revoked: bool| PeerCertificateRead {
            name: name.into(),
            wg_public_key: key(byte).to_base64(),
            not_before: 100,
            not_after: 900,
            revoked,
            renewing: false,
        };
        PeerCertificatesRead {
            now_unix: Some(5_000),
            peers: vec![peer("PC_FIXE", 1, false), peer("PC_BUREAU", 2, true)],
        }
    }

    fn astra_status(revoked_peers: Vec<String>) -> AuthorityStatusRead {
        AuthorityStatusRead {
            ca_epoch: 1,
            ca_fingerprint: "ab".repeat(32),
            next_ca_fingerprint: None,
            ca_tls_epoch: 1,
            ca_tls_fingerprint: None,
            next_ca_tls_fingerprint: None,
            issuer: None,
            vault_copy_fingerprint: None,
            credential_registry_epoch: None,
            revoked_peers,
            served_credentials: None,
        }
    }

    fn admitted(name: &str, byte: u8) -> AdmittedPeer {
        AdmittedPeer {
            name: name.into(),
            wg_public_key: key(byte).to_base64(),
        }
    }

    #[test]
    fn only_the_client_revocation_key_comes_back() {
        let gateway_op = "01".repeat(16);
        let client_op = "02".repeat(16);
        let fleet_op = "03".repeat(16);
        let pending = vec![
            pending_op(&gateway_op, "emergency_revocation"),
            pending_op(&client_op, "emergency_revocation"),
            pending_op(&fleet_op, "fleet_leafs"),
        ];
        let mut asked = Vec::new();
        let reach = pending_revocations(Reach::Ok(pending), |id| {
            asked.push(id.to_hex());
            if id.to_hex() == gateway_op {
                Ok(vec![
                    target(CertificateKind::GatewayTls, 9),
                    target(CertificateKind::GatewayPq, 9),
                ])
            } else {
                Ok(vec![target(CertificateKind::ClientPq, 7)])
            }
        });
        assert_eq!(reach, Reach::Ok(vec![key(7).to_base64()]));
        assert_eq!(
            asked,
            [gateway_op, client_op],
            "a fleet campaign is never fetched"
        );
    }

    #[test]
    fn a_failed_fetch_makes_the_whole_list_unreachable() {
        let pending = vec![
            pending_op(&"04".repeat(16), "emergency_revocation"),
            pending_op(&"05".repeat(16), "emergency_revocation"),
        ];
        let reach = pending_revocations(Reach::Ok(pending), |id| {
            if id.to_hex() == "05".repeat(16) {
                Err("campagne illisible".to_string())
            } else {
                Ok(vec![target(CertificateKind::ClientTls, 3)])
            }
        });
        assert_eq!(
            reach,
            Reach::Unreachable,
            "a partial list would show fewer revocations than are waiting"
        );
    }

    #[test]
    fn a_refused_pending_read_is_carried_as_it_was() {
        assert_eq!(
            pending_revocations(Reach::NotAdmin, |_| Ok(Vec::new())),
            Reach::NotAdmin
        );
    }

    #[test]
    fn peers_overview_merges_the_three_reads() {
        let overview = assemble(
            Reach::Ok(certificates_read()),
            Reach::Ok(vec![admitted("PC_FIXE", 1)]),
            Reach::Ok(astra_status(vec![key(2).to_base64()])),
            Reach::Ok(vec![key(3).to_base64()]),
            Some("OWN=".into()),
            Some(key(2).to_base64()),
        );
        assert_eq!(overview.certificates.ok().map(Vec::len), Some(2));
        assert_eq!(overview.admitted, Reach::Ok(vec![admitted("PC_FIXE", 1)]));
        assert_eq!(overview.astra_revoked, Reach::Ok(vec![key(2).to_base64()]));
        assert_eq!(
            overview.pending_revocations,
            Reach::Ok(vec![key(3).to_base64()])
        );
        assert_eq!(overview.own_key.as_deref(), Some("OWN="));
        assert_eq!(overview.now_unix, Some(5_000), "the gateway's clock");
        assert_eq!(overview.local_pending, Some(key(2).to_base64()));
    }

    #[test]
    fn an_unreachable_astra_leaves_the_gateway_reads() {
        let overview = assemble(
            Reach::Ok(certificates_read()),
            Reach::Ok(vec![admitted("PC_FIXE", 1)]),
            Reach::Unreachable,
            Reach::Unreachable,
            None,
            None,
        );
        assert_eq!(overview.certificates.ok().map(Vec::len), Some(2));
        assert_eq!(overview.admitted, Reach::Ok(vec![admitted("PC_FIXE", 1)]));
        assert_eq!(overview.astra_revoked, Reach::Unreachable);
        assert_eq!(overview.pending_revocations, Reach::Unreachable);
        assert_eq!(overview.now_unix, Some(5_000));
    }

    #[test]
    fn a_gateway_refusal_keeps_its_own_reach() {
        assert_eq!(
            reach_of_admin::<()>(Err(GatewayAdminError::Forbidden)),
            Reach::NotAdmin
        );
        assert_eq!(
            reach_of_admin::<()>(Err(GatewayAdminError::Refused {
                status: 429,
                reason: None
            })),
            Reach::Throttled
        );
        assert_eq!(
            reach_of_admin::<()>(Err(GatewayAdminError::Unreachable)),
            Reach::Unreachable
        );
    }
}
