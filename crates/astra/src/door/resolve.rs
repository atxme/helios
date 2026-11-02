//! The targets an opening resolves from the registry the service holds.
//!
//! Never from the caller: no request names its targets, and the door reads
//! them here, from the state in memory, under the lock the registry already
//! has. Every target is pinned to the generation and the **exact**
//! fingerprints the registry holds right now. That is what makes the
//! operator's touch an approval of a specific set rather than of a list
//! evaluated later: a target that moves in between changes the campaign
//! fingerprint, and `assert_unchanged` refuses it instead of quietly
//! recomputing.

use aether::certificates::status::{CampaignTarget, CertificateKind};

use aether::certificates::transport::RevocationExpiries;
use astra_channel::GatewayIdentityView;

use super::open::Resolved;
use super::DoorRefusal;
use crate::registry::AstraState;

/// One row per admitted peer, pinned to the generation it is actually at.
///
/// A revoked peer is not a target. `revoked` is terminal — no credential lifts
/// it — so including one would put an object in the campaign that every
/// downstream step must then refuse, and would make the count the operator
/// reads on their screen wrong.
pub(crate) fn fleet_leaf_rows(state: &AstraState) -> Vec<CampaignTarget> {
    state
        .peers
        .values()
        .filter(|peer| !peer.revoked)
        .map(|peer| CampaignTarget {
            certificate_kind: CertificateKind::ClientPq,
            identity_key: peer.client_wg_public_key,
            epoch: state.ca_epoch,
            generation: peer.active.generation,
            active_tls_certificate_fingerprint: peer.active.tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: peer.active.pq_certificate_fingerprint,
        })
        .collect()
}

/// The anchors of the domain, `CA-PQ` first.
///
/// One `CA-PQ` row, and it is the anchor as this registry holds it right now.
/// The companion compares it to the anchor its own vault holds: two
/// authorities that disagree about which `CA-PQ` is current must not be
/// reconciled by a rotation, they must stop.
///
/// The client TLS anchor is a second row, not a second campaign: §7.6 puts
/// both under `trust_authorities`, and the companion signs whichever the
/// ceremony is for. A domain that never pinned that anchor simply offers no
/// row for it — the rotation is then refused where the pin is missing, not
/// here.
pub(crate) fn trust_authority_rows(state: &AstraState) -> Vec<CampaignTarget> {
    let anchor = state.ca_public_key.authority_fingerprint();
    let mut targets = vec![CampaignTarget {
        certificate_kind: CertificateKind::CaPq,
        identity_key: state.gateway_wg_public_key,
        epoch: state.ca_epoch,
        generation: state.ca_epoch,
        active_tls_certificate_fingerprint: anchor,
        active_pq_certificate_fingerprint: anchor,
    }];
    if let Some(row) = client_tls_ca_row(state) {
        targets.push(row);
    }
    targets
}

/// The client `CA-TLS` row, when this domain pins that anchor at all.
///
/// Shared between `trust_authorities`, which offers it beside `CA-PQ`, and
/// the chain of §7.6, which offers it **alone** — the chain covers
/// «émetteur, CA TLS, gateway et leafs clientes, mais pas `CA-PQ`», and
/// leaving the anchor row out is what carries that exclusion:
/// `covers_authority_object` matches on the certificate kind, so a campaign
/// with no `CA-PQ` row refuses a `CA-PQ` transition by construction rather
/// than by a check somebody has to remember.
pub(crate) fn client_tls_ca_row(state: &AstraState) -> Option<CampaignTarget> {
    state
        .ca_tls_fingerprint
        .map(|client_tls_ca| CampaignTarget {
            certificate_kind: CertificateKind::CaTls,
            identity_key: state.gateway_wg_public_key,
            epoch: state.ca_tls_epoch,
            generation: state.ca_tls_epoch,
            active_tls_certificate_fingerprint: client_tls_ca,
            active_pq_certificate_fingerprint: client_tls_ca,
        })
}

/// One admitted client into an emergency revocation.
///
/// The peer must be an admitted, unrevoked identity: `revoked` is terminal, so
/// a second revocation would be a campaign every downstream step refuses. The
/// target is pinned to the generation this registry records as active, and
/// its counter is the peer's own revocation epoch.
///
/// A client's two halves share one generation, hence one signed expiry: it is
/// the value `astra revocation open` has always printed as `--not-after`, and
/// the registry refuses the deposit when it disagrees with the generation.
pub(crate) fn client_revocation(
    state: &AstraState,
    peer: &aether::certificates::encoding::WireGuardKey,
) -> Result<Resolved, DoorRefusal> {
    let record = state
        .peers
        .get(&peer.to_base64())
        .ok_or(DoorRefusal::PeerUnknown)?;
    if record.revoked {
        return Err(DoorRefusal::PeerRevoked);
    }
    let not_after = record.active.not_after;
    Ok(Resolved {
        targets: vec![CampaignTarget {
            certificate_kind: CertificateKind::ClientPq,
            identity_key: record.client_wg_public_key,
            epoch: record.revocation_epoch,
            generation: record.active.generation,
            active_tls_certificate_fingerprint: record.active.tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: record.active.pq_certificate_fingerprint,
        }],
        revocation_expiries: Some(RevocationExpiries {
            tls_not_after: Some(not_after),
            pq_not_after: Some(not_after),
        }),
    })
}

/// The gateway identity in service, as the daemon reports it.
///
/// # Why the gateway is read, not the registry
///
/// The gateway's own leaves were never recorded here: Astra transcribes
/// admissions, it does not hold the identity every client pins. Their
/// fingerprints and, above all, their **signed expiries** come from the
/// daemon that serves them. §10.1 makes each expiry exact: a value retyped or
/// inferred produces an object every recipient refuses, during the incident
/// that motivated it. A campaign built from anything but the leaf the daemon
/// presents would freeze a state no client has ever pinned.
///
/// The counter is the gateway's own axis (§4.2): the decision epoch the
/// daemon reports, which a revocation or a rotation then advances by one.
pub(crate) fn gateway_row(state: &AstraState, identity: &GatewayIdentityView) -> CampaignTarget {
    CampaignTarget {
        certificate_kind: CertificateKind::GatewayPq,
        identity_key: state.gateway_wg_public_key,
        epoch: identity.gateway_decision_epoch,
        generation: identity.active_gateway_identity_epoch,
        active_tls_certificate_fingerprint: identity.tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: identity.pq_certificate_fingerprint,
    }
}

/// The gateway revocation: the row, and the two leaves' own expiries.
pub(crate) fn gateway_revocation(state: &AstraState, identity: &GatewayIdentityView) -> Resolved {
    Resolved {
        targets: vec![gateway_row(state, identity)],
        revocation_expiries: Some(RevocationExpiries {
            tls_not_after: Some(identity.tls_certificate_not_after),
            pq_not_after: Some(identity.pq_certificate.not_after_unix),
        }),
    }
}
