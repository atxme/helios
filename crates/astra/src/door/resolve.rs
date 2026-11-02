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
