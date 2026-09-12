//! `astra campaign open`, and the rows a campaign resolves from the registry.
//!
//! The two row builders are shared with the chain of §7.6, which offers the
//! client TLS anchor alone where this command offers it beside `CA-PQ`.

use std::path::Path;

use anyhow::{Context, Result};
use astra::registry::AstraRegistry;

use crate::campaign_deposit::open_campaign;
use crate::{CampaignScopeArg, REGISTRY_FILE};

/// Resolves a campaign over the fleet as it stands, and deposits it (§7.6).
///
/// Every target is pinned to the generation and the **exact** fingerprints the
/// registry holds right now. That is what makes the operator's touch an
/// approval of a specific set rather than of a list evaluated later: a target
/// that moves in between changes the campaign fingerprint, and
/// `assert_unchanged` refuses it instead of quietly recomputing.
///
/// A revoked peer is not a target. `revoked` is terminal — no credential lifts
/// it — so including one would put an object in the campaign that every
/// downstream step must then refuse, and would make the count the operator
/// reads on their screen wrong.
pub(crate) fn campaign_open(
    state_dir: &Path,
    scope: CampaignScopeArg,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
) -> Result<()> {
    use aether::certificates::status::{CampaignScope, CampaignTarget, CertificateKind};

    let registry = AstraRegistry::load(&state_dir.join(REGISTRY_FILE), None)
        .context("loading the Astra registry")?;
    let state = registry.state();
    let scope = match scope {
        CampaignScopeArg::FleetLeafs => CampaignScope::FleetLeafs,
        CampaignScopeArg::TrustAuthorities => CampaignScope::TrustAuthorities,
    };

    let targets: Vec<CampaignTarget> = match scope {
        // One target, and it is the anchor as this registry holds it right
        // now. The companion compares it to the anchor its own vault holds:
        // two authorities that disagree about which `CA-PQ` is current must
        // not be reconciled by a rotation, they must stop.
        CampaignScope::TrustAuthorities => {
            let anchor = state.ca_public_key.authority_fingerprint();
            let mut targets = vec![CampaignTarget {
                certificate_kind: CertificateKind::CaPq,
                identity_key: state.gateway_wg_public_key,
                epoch: state.ca_epoch,
                generation: state.ca_epoch,
                active_tls_certificate_fingerprint: anchor,
                active_pq_certificate_fingerprint: anchor,
            }];
            // The client TLS anchor is a second row, not a second campaign:
            // §7.6 puts both under `trust_authorities`, and the companion
            // signs whichever the ceremony is for. A domain that never pinned
            // that anchor simply offers no row for it — the rotation is then
            // refused where the pin is missing, not here.
            if let Some(row) = client_tls_ca_row(state) {
                targets.push(row);
            }
            targets
        }
        _ => fleet_leaf_rows(state),
    };
    if targets.is_empty() {
        anyhow::bail!(
            "no admitted peer in this registry: there is nothing for an operator to approve"
        );
    }

    let deposited = open_campaign(
        state_dir,
        state,
        scope,
        targets,
        reason,
        requested_by,
        window_secs,
    )?;

    println!("{}", deposited.operation_id.to_hex());
    eprintln!(
        "campagne déposée : {} credential(s), fenêtre de {window_secs} s",
        scope.required_credentials()
    );
    eprintln!("empreinte de campagne : {}", deposited.fingerprint);
    eprintln!(
        "approuver depuis le poste opérateur :\n  astra-signer approve-campaign \\\n    \
         --authority-url {} \\\n    --operation-id {}",
        state.authority_url,
        deposited.operation_id.to_hex()
    );
    Ok(())
}

/// The client `CA-TLS` row, when this domain pins that anchor at all.
///
/// Shared between `campaign open --scope trust-authorities`, which offers it
/// beside `CA-PQ`, and the chain of §7.6, which offers it **alone** — the
/// chain covers «émetteur, CA TLS, gateway et leafs clientes, mais pas
/// `CA-PQ`», and leaving the anchor row out is what carries that exclusion:
/// `covers_authority_object` matches on the certificate kind, so a campaign
/// with no `CA-PQ` row refuses a `CA-PQ` transition by construction rather
/// than by a check somebody has to remember.
pub(super) fn client_tls_ca_row(
    state: &astra::registry::AstraState,
) -> Option<aether::certificates::status::CampaignTarget> {
    use aether::certificates::status::{CampaignTarget, CertificateKind};
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

/// One row per admitted peer, pinned to the generation it is actually at.
///
/// A revoked peer is not a target. `revoked` is terminal — no credential lifts
/// it — so including one would put an object in the campaign that every
/// downstream step must then refuse, and would make the count the operator
/// reads on their screen wrong.
pub(super) fn fleet_leaf_rows(
    state: &astra::registry::AstraState,
) -> Vec<aether::certificates::status::CampaignTarget> {
    use aether::certificates::status::{CampaignTarget, CertificateKind};
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
