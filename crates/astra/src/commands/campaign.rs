//! `astra campaign open`, through the door.
//!
//! The door resolves the targets from the registry the running service holds
//! (`astra::door`); this command only sends the request and prints the
//! answer.

use std::path::Path;

use anyhow::Result;
use astra::door::{DoorRequest, Opening};

use crate::console;
use crate::CampaignScopeArg;

/// Opens a campaign over the fleet as it stands (§7.6).
pub(crate) fn campaign_open(
    state_dir: &Path,
    scope: CampaignScopeArg,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
) -> Result<()> {
    let text = console::opening_text(reason, requested_by, window_secs);
    let request = match scope {
        CampaignScopeArg::FleetLeafs => DoorRequest::FleetLeafs { text },
        CampaignScopeArg::TrustAuthorities => DoorRequest::TrustAuthorities { text },
    };
    let opening = console::opened(console::open(state_dir, request)?)?;

    println!("{}", opening.opened.operation_id.to_hex());
    eprintln!(
        "campagne déposée : {} credential(s), fenêtre de {window_secs} s",
        opening.opened.required_credentials
    );
    print_approval(&opening);
    Ok(())
}

/// The campaign's fingerprint, and the companion command that approves it.
///
/// Shared with the chain, whose two registry steps print exactly this.
pub(super) fn print_approval(opening: &Opening) {
    eprintln!(
        "empreinte de campagne : {}",
        opening.opened.campaign_fingerprint
    );
    eprintln!(
        "approuver depuis le poste opérateur :\n  astra-signer approve-campaign \\\n    \
         --authority-url {} \\\n    --operation-id {}",
        opening.authority_url,
        opening.opened.operation_id.to_hex()
    );
}
