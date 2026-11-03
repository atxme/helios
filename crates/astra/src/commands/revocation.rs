//! `astra revocation open`, for a client identity or for the gateway's own.
//!
//! One command and two scopes, because the two resolve from different places:
//! a client revocation reads the generation the registry records, and the
//! gateway's reads the leaves — and above all the signed expiries — from the
//! daemon that serves them, over the running service's own channel. Both are
//! resolved by the door; this command sends the request and prints the
//! `astra-signer revoke` line the answer names.

use std::path::Path;

use aether::certificates::encoding::WireGuardKey;
use anyhow::{Context, Result};
use astra::door::{DoorOutcome, DoorRequest, OpenedSubject, OpeningText};

use crate::{console, RevocationScopeArg};

/// Opens an emergency revocation of one identity (§10.1).
pub(crate) fn revocation_open(
    state_dir: &Path,
    scope: RevocationScopeArg,
    peer: Option<&str>,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
) -> Result<()> {
    let text = console::opening_text(reason, requested_by, window_secs);
    if scope == RevocationScopeArg::Gateway {
        anyhow::ensure!(peer.is_none(), "--peer is refused for --scope gateway");
        return gateway_revocation_open(state_dir, text);
    }
    let peer = peer.context("--peer is required for --scope client")?;
    let peer = WireGuardKey::parse(peer).context("reading the client's WireGuard public key")?;

    let opening = console::opened(console::open(
        state_dir,
        DoorRequest::ClientRevocation { peer, text },
    )?)?;
    let OpenedSubject::Client {
        name,
        generation,
        revocation_epoch,
    } = &opening.subject
    else {
        return Err(console::unexpected(&DoorOutcome::Opened(opening)));
    };
    // One expiry for both halves: a client generation retires its two leaves
    // together, and `--not-after` is that generation's.
    let not_after = opening
        .opened
        .revocation_expiries
        .and_then(|expiries| expiries.pq_not_after)
        .context("la porte a répondu à la révocation d'un client sans son échéance signée")?;
    let next_epoch = revocation_epoch
        .checked_add(1)
        .context("revocation counter overflow")?;
    let operation_id = opening.opened.operation_id;
    println!("{}", operation_id.to_hex());
    eprintln!(
        "révocation déposée : {name}, génération {generation}, compteur {next_epoch}, fenêtre de {window_secs} s"
    );
    eprintln!(
        "empreinte de campagne : {}",
        opening.opened.campaign_fingerprint
    );
    eprintln!(
        "signer depuis le poste opérateur :\n  astra-signer revoke --authority-url {} \
         --operation-id {} --not-after {not_after}",
        opening.authority_url,
        operation_id.to_hex()
    );
    Ok(())
}

/// Freezes the gateway identity in service into a revocation campaign.
fn gateway_revocation_open(state_dir: &Path, text: OpeningText) -> Result<()> {
    let window_secs = text.window_secs;
    let opening = console::opened(console::open(
        state_dir,
        DoorRequest::GatewayRevocation { text },
    )?)?;
    let OpenedSubject::Gateway {
        decision_epoch,
        tls_certificate_fingerprint,
        pq_certificate_fingerprint,
    } = &opening.subject
    else {
        return Err(console::unexpected(&DoorOutcome::Opened(opening)));
    };
    let expiries = opening
        .opened
        .revocation_expiries
        .context("la porte a répondu à la révocation de la gateway sans ses échéances signées")?;
    let pq_not_after = expiries.pq_not_after.context(
        "la porte a répondu à la révocation de la gateway sans l'échéance de la feuille PQ",
    )?;
    let tls_not_after = expiries.tls_not_after.context(
        "la porte a répondu à la révocation de la gateway sans l'échéance de la feuille TLS",
    )?;
    // The counter is the gateway's own axis (§4.2): the decision epoch the
    // daemon reports, advanced by one.
    let next_epoch = decision_epoch
        .checked_add(1)
        .context("gateway revocation counter overflow")?;
    let operation_id = opening.opened.operation_id;
    println!("{}", operation_id.to_hex());
    eprintln!("révocation gateway déposée : compteur {next_epoch}, fenêtre de {window_secs} s");
    eprintln!("feuille PQ  : {pq_certificate_fingerprint} · expire {pq_not_after}");
    eprintln!("feuille TLS : {tls_certificate_fingerprint} · expire {tls_not_after}");
    eprintln!(
        "empreinte de campagne : {}",
        opening.opened.campaign_fingerprint
    );
    eprintln!(
        "terminal : la gateway ne négociera plus. Signer depuis le poste opérateur :\n  \
         astra-signer revoke --scope gateway --authority-url {} --operation-id {} \
         --pq-not-after {pq_not_after} --tls-not-after {tls_not_after}",
        opening.authority_url,
        operation_id.to_hex()
    );
    Ok(())
}
