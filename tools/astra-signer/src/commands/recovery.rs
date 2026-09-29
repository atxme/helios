//! Recovering an expired client identity.

use super::*;

/// Rotates `CA-PQ`, alone or as the execution of an authority campaign.
///
/// # Why the deposit happens before the vault moves
///
/// Astra learns of the successor first, and the local vault adopts it second.
/// The other order has a failed deposit leave an operator whose vault holds an
/// anchor the authority has never heard of: the next campaign would resolve
/// its target from the registry's old anchor, the companion would refuse the
/// mismatch, and there would be no gesture left that reconciles the two. A
/// deposit that fails before anything moves is simply a ceremony to redo.
///
/// The local half is still crash-safe on its own: the journal is written after
/// the deposit and replayed until every file has landed, so a resume needs no
/// network and no second touch.
#[allow(clippy::too_many_arguments)]
/// Recovers an identity whose leaf has expired (spec §7.5).
///
/// # Why one command and one connection
///
/// A recovery needs `CA-PQ` twice: once to authorize the staging, and once
/// again to sign the grant — which cannot exist until the gateway has
/// persisted the candidate and signed a receipt. Splitting that into two
/// commands would mean two ceremonies for one decision, and a second
/// ceremony's operator has no way to tell it is finishing the first. So the
/// key stays plugged and the vault stays open across one round trip through
/// the authority, which is what «the length of one operation» means here.
///
/// If anything fails before the grant is deposited, nothing has been installed
/// anywhere: the gateway holds a candidate under a lease it will purge, and the
/// operator reruns the command against a fresh request.
/// §7.5, driven through the one implementation the helper also drives.
///
/// The prompts are here and the ceremony is not: `astra-operator` verifies,
/// describes and signs, and this prints what it described. Two copies of a
/// ceremony are two places for a window rule to be got wrong, and this one was
/// got wrong twice.
pub(crate) fn recover(
    path: &Path,
    authority_url: &str,
    operation_id: &str,
    origin: Option<&str>,
    transport: Transport,
) -> Result<()> {
    let operation = Id16::parse_hex(operation_id)
        .map_err(|error| anyhow::anyhow!("--operation-id : {error}"))?;
    let verified = astra_operator::operations::recovery::begin(
        path,
        operation,
        Some(authority_url),
        origin,
        now_unix(),
    )?;

    // Everything the operator has to weigh, before a key is asked for
    // anything. A recovery reaches past a validity period: the one fact that
    // must not be buried is *which* identity, and how long it has been dead.
    let manifest = verified.manifest();
    println!("récupération     : {}", verified.operation().to_hex());
    println!("pair             : {}", manifest.client_wg_public_key);
    println!("nom              : {}", manifest.peer_name);
    println!(
        "génération       : {} → {}",
        manifest.expired_generation, manifest.next_generation
    );
    println!("expirée depuis   : {} s", manifest.expired_since_secs);
    println!("activation       : {}", manifest.activation_at);
    println!("empreinte        : {}", manifest.request_fingerprint);

    eprintln!("Brancher la clé autorisée, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;

    verified.approve(key.as_ref(), &pin, &mut |state| {
        println!("stade            : {state:?}");
    })?;
    println!(
        "le client peut installer sa nouvelle génération et committer ; la gateway relaiera son \
         commit par le canal privé"
    );
    Ok(())
}
