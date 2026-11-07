//! `astra-signer` — the operator companion of ADR-008 §4.
//!
//! It runs on the machine where the security key is plugged in, and it is the
//! only program in this repository that ever holds `CA-PQ` in the clear. Astra
//! stores the encrypted vault; the gateway never sees it; no browser touches
//! CTAP. The anchors exist in memory here, for the length of one operation,
//! and are zeroized after.
//!
//! # The gestures
//!
//! - `init` creates the vault around fresh anchors and registers the first
//!   key. It prints the **public** `CA-PQ` key — what `astra bootstrap` needs
//!   and the only half of the anchor that ever leaves this program.
//! - `enrol` registers another key. Two devices, plugged one at a time: the
//!   one already authorized opens the vault, the new one receives a slot.
//!   This is how a second key is added, and how a third or a fourth is,
//!   later, with no difference at all.
//! - `verify` proves a key opens the anchors. ADR-008 §4 finalises the
//!   bootstrap only «après enregistrement et essai des deux clés», and this is
//!   that trial.
//! - `list` prints the slot table, the vault fingerprint, and whether the
//!   authority is bootstrapped.
//! - `remove` withdraws a key, never the last recovery.
//! - `rename` changes a label, and needs no key: the label is deliberately
//!   outside everything cryptographic.
//! - `domain` records — and prints — the public values every signing command
//!   below reads: the gateway, the server name and the Astra service key this
//!   companion pins. Needs no key.
//! - `issue-ca-tls` self-signs the client TLS CA around the key the vault has
//!   held since the domain was created.
//! - `authorize-issuer` signs one `AstraIssuerAuthorization`: Astra's
//!   delegated issuer, bounded in time and in what it may ever emit.
//! - `bindings` re-emits the credential document from the key-slot table. Run
//!   automatically by every gesture that moves that table.
//! - `approve` approves one exact client renewal, from files or straight
//!   through the client's tunnel. **It does not open the vault**, and cannot:
//!   see [`aether_fido::approve_renewal`].
//! - `approve-campaign` approves a manual rotation campaign, at as many
//!   distinct keys as its scope demands.
//! - `issue-gateway-bootstrap` verifies the public request of a new gateway
//!   and issues its epoch-1 leaf under `CA-PQ`, after two distinct keys.
//! - `rotate-ca-pq` moves the anchor, under two distinct keys.
//! - `enroll` runs the operator half of a client enrollment (§15.2):
//!   `invite`, `accept`, `sign-document`, `list`, `revoke`. No client private
//!   key ever reaches this program.
//!
//! This file is the prompts and the printing. The sequences themselves are in
//! [`astra_operator::gestures`], where they are exercised.
//!
//! # Transport : le tunnel pour le renouvellement, des fichiers pour le reste
//!
//! `approve` sait désormais travailler **dans le tunnel** du client :
//! `--heliosd-url` et `--operation-id` remplacent `--request` et `--out`, et le
//! compagnon récupère la demande puis dépose son assertion par les routes
//! typées de `helios-api` (§8.1.2). C'est le chemin que l'IHM Orion lance, et
//! il tient debout parce que le compagnon tourne sur la machine du client : ces
//! routes authentifient le pair par sa VIP source, pas par un jeton porteur.
//!
//! Le transport ne décide de rien. La demande récupérée est signée par la clé
//! de service d'Astra et vérifiée contre le relais de domaine que ce compagnon
//! détient déjà — exactement comme une demande lue dans un fichier, puisque
//! c'est l'objet qui porte la signature et non le fil par lequel il arrive.
//!
//! `approve-campaign` a maintenant les **deux** transports : hors ligne par
//! `--campaign` et `--out`, ou par l'origine publique du §8.2 avec
//! `--authority-url` et `--operation-id`. C'est le canal que le relais
//! in-tunnel ne couvre pas — un opérateur sur son propre poste n'a aucune VIP
//! que la gateway résoudrait. L'origine ne décide de rien : la demande reste
//! vérifiée sous la clé de service que ce compagnon épingle, et le RP ID
//! annoncé est **comparé** à celui du coffre, jamais adopté.
//!
//! # Gestes qui voyagent par fichiers
//!
//! `issue-gateway-bootstrap` voyage nécessairement par fichiers : le domaine
//! neuf ne possède encore ni registre, ni clé de service, ni veth.
//! `authorize-issuer` et la forme hors ligne de `rotate-ca-pq` lisent aussi une
//! demande sur disque et écrivent leur résultat à côté. Elles ne portent pas
//! de campagne, donc rien ne les rattache à une opération : les routes du §8.2
//! sont liées à un `operation_id` et à un manifeste, et il n'existe pas encore
//! d'opération qui les décrive.
//!
//! # Limite connue : le matériel ne s'exerce pas en WSL2
//!
//! Voir [`astra_operator::authenticator`]. CTAP n'est pas une feature de
//! compilation : tout binaire porte la pile, et il n'existe aucun chemin qui
//! ouvre le coffre sans clé.

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use aether::certificates::approval::CredentialState;
use aether::certificates::encoding::{
    validate_server_name, DerCertificate, Id16, MlDsa87PublicKey, TrustDomainId, WireGuardKey,
};
use aether::certificates::transport::ClientRenewalOperationState;
use aether::certificates::window::TransitionWindow;
use anyhow::{bail, Context, Result};
use astra_operator::authenticator::{Opened, Transport};
use astra_operator::credentials;
use astra_operator::gestures::{self, NewAuthority, NewKey};
use astra_operator::signing::{self, DelegationBounds, IssuerDelegationRequest};
use astra_operator::vault::{AuthorityVault, KeySlot, SlotRole, MAX_SLOTS, REQUIRED_SLOTS};
use astra_operator::{authenticator, documents, handoff, prepared, store, tunnel};
use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

mod cli;
mod commands;

use cli::*;
use commands::*;

fn main() -> Result<()> {
    std::thread::Builder::new()
        .name("astra-signer".into())
        .stack_size(astra_operator::WORK_STACK_BYTES)
        .spawn(run)
        .context("démarrage du fil de travail")?
        .join()
        .map_err(|_| anyhow::anyhow!("le fil de travail s'est interrompu"))?
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let path = match cli.vault {
        Some(path) => path,
        None => store::default_path()?,
    };

    let transport = cli.transport.into();
    match cli.command {
        Command::Init {
            rp_id,
            trust_domain_id,
            label,
            role,
        } => init(
            &path,
            &rp_id,
            trust_domain_id.as_deref(),
            &label,
            role.into(),
            transport,
        ),
        Command::Enrol { label, role } => enrol(&path, &label, role.into(), transport),
        Command::Verify => verify(&path, transport),
        Command::List => list(&path),
        Command::Devices => devices(),
        Command::Domain {
            gateway_wg_public_key,
            server_name,
            astra_service_public_key,
            astra_service_key_epoch,
            astra_authority_url,
        } => domain(
            &path,
            gateway_wg_public_key.as_deref(),
            server_name.as_deref(),
            astra_service_public_key.as_deref(),
            astra_service_key_epoch,
            astra_authority_url.as_deref(),
        ),
        Command::Remove { slot } => remove(&path, &slot, transport),
        Command::Rename { slot, label } => rename(&path, &slot, &label),
        Command::IssueCaTls { days, out } => issue_ca_tls(&path, days, out.as_deref(), transport),
        Command::AuthorizeIssuer {
            request,
            out,
            authority_url,
            operation_id,
            origin,
            days,
            leaf_days,
        } => authorize_issuer(
            &path,
            &request,
            out.as_deref(),
            authority_url.as_deref().zip(operation_id.as_deref()),
            days,
            leaf_days,
            origin.as_deref(),
            transport,
        ),
        Command::Bindings { lost, active } => bindings(&path, &lost, &active, transport),
        Command::Approve {
            request,
            out,
            heliosd_url,
            operation_id,
            active_generation,
        } => approve(
            &path,
            request.as_deref(),
            out.as_deref(),
            heliosd_url.as_deref(),
            operation_id.as_deref(),
            active_generation,
            transport,
        ),
        Command::ApproveCampaign {
            campaign,
            out,
            authority_url,
            operation_id,
            origin,
        } => approve_campaign(
            &path,
            campaign.as_deref(),
            out.as_deref(),
            authority_url.as_deref(),
            operation_id.as_deref(),
            origin.as_deref(),
            transport,
        ),
        Command::Recover {
            authority_url,
            operation_id,
            origin,
        } => recover(
            &path,
            &authority_url,
            &operation_id,
            origin.as_deref(),
            transport,
        ),
        Command::RotateCaPq {
            out,
            prepare_days,
            overlap_days,
            authority_url,
            operation_id,
            origin,
        } => rotate_ca_pq(
            &path,
            &out,
            prepare_days,
            overlap_days,
            authority_url.as_deref(),
            operation_id.as_deref(),
            origin.as_deref(),
            transport,
        ),
        Command::Revoke {
            authority_url,
            operation_id,
            origin,
            scope,
            halves,
            not_after,
            tls_not_after,
            pq_not_after,
            reason,
            replacement_transition,
        } => revoke(
            &path,
            &authority_url,
            &operation_id,
            origin.as_deref(),
            RevocationInputs {
                scope: scope.into(),
                halves,
                tls_not_after: tls_not_after.or(not_after),
                pq_not_after: pq_not_after.or(not_after),
                reason: reason.into(),
                replacement: replacement_transition,
            },
            transport,
        ),
        Command::IssueGatewayBootstrap {
            request,
            out,
            validity_days,
        } => issue_gateway_bootstrap(&path, &request, &out, validity_days, transport),
        Command::SignGatewayTransition {
            authority_url,
            heliosd_url,
            operation_id,
            origin,
            request,
            active_certificate,
            tls_certificate,
            out,
            validity_days,
            prepare_days,
            overlap_days,
            key_recovery,
            emergency_replacement,
        } => sign_gateway_transition(
            &path,
            astra_operator::campaign::Campaign::select(
                authority_url.as_deref(),
                heliosd_url.as_deref(),
            )?,
            &operation_id,
            origin.as_deref(),
            GatewayTransitionInputs {
                request: &request,
                active_certificate: active_certificate.as_deref(),
                tls_certificate: tls_certificate.as_deref(),
                out: &out,
                validity_days,
                prepare_days,
                overlap_days,
                key_recovery,
                emergency_replacement,
            },
            transport,
        ),
        Command::RotateCaTls {
            authority_url,
            heliosd_url,
            operation_id,
            origin,
            out,
            prepare_days,
            overlap_days,
            validity_days,
        } => rotate_ca_tls(
            &path,
            astra_operator::campaign::Campaign::select(
                authority_url.as_deref(),
                heliosd_url.as_deref(),
            )?,
            &operation_id,
            origin.as_deref(),
            &out,
            (prepare_days, overlap_days, validity_days),
            transport,
        ),
        Command::ResumeRotation {
            authority_url,
            heliosd_url,
        } => resume_rotation(
            &path,
            astra_operator::campaign::Campaign::select(
                authority_url.as_deref(),
                heliosd_url.as_deref(),
            )?,
        ),
        Command::SignGatewayRollback {
            transition,
            out,
            hours,
            reason,
            requested_by,
            origin,
        } => sign_gateway_rollback(
            &path,
            &transition,
            &out,
            hours,
            &reason,
            &requested_by,
            origin.as_deref(),
            transport,
        ),
        Command::PromoteCaTls => promote_ca_tls(&path, transport),
        Command::Enroll { command } => enroll(&path, command, transport),
        Command::AbortGatewayTransition {
            authority_url,
            heliosd_url,
            operation_id,
            origin,
            transition,
            out,
            reason,
        } => abort_gateway_transition(
            &path,
            astra_operator::campaign::Campaign::select(
                authority_url.as_deref(),
                heliosd_url.as_deref(),
            )?,
            &operation_id,
            origin.as_deref(),
            &transition,
            &out,
            reason.into(),
            transport,
        ),
    }
}

#[cfg(test)]
mod tests;
