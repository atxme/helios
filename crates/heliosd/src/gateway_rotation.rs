//! Renewal of the gateway's own identity — the request half (spec §5, §6).
//!
//! # What this module does, and what no code can do for it
//!
//! §11.1 orders nine steps. The first two happen here: the gateway generates
//! and seals its next private material, then exports a
//! [`GatewayCertificateRequest`] carrying only public halves and two proofs.
//! Step 4 — turning that request into a leaf and into a signed
//! `GatewayIdentityTransition` — is an operator ceremony against `CA-PQ`,
//! which lives in a vault this machine must never hold. So the request leaves,
//! and something signed comes back.
//!
//! That asymmetry is the point of §5. The gateway proves possession of the key
//! it wants certified and, on an ordinary renewal, continuity from the leaf it
//! already serves. It proves nothing about *authorisation*: only `CA-PQ`
//! issues, and a gateway that could authorise its own renewal would be an
//! authority.
//!
//! # Why the candidate outlives the process
//!
//! `orion_core::certificate_renewal` deliberately loses its candidate keys on
//! an interruption: the operation is cheap to reopen and the active identity
//! is untouched. The gateway cannot copy that. Its ceremony happens on another
//! machine, in front of a person, and may take days — a candidate that did not
//! survive a restart would make every reboot a restart of the ceremony too.
//! The candidate is therefore sealed durably beside the active identity, bound
//! to the epoch that created it, and removed only by an abort or an explicit
//! replacement.
//!
//! # Known limitation: a request lives 24 hours, a ceremony may not
//!
//! §5 caps `expires_at - created_at` at 24 hours and
//! [`GatewayCertificateRequest::verify`] enforces it. A ceremony that takes
//! longer does not lose the candidate key: re-running the preparation re-signs
//! a fresh request over the **same** sealed material, and only `--new-key`
//! replaces it. Shortening the ceremony is an operational matter; extending
//! the request would be a specification change, and one that would let a
//! request stolen from an operator's desk stay usable for a week.

use anyhow::{Context, Result};

use aether::certificates::encoding::{DerCertificate, Fingerprint, Id16, MlDsa87PublicKey};
use aether::certificates::gateway::{
    GatewayCertificateRequest, GatewayIdentityTransition, GatewayTransitionAbort,
};
use aether::certificates::state::InstallOutcome;
use aether::certificates::status::CertificateServiceRollbackAuthorization;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use helios_provisioning::certificates::CertificateRegistry;

use crate::key_negotiation::RequestContinuity;

/// Where the exported request waits for its ceremony.
///
/// Public by construction — it carries two public keys and two signatures —
/// and it is also the local record of which candidate is sealed: the request
/// names the PQ public key whose private half is in the vault. One file, so
/// the two cannot describe different candidates.
const PENDING_REQUEST_PATH: &str = "/var/lib/helios/gateway-certificate-request.json";

fn pending_request_path() -> std::path::PathBuf {
    std::env::var_os("HELIOS_GATEWAY_REQUEST")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(PENDING_REQUEST_PATH))
}

/// What the preparation produced, for the operator reading the terminal.
pub(crate) struct PreparedRequest {
    pub(crate) request: GatewayCertificateRequest,
    pub(crate) path: std::path::PathBuf,
    /// Candidate TLS leaf, when this renewal replaces the TLS half too.
    pub(crate) tls_certificate: Option<DerCertificate>,
    /// True when this call reused a request that was already valid.
    pub(crate) reused: bool,
}

/// What the preparation decided before opening anything sealed.
///
/// Split out because the decision is the part that can be wrong in a way no
/// error message would reveal: which epoch, whether a key already exists, and
/// whether this call is a resumption. Deciding it against values in memory
/// keeps it verifiable on a machine with no TPM, which is every machine this
/// repository is developed on.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// A request for this epoch is already signed and still valid.
    Reuse(Box<GatewayCertificateRequest>),
    /// The ceremony outlived the 24 hours of §5, not the sealed key.
    Resign {
        epoch: u64,
        pq_public_key: aether::certificates::encoding::MlDsa87PublicKey,
    },
    /// No usable candidate: generate and seal one.
    Seal { epoch: u64 },
}

/// Decides what a preparation call must do (spec §5, §6.3).
fn plan(
    gateway: &aether::certificates::state::GatewayCertificateState,
    pending: Option<GatewayCertificateRequest>,
    new_key: bool,
    key_recovery: bool,
    now_unix: u64,
) -> Result<Plan> {
    // A revoked identity may not vouch for its successor. §5's continuity
    // signature is the revoked key signing for the next one, which is exactly
    // what a withdrawal removes the right to do — so the only request this
    // state produces is a `key_recovery` one, and the authority then has
    // nothing but its own out-of-band judgement to go on.
    //
    // Refusing outright would be simpler and was what this did, but §10.1 has
    // a revocation name the transition that replaces the identity it
    // withdraws: a gateway that could not prepare the key for it would make
    // that field unusable, and every withdrawal terminal in practice.
    anyhow::ensure!(
        !gateway.revoked || key_recovery,
        "this gateway identity is revoked at epoch {}; a revoked identity may not sign for its \
         successor, so the replacement of §10.1 is prepared with --key-recovery or not at all",
        gateway.revocation_epoch
    );
    // One candidate at a time (§6.3). Past `staged` the next epoch belongs to
    // a transition already persisted; preparing a second request would seal a
    // key for a decision number the first one already holds.
    if let Some(staged) = gateway.next_gateway_identity_epoch {
        anyhow::bail!(
            "a transition to epoch {staged} is already staged; promote it, or abort it with a \
             signed GatewayTransitionAbort, before preparing another request"
        );
    }
    let epoch = gateway
        .gateway_decision_epoch
        .checked_add(1)
        .context("gateway decision epoch is at its maximum")?;

    // A request left from an earlier epoch describes a candidate this decision
    // has moved past. It is not a resumption of anything.
    let pending = pending.filter(|held| held.gateway_identity_epoch == epoch);
    if new_key {
        return Ok(Plan::Seal { epoch });
    }
    match pending {
        // An unexpired request for this epoch is *the* request. Re-signing it
        // would change its identifier while the operator holds the fingerprint
        // of the first, and someone comparing two identifiers has no way to
        // tell a resumption from a substitution.
        Some(held) if now_unix < held.expires_at => Ok(Plan::Reuse(Box::new(held))),
        Some(held) => Ok(Plan::Resign {
            epoch,
            pq_public_key: held.new_ml_dsa_87_public_key,
        }),
        None => Ok(Plan::Seal { epoch }),
    }
}

/// Prepares the next gateway identity and exports its request (§11.1 1-2).
pub(crate) fn prepare_request(
    registry: &CertificateRegistry,
    secret: Option<&helios_tpm::SecretKey>,
    dry_run: bool,
    rotate_tls: bool,
    new_key: bool,
    key_recovery: bool,
    now_unix: u64,
) -> Result<PreparedRequest> {
    let gateway = &registry.state().gateway;
    let path = pending_request_path();

    // The epoch comes back from the plan and is not recomputed here: the
    // sealing context binds it, and a second derivation is a second value that
    // can disagree with the one the candidate was sealed under.
    let (epoch, candidate) = match plan(
        gateway,
        read_pending(&path)?,
        new_key,
        key_recovery,
        now_unix,
    )? {
        Plan::Reuse(held) => {
            return Ok(PreparedRequest {
                request: *held,
                path,
                tls_certificate: crate::key_negotiation::candidate_tls_certificate()?,
                reused: true,
            })
        }
        Plan::Resign {
            epoch,
            pq_public_key,
        } => (
            epoch,
            crate::key_negotiation::SealedCandidate {
                pq_public_key,
                tls_certificate: crate::key_negotiation::candidate_tls_certificate()?,
            },
        ),
        Plan::Seal { epoch } => (
            epoch,
            crate::key_negotiation::seal_candidate_identity(
                secret.context(
                    "TPM secret unavailable: cannot seal the candidate gateway identity",
                )?,
                &gateway.gateway_wg_public_key.to_base64(),
                &gateway.server_name,
                epoch,
                rotate_tls,
            )
            .context("sealing the candidate gateway identity")?,
        ),
    };

    let request = GatewayCertificateRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: gateway.trust_domain_id,
        gateway_identity_epoch: epoch,
        gateway_wg_public_key: gateway.gateway_wg_public_key,
        server_name: gateway.server_name.clone(),
        new_ml_dsa_87_public_key: candidate.pq_public_key,
        request_id: Id16::new(
            aether::random::public_bytes::<16>()
                .map_err(|error| anyhow::anyhow!("the approved DRBG refused: {error}"))?,
        )
        .context("drawing the request identifier")?,
        created_at: now_unix,
        expires_at: now_unix + aether::certificates::window::MAX_REQUEST_LIFETIME_SECS,
        new_key_proof: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        current_key_authorization: None,
    };
    let request = crate::key_negotiation::sign_certificate_request(
        request,
        secret,
        dry_run,
        &gateway.gateway_wg_public_key.to_base64(),
        epoch,
        if key_recovery {
            RequestContinuity::KeyRecovery
        } else {
            RequestContinuity::FromActiveLeaf
        },
    )?;

    // Verified before it is written, against the same registry it was built
    // from. A request that cannot pass the companion's check is one an
    // operator would carry to a ceremony and be refused at, having already
    // consumed the trip.
    let active_pq_public_key = aether::certificates::encoding::MlDsa87PublicKey::parse(
        &gateway.active_gateway_certificate.ml_dsa_87_public_key,
    )
    .context("reading the public key of the leaf in service")?;
    request
        .verify(
            if key_recovery {
                aether::certificates::gateway::Continuity::WaivedForKeyRecovery
            } else {
                aether::certificates::gateway::Continuity::Required(&active_pq_public_key)
            },
            &gateway.trust_domain_id,
            gateway.gateway_decision_epoch,
            &gateway.gateway_wg_public_key,
            &gateway.server_name,
            now_unix,
        )
        .context("verifying the gateway certificate request just built")?;

    write_pending(&path, &request)?;
    Ok(PreparedRequest {
        request,
        path,
        tls_certificate: candidate.tls_certificate,
        reused: false,
    })
}

fn read_pending(path: &std::path::Path) -> Result<Option<GatewayCertificateRequest>> {
    match std::fs::read(path) {
        Ok(raw) => Ok(Some(serde_json::from_slice(&raw).with_context(|| {
            format!("decoding the pending request {}", path.display())
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_pending(path: &std::path::Path, request: &GatewayCertificateRequest) -> Result<()> {
    write_document(path, request, "gateway certificate request")
}

/// Where the staged transition document is kept, once installed.
///
/// The registry persists the *decision* — the epoch, the window, the leaves —
/// but not the signed bytes that carried it. §6.3 needs those bytes again: an
/// abort names the exact document it cancels and is verified against it, and a
/// gateway that had thrown the document away could no longer apply an abort it
/// is otherwise entitled to.
const STAGED_TRANSITION_PATH: &str = "/var/lib/helios/gateway-identity-transition.json";
const PROMOTION_MARKER_PATH: &str = "/var/lib/helios/gateway-identity-promotion.json";

fn staged_transition_path() -> std::path::PathBuf {
    std::env::var_os("HELIOS_GATEWAY_TRANSITION")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(STAGED_TRANSITION_PATH))
}

fn promotion_marker_path() -> std::path::PathBuf {
    std::env::var_os("HELIOS_GATEWAY_PROMOTION")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(PROMOTION_MARKER_PATH))
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotionMarker {
    gateway_identity_epoch: u64,
    transition_fingerprint: Fingerprint,
}

/// What an installation moved, for the operator reading the terminal.
pub(crate) struct StagedTransition {
    pub(crate) transition: GatewayIdentityTransition,
    pub(crate) path: std::path::PathBuf,
    /// True when this exact signed document was already staged.
    pub(crate) already_present: bool,
}

/// What an abort cancelled.
pub(crate) struct AbortedTransition {
    pub(crate) abort: GatewayTransitionAbort,
    /// True when this exact abort had already been applied.
    pub(crate) already_present: bool,
}

/// Refuses a transition installing a leaf whose private half is not here.
///
/// This is the check no signature can make. `CA-PQ` certifies that the leaf is
/// authentic; it says nothing about which machine holds the matching private
/// key. Staging a leaf this gateway cannot sign with would look correct all
/// the way to `activation_at`, and then take every tunnel down at once — with
/// the old identity already retired and the ceremony days behind.
fn candidate_is_held(
    transition: &GatewayIdentityTransition,
    request: Option<&GatewayCertificateRequest>,
    candidate_tls: Option<&DerCertificate>,
) -> Result<()> {
    if let Some(certificate) = &transition.next_gateway_certificate {
        let named = MlDsa87PublicKey::parse(&certificate.ml_dsa_87_public_key)
            .context("reading the public key of the PQ leaf this transition installs")?;
        let request = request.context(
            "this transition installs a PQ leaf, but no certificate request is pending here:              the sealed candidate it answers is not on this gateway",
        )?;
        anyhow::ensure!(
            request.gateway_identity_epoch == transition.gateway_identity_epoch,
            "the pending request is for epoch {}, this transition for epoch {}",
            request.gateway_identity_epoch,
            transition.gateway_identity_epoch
        );
        anyhow::ensure!(
            named.as_bytes() == request.new_ml_dsa_87_public_key.as_bytes(),
            "this transition installs a PQ leaf for a key this gateway did not seal: its private              half is elsewhere, and the identity would stop signing at activation_at"
        );
    }
    if let Some(certificate) = &transition.next_gateway_tls_certificate {
        let held = candidate_tls.context(
            "this transition installs a TLS leaf, but no candidate TLS leaf was sealed here:              prepare the request with --rotate-tls, or have the ceremony leave TLS unchanged",
        )?;
        anyhow::ensure!(
            certificate.fingerprint().matches(&held.fingerprint()),
            "this transition installs a TLS leaf that is not the candidate sealed here"
        );
    }
    Ok(())
}

/// Installs a signed transition without changing the identity served (§11.1 5).
///
/// The gateway keeps serving the active leaf: staging is a persisted decision
/// about the future, and §6.3 has the switch happen at `activation_at`, not
/// here. Until then — and only until the first byte is distributed — the
/// operator can still cancel with a signed abort.
pub(crate) fn install_transition(
    registry: &mut CertificateRegistry,
    transition: GatewayIdentityTransition,
    now_unix: u64,
) -> Result<StagedTransition> {
    candidate_is_held(
        &transition,
        read_pending(&pending_request_path())?.as_ref(),
        crate::key_negotiation::candidate_tls_certificate()?.as_ref(),
    )?;

    // Verified on a copy before the document is written, so the two orders
    // that could go wrong both stay safe. A document written for a transition
    // the state machine then refuses would overwrite the one a *previous*
    // staging still needs to be abortable; a registry that persisted the
    // staging before the document reached disk would be a staged transition
    // that can no longer be aborted at all. The check is deterministic over
    // the same inputs, so paying for it twice costs one signature
    // verification on a ceremony that happens once per identity.
    let mut probe = registry.state().gateway.clone();
    probe
        .install_transition(&transition, &registry.state().ledger, now_unix)
        .context("verifying the transition against the anchors this gateway pins")?;

    let path = staged_transition_path();
    write_document(&path, &transition, "gateway identity transition")?;
    let outcome = registry
        .install_gateway_transition(&transition, now_unix)
        .context("staging the transition in the certificate registry")?;
    Ok(StagedTransition {
        transition,
        path,
        already_present: matches!(outcome, InstallOutcome::AlreadyPresent),
    })
}

/// Opens the registry for an **offline** operator command (spec §12.2).
///
/// The console route goes through the running daemon, which already owns the
/// registry under its lock. This one exists for a gateway whose daemon is
/// stopped: two writers on one file is the failure this module is otherwise
/// built to avoid, and the console route is what removes the need for it.
pub(crate) fn open_registry_for_command() -> Result<CertificateRegistry> {
    let registry_path = CertificateRegistry::path();
    CertificateRegistry::load(&registry_path)
        .context("opening the certificate registry")?
        .with_context(|| {
            format!(
                "this gateway has no trust domain: run `heliosd init-trust-domain` first — {} \
                 does not exist",
                registry_path.display()
            )
        })
}

/// Reads a signed decision an operator carried back from the ceremony.
pub(crate) fn read_signed_document<T: serde::de::DeserializeOwned>(
    source: &std::path::Path,
    what: &str,
) -> Result<T> {
    read_document(source, what)
}

/// The three local documents a gateway renewal moves through.
///
/// Grouped and passed in rather than resolved inside the orchestration, so the
/// crash windows below are exercised against temporary files. They are the
/// part of this module that no operator ever sees and that only a power cut
/// reaches, which is exactly the part a test has to be able to reach cheaply.
struct IdentityDocuments {
    transition: std::path::PathBuf,
    marker: std::path::PathBuf,
    pending_request: std::path::PathBuf,
}

impl IdentityDocuments {
    fn resolved() -> Self {
        Self {
            transition: staged_transition_path(),
            marker: promotion_marker_path(),
            pending_request: pending_request_path(),
        }
    }
}

/// Advances the gateway identity at the two clock boundaries of §11.1.
///
/// At startup inside the overlap this function leaves both slots untouched;
/// [`crate::key_negotiation::start`] selects the published candidate. At
/// `not_after` it first persists the promoted registry, then atomically
/// replaces the active sealed identity and finally removes the outgoing
/// artifacts. The promotion marker closes the only crash window where the
/// active vault is already synchronized but the retained transition has not
/// yet been cleaned up.
pub(crate) fn maintain_gateway_identity(
    registry: &mut CertificateRegistry,
    secret: Option<&helios_tpm::SecretKey>,
    now_unix: u64,
) -> Result<bool> {
    maintain_gateway_identity_in(registry, secret, now_unix, &IdentityDocuments::resolved())
}

fn maintain_gateway_identity_in(
    registry: &mut CertificateRegistry,
    secret: Option<&helios_tpm::SecretKey>,
    now_unix: u64,
    documents: &IdentityDocuments,
) -> Result<bool> {
    let Some(transition) = read_optional_document::<GatewayIdentityTransition>(
        &documents.transition,
        "staged gateway transition",
    )?
    else {
        if let Some(marker) = read_optional_document::<PromotionMarker>(
            &documents.marker,
            "gateway promotion marker",
        )? {
            anyhow::ensure!(
                registry.state().gateway.next_gateway_identity_epoch.is_none()
                    && marker.gateway_identity_epoch
                        == registry.state().gateway.active_gateway_identity_epoch,
                "a gateway promotion marker remains for epoch {}, while the registry is active at epoch {}",
                marker.gateway_identity_epoch,
                registry.state().gateway.active_gateway_identity_epoch
            );
            remove_document(&documents.marker)?;
        }
        return Ok(false);
    };

    let gateway = &registry.state().gateway;
    let due = gateway
        .retire_active_at
        .is_some_and(|retire_at| now_unix >= retire_at)
        && gateway.next_gateway_identity_epoch.is_some();
    let recovering = gateway.next_gateway_identity_epoch.is_none()
        && transition.gateway_identity_epoch == gateway.active_gateway_identity_epoch;
    if !due && !recovering {
        return Ok(false);
    }

    let expected_epoch = if due {
        gateway
            .next_gateway_identity_epoch
            .context("a due gateway transition has no next epoch")?
    } else {
        gateway.active_gateway_identity_epoch
    };
    anyhow::ensure!(
        transition.gateway_identity_epoch == expected_epoch,
        "the retained gateway transition is for epoch {}, while epoch {expected_epoch} must be finalized",
        transition.gateway_identity_epoch
    );
    let transition_fingerprint = transition
        .fingerprint()
        .context("fingerprinting the retained gateway transition")?;
    let marker =
        read_optional_document::<PromotionMarker>(&documents.marker, "gateway promotion marker")?;
    if let Some(marker) = &marker {
        anyhow::ensure!(
            recovering
                && marker.gateway_identity_epoch == expected_epoch
                && marker
                    .transition_fingerprint
                    .matches(&transition_fingerprint),
            "the gateway promotion marker does not name the promoted transition"
        );
    } else {
        // The state question before the machine one: a transition that was
        // never distributed must be refused for that reason, and not for a
        // sealed vault the operator would then go looking at.
        anyhow::ensure!(
            !due || registry.state().gateway.published,
            "the gateway transition reached not_after without being published"
        );
        let secret = secret.context(
            "TPM secret unavailable: the due gateway identity cannot be promoted or unsealed",
        )?;
        crate::key_negotiation::assert_candidate_identity_promotable(
            secret,
            &registry.state().gateway.gateway_wg_public_key.to_base64(),
            &transition,
        )
        .context("opening the gateway identity before its registry promotion")?;

        if due {
            anyhow::ensure!(
                registry
                    .promote_gateway_if_due(now_unix)
                    .context("persisting the promoted gateway generation")?,
                "the due gateway transition did not move the registry"
            );
        }
        crate::key_negotiation::promote_candidate_identity(
            secret,
            &registry.state().gateway,
            &transition,
        )
        .context("synchronizing the promoted gateway private identity")?;
        write_document(
            &documents.marker,
            &PromotionMarker {
                gateway_identity_epoch: expected_epoch,
                transition_fingerprint,
            },
            "gateway identity promotion marker",
        )?;
    }

    crate::key_negotiation::discard_candidate_identity()
        .context("destroying the redundant candidate slot after promotion")?;
    if read_pending(&documents.pending_request)?
        .is_some_and(|request| request.gateway_identity_epoch == expected_epoch)
    {
        remove_document(&documents.pending_request)?;
    }
    remove_document(&documents.transition)?;
    remove_document(&documents.marker)?;
    Ok(true)
}

/// Cancels a staged, unpublished transition (spec §6.3, `aborted`).
///
/// The epoch stays consumed. That is deliberate and not a leftover: a client
/// that already holds the tombstone refuses a second decision numbered the
/// same, and reusing the number would be the gateway asking a fleet to choose
/// between two documents at one epoch.
/// A service rollback the registry accepted (spec §4.4, §11.1 step 8).
pub(crate) struct InstalledRollback {
    pub(crate) gateway_identity_epoch: u64,
    pub(crate) selected_certificate_fingerprint: Fingerprint,
    pub(crate) expires_at: u64,
    pub(crate) already_present: bool,
}

/// Selects the outgoing leaf for the rest of the overlap (spec §11.1 step 8).
///
/// Nothing is written outside the registry, and nothing on disk is destroyed:
/// the candidate slot stays exactly where it is, because the overlap it
/// belongs to is untouched and its promotion still happens at `not_after`.
/// That is what makes this a *service* rollback — no key moves, only the
/// answer to «which leaf does the next start serve».
///
/// The daemon does not swap identity underneath itself: the leaf in service
/// was unsealed at startup and is held for the life of the process. This
/// records the decision; a restart applies it.
pub(crate) fn install_rollback(
    registry: &mut CertificateRegistry,
    authorization: CertificateServiceRollbackAuthorization,
    now_unix: u64,
) -> Result<InstalledRollback> {
    let epoch = registry
        .state()
        .gateway
        .next_gateway_identity_epoch
        .context("no gateway transition is staged: a rollback lives inside an overlap")?;
    let outcome = registry
        .install_gateway_rollback(&authorization, now_unix)
        .context("selecting the outgoing gateway leaf in the certificate registry")?;
    Ok(InstalledRollback {
        gateway_identity_epoch: epoch,
        selected_certificate_fingerprint: authorization.selected_certificate_fingerprint,
        expires_at: authorization.expires_at,
        already_present: matches!(outcome, InstallOutcome::AlreadyPresent),
    })
}

pub(crate) fn abort_transition(
    registry: &mut CertificateRegistry,
    abort: GatewayTransitionAbort,
    now_unix: u64,
) -> Result<AbortedTransition> {
    let staged_path = staged_transition_path();
    let transition: GatewayIdentityTransition = read_document(&staged_path, "transition")
        .with_context(|| {
            format!(
                "no staged transition document at {}: an abort is verified against the exact \
                 document it cancels",
                staged_path.display()
            )
        })?;

    let outcome = registry
        .abort_gateway_transition(&abort, &transition, now_unix)
        .context("cancelling the staged transition in the certificate registry")?;

    if matches!(outcome, InstallOutcome::Installed) {
        // After the registry, never before: the slot is destroyed for a
        // cancellation that has been accepted, and a candidate destroyed ahead
        // of a refusal would be destroyed for nothing — the ceremony that
        // produced it is days long and happens off this machine.
        crate::key_negotiation::discard_candidate_identity()
            .context("destroying the candidate identity the abort cancelled")?;
        remove_document(&staged_path)?;
        remove_document(&pending_request_path())?;
    }
    Ok(AbortedTransition {
        abort,
        already_present: matches!(outcome, InstallOutcome::AlreadyPresent),
    })
}

fn read_document<T: serde::de::DeserializeOwned>(path: &std::path::Path, what: &str) -> Result<T> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&raw)
        .with_context(|| format!("decoding the {what} in {}", path.display()))
}

fn read_optional_document<T: serde::de::DeserializeOwned>(
    path: &std::path::Path,
    what: &str,
) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(raw) => Ok(Some(serde_json::from_slice(&raw).with_context(|| {
            format!("decoding the {what} in {}", path.display())
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn write_document<T: serde::Serialize>(
    path: &std::path::Path,
    document: &T,
    what: &str,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let encoded =
        serde_json::to_vec_pretty(document).with_context(|| format!("encoding the {what}"))?;
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, &encoded)
        .with_context(|| format!("writing {}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("atomically replacing {}", path.display()))
}

fn remove_document(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::{
        generate_ml_dsa_87_keypair, MlDsa87PublicKey, MlDsa87Signature, TrustDomainId, WireGuardKey,
    };
    use aether::certificates::state::GatewayCertificateState;
    use aether::key_negotiation::{
        issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
    };

    const NOW: u64 = 1_700_000_000;

    fn gateway_leaf() -> PqCertificate {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, subject_public) = generate_ml_dsa_87_keypair().expect("keygen");
        issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [1; 16],
                subject: "gateway.example".into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Gateway,
                wireguard_public_key: WireGuardKey::from_bytes([9; 32]).to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
                not_before_unix: 0,
                not_after_unix: NOW + 1_000_000,
                ml_dsa_87_signature: String::new(),
            },
            &ca_private,
        )
        .expect("issue")
    }

    fn gateway() -> GatewayCertificateState {
        let (_, anchor) = generate_ml_dsa_87_keypair().expect("keygen");
        GatewayCertificateState {
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([9; 32]),
            server_name: "gateway.example".into(),
            ca_epoch: 1,
            current_ca_public_key: anchor,
            next_ca_public_key: None,
            next_ca_transition_fingerprint: None,
            ca_activation_at: None,
            ca_retire_active_at: None,
            active_gateway_identity_epoch: 3,
            gateway_decision_epoch: 3,
            next_gateway_identity_epoch: None,
            next_transition_fingerprint: None,
            last_aborted_transition: None,
            active_gateway_tls_certificate: aether::certificates::encoding::DerCertificate::new(
                vec![1; 64],
            )
            .expect("der"),
            next_gateway_tls_certificate: None,
            active_gateway_certificate: gateway_leaf(),
            next_gateway_certificate: None,
            activation_at: None,
            retire_active_at: None,
            published: false,
            revoked: false,
            revocation_epoch: 0,
            service_rollback: None,
            awaited_replacement: None,
        }
    }

    fn request(epoch: u64, expires_at: u64) -> GatewayCertificateRequest {
        let (_, candidate) = generate_ml_dsa_87_keypair().expect("keygen");
        GatewayCertificateRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_identity_epoch: epoch,
            gateway_wg_public_key: WireGuardKey::from_bytes([9; 32]),
            server_name: "gateway.example".into(),
            new_ml_dsa_87_public_key: MlDsa87PublicKey::new(candidate.as_bytes().to_vec())
                .expect("public key"),
            request_id: Id16::new([7; 16]).expect("id"),
            created_at: NOW,
            expires_at,
            new_key_proof: MlDsa87Signature::placeholder(),
            current_key_authorization: None,
        }
    }

    #[test]
    fn a_first_preparation_seals_the_epoch_after_the_last_decision() {
        assert_eq!(
            plan(&gateway(), None, false, false, NOW).expect("plan"),
            Plan::Seal { epoch: 4 }
        );
    }

    /// The operator holds one fingerprint. Re-signing would hand them a second.
    #[test]
    fn a_valid_request_for_the_same_epoch_is_returned_unchanged() {
        let held = request(4, NOW + 3600);
        let Plan::Reuse(reused) =
            plan(&gateway(), Some(held.clone()), false, false, NOW).expect("plan")
        else {
            panic!("a valid request must be reused");
        };
        assert_eq!(*reused, held);
    }

    /// §5 caps a request at 24 hours; a ceremony is not bound by that clock.
    #[test]
    fn an_expired_request_is_resigned_over_the_key_already_sealed() {
        let held = request(4, NOW - 1);
        let expected = held.new_ml_dsa_87_public_key.clone();
        assert_eq!(
            plan(&gateway(), Some(held), false, false, NOW).expect("plan"),
            Plan::Resign {
                epoch: 4,
                pq_public_key: expected,
            }
        );
    }

    #[test]
    fn new_key_replaces_the_candidate_even_while_its_request_is_valid() {
        assert_eq!(
            plan(&gateway(), Some(request(4, NOW + 3600)), true, false, NOW).expect("plan"),
            Plan::Seal { epoch: 4 }
        );
    }

    /// A request left from a decision this gateway has moved past describes a
    /// candidate that is no longer the one being prepared.
    #[test]
    fn a_request_from_an_earlier_epoch_is_not_a_resumption() {
        assert_eq!(
            plan(&gateway(), Some(request(3, NOW + 3600)), false, false, NOW).expect("plan"),
            Plan::Seal { epoch: 4 }
        );
    }

    /// §6.3: one candidate at a time. The staged transition already owns
    /// epoch 4, and a second request would seal a key for the same number.
    #[test]
    fn a_staged_transition_refuses_a_second_request() {
        let mut gateway = gateway();
        gateway.gateway_decision_epoch = 4;
        gateway.next_gateway_identity_epoch = Some(4);
        let error =
            plan(&gateway, None, false, false, NOW).expect_err("a staged transition must refuse");
        assert!(
            error.to_string().contains("already staged"),
            "unexpected refusal: {error}"
        );
    }

    /// A revoked identity may not sign for its successor: §5's continuity
    /// signature is exactly the right a withdrawal removes.
    #[test]
    fn a_revoked_gateway_prepares_nothing_that_claims_continuity() {
        let mut gateway = gateway();
        gateway.revoked = true;
        gateway.revocation_epoch = 2;
        let error =
            plan(&gateway, None, false, false, NOW).expect_err("a revoked identity must refuse");
        assert!(
            error.to_string().contains("revoked"),
            "unexpected refusal: {error}"
        );
    }

    /// But it prepares the §10.1 replacement, without continuity. Refusing
    /// that too would make `replacement_transition_fingerprint` unusable and
    /// every withdrawal terminal in practice.
    #[test]
    fn a_revoked_gateway_prepares_its_replacement_under_key_recovery() {
        let mut gateway = gateway();
        gateway.revoked = true;
        gateway.revocation_epoch = 2;
        assert_eq!(
            plan(&gateway, None, false, true, NOW).expect("replacement"),
            Plan::Seal {
                epoch: gateway.gateway_decision_epoch + 1
            }
        );
    }

    #[test]
    fn a_pending_request_survives_its_own_encoding() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("gateway-certificate-request.json");
        let held = request(4, NOW + 3600);
        write_pending(&path, &held).expect("write");
        assert_eq!(read_pending(&path).expect("read"), Some(held));
    }

    #[test]
    fn an_absent_request_is_not_an_error() {
        let directory = tempfile::tempdir().expect("temporary directory");
        assert_eq!(
            read_pending(&directory.path().join("absent.json")).expect("read"),
            None
        );
    }

    fn leaf_for(public_key: &MlDsa87PublicKey) -> PqCertificate {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
        issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [2; 16],
                subject: "gateway.example".into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Gateway,
                wireguard_public_key: WireGuardKey::from_bytes([9; 32]).to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(public_key.as_bytes()),
                not_before_unix: 0,
                not_after_unix: NOW + 1_000_000,
                ml_dsa_87_signature: String::new(),
            },
            &ca_private,
        )
        .expect("issue")
    }

    fn transition(
        epoch: u64,
        pq: Option<PqCertificate>,
        tls: Option<DerCertificate>,
    ) -> GatewayIdentityTransition {
        GatewayIdentityTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            gateway_identity_epoch: epoch,
            gateway_wg_public_key: WireGuardKey::from_bytes([9; 32]),
            server_name: "gateway.example".into(),
            active_gateway_tls_certificate_fingerprint:
                aether::certificates::encoding::Fingerprint::of(b"active tls"),
            next_gateway_tls_certificate: tls,
            active_gateway_certificate_fingerprint: aether::certificates::encoding::Fingerprint::of(
                b"active pq",
            ),
            next_gateway_certificate: pq,
            window: aether::certificates::window::TransitionWindow {
                not_before: NOW,
                activation_at: NOW + 1_000,
                not_after: NOW + 2_000,
            },
            reason: aether::certificates::authority::RotationReason::Scheduled,
            ca_signature: MlDsa87Signature::placeholder(),
        }
    }

    #[test]
    fn a_transition_installing_the_sealed_candidate_is_accepted() {
        let held = request(4, NOW + 3_600);
        let leaf = leaf_for(&held.new_ml_dsa_87_public_key);

        candidate_is_held(&transition(4, Some(leaf), None), Some(&held), None)
            .expect("the leaf this gateway sealed");
    }

    /// The check no signature makes: `CA-PQ` certifies that a leaf is
    /// authentic, never that its private half is on this machine.
    #[test]
    fn a_transition_installing_a_key_sealed_elsewhere_is_refused() {
        let held = request(4, NOW + 3_600);
        let (_, elsewhere) = generate_ml_dsa_87_keypair().expect("keygen");
        let stranger =
            leaf_for(&MlDsa87PublicKey::new(elsewhere.as_bytes().to_vec()).expect("public key"));

        let refusal = candidate_is_held(&transition(4, Some(stranger), None), Some(&held), None)
            .expect_err("a leaf whose private half is elsewhere");

        assert!(refusal.to_string().contains("did not seal"));
    }

    #[test]
    fn a_transition_answering_no_pending_request_is_refused() {
        let (_, orphan) = generate_ml_dsa_87_keypair().expect("keygen");
        let leaf = leaf_for(&MlDsa87PublicKey::new(orphan.as_bytes().to_vec()).expect("key"));

        candidate_is_held(&transition(4, Some(leaf), None), None, None)
            .expect_err("no candidate sealed here");
    }

    /// A request from an epoch already decided describes a candidate this
    /// gateway has moved past.
    #[test]
    fn a_transition_for_another_epoch_than_the_pending_request_is_refused() {
        let held = request(4, NOW + 3_600);
        let leaf = leaf_for(&held.new_ml_dsa_87_public_key);

        let refusal = candidate_is_held(&transition(5, Some(leaf), None), Some(&held), None)
            .expect_err("an epoch the sealed candidate was not prepared for");

        assert!(refusal.to_string().contains("epoch"));
    }

    #[test]
    fn a_tls_leaf_that_is_not_the_candidate_is_refused() {
        let held = request(4, NOW + 3_600);
        let leaf = leaf_for(&held.new_ml_dsa_87_public_key);
        let candidate = DerCertificate::new(vec![1; 64]).expect("der");
        let stranger = DerCertificate::new(vec![2; 64]).expect("der");

        candidate_is_held(
            &transition(4, Some(leaf), Some(stranger)),
            Some(&held),
            Some(&candidate),
        )
        .expect_err("a TLS leaf sealed elsewhere");
    }

    #[test]
    fn a_tls_leaf_with_no_candidate_sealed_here_is_refused() {
        let held = request(4, NOW + 3_600);
        let leaf = leaf_for(&held.new_ml_dsa_87_public_key);
        let tls = DerCertificate::new(vec![3; 64]).expect("der");

        let refusal = candidate_is_held(&transition(4, Some(leaf), Some(tls)), Some(&held), None)
            .expect_err("a TLS leaf this gateway never prepared");

        assert!(refusal.to_string().contains("--rotate-tls"));
    }

    /// A registry on disk, so the promotion path is exercised where it runs.
    fn registry_in(
        directory: &std::path::Path,
        gateway: GatewayCertificateState,
    ) -> CertificateRegistry {
        use helios_provisioning::certificates::RegistryState;

        let (_, service) = generate_ml_dsa_87_keypair().expect("keygen");
        let state =
            RegistryState {
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                gateway,
                client_tls_ca: aether::certificates::state::ClientTlsCaState {
                    ca_tls_epoch: 1,
                    active_client_tls_ca_certificate:
                        aether::certificates::test_x509::client_material("workstation").authority,
                    next_client_tls_ca_certificate: None,
                    next_transition_fingerprint: None,
                    activation_at: None,
                    retire_active_at: None,
                },
                astra: aether::certificates::state::AstraProfile {
                    authority_url: "https://astra.example".into(),
                    webauthn_rp_id: "astra.example".into(),
                    astra_policy_fingerprint: aether::certificates::approval::AstraPolicyPin::new(
                        aether::certificates::encoding::Fingerprint::of(b"policy"),
                    )
                    .expect("policy pin"),
                    credential_registry_epoch: 1,
                    credential_bindings: Default::default(),
                    active_astra_service_public_key: service,
                    next_astra_service_public_key: None,
                    next_service_key_transition_fingerprint: None,
                    astra_service_key_epoch: 1,
                    service_key_activation_at: None,
                    service_key_retire_active_at: None,
                    service_key_revocation_epoch: 0,
                    last_emergency_replacement_fingerprint: None,
                },
                issuer: None,
                peers: Default::default(),
                ledger: Default::default(),
            };
        CertificateRegistry::new(directory.join("certificates.json"), state)
    }

    fn documents_in(directory: &std::path::Path) -> IdentityDocuments {
        IdentityDocuments {
            transition: directory.join("transition.json"),
            marker: directory.join("promotion.json"),
            pending_request: directory.join("request.json"),
        }
    }

    fn staged_transition(epoch: u64) -> GatewayIdentityTransition {
        GatewayIdentityTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            gateway_identity_epoch: epoch,
            gateway_wg_public_key: WireGuardKey::from_bytes([9; 32]),
            server_name: "gateway.example".into(),
            active_gateway_tls_certificate_fingerprint:
                aether::certificates::encoding::Fingerprint::of(b"active tls"),
            next_gateway_tls_certificate: None,
            active_gateway_certificate_fingerprint: aether::certificates::encoding::Fingerprint::of(
                b"active pq",
            ),
            next_gateway_certificate: None,
            window: aether::certificates::window::TransitionWindow {
                not_before: NOW,
                activation_at: NOW + 1_000,
                not_after: NOW + 2_000,
            },
            reason: aether::certificates::authority::RotationReason::Scheduled,
            ca_signature: MlDsa87Signature::placeholder(),
        }
    }

    #[test]
    fn a_gateway_with_nothing_in_flight_is_left_alone() {
        let directory = tempfile::tempdir().expect("temp dir");
        let mut registry = registry_in(directory.path(), gateway());

        assert!(!maintain_gateway_identity_in(
            &mut registry,
            None,
            NOW,
            &documents_in(directory.path())
        )
        .expect("nothing to do"));
    }

    /// Before `not_after` the overlap is still running: both identities are
    /// legitimate, and promoting early would retire one the fleet still uses.
    #[test]
    fn a_staged_transition_is_not_promoted_before_its_not_after() {
        let directory = tempfile::tempdir().expect("temp dir");
        let documents = documents_in(directory.path());
        let transition = staged_transition(4);
        write_document(&documents.transition, &transition, "transition").expect("write");
        let mut gateway = gateway();
        gateway.next_gateway_identity_epoch = Some(4);
        gateway.activation_at = Some(NOW + 1_000);
        gateway.retire_active_at = Some(NOW + 2_000);
        gateway.published = true;
        let mut registry = registry_in(directory.path(), gateway);

        assert!(
            !maintain_gateway_identity_in(&mut registry, None, NOW + 1_999, &documents)
                .expect("still in overlap")
        );
        assert!(documents.transition.exists());
    }

    /// §11.1 forbids promoting what was never distributed: the fleet would be
    /// asked to follow a decision it was never offered.
    #[test]
    fn a_due_transition_that_was_never_published_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let documents = documents_in(directory.path());
        write_document(&documents.transition, &staged_transition(4), "transition").expect("write");
        let mut gateway = gateway();
        gateway.next_gateway_identity_epoch = Some(4);
        gateway.activation_at = Some(NOW + 1_000);
        gateway.retire_active_at = Some(NOW + 2_000);
        gateway.published = false;
        let mut registry = registry_in(directory.path(), gateway);

        let refusal = maintain_gateway_identity_in(&mut registry, None, NOW + 2_000, &documents)
            .expect_err("an unpublished promotion");
        assert!(refusal.to_string().contains("published"));
        assert_eq!(
            registry.state().gateway.active_gateway_identity_epoch,
            3,
            "the identity in service must not have moved"
        );
    }

    /// The candidate is sealed. Without the TPM secret the promotion cannot be
    /// completed, and the registry must not record one that the machine cannot
    /// then serve.
    #[test]
    fn a_due_transition_without_the_tpm_secret_moves_nothing() {
        let directory = tempfile::tempdir().expect("temp dir");
        let documents = documents_in(directory.path());
        write_document(&documents.transition, &staged_transition(4), "transition").expect("write");
        let mut gateway = gateway();
        gateway.next_gateway_identity_epoch = Some(4);
        gateway.activation_at = Some(NOW + 1_000);
        gateway.retire_active_at = Some(NOW + 2_000);
        gateway.published = true;
        let mut registry = registry_in(directory.path(), gateway);

        assert!(
            maintain_gateway_identity_in(&mut registry, None, NOW + 2_000, &documents).is_err()
        );
        assert_eq!(registry.state().gateway.active_gateway_identity_epoch, 3);
        assert!(documents.transition.exists());
    }

    /// The one crash window the marker exists for: the sealed vault is already
    /// the new one, the registry is already promoted, and the outgoing
    /// documents had not been removed yet. The replay must finish the cleanup
    /// without asking for a secret and without moving the epoch again.
    #[test]
    fn a_crash_between_the_vault_and_the_cleanup_is_replayed() {
        let directory = tempfile::tempdir().expect("temp dir");
        let documents = documents_in(directory.path());
        let transition = staged_transition(4);
        write_document(&documents.transition, &transition, "transition").expect("write");
        write_document(
            &documents.marker,
            &PromotionMarker {
                gateway_identity_epoch: 4,
                transition_fingerprint: transition.fingerprint().expect("fingerprint"),
            },
            "marker",
        )
        .expect("write");
        let mut gateway = gateway();
        gateway.active_gateway_identity_epoch = 4;
        gateway.gateway_decision_epoch = 4;
        let mut registry = registry_in(directory.path(), gateway);
        // The candidate slot lives in this run's own directory, never in the
        // machine's.
        std::env::set_var(
            "HELIOS_KEY_NEGO_NEXT_KEY",
            directory.path().join("next.sealed"),
        );
        std::env::set_var(
            "HELIOS_KEY_NEGO_NEXT_CERT",
            directory.path().join("next.der"),
        );

        assert!(
            maintain_gateway_identity_in(&mut registry, None, NOW + 3_000, &documents)
                .expect("replayed"),
            "the interrupted promotion must finish"
        );
        assert!(!documents.transition.exists());
        assert!(!documents.marker.exists());
        assert_eq!(registry.state().gateway.active_gateway_identity_epoch, 4);
    }

    /// A marker naming another document would let a crash finish a promotion
    /// that never happened.
    #[test]
    fn a_marker_naming_another_transition_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let documents = documents_in(directory.path());
        let transition = staged_transition(4);
        write_document(&documents.transition, &transition, "transition").expect("write");
        write_document(
            &documents.marker,
            &PromotionMarker {
                gateway_identity_epoch: 4,
                transition_fingerprint: aether::certificates::encoding::Fingerprint::of(
                    b"another decision",
                ),
            },
            "marker",
        )
        .expect("write");
        let mut gateway = gateway();
        gateway.active_gateway_identity_epoch = 4;
        gateway.gateway_decision_epoch = 4;
        let mut registry = registry_in(directory.path(), gateway);

        assert!(
            maintain_gateway_identity_in(&mut registry, None, NOW + 3_000, &documents).is_err()
        );
        assert!(documents.transition.exists());
    }

    /// A marker left behind with nothing staged is a completed promotion whose
    /// last write was lost. It is cleared, not acted on.
    #[test]
    fn a_marker_for_the_identity_in_service_is_swept() {
        let directory = tempfile::tempdir().expect("temp dir");
        let documents = documents_in(directory.path());
        write_document(
            &documents.marker,
            &PromotionMarker {
                gateway_identity_epoch: 3,
                transition_fingerprint: aether::certificates::encoding::Fingerprint::of(b"spent"),
            },
            "marker",
        )
        .expect("write");
        let mut registry = registry_in(directory.path(), gateway());

        assert!(
            !maintain_gateway_identity_in(&mut registry, None, NOW, &documents).expect("swept")
        );
        assert!(!documents.marker.exists());
    }

    /// The same marker at an epoch this gateway never reached describes a
    /// promotion of something else entirely.
    #[test]
    fn a_marker_for_an_epoch_never_reached_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let documents = documents_in(directory.path());
        write_document(
            &documents.marker,
            &PromotionMarker {
                gateway_identity_epoch: 9,
                transition_fingerprint: aether::certificates::encoding::Fingerprint::of(b"other"),
            },
            "marker",
        )
        .expect("write");
        let mut registry = registry_in(directory.path(), gateway());

        assert!(maintain_gateway_identity_in(&mut registry, None, NOW, &documents).is_err());
        assert!(documents.marker.exists());
    }
}
