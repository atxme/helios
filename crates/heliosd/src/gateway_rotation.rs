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

use aether::certificates::encoding::{DerCertificate, Id16};
use aether::certificates::gateway::GatewayCertificateRequest;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;
use helio_tpm::BootDecision;
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
    now_unix: u64,
) -> Result<Plan> {
    // §6.3: `revoked` is terminal and dominates every phase and every date.
    // Nothing local repairs it, and a renewal request would be this gateway
    // asking to continue an identity the authority has withdrawn.
    anyhow::ensure!(
        !gateway.revoked,
        "this gateway identity is revoked at epoch {}; a revocation is not repaired by a \
         renewal, and no new leaf may continue it",
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
    boot: &BootDecision,
    dry_run: bool,
    rotate_tls: bool,
    new_key: bool,
    key_recovery: bool,
    now_unix: u64,
) -> Result<PreparedRequest> {
    let registry_path = CertificateRegistry::path();
    let registry = CertificateRegistry::load(&registry_path)
        .context("opening the certificate registry")?
        .with_context(|| {
            format!(
                "this gateway has no trust domain: run `heliosd init-trust-domain` first. The \
                 request is built from the registry — {} does not exist",
                registry_path.display()
            )
        })?;
    let gateway = &registry.state().gateway;
    let path = pending_request_path();

    // The epoch comes back from the plan and is not recomputed here: the
    // sealing context binds it, and a second derivation is a second value that
    // can disagree with the one the candidate was sealed under.
    let (epoch, candidate) = match plan(gateway, read_pending(&path)?, new_key, now_unix)? {
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
                boot,
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
        boot,
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
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let encoded =
        serde_json::to_vec_pretty(request).context("encoding the gateway certificate request")?;
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, &encoded)
        .with_context(|| format!("writing {}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("atomically replacing {}", path.display()))
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
            plan(&gateway(), None, false, NOW).expect("plan"),
            Plan::Seal { epoch: 4 }
        );
    }

    /// The operator holds one fingerprint. Re-signing would hand them a second.
    #[test]
    fn a_valid_request_for_the_same_epoch_is_returned_unchanged() {
        let held = request(4, NOW + 3600);
        let Plan::Reuse(reused) = plan(&gateway(), Some(held.clone()), false, NOW).expect("plan")
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
            plan(&gateway(), Some(held), false, NOW).expect("plan"),
            Plan::Resign {
                epoch: 4,
                pq_public_key: expected,
            }
        );
    }

    #[test]
    fn new_key_replaces_the_candidate_even_while_its_request_is_valid() {
        assert_eq!(
            plan(&gateway(), Some(request(4, NOW + 3600)), true, NOW).expect("plan"),
            Plan::Seal { epoch: 4 }
        );
    }

    /// A request left from a decision this gateway has moved past describes a
    /// candidate that is no longer the one being prepared.
    #[test]
    fn a_request_from_an_earlier_epoch_is_not_a_resumption() {
        assert_eq!(
            plan(&gateway(), Some(request(3, NOW + 3600)), false, NOW).expect("plan"),
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
        let error = plan(&gateway, None, false, NOW).expect_err("a staged transition must refuse");
        assert!(
            error.to_string().contains("already staged"),
            "unexpected refusal: {error}"
        );
    }

    /// §6.3: `revoked` is terminal, and a renewal is not what repairs it.
    #[test]
    fn a_revoked_gateway_prepares_nothing() {
        let mut gateway = gateway();
        gateway.revoked = true;
        gateway.revocation_epoch = 2;
        let error = plan(&gateway, None, false, NOW).expect_err("a revoked identity must refuse");
        assert!(
            error.to_string().contains("revoked"),
            "unexpected refusal: {error}"
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
}
