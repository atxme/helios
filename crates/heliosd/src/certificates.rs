//! The gateway's certificate lifecycle service: one owner, one serializer.
//!
//! [`helios_provisioning::certificates::CertificateRegistry`] is a plain state
//! machine that takes `&mut self` and the clock as an argument. Something has
//! to own it, hold the lock, read the clock once per operation and hold the
//! sealed gateway key that signs receipts. That is this module, and there is
//! deliberately exactly one instance: a second one would give one slot two
//! writers, the same reason the negotiation state machine is a singleton.
//!
//! # What the gateway signs, and what it never signs
//!
//! It signs **receipts** — statements that a candidate is on its disk — with
//! its own active PQ leaf. It never signs a certificate, never holds `CA-PQ`,
//! and never calls an authority key on demand: every object it distributes was
//! pre-signed by Astra or by the operator companion (spec §8.1).
//!
//! # Limite connue
//!
//! The trust-update route can currently only answer "your trust is current".
//! Distributing a transition needs the private Astra ↔ Helios veth channel,
//! which is not implemented: the gateway has no store of pre-signed objects to
//! hand out. A caller that is provably behind therefore receives
//! [`TrustUpdateRefusal::Unavailable`] — a `503` — rather than an empty update,
//! because an empty update tells a client the opposite of the truth and it
//! would stop asking.
//!
//! For the same reason the response never carries a signed status. A status is
//! signed by the **Astra service key**, which this process does not hold and
//! must not hold; the gateway can only forward one it was given, and nothing
//! gives it one yet. Answering with an unsigned status, or with one signed by
//! the gateway leaf, would be inventing an authority — so the field stays
//! `None` until the private channel exists.

use std::path::PathBuf;
use std::sync::Arc;

use aether::certificates::client::GatewayCertificateStageReceipt;
use aether::certificates::{encoding::WireGuardKey, CertificateError};
use anyhow::{Context, Result};
use async_trait::async_trait;
use helios_api::certificates::{
    AstraStageHandler, StageCommitRequest, TrustUpdateHandler, TrustUpdateRefusal,
    TrustUpdateResponse,
};
use helios_provisioning::certificates::{CertificateRegistry, RegistryError};
use tokio::sync::Mutex;

/// Signs a staging receipt with the gateway's **served** PQ leaf.
///
/// A trait, and not a copy of the private key, because that key is unsealed
/// exactly once — by the negotiation service — and the receipt has to be
/// signed by the leaf the client already pins. Handing this module a second
/// copy of the secret would be a second place to leak it from, for no gain.
pub trait StageReceiptSigner: Send + Sync {
    fn sign_stage_receipt(
        &self,
        receipt: GatewayCertificateStageReceipt,
    ) -> Result<GatewayCertificateStageReceipt, CertificateError>;
}

/// Owner of the registry, and the only writer of its file.
pub struct CertificateService {
    registry: Mutex<CertificateRegistry>,
    signer: Arc<dyn StageReceiptSigner>,
}

impl CertificateService {
    pub fn new(registry: CertificateRegistry, signer: Arc<dyn StageReceiptSigner>) -> Self {
        Self {
            registry: Mutex::new(registry),
            signer,
        }
    }

    /// Loads the registry, or reports that this gateway has no trust domain.
    ///
    /// A missing file is not an empty domain: without `CA-PQ` there is no
    /// anchor to verify anything against, and the routes stay closed rather
    /// than accepting the first object that arrives.
    ///
    /// A gateway that runs no negotiation service has no served leaf to sign
    /// receipts with either, so the lifecycle needs the signer to exist — the
    /// two are not independently deployable.
    pub fn load(path: PathBuf, signer: Arc<dyn StageReceiptSigner>) -> Result<Option<Arc<Self>>> {
        let Some(registry) = CertificateRegistry::load(&path)
            .with_context(|| format!("reading the certificate registry {}", path.display()))?
        else {
            return Ok(None);
        };
        Ok(Some(Arc::new(Self::new(registry, signer))))
    }

    /// Drops expired candidates and promotes due generations.
    ///
    /// Run on the same lock as everything else, so a purge never races the
    /// commit it competes with.
    pub async fn maintain(&self, now_unix: u64) -> Result<(), RegistryError> {
        let mut registry = self.registry.lock().await;
        let purged = registry.purge_expired(now_unix)?;
        for peer in &purged {
            tracing::info!(peer = %peer, "staged certificate purged: its lease ran out");
        }
        let promoted = registry.promote_due(now_unix)?;
        for peer in &promoted {
            tracing::info!(peer = %peer, "certificate generation promoted at the end of its overlap");
        }
        Ok(())
    }
}

#[async_trait]
impl AstraStageHandler for CertificateService {
    /// Persists a stage authorization received from Astra on the private veth.
    ///
    /// The private listener calls this only after mutual TLS has authenticated
    /// Astra. The client identity comes from the signed authorization itself;
    /// Orion never relays this object and no in-tunnel route exposes it.
    async fn stage_from_astra(
        &self,
        authorization: Box<aether::certificates::client::ClientCertificateStageAuthorization>,
    ) -> Result<Box<GatewayCertificateStageReceipt>, TrustUpdateRefusal> {
        let caller = authorization.client_wg_public_key;
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let receipt = registry
            .stage(&caller, &authorization, now)
            .map_err(|error| {
                tracing::warn!(peer = %caller, %error, "staging from Astra refused");
                classify(error)
            })?;
        // `stage` has durably written the candidate before returning. Only then
        // may the served gateway leaf attest the receipt.
        let receipt = self
            .signer
            .sign_stage_receipt(receipt)
            .map_err(|_| TrustUpdateRefusal::Internal)?;
        Ok(Box::new(receipt))
    }
}

/// How often the lifecycle sweeps leases and overlaps.
///
/// A minute: the shortest deadline it enforces is a 24-hour lease, and the
/// commit path checks the clock itself, so the sweep is what turns "expired"
/// into "gone from disk" rather than what decides a race.
pub const MAINTENANCE_INTERVAL_SECS: u64 = 60;

/// Sweeps leases and overlaps for the life of the process.
pub fn spawn_maintenance(service: Arc<CertificateService>) {
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(error) = service.maintain(now_unix()).await {
                // Not fatal: an unwritable registry must not take the tunnel
                // down, and the next sweep tries again. It is loud because a
                // lease that never expires is a candidate that never frees
                // `active + 1`.
                tracing::error!(%error, "certificate lifecycle maintenance failed");
            }
        }
    });
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Whether the caller already holds everything this gateway would send it.
///
/// Every value the request declares is compared, and that exhaustiveness is
/// the property: a comparison that skipped a counter would answer "you are up
/// to date" to a client that is behind on exactly that counter, and the client
/// would stop asking. Since the only other answer this route can give today is
/// a `503`, a false "current" is the one outcome with no recovery — the client
/// has been told there is nothing to fetch.
///
/// Written as a free function over the persisted state so it can be exercised
/// without a runtime, a lock or a signer.
fn caller_is_current(
    state: &helios_provisioning::certificates::RegistryState,
    peer: &helios_provisioning::certificates::PeerCertificates,
    request: &aether::certificates::transport::TrustUpdateRequest,
) -> Result<bool, CertificateError> {
    let issuer_epoch = state
        .issuer
        .as_ref()
        .map_or(0, |issuer| issuer.issuer_epoch);
    Ok(request.ca_epoch == state.gateway.ca_epoch
        && request.ca_tls_epoch == state.client_tls_ca.ca_tls_epoch
        && request.astra_service_key_epoch == state.astra.astra_service_key_epoch
        && request.issuer_epoch == issuer_epoch
        && request.active_gateway_identity_epoch == state.gateway.active_gateway_identity_epoch
        && request.gateway_decision_epoch == state.gateway.gateway_decision_epoch
        && request
            .active_gateway_tls_certificate_fingerprint
            .matches(&state.gateway.active_tls_fingerprint())
        && request
            .active_gateway_certificate_fingerprint
            .matches(&state.gateway.active_pq_fingerprint()?)
        && request.client_identity_generation == peer.state.active.generation
        && request
            .active_client_tls_certificate_fingerprint
            .matches(&peer.state.active.tls_certificate_fingerprint)
        && request
            .active_client_pq_certificate_fingerprint
            .matches(&peer.state.active.pq_certificate_fingerprint))
}

/// Maps a registry refusal to the bounded class the API may report.
///
/// The detail goes to the protected log. A peer learns only the class, exactly
/// as on the public negotiation port: a finer taxonomy on an
/// authenticated-but-hostile caller is an oracle on other peers' generations.
fn classify(error: RegistryError) -> TrustUpdateRefusal {
    match error {
        RegistryError::Io(_) | RegistryError::Corrupt(_) => TrustUpdateRefusal::Internal,
        RegistryError::Certificate(CertificateError::UnsupportedFormatVersion { .. })
        | RegistryError::Certificate(CertificateError::UnsupportedProtocolVersion { .. }) => {
            TrustUpdateRefusal::Protocol
        }
        _ => TrustUpdateRefusal::Rejected,
    }
}

#[async_trait]
impl TrustUpdateHandler for CertificateService {
    async fn trust_update(
        &self,
        caller_wg_public_key: &str,
        request: aether::certificates::transport::AuthenticatedTrustUpdateRequest,
    ) -> Result<TrustUpdateResponse, TrustUpdateRefusal> {
        let caller =
            WireGuardKey::parse(caller_wg_public_key).map_err(|_| TrustUpdateRefusal::Rejected)?;
        let now = now_unix();
        let registry = self.registry.lock().await;
        let state = registry.state();

        // Both authorities that may have issued the caller's leaf: the anchor,
        // and the delegated issuer an ordinary renewal chains to.
        let mut issuers = vec![&state.gateway.current_ca_public_key];
        if let Some(next) = &state.gateway.next_ca_public_key {
            issuers.push(next);
        }
        if let Some(issuer) = &state.issuer {
            issuers.push(&issuer.authorization.pq_issuer_public_key);
        }

        request
            .verify(
                &issuers,
                &state.trust_domain_id,
                &state.gateway.gateway_wg_public_key,
                &caller,
                &registry.acceptable_pq_fingerprints(&caller, now),
                now,
            )
            .map_err(|error| {
                tracing::warn!(peer = %caller_wg_public_key, %error, "trust update refused");
                TrustUpdateRefusal::Rejected
            })?;

        let peer = registry.peer(&caller).ok_or(TrustUpdateRefusal::Rejected)?;
        let current = caller_is_current(state, peer, &request.request)
            .map_err(|_| TrustUpdateRefusal::Internal)?;

        if current {
            return Ok(TrustUpdateResponse {
                status: None,
                manifest: None,
                chunk: None,
            });
        }
        // Behind, and nothing signed to hand over — see the module's known
        // limitation. Saying so beats claiming the client is up to date.
        tracing::warn!(
            peer = %caller_wg_public_key,
            "trust update: the caller is behind and no signed object is available to \
             distribute; the private Astra channel is not implemented"
        );
        Err(TrustUpdateRefusal::Unavailable)
    }

    async fn stage_commit(
        &self,
        caller_wg_public_key: &str,
        request: Box<StageCommitRequest>,
    ) -> Result<(), TrustUpdateRefusal> {
        let caller =
            WireGuardKey::parse(caller_wg_public_key).map_err(|_| TrustUpdateRefusal::Rejected)?;
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        registry
            .commit(&caller, &request.commit, &request.grant, now)
            .map_err(|error| {
                tracing::warn!(peer = %caller_wg_public_key, %error, "commit refused");
                classify(error)
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::client::ClientCertificateGeneration;
    use aether::certificates::encoding::{
        generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, Id16, TrustDomainId,
    };
    use aether::certificates::state::{
        AstraProfile, ClientCertificateState, ClientTlsCaState, GatewayCertificateState,
    };
    use aether::certificates::transport::TrustUpdateRequest;
    use aether::certificates::CERTIFICATE_PROTOCOL_VERSION;
    use aether::key_negotiation::{
        issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
    };
    use helios_provisioning::certificates::{PeerCertificates, RegistryState};

    fn key(seed: u8) -> WireGuardKey {
        WireGuardKey::from_bytes([seed; 32])
    }

    fn generation() -> ClientCertificateGeneration {
        ClientCertificateGeneration {
            generation: 4,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(b"client tls"),
            pq_certificate_fingerprint: Fingerprint::of(b"client pq"),
            not_before: 0,
            not_after: 1_000_000,
        }
    }

    /// A signed leaf: the fingerprint of a PQ certificate covers its
    /// signature, so an unsigned placeholder has no fingerprint at all.
    fn signed_leaf(role: PqCertificateRole, subject: &str, serial: u8) -> PqCertificate {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, subject_public) = generate_ml_dsa_87_keypair().expect("keygen");
        issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [serial; 16],
                subject: subject.into(),
                issuer: "CA-PQ".into(),
                role,
                wireguard_public_key: key(9).to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(subject_public.as_bytes()),
                not_before_unix: 0,
                not_after_unix: 1_000_000,
                ml_dsa_87_signature: String::new(),
            },
            &ca_private,
        )
        .expect("issue")
    }

    fn gateway_leaf() -> PqCertificate {
        signed_leaf(PqCertificateRole::Gateway, "gateway.example", 1)
    }

    fn state() -> RegistryState {
        let (_, anchor) = generate_ml_dsa_87_keypair().expect("keygen");
        let (_, service) = generate_ml_dsa_87_keypair().expect("keygen");
        RegistryState {
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway: GatewayCertificateState {
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                gateway_wg_public_key: key(9),
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
                active_gateway_tls_certificate: DerCertificate::new(vec![1; 64]).expect("der"),
                next_gateway_tls_certificate: None,
                active_gateway_certificate: gateway_leaf(),
                next_gateway_certificate: None,
                activation_at: None,
                retire_active_at: None,
                published: false,
                revoked: false,
                revocation_epoch: 0,
            },
            client_tls_ca: ClientTlsCaState {
                ca_tls_epoch: 2,
                active_client_tls_ca_certificate: DerCertificate::new(vec![2; 64]).expect("der"),
                next_client_tls_ca_certificate: None,
                next_transition_fingerprint: None,
                activation_at: None,
                retire_active_at: None,
            },
            astra: AstraProfile {
                authority_url: "https://astra.example".into(),
                webauthn_rp_id: "astra.example".into(),
                active_astra_service_public_key: service,
                next_astra_service_public_key: None,
                next_service_key_transition_fingerprint: None,
                astra_service_key_epoch: 5,
                service_key_activation_at: None,
                service_key_retire_active_at: None,
                service_key_revocation_epoch: 0,
                last_emergency_replacement_fingerprint: None,
            },
            issuer: None,
            peers: Default::default(),
            ledger: Default::default(),
        }
    }

    fn peer() -> PeerCertificates {
        PeerCertificates {
            name: "workstation".into(),
            state: ClientCertificateState::new(generation()),
            active_pq_certificate: signed_leaf(PqCertificateRole::Client, "workstation", 2),
            staged_pq_certificate: None,
        }
    }

    /// A request that declares exactly what the gateway serves.
    fn request(state: &RegistryState, peer: &PeerCertificates) -> TrustUpdateRequest {
        TrustUpdateRequest {
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            request_id: Id16::new([7; 16]).expect("id"),
            trust_domain_id: state.trust_domain_id,
            gateway_wg_public_key: state.gateway.gateway_wg_public_key,
            client_wg_public_key: key(2),
            ca_epoch: state.gateway.ca_epoch,
            ca_tls_epoch: state.client_tls_ca.ca_tls_epoch,
            astra_service_key_epoch: state.astra.astra_service_key_epoch,
            issuer_epoch: 0,
            active_gateway_identity_epoch: state.gateway.active_gateway_identity_epoch,
            gateway_decision_epoch: state.gateway.gateway_decision_epoch,
            client_identity_generation: peer.state.active.generation,
            active_gateway_tls_certificate_fingerprint: state.gateway.active_tls_fingerprint(),
            active_gateway_certificate_fingerprint: state
                .gateway
                .active_pq_fingerprint()
                .expect("fingerprint"),
            active_client_tls_certificate_fingerprint: peer
                .state
                .active
                .tls_certificate_fingerprint,
            active_client_pq_certificate_fingerprint: peer.state.active.pq_certificate_fingerprint,
            client_pq_certificate_fingerprint: Fingerprint::of(b"presented"),
        }
    }

    #[test]
    fn a_caller_declaring_exactly_what_the_gateway_serves_is_current() {
        let state = state();
        let peer = peer();
        assert!(caller_is_current(&state, &peer, &request(&state, &peer)).expect("comparison"));
    }

    /// Every counter and every active fingerprint is compared. A gap in this
    /// list answers "you are up to date" to a client that is not, and the
    /// client stops asking — the one refusal with no recovery.
    #[test]
    fn a_caller_behind_on_any_single_value_is_not_current() {
        let state = state();
        let peer = peer();
        let stale = Fingerprint::of(b"an older certificate");

        /// One way of being behind, and the name it is reported under.
        type Mutation = (&'static str, fn(&mut TrustUpdateRequest, Fingerprint));

        let mutations: Vec<Mutation> = vec![
            ("ca_epoch", |request, _| request.ca_epoch -= 1),
            ("ca_tls_epoch", |request, _| request.ca_tls_epoch -= 1),
            ("astra_service_key_epoch", |request, _| {
                request.astra_service_key_epoch -= 1
            }),
            ("issuer_epoch", |request, _| request.issuer_epoch += 1),
            ("active_gateway_identity_epoch", |request, _| {
                request.active_gateway_identity_epoch -= 1
            }),
            ("gateway_decision_epoch", |request, _| {
                request.gateway_decision_epoch -= 1
            }),
            ("client_identity_generation", |request, _| {
                request.client_identity_generation -= 1
            }),
            ("gateway TLS leaf", |request, stale| {
                request.active_gateway_tls_certificate_fingerprint = stale
            }),
            ("gateway PQ leaf", |request, stale| {
                request.active_gateway_certificate_fingerprint = stale
            }),
            ("client TLS leaf", |request, stale| {
                request.active_client_tls_certificate_fingerprint = stale
            }),
            ("client PQ leaf", |request, stale| {
                request.active_client_pq_certificate_fingerprint = stale
            }),
        ];

        for (name, mutate) in mutations {
            let mut behind = request(&state, &peer);
            mutate(&mut behind, stale);
            assert!(
                !caller_is_current(&state, &peer, &behind).expect("comparison"),
                "a caller behind on {name} was reported as up to date"
            );
        }
    }

    /// The delegation counts too: a client that has never seen the installed
    /// issuer cannot verify a leaf renewed under it.
    #[test]
    fn a_caller_that_has_not_seen_the_installed_issuer_is_not_current() {
        let mut state = state();
        let peer = peer();
        let current = request(&state, &peer);

        let (_, issuer_key) = generate_ml_dsa_87_keypair().expect("keygen");
        state.issuer = Some(aether::certificates::state::AstraIssuerState {
            issuer_epoch: 4,
            authorization: aether::certificates::authority::AstraIssuerAuthorization {
                format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: state.trust_domain_id,
                ca_epoch: 1,
                ca_tls_epoch: 2,
                gateway_wg_public_key: state.gateway.gateway_wg_public_key,
                server_name: state.gateway.server_name.clone(),
                issuer_epoch: 4,
                pq_issuer_public_key: issuer_key,
                tls_intermediate_certificate: DerCertificate::new(vec![3; 64]).expect("der"),
                allowed_usage:
                    aether::certificates::authority::AllowedUsage::AdmittedClientLeafRenewal,
                maximum_leaf_lifetime_secs: 100,
                policy_fingerprint: Fingerprint::of(b"policy"),
                not_before: 0,
                not_after: 1_000_000,
                ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
            },
            state: aether::certificates::state::IssuerLifecycle::Active,
        });

        assert!(!caller_is_current(&state, &peer, &current).expect("comparison"));
    }
}
