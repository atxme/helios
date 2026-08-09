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

use std::path::PathBuf;
use std::sync::Arc;

use aether::certificates::client::GatewayCertificateStageReceipt;
use aether::certificates::{encoding::WireGuardKey, CertificateError};
use anyhow::{Context, Result};
use async_trait::async_trait;
use helios_api::certificates::{
    StageCommitRequest, TrustUpdateHandler, TrustUpdateRefusal, TrustUpdateResponse,
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
        let gateway_pq = state
            .gateway
            .active_pq_fingerprint()
            .map_err(|_| TrustUpdateRefusal::Internal)?;

        // What the caller declared it holds, against what this gateway serves.
        let current = request
            .request
            .active_gateway_certificate_fingerprint
            .matches(&gateway_pq)
            && request
                .request
                .active_gateway_tls_certificate_fingerprint
                .matches(&state.gateway.active_tls_fingerprint())
            && request.request.ca_epoch == state.gateway.ca_epoch
            && request.request.ca_tls_epoch == state.client_tls_ca.ca_tls_epoch
            && request.request.gateway_decision_epoch == state.gateway.gateway_decision_epoch
            && request.request.client_identity_generation == peer.state.active.generation;

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

    async fn stage(
        &self,
        caller_wg_public_key: &str,
        authorization: Box<aether::certificates::client::ClientCertificateStageAuthorization>,
    ) -> Result<Box<aether::certificates::client::GatewayCertificateStageReceipt>, TrustUpdateRefusal>
    {
        let caller =
            WireGuardKey::parse(caller_wg_public_key).map_err(|_| TrustUpdateRefusal::Rejected)?;
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let receipt = registry
            .stage(&caller, &authorization, now)
            .map_err(|error| {
                tracing::warn!(peer = %caller_wg_public_key, %error, "staging refused");
                classify(error)
            })?;
        // The candidate is on disk and synced by now: `stage` writes before it
        // returns, which is what makes this signature a statement about a fact
        // rather than an intention.
        let receipt = self
            .signer
            .sign_stage_receipt(receipt)
            .map_err(|_| TrustUpdateRefusal::Internal)?;
        Ok(Box::new(receipt))
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
