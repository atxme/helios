//! Renewing the negotiated PSK in place, inside the tunnel (design
//! 2026-10-09 §3): install, prove by a fresh handshake, commit — or restore
//! the previous slot however the task ends. When to renew is `renewal`'s
//! decision.

use super::*;

/// What a renewal needs from a prepared negotiation.
///
/// Implemented by [`crate::key_negotiation::NegotiatedKey`]; tests substitute
/// a fake to drive the failure and cancellation paths without a gateway.
#[async_trait]
pub(crate) trait PendingRenewal: Send {
    fn psk(&self) -> Option<&aether::SecretString>;
    fn transaction_id(&self) -> [u8; 16];
    fn confirmation_timeout(&self) -> Duration;
    async fn confirm(self: Box<Self>) -> anyhow::Result<()>;
}

#[async_trait]
impl PendingRenewal for crate::key_negotiation::NegotiatedKey {
    fn psk(&self) -> Option<&aether::SecretString> {
        self.psk.as_ref()
    }
    fn transaction_id(&self) -> [u8; 16] {
        crate::key_negotiation::NegotiatedKey::transaction_id(self)
    }
    fn confirmation_timeout(&self) -> Duration {
        self.confirmation_timeout
    }
    async fn confirm(self: Box<Self>) -> anyhow::Result<()> {
        crate::key_negotiation::NegotiatedKey::confirm(*self).await
    }
}

/// Re-registers the previous peer unless disarmed.
///
/// On an error return **and** when the renewal future is dropped mid-way: a
/// cancelled future runs no exit path of its own, so the restore is spawned
/// from `Drop`. Dropping the pending negotiation closes its QUIC session and
/// the gateway restores its own previous slot — both ends land on the old PSK.
///
/// Only while the renewal still owns the data plane: after a connection or a
/// disconnection took it over, re-registering the previous peer would
/// overwrite the newer tunnel with a PSK its gateway slot no longer holds.
struct RestorePrevious {
    backend: Arc<dyn VpnBackend>,
    previous: Option<ClientProfile>,
    sink: EventSink,
    owner: DataPlaneOwner,
}

impl RestorePrevious {
    fn disarm(mut self) {
        self.previous = None;
    }
}

impl Drop for RestorePrevious {
    fn drop(&mut self) {
        let Some(previous) = self.previous.take() else {
            return;
        };
        let backend = Arc::clone(&self.backend);
        let sink = Arc::clone(&self.sink);
        let owner = self.owner.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    if !owner.still_held() {
                        tracing::info!(
                            "renewal rollback skipped: a connection or a disconnection took the \
                             data plane over meanwhile"
                        );
                        return;
                    }
                    match backend.rekey_peer(&previous, &sink).await {
                        Ok(()) => sink(ClientEvent::log(
                            "warn",
                            "renouvellement non abouti : l'ancienne clé post-quantique est remise en place"
                                .to_string(),
                        )),
                        Err(error) => sink(ClientEvent::log(
                            "error",
                            format!(
                                "renouvellement non abouti et ancienne clé post-quantique non remise en place \
                                 ({error:#}) : la reconnexion automatique prendra le relais"
                            ),
                        )),
                    }
                });
            }
            Err(_) => {
                tracing::error!("renewal rollback: no runtime left to restore the previous peer");
            }
        }
    }
}

/// Installs a renewed PSK by re-registering the peer, proves it with a fresh
/// handshake, then commits (design 2026-10-09 §3).
pub(super) async fn renew_slot(
    backend: &Arc<dyn VpnBackend>,
    current: &InstalledNegotiation,
    pending: Box<dyn PendingRenewal>,
    sink: &EventSink,
    owner: DataPlaneOwner,
) -> anyhow::Result<InstalledNegotiation> {
    if !owner.still_held() {
        anyhow::bail!("a connection or a disconnection took the tunnel over before the renewal");
    }
    let psk = pending
        .psk()
        .context("an in-tunnel renewal must derive an ml_kem PSK")?
        .duplicate();
    let renewed = ClientProfile {
        preshared_key: Some(psk),
        preshared_key_is_negotiated: true,
        ..current.data_plane.duplicate()
    };
    let timeout = pending.confirmation_timeout();
    let transaction_id = pending.transaction_id();
    let prepared_at = tokio::time::Instant::now();
    let restore = RestorePrevious {
        backend: Arc::clone(backend),
        previous: Some(current.data_plane.duplicate()),
        sink: Arc::clone(sink),
        owner,
    };
    backend
        .rekey_peer(&renewed, sink)
        .await
        .context("re-registering the peer with the renewed PSK")?;
    if !wait_for_new_handshake(backend, prepared_at, timeout).await {
        anyhow::bail!(
            "no WireGuard handshake with the renewed PSK within {} s",
            timeout.as_secs()
        );
    }
    pending.confirm().await.context("confirming the renewal")?;
    restore.disarm();
    Ok(InstalledNegotiation::new(
        transaction_id,
        current.profile.duplicate(),
        renewed,
        backend.transfer_bytes().await,
    ))
}

/// Applies a renewal outcome to the receipt it started from — and only to it.
pub(super) fn settle_renewal(
    slot: &mut Option<InstalledNegotiation>,
    renewed_from: [u8; 16],
    outcome: anyhow::Result<InstalledNegotiation>,
    sink: &EventSink,
) {
    // A disconnection or a reconnection meanwhile owns the slot now.
    let Some(receipt) = slot
        .as_mut()
        .filter(|receipt| receipt.transaction_id == renewed_from)
    else {
        return;
    };
    match outcome {
        Ok(renewed) => {
            *receipt = renewed;
            sink(ClientEvent::protection(PskKind::MlKem));
            sink(ClientEvent::log(
                "info",
                "clé post-quantique renouvelée — nouvelle clé ML-KEM en place, durée et volume \
                 remis à zéro"
                    .to_string(),
            ));
        }
        Err(error) => {
            receipt.failures = receipt.failures.saturating_add(1);
            let delay = renewal::retry_delay(receipt.failures);
            receipt.next_attempt = Some(std::time::Instant::now() + delay);
            sink(ClientEvent::log(
                "warn",
                format!(
                    "renouvellement de la clé post-quantique : échec — {error:#}. Nouvel essai dans \
                     {} min ; l'ancienne clé reste en place jusqu'à son échéance.",
                    delay.as_secs() / 60
                ),
            ));
        }
    }
}

pub(super) async fn run_renewal(
    backend: &Arc<dyn VpnBackend>,
    identities: &dyn crate::key_negotiation::IdentityProvider,
    installed: &Mutex<Option<InstalledNegotiation>>,
    trigger: renewal::RenewalTrigger,
    sink: &EventSink,
    owner: DataPlaneOwner,
) {
    let Some(current) = installed
        .lock()
        .await
        .as_ref()
        .map(InstalledNegotiation::duplicate)
    else {
        return;
    };
    sink(ClientEvent::log(
        "info",
        format!(
            "renouvellement de la clé post-quantique déclenché ({}) — négociation ML-KEM dans \
             le tunnel",
            trigger.describe()
        ),
    ));
    let outcome = async {
        let negotiated =
            crate::key_negotiation::prepare_renewal_for_profile(&current.profile, identities)
                .await?;
        renew_slot(backend, &current, Box::new(negotiated), sink, owner).await
    }
    .await;
    settle_renewal(
        &mut *installed.lock().await,
        current.transaction_id,
        outcome,
        sink,
    );
}
