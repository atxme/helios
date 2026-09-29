//! The daemon itself: everything `heliosd run` brings up, in order.
//!
//! One entry point, `run`, which is the gateway's whole lifecycle — process
//! protection, uplink, TPM unseal, sealed identity, channels, API, speedtest,
//! then the orchestrator it hands control to.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use aether::{
    HeliosEvent, InstallPskRequest, NetworkConfig, ObserveHandshakeRequest, OrchestratorCmd,
    TunnelState, API_BIND_LOOPBACK,
};
use anyhow::Context;
use helios_api::AppState;
use helios_tpm::{BootController, BootDecision, TpmSettings};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{error, info, warn};

use crate::commands::wan::resolve_uplink;
use crate::process_guards::forbid_core_dumps;
use crate::{astra_channel, certificates, gateway_key, gateway_rotation, key_negotiation};
use crate::{orchestrator, static_psk};

/// Number of API listen attempts before giving up.
///
/// The listening address belongs to the WireGuard interface, created by the
/// orchestrator after the server starts: the first attempts necessarily
/// fail. The bound avoids an infinite loop if the address never comes —
/// a misconfiguration must stay visible, not be masked by silent retries.
const API_BIND_ATTEMPTS: u32 = 20;

/// Wait between two API listen attempts.
const API_BIND_DELAY: std::time::Duration = std::time::Duration::from_millis(500);
/// Cadence at which the raw speedtest keeps trying to bind, past the burst.
///
/// Thirty seconds: slow enough that a lasting conflict costs nothing, quick
/// enough that freeing the port brings the service back before an operator has
/// finished reading why it was gone.
const RAW_SPEEDTEST_RETRY: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) async fn run(
    mut network: NetworkConfig,
    dry_run: bool,
    firewall_mode: orchestrator::FirewallMode,
) -> anyhow::Result<()> {
    // Before the TPM unseal below, which is where the first key appears.
    forbid_core_dumps(dry_run)?;

    // The uplink, before any ruleset is built: every egress rule and the
    // masquerade are bound to this name, and resolving it later would mean
    // building the kill-switch around an interface we had not chosen yet.
    resolve_uplink(&mut network)?;

    // The guard that used to stand here — refusing to start when
    // `key_negotiation_port` was set on a binary built without the feature —
    // no longer has a case to catch: every heliosd serves that port. The
    // setting alone decides whether it opens.

    // TPM integrity validation — BEFORE any network access.
    let tpm = TpmSettings::default();
    let boot = BootController::unlock(&tpm)
        .map_err(|e| anyhow::anyhow!("TPM unsealing failed — stopping: {e}"))?;
    match &boot {
        BootDecision::Disabled => {}
        BootDecision::Bypassed => warn!("TPM integrity not verified (enforce=false)"),
        BootDecision::Unsealed(_) => info!("boot integrity confirmed (TPM)"),
        BootDecision::Provisioned(_) => warn!("first boot: TOFU provisioning performed"),
        BootDecision::Resealed(_) => warn!("post-OTA resealing performed (valid ticket)"),
        // Not a warning, unlike the line above it: the window preserved the
        // secret, so the vaults open and nothing has to be re-supplied. The
        // two decisions look alike and mean opposite things.
        BootDecision::WindowResealed(_) => info!(
            "update window consumed: the PCRs moved (OS upgrade) and the same secret \
             was resealed on the new state — vaults intact"
        ),
    }
    // The WireGuard private key comes from the sealed TPM vault, not from
    // network.toml. See `gateway_key`: in the clear on disk, it would be
    // enough to impersonate the gateway. The config now only carries a
    // possible legacy fallback.
    let mut network = network;
    let resolved = gateway_key::resolve(&network, &boot);
    match resolved.origin {
        gateway_key::KeyOrigin::Sealed => {}
        gateway_key::KeyOrigin::Recovered => warn!(
            "identity restored from escrow after a PCR change — \
             check that the recovery file was indeed erased"
        ),
        gateway_key::KeyOrigin::PlaintextConfig => warn!(
            "gateway identity in the clear on disk — seal the key then remove \
             `wg_private_key` from network.toml"
        ),
        gateway_key::KeyOrigin::Missing => warn!(
            "no WireGuard private key: the gateway starts fail-closed without \
             bringing up an interface. Provide a key (POST /api/gateway/wireguard-key)."
        ),
    }
    // A move, not a copy: both sides are a `SecretString`, so the buffer the
    // vault produced *becomes* the runtime one. `NetworkConfig` is the shared
    // state the data plane and the negotiation read from, and keeping the
    // gateway identity there is the limitation ADR-006 §5 declares.
    network.wg_private_key = resolved.private_key;

    // Static PSKs move out of `network.toml` and into the sealed table
    // (ADR-006 §4). The value is moved, not dropped: the running config is
    // refilled from the table, because the data plane reads it and a peer
    // without its PSK fails every handshake with no recovery channel.
    //
    // Not fatal when it cannot be read: `Undecipherable` means the identity
    // changed without the table being re-wrapped, and the ADR forbids both
    // starting without the PSK and falling back to classic mode. So the
    // affected peers keep no PSK and stay unable to handshake, which is the
    // fail-closed outcome — announced loudly rather than silently degraded.
    if !network.wg_private_key.is_empty() {
        let table = static_psk::default_path();
        // A copy, because `adopt_from_config` needs `&mut network` and the
        // identity at the same time. Named, and wiped when this block ends.
        let identity = network.wg_private_key.duplicate();
        match static_psk::adopt_from_config(&mut network, &table, identity.expose()) {
            Ok(0) => {}
            Ok(adopted) => warn!(
                adopted,
                "PSK statiques repris de network.toml vers la table scellée — \
                 `preshared_key` retiré du fichier"
            ),
            Err(error) => error!(
                %error,
                "table des PSK statiques inutilisable — les pairs concernés resteront \
                 sans PSK et ne pourront pas établir de handshake"
            ),
        }
    }

    let (event_tx, _) = broadcast::channel::<HeliosEvent>(256);
    let (cmd_tx, cmd_rx) = mpsc::channel::<OrchestratorCmd>(32);
    // Dedicated provisioning channel: it carries a secret and awaits an
    // acknowledgment, unlike the UI order flow.
    let (psk_tx, psk_rx) = mpsc::channel::<InstallPskRequest>(8);
    // Read-only counterpart, for the one decision that cannot use the
    // ten-second peer snapshot: proving a WireGuard handshake at the commit.
    let (handshake_tx, handshake_rx) = mpsc::channel::<ObserveHandshakeRequest>(8);
    let tunnel_state = Arc::new(RwLock::new(TunnelState::Down));
    let shared_network = Arc::new(RwLock::new(network));
    let shared_policy = Arc::new(RwLock::new(shared_network.read().await.firewall_policy()));

    // The API listens on the tunnel's address: this is how Orion clients
    // reach provisioning and telemetry. Filtering is still enforced by the
    // firewall (`admin_iface`), not by the bind address.
    // A simulation does not actually create the WireGuard address. It
    // therefore only listens locally, which makes manual testing possible
    // without exposing the development API on the machine's network.
    let api_bind = if dry_run {
        API_BIND_LOOPBACK.to_string()
    } else {
        shared_network.read().await.api_bind()
    };
    let raw_speedtest_bind = if dry_run {
        format!("127.0.0.1:{}", aether::SPEEDTEST_PORT)
    } else {
        shared_network.read().await.speedtest_bind()
    };
    info!("web interface on http://{api_bind}");
    info!("raw speedtest on {raw_speedtest_bind} (WireGuard TCP/UDP)");

    #[allow(unused_mut)]
    let mut state = AppState::new(
        Arc::clone(&shared_network),
        dry_run,
        Arc::clone(&tunnel_state),
        event_tx.clone(),
        cmd_tx,
        psk_tx.clone(),
        Arc::clone(&shared_policy),
    );
    // The sealing posture, as two non-secret facts. `boot` itself is moved
    // into the orchestrator below — it holds the unlock secret, and only the
    // orchestrator may seal.
    state = state.with_tpm(boot.kind(), boot.preserved_vaults());
    // Started here rather than earlier because the reclamation loop reads the
    // same data-plane snapshot the console does, and that snapshot is owned
    // by `AppState`. Polling the backend a second time would risk the two
    // readers disagreeing on whether a peer is still there — and the whole
    // point of v5's liveness is that there is one answer, read where the
    // traffic is.
    // Opened once, and shared. The negotiation *reads* it — a caller resolved
    // by the fingerprint mTLS proved has to be looked up in the thing that
    // recorded the last rotation, not in a file written at admission — while
    // the lifecycle service below is its single writer. Two `CertificateRegistry`
    // values over one path would be two writers of one slot.
    let registry = match certificates::open_registry(
        &helios_provisioning::certificates::CertificateRegistry::path(),
    ) {
        Ok(registry) => registry,
        Err(error) => {
            error!(
                %error,
                "certificate registry unusable — the in-tunnel lifecycle routes stay closed and \
                 the negotiation falls back to the pins of network.toml"
            );
            None
        }
    };
    if let Some(registry) = &registry {
        let mut registry = registry.lock().await;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock predates the Unix epoch")?
            .as_secs();
        if gateway_rotation::maintain_gateway_identity(&mut registry, boot.secret(), now_unix)
            .context("reconciling the scheduled gateway identity before startup")?
        {
            info!("gateway identity promoted and sealed slots synchronized");
        }
    }
    if let Some(handler) = key_negotiation::start(
        Arc::clone(&shared_network),
        psk_tx.clone(),
        handshake_tx,
        Arc::clone(&state.peer_runtime),
        registry.clone(),
        &boot,
        dry_run,
    )
    .await?
    {
        // The certificate lifecycle, when this gateway has a trust domain. It
        // signs its receipts through the negotiation handler — the same leaf
        // the client already pins, unsealed once — and it is the single owner
        // of the registry: a second one would give one slot two writers.
        // Built before the service, and shared with it: the same veth client
        // serves the four renewal routes and the trust-update producer, and a
        // second one would open a second connection to say the same thing.
        let authority = astra_channel::relay().map(Arc::new);
        let gateway_identity_secret = boot.secret().cloned();
        match registry.map(|registry| {
            let service = certificates::CertificateService::new(
                registry,
                Arc::clone(&handler) as Arc<dyn certificates::StageReceiptSigner>,
            )
            .with_gateway_identity_secret(gateway_identity_secret);
            Arc::new(match &authority {
                Some(relay) => service.with_authority(
                    Arc::clone(relay) as Arc<dyn ::astra_channel::TrustUpdatePreparer>
                ),
                None => service,
            })
        }) {
            Some(service) => {
                info!("certificate lifecycle ready");
                certificates::spawn_maintenance(Arc::clone(&service));
                // Admissions made on the console, in another process: it may
                // only leave the two public leaves in an inbox, because this
                // task is the single owner of the registry. Drained here, and
                // at every start — an admission made while the daemon was down
                // is recorded when it comes back.
                certificates::spawn_admission_drain(
                    Arc::clone(&service),
                    helios_provisioning::certificates::CertificateRegistry::path(),
                );
                // The private veth listener, on its own socket. Never a path
                // on the administration API: two listeners make "Astra may
                // not admit a peer" a fact about which socket the packet
                // arrived on, rather than about middleware ordering.
                astra_channel::spawn(
                    Arc::clone(&service) as Arc<dyn ::astra_channel::AstraChannelHandler>
                );
                // And the other direction: the four in-tunnel renewal routes
                // relay into Astra's own listener. Separate from the trust
                // update on purpose — a gateway may hold a registry and have
                // no way to dial the authority, and in that state the
                // trust-update route must keep working while the renewal
                // routes report the authority unreachable.
                if let Some(relay) = authority {
                    // The same relay on both surfaces: one veth client, two
                    // stores at the far end. The operator routes sit behind
                    // `require_admin` rather than `require_peer` (spec §8.5),
                    // which is what keeps a campaign out of reach of an
                    // ordinary admitted peer.
                    state = state.with_operator_campaign(Arc::clone(&relay)
                        as Arc<dyn helios_api::certificates::OperatorCampaignRelay>);
                    state = state.with_client_renewal(relay);
                }
                // The same service, on two surfaces: the lifecycle screen
                // reads through `trust_update`, and its four gestures go
                // through `gateway_identity`. One instance, because both
                // mutate the registry this task owns.
                state = state.with_gateway_identity(Arc::clone(&service)
                    as Arc<dyn helios_api::certificates::GatewayIdentityHandler>);
                state = state.with_trust_update(service);
            }
            None => info!(
                "no certificate registry: the trust domain is not bootstrapped, and the \
                 in-tunnel lifecycle routes stay closed"
            ),
        }
        // The in-tunnel `release` (spec §7.5) reaches the same state machine
        // as the public negotiation, through the same per-peer serializer.
        // A second instance here would give one slot two writers.
        state = state.with_psk_release(handler);
    }
    // Published for the operator tooling: `helios-ctl` builds a complete
    // Orion profile from the gateway rather than making the operator copy
    // certificates out of /var/lib/helios by hand.
    if let Some(material) = key_negotiation::public_material()? {
        state = state.with_key_negotiation(material);
    }
    let api_ready = Arc::clone(&state.api_ready);
    // The console reads the data plane through this snapshot; only the
    // orchestrator's poller writes it.
    let peer_runtime = Arc::clone(&state.peer_runtime);
    let api_state = state.clone();
    tokio::spawn(async move {
        // Outside simulation, the API listens on the WireGuard address —
        // which the orchestrator, started right after, has not yet assigned
        // to the interface. The first `bind` therefore fails with "Cannot
        // assign requested address", and without a retry the gateway would
        // run for good without an API: no provisioning, no telemetry, for a
        // race lost by a few dozen milliseconds.
        for attempt in 1..=API_BIND_ATTEMPTS {
            match helios_api::serve(api_state.clone(), &api_bind).await {
                Ok(()) => return,
                Err(e) if attempt < API_BIND_ATTEMPTS => {
                    warn!(
                        "API server unavailable (attempt {attempt}/{API_BIND_ATTEMPTS}), \
                         retrying: {e:#}"
                    );
                    tokio::time::sleep(API_BIND_DELAY).await;
                }
                Err(e) => {
                    tracing::error!(
                        "API server given up after {API_BIND_ATTEMPTS} attempts: {e:#}"
                    );
                }
            }
        }
    });

    let raw_speedtest_state = state.clone();
    let raw_speedtest_shutdown = Arc::new(AtomicBool::new(false));
    let raw_speedtest_task_shutdown = Arc::clone(&raw_speedtest_shutdown);
    tokio::spawn(async move {
        // It never gives up, and that is the point. The tunnel address appears
        // when WireGuard comes up, so the first binds legitimately fail — that
        // is what the fast burst is for. But the port can also be held by
        // **another program**, and that is not transient: `iperf3` listening on
        // a wildcard listener wins the port and keeps it, and a gateway that
        // stopped trying after ten seconds served no speedtest until someone
        // restarted the daemon. Worse, it said so once, in a line long gone by
        // the time a client reports « connexion fermée par l'hôte ».
        //
        // So after the burst it keeps retrying slowly, and logs only when the
        // situation *changes* — a conflict that persists for a day is one line,
        // not a hundred and seventy thousand.
        let mut attempt: u32 = 0;
        let mut reported: Option<String> = None;
        loop {
            attempt = attempt.saturating_add(1);
            match helios_api::speedtest::serve_raw(
                raw_speedtest_state.clone(),
                &raw_speedtest_bind,
                Arc::clone(&raw_speedtest_task_shutdown),
            )
            .await
            {
                Ok(()) => return,
                Err(error) => {
                    let reason = format!("{error:#}");
                    if attempt < API_BIND_ATTEMPTS {
                        warn!(
                            "raw speedtest unavailable (attempt {attempt}/{API_BIND_ATTEMPTS}), \
                             retrying: {reason}"
                        );
                        tokio::time::sleep(API_BIND_DELAY).await;
                        continue;
                    }
                    if reported.as_deref() != Some(reason.as_str()) {
                        tracing::error!(
                            bind = %raw_speedtest_bind,
                            "raw speedtest still unavailable after {attempt} attempts: {reason}. \
                             A client asking for a speedtest will be told the service is absent. \
                             If the address is in use, another program holds this port — \
                             `ss -lntup | grep {port}` names it, iperf3 on 0.0.0.0 being the \
                             usual one. Retrying every {retry}s.",
                            port = aether::speedtest::SPEEDTEST_PORT,
                            retry = RAW_SPEEDTEST_RETRY.as_secs(),
                        );
                        reported = Some(reason);
                    }
                    tokio::time::sleep(RAW_SPEEDTEST_RETRY).await;
                }
            }
        }
    });

    let result = orchestrator::run(
        shared_network,
        dry_run,
        firewall_mode,
        tunnel_state,
        event_tx,
        cmd_rx,
        psk_rx,
        handshake_rx,
        shared_policy,
        peer_runtime,
        boot,
        api_ready,
    )
    .await;
    raw_speedtest_shutdown.store(true, Ordering::Release);
    result
}
