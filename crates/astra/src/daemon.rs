//! Everything `astra run` brings up, and the tasks it leaves running.
//!
//! One entry point, `run`, which returns when the public endpoint or the door
//! socket fails, or when the process is asked to stop: the volume lock first,
//! then the pinned channel, then the registry and the secrets a served
//! authority needs, then the listener the gateway dials, then the runtime
//! that carries the public endpoint, the door's local socket, the
//! reconciliation repair and the sweep of expired anchor transitions.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};

use aether::certificates::encoding::Fingerprint;
use anyhow::{Context, Result};
use astra::registry::{AstraRegistry, ChallengeStore};
use astra::service::{AstraService, SourceBudget, MAX_LIVE_CHALLENGES};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::private_channel::{open_gateway_channel, private_listener};
use crate::{now_unix, REGISTRY_FILE, SERVICE_KEY_FILE};

/// Private material of one delegation, addressed by its epoch.
///
/// Epoch-addressed rather than fixed: `issuer request` writes the keys of the
/// **next** delegation while the current one is still signing, and the
/// registry names the epoch that is installed. An interrupted authorization
/// therefore leaves an unreferenced pair of files and a working issuer, rather
/// than a live delegation whose keys were overwritten by a candidate nobody
/// signed.
const OPERATIONS_FILE: &str = "client-renewal-operations.json";
/// The signed credential decisions of the domain, as the companion emits them.
///
/// Copied into Astra's state volume by an operator (spec §8.2 would carry it,
/// and answers `501`). It holds no secret: every row is public and signed by
/// `CA-PQ`, which is why it can travel by hand at all.
const CREDENTIALS_FILE: &str = "astra-credentials.json";
/// Largest credential document read, in bytes.
const MAX_CREDENTIALS_BYTES: u64 = 1024 * 1024;
/// The encrypted authority vault, as the companion wrote it.
///
/// Astra transports and backs it up; it does not open it, and nothing in this
/// container can — the key-slots unwrap under a FIDO2 `hmac-secret` output
/// that never leaves the operator's token. Copied in by an operator, exactly
/// like the credential document.
const VAULT_FILE: &str = "authority-vault.json";
/// Largest vault file read, in bytes.
///
/// The same ceiling the companion applies to its own copy: a file larger than
/// this is not a vault with more key-slots, it is a mistake or a wedge.
const MAX_VAULT_BYTES: u64 = 4 * 1024 * 1024;
/// How often anchor transitions past their window are forgotten.
///
/// Two seconds, the period of the campaign inbox drain this sweep used to
/// share a loop with.
const TRANSITION_SWEEP_INTERVAL_SECS: u64 = 2;

pub(crate) fn run(
    state_dir: &Path,
    bind: SocketAddr,
    expected_audit_head: Option<&str>,
    gateway_channel: Option<SocketAddr>,
    gateway_certificate: Option<&str>,
    private_bind: Option<SocketAddr>,
    gateway_client_certificate: Option<&str>,
) -> Result<()> {
    // First of all, and held until this function returns, which is the end of
    // the process: from here on this service is the only writer of the volume
    // (§5.9). Taken before anything is read, so that a service started while
    // a console holds the volume touches nothing and says why.
    let _volume = astra::door::VolumeLock::try_acquire(state_dir)
        .with_context(|| {
            format!(
                "locking {}",
                state_dir.join(astra::door::VOLUME_LOCK_FILE).display()
            )
        })?
        .with_context(|| {
            format!(
                "un autre processus tient {} : rien n'a démarré",
                state_dir.display()
            )
        })?;
    // Before the registry is touched: a mispinned channel is a deployment
    // error, and reporting it after "Astra ready" buries it under a success.
    let gateway = open_gateway_channel(state_dir, gateway_channel, gateway_certificate)?;
    let expected = expected_audit_head
        .map(Fingerprint::parse_hex)
        .transpose()
        .context("reading the expected audit head")?;
    let registry = AstraRegistry::load_allowing_unattended_tail(
        &state_dir.join(REGISTRY_FILE),
        expected.as_ref(),
    )
    .context("loading the Astra registry")?;
    let service_private_key = Zeroizing::new(
        std::fs::read(state_dir.join(SERVICE_KEY_FILE)).context("reading the Astra service key")?,
    );

    tracing::info!(
        domain = %registry.state().trust_domain_id,
        gateway = %registry.state().gateway_wg_public_key,
        audit_head = %registry.audit_head(),
        peers = registry.state().peers.len(),
        "Astra ready"
    );

    let issuer = astra::issuer::load_from_registry(state_dir, &registry)?;
    let (ids, epoch, credential_registry) = load_approval_credentials(state_dir, &registry)?;
    let service_public_key = registry.state().astra_service_public_key.clone();
    let operations =
        astra::operations::OperationStore::load(&state_dir.join(OPERATIONS_FILE), now_unix())
            .context("loading the client renewal operations")?;
    let encrypted_vault = load_encrypted_vault(state_dir)?;
    let service = Arc::new(AstraService {
        state_dir: state_dir.to_path_buf(),
        registry: Mutex::new(registry),
        issuer: RwLock::new(issuer.map(Arc::new)),
        challenges: Mutex::new(ChallengeStore::with_capacity(MAX_LIVE_CHALLENGES)),
        budgets: Mutex::new(SourceBudget::default()),
        service_private_key,
        service_public_key,
        operations: Mutex::new(operations),
        capabilities: Mutex::new(
            aether::certificates::capability::CapabilityTokens::new()
                .context("drawing the capability key")?,
        ),
        approval_credentials: RwLock::new(Arc::new(astra::service::ApprovalCredentials {
            ids,
            epoch,
            registry: credential_registry,
        })),
        signing: Mutex::new(astra::signing::SigningOperationStore::new()),
        recoveries: Mutex::new(astra::recovery::RecoveryStore::new()),
        reconciliation: Mutex::new(()),
        encrypted_vault: RwLock::new(encrypted_vault.map(Arc::new)),
        gateway,
        volume_writes: astra::door::VolumeWrites::new(),
    });

    // Built before the runtime, and fatal when unusable: a listener whose pin
    // does not load is an operator error, and finding it at the first renewal
    // is finding it at the one moment there is no fallback.
    let private = private_listener(state_dir, private_bind, gateway_client_certificate)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the Astra runtime")?;
    runtime.block_on(async move {
        if let Some((bind, config)) = private {
            // Its own task, and its failure is never the public endpoint's:
            // a gateway that cannot relay a renewal is a degraded authority,
            // not a dead one.
            let router = astra::renewal::router::router(service.clone());
            tokio::spawn(async move {
                if let Err(error) =
                    astra_channel::serve(bind, config, router, astra_channel::ASTRA_INTERNAL_PREFIX)
                        .await
                {
                    tracing::error!(
                        %bind, %error,
                        "the private renewal listener never came up; the gateway will answer 503 \
                         to every client renewal"
                    );
                }
            });
        }
        spawn_reconciliation_repair(service.clone());
        spawn_transition_sweep(service.clone());
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .with_context(|| format!("binding {bind}"))?;
        tracing::info!(%bind, "Astra public endpoint listening");
        let socket = state_dir.join(astra::door::DOOR_SOCKET_FILE);
        // Three ways out, and each ends the process. The door is fatal like
        // the public endpoint: a service the console cannot reach opens
        // nothing, and refusing to start says so where an operator looks. A
        // stop request ends both; dropping the door's future removes its
        // socket, while this process still holds the volume.
        tokio::select! {
            served = axum::serve(
                listener,
                astra::service::router(service.clone())
                    .into_make_service_with_connect_info::<SocketAddr>(),
            ) => served.context("serving the Astra public endpoint"),
            served = astra::door::local::serve(&socket, service) => {
                served.context("serving Astra's door on its local socket")
            }
            stopped = shutdown_signal() => {
                stopped?;
                tracing::info!("Astra stopping");
                Ok(())
            }
        }
    })
}

/// Waits for `SIGTERM` (a container stop) or `SIGINT`.
async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing the SIGTERM handler")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("waiting for SIGINT"),
        signal = terminate.recv() => {
            anyhow::ensure!(signal.is_some(), "the SIGTERM handler closed unexpectedly");
            Ok(())
        }
    }
}

/// Reads the encrypted vault, if an operator has copied one into the volume.
///
/// The bytes are kept exactly as written and never parsed: Astra serves them
/// to a companion that holds the key-slots, and a value it had opinions about
/// would be a value it could substitute. Its fingerprint is what the signed
/// `AstraSignerRequest` names, so a wrong file is refused by the companion —
/// not by this read.
///
/// Absent is a supported state, and the ordinary one: only a ceremony that
/// makes a master key sign needs it. Saying so at start-up beats discovering
/// it in the middle of a ceremony.
fn load_encrypted_vault(state_dir: &Path) -> Result<Option<Vec<u8>>> {
    let path = state_dir.join(VAULT_FILE);
    let Ok(metadata) = std::fs::metadata(&path) else {
        tracing::info!(
            path = %path.display(),
            "no encrypted vault in the state volume: anchor rotations and revocations are \
             refused by name; every other scope is unaffected"
        );
        return Ok(None);
    };
    if metadata.len() > MAX_VAULT_BYTES {
        anyhow::bail!(
            "{} is {} bytes, over the {MAX_VAULT_BYTES}-byte ceiling: this is not a vault",
            path.display(),
            metadata.len()
        );
    }
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let fingerprint = Fingerprint::of(&bytes);
    tracing::info!(
        path = %path.display(),
        vault_sha256 = %fingerprint,
        bytes = bytes.len(),
        "encrypted vault held for the companion — this process cannot open it"
    );
    Ok(Some(bytes))
}

/// Finishes recoveries whose promotions this authority never adopted.
///
/// The intent is written before the gateway is asked to promote and cleared
/// once this registry has caught up (see [`astra::reconciliation`]). A crash
/// in between leaves it on disk, and this is what closes it: one read of the
/// gateway per pending peer, forward-only, at the start that follows.
///
/// Its own task, and never fatal. A gateway that is not answering yet is the
/// ordinary case at boot, and refusing to serve over an adoption that the next
/// client contact would make anyway would turn a bookkeeping lag into an
/// outage.
fn spawn_reconciliation_repair(service: std::sync::Arc<astra::service::AstraService>) {
    tokio::spawn(async move {
        let intents = {
            let _reconciliation = service.reconciliation.lock().await;
            match astra::reconciliation::load(&service.state_dir) {
                Ok(intents) => intents,
                Err(error) => {
                    tracing::warn!(%error, "the pending reconciliation could not be read");
                    return;
                }
            }
        };
        for intent in intents {
            match astra::recovery::reconcile(
                &service,
                &intent.peer,
                intent.expected_generation,
                now_unix(),
            )
            .await
            {
                Ok(true) => tracing::info!(
                    peer = %intent.peer,
                    generation = intent.expected_generation,
                    "a recovery reconciliation interrupted at commit is now closed"
                ),
                Ok(false) => tracing::info!(
                    peer = %intent.peer,
                    generation = intent.expected_generation,
                    "the gateway has not promoted this recovered generation yet; it will be \
                     adopted at the next contact"
                ),
                Err(error) => tracing::warn!(
                    peer = %intent.peer,
                    %error,
                    "the interrupted recovery could not be adopted at start"
                ),
            }
        }
    });
}

/// Forgets anchor transitions that can no longer authorize anything.
///
/// Its own loop, on its own interval: a bounded store that only ever grows
/// refuses the next rotation, and it would refuse it during a ceremony.
fn spawn_transition_sweep(service: Arc<AstraService>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            TRANSITION_SWEEP_INTERVAL_SECS,
        ));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match service
                .registry
                .lock()
                .await
                .forget_expired_transitions(now_unix())
            {
                Ok(0) => {}
                Ok(dropped) => tracing::info!(
                    dropped,
                    "anchor transitions past their window forgotten: a peer that never collected \
                     one is repaired by an operator, not by a late delivery"
                ),
                Err(error) => tracing::error!(
                    %error,
                    "could not sweep the expired anchor transitions"
                ),
            }
        }
    });
}

/// The credentials an ordinary renewal may be approved by.
///
/// The document is **verified** here, under the `CA-PQ` the registry already
/// pins and at the registry's own epoch — never trusted for being on disk. A
/// file an operator copied to the wrong host, or one left behind by a previous
/// domain, would otherwise put credential identifiers into a signed approval
/// request that no key can answer.
///
/// Only `active` rows are kept. Naming a lost or revoked credential would ask
/// an operator for a touch the verifier then refuses — a ceremony spent on a
/// refusal, at the one moment there is nobody to ask twice.
///
/// A missing document is not fatal: the authority still serves statuses and
/// still holds the channel. Every ordinary renewal is then refused by name,
/// which is what an incomplete install should look like.
/// What the credential document yields at start-up.
///
/// The identifiers, the epoch they came from, and the document itself — the
/// last because whoever runs an approval verifies it under `CA-PQ`, and an
/// allow-list this process merely asserted would be an allow-list a compromised
/// Astra chooses.
type LoadedCredentials = (
    Vec<Vec<u8>>,
    u64,
    Option<Box<aether::certificates::approval::CredentialRegistry>>,
);

fn load_approval_credentials(
    state_dir: &Path,
    registry: &AstraRegistry,
) -> Result<LoadedCredentials> {
    let path = state_dir.join(CREDENTIALS_FILE);
    let Ok(metadata) = std::fs::metadata(&path) else {
        tracing::warn!(
            path = %path.display(),
            "no credential document: no operator credential can approve a renewal, so every \
             ordinary rotation will be refused until `astra-signer bindings` is copied here"
        );
        return Ok((Vec::new(), registry.state().credential_registry_epoch, None));
    };
    if metadata.len() > MAX_CREDENTIALS_BYTES {
        anyhow::bail!(
            "{} weighs {} bytes: that is not a credential document",
            path.display(),
            metadata.len()
        );
    }
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let document: aether::certificates::approval::CredentialRegistry =
        serde_json::from_slice(&bytes)
            .with_context(|| format!("reading the credential document {}", path.display()))?;

    let state = registry.state();
    document
        .verify(
            &state.ca_public_key,
            &state.trust_domain_id,
            &state.gateway_wg_public_key,
            state.ca_epoch,
            state.credential_registry_epoch,
        )
        .with_context(|| format!("verifying the credential document {}", path.display()))?;

    let approvable: Vec<Vec<u8>> = document
        .approvable()
        .into_iter()
        .map(|binding| binding.credential_id.clone())
        .collect();
    tracing::info!(
        credentials = approvable.len(),
        rows = document.bindings.len(),
        registry_epoch = document.credential_registry_epoch,
        "credential document loaded"
    );
    let epoch = document.credential_registry_epoch;
    Ok((approvable, epoch, Some(Box::new(document))))
}
