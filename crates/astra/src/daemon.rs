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
use astra::service::{
    verify_credentials, AstraService, SourceBudget, CREDENTIALS_FILE, MAX_LIVE_CHALLENGES,
    VAULT_FILE,
};
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
/// Largest credential document read, in bytes.
const MAX_CREDENTIALS_BYTES: u64 = 1024 * 1024;
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
    let mut registry = registry;
    let credentials = startup_credentials(state_dir, &mut registry)?;
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
        approval_credentials: RwLock::new(Arc::new(credentials)),
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
            // Restored on a failed save: otherwise a promotion only memory
            // knows would be adopted into the file and forgotten by a restart.
            match service
                .registry
                .lock()
                .await
                .write_or_restore(|registry| registry.forget_expired_transitions(now_unix()))
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
            // After the promotion, in the same pass; a failure stays pending
            // and is retried at the next one.
            if let Err(error) = adopt_promoted_credentials(&service).await {
                tracing::error!(
                    %error,
                    "could not adopt the rotated credential document; it stays pending"
                );
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
fn load_approval_credentials(
    state_dir: &Path,
    registry: &AstraRegistry,
) -> Result<astra::service::ApprovalCredentials> {
    let path = state_dir.join(CREDENTIALS_FILE);
    let Ok(metadata) = std::fs::metadata(&path) else {
        tracing::warn!(
            path = %path.display(),
            "no credential document: no operator credential can approve a renewal, so every \
             ordinary rotation will be refused until `astra-signer bindings` is copied here"
        );
        return Ok(astra::service::ApprovalCredentials {
            ids: Vec::new(),
            epoch: registry.state().credential_registry_epoch,
            registry: None,
        });
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

    verify_credentials(&document, registry)
        .with_context(|| format!("verifying the credential document {}", path.display()))?;

    let credentials = astra::service::ApprovalCredentials::from_document(Box::new(document));
    tracing::info!(
        credentials = credentials.ids.len(),
        rows = credentials
            .registry
            .as_ref()
            .map_or(0, |document| document.bindings.len()),
        registry_epoch = credentials.epoch,
        "credential document loaded"
    );
    Ok(credentials)
}

/// Writes the credential document where a crash leaves the old file or the new
/// one, durably: the pending copy in the registry is cleared right after, so
/// this must be on disk first.
fn write_credentials_file(
    state_dir: &Path,
    document: &aether::certificates::approval::CredentialRegistry,
) -> Result<()> {
    let path = state_dir.join(CREDENTIALS_FILE);
    let encoded =
        serde_json::to_vec_pretty(document).context("encoding the credential document")?;
    aether::private_file::write_private_atomic(&path, &encoded)
        .with_context(|| format!("writing {}", path.display()))
}

/// Adopts, at start-up, the document a promotion left pending: verify, write
/// the file, then clear the pending copy.
fn adopt_pending_at_start(state_dir: &Path, registry: &mut AstraRegistry) -> Result<()> {
    let Some(document) = registry.state().promoted_credentials.clone() else {
        return Ok(());
    };
    verify_credentials(&document, registry)
        .context("verifying the credential document a promotion left")?;
    write_credentials_file(state_dir, &document)?;
    registry
        .take_promoted_credentials()
        .context("clearing the adopted credential document")?;
    Ok(())
}

/// The credentials to serve at start-up.
///
/// A pending document is adopted first: the file on disk is signed under the
/// previous anchor and would not verify. A failed adoption must not stop the
/// service, because a service that cannot start cannot be repaired without a
/// terminal: it is logged, and when the stale file then fails to load the
/// service starts with no operator credential (every approval refused by
/// name) and the sweep retries. A failure with nothing pending keeps its
/// meaning and still aborts.
fn startup_credentials(
    state_dir: &Path,
    registry: &mut AstraRegistry,
) -> Result<astra::service::ApprovalCredentials> {
    if let Err(error) = adopt_pending_at_start(state_dir, registry) {
        tracing::error!(
            %error,
            "could not adopt the rotated credential document at start; it stays pending"
        );
    }
    match load_approval_credentials(state_dir, registry) {
        Err(error) if registry.state().promoted_credentials.is_some() => {
            tracing::error!(
                %error,
                "the credential file predates the promotion and its document is still                  pending: starting without operator credentials until the sweep adopts it"
            );
            Ok(astra::service::ApprovalCredentials {
                ids: Vec::new(),
                epoch: registry.state().credential_registry_epoch,
                registry: None,
            })
        }
        loaded => loaded,
    }
}

/// Puts the credential document a `CA-PQ` promotion left into service.
///
/// The order is the crash contract: the registry already holds the document
/// (written with the promotion), then the file, then memory, and only then is
/// the pending copy cleared. Replaying any suffix after a restart is harmless.
/// A failed file write keeps the pending copy for the next pass and leaves the
/// previous document serving.
pub(crate) async fn adopt_promoted_credentials(service: &AstraService) -> Result<()> {
    // One critical section for the read, the check, the write and the clear.
    // The file write under it is bounded the way `AstraRegistry::save` already
    // is under this lock, and the sweep is the only adopter, so nothing waits
    // on it for long nor can the pending copy change in between.
    let mut registry = service.registry.lock().await;
    let Some(document) = registry.state().promoted_credentials.clone() else {
        return Ok(());
    };
    verify_credentials(&document, &registry)
        .context("verifying the credential document a promotion left")?;
    // The registry's own epoch is only the bootstrap minimum (nothing here
    // advances it), so the epoch in service is the floor that matters: a
    // rotated document must never walk the allow-list backwards.
    let served = service.approval_credentials().epoch;
    anyhow::ensure!(
        document.credential_registry_epoch >= served,
        "the rotated credential document is at epoch {}, below the {served} in service",
        document.credential_registry_epoch
    );
    write_credentials_file(&service.state_dir, &document)?;
    let credentials = astra::service::ApprovalCredentials::from_document(document);
    let epoch = credentials.epoch;
    *service
        .approval_credentials
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(credentials);
    registry
        .take_promoted_credentials()
        .context("clearing the adopted credential document")?;
    tracing::info!(
        registry_epoch = epoch,
        "rotated credential document adopted"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::approval::CredentialRegistry;
    use aether::certificates::encoding::WireGuardKey;
    use aether::certificates::encoding::{generate_ml_dsa_87_keypair, TrustDomainId};
    use astra::registry::{AstraState, CaPqRotation};

    const DOMAIN: [u8; 16] = [1; 16];
    const GATEWAY: [u8; 32] = [1; 32];

    /// A well-formed COSE key; the document is verified, never asserted with.
    fn cose_key() -> Vec<u8> {
        let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        key.extend_from_slice(&[1; 32]);
        key.extend_from_slice(&[0x22, 0x58, 0x20]);
        key.extend_from_slice(&[2; 32]);
        key
    }

    fn document(ca_private: &[u8], ca_epoch: u64, registry_epoch: u64) -> Box<CredentialRegistry> {
        let binding = aether::certificates::approval::AstraCredentialBinding {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            credential_id: vec![7; 16],
            credential_public_key: cose_key(),
            aaguid: [0; 16],
            trust_domain_id: TrustDomainId::new(DOMAIN).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes(GATEWAY),
            state: aether::certificates::approval::CredentialState::Active,
            credential_epoch: 1,
            credential_registry_epoch: registry_epoch,
            ca_epoch,
            created_at: 500,
            ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        }
        .sign(ca_private)
        .expect("sign");
        Box::new(CredentialRegistry {
            trust_domain_id: TrustDomainId::new(DOMAIN).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes(GATEWAY),
            ca_epoch,
            credential_registry_epoch: registry_epoch,
            bindings: vec![binding],
        })
    }

    fn service(
        state_dir: &Path,
        ca_public: aether::certificates::encoding::MlDsa87PublicKey,
        ca_epoch: u64,
        rotation: Option<CaPqRotation>,
        pending: Option<Box<CredentialRegistry>>,
    ) -> AstraService {
        let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let state = AstraState {
            trust_domain_id: TrustDomainId::new(DOMAIN).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes(GATEWAY),
            server_name: "gateway.example".into(),
            authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: aether::certificates::approval::AstraPolicyPin::new(
                Fingerprint::of(b"policy"),
            )
            .expect("policy pin"),
            credential_registry_epoch: 1,
            ca_epoch,
            ca_public_key: ca_public,
            ca_rotation: rotation,
            ca_tls_epoch: 1,
            ca_tls_fingerprint: None,
            ca_tls_rotation: None,
            astra_service_key_epoch: 1,
            astra_service_public_key: service_public.clone(),
            issuer: None,
            transitions: Vec::new(),
            promoted_credentials: pending,
            peers: Default::default(),
            status_epochs: Default::default(),
            audit: Default::default(),
        };
        AstraService {
            state_dir: state_dir.to_path_buf(),
            registry: Mutex::new(AstraRegistry::new(state_dir.join(REGISTRY_FILE), state)),
            issuer: RwLock::new(None),
            challenges: Mutex::new(ChallengeStore::with_capacity(MAX_LIVE_CHALLENGES)),
            budgets: Mutex::new(SourceBudget::default()),
            service_private_key: service_private,
            service_public_key: service_public,
            operations: Mutex::new(astra::operations::OperationStore::new()),
            capabilities: Mutex::new(
                aether::certificates::capability::CapabilityTokens::new().expect("capability key"),
            ),
            approval_credentials: RwLock::new(Arc::new(
                astra::service::ApprovalCredentials::from_document(Box::new(CredentialRegistry {
                    trust_domain_id: TrustDomainId::new(DOMAIN).expect("domain"),
                    gateway_wg_public_key: WireGuardKey::from_bytes(GATEWAY),
                    ca_epoch: 1,
                    credential_registry_epoch: 1,
                    bindings: Vec::new(),
                })),
            )),
            signing: Mutex::new(astra::signing::SigningOperationStore::new()),
            recoveries: Mutex::new(astra::recovery::RecoveryStore::new()),
            reconciliation: Mutex::new(()),
            encrypted_vault: RwLock::new(None),
            gateway: None,
            volume_writes: astra::door::VolumeWrites::new(),
        }
    }

    #[tokio::test]
    async fn the_overlap_keeps_serving_the_outgoing_document() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (_, next) = generate_ml_dsa_87_keypair().expect("keygen");
        let rotation = CaPqRotation {
            next_ca_epoch: 2,
            next_ca_public_key: next,
            activation_at: 1_000,
            retire_active_at: 5_000,
        };
        let (_, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let service = service(directory.path(), ca_public, 1, Some(rotation), None);

        service
            .registry
            .lock()
            .await
            .forget_expired_transitions(4_999)
            .expect("sweep");
        adopt_promoted_credentials(&service).await.expect("pass");

        assert_eq!(service.approval_credentials().epoch, 1);
        assert!(!directory.path().join(CREDENTIALS_FILE).exists());
    }

    #[tokio::test]
    async fn a_promoted_document_is_written_served_then_cleared() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let rotated = document(&ca_private, 2, 2);
        let service = service(directory.path(), ca_public, 2, None, Some(rotated.clone()));
        // The file is the one the previous anchor signed, and must be replaced.
        std::fs::write(directory.path().join(CREDENTIALS_FILE), b"{}").expect("old file");

        adopt_promoted_credentials(&service).await.expect("adopted");

        assert_eq!(service.approval_credentials().epoch, 2);
        assert_eq!(service.approval_credentials().ids, vec![vec![7; 16]]);
        let written: CredentialRegistry = serde_json::from_slice(
            &std::fs::read(directory.path().join(CREDENTIALS_FILE)).expect("file"),
        )
        .expect("document");
        assert_eq!(written, *rotated);
        let mut registry = service.registry.lock().await;
        assert!(registry.state().promoted_credentials.is_none());
        assert!(registry
            .take_promoted_credentials()
            .expect("take")
            .is_none());
    }

    #[tokio::test]
    async fn a_failed_file_write_keeps_the_document_pending_and_the_old_one_serving() {
        let directory = tempfile::tempdir().expect("temp dir");
        let missing = directory.path().join("absent");
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let service = service(
            &missing,
            ca_public,
            2,
            None,
            Some(document(&ca_private, 2, 2)),
        );

        assert!(adopt_promoted_credentials(&service).await.is_err());

        assert_eq!(service.approval_credentials().epoch, 1);
        assert!(service
            .registry
            .lock()
            .await
            .state()
            .promoted_credentials
            .is_some());
    }

    #[tokio::test]
    async fn replaying_an_adoption_is_harmless() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let rotated = document(&ca_private, 2, 2);
        let service = service(directory.path(), ca_public, 2, None, Some(rotated.clone()));
        // A crash after the file write: the file already holds the document.
        write_credentials_file(directory.path(), &rotated).expect("file");

        adopt_promoted_credentials(&service).await.expect("first");
        adopt_promoted_credentials(&service).await.expect("second");

        assert_eq!(service.approval_credentials().epoch, 2);
    }

    fn registry_of(service: AstraService) -> AstraRegistry {
        service.registry.into_inner()
    }

    #[test]
    fn a_pending_document_that_cannot_be_written_does_not_stop_the_start() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut registry = registry_of(service(
            directory.path(),
            ca_public,
            2,
            None,
            Some(document(&ca_private, 2, 2)),
        ));
        // A symlink at the destination makes the atomic write refuse, and the
        // stale file behind it does not parse under the promoted anchor.
        let stale = directory.path().join("stale.json");
        std::fs::write(&stale, b"{}").expect("stale file");
        std::os::unix::fs::symlink(&stale, directory.path().join(CREDENTIALS_FILE))
            .expect("symlink");

        let credentials =
            startup_credentials(directory.path(), &mut registry).expect("service still starts");

        assert!(credentials.ids.is_empty());
        assert!(credentials.registry.is_none());
        assert!(registry.state().promoted_credentials.is_some());
    }

    #[test]
    fn a_pending_document_that_fails_verification_does_not_stop_the_start() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        // Signed for epoch 3 while the registry pins epoch 2.
        let mut registry = registry_of(service(
            directory.path(),
            ca_public,
            2,
            None,
            Some(document(&ca_private, 3, 2)),
        ));
        std::fs::write(directory.path().join(CREDENTIALS_FILE), b"{}").expect("stale file");

        let credentials =
            startup_credentials(directory.path(), &mut registry).expect("service still starts");

        assert!(credentials.registry.is_none());
        assert!(registry.state().promoted_credentials.is_some());
    }

    #[test]
    fn a_broken_file_with_nothing_pending_still_aborts_the_start() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (_, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut registry = registry_of(service(directory.path(), ca_public, 2, None, None));
        std::fs::write(directory.path().join(CREDENTIALS_FILE), b"{}").expect("broken file");

        assert!(startup_credentials(directory.path(), &mut registry).is_err());
    }

    #[test]
    fn a_pending_document_is_adopted_at_start() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut registry = registry_of(service(
            directory.path(),
            ca_public,
            2,
            None,
            Some(document(&ca_private, 2, 2)),
        ));

        let credentials = startup_credentials(directory.path(), &mut registry).expect("start");

        assert_eq!(credentials.epoch, 2);
        assert!(registry.state().promoted_credentials.is_none());
    }

    #[tokio::test]
    async fn a_rotated_document_below_the_served_epoch_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let service = service(
            directory.path(),
            ca_public,
            2,
            None,
            Some(document(&ca_private, 2, 1)),
        );
        *service.approval_credentials.write().expect("lock") =
            Arc::new(astra::service::ApprovalCredentials {
                ids: Vec::new(),
                epoch: 5,
                registry: None,
            });

        assert!(adopt_promoted_credentials(&service).await.is_err());
        assert_eq!(service.approval_credentials().epoch, 5);
    }
}
