//! Everything `astra run` brings up, and the two tasks it leaves running.
//!
//! One entry point, `run`, which never returns until the public endpoint
//! does: the pinned channel first, then the registry and the secrets a served
//! authority needs, then the listener the gateway dials, then the runtime that
//! carries the public endpoint, the reconciliation repair and the campaign
//! inbox drain.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aether::certificates::encoding::Fingerprint;
use anyhow::{Context, Result};
use astra::registry::{AstraRegistry, ChallengeStore};
use astra::service::{AstraService, SourceBudget, MAX_LIVE_CHALLENGES};
use astra::DelegatedIssuer;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::campaign_deposit::load_encrypted_vault;
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

pub(crate) fn run(
    state_dir: &Path,
    bind: SocketAddr,
    expected_audit_head: Option<&str>,
    gateway_channel: Option<SocketAddr>,
    gateway_certificate: Option<&str>,
    private_bind: Option<SocketAddr>,
    gateway_client_certificate: Option<&str>,
) -> Result<()> {
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

    let issuer = load_issuer(state_dir, &registry)?;
    let (approval_credential_ids, approval_credential_registry_epoch, approval_credential_registry) =
        load_approval_credentials(state_dir, &registry)?;
    let service_public_key = registry.state().astra_service_public_key.clone();
    let operations =
        astra::operations::OperationStore::load(&state_dir.join(OPERATIONS_FILE), now_unix())
            .context("loading the client renewal operations")?;
    let encrypted_vault = load_encrypted_vault(state_dir)?;
    let service = Arc::new(AstraService {
        state_dir: state_dir.to_path_buf(),
        registry: Mutex::new(registry),
        issuer,
        challenges: Mutex::new(ChallengeStore::with_capacity(MAX_LIVE_CHALLENGES)),
        budgets: Mutex::new(SourceBudget::default()),
        service_private_key,
        service_public_key,
        operations: Mutex::new(operations),
        capabilities: Mutex::new(
            aether::certificates::capability::CapabilityTokens::new()
                .context("drawing the capability key")?,
        ),
        approval_credential_ids,
        approval_credential_registry_epoch,
        approval_credential_registry,
        signing: Mutex::new(astra::signing::SigningOperationStore::new()),
        recoveries: Mutex::new(astra::recovery::RecoveryStore::new()),
        reconciliation: Mutex::new(()),
        encrypted_vault,
        gateway,
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
        spawn_campaign_drain(service.clone(), state_dir.to_path_buf());
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .with_context(|| format!("binding {bind}"))?;
        tracing::info!(%bind, "Astra public endpoint listening");
        axum::serve(
            listener,
            astra::service::router(service).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .context("serving the Astra public endpoint")
    })
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

/// Adopts the campaigns a local operator command deposited.
///
/// The store lives in this process, in memory; `astra campaign open` runs in
/// another one. This is the same arrangement `heliosd` uses for console
/// admissions, and for the same reason: one owner of the state, and a second
/// process that may only leave something for it.
///
/// A deposit that does not verify is **removed**, not retried. It sat between
/// two processes on disk, and re-reading it every two seconds until its window
/// closes would turn one bad file into a log the operator has to scroll past.
fn spawn_campaign_drain(service: Arc<AstraService>, state_dir: PathBuf) {
    tokio::spawn(async move {
        let directory = state_dir.join(astra::signing::CAMPAIGN_INBOX_DIR);
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            astra::signing::INBOX_POLL_INTERVAL_SECS,
        ));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            // Anchor transitions that can no longer authorize anything, on the
            // same tick. A bounded store that only ever grows refuses the next
            // rotation, and it would refuse it during a ceremony.
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
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                    continue;
                }
                match adopt_campaign_file(&service, &path).await {
                    Ok(operation_id) => tracing::info!(
                        %operation_id,
                        "manual campaign adopted; the companion may fetch it"
                    ),
                    Err(error) => tracing::error!(
                        file = %path.display(),
                        %error,
                        "manual campaign refused: nothing was opened, and the operator has to \
                         run `astra campaign open` again"
                    ),
                }
                let _ = std::fs::remove_file(&path);
            }
        }
    });
}

/// Reads one deposit and opens the operation it describes.
async fn adopt_campaign_file(
    service: &Arc<AstraService>,
    path: &Path,
) -> Result<aether::certificates::encoding::Id16> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > astra::signing::MAX_INBOX_ENTRY_BYTES {
        anyhow::bail!("{} bytes: this is not a campaign", metadata.len());
    }
    let bytes = std::fs::read(path)?;
    let deposit: astra::signing::CampaignDeposit =
        serde_json::from_slice(&bytes).context("decoding the campaign")?;
    let (service_public_key, service_key_epoch, authority_url) = {
        let registry = service.registry.lock().await;
        let state = registry.state();
        (
            state.astra_service_public_key.clone(),
            state.astra_service_key_epoch,
            state.authority_url.clone(),
        )
    };
    let mut store = service.signing.lock().await;
    astra::signing::adopt_deposit(
        &mut store,
        deposit,
        &service_public_key,
        service_key_epoch,
        &authority_url,
        now_unix(),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))
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
type ApprovalCredentials = (
    Vec<Vec<u8>>,
    u64,
    Option<Box<aether::certificates::approval::CredentialRegistry>>,
);

fn load_approval_credentials(
    state_dir: &Path,
    registry: &AstraRegistry,
) -> Result<ApprovalCredentials> {
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

/// Builds the delegated issuer, when the domain has one **and** its private
/// material is on disk.
///
/// The three parts are independent on purpose: the authorization is public and
/// travels in the registry, while the two private keys are generated and
/// sealed locally. A registry that names a delegation whose keys are missing is
/// an incomplete install, and it is reported as such — an issuer silently
/// forced to `None` would refuse every ordinary renewal with no explanation,
/// at 80 % of a leaf's life.
fn load_issuer(state_dir: &Path, registry: &AstraRegistry) -> Result<Option<DelegatedIssuer>> {
    let Some(installed) = registry.state().issuer.as_ref() else {
        tracing::warn!(
            "no delegated issuer in the registry: ordinary renewals stay refused until \
             `AstraIssuerAuthorization` is signed by the operator companion"
        );
        return Ok(None);
    };
    let pq_key = astra::issuer::pq_key_path(state_dir, installed.issuer_epoch);
    let tls_key = astra::issuer::tls_key_path(state_dir, installed.issuer_epoch);
    if !pq_key.exists() || !tls_key.exists() {
        tracing::error!(
            issuer_epoch = installed.issuer_epoch,
            pq_key = %pq_key.display(),
            tls_key = %tls_key.display(),
            "the registry names a delegated issuer but its private material is missing: \
             ordinary renewals will be refused"
        );
        return Ok(None);
    }
    let pq_private_key =
        Zeroizing::new(std::fs::read(&pq_key).context("reading the delegated issuer PQ key")?);
    let tls_private_key =
        Zeroizing::new(std::fs::read(&tls_key).context("reading the delegated issuer TLS key")?);
    registry
        .state()
        .astra_policy_fingerprint
        .assert_authorizes(&installed.authorization)
        .context("the delegated issuer does not match the pinned Astra policy")?;
    // Present is not the same as correct: the keys and the delegation come
    // from two different places, and a mismatch would only show up at the
    // first renewal.
    let issuer = DelegatedIssuer::load(
        installed.authorization.clone(),
        pq_private_key,
        tls_private_key,
    )
    .context("checking the delegated issuer's private material against the registry")?;
    tracing::info!(
        issuer_epoch = installed.issuer_epoch,
        not_after = installed.authorization.not_after,
        "delegated issuer loaded"
    );
    Ok(Some(issuer))
}
