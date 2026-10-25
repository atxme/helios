//! Certificates: inventory and overview, the actions on them, automatic
//! renewal and trust refresh, recovery, and the operator's approval.

use super::*;
use orion_engine::service::{InFlightRecovery, InFlightRenewal};
use orion_engine::{ActionOutcome, ProfileCertificates, RenewalProgress};

/// The four certificates a connection depends on, with their dates.
///
/// # Why the shell reads them rather than the screen
///
/// Two of them live in the protected identity store, which the WebView has no
/// business reaching, and all four are parsed by the same validator the
/// negotiation uses — `aether::certificates::x509` and the v5 PQ format. A
/// screen that decoded base64 and read dates itself would be a second
/// implementation of the lifecycle's arithmetic, and the day the two disagreed
/// the interface would be the one lying.
///
/// Nothing secret crosses back. The bundle is unsealed inside `orion-core`,
/// which keeps the two private halves and returns subjects, fingerprints and
/// instants (ADR-006 §5).
#[tauri::command]
pub(crate) fn certificate_inventory(
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
) -> orion_core::CertificateInventory {
    orion_core::certificate_inventory::inventory(key_negotiation.as_ref(), now_unix())
}

#[tauri::command]
pub(crate) async fn certificate_overview(
    state: State<'_, AppState>,
) -> Result<Vec<ProfileCertificates>, String> {
    let profiles: Vec<(String, Option<orion_core::KeyNegotiationSettings>)> = {
        let cfg = state.engine.config.lock().await;
        cfg.profiles
            .iter()
            .map(|profile| (profile.name.clone(), profile.key_negotiation.clone()))
            .collect()
    };
    let errors = state.engine.last_certificate_error.lock().await.clone();
    let identity_store = state.engine.controller.key_negotiation_ready();
    let protected_identities = orion_core::ProtectedIdentityStore::for_current_user().ok();
    let now = now_unix();

    Ok(profiles
        .into_iter()
        .map(|(name, settings)| {
            let promotion_error = settings
                .as_ref()
                .zip(protected_identities.as_ref())
                .and_then(|(settings, identities)| {
                    orion_core::certificate_renewal::promote_local_identity_if_due(
                        settings, identities, now,
                    )
                    .err()
                });
            let mut inventory =
                orion_core::certificate_inventory::inventory(settings.as_ref(), now);
            if let Some(error) = promotion_error {
                inventory
                    .faults
                    .push(format!("promotion de l'identité cliente : {error}"));
            }
            let actions = orion_core::certificate_actions::action_states(
                settings.as_ref(),
                &inventory,
                identity_store,
            );
            ProfileCertificates {
                identity: settings
                    .as_ref()
                    .map(|block| block.identity.clone())
                    .unwrap_or_default(),
                negotiates: settings.is_some(),
                last_error: errors.get(&name).cloned(),
                name,
                inventory,
                actions,
            }
        })
        .collect())
}

/// State of the four certificate actions of spec §12.2, for one profile.
///
/// Decided in `orion-core`, beside the state it reads. The screen renders the
/// reason it is given; a button greyed out with no sentence leaves the user
/// with the question they opened the screen to answer.
#[tauri::command]
pub(crate) fn certificate_actions(
    state: State<'_, AppState>,
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
) -> Vec<orion_core::CertificateActionState> {
    let inventory =
        orion_core::certificate_inventory::inventory(key_negotiation.as_ref(), now_unix());
    orion_core::certificate_actions::action_states(
        key_negotiation.as_ref(),
        &inventory,
        state.engine.controller.key_negotiation_ready(),
    )
}

/// Runs one of the four actions, or reports why it cannot run.
///
/// The refusal happens **before** a key pair is generated or an authority is
/// asked to certify anything: a press that produced a key and then discovered
/// it could not finish would leave a half-rotation behind every time.
///
/// The reason is recorded as this profile's last error, which is what §12.2
/// asks the surface to display.
#[tauri::command]
pub(crate) async fn run_certificate_action(
    state: State<'_, AppState>,
    name: String,
    action: orion_core::CertificateAction,
) -> Result<ActionOutcome, String> {
    match action {
        orion_core::CertificateAction::RenewEveryProfile => renew_every_profile(&state).await,
        // The other three each concern one profile.
        _ => {
            let step = run_for_one(&state, &name, action).await?;
            Ok(ActionOutcome::of(&name, step))
        }
    }
}

/// Asks the gateway, once per connection, whether this profile is behind.
///
/// # Why it is spawned and never awaited
///
/// It runs from the event sink, which the tunnel's own state machine drives. A
/// trust update that blocked there would make a gateway that accepts the
/// connection and then stalls hold up the client's notion of being connected —
/// the update is a convenience, the tunnel is the product.
///
/// Every outcome is said in the log the user actually reads, including the
/// refusals: a client that silently never catches up on a revocation is the
/// one failure this whole path exists to prevent, and «nothing happened» is
/// indistinguishable from «nothing was owed» unless one of them is written
/// down.
pub(crate) fn spawn_trust_refresh(
    settings: orion_core::KeyNegotiationSettings,
    heliosd_url: String,
    sink: EventSink,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        match orion_core::trust_update::refresh(&settings, &heliosd_url, now_unix()).await {
            Ok(orion_core::trust_update::TrustUpdateOutcome::UpToDate) => {
                tracing::debug!("mise à jour de confiance : rien à récupérer");
            }
            Ok(orion_core::trust_update::TrustUpdateOutcome::Applied { objects }) => {
                let message = format!(
                    "confiance mise à jour : {objects} objet(s) signé(s) appliqué(s) depuis la \
                     gateway"
                );
                tracing::info!(objects, "mise à jour de confiance appliquée");
                sink(ClientEvent::log("info", message));
            }
            Err(error) => {
                // Not fatal, and deliberately not silent. The tunnel works;
                // what may not is a future renewal, and that is worth a line
                // now rather than a refusal nobody can explain later.
                let message = format!(
                    "mise à jour de confiance impossible : {error}. Le tunnel n'est pas \
                             affecté."
                );
                tracing::warn!(%error, "mise à jour de confiance refusée");
                sink(ClientEvent::log("warn", message));
            }
        }
    })
}

/// Runs the ordinary client renewal at the fixed 80 % threshold.
///
/// The task is tied to the mounted connection. It first lets the authenticated
/// trust refresh finish, then waits for the locally computed threshold. A
/// reconnect cancels this task and creates a new one from the current durable
/// state, so no timer can act for a profile that is no longer mounted.
pub(crate) fn spawn_automatic_certificate_renewal(
    prerequisite: tokio::task::JoinHandle<()>,
    controller: Arc<VpnController>,
    renewals: Arc<Mutex<std::collections::HashMap<String, InFlightRenewal>>>,
    profile_name: String,
    settings: orion_core::KeyNegotiationSettings,
    heliosd_url: String,
    sink: EventSink,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = prerequisite.await;
        let now = now_unix();
        let inventory = orion_core::certificate_inventory::inventory(Some(&settings), now);
        let Some(client) = inventory.client_pq else {
            tracing::warn!(profile = %profile_name, "automatic renewal skipped: client PQ certificate is unavailable");
            return;
        };
        if client.phase == orion_core::certificate_inventory::CertificatePhase::Expired {
            sink(ClientEvent::log(
                "warn",
                format!(
                    "certificat du profil « {profile_name} » expiré : le renouvellement automatique ne peut plus prouver une identité active ; utiliser la récupération YubiKey"
                ),
            ));
            return;
        }

        let wait = client.renewal_at.saturating_sub(now);
        if wait > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        }
        if controller.state() != TunnelState::Up
            || controller.mounted_profile().await.as_deref() != Some(profile_name.as_str())
        {
            return;
        }

        match drive_renewal_in_map(&renewals, &profile_name, settings, heliosd_url).await {
            Ok(RenewalProgress::Committed { generation }) => {
                tracing::info!(profile = %profile_name, generation, "automatic certificate renewal committed");
                sink(ClientEvent::log(
                    "info",
                    format!(
                        "certificats du profil « {profile_name} » renouvelés automatiquement ; génération {generation} prête pour le chevauchement"
                    ),
                ));
            }
            Ok(progress) => {
                tracing::warn!(profile = %profile_name, ?progress, "automatic certificate renewal remains in progress");
                sink(ClientEvent::log(
                    "warn",
                    format!(
                        "renouvellement automatique du profil « {profile_name} » incomplet ; Orion réessaiera à la prochaine connexion"
                    ),
                ));
            }
            Err(error) => {
                tracing::warn!(profile = %profile_name, %error, "automatic certificate renewal failed");
                sink(ClientEvent::log(
                    "warn",
                    format!(
                        "renouvellement automatique du profil « {profile_name} » impossible : {error}. Orion réessaiera à la prochaine connexion"
                    ),
                ));
            }
        }
    })
}

/// One action, one profile.
async fn run_for_one(
    state: &State<'_, AppState>,
    name: &str,
    action: orion_core::CertificateAction,
) -> Result<RenewalProgress, String> {
    let (settings, heliosd_url) = {
        let cfg = state.engine.config.lock().await;
        let profile = cfg.find(name);
        (
            profile.and_then(|profile| profile.key_negotiation.clone()),
            profile.and_then(|profile| profile.heliosd_url.clone()),
        )
    };
    let inventory = orion_core::certificate_inventory::inventory(settings.as_ref(), now_unix());
    if let Err(block) = orion_core::certificate_actions::admits(
        action,
        settings.as_ref(),
        &inventory,
        state.engine.controller.key_negotiation_ready(),
    ) {
        return Err(record_certificate_error(state, name, block.message()).await);
    }

    let outcome = match action {
        orion_core::CertificateAction::RenewNow => {
            drive_renewal(state, name, settings, heliosd_url).await
        }
        orion_core::CertificateAction::RenewEveryProfile => {
            unreachable!("the fleet action is dispatched before this point")
        }
        orion_core::CertificateAction::RecoverExpired => {
            drive_recovery(state, name, settings).await
        }
        orion_core::CertificateAction::RollbackToPrevious => {
            let settings = settings.ok_or_else(|| "ce profil ne négocie pas de clé".to_string())?;
            let rollback =
                orion_core::certificate_renewal::rollback_to_previous(&settings, now_unix())
                    .map_err(|error| error.to_string())?;
            Ok(RenewalProgress::RolledBack {
                generation: rollback.selected_generation,
                available_until: rollback.available_until,
            })
        }
    };
    match outcome {
        Ok(progress) => {
            state
                .engine
                .last_certificate_error
                .lock()
                .await
                .remove(name);
            Ok(progress)
        }
        Err(message) => Err(record_certificate_error(state, name, message).await),
    }
}

/// Advances **every** Helios profile of this device by one step (§12.2).
///
/// # Why one step and not «until finished»
///
/// A renewal is not a call, it is a sequence that waits on a human: the
/// authority opens an operation, a security key answers its challenge, and
/// only then is anything issued. Driving one profile to completion before
/// starting the next would leave the other five untouched behind a touch that
/// may never come. Each press therefore advances all of them by one step,
/// exactly as a press on a single profile does — which also makes this action
/// the same shape as the one beside it, and resumable for the same reason.
///
/// # Why one profile's failure does not end the run
///
/// The profiles are independent: a gateway that is down, a block that is too
/// old to renew, a missing tunnel address — each concerns its own profile, and
/// stopping at the first would make the outcome depend on the order of a list.
/// Every refusal is recorded against **its** profile, where the screen already
/// shows it.
async fn renew_every_profile(state: &State<'_, AppState>) -> Result<ActionOutcome, String> {
    let profiles: Vec<String> = {
        let cfg = state.engine.config.lock().await;
        cfg.profiles
            .iter()
            .filter(|profile| profile.negotiates())
            .map(|profile| profile.name.clone())
            .collect()
    };
    if profiles.is_empty() {
        return Err("aucun profil Helios sur cet appareil".to_string());
    }

    let mut outcome = ActionOutcome::default();
    for name in profiles {
        match run_for_one(state, &name, orion_core::CertificateAction::RenewNow).await {
            Ok(step) => {
                outcome.progress.insert(name, step);
            }
            // Already recorded against this profile by `run_for_one`; carried
            // here too so the press that caused it reports it without waiting
            // for the overview to be read again.
            Err(message) => {
                outcome.refused.insert(name, message);
            }
        }
    }
    Ok(outcome)
}

/// Launches the companion for the operation held by one renewal session.
///
/// Only the profile name crosses IPC. The executable and every argument come
/// from the session owned by `orion-core`, so the WebView cannot turn this
/// permission into a shell or retarget an approval to another operation.
#[tauri::command]
pub(crate) async fn launch_certificate_companion(
    state: State<'_, AppState>,
    name: String,
) -> Result<(), String> {
    let invocation = {
        let renewals = state.engine.renewals.lock().await;
        let renewal = renewals
            .get(&name)
            .ok_or_else(|| format!("aucun renouvellement en attente pour le profil « {name} »"))?;
        renewal
            .session
            .companion_invocation()
            .ok_or_else(|| format!("le profil « {name} » n'attend aucune approbation opérateur"))?
    };
    companion::launch(&invocation)
}

pub(crate) fn companion_plugin<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("companion")
        .invoke_handler(tauri::generate_handler![launch_certificate_companion])
        .build()
}

/// Opens a renewal, or takes one more step on the one already open.
///
/// Resuming rather than restarting is the whole reason the session is kept:
/// a second `begin` would generate a second key pair and open a second
/// operation, burning a generation for nothing while the first one still waits
/// on the same operator.
async fn drive_renewal(
    state: &State<'_, AppState>,
    name: &str,
    settings: Option<orion_core::KeyNegotiationSettings>,
    heliosd_url: Option<String>,
) -> Result<RenewalProgress, String> {
    let settings = settings.ok_or_else(|| "ce profil ne négocie pas de clé".to_string())?;
    let url = heliosd_url.ok_or_else(|| {
        "ce profil ne porte pas l'adresse de l'API de la gateway dans le tunnel : sans elle il n'y          a aucune route de renouvellement à appeler."
            .to_string()
    })?;

    drive_renewal_in_map(&state.engine.renewals, name, settings, url).await
}

async fn drive_renewal_in_map(
    renewals: &Arc<Mutex<std::collections::HashMap<String, InFlightRenewal>>>,
    name: &str,
    settings: orion_core::KeyNegotiationSettings,
    url: String,
) -> Result<RenewalProgress, String> {
    let mut renewals = renewals.lock().await;
    if let Some(in_flight) = renewals.get_mut(name) {
        let step = orion_core::certificate_renewal::resume(
            &mut in_flight.session,
            &mut in_flight.store,
            &in_flight.settings,
            now_unix(),
        )
        .await
        .map_err(|error| error.to_string())?;
        let progress = RenewalProgress::of(&step, &in_flight.session);
        if matches!(
            step,
            orion_core::certificate_renewal::RenewalStep::Committed { .. }
        ) {
            renewals.remove(name);
        }
        return Ok(progress);
    }

    let (session, store, step) =
        orion_core::certificate_renewal::begin(&settings, &url, now_unix())
            .await
            .map_err(|error| error.to_string())?;
    let progress = RenewalProgress::of(&step, &session);
    if !matches!(
        step,
        orion_core::certificate_renewal::RenewalStep::Committed { .. }
    ) {
        renewals.insert(
            name.to_string(),
            InFlightRenewal {
                session,
                store,
                settings,
                approval: None,
            },
        );
    }
    Ok(progress)
}

/// Opens a §7.5 recovery, or takes one more step on the one already open.
///
/// # Why resuming matters even more here than for a renewal
///
/// A recovery burns the one historical proof this machine has: the expired
/// private key signs a request naming a specific generation, and Astra
/// consumes the challenge it answered. Starting a second one while the first
/// still waits would leave an operator holding an identifier that no longer
/// matches what the client will present — and the operator is on another
/// machine, with no way to see that.
async fn drive_recovery(
    state: &State<'_, AppState>,
    name: &str,
    settings: Option<orion_core::KeyNegotiationSettings>,
) -> Result<RenewalProgress, String> {
    let settings = settings.ok_or_else(|| "ce profil ne négocie pas de clé".to_string())?;

    let mut recoveries = state.engine.recoveries.lock().await;
    if let Some(in_flight) = recoveries.get(name) {
        let step = orion_core::certificate_recovery::resume(
            &in_flight.session,
            &in_flight.settings,
            now_unix(),
        )
        .await
        .map_err(|error| error.to_string())?;
        let progress = RenewalProgress::of_recovery(&step, &in_flight.session);
        tracing::info!(
            profile = %name,
            operation = %in_flight.session.operation_id().to_hex(),
            ?step,
            "récupération §7.5 reprise"
        );
        if matches!(
            step,
            orion_core::certificate_recovery::RecoveryStep::Recovered { .. }
        ) {
            recoveries.remove(name);
        }
        return Ok(progress);
    }

    let (session, step) = orion_core::certificate_recovery::begin(&settings, now_unix())
        .await
        .map_err(|error| error.to_string())?;
    let progress = RenewalProgress::of_recovery(&step, &session);
    tracing::info!(
        profile = %name,
        operation = %session.operation_id().to_hex(),
        autorite = %session.authority_url(),
        ?step,
        "récupération §7.5 ouverte"
    );
    if !matches!(
        step,
        orion_core::certificate_recovery::RecoveryStep::Recovered { .. }
    ) {
        recoveries.insert(name.to_string(), InFlightRecovery { session, settings });
    }
    Ok(progress)
}

/// Resumes the recovery whose operator ceremony has just released its grant.
///
/// The operation id is only a selector over sessions this Orion process
/// already owns. The WebView cannot name a profile, settings or authority,
/// and the lock is released before the network call so the ordinary recovery
/// driver remains the sole mutator of the session.
#[tauri::command]
pub(crate) async fn resume_certificate_recovery(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<ActionOutcome, String> {
    let operation = aether::certificates::encoding::Id16::parse_hex(&operation_id)
        .map_err(|_| "identifiant de récupération illisible".to_string())?;
    let found = {
        let recoveries = state.engine.recoveries.lock().await;
        recoveries
            .iter()
            .find(|(_, recovery)| recovery.session.operation_id() == operation)
            .map(|(name, recovery)| (name.clone(), recovery.settings.clone()))
    };
    let (name, settings) = found.ok_or_else(|| {
        "aucune récupération ouverte dans Orion ne correspond à cette opération".to_string()
    })?;

    match drive_recovery(&state, &name, Some(settings)).await {
        Ok(progress) => {
            state
                .engine
                .last_certificate_error
                .lock()
                .await
                .remove(&name);
            Ok(ActionOutcome::of(&name, progress))
        }
        Err(message) => Err(record_certificate_error(&state, &name, message).await),
    }
}

async fn record_certificate_error(
    state: &State<'_, AppState>,
    name: &str,
    message: String,
) -> String {
    state
        .engine
        .last_certificate_error
        .lock()
        .await
        .insert(name.to_string(), message.clone());
    message
}

/// Reads the approval request the open renewal is waiting on (§8.1.2 step 4a).
///
/// Verified before it comes back, against what the profile pins — so what the
/// screen shows is attested rather than announced. Nothing touches a security
/// key here: the manifest exists precisely so the user decides *before* the
/// ceremony, not during it.
#[tauri::command]
pub(crate) async fn certificate_approval_manifest(
    state: State<'_, AppState>,
    name: String,
) -> Result<orion_core::certificate_approval::ApprovalManifest, String> {
    let mut renewals = state.engine.renewals.lock().await;
    let in_flight = renewals
        .get_mut(&name)
        .ok_or_else(|| "aucun renouvellement ouvert pour ce profil".to_string())?;
    let verified = in_flight
        .session
        .fetch_approval(&in_flight.store, now_unix())
        .await
        .map_err(|error| error.to_string())?;
    let manifest = verified.manifest();
    in_flight.approval = Some(verified);
    Ok(manifest)
}

/// Runs the ceremony and posts the assertion (§8.1.2 step 4b).
///
/// The blocking call lives on a blocking thread: talking to a security key
/// puts a modal on screen and waits for a human, and holding the async runtime
/// for that would stop every other task in Orion — the tunnel's telemetry
/// included.
///
/// The verified request is **consumed**. A second run would ask for a touch
/// against a window the authority has since closed, and the user would be
/// standing at a prompt for nothing.
#[tauri::command]
pub(crate) async fn approve_certificate_renewal(
    state: State<'_, AppState>,
    name: String,
    pin: Option<String>,
) -> Result<RenewalProgress, String> {
    let verified = {
        let mut renewals = state.engine.renewals.lock().await;
        let in_flight = renewals
            .get_mut(&name)
            .ok_or_else(|| "aucun renouvellement ouvert pour ce profil".to_string())?;
        in_flight.approval.take().ok_or_else(|| {
            "lire d'abord la demande d'approbation : c'est elle qui est vérifiée, et ce qui est              signé est ce qui a été montré"
                .to_string()
        })?
    };

    let pin = pin.unwrap_or_default();
    let approval = tokio::task::spawn_blocking(move || verified.run(&pin, now_unix()))
        .await
        .map_err(|error| format!("la cérémonie n'a pas pu être lancée : {error}"))?
        .map_err(|error| error.to_string())?;

    let mut renewals = state.engine.renewals.lock().await;
    let in_flight = renewals
        .get_mut(&name)
        .ok_or_else(|| "aucun renouvellement ouvert pour ce profil".to_string())?;
    let step = in_flight
        .session
        .submit_approval(&approval)
        .await
        .map_err(|error| error.to_string())?;
    let progress = RenewalProgress::of(&step, &in_flight.session);
    Ok(progress)
}

/// Whether this machine's key collects its own PIN.
///
/// Asked rather than assumed: under Windows the platform API puts up its own
/// dialog and the PIN never enters this process, so prompting for one would be
/// asking the user for a secret Orion has no use for.
#[tauri::command]
pub(crate) async fn certificate_approval_needs_pin(
    state: State<'_, AppState>,
    name: String,
) -> Result<bool, String> {
    let renewals = state.engine.renewals.lock().await;
    let in_flight = renewals
        .get(&name)
        .ok_or_else(|| "aucun renouvellement ouvert pour ce profil".to_string())?;
    let approval = in_flight
        .approval
        .as_ref()
        .ok_or_else(|| "lire d'abord la demande d'approbation".to_string())?;
    approval.needs_pin().map_err(|error| error.to_string())
}

/// The last certificate action that failed on this profile, if any.
///
/// Kept in memory rather than persisted: it describes an attempt made in this
/// session, and a message surviving a restart would outlive the situation it
/// described — a missing identity imported since, a store now available.
#[tauri::command]
pub(crate) async fn last_certificate_error(
    state: State<'_, AppState>,
    name: String,
) -> Result<Option<String>, String> {
    Ok(state
        .engine
        .last_certificate_error
        .lock()
        .await
        .get(&name)
        .cloned())
}
