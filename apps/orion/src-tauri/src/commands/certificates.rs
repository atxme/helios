//! Certificates: inventory and overview, the actions on them, automatic
//! renewal and trust refresh, recovery, and the operator's approval.

use super::*;

use orion_engine::{
    ActionOutcome, EngineCommand, EngineReply, ProfileCertificates, RenewalProgress,
};

/// The four certificates a connection depends on, with their dates.
///
/// Read by the engine, which owns the protected identity store and the
/// validator the negotiation uses. See `orion_engine::service::certificates`.
#[tauri::command]
pub(crate) async fn certificate_inventory(
    state: State<'_, AppState>,
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
) -> Result<orion_core::CertificateInventory, String> {
    match state
        .client
        .call(EngineCommand::CertificateInventory { key_negotiation })
        .await?
    {
        EngineReply::CertificateInventory(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

#[tauri::command]
pub(crate) async fn certificate_overview(
    state: State<'_, AppState>,
) -> Result<Vec<ProfileCertificates>, String> {
    match state
        .client
        .call(EngineCommand::CertificateOverview)
        .await?
    {
        EngineReply::CertificateOverview(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// State of the four certificate actions of spec §12.2, for one profile.
#[tauri::command]
pub(crate) async fn certificate_actions(
    state: State<'_, AppState>,
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
) -> Result<Vec<orion_core::CertificateActionState>, String> {
    match state
        .client
        .call(EngineCommand::CertificateActions { key_negotiation })
        .await?
    {
        EngineReply::CertificateActions(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Runs one of the four actions, or reports why it cannot run.
#[tauri::command]
pub(crate) async fn run_certificate_action(
    state: State<'_, AppState>,
    name: String,
    action: orion_core::CertificateAction,
) -> Result<ActionOutcome, String> {
    match state
        .client
        .call(EngineCommand::RunCertificateAction { name, action })
        .await?
    {
        EngineReply::ActionOutcome(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Resumes the recovery whose operator ceremony has just released its grant.
#[tauri::command]
pub(crate) async fn resume_certificate_recovery(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<ActionOutcome, String> {
    match state
        .client
        .call(EngineCommand::ResumeCertificateRecovery { operation_id })
        .await?
    {
        EngineReply::ActionOutcome(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
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
#[tauri::command]
pub(crate) async fn last_certificate_error(
    state: State<'_, AppState>,
    name: String,
) -> Result<Option<String>, String> {
    match state
        .client
        .call(EngineCommand::LastCertificateError { name })
        .await?
    {
        EngineReply::LastError(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}
