//! The Astra CA-TLS rotation and the operator ceremonies, driven from this
//! window and signed in the companion.

use super::*;

use orion_engine::{ConfigView, EngineCommand, EngineReply};

/// Opens the two-key CA-TLS ceremony described in ADR-008 §9.4.
///
/// Everything that decides anything happens in the companion: the campaign is
/// fetched and verified there, under the Astra service key the vault's
/// hand-off pins, and the two credentials are exercised there. This command
/// starts it and returns the first state it publishes.
#[tauri::command]
pub(crate) async fn start_astra_ca_tls_rotation(
    state: State<'_, AppState>,
    input: astra::RotationInput,
) -> Result<aether::certificates::operator_ipc::AstraCaTlsStatus, String> {
    state.astra.start(input).await
}

/// Takes the next step, once the operator says the requested key is plugged in.
#[tauri::command]
pub(crate) async fn continue_astra_ca_tls_rotation(
    state: State<'_, AppState>,
) -> Result<aether::certificates::operator_ipc::AstraCaTlsStatus, String> {
    state
        .astra
        .advance(aether::certificates::operator_ipc::AstraIpcCommand::Continue)
        .await
}

/// Abandons the ceremony, which only the phases before the first durable write
/// accept.
#[tauri::command]
pub(crate) async fn cancel_astra_ca_tls_rotation(
    state: State<'_, AppState>,
) -> Result<aether::certificates::operator_ipc::AstraCaTlsStatus, String> {
    state
        .astra
        .advance(aether::certificates::operator_ipc::AstraIpcCommand::Cancel)
        .await
}

/// The ceremony's current state, for a view that was opened after it started.
#[tauri::command]
pub(crate) async fn astra_ca_tls_rotation_status(
    state: State<'_, AppState>,
) -> Result<aether::certificates::operator_ipc::AstraCaTlsStatus, String> {
    Ok(state.astra.status().await)
}

/// Opens an operator ceremony for the operation the WebView names.
///
/// The locator is all it may name — a kind, and at most an identifier this
/// process itself opened. Everything else is resolved from the hand-off pinned
/// beside the vault the ceremony holds.
#[tauri::command]
pub(crate) async fn begin_operator_ceremony(
    state: State<'_, AppState>,
    locator: aether::certificates::operator_session::OperationLocator,
) -> Result<aether::certificates::operator_session::OperatorStatus, String> {
    let vault_path = state.vault_location.path()?;
    state.operator.begin(locator, vault_path).await
}

/// The handle of the window the press came from, or `0` where there is none.
///
/// It is the owner of the WebAuthn dialog a key opens, so that dialog appears
/// over the window the operator is looking at. Read on every advance: a press
/// that opens no dialog carries it unused.
pub(crate) fn owner_window(window: &tauri::Window) -> isize {
    #[cfg(target_os = "windows")]
    {
        window.hwnd().map(|handle| handle.0 as isize).unwrap_or(0)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = window;
        0
    }
}

/// Takes the next step, or abandons, against the status the operator saw.
///
/// The revision is not decoration: a press on a screen the ceremony has already
/// left is refused here and again there, rather than applied to whatever
/// replaced it.
#[tauri::command]
pub(crate) async fn advance_operator_ceremony(
    state: State<'_, AppState>,
    window: tauri::Window,
    action: aether::certificates::operator_session::OperatorAction,
    revision: u64,
) -> Result<aether::certificates::operator_session::OperatorStatus, String> {
    state
        .operator
        .advance(action, revision, owner_window(&window))
        .await
}

/// Removes the final status once the operator has acknowledged it.
#[tauri::command]
pub(crate) async fn dismiss_operator_ceremony(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    // The operator's own screen may have cost a tunnel-up its look. A resumption's
    // dead end does not: dismissing it must not bring it back.
    if state.operator.dismiss().await? {
        look_for_a_rotation_again(app);
    }
    Ok(())
}

/// Everything waiting for an operator, through the gateway of one profile.
///
/// The gateway rather than Astra's public origin, and the difference is the
/// access control: the origin serves a §7.5 recovery without a tunnel, so a
/// list there would be readable by anyone who can reach it. Recoveries are
/// absent from what comes back — Orion already holds the identifier of the
/// ones it opened, and nothing else may enumerate them.
///
/// An unreachable gateway returns an empty list rather than an error: this
/// runs on a timer behind a navigation rail, and a tunnel that is down is
/// «rien en attente», not a red banner.
#[tauri::command]
pub(crate) async fn operator_pending_operations(
    state: State<'_, AppState>,
) -> Result<Vec<orion_core::operator_pending::OperatorPendingOperation>, String> {
    let gateways: Vec<String> = {
        let view = match state.client.call(EngineCommand::GetConfig).await? {
            EngineReply::Config(view) => view,
            _ => return Err(unexpected_engine_reply()),
        };
        let mut seen: Vec<String> = Vec::new();
        for profile in &view.profiles {
            if let Some(url) = profile.heliosd_url.as_ref() {
                if !seen.iter().any(|held| held == url) {
                    seen.push(url.clone());
                }
            }
        }
        seen
    };
    let mut pending = Vec::new();
    for gateway in gateways {
        match orion_core::operator_pending::pending(&gateway).await {
            Ok(list) => pending.extend(list.operations),
            Err(error) => {
                tracing::debug!(%gateway, %error, "aucune opération lisible sur cette gateway")
            }
        }
    }
    Ok(pending)
}

/// Opens an enrollment gesture: inviting a device, accepting its request, or
/// resuming an acceptance.
///
/// The gateway is the connected profile's, read here from the engine. Without
/// one the gesture goes on with what the operator supplied — an invitation can
/// be pinned from a leaf file — rather than failing for a tunnel it may not
/// need.
#[tauri::command]
pub(crate) async fn begin_enrollment_ceremony(
    state: State<'_, AppState>,
    gesture: crate::operator::EnrollmentGesture,
) -> Result<aether::certificates::operator_session::OperatorStatus, String> {
    let vault_path = state.vault_location.path()?;
    let gateway = connected_gateway(&state).await.ok();
    state
        .operator
        .begin_enrollment(gesture, gateway, vault_path)
        .await
}

/// Opens a vault or domain gesture: creating the domain, adding, removing or
/// marking a key, finalizing the domain.
#[tauri::command]
pub(crate) async fn begin_vault_ceremony(
    state: State<'_, AppState>,
    gesture: crate::operator::VaultGesture,
) -> Result<aether::certificates::operator_session::OperatorStatus, String> {
    let vault_path = state.vault_location.path()?;
    state.operator.begin_vault(gesture, vault_path).await
}

/// Opens the delegation of Astra's issuer, in a campaign or offline. Only the
/// request's text crosses: the file was read by the window.
#[tauri::command]
pub(crate) async fn begin_issuer_ceremony(
    state: State<'_, AppState>,
    gesture: crate::operator::IssuerGesture,
) -> Result<aether::certificates::operator_session::OperatorStatus, String> {
    let vault_path = state.vault_location.path()?;
    state.operator.begin_issuer(gesture, vault_path).await
}

/// Opens a CA rotation gesture: replacing a CA, ending a client TLS rotation, or
/// resuming one. The gateway is the connected profile's, read here from the engine;
/// without one the gesture stops before any key.
#[tauri::command]
pub(crate) async fn begin_rotation_ceremony(
    state: State<'_, AppState>,
    gesture: crate::operator::RotationGesture,
) -> Result<aether::certificates::operator_session::OperatorStatus, String> {
    let vault_path = state.vault_location.path()?;
    let gateway = connected_target(&state).await.ok();
    state
        .operator
        .begin_rotation(gesture, gateway, vault_path)
        .await
}

/// Answers the approval screen of a rotation, against the status the operator saw:
/// this is what opens its campaign.
#[tauri::command]
pub(crate) async fn approve_rotation_ceremony(
    state: State<'_, AppState>,
    terms: astra_operator::operations::rotation::RotationTerms,
    revision: u64,
) -> Result<aether::certificates::operator_session::OperatorStatus, String> {
    state.operator.approve_rotation(terms, revision).await
}

/// Renames a key. No key is asked anything: the label is outside what the
/// vault seals.
#[tauri::command]
pub(crate) async fn rename_operator_key(
    state: State<'_, AppState>,
    slot_id: String,
    label: String,
) -> Result<(), String> {
    ensure_no_open_ceremony(&state).await?;
    let vault_path = state.vault_location.path()?;
    crate::operator::rename_key(&vault_path, &slot_id, &label)
}

/// Records values on the domain relay beside the vault. No key: the relay is
/// public, and every value is checked before anything is written.
#[tauri::command]
pub(crate) async fn write_domain_relay(
    state: State<'_, AppState>,
    update: astra_operator::vault_gestures::RelayUpdate,
) -> Result<(), String> {
    ensure_no_open_ceremony(&state).await?;
    let vault_path = state.vault_location.path()?;
    astra_operator::vault_gestures::write_relay(&vault_path, &update)
        .map(|_| ())
        .map_err(|error| format!("{error:#}"))
}

/// Records the connected gateway on the relay, from the leaf it serves.
///
/// Before anything is written, three WireGuard keys must be one: the key the
/// leaf certifies, the key the gateway answers with, and the peer key of the
/// connected profile — the one the tunnel is up to. The leaf's subject must
/// also be the server name the gateway answers with. `adopt_gateway` then
/// verifies the leaf under the domain's `CA-PQ` for that identity, and refuses
/// a relay or document that already names another gateway.
#[tauri::command]
pub(crate) async fn adopt_connected_gateway(state: State<'_, AppState>) -> Result<(), String> {
    use orion_core::gateway_admin as admin;

    ensure_no_open_ceremony(&state).await?;
    let vault_path = state.vault_location.path()?;
    let (base, tunnel_peer_key) = connected_profile(&state).await?;
    let client = admin::orion_client().map_err(|error| error.to_string())?;
    let material = admin::gateway_negotiation(&client, &base)
        .await
        .map_err(|error| error.to_string())?;
    let leaf = admin::decode_pq_certificate(&material.gateway_pq_certificate)
        .map_err(|error| error.to_string())?;
    check_tunnel_leaf(&leaf, &material, &tunnel_peer_key)?;
    on_work_stack(
        "orion-gateway-adoption",
        "l'adoption de la gateway",
        move || {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            astra_operator::vault_gestures::adopt_gateway(&vault_path, &leaf, now)
                .map(|_| ())
                .map_err(|error| format!("{error:#}"))
        },
    )
    .await
}

/// Runs `work` on a thread of its own, with the stack the post-quantum
/// verifications need, and waits for its answer without holding a runtime
/// worker. `what` names the work in the two errors of the thread itself.
async fn on_work_stack<T, F>(name: &str, what: &str, work: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(name.into())
        .stack_size(astra_operator::WORK_STACK_BYTES)
        .spawn(move || {
            let _ = sender.send(work());
        })
        .map_err(|error| format!("{what} : {error}"))?;
    receiver
        .await
        .map_err(|_| format!("{what} s'est arrêtée"))?
}

/// What the domain creation form starts from: the RP ID the selected
/// profile's endpoint suggests, when it is a name.
#[tauri::command]
pub(crate) async fn operator_domain_defaults(
    state: State<'_, AppState>,
) -> Result<crate::operator::DomainDefaults, String> {
    let view = match state.client.call(EngineCommand::GetConfig).await? {
        EngineReply::Config(value) => value,
        _ => return Err(unexpected_engine_reply()),
    };
    let rp_id = view
        .selected
        .as_deref()
        .and_then(|name| view.profiles.iter().find(|profile| profile.name == name))
        .and_then(|profile| crate::operator::suggested_rp_id(&profile.endpoint));
    Ok(crate::operator::DomainDefaults { rp_id })
}

/// The files the current session produced, for the window to save.
#[tauri::command]
pub(crate) async fn operator_artifacts(
    state: State<'_, AppState>,
) -> Result<Vec<crate::operator::OperatorArtifact>, String> {
    Ok(state.operator.artifacts().await)
}

/// The ceremony's current state, for a view opened after it started.
#[tauri::command]
pub(crate) async fn operator_ceremony_status(
    state: State<'_, AppState>,
) -> Result<Option<aether::certificates::operator_session::OperatorStatus>, String> {
    Ok(state.operator.status().await)
}

/// The operator vault and its trust domain, read without any key.
///
/// Nothing is unwrapped: the slots come back as identifier, label and role, and
/// the domain as the public values of the relay beside the vault. No PIN and no
/// security key are involved, so this is safe to call whenever the tab opens.
///
/// The credential document is verified under `CA-PQ` on the way, so the read
/// runs on a work stack, as the adoption does.
#[tauri::command]
pub(crate) async fn operator_overview(
    state: State<'_, AppState>,
) -> Result<astra_operator::overview::VaultOverview, String> {
    let path = state.vault_location.path()?;
    on_work_stack("orion-vault-overview", "la lecture du coffre", move || {
        astra_operator::overview::read(&path).map_err(|error| error.to_string())
    })
    .await
}

/// Everything the rotations screen shows, in one read and with no key.
///
/// The gateway is the connected profile's. Without a tunnel the three reads are
/// `unreachable` and `tunnel` says why. The vault is looked at where it is, and
/// no folder is created for having looked. The page receives display data only.
#[tauri::command]
pub(crate) async fn operator_rotations_overview(
    state: State<'_, AppState>,
) -> Result<crate::operator::rotations::RotationsOverview, String> {
    use crate::operator::rotations::{read_local, RotationsOverview};
    use orion_core::operator_rotations as reads;

    let vault_path = state.vault_location.path_to_look_at();
    let target = connected_target(&state).await.ok();
    let (pending, authority, domain) = match &target {
        Some(target) => {
            tokio::join!(
                reads::pending(&target.address),
                reads::authority_status(&target.address),
                reads::domain(&target.address),
            )
        }
        None => (
            reads::Reach::Unreachable,
            reads::Reach::Unreachable,
            reads::Reach::Unreachable,
        ),
    };
    let now = crate::operator::now_unix();
    let local = on_work_stack(
        "orion-rotations-overview",
        "la lecture du coffre",
        move || Ok(read_local(&vault_path, now)),
    )
    .await?;
    Ok(RotationsOverview::assemble(
        target.is_some(),
        pending,
        authority,
        domain,
        local,
    ))
}

/// Sends the vault copy Astra keeps, and the credential document when it may.
///
/// The vault and the credentials are read here, from beside the vault; the page
/// names nothing. The copy goes only to the gateway the domain's relay names: Orion
/// holds several profiles and one vault, and another domain's gateway must not
/// receive this one. A copy Astra holds back is an answer, not a failure.
#[tauri::command]
pub(crate) async fn operator_send_vault_copy(
    state: State<'_, AppState>,
) -> Result<crate::operator::rotations::VaultCopyOutcome, String> {
    ensure_no_open_ceremony(&state).await?;
    let vault_path = state.vault_location.path_to_look_at()?;
    let target = connected_target(&state).await?;
    let handle = tokio::runtime::Handle::current();
    on_work_stack(
        "orion-vault-copy",
        "l'envoi de la copie du coffre",
        move || {
            let tunnel = astra_operator::tunnel::Tunnel::new(&target.address)
                .map_err(|error| format!("{error:#}"))?;
            crate::operator::rotations::send_copy_with(&tunnel, &vault_path, &target, || {
                handle.block_on(orion_core::operator_rotations::authority_status(
                    &target.address,
                ))
            })
        },
    )
    .await
}

/// Opens a campaign for the actions this screen runs outside a rotation ceremony:
/// renewing the workstations and the issuer's delegation.
///
/// `OperatorOpened` is public: identifiers, a fingerprint, counts, an expiry and the
/// delegation's public request. No token and no secret. The gateway is the
/// connected profile's, and must be the one the domain's relay names.
#[tauri::command]
pub(crate) async fn operator_open_campaign(
    state: State<'_, AppState>,
    action: aether::certificates::transport::OperatorOpenAction,
    reason: String,
    requested_by: String,
) -> Result<aether::certificates::transport::OperatorOpened, String> {
    let vault_path = state.vault_location.path_to_look_at()?;
    let target = connected_target(&state).await?;
    on_work_stack(
        "orion-open-campaign",
        "l'ouverture de la campagne",
        move || {
            let tunnel = astra_operator::tunnel::Tunnel::new(&target.address)
                .map_err(|error| format!("{error:#}"))?;
            crate::operator::rotations::open_campaign_with(
                &tunnel,
                &vault_path,
                &target,
                action,
                &reason,
                &requested_by,
            )
        },
    )
    .await
}

/// Where the operator vault is, and whether it is the default place. A
/// location that cannot be resolved is a view that says why, not an error:
/// the window must still offer to choose again or go back to the default.
#[tauri::command]
pub(crate) async fn operator_vault_location(
    state: State<'_, AppState>,
) -> Result<crate::operator::location::VaultLocationView, String> {
    Ok(state.vault_location.view())
}

/// Asks the operator, in a dialog over this window, where the vault is.
///
/// The path comes from the dialog and never from the WebView, which only asks
/// for the dialog to open. `None` when the operator cancels.
#[tauri::command]
pub(crate) async fn choose_vault_location(
    state: State<'_, AppState>,
    window: tauri::Window,
    app: tauri::AppHandle,
) -> Result<Option<crate::operator::location::VaultLocationView>, String> {
    #[cfg(target_os = "windows")]
    {
        ensure_no_open_ceremony(&state).await?;
        // Held until this command returns, whatever the path: one dialog at a
        // time.
        let _picker = state.vault_location.begin_pick()?;
        let owner = owner_window(&window);
        // An unreadable setting must still be replaceable: the dialog then
        // opens where it would by default.
        let current = state.vault_location.path().unwrap_or_default();
        // A thread of its own: the dialog sets that thread's COM apartment,
        // which a pooled worker would carry into unrelated work.
        let (sender, receiver) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("orion-vault-picker".into())
            .spawn(move || {
                let _ = sender.send(crate::operator::location::pick(owner, &current));
            })
            .map_err(|error| format!("boîte de choix de l'emplacement du coffre : {error}"))?;
        let picked = receiver.await.map_err(|_| {
            "la boîte de choix de l'emplacement du coffre s'est arrêtée".to_string()
        })??;
        match picked {
            // Asked again: the dialog may have stayed open while a ceremony
            // began.
            Some(path) => {
                ensure_no_open_ceremony(&state).await?;
                let view = state.vault_location.choose(path)?;
                look_for_a_rotation_again(app);
                Ok(Some(view))
            }
            None => Ok(None),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (state, window, app);
        Err("le choix d'emplacement n'existe que sous Windows".to_string())
    }
}

/// Goes back to the default vault location.
#[tauri::command]
pub(crate) async fn reset_vault_location(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<crate::operator::location::VaultLocationView, String> {
    ensure_no_open_ceremony(&state).await?;
    let view = state.vault_location.reset()?;
    look_for_a_rotation_again(app);
    Ok(view)
}

/// A vault the tunnel-up did not see may be in place now: the look is made again,
/// once, as after a dismissed screen.
fn look_for_a_rotation_again(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        crate::operator::resume_on_tunnel_up(&app).await;
    });
}

const CEREMONY_OPEN: &str =
    "une cérémonie opérateur est ouverte : la terminer ou l'annuler d'abord";

/// Refuses a key-less write to the vault, its relay or its location while a
/// ceremony is open: that ceremony checked them before its key, and writes
/// them after it.
async fn ensure_no_open_ceremony(state: &AppState) -> Result<(), String> {
    no_open_ceremony(state.operator.status().await.as_ref())
}

/// The decision of [`ensure_no_open_ceremony`], on the last status published.
fn no_open_ceremony(
    status: Option<&aether::certificates::operator_session::OperatorStatus>,
) -> Result<(), String> {
    match status {
        Some(status) if !status.gesture.is_terminal() => Err(CEREMONY_OPEN.to_string()),
        _ => Ok(()),
    }
}

const NOT_THE_TUNNEL_GATEWAY: &str = "la gateway qui répond n'est pas celle du profil connecté";

/// Whether the leaf a gateway served names that gateway, and the gateway is
/// the one the tunnel is up to: the leaf's key, the key the gateway answers
/// with and the connected profile's peer key are one parsed WireGuard key, and
/// the leaf's subject is the server name the gateway answers with. Any key
/// that does not parse is a mismatch.
fn check_tunnel_leaf(
    leaf: &aether::key_negotiation::PqCertificate,
    material: &orion_core::enrollment_draft::GatewayMaterial,
    tunnel_peer_key: &str,
) -> Result<(), String> {
    use aether::certificates::encoding::WireGuardKey;

    let parse = |value: &str| WireGuardKey::parse(value.trim()).ok();
    let leaf_key = parse(&leaf.wireguard_public_key);
    let one_key = leaf_key.is_some()
        && leaf_key == parse(&material.wireguard_public_key)
        && leaf_key == parse(tunnel_peer_key);
    if one_key && leaf.subject == material.server_name.trim() {
        Ok(())
    } else {
        Err(NOT_THE_TUNNEL_GATEWAY.to_string())
    }
}

/// The invitations of this machine's registry, with whether each device is
/// admitted on the connected gateway.
///
/// The gateway is asked on the runtime, with a wait, and only when one is
/// connected: without it the invitations still list, with `peer_admitted`
/// unknown. No key is involved.
#[tauri::command]
pub(crate) async fn operator_invitations(
    state: State<'_, AppState>,
) -> Result<Vec<crate::operator::invitations::InvitationView>, String> {
    use orion_core::gateway_admin as admin;

    let registry = astra_operator::enrollment::InvitationRegistry::default_location()
        .map_err(|error| format!("{error:#}"))?;
    let admitted = match connected_gateway(&state).await {
        Ok(base) => match admin::orion_client() {
            Ok(client) => admin::admitted_keys(&client, &base).await.ok(),
            Err(_) => None,
        },
        Err(_) => None,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    crate::operator::invitations::list(&registry, now, admitted.as_deref())
}

/// Revokes an invitation still issued. No key: the registry refuses anything
/// that is not issued, and the revocation destroys its proof key.
#[tauri::command]
pub(crate) async fn revoke_invitation(invitation_id: String) -> Result<(), String> {
    let id = aether::certificates::encoding::Id16::parse_hex(invitation_id.trim())
        .map_err(|error| error.to_string())?;
    let registry = astra_operator::enrollment::InvitationRegistry::default_location()
        .map_err(|error| format!("{error:#}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    crate::operator::invitations::revoke(&registry, &id, now)
}

const NO_CONNECTED_GATEWAY: &str = "Connectez d'abord le profil de la gateway, avec un pair \
                                    administrateur : l'admission passe par le tunnel.";

/// The control-plane address the operator gestures reach the gateway at.
///
/// Read here, from the engine, and never taken from the WebView: the page names
/// a gesture, not the machine it is carried out against. The profile must be
/// the selected one and its tunnel up, because the admission rides the tunnel
/// and a gateway reached any other way would not be the one the operator
/// connected to.
async fn connected_gateway(state: &AppState) -> Result<String, String> {
    connected_profile(state).await.map(|(url, _)| url)
}

/// [`connected_gateway`] and the peer key, as the gateway a rotation may be carried to.
pub(crate) async fn connected_target(
    state: &AppState,
) -> Result<crate::operator::GatewayTarget, String> {
    connected_profile(state)
        .await
        .map(|(address, peer_key)| crate::operator::GatewayTarget { address, peer_key })
}

/// [`connected_gateway`], with the peer key of the connected profile read
/// from the same answer of the engine.
async fn connected_profile(state: &AppState) -> Result<(String, String), String> {
    let tunnel = match state.client.call(EngineCommand::GetState).await? {
        EngineReply::State(value) => value,
        _ => return Err(unexpected_engine_reply()),
    };
    let view = match state.client.call(EngineCommand::GetConfig).await? {
        EngineReply::Config(value) => value,
        _ => return Err(unexpected_engine_reply()),
    };
    gateway_profile(&tunnel, &view)
        .map(|(url, profile)| (url, profile.peer_public_key.trim().to_string()))
}

/// The decision of [`connected_gateway`], on what the engine answered: the
/// control-plane address of the connected profile, and that profile.
fn gateway_profile<'v>(
    state: &str,
    view: &'v ConfigView,
) -> Result<(String, &'v orion_engine::ProfileView), String> {
    if aether::TunnelState::parse(state) != Some(aether::TunnelState::Up) {
        return Err(NO_CONNECTED_GATEWAY.to_string());
    }
    view.selected
        .as_deref()
        .and_then(|name| view.profiles.iter().find(|profile| profile.name == name))
        .and_then(|profile| {
            profile
                .heliosd_url
                .as_deref()
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .map(|url| (url.to_string(), profile))
        })
        .ok_or_else(|| NO_CONNECTED_GATEWAY.to_string())
}

#[cfg(test)]
mod tests;
