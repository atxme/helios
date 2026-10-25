//! Profiles: their views, import, editing, keys and PSK, the protected
//! volume, the SSH terminal, and validation.

use super::*;
use orion_core::{read_profile_document, ProfileIssues};
use orion_engine::service::{merge_draft, profile_edit_base, StagedKey, StagedPsk};
use orion_engine::{
    ConfigView, EngineCommand, EngineReply, ImportOutcome, ProfileDraft, SecretInput,
};

#[tauri::command]
pub(crate) async fn get_config(state: State<'_, AppState>) -> Result<ConfigView, String> {
    match state.client.call(EngineCommand::GetConfig).await? {
        EngineReply::Config(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Decodes a document chosen by the user without persisting it.
///
/// The UI displays the result as a draft: a valid file therefore never
/// silently replaces a profile with the same name. The identity, on the other
/// hand, is sealed straight away — it is a secret, and the shorter it stays
/// in memory the better.
#[tauri::command]
pub(crate) async fn import_profile(
    state: State<'_, AppState>,
    contents: String,
    file_name: String,
) -> Result<ImportOutcome, String> {
    match state
        .client
        .call(EngineCommand::ImportProfile {
            contents: SecretInput::from(contents),
            file_name,
        })
        .await?
    {
        EngineReply::Imported(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Rereads a profile whose path comes from the system association.
///
/// `path = None` consumes the next path queued at startup or forwarded by
/// the single-instance plugin. The frontend calls this form after
/// installing its listener, which makes the first double-click as reliable
/// as subsequent ones.
#[tauri::command]
pub(crate) async fn import_profile_path(
    state: State<'_, AppState>,
    path: Option<String>,
) -> Result<Option<ImportOutcome>, String> {
    let path = match path {
        Some(path) => PathBuf::from(path),
        None => match state.pending_profile_paths.lock().unwrap().pop_front() {
            Some(path) => path,
            None => return Ok(None),
        },
    };
    if !is_associated_profile_path(&path) {
        return Err(format!(
            "seuls les fichiers .{PROFILE_EXTENSION} sont acceptés par cette commande"
        ));
    }
    // Read here, by the process the user is in: the engine parses the text it
    // is sent and never opens a path the UI chose.
    let (contents, file_name) = read_profile_document(&path).map_err(|error| error.to_string())?;
    match state
        .client
        .call(EngineCommand::ImportProfile {
            contents: SecretInput::from(contents),
            file_name,
        })
        .await?
    {
        EngineReply::Imported(value) => Ok(Some(value)),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Public key corresponding to a profile's private key.
///
/// This is what the user communicates to the operator to be admitted on the
/// gateway (ADR-004 §6): deriving it here avoids making them manipulate
/// their private key in a terminal to obtain a value that is, itself, public.
/// What the vault can honestly claim about itself (ADR-006 §3).
///
/// Read on every call rather than cached: BitLocker can be suspended and the
/// memory-lock privilege can change while Orion runs, and a posture panel that
/// showed a stale "protected" would be worse than one that showed nothing.
#[tauri::command]
pub(crate) async fn vault_posture(
    state: State<'_, AppState>,
) -> Result<orion_core::vault::VaultPosture, String> {
    match state.client.call(EngineCommand::VaultPosture).await? {
        EngineReply::VaultPosture(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Persists the user's informed choice to keep profiles on a bare volume.
///
/// This command is deliberately separate from import/save: the interface must
/// first state the guarantees being withdrawn, and an ordinary write must
/// never turn a missing BitLocker posture into consent by itself.
#[tauri::command]
pub(crate) async fn allow_unencrypted_volume(
    state: State<'_, AppState>,
) -> Result<orion_core::vault::VaultPosture, String> {
    match state
        .client
        .call(EngineCommand::AllowUnencryptedVolume)
        .await?
    {
        EngineReply::VaultPosture(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Draws a WireGuard key pair and returns its **public** half.
///
/// The private half stays in
/// [`orion_engine::service::EngineService::staged_key`] until the profile is
/// saved. Returning the public key straight away is what makes the enrolment
/// workflow possible at all: the user copies it, hands it to the operator, and
/// receives an admitted profile — none of which can happen if the key only
/// comes into existence when the form is submitted.
#[tauri::command]
pub(crate) async fn generate_private_key(state: State<'_, AppState>) -> Result<String, String> {
    let pair = aether::wg::generate_keypair()
        .map_err(|error| format!("génération de la paire de clés : {error}"))?;
    let aether::wg::Keypair {
        private_key,
        public_key,
    } = pair;
    let returned_public_key = public_key.clone();
    *state.engine.staged_key.lock().await = Some(StagedKey {
        private_key,
        public_key,
    });
    Ok(returned_public_key)
}

/// Adopts a private key the user supplies, and returns its public half.
///
/// # Why this exists, having been refused once
///
/// An earlier revision removed every way of entering a key, on the grounds
/// that one arriving through the interface has crossed JavaScript. That is
/// true, and it is a real cost — but it left no path for the ordinary case of
/// a key produced by `wg genkey` or carried by an existing `wg-quick` file, and
/// a client that cannot accept an existing identity is not a client.
///
/// The direction is what makes this acceptable. A key **entering** crosses the
/// IPC once, at an explicit gesture, and the field is cleared immediately
/// after. A key **leaving** would sit in the DOM for as long as the screen
/// lives, on every render, for a value nobody asked to see. ADR-006 §5 forbids
/// the second; this is not it.
///
/// Validation happens here rather than on screen: `orion-core` owns the rules,
/// and a key the interface accepted but the core refuses would be a profile
/// that fails at connection time with a message about enrolment.
#[tauri::command]
pub(crate) async fn adopt_private_key(
    state: State<'_, AppState>,
    private_key: String,
) -> Result<String, String> {
    // Take ownership of the IPC buffer in a zeroizing container immediately.
    // Normalization necessarily creates a second buffer to preserve the prior
    // trimmed-storage behavior; the original is then dropped through
    // SecretString as soon as this binding is replaced.
    let private_key = SecretString::new(private_key);
    let normalized = SecretString::new(private_key.expose().trim().to_owned());
    let public_key = aether::wg::public_from_private(normalized.expose()).map_err(|_| {
        "clé privée invalide : une clé WireGuard est 32 octets encodés en base64 \
         (44 caractères finissant par « = »)"
            .to_string()
    })?;
    *state.engine.staged_key.lock().await = Some(StagedKey {
        private_key: normalized,
        public_key: public_key.clone(),
    });
    Ok(public_key)
}

/// Drops the staged key without saving it.
#[tauri::command]
pub(crate) async fn discard_staged_key(state: State<'_, AppState>) -> Result<(), String> {
    // `Drop` zeroizes it: cancelling must not leave the key in memory for the
    // rest of the session.
    state.engine.staged_key.lock().await.take();
    Ok(())
}

/// Holds a static PSK the user supplies, until the profile is saved.
///
/// Validated here and not on screen, for the reason [`adopt_private_key`]
/// gives: `aether` owns the shape of a WireGuard secret, and a value the
/// interface accepted but WireGuard refuses would produce a profile whose
/// handshakes fail with nothing naming the cause. A PSK is a 32-byte base64
/// value — the same shape as a key, which is why the same validator answers.
///
/// Nothing is returned but success: unlike a key pair there is no public half
/// to show, and echoing the secret back would put it in the DOM for the life
/// of the screen.
#[tauri::command]
pub(crate) async fn adopt_preshared_key(
    state: State<'_, AppState>,
    preshared_key: String,
) -> Result<(), String> {
    let preshared_key = SecretString::new(preshared_key);
    let value = SecretString::new(preshared_key.expose().trim().to_owned());
    aether::wg::validate_key(value.expose()).map_err(|_| {
        "PSK invalide : un PSK WireGuard est 32 octets encodés en base64 \
         (44 caractères finissant par « = »), tel que le produit `wg genpsk`"
            .to_string()
    })?;
    *state.engine.staged_psk.lock().await = Some(StagedPsk { value });
    Ok(())
}

/// Drops the staged PSK without saving it.
#[tauri::command]
pub(crate) async fn discard_staged_psk(state: State<'_, AppState>) -> Result<(), String> {
    state.engine.staged_psk.lock().await.take();
    Ok(())
}

/// Opens a terminal connected to the gateway, **below** Orion's privileges.
///
/// # The escalation this is written against
///
/// Orion runs elevated, always and by design: WireGuard-NT cannot be loaded
/// otherwise, and the shipped manifest asks for `requireAdministrator`
/// (`windows_manifest_requires_administrator_privileges`). A child inherits
/// its parent's token, so the ordinary `Command::spawn` would hand out an
/// **Administrator** shell from one click, with no UAC prompt of its own, to
/// whoever can reach this window — or anything that can reach this command,
/// the webview included.
///
/// So the child is built from the standard-user token Windows already keeps
/// linked to the elevated one, and [`crate::deelevate`] refuses to launch
/// anything until Windows itself confirms that token is not elevated. See
/// that module for why a thread impersonation would not have worked.
///
/// Failure is a refusal, never a fallback: a machine with no linked token
/// gets an error naming the reason, and the user still has
/// [`ssh_command`] to copy and paste into a shell of their own.
#[tauri::command]
pub(crate) async fn open_ssh_terminal(
    state: State<'_, AppState>,
    name: Option<String>,
) -> Result<(), String> {
    let command = match state
        .client
        .call(EngineCommand::SshCommand { name })
        .await?
    {
        EngineReply::SshCommand(value) => value,
        _ => return Err(unexpected_engine_reply()),
    };
    // The engine answers with the line `ssh <cible>`; only the target is launched.
    let target = command
        .strip_prefix("ssh ")
        .ok_or("le moteur n'a pas rendu une commande « ssh <cible> » : rien n'est ouvert")?;
    // Checked again here, by the process that builds the command line: the
    // engine validated the profile, but this is where a string becomes a
    // shell invocation, and the allow-list costs nothing.
    orion_core::profile_import::validate_ssh_target(target).map_err(|error| error.to_string())?;
    spawn_ssh_terminal(target)
}

/// The same command line, for the user to paste into their own terminal.
///
/// Kept beside [`open_ssh_terminal`] rather than replaced by it: the launcher
/// legitimately refuses on machines with no standard-user token — UAC off, the
/// built-in Administrator account, a service context — and on those the copy
/// is the whole feature rather than a consolation.
#[tauri::command]
pub(crate) async fn ssh_command(
    state: State<'_, AppState>,
    name: Option<String>,
) -> Result<String, String> {
    match state
        .client
        .call(EngineCommand::SshCommand { name })
        .await?
    {
        EngineReply::SshCommand(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

#[cfg(target_os = "windows")]
use crate::deelevate::spawn_ssh_terminal;

/// Refuses explicitly rather than silently doing nothing.
///
/// # Limite connue
///
/// The launcher is Windows-only because the de-elevation is: it rests on the
/// linked token UAC produces, which has no equivalent elsewhere. A Linux or
/// macOS build reaches this arm and fails with a message naming the reason,
/// instead of opening a window that never appears. What would unblock it:
/// choosing a terminal on those platforms, and a way to drop privileges that
/// is theirs rather than Windows'.
#[cfg(not(target_os = "windows"))]
fn spawn_ssh_terminal(_target: &str) -> Result<(), String> {
    Err("l'ouverture d'un terminal SSH n'est disponible que sur Windows".into())
}

/// Merges a draft onto the stored profile and seals the result.
///
/// The volume-encryption gate is here rather than in the store because this is
/// the moment a secret is about to be written: ADR-006 §3 makes BitLocker a
/// **verified prerequisite**, not a recommendation, because application
/// encryption reaches neither the old SSD blocks nor the hibernation file.
#[tauri::command]
pub(crate) async fn save_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    draft: ProfileDraft,
) -> Result<ConfigView, String> {
    let mut cfg = state.engine.config.lock().await;
    require_protected_volume(&state)?;
    // A pending import wins over the stored profile of the same name. An
    // imported document may carry a *new* WireGuard private key together
    // with a newly sealed key-negotiation identity. Keeping the old profile
    // here would pair those two identities from different admissions: the
    // gateway accepts the TLS certificate, then rejects the request because
    // its WireGuard key is the old one. Ordinary edits never have a pending
    // import, so they still use the stored profile and preserve its secrets.
    let pending = state
        .engine
        .pending_imports
        .lock()
        .await
        .remove(&draft.name);
    let known = cfg.find(&draft.name);
    let stored = profile_edit_base(pending.as_ref(), known);
    // Taken, not peeked: the key is now the profile's, and leaving a copy in
    // the slot would let the next profile saved adopt it too.
    let staged = state.engine.staged_key.lock().await.take();
    let staged_psk = state.engine.staged_psk.lock().await.take();
    let profile = merge_draft(draft, stored, staged.as_ref(), staged_psk.as_ref())?;
    if let Some(known) = known {
        profile
            .check_replacement_of(known)
            .map_err(|error| error.to_string())?;
    }
    let selected = profile.name.clone();
    state
        .engine
        .store
        .save_profile(&profile)
        .map_err(|e| e.to_string())?;
    if let Some(block) = &profile.key_negotiation {
        settle_saved_enrollment(&block.identity);
    }
    cfg.upsert(profile).map_err(|error| error.to_string())?;
    cfg.selected = Some(selected.clone());
    state
        .engine
        .store
        .select(&selected)
        .map_err(|e| e.to_string())?;
    let view = ConfigView::from(&*cfg);
    // Released before the menu is rebuilt: the rebuild reads the same lock,
    // and holding it here would have it wait on the very command it follows.
    drop(cfg);
    tray::refresh(&app);
    Ok(view)
}

/// Destroys the pending enrollment record once its profile is saved.
///
/// The profile is already persisted when this runs, so a failure is not a
/// failed save: the record left behind holds sealed keys the user can still
/// discard from the enrollment list.
fn settle_saved_enrollment(identity: &str) {
    if let Err(error) = ProtectedIdentityStore::for_current_user()
        .and_then(|store| orion_core::enrollment::settle_enrollment(&store, identity))
    {
        tracing::warn!(error = %format!("{error:#}"), "pending enrollment record kept after save");
    }
}

/// Removes a profile, unmounting its tunnel first if that tunnel is the one up.
///
/// The order is the whole point (spec §12.2). The signed `release` that frees
/// the gateway's PSK slot travels **inside** the tunnel and is signed by the
/// profile's own identity, so it has to leave before either disappears.
/// Deleting first left the slot held until the gateway reclaimed it on
/// handshake silence, five minutes later — and left the adapter mounted for a
/// profile that no longer existed.
#[tauri::command]
pub(crate) async fn delete_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
) -> Result<ConfigView, String> {
    // Before the configuration lock, not after: the disconnection is a network
    // round trip, and `stop_connection` rebuilds nothing that needs the config
    // — but holding a lock across it would stall every other command for the
    // two seconds the release is allowed.
    if state.engine.controller.mounted_profile().await.as_deref() == Some(name.as_str()) {
        stop_connection(&app).await?;
    }
    let mut cfg = state.engine.config.lock().await;
    state
        .engine
        .store
        .remove_profile(&name)
        .map_err(|e| e.to_string())?;
    cfg.remove(&name);
    let view = ConfigView::from(&*cfg);
    drop(cfg);
    tray::refresh(&app);
    Ok(view)
}

#[tauri::command]
pub(crate) async fn select_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
) -> Result<ConfigView, String> {
    let mut cfg = state.engine.config.lock().await;
    state
        .engine
        .store
        .select(&name)
        .map_err(|e| e.to_string())?;
    cfg.selected = Some(name);
    let view = ConfigView::from(&*cfg);
    drop(cfg);
    tray::refresh(&app);
    Ok(view)
}

/// Refuses to write a secret onto a volume nothing encrypts (ADR-006 §3).
///
/// `Indeterminate` refuses just like `Unprotected`: a posture we cannot
/// establish is a posture we cannot promise, and the failure mode of guessing
/// "probably fine" is a user believing their disk is protected when it is not.
fn require_protected_volume(state: &State<'_, AppState>) -> Result<(), String> {
    state.engine.store.may_write_secrets().map_err(|error| {
        format!(
            "{error} `danger_allow_unencrypted_volume = true` dans settings.toml l'autorise \
             explicitement, en retirant la couverture des anciens blocs disque et du fichier \
             d'hibernation."
        )
    })
}

/// Reports the faulty fields of a profile being edited.
///
/// Validation stays **on the Rust side**: the UI highlights what the core
/// refuses, it doesn't reimplement its rules. Two rule sets would eventually
/// diverge, and the UI would accept values the connection rejects.
#[tauri::command]
pub(crate) async fn validate_profile(
    state: State<'_, AppState>,
    draft: ProfileDraft,
) -> Result<ProfileIssues, String> {
    match state
        .client
        .call(EngineCommand::ValidateProfile { draft })
        .await?
    {
        EngineReply::Issues(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}
