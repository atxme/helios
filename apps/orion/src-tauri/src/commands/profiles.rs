//! Profiles: their views, import, editing, keys and PSK, the protected
//! volume, the SSH terminal, and validation.

use super::*;
use orion_core::{read_profile_document, ProfileIssues};
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
    match state.client.call(EngineCommand::GeneratePrivateKey).await? {
        EngineReply::PublicKey(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
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
    // Zeroizing from the first instruction: the engine receives it as a secret.
    let private_key = SecretInput::from(private_key);
    match state
        .client
        .call(EngineCommand::AdoptPrivateKey { private_key })
        .await?
    {
        EngineReply::PublicKey(value) => Ok(value),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Drops the staged key without saving it.
#[tauri::command]
pub(crate) async fn discard_staged_key(state: State<'_, AppState>) -> Result<(), String> {
    match state.client.call(EngineCommand::DiscardStagedKey).await? {
        EngineReply::Unit => Ok(()),
        _ => Err(unexpected_engine_reply()),
    }
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
    let preshared_key = SecretInput::from(preshared_key);
    match state
        .client
        .call(EngineCommand::AdoptPresharedKey { preshared_key })
        .await?
    {
        EngineReply::Unit => Ok(()),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Drops the staged PSK without saving it.
#[tauri::command]
pub(crate) async fn discard_staged_psk(state: State<'_, AppState>) -> Result<(), String> {
    match state.client.call(EngineCommand::DiscardStagedPsk).await? {
        EngineReply::Unit => Ok(()),
        _ => Err(unexpected_engine_reply()),
    }
}

/// Opens a terminal connected to the gateway, **below** Orion's privileges.
///
/// # The escalation this is written against
///
/// The UI runs at its caller's level (the manifest asks for `asInvoker`,
/// `the_manifest_asks_for_the_invoker_level`), and only the engine is elevated.
/// Nothing stops a UI started from an elevated shell from being elevated,
/// though, and a child inherits its parent's token: the ordinary
/// `Command::spawn` would then hand out an **Administrator** shell from one
/// click, with no UAC prompt of its own, to whoever can reach this window —
/// or anything that can reach this command, the webview included.
///
/// So [`crate::launch`] refuses to start anything while Windows reports the
/// UI's own token as elevated; otherwise the terminal inherits that
/// non-elevated token.
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

use crate::launch::spawn_ssh_terminal;

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
    let view = match state
        .client
        .call(EngineCommand::SaveProfile { draft })
        .await?
    {
        EngineReply::Config(value) => value,
        _ => return Err(unexpected_engine_reply()),
    };
    tray::refresh(&app);
    Ok(view)
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
    let view = match state
        .client
        .call(EngineCommand::DeleteProfile { name })
        .await?
    {
        EngineReply::Config(value) => value,
        _ => return Err(unexpected_engine_reply()),
    };
    tray::refresh(&app);
    Ok(view)
}

#[tauri::command]
pub(crate) async fn select_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
) -> Result<ConfigView, String> {
    let view = match state
        .client
        .call(EngineCommand::SelectProfile { name })
        .await?
    {
        EngineReply::Config(value) => value,
        _ => return Err(unexpected_engine_reply()),
    };
    tray::refresh(&app);
    Ok(view)
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
