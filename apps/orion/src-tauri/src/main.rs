// Prevents opening a Windows console in release mode.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Tauri shell of the Orion client.
//!
//! Thin wiring layer: it contains no WireGuard logic (delegated to
//! `orion-core`). Its role is to:
//! 1. expose `invoke` commands to the frontend (connect/disconnect, profile CRUD);
//! 2. relay the core's [`ClientEvent`]s to the frontend (`emit`);
//! 3. start heliosd telemetry **only** when the tunnel goes `Up`
//!    (the web server lives behind WireGuard) and stop it on disconnection.

/// Windows is the target platform: nothing is simulated there.
///
/// Without the `wireguard` feature, [`orion_core::default_backend`] falls back
/// to the dry-run backend — legitimate on WSL2, where the data plane does not
/// exist, and nowhere else. An installed Orion that mounts nothing while
/// displaying a profile, an address and a negotiated mode is a client that
/// protects nothing and says so only in a corner of the Connection screen.
///
/// Refusing at compile time rather than at startup is deliberate: the flag is
/// a build decision, and the person who forgot it is the one building. Use
/// `cargo xtask orion-msi`, which carries the features in one place.
#[cfg(all(target_os = "windows", not(feature = "wireguard")))]
compile_error!(
    "Orion for Windows must be built with --features wireguard: without it the shell falls \
     back to the simulated backend, which encrypts nothing. Build with `cargo xtask orion-msi`."
);

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
};

#[cfg(debug_assertions)]
use std::{
    net::{SocketAddr, TcpStream},
    process::{Child, Command},
    time::{Duration, Instant},
};

use aether::TunnelState;
use orion_core::{
    backend::EventSink, complete_profile_import, default_backend, inspect_profile,
    parse_profile_import, read_profile_import_path, telemetry, ClientConfig, ClientEvent,
    ClientProfile, ProfileIssues, ProtectedIdentityStore, VpnController,
};
#[cfg(target_os = "windows")]
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    WindowEvent,
};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{watch, Mutex};

/// Shared application state, injected into each command via [`State`].
struct AppState {
    controller: Arc<VpnController>,
    /// Vault-backed store. `config` below is the in-memory view the UI reads;
    /// this is what actually persists, and it never writes a secret in the
    /// clear (ADR-006 §3).
    store: Arc<orion_core::vault::ProfileStore>,
    config: Arc<Mutex<ClientConfig>>,
    telemetry: Arc<TelemetryManager>,
    pending_profile_paths: StdMutex<VecDeque<PathBuf>>,
    /// Imported profiles the user has not saved yet, keyed by display name.
    ///
    /// # Why the secret waits here rather than on screen
    ///
    /// An import produces a **draft**: the user reviews the endpoint and the
    /// pinned fingerprint before committing, and a valid file must not silently
    /// replace a profile of the same name. That review used to happen with the
    /// private key sitting in a WebView text field, because the draft was
    /// returned whole to JavaScript.
    ///
    /// The draft still goes to the screen — redacted — and the key it carries
    /// waits here instead, for the one gesture that follows. `save_profile`
    /// takes it; anything else drops it when Orion closes, which loses nothing:
    /// the document can be imported again.
    pending_imports: Arc<Mutex<std::collections::HashMap<String, ClientProfile>>>,
}

/// Polling interval for the last WireGuard handshake.
///
/// WireGuard is connectionless: the `Up` state is inferred from handshake
/// freshness, it's never notified (ADR-001 §3). Without this loop, the UI
/// would stay stuck on the last known state.
///
/// Three seconds rather than ten: this loop is what turns a tunnel that has
/// stopped answering into a visible state change, and ten seconds of a
/// screen claiming a dead tunnel is alive is ten seconds too many. A
/// negotiated connection no longer waits on it at all — the negotiation
/// announces `Up` itself, having just observed the handshake.
const HANDSHAKE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);

#[cfg(debug_assertions)]
const FRONTEND_DEV_PORT: u16 = 1420;

/// Vite server launched by Orion when the development binary is run
/// directly with Cargo. The Tauri CLI already starts it via
/// `beforeDevCommand`; in that case, Orion detects the open port and
/// doesn't create a second process.
#[cfg(debug_assertions)]
struct FrontendDevServer {
    child: Child,
}

#[cfg(debug_assertions)]
impl Drop for FrontendDevServer {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            if error.kind() != std::io::ErrorKind::InvalidInput {
                tracing::warn!(%error, "unable to stop Orion's Vite server");
            }
        }
        let _ = self.child.wait();
    }
}

#[cfg(debug_assertions)]
fn frontend_dev_is_ready() -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], FRONTEND_DEV_PORT));
    TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok()
}

/// Guarantees Tauri's `devUrl` responds before the window is created.
///
/// `cargo run` doesn't know about `beforeDevCommand`, unlike the Tauri CLI.
/// Without this bridge, WebKit loads `localhost:1420` while no frontend is
/// listening and the user gets an empty window.
#[cfg(debug_assertions)]
fn ensure_frontend_dev_server() -> anyhow::Result<Option<FrontendDevServer>> {
    if frontend_dev_is_ready() {
        return Ok(None);
    }

    let frontend_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Orion frontend directory not found"))?;
    let vite_entrypoint = frontend_dir.join("node_modules/vite/bin/vite.js");
    if !vite_entrypoint.is_file() {
        anyhow::bail!("Vite is missing; run `npm ci --prefix apps/orion` before launching Orion");
    }

    tracing::info!("automatically starting Orion's Vite frontend");
    let mut child = Command::new("node")
        .arg(vite_entrypoint)
        .args(["--host", "127.0.0.1", "--port"])
        .arg(FRONTEND_DEV_PORT.to_string())
        .arg("--strictPort")
        .current_dir(frontend_dir)
        .spawn()
        .map_err(|error| anyhow::anyhow!("unable to start Vite with Node.js: {error}"))?;

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if frontend_dev_is_ready() {
            return Ok(Some(FrontendDevServer { child }));
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("Vite stopped before serving the Orion UI ({status})");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Vite did not open port 1420 within the 15-second timeout");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Manages the telemetry task's lifecycle (only one active at a time).
#[derive(Default)]
struct TelemetryManager {
    cancel: StdMutex<Option<watch::Sender<bool>>>,
}

impl TelemetryManager {
    /// Starts a telemetry loop toward `url`, cancelling any previous one.
    fn start(&self, url: String, sink: EventSink) {
        self.stop();
        let (tx, rx) = watch::channel(false);
        *self.cancel.lock().unwrap() = Some(tx);
        tokio::spawn(telemetry::run(url, sink, rx));
    }

    /// Cancels the current telemetry loop, if any.
    fn stop(&self) {
        if let Some(tx) = self.cancel.lock().unwrap().take() {
            let _ = tx.send(true);
        }
    }
}

/// Builds a sink that relays each core event to the frontend.
fn emit_sink(app: AppHandle) -> EventSink {
    Arc::new(move |ev: ClientEvent| {
        let _ = app.emit("helios://event", &ev);
    })
}

/// Shows the main window after it was hidden in the Windows notification area.
fn reveal_main_window(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window("main") {
        window.show()?;
        window.unminimize()?;
        window.set_focus()?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
const TRAY_OPEN_MENU_ID: &str = "orion-tray-open";
#[cfg(target_os = "windows")]
const TRAY_QUIT_MENU_ID: &str = "orion-tray-quit";

/// Installs Orion in the Windows notification area.
///
/// Hiding the window deliberately leaves the process and VPN controller
/// untouched. The tunnel and its key-negotiation liveness link therefore keep
/// running exactly as they did while the window was visible.
#[cfg(target_os = "windows")]
fn configure_windows_tray(app: &mut tauri::App) -> anyhow::Result<()> {
    let open_item = MenuItem::with_id(app, TRAY_OPEN_MENU_ID, "Ouvrir Orion", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, TRAY_QUIT_MENU_ID, "Quitter Orion", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open_item, &quit_item])?;
    let icon = app
        .default_window_icon()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Orion's default window icon is unavailable"))?;

    TrayIconBuilder::with_id("orion-notification-area")
        .icon(icon)
        .tooltip("Orion")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            if event.id() == TRAY_OPEN_MENU_ID {
                if let Err(error) = reveal_main_window(app) {
                    tracing::warn!(%error, "unable to reveal Orion from the notification area");
                }
            } else if event.id() == TRAY_QUIT_MENU_ID {
                app.exit(0);
            }
        })
        .on_tray_icon_event(|tray, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                if let Err(error) = reveal_main_window(tray.app_handle()) {
                    tracing::warn!(%error, "unable to reveal Orion from the notification area");
                }
            }
        })
        .build(app)?;

    Ok(())
}

/// Turns the Windows title-bar close button into a hide-to-tray action.
#[cfg(target_os = "windows")]
fn hide_main_window_on_close(window: &tauri::Window, event: &WindowEvent) {
    if window.label() != "main" {
        return;
    }
    if let WindowEvent::CloseRequested { api, .. } = event {
        api.prevent_close();
        if let Err(error) = window.hide() {
            tracing::warn!(%error, "unable to hide Orion in the notification area");
        }
    }
}

// ─── Commands invoked by the frontend ───────────────────────────────────────

// WireGuard has only one suite (ChaCha20-Poly1305). Post-quantum protection
// comes from the ML-KEM PSK, automatically negotiated after the classic
// tunnel is mounted as soon as the profile carries an internal Helios URL —
// see `orion_core::backend::upgrade_to_post_quantum`.

#[tauri::command]
fn get_state(state: State<'_, AppState>) -> String {
    state.controller.state().as_str().to_string()
}

#[tauri::command]
fn backend_kind(state: State<'_, AppState>) -> &'static str {
    state.controller.backend_kind()
}

/// Indicates whether the WireGuard adapter is still mounted. On failure, it
/// must remain up to capture routes and prevent a clear-text leak.
#[tauri::command]
fn adapter_is_up(state: State<'_, AppState>) -> bool {
    state.controller.adapter_is_up()
}

/// What this machine can do with the gateway's key-negotiation port.
///
/// The negotiation itself is no longer a build option — it is compiled into
/// every Orion, because a binary that looks normal and refuses every pinned
/// profile at connection time is indistinguishable, for the user, from a
/// broken gateway. What remains conditional is the **machine**: the protected
/// certificate store is supplied by the shell, and DPAPI exists only on
/// Windows. The screen says so instead of letting the user find out when the
/// connection fails.
#[derive(serde::Serialize)]
struct KeyNegotiationSupport {
    identity_store: bool,
}

#[tauri::command]
fn key_negotiation_support(state: State<'_, AppState>) -> KeyNegotiationSupport {
    KeyNegotiationSupport {
        identity_store: state.controller.key_negotiation_ready(),
    }
}

/// Is this profile's identity already sealed on this machine?
///
/// Answered without unsealing: the screen needs to know whether the import
/// still has to happen, and that question must not depend on the session
/// being able to decrypt. `false` also covers "no negotiation block" — a
/// profile that needs no identity needs no import either.
#[tauri::command]
fn key_negotiation_identity_sealed(
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
) -> bool {
    // Takes the block alone rather than a whole profile: this answers a
    // question about the negotiation identity, and passing the profile would
    // have meant shipping its secrets across the IPC to read one field.
    let Some(settings) = key_negotiation else {
        return false;
    };
    ProtectedIdentityStore::for_current_user().is_ok_and(|store| store.contains(&settings.identity))
}

/// Fingerprint of the gateway PQ certificate pinned by a profile.
///
/// Same reasoning as [`profile_public_key`]: the value is derived on the Rust
/// side and displayed so the user can compare it, out loud or by phone, with
/// what `heliosd init-key-negotiation` printed on the gateway.
#[tauri::command]
fn key_negotiation_fingerprint(
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
) -> Option<String> {
    key_negotiation.and_then(|settings| settings.gateway_pq_fingerprint())
}

/// A profile **as the interface is allowed to see it** (ADR-006 §5).
///
/// # Why the WireGuard private key is not in here
///
/// It used to be. `get_config` cloned the whole `ClientProfile` across the
/// Tauri IPC, and the Profiles screen put it in a text field with a button to
/// reveal it. That single path defeated most of what the vault buys: the key
/// was serialised into a JSON message, parsed into a JavaScript `String` —
/// immutable, garbage-collected, impossible to wipe — held in a DOM node's
/// value for as long as the screen lived, and readable by anything that could
/// reach the WebView. Sealing a secret on disk and then handing it to a
/// browser engine is protecting the quiet half of its life.
///
/// ADR-006 §5 already forbids exactly this for the `nomade` passphrase — "ni le
/// DOM WebView2, ni JavaScript, ni un message Tauri sérialisé". The private key
/// is the secret that actually brings the tunnel up. The same rule applies, and
/// applies more.
///
/// What the screen genuinely needs is here: everything it displays or edits,
/// plus the **public** key it exists to show the operator, plus two booleans
/// saying whether the secrets are present. Nothing it needs requires the
/// secret itself.
#[derive(Debug, Clone, serde::Serialize)]
struct ProfileView {
    name: String,
    endpoint: String,
    peer_public_key: String,
    address: Option<String>,
    allowed_ips: String,
    persistent_keepalive: u16,
    heliosd_url: Option<String>,
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
    /// Public half of the profile's WireGuard key. The one value of the pair
    /// that is *meant* to leave the machine — it is what the operator admits.
    public_key: Option<String>,
    /// Whether a private key is stored. The screen shows a state, not a value.
    has_private_key: bool,
    /// Whether a **static** PSK is stored. A negotiated one is never at rest.
    has_static_psk: bool,
}

impl From<&ClientProfile> for ProfileView {
    fn from(profile: &ClientProfile) -> Self {
        Self {
            name: profile.name.clone(),
            endpoint: profile.endpoint.clone(),
            peer_public_key: profile.peer_public_key.clone(),
            address: profile.address.clone(),
            allowed_ips: profile.allowed_ips.clone(),
            persistent_keepalive: profile.persistent_keepalive,
            heliosd_url: profile.heliosd_url.clone(),
            key_negotiation: profile.key_negotiation.clone(),
            public_key: profile.public_key(),
            has_private_key: !profile.private_key.trim().is_empty(),
            has_static_psk: profile.has_static_psk(),
        }
    }
}

/// The configuration as the interface sees it: profiles, redacted.
#[derive(Debug, Clone, serde::Serialize)]
struct ConfigView {
    profiles: Vec<ProfileView>,
    selected: Option<String>,
}

impl From<&ClientConfig> for ConfigView {
    fn from(config: &ClientConfig) -> Self {
        Self {
            profiles: config.profiles.iter().map(ProfileView::from).collect(),
            selected: config.selected.clone(),
        }
    }
}

/// What the screen sends back when the user saves.
///
/// The secrets are **write-only and optional**: the interface never received
/// them, so it cannot send them back, and `None` therefore means *keep what is
/// stored*. That asymmetry is deliberate — it is what lets a profile be edited
/// without its private key ever making the round trip.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileDraft {
    name: String,
    endpoint: String,
    peer_public_key: String,
    address: Option<String>,
    allowed_ips: String,
    persistent_keepalive: u16,
    heliosd_url: Option<String>,
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
    /// Draws a fresh WireGuard key pair **in Rust** and adopts it.
    ///
    /// The only way this build creates a key. It never travels: the screen
    /// asks, `orion-core` generates, the vault seals, and the answer that comes
    /// back is the public half. A user who wants a new key gets one without any
    /// part of the pair crossing the IPC.
    #[serde(default)]
    generate_private_key: bool,
    /// Clears the stored static PSK. There is deliberately no field to *set*
    /// one from the screen: a static PSK is an out-of-band value, and the
    /// enrolment document is what carries it.
    #[serde(default)]
    clear_preshared_key: bool,
}

impl ProfileDraft {
    /// Merges the draft onto what is stored, keeping every secret in Rust.
    ///
    /// `stored` is `None` for a profile the user is creating, which is the one
    /// case where a key must be generated: refusing instead would leave the
    /// screen with no way at all to make a profile, and inventing an empty key
    /// would produce one that fails `validate` with a message about enrolment.
    fn merge(self, stored: Option<&ClientProfile>) -> Result<ClientProfile, String> {
        let mut profile = match stored {
            Some(profile) => profile.clone(),
            None => ClientProfile {
                name: self.name.clone(),
                ..ClientProfile::default()
            },
        };
        if self.generate_private_key || stored.is_none() {
            let pair = aether::wg::generate_keypair()
                .map_err(|error| format!("génération de la paire de clés : {error}"))?;
            profile.private_key = pair.private_key.expose().to_string();
        }
        if self.clear_preshared_key {
            profile.preshared_key = None;
        }
        profile.name = self.name;
        profile.endpoint = self.endpoint;
        profile.peer_public_key = self.peer_public_key;
        profile.address = self.address;
        profile.allowed_ips = self.allowed_ips;
        profile.persistent_keepalive = self.persistent_keepalive;
        profile.heliosd_url = self.heliosd_url;
        profile.key_negotiation = self.key_negotiation;
        // A stored profile never carries a negotiated PSK: that one only ever
        // exists in the ephemeral copy the backend mounts.
        profile.preshared_key_is_negotiated = false;
        Ok(profile)
    }
}

#[tauri::command]
async fn get_config(state: State<'_, AppState>) -> Result<ConfigView, String> {
    Ok(ConfigView::from(&*state.config.lock().await))
}

/// Result of an import: the draft profile, and what became of the identity.
///
/// The identity's fate is reported rather than raised because the two are
/// independent: a profile stays perfectly importable on a machine that cannot
/// seal, and hiding the profile behind that failure would leave the user with
/// nothing at all — not even the endpoint to check.
#[derive(serde::Serialize)]
struct ImportOutcome {
    /// The draft, redacted. Its private key waits in `pending_imports`.
    profile: ProfileView,
    /// `true` when the document carried an identity **and** it was sealed.
    identity_sealed: bool,
    /// Why sealing failed, when the document carried one and it did not.
    identity_error: Option<String>,
    /// Why the draft has no private key, when the document was an invitation
    /// and no local profile held the admitted half.
    private_key_missing: Option<String>,
}

/// Seals the identity shipped with a document, if any.
///
/// Import is where this happens because it is the only moment the plaintext
/// exists: from here on the material lives sealed in the store, and the
/// profile keeps nothing but the name of the entry.
fn seal_identity(identity: Option<orion_core::ClientIdentityBundle>) -> (bool, Option<String>) {
    let Some(identity) = identity else {
        return (false, None);
    };
    let sealed = ProtectedIdentityStore::for_current_user()
        .and_then(|store| store.store(&identity))
        .map(|_| ());
    match sealed {
        Ok(()) => (true, None),
        // `{:#}` keeps the anyhow context chain: the platform reason is the
        // useful half of the message.
        Err(error) => (false, Some(format!("{error:#}"))),
    }
}

/// Decodes a document chosen by the user without persisting it.
///
/// The UI displays the result as a draft: a valid file therefore never
/// silently replaces a profile with the same name. The identity, on the other
/// hand, is sealed straight away — it is a secret, and the shorter it stays
/// in memory the better.
#[tauri::command]
async fn import_profile(
    state: State<'_, AppState>,
    contents: String,
    file_name: String,
) -> Result<ImportOutcome, String> {
    let imported =
        parse_profile_import(&contents, &file_name).map_err(|error| error.to_string())?;
    finish_import(&state, imported).await
}

/// Rereads a profile whose path comes from the system association.
///
/// `path = None` consumes the next path queued at startup or forwarded by
/// the single-instance plugin. The frontend calls this form after
/// installing its listener, which makes the first double-click as reliable
/// as subsequent ones.
#[tauri::command]
async fn import_profile_path(
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
        return Err("seuls les fichiers .orionprofile sont acceptés par cette commande".into());
    }
    let imported = read_profile_import_path(&path).map_err(|error| error.to_string())?;
    finish_import(&state, imported).await.map(Some)
}

/// Seals the identity, completes the draft, and reports both fates.
///
/// Shared by the two import paths on purpose: the file picker and the system
/// association must not differ by one gesture — a document that seals its
/// identity on a double-click and not through the button would be
/// impossible to explain.
async fn finish_import(
    state: &State<'_, AppState>,
    imported: orion_core::ProfileImport,
) -> Result<ImportOutcome, String> {
    // Read before the bundle is consumed by sealing: it is the certificate
    // that says which key was admitted.
    let admitted = imported.admitted_public_key();
    let (identity_sealed, identity_error) = seal_identity(imported.identity);
    let completed = {
        let config = state.config.lock().await;
        complete_profile_import(imported.profile, &config, admitted.as_deref())
            .map_err(|error| error.to_string())?
    };

    // The draft goes to the screen redacted; its private key stays here until
    // the user saves. Returning it whole is what put a WireGuard private key
    // into the WebView in the first place (ADR-006 §5).
    let view = ProfileView::from(&completed.profile);
    state
        .pending_imports
        .lock()
        .await
        .insert(completed.profile.name.clone(), completed.profile);

    Ok(ImportOutcome {
        profile: view,
        identity_sealed,
        identity_error,
        private_key_missing: completed.private_key_missing,
    })
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
async fn vault_posture(
    state: State<'_, AppState>,
) -> Result<orion_core::vault::VaultPosture, String> {
    Ok(state.store.posture())
}

/// Merges a draft onto the stored profile and seals the result.
///
/// The volume-encryption gate is here rather than in the store because this is
/// the moment a secret is about to be written: ADR-006 §3 makes BitLocker a
/// **verified prerequisite**, not a recommendation, because application
/// encryption reaches neither the old SSD blocks nor the hibernation file.
#[tauri::command]
async fn save_profile(
    state: State<'_, AppState>,
    draft: ProfileDraft,
) -> Result<ConfigView, String> {
    let mut cfg = state.config.lock().await;
    require_protected_volume(&state)?;
    // A profile already stored wins over a pending import of the same name:
    // editing an existing profile must not silently adopt the key of a
    // document imported earlier in the session and never saved.
    let stored = match cfg.find(&draft.name).cloned() {
        Some(profile) => Some(profile),
        None => state.pending_imports.lock().await.remove(&draft.name),
    };
    let profile = draft.merge(stored.as_ref())?;
    let selected = profile.name.clone();
    state
        .store
        .save_profile(&profile)
        .map_err(|e| e.to_string())?;
    cfg.upsert(profile);
    cfg.selected = Some(selected.clone());
    state.store.select(&selected).map_err(|e| e.to_string())?;
    Ok(ConfigView::from(&*cfg))
}

#[tauri::command]
async fn delete_profile(state: State<'_, AppState>, name: String) -> Result<ConfigView, String> {
    let mut cfg = state.config.lock().await;
    state
        .store
        .remove_profile(&name)
        .map_err(|e| e.to_string())?;
    cfg.remove(&name);
    Ok(ConfigView::from(&*cfg))
}

#[tauri::command]
async fn select_profile(state: State<'_, AppState>, name: String) -> Result<ConfigView, String> {
    let mut cfg = state.config.lock().await;
    state.store.select(&name).map_err(|e| e.to_string())?;
    cfg.selected = Some(name);
    Ok(ConfigView::from(&*cfg))
}

/// Refuses to write a secret onto a volume nothing encrypts (ADR-006 §3).
///
/// `Indeterminate` refuses just like `Unprotected`: a posture we cannot
/// establish is a posture we cannot promise, and the failure mode of guessing
/// "probably fine" is a user believing their disk is protected when it is not.
fn require_protected_volume(state: &State<'_, AppState>) -> Result<(), String> {
    state.store.may_write_secrets().map_err(|error| {
        format!(
            "{error} `danger_allow_unencrypted_volume = true` dans settings.toml l'autorise \
             explicitement, en retirant la couverture des anciens blocs disque et du fichier \
             d'hibernation."
        )
    })
}

#[tauri::command]
async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    name: Option<String>,
) -> Result<(), String> {
    let profile = {
        let cfg = state.config.lock().await;
        match name {
            Some(n) => cfg.find(&n).cloned(),
            None => cfg.selected.as_deref().and_then(|n| cfg.find(n)).cloned(),
        }
        .ok_or_else(|| "aucun profil sélectionné".to_string())?
    };

    // Validates the WireGuard profile (endpoint + keys) BEFORE any side effect.
    profile.validate().map_err(|e| e.to_string())?;

    // A key that once lived in plaintext is presumed compromised, and sealing
    // the file did not recall the copies already in backups or roaming
    // profiles. ADR-006 §3 makes such a profile unconnectable until a new key
    // is generated and re-admitted — and the posture panel already tells the
    // user exactly that. Until this check existed, the panel said it and
    // nothing enforced it: the profile connected on the compromised key while
    // the screen claimed it would not.
    let rotation_required = state.store.rotation_required().unwrap_or_default();
    if rotation_required.contains(&profile.name) {
        return Err(format!(
            "« {} » a été repris d'un fichier en clair : sa clé privée est présumée compromise. \
             Générer une nouvelle clé et la faire admettre par l'opérateur avant de vous \
             connecter.",
            profile.name
        ));
    }

    // Sink combining relay to the frontend AND telemetry control: telemetry
    // only starts on transition to Up (web behind the tunnel).
    let base = emit_sink(app.clone());
    let telemetry = Arc::clone(&state.telemetry);
    let heliosd_url = profile.heliosd_url.clone();
    let app_for_tel = app.clone();
    let negotiating = profile.key_negotiation.is_some();
    let negotiated_profile = profile.name.clone();
    let config = Arc::clone(&state.config);
    let store = Arc::clone(&state.store);
    let sink: EventSink = Arc::new(move |ev: ClientEvent| {
        // Mirror of the gateway rule: a committed negotiation raises this
        // profile's floor for good. Helios does the same on its side and
        // would refuse a weaker mode afterwards — a client that kept
        // offering one would only produce a failed connection the user
        // couldn't explain.
        if negotiating {
            if let ClientEvent::Protection { psk } = &ev {
                raise_key_negotiation_floor(
                    Arc::clone(&config),
                    Arc::clone(&store),
                    negotiated_profile.clone(),
                    *psk,
                );
            }
        }
        if let ClientEvent::StateChanged { state } = &ev {
            match state {
                TunnelState::Up => {
                    if let Some(url) = heliosd_url.clone() {
                        telemetry.start(url, emit_sink(app_for_tel.clone()));
                    }
                }
                TunnelState::Down | TunnelState::Failed => telemetry.stop(),
                _ => {}
            }
        }
        base(ev);
    });

    state.controller.connect(profile, sink.clone()).await;

    // State inference loop: WireGuard notifies nothing, we poll the age of
    // the last handshake. Never touches the adapter (ADR-001 §3 bis).
    let controller = Arc::clone(&state.controller);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HANDSHAKE_POLL_INTERVAL);
        loop {
            ticker.tick().await;
            if controller.state() == TunnelState::Down {
                break; // explicit disconnection: nothing left to infer
            }
            controller.poll_handshake(sink.clone()).await;
        }
    });

    Ok(())
}

/// Persists a floor raise announced by a committed negotiation.
///
/// Runs in a task because the sink is synchronous while the configuration is
/// behind an async lock. A failed write is logged and nothing else: the
/// session in progress stays valid, and the gateway keeps its own floor —
/// which is the one that actually refuses a downgrade.
///
/// # Why this goes through the vault and not through `ClientConfig::save`
///
/// It used to call `cfg.save()`, which writes `profiles.toml` — the **legacy
/// plaintext file** ADR-006 exists to retire, in the very directory the store
/// occupies. Every negotiated connection that raised a floor therefore rewrote
/// the client's private key and static PSK in the clear on disk, undoing the
/// whole lot; the next start then found the file, migrated it again, and
/// marked the profile as having lived in plaintext. Raising a floor is a
/// security event, and it must be recorded the way every other one is.
fn raise_key_negotiation_floor(
    config: Arc<Mutex<ClientConfig>>,
    store: Arc<orion_core::vault::ProfileStore>,
    name: String,
    observed: orion_core::PskKind,
) {
    use aether::key_negotiation::ProtectionMode;

    let reached = match observed {
        orion_core::PskKind::MlKem => ProtectionMode::MlKem,
        orion_core::PskKind::Static => ProtectionMode::StaticPsk,
        // Classic commits nothing to raise.
        orion_core::PskKind::None => return,
    };
    tokio::spawn(async move {
        let mut cfg = config.lock().await;
        let Some(profile) = cfg.profiles.iter_mut().find(|profile| profile.name == name) else {
            return;
        };
        let Some(settings) = profile.key_negotiation.as_mut() else {
            return;
        };
        if settings.minimum_mode.satisfies(reached) {
            return;
        }
        settings.minimum_mode = reached;
        // Cloned out of the guard so the sealed write does not hold the lock
        // across an I/O the UI is waiting behind.
        let raised = profile.clone();
        drop(cfg);
        if let Err(error) = store.save_profile(&raised) {
            tracing::warn!(%error, "unable to persist the raised key-negotiation floor");
        }
    });
}

#[tauri::command]
async fn disconnect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    state.telemetry.stop();
    state.controller.disconnect(emit_sink(app)).await;
    Ok(())
}

/// Reports the faulty fields of a profile being edited.
///
/// Validation stays **on the Rust side**: the UI highlights what the core
/// refuses, it doesn't reimplement its rules. Two rule sets would eventually
/// diverge, and the UI would accept values the connection rejects.
#[tauri::command]
async fn validate_profile(
    state: State<'_, AppState>,
    draft: ProfileDraft,
) -> Result<ProfileIssues, String> {
    // Merged against what is stored before judging: the draft carries no
    // private key by construction, so inspecting it on its own would report
    // "clé privée requise" on every profile that has one — a red field the
    // user cannot clear, on a value they are not allowed to see.
    let cfg = state.config.lock().await;
    let stored = match cfg.find(&draft.name).cloned() {
        Some(profile) => Some(profile),
        // Peeked, not removed: validation runs on every keystroke, and
        // consuming the import here would make the third character typed lose
        // the key the first two had.
        None => state.pending_imports.lock().await.get(&draft.name).cloned(),
    };
    let profile = draft.merge(stored.as_ref())?;
    Ok(inspect_profile(&profile))
}

/// Window dimensions depending on the displayed view.
///
/// Each view has different needs: connection fits in a narrow column, the
/// profile form needs two columns, the log wants width so it doesn't wrap
/// its lines. A single window would force taking the maximum of the three
/// at all times.
///
/// An unknown view falls back to the "connection" size: it's the startup
/// view, and a default size is better than an error for a label only the
/// UI produces.
fn window_size_for(view: &str) -> (f64, f64) {
    match view {
        "profiles" => (800.0, 720.0),
        "logs" => (760.0, 640.0),
        // Connection has only an orb, a state, and a button: giving it the
        // height of the other views only produced a hole in the middle.
        _ => (520.0, 560.0),
    }
}

/// Adjusts the window to the requested view.
///
/// Resizing lives **on the Rust side** because exposing it to the frontend
/// would require `core:window:allow-set-size` in the capabilities — a
/// general right over the window for three sizes known at compile time.
#[tauri::command]
fn resize_for_view(app: AppHandle, view: String) -> Result<(), String> {
    let (width, height) = window_size_for(&view);
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "fenêtre principale introuvable".to_string())?;
    window
        .set_size(tauri::LogicalSize::new(width, height))
        .map_err(|e| format!("redimensionnement de la fenêtre : {e}"))
}

/// Export bound. The frontend log is capped at 80 lines, but the command
/// doesn't trust that bound: it comes from the caller.
const MAX_LOG_EXPORT_BYTES: usize = 512 * 1024;

/// Reduces a label proposed by the frontend to a safe file name.
///
/// The frontend picks the label — it's the only one that knows the local
/// time — but never the path. Only ordinary name characters survive, which
/// at once eliminates separators, `..`, and disguised extensions: an export
/// must not be able to write anywhere but the directory the command chose.
fn sanitize_stem(proposed: &str) -> String {
    let cleaned: String = proposed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "orion-journal".to_string()
    } else {
        cleaned
    }
}

/// Writes the log to a file and returns its path.
///
/// Goes through a command rather than the `dialog`/`fs` plugins: Orion only
/// grants `core:default` as a capability, and opening general disk access
/// to the frontend for a simple export would be disproportionate.
#[tauri::command]
fn export_logs(app: AppHandle, stem: String, contents: String) -> Result<String, String> {
    if contents.len() > MAX_LOG_EXPORT_BYTES {
        return Err("journal trop volumineux pour être exporté".to_string());
    }
    let dir = app
        .path()
        .document_dir()
        .or_else(|_| app.path().app_data_dir())
        .map_err(|e| format!("aucun répertoire d'export disponible : {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("création de {} : {e}", dir.display()))?;
    let path = dir.join(format!("{}.log", sanitize_stem(&stem)));
    std::fs::write(&path, contents).map_err(|e| format!("écriture de {} : {e}", path.display()))?;
    Ok(path.display().to_string())
}

fn is_associated_profile_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("orionprofile"))
}

fn associated_profile_paths(args: &[String], cwd: &Path) -> Vec<PathBuf> {
    args.iter()
        .skip(1)
        .map(PathBuf::from)
        .filter(|path| is_associated_profile_path(path))
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            }
        })
        .take(1)
        .collect()
}

/// `defguard_wireguard_rs 0.11.0` opens WireGuardNT via a relative path fixed
/// in its source. A double-click gives Orion a current directory that may
/// be the profile's; we replace it before building the backend.
#[cfg(all(target_os = "windows", feature = "wireguard"))]
fn prepare_wireguard_nt_working_directory() -> anyhow::Result<()> {
    #[cfg(target_arch = "x86_64")]
    const DLL: &str = "resources-windows/binaries/wireguard-amd64.dll";
    #[cfg(target_arch = "aarch64")]
    const DLL: &str = "resources-windows/binaries/wireguard-arm64.dll";

    let executable_dir = std::env::current_exe()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("Orion binary directory not found"))?;
    let source_dir = if executable_dir.join(DLL).is_file() {
        executable_dir
    } else {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .ok_or_else(|| anyhow::anyhow!("Orion workspace root not found"))?;
        if !workspace.join(DLL).is_file() {
            anyhow::bail!(
                "WireGuardNT is missing ({DLL}); run `cargo xtask orion-deps` before Orion"
            );
        }
        workspace.to_path_buf()
    };
    std::env::set_current_dir(&source_dir).map_err(|error| {
        anyhow::anyhow!(
            "unable to select WireGuardNT resources in {}: {error}",
            source_dir.display()
        )
    })
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    #[cfg(debug_assertions)]
    let _frontend_dev_server =
        ensure_frontend_dev_server().expect("unable to prepare Orion's development UI");

    let startup_cwd = std::env::current_dir().unwrap_or_default();
    let startup_args: Vec<String> = std::env::args().collect();
    let pending_profile_paths = associated_profile_paths(&startup_args, &startup_cwd).into();

    #[cfg(all(target_os = "windows", feature = "wireguard"))]
    prepare_wireguard_nt_working_directory()
        .expect("unable to prepare the WireGuardNT DLL shipped with Orion");

    let backend = default_backend().expect(
        "real WireGuard backend unavailable — Orion refuses to start with implicit simulation",
    );
    let controller = VpnController::new(backend);
    // The protected store is the shell's job: `orion-core` states the
    // boundary, the platform implementation lives with the platform.
    let controller = match ProtectedIdentityStore::for_current_user() {
        Ok(store) => controller.with_key_negotiation_identities(Arc::new(store)),
        Err(error) => {
            // Not fatal: profiles without negotiation still connect, and the
            // Profiles screen reports the missing store rather than letting
            // the failure surface as an unexplained refused connection.
            tracing::warn!(%error, "no protected identity store on this machine");
            controller
        }
    };
    let controller = Arc::new(controller);

    // Le stockage des profils passe par le coffre (ADR-006 §3) : `profiles.toml`
    // n'est plus qu'un format d'import. Hors Windows le fournisseur refuse, et
    // c'est le comportement spécifié — écrire la racine en clair offrirait une
    // protection que l'écran promettrait sans la rendre.
    let store_dir = orion_core::vault::ProfileStore::default_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));

    // Le contournement matériel est un choix local, lu à chaque démarrage. Un
    // fichier illisible ne l'active jamais : appliquer la valeur permissive
    // parce qu'une lecture a échoué est la façon dont une dégradation arrive
    // sans que personne l'ait décidée.
    let (settings, complaint) = orion_core::vault::LocalSettings::load(&store_dir);
    if let Some(complaint) = complaint {
        tracing::warn!(%complaint, "réglages locaux du coffre");
    }
    let waived = settings.danger_allow_software_keystore;
    let bare_volume = settings.danger_allow_unencrypted_volume;

    let store = Arc::new(
        orion_core::vault::ProfileStore::new(
            store_dir.clone(),
            Box::new(
                orion_core::vault::windows::PlatformRootKeyProvider::new(
                    store_dir.join("device-root"),
                )
                .allowing_software_keystore(waived),
            ),
        )
        .allowing_software_keystore(waived)
        .allowing_unencrypted_volume(bare_volume),
    );

    // Deux situations opposées, deux messages. Les confondre créditerait
    // l'opérateur d'une décision qu'il n'a pas prise, ou masquerait celle
    // qu'il a prise (ADR-006 §3).
    if waived {
        // À **chaque** démarrage, pas seulement à l'activation : une
        // dégradation qui ne se rappelle plus finit par être oubliée.
        tracing::warn!(
            "SÉCURITÉ MATÉRIELLE DÉSACTIVÉE par danger_allow_software_keystore — \
             la résistance à la copie inter-machine, au rollback matériel et à un \
             administrateur de domaine détenant les clés DPAPI n'est plus assurée"
        );
    } else if !store.hardware_backed() {
        tracing::error!(
            "aucune racine matérielle sur ce poste et aucun contournement déclaré — \
             Orion refuse de conserver des secrets. Poser \
             `danger_allow_software_keystore = true` dans {} l'autorise \
             explicitement, en retirant les garanties correspondantes",
            store_dir
                .join(orion_core::vault::settings::SETTINGS_FILE)
                .display()
        );
    }
    // Une configuration héritée est reprise dans le coffre avant tout usage, et
    // ses profils restent bloqués jusqu'à rotation de clé : le sceller ne
    // rappelle pas les copies déjà parties en sauvegarde.
    //
    // La migration est conditionnée au chiffrement du volume (ADR-006 §3) :
    // elle réécrit le secret ailleurs sur le même disque, et sur un volume nu
    // cela le recopie sans retirer l'ancien. Mieux vaut laisser le fichier
    // hérité en place, visible dans la posture, que produire une seconde copie
    // en croyant l'avoir protégée.
    if bare_volume {
        // À chaque démarrage, comme pour le coffre logiciel : une dégradation
        // qui cesse de se rappeler finit par être oubliée.
        tracing::warn!(
            "CHIFFREMENT DE VOLUME NON EXIGÉ par danger_allow_unencrypted_volume — \
             les anciens blocs disque, le fichier d'échange et celui d'hibernation ne sont \
             pas couverts"
        );
    }
    if let Err(error) = store.may_write_secrets() {
        tracing::error!(
            %error,
            "migration du fichier hérité suspendue. `danger_allow_unencrypted_volume = true` \
             dans {} l'autorise explicitement",
            store_dir
                .join(orion_core::vault::settings::SETTINGS_FILE)
                .display()
        );
    } else {
        match store.migrate_legacy() {
            Ok(report) if !report.migrated.is_empty() => tracing::warn!(
                profils = ?report.rotation_required,
                "profils repris du fichier en clair — rotation de clé obligatoire"
            ),
            Ok(_) => {}
            Err(error) => tracing::error!(%error, "migration du fichier hérité impossible"),
        }
    }
    let config = store.load().unwrap_or_else(|error| {
        tracing::error!(%error, "coffre illisible — aucun profil chargé");
        ClientConfig::default()
    });

    tauri::Builder::default()
        // Must stay the first plugin registered: it intercepts the secondary
        // instance before other plugins can act.
        .plugin(tauri_plugin_single_instance::init(|app, args, cwd| {
            let paths = associated_profile_paths(&args, Path::new(&cwd));
            if !paths.is_empty() {
                let state = app.state::<AppState>();
                state.pending_profile_paths.lock().unwrap().extend(paths);
                let _ = app.emit("helios://profile-path", ());
            }
            if let Err(error) = reveal_main_window(app) {
                tracing::warn!(%error, "unable to reveal Orion from the secondary instance");
            }
        }))
        .manage(AppState {
            controller,
            store,
            config: Arc::new(Mutex::new(config)),
            telemetry: Arc::new(TelemetryManager::default()),
            pending_profile_paths: StdMutex::new(pending_profile_paths),
            pending_imports: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
        .setup(|_app| {
            #[cfg(target_os = "windows")]
            configure_windows_tray(_app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            #[cfg(target_os = "windows")]
            hide_main_window_on_close(window, event);
            #[cfg(not(target_os = "windows"))]
            let _ = (window, event);
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            backend_kind,
            adapter_is_up,
            get_config,
            import_profile,
            import_profile_path,
            save_profile,
            delete_profile,
            select_profile,
            connect,
            disconnect,
            export_logs,
            resize_for_view,
            validate_profile,
            key_negotiation_support,
            key_negotiation_fingerprint,
            key_negotiation_identity_sealed,
            vault_posture,
        ])
        .run(tauri::generate_context!())
        .expect("error while launching Tauri");
}

#[cfg(test)]
mod security_tests {
    use super::{
        associated_profile_paths, sanitize_stem, window_size_for, ClientProfile, ConfigView, Path,
        PathBuf, ProfileDraft, ProfileView,
    };

    fn profile(name: &str) -> ClientProfile {
        let pair = aether::wg::generate_keypair().expect("keypair");
        let gateway = aether::wg::generate_keypair().expect("keypair");
        ClientProfile {
            name: name.into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: pair.private_key.expose().to_string(),
            peer_public_key: gateway.public_key,
            preshared_key: Some("cHNrLXN0YXRpcXVlLWhvcnMtYmFuZGU=".into()),
            address: Some("100.64.1.2/32".into()),
            ..ClientProfile::default()
        }
    }

    fn draft(name: &str) -> ProfileDraft {
        ProfileDraft {
            name: name.into(),
            endpoint: "203.0.113.10:51820".into(),
            peer_public_key: "cHVibGlj".into(),
            address: None,
            allowed_ips: "0.0.0.0/0".into(),
            persistent_keepalive: 25,
            heliosd_url: None,
            key_negotiation: None,
            generate_private_key: false,
            clear_preshared_key: false,
        }
    }

    /// **The** property of this lot: no secret crosses the Tauri IPC.
    ///
    /// The check is on the serialised bytes rather than on a list of fields we
    /// remembered to omit. A field added later that happens to carry a secret
    /// fails here, not in a WebView memory dump.
    #[test]
    fn no_secret_is_ever_serialised_towards_the_interface() {
        let profile = profile("poste");
        let private_key = profile.private_key.clone();
        let psk = profile.preshared_key.clone().expect("psk");

        let config = super::ClientConfig {
            profiles: vec![profile],
            selected: Some("poste".into()),
        };
        let json = serde_json::to_string(&ConfigView::from(&config)).expect("serialise");

        assert!(
            !json.contains(&private_key),
            "la clé privée traverse l'IPC :\n{json}"
        );
        assert!(!json.contains(&psk), "le PSK statique traverse l'IPC");
        // What the screen legitimately needs is still there.
        assert!(json.contains("publicKey") || json.contains("public_key"));
        assert!(json.contains("203.0.113.10:51820"));
    }

    /// The view states the *presence* of a secret, never its value.
    #[test]
    fn the_view_reports_presence_and_the_public_half() {
        let profile = profile("poste");
        let expected = profile.public_key().expect("public key");
        let view = ProfileView::from(&profile);

        assert!(view.has_private_key);
        assert!(view.has_static_psk);
        assert_eq!(view.public_key.as_deref(), Some(expected.as_str()));

        let bare = ClientProfile {
            name: "vide".into(),
            ..ClientProfile::default()
        };
        let view = ProfileView::from(&bare);
        assert!(!view.has_private_key);
        assert!(!view.has_static_psk);
        assert_eq!(view.public_key, None);
    }

    /// A draft that never carried the secret must not erase it on save.
    ///
    /// This is what makes the redaction usable rather than merely safe: the
    /// user edits an endpoint, the screen sends back everything it knows —
    /// which excludes the key — and the stored key survives untouched.
    #[test]
    fn editing_a_profile_keeps_the_secrets_it_never_saw() {
        let stored = profile("poste");
        let key = stored.private_key.clone();
        let psk = stored.preshared_key.clone();

        let mut edit = draft("poste");
        edit.endpoint = "198.51.100.7:51820".into();
        let merged = edit.merge(Some(&stored)).expect("merge");

        assert_eq!(merged.private_key, key, "la clé stockée a été perdue");
        assert_eq!(merged.preshared_key, psk, "le PSK stocké a été perdu");
        assert_eq!(merged.endpoint, "198.51.100.7:51820");
    }

    /// A new profile gets a key drawn in Rust, and so does an explicit rotation.
    #[test]
    fn a_key_is_drawn_in_rust_and_never_travels() {
        let created = draft("nouveau").merge(None).expect("merge");
        assert!(
            !created.private_key.trim().is_empty(),
            "un profil neuf doit recevoir une clé"
        );
        assert!(created.public_key().is_some(), "la clé doit être valide");

        let mut rotation = draft("poste");
        rotation.generate_private_key = true;
        let rotated = rotation.merge(Some(&created)).expect("merge");
        assert_ne!(
            rotated.private_key, created.private_key,
            "une rotation demandée doit produire une nouvelle clé"
        );
    }

    /// Clearing a static PSK is explicit, and is the only way to touch it.
    #[test]
    fn a_static_psk_can_only_be_cleared_never_set_from_the_screen() {
        let stored = profile("poste");
        let mut clearing = draft("poste");
        clearing.clear_preshared_key = true;
        assert_eq!(
            clearing.merge(Some(&stored)).expect("merge").preshared_key,
            None
        );

        // And a merge never marks a stored PSK as negotiated: that flag belongs
        // to the ephemeral profile the backend mounts, nowhere else.
        assert!(
            !draft("poste")
                .merge(Some(&stored))
                .expect("merge")
                .preshared_key_is_negotiated
        );
    }

    /// Each view has its size, and an unexpected label must not produce a
    /// degenerate window: it falls back to the startup view.
    #[test]
    fn each_view_has_its_size_and_unknown_falls_back_to_connect() {
        let connect = window_size_for("connect");
        assert_eq!(window_size_for("unknown"), connect);
        assert_ne!(window_size_for("profiles"), connect);
        assert_ne!(window_size_for("logs"), connect);
        // The profile form is the most demanding view of the three.
        for view in ["connect", "logs"] {
            assert!(window_size_for("profiles").0 >= window_size_for(view).0);
        }
        // No size drops below the minimum declared in tauri.conf.json.
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let window = &config["app"]["windows"][0];
        let (min_w, min_h) = (
            window["minWidth"].as_f64().expect("minWidth"),
            window["minHeight"].as_f64().expect("minHeight"),
        );
        for view in ["connect", "profiles", "logs"] {
            let (w, h) = window_size_for(view);
            assert!(w >= min_w, "{view} : {w} < {min_w}");
            assert!(h >= min_h, "{view} : {h} < {min_h}");
        }
    }

    /// The frontend names the export, it doesn't place it. Anything that
    /// could designate another directory must disappear from the label.
    #[test]
    fn the_export_name_cannot_designate_another_path() {
        assert_eq!(
            sanitize_stem("orion-journal-2026-07-23"),
            "orion-journal-2026-07-23"
        );
        assert_eq!(sanitize_stem("../../etc/passwd"), "etcpasswd");
        assert_eq!(
            sanitize_stem("C:\\Windows\\System32\\x"),
            "CWindowsSystem32x"
        );
        assert_eq!(sanitize_stem("journal.log.exe"), "journallogexe");
        // An empty or entirely filtered label falls back to a default name
        // rather than producing a hidden ".log" file.
        assert_eq!(sanitize_stem(""), "orion-journal");
        assert_eq!(sanitize_stem("../.."), "orion-journal");
        assert_eq!(sanitize_stem(&"a".repeat(200)).len(), 64);
    }

    #[test]
    fn cargo_run_server_aligns_with_the_tauri_dev_url() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let expected = format!("http://localhost:{}", super::FRONTEND_DEV_PORT);

        assert_eq!(config["build"]["devUrl"].as_str(), Some(expected.as_str()));
    }

    #[test]
    fn tauri_configuration_enforces_a_csp_and_freezes_prototypes() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let security = &config["app"]["security"];
        let csp = security["csp"].as_str().expect("Tauri CSP required");

        assert_eq!(security["freezePrototype"], true);
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(!csp.contains("unsafe-eval"));
        assert!(!csp.contains("script-src *"));
        assert!(!csp.contains("connect-src *"));
    }

    #[test]
    fn bundle_declares_association_and_linux_capability() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let association = &config["bundle"]["fileAssociations"][0];
        assert_eq!(association["ext"], serde_json::json!(["orionprofile"]));
        assert_eq!(
            config["bundle"]["linux"]["deb"]["postInstallScript"],
            "linux/postinst"
        );
        assert!(config["bundle"]["linux"]["deb"]["depends"]
            .as_array()
            .unwrap()
            .iter()
            .any(|dependency| dependency == "libcap2-bin"));
        let postinst = include_str!("../linux/postinst");
        assert!(postinst.contains("setcap cap_net_admin=ep"));
    }

    #[test]
    fn windows_bundle_ships_wireguard_and_requires_timestamped_signtool() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.windows.conf.json")).unwrap();
        assert_eq!(
            config["bundle"]["resources"]["../../../resources-windows/"],
            "resources-windows/"
        );
        let args = config["bundle"]["windows"]["signCommand"]["args"]
            .as_array()
            .unwrap();
        assert!(args.iter().any(|arg| arg == "windows/sign-orion.ps1"));
        let signer = include_str!("../windows/sign-orion.ps1");
        for required in ["ORION_TIMESTAMP_URL", "/tr", "/td", "SHA256", "/tw"] {
            assert!(signer.contains(required), "missing element: {required}");
        }
    }

    #[test]
    fn tauri_capabilities_stay_minimal() {
        let capabilities: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        assert_eq!(capabilities["windows"], serde_json::json!(["main"]));
        assert_eq!(
            capabilities["permissions"],
            serde_json::json!(["core:default"])
        );
    }

    #[test]
    fn association_only_forwards_orion_profiles() {
        let args = vec![
            "orion.exe".to_string(),
            "invitation.orionprofile".to_string(),
            "--unexpected".to_string(),
            "other.json".to_string(),
        ];
        assert_eq!(
            associated_profile_paths(&args, Path::new("/profils")),
            vec![PathBuf::from("/profils/invitation.orionprofile")]
        );
    }

    #[test]
    fn windows_manifest_requires_administrator_privileges() {
        let manifest = include_str!("../windows/orion-manifest.xml");
        assert!(manifest.contains("requireAdministrator"));
        assert!(manifest.contains("Microsoft.Windows.Common-Controls"));
    }
}
