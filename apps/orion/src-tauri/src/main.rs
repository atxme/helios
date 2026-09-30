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

use aether::{SecretString, TunnelState};
use orion_core::{
    backend::EventSink, complete_profile_import, default_backend, inspect_profile,
    parse_profile_import, read_profile_import_path, telemetry, ClientConfig, ClientEvent,
    ClientProfile, ProfileIssues, ProtectedIdentityStore, VpnController,
};
#[cfg(target_os = "windows")]
use tauri::WindowEvent;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{watch, Mutex};

/// De-elevation of the SSH terminal. Windows-only: it rests on the linked
/// token UAC produces, which has no equivalent elsewhere.
#[cfg(target_os = "windows")]
mod deelevate;

/// Process launch is isolated behind a one-command Tauri plugin and a fixed
/// executable. Keeping it out of the application invoke handler makes the ACL
/// visible and prevents this shell from acquiring a generic process right.
mod companion;

/// Notification-area menu. Its model and labels are portable and tested
/// everywhere; only the wiring inside is Windows-only.
mod tray;

/// The Astra CA-TLS ceremony, driven from this window and signed elsewhere.
/// The vault, the PIN and the FIDO gesture stay inside the companion; only
/// the public progress states cross into Orion.
mod astra;
mod operator;

/// Shared application state, injected into each command via [`State`].
struct AppState {
    controller: Arc<VpnController>,
    /// Vault-backed store. `config` below is the in-memory view the UI reads;
    /// this is what actually persists, and it never writes a secret in the
    /// clear (ADR-006 §3).
    store: Arc<orion_core::vault::ProfileStore>,
    config: Arc<Mutex<ClientConfig>>,
    telemetry: Arc<TelemetryManager>,
    /// Serializes the expensive benchmark. The UI disables its button, but
    /// the Rust boundary still refuses a second IPC invocation so two tests
    /// cannot divide the same path and both report half of its capacity.
    speedtest: Mutex<()>,
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
    /// The key the user just generated or pasted, waiting to be saved.
    ///
    /// # The workflow this exists for
    ///
    /// Admission is out of band (ADR-004 §6): the user needs a **public** key
    /// to hand the operator *before* a profile can be completed, since the
    /// gateway must admit it before the first handshake. Producing that key
    /// only at save time made the screen show a dash where the value belonged,
    /// and left no way to copy it.
    ///
    /// So the key is drawn on the spot and its public half returned at once —
    /// visible, copiable, and stable until the profile is saved. The private
    /// half stays here. One slot rather than a map: the screen edits one
    /// profile at a time, and a slot that could hold two keys would eventually
    /// attach the wrong one.
    staged_key: Arc<Mutex<Option<StagedKey>>>,
    /// Static PSK entered on screen, held until the profile is saved.
    ///
    /// Same slot discipline as [`Self::staged_key`] and the same reason: the
    /// secret crosses the IPC once, at an explicit gesture, and never comes
    /// back out. `None` means "no new PSK this session" — whatever the profile
    /// already held is left alone.
    staged_psk: Arc<Mutex<Option<StagedPsk>>>,
    /// The Astra CA-TLS rotation this window is hosting, if one is open.
    ///
    /// Owned by Rust, not by the WebView: the ceremony outlives the view that
    /// started it — leaving the screen mid-rotation must not abandon a
    /// companion that is about to write a durable decision — and its phase is
    /// the one thing a reload has to be able to recover.
    astra: astra::Ceremony,
    /// The protocol-2 ceremony, which every operation but the `CA-TLS`
    /// rotation now runs through.
    operator: operator::OperatorCeremony,
    /// Why the vault could not be opened at startup, if it could not.
    ///
    /// Orion keeps running — the screen is more useful than a blank window —
    /// but on an empty profile list, and that emptiness poisons every later
    /// diagnosis. An import then concludes that no key of this machine matches
    /// the admitted one, which is false: the machine's keys were never read.
    /// Carrying the cause lets those messages say so.
    vault_error: Option<String>,
    /// The handshake-inference loop of the current connection, if one runs.
    ///
    /// One at a time, like telemetry, and for the same reason: each connection
    /// starts one, and a connection that failed leaves a loop with nothing left
    /// to infer. Without this slot every attempt piled up another task polling
    /// the adapter every three seconds for the life of the process.
    handshake_poll: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    /// Where this run writes its log, when it writes one.
    ///
    /// A release build has no console (`windows_subsystem = "windows"`), so the
    /// file is the only trace left of a start that went wrong — and a path
    /// nobody can find is a file nobody reads. The About box states it.
    log_path: Option<PathBuf>,
    /// Last certificate action that failed, per profile — the «dernière
    /// erreur» spec §12.2 asks the Certificates surface to display.
    ///
    /// In memory rather than persisted: it describes an attempt made in this
    /// session, and a message surviving a restart would outlive the situation
    /// it described — an identity imported since, a store now available.
    last_certificate_error: Arc<Mutex<std::collections::HashMap<String, String>>>,
    /// Renewals opened in this session, by profile name.
    ///
    /// Held in memory and nowhere else, because the session carries the
    /// candidate **private keys**. That is what makes an abandoned renewal
    /// leave nothing behind: closing Orion drops them, the authority's
    /// operation expires on its own, and the active generation was never
    /// touched. The cost is that a restart reopens rather than resumes — the
    /// cheap failure, since nothing was committed.
    renewals: Arc<Mutex<std::collections::HashMap<String, InFlightRenewal>>>,
    /// One automatic renewal timer for the mounted profile. It is cancelled
    /// with the connection so reconnecting cannot leave stale tasks racing a
    /// newer profile.
    certificate_renewal_task: Arc<StdMutex<Option<tauri::async_runtime::JoinHandle<()>>>>,
    /// Recoveries of expired identities in progress (§7.5).
    ///
    /// A separate map, for the same reason Astra keeps a separate store: a
    /// recovery reaches past a validity period, and an identifier from one
    /// must never resolve where an ordinary renewal is resumed. Absence
    /// carries the rule; a comparison would only describe it.
    recoveries: Arc<Mutex<std::collections::HashMap<String, InFlightRecovery>>>,
}

/// One recovery in progress: the session that drives it, and its profile.
struct InFlightRecovery {
    session: orion_core::certificate_recovery::RecoverySession,
    settings: orion_core::KeyNegotiationSettings,
}

/// One renewal in progress: what drives it, and the state it writes into.
struct InFlightRenewal {
    session: orion_core::certificate_renewal::RenewalSession,
    store: orion_core::certificates::TrustStore,
    settings: orion_core::KeyNegotiationSettings,
    /// The approval request, once read and verified.
    ///
    /// Held between the read and the ceremony so that what is signed is what
    /// was shown: a screen that displayed one manifest and then re-fetched
    /// before touching the key would be asking for a touch on something the
    /// user never saw.
    approval: Option<orion_core::certificate_approval::VerifiedApproval>,
}

/// A WireGuard key pair held between its creation and its save.
///
/// Never `Clone`, never `Serialize`: only [`StagedKey::public_key`] is meant to
/// leave this process, and it does so as a plain `String` the caller asks for
/// explicitly (ADR-006 §5).
struct StagedKey {
    private_key: SecretString,
    public_key: String,
}

/// A static PSK held between the moment it is typed and the save.
///
/// Nothing of it is meant to leave this process — not even a public half, for
/// there is none. The screen learns only that a value is waiting.
struct StagedPsk {
    value: SecretString,
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
/// negotiated connection no longer waits on it to *reach* `Up` — the
/// negotiation announces it itself, having just observed the handshake — but it
/// is still what makes it leave that state, a lost session link included.
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
///
/// It is also where the notification-area menu learns that the tunnel changed:
/// every path that mounts or drops one — the button, the tray, the handshake
/// poll that infers a loss — ends up here, and hooking the transition at this
/// single point is what keeps the menu from claiming a tunnel that is gone.
/// Only the transition, deliberately: telemetry arrives once a second, and
/// rebuilding the menu at that rate would rebuild it under the pointer.
fn emit_sink(app: AppHandle) -> EventSink {
    Arc::new(move |ev: ClientEvent| {
        if matches!(ev, ClientEvent::StateChanged { .. }) {
            tray::refresh(&app);
        }
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

/// What the About box states.
///
/// Four facts, and each one is there because a support exchange asked for it:
/// which version is installed, whether it drives a real adapter or the dry-run
/// backend, what a profile file looks like, and where the log is.
#[derive(serde::Serialize)]
struct AboutView {
    version: &'static str,
    backend: &'static str,
    /// Extension of an Orion profile, without the dot. Read from Rust rather
    /// than written in the interface: it is the same string the file
    /// association and the import filter use, and three copies of it would
    /// eventually disagree.
    profile_extension: &'static str,
    log_path: Option<String>,
}

#[tauri::command]
fn about_orion(state: State<'_, AppState>) -> AboutView {
    AboutView {
        version: env!("CARGO_PKG_VERSION"),
        backend: state.controller.backend_kind(),
        profile_extension: PROFILE_EXTENSION,
        log_path: state
            .log_path
            .as_ref()
            .map(|path| path.display().to_string()),
    }
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
fn certificate_inventory(
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
) -> orion_core::CertificateInventory {
    orion_core::certificate_inventory::inventory(key_negotiation.as_ref(), now_unix())
}

/// Everything the Certificates screen shows, for every profile at once.
///
/// One command rather than two per profile, and the reason is the protected
/// store: answering unseals it, and a screen listing six profiles would
/// otherwise make twelve DPAPI round trips to build one view.
#[derive(Debug, Clone, serde::Serialize)]
struct ProfileCertificates {
    name: String,
    /// Protected identity the profile names. Empty when it negotiates nothing.
    identity: String,
    /// The profile carries a key-negotiation block.
    negotiates: bool,
    inventory: orion_core::CertificateInventory,
    actions: Vec<orion_core::CertificateActionState>,
    last_error: Option<String>,
}

#[tauri::command]
async fn certificate_overview(
    state: State<'_, AppState>,
) -> Result<Vec<ProfileCertificates>, String> {
    let profiles: Vec<(String, Option<orion_core::KeyNegotiationSettings>)> = {
        let cfg = state.config.lock().await;
        cfg.profiles
            .iter()
            .map(|profile| (profile.name.clone(), profile.key_negotiation.clone()))
            .collect()
    };
    let errors = state.last_certificate_error.lock().await.clone();
    let identity_store = state.controller.key_negotiation_ready();
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
fn certificate_actions(
    state: State<'_, AppState>,
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
) -> Vec<orion_core::CertificateActionState> {
    let inventory =
        orion_core::certificate_inventory::inventory(key_negotiation.as_ref(), now_unix());
    orion_core::certificate_actions::action_states(
        key_negotiation.as_ref(),
        &inventory,
        state.controller.key_negotiation_ready(),
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
async fn run_certificate_action(
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
fn spawn_trust_refresh(
    settings: orion_core::KeyNegotiationSettings,
    heliosd_url: String,
    sink: EventSink,
) -> tauri::async_runtime::JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
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
fn spawn_automatic_certificate_renewal(
    prerequisite: tauri::async_runtime::JoinHandle<()>,
    controller: Arc<VpnController>,
    renewals: Arc<Mutex<std::collections::HashMap<String, InFlightRenewal>>>,
    profile_name: String,
    settings: orion_core::KeyNegotiationSettings,
    heliosd_url: String,
    sink: EventSink,
) -> tauri::async_runtime::JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
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
        let cfg = state.config.lock().await;
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
        state.controller.key_negotiation_ready(),
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
            state.last_certificate_error.lock().await.remove(name);
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
        let cfg = state.config.lock().await;
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

/// What one press produced, per profile.
///
/// A map and not a single step, because one of the four actions is
/// device-wide: returning the progress of the profile the press happened to
/// start from would have attributed five other renewals to it, and hidden the
/// approval each of them is waiting for.
#[derive(serde::Serialize, Clone, Debug, Default, PartialEq, Eq)]
struct ActionOutcome {
    progress: std::collections::BTreeMap<String, RenewalProgress>,
    /// Profiles that could not be advanced, and why.
    ///
    /// Only ever populated by the fleet action: a single-profile press reports
    /// its refusal as an error, exactly as before.
    refused: std::collections::BTreeMap<String, String>,
}

impl ActionOutcome {
    fn of(name: &str, step: RenewalProgress) -> Self {
        Self {
            progress: [(name.to_string(), step)].into_iter().collect(),
            refused: std::collections::BTreeMap::new(),
        }
    }
}

/// Where a renewal stands, as the Certificates surface states it.
///
/// `companion_command` is a **value**, not advice: it is the exact fallback for
/// the invocation Orion launches automatically. It remains visible while an
/// operator is awaited, including after a successful launch.
#[derive(serde::Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "step")]
enum RenewalProgress {
    AwaitingOperator {
        operation_id: String,
        companion_command: String,
    },
    Issuing {
        operation_id: String,
    },
    Committed {
        generation: u64,
    },
    /// A §7.5 recovery, waiting on an operator who is not on this machine.
    ///
    /// The operator runs `astra-signer` on **their** workstation, so nothing
    /// here can be launched. `operator_command` is still carried, and for the
    /// same reason the renewal carries its companion line: what travels
    /// between the two people is a command to run, not an identifier to be
    /// reassembled by hand into arguments only one of them knows.
    RecoveryAwaitingOperator {
        operation_id: String,
        operator_command: String,
    },
    Recovered {
        generation: u64,
        activation_at: u64,
    },
    RolledBack {
        generation: u64,
        available_until: u64,
    },
}

/// Launches the companion for the operation held by one renewal session.
///
/// Only the profile name crosses IPC. The executable and every argument come
/// from the session owned by `orion-core`, so the WebView cannot turn this
/// permission into a shell or retarget an approval to another operation.
#[tauri::command]
async fn launch_certificate_companion(
    state: State<'_, AppState>,
    name: String,
) -> Result<(), String> {
    let invocation = {
        let renewals = state.renewals.lock().await;
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

fn companion_plugin<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("companion")
        .invoke_handler(tauri::generate_handler![launch_certificate_companion])
        .build()
}

impl RenewalProgress {
    fn of_recovery(
        step: &orion_core::certificate_recovery::RecoveryStep,
        session: &orion_core::certificate_recovery::RecoverySession,
    ) -> Self {
        use orion_core::certificate_recovery::RecoveryStep;
        match step {
            RecoveryStep::AwaitingOperator { operation_id } => Self::RecoveryAwaitingOperator {
                operation_id: operation_id.to_hex(),
                operator_command: format!(
                    "astra-signer recover --authority-url {} --operation-id {}",
                    session.authority_url(),
                    operation_id.to_hex()
                ),
            },
            RecoveryStep::Issuing { operation_id } => Self::Issuing {
                operation_id: operation_id.to_hex(),
            },
            RecoveryStep::Recovered {
                generation,
                activation_at,
            } => Self::Recovered {
                generation: *generation,
                activation_at: *activation_at,
            },
        }
    }
}

impl RenewalProgress {
    fn of(
        step: &orion_core::certificate_renewal::RenewalStep,
        session: &orion_core::certificate_renewal::RenewalSession,
    ) -> Self {
        use orion_core::certificate_renewal::RenewalStep;
        match step {
            RenewalStep::AwaitingOperator { operation_id } => Self::AwaitingOperator {
                operation_id: operation_id.to_hex(),
                companion_command: session
                    .companion_invocation()
                    .map(|invocation| invocation.command_line())
                    .unwrap_or_default(),
            },
            RenewalStep::Issuing { operation_id } => Self::Issuing {
                operation_id: operation_id.to_hex(),
            },
            RenewalStep::Committed { generation } => Self::Committed {
                generation: *generation,
            },
        }
    }
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

    drive_renewal_in_map(&state.renewals, name, settings, url).await
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

    let mut recoveries = state.recoveries.lock().await;
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
async fn resume_certificate_recovery(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<ActionOutcome, String> {
    let operation = aether::certificates::encoding::Id16::parse_hex(&operation_id)
        .map_err(|_| "identifiant de récupération illisible".to_string())?;
    let found = {
        let recoveries = state.recoveries.lock().await;
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
            state.last_certificate_error.lock().await.remove(&name);
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
async fn certificate_approval_manifest(
    state: State<'_, AppState>,
    name: String,
) -> Result<orion_core::certificate_approval::ApprovalManifest, String> {
    let mut renewals = state.renewals.lock().await;
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
async fn approve_certificate_renewal(
    state: State<'_, AppState>,
    name: String,
    pin: Option<String>,
) -> Result<RenewalProgress, String> {
    let verified = {
        let mut renewals = state.renewals.lock().await;
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

    let mut renewals = state.renewals.lock().await;
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
async fn certificate_approval_needs_pin(
    state: State<'_, AppState>,
    name: String,
) -> Result<bool, String> {
    let renewals = state.renewals.lock().await;
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
async fn last_certificate_error(
    state: State<'_, AppState>,
    name: String,
) -> Result<Option<String>, String> {
    Ok(state
        .last_certificate_error
        .lock()
        .await
        .get(&name)
        .cloned())
}

/// Measures the raw WireGuard data path to the active gateway.
///
/// This command is intentionally available only while WireGuard is `Up`: the
/// gateway's API lives behind that tunnel, and the Rust engine targets its
/// fixed in-tunnel address. TCP/UDP data is exchanged on a dedicated socket;
/// this command only relays progress and keeps the expensive benchmark
/// serialized. The transfer implementation itself lives in `orion-core`, so
/// it remains testable without Tauri or WebView.
#[tauri::command]
async fn run_speed_test(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: String,
) -> Result<orion_core::SpeedTestResult, String> {
    let _exclusive = state
        .speedtest
        .try_lock()
        .map_err(|_| "un speedtest est déjà en cours".to_string())?;
    if state.controller.state() != TunnelState::Up || !state.controller.adapter_is_up() {
        return Err("le speedtest nécessite un tunnel WireGuard connecté".into());
    }
    let mode = orion_core::SpeedTestMode::parse(&mode).map_err(|error| error.to_string())?;
    let progress_app = app.clone();
    let progress: orion_core::SpeedTestProgressSink = Arc::new(move |update| {
        let _ = progress_app.emit("helios://speedtest", &update);
    });
    orion_core::run_speedtest_with_progress(
        mode,
        aether::speedtest::SPEEDTEST_DEFAULT_DURATION_SECS,
        // No override: the UI runs `full`, where the UDP quality legs take
        // their rate from the TCP throughput measured moments earlier.
        None,
        progress,
    )
    .await
    .map_err(|error| error.to_string())
}

/// Wall clock in Unix seconds, for the lifecycle's own arithmetic.
///
/// A clock behind the certificate's `not_before` reads as "not yet valid" and
/// one far ahead reads as expired, which is exactly what the connection would
/// conclude: the panel is wrong in the same direction as the failure, rather
/// than reassuring while the handshake refuses.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
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
    ssh_target: Option<String>,
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
    /// Which of the two shapes of spec §19 this profile is.
    ///
    /// Resolved, never `null`: a profile sealed before the discriminant
    /// existed still has a kind, and the screen shows what the connection
    /// path will act on rather than what the file happens to record.
    profile_type: &'static str,
    /// Public half of the profile's WireGuard key. The one value of the pair
    /// that is *meant* to leave the machine — it is what the operator admits.
    public_key: Option<String>,
    /// Whether a private key is stored. The screen shows a state, not a value.
    has_private_key: bool,
    /// Whether a **static** PSK is stored. A negotiated one is never at rest.
    has_static_psk: bool,
    /// The stored list captures all of IPv4 and lets IPv6 out.
    ///
    /// Decided by `orion-core`, not by the screen: the posture panel warns on
    /// it, and a rule re-derived in TypeScript is one more place for the two
    /// to disagree about which profiles leak. Reported only — the stored list
    /// is never widened on the user's behalf.
    ipv6_uncaptured_full_tunnel: bool,
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
            ssh_target: profile.ssh_target.clone(),
            key_negotiation: profile.key_negotiation.clone(),
            profile_type: profile.kind().as_str(),
            public_key: profile.public_key(),
            has_private_key: !profile.private_key.trim().is_empty(),
            has_static_psk: profile.has_static_psk(),
            ipv6_uncaptured_full_tunnel: profile.ipv6_uncaptured_full_tunnel(),
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
/// # Naming, and the bug it caused
///
/// The profile fields keep serde's **snake_case**, because that is what
/// `ClientProfile` and `KeyNegotiationSettings` use on the wire and what the
/// screen echoes back after receiving a [`ProfileView`]. A blanket
/// `rename_all = "camelCase"` here made every one of them a different name —
/// `save_profile` then refused the payload with `missing field peerPublicKey`,
/// and no test caught it: the TypeScript suite mocks the command, and the Rust
/// suite builds the struct directly. Neither crossed the boundary where the
/// names actually have to agree. `the_frontend_payload_deserialises` does.
///
/// Only the two **intents** are camelCase, because they exist nowhere else and
/// the screen writes them by hand.
#[derive(Debug, Clone, serde::Deserialize)]
struct ProfileDraft {
    name: String,
    endpoint: String,
    peer_public_key: String,
    address: Option<String>,
    allowed_ips: String,
    persistent_keepalive: u16,
    heliosd_url: Option<String>,
    ssh_target: Option<String>,
    key_negotiation: Option<orion_core::KeyNegotiationSettings>,
    /// Adopts the key sitting in [`AppState::staged_key`].
    ///
    /// Set by the screen after `generate_private_key` or `adopt_private_key`
    /// has already produced one and shown its **public** half. The private half
    /// never travels back: it waited in Rust the whole time.
    #[serde(default, rename = "useStagedKey")]
    use_staged_key: bool,
    /// Clears the stored static PSK.
    #[serde(default, rename = "clearPresharedKey")]
    clear_preshared_key: bool,
    /// Adopts the PSK sitting in [`AppState::staged_psk`].
    ///
    /// The enrolment document remains the ordinary way a static PSK arrives.
    /// It is not the only one: an operator who rotates a PSK out of band, or
    /// who runs a gateway pinned to `static_psk`, otherwise had to reissue a
    /// whole profile to change one value the screen was already displaying the
    /// absence of. The direction is what makes it acceptable — the secret
    /// enters once, on an explicit gesture, and no path returns it (ADR-006
    /// §5), exactly as for [`Self::use_staged_key`].
    #[serde(default, rename = "useStagedPsk")]
    use_staged_psk: bool,
}

impl ProfileDraft {
    /// Merges the draft onto what is stored, keeping every secret in Rust.
    ///
    /// `stored` is `None` for a profile the user is creating, which is the one
    /// case where a key must be generated: refusing instead would leave the
    /// screen with no way at all to make a profile, and inventing an empty key
    /// would produce one that fails `validate` with a message about enrolment.
    fn merge(
        self,
        stored: Option<&ClientProfile>,
        staged: Option<&StagedKey>,
        staged_psk: Option<&StagedPsk>,
    ) -> Result<ClientProfile, String> {
        let stored_kind = stored.map(ClientProfile::kind);
        let mut profile = match stored {
            Some(profile) => profile.clone(),
            None => ClientProfile {
                name: self.name.clone(),
                ..ClientProfile::default()
            },
        };
        if self.use_staged_key {
            let staged = staged.ok_or(
                "aucune clé en attente : générer ou importer une clé privée avant d'enregistrer",
            )?;
            // The public half was shown, copied, and handed to the operator for
            // admission. Saving a private key that derives to anything else
            // would produce a profile whose handshakes never succeed, with
            // nothing on either side naming the cause — the gateway admitted a
            // key this profile does not hold. Re-deriving costs microseconds.
            let derived = aether::wg::public_from_private(staged.private_key.expose())
                .map_err(|error| format!("clé en attente illisible : {error}"))?;
            if derived != staged.public_key {
                return Err(
                    "la clé en attente ne correspond plus à la clé publique affichée — \
                     regénérer avant d'enregistrer"
                        .into(),
                );
            }
            // `ClientProfile` is the existing persistence/backend contract and
            // still owns a plain String. This is the one deliberate copy from
            // the zeroizing staging buffer; the source remains protected until
            // the staged value is dropped by the caller.
            profile.private_key = staged.private_key.expose().to_owned();
        }
        if self.use_staged_psk {
            let staged = staged_psk
                .ok_or("aucun PSK en attente : saisir le PSK statique avant d'enregistrer")?;
            // Same compatibility boundary as the private key above: the
            // profile contract requires an owned String, so make the copy
            // explicit and keep the staged SecretString zeroizing on drop.
            profile.preshared_key = Some(staged.value.expose().to_owned());
        }
        // After adoption, never before: clearing is what the screen sends when
        // the requested mode no longer tolerates a static PSK, and that verdict
        // has to apply to the value being adopted too. The other order let a
        // PSK typed under `static_psk` survive a switch to ML-KEM made in the
        // same edit.
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
        profile.ssh_target = self.ssh_target;
        profile.key_negotiation = self.key_negotiation;
        // An existing stable profile keeps its declared variant. Switching
        // between classic and Helios requires another profile identifier (spec
        // §14, §19); deriving the kind from the edited block here made deleting
        // that block a persistent downgrade. A new draft has no history and is
        // stamped from the shape the user chose before its first save.
        profile.profile_type = Some(stored_kind.unwrap_or_else(|| {
            if profile.key_negotiation.is_some() {
                orion_core::ProfileKind::HeliosKeyNegotiation
            } else {
                orion_core::ProfileKind::Classic
            }
        }));
        profile.check_kind().map_err(|error| error.to_string())?;
        // A stored profile never carries a negotiated PSK: that one only ever
        // exists in the ephemeral copy the backend mounts.
        profile.preshared_key_is_negotiated = false;
        Ok(profile)
    }
}

/// Selects the profile that is actually being edited.
///
/// An import is a replacement transaction, not a suggestion layered over a
/// profile with the same display name. In particular, its private WireGuard
/// key and its sealed negotiation identity were issued as one pair.
fn profile_edit_base<'a>(
    pending_import: Option<&'a ClientProfile>,
    stored: Option<&'a ClientProfile>,
) -> Option<&'a ClientProfile> {
    pending_import.or(stored)
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
    /// What else the document leaves to fill in, if anything.
    incomplete: Option<String>,
    /// What the document said that Orion read and does **not** apply.
    ///
    /// A wg-quick file routinely carries `DNS`, `MTU` or `Table`. Refusing the
    /// file over them made Orion unable to open an ordinary WireGuard
    /// configuration; dropping them without a word would hand back a tunnel
    /// that differs from the one the file describes. They are imported, and
    /// reported.
    notices: Vec<String>,
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
        return Err(format!(
            "seuls les fichiers .{PROFILE_EXTENSION} sont acceptés par cette commande"
        ));
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
    let mut completed = {
        let config = state.config.lock().await;
        complete_profile_import(
            imported.profile,
            &config,
            admitted.as_deref(),
            imported.notices,
        )
        .map_err(|error| error.to_string())?
    };

    // The staged key is the missing candidate.
    //
    // `complete_profile_import` looks for the admitted key among **saved**
    // profiles, which is exactly where a key generated three minutes ago is
    // not: it sits in the staging slot, waiting for a save that cannot happen
    // until this import completes. That circle broke the normal enrolment
    // order — generate, hand the public half over, receive an invitation,
    // import it — and left the user with "aucun profil de ce poste ne détient
    // la clé admise" naming the very key they had just produced.
    if completed.profile.private_key.trim().is_empty() {
        let mut slot = state.staged_key.lock().await;
        match (slot.as_ref(), admitted.as_deref()) {
            // The document names the admitted key: pair on it, never on the
            // profile name. A key that was not admitted would hand the user a
            // profile whose handshakes fail with nothing to explain them.
            (Some(staged), Some(admitted)) if staged.public_key == admitted => {
                if let Some(staged) = slot.take() {
                    // The completed import still uses ClientProfile's legacy
                    // String field; this explicit copy is the compatibility
                    // boundary. `staged` is dropped immediately afterwards.
                    completed.profile.private_key = staged.private_key.expose().to_owned();
                    completed.private_key_missing = None;
                }
            }
            // A key is waiting, and it is **not** the admitted one. Saying so
            // beats the generic "no key of this machine matches": the user is
            // holding a key they believe is the right one, and the useful fact
            // is that the operator admitted a different one.
            (Some(staged), Some(admitted)) => {
                completed.private_key_missing = Some(format!(
                    "la clé générée sur ce poste — « {} » — n'est pas celle que ce document \
                     déclare admise — « {admitted} ». Faire admettre la première par \
                     l'opérateur, ou importer la moitié privée de la seconde.",
                    staged.public_key
                ));
            }
            // No certificate to compare against. The staged key is the one the
            // user just obtained for this very purpose, so adopting it is what
            // they meant.
            (Some(_), None) => {
                if let Some(staged) = slot.take() {
                    completed.profile.private_key = staged.private_key.expose().to_owned();
                    completed.private_key_missing = None;
                }
            }
            (None, _) => {}
        }
    }

    // The vault never opened: the profile list this import was matched against
    // is empty because nothing was read, not because nothing matches. Blaming
    // the document here sends the user to look for a key they may well have.
    if completed.private_key_missing.is_some() {
        if let Some(cause) = &state.vault_error {
            completed.private_key_missing = Some(format!(
                "le coffre de ce poste n'a pas pu être ouvert ({cause}), donc aucun profil \
                 enregistré n'a été lu : le document n'est pas en cause. Corriger l'accès au \
                 coffre, puis réimporter."
            ));
        }
    }

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
        incomplete: completed.incomplete,
        notices: completed.notices,
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

/// Persists the user's informed choice to keep profiles on a bare volume.
///
/// This command is deliberately separate from import/save: the interface must
/// first state the guarantees being withdrawn, and an ordinary write must
/// never turn a missing BitLocker posture into consent by itself.
#[tauri::command]
async fn allow_unencrypted_volume(
    state: State<'_, AppState>,
) -> Result<orion_core::vault::VaultPosture, String> {
    let posture = state.store.posture();
    if posture.volume_protected || posture.unencrypted_volume_waived {
        return Ok(posture);
    }
    state
        .store
        .persist_unencrypted_volume_waiver()
        .map_err(|error| error.to_string())?;
    tracing::warn!(
        "CHIFFREMENT DE VOLUME NON EXIGÉ après confirmation dans Orion — les anciens blocs disque, le fichier d'échange et celui d'hibernation ne sont pas couverts"
    );
    Ok(state.store.posture())
}

/// Draws a WireGuard key pair and returns its **public** half.
///
/// The private half stays in [`AppState::staged_key`] until the profile is
/// saved. Returning the public key straight away is what makes the enrolment
/// workflow possible at all: the user copies it, hands it to the operator, and
/// receives an admitted profile — none of which can happen if the key only
/// comes into existence when the form is submitted.
#[tauri::command]
async fn generate_private_key(state: State<'_, AppState>) -> Result<String, String> {
    let pair = aether::wg::generate_keypair()
        .map_err(|error| format!("génération de la paire de clés : {error}"))?;
    let aether::wg::Keypair {
        private_key,
        public_key,
    } = pair;
    let returned_public_key = public_key.clone();
    *state.staged_key.lock().await = Some(StagedKey {
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
async fn adopt_private_key(
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
    *state.staged_key.lock().await = Some(StagedKey {
        private_key: normalized,
        public_key: public_key.clone(),
    });
    Ok(public_key)
}

/// Drops the staged key without saving it.
#[tauri::command]
async fn discard_staged_key(state: State<'_, AppState>) -> Result<(), String> {
    // `Drop` zeroizes it: cancelling must not leave the key in memory for the
    // rest of the session.
    state.staged_key.lock().await.take();
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
async fn adopt_preshared_key(
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
    *state.staged_psk.lock().await = Some(StagedPsk { value });
    Ok(())
}

/// Drops the staged PSK without saving it.
#[tauri::command]
async fn discard_staged_psk(state: State<'_, AppState>) -> Result<(), String> {
    state.staged_psk.lock().await.take();
    Ok(())
}

/// Resolves the SSH destination, and checks it is safe to act on.
///
/// Shared by the two commands below, because they must agree on every gate:
/// one launches a terminal, the other only copies a line, and a destination
/// good enough for the second is exactly the one good enough for the first.
///
/// The tunnel must be up — the gateway answers SSH on its tunnel address
/// alone, and the host could otherwise resolve to something else entirely on
/// the clear network. And the destination is re-validated here even though
/// import and save already did: this is where a profile field stops being
/// data and starts being a command line.
async fn resolve_ssh_target(
    state: &State<'_, AppState>,
    name: Option<String>,
) -> Result<String, String> {
    let cfg = state.config.lock().await;
    let profile = match &name {
        Some(name) => cfg.find(name),
        None => cfg.selected.as_deref().and_then(|s| cfg.find(s)),
    }
    .ok_or("aucun profil sélectionné")?;
    let target = profile
        .ssh_target
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or(
            "ce profil ne déclare aucune destination SSH — la renseigner dans « Profils → \
             Avancé → Destination SSH »",
        )?;
    drop(cfg);

    let target = target.trim().to_string();
    orion_core::profile_import::validate_ssh_target(&target).map_err(|error| error.to_string())?;

    if state.controller.state() != TunnelState::Up {
        return Err(
            "le tunnel n'est pas monté : la gateway n'est joignable en SSH qu'à travers lui".into(),
        );
    }
    Ok(target)
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
async fn open_ssh_terminal(state: State<'_, AppState>, name: Option<String>) -> Result<(), String> {
    let target = resolve_ssh_target(&state, name).await?;
    spawn_ssh_terminal(&target)
}

/// The same command line, for the user to paste into their own terminal.
///
/// Kept beside [`open_ssh_terminal`] rather than replaced by it: the launcher
/// legitimately refuses on machines with no standard-user token — UAC off, the
/// built-in Administrator account, a service context — and on those the copy
/// is the whole feature rather than a consolation.
#[tauri::command]
async fn ssh_command(state: State<'_, AppState>, name: Option<String>) -> Result<String, String> {
    let target = resolve_ssh_target(&state, name).await?;
    Ok(format!("ssh {target}"))
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
async fn save_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    draft: ProfileDraft,
) -> Result<ConfigView, String> {
    let mut cfg = state.config.lock().await;
    require_protected_volume(&state)?;
    // A pending import wins over the stored profile of the same name. An
    // imported document may carry a *new* WireGuard private key together
    // with a newly sealed key-negotiation identity. Keeping the old profile
    // here would pair those two identities from different admissions: the
    // gateway accepts the TLS certificate, then rejects the request because
    // its WireGuard key is the old one. Ordinary edits never have a pending
    // import, so they still use the stored profile and preserve its secrets.
    let pending = state.pending_imports.lock().await.remove(&draft.name);
    let known = cfg.find(&draft.name);
    let stored = profile_edit_base(pending.as_ref(), known);
    // Taken, not peeked: the key is now the profile's, and leaving a copy in
    // the slot would let the next profile saved adopt it too.
    let staged = state.staged_key.lock().await.take();
    let staged_psk = state.staged_psk.lock().await.take();
    let profile = draft.merge(stored, staged.as_ref(), staged_psk.as_ref())?;
    if let Some(known) = known {
        profile
            .check_replacement_of(known)
            .map_err(|error| error.to_string())?;
    }
    let selected = profile.name.clone();
    state
        .store
        .save_profile(&profile)
        .map_err(|e| e.to_string())?;
    cfg.upsert(profile).map_err(|error| error.to_string())?;
    cfg.selected = Some(selected.clone());
    state.store.select(&selected).map_err(|e| e.to_string())?;
    let view = ConfigView::from(&*cfg);
    // Released before the menu is rebuilt: the rebuild reads the same lock,
    // and holding it here would have it wait on the very command it follows.
    drop(cfg);
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
async fn delete_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
) -> Result<ConfigView, String> {
    // Before the configuration lock, not after: the disconnection is a network
    // round trip, and `stop_connection` rebuilds nothing that needs the config
    // — but holding a lock across it would stall every other command for the
    // two seconds the release is allowed.
    if state.controller.mounted_profile().await.as_deref() == Some(name.as_str()) {
        stop_connection(&app).await?;
    }
    let mut cfg = state.config.lock().await;
    state
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
async fn select_profile(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
) -> Result<ConfigView, String> {
    let mut cfg = state.config.lock().await;
    state.store.select(&name).map_err(|e| e.to_string())?;
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
    state.store.may_write_secrets().map_err(|error| {
        format!(
            "{error} `danger_allow_unencrypted_volume = true` dans settings.toml l'autorise \
             explicitement, en retirant la couverture des anciens blocs disque et du fichier \
             d'hibernation."
        )
    })
}

#[tauri::command]
async fn connect(app: AppHandle, name: Option<String>) -> Result<(), String> {
    start_connection(app, name).await
}

/// Selects a profile, then connects to it — the two gestures the notification
/// area couples into one click.
///
/// Selecting first is not cosmetic: the connection reads the selected profile
/// when no name is given, and every screen derives what it shows from it. A
/// tray click that connected without selecting would leave the window
/// displaying one profile while the tunnel carried another.
///
/// Only the notification-area menu calls it, so outside Windows nothing does.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
async fn select_and_connect(app: &AppHandle, name: &str) -> Result<(), String> {
    {
        let state = app.state::<AppState>();
        let mut config = state.config.lock().await;
        if config.find(name).is_none() {
            return Err(format!("profil « {name} » introuvable"));
        }
        state
            .store
            .select(name)
            .map_err(|error| error.to_string())?;
        config.selected = Some(name.to_string());
    }
    // The window may be open behind the menu: it reads its profile list from
    // Rust, and nothing else would tell it the selection just moved.
    let _ = app.emit("helios://config-changed", ());
    start_connection(app.clone(), Some(name.to_string())).await
}

/// Mounts the tunnel. Shared by the `connect` command and the tray menu, which
/// must not differ by one step: a connection started from a hidden window has
/// no screen to report a discrepancy on.
async fn start_connection(app: AppHandle, name: Option<String>) -> Result<(), String> {
    let state = app.state::<AppState>();
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

    // # Signalé, jamais bloqué (arbitrage du 2 août 2026)
    //
    // Un profil repris de `profiles.toml` a eu sa clé en clair sur le disque,
    // et le sceller ne rappelle pas les copies déjà parties en sauvegarde. La
    // décision initiale en faisait un **refus de connexion**, ce qui était une
    // erreur de périmètre : Orion constate l'historique d'un fichier, il ne
    // sait rien de la clé elle-même — elle peut n'avoir jamais quitté la
    // machine, ou être une clé de développement dont personne ne se soucie.
    // Décider à la place de l'utilisateur qu'elle est perdue, et lui interdire
    // son propre tunnel sur cette présomption, dépasse ce que le client a à
    // arbitrer. La rotation reste la bonne pratique ; elle n'est pas à lui
    // imposer.
    //
    // Ce qui reste : la posture le montre, le journal le dit, et l'écran
    // Profils propose la manœuvre en un clic.
    let rotation_required = state.store.rotation_required().unwrap_or_default();
    let presumed_exposed = rotation_required.contains(&profile.name);
    if presumed_exposed {
        tracing::warn!(
            profil = %profile.name,
            "connexion avec une clé reprise de profiles.toml, où elle était en clair : \
             une rotation reste recommandée"
        );
    }

    // Sink combining relay to the frontend AND telemetry control: telemetry
    // only starts on transition to Up (web behind the tunnel).
    let base = emit_sink(app.clone());
    let telemetry = Arc::clone(&state.telemetry);
    let heliosd_url = profile.heliosd_url.clone();
    let app_for_tel = app.clone();
    let negotiating = profile.negotiates();
    // The trust update of §8.1.1 lives inside the tunnel, so the moment it
    // becomes reachable is the moment it is worth asking. Captured here rather
    // than read later: by the time the tunnel is up, the configuration may
    // already describe a different profile.
    let trust_settings = profile.key_negotiation.clone();
    let trust_url = profile.heliosd_url.clone();
    // Once per connection. `Up` is re-emitted whenever the inference loop sees
    // a fresh handshake after a stall, and each of those is the same tunnel —
    // asking again on every one would poll the gateway for the life of the
    // session.
    let trust_asked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let renewal_task = Arc::clone(&state.certificate_renewal_task);
    let renewal_controller = Arc::clone(&state.controller);
    let renewal_sessions = Arc::clone(&state.renewals);
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
                    if let (Some(settings), Some(url), false) = (
                        trust_settings.clone(),
                        trust_url.clone(),
                        trust_asked.swap(true, std::sync::atomic::Ordering::SeqCst),
                    ) {
                        let refresh = spawn_trust_refresh(
                            settings.clone(),
                            url.clone(),
                            emit_sink(app_for_tel.clone()),
                        );
                        let renewal = spawn_automatic_certificate_renewal(
                            refresh,
                            Arc::clone(&renewal_controller),
                            Arc::clone(&renewal_sessions),
                            negotiated_profile.clone(),
                            settings,
                            url,
                            emit_sink(app_for_tel.clone()),
                        );
                        if let Some(previous) = renewal_task.lock().unwrap().replace(renewal) {
                            previous.abort();
                        }
                    }
                }
                TunnelState::Down | TunnelState::Failed => {
                    telemetry.stop();
                    if let Some(task) = renewal_task.lock().unwrap().take() {
                        task.abort();
                    }
                }
                _ => {}
            }
        }
        base(ev);
    });

    // Said in the event log the user is actually looking at, not only in the
    // file. A recommendation nobody reads is not a recommendation.
    if presumed_exposed {
        sink(ClientEvent::log(
            "warn",
            "clé reprise de profiles.toml, où elle était en clair : une rotation reste \
             recommandée — onglet Profils, « Générer une nouvelle clé »."
                .to_string(),
        ));
    }

    state.controller.connect(profile, sink.clone()).await;

    // State inference loop: WireGuard notifies nothing, we poll the age of
    // the last handshake. Never touches the adapter (ADR-001 §3 bis).
    //
    // `Down` ends it — but only once the connection has left that state. The
    // first tick of a `tokio` interval fires immediately, and reading `Down`
    // there is what a starting connection looks like, not a finished one: the
    // loop used to end on that very tick and infer nothing for the rest of the
    // session. A lost session link then kept the screen on «Connecté» while the
    // log announced the tunnel was over.
    let controller = Arc::clone(&state.controller);
    let poll = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HANDSHAKE_POLL_INTERVAL);
        let mut started = false;
        loop {
            ticker.tick().await;
            match controller.state() {
                // Explicit disconnection: nothing left to infer.
                TunnelState::Down if started => break,
                TunnelState::Down => continue,
                _ => started = true,
            }
            controller.poll_handshake(sink.clone()).await;
        }
    });
    let previous = state.handshake_poll.lock().unwrap().replace(poll);
    if let Some(previous) = previous {
        previous.abort();
    }

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
async fn disconnect(app: AppHandle) -> Result<(), String> {
    stop_connection(&app).await
}

/// Unmounts the tunnel. Shared by the `disconnect` command and the tray menu,
/// for the same reason as [`start_connection`]: two paths that differ by one
/// step end up differing by more.
async fn stop_connection(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    state.telemetry.stop();
    // The inference stops before the state moves, not after: a poll that read
    // `Up` and lands once the tunnel is down would re-announce `Connecting`
    // behind the disconnection the user just asked for.
    let poll = state.handshake_poll.lock().unwrap().take();
    if let Some(poll) = poll {
        poll.abort();
    }
    state
        .controller
        .disconnect(emit_sink(app.clone()))
        .await
        .map_err(|error| error.to_string())
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
    // The pending import is the profile being edited, even when it replaces a
    // stored profile with the same name. Looking at the stored key here would
    // report a valid replacement as if its new negotiation identity belonged
    // to the old WireGuard key, then `save_profile` would persist that split.
    // Peeked, not removed: validation runs on every keystroke.
    let pending = state.pending_imports.lock().await.get(&draft.name).cloned();
    let known = cfg.find(&draft.name);
    let stored = profile_edit_base(pending.as_ref(), known);
    // Validation runs on every keystroke: the staged secrets are read, never
    // taken.
    let staged = state.staged_key.lock().await;
    let staged_psk = state.staged_psk.lock().await;
    let profile = draft.merge(stored, staged.as_ref(), staged_psk.as_ref())?;
    if let Some(known) = known {
        profile
            .check_replacement_of(known)
            .map_err(|error| error.to_string())?;
    }
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
        // Certificates is a column of cards: a name, four dated rows and the
        // four actions of §12.2, wrapped rather than stacked. It was given the
        // width of a two-column form and the height of six profiles, and a
        // device that holds one spent the difference on empty paper. Beyond
        // what fits, the view scrolls.
        "certificates" => (680.0, 620.0),
        // The speedtest is a single centred column showing one state at a
        // time — the launch, the leg under way and its curve, or the finished
        // figures above the previous runs. It was given the width of a
        // two-column form and spent it on margins.
        "speedtest" => (520.0, 620.0),
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

/// Extension of an Orion profile, without the dot.
///
/// It is the extension the installer registers, the one `helios-ctl` writes,
/// and the one the import filter offers. One constant so those three cannot
/// drift apart.
const PROFILE_EXTENSION: &str = "orion";

/// The extension distributed until August 2026.
///
/// Still accepted, and only accepted — nothing produces it anymore. A profile
/// on an operator's disk outlives the client that reads it, and refusing the
/// document Orion itself wrote last month would send the user back to an
/// enrolment they have no reason to redo. The installer no longer registers
/// it, so a double-click on such a file no longer starts Orion; dragging it
/// onto the import button still works.
const LEGACY_PROFILE_EXTENSION: &str = "orionprofile";

fn is_associated_profile_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case(PROFILE_EXTENSION)
                || extension.eq_ignore_ascii_case(LEGACY_PROFILE_EXTENSION)
        })
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
                "WireGuardNT is missing ({DLL}); rebuild Orion so its Windows dependencies are prepared"
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

/// Default log filter.
///
/// `info` everywhere, `debug` for the crates that are **ours**. A flat `info`
/// left the interesting half of a startup unsaid — which vault path was taken,
/// what the TPM answered, why a profile did not load — while a flat `debug`
/// buries it under `hyper`.
///
/// `quinn` and `rustls` are in, deliberately. Key negotiation fails *inside*
/// the QUIC handshake far more often than after it — a wrong certificate, a
/// path that will not carry the PQ material, a port nobody forwarded — and
/// none of that has a name until those two crates are allowed to speak. They
/// are quiet as long as nothing connects, so the cost is paid only where the
/// answer lives. `RUST_LOG` overrides the whole thing.
const DEFAULT_LOG_FILTER: &str = "info,orion=debug,orion_core=debug,aether=debug,\
                                  aether_vault=debug,aether_key_negotiation=debug,\
                                  quinn=debug,quinn_proto=debug,rustls=debug";

/// Log file, beside the vault it describes.
const LOG_FILE: &str = "orion.log";

/// Shared handle to the log file.
///
/// `tracing-appender` would do this and is not in the lockfile; adding a
/// dependency for fifteen lines is the worse trade. Locking per event is fine
/// at the rate this application logs.
#[derive(Clone)]
struct FileWriter(Arc<StdMutex<std::fs::File>>);

impl std::io::Write for FileWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("log file mutex poisoned"))?
            .write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("log file mutex poisoned"))?
            .flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FileWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Opens the log file, truncating what a previous run left.
///
/// Truncating rather than appending, and rotating nothing: what is wanted is
/// *this* start, in full. A file that grows across weeks makes the operator
/// scroll past six boots to reach the one that failed, and a VPN client that
/// silently fills a disk is its own incident.
fn open_log_file() -> Option<FileWriter> {
    let path = orion_core::vault::ProfileStore::default_dir()
        .ok()?
        .join(LOG_FILE);
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent).ok()?;
    }
    let file = std::fs::File::create(&path).ok()?;
    Some(FileWriter(Arc::new(StdMutex::new(file))))
}

/// Wires stdout **and** a file.
///
/// The file is what makes a release build diagnosable at all: `windows_subsystem
/// = "windows"` means an installed Orion has no console, so everything written
/// to stdout goes nowhere. Asking a user to reproduce under `cargo run` to see
/// a log is asking them to rebuild the product.
fn init_logging() -> Option<PathBuf> {
    let filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| DEFAULT_LOG_FILTER.into())
    };

    let path = orion_core::vault::ProfileStore::default_dir()
        .ok()
        .map(|dir| dir.join(LOG_FILE));

    match open_log_file() {
        Some(file) => {
            use tracing_subscriber::layer::SubscriberExt as _;
            use tracing_subscriber::util::SubscriberInitExt as _;
            tracing_subscriber::registry()
                .with(filter())
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
                .with(
                    tracing_subscriber::fmt::layer()
                        // No colour codes in a file somebody will paste back.
                        .with_ansi(false)
                        .with_writer(file),
                )
                .init();
            path
        }
        None => {
            tracing_subscriber::fmt().with_env_filter(filter()).init();
            None
        }
    }
}

fn main() {
    let log_path = init_logging();
    if let Some(path) = &log_path {
        tracing::info!(fichier = %path.display(), "journal d'Orion");
    } else {
        tracing::warn!("journal fichier indisponible — sortie standard uniquement");
    }
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        backend = if cfg!(feature = "wireguard") {
            "wireguard"
        } else {
            "dry-run"
        },
        "démarrage d'Orion"
    );

    // The randomness pipeline is named before anything draws from it, and an
    // unusable provider stops the start-up: a client that cannot draw a
    // transaction identifier cannot negotiate, and failing here says why
    // (NEGOCIATION-DE-CLE-V5 §4.3).
    let drbg = aether::random::configure().expect("no usable DRBG provider for the negotiation");
    tracing::info!(%drbg, "randomness provider");

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
    } else if !store.probe_hardware_root() {
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
    // A vault that would not open leaves Orion running on an **empty** profile
    // list, and every later message then reasons from that emptiness: an import
    // reports that no key of this machine matches the admitted one, when the
    // truth is that the machine's keys were never read. The cause is recorded
    // so those messages can name it instead of blaming the document.
    let mut vault_error = None;
    let config = store.load().unwrap_or_else(|error| {
        tracing::error!(%error, "coffre illisible — aucun profil chargé");
        vault_error = Some(error.to_string());
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
        .plugin(companion_plugin())
        .manage(AppState {
            controller,
            store,
            config: Arc::new(Mutex::new(config)),
            telemetry: Arc::new(TelemetryManager::default()),
            speedtest: Mutex::new(()),
            pending_profile_paths: StdMutex::new(pending_profile_paths),
            pending_imports: Arc::new(Mutex::new(std::collections::HashMap::new())),
            staged_key: Arc::new(Mutex::new(None)),
            staged_psk: Arc::new(Mutex::new(None)),
            astra: astra::Ceremony::default(),
            operator: operator::OperatorCeremony::default(),
            handshake_poll: StdMutex::new(None),
            vault_error,
            log_path,
            last_certificate_error: Arc::new(Mutex::new(std::collections::HashMap::new())),
            renewals: Arc::new(Mutex::new(std::collections::HashMap::new())),
            certificate_renewal_task: Arc::new(StdMutex::new(None)),
            recoveries: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
        .setup(|_app| {
            #[cfg(target_os = "windows")]
            tray::install(_app)?;
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
            about_orion,
            get_config,
            import_profile,
            import_profile_path,
            save_profile,
            generate_private_key,
            adopt_private_key,
            discard_staged_key,
            adopt_preshared_key,
            discard_staged_psk,
            ssh_command,
            open_ssh_terminal,
            delete_profile,
            select_profile,
            connect,
            disconnect,
            export_logs,
            resize_for_view,
            validate_profile,
            allow_unencrypted_volume,
            key_negotiation_support,
            certificate_inventory,
            certificate_actions,
            certificate_approval_manifest,
            certificate_approval_needs_pin,
            approve_certificate_renewal,
            certificate_overview,
            run_certificate_action,
            resume_certificate_recovery,
            last_certificate_error,
            run_speed_test,
            vault_posture,
            start_astra_ca_tls_rotation,
            continue_astra_ca_tls_rotation,
            cancel_astra_ca_tls_rotation,
            astra_ca_tls_rotation_status,
            begin_operator_ceremony,
            advance_operator_ceremony,
            dismiss_operator_ceremony,
            operator_ceremony_status,
            operator_pending_operations,
        ])
        .run(tauri::generate_context!())
        .expect("error while launching Tauri");
}

/// Opens the two-key CA-TLS ceremony described in ADR-008 §9.4.
///
/// Everything that decides anything happens in the companion: the campaign is
/// fetched and verified there, under the Astra service key the vault's
/// hand-off pins, and the two credentials are exercised there. This command
/// starts it and returns the first state it publishes.
#[tauri::command]
async fn start_astra_ca_tls_rotation(
    state: State<'_, AppState>,
    input: astra::RotationInput,
) -> Result<aether::certificates::operator_ipc::AstraCaTlsStatus, String> {
    state.astra.start(input).await
}

/// Takes the next step, once the operator says the requested key is plugged in.
#[tauri::command]
async fn continue_astra_ca_tls_rotation(
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
async fn cancel_astra_ca_tls_rotation(
    state: State<'_, AppState>,
) -> Result<aether::certificates::operator_ipc::AstraCaTlsStatus, String> {
    state
        .astra
        .advance(aether::certificates::operator_ipc::AstraIpcCommand::Cancel)
        .await
}

/// The ceremony's current state, for a view that was opened after it started.
#[tauri::command]
async fn astra_ca_tls_rotation_status(
    state: State<'_, AppState>,
) -> Result<aether::certificates::operator_ipc::AstraCaTlsStatus, String> {
    Ok(state.astra.status().await)
}

/// Opens an operator ceremony for the operation the WebView names.
///
/// The locator is all it may name — a kind, and at most an identifier this
/// process itself opened. Everything else the helper resolves from the hand-off
/// pinned beside the vault it holds.
#[tauri::command]
async fn begin_operator_ceremony(
    state: State<'_, AppState>,
    locator: aether::certificates::operator_session::OperationLocator,
) -> Result<aether::certificates::operator_session::OperatorStatus, String> {
    state.operator.begin(locator).await
}

/// The handle of the window the press came from, or `0` where there is none.
///
/// Read on the exact advance that opens a key dialog, so Orion can re-assert
/// its own foreground right before ceding it to the helper. The click was
/// delivered to the WebView's renderer process, and Windows grants that right
/// to whoever received the last input — not to the process that owns the
/// window around it.
fn owner_window(window: &tauri::Window) -> isize {
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
/// The revision is not decoration: a press on a screen the helper has already
/// left is refused here and again there, rather than applied to whatever
/// replaced it.
#[tauri::command]
async fn advance_operator_ceremony(
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
async fn dismiss_operator_ceremony(state: State<'_, AppState>) -> Result<(), String> {
    state.operator.dismiss().await
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
async fn operator_pending_operations(
    state: State<'_, AppState>,
) -> Result<Vec<orion_core::operator_pending::OperatorPendingOperation>, String> {
    let gateways: Vec<String> = {
        let cfg = state.config.lock().await;
        let mut seen: Vec<String> = Vec::new();
        for profile in &cfg.profiles {
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

/// The ceremony's current state, for a view opened after it started.
#[tauri::command]
async fn operator_ceremony_status(
    state: State<'_, AppState>,
) -> Result<Option<aether::certificates::operator_session::OperatorStatus>, String> {
    Ok(state.operator.status().await)
}

#[cfg(test)]
mod security_tests;
