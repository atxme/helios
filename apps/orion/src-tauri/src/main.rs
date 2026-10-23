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

/// The commands the frontend invokes, one child per capability.
mod commands;
use commands::*;

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

/// Extension of an Orion profile, without the dot.
///
/// It is the extension the installer registers, the one `helios` writes,
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

/// `defguard_wireguard_rs 0.12` opens WireGuardNT via a relative path fixed
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
            preview_enrollment_invitation,
            begin_enrollment,
            list_pending_enrollments,
            discard_pending_enrollment,
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
            renew_psk,
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

#[cfg(test)]
mod security_tests;
