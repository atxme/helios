// Empêche l'ouverture d'une console Windows en mode release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Shell Tauri du client VPN Orion.
//!
//! Mince couche de câblage : il ne contient aucune logique WireGuard (déléguée à
//! `orion-core`). Son rôle est de :
//! 1. exposer des commandes `invoke` au frontend (connect/disconnect, CRUD profils) ;
//! 2. relayer les [`ClientEvent`] du cœur vers le frontend (`emit`) ;
//! 3. démarrer la télémétrie heliosd **uniquement** quand le tunnel passe `Up`
//!    (le serveur web vit derrière WireGuard) et l'arrêter à la déconnexion.

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
    backend::EventSink, complete_profile_import, default_backend, parse_profile_import,
    read_profile_import_path, telemetry, ClientConfig, ClientEvent, ClientProfile, VpnController,
};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{watch, Mutex};

/// État applicatif partagé, injecté dans chaque commande via [`State`].
struct AppState {
    controller: Arc<VpnController>,
    config: Mutex<ClientConfig>,
    telemetry: Arc<TelemetryManager>,
    pending_profile_paths: StdMutex<VecDeque<PathBuf>>,
}

/// Intervalle d'interrogation du dernier handshake WireGuard.
///
/// WireGuard est sans connexion : l'état `Up` s'infère de la fraîcheur du
/// handshake, il n'est jamais notifié (ADR-001 §3). Sans cette boucle, l'IHM
/// resterait bloquée sur le dernier état connu.
const HANDSHAKE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(debug_assertions)]
const FRONTEND_DEV_PORT: u16 = 1420;

/// Serveur Vite lancé par Orion lorsque le binaire de développement est exécuté
/// directement avec Cargo. La CLI Tauri le démarre déjà via `beforeDevCommand` ;
/// dans ce cas, Orion détecte le port ouvert et ne crée aucun second processus.
#[cfg(debug_assertions)]
struct FrontendDevServer {
    child: Child,
}

#[cfg(debug_assertions)]
impl Drop for FrontendDevServer {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            if error.kind() != std::io::ErrorKind::InvalidInput {
                tracing::warn!(%error, "impossible d'arrêter le serveur Vite d'Orion");
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

/// Garantit que la `devUrl` Tauri répond avant la création de la fenêtre.
///
/// `cargo run` ne connaît pas `beforeDevCommand`, contrairement à la CLI Tauri.
/// Sans ce pont, WebKit charge `localhost:1420` alors qu'aucun frontend n'écoute
/// et l'utilisateur obtient une fenêtre vide.
#[cfg(debug_assertions)]
fn ensure_frontend_dev_server() -> anyhow::Result<Option<FrontendDevServer>> {
    if frontend_dev_is_ready() {
        return Ok(None);
    }

    let frontend_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("répertoire frontend Orion introuvable"))?;
    let vite_entrypoint = frontend_dir.join("node_modules/vite/bin/vite.js");
    if !vite_entrypoint.is_file() {
        anyhow::bail!(
            "Vite est absent ; exécutez `npm ci --prefix apps/orion` avant de lancer Orion"
        );
    }

    tracing::info!("démarrage automatique du frontend Vite d'Orion");
    let mut child = Command::new("node")
        .arg(vite_entrypoint)
        .args(["--host", "127.0.0.1", "--port"])
        .arg(FRONTEND_DEV_PORT.to_string())
        .arg("--strictPort")
        .current_dir(frontend_dir)
        .spawn()
        .map_err(|error| anyhow::anyhow!("impossible de démarrer Vite avec Node.js : {error}"))?;

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if frontend_dev_is_ready() {
            return Ok(Some(FrontendDevServer { child }));
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("Vite s'est arrêté avant de servir l'IHM Orion ({status})");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Vite n'a pas ouvert le port 1420 dans le délai de 15 secondes");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Gère le cycle de vie de la tâche de télémétrie (une seule active à la fois).
#[derive(Default)]
struct TelemetryManager {
    cancel: StdMutex<Option<watch::Sender<bool>>>,
}

impl TelemetryManager {
    /// Démarre une boucle de télémétrie vers `url`, en annulant l'éventuelle précédente.
    fn start(&self, url: String, sink: EventSink) {
        self.stop();
        let (tx, rx) = watch::channel(false);
        *self.cancel.lock().unwrap() = Some(tx);
        tokio::spawn(telemetry::run(url, sink, rx));
    }

    /// Annule la boucle de télémétrie en cours, le cas échéant.
    fn stop(&self) {
        if let Some(tx) = self.cancel.lock().unwrap().take() {
            let _ = tx.send(true);
        }
    }
}

/// Construit un puits qui relaie chaque événement du cœur vers le frontend.
fn emit_sink(app: AppHandle) -> EventSink {
    Arc::new(move |ev: ClientEvent| {
        let _ = app.emit("helios://event", &ev);
    })
}

// ─── Commandes invoquées par le frontend ───────────────────────────────────────

// WireGuard n'a qu'une seule suite (ChaCha20-Poly1305). La protection
// post-quantique vient du PSK ML-KEM, négocié automatiquement après montage du
// tunnel classique dès que le profil porte une URL Helios interne — voir
// `orion_core::backend::upgrade_to_post_quantum`.

#[tauri::command]
fn get_state(state: State<'_, AppState>) -> String {
    state.controller.state().as_str().to_string()
}

#[tauri::command]
fn backend_kind(state: State<'_, AppState>) -> &'static str {
    state.controller.backend_kind()
}

/// Indique si l'adaptateur WireGuard est toujours monté. En cas d'échec, il
/// doit rester debout pour capter les routes et empêcher une fuite en clair.
#[tauri::command]
fn adapter_is_up(state: State<'_, AppState>) -> bool {
    state.controller.adapter_is_up()
}

#[tauri::command]
async fn get_config(state: State<'_, AppState>) -> Result<ClientConfig, String> {
    Ok(state.config.lock().await.clone())
}

/// Décode un document choisi par l'utilisateur sans le persister.
///
/// L'IHM affiche le résultat comme brouillon : un fichier valide ne remplace
/// donc jamais silencieusement un profil portant le même nom.
#[tauri::command]
async fn import_profile(
    state: State<'_, AppState>,
    contents: String,
    file_name: String,
) -> Result<ClientProfile, String> {
    let profile = parse_profile_import(&contents, &file_name).map_err(|error| error.to_string())?;
    let config = state.config.lock().await;
    complete_profile_import(profile, &config).map_err(|error| error.to_string())
}

/// Relit un profil dont le chemin vient de l'association système.
///
/// `path = None` consomme le prochain chemin mis en attente au démarrage ou
/// transmis par le plugin single-instance. Le frontend appelle cette forme
/// après avoir installé son écouteur, ce qui rend le premier double-clic aussi
/// fiable que les suivants.
#[tauri::command]
async fn import_profile_path(
    state: State<'_, AppState>,
    path: Option<String>,
) -> Result<Option<ClientProfile>, String> {
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
    let profile = read_profile_import_path(&path).map_err(|error| error.to_string())?;
    let config = state.config.lock().await;
    complete_profile_import(profile, &config)
        .map(Some)
        .map_err(|error| error.to_string())
}

/// Clé publique correspondant à la clé privée d'un profil.
///
/// C'est ce que l'utilisateur communique à l'opérateur pour être admis sur la
/// gateway (ADR-004 §6) : la dériver ici évite de lui faire manipuler sa clé
/// privée dans un terminal pour obtenir une valeur qui, elle, est publique.
#[tauri::command]
fn profile_public_key(profile: ClientProfile) -> Option<String> {
    profile.public_key()
}

#[tauri::command]
async fn save_profile(
    state: State<'_, AppState>,
    profile: ClientProfile,
) -> Result<ClientConfig, String> {
    let mut cfg = state.config.lock().await;
    let selected = profile.name.clone();
    cfg.upsert(profile);
    cfg.selected = Some(selected);
    cfg.save().map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
async fn delete_profile(state: State<'_, AppState>, name: String) -> Result<ClientConfig, String> {
    let mut cfg = state.config.lock().await;
    cfg.remove(&name);
    cfg.save().map_err(|e| e.to_string())?;
    Ok(cfg.clone())
}

#[tauri::command]
async fn select_profile(state: State<'_, AppState>, name: String) -> Result<ClientConfig, String> {
    let mut cfg = state.config.lock().await;
    cfg.selected = Some(name);
    cfg.save().map_err(|e| e.to_string())?;
    Ok(cfg.clone())
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

    // Valide le profil WireGuard (endpoint + clés) AVANT tout effet de bord.
    profile.validate().map_err(|e| e.to_string())?;

    // Puits combinant relais vers le frontend ET pilotage de la télémétrie :
    // la télémétrie ne démarre QUE sur passage à Up (web derrière le tunnel).
    let base = emit_sink(app.clone());
    let telemetry = Arc::clone(&state.telemetry);
    let heliosd_url = profile.heliosd_url.clone();
    let app_for_tel = app.clone();
    let sink: EventSink = Arc::new(move |ev: ClientEvent| {
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

    // Boucle d'inférence d'état : WireGuard ne notifie rien, on interroge l'âge
    // du dernier handshake. Ne touche jamais à l'adaptateur (ADR-001 §3 bis).
    let controller = Arc::clone(&state.controller);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HANDSHAKE_POLL_INTERVAL);
        loop {
            ticker.tick().await;
            if controller.state() == TunnelState::Down {
                break; // déconnexion explicite : plus rien à inférer
            }
            controller.poll_handshake(sink.clone()).await;
        }
    });

    Ok(())
}

#[tauri::command]
async fn disconnect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    state.telemetry.stop();
    state.controller.disconnect(emit_sink(app)).await;
    Ok(())
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

/// `defguard_wireguard_rs 0.11.0` ouvre WireGuardNT par un chemin relatif fixé
/// dans sa source. Un double-clic donne à Orion un répertoire courant qui peut
/// être celui du profil ; on le remplace donc avant de construire le backend.
#[cfg(all(target_os = "windows", feature = "wireguard"))]
fn prepare_wireguard_nt_working_directory() -> anyhow::Result<()> {
    #[cfg(target_arch = "x86_64")]
    const DLL: &str = "resources-windows/binaries/wireguard-amd64.dll";
    #[cfg(target_arch = "aarch64")]
    const DLL: &str = "resources-windows/binaries/wireguard-arm64.dll";

    let executable_dir = std::env::current_exe()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("répertoire du binaire Orion introuvable"))?;
    let source_dir = if executable_dir.join(DLL).is_file() {
        executable_dir
    } else {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .ok_or_else(|| anyhow::anyhow!("racine du workspace Orion introuvable"))?;
        if !workspace.join(DLL).is_file() {
            anyhow::bail!(
                "WireGuardNT est absent ({DLL}) ; exécuter `cargo xtask orion-deps` avant Orion"
            );
        }
        workspace.to_path_buf()
    };
    std::env::set_current_dir(&source_dir).map_err(|error| {
        anyhow::anyhow!(
            "impossible de sélectionner les ressources WireGuardNT dans {} : {error}",
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
        ensure_frontend_dev_server().expect("impossible de préparer l'IHM de développement Orion");

    let startup_cwd = std::env::current_dir().unwrap_or_default();
    let startup_args: Vec<String> = std::env::args().collect();
    let pending_profile_paths = associated_profile_paths(&startup_args, &startup_cwd).into();

    #[cfg(all(target_os = "windows", feature = "wireguard"))]
    prepare_wireguard_nt_working_directory()
        .expect("impossible de préparer la DLL WireGuardNT livrée avec Orion");

    let backend = default_backend().expect(
        "backend WireGuard réel indisponible — Orion refuse de démarrer en simulation implicite",
    );
    let controller = Arc::new(VpnController::new(backend));
    let config = ClientConfig::load().unwrap_or_default();

    tauri::Builder::default()
        // Doit rester le premier plugin enregistré : il intercepte l'instance
        // secondaire avant que les autres plugins puissent agir.
        .plugin(tauri_plugin_single_instance::init(|app, args, cwd| {
            let paths = associated_profile_paths(&args, Path::new(&cwd));
            if !paths.is_empty() {
                let state = app.state::<AppState>();
                state.pending_profile_paths.lock().unwrap().extend(paths);
                let _ = app.emit("helios://profile-path", ());
            }
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .manage(AppState {
            controller,
            config: Mutex::new(config),
            telemetry: Arc::new(TelemetryManager::default()),
            pending_profile_paths: StdMutex::new(pending_profile_paths),
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            backend_kind,
            adapter_is_up,
            get_config,
            import_profile,
            import_profile_path,
            profile_public_key,
            save_profile,
            delete_profile,
            select_profile,
            connect,
            disconnect,
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de Tauri");
}

#[cfg(test)]
mod security_tests {
    use super::{associated_profile_paths, Path, PathBuf};

    #[test]
    fn serveur_cargo_run_aligne_avec_la_dev_url_tauri() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let expected = format!("http://localhost:{}", super::FRONTEND_DEV_PORT);

        assert_eq!(config["build"]["devUrl"].as_str(), Some(expected.as_str()));
    }

    #[test]
    fn configuration_tauri_impose_une_csp_et_fige_les_prototypes() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let security = &config["app"]["security"];
        let csp = security["csp"].as_str().expect("CSP Tauri obligatoire");

        assert_eq!(security["freezePrototype"], true);
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(!csp.contains("unsafe-eval"));
        assert!(!csp.contains("script-src *"));
        assert!(!csp.contains("connect-src *"));
    }

    #[test]
    fn bundle_declare_association_et_capability_linux() {
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
    fn bundle_windows_livre_wireguard_et_impose_signtool_horodate() {
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
            assert!(signer.contains(required), "élément absent : {required}");
        }
    }

    #[test]
    fn capabilities_tauri_restent_minimales() {
        let capabilities: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        assert_eq!(capabilities["windows"], serde_json::json!(["main"]));
        assert_eq!(
            capabilities["permissions"],
            serde_json::json!(["core:default"])
        );
    }

    #[test]
    fn association_ne_transmet_que_les_profils_orion() {
        let args = vec![
            "orion.exe".to_string(),
            "invitation.orionprofile".to_string(),
            "--inattendu".to_string(),
            "autre.json".to_string(),
        ];
        assert_eq!(
            associated_profile_paths(&args, Path::new("/profils")),
            vec![PathBuf::from("/profils/invitation.orionprofile")]
        );
    }

    #[test]
    fn manifeste_windows_exige_les_privileges_administrateur() {
        let manifest = include_str!("../windows/orion-manifest.xml");
        assert!(manifest.contains("requireAdministrator"));
        assert!(manifest.contains("Microsoft.Windows.Common-Controls"));
    }
}
