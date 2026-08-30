//! Build script de la coquille Orion.
//!
//! # Ce qu'il garantit, et pourquoi il le fait ici
//!
//! `cargo build` doit produire un Orion **complet** : icône, nom et interface à
//! jour. C'est le geste de tous les jours ; construire un MSI pour vérifier une
//! modification d'écran ne l'est pas.
//!
//! Deux choses ne viennent pas seules avec Cargo :
//!
//! * `beforeBuildCommand` de `tauri.conf.json` est une notion de la **CLI
//!   Tauri**. `cargo build --release` ne la connaît pas, donc `../dist` reste
//!   tel que le dernier `npm run build` l'a laissé — c'est-à-dire, sur un dépôt
//!   fraîchement cloné, absent, et sur un poste de développement, périmé. Une
//!   interface périmée n'est pas un défaut cosmétique : c'est un écran qui
//!   affiche encore ce que le code ne fait plus ;
//! * Cargo ne relance ce script que si un fichier qu'il a **déclaré** a changé.
//!   Sans les `rerun-if-changed` ci-dessous, remplacer une icône ne reconstruit
//!   rien et l'ancienne reste embarquée dans l'exécutable.

use std::path::{Path, PathBuf};

fn main() {
    let orion = frontend_root();
    watch_frontend(&orion);
    watch_icons();
    let npm = ensure_npm_available();
    ensure_npm_dependencies(&orion, &npm);
    ensure_windows_dependencies();

    // Debug charge `devUrl` : Vite sert les sources, et
    // `ensure_frontend_dev_server` le démarre au besoin. Rien à construire, et
    // le construire coûterait une minute à chaque `cargo run`.
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        ensure_frontend_built(&orion, &npm);
    }

    let windows = tauri_build::WindowsAttributes::new()
        .app_manifest(include_str!("windows/orion-manifest.xml"));
    // The WebView may ask for exactly one process-related action. Model it as
    // an inlined plugin so Tauri's ACL applies to that command without turning
    // every application command into an all-or-nothing app manifest.
    let companion = tauri_build::InlinedPlugin::new().commands(&["launch_certificate_companion"]);
    let attributes = tauri_build::Attributes::new()
        .windows_attributes(windows)
        .plugin("companion", companion);
    tauri_build::try_build(attributes).expect("construction des ressources Tauri Orion");
}

/// Downloads and verifies the native dependency used by the real Windows
/// backend before Tauri tries to copy its bundle resources.
///
/// This calls the shared `xtask` library directly instead of spawning Cargo
/// from a Cargo build script. The latter can deadlock on Cargo's target lock;
/// direct invocation keeps `cargo build -p orion --features wireguard` a single
/// coherent build operation.
fn ensure_windows_dependencies() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("Orion workspace root not found");
    xtask::orion_deps::prepare(workspace)
        .expect("unable to download and prepare Orion's Windows dependencies");
}

fn frontend_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("le répertoire du frontend Orion est le parent de src-tauri")
        .to_path_buf()
}

/// Déclare les sources du frontend, pour que les modifier reconstruise.
fn watch_frontend(orion: &Path) {
    for entry in [
        "index.html",
        "package.json",
        "package-lock.json",
        "vite.config.ts",
        "tsconfig.json",
    ] {
        println!("cargo:rerun-if-changed={}", orion.join(entry).display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        orion.join("node_modules/vite/bin/vite.js").display()
    );
    watch_tree(&orion.join("src"));
}

/// Déclare les icônes et la configuration.
///
/// `tauri_build` embarque l'icône dans les ressources de l'exécutable et
/// `generate_context!` en dérive celle de la fenêtre et de la zone de
/// notification. Les trois viennent du même `.ico` ; sans cette déclaration, le
/// remplacer ne déclenche aucune reconstruction et l'exécutable garde
/// l'ancienne — silencieusement.
fn watch_icons() {
    println!("cargo:rerun-if-changed=tauri.conf.json");
    watch_tree(&Path::new(env!("CARGO_MANIFEST_DIR")).join("icons"));
}

fn watch_tree(directory: &Path) {
    // Le répertoire lui-même : une création ou une suppression s'y voit, alors
    // qu'elle ne change aucun fichier existant.
    println!("cargo:rerun-if-changed={}", directory.display());
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            watch_tree(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

/// Construit `../dist` si ce qui s'y trouve ne correspond plus aux sources.
///
/// L'alternative — laisser `generate_context!` embarquer un `dist` périmé —
/// produit un exécutable qui se lance, s'affiche, et ment. C'est exactement la
/// panne qui fait chercher un défaut dans le code Rust pendant une demi-heure
/// avant de comprendre que l'écran affiché date d'avant la correction.
fn ensure_frontend_built(orion: &Path, npm: &Path) {
    if !stale(&orion.join("dist"), orion) {
        return;
    }
    println!("cargo:warning=frontend Orion périmé — `npm run build` en cours");

    match std::process::Command::new(npm)
        .args(["run", "build"])
        .current_dir(orion)
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => panic!(
            "`npm run build` a échoué ({status}). L'interface embarquée serait celle d'avant : \
             corriger le frontend plutôt que livrer un écran périmé."
        ),
        Err(error) => panic!(
            "impossible de lancer `npm run build` ({error}). Node.js est requis pour une \
             compilation release d'Orion ; en debug, l'interface est servie par Vite et cette \
             étape n'a pas lieu."
        ),
    }
}

/// Ensures that the frontend toolchain is present before Cargo finishes.
///
/// `cargo run` starts Vite from the compiled shell in debug, so merely having
/// Rust dependencies compiled is not enough to launch Orion. `npm ls` checks
/// the installed direct dependency graph; the Vite entrypoint check catches a
/// missing package directory. For a fresh, partial or damaged installation,
/// `npm ci` restores the lockfile's exact dependency graph.
fn ensure_npm_dependencies(orion: &Path, npm: &Path) {
    let vite = orion.join("node_modules/vite/bin/vite.js");
    let dependencies_are_healthy = vite.is_file()
        && std::process::Command::new(npm)
            .args(["ls", "--depth=0", "--silent"])
            .current_dir(orion)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
    if dependencies_are_healthy {
        return;
    }

    println!("cargo:warning=Orion npm dependencies missing — `npm ci` in progress");
    match std::process::Command::new(npm)
        .args(["ci"])
        .current_dir(orion)
        .status()
    {
        Ok(status) if status.success() && vite.is_file() => {}
        Ok(status) if !status.success() => panic!(
            "`npm ci` failed ({status}); Orion's frontend dependencies could not be installed"
        ),
        Ok(_) => panic!(
            "`npm ci` completed but Vite is still missing at {}; \
             check package-lock.json and the Node.js installation",
            vite.display()
        ),
        Err(error) => {
            panic!("unable to run `npm ci` ({error}); Node.js and npm are required to build Orion")
        }
    }
}

/// Finds npm, installing Node.js LTS on Windows when the toolchain is absent.
///
/// Cargo invokes this build script before Orion can start its Vite development
/// server. A fresh Windows workstation therefore cannot rely on `npm ci`: the
/// command itself is unavailable until Node.js is installed. `winget` provides
/// the signed official OpenJS package without requiring a repository checkout
/// to carry a second installer.
fn ensure_npm_available() -> std::path::PathBuf {
    let default = if cfg!(windows) { "npm.cmd" } else { "npm" };
    if command_succeeds(default) {
        return std::path::PathBuf::from(default);
    }

    if !cfg!(windows) {
        panic!(
            "Node.js and npm are required to build Orion; install them with the platform package manager"
        );
    }

    println!("cargo:warning=Node.js/npm not found — installing OpenJS Node.js LTS with winget");
    let status = std::process::Command::new("winget")
        .args([
            "install",
            "--id",
            "OpenJS.NodeJS.LTS",
            "--exact",
            "--silent",
            "--accept-source-agreements",
            "--accept-package-agreements",
        ])
        .status();
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => panic!(
            "winget could not install OpenJS Node.js LTS ({status}); install Node.js manually and retry"
        ),
        Err(error) => panic!(
            "Node.js/npm are missing and winget could not be started ({error}); \
             install Node.js LTS manually and retry"
        ),
    }

    for candidate in windows_npm_candidates() {
        if candidate.is_file() {
            return candidate;
        }
    }
    if command_succeeds("npm.cmd") {
        return std::path::PathBuf::from("npm.cmd");
    }
    panic!(
        "Node.js was installed but npm.cmd is still unavailable; restart the terminal so PATH changes apply, then retry"
    );
}

fn command_succeeds(program: &str) -> bool {
    std::process::Command::new(program)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn windows_npm_candidates() -> Vec<std::path::PathBuf> {
    [
        "ProgramFiles",
        "LOCALAPPDATA",
        "ProgramW6432",
        "ProgramFiles(x86)",
    ]
    .into_iter()
    .filter_map(std::env::var_os)
    .map(std::path::PathBuf::from)
    .map(|root| root.join("nodejs").join("npm.cmd"))
    .collect()
}

/// `dist` est-il plus vieux que la source la plus récemment modifiée ?
///
/// Comparaison de dates plutôt qu'empreinte de contenu : il s'agit de décider
/// s'il faut relancer un outil, pas de prouver une intégrité. Dans le doute —
/// `dist` absent, date illisible — la réponse est « périmé » : reconstruire de
/// trop coûte une minute, livrer une interface périmée coûte une session de
/// débogage sur un défaut qui n'existe plus.
fn stale(dist: &Path, orion: &Path) -> bool {
    let Some(built) = modified(&dist.join("index.html")) else {
        return true;
    };
    [
        orion.join("src"),
        orion.join("index.html"),
        orion.join("package.json"),
        orion.join("vite.config.ts"),
    ]
    .iter()
    .filter_map(|source| newest(source))
    .any(|source| source > built)
}

fn modified(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

fn newest(path: &Path) -> Option<std::time::SystemTime> {
    if path.is_file() {
        return modified(path);
    }
    let mut latest = None;
    for entry in std::fs::read_dir(path).ok()?.flatten() {
        let candidate = newest(&entry.path());
        if candidate > latest {
            latest = candidate;
        }
    }
    latest
}
