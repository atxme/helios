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

    // Debug charge `devUrl` : Vite sert les sources, et
    // `ensure_frontend_dev_server` le démarre au besoin. Rien à construire, et
    // le construire coûterait une minute à chaque `cargo run`.
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        ensure_frontend_built(&orion);
    }

    let windows = tauri_build::WindowsAttributes::new()
        .app_manifest(include_str!("windows/orion-manifest.xml"));
    let attributes = tauri_build::Attributes::new().windows_attributes(windows);
    tauri_build::try_build(attributes).expect("construction des ressources Tauri Orion");
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
        "vite.config.ts",
        "tsconfig.json",
    ] {
        println!("cargo:rerun-if-changed={}", orion.join(entry).display());
    }
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
fn ensure_frontend_built(orion: &Path) {
    if !stale(&orion.join("dist"), orion) {
        return;
    }
    println!("cargo:warning=frontend Orion périmé — `npm run build` en cours");

    if !orion.join("node_modules").is_dir() {
        panic!(
            "les dépendances npm d'Orion sont absentes : lancer `npm ci --prefix apps/orion` \
             avant une compilation release. Le frontend ne peut pas être construit sans elles, \
             et embarquer un `dist` périmé produirait une interface qui n'est plus celle du code."
        );
    }

    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };
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
            "impossible de lancer `{npm} run build` ({error}). Node.js est requis pour une \
             compilation release d'Orion ; en debug, l'interface est servie par Vite et cette \
             étape n'a pas lieu."
        ),
    }
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
