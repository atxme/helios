use super::*;
use orion_core::backend::dryrun::DryRunBackend;
use std::path::{Path, PathBuf};

/// A scratch directory removed when the test ends, whatever its outcome.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("orion-engine-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn paths_under(root: &Path) -> EnginePaths {
    EnginePaths {
        root: root.to_path_buf(),
        vault: root.join("vault"),
        config: root.join("config.toml"),
        identities: root.join("identities"),
        log: root.join("orion.log"),
    }
}

#[test]
fn open_builds_the_service_on_the_given_paths() {
    let scratch = Scratch::new("open-builds");
    let paths = paths_under(&scratch.0);

    let service = EngineService::open(paths.clone(), Arc::new(DryRunBackend::default()), None)
        .expect("the service opens on a fresh directory");

    assert!(service.log_path.is_none());
    assert!(service.store.device_root_path().starts_with(&paths.vault));
}

#[test]
fn open_keeps_running_on_a_vault_it_cannot_read() {
    let scratch = Scratch::new("open-vault");
    let paths = paths_under(&scratch.0);

    let service = EngineService::open(paths, Arc::new(DryRunBackend::default()), None)
        .expect("an unreadable vault does not stop the service");

    // Outside Windows the root provider refuses, so the vault cannot load: the
    // service keeps an empty configuration and records why.
    assert!(service.vault_error.is_some());
    let config = service
        .config
        .try_lock()
        .expect("nothing holds the configuration yet");
    assert!(config.profiles.is_empty());
}
