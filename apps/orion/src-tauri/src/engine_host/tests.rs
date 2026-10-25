use super::*;

use std::time::{SystemTime, UNIX_EPOCH};

const DLL: &str = "wireguard-test.dll";

/// A directory under the system temporary folder, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "orion-engine-host-{}-{label}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn place_dll(directory: &Path) {
    std::fs::write(directory.join(DLL), b"dll").expect("write the DLL stand-in");
}

#[cfg(not(windows))]
#[test]
fn off_windows_engine_mode_is_refused() {
    let token = "ab".repeat(32);
    let args = EngineArgs::parse(&[
        "--engine".to_owned(),
        "--pipe".to_owned(),
        r"\\.\pipe\orion-engine-1".to_owned(),
        "--ui-pid".to_owned(),
        "4242".to_owned(),
        "--ui-created".to_owned(),
        "7".to_owned(),
        "--token".to_owned(),
        token,
    ])
    .expect("valid arguments")
    .expect("engine mode");
    assert_eq!(run(args), BAD_ARGUMENTS);
}

#[test]
fn the_workspace_fallback_is_refused_when_not_allowed() {
    let executable = Scratch::new("exe-fallback");
    let workspace = Scratch::new("workspace-fallback");
    let empty = Scratch::new("empty-fallback");

    // Beside the executable: that directory, whatever the fallback says.
    place_dll(executable.path());
    assert_eq!(
        wireguard_source_dir(executable.path(), workspace.path(), DLL, false),
        Ok(executable.path().to_path_buf())
    );
    assert_eq!(
        wireguard_source_dir(executable.path(), workspace.path(), DLL, true),
        Ok(executable.path().to_path_buf())
    );

    // Only in the workspace: refused without the fallback, used with it.
    let elsewhere = Scratch::new("exe-without-dll");
    place_dll(workspace.path());
    assert!(wireguard_source_dir(elsewhere.path(), workspace.path(), DLL, false).is_err());
    assert_eq!(
        wireguard_source_dir(elsewhere.path(), workspace.path(), DLL, true),
        Ok(workspace.path().to_path_buf())
    );

    // Nowhere: refused either way.
    assert!(wireguard_source_dir(empty.path(), empty.path(), DLL, true).is_err());
    assert!(wireguard_source_dir(empty.path(), empty.path(), DLL, false).is_err());
}
