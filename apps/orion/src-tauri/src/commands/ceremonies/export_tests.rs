use super::export_picked_vault;

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "orion-command-vault-export-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

#[test]
fn picked_export_copies_bytes_and_returns_only_success() {
    let dir = scratch("success");
    let vault = dir.join("authority-vault.json");
    let target = dir.join("private-copy.json");
    let contents = b"vault bytes including private material";
    std::fs::write(&vault, contents).expect("vault");

    assert_eq!(export_picked_vault(&vault, Some(target.clone())), Ok(true));
    assert_eq!(std::fs::read(&vault).expect("original vault"), contents);
    assert_eq!(std::fs::read(&target).expect("export"), contents);
}

#[test]
fn cancelled_export_creates_nothing_and_returns_only_cancellation() {
    let dir = scratch("cancel");
    let vault = dir.join("authority-vault.json");
    let contents = b"vault bytes";
    std::fs::write(&vault, contents).expect("vault");

    assert_eq!(export_picked_vault(&vault, None), Ok(false));
    assert_eq!(std::fs::read(&vault).expect("original vault"), contents);
    assert_eq!(std::fs::read_dir(&dir).expect("directory").count(), 1);
}

#[test]
fn refused_export_returns_no_vault_data_and_preserves_the_vault() {
    let dir = scratch("refusal");
    let vault = dir.join("authority-vault.json");
    let contents = b"vault bytes including private material";
    std::fs::write(&vault, contents).expect("vault");

    let error = export_picked_vault(&vault, Some(vault.clone())).expect_err("self export refused");
    assert_eq!(error, "le coffre ne peut pas être exporté sur lui-même");
    assert!(!error.contains("private material"));
    assert_eq!(std::fs::read(&vault).expect("original vault"), contents);
    assert_eq!(std::fs::read_dir(&dir).expect("directory").count(), 1);
}
