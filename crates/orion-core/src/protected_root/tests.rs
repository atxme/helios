use super::*;

#[test]
fn the_vault_and_the_log_sit_under_the_root() {
    let paths = EnginePaths::for_current_user().expect("the per-user directories");

    assert!(paths.vault.starts_with(&paths.root));
    assert!(paths.log.starts_with(&paths.root));
    assert_eq!(paths.log, paths.vault.join(LOG_FILE));
}

#[test]
fn the_config_file_sits_under_the_root() {
    let paths = EnginePaths::for_current_user().expect("the per-user directories");

    assert!(paths.config.starts_with(&paths.root));
}
