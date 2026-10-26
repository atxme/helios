use super::*;

const USER: &str = "S-1-5-21-1-2-3-1001";
const OTHER_USER: &str = "S-1-5-21-1-2-3-1002";
const USERS: &str = "S-1-5-32-545";
const FULL: u32 = 0x001F_01FF;

fn ace(sid: &str, allow: bool) -> Ace {
    Ace {
        sid: sid.to_string(),
        allow,
        mask: FULL,
        inherited: false,
    }
}

fn admins_and_system() -> Vec<Ace> {
    vec![ace(ADMINISTRATORS, true), ace(SYSTEM, true)]
}

#[cfg(not(windows))]
#[test]
fn the_vault_and_the_log_sit_under_the_root() {
    let paths = EnginePaths::for_current_user().expect("the per-user directories");

    assert!(paths.vault.starts_with(&paths.root));
    assert!(paths.log.starts_with(&paths.root));
    assert_eq!(paths.log, paths.vault.join(LOG_FILE));
}

#[cfg(not(windows))]
#[test]
fn the_config_file_sits_under_the_root() {
    let paths = EnginePaths::for_current_user().expect("the per-user directories");

    assert!(paths.config.starts_with(&paths.root));
}

#[test]
fn an_admin_and_system_only_dacl_is_accepted() {
    assert!(admits_only_admins(
        ADMINISTRATORS,
        &admins_and_system(),
        true
    ));
    assert!(admits_only_admins(SYSTEM, &admins_and_system(), true));
}

#[test]
fn a_user_allow_ace_is_refused() {
    let mut aces = admins_and_system();
    aces.push(ace(USER, true));

    assert!(!admits_only_admins(ADMINISTRATORS, &aces, true));
}

#[test]
fn an_unprotected_dacl_is_refused() {
    assert!(!admits_only_admins(
        ADMINISTRATORS,
        &admins_and_system(),
        false
    ));
}

#[test]
fn deny_aces_do_not_widen_access() {
    let mut aces = admins_and_system();
    aces.push(ace(USER, false));

    assert!(admits_only_admins(ADMINISTRATORS, &aces, true));
}

#[test]
fn a_user_owned_directory_is_refused() {
    assert!(!admits_only_admins(USER, &admins_and_system(), true));
}

#[test]
fn the_protected_root_is_per_user_sid() {
    let program_data = Path::new("/programdata");
    let first = protected_root_for(program_data, USER).expect("a plain SID");
    let second = protected_root_for(program_data, OTHER_USER).expect("a plain SID");

    assert_ne!(first, second);
    assert_eq!(first, Path::new("/programdata/helios/orion").join(USER));
}

#[test]
fn a_sid_that_is_not_a_plain_path_component_is_refused() {
    let program_data = Path::new("/programdata");

    assert!(protected_root_for(program_data, r"S-1-5-21\..\x").is_err());
    assert!(protected_root_for(program_data, "S-1-5-21-1/../../x").is_err());
    assert!(protected_root_for(program_data, "..").is_err());
}

#[test]
fn every_engine_path_is_under_the_protected_root() {
    let root = Path::new("/protected/S-1-5-21-1-2-3-1001");
    let paths = EnginePaths::under(root);

    assert_eq!(paths.root, root);
    assert_eq!(paths.vault, root.join("vault"));
    assert_eq!(paths.config, root.join("profiles.toml"));
    assert_eq!(paths.identities, root.join("identities"));
    assert_eq!(paths.log, root.join(LOG_FILE));
    for path in [&paths.vault, &paths.config, &paths.identities, &paths.log] {
        assert!(path.starts_with(&paths.root), "{path:?} escapes the root");
    }
}

#[test]
fn release_builds_ignore_path_overrides() {
    const VARIABLE: &str = "ORION_TEST_RELEASE_ONLY_OVERRIDE";
    std::env::set_var(VARIABLE, "/somewhere/else");

    let ignored = path_override(VARIABLE, false);
    let honoured = path_override(VARIABLE, true);
    std::env::remove_var(VARIABLE);

    assert_eq!(ignored, None);
    assert_eq!(honoured, Some(PathBuf::from("/somewhere/else")));
}

#[test]
fn an_override_wins_in_development_builds() {
    let chosen = select(
        Some(PathBuf::from("/override")),
        Some(PathBuf::from("/installed")),
        || Ok(PathBuf::from("/platform")),
    );

    assert_eq!(chosen, Ok(PathBuf::from("/override")));
}

#[test]
fn an_installed_root_wins_over_the_platform_default() {
    let chosen = select(None, Some(PathBuf::from("/installed")), || {
        Ok(PathBuf::from("/platform"))
    });

    assert_eq!(chosen, Ok(PathBuf::from("/installed")));
}

#[test]
fn the_platform_default_applies_when_nothing_else_does() {
    let chosen = select(None, None, || Ok(PathBuf::from("/platform")));

    assert_eq!(chosen, Ok(PathBuf::from("/platform")));
}

#[test]
fn no_location_is_chosen_when_the_platform_has_none() {
    let chosen = select(None, None, || Err(NOT_ESTABLISHED.to_string()));

    assert_eq!(chosen, Err(NOT_ESTABLISHED.to_string()));
}

#[test]
fn a_refused_root_reads_as_the_dacl_refusal() {
    assert_eq!(RootError::Refused.to_string(), REFUSED_ROOT);
    assert_eq!(
        RootError::Unavailable("autre cause".to_string()).to_string(),
        "autre cause"
    );
}

#[test]
fn an_unknown_ace_type_is_refused() {
    let aces = vec![
        ace(ADMINISTRATORS, true),
        ace(SYSTEM, true),
        classify_ace(0x05, FULL, ADMINISTRATORS.to_string(), false),
    ];

    assert!(!admits_only_admins(ADMINISTRATORS, &aces, true));
}

fn ace_with(sid: &str, mask: u32) -> Ace {
    Ace {
        sid: sid.to_string(),
        allow: true,
        mask,
        inherited: false,
    }
}

#[test]
fn an_executable_directory_writable_by_a_user_is_refused() {
    let aces = vec![
        ace(ADMINISTRATORS, true),
        ace(SYSTEM, true),
        ace_with(USERS, FILE_ADD_FILE),
    ];

    assert!(grants_user_write(
        ADMINISTRATORS,
        &aces,
        DIRECTORY_WRITE_MASK
    ));
}

#[test]
fn a_program_files_like_dacl_is_accepted() {
    let aces = vec![
        ace(ADMINISTRATORS, true),
        ace(SYSTEM, true),
        ace(TRUSTED_INSTALLER, true),
        ace_with(USERS, 0x0012_00A9),
        ace_with(CREATOR_OWNER, GENERIC_ALL),
    ];

    for mask in [DIRECTORY_WRITE_MASK, FILE_WRITE_MASK, PARENT_WRITE_MASK] {
        assert!(
            !grants_user_write(TRUSTED_INSTALLER, &aces, mask),
            "mask {mask:#x} is writable"
        );
    }
}

#[test]
fn a_user_owned_install_is_refused() {
    assert!(grants_user_write(
        USER,
        &admins_and_system(),
        FILE_WRITE_MASK
    ));
}

#[test]
fn a_parent_that_lets_users_delete_children_is_refused() {
    let aces = vec![
        ace(ADMINISTRATORS, true),
        ace(SYSTEM, true),
        ace_with(USERS, FILE_DELETE_CHILD),
    ];

    assert!(grants_user_write(ADMINISTRATORS, &aces, PARENT_WRITE_MASK));
}

#[test]
fn a_writable_dll_is_refused() {
    let aces = vec![
        ace(ADMINISTRATORS, true),
        ace(SYSTEM, true),
        ace_with(USERS, FILE_WRITE_DATA),
    ];

    assert!(grants_user_write(ADMINISTRATORS, &aces, FILE_WRITE_MASK));
}

#[test]
fn deny_aces_do_not_make_an_install_writable() {
    let mut aces = admins_and_system();
    aces.push(Ace {
        sid: USERS.to_string(),
        allow: false,
        mask: FULL,
        inherited: false,
    });

    assert!(!grants_user_write(
        ADMINISTRATORS,
        &aces,
        DIRECTORY_WRITE_MASK
    ));
    assert!(!grants_user_write(ADMINISTRATORS, &aces, FILE_WRITE_MASK));
    assert!(!grants_user_write(ADMINISTRATORS, &aces, PARENT_WRITE_MASK));
}

#[test]
fn an_unknown_ace_type_in_an_install_is_refused() {
    let mut aces = admins_and_system();
    aces.push(classify_ace(0x05, 0, String::new(), false));

    assert!(grants_user_write(ADMINISTRATORS, &aces, FILE_WRITE_MASK));
}

#[test]
fn the_writable_install_error_reads_as_its_message() {
    assert_eq!(RootError::WritableInstall.to_string(), WRITABLE_INSTALL);
}
