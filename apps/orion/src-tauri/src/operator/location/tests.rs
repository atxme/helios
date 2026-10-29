use super::*;

/// A directory of its own per test, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "orion-vault-location-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("scratch directory");
        Self(directory)
    }

    fn settings(&self) -> PathBuf {
        self.0.join("settings.json")
    }

    /// A default vault whose folder does not exist yet, as on a fresh machine.
    fn default_vault(&self) -> PathBuf {
        self.0.join("appdata").join("astra").join(VAULT_FILE_NAME)
    }

    /// A location whose default vault is [`Scratch::default_vault`], so no
    /// test creates the real default folder.
    fn location(&self) -> VaultLocation {
        VaultLocation::with_default(self.settings(), Ok(self.default_vault()))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Without a setting, the vault is where the operator tooling always kept it.
#[test]
fn the_default_applies_until_a_choice_is_made() {
    let scratch = Scratch::new("default");
    let location = scratch.location();
    let view = location.view();
    assert!(view.is_default);
    assert_eq!(view.picker_available, cfg!(windows));
    assert_eq!(view.error, None);
    let default = scratch.default_vault();
    assert_eq!(location.path().expect("path"), default);
    assert_eq!(view.path, Some(default.display().to_string()));
}

/// The tooling's default is the one `load` and `at` open with.
#[test]
fn the_default_is_the_tooling_default() {
    let scratch = Scratch::new("tooling-default");
    let location = VaultLocation::at(scratch.settings());
    assert_eq!(
        location.default,
        Ok(astra_operator::store::default_path().expect("default path"))
    );
}

/// On a fresh machine nothing has created the default folder yet: resolving
/// the vault creates it, privately, so a domain can be created there.
#[test]
fn the_default_folder_is_created_when_the_vault_is_resolved() {
    let scratch = Scratch::new("fresh");
    let default = scratch.default_vault();
    let folder = default.parent().expect("folder").to_path_buf();
    assert!(!folder.exists());
    assert!(
        !astra_operator::overview::read(&default)
            .expect("overview")
            .location_available
    );

    let path = scratch.location().path().expect("path");

    assert_eq!(path, default);
    assert!(folder.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&folder)
            .expect("folder")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }
    let overview = astra_operator::overview::read(&path).expect("overview");
    assert!(overview.location_available);
    assert!(!overview.exists);
    assert_eq!(
        astra_operator::vault_gestures::check_creation(&path),
        Ok(())
    );
}

/// A chosen folder is the operator's: an unplugged medium is not recreated
/// on the disk underneath it.
#[test]
fn a_chosen_folder_is_never_created() {
    let scratch = Scratch::new("chosen-missing");
    let location = scratch.location();
    let chosen = scratch.0.join("usb").join(VAULT_FILE_NAME);
    location.choose(chosen.clone()).expect("choose");

    assert_eq!(location.path().expect("path"), chosen);

    assert!(!scratch.0.join("usb").exists());
    assert!(!scratch.default_vault().parent().expect("folder").exists());
    assert_eq!(
        astra_operator::vault_gestures::check_creation(&chosen),
        Err(astra_operator::vault_gestures::SetupRefusal::LocationUnavailable)
    );
}

/// A default folder that cannot be created stays absent, and the creation is
/// refused as it was: nothing is written anywhere else.
#[test]
fn a_default_folder_that_cannot_be_created_stays_unavailable() {
    let scratch = Scratch::new("blocked");
    let blocker = scratch.0.join("appdata");
    std::fs::write(&blocker, "not a folder").expect("blocker");
    let location = scratch.location();

    let path = location.path().expect("the path still resolves");

    assert!(blocker.is_file());
    // The overview fails or says unavailable; it never offers a creation.
    assert!(!matches!(
        astra_operator::overview::read(&path),
        Ok(overview) if overview.location_available
    ));
    assert_eq!(
        astra_operator::vault_gestures::check_creation(&path),
        Err(astra_operator::vault_gestures::SetupRefusal::LocationUnavailable)
    );
}

/// The choice is written, and a later start reads it back.
#[test]
fn a_choice_survives_a_reload() {
    let scratch = Scratch::new("reload");
    let chosen = scratch.0.join("x").join(VAULT_FILE_NAME);
    let view = scratch.location().choose(chosen.clone()).expect("choose");
    assert!(!view.is_default);
    assert_eq!(view.path, Some(chosen.display().to_string()));

    let reloaded = scratch.location();
    assert_eq!(reloaded.path().expect("path"), chosen);
    assert!(!reloaded.view().is_default);

    let reset = reloaded.reset().expect("reset");
    assert!(reset.is_default);
    assert_eq!(
        scratch.location().path().expect("path"),
        scratch.default_vault()
    );
}

/// A relative path would follow the working directory, and another name would
/// not be a vault the tooling recognises: both are refused, and the setting
/// already written stays as it was.
#[test]
fn only_an_absolute_vault_file_is_accepted() {
    let scratch = Scratch::new("refused");
    let location = scratch.location();
    let kept = scratch.0.join("kept").join(VAULT_FILE_NAME);
    location.choose(kept.clone()).expect("choose");
    let written = std::fs::read(scratch.settings()).expect("setting");

    for refused in [
        PathBuf::from("relative").join(VAULT_FILE_NAME),
        scratch.0.join("autre.json"),
    ] {
        assert!(location.choose(refused.clone()).is_err(), "{refused:?}");
        assert_eq!(location.path().expect("path"), kept);
    }
    assert_eq!(std::fs::read(scratch.settings()).expect("setting"), written);
}

/// A setting that cannot be read is not silently replaced by the default: the
/// operator chose a vault, and a ceremony against another one would sign with
/// a domain they did not mean.
#[test]
fn an_unreadable_setting_is_an_error_not_the_default() {
    let scratch = Scratch::new("unreadable");
    std::fs::write(scratch.settings(), "{").expect("write");
    let location = scratch.location();
    assert!(location.path().is_err());
    assert!(
        !scratch.default_vault().parent().expect("folder").exists(),
        "the default is not opened instead"
    );

    for unexpected in [
        r#"{"vault_path":"relative/authority-vault.json"}"#,
        r#"{"vault_path":"/a/authority-vault.json","other":1}"#,
    ] {
        std::fs::write(scratch.settings(), unexpected).expect("write");
        assert!(scratch.location().path().is_err(), "{unexpected}");
    }
}

/// The view of an unreadable setting says why, and still offers the ways out:
/// it is not the default, so going back to the default is offered, and the
/// picker stays where it exists. Going back then serves the default again.
#[test]
fn an_unreadable_setting_still_has_a_view_with_its_ways_out() {
    let scratch = Scratch::new("unreadable-view");
    std::fs::write(scratch.settings(), "{").expect("write");
    let location = scratch.location();

    let view = location.view();
    assert_eq!(view.path, None);
    assert!(!view.is_default);
    assert_eq!(view.picker_available, cfg!(windows));
    let error = view.error.expect("the reason");
    assert!(error.contains("illisible"), "{error}");

    let reset = location.reset().expect("reset");
    assert!(reset.is_default);
    assert_eq!(reset.error, None);
    assert_eq!(
        reset.path,
        Some(scratch.default_vault().display().to_string())
    );
}

/// Windows ignores the case of a file name, so a dialog answer in another case
/// still names the vault there; elsewhere only the exact name does.
#[test]
fn the_vault_name_ignores_case_only_where_the_file_system_does() {
    let typed = std::ffi::OsStr::new("Authority-Vault.JSON");
    let exact = std::ffi::OsStr::new(VAULT_FILE_NAME);
    let other = std::ffi::OsStr::new("authority-vault.json.bak");
    assert!(names_a_vault(typed, true));
    assert!(!names_a_vault(typed, false));
    assert!(names_a_vault(exact, true));
    assert!(names_a_vault(exact, false));
    assert!(!names_a_vault(other, true));
    assert!(!names_a_vault(other, false));
}

/// One dialog at a time: a second is refused while the first is open, and the
/// place is free again once it closes.
#[test]
fn only_one_picker_is_open_at_a_time() {
    let scratch = Scratch::new("picker");
    let location = scratch.location();
    let first = location.begin_pick().expect("first picker");
    assert_eq!(
        location.begin_pick().err().as_deref(),
        Some(PICKER_ALREADY_OPEN)
    );
    drop(first);
    let again = location.begin_pick().expect("free once the first closed");
    drop(again);

    // A return through an error releases it the same way.
    let failed = || -> Result<(), String> {
        let _picker = location.begin_pick()?;
        Err("cancelled".into())
    };
    assert!(failed().is_err());
    assert!(location.begin_pick().is_ok());
}
