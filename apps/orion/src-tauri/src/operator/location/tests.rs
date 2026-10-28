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
    let location = VaultLocation::at(scratch.settings());
    let view = location.view().expect("view");
    assert!(view.is_default);
    assert_eq!(view.picker_available, cfg!(windows));
    let default = astra_operator::store::default_path().expect("default path");
    assert_eq!(location.path().expect("path"), default);
    assert_eq!(view.path, default.display().to_string());
}

/// The choice is written, and a later start reads it back.
#[test]
fn a_choice_survives_a_reload() {
    let scratch = Scratch::new("reload");
    let chosen = scratch.0.join("x").join(VAULT_FILE_NAME);
    let view = VaultLocation::at(scratch.settings())
        .choose(chosen.clone())
        .expect("choose");
    assert!(!view.is_default);
    assert_eq!(view.path, chosen.display().to_string());

    let reloaded = VaultLocation::at(scratch.settings());
    assert_eq!(reloaded.path().expect("path"), chosen);
    assert!(!reloaded.view().expect("view").is_default);

    let reset = reloaded.reset().expect("reset");
    assert!(reset.is_default);
    assert_eq!(
        VaultLocation::at(scratch.settings()).path().expect("path"),
        astra_operator::store::default_path().expect("default path")
    );
}

/// A relative path would follow the working directory, and another name would
/// not be a vault the tooling recognises: both are refused, and the setting
/// already written stays as it was.
#[test]
fn only_an_absolute_vault_file_is_accepted() {
    let scratch = Scratch::new("refused");
    let location = VaultLocation::at(scratch.settings());
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
    let location = VaultLocation::at(scratch.settings());
    assert!(location.path().is_err());
    assert!(location.view().is_err());

    for unexpected in [
        r#"{"vault_path":"relative/authority-vault.json"}"#,
        r#"{"vault_path":"/a/authority-vault.json","other":1}"#,
    ] {
        std::fs::write(scratch.settings(), unexpected).expect("write");
        assert!(
            VaultLocation::at(scratch.settings()).path().is_err(),
            "{unexpected}"
        );
    }
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
    let location = VaultLocation::at(scratch.settings());
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
