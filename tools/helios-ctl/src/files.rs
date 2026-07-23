//! Écritures de fichiers sensibles : exclusives, et privées quand il le faut.
//!
//! Deux propriétés valent la peine d'être centralisées :
//!
//! * **création exclusive** — écraser un secret existant est irréversible, et
//!   le seul moment où l'opérateur peut s'en apercevoir est celui où on refuse ;
//! * **permissions restrictives dès la création** — un `chmod` après coup
//!   laisse une fenêtre pendant laquelle le secret est lisible par tous.
//!
//! Le même raisonnement vaut dans `helios-publisher`, qui a ses propres copies
//! pour la même raison : les deux outils ne partagent aucune dépendance.

use std::{fs, io::Write, path::Path};

use anyhow::{Context, Result};

/// Crée un répertoire destiné à contenir des secrets (0700 sous Unix).
pub fn create_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .with_context(|| format!("création du répertoire privé {}", path.display()))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
            .with_context(|| format!("création du répertoire privé {}", path.display()))
    }
}

/// Écrit un fichier neuf, en refusant d'écraser un existant.
///
/// `secret` restreint les permissions à 0600 dès la création sous Unix.
pub fn write_new(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| {
        format!(
            "création exclusive de {} — un fichier de ce nom existe déjà ?",
            path.display()
        )
    })?;
    file.write_all(bytes)
        .with_context(|| format!("écriture de {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("synchronisation de {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(nom: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "helios-ctl-{nom}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("répertoire de test");
        dir
    }

    #[test]
    fn ecrase_jamais_un_fichier_existant() {
        let dir = temp_dir("write-new");
        let path = dir.join("secret");
        write_new(&path, b"premier", true).expect("première écriture");
        assert!(
            write_new(&path, b"second", true).is_err(),
            "un secret existant ne doit jamais être écrasé"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "premier");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn un_secret_nait_deja_illisible_par_les_autres() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        let path = dir.join("secret");
        write_new(&path, b"contenu", true).expect("écriture");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode obtenu : {mode:o}");
        let _ = fs::remove_dir_all(&dir);
    }
}
