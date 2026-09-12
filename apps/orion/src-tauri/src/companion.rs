//! Narrow launcher for the Astra operator companion.
//!
//! The WebView never supplies an executable or arguments. It asks the
//! `companion` Tauri plugin to approve one profile; the command resolves that
//! profile's in-memory renewal session and hands this module the invocation
//! built by `orion-core`.
//!
//! # Binary resolution
//!
//! `astra-signer` is resolved through `PATH`. The name is fixed here and in
//! `orion-core`: it does not come from a profile field, a UI field or the
//! network. This keeps development and packaged installations on the same
//! contract without embedding a platform-specific absolute path. A local user
//! can replace a binary on their own `PATH`, but the child runs as that same
//! user; on Windows Orion explicitly drops its Administrator token first.
//!
//! The Tauri capability grants one command from one inlined plugin. There is
//! no generic shell permission, and this module refuses if the core ever asks
//! it to launch anything other than the companion named here.

use std::path::PathBuf;

use orion_core::certificate_renewal::CompanionInvocation;

const PROGRAM: &str = "astra-signer";

/// The operator process of protocol 2.
///
/// A second literal beside the first, and not a parameter: this module exists
/// so that no WebView value, profile field or network answer can ever name an
/// executable. Two names it will launch, both written here.
const HELPER: &str = "helios-astra-helper";

fn arguments(invocation: &CompanionInvocation) -> Result<&[String], String> {
    if invocation.program != PROGRAM {
        return Err(format!(
            "lancement refusé : le compagnon attendu est « {PROGRAM} », pas « {} »",
            invocation.program
        ));
    }
    Ok(&invocation.arguments)
}

/// Starts the exact companion invocation produced by the renewal session.
pub fn launch(invocation: &CompanionInvocation) -> Result<(), String> {
    let arguments = arguments(invocation)?;

    #[cfg(target_os = "windows")]
    {
        crate::deelevate::spawn_astra_signer(arguments)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let mut child = tokio::process::Command::new(PROGRAM)
            .args(arguments)
            .spawn()
            .map_err(|error| format!("lancement de « {PROGRAM} » impossible : {error}"))?;
        // Reap in the existing application runtime without tying the
        // companion's interactive lifetime to an IPC request.
        tauri::async_runtime::spawn(async move {
            let _ = child.wait().await;
        });
        Ok(())
    }
}

/// Starts the operator helper, handing it the session in its environment.
///
/// `arguments` carries the address to connect back to — public, and useful in
/// a log. `environment` carries the session token, keeping it out of ordinary
/// process-list command lines.
pub fn launch_helper(
    arguments: &[String],
    environment: &[(String, String)],
) -> Result<u32, String> {
    let program = helper_program()?;
    #[cfg(target_os = "windows")]
    {
        crate::deelevate::spawn_astra_helper(&program, arguments, environment)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let mut child = tokio::process::Command::new(&program)
            .args(arguments)
            .envs(environment.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .spawn()
            .map_err(|error| format!("lancement de « {HELPER} » impossible : {error}"))?;
        let process_id = child
            .id()
            .ok_or_else(|| format!("identifiant du processus « {HELPER} » indisponible"))?;
        tauri::async_runtime::spawn(async move {
            let _ = child.wait().await;
        });
        Ok(process_id)
    }
}

/// Transfers the foreground right at the press that will open WebAuthn.
pub fn allow_helper_foreground(owner: isize, process_id: u32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        crate::deelevate::cede_foreground(owner, process_id)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (owner, process_id);
        Ok(())
    }
}

/// The helper is a sidecar of this exact Orion build, never a name resolved
/// through the current directory or `PATH`.
fn helper_program() -> Result<PathBuf, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("emplacement d'Orion introuvable : {error}"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| "le chemin d'Orion n'a aucun répertoire parent".to_string())?;
    let helper = directory.join(format!("{HELPER}{}", std::env::consts::EXE_SUFFIX));
    if !helper.is_file() {
        return Err(format!(
            "le processus opérateur installé avec Orion est absent : {}",
            helper.display()
        ));
    }
    Ok(helper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_launcher_accepts_only_astra_signer() {
        let approved = CompanionInvocation {
            program: "astra-signer",
            arguments: vec!["approve".into()],
        };
        assert_eq!(arguments(&approved), Ok(approved.arguments.as_slice()));

        let rejected = CompanionInvocation {
            program: "sh",
            arguments: vec!["-c".into(), "anything".into()],
        };
        assert!(arguments(&rejected)
            .expect_err("a generic shell must be refused")
            .contains("compagnon attendu"));
    }
}
