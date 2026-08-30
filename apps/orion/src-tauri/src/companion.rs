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

use orion_core::certificate_renewal::CompanionInvocation;

const PROGRAM: &str = "astra-signer";

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
