//! Narrow launcher for the Astra operator companion.
//!
//! The WebView never supplies an executable or arguments. It asks the
//! `companion` Tauri plugin to approve one profile; the command asks the engine
//! for the arguments of that profile's renewal session, built by `orion-core`.
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
//! no generic shell permission: the engine hands over arguments only, after
//! refusing any invocation that names another program, and this module
//! launches the companion named here and nothing else.

#[cfg(not(target_os = "windows"))]
const PROGRAM: &str = "astra-signer";

/// Starts the companion with the arguments the engine approved for the session.
pub fn launch(arguments: &[String]) -> Result<(), String> {
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
