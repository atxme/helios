//! Narrow launcher for `astra-signer`.
//!
//! Its only caller is the CA-TLS rotation in [`crate::astra`], until lot 5
//! brings that rotation into Orion. Renewal approval no longer goes through
//! it: Orion runs that ceremony itself. The WebView never supplies an
//! executable or arguments, and no Tauri permission launches it.
//!
//! # Binary resolution
//!
//! `astra-signer` is resolved through `PATH`. The name is fixed here and in
//! `orion-core`: it does not come from a profile field, a UI field or the
//! network. This keeps development and packaged installations on the same
//! contract without embedding a platform-specific absolute path. A local user
//! can replace a binary on their own `PATH`, but the child runs as that same
//! user; on Windows the launch is refused while Orion runs elevated (see
//! [`crate::launch`]).
//!
//! There is no generic shell permission: the rotation hands over arguments
//! only, and this module launches the program named here and nothing else.

#[cfg(not(target_os = "windows"))]
const PROGRAM: &str = "astra-signer";

/// Starts `astra-signer` with the arguments the CA-TLS rotation built.
pub fn launch(arguments: &[String]) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        crate::launch::spawn_astra_signer(arguments)
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
