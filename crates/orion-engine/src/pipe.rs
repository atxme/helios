//! Named pipe between the Orion UI and the privileged engine (Windows).
//!
//! The engine creates the pipe, the UI opens it. Only the launching UI may
//! connect: the engine checks the client's PID, image and creation time
//! against the process that started it. The Win32 calls live in `windows`;
//! the decisions here are portable and tested under Linux.

use std::path::{Path, PathBuf};

#[cfg(windows)]
mod windows;

#[cfg(test)]
use orion_core::protected_root::is_plain_sid;

#[cfg(windows)]
pub use windows::{
    connect_client, create_server, observe_client, observe_process, process_user_sid,
    server_process_id,
};

#[cfg(windows)]
pub(crate) use windows::token_user_sid;

/// A process as the engine sees it: PID, executable path, creation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedClient {
    pub pid: u32,
    pub image: PathBuf,
    /// FILETIME of the process creation: 100 ns ticks since 1601, as u64.
    pub created_at: u64,
}

/// The same three facts, read from the connected client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedClient {
    pub pid: u32,
    pub image: PathBuf,
    /// FILETIME of the process creation: 100 ns ticks since 1601, as u64.
    pub created_at: u64,
}

/// Why a client or a launcher is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRefusal {
    OtherProcess,
    OtherImage,
    ReusedPid,
    StartedAfterEngine,
}

impl std::fmt::Display for ClientRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::OtherProcess => "le client n'est pas l'IHM qui a lancé le moteur",
            Self::OtherImage => "le client n'est pas ce programme Orion",
            Self::ReusedPid => "le PID de l'IHM a été réutilisé par un autre processus",
            Self::StartedAfterEngine => "l'IHM annoncée a démarré après le moteur",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ClientRefusal {}

/// The pipe name: `\\.\pipe\orion-engine-<ui_pid>-<nonce in lowercase hex>`.
///
/// The nonce comes from the system's random source, so two engines never
/// choose the same name.
pub fn pipe_name(ui_pid: u32, nonce: &[u8; 16]) -> String {
    let mut name = format!(r"\\.\pipe\orion-engine-{ui_pid}-");
    for byte in nonce {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

/// Turns the launcher the UI announced at start-up into the expected client.
///
/// Refused when the launcher runs another image than the engine, or when it
/// was created at or after the engine: a UI started later cannot be the
/// launcher, so its PID must have been reused. A launcher whose creation time
/// reads as zero is refused as reused too: its time is unknown, so it cannot
/// be trusted.
pub fn expected_from_launcher(
    launcher: ObservedClient,
    engine_image: &Path,
    engine_created_at: u64,
) -> Result<ExpectedClient, ClientRefusal> {
    if !same_image(&launcher.image, engine_image) {
        return Err(ClientRefusal::OtherImage);
    }
    if launcher.created_at == 0 {
        return Err(ClientRefusal::ReusedPid);
    }
    if launcher.created_at >= engine_created_at {
        return Err(ClientRefusal::StartedAfterEngine);
    }
    Ok(ExpectedClient {
        pid: launcher.pid,
        image: launcher.image,
        created_at: launcher.created_at,
    })
}

/// Checks a connected client against the expected process.
pub fn verify_client(
    expected: &ExpectedClient,
    observed: &ObservedClient,
) -> Result<(), ClientRefusal> {
    if observed.pid != expected.pid {
        return Err(ClientRefusal::OtherProcess);
    }
    if !same_image(&observed.image, &expected.image) {
        return Err(ClientRefusal::OtherImage);
    }
    if observed.created_at != expected.created_at {
        return Err(ClientRefusal::ReusedPid);
    }
    Ok(())
}

/// Case-insensitive comparison of two image paths, after dropping the
/// `\\?\` verbatim prefix on either side. Only ASCII letters fold: a
/// non-ASCII character that lowercases to an ASCII letter (such as the Kelvin
/// sign) does not make two paths the same. A path that is not valid Unicode
/// is never equal: refusing is the safe answer.
fn same_image(a: &Path, b: &Path) -> bool {
    let (Some(a), Some(b)) = (a.to_str(), b.to_str()) else {
        return false;
    };
    let a = a.strip_prefix(r"\\?\").unwrap_or(a);
    let b = b.strip_prefix(r"\\?\").unwrap_or(b);
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests;
