//! The commands the frontend invokes, by capability.
//!
//! Each child keeps the private helpers of its commands. Everything a
//! command needs from the shell — the state, the sinks, the window — stays at
//! the crate root, which the notification-area wiring also reaches.

use super::*;

mod app;
mod ceremonies;
mod certificates;
mod connection;
mod enrollment;
mod gateway_recovery;
mod profiles;
#[cfg(test)]
mod test_support;

/// What the shell answers when the engine replies with another family's variant.
pub(crate) fn unexpected_engine_reply() -> String {
    "Réponse inattendue du moteur d'Orion.".into()
}

pub(crate) use app::*;
pub(crate) use ceremonies::*;
pub(crate) use certificates::*;
pub(crate) use connection::*;
pub(crate) use enrollment::*;
pub(crate) use gateway_recovery::*;
pub(crate) use profiles::*;

/// Lets the elevated engine take the foreground before a command that may open
/// its passphrase dialog: see [`crate::engine_launch::allow_foreground`].
pub(crate) fn allow_engine_foreground(state: &AppState) {
    #[cfg(windows)]
    crate::engine_launch::allow_foreground(&state.engine);
    #[cfg(not(windows))]
    let _ = state;
}
