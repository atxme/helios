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
mod profiles;

pub(crate) use app::*;
pub(crate) use ceremonies::*;
pub(crate) use certificates::*;
pub(crate) use connection::*;
pub(crate) use enrollment::*;
pub(crate) use profiles::*;
