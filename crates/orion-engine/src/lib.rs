//! Channel between the privileged Orion engine and its unprivileged UI.
//!
//! F11 splits the client into two processes: an elevated engine that brings
//! up the tunnel, and an unprivileged UI. This crate carries the only link
//! between them: one JSON object per line, size-bounded on both reading and
//! writing.

pub mod command;
pub mod session;
pub mod wire;

pub use command::{EngineCommand, EngineReply, ProfileDraft, SecretInput};
pub use wire::{
    limits, read_frame, write_frame, ClientFrame, EngineFrame, Hello, WireError, PROTOCOL_VERSION,
};
