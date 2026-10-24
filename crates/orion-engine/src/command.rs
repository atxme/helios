//! Commands from the UI to the engine, and their replies.
//!
//! Minimal set for now: shutdown. Further commands arrive with the engine
//! that executes them.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum EngineCommand {
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum EngineReply {
    Unit,
}
