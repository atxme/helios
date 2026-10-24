//! Commandes de l'IHM vers le moteur, et leurs réponses.
//!
//! Ensemble minimal pour l'instant : l'arrêt. Les autres commandes suivent
//! avec le moteur qui les exécute.

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
