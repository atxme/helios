//! Canal entre le moteur privilégié d'Orion et son IHM non élevée.
//!
//! F11 sépare le client en deux processus : un moteur élevé qui monte le
//! tunnel, et une IHM sans privilège. Ce crate porte la seule liaison qui les
//! relie, un objet JSON par ligne et bornée en taille, côté lecture comme
//! côté écriture.

pub mod command;
pub mod wire;

pub use command::{EngineCommand, EngineReply};
pub use wire::{
    limits, read_frame, write_frame, ClientFrame, EngineFrame, Hello, WireError, PROTOCOL_VERSION,
};
