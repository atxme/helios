//! Trames du canal moteur / IHM : un objet JSON par ligne, borné en taille.
//!
//! Même forme que `tools/helios-astra-helper/src/session.rs`, en asynchrone.
//! Une ligne au-delà de sa limite est refusée sans être lue jusqu'au bout.

use std::io;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::command::{EngineCommand, EngineReply};
use orion_core::events::ClientEvent;

/// Version du protocole : une IHM dont la version diffère est refusée au `Hello`.
pub const PROTOCOL_VERSION: u16 = 1;

/// Tailles maximales d'une trame, saut de ligne non compris.
pub mod limits {
    pub const HELLO_BYTES: usize = 1024;
    pub const REQUEST_BYTES: usize = 1024 * 1024;
    pub const REPLY_BYTES: usize = 1024 * 1024;
    pub const EVENT_BYTES: usize = 64 * 1024;
}

/// Première trame de l'IHM : elle présente le jeton que le moteur lui a remis.
#[derive(Serialize, Deserialize)]
pub struct Hello {
    pub protocol_version: u16,
    /// Secret : ce type n'implémente pas `Debug` pour qu'il ne s'affiche pas.
    pub token: String,
}

/// Trames émises par l'IHM.
#[derive(Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
pub enum ClientFrame {
    Hello(Hello),
    Request { id: u64, command: EngineCommand },
}

/// Trames émises par le moteur : la réponse à une requête, ou un événement poussé.
#[derive(Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
pub enum EngineFrame {
    Reply {
        id: u64,
        result: Result<EngineReply, String>,
    },
    Event(ClientEvent),
}

/// Échec du canal. Toute erreur ferme la connexion : il n'y a pas de reprise
/// au milieu d'une ligne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// La trame dépasse la limite fixée par l'appelant.
    TooLarge { limit: usize },
    /// Ligne qui n'est pas une trame valide, ou flux fermé au milieu d'une ligne.
    Malformed,
    /// Erreur d'entrée-sortie, réduite à son genre.
    Io(io::ErrorKind),
}

impl From<io::Error> for WireError {
    fn from(error: io::Error) -> Self {
        WireError::Io(error.kind())
    }
}

/// Lit une trame. `Ok(None)` est une fin de flux propre, avant tout octet.
pub async fn read_frame<R, T>(reader: &mut R, limit: usize) -> Result<Option<T>, WireError>
where
    R: AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    let mut line = Vec::new();
    // Un octet de plus que la limite, saut de ligne compris : une trame à la
    // limite passe, le premier octet au-delà est refusé sans être bufferisé.
    let mut window = AsyncReadExt::take(&mut *reader, limit as u64 + 1);
    let read = window.read_until(b'\n', &mut line).await?;
    if read == 0 {
        return Ok(None);
    }
    let terminated = line.last() == Some(&b'\n');
    if terminated {
        line.pop();
    }
    if line.len() > limit {
        return Err(WireError::TooLarge { limit });
    }
    if !terminated {
        return Err(WireError::Malformed);
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|_| WireError::Malformed)
}

/// Écrit une trame suivie d'un saut de ligne, refusant d'en écrire une
/// au-delà de `limit` : rien n'est écrit dans ce cas.
pub async fn write_frame<W, T>(writer: &mut W, frame: &T, limit: usize) -> Result<(), WireError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut bytes = serde_json::to_vec(frame).map_err(|_| WireError::Malformed)?;
    if bytes.len() > limit {
        return Err(WireError::TooLarge { limit });
    }
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
