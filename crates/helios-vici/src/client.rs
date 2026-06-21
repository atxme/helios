//! Client asynchrone VICI au-dessus d'un socket Unix.

use std::path::Path;

use helios_core::{HeliosError, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::codec;
use crate::message::Message;

/// Types de paquets VICI (premier octet du corps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    CmdRequest = 0,
    CmdResponse = 1,
    CmdUnknown = 2,
    EventRegister = 3,
    EventUnregister = 4,
    EventConfirm = 5,
    EventUnknown = 6,
    Event = 7,
}

async fn write_packet(stream: &mut UnixStream, body: &[u8]) -> Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| HeliosError::Vici("paquet trop grand".into()))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_packet(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

/// Client connecté à charon via VICI pour l'envoi de commandes.
pub struct ViciClient {
    stream: UnixStream,
}

impl ViciClient {
    /// Se connecte au socket VICI de charon (typiquement `/var/run/charon.vici`).
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let stream = UnixStream::connect(path.as_ref()).await?;
        Ok(Self { stream })
    }

    /// Émet une commande et renvoie la réponse de charon.
    ///
    /// Les paquets d'événements reçus entre-temps sont ignorés ; utiliser une
    /// [`ViciEventStream`] dédiée pour les abonnements asynchrones.
    pub async fn request(&mut self, command: &str, payload: Message) -> Result<Message> {
        let mut body = Vec::with_capacity(64);
        body.push(PacketType::CmdRequest as u8);
        let name = command.as_bytes();
        if name.len() > u8::MAX as usize {
            return Err(HeliosError::Vici("nom de commande trop long".into()));
        }
        body.push(name.len() as u8);
        body.extend_from_slice(name);
        codec::encode(&payload, &mut body);
        write_packet(&mut self.stream, &body).await?;

        loop {
            let packet = read_packet(&mut self.stream).await?;
            let (tag, rest) = packet
                .split_first()
                .ok_or_else(|| HeliosError::Vici("paquet vide".into()))?;
            match *tag {
                t if t == PacketType::CmdResponse as u8 => return codec::decode(rest),
                t if t == PacketType::Event as u8 => continue, // ignoré pendant un request
                t if t == PacketType::CmdUnknown as u8 => {
                    return Err(HeliosError::Vici(format!("commande inconnue : {command}")))
                }
                other => {
                    return Err(HeliosError::Vici(format!(
                        "type de paquet inattendu : {other}"
                    )))
                }
            }
        }
    }
}

/// Connexion VICI dédiée à la réception d'événements asynchrones.
///
/// Utilise un socket séparé de [`ViciClient`] pour éviter l'entrelacement
/// commande/réponse et événement sur la même connexion. Après [`connect`],
/// appeler [`subscribe`] pour chaque événement voulu, puis boucler sur
/// [`next_event`].
///
/// [`connect`]: ViciEventStream::connect
/// [`subscribe`]: ViciEventStream::subscribe
/// [`next_event`]: ViciEventStream::next_event
pub struct ViciEventStream {
    stream: UnixStream,
}

impl ViciEventStream {
    /// Se connecte au socket VICI de charon.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let stream = UnixStream::connect(path.as_ref()).await?;
        Ok(Self { stream })
    }

    /// S'abonne à un événement VICI (ex. `ike-updown`, `child-updown`).
    ///
    /// Envoie un paquet `EventRegister` et attend la confirmation de charon.
    /// Renvoie une erreur si l'événement est inconnu de charon.
    pub async fn subscribe(&mut self, event: &str) -> Result<()> {
        let name = event.as_bytes();
        if name.len() > u8::MAX as usize {
            return Err(HeliosError::Vici("nom d'événement trop long".into()));
        }
        let mut body = Vec::with_capacity(2 + name.len());
        body.push(PacketType::EventRegister as u8);
        body.push(name.len() as u8);
        body.extend_from_slice(name);
        write_packet(&mut self.stream, &body).await?;

        let packet = read_packet(&mut self.stream).await?;
        let tag = packet
            .first()
            .copied()
            .ok_or_else(|| HeliosError::Vici("réponse d'abonnement vide".into()))?;
        if tag == PacketType::EventUnknown as u8 {
            return Err(HeliosError::Vici(format!("événement inconnu de charon : {event}")));
        }
        if tag != PacketType::EventConfirm as u8 {
            return Err(HeliosError::Vici(format!(
                "réponse inattendue à l'abonnement `{event}` : type {tag}"
            )));
        }
        Ok(())
    }

    /// Lit le prochain paquet d'événement VICI.
    ///
    /// Retourne `(nom_événement, message)`. Bloque jusqu'à réception d'un paquet
    /// de type `Event(7)`. Les autres types sont ignorés pour tolérer les
    /// variations de protocole.
    pub async fn next_event(&mut self) -> Result<(String, Message)> {
        loop {
            let packet = read_packet(&mut self.stream).await?;
            let (tag, rest) = packet
                .split_first()
                .ok_or_else(|| HeliosError::Vici("paquet d'événement vide".into()))?;
            if *tag != PacketType::Event as u8 {
                continue;
            }
            // [Event=7][name_len u8][name bytes][corps encodé...]
            let (&name_len, rest) = rest
                .split_first()
                .ok_or_else(|| HeliosError::Vici("longueur de nom d'événement manquante".into()))?;
            let name_len = name_len as usize;
            if rest.len() < name_len {
                return Err(HeliosError::Vici("nom d'événement tronqué".into()));
            }
            let (name_bytes, body) = rest.split_at(name_len);
            let event_name = String::from_utf8_lossy(name_bytes).into_owned();
            let msg = codec::decode(body)?;
            return Ok((event_name, msg));
        }
    }
}
