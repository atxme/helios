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

/// Client connecté à charon via VICI.
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
    /// Les paquets d'événements reçus entre-temps sont ignorés (utiliser une
    /// boucle dédiée pour s'abonner aux événements).
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
        self.write_packet(&body).await?;

        loop {
            let packet = self.read_packet().await?;
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

    async fn write_packet(&mut self, body: &[u8]) -> Result<()> {
        let len = u32::try_from(body.len())
            .map_err(|_| HeliosError::Vici("paquet trop grand".into()))?;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(body).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        self.stream.read_exact(&mut body).await?;
        Ok(body)
    }
}
