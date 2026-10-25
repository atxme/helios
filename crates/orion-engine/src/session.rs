//! Authentication of the one client an engine accepts.
//!
//! The engine runs elevated; the UI that drives it does not. The engine hands
//! its UI a token at launch, and the first frame on the channel must present
//! it. A single attempt: the engine serves one client, so any refusal stops it.

use std::fmt;
use std::time::Duration;

use tokio::io::AsyncBufRead;
use zeroize::Zeroizing;

use crate::wire::{limits, read_frame, ClientFrame, WireError, PROTOCOL_VERSION};

/// Time the engine waits for the first frame before it gives up.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Session secret: 256 bits, hexadecimal. Its `Debug` never shows it.
pub struct SessionToken(Zeroizing<String>);

impl SessionToken {
    /// Draws 256 bits from the one entry point this repository draws randomness through.
    pub fn generate() -> Result<Self, String> {
        let bytes = aether::random::secret_bytes::<32>()
            .map_err(|error| format!("tirage du jeton de session : {error}"))?;
        Ok(Self(Zeroizing::new(
            bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        )))
    }

    /// Reads a token written by [`SessionToken::generate`]: 64 lowercase hexadecimal digits.
    /// The refusal never repeats the text it was given.
    pub fn parse(text: &str) -> Result<Self, String> {
        let well_formed = text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !well_formed {
            return Err("jeton de session illisible".to_owned());
        }
        Ok(Self(Zeroizing::new(text.to_owned())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(…)")
    }
}

/// Why the engine refuses its client. None of the variants carries the token.
pub enum SessionRefusal {
    /// No first frame before [`HELLO_TIMEOUT`].
    Timeout,
    /// The client speaks another protocol version.
    WrongVersion,
    /// The presented token is not the session's.
    WrongToken,
    /// The first frame is a request, not a presentation.
    NotAHello,
    /// The first frame cannot be read.
    Wire(WireError),
    /// The client disconnected before its first frame.
    Closed,
}

impl fmt::Debug for SessionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("Timeout"),
            Self::WrongVersion => f.write_str("WrongVersion"),
            Self::WrongToken => f.write_str("WrongToken"),
            Self::NotAHello => f.write_str("NotAHello"),
            Self::Wire(error) => write!(f, "Wire({error:?})"),
            Self::Closed => f.write_str("Closed"),
        }
    }
}

impl fmt::Display for SessionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("aucune présentation avant l'échéance"),
            Self::WrongVersion => f.write_str("version de protocole non reconnue"),
            Self::WrongToken => f.write_str("jeton de session refusé"),
            Self::NotAHello => f.write_str("la première trame n'est pas une présentation"),
            Self::Wire(_) => f.write_str("trame de présentation illisible"),
            Self::Closed => f.write_str("connexion fermée avant la présentation"),
        }
    }
}

/// Reads the first frame and checks it presents `expected`.
///
/// Version is checked before the token, so a refusal for a stale UI does not
/// depend on the secret.
pub async fn accept_hello<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    expected: &SessionToken,
) -> Result<(), SessionRefusal> {
    let frame = tokio::time::timeout(
        HELLO_TIMEOUT,
        read_frame::<_, ClientFrame>(reader, limits::HELLO_BYTES),
    )
    .await
    .map_err(|_| SessionRefusal::Timeout)?;
    let hello = match frame.map_err(SessionRefusal::Wire)? {
        None => return Err(SessionRefusal::Closed),
        Some(ClientFrame::Request { .. }) => return Err(SessionRefusal::NotAHello),
        Some(ClientFrame::Hello(hello)) => hello,
    };
    if hello.protocol_version != PROTOCOL_VERSION {
        return Err(SessionRefusal::WrongVersion);
    }
    if !same_secret(&hello.token, expected.as_str()) {
        return Err(SessionRefusal::WrongToken);
    }
    Ok(())
}

/// Compares two secrets without letting the timing say where they differ.
pub fn same_secret(candidate: &str, expected: &str) -> bool {
    let (candidate, expected) = (candidate.as_bytes(), expected.as_bytes());
    candidate.len() == expected.len()
        && candidate
            .iter()
            .zip(expected)
            .fold(0u8, |accumulator, (left, right)| {
                accumulator | (left ^ right)
            })
            == 0
}

#[cfg(test)]
mod tests;
