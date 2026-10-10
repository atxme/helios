//! Explicit JSON encoding at secret persistence and exchange boundaries.
//!
//! Secret types never implement `Serialize`. Public fields may use serde,
//! while secret strings are escaped directly into a fixed-capacity, zeroizing
//! buffer. The buffer never reallocates after it has received a secret.

use std::io::{self, Write};

use serde::Serialize;
use zeroize::Zeroizing;

use super::SecretString;

#[derive(Debug, thiserror::Error)]
pub enum SecretJsonError {
    #[error("secret JSON document exceeds its {0}-byte limit")]
    TooLarge(usize),
    #[error("encoding public JSON fields: {0}")]
    PublicEncoding(#[from] serde_json::Error),
    #[error("secret JSON document is not UTF-8")]
    InvalidUtf8,
}

/// An explicit encoder, deliberately neither `Debug`, `Clone` nor `Serialize`.
pub struct SecretJson {
    buffer: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl SecretJson {
    pub fn new(limit: usize) -> Self {
        Self {
            buffer: Zeroizing::new(Vec::with_capacity(limit)),
            limit,
        }
    }

    /// Appends a trusted JSON delimiter or an already encoded document.
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), SecretJsonError> {
        if bytes.len() > self.limit - self.buffer.len() {
            return Err(SecretJsonError::TooLarge(self.limit));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    /// Encodes public values only. Secret types cannot satisfy this bound.
    pub fn public<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), SecretJsonError> {
        serde_json::to_writer(self, value)?;
        Ok(())
    }

    /// Encodes a runtime secret through an explicit exposure point.
    pub fn secret(&mut self, value: &SecretString) -> Result<(), SecretJsonError> {
        self.secret_str(value.expose())
    }

    /// Encodes secret input already borrowed from an exchange boundary.
    pub fn secret_str(&mut self, value: &str) -> Result<(), SecretJsonError> {
        self.append(b"\"")?;
        for &byte in value.as_bytes() {
            match byte {
                b'"' => self.append(b"\\\"")?,
                b'\\' => self.append(b"\\\\")?,
                0..=0x1f => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    self.append(&[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        HEX[(byte >> 4) as usize],
                        HEX[(byte & 15) as usize],
                    ])?;
                }
                _ => self.append(&[byte])?,
            }
        }
        self.append(b"\"")
    }

    pub fn finish(self) -> Zeroizing<Vec<u8>> {
        self.buffer
    }

    pub fn finish_string(self) -> Result<Zeroizing<String>, SecretJsonError> {
        let mut bytes = self.finish();
        match String::from_utf8(std::mem::take(&mut *bytes)) {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(error) => {
                let _bytes = Zeroizing::new(error.into_bytes());
                Err(SecretJsonError::InvalidUtf8)
            }
        }
    }
}

impl Write for SecretJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.append(bytes).map_err(io::Error::other)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_strings_round_trip_with_json_metacharacters_and_unicode() {
        let secret = SecretString::new("key\"\\\n\0\té中");
        let mut encoded = SecretJson::new(128);
        encoded.append(b"{\"secret\":").unwrap();
        encoded.secret(&secret).unwrap();
        encoded.append(b"}").unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&encoded.finish()).unwrap();
        assert_eq!(decoded["secret"], secret.expose());
    }

    #[test]
    fn encoding_refuses_growth_for_both_public_and_secret_values() {
        let mut encoded = SecretJson::new(4);
        encoded.secret_str("ab").unwrap();
        assert!(matches!(
            encoded.append(b"x"),
            Err(SecretJsonError::TooLarge(4))
        ));
        assert_eq!(&*encoded.finish(), b"\"ab\"");
        assert!(SecretJson::new(3).secret_str("ab").is_err());
        assert!(SecretJson::new(3).public("ab").is_err());
    }

    #[test]
    fn invalid_utf8_cannot_be_returned_as_a_string() {
        let mut encoded = SecretJson::new(1);
        encoded.append(&[0xff]).unwrap();
        assert!(matches!(
            encoded.finish_string(),
            Err(SecretJsonError::InvalidUtf8)
        ));
    }
}
