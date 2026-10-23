//! Text files that crossed a Windows machine on their way here.
//!
//! An Orion document, an invitation and a request are all JSON text, and all
//! of them can be re-saved on the way: PowerShell 5.1 `Out-File` writes UTF-16
//! with a byte-order mark, Notepad a UTF-8 one. Every reader decodes them
//! here, so a file accepted on one side is never refused on the other.

/// Why bytes are not a text document.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransitTextError {
    #[error("UTF-16 text with an odd number of bytes")]
    TruncatedUtf16,
    #[error("invalid UTF-16 text")]
    InvalidUtf16,
    #[error("invalid UTF-8 text")]
    InvalidUtf8,
}

/// Decodes UTF-8 with or without a byte-order mark, or UTF-16 with one.
pub fn decode_transit_text(bytes: &[u8]) -> Result<String, TransitTextError> {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => from_utf16(rest, true),
        [0xFE, 0xFF, rest @ ..] => from_utf16(rest, false),
        [0xEF, 0xBB, 0xBF, rest @ ..] => from_utf8(rest),
        _ => from_utf8(bytes),
    }
}

fn from_utf8(bytes: &[u8]) -> Result<String, TransitTextError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| TransitTextError::InvalidUtf8)
}

fn from_utf16(bytes: &[u8], little_endian: bool) -> Result<String, TransitTextError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(TransitTextError::TruncatedUtf16);
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes(*pair)
            } else {
                u16::from_be_bytes(*pair)
            }
        })
        .collect();
    String::from_utf16(&units).map_err(|_| TransitTextError::InvalidUtf16)
}
