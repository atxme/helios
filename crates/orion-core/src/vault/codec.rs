//! Shared binary encoding for the vault's contents (ADR-006 §5).
//!
//! Both the manifest and the registry are written with these primitives rather
//! than a serialiser. For the manifest the reason is hard: §5 forbids handing a
//! secret-bearing type to TOML or JSON, which build intermediate `String`s
//! nobody can wipe. For the registry — which holds no secret — the reason is
//! that two encodings in one vault is one too many: a reader auditing the
//! bounds of one would have to audit the other separately.
//!
//! The shape is deliberately dull: length-prefixed fields in a fixed order, no
//! names, nothing self-describing. Adding a field means a new version byte,
//! which an older binary refuses rather than misreads.

use super::VaultError;

/// Longest single field. Certificates are the largest, and they are far below.
pub const MAX_FIELD_BYTES: usize = 32 * 1024;

/// Appends a length-prefixed field.
pub fn put(out: &mut Vec<u8>, value: &[u8]) -> Result<(), VaultError> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(VaultError::ManifestEncoding(format!(
            "field of {} bytes exceeds {MAX_FIELD_BYTES}",
            value.len()
        )));
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// Appends an optional field, prefixed by its presence byte.
pub fn put_option(out: &mut Vec<u8>, value: Option<&[u8]>) -> Result<(), VaultError> {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            put(out, value)?;
        }
    }
    Ok(())
}

/// Bounds-checked reader.
///
/// Every read validates before indexing: this runs on whatever a decryption
/// returned, and a panic here would take the client down on a corrupted file.
pub struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8], VaultError> {
        let end = self
            .at
            .checked_add(count)
            .ok_or_else(|| VaultError::ManifestEncoding("length overflow".into()))?;
        if end > self.bytes.len() {
            return Err(VaultError::ManifestEncoding(format!(
                "truncated: {count} bytes wanted at offset {}",
                self.at
            )));
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    pub fn byte(&mut self) -> Result<u8, VaultError> {
        Ok(self.take(1)?[0])
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], VaultError> {
        let slice = self.take(N)?;
        slice
            .try_into()
            .map_err(|_| VaultError::ManifestEncoding("array read failed".into()))
    }

    pub fn text(&mut self) -> Result<String, VaultError> {
        let length = u32::from_be_bytes(self.array::<4>()?) as usize;
        if length > MAX_FIELD_BYTES {
            return Err(VaultError::ManifestEncoding(format!(
                "declared field of {length} bytes exceeds {MAX_FIELD_BYTES}"
            )));
        }
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| VaultError::ManifestEncoding("field is not valid UTF-8".into()))
    }

    pub fn option_text(&mut self) -> Result<Option<String>, VaultError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.text()?)),
            other => Err(VaultError::ManifestEncoding(format!(
                "invalid option byte {other}"
            ))),
        }
    }

    /// Refuses trailing bytes.
    ///
    /// Ignoring them is how an encoder and a decoder fork without anyone
    /// noticing, and how a field appended by an attacker rides along unread.
    pub fn expect_end(&self) -> Result<(), VaultError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(VaultError::ManifestEncoding(format!(
                "{} trailing bytes",
                self.bytes.len() - self.at
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_round_trips() {
        let mut out = Vec::new();
        put(&mut out, b"valeur").unwrap();
        put_option(&mut out, None).unwrap();
        put_option(&mut out, Some(b"present")).unwrap();

        let mut cursor = Cursor::new(&out);
        assert_eq!(cursor.text().unwrap(), "valeur");
        assert_eq!(cursor.option_text().unwrap(), None);
        assert_eq!(cursor.option_text().unwrap().as_deref(), Some("present"));
        cursor.expect_end().unwrap();
    }

    #[test]
    fn an_over_long_field_is_refused_at_write_time() {
        let mut out = Vec::new();
        assert!(put(&mut out, &vec![0u8; MAX_FIELD_BYTES + 1]).is_err());
    }

    #[test]
    fn a_lying_length_is_refused_without_allocating() {
        let mut out = Vec::new();
        out.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(Cursor::new(&out).text().is_err());
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut out = Vec::new();
        put(&mut out, b"x").unwrap();
        out.push(0);
        let mut cursor = Cursor::new(&out);
        cursor.text().unwrap();
        assert!(cursor.expect_end().is_err());
    }

    #[test]
    fn an_invalid_option_byte_is_refused() {
        let out = vec![7u8];
        assert!(Cursor::new(&out).option_text().is_err());
    }
}
