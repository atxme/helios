//! Encrypted, authenticated installation registry (ADR-006 §2).
//!
//! # What it is for
//!
//! The registry answers "which profiles exist, and what public keys should each
//! one hold". It is the **authenticated** source those expectations come from.
//!
//! That indirection is the whole point. A profile blob carries its own object
//! context, so it cannot be opened as another profile's — but if the expected
//! keys were read from an unauthenticated record sitting next to the blob, an
//! attacker could swap the pair *record + blob* wholesale and the check would
//! agree with itself. ADR-006 says it plainly: a context is never validated
//! against a value coming from the same unauthenticated record. So the
//! expectations live here, sealed under the installation root.
//!
//! # What it deliberately does not hold
//!
//! No private key, no PSK. Those live in the profile manifests. Losing the
//! registry costs the profile list and the selection, not the secrets — and a
//! registry that carried secrets would make one blob the single point whose
//! compromise hands over everything.
//!
//! # Freshness
//!
//! Each entry carries the `security_generation` of its manifest. Opening a
//! manifest whose generation is **below** what the registry recorded means an
//! older blob was put back — refused. Restoring registry *and* blobs together
//! is the full offline rollback ADR-006 declares unsolved; nothing here claims
//! to catch it.

use super::{codec, ProfileId, SecurityGeneration, VaultError};

/// Registry encoding version. Any other value is refused, never guessed.
///
/// Raised to 2 when `security_digest` entered the entry. Version 1 is refused
/// rather than read with a zero digest: a zero would mean "no security state
/// ever observed", which would let the first save after an update look like a
/// change and raise every generation — or, worse, look like no change when one
/// had happened.
const REGISTRY_VERSION: u8 = 2;

/// Bound on a decoded registry, checked before allocation.
pub const MAX_REGISTRY_BYTES: usize = 256 * 1024;

/// What the installation knows about one profile, without its secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    pub id: ProfileId,
    /// Display name. Also inside the manifest, and the two must agree — the
    /// copy here is what lets the list be shown without opening every blob.
    pub name: String,
    /// Public key the manifest's private key must derive to.
    pub client_public_key: String,
    /// Gateway public key this profile speaks to.
    pub gateway_public_key: String,
    /// Highest generation ever observed for this profile.
    pub generation: SecurityGeneration,
    /// Digest of the profile's security-relevant state, as
    /// [`crate::vault::ProfileManifest::security_digest`] computes it.
    ///
    /// Kept here so a change of PSK, of trust anchor or of floor can be
    /// **detected** across sessions and raise the generation. Without it the
    /// counter only ever moved on a WireGuard key rotation, and the three
    /// other triggers ADR-006 §2 names went unwitnessed. It is a hash, so the
    /// registry still holds no secret.
    pub security_digest: [u8; 32],
    /// The profile came from a plaintext file and its key is presumed
    /// compromised. It stays unconnectable until a new key is admitted
    /// (ADR-006 §3, migration).
    pub rotation_required: bool,
}

/// The installation's profile table.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Registry {
    pub entries: Vec<RegistryEntry>,
    pub selected: Option<ProfileId>,
}

impl Registry {
    pub fn find_by_name(&self, name: &str) -> Option<&RegistryEntry> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    pub fn find(&self, id: ProfileId) -> Option<&RegistryEntry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    /// Inserts or replaces an entry, keyed by identifier.
    ///
    /// The generation only ever goes **up**: accepting a lower one would let a
    /// restored blob present itself as current, which is the in-process half of
    /// the replay defence.
    pub fn upsert(&mut self, entry: RegistryEntry) -> Result<(), VaultError> {
        if let Some(existing) = self.entries.iter_mut().find(|slot| slot.id == entry.id) {
            if entry.generation < existing.generation {
                return Err(VaultError::GenerationWentBackwards {
                    observed: existing.generation.0,
                    offered: entry.generation.0,
                });
            }
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
        Ok(())
    }

    pub fn remove(&mut self, id: ProfileId) {
        self.entries.retain(|entry| entry.id != id);
        if self.selected == Some(id) {
            self.selected = None;
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, VaultError> {
        let mut out = Vec::with_capacity(512);
        out.push(REGISTRY_VERSION);
        let count = u16::try_from(self.entries.len())
            .map_err(|_| VaultError::ManifestEncoding("too many profiles".into()))?;
        out.extend_from_slice(&count.to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(entry.id.as_bytes());
            codec::put(&mut out, entry.name.as_bytes())?;
            codec::put(&mut out, entry.client_public_key.as_bytes())?;
            codec::put(&mut out, entry.gateway_public_key.as_bytes())?;
            out.extend_from_slice(&entry.generation.0.to_be_bytes());
            out.extend_from_slice(&entry.security_digest);
            out.push(u8::from(entry.rotation_required));
        }
        match self.selected {
            None => out.push(0),
            Some(id) => {
                out.push(1);
                out.extend_from_slice(id.as_bytes());
            }
        }
        if out.len() > MAX_REGISTRY_BYTES {
            return Err(VaultError::ManifestTooLarge(out.len()));
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(VaultError::ManifestTooLarge(bytes.len()));
        }
        let mut cursor = codec::Cursor::new(bytes);
        let version = cursor.byte()?;
        if version != REGISTRY_VERSION {
            return Err(VaultError::UnsupportedManifest(version));
        }
        let count = u16::from_be_bytes(cursor.array::<2>()?) as usize;
        let mut entries = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            entries.push(RegistryEntry {
                id: ProfileId::from_bytes(cursor.array::<16>()?),
                name: cursor.text()?,
                client_public_key: cursor.text()?,
                gateway_public_key: cursor.text()?,
                generation: SecurityGeneration(u64::from_be_bytes(cursor.array::<8>()?)),
                security_digest: cursor.array::<32>()?,
                rotation_required: match cursor.byte()? {
                    0 => false,
                    1 => true,
                    other => {
                        return Err(VaultError::ManifestEncoding(format!(
                            "invalid rotation flag {other}"
                        )))
                    }
                },
            });
        }
        let selected = match cursor.byte()? {
            0 => None,
            1 => Some(ProfileId::from_bytes(cursor.array::<16>()?)),
            other => {
                return Err(VaultError::ManifestEncoding(format!(
                    "invalid selection byte {other}"
                )))
            }
        };
        cursor.expect_end()?;
        Ok(Self { entries, selected })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, id: u8, generation: u64) -> RegistryEntry {
        RegistryEntry {
            id: ProfileId::from_bytes([id; 16]),
            name: name.into(),
            client_public_key: format!("client-{name}"),
            gateway_public_key: format!("gateway-{name}"),
            generation: SecurityGeneration(generation),
            security_digest: [id; 32],
            rotation_required: false,
        }
    }

    #[test]
    fn a_registry_round_trips() {
        let mut registry = Registry::default();
        registry.upsert(entry("poste", 1, 3)).unwrap();
        registry.upsert(entry("portable", 2, 1)).unwrap();
        registry.selected = Some(ProfileId::from_bytes([2; 16]));

        let decoded = Registry::decode(&registry.encode().unwrap()).unwrap();
        assert_eq!(decoded, registry);
        assert_eq!(decoded.find_by_name("poste").unwrap().generation.0, 3);
    }

    #[test]
    fn an_empty_registry_round_trips() {
        let decoded = Registry::decode(&Registry::default().encode().unwrap()).unwrap();
        assert!(decoded.entries.is_empty());
        assert!(decoded.selected.is_none());
    }

    /// The in-process half of the replay defence.
    #[test]
    fn a_generation_never_goes_backwards() {
        let mut registry = Registry::default();
        registry.upsert(entry("poste", 1, 5)).unwrap();
        let error = registry.upsert(entry("poste", 1, 4)).unwrap_err();
        assert!(
            matches!(error, VaultError::GenerationWentBackwards { .. }),
            "obtained: {error}"
        );
        // The stored entry is untouched by the refused update.
        assert_eq!(registry.find_by_name("poste").unwrap().generation.0, 5);
        // Equal is accepted: rewriting a profile without a security change
        // must not be blocked.
        registry.upsert(entry("poste", 1, 5)).unwrap();
        registry.upsert(entry("poste", 1, 6)).unwrap();
        assert_eq!(registry.find_by_name("poste").unwrap().generation.0, 6);
    }

    #[test]
    fn removing_a_profile_clears_a_stale_selection() {
        let mut registry = Registry::default();
        registry.upsert(entry("poste", 1, 1)).unwrap();
        registry.selected = Some(ProfileId::from_bytes([1; 16]));
        registry.remove(ProfileId::from_bytes([1; 16]));
        assert!(registry.entries.is_empty());
        assert!(
            registry.selected.is_none(),
            "a selection pointing at a deleted profile would be reported as connectable"
        );
    }

    #[test]
    fn the_rotation_flag_survives_the_round_trip() {
        let mut registry = Registry::default();
        let mut migrated = entry("historique", 9, 1);
        migrated.rotation_required = true;
        registry.upsert(migrated).unwrap();
        let decoded = Registry::decode(&registry.encode().unwrap()).unwrap();
        assert!(
            decoded
                .find_by_name("historique")
                .unwrap()
                .rotation_required,
            "losing the flag would silently make a compromised profile connectable"
        );
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let mut encoded = Registry::default().encode().unwrap();
        encoded[0] = 42;
        assert!(matches!(
            Registry::decode(&encoded),
            Err(VaultError::UnsupportedManifest(42))
        ));
    }

    #[test]
    fn a_lying_entry_count_is_refused_without_panicking() {
        let mut encoded = Registry::default().encode().unwrap();
        encoded[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(Registry::decode(&encoded).is_err());
    }

    #[test]
    fn every_truncation_is_refused_without_panicking() {
        let mut registry = Registry::default();
        registry.upsert(entry("poste", 1, 1)).unwrap();
        registry.selected = Some(ProfileId::from_bytes([1; 16]));
        let encoded = registry.encode().unwrap();
        for cut in 0..encoded.len() {
            assert!(
                Registry::decode(&encoded[..cut]).is_err(),
                "a truncated registry decoded at {cut}"
            );
        }
    }
}
