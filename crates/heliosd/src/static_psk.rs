//! Table chiffrée des PSK statiques ([ADR-006](../../../docs/adr/ADR-006-SECRETS-AU-REPOS.md) §4).
//!
//! # Two kinds of PSK, one of which never reaches a disk
//!
//! A **negotiated** PSK is derived from ML-KEM on every connection and stays in
//! memory: nothing here concerns it. A **static** PSK is shared out of band,
//! never rotates, and has to survive a restart — so it must be persisted, and
//! `network.toml` is the one place it must never be.
//!
//! # Why the key comes from the WireGuard identity, not from the TPM secret
//!
//! Sealing this table under the general TPM secret would look natural and be
//! wrong: that secret is **regenerated** on some PCR changes, and the escrow
//! restores only the WireGuard identity. The table would then be permanently
//! unreadable while the gateway itself recovered fine — the worst shape of
//! failure, because everything else would appear to work.
//!
//! The key is therefore derived from the 32 bytes of the gateway's WireGuard
//! private key, with a fresh salt and `info = "helios/static-psk-map/v1"`. The
//! table survives a resealing **if and only if** the identity survives or is
//! restored, which is exactly the property an operator can reason about.
//!
//! This widens nothing: compromising the gateway identity already compromises
//! the authentication of every tunnel. The domain separation stops that key
//! from being usable anywhere else.
//!
//! # Binding to the peers it describes
//!
//! The object context carries the gateway's public key and a canonical
//! fingerprint of the peer table. A blob from another gateway therefore does
//! not open, and neither does one whose peer set has changed — the second is
//! the case that matters: a PSK must stay attached to the exact public key it
//! was agreed with, never slide onto a peer admitted later.

use std::collections::BTreeMap;

use aether::SecretString;
use helios_tpm::Context;
use zeroize::Zeroizing;

/// Vault domain of the table (ADR-006 §2).
const DOMAIN: &str = "helios.peer.static-psk-map";

/// HKDF label separating this derivation from every other use of the identity.
const INFO: &[u8] = b"helios/static-psk-map/v1";

/// Table encoding version. Any other value is refused, never guessed.
const TABLE_VERSION: u8 = 1;

/// Bound on a decoded table, checked before allocation.
const MAX_TABLE_BYTES: usize = 64 * 1024;

/// Longest single field.
const MAX_FIELD_BYTES: usize = 4 * 1024;

/// Where the table lives, beside the identity it is derived from.
const TABLE_PATH: &str = "/var/lib/helios/static-psk.hvlt";

/// Production location, overridable by `HELIOS_IDENTITY_DIR` like the other
/// identity files, so a test can exercise the real paths.
pub fn default_path() -> std::path::PathBuf {
    match std::env::var_os("HELIOS_IDENTITY_DIR") {
        Some(directory) => std::path::Path::new(&directory).join("static-psk.hvlt"),
        None => std::path::PathBuf::from(TABLE_PATH),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StaticPskError {
    #[error("identité WireGuard de la gateway inutilisable : {0}")]
    Identity(String),
    #[error("table des PSK statiques illisible : {0}")]
    Encoding(String),
    #[error(
        "table des PSK statiques indéchiffrable sous l'identité courante — l'identité a changé \
         sans que la table soit ré-enveloppée. Les pairs concernés restent désactivés jusqu'à \
         rotation de leur PSK ; aucun démarrage sans PSK n'est autorisé"
    )]
    Undecipherable,
    #[error("{path} : {cause}")]
    Io { path: String, cause: String },
}

/// Peer public key → static PSK.
///
/// `BTreeMap` rather than `HashMap`: the fingerprint below must be canonical,
/// and an iteration order that depends on hashing would make it differ between
/// two runs holding the same peers.
#[derive(Default)]
pub struct StaticPskMap(BTreeMap<String, SecretString>);

/// Prints how many peers, never a PSK.
///
/// A derived `Debug` would put every static secret into the first log line
/// that formats the map — the leak ADR-006 §5 puts on the **type** rather than
/// on discipline. The peer count is not a secret: `network.toml` lists the
/// peers in the clear.
impl std::fmt::Debug for StaticPskMap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StaticPskMap")
            .field("peers", &self.0.len())
            .field("psks", &"***")
            .finish()
    }
}

impl StaticPskMap {
    pub fn get(&self, public_key: &str) -> Option<&SecretString> {
        self.0.get(public_key)
    }

    pub fn insert(&mut self, public_key: impl Into<String>, psk: SecretString) {
        self.0.insert(public_key.into(), psk);
    }

    pub fn remove(&mut self, public_key: &str) -> bool {
        self.0.remove(public_key).is_some()
    }

    pub fn peers(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Canonical fingerprint of the peer set — public keys only, never a PSK.
    ///
    /// It goes into the object context, so a table cannot be opened after its
    /// peer set has changed. Each key is length-prefixed: without that,
    /// `["ab", "c"]` and `["a", "bc"]` would hash identically and two different
    /// peer sets would share a context.
    fn fingerprint(&self) -> [u8; 32] {
        let mut input = Vec::new();
        for public_key in self.0.keys() {
            input.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
            input.extend_from_slice(public_key.as_bytes());
        }
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &input);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, StaticPskError> {
        let mut out = Zeroizing::new(Vec::with_capacity(256));
        out.push(TABLE_VERSION);
        let count = u16::try_from(self.0.len())
            .map_err(|_| StaticPskError::Encoding("trop de pairs".into()))?;
        out.extend_from_slice(&count.to_be_bytes());
        for (public_key, psk) in &self.0 {
            put(&mut out, public_key.as_bytes())?;
            put(&mut out, psk.expose().as_bytes())?;
        }
        if out.len() > MAX_TABLE_BYTES {
            return Err(StaticPskError::Encoding(format!(
                "table de {} octets au-delà de la borne",
                out.len()
            )));
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StaticPskError> {
        if bytes.len() > MAX_TABLE_BYTES {
            return Err(StaticPskError::Encoding("table au-delà de la borne".into()));
        }
        let mut at = 0usize;
        let mut take = |count: usize| -> Result<&[u8], StaticPskError> {
            let end = at
                .checked_add(count)
                .ok_or_else(|| StaticPskError::Encoding("débordement de longueur".into()))?;
            if end > bytes.len() {
                return Err(StaticPskError::Encoding(format!(
                    "table tronquée : {count} octets attendus à l'offset {at}"
                )));
            }
            let slice = &bytes[at..end];
            at = end;
            Ok(slice)
        };

        if take(1)?[0] != TABLE_VERSION {
            return Err(StaticPskError::Encoding("version inconnue".into()));
        }
        let count = u16::from_be_bytes(
            take(2)?
                .try_into()
                .map_err(|_| StaticPskError::Encoding("compteur illisible".into()))?,
        ) as usize;

        let mut map = BTreeMap::new();
        for _ in 0..count {
            let public_key = text(&mut take)?;
            let psk = text(&mut take)?;
            map.insert(public_key, SecretString::new(psk));
        }
        if at != bytes.len() {
            return Err(StaticPskError::Encoding("octets excédentaires".into()));
        }
        Ok(Self(map))
    }
}

fn put(out: &mut Vec<u8>, value: &[u8]) -> Result<(), StaticPskError> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(StaticPskError::Encoding("champ trop long".into()));
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn text<'a>(
    take: &mut impl FnMut(usize) -> Result<&'a [u8], StaticPskError>,
) -> Result<String, StaticPskError> {
    let length = u32::from_be_bytes(
        take(4)?
            .try_into()
            .map_err(|_| StaticPskError::Encoding("longueur illisible".into()))?,
    ) as usize;
    if length > MAX_FIELD_BYTES {
        return Err(StaticPskError::Encoding("champ déclaré trop long".into()));
    }
    String::from_utf8(take(length)?.to_vec())
        .map_err(|_| StaticPskError::Encoding("champ non UTF-8".into()))
}

/// Input keying material: the raw 32 bytes of the gateway's private key.
///
/// Decoded from base64 rather than hashed from the text form, so the
/// derivation is bound to the key itself and not to one of its encodings.
fn identity_material(gateway_private_key: &str) -> Result<Zeroizing<Vec<u8>>, StaticPskError> {
    use base64::Engine as _;

    let raw = base64::engine::general_purpose::STANDARD
        .decode(gateway_private_key.trim())
        .map_err(|e| StaticPskError::Identity(format!("base64 illisible : {e}")))?;
    if raw.len() != 32 {
        return Err(StaticPskError::Identity(format!(
            "{} octets au lieu de 32",
            raw.len()
        )));
    }
    Ok(Zeroizing::new(raw))
}

fn context_for(gateway_private_key: &str, map: &StaticPskMap) -> Result<Context, StaticPskError> {
    let public = aether::wg::public_from_private(gateway_private_key)
        .map_err(|e| StaticPskError::Identity(format!("clé publique indérivable : {e}")))?;
    Ok(Context::new()
        .field("gateway_public_key", public.as_bytes())
        .field("peer_table", &map.fingerprint()))
}

/// Seals the table under the gateway identity.
pub fn store(
    path: &std::path::Path,
    gateway_private_key: &str,
    map: &StaticPskMap,
) -> Result<(), StaticPskError> {
    let ikm = identity_material(gateway_private_key)?;
    let context = context_for(gateway_private_key, map)?;
    let blob = helios_vault::seal(
        DOMAIN,
        &context,
        &helios_vault::Unlock::Derived {
            ikm: &ikm,
            info: INFO,
        },
        &map.encode()?,
    )
    .map_err(|e| StaticPskError::Encoding(e.to_string()))?;

    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent).map_err(|e| StaticPskError::Io {
            path: parent.display().to_string(),
            cause: e.to_string(),
        })?;
    }
    aether::private_file::write_private_atomic(path, &blob).map_err(|e| StaticPskError::Io {
        path: path.display().to_string(),
        cause: e.to_string(),
    })
}

/// Opens the table sealed under the gateway identity.
///
/// An absent file is an empty table, not an error: a gateway with no static
/// peer has nothing to store, and treating that as a failure would block
/// startup on a perfectly ordinary configuration.
pub fn load(
    path: &std::path::Path,
    gateway_private_key: &str,
) -> Result<StaticPskMap, StaticPskError> {
    if !path.exists() {
        return Ok(StaticPskMap::default());
    }
    let ikm = identity_material(gateway_private_key)?;
    // Bounded on the metadata **before** the allocation, not after: ADR-006 §2
    // is explicit that a `std::fs::read` followed by a length check is not the
    // rule being asked for. The table is read at every start, from a path a
    // local attacker can replace with a sparse file.
    let blob = helios_vault::read_file_bounded(path).map_err(|e| StaticPskError::Io {
        path: path.display().to_string(),
        cause: e.to_string(),
    })?;

    // The context carries the peer-set fingerprint, which cannot be known
    // before decoding. It is read from the blob and handed straight back, so
    // the AEAD is what authenticates it — then checked against what the
    // decoded table actually contains.
    let declared =
        helios_vault::peek_context(&blob).map_err(|e| StaticPskError::Encoding(e.to_string()))?;
    let plaintext = helios_vault::open(
        DOMAIN,
        &Context::from_encoded(declared.clone()),
        &helios_vault::Unlock::Derived {
            ikm: &ikm,
            info: INFO,
        },
        &blob,
    )
    .map_err(|error| match error {
        helios_vault::VaultError::Undecipherable => StaticPskError::Undecipherable,
        other => StaticPskError::Encoding(other.to_string()),
    })?;

    let map = StaticPskMap::decode(&plaintext)?;
    // Recomputed from the decoded table: a context that decrypts but describes
    // another peer set would mean a PSK slid onto a peer it was never agreed
    // with.
    if context_for(gateway_private_key, &map)?.as_bytes() != declared {
        return Err(StaticPskError::Encoding(
            "le contexte ne décrit pas la table qu'il scelle".into(),
        ));
    }
    Ok(map)
}

/// Re-wraps the table from the old identity onto the new one.
///
/// Verifies the result **before** returning, because the caller publishes the
/// new public key on success: a table that turned out unreadable afterwards
/// would leave every static peer unable to handshake, with the old identity
/// already gone.
pub fn rotate(
    path: &std::path::Path,
    old_private_key: &str,
    new_private_key: &str,
) -> Result<usize, StaticPskError> {
    let map = load(path, old_private_key)?;
    if map.is_empty() {
        // Nothing to carry over. Re-sealing an empty table would still be
        // correct, but writing a file where there was none is a surprise.
        return Ok(0);
    }
    store(path, new_private_key, &map)?;

    let reopened = load(path, new_private_key)?;
    if reopened.len() != map.len() || reopened.peers().ne(map.peers()) {
        return Err(StaticPskError::Encoding(
            "la table ré-enveloppée ne correspond pas à l'ancienne".into(),
        ));
    }
    for peer in map.peers() {
        let (Some(before), Some(after)) = (map.get(peer), reopened.get(peer)) else {
            return Err(StaticPskError::Encoding("pair perdu à la rotation".into()));
        };
        if before != after {
            return Err(StaticPskError::Encoding("PSK altéré à la rotation".into()));
        }
    }
    Ok(map.len())
}

/// Moves any plaintext static PSK out of `network.toml` and into the table,
/// then fills the running config back from it.
///
/// Called once at startup. It is the bridge ADR-006 §4 requires: the file must
/// never carry a PSK, but the data plane still needs one in memory, so the
/// value moves rather than disappears.
///
/// Idempotent. A second call finds nothing to adopt and simply refills the
/// config from the table, which is what every restart after the first does.
///
/// Returns how many PSKs were adopted from the file — a number worth logging,
/// because it is non-zero exactly once per gateway.
pub fn adopt_from_config(
    network: &mut aether::NetworkConfig,
    path: &std::path::Path,
    gateway_private_key: &str,
) -> Result<usize, StaticPskError> {
    let mut map = load(path, gateway_private_key)?;
    let mut adopted = 0usize;

    for peer in &mut network.peers {
        match peer.preshared_key.take() {
            Some(psk) if !psk.trim().is_empty() => {
                // The file wins over the table: an operator who edited
                // `network.toml` by hand meant that value, and silently
                // keeping the old one would make the edit look ignored.
                map.insert(peer.public_key.clone(), SecretString::new(psk));
                adopted += 1;
            }
            _ => {}
        }
    }
    if adopted > 0 {
        // Sealed table first, file second. The reverse order has a window in
        // which the PSK exists nowhere: a crash between the two would lose it
        // for good, and a static PSK has no recovery channel.
        store(path, gateway_private_key, &map)?;
        strip_from_file()?;
    }

    // Refill the running config: the data plane reads it, and a peer left
    // without its PSK would fail every handshake with no channel to recover.
    for peer in &mut network.peers {
        if let Some(psk) = map.get(&peer.public_key) {
            peer.preshared_key = Some(psk.expose().to_string());
        }
    }
    Ok(adopted)
}

/// Removes every `preshared_key` from `network.toml`, and nothing else.
///
/// ADR-006 §4 says the file never carries a static PSK. Warning the operator
/// to delete it by hand left the secret on disk for as long as nobody read the
/// log — which is to say, indefinitely.
///
/// It re-reads the file rather than persisting the running configuration, and
/// that is the whole care of this function. By the time it is called the
/// in-memory config holds the **unsealed** gateway private key, which
/// `gateway_key::resolve` put there; saving it would write that key back in the
/// clear. Re-reading touches one field and leaves `wg_private_key` exactly as
/// the file holds it — including the legacy plaintext case, where erasing it
/// would take the gateway's identity away.
fn strip_from_file() -> Result<(), StaticPskError> {
    let path = aether::NetworkConfig::path();
    if !path.exists() {
        // Nothing on disk to redact: a gateway configured entirely through the
        // API has no file yet, and creating one here would be a surprise.
        return Ok(());
    }
    let mut on_disk = aether::NetworkConfig::load().map_err(|e| StaticPskError::Io {
        path: path.display().to_string(),
        cause: e.to_string(),
    })?;
    if on_disk
        .peers
        .iter()
        .all(|peer| peer.preshared_key.is_none())
    {
        return Ok(());
    }
    for peer in &mut on_disk.peers {
        peer.preshared_key = None;
    }
    on_disk
        .save_preserving_legacy_identity()
        .map_err(|e| StaticPskError::Io {
            path: path.display().to_string(),
            cause: e.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> String {
        aether::wg::generate_keypair()
            .expect("keypair")
            .private_key
            .expose()
            .to_string()
    }

    fn peer() -> String {
        aether::wg::generate_keypair().expect("keypair").public_key
    }

    fn dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "helios-psk-map-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test directory");
        dir
    }

    /// Serialises the tests that drive `HELIOS_NETWORK_CONFIG`.
    ///
    /// The variable is process-wide, so two tests setting it would point each
    /// other's redaction at the wrong file — and a test that left it unset
    /// would aim `strip_from_file` at the real `/var/lib/helios/network.toml`.
    static NETWORK_CONFIG_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Points `network.toml` inside `dir` for the duration of a test.
    fn with_network_config<T>(dir: &std::path::Path, body: impl FnOnce() -> T) -> T {
        let _guard = NETWORK_CONFIG_ENV.lock().unwrap_or_else(|e| e.into_inner());
        let path = dir.join("network.toml");
        std::env::set_var("HELIOS_NETWORK_CONFIG", &path);
        let outcome = body();
        std::env::remove_var("HELIOS_NETWORK_CONFIG");
        outcome
    }

    fn table(peers: &[(&str, &str)]) -> StaticPskMap {
        let mut map = StaticPskMap::default();
        for (public_key, psk) in peers {
            map.insert(*public_key, SecretString::new(*psk));
        }
        map
    }

    #[test]
    fn a_table_round_trips_through_the_vault() {
        let dir = dir("roundtrip");
        let path = dir.join("static-psk.hvlt");
        let gateway = identity();
        let alice = peer();
        let map = table(&[(alice.as_str(), "cHNrLWFsaWNl")]);

        store(&path, &gateway, &map).expect("store");
        let loaded = load(&path, &gateway).expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&alice).expect("psk").expose(), "cHNrLWFsaWNl");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The property the whole module exists for.
    #[test]
    fn no_psk_reaches_the_file_in_the_clear() {
        let dir = dir("no-secret");
        let path = dir.join("static-psk.hvlt");
        let gateway = identity();
        let secret = "MOTIF-PSK-STATIQUE-A-NE-JAMAIS-ECRIRE";
        store(&path, &gateway, &table(&[(peer().as_str(), secret)])).expect("store");

        let bytes = std::fs::read(&path).expect("read");
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "the PSK is readable in the sealed table"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_file_is_an_empty_table_not_an_error() {
        let dir = dir("absent");
        let loaded = load(&dir.join("nowhere.hvlt"), &identity()).expect("load");
        assert!(loaded.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The table lives and dies with the gateway identity: that is the whole
    /// reason its key is derived from it rather than from the TPM secret.
    #[test]
    fn another_identity_cannot_open_the_table() {
        let dir = dir("foreign");
        let path = dir.join("static-psk.hvlt");
        store(&path, &identity(), &table(&[(peer().as_str(), "cHNr")])).expect("store");

        let error = load(&path, &identity()).expect_err("another identity must not open it");
        assert!(
            matches!(error, StaticPskError::Undecipherable),
            "obtained: {error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A PSK must stay attached to the exact public key it was agreed with.
    #[test]
    fn the_context_is_bound_to_the_peer_set() {
        let alice = peer();
        let bob = peer();
        let gateway = identity();
        let one = context_for(&gateway, &table(&[(alice.as_str(), "a")])).expect("context");
        let two = context_for(
            &gateway,
            &table(&[(alice.as_str(), "a"), (bob.as_str(), "b")]),
        )
        .expect("context");
        assert_ne!(
            one.as_bytes(),
            two.as_bytes(),
            "adding a peer must change the context"
        );
    }

    /// Length prefixing in the fingerprint: without it, two different peer
    /// sets would hash identically and share a context.
    #[test]
    fn the_fingerprint_cannot_be_confused_by_concatenation() {
        assert_ne!(
            table(&[("ab", "x"), ("c", "y")]).fingerprint(),
            table(&[("a", "x"), ("bc", "y")]).fingerprint()
        );
    }

    #[test]
    fn the_fingerprint_does_not_depend_on_insertion_order() {
        let alice = peer();
        let bob = peer();
        assert_eq!(
            table(&[(alice.as_str(), "a"), (bob.as_str(), "b")]).fingerprint(),
            table(&[(bob.as_str(), "b"), (alice.as_str(), "a")]).fingerprint()
        );
    }

    /// Rotation must verify before the caller publishes the new public key.
    #[test]
    fn a_rotation_carries_every_psk_onto_the_new_identity() {
        let dir = dir("rotate");
        let path = dir.join("static-psk.hvlt");
        let old = identity();
        let new = identity();
        let alice = peer();
        let bob = peer();
        store(
            &path,
            &old,
            &table(&[(alice.as_str(), "cHNrLWE="), (bob.as_str(), "cHNrLWI=")]),
        )
        .expect("store");

        assert_eq!(rotate(&path, &old, &new).expect("rotate"), 2);
        let loaded = load(&path, &new).expect("load under the new identity");
        assert_eq!(loaded.get(&alice).expect("alice").expose(), "cHNrLWE=");
        assert_eq!(loaded.get(&bob).expect("bob").expose(), "cHNrLWI=");
        // And the old identity no longer opens it.
        assert!(load(&path, &old).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unrecoverable old identity must fail loudly: ADR-006 §4 forbids
    /// starting without the PSK or falling back to classic mode.
    #[test]
    fn a_rotation_from_an_unopenable_identity_fails_rather_than_emptying_the_table() {
        let dir = dir("rotate-lost");
        let path = dir.join("static-psk.hvlt");
        store(&path, &identity(), &table(&[(peer().as_str(), "cHNr")])).expect("store");

        let error = rotate(&path, &identity(), &identity())
            .expect_err("an unopenable identity must not silently produce an empty table");
        assert!(
            matches!(error, StaticPskError::Undecipherable),
            "obtained: {error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rotation_with_nothing_to_carry_writes_nothing() {
        let dir = dir("rotate-empty");
        let path = dir.join("static-psk.hvlt");
        assert_eq!(rotate(&path, &identity(), &identity()).expect("rotate"), 0);
        assert!(!path.exists(), "an empty rotation must not create a file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unusable_identity_is_named_rather_than_guessed() {
        let dir = dir("bad-identity");
        let path = dir.join("static-psk.hvlt");
        let error = store(&path, "pas-du-base64", &StaticPskMap::default()).expect_err("must fail");
        assert!(matches!(error, StaticPskError::Identity(_)), "{error}");

        let short = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1u8; 8]);
        let error = store(&path, &short, &StaticPskMap::default()).expect_err("must fail");
        assert!(matches!(error, StaticPskError::Identity(_)), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_encoding_round_trips_and_refuses_what_it_cannot_read() {
        let alice = peer();
        let map = table(&[(alice.as_str(), "cHNr")]);
        let encoded = map.encode().expect("encode");
        let decoded = StaticPskMap::decode(&encoded).expect("decode");
        assert_eq!(decoded.get(&alice).expect("psk").expose(), "cHNr");

        for cut in 0..encoded.len() {
            assert!(
                StaticPskMap::decode(&encoded[..cut]).is_err(),
                "a truncated table decoded at {cut}"
            );
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(StaticPskMap::decode(&trailing).is_err(), "trailing bytes");

        let mut wrong_version = encoded.to_vec();
        wrong_version[0] = 42;
        assert!(StaticPskMap::decode(&wrong_version).is_err());
    }

    #[test]
    fn a_lying_count_is_refused_without_panicking() {
        let mut encoded = table(&[(peer().as_str(), "cHNr")])
            .encode()
            .expect("encode")
            .to_vec();
        encoded[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(StaticPskMap::decode(&encoded).is_err());
    }

    /// The bridge: the file must stop carrying PSKs, and the data plane must
    /// keep having them.
    #[test]
    fn a_plaintext_psk_is_adopted_then_refilled() {
        let dir = dir("adopt");
        let path = dir.join("static-psk.hvlt");
        let gateway = identity();
        let alice = peer();

        let mut network = aether::NetworkConfig {
            peers: vec![aether::WgPeer {
                name: "alice".into(),
                public_key: alice.clone(),
                address: "100.64.1.2/32".into(),
                admin: false,
                preshared_key: Some("cHNrLWFsaWNl".into()),
                key_negotiation_certificate_sha256: None,
                key_negotiation_pq_certificate_sha256: None,
                minimum_key_negotiation_mode: Default::default(),
                persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
            }],
            ..aether::NetworkConfig::default()
        };

        assert_eq!(
            with_network_config(&dir, || adopt_from_config(&mut network, &path, &gateway))
                .expect("adopt"),
            1
        );
        // Back in the running config, so the data plane still works…
        assert_eq!(
            network.peers[0].preshared_key.as_deref(),
            Some("cHNrLWFsaWNl")
        );
        // …and in the sealed table.
        assert_eq!(
            load(&path, &gateway)
                .expect("load")
                .get(&alice)
                .expect("psk")
                .expose(),
            "cHNrLWFsaWNl"
        );

        // Idempotent: a restart adopts nothing and still refills.
        network.peers[0].preshared_key = None;
        assert_eq!(
            with_network_config(&dir, || adopt_from_config(&mut network, &path, &gateway))
                .expect("second adopt"),
            0
        );
        assert_eq!(
            network.peers[0].preshared_key.as_deref(),
            Some("cHNrLWFsaWNl")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A hand edit of `network.toml` must win: silently keeping the stored
    /// value would make the operator's change look ignored.
    #[test]
    fn a_hand_edited_psk_replaces_the_stored_one() {
        let dir = dir("adopt-edit");
        let path = dir.join("static-psk.hvlt");
        let gateway = identity();
        let alice = peer();
        store(&path, &gateway, &table(&[(alice.as_str(), "YW5jaWVu")])).expect("store");

        let mut network = aether::NetworkConfig {
            peers: vec![aether::WgPeer {
                name: "alice".into(),
                public_key: alice.clone(),
                address: "100.64.1.2/32".into(),
                admin: false,
                preshared_key: Some("bm91dmVhdQ==".into()),
                key_negotiation_certificate_sha256: None,
                key_negotiation_pq_certificate_sha256: None,
                minimum_key_negotiation_mode: Default::default(),
                persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
            }],
            ..aether::NetworkConfig::default()
        };
        with_network_config(&dir, || adopt_from_config(&mut network, &path, &gateway))
            .expect("adopt");
        assert_eq!(
            load(&path, &gateway)
                .expect("load")
                .get(&alice)
                .expect("psk")
                .expose(),
            "bm91dmVhdQ=="
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR-006 §4: `network.toml` never carries a static PSK.
    ///
    /// Warning the operator to delete it by hand left the secret on disk for
    /// as long as nobody read the log. The file is redacted in place — and
    /// **only** of its PSKs: `wg_private_key` is left exactly as the file holds
    /// it, because at this point the running config carries the *unsealed* key
    /// and persisting that would write the gateway identity in the clear.
    #[test]
    fn adopting_removes_the_psk_from_the_file_and_leaves_the_identity_alone() {
        let dir = dir("adopt-strip");
        let table_path = dir.join("static-psk.hvlt");
        let gateway = identity();
        let alice = peer();
        const LEGACY_IDENTITY: &str = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=";

        let on_disk = aether::NetworkConfig {
            wg_private_key: LEGACY_IDENTITY.into(),
            wg_address: "100.64.0.1/10".into(),
            peers: vec![aether::WgPeer {
                name: "alice".into(),
                public_key: alice.clone(),
                address: "100.64.1.2/32".into(),
                admin: false,
                preshared_key: Some("cHNrLXN0YXRpcXVlLWVuLWNsYWly".into()),
                key_negotiation_certificate_sha256: None,
                key_negotiation_pq_certificate_sha256: None,
                minimum_key_negotiation_mode: Default::default(),
                persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
            }],
            ..aether::NetworkConfig::default()
        };

        let network_path = dir.join("network.toml");
        with_network_config(&dir, || {
            let legacy = format!(
                "wg_private_key = \"{LEGACY_IDENTITY}\"\nwg_address = \"100.64.0.1/10\"\n\
                 [[peers]]\nname = \"alice\"\npublic_key = \"{alice}\"\n\
                 address = \"100.64.1.2/32\"\nadmin = false\n\
                 preshared_key = \"cHNrLXN0YXRpcXVlLWVuLWNsYWly\"\n"
            );
            std::fs::write(&network_path, legacy).expect("write the legacy file");
            // What the daemon holds by then: the identity already resolved from
            // the sealed vault, not the one the file carries.
            let mut running = aether::NetworkConfig {
                wg_private_key: "REMPLACEE-PAR-LE-COFFRE".into(),
                ..on_disk.clone()
            };
            assert_eq!(
                adopt_from_config(&mut running, &table_path, &gateway).expect("adopt"),
                1
            );
        });

        let raw = std::fs::read_to_string(&network_path).expect("reread");
        assert!(
            !raw.contains("cHNrLXN0YXRpcXVlLWVuLWNsYWly"),
            "le PSK statique est resté dans network.toml :\n{raw}"
        );
        assert!(
            !raw.contains("REMPLACEE-PAR-LE-COFFRE"),
            "la clé descellée a été persistée dans network.toml :\n{raw}"
        );
        assert!(
            raw.contains(LEGACY_IDENTITY),
            "l'expurgation a emporté l'identité que le fichier portait :\n{raw}"
        );

        // And the PSK is still readable where it now lives.
        assert_eq!(
            load(&table_path, &gateway)
                .expect("load")
                .get(&alice)
                .expect("psk")
                .expose(),
            "cHNrLXN0YXRpcXVlLWVuLWNsYWly"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_gateway_without_static_peers_adopts_nothing() {
        let dir = dir("adopt-none");
        let path = dir.join("static-psk.hvlt");
        let mut network = aether::NetworkConfig::default();
        assert_eq!(
            adopt_from_config(&mut network, &path, &identity()).expect("adopt"),
            0
        );
        assert!(!path.exists(), "nothing to store, nothing written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removing_a_peer_drops_its_psk() {
        let alice = peer();
        let mut map = table(&[(alice.as_str(), "cHNr")]);
        assert!(map.remove(&alice));
        assert!(!map.remove(&alice));
        assert!(map.is_empty());
    }

    /// The table is read at every start, from a path a local attacker can
    /// replace. A sparse file costs nothing to create and would cost the
    /// gateway its address space if the bound came after the read — which is
    /// precisely what ADR-006 §2 refuses.
    #[test]
    fn a_sparse_table_is_refused_without_being_read() {
        let dir = dir("sparse");
        let path = dir.join("static-psk.hvlt");
        let file = std::fs::File::create(&path).expect("create");
        file.set_len(2 * 1024 * 1024 * 1024).expect("set_len");
        drop(file);

        let error = load(&path, &identity()).expect_err("an oversized table must be refused");
        assert!(
            matches!(error, StaticPskError::Io { .. }),
            "obtenu : {error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
