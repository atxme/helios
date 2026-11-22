//! Gateway's WireGuard private key: sealed loading and update.
//!
//! # Why the key no longer lives in `network.toml`
//!
//! `wg_private_key` is the gateway's **cryptographic identity**: it is what
//! authenticates every WireGuard handshake. In the clear on disk, a stolen
//! disk is enough to impersonate the gateway. It is therefore moved into a
//! vault encrypted by the secret sealed in the TPM ([`helios_tpm::keystore`]):
//! decrypting it requires a successful unseal, hence an intact boot chain
//! (PCR 0/4/7).
//!
//! # Which updates lose the key — and which do nothing
//!
//! Sealing is bound to **PCR 0/4/7**: firmware, boot chain, Secure Boot.
//! That is what decides, not "there was an OTA":
//!
//! | Update | PCR | Key |
//! |---|---|---|
//! | `heliosd` binary alone (userspace) | unchanged | **survives** |
//! | kernel / initrd | PCR 4 | lost |
//! | bootloader | PCR 4 | lost |
//! | UEFI firmware | PCR 0 | lost |
//! | Secure Boot keys | PCR 7 | lost |
//!
//! PCR 4 measures the boot chain, not the rootfs files: replacing
//! `/usr/bin/heliosd` does not move it. The "lost key" case is therefore
//! rarer than it appears — it only concerns OTAs that ship a kernel.
//!
//! # Recovery without SSH: escrow
//!
//! When the PCRs change, resealing generates a **new** secret and the vault
//! becomes undecipherable. [`helios_escrow`] covers this case: a copy of the
//! key, encrypted to the operator's public key (HESC v2, which also carries in
//! clear the anti-rollback counter and the gateway's public key), is written
//! on every sealing. The operator prepares a request offline, the publisher
//! signs it for the counter in force, and the operator assembles the recovery
//! file `/var/lib/helios/wg-key.recovery`, which is deposited out of band.
//! At startup, and only when the vault is undecipherable, the gateway checks
//! the publisher's authorization against the counter, spends the counter,
//! reseals the key, and erases the file. See [`helios_escrow::recovery`].
//!
//! Without escrow configured (`escrow_public_key` absent), the key is
//! permanently lost in this case and recovery becomes manual again.

use std::io::Read;
use std::path::PathBuf;

use aether::{NetworkConfig, SecretString};
use helios_escrow::recovery::{decode_recovery_frame, MAX_RECOVERY_FRAME};
use helios_tpm::{
    anti_rollback, wg_recovery, BootDecision, KeystoreError, SealedKeystore, TpmError, TpmSettings,
};
use tracing::{error, info, warn};
use zeroize::Zeroizing;

/// Location of the vault containing the WireGuard private key.
const KEYSTORE_PATH: &str = "/var/lib/helios/wg-key.sealed";

/// Directory holding the three identity files, overridable for tests.
///
/// Same pattern, and same reason, as `HELIOS_NETWORK_CONFIG`: the production
/// service keeps the system path when the variable is absent, and a test can
/// exercise the real write paths without touching `/var/lib/helios`. Without
/// it, everything that actually puts bytes on disk — the escrow, the atomic
/// write — is reachable only on a provisioned gateway.
fn path_of(default: &str, variable: &str) -> String {
    match std::env::var_os(variable) {
        Some(directory) => std::path::Path::new(&directory)
            .join(default.rsplit('/').next().unwrap_or(default))
            .to_string_lossy()
            .into_owned(),
        None => default.to_string(),
    }
}

/// Root under which the three identity files live.
const IDENTITY_DIR_ENV: &str = "HELIOS_IDENTITY_DIR";

fn keystore_path() -> String {
    path_of(KEYSTORE_PATH, IDENTITY_DIR_ENV)
}

fn escrow_path() -> String {
    path_of(ESCROW_PATH, IDENTITY_DIR_ENV)
}

fn recovery_path() -> String {
    path_of(RECOVERY_PATH, IDENTITY_DIR_ENV)
}

/// Escrow: copy of the key encrypted to the operator's public key.
///
/// Rewritten on every sealing. The operator retrieves it and keeps it; only
/// they can open it. The gateway itself is unable to — that is the point.
const ESCROW_PATH: &str = "/var/lib/helios/wg-key.escrow";

/// Recovery file, deposited by the operator out of band. It is **not**
/// delivered with the OTA bundle: the bundle carries no recovery material.
///
/// A frame of `helios_escrow::recovery`: the publisher's authorization, then
/// the WireGuard private key. Consumed **only once**, and only if the vault is
/// actually undecipherable and the authorization is valid for the current
/// anti-rollback counter; erased immediately after.
const RECOVERY_PATH: &str = "/var/lib/helios/wg-key.recovery";

/// Origin of the key actually in use — used to alert the operator.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    /// Loaded from the TPM vault. Nominal case.
    Sealed,
    /// Read in the clear from `network.toml`. **Degraded**: to be sealed as
    /// soon as possible.
    PlaintextConfig,
    /// Restored from escrow after a PCR change.
    Recovered,
    /// No usable key: the gateway cannot bring up its interface.
    Missing,
}

/// Key resolved at startup.
///
/// The key is a [`SecretString`] rather than a `String`: it is the gateway's
/// identity, this structure is what carries it out of the vault, and an
/// ordinary `String` here is a buffer nobody wipes and a field a future
/// `#[derive(Debug)]` would print (ADR-006 §5).
pub struct ResolvedKey {
    /// Private key in base64, ready for the data plane. Empty if `Missing`.
    pub private_key: SecretString,
    pub origin: KeyOrigin,
}

impl ResolvedKey {
    /// The one outcome with no key: named, so the three refusal paths in
    /// [`resolve`] cannot disagree about what "no key" looks like.
    fn missing() -> Self {
        Self {
            private_key: SecretString::new(String::new()),
            origin: KeyOrigin::Missing,
        }
    }
}

fn keystore() -> SealedKeystore {
    SealedKeystore::new(
        PathBuf::from(keystore_path()),
        helios_tpm::DOMAIN_GATEWAY_WG_KEY,
    )
}

/// Object context of the gateway identity vault: its own WireGuard public key.
///
/// It is what stops a vault from being opened as another gateway's, and it is
/// derivable from the very secret the vault holds — which is why reading goes
/// through `load_declared` and compares afterwards (ADR-006 §2).
fn identity_context(private_key: &str) -> Result<helios_tpm::Context, String> {
    let public = aether::wg::public_from_private(private_key)
        .map_err(|e| format!("deriving the gateway public key: {e}"))?;
    Ok(helios_tpm::Context::new().field("wg_public_key", public.as_bytes()))
}

/// What a vault's declared context says about the key it contains.
#[derive(Debug, PartialEq, Eq)]
enum ContextVerdict {
    /// The context names the public key the private key derives to. This vault
    /// belongs to this identity.
    Matches,
    /// A legacy `HKS1` vault, which predates object contexts. Accepted so a
    /// gateway updating in place keeps its identity; the next sealing binds one.
    Legacy,
    /// The context names another public key: the blob comes from another
    /// gateway, or the key inside was substituted.
    Foreign,
    /// The recovered key cannot even be parsed, so nothing can be verified.
    UnusableKey(String),
}

/// Decides whether a vault's context describes the key it gave back.
///
/// Extracted from [`resolve`] because it is the security decision of the whole
/// function, and inline it was reachable only with a TPM secret and a real
/// vault — neither of which a test can build. The AEAD already proves nobody
/// rewrote the context; this proves the context is not describing *another*
/// gateway's key (ADR-006 §2).
fn verify_declared_context(declared: &[u8], private_key: &str) -> ContextVerdict {
    match identity_context(private_key) {
        Err(cause) => ContextVerdict::UnusableKey(cause),
        // An empty declared context is the **legacy format**, not a mismatch.
        // Collapsing the two would refuse every gateway that has not resealed
        // yet, turning a routine update into a loss of identity. The arm's
        // position is not what matters — `expected` is never empty, so the
        // comparison above could not claim it — but its *existence* is.
        Ok(_) if declared.is_empty() => ContextVerdict::Legacy,
        Ok(expected) if expected.as_bytes() == declared => ContextVerdict::Matches,
        Ok(_) => ContextVerdict::Foreign,
    }
}

/// Writes the escrow of `private_key` to the operator's public key.
///
/// No fatal error: a missing escrow does not prevent the gateway from
/// working, it only removes a recovery option. It is reported loudly rather
/// than failing at startup.
fn write_escrow(network: &NetworkConfig, private_key: &str, tpm: &TpmSettings) {
    use base64::Engine as _;

    let Some(pubkey_b64) = network.escrow_public_key.as_deref().map(str::trim) else {
        warn!(
            "no escrow public key configured (`escrow_public_key`) — \
             in case of a PCR change (kernel, bootloader, firmware), the \
             gateway's identity will be permanently lost"
        );
        return;
    };
    if pubkey_b64.is_empty() {
        return;
    }

    let pubkey = match base64::engine::general_purpose::STANDARD.decode(pubkey_b64) {
        Ok(k) => k,
        Err(e) => {
            warn!("unreadable escrow public key ({e}) — escrow not written");
            return;
        }
    };

    // The escrow records the public key the carried private key derives to,
    // and the counter in force when it is written: the operator checks a
    // recovery against both. Without a readable counter, the field is absent.
    let gateway_public_key = match aether::wg::public_from_private(private_key)
        .ok()
        .and_then(|public| {
            base64::engine::general_purpose::STANDARD
                .decode(public)
                .ok()
        })
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    {
        Some(key) => key,
        None => {
            warn!("the WireGuard key cannot be derived — escrow not written");
            return;
        }
    };
    let metadata = helios_escrow::EscrowMetadata {
        counter: anti_rollback::current(tpm).ok(),
        gateway_public_key,
    };

    match helios_escrow::seal_to_operator(&pubkey, private_key.as_bytes(), &metadata) {
        Ok(blob) => match write_atomic(&escrow_path(), &blob) {
            Ok(()) => info!(
                path = %escrow_path(),
                "WireGuard key escrow written — retrieve it and keep it off the gateway"
            ),
            Err(e) => warn!("could not write escrow: {e}"),
        },
        Err(e) => warn!("could not seal escrow: {e}"),
    }
}

/// Attempts recovery from the recovery file left by the operator.
///
/// Only called when the vault is undecipherable: outside of that case, a
/// stray recovery file must never be able to replace the key in effect —
/// that would be an identity substitution vector. The file is accepted only
/// with a publisher authorization for the current anti-rollback counter.
fn try_recovery(secret: &helios_tpm::SecretKey, tpm: &TpmSettings) -> Option<SecretString> {
    use base64::Engine as _;

    let path = PathBuf::from(recovery_path());
    let frame = read_recovery_frame(&path)?;
    let (authorization, key) = match decode_recovery_frame(&frame) {
        Ok(decoded) => decoded,
        Err(e) => {
            warn!("invalid recovery file ({e}) — ignored, not consumed");
            return None;
        }
    };
    // Every refusal happens before the counter is spent: the file stays.
    // `resolve` runs once at startup, so callers are serialised, as `consume` requires.
    if let Err(e) = wg_recovery::accept(tpm, &authorization, &key) {
        warn!("recovery file refused ({e}) — left in place, the identity is not restored");
        return None;
    }

    // The counter is spent from here on: whatever follows, this file cannot
    // restore the identity again.
    let text = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(key.as_slice()));
    let resealed = identity_context(&text)
        .map_err(|e| format!("building its context: {e}"))
        .and_then(|context| {
            keystore()
                .store(secret, &context, text.as_bytes())
                .map_err(|e| e.to_string())
        });
    let sealed = match resealed {
        Ok(()) => true,
        Err(cause) => {
            // The key is used for this boot only. Erasing the file below is what
            // keeps the counter from being spent twice.
            error!(
                "the recovered key is NOT sealed: its counter is spent and the recovery \
                 file is erased ({cause}). The tunnel comes up on this boot only. The next \
                 start will need a new authorization for the counter now in force \
                 (`heliosd tpm counter-status`)"
            );
            false
        }
    };

    // Then erases: the key must not stay in the clear on disk longer than
    // this startup. A deletion failure is an anomaly to report loudly.
    match std::fs::remove_file(&path) {
        Ok(()) => info!("recovery file consumed and erased"),
        Err(e) => warn!(
            "FAILED TO ERASE {RECOVERY_PATH} ({e}) — the private key remains \
             IN THE CLEAR on disk, delete it manually without delay"
        ),
    }

    if sealed {
        warn!("WireGuard identity restored from escrow and resealed");
    }
    Some(SecretString::new(text.as_str()))
}

/// Reads the operator-delivered recovery frame without consuming it, at most
/// one byte past `MAX_RECOVERY_FRAME`: a larger file then fails to decode.
/// Absent, unreadable or oversized files are left untouched. The bytes are
/// wiped on drop (ADR-006 §5).
fn read_recovery_frame(path: &std::path::Path) -> Option<Zeroizing<Vec<u8>>> {
    if !path.exists() {
        return None;
    }
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            warn!("unreadable recovery file: {error}");
            return None;
        }
    };
    let mut frame = Zeroizing::new(Vec::new());
    let bound = MAX_RECOVERY_FRAME as u64 + 1;
    if let Err(error) = file.take(bound).read_to_end(&mut frame) {
        warn!("unreadable recovery file: {error}");
        return None;
    }
    Some(frame)
}

/// Moves the anti-rollback counter after an identity rotation. A failure is
/// logged and does not undo the rotation: the older authorizations then stay
/// valid until the counter can be moved.
fn advance_counter(tpm: &TpmSettings) {
    if let Err(error) = anti_rollback::advance(tpm) {
        warn!(
            "anti-rollback counter could not be advanced after the rotation ({error}) — \
             older recovery authorizations stay valid until it can be"
        );
    }
}

fn write_atomic(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)
}

/// Resolves the WireGuard private key at startup.
///
/// Priority order:
/// 1. the sealed vault (nominal);
/// 2. the plaintext key from `network.toml`, **with a warning** — and it is
///    sealed immediately so the switch to protected mode is automatic;
/// 3. nothing: the gateway starts fail-closed without bringing up an
///    interface.
pub fn resolve(network: &NetworkConfig, boot: &BootDecision, tpm: &TpmSettings) -> ResolvedKey {
    let store = keystore();
    let secret = boot.secret();

    // 1. Sealed vault.
    if store.exists() {
        match secret {
            None => {
                // TPM disabled or bypassed: the vault cannot be opened.
                warn!(
                    "key vault present but no TPM secret available \
                     (tpm.enabled=false or enforce=false) — key inaccessible"
                );
            }
            Some(secret) => match store.load_declared(secret) {
                // `bytes` is already `Zeroizing`; the two decoding steps that
                // follow must be too, or the vault's content survives in two
                // freed allocations (ADR-006 §5).
                Ok((declared, bytes)) => match std::str::from_utf8(&bytes) {
                    Ok(key) => {
                        let key = Zeroizing::new(key.trim().to_string());
                        match verify_declared_context(&declared, &key) {
                            ContextVerdict::Matches => {}
                            ContextVerdict::Legacy => warn!(
                                "legacy vault without object context — it will be bound \
                                 on the next sealing"
                            ),
                            ContextVerdict::Foreign => {
                                warn!(
                                    "vault context does not match the key it contains — \
                                     refusing this identity"
                                );
                                return ResolvedKey::missing();
                            }
                            ContextVerdict::UnusableKey(cause) => {
                                warn!("unusable vault content ({cause})");
                                return ResolvedKey::missing();
                            }
                        }
                        info!("WireGuard key loaded from the sealed TPM vault");
                        // Escrow follows the key: if the escrow configuration
                        // was just added, it is created on this very startup.
                        write_escrow(network, &key, tpm);
                        return ResolvedKey {
                            private_key: SecretString::new(key.as_str()),
                            origin: KeyOrigin::Sealed,
                        };
                    }
                    Err(_) => warn!("unreadable vault content (encoding)"),
                },
                Err(TpmError::Keystore(KeystoreError::Undecipherable)) => {
                    // The PCRs have moved (new kernel, bootloader or
                    // firmware): the secret has been regenerated and the old
                    // vault is lost. This is exactly the case escrow exists
                    // to cover.
                    warn!(
                        "UNDECIPHERABLE VAULT — the PCRs have changed (new kernel, \
                         bootloader or firmware) and the TPM secret has been \
                         regenerated. Looking for a recovery file…"
                    );
                    if let Some(key) = try_recovery(secret, tpm) {
                        write_escrow(network, key.expose(), tpm);
                        return ResolvedKey {
                            private_key: key,
                            origin: KeyOrigin::Recovered,
                        };
                    }
                    warn!(
                        "no usable recovery file in {RECOVERY_PATH}. Open the escrow \
                         {ESCROW_PATH} with the operator's private key, obtain the \
                         publisher-signed authorization for the counter in force, and \
                         deposit the frame (authorization and private key) into this file, \
                         deposited out of band (never with the OTA bundle), then restart."
                    );
                }
                Err(e) => warn!("could not read the vault: {e}"),
            },
        }
    }

    // 2. Fall back to the plaintext key from the config — degraded mode.
    let plain = network.wg_private_key.expose().trim();
    if !plain.is_empty() {
        warn!(
            "WireGuard key read IN THE CLEAR from network.toml — a stolen disk is \
             enough to impersonate the gateway. Automatic sealing into the TPM vault…"
        );
        if let Some(secret) = secret {
            let context = match identity_context(plain) {
                Ok(context) => context,
                Err(e) => {
                    warn!("plaintext key unusable ({e}) — not sealed");
                    return ResolvedKey::missing();
                }
            };
            match store.store(secret, &context, plain.as_bytes()) {
                Ok(()) => {
                    info!(
                        "key sealed into {KEYSTORE_PATH} — remove `wg_private_key` from network.toml"
                    );
                    write_escrow(network, plain, tpm);
                }
                Err(e) => warn!("automatic sealing failed: {e}"),
            }
        } else {
            warn!("no TPM secret available: the key stays in the clear");
        }
        return ResolvedKey {
            private_key: SecretString::new(plain),
            origin: KeyOrigin::PlaintextConfig,
        };
    }

    // 3. Nothing usable.
    ResolvedKey::missing()
}

/// Creates the gateway's WireGuard identity, seals it, and returns its
/// **public** key — the only half meant to leave here.
///
/// This is the first-provisioning path (ADR-004 §3). It is necessarily
/// **local**: `POST /api/gateway/wireguard-key` lives behind `admin_iface`,
/// hence behind a tunnel that already assumes a gateway identity and an
/// admitted administrator peer. This route is a rotation path, not a
/// bootstrap one.
///
/// The private key is never written in the clear: it is generated in memory
/// and sealed directly. `rotate` authorizes replacing an existing identity —
/// a heavy operation, since all clients will need to update their
/// `peer_public_key`.
pub fn initialize(
    network: &NetworkConfig,
    boot: &BootDecision,
    rotate: bool,
    tpm: &TpmSettings,
) -> Result<String, String> {
    let store = keystore();
    reject_overwrite(store.exists(), rotate)?;

    let secret = boot.secret().ok_or_else(|| {
        "no TPM secret available: cannot seal an identity. Provision the vault \
         first (`heliosd provision-tpm`), or build with --features tpm on the target."
            .to_string()
    })?;

    let keypair = aether::wg::generate_keypair().map_err(|e| e.to_string())?;
    let context = identity_context(keypair.private_key.expose())?;
    store
        .store(secret, &context, keypair.private_key.expose().as_bytes())
        .map_err(|e| format!("could not seal the identity: {e}"))?;
    if rotate {
        advance_counter(tpm);
    }
    write_escrow(network, keypair.private_key.expose(), tpm);

    if rotate {
        warn!(
            "WireGuard identity regenerated — all clients must update \
             `peer_public_key` before they can reconnect"
        );
    } else {
        info!("WireGuard identity created and sealed into {KEYSTORE_PATH}");
    }
    Ok(keypair.public_key)
}

/// Refuses to overwrite an already-sealed identity unless rotation is
/// requested.
///
/// Isolated from the filesystem so the rule is verifiable without a TPM: it
/// is this rule that protects against identity loss, not the vault path.
fn reject_overwrite(exists: bool, rotate: bool) -> Result<(), String> {
    if exists && !rotate {
        return Err(format!(
            "an identity is already sealed in {KEYSTORE_PATH} — overwriting it would lose \
             the gateway's identity and cut off all clients. Use --rotate to \
             explicitly accept that."
        ));
    }
    Ok(())
}

/// Replaces the WireGuard private key and seals it.
///
/// Called by the API (`POST /api/gateway/wireguard-key`), hence **only
/// through the tunnel**: the firewall restricts the API to `admin_iface`.
///
/// Changing this key changes the gateway's identity: **all clients will
/// have to update their `peer_public_key`**. This is a rotation, not a
/// trivial operation — hence the strict upfront validation.
pub fn update_sealed(
    network: &NetworkConfig,
    boot: &BootDecision,
    new_private_key: &str,
    tpm: &TpmSettings,
) -> Result<(), String> {
    let key = new_private_key.trim();
    validate_wg_key(key)?;

    let secret = boot
        .secret()
        .ok_or_else(|| "no TPM secret available: cannot seal".to_string())?;

    // The static-PSK table is keyed by the identity, so it must be re-wrapped
    // **before** the new key is published — ADR-006 §4. Doing it after would
    // leave a window where the old identity is gone and the table still needs
    // it: every static peer would stop handshaking, with no way back.
    //
    // A failure here aborts the rotation rather than proceeding: an identity
    // replaced while its PSK table stayed behind is exactly the silent
    // half-migration the ADR forbids.
    let old_key = network.wg_private_key.expose().trim();
    if !old_key.is_empty() && old_key != key {
        match crate::static_psk::rotate(&crate::static_psk::default_path(), old_key, key) {
            Ok(0) => {}
            Ok(carried) => info!(
                carried,
                "PSK statiques ré-enveloppés sous la nouvelle identité"
            ),
            Err(e) => {
                return Err(format!(
                    "rotation refusée : la table des PSK statiques n'a pas pu être \
                     ré-enveloppée ({e}). L'identité n'a pas été remplacée."
                ))
            }
        }
    }

    let context = identity_context(key)?;
    keystore()
        .store(secret, &context, key.as_bytes())
        .map_err(|e| format!("could not seal the new key: {e}"))?;

    advance_counter(tpm);

    // Escrow must follow the new key: otherwise a post-OTA recovery would
    // restore the old identity, which no client expects anymore.
    write_escrow(network, key, tpm);

    warn!(
        "WireGuard private key replaced and resealed — the gateway's identity has \
         changed, all clients must update `peer_public_key`"
    );
    Ok(())
}

/// Validates that a string is indeed a 32-byte base64 Curve25519 key.
///
/// Refused **before** writing: sealing an invalid key would leave the
/// gateway unable to bring up its interface, with no way to reach it to fix
/// it.
pub fn validate_wg_key(key: &str) -> Result<(), String> {
    aether::wg::validate_key(key).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::sig::{
        PublisherSigner, ResealPayload, SignedWireGuardRecovery, WireGuardRecoveryPayload,
    };
    use base64::Engine as _;
    use helios_escrow::recovery::encode_recovery_frame;
    use helios_tpm::{BootController, SecretKey};

    const VALID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// A real Curve25519 pair, so the derivation is genuinely exercised.
    fn keypair() -> (String, String) {
        let pair = aether::wg::generate_keypair().expect("keypair");
        (
            pair.private_key.expose().to_string(),
            pair.public_key.clone(),
        )
    }

    fn context_of(public_key: &str) -> Vec<u8> {
        helios_tpm::Context::new()
            .field("wg_public_key", public_key.as_bytes())
            .as_bytes()
            .to_vec()
    }

    /// The context must name the public key the private key derives to.
    #[test]
    fn a_context_naming_its_own_key_is_accepted() {
        let (private_key, public_key) = keypair();
        assert_eq!(
            verify_declared_context(&context_of(&public_key), &private_key),
            ContextVerdict::Matches
        );
    }

    /// The property the object context exists for: a vault copied from another
    /// gateway must not be adopted, even if it decrypts.
    #[test]
    fn a_context_naming_another_gateway_is_refused() {
        let (private_key, _) = keypair();
        let (_, other_public) = keypair();
        assert_eq!(
            verify_declared_context(&context_of(&other_public), &private_key),
            ContextVerdict::Foreign
        );
    }

    /// A legacy `HKS1` vault carries no context. Confusing "absent" with
    /// "wrong" would refuse every gateway that has not resealed yet — the
    /// update turning into a loss of identity.
    #[test]
    fn a_legacy_vault_without_context_is_accepted_not_refused() {
        let (private_key, _) = keypair();
        assert_eq!(
            verify_declared_context(&[], &private_key),
            ContextVerdict::Legacy
        );
    }

    /// Nothing can be verified against a key that will not parse, so the
    /// identity is refused rather than accepted on a failed comparison.
    #[test]
    fn an_unparsable_key_is_refused_rather_than_compared() {
        let verdict = verify_declared_context(&context_of("peu-importe"), "pas-du-base64");
        assert!(
            matches!(verdict, ContextVerdict::UnusableKey(_)),
            "obtained: {verdict:?}"
        );
        // And an empty context does not turn an unusable key into a legacy
        // vault: the key is checked first.
        assert!(matches!(
            verify_declared_context(&[], "pas-du-base64"),
            ContextVerdict::UnusableKey(_)
        ));
    }

    /// A truncated or padded context must not pass: the comparison is on the
    /// whole canonical encoding, not a prefix.
    #[test]
    fn a_truncated_or_extended_context_is_refused() {
        let (private_key, public_key) = keypair();
        let full = context_of(&public_key);

        assert_eq!(
            verify_declared_context(&full[..full.len() - 1], &private_key),
            ContextVerdict::Foreign
        );
        let mut extended = full.clone();
        extended.push(0);
        assert_eq!(
            verify_declared_context(&extended, &private_key),
            ContextVerdict::Foreign
        );
    }

    /// The label is part of the context, so a value carried under another
    /// label is not the same context.
    #[test]
    fn a_context_under_another_label_is_refused() {
        let (private_key, public_key) = keypair();
        let mislabelled = helios_tpm::Context::new()
            .field("public_key", public_key.as_bytes())
            .as_bytes()
            .to_vec();
        assert_eq!(
            verify_declared_context(&mislabelled, &private_key),
            ContextVerdict::Foreign
        );
    }

    #[test]
    fn the_context_is_deterministic_and_separates_identities() {
        let (private_key, _) = keypair();
        let (other_private, _) = keypair();
        let first = identity_context(&private_key).expect("context");
        let second = identity_context(&private_key).expect("context");
        let foreign = identity_context(&other_private).expect("context");

        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_ne!(first.as_bytes(), foreign.as_bytes());
    }

    #[test]
    fn a_context_cannot_be_built_from_an_invalid_key() {
        let error = identity_context("pas-du-base64").expect_err("must fail");
        assert!(error.contains("public key"), "message: {error}");
    }

    /// Serialises the tests that drive `HELIOS_IDENTITY_DIR`.
    ///
    /// The variable is process-wide, so two tests setting it would point each
    /// other's writes at the wrong directory under the parallel harness.
    static IDENTITY_DIR: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Runs `body` with the identity files redirected into a fresh directory.
    fn in_identity_dir<T>(name: &str, body: impl FnOnce(&std::path::Path) -> T) -> T {
        let _guard = IDENTITY_DIR.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "helios-identity-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test directory");
        std::env::set_var(IDENTITY_DIR_ENV, &dir);
        let outcome = body(&dir);
        std::env::remove_var(IDENTITY_DIR_ENV);
        let _ = std::fs::remove_dir_all(&dir);
        outcome
    }

    const ISOLATED_KEY_SCENARIO: &str = "HELIOSD_GATEWAY_KEY_SCENARIO";

    /// The identity directory is process-wide, so filesystem scenarios run in
    /// a child rather than relying on a lock invisible to other test modules.
    fn run_isolated_identity_scenario(name: &str) -> bool {
        if std::env::var(ISOLATED_KEY_SCENARIO).ok().as_deref() == Some(name) {
            return false;
        }
        let directory = tempfile::tempdir().expect("temporary identity directory");
        let test_name = format!("gateway_key::tests::{name}");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", test_name.as_str(), "--nocapture"])
            .env(ISOLATED_KEY_SCENARIO, name)
            .env(IDENTITY_DIR_ENV, directory.path())
            .output()
            .expect("isolated identity scenario starts");
        assert!(
            output.status.success(),
            "isolated {name} failed:
{}
{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "isolated {name} must execute exactly one test:
{}",
            String::from_utf8_lossy(&output.stdout)
        );
        true
    }

    const OTHER_ED_SEED: [u8; 32] = *b"helios-sign-ed25519-other-seed01";
    const OTHER_ML_SEED: [u8; 32] = *b"helios-sign-mldsa65-other-seed01";
    const DEV_ED_SEED: [u8; 32] = *b"helios-sign-ed25519-dev-seed-001";
    const DEV_ML_SEED: [u8; 32] = *b"helios-sign-mldsa65-dev-seed-001";

    /// The TPM of one identity directory. The counter and the simulated
    /// secret live there, and a boot provisions its secret into it.
    fn tpm_in(dir: &std::path::Path) -> TpmSettings {
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
        TpmSettings {
            enabled: true,
            allow_provisioning: true,
            device: path("no-tpm-device"),
            sealed_blob_path: path("tpm-sealed.key"),
            ticket_path: path("reseal-ticket.json"),
            update_window_marker_path: path("update-window.marker"),
            simulated_counter_path: path("simulated-nv-counter"),
            counter_status_path: path("anti-rollback.json"),
            ..TpmSettings::default()
        }
    }

    /// The directory the isolated scenario was given.
    fn identity_dir() -> PathBuf {
        PathBuf::from(std::env::var_os(IDENTITY_DIR_ENV).expect("isolated identity directory"))
    }

    /// The secret of a boot over `tpm`, as the boot flow provisions it. A boot
    /// also defines the anti-rollback counter.
    fn boot_secret(tpm: &TpmSettings) -> SecretKey {
        BootController::unlock(tpm)
            .expect("simulated TPM boot")
            .secret()
            .expect("a boot with a secret")
            .clone()
    }

    /// The secret of a boot in its own directory: the one a vault is sealed
    /// under before a PCR change.
    fn secret_in(dir: &std::path::Path) -> SecretKey {
        std::fs::create_dir_all(dir).expect("secret directory");
        boot_secret(&tpm_in(dir))
    }

    fn raw_key(base64_key: &str) -> [u8; 32] {
        <[u8; 32]>::try_from(
            base64::engine::general_purpose::STANDARD
                .decode(base64_key)
                .expect("base64 key"),
        )
        .expect("32-byte key")
    }

    /// The publisher's authorization for `counter`, under the development keys
    /// the compiled keyring accepts.
    fn signed_recovery(counter: u64, public_key: &str) -> SignedWireGuardRecovery {
        PublisherSigner::from_seed_material(1, &DEV_ED_SEED, &DEV_ML_SEED)
            .expect("development signer")
            .sign(WireGuardRecoveryPayload {
                counter,
                gateway_public_key: raw_key(public_key),
                expected_pcr_digest: None,
            })
            .expect("signature")
    }

    /// The frame the operator deposits for `authorization`.
    fn frame_of(authorization: &SignedWireGuardRecovery, private_key: &str) -> Vec<u8> {
        encode_recovery_frame(authorization, &raw_key(private_key))
            .expect("recovery frame")
            .to_vec()
    }

    /// Seals `private_key` as the identity vault an earlier boot wrote.
    fn seal_vault(secret: &SecretKey, private_key: &str) {
        let context = identity_context(private_key).expect("context");
        keystore()
            .store(secret, &context, private_key.as_bytes())
            .expect("vault sealed");
    }

    /// The state after a PCR change: the vault was sealed under a secret the
    /// current boot does not have. Returns the key pair and the current secret.
    fn lost_vault(dir: &std::path::Path) -> (String, String, SecretKey) {
        let (private_key, public_key) = keypair();
        seal_vault(&secret_in(&dir.join("previous")), &private_key);
        (private_key, public_key, boot_secret(&tpm_in(dir)))
    }

    /// The escrow is the only recovery channel after a PCR change, and the
    /// gateway itself must be unable to open it — that is the whole design.
    /// This exercises the real write path, then opens the result as the
    /// operator would.
    #[test]
    fn the_escrow_is_written_and_only_the_operator_can_open_it() {
        let (private_key, public_key) =
            helios_escrow::generate_operator_keypair().expect("operator keypair");
        let network = NetworkConfig {
            escrow_public_key: Some(base64::engine::general_purpose::STANDARD.encode(public_key)),
            ..NetworkConfig::default()
        };
        let (wg_private, _) = keypair();

        in_identity_dir("escrow-write", |dir| {
            write_escrow(&network, &wg_private, &tpm_in(dir));
            let blob = std::fs::read(dir.join("wg-key.escrow")).expect("escrow written");
            assert!(
                !blob
                    .windows(wg_private.len())
                    .any(|w| w == wg_private.as_bytes()),
                "the escrow holds the key in the clear"
            );
            let opened = helios_escrow::open_as_operator(private_key.as_ref(), &blob)
                .expect("the operator must be able to open it");
            assert_eq!(opened.plaintext.as_slice(), wg_private.as_bytes());
        });
    }

    /// Rewritten on every sealing: a stale escrow would restore an identity
    /// no client expects anymore.
    #[test]
    fn the_escrow_is_replaced_rather_than_appended() {
        let (_, public_key) = helios_escrow::generate_operator_keypair().expect("operator keypair");
        let network = NetworkConfig {
            escrow_public_key: Some(base64::engine::general_purpose::STANDARD.encode(public_key)),
            ..NetworkConfig::default()
        };
        let (first, _) = keypair();
        let (second, _) = keypair();

        in_identity_dir("escrow-replace", |dir| {
            write_escrow(&network, &first, &tpm_in(dir));
            let before = std::fs::read(dir.join("wg-key.escrow")).expect("first escrow");
            write_escrow(&network, &second, &tpm_in(dir));
            let after = std::fs::read(dir.join("wg-key.escrow")).expect("second escrow");
            assert_ne!(before, after, "the escrow was not rewritten");
        });
    }

    /// A missing escrow key removes a recovery option; it must not stop the
    /// gateway, and it must not write anything either.
    #[test]
    fn an_absent_escrow_key_is_reported_without_writing() {
        in_identity_dir("escrow-absent", |dir| {
            write_escrow(&NetworkConfig::default(), VALID, &tpm_in(dir));
            write_escrow(
                &NetworkConfig {
                    escrow_public_key: Some("   ".into()),
                    ..NetworkConfig::default()
                },
                VALID,
                &tpm_in(dir),
            );
            assert!(
                !dir.join("wg-key.escrow").exists(),
                "nothing must be written without an escrow key"
            );
        });
    }

    /// An unreadable escrow key is reported, never fatal: it costs a recovery
    /// option, not the gateway's ability to start.
    #[test]
    fn an_unreadable_escrow_key_does_not_panic() {
        in_identity_dir("escrow-invalid", |dir| {
            write_escrow(
                &NetworkConfig {
                    escrow_public_key: Some("pas-du-base64-!!".into()),
                    ..NetworkConfig::default()
                },
                VALID,
                &tpm_in(dir),
            );
            assert!(!dir.join("wg-key.escrow").exists());
            // A syntactically valid but wrong-sized key: base64 decodes, the
            // sealing refuses. Reported, never fatal.
            write_escrow(
                &NetworkConfig {
                    escrow_public_key: Some(
                        base64::engine::general_purpose::STANDARD.encode([7u8; 8]),
                    ),
                    ..NetworkConfig::default()
                },
                VALID,
                &tpm_in(dir),
            );
            assert!(!dir.join("wg-key.escrow").exists());
        });
    }

    #[test]
    fn recovery_file_absence_is_not_an_error() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("missing-recovery");

        assert!(read_recovery_frame(&path).is_none());
    }

    #[test]
    fn unreadable_recovery_path_is_refused_without_consuming_it() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("recovery-directory");
        std::fs::create_dir(&path).expect("create directory at recovery path");

        assert!(read_recovery_frame(&path).is_none());
        assert!(path.is_dir());
    }

    #[test]
    fn a_recovery_frame_is_read_without_consuming_it() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("wg-key.recovery");
        let (private_key, public_key) = keypair();
        let frame = frame_of(&signed_recovery(1, &public_key), &private_key);
        std::fs::write(&path, &frame).expect("write recovery frame");

        let read = read_recovery_frame(&path).expect("readable recovery frame");

        assert_eq!(read.as_slice(), frame.as_slice());
        assert!(
            path.exists(),
            "reading alone must not consume the recovery file"
        );
    }

    #[test]
    fn atomic_write_replaces_the_destination_with_complete_bytes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("nested/identity.bin");
        std::fs::create_dir_all(path.parent().expect("destination parent"))
            .expect("create destination parent");
        std::fs::write(&path, b"stale identity").expect("create existing destination");

        write_atomic(
            path.to_str().expect("UTF-8 test path"),
            b"complete identity",
        )
        .expect("atomic write");

        assert_eq!(
            std::fs::read(path).expect("read destination"),
            b"complete identity"
        );
    }

    #[test]
    fn atomic_write_reports_parent_creation_failure_without_partial_destination() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let parent = directory.path().join("parent-file");
        std::fs::write(&parent, b"not a directory").expect("create blocking file");
        let path = parent.join("identity.bin");

        let result = write_atomic(path.to_str().expect("UTF-8 test path"), b"secret");

        assert!(result.is_err());
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(parent).expect("blocking file unchanged"),
            b"not a directory"
        );
    }

    #[test]
    fn a_locked_vault_without_plaintext_fails_closed_and_is_preserved() {
        if run_isolated_identity_scenario(
            "a_locked_vault_without_plaintext_fails_closed_and_is_preserved",
        ) {
            return;
        }
        let path = PathBuf::from(keystore_path());
        std::fs::write(&path, b"vault marker").expect("existing sealed vault");

        let resolved = resolve(
            &NetworkConfig::default(),
            &BootDecision::Disabled,
            &TpmSettings::default(),
        );

        assert_eq!(resolved.origin, KeyOrigin::Missing);
        assert!(resolved.private_key.is_empty());
        assert_eq!(std::fs::read(path).unwrap(), b"vault marker");
    }

    #[test]
    fn a_locked_vault_uses_only_the_explicit_plaintext_fallback() {
        if run_isolated_identity_scenario(
            "a_locked_vault_uses_only_the_explicit_plaintext_fallback",
        ) {
            return;
        }
        let path = PathBuf::from(keystore_path());
        std::fs::write(&path, b"vault marker").expect("existing sealed vault");
        let network = NetworkConfig {
            wg_private_key: VALID.into(),
            ..NetworkConfig::default()
        };

        let resolved = resolve(&network, &BootDecision::Disabled, &TpmSettings::default());

        assert_eq!(resolved.origin, KeyOrigin::PlaintextConfig);
        assert_eq!(resolved.private_key.expose(), VALID);
        assert_eq!(std::fs::read(path).unwrap(), b"vault marker");
    }

    /// A signed authorization for the current counter restores the identity:
    /// the counter is spent, the key is resealed under the current secret, and
    /// the file is erased.
    #[test]
    #[cfg_attr(
        feature = "tpm",
        ignore = "needs the simulated TPM backend (the tpm feature selects the real device); run by the default-feature heliosd step"
    )]
    fn a_signed_recovery_for_the_current_counter_is_resealed_and_erased() {
        if run_isolated_identity_scenario(
            "a_signed_recovery_for_the_current_counter_is_resealed_and_erased",
        ) {
            return;
        }
        let dir = identity_dir();
        let tpm = tpm_in(&dir);
        let (private_key, public_key, current) = lost_vault(&dir);
        let counter = anti_rollback::current(&tpm).expect("counter");
        let recovery = PathBuf::from(recovery_path());
        std::fs::write(
            &recovery,
            frame_of(&signed_recovery(counter, &public_key), &private_key),
        )
        .expect("operator recovery file");

        let resolved = resolve(
            &NetworkConfig::default(),
            &BootDecision::Unsealed(current.clone()),
            &tpm,
        );

        assert_eq!(resolved.origin, KeyOrigin::Recovered);
        assert_eq!(resolved.private_key.expose(), private_key.as_str());
        assert!(!recovery.exists(), "the recovery file must be erased");
        assert_eq!(anti_rollback::current(&tpm).expect("counter"), counter + 1);
        let again = resolve(
            &NetworkConfig::default(),
            &BootDecision::Unsealed(current),
            &tpm,
        );
        assert_eq!(
            again.origin,
            KeyOrigin::Sealed,
            "the vault opens under the current secret"
        );
    }

    /// Only the publisher-signed, key-bound authorization is accepted. Each
    /// refusal leaves the file in place and the counter where it was.
    #[test]
    #[cfg_attr(
        feature = "tpm",
        ignore = "needs the simulated TPM backend (the tpm feature selects the real device); run by the default-feature heliosd step"
    )]
    fn an_unsigned_or_foreign_recovery_is_left_in_place() {
        if run_isolated_identity_scenario("an_unsigned_or_foreign_recovery_is_left_in_place") {
            return;
        }
        let dir = identity_dir();
        let tpm = tpm_in(&dir);
        let (private_key, public_key, current) = lost_vault(&dir);
        let counter = anti_rollback::current(&tpm).expect("counter");
        let (other_private_key, _) = keypair();
        let unknown_signer = PublisherSigner::from_seed_material(9, &OTHER_ED_SEED, &OTHER_ML_SEED)
            .expect("unknown signer")
            .sign(WireGuardRecoveryPayload {
                counter,
                gateway_public_key: raw_key(&public_key),
                expected_pcr_digest: None,
            })
            .expect("signature");
        // A signature made for a reseal ticket, with the same keys and epoch,
        // carried over to a recovery: the domain must differ.
        let reseal = PublisherSigner::from_seed_material(1, &DEV_ED_SEED, &DEV_ML_SEED)
            .expect("development signer")
            .sign(ResealPayload {
                counter,
                sealed_blob_anchor: [0; 32],
                expected_pcr_digest: None,
            })
            .expect("signature");
        let cross_domain = SignedWireGuardRecovery {
            payload: WireGuardRecoveryPayload {
                counter,
                gateway_public_key: raw_key(&public_key),
                expected_pcr_digest: None,
            },
            key_epoch: reseal.key_epoch,
            signatures: reseal.signatures,
        };
        let cases = [
            (
                "a key that does not derive the authorized public key",
                frame_of(&signed_recovery(counter, &public_key), &other_private_key),
            ),
            (
                "a signature by an unknown key",
                frame_of(&unknown_signer, &private_key),
            ),
            (
                "a signature made over another domain",
                frame_of(&cross_domain, &private_key),
            ),
        ];
        let recovery = PathBuf::from(recovery_path());

        for (case, frame) in cases {
            std::fs::write(&recovery, &frame).expect("operator recovery file");
            let resolved = resolve(
                &NetworkConfig::default(),
                &BootDecision::Unsealed(current.clone()),
                &tpm,
            );
            assert_eq!(resolved.origin, KeyOrigin::Missing, "{case}");
            assert_eq!(
                std::fs::read(&recovery).expect("file"),
                frame,
                "{case}: file kept"
            );
            assert_eq!(
                anti_rollback::current(&tpm).expect("counter"),
                counter,
                "{case}: counter unchanged"
            );
        }
    }

    /// An authorization for another counter value is refused, and nothing moves.
    #[test]
    #[cfg_attr(
        feature = "tpm",
        ignore = "needs the simulated TPM backend (the tpm feature selects the real device); run by the default-feature heliosd step"
    )]
    fn a_recovery_for_another_counter_is_refused() {
        if run_isolated_identity_scenario("a_recovery_for_another_counter_is_refused") {
            return;
        }
        let dir = identity_dir();
        let tpm = tpm_in(&dir);
        let (private_key, public_key, current) = lost_vault(&dir);
        let counter = anti_rollback::current(&tpm).expect("counter");
        let frame = frame_of(&signed_recovery(counter + 1, &public_key), &private_key);
        let recovery = PathBuf::from(recovery_path());
        std::fs::write(&recovery, &frame).expect("operator recovery file");

        let resolved = resolve(
            &NetworkConfig::default(),
            &BootDecision::Unsealed(current),
            &tpm,
        );

        assert_eq!(resolved.origin, KeyOrigin::Missing);
        assert_eq!(std::fs::read(&recovery).expect("file"), frame);
        assert_eq!(anti_rollback::current(&tpm).expect("counter"), counter);
    }

    /// Once spent, the same file cannot restore the identity again, even after
    /// the vault is lost once more.
    #[test]
    #[cfg_attr(
        feature = "tpm",
        ignore = "needs the simulated TPM backend (the tpm feature selects the real device); run by the default-feature heliosd step"
    )]
    fn a_consumed_recovery_cannot_be_replayed() {
        if run_isolated_identity_scenario("a_consumed_recovery_cannot_be_replayed") {
            return;
        }
        let dir = identity_dir();
        let tpm = tpm_in(&dir);
        let (private_key, public_key, current) = lost_vault(&dir);
        let counter = anti_rollback::current(&tpm).expect("counter");
        let frame = frame_of(&signed_recovery(counter, &public_key), &private_key);
        let recovery = PathBuf::from(recovery_path());
        std::fs::write(&recovery, &frame).expect("operator recovery file");
        let first = resolve(
            &NetworkConfig::default(),
            &BootDecision::Unsealed(current.clone()),
            &tpm,
        );
        assert_eq!(first.origin, KeyOrigin::Recovered);

        seal_vault(&secret_in(&dir.join("previous")), &private_key);
        std::fs::write(&recovery, &frame).expect("replayed recovery file");
        let replay = resolve(
            &NetworkConfig::default(),
            &BootDecision::Unsealed(current),
            &tpm,
        );

        assert_eq!(replay.origin, KeyOrigin::Missing);
        assert_eq!(
            std::fs::read(&recovery).expect("file"),
            frame,
            "replay kept"
        );
        assert_eq!(anti_rollback::current(&tpm).expect("counter"), counter + 1);
    }

    /// A frame that does not decode is ignored and left for correction.
    #[test]
    #[cfg_attr(
        feature = "tpm",
        ignore = "needs the simulated TPM backend (the tpm feature selects the real device); run by the default-feature heliosd step"
    )]
    fn an_invalid_recovery_frame_is_left_in_place() {
        if run_isolated_identity_scenario("an_invalid_recovery_frame_is_left_in_place") {
            return;
        }
        let dir = identity_dir();
        let tpm = tpm_in(&dir);
        let (_, _, current) = lost_vault(&dir);
        let recovery = PathBuf::from(recovery_path());
        std::fs::write(&recovery, b"not a recovery frame").expect("invalid recovery file");

        let resolved = resolve(
            &NetworkConfig::default(),
            &BootDecision::Unsealed(current),
            &tpm,
        );

        assert_eq!(resolved.origin, KeyOrigin::Missing);
        assert_eq!(
            std::fs::read(&recovery).expect("file"),
            b"not a recovery frame"
        );
    }

    /// The recovery file is never read while the vault opens, and without a
    /// vault the recovery path is never reached: no consumption, no counter
    /// movement, in either case.
    #[test]
    #[cfg_attr(
        feature = "tpm",
        ignore = "needs the simulated TPM backend (the tpm feature selects the real device); run by the default-feature heliosd step"
    )]
    fn a_recovery_file_without_a_locked_vault_is_not_consumed_or_used() {
        if run_isolated_identity_scenario(
            "a_recovery_file_without_a_locked_vault_is_not_consumed_or_used",
        ) {
            return;
        }
        let dir = identity_dir();
        let tpm = tpm_in(&dir);
        let current = boot_secret(&tpm);
        let counter = anti_rollback::current(&tpm).expect("counter");
        let (private_key, public_key) = keypair();
        let recovery = PathBuf::from(recovery_path());
        let frame = frame_of(&signed_recovery(counter, &public_key), &private_key);
        std::fs::write(&recovery, &frame).expect("operator recovery file");

        // No vault at all.
        let resolved = resolve(&NetworkConfig::default(), &BootDecision::Disabled, &tpm);
        assert_eq!(resolved.origin, KeyOrigin::Missing);
        assert!(resolved.private_key.is_empty());
        assert_eq!(std::fs::read(&recovery).expect("file"), frame);
        assert_eq!(anti_rollback::current(&tpm).expect("counter"), counter);

        // A vault that opens under the current secret: the file is never read.
        seal_vault(&current, &private_key);
        let resolved = resolve(
            &NetworkConfig::default(),
            &BootDecision::Unsealed(current),
            &tpm,
        );
        assert_eq!(resolved.origin, KeyOrigin::Sealed);
        assert_eq!(resolved.private_key.expose(), private_key.as_str());
        assert_eq!(std::fs::read(&recovery).expect("file"), frame);
        assert_eq!(anti_rollback::current(&tpm).expect("counter"), counter);
    }

    /// A reseal that fails after the counter was spent: the recovery file
    /// stays, the counter has moved, and a replay of the same file is refused.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(
        feature = "tpm",
        ignore = "needs the simulated TPM backend (the tpm feature selects the real device); run by the default-feature heliosd step"
    )]
    fn a_reseal_failure_after_an_accepted_recovery_erases_it_and_restores_this_boot() {
        if run_isolated_identity_scenario(
            "a_reseal_failure_after_an_accepted_recovery_erases_it_and_restores_this_boot",
        ) {
            return;
        }
        let dir = identity_dir();
        let tpm = tpm_in(&dir);
        let (private_key, public_key, current) = lost_vault(&dir);
        // The vault path becomes a symbolic link to the old vault. It still
        // opens under the previous secret, while the atomic write refuses a
        // symbolic link at its destination: the reseal fails without root.
        let vault = dir.join("wg-key.sealed");
        let old = dir.join("previous-vault.sealed");
        std::fs::rename(&vault, &old).expect("move the old vault");
        std::os::unix::fs::symlink(&old, &vault).expect("symbolic link");
        let context = identity_context(&private_key).expect("context");
        assert!(
            keystore()
                .store(&current, &context, private_key.as_bytes())
                .is_err(),
            "the reseal must fail for this scenario to mean anything"
        );

        let counter = anti_rollback::current(&tpm).expect("counter");
        let recovery = PathBuf::from(recovery_path());
        let frame = frame_of(&signed_recovery(counter, &public_key), &private_key);
        std::fs::write(&recovery, &frame).expect("operator recovery file");

        let first = resolve(
            &NetworkConfig::default(),
            &BootDecision::Unsealed(current.clone()),
            &tpm,
        );
        // The counter is spent, so the key is used for this boot even though it
        // could not be sealed; the file is erased so it cannot be used again.
        assert_eq!(first.origin, KeyOrigin::Recovered);
        assert_eq!(first.private_key.expose(), private_key);
        assert!(!recovery.exists(), "the recovery file is erased");
        assert_eq!(
            anti_rollback::current(&tpm).expect("counter"),
            counter + 1,
            "the counter is spent"
        );

        let replay = resolve(
            &NetworkConfig::default(),
            &BootDecision::Unsealed(current),
            &tpm,
        );
        assert_eq!(replay.origin, KeyOrigin::Missing, "the replay is refused");
        assert!(replay.private_key.is_empty(), "no key is adopted");
        assert_eq!(
            anti_rollback::current(&tpm).expect("counter"),
            counter + 1,
            "the replay does not advance the counter again"
        );
    }

    /// Rotation spends a counter value, so an authorization issued before it
    /// no longer validates.
    #[test]
    #[cfg_attr(
        feature = "tpm",
        ignore = "needs the simulated TPM backend (the tpm feature selects the real device); run by the default-feature heliosd step"
    )]
    fn rotation_advances_the_counter_and_invalidates_an_older_authorization() {
        if run_isolated_identity_scenario(
            "rotation_advances_the_counter_and_invalidates_an_older_authorization",
        ) {
            return;
        }
        let dir = identity_dir();
        let tpm = tpm_in(&dir);
        let secret = boot_secret(&tpm);
        let (private_key, public_key) = keypair();
        seal_vault(&secret, &private_key);
        let before = anti_rollback::current(&tpm).expect("counter");
        let older = signed_recovery(before, &public_key);

        initialize(
            &NetworkConfig::default(),
            &BootDecision::Unsealed(secret),
            true,
            &tpm,
        )
        .expect("rotation");

        assert_eq!(anti_rollback::current(&tpm).expect("counter"), before + 1);
        let error = wg_recovery::accept(&tpm, &older, &raw_key(&private_key))
            .expect_err("the older authorization must be refused");
        assert!(
            matches!(error, TpmError::CounterMismatch { .. }),
            "{error:?}"
        );
    }

    /// A key update escrows the counter value it leaves in place, after the
    /// rotation.
    #[test]
    #[cfg_attr(
        feature = "tpm",
        ignore = "needs the simulated TPM backend (the tpm feature selects the real device); run by the default-feature heliosd step"
    )]
    fn an_update_escrows_the_counter_after_the_rotation() {
        if run_isolated_identity_scenario("an_update_escrows_the_counter_after_the_rotation") {
            return;
        }
        let dir = identity_dir();
        let tpm = tpm_in(&dir);
        let secret = boot_secret(&tpm);
        let (operator_private_key, operator_public_key) =
            helios_escrow::generate_operator_keypair().expect("operator keypair");
        let network = NetworkConfig {
            escrow_public_key: Some(
                base64::engine::general_purpose::STANDARD.encode(operator_public_key),
            ),
            ..NetworkConfig::default()
        };
        let (private_key, public_key) = keypair();
        let before = anti_rollback::current(&tpm).expect("counter");

        update_sealed(
            &network,
            &BootDecision::Unsealed(secret),
            &private_key,
            &tpm,
        )
        .expect("update");

        let blob = std::fs::read(dir.join("wg-key.escrow")).expect("escrow written");
        let opened = helios_escrow::open_as_operator(operator_private_key.as_ref(), &blob)
            .expect("the operator opens the escrow");
        let metadata = opened.metadata.expect("HESC v2 metadata");
        assert_eq!(metadata.counter, Some(before + 1));
        assert_eq!(metadata.gateway_public_key, raw_key(&public_key));
    }

    /// The escrow records the counter and the public key of the identity it
    /// carries, so the operator can check a recovery against them.
    #[test]
    #[cfg_attr(
        feature = "tpm",
        ignore = "needs the simulated TPM backend (the tpm feature selects the real device); run by the default-feature heliosd step"
    )]
    fn the_escrow_carries_the_counter_and_the_public_key() {
        let (operator_private_key, operator_public_key) =
            helios_escrow::generate_operator_keypair().expect("operator keypair");
        let network = NetworkConfig {
            escrow_public_key: Some(
                base64::engine::general_purpose::STANDARD.encode(operator_public_key),
            ),
            ..NetworkConfig::default()
        };
        let (private_key, public_key) = keypair();

        in_identity_dir("escrow-counter", |dir| {
            let tpm = tpm_in(dir);
            let _ = boot_secret(&tpm);
            let counter = anti_rollback::current(&tpm).expect("counter");

            write_escrow(&network, &private_key, &tpm);

            let blob = std::fs::read(dir.join("wg-key.escrow")).expect("escrow written");
            let metadata = helios_escrow::open_as_operator(operator_private_key.as_ref(), &blob)
                .expect("the operator opens the escrow")
                .metadata
                .expect("HESC v2 metadata");
            assert_eq!(metadata.counter, Some(counter));
            assert_eq!(metadata.gateway_public_key, raw_key(&public_key));
        });
    }

    #[test]
    fn initialization_preserves_an_existing_vault_without_rotation_or_secret() {
        if run_isolated_identity_scenario(
            "initialization_preserves_an_existing_vault_without_rotation_or_secret",
        ) {
            return;
        }
        let path = PathBuf::from(keystore_path());
        std::fs::write(&path, b"existing sealed bytes").expect("existing vault");

        let no_rotation = initialize(
            &NetworkConfig::default(),
            &BootDecision::Disabled,
            false,
            &TpmSettings::default(),
        )
        .expect_err("initialize must require explicit rotation");
        assert!(no_rotation.contains("Use --rotate"), "{no_rotation}");
        let unavailable_rotation = initialize(
            &NetworkConfig::default(),
            &BootDecision::Disabled,
            true,
            &TpmSettings::default(),
        )
        .expect_err("rotation still requires a TPM secret");
        assert!(
            unavailable_rotation.contains("no TPM secret"),
            "{unavailable_rotation}"
        );
        assert_eq!(std::fs::read(path).unwrap(), b"existing sealed bytes");
    }

    #[test]
    fn key_validation() {
        assert!(validate_wg_key(VALID).is_ok());
        assert!(validate_wg_key("not-base64").is_err());
        assert!(validate_wg_key("AAAA").is_err(), "invalid length");
        assert!(validate_wg_key("").is_err());
    }

    /// Without a vault or a key in the config, the gateway must say so
    /// clearly rather than starting with an empty identity.
    #[test]
    fn total_absence_of_key_is_reported() {
        let network = NetworkConfig::default();
        let resolved = resolve(&network, &BootDecision::Disabled, &TpmSettings::default());
        assert_eq!(resolved.origin, KeyOrigin::Missing);
        assert!(resolved.private_key.is_empty());
    }

    /// TPM disabled + plaintext key: it works, but reports the degraded mode
    /// (automatic sealing is impossible without a secret).
    #[test]
    fn plaintext_key_used_but_reported_degraded() {
        let network = NetworkConfig {
            wg_private_key: VALID.into(),
            ..NetworkConfig::default()
        };
        let resolved = resolve(&network, &BootDecision::Disabled, &TpmSettings::default());
        assert_eq!(resolved.origin, KeyOrigin::PlaintextConfig);
        assert_eq!(resolved.private_key.expose(), VALID);
    }

    /// Without a TPM secret, sealing is refused rather than silently failing.
    #[test]
    fn update_refused_without_tpm_secret() {
        assert!(update_sealed(
            &NetworkConfig::default(),
            &BootDecision::Disabled,
            VALID,
            &TpmSettings::default()
        )
        .is_err());
    }

    /// Without a TPM secret, no sealing is possible: refuse rather than
    /// create an identity that would end up in the clear somewhere.
    #[test]
    fn initialization_refused_without_tpm_secret() {
        let error = initialize(
            &NetworkConfig::default(),
            &BootDecision::Disabled,
            false,
            &TpmSettings::default(),
        )
        .expect_err("without a TPM secret, initialization must fail");
        assert!(error.contains("provision-tpm"), "message: {error}");
    }

    /// Overwriting a sealed identity cuts off the whole fleet: that cannot
    /// be the default behavior of an initialization command.
    #[test]
    fn initialization_refuses_to_overwrite_without_explicit_rotation() {
        assert!(reject_overwrite(true, false).is_err());
        assert!(reject_overwrite(true, true).is_ok(), "--rotate accepts it");
        assert!(reject_overwrite(false, false).is_ok(), "first boot");
    }

    #[test]
    fn update_refuses_an_invalid_key() {
        assert!(update_sealed(
            &NetworkConfig::default(),
            &BootDecision::Disabled,
            "not-a-key",
            &TpmSettings::default(),
        )
        .is_err());
    }
}
