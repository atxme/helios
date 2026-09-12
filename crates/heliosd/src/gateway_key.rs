//! Gateway's WireGuard private key: sealed loading and update.
//!
//! # Why the key no longer lives in `network.toml`
//!
//! `wg_private_key` is the gateway's **cryptographic identity**: it is what
//! authenticates every WireGuard handshake. In the clear on disk, a stolen
//! disk is enough to impersonate the gateway. It is therefore moved into a
//! vault encrypted by the secret sealed in the TPM ([`helio_tpm::keystore`]):
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
//! becomes undecipherable. [`helios_escrow`] covers this case: a
//! copy of the key, encrypted to the operator's public key, is written on
//! every sealing. The operator opens it offline, deposits the key into a
//! recovery file delivered **with the OTA bundle** — the same channel as the
//! resealing ticket — and the gateway reseals it at startup.
//!
//! Without escrow configured (`escrow_public_key` absent), the key is
//! permanently lost in this case and recovery becomes manual again.

use std::path::PathBuf;

use aether::NetworkConfig;
use helio_tpm::{BootDecision, KeystoreError, SealedKeystore, TpmError};
use tracing::{info, warn};

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

/// Recovery file, delivered by the operator with the OTA bundle — the same
/// channel as the resealing ticket, hence **no SSH required**.
///
/// Contains the WireGuard private key in base64. Consumed **only once**, and
/// only if the vault is actually undecipherable; erased immediately after.
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
pub struct ResolvedKey {
    /// Private key in base64, ready for the data plane. Empty if `Missing`.
    pub private_key: String,
    pub origin: KeyOrigin,
}

fn keystore() -> SealedKeystore {
    SealedKeystore::new(
        PathBuf::from(keystore_path()),
        helio_tpm::DOMAIN_GATEWAY_WG_KEY,
    )
}

/// Object context of the gateway identity vault: its own WireGuard public key.
///
/// It is what stops a vault from being opened as another gateway's, and it is
/// derivable from the very secret the vault holds — which is why reading goes
/// through `load_declared` and compares afterwards (ADR-006 §2).
fn identity_context(private_key: &str) -> Result<helio_tpm::Context, String> {
    let public = aether::wg::public_from_private(private_key)
        .map_err(|e| format!("deriving the gateway public key: {e}"))?;
    Ok(helio_tpm::Context::new().field("wg_public_key", public.as_bytes()))
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
fn write_escrow(network: &NetworkConfig, private_key: &str) {
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

    match helios_escrow::seal_to_operator(&pubkey, private_key.as_bytes()) {
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
/// that would be an identity substitution vector.
fn try_recovery(secret: &helio_tpm::SecretKey) -> Option<String> {
    let path = PathBuf::from(recovery_path());
    if !path.exists() {
        return None;
    }

    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            warn!("unreadable recovery file: {e}");
            return None;
        }
    };
    let key = raw.trim().to_string();

    if let Err(e) = validate_wg_key(&key) {
        warn!("invalid recovery file ({e}) — ignored, not consumed");
        return None;
    }

    // Reseals immediately under the new TPM secret.
    let context = match identity_context(&key) {
        Ok(context) => context,
        Err(e) => {
            warn!("recovered key unusable ({e}) — ignored, not consumed");
            return None;
        }
    };
    if let Err(e) = keystore().store(secret, &context, key.as_bytes()) {
        warn!("could not reseal the recovered key: {e}");
        return None;
    }

    // Then erases: the key must not stay in the clear on disk longer than
    // this startup. A deletion failure is an anomaly to report loudly.
    match std::fs::remove_file(&path) {
        Ok(()) => info!("recovery file consumed and erased"),
        Err(e) => warn!(
            "FAILED TO ERASE {RECOVERY_PATH} ({e}) — the private key remains \
             IN THE CLEAR on disk, delete it manually without delay"
        ),
    }

    warn!("WireGuard identity restored from escrow and resealed");
    Some(key)
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
pub fn resolve(network: &NetworkConfig, boot: &BootDecision) -> ResolvedKey {
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
                Ok((declared, bytes)) => match String::from_utf8(bytes.to_vec()) {
                    Ok(key) => {
                        let key = key.trim().to_string();
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
                                return ResolvedKey {
                                    private_key: String::new(),
                                    origin: KeyOrigin::Missing,
                                };
                            }
                            ContextVerdict::UnusableKey(cause) => {
                                warn!("unusable vault content ({cause})");
                                return ResolvedKey {
                                    private_key: String::new(),
                                    origin: KeyOrigin::Missing,
                                };
                            }
                        }
                        info!("WireGuard key loaded from the sealed TPM vault");
                        // Escrow follows the key: if the escrow configuration
                        // was just added, it is created on this very startup.
                        write_escrow(network, &key);
                        return ResolvedKey {
                            private_key: key,
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
                    if let Some(key) = try_recovery(secret) {
                        write_escrow(network, &key);
                        return ResolvedKey {
                            private_key: key,
                            origin: KeyOrigin::Recovered,
                        };
                    }
                    warn!(
                        "no usable recovery file in {RECOVERY_PATH}. Open the escrow \
                         {ESCROW_PATH} with the operator's private key, deposit the \
                         recovered key into this file (delivered with the OTA bundle, \
                         like the resealing ticket) and restart."
                    );
                }
                Err(e) => warn!("could not read the vault: {e}"),
            },
        }
    }

    // 2. Fall back to the plaintext key from the config — degraded mode.
    let plain = network.wg_private_key.trim();
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
                    return ResolvedKey {
                        private_key: String::new(),
                        origin: KeyOrigin::Missing,
                    };
                }
            };
            match store.store(secret, &context, plain.as_bytes()) {
                Ok(()) => {
                    info!(
                        "key sealed into {KEYSTORE_PATH} — remove `wg_private_key` from network.toml"
                    );
                    write_escrow(network, plain);
                }
                Err(e) => warn!("automatic sealing failed: {e}"),
            }
        } else {
            warn!("no TPM secret available: the key stays in the clear");
        }
        return ResolvedKey {
            private_key: plain.to_string(),
            origin: KeyOrigin::PlaintextConfig,
        };
    }

    // 3. Nothing usable.
    ResolvedKey {
        private_key: String::new(),
        origin: KeyOrigin::Missing,
    }
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
    write_escrow(network, keypair.private_key.expose());

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
    let old_key = network.wg_private_key.trim();
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

    // Escrow must follow the new key: otherwise a post-OTA recovery would
    // restore the old identity, which no client expects anymore.
    write_escrow(network, key);

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
    use base64::Engine as _;

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
        helio_tpm::Context::new()
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
        let mislabelled = helio_tpm::Context::new()
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
            write_escrow(&network, &wg_private);
            let blob = std::fs::read(dir.join("wg-key.escrow")).expect("escrow written");
            assert!(
                !blob
                    .windows(wg_private.len())
                    .any(|w| w == wg_private.as_bytes()),
                "the escrow holds the key in the clear"
            );
            let opened = helios_escrow::open_as_operator(private_key.as_ref(), &blob)
                .expect("the operator must be able to open it");
            assert_eq!(opened.as_slice(), wg_private.as_bytes());
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
            write_escrow(&network, &first);
            let before = std::fs::read(dir.join("wg-key.escrow")).expect("first escrow");
            write_escrow(&network, &second);
            let after = std::fs::read(dir.join("wg-key.escrow")).expect("second escrow");
            assert_ne!(before, after, "the escrow was not rewritten");
        });
    }

    /// A missing escrow key removes a recovery option; it must not stop the
    /// gateway, and it must not write anything either.
    #[test]
    fn an_absent_escrow_key_is_reported_without_writing() {
        in_identity_dir("escrow-absent", |dir| {
            write_escrow(&NetworkConfig::default(), VALID);
            write_escrow(
                &NetworkConfig {
                    escrow_public_key: Some("   ".into()),
                    ..NetworkConfig::default()
                },
                VALID,
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
            );
            assert!(!dir.join("wg-key.escrow").exists());
        });
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
        let resolved = resolve(&network, &BootDecision::Disabled);
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
        let resolved = resolve(&network, &BootDecision::Disabled);
        assert_eq!(resolved.origin, KeyOrigin::PlaintextConfig);
        assert_eq!(resolved.private_key, VALID);
    }

    /// Without a TPM secret, sealing is refused rather than silently failing.
    #[test]
    fn update_refused_without_tpm_secret() {
        assert!(update_sealed(&NetworkConfig::default(), &BootDecision::Disabled, VALID).is_err());
    }

    /// Without a TPM secret, no sealing is possible: refuse rather than
    /// create an identity that would end up in the clear somewhere.
    #[test]
    fn initialization_refused_without_tpm_secret() {
        let error = initialize(&NetworkConfig::default(), &BootDecision::Disabled, false)
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
            "not-a-key"
        )
        .is_err());
    }
}
