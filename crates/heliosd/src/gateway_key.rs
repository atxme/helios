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
//! becomes undecipherable. [Escrow](helio_tpm::escrow) covers this case: a
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
    SealedKeystore::new(PathBuf::from(KEYSTORE_PATH))
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

    match helio_tpm::escrow::seal_to_operator(&pubkey, private_key.as_bytes()) {
        Ok(blob) => match write_atomic(ESCROW_PATH, &blob) {
            Ok(()) => info!(
                "WireGuard key escrow written to {ESCROW_PATH} — \
                 retrieve it and keep it off the gateway"
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
    let path = PathBuf::from(RECOVERY_PATH);
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
    if let Err(e) = keystore().store(secret, key.as_bytes()) {
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
            Some(secret) => match store.load(secret) {
                Ok(bytes) => match String::from_utf8(bytes.to_vec()) {
                    Ok(key) => {
                        info!("WireGuard key loaded from the sealed TPM vault");
                        let key = key.trim().to_string();
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
            match store.store(secret, plain.as_bytes()) {
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
    store
        .store(secret, keypair.private_key.expose().as_bytes())
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

    keystore()
        .store(secret, key.as_bytes())
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

    const VALID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

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
