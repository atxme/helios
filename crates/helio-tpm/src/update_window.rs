//! Update window: carrying the **same** secret across one planned reboot.
//!
//! # Why it exists
//!
//! Sealing binds the secret to PCR 0/4/7. A kernel or bootloader upgrade
//! moves PCR 4, so the next boot cannot unseal. The existing answer is the
//! reseal ticket — but [`crate::provisioning::reseal`] generates a **new**
//! secret, which makes every vault encrypted under the old one unreadable:
//! the WireGuard identity, the key-negotiation identity, and through it the
//! static-PSK table. An `apt upgrade` that ships a kernel therefore costs the
//! re-enrollment of the whole fleet.
//!
//! That destruction is not inherent to the update; it is inherent to
//! *repairing after the fact*, when the secret is already gone. An OS upgrade
//! is the opposite situation: it is planned, and it runs on a machine whose
//! secret is unsealed and in memory. The window exploits that asymmetry — it
//! carries the same secret through the reboot, so nothing is re-keyed and no
//! client is touched.
//!
//! # What the TPM enforces
//!
//! The window is an independent **policy-protected NV slot**. The nominal
//! sealed object is untouched: same PCR 0/4/7 policy, same template, same
//! unseal path. Reading the NV slot chains three assertions:
//!
//! - `PolicyPCR(0, 7)` — the nominal selection minus PCR 4, which is the one
//!   the upgrade legitimately moves. Firmware substitution and Secure Boot
//!   being turned off still close this path.
//! - `PolicyNvWritten(true)` — valid here because the authorized entity is the
//!   NV index itself. It rejects an uninitialized slot.
//! - `PolicyCommandCode(TPM2_NV_Read)` — the policy serves nothing else.
//!
//! The index permits policy reads but never owner reads. Arming writes the
//! payload through a salted encrypted session; revocation overwrites it with
//! zeros inside the TPM. The disk only carries a non-secret deadline/anchor
//! marker, so restoring a disk copy cannot resurrect a spent window.
//!
//! # Limite connue
//!
//! An attacker with physical access who boots **another Secure-Boot-signed
//! OS on this machine while the window is open** unseals the secret. The TPM
//! cannot distinguish "the next boot" from "the attacker's boot": doing so
//! needs `TPM2_PolicyCounterTimer` over `resetCount`, which `tss-esapi` 7.7
//! does not expose (`// Missing function: PolicyCounterTimer`). Two things
//! reduce exposure. The window lasts one reboot when armed with `--reboot`,
//! and the timer overwrites the NV payload when it expires. A hostile read is
//! not detectable: `TPM2_NV_Read` cannot atomically read and erase, so the
//! attacker may copy the secret without changing the slot.
//!
//! Reaching `PolicyCounterTimer` through the raw `tss2_esys` bindings would
//! remove that residue; it would also put `unsafe` into the one module no
//! test can exercise. That trade is for ADR-007, not for this file.
//!
//! An upgrade that moves PCR 0 or 7 — firmware, Secure Boot database — is
//! **out of scope**: the window will not unseal and the boot falls back to
//! ticket plus escrow, exactly as today. That is the rare case; kernel and
//! bootloader upgrades are the frequent one.

use zeroize::Zeroizing;

use crate::{secret::SecretKey, Result, TpmError};

/// Magic of the payload held inside the TPM NV index.
const PAYLOAD_MAGIC: &[u8; 4] = b"HUPD";
/// Version of the protected payload.
const VERSION: u8 = 1;
/// `magic | version | deadline | anchor | secret`.
pub(crate) const PAYLOAD_LEN: usize = 4 + 1 + 8 + 32 + 32;

/// Magic of the non-secret disk marker.
const MARKER_MAGIC: &[u8; 4] = b"HUMK";
/// `magic | version | deadline | anchor`.
const MARKER_LEN: usize = 4 + 1 + 8 + 32;

/// What the window carries through the reboot.
pub(crate) struct WindowPayload {
    /// Unix seconds past which the window is refused.
    pub(crate) deadline: u64,
    /// SHA-256 of the nominal sealed blob when the window was armed.
    ///
    /// Consumption compares it with the blob actually on disk: a window
    /// armed for one identity must not resurrect a secret onto another. The
    /// TPM already binds the blob to this machine; this binds it to this
    /// *identity*.
    pub(crate) anchor: [u8; 32],
    pub(crate) secret: SecretKey,
}

impl WindowPayload {
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
        out.extend_from_slice(PAYLOAD_MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.deadline.to_be_bytes());
        out.extend_from_slice(&self.anchor);
        out.extend_from_slice(self.secret.as_bytes());
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PAYLOAD_LEN {
            return Err(TpmError::UpdateWindowMalformed("unexpected payload length"));
        }
        if &bytes[..4] != PAYLOAD_MAGIC {
            return Err(TpmError::UpdateWindowMalformed("wrong magic"));
        }
        if bytes[4] != VERSION {
            return Err(TpmError::UpdateWindowMalformed("unsupported version"));
        }
        let mut deadline = [0u8; 8];
        deadline.copy_from_slice(&bytes[5..13]);
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(&bytes[13..45]);
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes[45..]);
        let payload = Self {
            deadline: u64::from_be_bytes(deadline),
            anchor,
            secret: SecretKey::from_bytes(secret),
        };
        zeroize::Zeroize::zeroize(&mut secret);
        Ok(payload)
    }

    /// Refuses a window that outlived its deadline or names another identity.
    ///
    /// The same checks run on the non-secret marker before the TPM hands the
    /// payload back, then again here as a consistency check. They defend the
    /// gateway against consuming its own stale window, which is the case that
    /// actually happens: an upgrade prepared, then postponed, then forgotten.
    pub(crate) fn accept(&self, now: u64, anchor: &[u8; 32]) -> Result<()> {
        if now > self.deadline {
            return Err(TpmError::UpdateWindowExpired {
                deadline: self.deadline,
                now,
            });
        }
        if self.anchor != *anchor {
            return Err(TpmError::UpdateWindowForeign);
        }
        Ok(())
    }
}

/// Non-secret disk marker written before the NV payload is armed.
///
/// It lets the expiry service inspect the deadline without asking the TPM to
/// release the secret. The marker is cross-checked with the protected payload
/// before consumption, so changing it can only make the gateway refuse or
/// revoke a window; it cannot substitute another identity.
pub(crate) struct WindowMarker {
    pub(crate) deadline: u64,
    pub(crate) anchor: [u8; 32],
}

impl WindowMarker {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MARKER_LEN);
        out.extend_from_slice(MARKER_MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.deadline.to_be_bytes());
        out.extend_from_slice(&self.anchor);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MARKER_LEN {
            return Err(TpmError::UpdateWindowMalformed("unexpected marker length"));
        }
        if &bytes[..4] != MARKER_MAGIC {
            return Err(TpmError::UpdateWindowMalformed("wrong marker magic"));
        }
        if bytes[4] != VERSION {
            return Err(TpmError::UpdateWindowMalformed(
                "unsupported marker version",
            ));
        }
        let mut deadline = [0u8; 8];
        deadline.copy_from_slice(&bytes[5..13]);
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(&bytes[13..]);
        Ok(Self {
            deadline: u64::from_be_bytes(deadline),
            anchor,
        })
    }

    pub(crate) fn matches_payload(&self, payload: &WindowPayload) -> Result<()> {
        if self.deadline != payload.deadline || self.anchor != payload.anchor {
            return Err(TpmError::UpdateWindowForeign);
        }
        Ok(())
    }

    pub(crate) fn accept(&self, now: u64, anchor: &[u8; 32]) -> Result<()> {
        if now > self.deadline {
            return Err(TpmError::UpdateWindowExpired {
                deadline: self.deadline,
                now,
            });
        }
        if self.anchor != *anchor {
            return Err(TpmError::UpdateWindowForeign);
        }
        Ok(())
    }
}

/// Whether an NV data area still contains a live Helios window payload.
pub(crate) fn is_armed_payload(bytes: &[u8]) -> bool {
    bytes.len() == PAYLOAD_LEN && &bytes[..4] == PAYLOAD_MAGIC
}

/// Whether a short NV read identifies a live Helios window payload.
///
/// Status and nominal-boot cleanup only need this prefix. They deliberately
/// avoid copying the secret out of the TPM merely to answer a boolean.
pub(crate) fn is_armed_prefix(bytes: &[u8]) -> bool {
    bytes == PAYLOAD_MAGIC
}

/// SHA-256 anchor of a nominal sealed blob.
pub(crate) fn anchor_of(blob: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(blob);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(deadline: u64, anchor: [u8; 32]) -> WindowPayload {
        WindowPayload {
            deadline,
            anchor,
            secret: SecretKey::from_bytes([7u8; 32]),
        }
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let encoded = payload(1234, [9u8; 32]).encode();
        let decoded = WindowPayload::decode(&encoded).unwrap();

        assert_eq!(decoded.deadline, 1234);
        assert_eq!(decoded.anchor, [9u8; 32]);
        assert_eq!(decoded.secret.as_bytes(), &[7u8; 32]);
    }

    #[test]
    fn the_payload_has_the_fixed_nv_slot_size() {
        assert_eq!(payload(0, [0u8; 32]).encode().len(), PAYLOAD_LEN);
    }

    #[test]
    fn malformed_payloads_are_refused() {
        assert!(matches!(
            WindowPayload::decode(b"short"),
            Err(TpmError::UpdateWindowMalformed(_))
        ));

        let mut wrong_magic = payload(1, [0u8; 32]).encode().to_vec();
        wrong_magic[0] = b'X';
        assert!(matches!(
            WindowPayload::decode(&wrong_magic),
            Err(TpmError::UpdateWindowMalformed(_))
        ));

        let mut wrong_version = payload(1, [0u8; 32]).encode().to_vec();
        wrong_version[4] = 9;
        assert!(matches!(
            WindowPayload::decode(&wrong_version),
            Err(TpmError::UpdateWindowMalformed(_))
        ));
    }

    #[test]
    fn marker_round_trip_and_payload_binding() {
        let marker = WindowMarker {
            deadline: 1234,
            anchor: [9u8; 32],
        };
        let decoded = WindowMarker::decode(&marker.encode()).unwrap();

        assert_eq!(decoded.deadline, 1234);
        assert_eq!(decoded.anchor, [9u8; 32]);
        assert!(decoded.matches_payload(&payload(1234, [9u8; 32])).is_ok());
        assert!(matches!(
            decoded.matches_payload(&payload(1235, [9u8; 32])),
            Err(TpmError::UpdateWindowForeign)
        ));
    }

    #[test]
    fn only_a_complete_payload_is_reported_armed() {
        let encoded = payload(1234, [9u8; 32]).encode();
        assert!(is_armed_payload(&encoded));
        assert!(!is_armed_payload(&[]));
        assert!(!is_armed_payload(&[0u8; PAYLOAD_LEN]));
    }

    #[test]
    fn a_window_past_its_deadline_is_refused() {
        let payload = payload(100, [1u8; 32]);

        assert!(payload.accept(100, &[1u8; 32]).is_ok());
        assert!(matches!(
            payload.accept(101, &[1u8; 32]),
            Err(TpmError::UpdateWindowExpired {
                deadline: 100,
                now: 101
            })
        ));
    }

    #[test]
    fn a_window_armed_for_another_identity_is_refused() {
        assert!(matches!(
            payload(100, [1u8; 32]).accept(0, &[2u8; 32]),
            Err(TpmError::UpdateWindowForeign)
        ));
    }

    /// The anchor must actually distinguish two blobs, otherwise the check
    /// above is decorative.
    #[test]
    fn the_anchor_follows_the_blob() {
        assert_ne!(anchor_of(b"blob-a"), anchor_of(b"blob-b"));
        assert_eq!(anchor_of(b"blob-a"), anchor_of(b"blob-a"));
    }
}
