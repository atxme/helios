//! Boot integrity validator through **TPM sealing** (TPM Sealing).
//!
//! Security model (see `docs/` and the lifecycle specification):
//!
//! - **Provisioning (TOFU, factory)**: a 256-bit secret is generated then
//!   *sealed* by the TPM against the PCR state (0/4/7). The sealed blob is
//!   stored on the configuration partition.
//! - **Production boot**: an *unseal* is attempted. The TPM only returns the
//!   secret if the hardware PCRs match those at sealing time. Otherwise
//!   (tampered bootloader/kernel) -> `TPM2_RC_POLICY_FAIL`, the secret stays
//!   locked.
//! - **OTA update**: the OTA changes the kernel -> the PCRs change -> unseal
//!   legitimately fails. Resealing is only authorized by a **signed ticket**
//!   (Ed25519 **and** ML-DSA-65) verified against the publisher's compiled
//!   keyring. This closes the TOFU gap in the field (an attacker cannot force
//!   a fake "first boot" to seal their own malicious kernel).
//!
//! The unsealed secret is not just a gate: it **decrypts the WireGuard
//! credentials** before the interface comes up. Tampering with the binary
//! therefore does not yield the key — the guarantee is hardware-based, not
//! software-based.
//!
//! ## WSL2 / target split
//!
//! All decision logic (boot flow, hybrid ticket, blob store, anti-replay) is
//! testable on WSL2 via `tpm_interface::DryRunTpm`. The real backend
//! (`feature tpm`, `tpm_interface::TpmDevice`) can run against a software TPM
//! to verify its ESAPI command flow. Secure Boot measurements, hardware-bus
//! protection, and persistence still require target trials — like the
//! firewall's Netlink effects.

mod blob_store;
mod boot_controller;
#[cfg(test)]
mod escrow_recovery_tests;
pub mod keystore;
mod provisioning;
mod reseal_ticket;
mod secret;
mod settings;
mod tpm_interface;
#[cfg(feature = "tpm")]
mod tpm_real;
mod update_window;

pub use boot_controller::{BootController, BootDecision};
pub use keystore::{
    Context, KeystoreError, SealedKeystore, DOMAIN_GATEWAY_WG_KEY, DOMAIN_KEY_NEGOTIATION_IDENTITY,
};
pub use secret::SecretKey;
pub use settings::TpmSettings;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TpmError {
    #[error("TPM connection failed: {0}")]
    Connection(String),

    #[error("PCR {index} read failed: {cause}")]
    PcrRead { index: u8, cause: String },

    #[error("secret generation (CSPRNG) failed: {0}")]
    Rng(String),

    #[error("I/O on {path}: {cause}")]
    Io { path: String, cause: String },

    #[error("serialization/deserialization: {0}")]
    Serde(String),

    #[error(
        "sealed blob missing outside provisioning — security anomaly \
         (an attacker may have deleted it to force a fake first boot)"
    )]
    MissingBlobOnField,

    #[error("unseal refused by the TPM (PCRs changed) — TPM2_RC_POLICY_FAIL")]
    UnsealPolicyFail,

    #[error("unseal failed and no valid reseal ticket is present")]
    UnsealFailedNoTicket,

    #[error("invalid reseal ticket signature")]
    TicketInvalidSignature,

    #[error("reseal ticket rejected (anti-replay): version {ticket} <= current {current}")]
    TicketRollback { ticket: u64, current: u64 },

    #[error("reseal ticket bound to a PCR state different from the current one")]
    TicketPcrMismatch,

    #[error("malformed update-window payload: {0}")]
    UpdateWindowMalformed(&'static str),

    #[error("update window expired (deadline {deadline}, now {now}) — arm a new one")]
    UpdateWindowExpired { deadline: u64, now: u64 },

    #[error("update window armed for another sealed identity — refused")]
    UpdateWindowForeign,

    #[error(
        "no update window is armed: arming one requires a nominal unseal, \
         which has not happened on this boot"
    )]
    UpdateWindowUnavailable,

    #[error("update-window state is uncertain and could not be safely cleaned up: {0}")]
    UpdateWindowCleanupFailed(String),

    #[error(transparent)]
    Keystore(#[from] keystore::KeystoreError),

    #[error("real TPM operation not implemented ({0}) — to be validated on target")]
    NotImplemented(&'static str),
}

pub type Result<T> = std::result::Result<T, TpmError>;
