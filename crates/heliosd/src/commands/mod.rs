//! One-shot operator commands: everything `heliosd` does and then exits.
//!
//! Each module is one domain the console acts on — the TPM vault and its
//! update window, the identities this gateway serves, the certificate
//! registry, local admission, and the WAN interface.

pub(crate) mod identity;
pub(crate) mod peer;
pub(crate) mod tpm;
pub(crate) mod trust;
pub(crate) mod wan;
