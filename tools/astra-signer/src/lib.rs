//! The operator companion of ADR-008 §4, as a library.
//!
//! Split from the binary so the parts that have nothing to do with a terminal
//! — the security-key boundary, the authority gestures and the vault file —
//! are reachable from tests. The binary is the prompts; this is what they act
//! on.
//!
//! See [`authenticator`] for what a security key does here, and what it never
//! does.

/// Stack the authority gestures run on.
///
/// ML-DSA-87 holds its working state on the stack, and a debug build copies
/// every intermediate rather than eliding it: key generation alone was
/// measured at **between 768 KiB and 1 MiB**. Windows gives a main thread
/// exactly 1 MiB where Linux gives 8 — so the same gesture lands just over the
/// edge there and nowhere else, which is the kind of defect that only appears
/// on the operator's machine, at the one command that cannot be retried
/// casually. It did.
///
/// Running the work on our own thread makes the size ours rather than the
/// platform's. It is a reservation, not an allocation: only the pages actually
/// touched are ever committed.
pub const WORK_STACK_BYTES: usize = 32 * 1024 * 1024;

/// The hardware boundary, and the one ceremony that opens no vault.
///
/// Both live in `helios-fido` since Orion runs the approval itself: the
/// gesture receives no salt, so no `hmac-secret` output exists for it and no
/// key-slot can be unwrapped (§14.1). Keeping it here as well would be a
/// second copy of a security boundary.
pub use helios_fido::authenticator;
pub mod authority;
pub mod campaign;
pub mod credentials;
pub mod documents;
pub mod gestures;
pub mod handoff;
pub mod origin;
pub mod prepared;
pub mod store;
pub mod tunnel;
