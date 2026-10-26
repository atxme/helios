//! The operator half of ADR-008 §4.
//!
//! # What lives here, and what must not depend on it
//!
//! Everything that opens the authority vault or signs under `CA-PQ`: the vault
//! file itself, the FIDO2 gestures that unwrap a key-slot, and the objects
//! those gestures produce. This is the master-signing surface of the domain.
//!
//! It is a crate of its own so that the boundary is a dependency edge rather
//! than a convention. **Astra does not depend on it** — the server holds the
//! encrypted vault as opaque bytes and never opens it, which is the whole
//! point of §4. **The elevated engine does not depend on it either**: the
//! engine loads WireGuard-NT with administrator rights, and pulling the
//! master-signing primitives into that process would put them one bug away from
//! a privilege the operator never granted. The ceremony runs in the Orion UI,
//! which is not elevated, and speaks through the typed session of
//! [`aether::certificates::operator_session`].
//!
//! The terminal is not here either. Prompts, paths and arguments belong to
//! whatever drives this — a helper launched by Orion, or the compatibility CLI
//! kept while §8.5 still requires an offline transport.
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
/// Both live in `aether-fido` since Orion runs the approval itself: the
/// gesture receives no salt, so no `hmac-secret` output exists for it and no
/// key-slot can be unwrapped (§14.1). Keeping it here as well would be a
/// second copy of a security boundary.
pub use aether_fido::authenticator;
pub mod campaign;
pub mod credentials;
pub mod documents;
pub mod enrollment;
pub mod gestures;
pub mod handoff;
pub mod operations;
pub mod origin;
pub mod orion;
pub mod prepared;
pub mod signing;
pub mod store;
pub mod tunnel;
pub mod vault;
