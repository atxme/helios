//! The operator companion of ADR-008 §4, as a library.
//!
//! Split from the binary so the parts that have nothing to do with a terminal
//! — the security-key boundary, the authority gestures and the vault file —
//! are reachable from tests. The binary is the prompts; this is what they act
//! on.
//!
//! See [`authenticator`] for what a security key does here, and what it never
//! does.

pub mod authenticator;
pub mod gestures;
pub mod handoff;
pub mod store;
