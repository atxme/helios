//! Enrollment of Orion clients on the Helios gateway side (ADR-001, §4).
//!
//! WireGuard provides neither rich authentication (X.509/EAP) nor built-in
//! dynamic addressing: this crate explicitly provides what WireGuard doesn't
//! give for free. It runs **on the gateway** — its client is Orion, but the
//! service lives here. The primitives shared by both ends (the ML-KEM
//! exchange) live in [`aether::pq`], not here, so `orion-core` never has to
//! depend on a `helios-*` crate.
//!
//! # Enrollment = admission + provisioning
//!
//! The two are not automated the same way, and conflating them leads to an
//! impossible design:
//!
//! * **Admission** (first contact) — a client whose public key is unknown
//!   cannot bring up the tunnel: WireGuard is built on Noise_IK, the
//!   responder rejects an initiator it doesn't know. Admission is therefore
//!   **necessarily out of band**: an operator declares the public key in
//!   `peers`, via [`admission`]. Its VIP is deterministically derived from it
//!   by [`ipam`], with no state on disk.
//! * **Provisioning** ([`session`]) — once the classical tunnel is up, the
//!   control channel *inside* the tunnel automates the ML-KEM exchange, the
//!   derivation of the post-quantum PSK, and confirmation of the VIP.
//!
//! The protocol messages and PSK derivation live in [`aether::enroll`], since
//! the client has to share them.
//!
//! # Transport: no TLS, and it's deliberate
//!
//! ADR-001 planned a dedicated TLS 1.3 channel, TPM-anchored. It was
//! **dropped at implementation time**: the channel lives inside the
//! WireGuard tunnel anyway, which already provides confidentiality and
//! mutual authentication. The full reasoning is at the top of
//! `helios-api::provision` and `orion_core::provisioning`. The real
//! transport is therefore `POST /api/provision` on the existing HTTP server,
//! itself also behind the tunnel.
//!
//! The TPM intent remains valid but targets a different secret:
//! `wg_private_key`, the gateway's real identity, today stored in clear in
//! `network.toml`.
//!
//! # PSK installation: the order is a safety invariant
//!
//! The derived PSK is installed on the data plane **before** being announced
//! to the client. WireGuard has only one PSK slot per peer: a value present
//! on only one side makes *every* subsequent handshake fail, and the control
//! channel that would allow recovery lives precisely in the tunnel that just
//! died.
//!
//! The chain is therefore fail-closed end to end: `helios-api::provision`
//! forwards the PSK to the orchestrator via [`aether::InstallPskRequest`] and
//! waits for its acknowledgement; the orchestrator only acknowledges it after
//! a successful `sync_peers`, and rolls back its in-memory change otherwise.
//! Any failure results in a refused request, leaving the classical tunnel
//! intact rather than creating an orphaned PSK.
//!
//! On the client side, `orion_core::backend` only installs the PSK once this
//! response is received, via an idempotent `up()` that never tears down the
//! adapter.
//!
//! # Known limitation: the derived VIP is not reconciled
//!
//! [`ipam::assign_vip`] derives the VIP from the peer's public key and never
//! consults the address declared in `network.toml`. The two can diverge.
//! Neither end arbitrates: the gateway keeps the address the operator
//! declared, the client keeps the one from its profile, and the discrepancy
//! is logged on both sides. Reconciling requires deciding who has
//! authority — the operator or the derivation — which is beyond the scope of
//! provisioning.
//!
//! [`admission::admit`] **reduces** this gap without eliminating it: it
//! declares precisely the address the IPAM derives, so a peer admitted this
//! way does not diverge. What remains are entries written by hand into
//! `network.toml`, for which the above limitation still holds.

pub mod admission;
pub mod certificates;
pub mod ipam;
pub mod rotation;
pub mod session;

pub use admission::{admit_with_key_negotiation, revoke, AdmissionError};
pub use ipam::{assign_vip, derive_cgnat_ip, IpamError, PeerTable, MAX_VIP_PROBES, POOL_SIZE};
pub use rotation::{RotationAction, RotationState, REVERT_AFTER};
pub use session::{
    handle_request, AdmittedPeers, GatewayIdentity, Provisioned, DEFAULT_PSK_LIFETIME_SECS,
};
