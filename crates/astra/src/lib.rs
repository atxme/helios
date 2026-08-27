//! **Astra** — the certificate authority coordinator of the v5 negotiation
//! PKI ([ADR-008](../../../docs/adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md)).
//!
//! Astra runs in its own container on the same machine as `heliosd`. That
//! co-location answers an operational fact — without this gateway, the trust
//! domain serves no traffic — and it is **not** a boundary against `root`. It
//! separates processes, files, capabilities and interfaces; it does not
//! separate the authority from whoever owns the kernel.
//!
//! # What Astra holds, and what it deliberately does not
//!
//! It holds the registry, the audit chain, the delegated issuer and the
//! encrypted master vault. It never holds `CA-PQ` in the clear: the vault is
//! opened on the operator's machine by the `astra-signer` companion against a
//! hardware credential, which signs and zeroizes. The only key usable here
//! without a human is [`issuer::DelegatedIssuer`], and every consumer checks
//! its scope before its signature.
//!
//! That bounds a host compromise rather than preventing one. An attacker with
//! `root` can use the delegated key until it expires, and can present a lying
//! campaign to the companion — which is why the companion displays the exact
//! manifest before signing. Protecting the operational issuer from the host
//! kernel too would need an HSM or an attested execution environment carrying
//! ML-DSA-87; no container, veth, mTLS or host-controlled vTPM provides it.
//!
//! # Limites connues
//!
//! Three integration parts of ADR-008 are not implemented, and are refused
//! explicitly rather than approximated:
//!
//! - **opening a campaign from the public origin**. The approval itself is
//!   live in both directions: in the tunnel through [`renewal`], and out of it
//!   through [`signing`] and the three capability-bound routes of §8.2. What
//!   stays `501` is `POST /v1/campaigns`, because §11.6 has that route
//!   *resolve* a campaign over the fleet's current targets — on an
//!   unauthenticated public route, that answers every caller with the domain's
//!   inventory, and the authentication it would need is not settled anywhere.
//!   `astra campaign open` does the resolution locally instead. Recovery of an
//!   expired identity answers `501` for its own reason: it needs the
//!   historical validator of §7.5;
//! - the **objects that would travel on the private veth channel**. The
//!   channel itself exists: [`gateway`] dials `heliosd`'s
//!   `/internal/v1/certificates/*` listener under mutually authenticated TLS
//!   1.3 with pinned identities, no resumption and no 0-RTT, and `astra run`
//!   opens it — and checks its pin — at startup. What is missing is what would
//!   be sent: issuing a staging authorization needs the operator approval
//!   above. The reverse relay of the 15 August 2026 amendment, in which
//!   `heliosd` forwards an active Orion's canonical request to Astra, has no
//!   Astra-side route in §8.3 and is a specification change rather than an
//!   implementation gap;
//! - the **end-to-end orchestration** which joins approval, delegated issuance,
//!   gateway staging, receipt, grant and commit without exposing a direct Astra
//!   route to an Orion whose tunnel still works.
//!
//! See [`docs/testing/TESTING.md`](../../../docs/testing/TESTING.md) for what
//! a WSL2 build does and does not prove.

pub mod audit;
pub mod distribution;
pub mod gateway;
pub mod issuer;
pub mod operations;
pub mod planner;
pub mod recovery;
pub mod registry;
pub mod renewal;
pub mod service;
pub mod signing;
pub mod vault;

pub use audit::{AuditChain, AuditEvent};
pub use issuer::DelegatedIssuer;
pub use registry::{AstraRegistry, AstraState, PeerRecord};
