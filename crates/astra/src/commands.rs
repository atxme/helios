//! One-shot operator commands: everything Astra does and then exits.
//!
//! Each module is one thing an operator decides about — the trust domain's own
//! anchors, a rotation campaign over the fleet, the four-step certificate
//! chain, the gateway's identity, an emergency revocation, and the delegated
//! issuer.

mod campaign;
mod chain;
mod gateway_identity;
mod issuer;
mod revocation;
mod trust_domain;

pub(crate) use campaign::campaign_open;
pub(crate) use chain::{chain_abandon, chain_next, chain_open, chain_status};
pub(crate) use gateway_identity::{gateway_identity_open, gateway_identity_publish};
pub(crate) use issuer::{issuer_install, issuer_request};
pub(crate) use revocation::revocation_open;
pub(crate) use trust_domain::{bootstrap, pin_ca_tls, status};
