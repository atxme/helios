//! Registry transition tests grouped by decision family.
//!
//! The submodules keep each signed lifecycle decision close to the helpers and
//! assertions that define its behavior. Shared support is limited to registry
//! and campaign fixtures.

use super::*;

mod fixtures;
use fixtures::{anchor_campaign, anchored, campaign, Anchored};
mod ca_pq;
use ca_pq::transition;
mod client_tls_ca;
mod gateway;
mod trust_transitions;
