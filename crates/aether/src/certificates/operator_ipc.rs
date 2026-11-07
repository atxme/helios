//! The campaign summary a prepared CA-TLS rotation records.
//!
//! This was the local protocol between Orion and the `astra-signer` companion.
//! Orion now runs that ceremony itself, so the channel is gone; only the
//! manifest stays, because records written by an older build carry it and a
//! resume must still read them.

use serde::{Deserialize, Serialize};

/// The public summary of the campaign a CA-TLS rotation approved, kept in the
/// prepared record so a resume can name it without fetching a closed campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AstraCaTlsManifest {
    pub reason: String,
    pub requested_by: String,
    pub fingerprint: String,
    pub current_ca_tls_epoch: u64,
    pub next_ca_tls_epoch: u64,
    pub activation_at: u64,
    pub not_after: u64,
    pub outgoing_anchor_fingerprint: String,
    pub affected_ca: String,
    pub target_count: usize,
}
