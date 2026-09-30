//! Import of Orion profiles from an exchange document.
//!
//! Two formats are accepted: versioned Orion JSON, intended for Helios tools,
//! and the single-peer `wg-quick` format. Import persists nothing: it
//! produces a validated [`ClientProfile`] that the UI presents as a draft.

// Named by the module documentation above, and by nothing else: an intra-doc
// link only resolves in the scope it is written in.
#[allow(unused_imports)]
use crate::ClientProfile;

mod document;
mod field_rules;
mod json;
mod validation;
mod wg_quick;

pub use document::{
    complete_profile_import, parse_profile_import, read_profile_import_path, CompletedImport,
    ProfileImport, MAX_PROFILE_IMPORT_BYTES,
};
pub use field_rules::{
    normalize_cidr_list, split_cidr_list, tunnel_capture, validate_allowed_ips,
    validate_ssh_target, TunnelCapture,
};
pub use json::{PROFILE_IMPORT_FORMAT, PROFILE_IMPORT_VERSION};
pub use validation::{inspect_profile, ProfileIssues};

use validation::validate_imported_profile;

/// The §19 discriminant, defined with the profile model it belongs to.
///
/// Re-exported here because a document is where it is first read.
pub use crate::config::ProfileKind;

#[cfg(test)]
mod tests;
