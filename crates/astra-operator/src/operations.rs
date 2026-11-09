//! The ceremonies, as things a caller drives rather than as commands.
//!
//! Each one splits at the same seam: a verification that produces the typed
//! manifest §12.2 requires, and an approval that runs the gesture. Nothing
//! here prints, prompts, or reads a path from an argument — those belong to
//! whatever drives it, and the point of the split is that a terminal and a
//! window can both do so without either shape leaking into the other.

pub mod campaign;
pub mod issuer;
pub(crate) mod keys;

pub use keys::key_step_of_opening;
pub mod recovery;
pub mod revocation;
pub mod rotation;

#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures;

use aether::certificates::status::{AstraSignerResult, CampaignApproval};
use anyhow::{bail, Result};

/// The pinned origin wins; a disagreement refuses.
///
/// Not «the caller's value if given», and not «the pin if given»: either rule
/// silently picks a side of a disagreement that means one of the two is wrong
/// about which domain this is. Refusing is the only answer that does not
/// choose for the operator.
///
/// The caller that has no business choosing — the helper Orion launches —
/// passes `None`. The parameter exists for the compatibility CLI, whose flags
/// predate the hand-off field, and for a hand-off written before it existed.
pub(crate) fn resolve_authority_url(pinned: Option<&str>, offered: Option<&str>) -> Result<String> {
    match (pinned.map(str::trim), offered.map(str::trim)) {
        (Some(pinned), Some(offered))
            if pinned.trim_end_matches('/') != offered.trim_end_matches('/') =>
        {
            bail!(
                "ce coffre épingle l'origine « {pinned} » et on lui en présente « {offered} » : \
                 l'une des deux se trompe de domaine, et rien n'est signé tant que la question \
                 n'est pas tranchée"
            )
        }
        (Some(pinned), _) => Ok(pinned.to_string()),
        (None, Some(offered)) => Ok(offered.to_string()),
        (None, None) => bail!(
            "ce relais de domaine ne nomme pas l'origine de l'autorité : elle est écrite par \
             l'amorçage du domaine, et la prendre d'ailleurs reviendrait à laisser l'appelant \
             choisir où partent les signatures"
        ),
    }
}

/// Wraps what a ceremony produced into the one document §8.2 accepts.
///
/// Built here rather than by each gesture so the cases stay visibly the same
/// shape: an ordinary campaign carries an approval and nothing else, an anchor
/// campaign carries the same approval plus what `CA-PQ` signed under it. A
/// second document for the second case would be a second thing to keep equal
/// on the wire.
pub(crate) fn campaign_result(
    approval: &CampaignApproval,
    objects: Vec<aether::certificates::transport::TrustUpdateObject>,
    credential_registry: Option<Box<aether::certificates::approval::CredentialRegistry>>,
) -> AstraSignerResult {
    AstraSignerResult {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        approval: Box::new(approval.clone()),
        objects,
        credential_registry,
        issuer_authorization: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pin is the authority on where signatures go, and a caller that
    /// disagrees with it is a question, not an input.
    #[test]
    fn a_disagreement_about_the_origin_refuses_rather_than_choosing() {
        assert_eq!(
            resolve_authority_url(Some("https://a.example"), None).expect("pinned"),
            "https://a.example"
        );
        assert_eq!(
            resolve_authority_url(Some("https://a.example/"), Some("https://a.example"))
                .expect("same origin, one trailing slash"),
            "https://a.example/"
        );
        assert!(
            resolve_authority_url(Some("https://a.example"), Some("https://b.example")).is_err()
        );
        assert_eq!(
            resolve_authority_url(None, Some("https://b.example")).expect("legacy hand-off"),
            "https://b.example"
        );
        assert!(resolve_authority_url(None, None).is_err());
    }
}
