//! The `type` discriminant of spec §19: declared, inferred, and refused when
//! the claim and the document disagree.

use aether::key_negotiation::ProtectionMode;

use super::fixtures::{document_of_kind, document_with, gateway_settings};
use crate::profile_import::parse_profile_import;
use crate::ProfileKind;

/// The discriminant of spec §19: a claim and a content that disagree are
/// refused, in both directions.
///
/// Inference reads a **presence** as an **intention**, and the two come
/// apart in the direction that matters: a negotiation block dropped by an
/// editor arrives looking exactly like a deliberate classic profile, and
/// Orion would mount a tunnel with no pre-WireGuard authentication and
/// report nothing.
#[test]
fn a_declared_kind_that_contradicts_the_document_is_refused() {
    let settings = serde_json::to_value(gateway_settings(ProtectionMode::MlKem)).unwrap();

    let error = parse_profile_import(
        &document_of_kind("helios_key_negotiation", None),
        "portable.orion",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("ne porte pas de bloc de négociation"));

    let error = parse_profile_import(
        &document_of_kind("classic", Some(settings.clone())),
        "portable.orion",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("se déclare « classic »"));

    // And the two consistent documents import.
    parse_profile_import(&document_of_kind("classic", None), "portable.orion")
        .expect("a declared classic profile without a block");
    parse_profile_import(
        &document_of_kind("helios_key_negotiation", Some(settings)),
        "portable.orion",
    )
    .expect("a declared Helios profile with its block");
}

/// After import the kind is a **recorded fact**, never re-derived.
///
/// A document written before §19 declares nothing, and the historical
/// inference is applied here — once, at the single point that turns a
/// document into a profile. Everything downstream reads the answer.
#[test]
fn an_undeclared_document_is_stamped_at_import() {
    let settings = serde_json::to_value(gateway_settings(ProtectionMode::MlKem)).unwrap();

    let helios = parse_profile_import(&document_with(settings), "portable.orion")
        .expect("a document without the field still imports");
    assert_eq!(
        helios.profile.profile_type,
        Some(ProfileKind::HeliosKeyNegotiation),
        "the block resolved the kind, and the answer is written down"
    );

    let classic = parse_profile_import(&document_of_kind("classic", None), "portable.orion")
        .expect("a declared classic document imports");
    assert_eq!(classic.profile.profile_type, Some(ProfileKind::Classic));
}

/// The document spells it `type`, and the former name keeps being read.
///
/// A spelling change must not make an already-written document
/// unintelligible — that is exactly the class of failure this whole field
/// exists to prevent.
#[test]
fn the_former_spelling_of_the_discriminant_is_still_accepted() {
    let document = document_of_kind("classic", None).replace("\"type\"", "\"profile_type\"");
    let imported =
        parse_profile_import(&document, "portable.orion").expect("the alias is accepted");
    assert_eq!(imported.profile.profile_type, Some(ProfileKind::Classic));
}

/// A document written before §19 declares nothing, and is still inferred.
/// That arm is what the discriminant exists to retire, not to break.
#[test]
fn a_document_without_a_declared_kind_is_still_inferred() {
    let settings = serde_json::to_value(gateway_settings(ProtectionMode::MlKem)).unwrap();
    let imported = parse_profile_import(&document_with(settings), "portable.orion")
        .expect("a document written before the discriminant");
    assert!(imported.profile.key_negotiation.is_some());
}
