use crate::framing::ClientMessage;

/// The historical validator of an expired identity has no door on this
/// transport (spec §7.5, §14.1).
///
/// Recovery is an Astra decision, reached over the veth after an operator
/// ceremony. QUIC carries three messages, its vocabulary is closed, and a
/// recovery request is not a message it can be asked to read — so an
/// expired leaf stays refused here for want of anything to present it to.
#[test]
fn the_quic_vocabulary_holds_no_recovery_message() {
    // The whole vocabulary, and the only member that needs no signed
    // material to build.
    assert!(serde_json::from_str::<ClientMessage>(
        r#"{"type":"challenge_request","protocol_version":5}"#
    )
    .is_ok());

    // A recovery request has no discriminant here.
    for smuggled in [
        r#"{"type":"expired_certificate_recovery_request"}"#,
        r#"{"type":"recovery"}"#,
        r#"{"type":"historical_certificate"}"#,
    ] {
        assert!(
            serde_json::from_str::<ClientMessage>(smuggled).is_err(),
            "the transport accepted {smuggled}"
        );
    }

    // Nor can one ride inside a message that does exist: the frames deny
    // unknown fields, so a historical proof appended to a legal request is
    // a frame the transport never parses.
    assert!(serde_json::from_str::<ClientMessage>(
        r#"{"type":"challenge_request","protocol_version":5,"historical_certificate":"x"}"#
    )
    .is_err());
}
