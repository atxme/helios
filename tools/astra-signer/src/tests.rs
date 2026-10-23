use super::*;
use aether::certificates::authority::ClientTlsCaTransition;
use aether::certificates::encoding::{
    DerCertificate, Fingerprint, MlDsa87Signature, TrustDomainId,
};
use aether::certificates::transport::TrustUpdateObject;
use aether::certificates::window::TransitionWindow;
use aether::certificates::CERTIFICATE_FORMAT_VERSION;

fn transition() -> ClientTlsCaTransition {
    ClientTlsCaTransition {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
        ca_epoch: 1,
        current_ca_tls_epoch: 1,
        next_ca_tls_epoch: 2,
        active_client_tls_ca_fingerprint: Fingerprint::of(b"ancre sortante"),
        next_client_tls_ca_certificate: DerCertificate::new(vec![0x30, 0x03, 0x02, 0x01, 0x00])
            .expect("certificate"),
        window: TransitionWindow {
            not_before: 10,
            activation_at: 20,
            not_after: 30,
        },
        ca_pq_signature: MlDsa87Signature::new(vec![7; 4627]).expect("signature"),
    }
}

/// The operator's copy is what `heliosd install-*` reads, so it carries no
/// routing envelope.
///
/// The tag `TrustUpdateObject` adds is how Astra's registry tells one
/// decision from another; the gateway readers take one concrete type and
/// refuse an unknown `kind`. Writing the envelope produced a file the very
/// command this companion printed could not parse — which is the failure
/// this test exists to keep from coming back.
#[test]
fn the_file_written_for_the_gateway_carries_no_routing_envelope() {
    let object = TrustUpdateObject::ClientTlsCaTransition(Box::new(transition()));
    let encoded = document_nu(&object).expect("encoding");

    let value: serde_json::Value = serde_json::from_slice(&encoded).expect("readable JSON");
    assert!(
        value.get("kind").is_none(),
        "the gateway reader refuses an unknown `kind` field"
    );
    let parsed: ClientTlsCaTransition =
        serde_json::from_slice(&encoded).expect("the gateway must be able to read this file");
    assert_eq!(parsed.next_ca_tls_epoch, 2);
}

/// A rotation window is a date an operator diaries, not a raw counter.
#[test]
fn a_window_bound_is_printed_as_a_date() {
    assert_eq!(horodatage(1_791_792_171), "2026-10-12 10:02 CEST");
    // Out of range is named rather than silently rendered as an epoch.
    assert!(horodatage(u64::MAX).contains("hors plage"));
}

/// The five enrollment gestures parse as an operator types them, and an
/// invitation cannot outlive the 24 hours §15.2 allows.
#[test]
fn enroll_subcommands_parse() {
    use clap::Parser as _;

    for line in [
        "astra-signer enroll invite --gateway-certificate gw.json --out a.helios-invite",
        "astra-signer enroll invite --gateway-certificate gw.json --valid-for-hours 2 \
         --allow-readmission --out a.helios-invite",
        "astra-signer enroll accept --request a.helios-request --out-dir leaves",
        "astra-signer enroll sign-document --draft draft.json --out a.orion",
        "astra-signer enroll list",
        "astra-signer enroll revoke 01010101010101010101010101010101",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_ok(), "{line}");
    }
    for refused in [
        "astra-signer enroll invite --gateway-certificate gw.json --valid-for-hours 25 --out a",
        "astra-signer enroll invite --gateway-certificate gw.json --valid-for-hours 0 --out a",
        "astra-signer enroll accept --request a.helios-request",
    ] {
        let words: Vec<&str> = refused.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_err(), "{refused}");
    }
}

#[test]
fn a_fingerprint_is_shown_in_groups_of_four() {
    assert_eq!(grouped_hex("0123456789abcdef"), "0123 4567 89ab cdef");
}

#[test]
fn a_shell_word_survives_quotes_and_spaces() {
    assert_eq!(shell_word("laptop-alice"), "laptop-alice");
    assert_eq!(shell_word("poste d'alice"), "'poste d'\\''alice'");
}
