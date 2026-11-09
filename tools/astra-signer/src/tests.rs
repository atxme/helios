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

/// CLI-level constraints for the two approval transports. Handler tests cover
/// the complementary pair-completeness checks performed after parsing.
#[test]
fn approval_cli_accepts_complete_channels_and_refuses_mixed_or_incomplete_tunnels() {
    use clap::Parser as _;

    for line in [
        "astra-signer approve --request request.json --out approval.json",
        "astra-signer approve --heliosd-url http://100.64.0.1:8080 --operation-id 01010101010101010101010101010101",
        "astra-signer approve-campaign --campaign campaign.json --out approval.json",
        "astra-signer approve-campaign --authority-url https://astra.example --operation-id 01010101010101010101010101010101",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_ok(), "{line}");
    }

    for line in [
        "astra-signer approve --heliosd-url http://100.64.0.1:8080",
        "astra-signer approve --operation-id 01010101010101010101010101010101",
        "astra-signer approve --request request.json --heliosd-url http://100.64.0.1:8080 --operation-id 01010101010101010101010101010101",
        "astra-signer approve-campaign --authority-url https://astra.example",
        "astra-signer approve-campaign --operation-id 01010101010101010101010101010101",
        "astra-signer approve-campaign --campaign campaign.json --authority-url https://astra.example --operation-id 01010101010101010101010101010101",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_err(), "{line}");
    }
}

/// Required arguments, value enums, transport placement and numeric edges are
/// part of the operator interface: reject typos before any gesture starts.
#[test]
fn cli_rejects_missing_required_arguments_and_invalid_scalar_values() {
    use clap::{error::ErrorKind, Parser as _};

    for line in [
        "astra-signer init",
        "astra-signer enrol",
        "astra-signer remove",
        "astra-signer rename --slot abc",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            Cli::try_parse_from(&words)
                .err()
                .expect("CLI should reject input")
                .kind(),
            ErrorKind::MissingRequiredArgument,
            "{line}"
        );
    }

    for line in [
        "astra-signer domain --astra-service-key-epoch nope",
        "astra-signer issue-ca-tls --days nope",
        "astra-signer enroll invite --gateway-certificate gw --out invite --valid-for-hours 18446744073709551616",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            Cli::try_parse_from(&words).err().expect("CLI should reject input").kind(),
            ErrorKind::ValueValidation,
            "{line}"
        );
    }
}

#[test]
fn cli_unknown_enum_values_are_invalid_value_errors_after_required_args() {
    use clap::{error::ErrorKind, Parser as _};

    for line in [
        "astra-signer revoke --authority-url https://astra.example --operation-id op --scope server",
        "astra-signer revoke --authority-url https://astra.example --operation-id op --halves tls-pq",
        "astra-signer revoke --authority-url https://astra.example --operation-id op --reason unknown",
        "astra-signer abort-gateway-transition --authority-url https://astra.example --operation-id op --transition t --out o --reason unknown",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            Cli::try_parse_from(&words).err().expect("CLI should reject input").kind(),
            ErrorKind::InvalidValue,
            "{line}"
        );
    }
}

#[test]
fn global_transport_is_accepted_on_either_side_and_rejects_unknown_values() {
    use clap::Parser as _;

    for line in [
        "astra-signer --transport hid list",
        "astra-signer list --transport hid",
        "astra-signer --transport platform verify",
        "astra-signer verify --transport platform",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_ok(), "{line}");
    }
    for line in [
        "astra-signer --transport usb list",
        "astra-signer list --transport usb",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_err(), "{line}");
    }
}

#[test]
fn enrollment_lifetime_and_readmission_flag_edges_parse_correctly() {
    use clap::Parser as _;

    for line in [
        "astra-signer enroll invite --gateway-certificate gw --valid-for-hours 1 --out invite",
        "astra-signer enroll invite --gateway-certificate gw --valid-for-hours 24 --out invite",
        "astra-signer enroll accept --request req --validity-days 1 --out-dir leaves",
        "astra-signer enroll accept --request req --validity-days 365 --out-dir leaves",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_ok(), "{line}");
    }
    for line in [
        "astra-signer enroll invite --gateway-certificate gw --valid-for-hours 0 --out invite",
        "astra-signer enroll invite --gateway-certificate gw --valid-for-hours 25 --out invite",
        "astra-signer enroll invite --gateway-certificate gw --out invite --allow-readmission --valid-for-hours 0",
        "astra-signer enroll accept --request req --validity-days 0 --out-dir leaves",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        let parsed = Cli::try_parse_from(&words);
        if line.contains("valid-for-hours") {
            assert!(parsed.is_err(), "{line}");
        } else {
            assert!(parsed.is_ok(), "{line}");
        }
    }
}

#[test]
fn signing_commands_expose_mutually_exclusive_transport_options() {
    use clap::Parser as _;

    for line in [
        "astra-signer sign-gateway-transition --operation-id op --request req --out out --authority-url https://astra.example",
        "astra-signer sign-gateway-transition --operation-id op --request req --out out --heliosd-url http://100.64.0.1:8080",
        "astra-signer rotate-ca-tls --operation-id op --out out --authority-url https://astra.example",
        "astra-signer rotate-ca-tls --operation-id op --out out --heliosd-url http://100.64.0.1:8080",
        "astra-signer abort-gateway-transition --operation-id op --transition t --out out --authority-url https://astra.example",
        "astra-signer abort-gateway-transition --operation-id op --transition t --out out --heliosd-url http://100.64.0.1:8080",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_ok(), "{line}");
    }
    for line in [
        "astra-signer sign-gateway-transition --operation-id op --request req --out out --authority-url https://astra.example --heliosd-url http://100.64.0.1:8080",
        "astra-signer rotate-ca-tls --operation-id op --out out --authority-url https://astra.example --heliosd-url http://100.64.0.1:8080",
        "astra-signer abort-gateway-transition --operation-id op --transition t --out out --authority-url https://astra.example --heliosd-url http://100.64.0.1:8080",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_err(), "{line}");
    }
}

#[test]
fn approval_generation_and_optional_source_combinations_parse() {
    use clap::Parser as _;

    for line in [
        "astra-signer approve --request req --out out --active-generation 0",
        "astra-signer approve --request req --out out --active-generation 18446744073709551615",
        "astra-signer approve-campaign --campaign campaign --out out --origin https://astra.example",
        "astra-signer approve-campaign --authority-url https://astra.example --operation-id 00000000000000000000000000000000 --origin https://login.example",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_ok(), "{line}");
    }
    for line in [
        "astra-signer approve --request req --active-generation -1",
        "astra-signer approve --request req --active-generation 18446744073709551616",
        "astra-signer approve-campaign --authority-url https://astra.example --operation-id 00000000000000000000000000000000 --campaign campaign",
    ] {
        let words: Vec<&str> = line.split_whitespace().collect();
        assert!(Cli::try_parse_from(&words).is_err(), "{line}");
    }
}
