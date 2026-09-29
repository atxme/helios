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
