//! Shared constructors for the renewal tests: the active identity, the
//! transition window, a grant as Astra would build it, and a signed session.

use aether::certificates::authority::RotationReason;
use aether::certificates::client::{
    ClientCertificateRotationGrant, GatewayCertificateStageReceipt, IssuerKind,
};
use aether::certificates::encoding::{DerCertificate, Fingerprint, Id16, MlDsa87Signature};
use aether::certificates::window::TransitionWindow;
use aether::certificates::{CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION};
use aether::key_negotiation::{
    issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
};
use rcgen::{
    CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose,
};
use zeroize::Zeroizing;

use crate::certificate_renewal::{ActiveIdentity, RenewalSession};
use crate::certificates::TrustStore;
use crate::test_domain::*;

fn active_identity(domain: &Domain) -> ActiveIdentity {
    ActiveIdentity {
        pq_private_key: domain.active_client_private.clone(),
        tls_private_key_der: Zeroizing::new(vec![7; 64]),
    }
}

pub(super) fn window() -> TransitionWindow {
    TransitionWindow {
        not_before: NOW - 60,
        activation_at: NOW + 3_600,
        not_after: NOW + 30 * 86_400,
    }
}

/// A grant as Astra would build it, signed by `CA-PQ` under
/// [`IssuerKind::Master`] — the campaign path, which needs no delegation.
pub(super) fn grant(
    domain: &Domain,
    session: &RenewalSession,
    window: TransitionWindow,
) -> ClientCertificateRotationGrant {
    let request = session.request();

    // The leaf certifies the key the CSR proved possession of. Issuing
    // from a fresh key here would pass every signature check and fail the
    // one that matters.
    let csr =
        CertificateSigningRequestParams::from_der(&request.tls_csr.as_bytes().to_vec().into())
            .expect("csr");
    let mut params = csr.params.clone();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.not_before = seconds_since_epoch(window.not_before);
    params.not_after = seconds_since_epoch(window.not_after + 86_400);
    let leaf = CertificateSigningRequestParams {
        params,
        public_key: csr.public_key,
    }
    .signed_by(
        &Issuer::from_ca_cert_der(domain.tls_ca.der(), &domain.tls_ca_key).expect("CA-TLS issuer"),
    )
    .expect("client leaf");
    let next_tls = DerCertificate::new(leaf.der().to_vec()).expect("der");

    let next_pq = issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [3; 16],
            subject: SUBJECT.into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Client,
            wireguard_public_key: client_key().to_base64(),
            ml_dsa_87_public_key: request.new_ml_dsa_87_public_key.to_base64(),
            not_before_unix: window.not_before,
            not_after_unix: window.not_after + 86_400,
            ml_dsa_87_signature: String::new(),
        },
        &domain.ca_pq_private,
    )
    .expect("candidate leaf");

    let approval = Fingerprint::of(b"operator approval");
    let staged_pq =
        aether::certificates::gateway::pq_certificate_fingerprint(&next_pq).expect("pq");
    let receipt = GatewayCertificateStageReceipt {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain_id(),
        stage_id: Id16::new([5; 16]).expect("stage id"),
        stage_authorization_fingerprint: Fingerprint::of(b"authorization"),
        request_fingerprint: request.fingerprint(),
        renewal_authorization_fingerprint: approval,
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: client_key(),
        active_generation: request.active_generation,
        staged_generation: request.requested_generation,
        staged_tls_certificate_fingerprint: next_tls.fingerprint(),
        staged_pq_certificate_fingerprint: staged_pq,
        persisted_at: NOW,
        stage_expires_at: NOW + 900,
        active_gateway_identity_epoch: 1,
        gateway_decision_epoch: 1,
        gateway_certificate_fingerprint: aether::certificates::gateway::pq_certificate_fingerprint(
            &domain.gateway_leaf,
        )
        .expect("gateway fingerprint"),
        gateway_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&domain.gateway_pq_private)
    .expect("receipt");

    ClientCertificateRotationGrant {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: domain_id(),
        ca_epoch: 1,
        ca_tls_epoch: 1,
        issuer_kind: IssuerKind::Master,
        issuer_epoch: 0,
        issuer_authorization_fingerprint: Fingerprint::from_bytes([0; 32]),
        issuer_authorization: None,
        request_fingerprint: request.fingerprint(),
        renewal_authorization_fingerprint: approval,
        renewal_approval: None,
        campaign_approval: None,
        stage_receipt_fingerprint: receipt.fingerprint(),
        stage_receipt: receipt,
        gateway_wg_public_key: gateway_key(),
        server_name: SERVER_NAME.into(),
        client_wg_public_key: client_key(),
        active_generation: request.active_generation,
        next_generation: request.requested_generation,
        active_tls_certificate_fingerprint: request.active_tls_certificate_fingerprint,
        active_pq_certificate_fingerprint: request.active_pq_certificate_fingerprint,
        next_tls_ca_certificate_fingerprint: domain.tls_ca_der.fingerprint(),
        next_tls_certificate: next_tls,
        next_pq_certificate: next_pq,
        stage_expires_at: NOW + 900,
        window,
        reason: RotationReason::Scheduled,
        signature: MlDsa87Signature::placeholder(),
    }
    .sign(&domain.ca_pq_private)
    .expect("grant")
}

pub(super) fn session(store: &TrustStore, domain: &Domain) -> RenewalSession {
    let mut session =
        RenewalSession::prepare(store, SUBJECT, "http://100.64.0.1:8080", NOW).expect("prepare");
    session.sign(&active_identity(domain)).expect("sign");
    session
}
