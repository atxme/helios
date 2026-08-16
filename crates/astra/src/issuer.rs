//! The delegated issuer: the only key Astra may use without a human present.
//!
//! It holds two subordinate keys — an ML-DSA-87 one and a TLS intermediate —
//! and an [`AstraIssuerAuthorization`] signed by `CA-PQ` that says exactly what
//! they may do: renew the leaves of an already-admitted, non-revoked peer of
//! **one** gateway, to generation `active + 1`, for at most a stated lifetime,
//! inside a stated window.
//!
//! # What a host compromise buys
//!
//! This key is sealed in Astra's state on the gateway, so an attacker with
//! `root` can use it until the delegation expires. That is accepted and
//! bounded (ADR-008, *Conséquences*): they can renew tomorrow's leaf of a peer
//! that is already admitted. They cannot enrol, readmit, recover an expired
//! identity, rotate the gateway, rotate a CA, or skip a generation — every
//! consumer checks the scope before the signature, and the master key is not
//! here to be stolen.
//!
//! # Limite connue
//!
//! Astra issues the leaves; it never signs a `GatewayIdentityTransition`, a
//! `CaTransition` or a recovery authorization. Those need `CA-PQ`, which lives
//! in the encrypted vault and is opened by the operator companion against a
//! hardware credential. This crate therefore refuses those operations in the
//! type — [`IssuerError::MasterAuthorityRequired`] — rather than offering a
//! degraded path.

use aether::certificates::{
    authority::{AstraIssuerAuthorization, RotationReason},
    client::{
        ClientCertificateGeneration, ClientCertificateRotationGrant,
        ClientCertificateRotationRequest, ClientCertificateStageAuthorization,
        GatewayCertificateStageReceipt, IssuerKind,
    },
    encoding::{DerCertificate, Fingerprint, Id16, MlDsa87Signature},
    gateway::pq_certificate_fingerprint,
    window::TransitionWindow,
    CertificateError, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};
use aether::key_negotiation::{
    issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rcgen::{CertificateParams, CertificateSigningRequestParams, KeyPair};
use zeroize::Zeroizing;

/// Unix seconds as the X.509 encoder wants them.
fn to_offset_date_time(seconds: u64) -> Result<time::OffsetDateTime, IssuerError> {
    let seconds = i64::try_from(seconds).map_err(|_| CertificateError::ArithmeticOverflow)?;
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| IssuerError::Certificate(CertificateError::InvalidValidityPeriod))
}

#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    #[error("certificate object refused: {0}")]
    Certificate(#[from] CertificateError),
    #[error("X.509 issuance failed: {0}")]
    X509(#[from] rcgen::Error),
    #[error(
        "this operation requires the master authority `CA-PQ`, which the delegated issuer does \
         not hold: run it through the operator companion"
    )]
    MasterAuthorityRequired,
    #[error("the gateway receipt does not answer this staging authorization")]
    ReceiptMismatch,
    #[error(
        "the {0} private key on disk does not belong to the delegation the registry holds: Astra \
         would announce an issuer it cannot issue with"
    )]
    IssuerKeyMismatch(&'static str),
}

/// The issuer's private material, as Astra holds it.
///
/// The private halves are `Zeroizing`: they are read once at startup and never
/// serialized back out. No route in [`crate::service`] can reach them.
pub struct DelegatedIssuer {
    pub authorization: AstraIssuerAuthorization,
    pq_private_key: Zeroizing<Vec<u8>>,
    tls_intermediate_key_der: Zeroizing<Vec<u8>>,
}

impl DelegatedIssuer {
    pub fn new(
        authorization: AstraIssuerAuthorization,
        pq_private_key: Zeroizing<Vec<u8>>,
        tls_intermediate_key_der: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            authorization,
            pq_private_key,
            tls_intermediate_key_der,
        }
    }

    /// Builds the issuer only if both private keys match the delegation.
    ///
    /// The three parts arrive from two different places — the authorization is
    /// public and travels in the registry, the keys are sealed locally — so
    /// nothing else guarantees they belong together. Checking that the files
    /// merely *exist* lets Astra start up announcing a delegation it cannot
    /// use, and the mismatch then surfaces at the first renewal: at 80 % of a
    /// leaf's life, on a client with no fallback, as an unexplained refusal.
    ///
    /// Both checks are possession proofs against the **public** halves the
    /// delegation names: an ML-DSA-87 signature verified under
    /// `pq_issuer_public_key`, and the TLS key's `SubjectPublicKeyInfo`
    /// compared with the intermediate's.
    pub fn load(
        authorization: AstraIssuerAuthorization,
        pq_private_key: Zeroizing<Vec<u8>>,
        tls_intermediate_key_der: Zeroizing<Vec<u8>>,
    ) -> Result<Self, IssuerError> {
        let derived = aether::certificates::encoding::derive_ml_dsa_87_public_key(&pq_private_key)
            .map_err(|_| IssuerError::IssuerKeyMismatch("ML-DSA-87"))?;
        if derived != authorization.pq_issuer_public_key {
            return Err(IssuerError::IssuerKeyMismatch("ML-DSA-87"));
        }

        let tls_key = KeyPair::try_from(tls_intermediate_key_der.as_slice())
            .map_err(|_| IssuerError::IssuerKeyMismatch("TLS"))?;
        let certified = aether::certificates::x509::subject_public_key_info(
            &authorization.tls_intermediate_certificate,
        )?;
        if tls_key.public_key_der() != certified {
            return Err(IssuerError::IssuerKeyMismatch("TLS"));
        }

        Ok(Self::new(
            authorization,
            pq_private_key,
            tls_intermediate_key_der,
        ))
    }

    /// Issues the two leaves of a candidate generation.
    ///
    /// The TLS leaf comes from the client's own CSR, so the private key stays
    /// in Orion's protected store; the PQ leaf certifies the public key the
    /// request proved possession of. Both chain to the **delegation**, not to
    /// `CA-PQ` — which is what every consumer then checks.
    pub fn issue_generation(
        &self,
        request: &ClientCertificateRotationRequest,
        subject_name: &str,
        window: &TransitionWindow,
        validity: (u64, u64),
        serial: [u8; 16],
    ) -> Result<(DerCertificate, PqCertificate), IssuerError> {
        let lifetime = validity
            .1
            .checked_sub(validity.0)
            .ok_or(CertificateError::InvalidValidityPeriod)?;
        // Scope first: an issuer that signed and *then* checked would have
        // already produced the object it was not allowed to produce.
        self.authorization.authorize_renewal(
            request.active_generation,
            request.requested_generation,
            lifetime,
            RotationReason::Scheduled,
        )?;
        let _ = window;

        let mut csr =
            CertificateSigningRequestParams::from_der(&request.tls_csr.as_bytes().into())?;
        // A PKCS#10 request carries no validity — and must not: the period is
        // the **issuer's** decision, bounded by the delegation's ceiling. Left
        // alone, the leaf would silently inherit the library's default window
        // and stop matching the generation it belongs to.
        csr.params.not_before = to_offset_date_time(validity.0)?;
        csr.params.not_after = to_offset_date_time(validity.1)?;
        let issuer_key = KeyPair::try_from(self.tls_intermediate_key_der.as_slice())?;
        let issuer_params = CertificateParams::from_ca_cert_der(
            &self
                .authorization
                .tls_intermediate_certificate
                .as_bytes()
                .into(),
        )?;
        let issuer = issuer_params.self_signed(&issuer_key)?;
        let tls_leaf = csr.signed_by(&issuer, &issuer_key)?;

        let pq_leaf = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial,
                subject: subject_name.to_string(),
                issuer: "astra-delegated-issuer".to_string(),
                role: PqCertificateRole::Client,
                wireguard_public_key: request.client_wg_public_key.to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(request.new_ml_dsa_87_public_key.as_bytes()),
                not_before_unix: validity.0,
                not_after_unix: validity.1,
                ml_dsa_87_signature: String::new(),
            },
            &self.pq_private_key,
        )
        .map_err(|_| CertificateError::Signing)?;

        Ok((DerCertificate::new(tls_leaf.der().to_vec())?, pq_leaf))
    }

    /// Builds the staging authorization the gateway will act on (spec §7.2).
    ///
    /// It carries the issued leaves but is **not** the grant: the client
    /// receives nothing installable until the gateway has persisted the
    /// candidate and signed a receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_stage(
        &self,
        request: &ClientCertificateRotationRequest,
        active: &ClientCertificateGeneration,
        stage_id: Id16,
        tls_ca_fingerprint: Fingerprint,
        tls_leaf: DerCertificate,
        pq_leaf: PqCertificate,
        window: TransitionWindow,
        issued_at: u64,
        stage_expires_at: u64,
        reason: RotationReason,
    ) -> Result<ClientCertificateStageAuthorization, IssuerError> {
        if !reason.is_delegable() {
            return Err(IssuerError::MasterAuthorityRequired);
        }
        let authorization = ClientCertificateStageAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: self.authorization.trust_domain_id,
            ca_epoch: self.authorization.ca_epoch,
            ca_tls_epoch: self.authorization.ca_tls_epoch,
            issuer_kind: IssuerKind::Astra,
            issuer_epoch: self.authorization.issuer_epoch,
            issuer_authorization_fingerprint: self.authorization.fingerprint(),
            issuer_authorization: Some(self.authorization.clone()),
            stage_id,
            request_fingerprint: request.fingerprint(),
            gateway_wg_public_key: self.authorization.gateway_wg_public_key,
            server_name: self.authorization.server_name.clone(),
            client_wg_public_key: request.client_wg_public_key,
            active_generation: active.generation,
            next_generation: request.requested_generation,
            active_tls_certificate_fingerprint: active.tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: active.pq_certificate_fingerprint,
            next_tls_ca_certificate_fingerprint: tls_ca_fingerprint,
            next_tls_certificate: tls_leaf,
            next_pq_certificate: pq_leaf,
            issued_at,
            stage_expires_at,
            window,
            reason,
            signature: MlDsa87Signature::placeholder(),
        };
        Ok(authorization.sign(&self.pq_private_key)?)
    }

    /// Releases the grant — and **only** against a receipt that answers this
    /// exact authorization (spec §7.3).
    ///
    /// Every field is compared, not just the identifier. A receipt naming the
    /// right `stage_id` while describing another generation would otherwise be
    /// a valid signature over the wrong fact.
    pub fn release_grant(
        &self,
        authorization: &ClientCertificateStageAuthorization,
        receipt: &GatewayCertificateStageReceipt,
        gateway_pq_public_key: &aether::certificates::encoding::MlDsa87PublicKey,
        gateway_certificate_fingerprint: &Fingerprint,
    ) -> Result<ClientCertificateRotationGrant, IssuerError> {
        receipt
            .verify(
                gateway_pq_public_key,
                gateway_certificate_fingerprint,
                authorization,
            )
            .map_err(|_| IssuerError::ReceiptMismatch)?;

        let grant = ClientCertificateRotationGrant {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: authorization.trust_domain_id,
            ca_epoch: authorization.ca_epoch,
            ca_tls_epoch: authorization.ca_tls_epoch,
            issuer_kind: authorization.issuer_kind,
            issuer_epoch: authorization.issuer_epoch,
            issuer_authorization_fingerprint: authorization.issuer_authorization_fingerprint,
            issuer_authorization: authorization.issuer_authorization.clone(),
            request_fingerprint: authorization.request_fingerprint,
            stage_receipt_fingerprint: receipt.fingerprint(),
            stage_receipt: receipt.clone(),
            gateway_wg_public_key: authorization.gateway_wg_public_key,
            server_name: authorization.server_name.clone(),
            client_wg_public_key: authorization.client_wg_public_key,
            active_generation: authorization.active_generation,
            next_generation: authorization.next_generation,
            active_tls_certificate_fingerprint: authorization.active_tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: authorization.active_pq_certificate_fingerprint,
            next_tls_ca_certificate_fingerprint: authorization.next_tls_ca_certificate_fingerprint,
            next_tls_certificate: authorization.next_tls_certificate.clone(),
            next_pq_certificate: authorization.next_pq_certificate.clone(),
            stage_expires_at: authorization.stage_expires_at,
            window: authorization.window,
            reason: authorization.reason,
            signature: MlDsa87Signature::placeholder(),
        };
        Ok(grant.sign(&self.pq_private_key)?)
    }

    /// The candidate generation this issuance describes.
    pub fn candidate(
        authorization: &ClientCertificateStageAuthorization,
    ) -> Result<ClientCertificateGeneration, CertificateError> {
        Ok(ClientCertificateGeneration {
            generation: authorization.next_generation,
            ca_tls_epoch: authorization.ca_tls_epoch,
            tls_ca_certificate_fingerprint: authorization.next_tls_ca_certificate_fingerprint,
            tls_certificate_fingerprint: authorization.next_tls_certificate.fingerprint(),
            pq_certificate_fingerprint: pq_certificate_fingerprint(
                &authorization.next_pq_certificate,
            )?,
            not_before: authorization.next_pq_certificate.not_before_unix,
            not_after: authorization.next_pq_certificate.not_after_unix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::authority::AllowedUsage;
    use aether::certificates::encoding::{
        generate_ml_dsa_87_keypair, MlDsa87PublicKey, TrustDomainId, WireGuardKey,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyUsagePurpose,
    };

    const SERVER_NAME: &str = "gateway.example";

    struct Fixture {
        issuer: DelegatedIssuer,
        /// The delegated intermediate, self-signed here so it is both the
        /// intermediate and the anchor a test verifier holds.
        tls_anchor: DerCertificate,
        ca_public: MlDsa87PublicKey,
        client_active: Zeroizing<Vec<u8>>,
    }

    fn domain() -> TrustDomainId {
        TrustDomainId::new([1; 16]).expect("domain")
    }

    fn gateway_key() -> WireGuardKey {
        WireGuardKey::from_bytes([1; 32])
    }

    fn client_key() -> WireGuardKey {
        WireGuardKey::from_bytes([2; 32])
    }

    fn intermediate() -> (DerCertificate, Zeroizing<Vec<u8>>) {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "astra-issuer");
        params.distinguished_name = name;
        // Every link of a chain is read against the clock, this one included,
        // and these tests drive a synthetic clock near the Unix epoch.
        params.not_before = rcgen::date_time_ymd(1970, 1, 1);
        params.not_after = rcgen::date_time_ymd(4096, 1, 1);
        let key = KeyPair::generate().expect("key");
        let certificate = params.self_signed(&key).expect("intermediate");
        (
            DerCertificate::new(certificate.der().to_vec()).expect("der"),
            Zeroizing::new(key.serialize_der()),
        )
    }

    fn fixture() -> Fixture {
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (issuer_private, issuer_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (client_active, _client_active_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (intermediate_der, intermediate_key) = intermediate();

        let authorization = AstraIssuerAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            issuer_epoch: 1,
            pq_issuer_public_key: issuer_public,
            tls_intermediate_certificate: intermediate_der,
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 200_000,
            policy_fingerprint: Fingerprint::of(b"policy"),
            not_before: 0,
            not_after: 1_000_000,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca_private)
        .expect("sign delegation");

        Fixture {
            tls_anchor: authorization.tls_intermediate_certificate.clone(),
            issuer: DelegatedIssuer::new(authorization, issuer_private, intermediate_key),
            ca_public,
            client_active,
        }
    }

    fn csr() -> (DerCertificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "workstation");
        params.distinguished_name = name;
        // The tests drive synthetic clocks near the Unix epoch, so the leaf
        // issued from this request has to be valid there.
        params.not_before = rcgen::date_time_ymd(1970, 1, 1);
        params.not_after = rcgen::date_time_ymd(4096, 1, 1);
        let key = KeyPair::generate().expect("key");
        let request = params.serialize_request(&key).expect("csr");
        (
            DerCertificate::new(request.der().to_vec()).expect("der"),
            key,
        )
    }

    fn active() -> ClientCertificateGeneration {
        ClientCertificateGeneration {
            generation: 4,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
            pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
            not_before: 0,
            not_after: 1_000_000,
        }
    }

    fn request(
        fixture: &Fixture,
        csr: DerCertificate,
        new_public: &MlDsa87PublicKey,
        new_private: &[u8],
        requested_generation: u64,
    ) -> ClientCertificateRotationRequest {
        ClientCertificateRotationRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            request_id: Id16::new([3; 16]).expect("id"),
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            client_wg_public_key: client_key(),
            active_generation: 4,
            requested_generation,
            active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
            tls_csr: csr,
            new_ml_dsa_87_public_key: new_public.clone(),
            created_at: 1_000,
            expires_at: 1_000 + 3_600,
            active_pq_signature: MlDsa87Signature::placeholder(),
            new_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&fixture.client_active, new_private)
        .expect("sign request")
    }

    /// The whole point of the delegation: the leaves it issues verify under
    /// **it**, and the object it signs verifies as an `astra` issuance.
    #[test]
    fn an_issued_generation_verifies_under_the_delegation() {
        let fixture = fixture();
        let (csr_der, _csr_key) = csr();
        let (new_private, new_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let request = request(&fixture, csr_der, &new_public, &new_private, 5);

        let window = TransitionWindow::new(1_000, 50_000, 60_000).expect("window");
        let (tls_leaf, pq_leaf) = fixture
            .issuer
            .issue_generation(&request, "workstation", &window, (0, 100_000), [9; 16])
            .expect("issuance");

        let authorization = fixture
            .issuer
            .authorize_stage(
                &request,
                &active(),
                Id16::new([4; 16]).expect("stage"),
                fixture.tls_anchor.fingerprint(),
                tls_leaf,
                pq_leaf,
                window,
                1_000,
                1_000 + 3_600,
                RotationReason::Scheduled,
            )
            .expect("authorization");

        authorization
            .verify(
                &fixture.ca_public,
                &domain(),
                1,
                1,
                &gateway_key(),
                SERVER_NAME,
                &client_key(),
                &active(),
                &[&fixture.tls_anchor],
                None,
                1_100,
            )
            .expect("the gateway accepts a delegated staging");
    }

    /// Present is not correct. The delegation and the two private keys arrive
    /// from different places, and a mismatch that startup lets through only
    /// surfaces at the first renewal — on a client with no fallback.
    #[test]
    fn loading_refuses_private_material_that_does_not_match_the_delegation() {
        let (ca_private, _) = generate_ml_dsa_87_keypair().expect("keygen");
        let (issuer_private, issuer_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let (intermediate_der, intermediate_key) = intermediate();
        let authorization = AstraIssuerAuthorization {
            pq_issuer_public_key: issuer_public,
            tls_intermediate_certificate: intermediate_der,
            ca_pq_signature: MlDsa87Signature::placeholder(),
            ..fixture().issuer.authorization.clone()
        }
        .sign(&ca_private)
        .expect("sign delegation");

        // The genuine triple loads.
        DelegatedIssuer::load(
            authorization.clone(),
            issuer_private.clone(),
            intermediate_key.clone(),
        )
        .expect("the genuine material loads");

        // A stranger's PQ key signs perfectly and verifies under nothing this
        // delegation names.
        let (stranger_pq, _) = generate_ml_dsa_87_keypair().expect("keygen");
        assert!(matches!(
            DelegatedIssuer::load(authorization.clone(), stranger_pq, intermediate_key),
            Err(IssuerError::IssuerKeyMismatch("ML-DSA-87"))
        ));

        // And a TLS key that is not the intermediate's.
        let (_, other_tls_key) = intermediate();
        assert!(matches!(
            DelegatedIssuer::load(authorization, issuer_private, other_tls_key),
            Err(IssuerError::IssuerKeyMismatch("TLS"))
        ));
    }

    /// The four things the delegation withholds, checked before any signature
    /// exists — so a compromised Astra never produces the object at all.
    #[test]
    fn the_issuer_refuses_a_skipped_generation_and_an_undelegable_reason() {
        let fixture = fixture();
        let (csr_der, _csr_key) = csr();
        let (new_private, new_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let window = TransitionWindow::new(1_000, 50_000, 60_000).expect("window");

        let skipped = request(&fixture, csr_der.clone(), &new_public, &new_private, 6);
        assert!(matches!(
            fixture.issuer.issue_generation(
                &skipped,
                "workstation",
                &window,
                (0, 100_000),
                [9; 16]
            ),
            Err(IssuerError::Certificate(
                CertificateError::IssuerScopeViolation("generation")
            ))
        ));

        let request = request(&fixture, csr_der, &new_public, &new_private, 5);
        let (tls_leaf, pq_leaf) = fixture
            .issuer
            .issue_generation(&request, "workstation", &window, (0, 100_000), [9; 16])
            .expect("issuance");
        for forbidden in [
            RotationReason::ExpiredRecovery,
            RotationReason::Readmission,
            RotationReason::EmergencyReplacement,
            RotationReason::KeyRecovery,
        ] {
            assert!(matches!(
                fixture.issuer.authorize_stage(
                    &request,
                    &active(),
                    Id16::new([4; 16]).expect("stage"),
                    fixture.tls_anchor.fingerprint(),
                    tls_leaf.clone(),
                    pq_leaf.clone(),
                    window,
                    1_000,
                    1_000 + 3_600,
                    forbidden,
                ),
                Err(IssuerError::MasterAuthorityRequired)
            ));
        }
    }

    /// A lifetime beyond the delegation's ceiling is refused before issuance.
    #[test]
    fn the_issuer_refuses_a_leaf_longer_than_its_ceiling() {
        let fixture = fixture();
        let (csr_der, _csr_key) = csr();
        let (new_private, new_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let request = request(&fixture, csr_der, &new_public, &new_private, 5);
        let window = TransitionWindow::new(1_000, 50_000, 60_000).expect("window");

        assert!(matches!(
            fixture.issuer.issue_generation(
                &request,
                "workstation",
                &window,
                (0, 300_000),
                [9; 16]
            ),
            Err(IssuerError::Certificate(
                CertificateError::IssuerScopeViolation("leaf lifetime")
            ))
        ));
    }

    /// No receipt, no grant — the ordering the whole staging protocol exists
    /// to enforce.
    #[test]
    fn a_grant_is_refused_without_a_matching_receipt() {
        let fixture = fixture();
        let (csr_der, _csr_key) = csr();
        let (new_private, new_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let request = request(&fixture, csr_der, &new_public, &new_private, 5);
        let window = TransitionWindow::new(1_000, 50_000, 60_000).expect("window");
        let (tls_leaf, pq_leaf) = fixture
            .issuer
            .issue_generation(&request, "workstation", &window, (0, 100_000), [9; 16])
            .expect("issuance");
        let authorization = fixture
            .issuer
            .authorize_stage(
                &request,
                &active(),
                Id16::new([4; 16]).expect("stage"),
                fixture.tls_anchor.fingerprint(),
                tls_leaf,
                pq_leaf,
                window,
                1_000,
                1_000 + 3_600,
                RotationReason::Scheduled,
            )
            .expect("authorization");

        let (gateway_private, gateway_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let candidate = DelegatedIssuer::candidate(&authorization).expect("candidate");
        let gateway_fingerprint = Fingerprint::of(b"gateway leaf");

        // A receipt describing another generation carries a valid signature
        // over the wrong fact, and is refused on the field comparison.
        let wrong = GatewayCertificateStageReceipt {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain(),
            stage_id: authorization.stage_id,
            stage_authorization_fingerprint: authorization.fingerprint().expect("fingerprint"),
            request_fingerprint: authorization.request_fingerprint,
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            active_generation: 4,
            staged_generation: 9,
            staged_tls_certificate_fingerprint: candidate.tls_certificate_fingerprint,
            staged_pq_certificate_fingerprint: candidate.pq_certificate_fingerprint,
            persisted_at: 1_100,
            stage_expires_at: authorization.stage_expires_at,
            active_gateway_identity_epoch: 1,
            gateway_decision_epoch: 1,
            gateway_certificate_fingerprint: gateway_fingerprint,
            gateway_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&gateway_private)
        .expect("sign receipt");

        assert!(matches!(
            fixture.issuer.release_grant(
                &authorization,
                &wrong,
                &gateway_public,
                &gateway_fingerprint
            ),
            Err(IssuerError::ReceiptMismatch)
        ));
    }
}
