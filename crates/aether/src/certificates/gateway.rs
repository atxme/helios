//! The gateway identity: request, transition, abort — spec §5 and §6.
//!
//! # The asymmetry between the two leaves
//!
//! The gateway serves two certificates and they are anchored differently. The
//! PQ leaf chains to `CA-PQ`: it carries the post-quantum application
//! authority, and a compromised leaf must not be able to authorize its own
//! replacement. The TLS leaf stays self-signed and pinned: it protects a
//! transport, and its replacement is authorized by `CA-PQ` — a pin cannot
//! authorize its own successor without being exactly the self-certification
//! this design refuses.
//!
//! This is deliberate (ADR-008, *Conséquences*), and it is the reason a
//! transition covers TLS alone, PQ alone, or both **atomically**: the two
//! families move on one signed decision, so no client can end up trusting the
//! new TLS pin against the old PQ identity.
//!
//! # Why an abort consumes its epoch
//!
//! A staged transition that is cancelled does not free its number. A client
//! may have observed the first attempt; reusing the epoch for a different set
//! of certificates would present that client with two documents claiming the
//! same decision. The abort is therefore itself a sequential decision, it
//! leaves a tombstone, and the next attempt uses `current + 1` (spec §4.2).
//!
//! And it is only available **before publication**. Once Astra has persisted
//! `published`, a client may hold the decision, go offline and promote it
//! alone at `not_after`; cancelling on the gateway alone would create two
//! truths. After that point the exits are the bounded service rollback and a
//! new forward transition.

use serde::{Deserialize, Serialize};

use crate::key_negotiation::{PqCertificate, PqCertificateRole};

use super::{
    authority::RotationReason,
    encoding::{
        validate_server_name, verify_ml_dsa_87, CanonicalBytes, DerCertificate, Fingerprint, Id16,
        MlDsa87PublicKey, MlDsa87Signature, SignedTranscript, TrustDomainId, WireGuardKey,
    },
    window::{require_next_generation, TransitionWindow, MAX_REQUEST_LIFETIME_SECS},
    CertificateError, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};

const GATEWAY_REQUEST_DOMAIN: &[u8] = b"helios-gateway-certificate-request-v5";
const GATEWAY_TRANSITION_DOMAIN: &[u8] = b"helios-gateway-identity-transition-v5";
const GATEWAY_ABORT_DOMAIN: &[u8] = b"helios-gateway-identity-transition-abort-v5";

/// Fingerprint of a v5 PQ certificate, as a typed 32-byte value.
///
/// [`PqCertificate::fingerprint`] returns the hexadecimal form the negotiation
/// wire format uses. Everything in this module signs the raw bytes, so the
/// conversion happens once, here, rather than at every comparison.
pub fn pq_certificate_fingerprint(
    certificate: &PqCertificate,
) -> Result<Fingerprint, CertificateError> {
    let hex = certificate
        .fingerprint()
        .map_err(|_| CertificateError::InvalidFingerprint)?;
    Fingerprint::parse_hex(&hex)
}

/// Whether a gateway certificate request proves continuity with the leaf in
/// service, or is a recovery from the loss of that private key (spec §5).
pub enum Continuity<'a> {
    /// Ordinary renewal: the active leaf signs the request.
    Required(&'a MlDsa87PublicKey),
    /// The active private key is gone. Accepted only after an explicit local
    /// operator procedure, and the resulting transition must carry
    /// [`RotationReason::KeyRecovery`].
    WaivedForKeyRecovery,
}

/// Public request the operator companion turns into a leaf (spec §5).
///
/// The gateway generates and seals its own ML-DSA-87 private key; this object
/// exports only the public half plus two proofs. No path in the lifecycle ever
/// moves a gateway private key off the machine that created it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayCertificateRequest {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub gateway_identity_epoch: u64,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub new_ml_dsa_87_public_key: MlDsa87PublicKey,
    pub request_id: Id16,
    pub created_at: u64,
    pub expires_at: u64,
    /// Possession of the key being certified.
    pub new_key_proof: MlDsa87Signature,
    /// Continuity from the leaf currently in service. Absent only on the
    /// recovery path of [`Continuity::WaivedForKeyRecovery`].
    pub current_key_authorization: Option<MlDsa87Signature>,
}

impl GatewayCertificateRequest {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(GATEWAY_REQUEST_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .u64(self.gateway_identity_epoch)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .length_prefixed(self.new_ml_dsa_87_public_key.as_bytes())
            .id(&self.request_id)
            .u64(self.created_at)
            .u64(self.expires_at);
        bytes.finish_signed()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes.length_prefixed(self.new_key_proof.as_bytes());
        match &self.current_key_authorization {
            Some(signature) => {
                bytes.u8(1).length_prefixed(signature.as_bytes());
            }
            None => {
                bytes.u8(0);
            }
        }
        Fingerprint::of(&bytes.finish())
    }

    /// Verifies the request without any authority key: it is a *request*, and
    /// only the operator companion turns it into a certificate.
    pub fn verify(
        &self,
        continuity: Continuity<'_>,
        trust_domain_id: &TrustDomainId,
        gateway_decision_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key || self.server_name != server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        validate_server_name(&self.server_name)?;
        require_next_generation(gateway_decision_epoch, self.gateway_identity_epoch)?;
        if self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_REQUEST_LIFETIME_SECS
        {
            return Err(CertificateError::InvalidLease);
        }
        if now_unix >= self.expires_at {
            return Err(CertificateError::StageExpired);
        }

        let transcript = self.signing_bytes();
        verify_ml_dsa_87(
            &self.new_ml_dsa_87_public_key,
            &transcript,
            &self.new_key_proof,
        )
        .map_err(|_| CertificateError::MissingProof("new gateway"))?;

        match continuity {
            Continuity::Required(active) => {
                let authorization = self
                    .current_key_authorization
                    .as_ref()
                    .ok_or(CertificateError::MissingProof("active gateway"))?;
                verify_ml_dsa_87(active, &transcript, authorization)
                    .map_err(|_| CertificateError::MissingProof("active gateway"))
            }
            // Not "ignored": the field must be absent. A request that carries a
            // continuity signature nobody checked would read, in an audit, as
            // one that proved continuity.
            Continuity::WaivedForKeyRecovery => {
                if self.current_key_authorization.is_some() {
                    return Err(CertificateError::IllegalStateTransition(
                        "key recovery carries no continuity signature",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// One decision moving the gateway identity forward (spec §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayIdentityTransition {
    pub format_version: u16,
    pub protocol_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub gateway_identity_epoch: u64,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub active_gateway_tls_certificate_fingerprint: Fingerprint,
    /// Complete DER, absent when TLS does not change.
    pub next_gateway_tls_certificate: Option<DerCertificate>,
    pub active_gateway_certificate_fingerprint: Fingerprint,
    /// Complete PQ certificate, absent when the PQ leaf does not change.
    pub next_gateway_certificate: Option<PqCertificate>,
    pub window: TransitionWindow,
    pub reason: RotationReason,
    pub ca_signature: MlDsa87Signature,
}

impl GatewayIdentityTransition {
    fn signing_bytes(&self) -> Result<SignedTranscript, CertificateError> {
        let next_tls = self
            .next_gateway_tls_certificate
            .as_ref()
            .map(DerCertificate::fingerprint);
        let next_pq = self
            .next_gateway_certificate
            .as_ref()
            .map(pq_certificate_fingerprint)
            .transpose()?;

        let mut bytes = CanonicalBytes::new(GATEWAY_TRANSITION_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .u64(self.gateway_identity_epoch)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .fingerprint(&self.active_gateway_tls_certificate_fingerprint)
            .optional_fingerprint(next_tls.as_ref())
            .fingerprint(&self.active_gateway_certificate_fingerprint)
            .optional_fingerprint(next_pq.as_ref())
            .u64(self.window.not_before)
            .u64(self.window.activation_at)
            .u64(self.window.not_after)
            .u8(self.reason.domain_byte());
        Ok(bytes.finish_signed())
    }

    /// Identifies the exact document an abort names (spec §6.3).
    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        let mut bytes = CanonicalBytes::new(self.signing_bytes()?.as_bytes());
        bytes.length_prefixed(self.ca_signature.as_bytes());
        Ok(Fingerprint::of(&bytes.finish()))
    }

    /// Fingerprints of the leaves this transition installs.
    pub fn next_fingerprints(
        &self,
    ) -> Result<(Option<Fingerprint>, Option<Fingerprint>), CertificateError> {
        Ok((
            self.next_gateway_tls_certificate
                .as_ref()
                .map(DerCertificate::fingerprint),
            self.next_gateway_certificate
                .as_ref()
                .map(pq_certificate_fingerprint)
                .transpose()?,
        ))
    }

    /// The same fingerprints, flattened — what a revocation check needs.
    pub fn installed_fingerprints(&self) -> Result<Vec<Fingerprint>, CertificateError> {
        let (tls, pq) = self.next_fingerprints()?;
        Ok([tls, pq].into_iter().flatten().collect())
    }

    /// Verifies the whole decision against the locally trusted anchor.
    ///
    /// Order matters, and it is the order of spec §6.2: the parser recomputes
    /// each embedded fingerprint and compares it in constant time **before**
    /// any chain verification, so a substituted certificate is a fingerprint
    /// mismatch rather than an ML-DSA operation an attacker got for free.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        gateway_decision_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        active_tls_fingerprint: &Fingerprint,
        active_pq_fingerprint: &Fingerprint,
    ) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.protocol_version != CERTIFICATE_PROTOCOL_VERSION {
            return Err(CertificateError::UnsupportedProtocolVersion {
                received: self.protocol_version,
                supported: CERTIFICATE_PROTOCOL_VERSION,
            });
        }
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.ca_epoch != ca_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key || self.server_name != server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        validate_server_name(&self.server_name)?;
        require_next_generation(gateway_decision_epoch, self.gateway_identity_epoch)?;
        if self.next_gateway_tls_certificate.is_none() && self.next_gateway_certificate.is_none() {
            return Err(CertificateError::EmptyTransition);
        }
        if !self
            .active_gateway_tls_certificate_fingerprint
            .matches(active_tls_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("active gateway TLS"));
        }
        if !self
            .active_gateway_certificate_fingerprint
            .matches(active_pq_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("active gateway PQ"));
        }
        self.window.validate()?;

        if let Some(certificate) = &self.next_gateway_tls_certificate {
            crate::certificates::x509::assert_pinned_gateway_leaf(
                certificate,
                server_name,
                self.window.activation_at,
                self.window.not_after,
            )?;
        }

        if let Some(certificate) = &self.next_gateway_certificate {
            // The incoming leaf is verified **at `activation_at`**, not at the
            // current instant: a transition prepared weeks ahead carries a
            // certificate that is not yet valid today, and reading it against
            // the wrong clock would refuse every scheduled rotation.
            certificate
                .verify(
                    ca_pq.as_bytes(),
                    PqCertificateRole::Gateway,
                    Some(server_name),
                    &gateway_wg_public_key.to_base64(),
                    self.window.activation_at,
                )
                .map_err(|_| CertificateError::UnauthorizedIssuer)?;
            // And it must outlive the overlap: a leaf expiring inside the
            // window would promote the fleet onto an already-dead identity.
            if certificate.not_after_unix <= self.window.not_after {
                return Err(CertificateError::OutsideValidityPeriod);
            }
        }

        verify_ml_dsa_87(ca_pq, &self.signing_bytes()?, &self.ca_signature)
    }
}

/// Why a staged transition was cancelled (spec §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortReason {
    OperatorCancelled,
    SupersededBeforeActivation,
}

impl AbortReason {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::OperatorCancelled => 0,
            Self::SupersededBeforeActivation => 1,
        }
    }
}

/// Cancellation of a staged, unpublished gateway transition (spec §6.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayTransitionAbort {
    pub format_version: u16,
    pub protocol_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub gateway_identity_epoch: u64,
    pub gateway_transition_fingerprint: Fingerprint,
    pub aborted_at: u64,
    pub reason: AbortReason,
    pub campaign_fingerprint: Fingerprint,
    pub ca_signature: MlDsa87Signature,
}

impl GatewayTransitionAbort {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(GATEWAY_ABORT_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .u64(self.gateway_identity_epoch)
            .fingerprint(&self.gateway_transition_fingerprint)
            .u64(self.aborted_at)
            .u8(self.reason.domain_byte())
            .fingerprint(&self.campaign_fingerprint);
        bytes.finish_signed()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes.length_prefixed(self.ca_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Verifies an abort against the transition it names.
    ///
    /// `now_unix` is read **under the same lock** that holds the staged slot,
    /// and both it and `aborted_at` must be strictly before `activation_at`.
    /// Checking only the signed field would let an antedated object cancel a
    /// transition that is already in overlap on the client side.
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        transition: &GatewayIdentityTransition,
        published: bool,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        if self.format_version != CERTIFICATE_FORMAT_VERSION {
            return Err(CertificateError::UnsupportedFormatVersion {
                received: self.format_version,
                supported: CERTIFICATE_FORMAT_VERSION,
            });
        }
        if self.protocol_version != CERTIFICATE_PROTOCOL_VERSION {
            return Err(CertificateError::UnsupportedProtocolVersion {
                received: self.protocol_version,
                supported: CERTIFICATE_PROTOCOL_VERSION,
            });
        }
        if published {
            return Err(CertificateError::AlreadyPublished);
        }
        if self.trust_domain_id != transition.trust_domain_id
            || self.ca_epoch != transition.ca_epoch
        {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.gateway_wg_public_key != transition.gateway_wg_public_key
            || self.server_name != transition.server_name
        {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.gateway_identity_epoch != transition.gateway_identity_epoch {
            return Err(CertificateError::GenerationConflict {
                generation: self.gateway_identity_epoch,
            });
        }
        if !self
            .gateway_transition_fingerprint
            .matches(&transition.fingerprint()?)
        {
            return Err(CertificateError::FingerprintMismatch("gateway transition"));
        }
        if self.aborted_at >= transition.window.activation_at
            || now_unix >= transition.window.activation_at
        {
            return Err(CertificateError::IllegalStateTransition(
                "abort after activation",
            ));
        }
        verify_ml_dsa_87(ca_pq, &self.signing_bytes(), &self.ca_signature)
    }

    /// The record a client persists in place of the cancelled decision.
    pub fn tombstone(&self) -> GatewayTransitionAbortTombstone {
        GatewayTransitionAbortTombstone {
            gateway_identity_epoch: self.gateway_identity_epoch,
            gateway_transition_fingerprint: self.gateway_transition_fingerprint,
            abort_fingerprint: self.fingerprint(),
            aborted_at: self.aborted_at,
        }
    }
}

/// What remains of an aborted attempt: an epoch that is spent (spec §3.2).
///
/// Enough to make the last abort idempotent. Anything older is already
/// refused by the decision counter, so the state keeps one tombstone rather
/// than a growing list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayTransitionAbortTombstone {
    pub gateway_identity_epoch: u64,
    pub gateway_transition_fingerprint: Fingerprint,
    pub abort_fingerprint: Fingerprint,
    pub aborted_at: u64,
}

/// Signing side of the gateway objects (see `authority::signing`).
#[cfg(feature = "key-negotiation-signing")]
mod signing {
    use super::*;
    use crate::certificates::encoding::sign_ml_dsa_87;

    impl GatewayCertificateRequest {
        /// `current_key_private` is `None` on the key-recovery path, where the
        /// field must be **absent** rather than merely unverified.
        pub fn sign(
            mut self,
            new_key_private: &[u8],
            current_key_private: Option<&[u8]>,
        ) -> Result<Self, CertificateError> {
            let transcript = self.signing_bytes();
            self.new_key_proof = sign_ml_dsa_87(new_key_private, &transcript)?;
            self.current_key_authorization = current_key_private
                .map(|key| sign_ml_dsa_87(key, &transcript))
                .transpose()?;
            Ok(self)
        }
    }

    impl GatewayIdentityTransition {
        pub fn sign(mut self, ca_pq_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.ca_signature = sign_ml_dsa_87(ca_pq_private_key, &self.signing_bytes()?)?;
            Ok(self)
        }
    }

    impl GatewayTransitionAbort {
        pub fn sign(mut self, ca_pq_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.ca_signature = sign_ml_dsa_87(ca_pq_private_key, &self.signing_bytes())?;
            Ok(self)
        }
    }
}

#[cfg(all(test, feature = "key-negotiation-signing"))]
mod tests {
    use super::*;
    use crate::certificates::encoding::{generate_ml_dsa_87_keypair, sign_ml_dsa_87};
    use crate::key_negotiation::{issue_pq_certificate, PQ_CERTIFICATE_VERSION};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
    use zeroize::Zeroizing;

    const SERVER_NAME: &str = "gateway.example";

    struct Keys {
        private: Zeroizing<Vec<u8>>,
        public: MlDsa87PublicKey,
    }

    fn keys() -> Keys {
        let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
        Keys { private, public }
    }

    fn domain() -> TrustDomainId {
        TrustDomainId::new([4; 16]).expect("domain")
    }

    fn gateway_key() -> WireGuardKey {
        WireGuardKey::from_bytes([5; 32])
    }

    fn window() -> TransitionWindow {
        TransitionWindow::new(1_000, 2_000, 3_000).expect("window")
    }

    /// A gateway leaf issued by `CA-PQ`, valid across the whole window.
    fn gateway_leaf(ca: &Keys, subject: &Keys) -> PqCertificate {
        let certificate = PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [1; 16],
            subject: SERVER_NAME.into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: gateway_key().to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(subject.public.as_bytes()),
            not_before_unix: 0,
            not_after_unix: 100_000,
            ml_dsa_87_signature: String::new(),
        };
        issue_pq_certificate(certificate, &ca.private).expect("issue")
    }

    fn gateway_tls_leaf(server_name: &str, not_after_year: i32) -> DerCertificate {
        let mut params = CertificateParams::new(vec![server_name.to_string()]).expect("params");
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = rcgen::date_time_ymd(1970, 1, 1);
        params.not_after = rcgen::date_time_ymd(not_after_year, 1, 1);
        let key = KeyPair::generate().expect("TLS key");
        let certificate = params.self_signed(&key).expect("TLS certificate");
        DerCertificate::new(certificate.der().to_vec()).expect("DER")
    }

    fn transition(ca: &Keys, next_leaf: Option<PqCertificate>) -> GatewayIdentityTransition {
        let mut transition = GatewayIdentityTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            gateway_identity_epoch: 2,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            active_gateway_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
            next_gateway_tls_certificate: None,
            active_gateway_certificate_fingerprint: Fingerprint::of(b"active pq"),
            next_gateway_certificate: next_leaf,
            window: window(),
            reason: RotationReason::Scheduled,
            ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
        };
        let transcript = transition.signing_bytes().expect("transcript");
        transition.ca_signature = sign_ml_dsa_87(&ca.private, &transcript).expect("sign");
        transition
    }

    fn verify(
        transition: &GatewayIdentityTransition,
        ca: &Keys,
        decision_epoch: u64,
    ) -> Result<(), CertificateError> {
        transition.verify(
            &ca.public,
            &domain(),
            1,
            decision_epoch,
            &gateway_key(),
            SERVER_NAME,
            &Fingerprint::of(b"active tls"),
            &Fingerprint::of(b"active pq"),
        )
    }

    #[test]
    fn a_transition_may_carry_tls_alone_pq_alone_or_both() {
        let ca = keys();
        let subject = keys();
        let leaf = gateway_leaf(&ca, &subject);

        let pq_only = transition(&ca, Some(leaf.clone()));
        assert!(verify(&pq_only, &ca, 1).is_ok());

        let tls_leaf = gateway_tls_leaf(SERVER_NAME, 4096);
        let mut tls_only = transition(&ca, None);
        tls_only.next_gateway_tls_certificate = Some(tls_leaf.clone());
        let transcript = tls_only.signing_bytes().unwrap();
        tls_only.ca_signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();
        assert!(verify(&tls_only, &ca, 1).is_ok());

        let mut both = transition(&ca, Some(leaf));
        both.next_gateway_tls_certificate = Some(tls_leaf);
        let transcript = both.signing_bytes().unwrap();
        both.ca_signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();
        assert!(verify(&both, &ca, 1).is_ok());
    }

    #[test]
    fn a_gateway_tls_leaf_must_be_a_valid_self_signed_server_identity() {
        let ca = keys();
        let mut malformed = transition(&ca, None);
        malformed.next_gateway_tls_certificate =
            Some(DerCertificate::new(vec![7; 64]).expect("bounded DER"));
        let transcript = malformed.signing_bytes().expect("transcript");
        malformed.ca_signature = sign_ml_dsa_87(&ca.private, &transcript).expect("sign");
        assert!(matches!(
            verify(&malformed, &ca, 1),
            Err(CertificateError::InvalidX509("unparsable"))
        ));

        let mut wrong_name = transition(&ca, None);
        wrong_name.next_gateway_tls_certificate = Some(gateway_tls_leaf("other.example", 4096));
        let transcript = wrong_name.signing_bytes().expect("transcript");
        wrong_name.ca_signature = sign_ml_dsa_87(&ca.private, &transcript).expect("sign");
        assert!(matches!(
            verify(&wrong_name, &ca, 1),
            Err(CertificateError::InvalidX509(
                "gateway DNS name is not in subjectAltName"
            ))
        ));
    }

    /// A transition that installs nothing is not a decision.
    #[test]
    fn a_transition_with_neither_leaf_is_refused() {
        let ca = keys();
        let empty = transition(&ca, None);
        assert!(matches!(
            verify(&empty, &ca, 1),
            Err(CertificateError::EmptyTransition)
        ));
    }

    /// The signed transcript carries the leaf's fingerprint, so swapping the
    /// certificate changes the signature — the parser catches it before ever
    /// verifying a chain.
    #[test]
    fn substituting_the_embedded_leaf_breaks_the_signature() {
        let ca = keys();
        let subject = keys();
        let other = keys();
        let mut forged = transition(&ca, Some(gateway_leaf(&ca, &subject)));
        forged.next_gateway_certificate = Some(gateway_leaf(&ca, &other));
        assert!(matches!(
            verify(&forged, &ca, 1),
            Err(CertificateError::InvalidSignature)
        ));
    }

    /// A leaf that dies inside the overlap would promote the fleet onto an
    /// already-expired identity.
    #[test]
    fn a_next_leaf_must_outlive_the_overlap() {
        let ca = keys();
        let subject = keys();
        let mut leaf = gateway_leaf(&ca, &subject);
        leaf.not_after_unix = 2_500;
        let leaf = issue_pq_certificate(leaf, &ca.private).expect("reissue");
        let short_lived_transition = transition(&ca, Some(leaf));
        assert!(matches!(
            verify(&short_lived_transition, &ca, 1),
            Err(CertificateError::OutsideValidityPeriod)
        ));

        let mut equal = gateway_leaf(&ca, &subject);
        equal.not_after_unix = window().not_after;
        let equal = issue_pq_certificate(equal, &ca.private).expect("reissue");
        assert!(matches!(
            verify(&transition(&ca, Some(equal)), &ca, 1),
            Err(CertificateError::OutsideValidityPeriod)
        ));
    }

    /// A leaf signed by anything other than the pinned `CA-PQ` is not a
    /// gateway identity, whatever else the document proves.
    #[test]
    fn a_next_leaf_under_an_unpinned_authority_is_refused() {
        let ca = keys();
        let rogue = keys();
        let subject = keys();
        let transition = transition(&ca, Some(gateway_leaf(&rogue, &subject)));
        assert!(matches!(
            verify(&transition, &ca, 1),
            Err(CertificateError::UnauthorizedIssuer)
        ));
    }

    #[test]
    fn a_transition_is_bound_to_the_stable_gateway_identity() {
        let ca = keys();
        let subject = keys();
        let transition = transition(&ca, Some(gateway_leaf(&ca, &subject)));
        assert!(matches!(
            transition.verify(
                &ca.public,
                &domain(),
                1,
                1,
                &WireGuardKey::from_bytes([8; 32]),
                SERVER_NAME,
                &Fingerprint::of(b"active tls"),
                &Fingerprint::of(b"active pq"),
            ),
            Err(CertificateError::GatewayIdentityMismatch)
        ));
        assert!(matches!(
            transition.verify(
                &ca.public,
                &domain(),
                1,
                1,
                &gateway_key(),
                SERVER_NAME,
                &Fingerprint::of(b"another tls"),
                &Fingerprint::of(b"active pq"),
            ),
            Err(CertificateError::FingerprintMismatch("active gateway TLS"))
        ));
    }

    #[test]
    fn a_transition_epoch_is_exactly_the_decision_epoch_plus_one() {
        let ca = keys();
        let subject = keys();
        let transition = transition(&ca, Some(gateway_leaf(&ca, &subject)));
        assert!(verify(&transition, &ca, 1).is_ok());
        assert!(matches!(
            verify(&transition, &ca, 2),
            Err(CertificateError::GenerationConflict { .. })
        ));
        assert!(matches!(
            verify(&transition, &ca, 0),
            Err(CertificateError::GenerationSkipped { .. })
        ));
        assert!(matches!(
            verify(&transition, &ca, 3),
            Err(CertificateError::GenerationRollback { .. })
        ));
    }

    fn abort(
        ca: &Keys,
        transition: &GatewayIdentityTransition,
        aborted_at: u64,
    ) -> GatewayTransitionAbort {
        let mut abort = GatewayTransitionAbort {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: transition.trust_domain_id,
            ca_epoch: transition.ca_epoch,
            gateway_wg_public_key: transition.gateway_wg_public_key,
            server_name: transition.server_name.clone(),
            gateway_identity_epoch: transition.gateway_identity_epoch,
            gateway_transition_fingerprint: transition.fingerprint().expect("fingerprint"),
            aborted_at,
            reason: AbortReason::OperatorCancelled,
            campaign_fingerprint: Fingerprint::of(b"campaign"),
            ca_signature: MlDsa87Signature::new(vec![0; 4627]).expect("placeholder"),
        };
        abort.ca_signature = sign_ml_dsa_87(&ca.private, &abort.signing_bytes()).expect("sign");
        abort
    }

    #[test]
    fn an_abort_is_accepted_only_before_publication_and_before_activation() {
        let ca = keys();
        let subject = keys();
        let transition = transition(&ca, Some(gateway_leaf(&ca, &subject)));
        let abort = abort(&ca, &transition, 1_500);

        assert!(abort.verify(&ca.public, &transition, false, 1_600).is_ok());
        assert!(matches!(
            abort.verify(&ca.public, &transition, true, 1_600),
            Err(CertificateError::AlreadyPublished)
        ));
    }

    /// Antedating the object is not enough: the clock is read under the lock
    /// that holds the staged slot, and it must also be before activation.
    #[test]
    fn an_antedated_abort_arriving_after_activation_is_refused() {
        let ca = keys();
        let subject = keys();
        let transition = transition(&ca, Some(gateway_leaf(&ca, &subject)));
        let abort = abort(&ca, &transition, 1_500);
        assert!(matches!(
            abort.verify(&ca.public, &transition, false, 2_001),
            Err(CertificateError::IllegalStateTransition(_))
        ));
    }

    #[test]
    fn an_abort_naming_another_transition_is_refused() {
        let ca = keys();
        let subject = keys();
        let transition = transition(&ca, Some(gateway_leaf(&ca, &subject)));
        let mut abort = abort(&ca, &transition, 1_500);
        abort.gateway_transition_fingerprint = Fingerprint::of(b"another transition");
        abort.ca_signature = sign_ml_dsa_87(&ca.private, &abort.signing_bytes()).unwrap();
        assert!(matches!(
            abort.verify(&ca.public, &transition, false, 1_600),
            Err(CertificateError::FingerprintMismatch("gateway transition"))
        ));
    }

    #[test]
    fn a_gateway_request_proves_the_new_key_and_the_continuity_of_the_old_one() {
        let active = keys();
        let candidate = keys();
        let mut request = GatewayCertificateRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            gateway_identity_epoch: 2,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            new_ml_dsa_87_public_key: candidate.public.clone(),
            request_id: Id16::new([6; 16]).expect("id"),
            created_at: 1_000,
            expires_at: 1_000 + 3_600,
            new_key_proof: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
            current_key_authorization: None,
        };
        let transcript = request.signing_bytes();
        request.new_key_proof = sign_ml_dsa_87(&candidate.private, &transcript).unwrap();

        // Without the continuity signature, an ordinary renewal is refused.
        assert!(matches!(
            request.verify(
                Continuity::Required(&active.public),
                &domain(),
                1,
                &gateway_key(),
                SERVER_NAME,
                1_100
            ),
            Err(CertificateError::MissingProof("active gateway"))
        ));

        request.current_key_authorization =
            Some(sign_ml_dsa_87(&active.private, &transcript).unwrap());
        assert!(request
            .verify(
                Continuity::Required(&active.public),
                &domain(),
                1,
                &gateway_key(),
                SERVER_NAME,
                1_100
            )
            .is_ok());

        // On the recovery path the field must be absent, not merely unchecked.
        assert!(matches!(
            request.verify(
                Continuity::WaivedForKeyRecovery,
                &domain(),
                1,
                &gateway_key(),
                SERVER_NAME,
                1_100
            ),
            Err(CertificateError::IllegalStateTransition(_))
        ));
    }

    #[test]
    fn an_expired_gateway_request_is_refused() {
        let candidate = keys();
        let mut request = GatewayCertificateRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            gateway_identity_epoch: 2,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            new_ml_dsa_87_public_key: candidate.public.clone(),
            request_id: Id16::new([6; 16]).expect("id"),
            created_at: 1_000,
            expires_at: 1_100,
            new_key_proof: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
            current_key_authorization: None,
        };
        request.new_key_proof =
            sign_ml_dsa_87(&candidate.private, &request.signing_bytes()).unwrap();
        assert!(matches!(
            request.verify(
                Continuity::WaivedForKeyRecovery,
                &domain(),
                1,
                &gateway_key(),
                SERVER_NAME,
                1_100
            ),
            Err(CertificateError::StageExpired)
        ));

        // A lifetime beyond 24 hours is refused whatever the clock says.
        request.expires_at = 1_000 + MAX_REQUEST_LIFETIME_SECS + 1;
        request.new_key_proof =
            sign_ml_dsa_87(&candidate.private, &request.signing_bytes()).unwrap();
        assert!(matches!(
            request.verify(
                Continuity::WaivedForKeyRecovery,
                &domain(),
                1,
                &gateway_key(),
                SERVER_NAME,
                1_100
            ),
            Err(CertificateError::InvalidLease)
        ));
    }
}
