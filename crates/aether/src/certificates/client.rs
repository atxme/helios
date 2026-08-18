//! The client identity: request, staging, receipt, grant, commit and the
//! recovery of an expired leaf — spec §7.
//!
//! # Why a renewal takes five objects instead of one
//!
//! The naive design is: the client asks, the authority issues, the client
//! installs. It has a hole. The authority would have handed out a leaf the
//! gateway has not admitted yet, and a client that then disappears leaves the
//! gateway either refusing an issued identity or holding a generation nobody
//! uses. The five objects close it by ordering the two persistences:
//!
//! 1. [`ClientCertificateRotationRequest`] — the client proves the active key,
//!    the new PQ key and the new TLS key. Three proofs, because continuity
//!    alone would let a stolen active identity pick the successor's keys.
//! 2. [`ClientCertificateStageAuthorization`] — the authority issues both
//!    leaves but does **not** release them; it authorizes the gateway to hold
//!    them as a candidate under a bounded lease.
//! 3. [`GatewayCertificateStageReceipt`] — the gateway persists the candidate,
//!    `fsync`s, and only then signs. This receipt is the proof that admission
//!    happened before issuance was revealed.
//! 4. [`ClientCertificateRotationGrant`] — the authority releases the leaves,
//!    and only against that receipt.
//! 5. [`ClientCertificateStageCommit`] — the client, having persisted the
//!    candidate, commits under both the active and the candidate key. Until
//!    then neither end can present the new generation.
//!
//! Without a commit before the lease expires, both ends purge the candidate
//! and `active + 1` becomes requestable again under a **new** `stage_id`. No
//! object of the dead stage is valid for the new one.
//!
//! # Why TLS and PQ are one indivisible generation
//!
//! A connection recognised under generation `N+1` must present and use the PQ
//! certificate of that same generation. `TLS N / PQ N+1` and `TLS N+1 / PQ N`
//! are refused (spec §3.3). Both pairs are individually valid, and treating
//! the two families as independent sets would let an attacker holding one half
//! of each generation assemble an identity that was never issued.

use serde::{Deserialize, Serialize};

use crate::key_negotiation::{PqCertificate, PqCertificateRole};

use super::{
    approval::{AstraPolicyPin, AstraRenewalApprovalEvidence},
    authority::{AstraIssuerAuthorization, RotationReason},
    encoding::{
        validate_server_name, verify_ml_dsa_87, CanonicalBytes, DerCertificate, Fingerprint, Id16,
        MlDsa87PublicKey, MlDsa87Signature, SignedTranscript, TrustDomainId, WireGuardKey,
    },
    gateway::pq_certificate_fingerprint,
    window::{
        require_next_generation, validate_lease, TransitionWindow, ValidityPeriod,
        MAX_RECOVERY_REQUEST_LIFETIME_SECS, MAX_REQUEST_LIFETIME_SECS, MAX_STAGE_LEASE_SECS,
    },
    CertificateError, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};

const ROTATION_REQUEST_DOMAIN: &[u8] = b"helios-client-certificate-rotation-request-v5";
const STAGE_AUTHORIZATION_DOMAIN: &[u8] = b"helios-client-certificate-stage-authorization-v5";
const STAGE_RECEIPT_DOMAIN: &[u8] = b"helios-gateway-certificate-stage-receipt-v5";
const ROTATION_GRANT_DOMAIN: &[u8] = b"helios-client-certificate-rotation-grant-v5";
const STAGE_COMMIT_DOMAIN: &[u8] = b"helios-client-certificate-stage-commit-v5";
const RECOVERY_REQUEST_DOMAIN: &[u8] = b"helios-expired-client-certificate-recovery-request-v5";
const RECOVERY_APPROVAL_DOMAIN: &[u8] = b"helios-astra-expired-recovery-approval-v5";

/// Longest credential identifier accepted from a FIDO2 authenticator.
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1024;

/// Verifies a client PQ leaf under whichever authority may have issued it.
///
/// After an ordinary renewal a client leaf chains to the **delegated Astra
/// issuer**, not to `CA-PQ`. A consumer that only ever tried the anchor would
/// refuse every renewed identity — which is exactly what happened to the
/// in-tunnel trust-update route before this existed.
///
/// The candidates are supplied by the caller, in the order it trusts them, and
/// they come from its own state: the anchor it pins and the delegation it has
/// installed. The certificate never names the key that verifies it.
pub fn verify_client_leaf_under_any(
    certificate: &PqCertificate,
    issuers: &[&MlDsa87PublicKey],
    client_wg_public_key: &WireGuardKey,
    now_unix: u64,
) -> Result<(), CertificateError> {
    if issuers.is_empty() {
        return Err(CertificateError::UnauthorizedIssuer);
    }
    for issuer in issuers {
        if certificate
            .verify(
                issuer.as_bytes(),
                PqCertificateRole::Client,
                None,
                &client_wg_public_key.to_base64(),
                now_unix,
            )
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(CertificateError::UnauthorizedIssuer)
}

/// One client generation: TLS and PQ bound together (spec §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificateGeneration {
    pub generation: u64,
    pub ca_tls_epoch: u64,
    pub tls_ca_certificate_fingerprint: Fingerprint,
    pub tls_certificate_fingerprint: Fingerprint,
    pub pq_certificate_fingerprint: Fingerprint,
    pub not_before: u64,
    pub not_after: u64,
}

impl ClientCertificateGeneration {
    pub fn validity(&self) -> Result<ValidityPeriod, CertificateError> {
        ValidityPeriod::new(self.not_before, self.not_after)
    }

    /// Whether this generation may be presented at `now_unix`.
    ///
    /// A status of `active` published by Astra never widens this: an expired
    /// leaf stays expired (spec §6 of ADR-008).
    pub fn is_valid_at(&self, now_unix: u64) -> bool {
        self.not_before <= now_unix && now_unix < self.not_after
    }

    /// Refuses the two mixed pairs of spec §3.3.
    ///
    /// Given the TLS and PQ fingerprints a connection actually presented, both
    /// must belong to *this* generation. Called by the gateway after mTLS and
    /// before any negotiation decision.
    pub fn accepts_pair(&self, tls: &Fingerprint, pq: &Fingerprint) -> bool {
        self.tls_certificate_fingerprint.matches(tls) && self.pq_certificate_fingerprint.matches(pq)
    }
}

/// Which authority signed a staging authorization or a grant (spec §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerKind {
    /// `CA-PQ` itself, opened by the operator companion.
    Master,
    /// The bounded online delegation of [`AstraIssuerAuthorization`].
    Astra,
}

impl IssuerKind {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::Master => 0,
            Self::Astra => 1,
        }
    }
}

/// Renewal asked for by an Orion whose identity is still active (spec §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificateRotationRequest {
    pub format_version: u16,
    pub protocol_version: u16,
    pub request_id: Id16,
    pub trust_domain_id: TrustDomainId,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    /// Unchanged by a rotation: a new WireGuard key is a readmission, not a
    /// renewal (spec §7.3).
    pub client_wg_public_key: WireGuardKey,
    pub active_generation: u64,
    pub requested_generation: u64,
    pub active_tls_certificate_fingerprint: Fingerprint,
    pub active_pq_certificate_fingerprint: Fingerprint,
    /// PKCS#10 certification request, DER, signed by the new TLS key.
    pub tls_csr: DerCertificate,
    pub new_ml_dsa_87_public_key: MlDsa87PublicKey,
    pub created_at: u64,
    pub expires_at: u64,
    /// Continuity, by the PQ key of the active generation.
    pub active_pq_signature: MlDsa87Signature,
    /// Possession, by the PQ key being certified.
    pub new_pq_signature: MlDsa87Signature,
}

impl ClientCertificateRotationRequest {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(ROTATION_REQUEST_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.trust_domain_id)
            .id(&self.request_id)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .key(&self.client_wg_public_key)
            .u64(self.active_generation)
            .u64(self.requested_generation)
            .fingerprint(&self.active_tls_certificate_fingerprint)
            .fingerprint(&self.active_pq_certificate_fingerprint)
            .fingerprint(&self.tls_csr.fingerprint())
            .length_prefixed(self.new_ml_dsa_87_public_key.as_bytes())
            .u64(self.created_at)
            .u64(self.expires_at);
        bytes.finish_signed()
    }

    /// Spec §7.2: the signed bytes, then each signature length-prefixed.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes
            .length_prefixed(self.active_pq_signature.as_bytes())
            .length_prefixed(self.new_pq_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Verifies the three proofs and the binding to the admitted peer.
    ///
    /// `active_pq_public_key` comes from the admitted generation, never from
    /// the request: taking the key out of the object that the key is supposed
    /// to authenticate proves nothing at all.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        active_pq_public_key: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        active: &ClientCertificateGeneration,
        client_wg_public_key: &WireGuardKey,
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
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key || self.server_name != server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        validate_server_name(&self.server_name)?;
        if self.client_wg_public_key != *client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        if self.active_generation != active.generation {
            return Err(CertificateError::GenerationRollback {
                current: active.generation,
                proposed: self.active_generation,
            });
        }
        require_next_generation(self.active_generation, self.requested_generation)?;
        if !self
            .active_tls_certificate_fingerprint
            .matches(&active.tls_certificate_fingerprint)
            || !self
                .active_pq_certificate_fingerprint
                .matches(&active.pq_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("active client"));
        }
        if self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_REQUEST_LIFETIME_SECS
        {
            return Err(CertificateError::InvalidLease);
        }
        if now_unix >= self.expires_at {
            return Err(CertificateError::StageExpired);
        }

        let transcript = self.signing_bytes();
        verify_ml_dsa_87(active_pq_public_key, &transcript, &self.active_pq_signature)
            .map_err(|_| CertificateError::MissingProof("active client"))?;
        verify_ml_dsa_87(
            &self.new_ml_dsa_87_public_key,
            &transcript,
            &self.new_pq_signature,
        )
        .map_err(|_| CertificateError::MissingProof("new client"))
    }
}

/// Authority's permission for the gateway to hold a candidate (spec §7.2).
///
/// It carries both issued certificates, but it is **not** the grant: until the
/// gateway has persisted the candidate and signed a receipt, the client never
/// receives anything it could install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificateStageAuthorization {
    pub format_version: u16,
    pub protocol_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub ca_tls_epoch: u64,
    pub issuer_kind: IssuerKind,
    pub issuer_epoch: u64,
    /// All-zero under [`IssuerKind::Master`], where `CA-PQ` signs directly.
    pub issuer_authorization_fingerprint: Fingerprint,
    /// The delegation itself, carried so every consumer can check its scope.
    pub issuer_authorization: Option<AstraIssuerAuthorization>,
    pub stage_id: Id16,
    pub request_fingerprint: Fingerprint,
    /// Non-zero fingerprint of the exact operator approval carried below.
    pub operator_approval_fingerprint: Fingerprint,
    /// Complete ordinary-renewal evidence. Master-authority paths use another
    /// approval family and therefore leave this absent; their caller must
    /// verify that family before invoking this leaf-level verifier.
    pub renewal_approval: Option<AstraRenewalApprovalEvidence>,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub client_wg_public_key: WireGuardKey,
    pub active_generation: u64,
    pub next_generation: u64,
    pub active_tls_certificate_fingerprint: Fingerprint,
    pub active_pq_certificate_fingerprint: Fingerprint,
    pub next_tls_ca_certificate_fingerprint: Fingerprint,
    pub next_tls_certificate: DerCertificate,
    pub next_pq_certificate: PqCertificate,
    pub issued_at: u64,
    pub stage_expires_at: u64,
    pub window: TransitionWindow,
    pub reason: RotationReason,
    pub signature: MlDsa87Signature,
}

impl ClientCertificateStageAuthorization {
    fn signing_bytes(&self) -> Result<SignedTranscript, CertificateError> {
        let next_pq = pq_certificate_fingerprint(&self.next_pq_certificate)?;
        let mut bytes = CanonicalBytes::new(STAGE_AUTHORIZATION_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .u64(self.ca_tls_epoch)
            .u8(self.issuer_kind.domain_byte())
            .u64(self.issuer_epoch)
            .fingerprint(&self.issuer_authorization_fingerprint)
            .id(&self.stage_id)
            .fingerprint(&self.request_fingerprint)
            .fingerprint(&self.operator_approval_fingerprint)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .key(&self.client_wg_public_key)
            .u64(self.active_generation)
            .u64(self.next_generation)
            .fingerprint(&self.active_tls_certificate_fingerprint)
            .fingerprint(&self.active_pq_certificate_fingerprint)
            .fingerprint(&self.next_tls_ca_certificate_fingerprint)
            .fingerprint(&self.next_tls_certificate.fingerprint())
            .fingerprint(&next_pq)
            .u64(self.issued_at)
            .u64(self.stage_expires_at)
            .u64(self.window.not_before)
            .u64(self.window.activation_at)
            .u64(self.window.not_after)
            .u8(self.reason.domain_byte());
        Ok(bytes.finish_signed())
    }

    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        let mut bytes = CanonicalBytes::new(self.signing_bytes()?.as_bytes());
        bytes.length_prefixed(self.signature.as_bytes());
        Ok(Fingerprint::of(&bytes.finish()))
    }

    /// The candidate generation this authorization describes.
    pub fn candidate(&self) -> Result<ClientCertificateGeneration, CertificateError> {
        Ok(ClientCertificateGeneration {
            generation: self.next_generation,
            ca_tls_epoch: self.ca_tls_epoch,
            tls_ca_certificate_fingerprint: self.next_tls_ca_certificate_fingerprint,
            tls_certificate_fingerprint: self.next_tls_certificate.fingerprint(),
            pq_certificate_fingerprint: pq_certificate_fingerprint(&self.next_pq_certificate)?,
            not_before: self.next_pq_certificate.not_before_unix,
            not_after: self.next_pq_certificate.not_after_unix,
        })
    }

    /// Verifies the authorization as Helios does before persisting anything.
    ///
    /// `request_expires_at` is `Some` only where the caller holds the request
    /// itself — Astra. Helios never sees it, so it enforces the bounds it can
    /// see: the lease ceiling and `activation_at`.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        client_wg_public_key: &WireGuardKey,
        active: &ClientCertificateGeneration,
        tls_anchors: &[&DerCertificate],
        policy_pin: Option<&AstraPolicyPin>,
        request_expires_at: Option<u64>,
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
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.ca_epoch != ca_epoch || self.ca_tls_epoch != ca_tls_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key || self.server_name != server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.client_wg_public_key != *client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        if self
            .operator_approval_fingerprint
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(CertificateError::ApprovalMismatch("missing approval"));
        }
        match (self.issuer_kind, &self.renewal_approval) {
            (IssuerKind::Astra, Some(evidence))
                if self
                    .operator_approval_fingerprint
                    .matches(&evidence.fingerprint()) => {}
            (IssuerKind::Astra, Some(_)) => {
                return Err(CertificateError::ApprovalMismatch(
                    "operator approval fingerprint",
                ));
            }
            (IssuerKind::Astra, None) => {
                return Err(CertificateError::ApprovalMismatch(
                    "delegated renewal approval",
                ));
            }
            // Master-authority operations use their own approval family. It
            // must not be confused with an ordinary delegated renewal.
            (IssuerKind::Master, Some(_)) => {
                return Err(CertificateError::ApprovalMismatch(
                    "unexpected delegated renewal approval",
                ));
            }
            (IssuerKind::Master, None) => {}
        }
        if self.active_generation != active.generation {
            return Err(CertificateError::GenerationRollback {
                current: active.generation,
                proposed: self.active_generation,
            });
        }
        require_next_generation(self.active_generation, self.next_generation)?;
        if !self
            .active_tls_certificate_fingerprint
            .matches(&active.tls_certificate_fingerprint)
            || !self
                .active_pq_certificate_fingerprint
                .matches(&active.pq_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("active client"));
        }
        self.window.validate()?;

        let mut bounds = vec![self.window.activation_at];
        if let Some(expiry) = request_expires_at {
            bounds.push(expiry);
        }
        validate_lease(
            self.issued_at,
            self.stage_expires_at,
            MAX_STAGE_LEASE_SECS,
            &bounds,
        )?;
        if now_unix >= self.stage_expires_at {
            return Err(CertificateError::StageExpired);
        }

        // Resolve the issuer **before** touching the leaf: a leaf signed by the
        // delegated issuer chains to that issuer, not to `CA-PQ`, and reading
        // it under the wrong key would refuse every ordinary renewal — or, the
        // other way round, accept a leaf nobody authorized.
        let issuer_key = self.resolve_issuer(
            ca_pq,
            trust_domain_id,
            ca_epoch,
            ca_tls_epoch,
            gateway_wg_public_key,
            server_name,
            &self.next_pq_certificate,
            self.active_generation,
            self.next_generation,
            self.reason,
            policy_pin,
            now_unix,
        )?;

        // The incoming PQ leaf is read at `activation_at`, for the same reason
        // a gateway leaf is: a candidate prepared ahead of time is not valid
        // today, and it must still be valid at the end of the overlap.
        self.next_pq_certificate
            .verify(
                issuer_key.as_bytes(),
                PqCertificateRole::Client,
                None,
                &client_wg_public_key.to_base64(),
                self.window.activation_at,
            )
            .map_err(|_| CertificateError::UnauthorizedIssuer)?;
        if self.next_pq_certificate.not_after_unix < self.window.not_after {
            return Err(CertificateError::OutsideValidityPeriod);
        }
        self.verify_tls_leaf(tls_anchors)?;

        verify_ml_dsa_87(issuer_key, &self.signing_bytes()?, &self.signature)
    }

    /// The TLS half of the candidate: a real client leaf, on a real path.
    ///
    /// The PQ half has always been verified; the TLS one used to be a byte
    /// string nobody parsed. A generation is indivisible, so half of it being
    /// unchecked made the whole of it unchecked.
    fn verify_tls_leaf(&self, tls_anchors: &[&DerCertificate]) -> Result<(), CertificateError> {
        crate::certificates::x509::assert_client_leaf(
            &self.next_tls_certificate,
            self.window.activation_at,
            self.window.not_after,
        )?;
        let intermediates: Vec<&DerCertificate> = self
            .issuer_authorization
            .as_ref()
            .map(|delegation| vec![&delegation.tls_intermediate_certificate])
            .unwrap_or_default();
        // The chain is read at `activation_at`, like the leaf itself: an anchor
        // that expires before the candidate goes into service could not have
        // vouched for it there.
        crate::certificates::x509::assert_chains_to(
            &self.next_tls_certificate,
            &intermediates,
            tls_anchors,
            self.window.activation_at,
            self.window.not_after,
        )?;
        // The anchor the object *names* must be the one it actually chains to.
        if !tls_anchors.iter().any(|anchor| {
            anchor
                .fingerprint()
                .matches(&self.next_tls_ca_certificate_fingerprint)
        }) {
            return Err(CertificateError::FingerprintMismatch("client TLS CA"));
        }
        Ok(())
    }

    /// The key that signed both this object and the leaf it carries.
    ///
    /// Under [`IssuerKind::Master`] that is `CA-PQ` itself, and the delegation
    /// fields must be absent — naming two authorities at once is one authority
    /// too many. Under [`IssuerKind::Astra`] the delegation is verified
    /// against the anchor first, then its scope, and only then is its key
    /// allowed to stand for the authority.
    #[allow(clippy::too_many_arguments)]
    fn resolve_issuer<'a>(
        &'a self,
        ca_pq: &'a MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        leaf: &PqCertificate,
        active_generation: u64,
        next_generation: u64,
        reason: RotationReason,
        policy_pin: Option<&AstraPolicyPin>,
        now_unix: u64,
    ) -> Result<&'a MlDsa87PublicKey, CertificateError> {
        match self.issuer_kind {
            IssuerKind::Master => {
                if self.issuer_authorization.is_some()
                    || self.issuer_authorization_fingerprint != Fingerprint::from_bytes([0; 32])
                {
                    return Err(CertificateError::UnauthorizedIssuer);
                }
                Ok(ca_pq)
            }
            IssuerKind::Astra => {
                let delegation = self
                    .issuer_authorization
                    .as_ref()
                    .ok_or(CertificateError::UnauthorizedIssuer)?;
                policy_pin
                    .ok_or(CertificateError::PolicyNotPinned)?
                    .assert_authorizes(delegation)?;
                delegation.verify(
                    ca_pq,
                    trust_domain_id,
                    ca_epoch,
                    ca_tls_epoch,
                    gateway_wg_public_key,
                    server_name,
                    now_unix,
                )?;
                if delegation.issuer_epoch != self.issuer_epoch
                    || !self
                        .issuer_authorization_fingerprint
                        .matches(&delegation.fingerprint())
                {
                    return Err(CertificateError::UnauthorizedIssuer);
                }
                let lifetime = leaf
                    .not_after_unix
                    .checked_sub(leaf.not_before_unix)
                    .ok_or(CertificateError::InvalidValidityPeriod)?;
                delegation.authorize_renewal(
                    active_generation,
                    next_generation,
                    lifetime,
                    reason,
                )?;
                Ok(&delegation.pq_issuer_public_key)
            }
        }
    }
}

/// Proof that the gateway persisted the candidate before it was released.
///
/// Signed by the **active** gateway PQ leaf, after an atomic write and an
/// `fsync` of the file and of its directory (spec §7.3). Astra refuses to
/// build a grant without it, which is what keeps an issued client identity
/// from existing before the gateway admits it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayCertificateStageReceipt {
    pub format_version: u16,
    pub protocol_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub stage_id: Id16,
    pub stage_authorization_fingerprint: Fingerprint,
    pub request_fingerprint: Fingerprint,
    pub operator_approval_fingerprint: Fingerprint,
    pub gateway_wg_public_key: WireGuardKey,
    pub client_wg_public_key: WireGuardKey,
    pub active_generation: u64,
    pub staged_generation: u64,
    pub staged_tls_certificate_fingerprint: Fingerprint,
    pub staged_pq_certificate_fingerprint: Fingerprint,
    pub persisted_at: u64,
    pub stage_expires_at: u64,
    pub active_gateway_identity_epoch: u64,
    pub gateway_decision_epoch: u64,
    pub gateway_certificate_fingerprint: Fingerprint,
    pub gateway_signature: MlDsa87Signature,
}

impl GatewayCertificateStageReceipt {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(STAGE_RECEIPT_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.trust_domain_id)
            .id(&self.stage_id)
            .fingerprint(&self.stage_authorization_fingerprint)
            .fingerprint(&self.request_fingerprint)
            .fingerprint(&self.operator_approval_fingerprint)
            .key(&self.gateway_wg_public_key)
            .key(&self.client_wg_public_key)
            .u64(self.active_generation)
            .u64(self.staged_generation)
            .fingerprint(&self.staged_tls_certificate_fingerprint)
            .fingerprint(&self.staged_pq_certificate_fingerprint)
            .u64(self.persisted_at)
            .u64(self.stage_expires_at)
            .u64(self.active_gateway_identity_epoch)
            .u64(self.gateway_decision_epoch)
            .fingerprint(&self.gateway_certificate_fingerprint);
        bytes.finish_signed()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes.length_prefixed(self.gateway_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Verifies the receipt against the authorization it answers.
    ///
    /// Every field is compared, not merely the identifier: a receipt that
    /// named the right `stage_id` while describing another generation would be
    /// a valid signature over the wrong fact.
    pub fn verify(
        &self,
        gateway_pq_public_key: &MlDsa87PublicKey,
        gateway_certificate_fingerprint: &Fingerprint,
        authorization: &ClientCertificateStageAuthorization,
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
        if self.trust_domain_id != authorization.trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.stage_id != authorization.stage_id {
            return Err(CertificateError::UnknownStage);
        }
        if !self
            .stage_authorization_fingerprint
            .matches(&authorization.fingerprint()?)
            || !self
                .request_fingerprint
                .matches(&authorization.request_fingerprint)
            || !self
                .operator_approval_fingerprint
                .matches(&authorization.operator_approval_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("stage authorization"));
        }
        if self.gateway_wg_public_key != authorization.gateway_wg_public_key {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.client_wg_public_key != authorization.client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        if self.active_generation != authorization.active_generation
            || self.staged_generation != authorization.next_generation
        {
            return Err(CertificateError::GenerationConflict {
                generation: self.staged_generation,
            });
        }
        let candidate = authorization.candidate()?;
        if !self
            .staged_tls_certificate_fingerprint
            .matches(&candidate.tls_certificate_fingerprint)
            || !self
                .staged_pq_certificate_fingerprint
                .matches(&candidate.pq_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("staged client"));
        }
        if self.stage_expires_at != authorization.stage_expires_at {
            return Err(CertificateError::InvalidLease);
        }
        if !self
            .gateway_certificate_fingerprint
            .matches(gateway_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("gateway leaf"));
        }
        verify_ml_dsa_87(
            gateway_pq_public_key,
            &self.signing_bytes(),
            &self.gateway_signature,
        )
    }
}

/// Release of the two issued leaves, against a valid receipt (spec §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificateRotationGrant {
    pub format_version: u16,
    pub protocol_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub ca_tls_epoch: u64,
    pub issuer_kind: IssuerKind,
    pub issuer_epoch: u64,
    pub issuer_authorization_fingerprint: Fingerprint,
    pub issuer_authorization: Option<AstraIssuerAuthorization>,
    pub request_fingerprint: Fingerprint,
    pub operator_approval_fingerprint: Fingerprint,
    pub renewal_approval: Option<AstraRenewalApprovalEvidence>,
    pub stage_receipt_fingerprint: Fingerprint,
    pub stage_receipt: GatewayCertificateStageReceipt,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub client_wg_public_key: WireGuardKey,
    pub active_generation: u64,
    pub next_generation: u64,
    pub active_tls_certificate_fingerprint: Fingerprint,
    pub active_pq_certificate_fingerprint: Fingerprint,
    pub next_tls_ca_certificate_fingerprint: Fingerprint,
    pub next_tls_certificate: DerCertificate,
    pub next_pq_certificate: PqCertificate,
    pub stage_expires_at: u64,
    pub window: TransitionWindow,
    pub reason: RotationReason,
    pub signature: MlDsa87Signature,
}

impl ClientCertificateRotationGrant {
    fn signing_bytes(&self) -> Result<SignedTranscript, CertificateError> {
        let next_pq = pq_certificate_fingerprint(&self.next_pq_certificate)?;
        let mut bytes = CanonicalBytes::new(ROTATION_GRANT_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .u64(self.ca_tls_epoch)
            .u8(self.issuer_kind.domain_byte())
            .u64(self.issuer_epoch)
            .fingerprint(&self.issuer_authorization_fingerprint)
            .fingerprint(&self.request_fingerprint)
            .fingerprint(&self.operator_approval_fingerprint)
            .fingerprint(&self.stage_receipt_fingerprint)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .key(&self.client_wg_public_key)
            .u64(self.active_generation)
            .u64(self.next_generation)
            .fingerprint(&self.active_tls_certificate_fingerprint)
            .fingerprint(&self.active_pq_certificate_fingerprint)
            .fingerprint(&self.next_tls_ca_certificate_fingerprint)
            .fingerprint(&self.next_tls_certificate.fingerprint())
            .fingerprint(&next_pq)
            .u64(self.stage_expires_at)
            .u64(self.window.not_before)
            .u64(self.window.activation_at)
            .u64(self.window.not_after)
            .u8(self.reason.domain_byte());
        Ok(bytes.finish_signed())
    }

    pub fn fingerprint(&self) -> Result<Fingerprint, CertificateError> {
        let mut bytes = CanonicalBytes::new(self.signing_bytes()?.as_bytes());
        bytes.length_prefixed(self.signature.as_bytes());
        Ok(Fingerprint::of(&bytes.finish()))
    }

    pub fn candidate(&self) -> Result<ClientCertificateGeneration, CertificateError> {
        Ok(ClientCertificateGeneration {
            generation: self.next_generation,
            ca_tls_epoch: self.ca_tls_epoch,
            tls_ca_certificate_fingerprint: self.next_tls_ca_certificate_fingerprint,
            tls_certificate_fingerprint: self.next_tls_certificate.fingerprint(),
            pq_certificate_fingerprint: pq_certificate_fingerprint(&self.next_pq_certificate)?,
            not_before: self.next_pq_certificate.not_before_unix,
            not_after: self.next_pq_certificate.not_after_unix,
        })
    }

    /// Verifies the grant as Orion does, before writing anything locally.
    ///
    /// The embedded receipt is verified under the gateway leaf **this client
    /// pins**: a grant is only worth what the gateway admitted, and a receipt
    /// signed by another gateway describes another fleet.
    ///
    /// On top of what [`Self::verify_for_gateway`] checks, this binds the
    /// grant to the **local** request: its fingerprint, its generations and
    /// the public key it proved possession of. Without that, a valid grant
    /// issued for another machine would be installed against private keys
    /// nobody on this one holds.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        gateway_pq_public_key: &MlDsa87PublicKey,
        gateway_certificate_fingerprint: &Fingerprint,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        client_wg_public_key: &WireGuardKey,
        request: &ClientCertificateRotationRequest,
        tls_anchors: &[&DerCertificate],
        policy_pin: Option<&AstraPolicyPin>,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        let issuer_key = self.verify_common(
            ca_pq,
            gateway_pq_public_key,
            gateway_certificate_fingerprint,
            trust_domain_id,
            ca_epoch,
            ca_tls_epoch,
            gateway_wg_public_key,
            server_name,
            client_wg_public_key,
            tls_anchors,
            policy_pin,
            now_unix,
        )?;

        // The TLS leaf must certify the key **this** client generated. A grant
        // can be perfectly signed and still install a certificate whose private
        // key nobody holds; the failure would then surface at the next mTLS
        // handshake, after the old generation was retired.
        crate::certificates::x509::assert_csr_matches(
            &request.tls_csr,
            &self.next_tls_certificate,
        )?;

        if !self.request_fingerprint.matches(&request.fingerprint()) {
            return Err(CertificateError::FingerprintMismatch("rotation request"));
        }
        if self.active_generation != request.active_generation
            || self.next_generation != request.requested_generation
        {
            return Err(CertificateError::GenerationConflict {
                generation: self.next_generation,
            });
        }
        // The leaf must certify the key the client actually generated, or the
        // candidate would be a certificate without a usable private key.
        if self.next_pq_certificate.ml_dsa_87_public_key
            != request.new_ml_dsa_87_public_key.to_base64()
        {
            return Err(CertificateError::MissingProof("new client"));
        }

        verify_ml_dsa_87(issuer_key, &self.signing_bytes()?, &self.signature)
    }

    /// Verifies the grant as **Helios** does, on a commit arriving in the
    /// tunnel (spec §7.3).
    ///
    /// The gateway never sees the rotation request — it only ever held the
    /// staging authorization — so it binds the grant to what it *does* know:
    /// the receipt it signed itself, the candidate it persisted, and the
    /// generation that candidate follows. Requiring the grant here is what
    /// closes the protocol: without it a client holding both private keys
    /// could commit a candidate the authority never released.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_for_gateway(
        &self,
        ca_pq: &MlDsa87PublicKey,
        gateway_pq_public_key: &MlDsa87PublicKey,
        gateway_certificate_fingerprint: &Fingerprint,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        client_wg_public_key: &WireGuardKey,
        active_generation: u64,
        candidate: &ClientCertificateGeneration,
        stage_id: &Id16,
        tls_anchors: &[&DerCertificate],
        policy_pin: Option<&AstraPolicyPin>,
        now_unix: u64,
    ) -> Result<(), CertificateError> {
        let issuer_key = self.verify_common(
            ca_pq,
            gateway_pq_public_key,
            gateway_certificate_fingerprint,
            trust_domain_id,
            ca_epoch,
            ca_tls_epoch,
            gateway_wg_public_key,
            server_name,
            client_wg_public_key,
            tls_anchors,
            policy_pin,
            now_unix,
        )?;

        if self.stage_receipt.stage_id != *stage_id {
            return Err(CertificateError::UnknownStage);
        }
        if self.active_generation != active_generation {
            return Err(CertificateError::GenerationConflict {
                generation: self.active_generation,
            });
        }
        // Every field of the candidate, not just its fingerprints: a grant
        // that released another window or another TLS anchor for the same two
        // leaves would be describing a different decision.
        if self.candidate()? != *candidate {
            return Err(CertificateError::FingerprintMismatch("staged client"));
        }

        verify_ml_dsa_87(issuer_key, &self.signing_bytes()?, &self.signature)
    }

    /// Everything both verifiers share: identities, the embedded receipt, the
    /// window, and the resolution of the issuer that signed the leaf.
    ///
    /// Returns the issuer key, so neither caller can verify the grant's own
    /// signature under a key the grant chose for itself.
    #[allow(clippy::too_many_arguments)]
    fn verify_common<'a>(
        &'a self,
        ca_pq: &'a MlDsa87PublicKey,
        gateway_pq_public_key: &MlDsa87PublicKey,
        gateway_certificate_fingerprint: &Fingerprint,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        client_wg_public_key: &WireGuardKey,
        tls_anchors: &[&DerCertificate],
        policy_pin: Option<&AstraPolicyPin>,
        now_unix: u64,
    ) -> Result<&'a MlDsa87PublicKey, CertificateError> {
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
        if self.ca_epoch != ca_epoch || self.ca_tls_epoch != ca_tls_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key || self.server_name != server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.client_wg_public_key != *client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        if self
            .operator_approval_fingerprint
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(CertificateError::ApprovalMismatch("missing approval"));
        }
        match (self.issuer_kind, &self.renewal_approval) {
            (IssuerKind::Astra, Some(evidence))
                if self
                    .operator_approval_fingerprint
                    .matches(&evidence.fingerprint()) => {}
            (IssuerKind::Astra, Some(_)) => {
                return Err(CertificateError::ApprovalMismatch(
                    "operator approval fingerprint",
                ));
            }
            (IssuerKind::Astra, None) => {
                return Err(CertificateError::ApprovalMismatch(
                    "delegated renewal approval",
                ));
            }
            (IssuerKind::Master, Some(_)) => {
                return Err(CertificateError::ApprovalMismatch(
                    "unexpected delegated renewal approval",
                ));
            }
            (IssuerKind::Master, None) => {}
        }
        if !self
            .stage_receipt_fingerprint
            .matches(&self.stage_receipt.fingerprint())
        {
            return Err(CertificateError::FingerprintMismatch("stage receipt"));
        }
        if self.stage_receipt.stage_expires_at != self.stage_expires_at
            || self.stage_receipt.staged_generation != self.next_generation
            || !self
                .stage_receipt
                .request_fingerprint
                .matches(&self.request_fingerprint)
            || !self
                .stage_receipt
                .operator_approval_fingerprint
                .matches(&self.operator_approval_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("stage receipt"));
        }
        let candidate = self.candidate()?;
        if !self
            .stage_receipt
            .staged_tls_certificate_fingerprint
            .matches(&candidate.tls_certificate_fingerprint)
            || !self
                .stage_receipt
                .staged_pq_certificate_fingerprint
                .matches(&candidate.pq_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("staged client"));
        }
        verify_ml_dsa_87(
            gateway_pq_public_key,
            &self.stage_receipt.signing_bytes(),
            &self.stage_receipt.gateway_signature,
        )
        .map_err(|_| CertificateError::MissingProof("gateway receipt"))?;
        if !self
            .stage_receipt
            .gateway_certificate_fingerprint
            .matches(gateway_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("gateway leaf"));
        }

        self.window.validate()?;
        if now_unix >= self.stage_expires_at {
            return Err(CertificateError::StageExpired);
        }

        let issuer_key = self.resolve_issuer(
            ca_pq,
            trust_domain_id,
            ca_epoch,
            ca_tls_epoch,
            gateway_wg_public_key,
            server_name,
            policy_pin,
            now_unix,
        )?;
        self.next_pq_certificate
            .verify(
                issuer_key.as_bytes(),
                PqCertificateRole::Client,
                None,
                &client_wg_public_key.to_base64(),
                self.window.activation_at,
            )
            .map_err(|_| CertificateError::UnauthorizedIssuer)?;
        crate::certificates::x509::assert_client_leaf(
            &self.next_tls_certificate,
            self.window.activation_at,
            self.window.not_after,
        )?;
        let intermediates: Vec<&DerCertificate> = self
            .issuer_authorization
            .as_ref()
            .map(|delegation| vec![&delegation.tls_intermediate_certificate])
            .unwrap_or_default();
        crate::certificates::x509::assert_chains_to(
            &self.next_tls_certificate,
            &intermediates,
            tls_anchors,
            self.window.activation_at,
            self.window.not_after,
        )?;
        if !tls_anchors.iter().any(|anchor| {
            anchor
                .fingerprint()
                .matches(&self.next_tls_ca_certificate_fingerprint)
        }) {
            return Err(CertificateError::FingerprintMismatch("client TLS CA"));
        }
        Ok(issuer_key)
    }

    /// Same rule as [`ClientCertificateStageAuthorization::resolve_issuer`]:
    /// the delegated issuer stands for the authority only after `CA-PQ` has
    /// authorized it and its scope has been checked.
    #[allow(clippy::too_many_arguments)]
    fn resolve_issuer<'a>(
        &'a self,
        ca_pq: &'a MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        ca_tls_epoch: u64,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        policy_pin: Option<&AstraPolicyPin>,
        now_unix: u64,
    ) -> Result<&'a MlDsa87PublicKey, CertificateError> {
        match self.issuer_kind {
            IssuerKind::Master => {
                if self.issuer_authorization.is_some()
                    || self.issuer_authorization_fingerprint != Fingerprint::from_bytes([0; 32])
                {
                    return Err(CertificateError::UnauthorizedIssuer);
                }
                Ok(ca_pq)
            }
            IssuerKind::Astra => {
                let delegation = self
                    .issuer_authorization
                    .as_ref()
                    .ok_or(CertificateError::UnauthorizedIssuer)?;
                policy_pin
                    .ok_or(CertificateError::PolicyNotPinned)?
                    .assert_authorizes(delegation)?;
                delegation.verify(
                    ca_pq,
                    trust_domain_id,
                    ca_epoch,
                    ca_tls_epoch,
                    gateway_wg_public_key,
                    server_name,
                    now_unix,
                )?;
                if delegation.issuer_epoch != self.issuer_epoch
                    || !self
                        .issuer_authorization_fingerprint
                        .matches(&delegation.fingerprint())
                {
                    return Err(CertificateError::UnauthorizedIssuer);
                }
                let lifetime = self
                    .next_pq_certificate
                    .not_after_unix
                    .checked_sub(self.next_pq_certificate.not_before_unix)
                    .ok_or(CertificateError::InvalidValidityPeriod)?;
                delegation.authorize_renewal(
                    self.active_generation,
                    self.next_generation,
                    lifetime,
                    self.reason,
                )?;
                Ok(&delegation.pq_issuer_public_key)
            }
        }
    }
}

/// The client's commit, signed by the active **and** the candidate PQ key.
///
/// Two signatures because the commit does two things: it proves the client
/// that owns the current generation asked for the change, and it proves the
/// client actually holds the private key of the generation it is about to
/// depend on. A commit signed only by the candidate would let a leaked grant
/// install an identity its owner never asked for; one signed only by the
/// active key would let a client commit to a key it cannot use, and lock
/// itself out at `activation_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCertificateStageCommit {
    pub format_version: u16,
    pub protocol_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub stage_id: Id16,
    pub grant_fingerprint: Fingerprint,
    pub stage_receipt_fingerprint: Fingerprint,
    pub gateway_wg_public_key: WireGuardKey,
    pub client_wg_public_key: WireGuardKey,
    pub active_generation: u64,
    pub staged_generation: u64,
    pub staged_tls_certificate_fingerprint: Fingerprint,
    pub staged_pq_certificate_fingerprint: Fingerprint,
    pub stage_expires_at: u64,
    pub committed_at: u64,
    pub active_pq_signature: MlDsa87Signature,
    pub staged_pq_signature: MlDsa87Signature,
}

impl ClientCertificateStageCommit {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(STAGE_COMMIT_DOMAIN);
        bytes
            .u16(self.format_version)
            .u16(self.protocol_version)
            .id(&self.trust_domain_id)
            .id(&self.stage_id)
            .fingerprint(&self.grant_fingerprint)
            .fingerprint(&self.stage_receipt_fingerprint)
            .key(&self.gateway_wg_public_key)
            .key(&self.client_wg_public_key)
            .u64(self.active_generation)
            .u64(self.staged_generation)
            .fingerprint(&self.staged_tls_certificate_fingerprint)
            .fingerprint(&self.staged_pq_certificate_fingerprint)
            .u64(self.stage_expires_at)
            .u64(self.committed_at);
        bytes.finish_signed()
    }

    /// SHA-256 of the signed transcript followed by both client signatures.
    ///
    /// This is the identity a replay is recognised by: once the candidate has
    /// become `next`, nothing else about the commit is still comparable, and
    /// "the same stage identifier" is not the same document.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes
            .length_prefixed(self.active_pq_signature.as_bytes())
            .length_prefixed(self.staged_pq_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Verifies the commit against the candidate the gateway is holding.
    ///
    /// The clock is read **once** by the caller, under the same serializer as
    /// revocation and purge, and both `committed_at` and `now_unix` must be
    /// before the lease expiry: a client cannot antedate a commit that arrived
    /// too late and win the race against the purge.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        active_pq_public_key: &MlDsa87PublicKey,
        staged_pq_public_key: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        client_wg_public_key: &WireGuardKey,
        stage_id: &Id16,
        candidate: &ClientCertificateGeneration,
        active_generation: u64,
        stage_expires_at: u64,
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
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.stage_id != *stage_id {
            return Err(CertificateError::UnknownStage);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.client_wg_public_key != *client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        if self.active_generation != active_generation
            || self.staged_generation != candidate.generation
        {
            return Err(CertificateError::GenerationConflict {
                generation: self.staged_generation,
            });
        }
        if !self
            .staged_tls_certificate_fingerprint
            .matches(&candidate.tls_certificate_fingerprint)
            || !self
                .staged_pq_certificate_fingerprint
                .matches(&candidate.pq_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("staged client"));
        }
        if self.stage_expires_at != stage_expires_at {
            return Err(CertificateError::InvalidLease);
        }
        if self.committed_at >= stage_expires_at || now_unix >= stage_expires_at {
            return Err(CertificateError::StageExpired);
        }

        let transcript = self.signing_bytes();
        verify_ml_dsa_87(active_pq_public_key, &transcript, &self.active_pq_signature)
            .map_err(|_| CertificateError::MissingProof("active client"))?;
        verify_ml_dsa_87(staged_pq_public_key, &transcript, &self.staged_pq_signature)
            .map_err(|_| CertificateError::MissingProof("staged client"))
    }
}

/// Recovery of an identity whose leaf has already expired (spec §7.5).
///
/// The expired certificate is a **historical proof**, never a credential: it
/// is refused by mTLS, by QUIC and by every ordinary validator, and the
/// separate validator used here checks signature, chain, identities,
/// fingerprints and last known generation — everything except the period. It
/// is a distinct type precisely so the negotiation path cannot reach it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpiredCertificateRecoveryRequest {
    pub format_version: u16,
    pub protocol_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub astra_challenge: [u8; 32],
    pub request_id: Id16,
    pub gateway_wg_public_key: WireGuardKey,
    pub server_name: String,
    pub client_wg_public_key: WireGuardKey,
    pub expired_generation: u64,
    pub requested_generation: u64,
    /// The complete expired leaves, so the historical validator can check the
    /// chain rather than trust a fingerprint the requester chose.
    pub expired_tls_certificate: DerCertificate,
    pub expired_pq_certificate: PqCertificate,
    pub tls_csr: DerCertificate,
    pub new_ml_dsa_87_public_key: MlDsa87PublicKey,
    /// Identifier of the operator credential that will approve the request.
    pub credential_id: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    /// Signed by the private key of the expired generation.
    pub expired_pq_signature: MlDsa87Signature,
    pub new_pq_signature: MlDsa87Signature,
}

impl ExpiredCertificateRecoveryRequest {
    fn signing_bytes(&self) -> SignedTranscript {
        let mut bytes = CanonicalBytes::new(RECOVERY_REQUEST_DOMAIN);
        bytes
            .id(&self.trust_domain_id)
            .raw(&self.astra_challenge)
            .id(&self.request_id)
            .key(&self.gateway_wg_public_key)
            .text(&self.server_name)
            .key(&self.client_wg_public_key)
            .u64(self.expired_generation)
            .u64(self.requested_generation)
            .fingerprint(&self.expired_tls_certificate.fingerprint())
            .fingerprint(
                &pq_certificate_fingerprint(&self.expired_pq_certificate)
                    .unwrap_or_else(|_| Fingerprint::from_bytes([0; 32])),
            )
            .fingerprint(&self.tls_csr.fingerprint())
            .length_prefixed(self.new_ml_dsa_87_public_key.as_bytes())
            .fingerprint(&Fingerprint::of(&self.credential_id))
            .u64(self.created_at)
            .u64(self.expires_at);
        bytes.finish_signed()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(self.signing_bytes().as_bytes());
        bytes
            .length_prefixed(self.expired_pq_signature.as_bytes())
            .length_prefixed(self.new_pq_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// The historical validator of spec §7.5.
    ///
    /// It ignores the validity period **and nothing else**, and only after
    /// everything else has passed. `last_known` is the last generation Astra
    /// recorded for this peer: a request naming an older one, or one for which
    /// a newer generation exists, is refused before any signature work that
    /// would confirm the peer exists.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_historical(
        &self,
        issuers: &[&MlDsa87PublicKey],
        trust_domain_id: &TrustDomainId,
        gateway_wg_public_key: &WireGuardKey,
        server_name: &str,
        client_wg_public_key: &WireGuardKey,
        last_known: &ClientCertificateGeneration,
        expected_challenge: &[u8; 32],
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
        if self.trust_domain_id != *trust_domain_id {
            return Err(CertificateError::TrustDomainMismatch);
        }
        if self.astra_challenge != *expected_challenge
            || self.astra_challenge.iter().all(|byte| *byte == 0)
        {
            return Err(CertificateError::InvalidChallenge);
        }
        if self.gateway_wg_public_key != *gateway_wg_public_key || self.server_name != server_name {
            return Err(CertificateError::GatewayIdentityMismatch);
        }
        if self.client_wg_public_key != *client_wg_public_key {
            return Err(CertificateError::ClientIdentityMismatch);
        }
        if self.credential_id.is_empty() || self.credential_id.len() > MAX_CREDENTIAL_ID_BYTES {
            return Err(CertificateError::CampaignMismatch);
        }
        if self.expired_generation != last_known.generation {
            return Err(CertificateError::GenerationRollback {
                current: last_known.generation,
                proposed: self.expired_generation,
            });
        }
        require_next_generation(self.expired_generation, self.requested_generation)?;
        if self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_RECOVERY_REQUEST_LIFETIME_SECS
        {
            return Err(CertificateError::InvalidLease);
        }
        if now_unix >= self.expires_at {
            return Err(CertificateError::StageExpired);
        }
        // The expired leaves must be exactly the last recorded ones. This is
        // where an attacker holding *some* old certificate of the peer is
        // stopped: only the newest one can prove continuity.
        if !self
            .expired_tls_certificate
            .fingerprint()
            .matches(&last_known.tls_certificate_fingerprint)
        {
            return Err(CertificateError::FingerprintMismatch("expired TLS leaf"));
        }
        let expired_pq = pq_certificate_fingerprint(&self.expired_pq_certificate)?;
        if !expired_pq.matches(&last_known.pq_certificate_fingerprint) {
            return Err(CertificateError::FingerprintMismatch("expired PQ leaf"));
        }
        // The chain is verified at an instant **inside** the expired leaf's own
        // validity: this validator waives the period, it does not waive the
        // issuer signature, the role or the WireGuard binding. The leaf may
        // have been issued by a delegated issuer of an earlier epoch, so the
        // caller supplies every authority that could legitimately have signed
        // it.
        verify_client_leaf_under_any(
            &self.expired_pq_certificate,
            issuers,
            client_wg_public_key,
            self.expired_pq_certificate.not_before_unix,
        )?;

        let expired_key =
            MlDsa87PublicKey::parse(&self.expired_pq_certificate.ml_dsa_87_public_key)?;
        let transcript = self.signing_bytes();
        verify_ml_dsa_87(&expired_key, &transcript, &self.expired_pq_signature)
            .map_err(|_| CertificateError::MissingProof("expired client"))?;
        verify_ml_dsa_87(
            &self.new_ml_dsa_87_public_key,
            &transcript,
            &self.new_pq_signature,
        )
        .map_err(|_| CertificateError::MissingProof("new client"))
    }

    /// The exact operation an operator confirms for this request.
    ///
    /// Not something the token signs: a YubiKey signs no ML-DSA, and nothing
    /// here verifies a WebAuthn assertion. This is the value `astra-signer`
    /// displays before the touch that unwraps the vault, and the value the
    /// resulting `CA-PQ` signature is bound to.
    pub fn approval_challenge(&self) -> Fingerprint {
        expired_recovery_approval_challenge(
            &self.fingerprint(),
            &self.astra_challenge,
            self.expires_at,
        )
    }
}

/// The operation hash bound to one recovery request (spec §7.5).
///
/// It is what makes an approval unmovable: displayed before the unlock and
/// bound into the signature that follows, it cannot be carried to another
/// peer, another generation or a later deadline.
pub fn expired_recovery_approval_challenge(
    request_fingerprint: &Fingerprint,
    astra_challenge: &[u8; 32],
    expires_at: u64,
) -> Fingerprint {
    let mut bytes = CanonicalBytes::new(RECOVERY_APPROVAL_DOMAIN);
    bytes
        .fingerprint(request_fingerprint)
        .raw(astra_challenge)
        .u64(expires_at);
    Fingerprint::of(&bytes.finish())
}

/// Signing side of the client objects (see `authority::signing`).
#[cfg(feature = "key-negotiation-signing")]
mod signing {
    use super::*;
    use crate::certificates::encoding::sign_ml_dsa_87;

    impl ClientCertificateRotationRequest {
        pub fn sign(
            mut self,
            active_pq_private_key: &[u8],
            new_pq_private_key: &[u8],
        ) -> Result<Self, CertificateError> {
            let transcript = self.signing_bytes();
            self.active_pq_signature = sign_ml_dsa_87(active_pq_private_key, &transcript)?;
            self.new_pq_signature = sign_ml_dsa_87(new_pq_private_key, &transcript)?;
            Ok(self)
        }
    }

    impl ClientCertificateStageAuthorization {
        /// Signed by `CA-PQ` under [`IssuerKind::Master`], by the delegated
        /// issuer under [`IssuerKind::Astra`]. Which key is legitimate is
        /// decided by `issuer_kind`, and the verifier checks both.
        pub fn sign(mut self, issuer_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.signature = sign_ml_dsa_87(issuer_private_key, &self.signing_bytes()?)?;
            Ok(self)
        }
    }

    impl GatewayCertificateStageReceipt {
        /// Signed **after** the candidate is on disk and `fsync`ed. A receipt
        /// produced before that write would be a signature over a fact that
        /// has not happened yet.
        pub fn sign(mut self, gateway_pq_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.gateway_signature = sign_ml_dsa_87(gateway_pq_private_key, &self.signing_bytes())?;
            Ok(self)
        }
    }

    impl ClientCertificateRotationGrant {
        pub fn sign(mut self, issuer_private_key: &[u8]) -> Result<Self, CertificateError> {
            self.signature = sign_ml_dsa_87(issuer_private_key, &self.signing_bytes()?)?;
            Ok(self)
        }
    }

    impl ClientCertificateStageCommit {
        pub fn sign(
            mut self,
            active_pq_private_key: &[u8],
            staged_pq_private_key: &[u8],
        ) -> Result<Self, CertificateError> {
            let transcript = self.signing_bytes();
            self.active_pq_signature = sign_ml_dsa_87(active_pq_private_key, &transcript)?;
            self.staged_pq_signature = sign_ml_dsa_87(staged_pq_private_key, &transcript)?;
            Ok(self)
        }
    }

    impl ExpiredCertificateRecoveryRequest {
        pub fn sign(
            mut self,
            expired_pq_private_key: &[u8],
            new_pq_private_key: &[u8],
        ) -> Result<Self, CertificateError> {
            let transcript = self.signing_bytes();
            self.expired_pq_signature = sign_ml_dsa_87(expired_pq_private_key, &transcript)?;
            self.new_pq_signature = sign_ml_dsa_87(new_pq_private_key, &transcript)?;
            Ok(self)
        }
    }
}

#[cfg(all(test, feature = "key-negotiation-signing"))]
mod tests {
    use super::*;
    use crate::certificates::approval::{
        AstraCredentialApprovalRequest, AstraCredentialBinding, AstraRenewalApproval,
        CredentialState,
    };
    use crate::certificates::encoding::{generate_ml_dsa_87_keypair, sign_ml_dsa_87};
    use crate::certificates::webauthn::WebAuthnAssertion;
    use crate::key_negotiation::{issue_pq_certificate, PQ_CERTIFICATE_VERSION};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
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
        TrustDomainId::new([3; 16]).expect("domain")
    }

    fn gateway_key() -> WireGuardKey {
        WireGuardKey::from_bytes([1; 32])
    }

    fn client_key() -> WireGuardKey {
        WireGuardKey::from_bytes([2; 32])
    }

    fn client_leaf(ca: &Keys, subject: &Keys, serial: u8) -> PqCertificate {
        let certificate = PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [serial; 16],
            subject: "orion".into(),
            issuer: "CA-PQ".into(),
            role: PqCertificateRole::Client,
            wireguard_public_key: client_key().to_base64(),
            ml_dsa_87_public_key: STANDARD.encode(subject.public.as_bytes()),
            not_before_unix: 0,
            not_after_unix: 100_000,
            ml_dsa_87_signature: String::new(),
        };
        issue_pq_certificate(certificate, &ca.private).expect("issue")
    }

    fn tls_material() -> crate::certificates::test_x509::TlsMaterial {
        crate::certificates::test_x509::client_material("workstation")
    }

    fn active_generation() -> ClientCertificateGeneration {
        ClientCertificateGeneration {
            generation: 4,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
            pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
            not_before: 0,
            not_after: 100_000,
        }
    }

    /// Structurally complete evidence for tests whose subject is issuer
    /// resolution. Full WebAuthn and CA-PQ verification lives in
    /// `certificates::approval`; the leaf-level verifier only binds its exact
    /// fingerprint before the registry performs that cryptographic check.
    fn approval_evidence(request_fingerprint: Fingerprint) -> AstraRenewalApprovalEvidence {
        let operation_id = Id16::new([7; 16]).expect("operation id");
        let approval_request = AstraCredentialApprovalRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id,
            request_fingerprint,
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            active_generation: 4,
            requested_generation: 5,
            credential_registry_epoch: 1,
            webauthn_rp_id: "astra.example".into(),
            webauthn_origin: "https://astra.example".into(),
            allowed_credential_ids: vec![vec![1]],
            required_credentials: 1,
            created_at: 1_000,
            expires_at: 1_300,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        };
        let binding = AstraCredentialBinding {
            format_version: CERTIFICATE_FORMAT_VERSION,
            credential_id: vec![1],
            credential_public_key: vec![1],
            aaguid: [0; 16],
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            state: CredentialState::Active,
            credential_epoch: 1,
            credential_registry_epoch: 1,
            ca_epoch: 1,
            created_at: 1_000,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        };
        let assertion = WebAuthnAssertion {
            authenticator_data: vec![1],
            client_data_json: vec![1],
            signature: vec![1],
        };
        let approval = AstraRenewalApproval {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id,
            request_fingerprint,
            approval_request_fingerprint: approval_request.fingerprint(),
            credential_fingerprint: binding.fingerprint(),
            assertion_fingerprint: assertion.fingerprint(),
            credential_binding: binding,
            webauthn_assertion: assertion,
            approved_at: 1_000,
            expires_at: 1_300,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        };
        AstraRenewalApprovalEvidence {
            approval_request,
            approval,
        }
    }

    fn request(active: &Keys, candidate: &Keys) -> ClientCertificateRotationRequest {
        let mut request = ClientCertificateRotationRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            request_id: Id16::new([8; 16]).expect("id"),
            trust_domain_id: domain(),
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            client_wg_public_key: client_key(),
            active_generation: 4,
            requested_generation: 5,
            active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
            tls_csr: DerCertificate::new(vec![9; 256]).expect("csr"),
            new_ml_dsa_87_public_key: candidate.public.clone(),
            created_at: 1_000,
            expires_at: 1_000 + 3_600,
            active_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
            new_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        };
        let transcript = request.signing_bytes();
        request.active_pq_signature = sign_ml_dsa_87(&active.private, &transcript).unwrap();
        request.new_pq_signature = sign_ml_dsa_87(&candidate.private, &transcript).unwrap();
        request
    }

    #[test]
    fn a_rotation_request_needs_continuity_and_possession() {
        let active = keys();
        let candidate = keys();
        let request = request(&active, &candidate);

        assert!(request
            .verify(
                &active.public,
                &domain(),
                &gateway_key(),
                SERVER_NAME,
                &active_generation(),
                &client_key(),
                1_100
            )
            .is_ok());

        let stranger = keys();
        let mut forged = request.clone();
        forged.active_pq_signature =
            sign_ml_dsa_87(&stranger.private, &request.signing_bytes()).unwrap();
        assert!(matches!(
            forged.verify(
                &active.public,
                &domain(),
                &gateway_key(),
                SERVER_NAME,
                &active_generation(),
                &client_key(),
                1_100
            ),
            Err(CertificateError::MissingProof("active client"))
        ));

        let mut unproven = request.clone();
        unproven.new_pq_signature =
            sign_ml_dsa_87(&stranger.private, &request.signing_bytes()).unwrap();
        assert!(matches!(
            unproven.verify(
                &active.public,
                &domain(),
                &gateway_key(),
                SERVER_NAME,
                &active_generation(),
                &client_key(),
                1_100
            ),
            Err(CertificateError::MissingProof("new client"))
        ));
    }

    /// A renewal never moves the WireGuard identity: that is a readmission.
    #[test]
    fn a_rotation_request_for_another_peer_is_refused() {
        let active = keys();
        let candidate = keys();
        let request = request(&active, &candidate);
        assert!(matches!(
            request.verify(
                &active.public,
                &domain(),
                &gateway_key(),
                SERVER_NAME,
                &active_generation(),
                &WireGuardKey::from_bytes([9; 32]),
                1_100
            ),
            Err(CertificateError::ClientIdentityMismatch)
        ));
    }

    #[test]
    fn a_rotation_request_asks_for_exactly_the_next_generation() {
        let active = keys();
        let candidate = keys();
        let mut request = request(&active, &candidate);
        request.requested_generation = 6;
        let transcript = request.signing_bytes();
        request.active_pq_signature = sign_ml_dsa_87(&active.private, &transcript).unwrap();
        request.new_pq_signature = sign_ml_dsa_87(&candidate.private, &transcript).unwrap();
        assert!(matches!(
            request.verify(
                &active.public,
                &domain(),
                &gateway_key(),
                SERVER_NAME,
                &active_generation(),
                &client_key(),
                1_100
            ),
            Err(CertificateError::GenerationSkipped { .. })
        ));
    }

    /// The two mixed pairs of spec §3.3, refused by the generation itself.
    #[test]
    fn a_generation_refuses_a_mixed_tls_and_pq_pair() {
        let generation = active_generation();
        assert!(generation.accepts_pair(
            &Fingerprint::of(b"active tls"),
            &Fingerprint::of(b"active pq")
        ));
        assert!(!generation.accepts_pair(
            &Fingerprint::of(b"active tls"),
            &Fingerprint::of(b"next pq")
        ));
        assert!(!generation.accepts_pair(
            &Fingerprint::of(b"next tls"),
            &Fingerprint::of(b"active pq")
        ));
    }

    fn authorization(
        issuer: &Keys,
        ca: &Keys,
        candidate_leaf: PqCertificate,
        request_fingerprint: Fingerprint,
        tls: &crate::certificates::test_x509::TlsMaterial,
    ) -> ClientCertificateStageAuthorization {
        let mut authorization = ClientCertificateStageAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            issuer_kind: IssuerKind::Master,
            issuer_epoch: 0,
            issuer_authorization_fingerprint: Fingerprint::from_bytes([0; 32]),
            issuer_authorization: None,
            stage_id: Id16::new([5; 16]).expect("stage"),
            request_fingerprint,
            operator_approval_fingerprint: Fingerprint::of(b"operator approval"),
            renewal_approval: None,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            client_wg_public_key: client_key(),
            active_generation: 4,
            next_generation: 5,
            active_tls_certificate_fingerprint: Fingerprint::of(b"active tls"),
            active_pq_certificate_fingerprint: Fingerprint::of(b"active pq"),
            next_tls_ca_certificate_fingerprint: tls.authority.fingerprint(),
            next_tls_certificate: tls.leaf.clone(),
            next_pq_certificate: candidate_leaf,
            issued_at: 1_000,
            stage_expires_at: 1_000 + 3_600,
            window: TransitionWindow::new(1_000, 10_000, 20_000).expect("window"),
            reason: RotationReason::Scheduled,
            signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        };
        let _ = issuer;
        let transcript = authorization.signing_bytes().expect("transcript");
        authorization.signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();
        authorization
    }

    #[test]
    fn a_master_authorization_verifies_directly_under_ca_pq() {
        let ca = keys();
        let subject = keys();
        let leaf = client_leaf(&ca, &subject, 2);
        let tls = tls_material();
        let authorization = authorization(&ca, &ca, leaf, Fingerprint::of(b"request"), &tls);

        assert!(authorization
            .verify(
                &ca.public,
                &domain(),
                1,
                1,
                &gateway_key(),
                SERVER_NAME,
                &client_key(),
                &active_generation(),
                &[&tls.authority],
                None,
                None,
                1_100,
            )
            .is_ok());
    }

    /// A `master` authorization that also carries a delegation is refused:
    /// two authorities named at once is one authority too many.
    #[test]
    fn a_master_authorization_carrying_a_delegation_is_refused() {
        let ca = keys();
        let subject = keys();
        let leaf = client_leaf(&ca, &subject, 2);
        let tls = tls_material();
        let mut authorization = authorization(&ca, &ca, leaf, Fingerprint::of(b"request"), &tls);
        authorization.issuer_authorization_fingerprint = Fingerprint::of(b"delegation");
        let transcript = authorization.signing_bytes().unwrap();
        authorization.signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();
        assert!(matches!(
            authorization.verify(
                &ca.public,
                &domain(),
                1,
                1,
                &gateway_key(),
                SERVER_NAME,
                &client_key(),
                &active_generation(),
                &[&tls.authority],
                None,
                None,
                1_100,
            ),
            Err(CertificateError::UnauthorizedIssuer)
        ));
    }

    /// A leaf issued by the delegated issuer chains to **that issuer**, and
    /// the delegation is what makes the issuer stand for the authority. Both
    /// halves matter: reading the leaf under `CA-PQ` would refuse every
    /// ordinary renewal, and skipping the delegation check would accept a leaf
    /// nobody authorized.
    #[test]
    fn an_astra_issued_leaf_chains_to_the_delegation_not_to_ca_pq() {
        use crate::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};

        let ca = keys();
        let issuer = keys();
        let subject = keys();
        let tls = tls_material();

        let delegation = AstraIssuerAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            issuer_epoch: 3,
            pq_issuer_public_key: issuer.public.clone(),
            tls_intermediate_certificate: crate::certificates::test_x509::certificate_authority(
                "astra-issuer",
            ),
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 200_000,
            policy_fingerprint: Fingerprint::of(b"policy"),
            not_before: 0,
            not_after: 500_000,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&ca.private)
        .expect("sign delegation");

        let delegated_leaf = client_leaf(&issuer, &subject, 4);
        let mut authorization =
            authorization(&ca, &ca, delegated_leaf, Fingerprint::of(b"request"), &tls);
        authorization.issuer_kind = IssuerKind::Astra;
        authorization.issuer_epoch = 3;
        authorization.issuer_authorization_fingerprint = delegation.fingerprint();
        authorization.issuer_authorization = Some(delegation.clone());
        let evidence = approval_evidence(authorization.request_fingerprint);
        authorization.operator_approval_fingerprint = evidence.fingerprint();
        authorization.renewal_approval = Some(evidence);
        let authorization = authorization.sign(&issuer.private).expect("sign");

        authorization
            .verify(
                &ca.public,
                &domain(),
                1,
                1,
                &gateway_key(),
                SERVER_NAME,
                &client_key(),
                &active_generation(),
                &[&tls.authority],
                Some(&AstraPolicyPin::new(Fingerprint::of(b"policy")).expect("policy pin")),
                None,
                1_100,
            )
            .expect("a delegated leaf verifies under its delegation");

        let mut missing_approval = authorization.clone();
        missing_approval.renewal_approval = None;
        let missing_approval = missing_approval.sign(&issuer.private).expect("sign");
        assert!(matches!(
            missing_approval.verify(
                &ca.public,
                &domain(),
                1,
                1,
                &gateway_key(),
                SERVER_NAME,
                &client_key(),
                &active_generation(),
                &[&tls.authority],
                Some(&AstraPolicyPin::new(Fingerprint::of(b"policy")).expect("policy pin"),),
                None,
                1_100,
            ),
            Err(CertificateError::ApprovalMismatch(
                "delegated renewal approval"
            ))
        ));

        // The same object carrying a leaf issued by `CA-PQ` instead does not:
        // the delegation names the issuer, and the leaf must match it.
        let master_leaf = client_leaf(&ca, &subject, 5);
        let mut mismatched = authorization.clone();
        mismatched.next_pq_certificate = master_leaf;
        let mismatched = mismatched.sign(&issuer.private).expect("sign");
        assert!(matches!(
            mismatched.verify(
                &ca.public,
                &domain(),
                1,
                1,
                &gateway_key(),
                SERVER_NAME,
                &client_key(),
                &active_generation(),
                &[&tls.authority],
                Some(&AstraPolicyPin::new(Fingerprint::of(b"policy")).expect("policy pin"),),
                None,
                1_100,
            ),
            Err(CertificateError::UnauthorizedIssuer)
        ));
    }

    #[test]
    fn a_staging_lease_never_outlives_activation_or_twenty_four_hours() {
        let ca = keys();
        let subject = keys();
        let leaf = client_leaf(&ca, &subject, 2);
        let tls = tls_material();
        let mut authorization = authorization(&ca, &ca, leaf, Fingerprint::of(b"request"), &tls);

        authorization.stage_expires_at = authorization.window.activation_at + 1;
        let transcript = authorization.signing_bytes().unwrap();
        authorization.signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();
        assert!(matches!(
            authorization.verify(
                &ca.public,
                &domain(),
                1,
                1,
                &gateway_key(),
                SERVER_NAME,
                &client_key(),
                &active_generation(),
                &[&tls.authority],
                None,
                None,
                1_100,
            ),
            Err(CertificateError::InvalidLease)
        ));

        authorization.stage_expires_at = authorization.issued_at + MAX_STAGE_LEASE_SECS + 1;
        authorization.window =
            TransitionWindow::new(1_000, 1_000 + MAX_STAGE_LEASE_SECS + 100, 200_000).unwrap();
        let transcript = authorization.signing_bytes().unwrap();
        authorization.signature = sign_ml_dsa_87(&ca.private, &transcript).unwrap();
        assert!(matches!(
            authorization.verify(
                &ca.public,
                &domain(),
                1,
                1,
                &gateway_key(),
                SERVER_NAME,
                &client_key(),
                &active_generation(),
                &[&tls.authority],
                None,
                None,
                1_100,
            ),
            Err(CertificateError::LeaseTooLong { .. })
        ));
    }

    #[test]
    fn a_commit_needs_both_the_active_and_the_candidate_signature() {
        let active = keys();
        let candidate = keys();
        let generation = ClientCertificateGeneration {
            generation: 5,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(b"next tls"),
            pq_certificate_fingerprint: Fingerprint::of(b"next pq"),
            not_before: 0,
            not_after: 100_000,
        };
        let stage_id = Id16::new([5; 16]).expect("stage");

        let mut commit = ClientCertificateStageCommit {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain(),
            stage_id,
            grant_fingerprint: Fingerprint::of(b"grant"),
            stage_receipt_fingerprint: Fingerprint::of(b"receipt"),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            active_generation: 4,
            staged_generation: 5,
            staged_tls_certificate_fingerprint: Fingerprint::of(b"next tls"),
            staged_pq_certificate_fingerprint: Fingerprint::of(b"next pq"),
            stage_expires_at: 5_000,
            committed_at: 1_200,
            active_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
            staged_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        };
        let transcript = commit.signing_bytes();
        commit.active_pq_signature = sign_ml_dsa_87(&active.private, &transcript).unwrap();
        commit.staged_pq_signature = sign_ml_dsa_87(&candidate.private, &transcript).unwrap();

        let verify = |commit: &ClientCertificateStageCommit, now: u64| {
            commit.verify(
                &active.public,
                &candidate.public,
                &domain(),
                &gateway_key(),
                &client_key(),
                &stage_id,
                &generation,
                4,
                5_000,
                now,
            )
        };
        assert!(verify(&commit, 1_300).is_ok());

        let stranger = keys();
        let mut half = commit.clone();
        half.staged_pq_signature = sign_ml_dsa_87(&stranger.private, &transcript).unwrap();
        assert!(matches!(
            verify(&half, 1_300),
            Err(CertificateError::MissingProof("staged client"))
        ));
    }

    /// Antedating the commit does not win the race against the purge: the
    /// clock the gateway reads is checked too.
    #[test]
    fn an_antedated_commit_arriving_after_the_lease_is_refused() {
        let active = keys();
        let candidate = keys();
        let generation = ClientCertificateGeneration {
            generation: 5,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: Fingerprint::of(b"tls ca"),
            tls_certificate_fingerprint: Fingerprint::of(b"next tls"),
            pq_certificate_fingerprint: Fingerprint::of(b"next pq"),
            not_before: 0,
            not_after: 100_000,
        };
        let stage_id = Id16::new([5; 16]).expect("stage");
        let mut commit = ClientCertificateStageCommit {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain(),
            stage_id,
            grant_fingerprint: Fingerprint::of(b"grant"),
            stage_receipt_fingerprint: Fingerprint::of(b"receipt"),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            active_generation: 4,
            staged_generation: 5,
            staged_tls_certificate_fingerprint: Fingerprint::of(b"next tls"),
            staged_pq_certificate_fingerprint: Fingerprint::of(b"next pq"),
            stage_expires_at: 5_000,
            committed_at: 4_999,
            active_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
            staged_pq_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        };
        let transcript = commit.signing_bytes();
        commit.active_pq_signature = sign_ml_dsa_87(&active.private, &transcript).unwrap();
        commit.staged_pq_signature = sign_ml_dsa_87(&candidate.private, &transcript).unwrap();

        assert!(matches!(
            commit.verify(
                &active.public,
                &candidate.public,
                &domain(),
                &gateway_key(),
                &client_key(),
                &stage_id,
                &generation,
                4,
                5_000,
                5_001,
            ),
            Err(CertificateError::StageExpired)
        ));
    }

    /// The approved operation is bound to the exact request, its challenge and
    /// its deadline: none of the three can be moved afterwards.
    #[test]
    fn the_recovery_approval_challenge_binds_request_challenge_and_deadline() {
        let request = Fingerprint::of(b"request");
        let challenge = [7u8; 32];
        let base = expired_recovery_approval_challenge(&request, &challenge, 1_000);
        assert_ne!(
            base,
            expired_recovery_approval_challenge(&Fingerprint::of(b"other"), &challenge, 1_000)
        );
        assert_ne!(
            base,
            expired_recovery_approval_challenge(&request, &[8u8; 32], 1_000)
        );
        assert_ne!(
            base,
            expired_recovery_approval_challenge(&request, &challenge, 1_001)
        );
    }
}
