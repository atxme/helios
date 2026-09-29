//! The stage commit: the client promotes the staged generation, and the
//! request that carries it to the gateway.

use super::*;

/// A commit and the grant that authorizes it (spec §7.3).
///
/// The two travel together because the gateway needs both: the signatures
/// prove who is committing, the grant proves the authority released anything
/// at all. A commit alone would let a client that holds its own two private
/// keys — which it always does, it generated them — activate a candidate the
/// authority never granted.
///
/// It lives beside its two members rather than in the API crate that serves
/// the route: a client cannot depend on the gateway's HTTP layer, and when the
/// shape was defined there the two ends drifted — Orion posted a bare commit
/// to a gateway that had always required the pair, and the mismatch only
/// surfaced as an unreadable body on a real renewal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageCommitRequest {
    pub commit: ClientCertificateStageCommit,
    pub grant: ClientCertificateRotationGrant,
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
    pub(super) fn signing_bytes(&self) -> SignedTranscript {
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
