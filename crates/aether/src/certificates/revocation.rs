//! Emergency revocation — spec §10.
//!
//! A revocation is not a transition, and the difference is the whole point. A
//! transition negotiates time: it prepares, overlaps, then promotes. A
//! revocation removes a named fingerprint **at** `effective_at`, whatever its
//! validity or its overlap says, and it dominates `staged`, `published`,
//! `overlap`, a service rollback and any callback from an earlier generation.
//!
//! Its counter lives on its own axis, per WireGuard identity. Certificate
//! generations and revocation epochs never share a number, so a later rotation
//! can neither reintroduce a revoked leaf nor make the decision disappear
//! behind a concurrent generation.
//!
//! # What this object does not do
//!
//! For a client, `peer remove` remains the immediate revocation: it withdraws
//! the admission itself, and no signed document should ever delay it. This
//! object exists to **distribute and audit** the decision — including to an
//! Orion that will only learn about it later.
//!
//! And it cannot beat a dishonest host. A gateway that withholds the object
//! produces the freeze attack ADR-008 accepts explicitly: without an
//! independent freshness service, an isolated client is bounded only by
//! expiry and by out-of-band distribution.

use serde::{Deserialize, Serialize};

use super::{
    encoding::{
        validate_server_name, verify_ml_dsa_87, CanonicalBytes, Fingerprint, MlDsa87PublicKey,
        MlDsa87Signature, TrustDomainId, WireGuardKey,
    },
    window::require_next_generation,
    CertificateError, CERTIFICATE_FORMAT_VERSION,
};

const REVOCATION_DOMAIN: &[u8] = b"helios-certificate-emergency-revocation-v5";

/// Which identity a revocation names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationScope {
    Gateway,
    Client,
}

impl RevocationScope {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::Gateway => 0,
            Self::Client => 1,
        }
    }
}

/// Why a certificate was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    KeyCompromise,
    SuspectedCompromise,
    Cessation,
    Superseded,
}

impl RevocationReason {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::KeyCompromise => 0,
            Self::SuspectedCompromise => 1,
            Self::Cessation => 2,
            Self::Superseded => 3,
        }
    }
}

/// Immediate withdrawal of one or both leaves of an identity (spec §10.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmergencyCertificateRevocation {
    pub format_version: u16,
    pub trust_domain_id: TrustDomainId,
    pub ca_epoch: u64,
    pub scope: RevocationScope,
    /// WireGuard key of the gateway or of the client being revoked.
    pub identity_key: WireGuardKey,
    /// Mandatory for a gateway scope, absent for a client.
    pub server_name: Option<String>,
    pub revocation_epoch: u64,
    pub revoked_tls_fingerprint: Option<Fingerprint>,
    /// Cryptographic expiry of the named TLS leaf.
    ///
    /// It is signed even when the recipient never held the leaf, so the
    /// recipient can eventually forget the tombstone without guessing.
    pub revoked_tls_not_after: Option<u64>,
    pub revoked_pq_fingerprint: Option<Fingerprint>,
    /// Cryptographic expiry of the named PQ leaf.
    pub revoked_pq_not_after: Option<u64>,
    pub effective_at: u64,
    pub reason: RevocationReason,
    pub replacement_transition_fingerprint: Option<Fingerprint>,
    pub ca_signature: MlDsa87Signature,
}

impl EmergencyCertificateRevocation {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = CanonicalBytes::new(REVOCATION_DOMAIN);
        bytes
            .u16(self.format_version)
            .id(&self.trust_domain_id)
            .u64(self.ca_epoch)
            .u8(self.scope.domain_byte())
            .key(&self.identity_key)
            .text(self.server_name.as_deref().unwrap_or(""))
            .u64(self.revocation_epoch)
            .optional_fingerprint(self.revoked_tls_fingerprint.as_ref())
            .optional_u64(self.revoked_tls_not_after)
            .optional_fingerprint(self.revoked_pq_fingerprint.as_ref())
            .optional_u64(self.revoked_pq_not_after)
            .u64(self.effective_at)
            .u8(self.reason.domain_byte())
            .optional_fingerprint(self.replacement_transition_fingerprint.as_ref());
        bytes.finish()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(&self.signing_bytes());
        bytes.length_prefixed(self.ca_signature.as_bytes());
        Fingerprint::of(&bytes.finish())
    }

    /// Verifies the object against the anchor and the local revocation counter.
    ///
    /// `current_revocation_epoch` is the one persisted for **this identity**:
    /// the counters of two peers are independent, and comparing against a
    /// global one would let a busy peer's revocations block a quiet peer's.
    pub fn verify(
        &self,
        ca_pq: &MlDsa87PublicKey,
        trust_domain_id: &TrustDomainId,
        ca_epoch: u64,
        current_revocation_epoch: u64,
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
        if self.ca_epoch != ca_epoch {
            return Err(CertificateError::UnauthorizedIssuer);
        }
        match self.scope {
            RevocationScope::Gateway => {
                let name = self
                    .server_name
                    .as_deref()
                    .ok_or(CertificateError::GatewayIdentityMismatch)?;
                validate_server_name(name)?;
            }
            // A client revocation naming a server would be describing an
            // identity it does not revoke.
            RevocationScope::Client => {
                if self.server_name.is_some() {
                    return Err(CertificateError::GatewayIdentityMismatch);
                }
            }
        }
        // "At least one fingerprint": an object naming neither leaf revokes
        // nothing while looking like a decision.
        if self.revoked_tls_fingerprint.is_none() && self.revoked_pq_fingerprint.is_none() {
            return Err(CertificateError::EmptyTransition);
        }
        if self.revoked_tls_fingerprint.is_some() != self.revoked_tls_not_after.is_some()
            || self.revoked_pq_fingerprint.is_some() != self.revoked_pq_not_after.is_some()
        {
            return Err(CertificateError::InvalidValidityPeriod);
        }
        require_next_generation(current_revocation_epoch, self.revocation_epoch)?;
        verify_ml_dsa_87(ca_pq, &self.signing_bytes(), &self.ca_signature)
    }

    /// Whether this revocation withdraws the given fingerprint at `now_unix`.
    pub fn revokes(&self, fingerprint: &Fingerprint, now_unix: u64) -> bool {
        if now_unix < self.effective_at {
            return false;
        }
        self.revoked_tls_fingerprint
            .as_ref()
            .is_some_and(|revoked| revoked.matches(fingerprint))
            || self
                .revoked_pq_fingerprint
                .as_ref()
                .is_some_and(|revoked| revoked.matches(fingerprint))
    }
}

/// Signing side of the revocation object (see `authority::signing`).
#[cfg(feature = "key-negotiation-signing")]
mod signing {
    use super::*;
    use crate::certificates::encoding::sign_ml_dsa_87;

    impl EmergencyCertificateRevocation {
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

    fn domain() -> TrustDomainId {
        TrustDomainId::new([2; 16]).expect("domain")
    }

    fn revocation(
        private: &[u8],
        scope: RevocationScope,
        server_name: Option<&str>,
    ) -> EmergencyCertificateRevocation {
        let mut revocation = EmergencyCertificateRevocation {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            ca_epoch: 1,
            scope,
            identity_key: WireGuardKey::from_bytes([6; 32]),
            server_name: server_name.map(str::to_string),
            revocation_epoch: 1,
            revoked_tls_fingerprint: None,
            revoked_tls_not_after: None,
            revoked_pq_fingerprint: Some(Fingerprint::of(b"compromised")),
            revoked_pq_not_after: Some(10_000),
            effective_at: 5_000,
            reason: RevocationReason::KeyCompromise,
            replacement_transition_fingerprint: None,
            ca_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
        };
        revocation.ca_signature = sign_ml_dsa_87(private, &revocation.signing_bytes()).unwrap();
        revocation
    }

    #[test]
    fn a_client_revocation_verifies_under_the_pinned_anchor() {
        let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
        let revocation = revocation(&private, RevocationScope::Client, None);
        assert!(revocation.verify(&public, &domain(), 1, 0).is_ok());

        let (stranger, _) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut forged = revocation.clone();
        forged.ca_signature = sign_ml_dsa_87(&stranger, &revocation.signing_bytes()).unwrap();
        assert!(matches!(
            forged.verify(&public, &domain(), 1, 0),
            Err(CertificateError::InvalidSignature)
        ));
    }

    /// The revocation counter is per identity and only ever moves forward.
    #[test]
    fn a_replayed_revocation_epoch_is_a_conflict_and_an_older_one_a_rollback() {
        let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
        let revocation = revocation(&private, RevocationScope::Client, None);
        assert!(matches!(
            revocation.verify(&public, &domain(), 1, 1),
            Err(CertificateError::GenerationConflict { .. })
        ));
        assert!(matches!(
            revocation.verify(&public, &domain(), 1, 2),
            Err(CertificateError::GenerationRollback { .. })
        ));
    }

    #[test]
    fn a_gateway_revocation_must_name_its_server_and_a_client_one_must_not() {
        let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
        let missing = revocation(&private, RevocationScope::Gateway, None);
        assert!(matches!(
            missing.verify(&public, &domain(), 1, 0),
            Err(CertificateError::GatewayIdentityMismatch)
        ));

        let extra = revocation(&private, RevocationScope::Client, Some("gateway.example"));
        assert!(matches!(
            extra.verify(&public, &domain(), 1, 0),
            Err(CertificateError::GatewayIdentityMismatch)
        ));

        let correct = revocation(&private, RevocationScope::Gateway, Some("gateway.example"));
        assert!(correct.verify(&public, &domain(), 1, 0).is_ok());
    }

    #[test]
    fn a_revocation_naming_no_fingerprint_is_refused() {
        let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut empty = revocation(&private, RevocationScope::Client, None);
        empty.revoked_pq_fingerprint = None;
        empty.ca_signature = sign_ml_dsa_87(&private, &empty.signing_bytes()).unwrap();
        assert!(matches!(
            empty.verify(&public, &domain(), 1, 0),
            Err(CertificateError::EmptyTransition)
        ));
    }

    #[test]
    fn every_revoked_fingerprint_carries_its_signed_cryptographic_expiry() {
        let (private, public) = generate_ml_dsa_87_keypair().expect("keygen");
        let mut missing = revocation(&private, RevocationScope::Client, None);
        missing.revoked_pq_not_after = None;
        missing.ca_signature = sign_ml_dsa_87(&private, &missing.signing_bytes()).expect("sign");
        assert!(matches!(
            missing.verify(&public, &domain(), 1, 0),
            Err(CertificateError::InvalidValidityPeriod)
        ));

        let mut expiry_without_leaf = revocation(&private, RevocationScope::Client, None);
        expiry_without_leaf.revoked_tls_not_after = Some(10_000);
        expiry_without_leaf.ca_signature =
            sign_ml_dsa_87(&private, &expiry_without_leaf.signing_bytes()).expect("sign");
        assert!(matches!(
            expiry_without_leaf.verify(&public, &domain(), 1, 0),
            Err(CertificateError::InvalidValidityPeriod)
        ));
    }

    #[test]
    fn a_revocation_takes_effect_at_its_own_instant() {
        let (private, _) = generate_ml_dsa_87_keypair().expect("keygen");
        let revocation = revocation(&private, RevocationScope::Client, None);
        let target = Fingerprint::of(b"compromised");
        assert!(!revocation.revokes(&target, 4_999));
        assert!(revocation.revokes(&target, 5_000));
        assert!(!revocation.revokes(&Fingerprint::of(b"other"), 6_000));
    }
}
