//! The single ML-DSA-87 entry point of the negotiation and lifecycle PKI.
//!
//! Both specifications say the same thing in two places — negotiation §8 and
//! rotation §2.3.1 — and it is a rule no signature can be exempt from: **pure
//! ML-DSA of FIPS 204, with a non-empty external context equal to the ASCII
//! domain of the signed type**. So there is one door, and the door asks for
//! the context.
//!
//! # Why the context is not the transcript prefix
//!
//! Every canonical transcript in this codebase already begins with its domain,
//! and it is tempting to read that as "the domain is signed, we are covered".
//! It is not the same control. The prefix lives inside `M`, so a verifier that
//! forgets to compare it verifies a well-formed signature over bytes it
//! misread. The context lives *outside* `M`, in the challenge FIPS 204 builds
//! before hashing: a signature made under another type's context does not
//! verify at all, whatever the verifier remembers to check. One is a
//! convention the reader must uphold; the other is arithmetic.
//!
//! That is also why [`sign`] and [`verify`] refuse a message that does not
//! carry its context as a prefix: the two controls are distinct, and the
//! specification asks for both, so neither is allowed to stand in for the
//! other.
//!
//! # What is refused
//!
//! - an empty context. A library that can only pass `ctx = ""` is
//!   non-conforming, and prefixing `M` does not emulate it — including under
//!   `CA-PQ`, whose signatures with an empty context are refused like any
//!   other;
//! - a context over 255 bytes, or one carrying a NUL or a non-printable byte:
//!   FIPS 204 encodes the context length in a single byte, and a domain that
//!   is not plain ASCII is a domain two implementations will disagree about;
//! - **HashML-DSA**, in both directions. No path here calls a prehash variant,
//!   and a HashML-DSA signature fails [`verify`] on its own: FIPS 204 separates
//!   the two with a leading domain byte, so the pure verifier reconstructs a
//!   different message representative;
//! - a message that does not begin with its context.
//!
//! Randomness for the hedged signature and for key generation comes from the
//! approved DRBG of [`crate::random`], never from the platform CSPRNG
//! directly.

use fips204::{
    ml_dsa_87::{self, PublicKey},
    traits::{SerDes as _, Verifier as _},
};

/// Longest external context FIPS 204 can encode.
pub const MAX_CONTEXT_LEN: usize = 255;

/// Bytes of an ML-DSA-87 public key.
pub const PUBLIC_KEY_LEN: usize = ml_dsa_87::PK_LEN;

/// Bytes of an ML-DSA-87 private key.
#[cfg(feature = "key-negotiation-signing")]
pub const PRIVATE_KEY_LEN: usize = ml_dsa_87::SK_LEN;

/// Bytes of an ML-DSA-87 signature.
pub const SIGNATURE_LEN: usize = ml_dsa_87::SIG_LEN;

/// Exhaustive registry of the ML-DSA contexts admitted by negotiation v5 and
/// the certificate lifecycle specification.
///
/// A new wire type is deliberately not signable merely because its author
/// picked a printable domain. Adding it requires amending the relevant table,
/// then extending this registry in the same change.
const SUPPORTED_CONTEXTS: &[&[u8]] = &[
    // NEGOCIATION-DE-CLE-V5 §8.
    b"helios-key-negotiation-pq-certificate-v2",
    b"helios-key-negotiation-pq-request-v5",
    b"helios-key-negotiation-pq-response-v5",
    b"helios-key-negotiation-pq-confirmation-v5",
    b"helios-key-negotiation-pq-commit-v5",
    b"helios-key-negotiation-pq-in-tunnel-release-v5",
    // NEGOCIATION-DE-CLE-V5 §15.3.
    b"helios-key-negotiation-enrollment-invitation-v5",
    b"helios-key-negotiation-enrollment-request-v5",
    b"helios-key-negotiation-orion-document-v5",
    // ROTATION-CERTIFICATS §2.3.1.
    b"helios-trust-base-state-v5",
    b"helios-gateway-bootstrap-request-v5",
    b"helios-gateway-certificate-request-v5",
    b"helios-gateway-identity-transition-v5",
    b"helios-gateway-identity-transition-abort-v5",
    b"helios-client-certificate-rotation-request-v5",
    b"helios-client-certificate-stage-authorization-v5",
    b"helios-gateway-certificate-stage-receipt-v5",
    b"helios-client-certificate-rotation-grant-v5",
    b"helios-client-certificate-stage-commit-v5",
    b"helios-expired-client-certificate-recovery-request-v5",
    b"helios-astra-credential-binding-v5",
    b"helios-astra-credential-approval-request-v5",
    b"helios-astra-renewal-approval-v5",
    b"helios-astra-issuer-authorization-v5",
    b"helios-in-tunnel-trust-update-request-v5",
    b"helios-trust-update-transaction-manifest-v5",
    b"helios-trust-update-chunk-v5",
    b"helios-orion-trust-update-document-v5",
    b"helios-astra-certificate-status-v5",
    b"helios-astra-certificate-status-query-v5",
    b"helios-astra-signer-request-v5",
    b"helios-certificate-service-rollback-authorization-v5",
    b"helios-ca-transition-v5",
    b"helios-client-tls-ca-transition-v5",
    b"helios-astra-service-key-transition-v5",
    b"helios-astra-service-key-emergency-replacement-v5",
    b"helios-certificate-emergency-revocation-v5",
];

/// What can refuse a signature or a verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MlDsaError {
    /// The context was empty, too long, or not printable ASCII.
    #[error("the ML-DSA-87 context is not a usable domain")]
    InvalidContext,
    /// The message does not carry its context as a prefix.
    #[error("the signed transcript does not open with its domain")]
    DomainMismatch,
    /// The public key is not an ML-DSA-87 key.
    #[error("invalid ML-DSA-87 public key")]
    InvalidPublicKey,
    /// The private key is not an ML-DSA-87 key.
    #[cfg(feature = "key-negotiation-signing")]
    #[error("invalid ML-DSA-87 private key")]
    InvalidPrivateKey,
    /// The signature does not verify under this key, message and context.
    #[error("the ML-DSA-87 signature does not verify")]
    InvalidSignature,
    /// Signing or key generation failed, randomness included.
    #[cfg(feature = "key-negotiation-signing")]
    #[error("ML-DSA-87 signing failed")]
    Signing,
}

/// The external context of one signed type, validated once.
///
/// Holding it as a type rather than a `&[u8]` parameter is what keeps the
/// empty context from being expressible: there is no way to reach [`sign`] or
/// [`verify`] without having built one of these first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context<'a> {
    domain: &'a [u8],
}

impl<'a> Context<'a> {
    /// Accepts the registered ASCII domain of a signed type.
    pub(crate) fn new(domain: &'a [u8]) -> Result<Self, MlDsaError> {
        if domain.is_empty() || domain.len() > MAX_CONTEXT_LEN {
            return Err(MlDsaError::InvalidContext);
        }
        // Printable ASCII only: a NUL — the classic "harmless" terminator — and
        // anything an encoding could normalize are both refused here rather
        // than discovered as a signature that verifies on one side only.
        if domain.iter().any(|byte| !(0x21..=0x7e).contains(byte)) {
            return Err(MlDsaError::InvalidContext);
        }
        if !SUPPORTED_CONTEXTS.contains(&domain) {
            return Err(MlDsaError::InvalidContext);
        }
        Ok(Self { domain })
    }

    /// The domain, as passed to `ML-DSA.Sign` and `ML-DSA.Verify`.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.domain
    }

    /// Whether `message` opens with this domain, as its transcript must.
    pub fn covers(&self, message: &[u8]) -> bool {
        message.starts_with(self.domain)
    }
}

/// Verifies a pure ML-DSA-87 signature under its type's context.
pub(crate) fn verify(
    public_key: &[u8],
    context: Context<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), MlDsaError> {
    if !context.covers(message) {
        return Err(MlDsaError::DomainMismatch);
    }
    let public_key =
        <[u8; PUBLIC_KEY_LEN]>::try_from(public_key).map_err(|_| MlDsaError::InvalidPublicKey)?;
    let public_key =
        PublicKey::try_from_bytes(public_key).map_err(|_| MlDsaError::InvalidPublicKey)?;
    let signature =
        <[u8; SIGNATURE_LEN]>::try_from(signature).map_err(|_| MlDsaError::InvalidSignature)?;
    if !public_key.verify(message, &signature, context.as_bytes()) {
        return Err(MlDsaError::InvalidSignature);
    }
    Ok(())
}

/// Signs a canonical transcript with pure ML-DSA-87 under its type's context.
///
/// Behind the signing feature, like every other minting path: a gateway that
/// only verifies does not link one.
#[cfg(feature = "key-negotiation-signing")]
pub(crate) fn sign(
    private_key: &[u8],
    context: Context<'_>,
    message: &[u8],
) -> Result<Vec<u8>, MlDsaError> {
    use fips204::{ml_dsa_87::PrivateKey, traits::Signer as _};

    if !context.covers(message) {
        return Err(MlDsaError::DomainMismatch);
    }
    let private_key = <[u8; PRIVATE_KEY_LEN]>::try_from(private_key)
        .map_err(|_| MlDsaError::InvalidPrivateKey)?;
    let private_key =
        PrivateKey::try_from_bytes(private_key).map_err(|_| MlDsaError::InvalidPrivateKey)?;
    // The hedged signature draws its randomness from the approved DRBG, and a
    // DRBG that refuses to produce is a signature that does not happen.
    let signature = private_key
        .try_sign_with_rng(&mut crate::random::DrbgRng, message, context.as_bytes())
        .map_err(|_| MlDsaError::Signing)?;
    Ok(signature.to_vec())
}

/// Generates an ML-DSA-87 key pair from the approved DRBG.
///
/// The private half is drawn with prediction resistance, so a fresh entropy
/// input precedes it — the rule the two specifications state for every private
/// key.
#[cfg(feature = "key-negotiation-signing")]
pub fn generate_keypair() -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>), MlDsaError> {
    let (public_key, private_key) = ml_dsa_87::try_keygen_with_rng(&mut crate::random::DrbgRng)
        .map_err(|_| MlDsaError::Signing)?;
    Ok((
        zeroize::Zeroizing::new(private_key.into_bytes().to_vec()),
        public_key.into_bytes().to_vec(),
    ))
}

/// Derives the public half of an encoded ML-DSA-87 private key.
///
/// This is the possession check for a key loaded from a vault. It avoids
/// inventing a local signature context that is absent from the exhaustive wire
/// registry.
#[cfg(feature = "key-negotiation-signing")]
pub(crate) fn public_key_from_private(private_key: &[u8]) -> Result<Vec<u8>, MlDsaError> {
    use fips204::{ml_dsa_87::PrivateKey, traits::Signer as _};

    let private_key = <[u8; PRIVATE_KEY_LEN]>::try_from(private_key)
        .map_err(|_| MlDsaError::InvalidPrivateKey)?;
    let private_key =
        PrivateKey::try_from_bytes(private_key).map_err(|_| MlDsaError::InvalidPrivateKey)?;
    Ok(private_key.get_public_key().into_bytes().to_vec())
}

#[cfg(all(test, feature = "key-negotiation-signing"))]
mod tests {
    use super::*;

    const DOMAIN: &[u8] = b"helios-gateway-identity-transition-v5";
    const OTHER_DOMAIN: &[u8] = b"helios-gateway-identity-transition-abort-v5";

    fn transcript(domain: &[u8]) -> Vec<u8> {
        let mut message = domain.to_vec();
        message.extend_from_slice(&[0x01, 0x02, 0x03]);
        message
    }

    fn context(domain: &[u8]) -> Context<'_> {
        Context::new(domain).expect("domain")
    }

    #[test]
    fn a_signature_verifies_under_the_context_it_was_made_with() {
        let (private, public) = generate_keypair().expect("keys");
        let message = transcript(DOMAIN);
        let signature = sign(&private, context(DOMAIN), &message).expect("sign");
        verify(&public, context(DOMAIN), &message, &signature).expect("verify");
    }

    #[test]
    fn another_types_context_refuses_a_cryptographically_valid_signature() {
        let (private, public) = generate_keypair().expect("keys");
        let message = transcript(DOMAIN);
        let signature = sign(&private, context(DOMAIN), &message).expect("sign");
        // The bytes are untouched and the key is right: only the context moved.
        let mut moved = OTHER_DOMAIN.to_vec();
        moved.extend_from_slice(&message[DOMAIN.len()..]);
        assert_eq!(
            verify(&public, context(OTHER_DOMAIN), &moved, &signature).err(),
            Some(MlDsaError::InvalidSignature)
        );
    }

    #[test]
    fn an_empty_context_cannot_even_be_built() {
        assert_eq!(Context::new(b"").err(), Some(MlDsaError::InvalidContext));
    }

    #[test]
    fn a_context_with_a_trailing_nul_or_over_255_bytes_is_refused() {
        assert_eq!(
            Context::new(b"helios-gateway-identity-transition-v5\0").err(),
            Some(MlDsaError::InvalidContext)
        );
        let long = vec![b'a'; MAX_CONTEXT_LEN + 1];
        assert_eq!(Context::new(&long).err(), Some(MlDsaError::InvalidContext));
    }

    #[test]
    fn a_printable_but_unregistered_context_is_refused() {
        assert_eq!(
            Context::new(b"helios-unregistered-object-v5").err(),
            Some(MlDsaError::InvalidContext)
        );
        for domain in SUPPORTED_CONTEXTS {
            Context::new(domain).expect("every normative context is admitted");
        }
    }

    #[test]
    fn the_public_half_is_derived_without_an_unregistered_probe_signature() {
        let (private, public) = generate_keypair().expect("keys");
        assert_eq!(
            public_key_from_private(&private).expect("public key"),
            public
        );
    }

    #[test]
    fn a_signature_made_with_an_empty_context_is_refused() {
        use fips204::traits::{SerDes as _, Signer as _};

        let (private, public) = generate_keypair().expect("keys");
        let message = transcript(DOMAIN);
        let key = fips204::ml_dsa_87::PrivateKey::try_from_bytes(
            <[u8; PRIVATE_KEY_LEN]>::try_from(private.as_slice()).expect("length"),
        )
        .expect("private key");
        // Exactly what a v4-era signer produces: right key, right bytes, no
        // context. It must not verify under the v5 rule.
        let signature = key.try_sign(&message, &[]).expect("sign");
        assert_eq!(
            verify(&public, context(DOMAIN), &message, &signature).err(),
            Some(MlDsaError::InvalidSignature)
        );
    }

    #[test]
    fn a_hash_ml_dsa_signature_is_refused_by_the_pure_verifier() {
        use fips204::traits::{SerDes as _, Signer as _};

        let (private, public) = generate_keypair().expect("keys");
        let message = transcript(DOMAIN);
        let key = fips204::ml_dsa_87::PrivateKey::try_from_bytes(
            <[u8; PRIVATE_KEY_LEN]>::try_from(private.as_slice()).expect("length"),
        )
        .expect("private key");
        let signature = key
            .try_hash_sign(&message, DOMAIN, &fips204::Ph::SHA256)
            .expect("prehashed signature");
        assert_eq!(
            verify(&public, context(DOMAIN), &message, &signature).err(),
            Some(MlDsaError::InvalidSignature)
        );
    }

    #[test]
    fn a_transcript_that_does_not_open_with_its_domain_is_refused_on_both_sides() {
        let (private, public) = generate_keypair().expect("keys");
        let stray = b"not-the-domain and then some bytes".to_vec();
        assert_eq!(
            sign(&private, context(DOMAIN), &stray).err(),
            Some(MlDsaError::DomainMismatch)
        );
        let message = transcript(DOMAIN);
        let signature = sign(&private, context(DOMAIN), &message).expect("sign");
        assert_eq!(
            verify(&public, context(DOMAIN), &stray, &signature).err(),
            Some(MlDsaError::DomainMismatch)
        );
    }

    #[test]
    fn a_key_or_signature_of_the_wrong_length_is_refused_before_any_arithmetic() {
        let (private, public) = generate_keypair().expect("keys");
        let message = transcript(DOMAIN);
        let signature = sign(&private, context(DOMAIN), &message).expect("sign");
        assert_eq!(
            verify(&public[..8], context(DOMAIN), &message, &signature).err(),
            Some(MlDsaError::InvalidPublicKey)
        );
        assert_eq!(
            verify(&public, context(DOMAIN), &message, &signature[..8]).err(),
            Some(MlDsaError::InvalidSignature)
        );
        assert_eq!(
            sign(&private[..8], context(DOMAIN), &message).err(),
            Some(MlDsaError::InvalidPrivateKey)
        );
    }

    #[test]
    fn two_generated_identities_differ() {
        let (first_private, first_public) = generate_keypair().expect("keys");
        let (second_private, second_public) = generate_keypair().expect("keys");
        assert_ne!(first_public, second_public);
        assert_ne!(*first_private, *second_private);
    }
}
