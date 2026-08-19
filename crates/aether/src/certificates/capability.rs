//! Capability tokens of the signing companion — spec §8.2.
//!
//! # What these are for
//!
//! Three public routes exist only so `astra-signer` can fetch what it needs
//! for one operation: the signer request, the encrypted vault, and the slot to
//! post the result back into. None of them may be reachable by knowing an
//! identifier. So each carries a bearer token that names exactly one scope,
//! one operation, one manifest, one vault and a five-minute window — and
//! confers nothing outside that tuple.
//!
//! # Why a MAC and not a signature
//!
//! Astra issues these to itself: it mints the token and it verifies the token,
//! and no third party ever needs to check one. A signature would add a public
//! verifier nobody wants, and — worse — would tempt an implementation to reach
//! for the service key or the anchor. The token derives from `K_capability`,
//! which is drawn at start-up, lives only in memory and is zeroized at
//! shutdown: a restart invalidates every live token, which is the right
//! failure mode for a five-minute credential.
//!
//! # Why the scope is inside the MAC key, not only inside the payload
//!
//! The HKDF `info` repeats scope, manifest, vault and window. A token whose
//! scope byte is flipped therefore does not merely fail a field comparison —
//! it is authenticated under a key that was never derived, so the tag cannot
//! be recomputed at all. The field comparisons that follow are the second
//! control, not the only one.
//!
//! # Replay is decided by the operation
//!
//! Reads are idempotent within the window: fetching the same signer request
//! twice is not an attack, and the companion legitimately retries. A result
//! token authenticates the route but does not know the result body. The
//! operation therefore records the accepted body's fingerprint: an identical
//! `POST` is idempotent as §8.2 requires, while different bytes under the same
//! operation are a conflict. Spending the token before reading the body made a
//! malformed upload consume the only retry and made identical replay
//! impossible.

use aws_lc_rs::{hkdf, hmac};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::Zeroizing;

use super::{
    encoding::{Fingerprint, Id16, FINGERPRINT_LEN, ID_LEN},
    CertificateError,
};

/// Version byte opening every capability payload.
pub const CAPABILITY_TOKEN_VERSION: u8 = 1;

/// Length of `K_capability`.
pub const CAPABILITY_SECRET_LEN: usize = 32;

/// Length of the per-token nonce.
pub const CAPABILITY_NONCE_LEN: usize = 16;

/// Length of the HMAC-SHA-256 tag.
const CAPABILITY_TAG_LEN: usize = 32;

/// Longest life of a capability token (spec §8.2).
pub const MAX_CAPABILITY_TOKEN_LIFETIME_SECS: u64 = 300;

/// HKDF `info` domain of a capability token.
///
/// Named in §2.3.1 as a key-derivation domain and **not** as an ML-DSA
/// context: no key signs under it, which is why it is absent from the registry
/// of [`crate::ml_dsa`].
const CAPABILITY_TOKEN_DOMAIN: &[u8] = b"helios-astra-capability-token-v1";

/// Payload length without a vault fingerprint, and with one.
const PAYLOAD_LEN_WITHOUT_VAULT: usize = 1 + 1 + ID_LEN + FINGERPRINT_LEN + 1 + 8 + 8 + ID_LEN;
const PAYLOAD_LEN_WITH_VAULT: usize = PAYLOAD_LEN_WITHOUT_VAULT + FINGERPRINT_LEN;

/// What one token may be used for (spec §8.2).
///
/// The byte value binds the HTTP method and the route template as well as the
/// operation, which is why it is fixed by the specification rather than chosen
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityScope {
    /// `GET /v1/signer-requests/<operation_id>`.
    SignerRequestRead,
    /// `GET /v1/vaults/<fingerprint>`.
    EncryptedVaultRead,
    /// `POST /v1/signer-results/<operation_id>`.
    SignerResultSubmit,
}

impl CapabilityScope {
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::SignerRequestRead => 0,
            Self::EncryptedVaultRead => 1,
            Self::SignerResultSubmit => 2,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, CertificateError> {
        match byte {
            0 => Ok(Self::SignerRequestRead),
            1 => Ok(Self::EncryptedVaultRead),
            2 => Ok(Self::SignerResultSubmit),
            _ => Err(CertificateError::CapabilityScopeViolation("scope")),
        }
    }
}

/// The exact authority one token carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGrant {
    pub scope: CapabilityScope,
    pub operation_id: Id16,
    pub operation_manifest_fingerprint: Fingerprint,
    pub encrypted_vault_fingerprint: Option<Fingerprint>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub token_nonce: [u8; CAPABILITY_NONCE_LEN],
}

impl CapabilityGrant {
    /// A grant for `scope`, with a fresh nonce from the approved DRBG.
    ///
    /// The nonce is a public value, so it is drawn without prediction
    /// resistance — but it is still drawn from the one door of
    /// [`crate::random`], never from a counter or a clock.
    pub fn new(
        scope: CapabilityScope,
        operation_id: Id16,
        operation_manifest_fingerprint: Fingerprint,
        encrypted_vault_fingerprint: Option<Fingerprint>,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, CertificateError> {
        let token_nonce = crate::random::public_bytes::<CAPABILITY_NONCE_LEN>()
            .map_err(|_| CertificateError::RandomnessUnavailable)?;
        Ok(Self {
            scope,
            operation_id,
            operation_manifest_fingerprint,
            encrypted_vault_fingerprint,
            issued_at,
            expires_at,
            token_nonce,
        })
    }

    /// The canonical payload of §8.2.
    ///
    /// It carries no domain prefix, and that is deliberate: the domain lives
    /// in the HKDF `info` that derives the key this payload is authenticated
    /// under, so a payload read under another domain has no valid tag at all.
    fn payload(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PAYLOAD_LEN_WITH_VAULT);
        bytes.push(CAPABILITY_TOKEN_VERSION);
        bytes.push(self.scope.as_byte());
        bytes.extend_from_slice(self.operation_id.as_bytes());
        bytes.extend_from_slice(self.operation_manifest_fingerprint.as_bytes());
        match &self.encrypted_vault_fingerprint {
            Some(fingerprint) => {
                bytes.push(1);
                bytes.extend_from_slice(fingerprint.as_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&self.token_nonce);
        bytes
    }

    /// The HKDF `info`: everything the token authorizes except its nonce and
    /// its operation, which are the salt and the payload respectively.
    fn derivation_info(&self) -> Vec<u8> {
        let mut info = CAPABILITY_TOKEN_DOMAIN.to_vec();
        info.push(self.scope.as_byte());
        info.extend_from_slice(self.operation_manifest_fingerprint.as_bytes());
        match &self.encrypted_vault_fingerprint {
            Some(fingerprint) => {
                info.push(1);
                info.extend_from_slice(fingerprint.as_bytes());
            }
            None => info.push(0),
        }
        info.extend_from_slice(&self.issued_at.to_be_bytes());
        info.extend_from_slice(&self.expires_at.to_be_bytes());
        info
    }

    fn validate(&self) -> Result<(), CertificateError> {
        if self.token_nonce.iter().all(|byte| *byte == 0) {
            return Err(CertificateError::InvalidCapabilityToken);
        }
        if self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_CAPABILITY_TOKEN_LIFETIME_SECS
        {
            return Err(CertificateError::CapabilityTokenExpired);
        }
        // The vault-read scope has nothing to read without a vault; the other
        // two repeat whatever the operation carries.
        if self.scope == CapabilityScope::EncryptedVaultRead
            && self.encrypted_vault_fingerprint.is_none()
        {
            return Err(CertificateError::CapabilityScopeViolation("vault"));
        }
        Ok(())
    }
}

/// What a route requires of the token presented to it.
///
/// Every field comes from the route and from Astra's own operation record,
/// never from the token: a requirement read out of the credential being
/// checked would require nothing.
#[derive(Debug, Clone, Copy)]
pub struct CapabilityRequirement<'a> {
    pub scope: CapabilityScope,
    pub operation_id: &'a Id16,
    pub operation_manifest_fingerprint: &'a Fingerprint,
    pub encrypted_vault_fingerprint: Option<&'a Fingerprint>,
    /// The operation's own deadline. A token may not outlive it (spec §8.2).
    pub operation_expires_at: u64,
}

/// Process-local `K_capability`.
pub struct CapabilityTokens {
    secret: Zeroizing<[u8; CAPABILITY_SECRET_LEN]>,
}

impl CapabilityTokens {
    /// Draws `K_capability` at start-up, with prediction resistance.
    ///
    /// There is deliberately no constructor from supplied bytes: the key is a
    /// process-lifetime secret, and a path that accepted one from outside
    /// would be a path that can be handed a weak or a shared one.
    pub fn new() -> Result<Self, CertificateError> {
        let secret = crate::random::secret_bytes::<CAPABILITY_SECRET_LEN>()
            .map_err(|_| CertificateError::RandomnessUnavailable)?;
        Ok(Self { secret })
    }

    /// Mints the bearer form: `base64url` of payload followed by its tag.
    pub fn issue(
        &self,
        grant: &CapabilityGrant,
        operation_expires_at: u64,
    ) -> Result<String, CertificateError> {
        grant.validate()?;
        if grant.expires_at > operation_expires_at {
            return Err(CertificateError::CapabilityTokenExpired);
        }
        let payload = grant.payload();
        let key = self.token_key(grant)?;
        let tag = hmac::sign(&key, &payload);
        let mut token = payload;
        token.extend_from_slice(tag.as_ref());
        Ok(URL_SAFE_NO_PAD.encode(token))
    }

    /// Authenticates a bearer token for one exact route and operation.
    pub fn authenticate(
        &mut self,
        token: &str,
        requirement: &CapabilityRequirement<'_>,
        now_unix: u64,
    ) -> Result<CapabilityGrant, CertificateError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(token.as_bytes())
            .map_err(|_| CertificateError::InvalidCapabilityToken)?;
        let (payload, tag) = split_tag(&decoded)?;
        let grant = decode_payload(payload)?;

        // The tag is checked before any field is believed, and it is checked
        // under a key derived from the fields as presented — so a mutated
        // scope, manifest, vault or window changes the key, not just a
        // comparison further down.
        let key = self.token_key(&grant)?;
        hmac::verify(&key, payload, tag).map_err(|_| CertificateError::InvalidCapabilityToken)?;

        grant.validate()?;
        if grant.scope != requirement.scope {
            return Err(CertificateError::CapabilityScopeViolation("scope"));
        }
        if grant.operation_id != *requirement.operation_id {
            return Err(CertificateError::CapabilityScopeViolation("operation"));
        }
        if !grant
            .operation_manifest_fingerprint
            .matches(requirement.operation_manifest_fingerprint)
        {
            return Err(CertificateError::CapabilityScopeViolation("manifest"));
        }
        match (
            &grant.encrypted_vault_fingerprint,
            requirement.encrypted_vault_fingerprint,
        ) {
            (Some(presented), Some(expected)) if presented.matches(expected) => {}
            (None, None) => {}
            _ => return Err(CertificateError::CapabilityScopeViolation("vault")),
        }
        if now_unix < grant.issued_at
            || now_unix >= grant.expires_at
            || grant.expires_at > requirement.operation_expires_at
        {
            return Err(CertificateError::CapabilityTokenExpired);
        }

        Ok(grant)
    }

    fn token_key(&self, grant: &CapabilityGrant) -> Result<hmac::Key, CertificateError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, grant.operation_id.as_bytes());
        let info = grant.derivation_info();
        let mut material = Zeroizing::new([0u8; CAPABILITY_SECRET_LEN]);
        salt.extract(self.secret.as_slice())
            .expand(&[&info], hkdf::HKDF_SHA256)
            .and_then(|okm| okm.fill(material.as_mut_slice()))
            .map_err(|_| CertificateError::InvalidCapabilityToken)?;
        Ok(hmac::Key::new(hmac::HMAC_SHA256, material.as_slice()))
    }
}

fn split_tag(decoded: &[u8]) -> Result<(&[u8], &[u8]), CertificateError> {
    let payload_len = match decoded.len() {
        length if length == PAYLOAD_LEN_WITHOUT_VAULT + CAPABILITY_TAG_LEN => {
            PAYLOAD_LEN_WITHOUT_VAULT
        }
        length if length == PAYLOAD_LEN_WITH_VAULT + CAPABILITY_TAG_LEN => PAYLOAD_LEN_WITH_VAULT,
        _ => return Err(CertificateError::InvalidCapabilityToken),
    };
    Ok(decoded.split_at(payload_len))
}

fn decode_payload(payload: &[u8]) -> Result<CapabilityGrant, CertificateError> {
    let mut cursor = Cursor::new(payload);
    if cursor.u8()? != CAPABILITY_TOKEN_VERSION {
        return Err(CertificateError::InvalidCapabilityToken);
    }
    let scope = CapabilityScope::from_byte(cursor.u8()?)?;
    let operation_id = Id16::new(cursor.array::<ID_LEN>()?)
        .map_err(|_| CertificateError::InvalidCapabilityToken)?;
    let operation_manifest_fingerprint =
        Fingerprint::from_bytes(cursor.array::<FINGERPRINT_LEN>()?);
    let encrypted_vault_fingerprint = match cursor.u8()? {
        0 => None,
        1 => Some(Fingerprint::from_bytes(cursor.array::<FINGERPRINT_LEN>()?)),
        // The presence byte is strictly `0|1`, like every optional of §6.2.
        _ => return Err(CertificateError::InvalidCapabilityToken),
    };
    let issued_at = u64::from_be_bytes(cursor.array::<8>()?);
    let expires_at = u64::from_be_bytes(cursor.array::<8>()?);
    let token_nonce = cursor.array::<CAPABILITY_NONCE_LEN>()?;
    if !cursor.is_exhausted() {
        return Err(CertificateError::InvalidCapabilityToken);
    }
    Ok(CapabilityGrant {
        scope,
        operation_id,
        operation_manifest_fingerprint,
        encrypted_vault_fingerprint,
        issued_at,
        expires_at,
        token_nonce,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_exhausted(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn u8(&mut self) -> Result<u8, CertificateError> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or(CertificateError::InvalidCapabilityToken)?;
        self.offset += 1;
        Ok(byte)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CertificateError> {
        let end = self.offset + N;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(CertificateError::InvalidCapabilityToken)?;
        self.offset = end;
        Ok(<[u8; N]>::try_from(slice).expect("slice of exactly N bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation() -> Id16 {
        Id16::new([6; ID_LEN]).expect("operation")
    }

    fn manifest() -> Fingerprint {
        Fingerprint::of(b"manifest")
    }

    fn vault() -> Fingerprint {
        Fingerprint::of(b"vault")
    }

    fn grant(scope: CapabilityScope) -> CapabilityGrant {
        CapabilityGrant::new(scope, operation(), manifest(), Some(vault()), 1_000, 1_240)
            .expect("grant")
    }

    fn requirement(scope: CapabilityScope) -> CapabilityRequirement<'static> {
        // Leaked so the borrowed fields outlive the requirement inside a test
        // without threading lifetimes through every assertion.
        static OPERATION: std::sync::OnceLock<Id16> = std::sync::OnceLock::new();
        static MANIFEST: std::sync::OnceLock<Fingerprint> = std::sync::OnceLock::new();
        static VAULT: std::sync::OnceLock<Fingerprint> = std::sync::OnceLock::new();
        CapabilityRequirement {
            scope,
            operation_id: OPERATION.get_or_init(operation),
            operation_manifest_fingerprint: MANIFEST.get_or_init(manifest),
            encrypted_vault_fingerprint: Some(VAULT.get_or_init(vault)),
            operation_expires_at: 2_000,
        }
    }

    #[test]
    fn a_token_authenticates_for_its_own_scope_operation_and_manifest() {
        let mut tokens = CapabilityTokens::new().expect("tokens");
        let grant = grant(CapabilityScope::SignerRequestRead);
        let token = tokens.issue(&grant, 2_000).expect("issue");
        let authenticated = tokens
            .authenticate(
                &token,
                &requirement(CapabilityScope::SignerRequestRead),
                1_100,
            )
            .expect("authenticate");
        assert_eq!(authenticated, grant);
    }

    /// A route token is legitimately retried inside its window. The operation
    /// layer, which sees the body, decides identical replay versus conflict.
    #[test]
    fn read_and_submission_tokens_are_replayable_inside_their_window() {
        let mut tokens = CapabilityTokens::new().expect("tokens");
        let read = tokens
            .issue(&grant(CapabilityScope::SignerRequestRead), 2_000)
            .expect("issue");
        let reads = requirement(CapabilityScope::SignerRequestRead);
        tokens.authenticate(&read, &reads, 1_100).expect("first");
        tokens.authenticate(&read, &reads, 1_101).expect("second");

        let submit = tokens
            .issue(&grant(CapabilityScope::SignerResultSubmit), 2_000)
            .expect("issue");
        let submissions = requirement(CapabilityScope::SignerResultSubmit);
        tokens
            .authenticate(&submit, &submissions, 1_100)
            .expect("first");
        tokens
            .authenticate(&submit, &submissions, 1_101)
            .expect("identical route retry");
    }

    #[test]
    fn a_token_presented_after_its_window_or_after_its_operation_is_refused() {
        let mut tokens = CapabilityTokens::new().expect("tokens");
        let token = tokens
            .issue(&grant(CapabilityScope::SignerRequestRead), 2_000)
            .expect("issue");
        let expected = requirement(CapabilityScope::SignerRequestRead);
        assert!(matches!(
            tokens.authenticate(&token, &expected, 1_240),
            Err(CertificateError::CapabilityTokenExpired)
        ));
        assert!(matches!(
            tokens.authenticate(&token, &expected, 900),
            Err(CertificateError::CapabilityTokenExpired)
        ));
        let mut shortened = expected;
        shortened.operation_expires_at = 1_100;
        assert!(matches!(
            tokens.authenticate(&token, &shortened, 1_050),
            Err(CertificateError::CapabilityTokenExpired)
        ));
    }

    #[test]
    fn a_window_longer_than_five_minutes_is_never_minted() {
        let tokens = CapabilityTokens::new().expect("tokens");
        let stretched = CapabilityGrant::new(
            CapabilityScope::SignerRequestRead,
            operation(),
            manifest(),
            Some(vault()),
            1_000,
            1_000 + MAX_CAPABILITY_TOKEN_LIFETIME_SECS + 1,
        )
        .expect("grant");
        assert!(matches!(
            tokens.issue(&stretched, 10_000),
            Err(CertificateError::CapabilityTokenExpired)
        ));
    }

    /// Scope, manifest, vault and operation are each inside the MAC key, so a
    /// token moved between them fails authentication rather than a comparison.
    #[test]
    fn a_token_confers_nothing_on_another_scope_manifest_vault_or_operation() {
        let mut tokens = CapabilityTokens::new().expect("tokens");
        let token = tokens
            .issue(&grant(CapabilityScope::SignerRequestRead), 2_000)
            .expect("issue");

        assert!(matches!(
            tokens.authenticate(
                &token,
                &requirement(CapabilityScope::EncryptedVaultRead),
                1_100
            ),
            Err(CertificateError::CapabilityScopeViolation("scope"))
        ));

        let elsewhere = Fingerprint::of(b"another manifest");
        let mut moved = requirement(CapabilityScope::SignerRequestRead);
        moved.operation_manifest_fingerprint = &elsewhere;
        assert!(matches!(
            tokens.authenticate(&token, &moved, 1_100),
            Err(CertificateError::CapabilityScopeViolation("manifest"))
        ));

        let other_vault = Fingerprint::of(b"another vault");
        let mut moved = requirement(CapabilityScope::SignerRequestRead);
        moved.encrypted_vault_fingerprint = Some(&other_vault);
        assert!(matches!(
            tokens.authenticate(&token, &moved, 1_100),
            Err(CertificateError::CapabilityScopeViolation("vault"))
        ));

        let other_operation = Id16::new([7; ID_LEN]).expect("operation");
        let mut moved = requirement(CapabilityScope::SignerRequestRead);
        moved.operation_id = &other_operation;
        assert!(matches!(
            tokens.authenticate(&token, &moved, 1_100),
            Err(CertificateError::CapabilityScopeViolation("operation"))
        ));
    }

    /// Any byte of the payload changed invalidates the tag, because the tag is
    /// verified in constant time under a key derived from those same bytes.
    #[test]
    fn a_mutated_payload_never_authenticates() {
        let mut tokens = CapabilityTokens::new().expect("tokens");
        let token = tokens
            .issue(&grant(CapabilityScope::SignerRequestRead), 2_000)
            .expect("issue");
        let decoded = URL_SAFE_NO_PAD.decode(&token).expect("decode");
        for index in 0..decoded.len() {
            let mut mutated = decoded.clone();
            mutated[index] ^= 0x01;
            let mutated = URL_SAFE_NO_PAD.encode(&mutated);
            assert!(
                tokens
                    .authenticate(
                        &mutated,
                        &requirement(CapabilityScope::SignerRequestRead),
                        1_100
                    )
                    .is_err(),
                "byte {index} accepted after mutation"
            );
        }
        // And the untouched token still works, so the loop above proved
        // something about the mutations rather than about the fixture.
        tokens
            .authenticate(
                &token,
                &requirement(CapabilityScope::SignerRequestRead),
                1_100,
            )
            .expect("untouched token");
    }

    #[test]
    fn a_token_from_another_process_key_authenticates_nowhere() {
        let issuer = CapabilityTokens::new().expect("tokens");
        let token = issuer
            .issue(&grant(CapabilityScope::SignerRequestRead), 2_000)
            .expect("issue");
        // A restart draws a fresh `K_capability`, so live tokens die with it.
        let mut restarted = CapabilityTokens::new().expect("tokens");
        assert!(matches!(
            restarted.authenticate(
                &token,
                &requirement(CapabilityScope::SignerRequestRead),
                1_100
            ),
            Err(CertificateError::InvalidCapabilityToken)
        ));
    }

    #[test]
    fn a_vault_read_without_a_vault_is_never_minted() {
        let tokens = CapabilityTokens::new().expect("tokens");
        let grant = CapabilityGrant::new(
            CapabilityScope::EncryptedVaultRead,
            operation(),
            manifest(),
            None,
            1_000,
            1_240,
        )
        .expect("grant");
        assert!(matches!(
            tokens.issue(&grant, 2_000),
            Err(CertificateError::CapabilityScopeViolation("vault"))
        ));
    }

    #[test]
    fn a_truncated_or_overlong_token_is_refused_before_any_derivation() {
        let mut tokens = CapabilityTokens::new().expect("tokens");
        for malformed in ["", "not-base64url!!", &"A".repeat(200)] {
            assert!(matches!(
                tokens.authenticate(
                    malformed,
                    &requirement(CapabilityScope::SignerRequestRead),
                    1_100
                ),
                Err(CertificateError::InvalidCapabilityToken)
            ));
        }
    }
}
