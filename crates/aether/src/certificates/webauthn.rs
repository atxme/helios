//! Verification of the operator assertion carried by an approval — spec §2.4.
//!
//! # Why this exists at all
//!
//! Astra says an operator approved a renewal. Helios and Orion are not allowed
//! to believe it (spec §0.4): the grant therefore carries the **bytes** of the
//! WebAuthn assertion and the public binding of the credential signed by
//! `CA-PQ`, so both consumers re-derive the fact for themselves. An approval
//! that carried only Astra's word — or only the assertion's fingerprint — is
//! refused, and §14.1 names that refusal explicitly.
//!
//! # What an assertion is, and what it is not
//!
//! It is an **authorization**, never a signature of this protocol. A YubiKey 5
//! holds RSA, P-256/P-384 and Ed25519; every signature field of the
//! certificate lifecycle is an `MlDsa87Signature`, which no authenticator can
//! produce. So what is checked here is that a specific credential was
//! exercised, with user presence and user verification, against a challenge
//! that is the hash of one exact request. Nothing more is inferred, and the
//! assertion opens no key-slot: a `hmac-secret` output is a separate CTAP
//! extension that an ordinary renewal never asks for.
//!
//! # Limite connue — supported credential algorithms
//!
//! Only **ES256** (COSE `-7`, ECDSA P-256 with SHA-256) and **EdDSA** (COSE
//! `-8`, Ed25519) verify here. Both are what a FIDO2 authenticator registers
//! by default, and both are directly verifiable by the library already in the
//! tree. RS256 and every other COSE algorithm are refused by name
//! ([`CertificateError::UnsupportedCredentialAlgorithm`]) rather than skipped:
//! an unverifiable assertion must not become an accepted one. Supporting RS256
//! would mean re-encoding a COSE modulus and exponent into a PKCS#1 public
//! key; nothing in ADR-008 asks for it, and no credential the companion
//! enrols uses it.
//!
//! # Why the CBOR reader is written here
//!
//! A COSE key is a five-entry CBOR map, and the workspace carries no CBOR
//! crate. The reader below decodes exactly that shape — definite-length map,
//! integer labels, integer and byte-string values — and refuses everything
//! else, tags and indefinite lengths included. A parser that accepted more
//! than the shape it needs would be a parser with a surface nobody reviewed.

use aws_lc_rs::{digest, signature};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

use super::{
    encoding::{validate_server_name, CanonicalBytes, Fingerprint},
    CertificateError,
};

/// Domain of the assertion fingerprint.
///
/// The specification names `assertion_fingerprint` without fixing its
/// transcript, so it is fixed here: a domain-separated hash of the three
/// length-prefixed fields. It is a hash, never an ML-DSA context, and it is
/// deliberately not one of the domains of §2.3.1 — no key ever signs under it.
const ASSERTION_FINGERPRINT_DOMAIN: &[u8] = b"helios-astra-webauthn-assertion-fingerprint-v5";

/// Shortest authenticator data an assertion can carry: `rpIdHash || flags ||
/// signCount`.
const MIN_AUTHENTICATOR_DATA_BYTES: usize = 32 + 1 + 4;

/// Upper bound on authenticator data, which may carry CBOR extension output.
pub const MAX_AUTHENTICATOR_DATA_BYTES: usize = 2048;

/// Upper bound on `clientDataJSON`, which the platform composes.
pub const MAX_CLIENT_DATA_BYTES: usize = 2048;

/// Upper bound on the assertion signature, generous enough for an RSA one so
/// the refusal is about the algorithm rather than about a length.
pub const MAX_ASSERTION_SIGNATURE_BYTES: usize = 1024;

/// Upper bound on a COSE public key.
pub const MAX_CREDENTIAL_PUBLIC_KEY_BYTES: usize = 1024;

/// Length of the salt handed to `hmac-secret`, in bytes.
///
/// CTAP2 fixes it: the extension takes a 32-byte salt and returns a 32-byte
/// output. It is a property of the key, not of any file format and not of the
/// program that speaks to the key — which is why it is defined here, where a
/// reader that never links a HID stack can still name it.
pub const SALT_LEN: usize = 32;

/// Key material an authenticator released for one slot.
///
/// On a real machine this is the CTAP2 `hmac-secret` output for a credential
/// and a salt, obtained with user presence **and** user verification. The type
/// exists so nothing above the hardware boundary can confuse it with a key: it
/// is input to a derivation, never a wrapping key itself.
///
/// Nothing in the approval path ever produces one — the approval ceremony is
/// handed no salt (spec §14.1), so a caller that holds only that method cannot
/// obtain this type at all.
pub struct SlotSecret(zeroize::Zeroizing<Vec<u8>>);

impl SlotSecret {
    pub fn new(material: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(material))
    }

    /// The bytes, for the single derivation that consumes them.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SlotSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SlotSecret(<redacted>)")
    }
}

/// User presence: the operator physically touched the authenticator.
const FLAG_USER_PRESENT: u8 = 0x01;

/// User verification: a PIN or biometric was checked by the authenticator.
const FLAG_USER_VERIFIED: u8 = 0x04;

/// The three byte strings a WebAuthn `GetAssertion` returns.
///
/// Carried whole rather than summarised, because a summary is exactly what
/// spec §14.1 refuses: "assertion refusée si Astra ne transporte que son
/// empreinte sans les octets WebAuthn vérifiables par Helios et Orion".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebAuthnAssertion {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
}

impl WebAuthnAssertion {
    /// Identifies these exact bytes, for the fingerprint chain of §2.4.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut bytes = CanonicalBytes::new(ASSERTION_FINGERPRINT_DOMAIN);
        bytes
            .length_prefixed(&self.authenticator_data)
            .length_prefixed(&self.client_data_json)
            .length_prefixed(&self.signature);
        Fingerprint::of(&bytes.finish())
    }

    fn bounds(&self) -> Result<(), CertificateError> {
        if self.authenticator_data.len() < MIN_AUTHENTICATOR_DATA_BYTES
            || self.authenticator_data.len() > MAX_AUTHENTICATOR_DATA_BYTES
        {
            return Err(CertificateError::InvalidAssertion("authenticator data"));
        }
        if self.client_data_json.is_empty() || self.client_data_json.len() > MAX_CLIENT_DATA_BYTES {
            return Err(CertificateError::InvalidAssertion("client data"));
        }
        if self.signature.is_empty() || self.signature.len() > MAX_ASSERTION_SIGNATURE_BYTES {
            return Err(CertificateError::InvalidAssertion("signature"));
        }
        Ok(())
    }
}

/// What one assertion has to be an assertion *of*.
///
/// Every field comes from the signed approval request, never from the
/// assertion: an assertion that chose its own relying party, origin or
/// challenge would be an assertion of nothing.
#[derive(Debug, Clone, Copy)]
pub struct AssertionExpectation<'a> {
    pub relying_party_id: &'a str,
    pub origin: &'a str,
    /// SHA-256 of the canonical approval request — the "hash exact" of §0.4.
    pub challenge: &'a Fingerprint,
}

/// The subset of `clientDataJSON` WebAuthn fixes.
///
/// Unknown members are tolerated on purpose: the platform is allowed to add
/// them, and a strict decoder here would refuse honest browsers and honest
/// `webauthn.dll` output alike.
#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

/// Verifies an assertion against the request it must be bound to.
///
/// The order is deliberate: the cheap structural bindings first — relying
/// party, presence, verification, challenge, origin — then the public key,
/// then the arithmetic. A caller that stopped after the structural half would
/// accept an assertion nobody produced; a caller that only ran the arithmetic
/// would accept a genuine assertion made for another request.
pub fn verify_assertion(
    assertion: &WebAuthnAssertion,
    credential_public_key: &[u8],
    expectation: &AssertionExpectation<'_>,
) -> Result<(), CertificateError> {
    assertion.bounds()?;
    validate_server_name(expectation.relying_party_id)
        .map_err(|_| CertificateError::InvalidAssertion("relying party identifier"))?;
    validate_https_origin(expectation.origin, expectation.relying_party_id)?;

    let relying_party_hash = Fingerprint::from_bytes(
        <[u8; 32]>::try_from(&assertion.authenticator_data[..32])
            .expect("authenticator data is at least 37 bytes, checked immediately above"),
    );
    if !relying_party_hash.matches(&Fingerprint::of(expectation.relying_party_id.as_bytes())) {
        return Err(CertificateError::InvalidAssertion("relying party hash"));
    }
    let flags = assertion.authenticator_data[32];
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(CertificateError::InvalidAssertion("user presence"));
    }
    // User verification is what makes the approval an operator's and not a
    // touch anybody with the token could produce. The signature counter is
    // deliberately not read: spec §2.4 says it is never the primary replay
    // defence, and the single-use challenge is.
    if flags & FLAG_USER_VERIFIED == 0 {
        return Err(CertificateError::InvalidAssertion("user verification"));
    }

    let client_data: ClientData = serde_json::from_slice(&assertion.client_data_json)
        .map_err(|_| CertificateError::InvalidAssertion("client data JSON"))?;
    if client_data.kind != "webauthn.get" {
        return Err(CertificateError::InvalidAssertion("client data type"));
    }
    if client_data.origin != expectation.origin {
        return Err(CertificateError::InvalidAssertion("client data origin"));
    }
    // The challenge is the hash of the exact request. Comparing the decoded
    // bytes rather than the base64 text keeps a padded or differently-cased
    // spelling from being read as a different challenge — or as the same one.
    let challenge = URL_SAFE_NO_PAD
        .decode(client_data.challenge.as_bytes())
        .map_err(|_| CertificateError::InvalidAssertion("client data challenge"))?;
    let challenge = <[u8; 32]>::try_from(challenge.as_slice())
        .map_err(|_| CertificateError::InvalidAssertion("client data challenge"))?;
    if !Fingerprint::from_bytes(challenge).matches(expectation.challenge) {
        return Err(CertificateError::InvalidAssertion("challenge binding"));
    }

    let mut message = assertion.authenticator_data.clone();
    message
        .extend_from_slice(digest::digest(&digest::SHA256, &assertion.client_data_json).as_ref());
    parse_cose_key(credential_public_key)?.verify(&message, &assertion.signature)
}

/// A COSE public key in one of the two shapes a FIDO2 credential registers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CoseKey {
    /// ECDSA P-256 with SHA-256, as an uncompressed point.
    EcdsaP256(Vec<u8>),
    /// Ed25519, as its 32-byte public key.
    Ed25519([u8; 32]),
}

impl CoseKey {
    fn verify(&self, message: &[u8], candidate: &[u8]) -> Result<(), CertificateError> {
        let (algorithm, key): (&dyn signature::VerificationAlgorithm, &[u8]) = match self {
            // WebAuthn ES256 signatures are ASN.1 DER `SEQUENCE { r, s }`,
            // never the fixed-width pair.
            Self::EcdsaP256(point) => (&signature::ECDSA_P256_SHA256_ASN1, point.as_slice()),
            Self::Ed25519(key) => (&signature::ED25519, key.as_slice()),
        };
        signature::UnparsedPublicKey::new(algorithm, key)
            .verify(message, candidate)
            .map_err(|_| CertificateError::InvalidAssertion("assertion signature"))
    }
}

/// Checks that a credential public key is one this build can actually use.
///
/// Called when a binding is verified, so no consumer ever stores a credential
/// it would only discover to be unusable at the moment of an approval — which
/// is the moment there is no fallback.
pub fn assert_supported_credential_key(bytes: &[u8]) -> Result<(), CertificateError> {
    parse_cose_key(bytes).map(|_| ())
}

/// COSE label of the key type.
const COSE_LABEL_KTY: i64 = 1;
/// COSE label of the algorithm.
const COSE_LABEL_ALG: i64 = 3;
/// COSE label of the curve.
const COSE_LABEL_CRV: i64 = -1;
/// COSE label of the x coordinate, or of the whole OKP key.
const COSE_LABEL_X: i64 = -2;
/// COSE label of the y coordinate.
const COSE_LABEL_Y: i64 = -3;

fn parse_cose_key(bytes: &[u8]) -> Result<CoseKey, CertificateError> {
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_PUBLIC_KEY_BYTES {
        return Err(CertificateError::InvalidAssertion("credential public key"));
    }
    let mut reader = Cbor::new(bytes);
    let entries = reader.map_len()?;
    let mut key_type = None;
    let mut algorithm = None;
    let mut curve = None;
    let mut x = None;
    let mut y = None;
    for _ in 0..entries {
        let label = reader.integer()?;
        // The value is decoded before the algorithm is known, because the same
        // labels hold coordinates for an EC key and moduli for an RSA one. An
        // unsupported algorithm must be refused *as* an unsupported algorithm,
        // not as a parse failure that says nothing an operator can act on.
        let value = reader.value()?;
        match label {
            COSE_LABEL_KTY => key_type = Some(value.integer()?),
            COSE_LABEL_ALG => algorithm = Some(value.integer()?),
            COSE_LABEL_CRV => curve = Some(value),
            COSE_LABEL_X => x = Some(value),
            COSE_LABEL_Y => y = Some(value),
            // A label outside the five COSE fixes here belongs to a key shape
            // this reader does not claim to understand.
            _ => return Err(CertificateError::InvalidAssertion("COSE label")),
        }
    }
    if !reader.is_exhausted() {
        return Err(CertificateError::InvalidAssertion("trailing COSE bytes"));
    }

    match (key_type, algorithm) {
        // EC2 / ES256 / P-256.
        (Some(2), Some(-7)) => {
            if curve.map(CborValue::integer).transpose()? != Some(1) {
                return Err(CertificateError::InvalidAssertion("COSE curve"));
            }
            let x = x
                .ok_or(CertificateError::InvalidAssertion("COSE x coordinate"))?
                .byte_string()?;
            let y = y
                .ok_or(CertificateError::InvalidAssertion("COSE y coordinate"))?
                .byte_string()?;
            if x.len() != 32 || y.len() != 32 {
                return Err(CertificateError::InvalidAssertion("COSE coordinate"));
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            Ok(CoseKey::EcdsaP256(point))
        }
        // OKP / EdDSA / Ed25519.
        (Some(1), Some(-8)) => {
            if curve.map(CborValue::integer).transpose()? != Some(6) || y.is_some() {
                return Err(CertificateError::InvalidAssertion("COSE curve"));
            }
            let x = x
                .ok_or(CertificateError::InvalidAssertion("COSE x coordinate"))?
                .byte_string()?;
            let x = <[u8; 32]>::try_from(x)
                .map_err(|_| CertificateError::InvalidAssertion("COSE coordinate"))?;
            Ok(CoseKey::Ed25519(x))
        }
        (Some(_), Some(_)) => Err(CertificateError::UnsupportedCredentialAlgorithm),
        _ => Err(CertificateError::InvalidAssertion("COSE key shape")),
    }
}

/// One decoded CBOR value: the only two shapes a COSE key holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CborValue<'a> {
    Integer(i64),
    Bytes(&'a [u8]),
}

impl<'a> CborValue<'a> {
    fn integer(self) -> Result<i64, CertificateError> {
        match self {
            Self::Integer(value) => Ok(value),
            Self::Bytes(_) => Err(CertificateError::InvalidAssertion("COSE integer")),
        }
    }

    fn byte_string(self) -> Result<&'a [u8], CertificateError> {
        match self {
            Self::Bytes(value) => Ok(value),
            Self::Integer(_) => Err(CertificateError::InvalidAssertion("COSE byte string")),
        }
    }
}

/// The CBOR subset a COSE key needs: definite-length maps, integers and byte
/// strings, and nothing else.
struct Cbor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cbor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_exhausted(&self) -> bool {
        self.offset == self.bytes.len()
    }

    /// Reads one head: the major type and its argument.
    ///
    /// Indefinite lengths and the reserved additional information values are
    /// refused here, which is what keeps every caller below finite.
    fn head(&mut self) -> Result<(u8, u64), CertificateError> {
        let initial = *self
            .bytes
            .get(self.offset)
            .ok_or(CertificateError::InvalidAssertion("truncated COSE key"))?;
        self.offset += 1;
        let major = initial >> 5;
        let argument = match initial & 0x1f {
            small @ 0..=23 => u64::from(small),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().expect("two bytes"),
            )),
            26 => u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().expect("four bytes"),
            )),
            27 => u64::from_be_bytes(self.take(8)?.try_into().expect("eight bytes")),
            _ => return Err(CertificateError::InvalidAssertion("COSE encoding")),
        };
        Ok((major, argument))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CertificateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CertificateError::InvalidAssertion("COSE length"))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(CertificateError::InvalidAssertion("truncated COSE key"))?;
        self.offset = end;
        Ok(slice)
    }

    fn map_len(&mut self) -> Result<u64, CertificateError> {
        match self.head()? {
            // A map larger than the five labels of a COSE key is refused
            // before a single entry is read, so a declared length can never
            // drive the loop above.
            (5, entries) if entries <= 5 => Ok(entries),
            _ => Err(CertificateError::InvalidAssertion("COSE map")),
        }
    }

    fn integer(&mut self) -> Result<i64, CertificateError> {
        match self.head()? {
            (0, value) => {
                i64::try_from(value).map_err(|_| CertificateError::InvalidAssertion("COSE integer"))
            }
            (1, value) => i64::try_from(value)
                .map(|value| -1 - value)
                .map_err(|_| CertificateError::InvalidAssertion("COSE integer")),
            _ => Err(CertificateError::InvalidAssertion("COSE integer")),
        }
    }

    /// Reads one value, which is either an integer or a byte string.
    fn value(&mut self) -> Result<CborValue<'a>, CertificateError> {
        match self.head()? {
            (0, value) => i64::try_from(value)
                .map(CborValue::Integer)
                .map_err(|_| CertificateError::InvalidAssertion("COSE integer")),
            (1, value) => i64::try_from(value)
                .map(|value| CborValue::Integer(-1 - value))
                .map_err(|_| CertificateError::InvalidAssertion("COSE integer")),
            (2, length) => {
                let length = usize::try_from(length)
                    .map_err(|_| CertificateError::InvalidAssertion("COSE length"))?;
                self.take(length).map(CborValue::Bytes)
            }
            _ => Err(CertificateError::InvalidAssertion("COSE value")),
        }
    }
}

/// Checks an HTTPS origin and that the relying party identifier governs it.
///
/// WebAuthn requires the RP ID to be a registrable suffix of the origin's
/// host. Checking it here is what stops a signed approval request from naming
/// `webauthn_rp_id = astra.example` while pointing the operator's browser at
/// an origin somebody else controls.
pub fn validate_https_origin(origin: &str, relying_party_id: &str) -> Result<(), CertificateError> {
    let authority = origin
        .strip_prefix("https://")
        .ok_or(CertificateError::InvalidOrigin)?;
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('@')
        || authority.contains('?')
        || authority.contains('#')
    {
        return Err(CertificateError::InvalidOrigin);
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CertificateError::InvalidOrigin);
        }
    }
    validate_server_name(host).map_err(|_| CertificateError::InvalidOrigin)?;
    if host == relying_party_id {
        return Ok(());
    }
    match host.strip_suffix(relying_party_id) {
        Some(prefix) if prefix.ends_with('.') && prefix.len() > 1 => Ok(()),
        _ => Err(CertificateError::InvalidOrigin),
    }
}

#[cfg(test)]
pub(crate) mod test_credentials {
    //! A real ES256 credential, so the assertion tests exercise arithmetic
    //! rather than a fixture that agrees with itself.

    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_ASN1_SIGNING},
    };

    /// A P-256 credential able to answer a `GetAssertion`.
    pub struct Credential {
        key_pair: EcdsaKeyPair,
        rng: SystemRandom,
    }

    impl Credential {
        pub fn generate() -> Self {
            // Test material only; the protocol's own randomness goes through
            // `crate::random`, and nothing here produces a protocol value.
            let rng = SystemRandom::new();
            let document =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).expect("pkcs8");
            let key_pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref())
                    .expect("key pair");
            Self { key_pair, rng }
        }

        /// The credential's COSE public key, in the shape CTAP2 emits.
        pub fn cose_public_key(&self) -> Vec<u8> {
            let point = self.key_pair.public_key().as_ref();
            assert_eq!(point.len(), 65, "uncompressed point");
            let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
            key.extend_from_slice(&point[1..33]);
            key.extend_from_slice(&[0x22, 0x58, 0x20]);
            key.extend_from_slice(&point[33..65]);
            key
        }

        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.key_pair
                .sign(&self.rng, message)
                .expect("signature")
                .as_ref()
                .to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_credentials::Credential;
    use super::*;

    const RELYING_PARTY: &str = "astra.example";
    const ORIGIN: &str = "https://astra.example";

    fn authenticator_data(relying_party: &str, flags: u8) -> Vec<u8> {
        let mut data = Fingerprint::of(relying_party.as_bytes())
            .as_bytes()
            .to_vec();
        data.push(flags);
        data.extend_from_slice(&7u32.to_be_bytes());
        data
    }

    fn client_data(challenge: &Fingerprint, origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
            URL_SAFE_NO_PAD.encode(challenge.as_bytes())
        )
        .into_bytes()
    }

    fn assertion(
        credential: &Credential,
        challenge: &Fingerprint,
        relying_party: &str,
        origin: &str,
        flags: u8,
    ) -> WebAuthnAssertion {
        let authenticator_data = authenticator_data(relying_party, flags);
        let client_data_json = client_data(challenge, origin);
        let mut message = authenticator_data.clone();
        message.extend_from_slice(digest::digest(&digest::SHA256, &client_data_json).as_ref());
        WebAuthnAssertion {
            authenticator_data,
            client_data_json,
            signature: credential.sign(&message),
        }
    }

    fn expectation<'a>(challenge: &'a Fingerprint) -> AssertionExpectation<'a> {
        AssertionExpectation {
            relying_party_id: RELYING_PARTY,
            origin: ORIGIN,
            challenge,
        }
    }

    #[test]
    fn an_assertion_over_the_expected_challenge_verifies_under_its_credential() {
        let credential = Credential::generate();
        let challenge = Fingerprint::of(b"request");
        let assertion = assertion(
            &credential,
            &challenge,
            RELYING_PARTY,
            ORIGIN,
            FLAG_USER_PRESENT | FLAG_USER_VERIFIED,
        );
        verify_assertion(
            &assertion,
            &credential.cose_public_key(),
            &expectation(&challenge),
        )
        .expect("assertion");
    }

    /// The whole point of §0.4: an approval is bound to one exact request.
    #[test]
    fn an_assertion_made_for_another_request_hash_is_refused() {
        let credential = Credential::generate();
        let elsewhere = Fingerprint::of(b"another request");
        let assertion = assertion(
            &credential,
            &elsewhere,
            RELYING_PARTY,
            ORIGIN,
            FLAG_USER_PRESENT | FLAG_USER_VERIFIED,
        );
        let challenge = Fingerprint::of(b"request");
        assert!(matches!(
            verify_assertion(
                &assertion,
                &credential.cose_public_key(),
                &expectation(&challenge)
            ),
            Err(CertificateError::InvalidAssertion("challenge binding"))
        ));
    }

    #[test]
    fn an_assertion_under_another_relying_party_is_refused() {
        let credential = Credential::generate();
        let challenge = Fingerprint::of(b"request");
        let assertion = assertion(
            &credential,
            &challenge,
            "other.example",
            ORIGIN,
            FLAG_USER_PRESENT | FLAG_USER_VERIFIED,
        );
        assert!(matches!(
            verify_assertion(
                &assertion,
                &credential.cose_public_key(),
                &expectation(&challenge)
            ),
            Err(CertificateError::InvalidAssertion("relying party hash"))
        ));
    }

    #[test]
    fn an_assertion_without_presence_or_user_verification_is_refused() {
        let credential = Credential::generate();
        let challenge = Fingerprint::of(b"request");
        for flags in [0, FLAG_USER_PRESENT, FLAG_USER_VERIFIED] {
            let assertion = assertion(&credential, &challenge, RELYING_PARTY, ORIGIN, flags);
            assert!(
                verify_assertion(
                    &assertion,
                    &credential.cose_public_key(),
                    &expectation(&challenge)
                )
                .is_err(),
                "accepted flags {flags:#04x}"
            );
        }
    }

    #[test]
    fn an_assertion_signed_by_another_credential_is_refused() {
        let credential = Credential::generate();
        let stranger = Credential::generate();
        let challenge = Fingerprint::of(b"request");
        let assertion = assertion(
            &stranger,
            &challenge,
            RELYING_PARTY,
            ORIGIN,
            FLAG_USER_PRESENT | FLAG_USER_VERIFIED,
        );
        assert!(matches!(
            verify_assertion(
                &assertion,
                &credential.cose_public_key(),
                &expectation(&challenge)
            ),
            Err(CertificateError::InvalidAssertion("assertion signature"))
        ));
    }

    #[test]
    fn a_client_data_origin_the_request_did_not_name_is_refused() {
        let credential = Credential::generate();
        let challenge = Fingerprint::of(b"request");
        let assertion = assertion(
            &credential,
            &challenge,
            RELYING_PARTY,
            "https://sub.astra.example",
            FLAG_USER_PRESENT | FLAG_USER_VERIFIED,
        );
        assert!(matches!(
            verify_assertion(
                &assertion,
                &credential.cose_public_key(),
                &expectation(&challenge)
            ),
            Err(CertificateError::InvalidAssertion("client data origin"))
        ));
    }

    #[test]
    fn a_cose_key_of_an_algorithm_this_build_cannot_verify_is_refused_by_name() {
        // RS256: kty = 3 (RSA), alg = -257, encoded as a two-byte argument.
        let key = vec![0xa2, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00];
        assert!(matches!(
            parse_cose_key(&key),
            Err(CertificateError::UnsupportedCredentialAlgorithm)
        ));
    }

    #[test]
    fn a_malformed_or_indefinite_cose_key_is_refused_rather_than_skipped() {
        for malformed in [
            vec![],
            // Indefinite-length map.
            vec![0xbf, 0x01, 0x02, 0xff],
            // Truncated byte string.
            vec![0xa1, 0x21, 0x58, 0x20, 0x00],
            // A text-string value where an integer is required.
            vec![0xa1, 0x01, 0x62, 0x68, 0x69],
            // Trailing bytes after a complete map.
            vec![0xa1, 0x01, 0x02, 0x00],
        ] {
            assert!(
                parse_cose_key(&malformed).is_err(),
                "accepted: {malformed:02x?}"
            );
        }
    }

    #[test]
    fn an_ed25519_cose_key_is_accepted_and_a_wrong_curve_is_not() {
        let mut key = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
        key.extend_from_slice(&[9u8; 32]);
        assert!(matches!(parse_cose_key(&key), Ok(CoseKey::Ed25519(_))));
        key[6] = 0x01;
        assert!(matches!(
            parse_cose_key(&key),
            Err(CertificateError::InvalidAssertion("COSE curve"))
        ));
    }

    #[test]
    fn an_origin_is_https_and_governed_by_its_relying_party_identifier() {
        assert!(validate_https_origin("https://astra.example", "astra.example").is_ok());
        assert!(validate_https_origin("https://astra.example:8443", "astra.example").is_ok());
        assert!(validate_https_origin("https://a.astra.example", "astra.example").is_ok());
        for refused in [
            "http://astra.example",
            "https://astra.example/path",
            "https://evil.example",
            // A suffix that is not a label boundary: `notastra.example` must
            // not be governed by `astra.example`.
            "https://notastra.example",
            "https://astra.example:",
            "https://user@astra.example",
        ] {
            assert!(
                validate_https_origin(refused, "astra.example").is_err(),
                "accepted: {refused}"
            );
        }
    }
}
