//! The signed `.orion` document the operator returns (§15.3).
//!
//! Unlike the invitation and the request, this one is signed over **JSON**:
//! its profile is a free-form public object that Orion reads field by field,
//! and a binary transcript of it would be a second schema to keep in step. The
//! JSON is therefore brought to its RFC 8785 (JCS) form first, so two writers
//! that order members or spaces differently sign the same bytes.
//!
//! JCS is only canonical over I-JSON, so the parser enforces it: no duplicate
//! member at any depth, no number that is not an integer of at most 2^53 in
//! magnitude. Every field this protocol carries is an integer; a float is
//! refused rather than handed to a number formatter whose rounding the two
//! ends would have to agree on.

use std::fmt;

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};

use super::{strip_bom, CanonicalBytes, EnrollmentError};
use crate::certificates::encoding::{
    verify_ml_dsa_87, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature,
};

/// `format` of the document, shared with the v1 Orion profile.
pub const ENROLLMENT_DOCUMENT_FORMAT: &str = "orion-profile";
/// `format_version` of the signed enrollment document.
pub const ENROLLMENT_DOCUMENT_VERSION: u16 = 5;

const DOCUMENT_DOMAIN: &[u8] = b"helios-key-negotiation-orion-document-v5";
/// Largest integer magnitude I-JSON represents exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The `.orion` v5 document: public profile, client leaves, binding to the
/// request, operator signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentDocument {
    pub format: String,
    pub format_version: u16,
    pub invitation_id: Id16,
    pub request_id: Id16,
    pub request_fingerprint: Fingerprint,
    pub operator_ca_fingerprint: Fingerprint,
    pub issued_at_unix: u64,
    /// The public profile. Opaque here; Orion validates its members.
    #[serde(deserialize_with = "strict_object")]
    pub profile: serde_json::Map<String, serde_json::Value>,
    pub client_tls_certificate: DerCertificate,
    /// The client PQ leaf: base64 of the JSON `PqCertificate` serializes to,
    /// the encoding of the profile's `gateway_pq_certificate`.
    pub client_pq_certificate: String,
    /// Absent in the draft the gateway side writes, present once `CA-PQ`
    /// has signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_signature: Option<MlDsa87Signature>,
}

impl EnrollmentDocument {
    /// Reads a document, refusing everything JCS cannot sign unambiguously.
    pub fn parse(text: &str) -> Result<Self, EnrollmentError> {
        let document: Self = serde_json::from_str(strip_bom(text))
            .map_err(|_| EnrollmentError::Format("not a v5 Orion document"))?;
        if document.format != ENROLLMENT_DOCUMENT_FORMAT {
            return Err(EnrollmentError::Format("format"));
        }
        if document.format_version != ENROLLMENT_DOCUMENT_VERSION {
            return Err(EnrollmentError::Format("format_version"));
        }
        Ok(document)
    }

    /// RFC 8785 form of the document **without** `operator_signature`.
    pub fn canonical_unsigned(&self) -> Result<Vec<u8>, EnrollmentError> {
        let unsigned = Self {
            operator_signature: None,
            ..self.clone()
        };
        serde_json_canonicalizer::to_vec(&unsigned)
            .map_err(|_| EnrollmentError::Format("not representable in JCS"))
    }

    /// `domain || len(jcs):u32 || jcs`.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, EnrollmentError> {
        Ok(self.transcript()?.finish())
    }

    fn transcript(&self) -> Result<CanonicalBytes, EnrollmentError> {
        let jcs = self.canonical_unsigned()?;
        let mut bytes = CanonicalBytes::new(DOCUMENT_DOMAIN);
        bytes.length_prefixed(&jcs);
        Ok(bytes)
    }

    /// Verifies the document under the `CA-PQ` key pinned at invitation time.
    ///
    /// The document must name that key's fingerprint: a CA that only the
    /// document brings is never an anchor.
    pub fn verify(&self, pinned_ca: &MlDsa87PublicKey) -> Result<(), EnrollmentError> {
        if self.operator_ca_fingerprint != pinned_ca.authority_fingerprint() {
            return Err(EnrollmentError::Binding("operator_ca_fingerprint"));
        }
        let signature = self
            .operator_signature
            .as_ref()
            .ok_or(EnrollmentError::Signature)?;
        verify_ml_dsa_87(pinned_ca, &self.transcript()?.finish_signed(), signature)
            .map_err(|_| EnrollmentError::Signature)
    }

    /// Signs the document with the `CA-PQ` private key it names.
    #[cfg(feature = "key-negotiation-signing")]
    pub fn sign(mut self, ca_pq_private_key: &[u8]) -> Result<Self, EnrollmentError> {
        let public = crate::certificates::encoding::derive_ml_dsa_87_public_key(ca_pq_private_key)
            .map_err(|_| EnrollmentError::Signing)?;
        if public.authority_fingerprint() != self.operator_ca_fingerprint {
            return Err(EnrollmentError::Binding("operator_ca_fingerprint"));
        }
        let signature = crate::certificates::encoding::sign_ml_dsa_87(
            ca_pq_private_key,
            &self.transcript()?.finish_signed(),
        )
        .map_err(|_| EnrollmentError::Signing)?;
        self.operator_signature = Some(signature);
        Ok(self)
    }

    /// The document as it is written to disk.
    pub fn to_json(&self) -> Result<String, EnrollmentError> {
        serde_json::to_string_pretty(self).map_err(|_| EnrollmentError::Format("serialization"))
    }
}

fn strict_object<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<serde_json::Map<String, serde_json::Value>, D::Error> {
    match deserializer.deserialize_any(StrictValue)? {
        serde_json::Value::Object(members) => Ok(members),
        _ => Err(de::Error::custom("profile must be an object")),
    }
}

/// Builds a `serde_json::Value`, refusing what I-JSON forbids.
///
/// `serde_json::Value`'s own visitor keeps the last of two duplicate members
/// and accepts any float; both would let two readers of the same bytes see two
/// documents.
struct StrictValue;

impl<'de> Visitor<'de> for StrictValue {
    type Value = serde_json::Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an I-JSON value without floats")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(E::custom("integer beyond 2^53"));
        }
        Ok(value.into())
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        if value > MAX_SAFE_INTEGER {
            return Err(E::custom("integer beyond 2^53"));
        }
        Ok(value.into())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Err(E::custom("floating-point numbers are refused"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(StrictSeed)? {
            items.push(item);
        }
        Ok(serde_json::Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut members = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if members.contains_key(&key) {
                return Err(de::Error::custom("duplicate member"));
            }
            let value = map.next_value_seed(StrictSeed)?;
            members.insert(key, value);
        }
        Ok(serde_json::Value::Object(members))
    }
}

struct StrictSeed;

impl<'de> de::DeserializeSeed<'de> for StrictSeed {
    type Value = serde_json::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(StrictValue)
    }
}
