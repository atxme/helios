//! Signatures hybrides des artefacts de confiance de l'éditeur.
//!
//! La politique est volontairement non configurable : Ed25519 **et**
//! ML-DSA-65 doivent vérifier le même message canonique. Les algorithmes
//! supplémentaires inconnus sont ignorés pour permettre une extension future,
//! mais retirer l'une des deux signatures requises est toujours un rejet.

use std::collections::HashSet;

use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use fips204::{
    ml_dsa_65::{self, PublicKey},
    traits::{SerDes, Verifier},
};
use serde::{Deserialize, Serialize};

/// Taille d'une clé publique Ed25519 brute.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Taille d'une signature Ed25519.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Taille d'une clé publique ML-DSA-65 sérialisée (FIPS 204).
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = ml_dsa_65::PK_LEN;
/// Taille d'une clé privée ML-DSA-65 sérialisée (outil éditeur uniquement).
#[cfg(feature = "publisher-signing")]
pub const ML_DSA_65_PRIVATE_KEY_LEN: usize = ml_dsa_65::SK_LEN;
/// Taille d'une signature ML-DSA-65.
pub const ML_DSA_65_SIGNATURE_LEN: usize = ml_dsa_65::SIG_LEN;

/// Algorithmes compris par ce vérificateur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgId {
    Ed25519,
    MlDsa65,
}

impl AlgId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::MlDsa65 => "ml-dsa-65",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "ed25519" => Some(Self::Ed25519),
            "ml-dsa-65" => Some(Self::MlDsa65),
            _ => None,
        }
    }
}

impl std::fmt::Display for AlgId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Politique anti-downgrade compilée dans tous les vérificateurs.
pub const REQUIRED_ALGS: &[AlgId] = &[AlgId::Ed25519, AlgId::MlDsa65];

/// Clés publiques d'une époque éditeur.
#[derive(Clone, Copy)]
pub struct PublisherPublicKeys {
    pub key_epoch: u32,
    pub ed25519: [u8; ED25519_PUBLIC_KEY_LEN],
    pub ml_dsa_65: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
}

impl PublisherPublicKeys {
    /// Empreinte affichable de l'ancre de confiance, pour comparaison visuelle
    /// avec ce que l'éditeur publie hors bande.
    ///
    /// Les deux clés sont hachées **ensemble** : l'empreinte identifie l'époque
    /// dans son entier, pas l'une de ses moitiés. Un opérateur qui la compare ne
    /// peut donc pas valider un trousseau dont seule la partie Ed25519 est la
    /// bonne. Tronquée à 128 bits — c'est un aide-mémoire de comparaison, pas un
    /// contrôle de sécurité : la vraie ancre est compilée dans le binaire.
    pub fn fingerprint(&self) -> String {
        let mut material = Vec::with_capacity(ED25519_PUBLIC_KEY_LEN + ML_DSA_65_PUBLIC_KEY_LEN);
        material.extend_from_slice(&self.ed25519);
        material.extend_from_slice(&self.ml_dsa_65);
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &material);
        hex::encode(&digest.as_ref()[..16])
    }
}

// Généré depuis le fichier public désigné au build. En release, le build script
// refuse le trousseau de développement livré avec les tests.
include!(concat!(env!("OUT_DIR"), "/publisher_keyring.rs"));

/// Une signature encodée en base64 dans l'enveloppe JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSignature {
    pub alg: String,
    pub sig: String,
}

/// Enveloppe commune à tous les artefacts signés.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope<P> {
    pub payload: P,
    pub key_epoch: u32,
    pub signatures: Vec<ArtifactSignature>,
}

/// Sérialisation canonique et domaine propres à un artefact.
pub trait ArtifactPayload {
    /// Domaine complet, distinct pour chaque type d'artefact.
    const DOMAIN: &'static [u8];
    /// Version de format encodée sur 32 bits big-endian dans le message.
    const FORMAT_VERSION: u32;

    /// Ajoute le payload canonique à `output`, sans passer par JSON.
    fn encode_canonical(&self, output: &mut Vec<u8>);
}

/// Backend de vérification d'un algorithme de signature.
pub trait SignatureSuite {
    const ALGORITHM: AlgId;

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

pub struct Ed25519Suite;

impl SignatureSuite for Ed25519Suite {
    const ALGORITHM: AlgId = AlgId::Ed25519;

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if !ed25519_inputs_are_strict(public_key, signature) {
            return false;
        }
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(message, signature)
            .is_ok()
    }
}

/// AWS-LC 1.17.1 accepte notamment une forge avec clé et `R` au point identité.
/// Ces précontrôles conservent donc explicitement les garanties de
/// `ed25519-dalek::verify_strict()` avant de déléguer l'équation à AWS-LC.
fn ed25519_inputs_are_strict(public_key: &[u8], signature: &[u8]) -> bool {
    let Ok(public_key) = <[u8; ED25519_PUBLIC_KEY_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(signature) = <[u8; ED25519_SIGNATURE_LEN]>::try_from(signature) else {
        return false;
    };
    let Some(public_point) = CompressedEdwardsY(public_key).decompress() else {
        return false;
    };
    let Ok(encoded_r) = <[u8; 32]>::try_from(&signature[..32]) else {
        return false;
    };
    let Some(signature_r) = CompressedEdwardsY(encoded_r).decompress() else {
        return false;
    };
    if public_point.is_small_order() || signature_r.is_small_order() {
        return false;
    }
    let Ok(encoded_s) = <[u8; 32]>::try_from(&signature[32..]) else {
        return false;
    };
    bool::from(Scalar::from_canonical_bytes(encoded_s).is_some())
}

pub struct MlDsa65Suite;

impl SignatureSuite for MlDsa65Suite {
    const ALGORITHM: AlgId = AlgId::MlDsa65;

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(public_key) = <[u8; ML_DSA_65_PUBLIC_KEY_LEN]>::try_from(public_key) else {
            return false;
        };
        let Ok(signature) = <[u8; ML_DSA_65_SIGNATURE_LEN]>::try_from(signature) else {
            return false;
        };
        let Ok(public_key) = PublicKey::try_from_bytes(public_key) else {
            return false;
        };
        public_key.verify(message, &signature, &[])
    }
}

/// Erreurs fail-closed de l'enveloppe hybride.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("époque de clé éditeur inconnue : {0}")]
    UnknownKeyEpoch(u32),
    #[error("signature requise absente : {0}")]
    MissingRequiredAlgorithm(AlgId),
    #[error("algorithme de signature dupliqué : {0}")]
    DuplicateAlgorithm(AlgId),
    #[error("signature {0} mal encodée")]
    InvalidEncoding(AlgId),
    #[error("signature {0} invalide")]
    InvalidSignature(AlgId),
    #[cfg(feature = "publisher-signing")]
    #[error("clé privée éditeur invalide : {0}")]
    InvalidPrivateKey(&'static str),
    #[cfg(feature = "publisher-signing")]
    #[error("opération de signature éditeur échouée : {0}")]
    Signing(&'static str),
}

impl<P: ArtifactPayload> SignedEnvelope<P> {
    /// Vérifie l'époque authentifiée puis toutes les signatures requises.
    pub fn verify(&self, keyring: &[PublisherPublicKeys]) -> Result<(), SignatureError> {
        let keys = keyring
            .iter()
            .find(|keys| keys.key_epoch == self.key_epoch)
            .ok_or(SignatureError::UnknownKeyEpoch(self.key_epoch))?;
        let message = signing_bytes(&self.payload, self.key_epoch);
        let mut seen = HashSet::new();

        for entry in &self.signatures {
            let Some(algorithm) = AlgId::parse(&entry.alg) else {
                // Extension avant : la politique compilée décidera quand elle devient requise.
                continue;
            };
            if !seen.insert(algorithm) {
                return Err(SignatureError::DuplicateAlgorithm(algorithm));
            }
            let signature = STANDARD
                .decode(&entry.sig)
                .map_err(|_| SignatureError::InvalidEncoding(algorithm))?;
            let valid = match algorithm {
                AlgId::Ed25519 => Ed25519Suite::verify(&keys.ed25519, &message, &signature),
                AlgId::MlDsa65 => MlDsa65Suite::verify(&keys.ml_dsa_65, &message, &signature),
            };
            if !valid {
                return Err(SignatureError::InvalidSignature(algorithm));
            }
        }

        for required in REQUIRED_ALGS {
            if !seen.contains(required) {
                return Err(SignatureError::MissingRequiredAlgorithm(*required));
            }
        }
        Ok(())
    }
}

/// Octets signés : domaine || version format || époque || payload canonique.
pub fn signing_bytes<P: ArtifactPayload>(payload: &P, key_epoch: u32) -> Vec<u8> {
    let mut message = Vec::with_capacity(P::DOMAIN.len() + 8 + 64);
    message.extend_from_slice(P::DOMAIN);
    message.extend_from_slice(&P::FORMAT_VERSION.to_be_bytes());
    message.extend_from_slice(&key_epoch.to_be_bytes());
    payload.encode_canonical(&mut message);
    message
}

/// Payload du billet de rescellement TPM v2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResealPayload {
    pub version: u64,
    #[serde(
        default,
        serialize_with = "serialize_optional_digest",
        deserialize_with = "deserialize_optional_digest"
    )]
    pub expected_pcr_digest: Option<[u8; 32]>,
}

impl ArtifactPayload for ResealPayload {
    const DOMAIN: &'static [u8] = b"helios-tpm-reseal-v2";
    const FORMAT_VERSION: u32 = 2;

    fn encode_canonical(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.version.to_be_bytes());
        match self.expected_pcr_digest {
            Some(digest) => {
                output.push(1);
                output.extend_from_slice(&digest);
            }
            None => output.push(0),
        }
    }
}

pub type SignedResealTicket = SignedEnvelope<ResealPayload>;

fn serialize_optional_digest<S>(digest: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    digest.as_ref().map(hex::encode).serialize(serializer)
}

fn deserialize_optional_digest<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = Option::<String>::deserialize(deserializer)?;
    encoded
        .map(|value| {
            hex::decode(value)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .ok_or_else(|| serde::de::Error::custom("digest PCR hex invalide"))
        })
        .transpose()
}

#[cfg(feature = "publisher-signing")]
mod signing {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use fips204::{
        ml_dsa_65::{self, PrivateKey},
        traits::{KeyGen, SerDes, Signer},
    };

    use super::*;

    /// Paire de clés privées chargée uniquement par l'outil éditeur.
    pub struct PublisherSigner {
        key_epoch: u32,
        ed25519: Ed25519KeyPair,
        ml_dsa_65: PrivateKey,
    }

    impl PublisherSigner {
        /// Charge deux clés privées sérialisées et cohérentes avec une époque.
        pub fn from_private_keys(
            key_epoch: u32,
            ed25519_pkcs8: &[u8],
            ml_dsa_65: &[u8],
        ) -> Result<Self, SignatureError> {
            let ed25519 = Ed25519KeyPair::from_pkcs8(ed25519_pkcs8)
                .map_err(|_| SignatureError::InvalidPrivateKey("Ed25519 PKCS#8"))?;
            let ml_dsa_65 = <[u8; ml_dsa_65::SK_LEN]>::try_from(ml_dsa_65)
                .map_err(|_| SignatureError::InvalidPrivateKey("longueur ML-DSA-65"))?;
            let ml_dsa_65 =
                PrivateKey::try_from_bytes(ml_dsa_65).map_err(SignatureError::InvalidPrivateKey)?;
            Ok(Self {
                key_epoch,
                ed25519,
                ml_dsa_65,
            })
        }

        /// Reconstruit deux clés depuis leurs graines brutes de 32 octets.
        /// Préférer PKCS#8 et [`Self::from_private_keys`] pour le stockage réel.
        pub fn from_seed_material(
            key_epoch: u32,
            ed25519_seed: &[u8; 32],
            ml_dsa_65_seed: &[u8; 32],
        ) -> Result<Self, SignatureError> {
            let ed25519 = Ed25519KeyPair::from_seed_unchecked(ed25519_seed)
                .map_err(|_| SignatureError::InvalidPrivateKey("graine Ed25519"))?;
            let (_, ml_dsa_65) = ml_dsa_65::KG::keygen_from_seed(ml_dsa_65_seed);
            Ok(Self {
                key_epoch,
                ed25519,
                ml_dsa_65,
            })
        }

        /// Génère hors gateway les deux paires de clés d'une nouvelle époque.
        pub fn generate(key_epoch: u32) -> Result<Self, SignatureError> {
            let ed25519 = Ed25519KeyPair::generate()
                .map_err(|_| SignatureError::Signing("génération Ed25519"))?;
            let (_, ml_dsa_65) = ml_dsa_65::try_keygen().map_err(SignatureError::Signing)?;
            Ok(Self {
                key_epoch,
                ed25519,
                ml_dsa_65,
            })
        }

        pub const fn key_epoch(&self) -> u32 {
            self.key_epoch
        }

        /// Extrait les clés publiques destinées au trousseau compilé.
        pub fn public_keys(&self) -> PublisherPublicKeys {
            let ed25519 = self
                .ed25519
                .public_key()
                .as_ref()
                .try_into()
                .expect("AWS-LC garantit 32 octets pour Ed25519");
            let ml_dsa_65 = self.ml_dsa_65.get_public_key().into_bytes();
            PublisherPublicKeys {
                key_epoch: self.key_epoch,
                ed25519,
                ml_dsa_65,
            }
        }

        /// Sérialise les secrets pour leur stockage hors ligne.
        pub fn private_key_bytes(&self) -> Result<(Vec<u8>, Vec<u8>), SignatureError> {
            let ed25519 = self
                .ed25519
                .to_pkcs8()
                .map_err(|_| SignatureError::Signing("sérialisation Ed25519 PKCS#8"))?;
            let ml_dsa_65 = self.ml_dsa_65.clone().into_bytes();
            Ok((ed25519.as_ref().to_vec(), ml_dsa_65.to_vec()))
        }

        /// Produit l'enveloppe hybride ; les deux signatures couvrent les mêmes octets.
        pub fn sign<P: ArtifactPayload>(
            &self,
            payload: P,
        ) -> Result<SignedEnvelope<P>, SignatureError> {
            let message = signing_bytes(&payload, self.key_epoch);
            let ed25519 = self
                .ed25519
                .try_sign(&message)
                .map_err(|_| SignatureError::Signing("Ed25519"))?;
            let ml_dsa_65 = self
                .ml_dsa_65
                .try_sign(&message, &[])
                .map_err(SignatureError::Signing)?;
            Ok(SignedEnvelope {
                payload,
                key_epoch: self.key_epoch,
                signatures: vec![
                    ArtifactSignature {
                        alg: AlgId::Ed25519.as_str().to_string(),
                        sig: STANDARD.encode(ed25519.as_ref()),
                    },
                    ArtifactSignature {
                        alg: AlgId::MlDsa65.as_str().to_string(),
                        sig: STANDARD.encode(ml_dsa_65),
                    },
                ],
            })
        }
    }
}

#[cfg(feature = "publisher-signing")]
pub use signing::PublisherSigner;

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use fips204::{
        ml_dsa_65::KG,
        traits::{KeyGen, SerDes, Signer},
    };

    use super::*;

    const ED_SEED: [u8; 32] = *b"helios-sign-ed25519-test-seed001";
    const ML_SEED: [u8; 32] = *b"helios-sign-mldsa65-test-seed001";

    fn signed(payload: ResealPayload, key_epoch: u32) -> (SignedResealTicket, PublisherPublicKeys) {
        let ed = Ed25519KeyPair::from_seed_unchecked(&ED_SEED).unwrap();
        let (ml_public, ml_private) = KG::keygen_from_seed(&ML_SEED);
        let keys = PublisherPublicKeys {
            key_epoch,
            ed25519: ed.public_key().as_ref().try_into().unwrap(),
            ml_dsa_65: ml_public.into_bytes(),
        };
        let message = signing_bytes(&payload, key_epoch);
        let ed_signature = ed.sign(&message);
        let ml_signature = ml_private
            .try_sign_with_seed(&[7u8; 32], &message, &[])
            .unwrap();
        (
            SignedEnvelope {
                payload,
                key_epoch,
                signatures: vec![
                    ArtifactSignature {
                        alg: "ed25519".into(),
                        sig: STANDARD.encode(ed_signature.as_ref()),
                    },
                    ArtifactSignature {
                        alg: "ml-dsa-65".into(),
                        sig: STANDARD.encode(ml_signature),
                    },
                ],
            },
            keys,
        )
    }

    #[test]
    fn les_deux_signatures_valides_sont_requises() {
        let (envelope, keys) = signed(
            ResealPayload {
                version: 3,
                expected_pcr_digest: None,
            },
            1,
        );
        assert_eq!(envelope.verify(&[keys]), Ok(()));

        for algorithm in REQUIRED_ALGS {
            let mut missing = envelope.clone();
            missing
                .signatures
                .retain(|entry| entry.alg != algorithm.as_str());
            assert_eq!(
                missing.verify(&[keys]),
                Err(SignatureError::MissingRequiredAlgorithm(*algorithm))
            );
        }
    }

    #[test]
    fn une_signature_connue_invalide_est_un_rejet() {
        let (envelope, keys) = signed(
            ResealPayload {
                version: 3,
                expected_pcr_digest: None,
            },
            1,
        );
        for algorithm in REQUIRED_ALGS {
            let mut corrupted = envelope.clone();
            let entry = corrupted
                .signatures
                .iter_mut()
                .find(|entry| entry.alg == algorithm.as_str())
                .unwrap();
            let mut bytes = STANDARD.decode(&entry.sig).unwrap();
            bytes[0] ^= 1;
            entry.sig = STANDARD.encode(bytes);
            assert_eq!(
                corrupted.verify(&[keys]),
                Err(SignatureError::InvalidSignature(*algorithm))
            );
        }
    }

    #[test]
    fn algorithme_inconnu_ignore_mais_doublon_connu_rejete() {
        let (mut envelope, keys) = signed(
            ResealPayload {
                version: 1,
                expected_pcr_digest: None,
            },
            1,
        );
        envelope.signatures.push(ArtifactSignature {
            alg: "slh-dsa-128s-futur".into(),
            sig: "même pas du base64".into(),
        });
        assert_eq!(envelope.verify(&[keys]), Ok(()));

        envelope.signatures.push(envelope.signatures[0].clone());
        assert_eq!(
            envelope.verify(&[keys]),
            Err(SignatureError::DuplicateAlgorithm(AlgId::Ed25519))
        );
    }

    #[test]
    fn epoque_inconnue_et_reecriture_de_lepoque_sont_rejetees() {
        let (mut envelope, keys) = signed(
            ResealPayload {
                version: 1,
                expected_pcr_digest: None,
            },
            1,
        );
        assert_eq!(
            envelope.verify(&[]),
            Err(SignatureError::UnknownKeyEpoch(1))
        );

        envelope.key_epoch = 2;
        let same_keys_other_epoch = PublisherPublicKeys {
            key_epoch: 2,
            ..keys
        };
        assert_eq!(
            envelope.verify(&[same_keys_other_epoch]),
            Err(SignatureError::InvalidSignature(AlgId::Ed25519))
        );
    }

    #[test]
    fn mutation_du_payload_est_rejetee() {
        let (mut envelope, keys) = signed(
            ResealPayload {
                version: 1,
                expected_pcr_digest: Some([4u8; 32]),
            },
            1,
        );
        envelope.payload.version = 2;
        assert!(matches!(
            envelope.verify(&[keys]),
            Err(SignatureError::InvalidSignature(_))
        ));
    }

    #[test]
    fn domaine_et_version_de_format_font_partie_de_la_signature() {
        #[derive(Clone)]
        struct OtherArtifact(ResealPayload);

        impl ArtifactPayload for OtherArtifact {
            const DOMAIN: &'static [u8] = b"helios-wg-recovery-v1";
            const FORMAT_VERSION: u32 = 1;

            fn encode_canonical(&self, output: &mut Vec<u8>) {
                self.0.encode_canonical(output);
            }
        }

        let (ticket, keys) = signed(
            ResealPayload {
                version: 1,
                expected_pcr_digest: None,
            },
            1,
        );
        let wrong_context = SignedEnvelope {
            payload: OtherArtifact(ticket.payload),
            key_epoch: ticket.key_epoch,
            signatures: ticket.signatures,
        };
        assert!(matches!(
            wrong_context.verify(&[keys]),
            Err(SignatureError::InvalidSignature(_))
        ));
    }

    #[test]
    fn ed25519_rejette_les_encodages_non_canoniques_et_les_points_faibles() {
        let message = b"preuve du chemin strict AWS-LC";
        let ed = Ed25519KeyPair::from_seed_unchecked(&ED_SEED).unwrap();
        let signature = ed.sign(message);
        assert!(Ed25519Suite::verify(
            ed.public_key().as_ref(),
            message,
            signature.as_ref()
        ));

        // S = ordre du sous-groupe (non canonique, il faut S < L).
        let mut non_canonical_s: [u8; 64] = signature.as_ref().try_into().unwrap();
        non_canonical_s[32..].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ]);
        assert!(!Ed25519Suite::verify(
            ed.public_key().as_ref(),
            message,
            &non_canonical_s
        ));

        // Clé publique et R au point identité : une vérification non stricte
        // pourrait accepter cette forge triviale avec S = 0.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut weak_signature = [0u8; 64];
        weak_signature[0] = 1;
        assert!(!Ed25519Suite::verify(&identity, message, &weak_signature));
    }

    #[test]
    fn json_reordonne_ne_change_pas_les_octets_canoniques() {
        let first: SignedResealTicket = serde_json::from_str(
            r#"{"payload":{"version":9,"expected_pcr_digest":null},"key_epoch":1,"signatures":[]}"#,
        )
        .unwrap();
        let second: SignedResealTicket = serde_json::from_str(
            r#"{"signatures":[],"key_epoch":1,"payload":{"expected_pcr_digest":null,"version":9}}"#,
        )
        .unwrap();
        assert_eq!(
            signing_bytes(&first.payload, first.key_epoch),
            signing_bytes(&second.payload, second.key_epoch)
        );
    }

    #[test]
    fn encodage_base64_invalide_et_signature_vide_sont_fail_closed() {
        let (envelope, keys) = signed(
            ResealPayload {
                version: 5,
                expected_pcr_digest: None,
            },
            1,
        );

        let mut invalid_base64 = envelope.clone();
        invalid_base64.signatures[0].sig = "%%%".into();
        assert_eq!(
            invalid_base64.verify(&[keys]),
            Err(SignatureError::InvalidEncoding(AlgId::Ed25519))
        );

        let mut empty = envelope;
        empty.signatures[1].sig.clear();
        assert_eq!(
            empty.verify(&[keys]),
            Err(SignatureError::InvalidSignature(AlgId::MlDsa65))
        );
    }

    #[test]
    fn json_refuse_tout_champ_non_authentifie() {
        for json in [
            r#"{"payload":{"version":9,"expected_pcr_digest":null},"key_epoch":1,"signatures":[],"selector":"attaquant"}"#,
            r#"{"payload":{"version":9,"expected_pcr_digest":null,"ignored":true},"key_epoch":1,"signatures":[]}"#,
            r#"{"payload":{"version":9,"expected_pcr_digest":null},"key_epoch":1,"signatures":[{"alg":"ed25519","sig":"AA==","extra":1}]}"#,
        ] {
            assert!(serde_json::from_str::<SignedResealTicket>(json).is_err());
        }
    }

    #[test]
    fn empreinte_identifie_les_deux_moitie_du_trousseau() {
        let (_, keys) = signed(
            ResealPayload {
                version: 1,
                expected_pcr_digest: None,
            },
            7,
        );
        assert_eq!(keys.fingerprint(), keys.fingerprint());
        assert_eq!(keys.fingerprint().len(), 32);

        let mut changed_ed = keys;
        changed_ed.ed25519[0] ^= 1;
        assert_ne!(keys.fingerprint(), changed_ed.fingerprint());

        let mut changed_ml = keys;
        changed_ml.ml_dsa_65[0] ^= 1;
        assert_ne!(keys.fingerprint(), changed_ml.fingerprint());
    }
}
