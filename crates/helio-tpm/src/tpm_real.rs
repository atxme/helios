//! Backend TPM2 **réel** — scellement/déscellement durci (cible uniquement).
//!
//! ⚠️ **Module critique de sécurité, validable uniquement sur matériel TPM.**
//! Comme `helios-firewall/src/netlink.rs`, ce code ne compile qu'avec `--features
//! tpm` (libtss2-esys présente) et ne peut être exercé ni sur WSL2 ni par la CI.
//! Les invariants ci-dessous doivent être revérifiés lors du bring-up matériel.
//!
//! ## Mesures de durcissement appliquées
//!
//! 1. **Liaison aux PCR par politique (PolicyPCR)** : le secret n'est descellable
//!    que si PCR 0/4/7 (banque SHA-256) sont identiques au scellement. Un kernel
//!    ou bootloader altéré change les PCR → `TPM2_RC_POLICY_FAIL`.
//! 2. **Sessions salées + chiffrées (anti-sniffing du bus SPI/I2C)** : les sessions
//!    qui transportent le secret (Create, Unseal) sont *salées* par la clé primaire
//!    ECC et portent les attributs `decrypt|encrypt`. Le secret ne transite jamais
//!    en clair sur le bus matériel — mitigation directe de l'attaque MITM décrite
//!    dans le modèle de menaces.
//! 3. **Objet non duplicable** : `fixedTPM` + `fixedParent` lient le blob à *ce*
//!    TPM ; il est inutilisable ailleurs même copié.
//! 4. **Autorisation par politique seule** : `userWithAuth = false` interdit le
//!    déscellement par simple mot de passe ; seule la politique PCR ouvre l'objet.
//! 5. **Banque faible refusée** : SHA-1 est rejeté ; seule SHA-256 est acceptée.
//! 6. **Hygiène des handles** : sessions et objets transitoires sont systématiquement
//!    purgés (`flush_context`), y compris sur chemin d'erreur.
//! 7. **Secret minimisé en mémoire** : la donnée descellée est immédiatement copiée
//!    dans [`SecretKey`] (zeroïsé au drop) et les tampons intermédiaires effacés.

use std::str::FromStr;

use sha2::{Digest as _, Sha256};
use tss_esapi::{
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::{KeyHandle, ObjectHandle, SessionHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::AesKeyBits,
        resource_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Digest, EccPoint, EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme, Private, Public,
        PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData,
        SymmetricDefinition, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    Context, TctiNameConf,
};
use zeroize::Zeroize;

use crate::{
    secret::SecretKey,
    tpm_interface::{SealedBlob, TpmSealer},
    Result, TpmError,
};

/// En-tête du blob persistant : magie + version + banque + sélection PCR.
/// Stocker la sélection rend le déscellement auto-cohérent même si la config dérive.
const BLOB_MAGIC: &[u8; 4] = b"HTPM";
const BLOB_VERSION: u8 = 1;
const BANK_SHA256: u8 = 1;

pub(crate) struct TpmDevice {
    device_path: String,
    bank: String,
    indices: Vec<u8>,
}

impl TpmDevice {
    pub(crate) fn new(cfg: &crate::settings::TpmSettings) -> Result<Self> {
        // Refus immédiat des banques faibles (SHA-1) — défense en profondeur.
        hash_alg_from_bank(&cfg.pcr_bank)?;
        Ok(Self {
            device_path: cfg.device.clone(),
            bank: cfg.pcr_bank.clone(),
            indices: cfg.pcr_selection.clone(),
        })
    }
}

impl TpmSealer for TpmDevice {
    fn current_pcr_digest(&mut self) -> Result<[u8; 32]> {
        let mut ctx = open_context(&self.device_path)?;
        let alg = hash_alg_from_bank(&self.bank)?;
        let selection = pcr_selection(alg, &self.indices)?;

        let (_, _, digests) = ctx.pcr_read(selection).map_err(|e| TpmError::PcrRead {
            index: 0,
            cause: e.to_string(),
        })?;

        // Empreinte d'identité de l'état PCR (sert à lier le billet de rescellement) :
        // SHA-256 de la concaténation des valeurs PCR lues, dans l'ordre.
        let mut hasher = Sha256::new();
        for d in digests.value() {
            hasher.update(d.value());
        }
        Ok(hasher.finalize().into())
    }

    fn seal(&mut self, secret: &SecretKey) -> Result<SealedBlob> {
        let mut ctx = open_context(&self.device_path)?;
        let alg = hash_alg_from_bank(&self.bank)?;
        let selection = pcr_selection(alg, &self.indices)?;

        // Clé primaire ECC (hiérarchie Owner) : sert à la fois de parent du blob et
        // de clé de sel des sessions chiffrées. Déterministe pour ce TPM.
        let primary = create_primary(&mut ctx)?;

        let outcome = (|| {
            // authPolicy = digest de la politique PCR calculé par le TPM sur les PCR
            // courants (session d'essai → le digest n'est pas secret).
            let auth_policy = compute_pcr_policy_digest(&mut ctx, alg, &selection)?;
            let public = sealed_template(auth_policy)?;

            // Session HMAC salée + chiffrée : protège le secret (paramètre de commande)
            // contre l'écoute du bus pendant TPM2_Create.
            let session = start_salted_session(&mut ctx, primary.key_handle, SessionType::Hmac)?;

            let mut sensitive_bytes = secret.as_bytes().to_vec();
            let sensitive = SensitiveData::try_from(sensitive_bytes.clone())
                .map_err(|e| TpmError::Connection(format!("sensitive: {e}")))?;
            sensitive_bytes.zeroize();

            let created = ctx
                .execute_with_session(Some(session), |ctx| {
                    ctx.create(
                        primary.key_handle,
                        public,
                        None,
                        Some(sensitive),
                        None,
                        None,
                    )
                })
                .map_err(|e| TpmError::Connection(format!("create (seal): {e}")));

            let _ = ctx.flush_context(SessionHandle::from(session).into());
            let created = created?;

            let blob = marshal_blob(&self.indices, &created.out_public, &created.out_private)?;
            Ok(SealedBlob::from_bytes(blob))
        })();

        let _ = ctx.flush_context(primary.key_handle.into());
        outcome
    }

    fn unseal(&mut self, blob: &SealedBlob) -> Result<SecretKey> {
        let mut ctx = open_context(&self.device_path)?;
        let (indices, public, private) = unmarshal_blob(blob.as_bytes())?;
        let alg = hash_alg_from_bank(&self.bank)?;
        let selection = pcr_selection(alg, &indices)?;

        let primary = create_primary(&mut ctx)?;

        let outcome = (|| {
            // Chargement de l'objet scellé sous la primaire (auth parent = null).
            let object: ObjectHandle = ctx
                .execute_with_nullauth_session(|ctx| ctx.load(primary.key_handle, private, public))
                .map_err(|e| TpmError::Connection(format!("load (unseal): {e}")))?
                .into();

            // Session de politique salée + chiffrée : PolicyPCR lit les PCR courants,
            // et l'attribut `encrypt` chiffre le secret renvoyé sur le bus.
            let session = start_salted_session(&mut ctx, primary.key_handle, SessionType::Policy)?;
            let policy_session = PolicySession::try_from(session)
                .map_err(|e| TpmError::Connection(format!("policy session: {e}")))?;

            let policy_step = ctx
                .policy_pcr(policy_session, empty_digest()?, selection)
                .map_err(|e| TpmError::Connection(format!("policy_pcr: {e}")));

            let unsealed = policy_step.and_then(|()| {
                ctx.execute_with_session(Some(session), |ctx| ctx.unseal(object))
                    .map_err(|e| {
                        // PCR modifiés → TPM2_RC_POLICY_FAIL : c'est le signal d'un OTA
                        // (rescellement sous billet) ou d'une altération (refus).
                        if is_policy_fail(&e) {
                            TpmError::UnsealPolicyFail
                        } else {
                            TpmError::Connection(format!("unseal: {e}"))
                        }
                    })
            });

            let _ = ctx.flush_context(SessionHandle::from(session).into());
            let _ = ctx.flush_context(object);

            let sensitive = unsealed?;
            to_secret_key(sensitive)
        })();

        let _ = ctx.flush_context(primary.key_handle.into());
        outcome
    }
}

// ─────────────────────────────── Helpers TPM2 ───────────────────────────────

fn open_context(device: &str) -> Result<Context> {
    let tcti = TctiNameConf::from_str(&format!("device:{device}"))
        .map_err(|e| TpmError::Connection(format!("TCTI {device}: {e}")))?;
    Context::new(tcti).map_err(|e| TpmError::Connection(e.to_string()))
}

/// Refuse toute banque autre que SHA-256 (SHA-1 obsolète = vecteur d'attaque).
fn hash_alg_from_bank(bank: &str) -> Result<HashingAlgorithm> {
    match bank.to_ascii_lowercase().as_str() {
        "sha256" => Ok(HashingAlgorithm::Sha256),
        other => Err(TpmError::Connection(format!(
            "banque PCR refusée : {other} (seule sha256 est autorisée)"
        ))),
    }
}

fn pcr_selection(
    alg: HashingAlgorithm,
    indices: &[u8],
) -> Result<tss_esapi::structures::PcrSelectionList> {
    use tss_esapi::structures::{PcrSelectionListBuilder, PcrSlot};

    let slot_for = |i: &u8| -> Result<PcrSlot> {
        Ok(match i {
            0 => PcrSlot::Slot0,
            1 => PcrSlot::Slot1,
            2 => PcrSlot::Slot2,
            3 => PcrSlot::Slot3,
            4 => PcrSlot::Slot4,
            5 => PcrSlot::Slot5,
            6 => PcrSlot::Slot6,
            7 => PcrSlot::Slot7,
            other => {
                return Err(TpmError::PcrRead {
                    index: *other,
                    cause: "index PCR non supporté (0–7 attendus)".into(),
                })
            }
        })
    };
    let slots: Vec<PcrSlot> = indices.iter().map(slot_for).collect::<Result<_>>()?;
    PcrSelectionListBuilder::new()
        .with_selection(alg, &slots)
        .build()
        .map_err(|e| TpmError::Connection(format!("sélection PCR: {e}")))
}

fn empty_digest() -> Result<Digest> {
    Digest::try_from(Vec::<u8>::new())
        .map_err(|e| TpmError::Connection(format!("digest vide: {e}")))
}

/// Gabarit de la clé primaire ECC P-256 (clé de stockage restreinte).
/// Déterministe : recréée à l'identique au déscellement → même parent.
fn primary_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()
        .map_err(|e| TpmError::Connection(format!("attributs primaire: {e}")))?;

    let ecc = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        // Schéma symétrique de la clé de stockage : AES-128-CFB.
        .with_symmetric(SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes128,
            mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
        })
        .build()
        .map_err(|e| TpmError::Connection(format!("params ECC primaire: {e}")))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| TpmError::Connection(format!("template primaire: {e}")))
}

/// Gabarit de l'objet scellé (keyedhash, donnée fournie) lié à `auth_policy`.
fn sealed_template(auth_policy: Digest) -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        // On fournit la donnée → l'origine n'est pas le TPM.
        .with_sensitive_data_origin(false)
        // Pas d'auth par mot de passe : seule la politique PCR ouvre l'objet.
        .with_user_with_auth(false)
        .with_admin_with_policy(true)
        .with_no_da(true)
        .with_restricted(false)
        .with_decrypt(false)
        .with_sign_encrypt(false)
        .build()
        .map_err(|e| TpmError::Connection(format!("attributs scellé: {e}")))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_auth_policy(auth_policy)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(empty_digest()?)
        .build()
        .map_err(|e| TpmError::Connection(format!("template scellé: {e}")))
}

fn create_primary(ctx: &mut Context) -> Result<tss_esapi::structures::CreatePrimaryKeyResult> {
    let public = primary_template()?;
    ctx.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
    })
    .map_err(|e| TpmError::Connection(format!("create_primary: {e}")))
}

/// Session salée (par la primaire ECC) avec chiffrement de paramètres.
///
/// Le sel rend la clé de session inaccessible à une écoute passive du bus ;
/// `decrypt|encrypt` chiffrent les paramètres sensibles (secret) dans les deux sens.
fn start_salted_session(
    ctx: &mut Context,
    salt_key: KeyHandle,
    session_type: SessionType,
) -> Result<AuthSession> {
    let session = ctx
        .start_auth_session(
            Some(salt_key), // clé de sel → résistance au sniffing du bus
            None,
            None,
            session_type,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| TpmError::Connection(format!("start_auth_session: {e}")))?
        .ok_or_else(|| TpmError::Connection("session d'autorisation vide".into()))?;

    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .with_continue_session(true)
        .build();
    ctx.tr_sess_set_attributes(session, attrs, mask)
        .map_err(|e| TpmError::Connection(format!("attributs session: {e}")))?;

    Ok(session)
}

/// Calcule le digest de la politique PCR via une session d'essai (digest public).
fn compute_pcr_policy_digest(
    ctx: &mut Context,
    _alg: HashingAlgorithm,
    selection: &tss_esapi::structures::PcrSelectionList,
) -> Result<Digest> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| TpmError::Connection(format!("trial session: {e}")))?
        .ok_or_else(|| TpmError::Connection("session d'essai vide".into()))?;

    let result = (|| {
        let policy_session = PolicySession::try_from(session)
            .map_err(|e| TpmError::Connection(format!("policy session: {e}")))?;
        // pcrDigest vide → le TPM intègre les valeurs PCR courantes.
        ctx.policy_pcr(policy_session, empty_digest()?, selection.clone())
            .map_err(|e| TpmError::Connection(format!("policy_pcr (essai): {e}")))?;
        ctx.policy_get_digest(policy_session)
            .map_err(|e| TpmError::Connection(format!("policy_get_digest: {e}")))
    })();

    let _ = ctx.flush_context(SessionHandle::from(session).into());
    result
}

fn to_secret_key(sensitive: SensitiveData) -> Result<SecretKey> {
    let bytes = sensitive.value();
    if bytes.len() != 32 {
        return Err(TpmError::Connection(format!(
            "secret descellé de taille inattendue : {} octets (32 attendus)",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    let secret = SecretKey::from_bytes(key);
    key.zeroize();
    Ok(secret)
}

// ───────────────────────────── (Dé)sérialisation du blob ─────────────────────────────

fn marshal_blob(indices: &[u8], public: &Public, private: &Private) -> Result<Vec<u8>> {
    let pub_bytes = public
        .marshall()
        .map_err(|e| TpmError::Serde(format!("marshall public: {e}")))?;
    // `Private` est déjà un TPM2B opaque (format fil) → octets bruts directs.
    let priv_bytes = private.value().to_vec();

    let mut out = Vec::new();
    out.extend_from_slice(BLOB_MAGIC);
    out.push(BLOB_VERSION);
    out.push(BANK_SHA256);
    out.push(indices.len() as u8);
    out.extend_from_slice(indices);
    out.extend_from_slice(&(pub_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&pub_bytes);
    out.extend_from_slice(&(priv_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&priv_bytes);
    Ok(out)
}

fn unmarshal_blob(bytes: &[u8]) -> Result<(Vec<u8>, Public, Private)> {
    let mut cur = bytes;

    let take = |cur: &mut &[u8], n: usize| -> Result<Vec<u8>> {
        if cur.len() < n {
            return Err(TpmError::Serde("blob tronqué".into()));
        }
        let (head, tail) = cur.split_at(n);
        *cur = tail;
        Ok(head.to_vec())
    };
    let take_u32 = |cur: &mut &[u8]| -> Result<u32> {
        let b = take(cur, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    if take(&mut cur, 4)? != BLOB_MAGIC {
        return Err(TpmError::Serde("magie du blob invalide".into()));
    }
    if take(&mut cur, 1)?[0] != BLOB_VERSION {
        return Err(TpmError::Serde("version de blob non supportée".into()));
    }
    if take(&mut cur, 1)?[0] != BANK_SHA256 {
        return Err(TpmError::Serde("banque du blob non supportée".into()));
    }
    let n = take(&mut cur, 1)?[0] as usize;
    let indices = take(&mut cur, n)?;

    let pub_len = take_u32(&mut cur)? as usize;
    let pub_bytes = take(&mut cur, pub_len)?;
    let priv_len = take_u32(&mut cur)? as usize;
    let priv_bytes = take(&mut cur, priv_len)?;

    let public =
        Public::unmarshall(&pub_bytes).map_err(|e| TpmError::Serde(format!("public: {e}")))?;
    let private =
        Private::try_from(priv_bytes).map_err(|e| TpmError::Serde(format!("private: {e}")))?;
    Ok((indices, public, private))
}

/// Détecte TPM2_RC_POLICY_FAIL (PCR ne correspondant plus à l'authPolicy).
///
/// Détection via le `Debug` de l'erreur pour ne pas dépendre du chemin exact des
/// enums de `tss-esapi` (à confirmer au bring-up). Seul ce cas déclenche la voie
/// de rescellement ; toute autre erreur reste une erreur dure.
fn is_policy_fail(e: &tss_esapi::Error) -> bool {
    let s = format!("{e:?}");
    s.contains("PolicyFail") || s.contains("policy_fail")
}
