//! Validateur d'intégrité de démarrage par **scellement TPM** (TPM Sealing).
//!
//! Modèle de sécurité (cf. `docs/` et la spécification de cycle de vie) :
//!
//! - **Provisionnement (TOFU, usine)** : un secret 256 bits est généré puis
//!   *scellé* par le TPM contre l'état des PCR (0/4/7). Le blob scellé est
//!   stocké sur la partition de configuration.
//! - **Démarrage en production** : on tente l'*unseal*. Le TPM ne rend le secret
//!   que si les PCR matériels sont identiques à ceux du scellement. Sinon
//!   (bootloader/kernel altéré) → `TPM2_RC_POLICY_FAIL`, le secret reste verrouillé.
//! - **Mise à jour OTA** : l'OTA change le kernel → les PCR changent → l'unseal
//!   échoue légitimement. Le rescellement n'est autorisé que par un **billet
//!   signé** (Ed25519) vérifié avec la clé publique de l'éditeur. Cela ferme la
//!   faille du TOFU sur le terrain (un attaquant ne peut pas forcer un faux
//!   « premier boot » pour sceller son kernel malveillant).
//!
//! Le secret descellé n'est pas qu'une porte : il **déchiffre les identifiants
//! IPsec** avant `load-conn`. Modifier le binaire ne donne donc pas la clé — la
//! garantie est matérielle, pas logicielle.
//!
//! ## Découpage WSL2 / cible
//!
//! Toute la logique de décision (flux de boot, billet Ed25519, blob store,
//! anti-rejeu) est testable sur WSL2 via [`tpm_interface::DryRunTpm`]. Le backend
//! réel (`feature tpm`, `tpm_interface::TpmDevice`) n'est validable que sur la
//! cible — comme le backend Netlink du pare-feu.

mod blob_store;
mod boot_controller;
pub mod escrow;
pub mod keystore;
mod provisioning;
mod reseal_ticket;
mod secret;
mod settings;
mod tpm_interface;
#[cfg(feature = "tpm")]
mod tpm_real;

pub use boot_controller::{BootController, BootDecision};
pub use escrow::EscrowError;
pub use keystore::{KeystoreError, SealedKeystore};
pub use secret::SecretKey;
pub use settings::TpmSettings;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TpmError {
    #[error("connexion au TPM impossible : {0}")]
    Connection(String),

    #[error("lecture PCR {index} échouée : {cause}")]
    PcrRead { index: u8, cause: String },

    #[error("génération du secret (CSPRNG) échouée : {0}")]
    Rng(String),

    #[error("I/O sur {path} : {cause}")]
    Io { path: String, cause: String },

    #[error("sérialisation/désérialisation : {0}")]
    Serde(String),

    #[error(
        "blob scellé absent hors provisionnement — anomalie de sécurité \
         (un attaquant a pu le supprimer pour forcer un faux premier boot)"
    )]
    MissingBlobOnField,

    #[error("déscellement refusé par le TPM (PCR modifiés) — TPM2_RC_POLICY_FAIL")]
    UnsealPolicyFail,

    #[error("déscellement impossible et aucun billet de rescellement valide présent")]
    UnsealFailedNoTicket,

    #[error("signature du billet de rescellement invalide")]
    TicketInvalidSignature,

    #[error("billet de rescellement rejeté (anti-rejeu) : version {ticket} <= courante {current}")]
    TicketRollback { ticket: u64, current: u64 },

    #[error("billet de rescellement lié à un état PCR différent de l'état courant")]
    TicketPcrMismatch,

    #[error(transparent)]
    Keystore(#[from] keystore::KeystoreError),

    #[error(transparent)]
    Escrow(#[from] escrow::EscrowError),

    #[error("opération TPM réelle non implémentée ({0}) — à valider sur la cible")]
    NotImplemented(&'static str),
}

pub type Result<T> = std::result::Result<T, TpmError>;
