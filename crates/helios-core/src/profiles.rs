//! Profils de sécurité IKEv2 prédéfinis, du classique au post-quantique strict.

use serde::Serialize;

/// Niveau de protection post-quantique d'un profil.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqcLevel {
    /// ECDHE classique uniquement, sans échange ML-KEM.
    None,
    /// Hybride : ECDHE P-384 + ML-KEM-768 (RFC 9370 additional KE).
    Hybrid768,
    /// Hybride renforcé : ECDHE P-521 + ML-KEM-1024.
    Hybrid1024,
    /// Post-quantique strict : ML-KEM-1024 sans groupe DH classique.
    FullStrict1024,
}

/// Profil IKEv2 statique (défini dans le code, pas dans le TOML).
#[derive(Debug, Clone, Serialize)]
pub struct IkeProfile {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub ike_proposal: &'static str,
    pub esp_proposal: &'static str,
    pub pqc_level: PqcLevel,
    /// Si `true`, la connexion avec ce profil nécessite une confirmation explicite dans l'UI.
    pub reserved: bool,
}

pub const PROFILES: &[IkeProfile] = &[
    IkeProfile {
        id:           "classic",
        name:         "Classique",
        description:  "ECDHE P-256 uniquement — sans post-quantique. Interopérabilité maximale.",
        ike_proposal: "aes256gcm16-prfsha256-ecp256",
        esp_proposal: "aes256gcm16-ecp256",
        pqc_level:    PqcLevel::None,
        reserved:     false,
    },
    IkeProfile {
        id:           "hybrid",
        name:         "Hybride PQC",
        description:  "ECDHE P-384 + ML-KEM-768 — protection hybride classique/post-quantique (recommandé).",
        ike_proposal: "aes256gcm16-prfsha384-ecp384-ke1_mlkem768",
        esp_proposal: "aes256gcm16-ecp384",
        pqc_level:    PqcLevel::Hybrid768,
        reserved:     false,
    },
    IkeProfile {
        id:           "hybrid-max",
        name:         "Hybride Maximum",
        description:  "ECDHE P-521 + ML-KEM-1024 — niveau maximal hybride, opérations réservées.",
        ike_proposal: "aes256gcm16-prfsha512-ecp521-ke1_mlkem1024",
        esp_proposal: "aes256gcm16-ecp521",
        pqc_level:    PqcLevel::Hybrid1024,
        reserved:     true,
    },
    IkeProfile {
        id:           "full-pqc",
        name:         "Post-Quantique Strict",
        description:  "ML-KEM-1024 exclusif — sans échange classique DH. Requiert strongSwan ≥ 6 + plugin ML-KEM.",
        ike_proposal: "aes256gcm16-prfsha512-ke1_mlkem1024",
        esp_proposal: "aes256gcm16",
        pqc_level:    PqcLevel::FullStrict1024,
        reserved:     true,
    },
];

/// Retourne le profil correspondant à `id`, ou `None` si inconnu.
pub fn find(id: &str) -> Option<&'static IkeProfile> {
    PROFILES.iter().find(|p| p.id == id)
}

/// Détecte le profil correspondant à une proposition IKE donnée.
pub fn detect(ike_proposal: &str) -> Option<&'static IkeProfile> {
    PROFILES.iter().find(|p| p.ike_proposal == ike_proposal)
}
