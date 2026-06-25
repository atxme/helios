/// Paramètres du contrôleur TPM — constantes d'architecture de l'appliance.
///
/// Tous les choix (banque PCR, sélection, chemins de persistance) sont des
/// décisions d'architecture figées pour la durée de vie du produit. Seul `enabled`
/// varie : il est positionné à `true` uniquement si la feature `tpm` est compilée
/// (cible physique).
pub struct TpmSettings {
    /// Active le scellement/déscellement. `false` = bypass (WSL2 / dev).
    pub enabled: bool,
    /// `false` = log seulement en cas d'échec (RÉSERVÉ AU DÉBOGAGE).
    pub enforce: bool,
    /// Autorise le provisionnement TOFU si aucun blob scellé n'existe.
    /// `true` uniquement en usine (premier boot). Sur le terrain, un blob absent
    /// est une anomalie de sécurité.
    pub allow_provisioning: bool,
    pub device: String,
    pub pcr_bank: String,
    /// PCR liés au scellement : 0=firmware, 4=bootloader, 7=Secure Boot.
    pub pcr_selection: Vec<u8>,
    pub sealed_blob_path: String,
    pub ticket_path: String,
    pub state_path: String,
}

impl Default for TpmSettings {
    fn default() -> Self {
        Self {
            enabled: cfg!(feature = "tpm"),
            enforce: true,
            allow_provisioning: false,
            device: "/dev/tpmrm0".to_string(),
            pcr_bank: "sha256".to_string(),
            pcr_selection: vec![0, 4, 7],
            sealed_blob_path: "/var/lib/helios/sealed.key".to_string(),
            ticket_path: "/var/lib/helios/reseal-ticket.json".to_string(),
            state_path: "/var/lib/helios/tpm-state.json".to_string(),
        }
    }
}
