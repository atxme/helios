//! Mises à jour OTA de l'appliance — stratégie **A/B avec RAUC**.
//!
//! Modèle A/B : deux slots système (A et B). On installe la nouvelle image dans
//! le slot inactif, on rebascule au reboot, puis un *health check* confirme le
//! slot (`mark-good`). Si le boot échoue, le bootloader fait un **rollback**
//! automatique vers le slot précédent. RAUC + le bootloader gèrent l'atomicité
//! et le partitionnement ; Helios se contente de piloter `rauc`.
//!
//! * [`RaucChannel`] — pilote le binaire `rauc` (cible).
//! * [`DryRunChannel`] — simule tout, pour le dev sur WSL2.

mod dryrun;
mod rauc;

pub use dryrun::DryRunChannel;
pub use rauc::RaucChannel;

use async_trait::async_trait;
use helios_core::Result;
use serde::{Deserialize, Serialize};

/// Une release disponible, telle que décrite par l'index de mises à jour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub version: String,
    /// Chemin local ou URL HTTPS du bundle `.raucb`.
    pub bundle: String,
}

/// Résultat d'une installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Installée dans le slot inactif ; un reboot est requis pour basculer.
    Installed { reboot_required: bool },
    /// Déjà à jour, rien à faire.
    AlreadyUpToDate,
}

/// Canal de mise à jour de l'appliance.
#[async_trait]
pub trait UpdateChannel: Send + Sync {
    /// Version actuellement active.
    async fn current_version(&self) -> Result<String>;

    /// Interroge l'index : une release plus récente est-elle disponible ?
    async fn check(&self) -> Result<Option<Release>>;

    /// Installe une release dans le slot inactif.
    async fn install(&self, release: &Release) -> Result<InstallOutcome>;

    /// Confirme que le boot courant est sain (RAUC `mark-good`). À appeler après
    /// un démarrage réussi pour empêcher le rollback automatique.
    async fn confirm_boot(&self) -> Result<()>;
}
