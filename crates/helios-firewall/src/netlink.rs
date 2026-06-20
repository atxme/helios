//! Backend Netlink réel, basé sur `rustables` (nf_tables).
//!
//! ⚠️ **Cible uniquement.** Ce module dépend de `libnftnl`/`libmnl` et d'un kernel
//! disposant de `nf_tables`. Il est derrière la feature `netlink` et ne se
//! compile pas sur le kernel WSL2 par défaut. À construire et valider sur la
//! machine dédiée :
//!
//! ```sh
//! sudo apt install libnftnl-dev libmnl-dev
//! cargo build -p helios-firewall --features netlink
//! ```
//!
//! ## État
//!
//! Le squelette ci-dessous pose l'ossature (rendu de règles + transaction
//! `Batch` Netlink atomique) mais **la construction des expressions de règles
//! reste à finaliser** contre l'API exacte de `rustables` installée sur la
//! cible. Tant que ce n'est pas fait, [`NetlinkBackend::commit`] refuse
//! explicitement d'appliquer une politique partielle plutôt que d'ouvrir une
//! brèche dans le kill-switch — c'est délibérément **fail-closed**.
//!
//! Étapes d'intégration (sur la cible) :
//! 1. créer la table `inet helios` ;
//! 2. créer les chaînes `input`/`forward`/`output` à hook, politique par défaut
//!    `drop` (= [`crate::Verdict::Drop`]) ;
//! 3. traduire chaque entrée de [`crate::ruleset::Ruleset::rules`] en expression
//!    Netlink (`iif lo`, `ct state established,related`, match d'IP/port pour
//!    IKE, forward LAN -> WAN) ;
//! 4. `batch.send()` pour un commit atomique.

use async_trait::async_trait;
use helios_core::{FirewallPolicy, HeliosError, Result, TunnelState};
use rustables::Batch;
use tracing::{info, warn};

use crate::ruleset::render;
use crate::FirewallBackend;

const TABLE_NAME: &str = "helios";

pub struct NetlinkBackend {
    table_name: String,
}

impl NetlinkBackend {
    pub fn new() -> Self {
        Self {
            table_name: TABLE_NAME.to_string(),
        }
    }

    /// Pousse le jeu de règles voulu dans le kernel via une transaction Netlink.
    fn commit(&self, policy: &FirewallPolicy, state: TunnelState) -> Result<()> {
        let rs = render(policy, state);
        let _batch = Batch::new();

        info!(
            "table inet {} — politique cible {:?}, état {:?}",
            self.table_name, rs.default_verdict, state
        );
        for rule in &rs.rules {
            info!("  (à traduire en expr Netlink) {}", rule);
        }

        // Voir le module-level doc : tant que la traduction des règles n'est pas
        // finalisée, on refuse d'appliquer une politique incomplète.
        warn!("backend Netlink non finalisé : aucune règle appliquée");
        Err(HeliosError::Firewall(
            "backend Netlink à finaliser sur la cible (voir netlink.rs)".into(),
        ))
    }
}

impl Default for NetlinkBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FirewallBackend for NetlinkBackend {
    async fn apply(&self, policy: &FirewallPolicy, state: TunnelState) -> Result<()> {
        self.commit(policy, state)
    }

    async fn teardown(&self) -> Result<()> {
        let _batch = Batch::new();
        info!("teardown de la table inet {} (à finaliser)", self.table_name);
        Ok(())
    }
}
