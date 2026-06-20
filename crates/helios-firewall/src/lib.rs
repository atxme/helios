//! Plan de données firewall : le **kill-switch**.
//!
//! Le moteur de rendu ([`ruleset`]) traduit une [`FirewallPolicy`] + un
//! [`TunnelState`] en un jeu de règles déclaratif, indépendant du backend. Deux
//! backends consomment ce jeu de règles :
//!
//! * [`DryRunBackend`] — journalise les règles sans toucher au kernel. Backend
//!   par défaut, utilisable partout (WSL2 compris).
//! * `NetlinkBackend` (feature `netlink`) — applique les règles atomiquement via
//!   l'API Netlink de nf_tables (crate `rustables`). Réservé à la cible.
//!
//! Principe directeur : **fail-closed**. Au démarrage, avant toute négociation,
//! on engage le kill-switch ; le trafic LAN n'est ouvert que lorsque l'état
//! passe à `Up`/`Rekeying`.

pub mod ruleset;

mod dryrun;
#[cfg(feature = "netlink")]
mod netlink;

pub use dryrun::DryRunBackend;
pub use ruleset::{render, Ruleset, Verdict};

#[cfg(feature = "netlink")]
pub use netlink::NetlinkBackend;

use async_trait::async_trait;
use helios_core::{FirewallPolicy, Result, TunnelState};

/// Backend chargé d'imposer concrètement la politique de pare-feu.
#[async_trait]
pub trait FirewallBackend: Send + Sync {
    /// Applique le jeu de règles correspondant à l'état courant du tunnel.
    async fn apply(&self, policy: &FirewallPolicy, state: TunnelState) -> Result<()>;

    /// Engage le kill-switch (équivaut à `apply(policy, TunnelState::Down)`).
    /// À appeler au démarrage du daemon, avant tout contact avec charon.
    async fn engage_kill_switch(&self, policy: &FirewallPolicy) -> Result<()> {
        self.apply(policy, TunnelState::Down).await
    }

    /// Supprime entièrement la table Helios (nettoyage à l'arrêt).
    async fn teardown(&self) -> Result<()>;
}
