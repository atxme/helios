use serde::{Deserialize, Serialize};

use crate::error::{HeliosError, Result};

/// État opérationnel du tunnel IPsec.
///
/// Invariant de sécurité : le trafic du LAN n'est autorisé à sortir QUE lorsque
/// le tunnel est réellement opérationnel ([`TunnelState::Up`] ou
/// [`TunnelState::Rekeying`]). Dans tout autre état, le kill-switch est engagé
/// (« fail-closed ») : aucune fuite en clair n'est possible.
///
/// Exception contrôlée : [`TunnelState::CaptivePortal`] lève partiellement le
/// kill-switch (HTTP/HTTPS vers la passerelle locale uniquement) le temps que
/// l'utilisateur accepte le portail captif.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelState {
    #[default]
    /// Aucun tunnel. Kill-switch ACTIF.
    Down,
    /// Négociation IKE/CHILD_SA en cours. Kill-switch ACTIF.
    Connecting,
    /// SA établies, trafic autorisé à travers le tunnel.
    Up,
    /// Renégociation des clés ; les anciennes SA protègent encore le trafic.
    Rekeying,
    /// Échec. Kill-switch ACTIF.
    Failed,
    /// Portail captif interceptant le trafic : kill-switch partiel
    /// (HTTP/HTTPS vers la passerelle locale autorisés, tout le reste bloqué).
    CaptivePortal,
}

/// Événements provenant du plan de contrôle (charon via VICI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelEvent {
    StartRequested,
    IkeEstablished,
    ChildUp,
    ChildRekeying,
    Disconnected,
    Error,
    /// Migration MOBIKE (RFC 4555) : l'adresse IP locale a changé sans rupture de SA.
    /// Le tunnel reste opérationnel ; charon met à jour l'adresse dynamiquement.
    AddressChanged,
    /// Portail captif détecté — HTTP intercepté sur le réseau courant.
    CaptivePortalDetected,
    /// L'utilisateur a validé le portail captif — tenter une reconnexion.
    CaptivePortalResolved,
}

impl TunnelState {
    /// Le trafic utilisateur (LAN -> WAN) est-il autorisé dans cet état ?
    pub fn traffic_allowed(self) -> bool {
        matches!(self, TunnelState::Up | TunnelState::Rekeying)
    }

    /// Le kill-switch est-il engagé (tout est bloqué sauf IKE) ?
    pub fn kill_switch_engaged(self) -> bool {
        !self.traffic_allowed()
    }

    /// Portail captif actif : HTTP/HTTPS vers la passerelle locale autorisés.
    pub fn captive_portal_active(self) -> bool {
        matches!(self, TunnelState::CaptivePortal)
    }

    /// Représentation chaîne stable (utilisée par l'API REST).
    pub fn as_str(self) -> &'static str {
        match self {
            TunnelState::Down          => "down",
            TunnelState::Connecting    => "connecting",
            TunnelState::Up            => "up",
            TunnelState::Rekeying      => "rekeying",
            TunnelState::Failed        => "failed",
            TunnelState::CaptivePortal => "captive_portal",
        }
    }

    /// Applique un événement et renvoie l'état suivant, ou une erreur si la
    /// transition n'a pas de sens.
    pub fn on(self, event: TunnelEvent) -> Result<TunnelState> {
        use TunnelEvent::*;
        use TunnelState::*;

        let next = match (self, event) {
            (Down | Failed, StartRequested) => Connecting,
            // Portail captif : résolu par l'utilisateur → on retente la connexion
            (CaptivePortal, CaptivePortalResolved) => Connecting,
            (Connecting, IkeEstablished) => Connecting, // IKE_SA up, on attend la CHILD_SA
            (Connecting, ChildUp) => Up,
            (Up, ChildRekeying) => Rekeying,
            (Rekeying, ChildUp) => Up,
            // MOBIKE : migration d'adresse sans rupture de SA — l'état ne change pas
            (Up, AddressChanged) => Up,
            (Rekeying, AddressChanged) => Rekeying,
            // Portail captif détecté depuis n'importe quel état non-Up
            (Down | Failed | Connecting, CaptivePortalDetected) => CaptivePortal,
            (_, Disconnected) => Down,
            (_, Error) => Failed,
            (s, e) => {
                return Err(HeliosError::State(format!(
                    "l'état {s:?} ne peut pas traiter l'événement {e:?}"
                )))
            }
        };
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn down_is_fail_closed() {
        assert!(TunnelState::Down.kill_switch_engaged());
        assert!(TunnelState::Failed.kill_switch_engaged());
        assert!(TunnelState::Connecting.kill_switch_engaged());
        assert!(TunnelState::CaptivePortal.kill_switch_engaged());
    }

    #[test]
    fn only_up_and_rekeying_allow_traffic() {
        assert!(TunnelState::Up.traffic_allowed());
        assert!(TunnelState::Rekeying.traffic_allowed());
        assert!(!TunnelState::Down.traffic_allowed());
        assert!(!TunnelState::CaptivePortal.traffic_allowed());
    }

    #[test]
    fn captive_portal_lifecycle() {
        // Connecting → portail détecté → CaptivePortal
        let s = TunnelState::Connecting
            .on(TunnelEvent::CaptivePortalDetected)
            .unwrap();
        assert_eq!(s, TunnelState::CaptivePortal);
        assert!(s.captive_portal_active());
        // Résolu → Connecting
        let s = s.on(TunnelEvent::CaptivePortalResolved).unwrap();
        assert_eq!(s, TunnelState::Connecting);
    }

    #[test]
    fn nominal_lifecycle() {
        let s = TunnelState::Down;
        let s = s.on(TunnelEvent::StartRequested).unwrap();
        assert_eq!(s, TunnelState::Connecting);
        let s = s.on(TunnelEvent::IkeEstablished).unwrap();
        assert_eq!(s, TunnelState::Connecting);
        let s = s.on(TunnelEvent::ChildUp).unwrap();
        assert_eq!(s, TunnelState::Up);
        let s = s.on(TunnelEvent::ChildRekeying).unwrap();
        assert_eq!(s, TunnelState::Rekeying);
        let s = s.on(TunnelEvent::ChildUp).unwrap();
        assert_eq!(s, TunnelState::Up);
    }

    #[test]
    fn error_always_fails_closed() {
        for start in [TunnelState::Up, TunnelState::Rekeying, TunnelState::Connecting] {
            assert_eq!(start.on(TunnelEvent::Error).unwrap(), TunnelState::Failed);
        }
    }

    #[test]
    fn invalid_transition_is_rejected() {
        assert!(TunnelState::Down.on(TunnelEvent::ChildRekeying).is_err());
    }

    #[test]
    fn mobike_address_change_preserves_state() {
        assert_eq!(
            TunnelState::Up.on(TunnelEvent::AddressChanged).unwrap(),
            TunnelState::Up
        );
        assert_eq!(
            TunnelState::Rekeying.on(TunnelEvent::AddressChanged).unwrap(),
            TunnelState::Rekeying
        );
        // MOBIKE n'a pas de sens hors tunnel actif
        assert!(TunnelState::Down.on(TunnelEvent::AddressChanged).is_err());
        assert!(TunnelState::Connecting.on(TunnelEvent::AddressChanged).is_err());
    }
}
