use serde::{Deserialize, Serialize};

use crate::error::{HeliosError, Result};

/// État opérationnel du tunnel IPsec.
///
/// Invariant de sécurité : le trafic du LAN n'est autorisé à sortir QUE lorsque
/// le tunnel est réellement opérationnel ([`TunnelState::Up`] ou
/// [`TunnelState::Rekeying`]). Dans tout autre état, le kill-switch est engagé
/// (« fail-closed ») : aucune fuite en clair n'est possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelState {
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

    /// Applique un événement et renvoie l'état suivant, ou une erreur si la
    /// transition n'a pas de sens.
    pub fn on(self, event: TunnelEvent) -> Result<TunnelState> {
        use TunnelEvent::*;
        use TunnelState::*;

        let next = match (self, event) {
            (Down | Failed, StartRequested) => Connecting,
            (Connecting, IkeEstablished) => Connecting, // IKE_SA up, on attend la CHILD_SA
            (Connecting, ChildUp) => Up,
            (Up, ChildRekeying) => Rekeying,
            (Rekeying, ChildUp) => Up,
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
    }

    #[test]
    fn only_up_and_rekeying_allow_traffic() {
        assert!(TunnelState::Up.traffic_allowed());
        assert!(TunnelState::Rekeying.traffic_allowed());
        assert!(!TunnelState::Down.traffic_allowed());
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
}
