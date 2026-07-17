use serde::{Deserialize, Serialize};

use crate::error::{HeliosError, Result};

/// État opérationnel du tunnel WireGuard.
///
/// Invariant de sécurité (gateway) : le trafic du LAN n'est autorisé à sortir QUE
/// lorsque le tunnel est [`TunnelState::Up`]. Dans tout autre état, le kill-switch
/// est engagé (« fail-closed »).
///
/// WireGuard est sans connexion : il n'y a pas d'état « en cours de rekey »
/// observable (le rekey est transparent, ~toutes les 2 min). L'état `Up` est
/// *inféré* d'un handshake récent (`last_handshake_time`, seuil ~150 s), pas reçu
/// comme un événement de plan de contrôle — voir ADR-001 §3.
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
    /// Tunnel en cours d'établissement. Kill-switch ACTIF.
    ///
    /// Couvre aussi la fenêtre de montée en deux temps de WireGuard : tunnel
    /// classique monté (clés Curve25519) mais PSK post-quantique pas encore
    /// installé. Le trafic reste bloqué jusqu'au passage `Up` (ADR-001,
    /// cinématique).
    Connecting,
    /// Handshake WireGuard récent : trafic autorisé à travers le tunnel.
    Up,
    /// Échec. Kill-switch ACTIF.
    Failed,
    /// Portail captif interceptant le trafic : kill-switch partiel
    /// (HTTP/HTTPS vers la passerelle locale autorisés, tout le reste bloqué).
    CaptivePortal,
}

/// Événements pilotant la machine à états.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelEvent {
    /// Montée demandée (UI ou démarrage).
    StartRequested,
    /// Handshake WireGuard frais observé (polling) *et* PSK en place → tunnel
    /// pleinement opérationnel.
    HandshakeEstablished,
    /// Plus de handshake récent (polling) : le tunnel n'est plus considéré `Up`,
    /// on retombe en tentative de rétablissement. Pas un échec dur.
    HandshakeExpired,
    /// Démontage explicite.
    Disconnected,
    /// Erreur : retour fail-closed.
    Error,
    /// Portail captif détecté — HTTP intercepté sur le réseau courant.
    CaptivePortalDetected,
    /// L'utilisateur a validé le portail captif — tenter une reconnexion.
    CaptivePortalResolved,
}

impl TunnelState {
    /// Le trafic utilisateur (LAN -> WAN) est-il autorisé dans cet état ?
    pub fn traffic_allowed(self) -> bool {
        matches!(self, TunnelState::Up)
    }

    /// Le kill-switch est-il engagé (tout est bloqué sauf le port WireGuard) ?
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
            // Handshake frais + PSK en place → tunnel pleinement opérationnel
            (Connecting, HandshakeEstablished) => Up,
            // Le handshake a vieilli au-delà du seuil → retour en tentative
            (Up, HandshakeExpired) => Connecting,
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
    fn only_up_allows_traffic() {
        assert!(TunnelState::Up.traffic_allowed());
        assert!(!TunnelState::Connecting.traffic_allowed());
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
        // Montée classique + upgrade PSK → handshake pleinement établi
        let s = s.on(TunnelEvent::HandshakeEstablished).unwrap();
        assert_eq!(s, TunnelState::Up);
    }

    #[test]
    fn handshake_expiry_returns_to_connecting() {
        let s = TunnelState::Up.on(TunnelEvent::HandshakeExpired).unwrap();
        assert_eq!(s, TunnelState::Connecting);
        // Un nouveau handshake frais rétablit Up.
        let s = s.on(TunnelEvent::HandshakeEstablished).unwrap();
        assert_eq!(s, TunnelState::Up);
    }

    #[test]
    fn error_always_fails_closed() {
        for start in [TunnelState::Up, TunnelState::Connecting] {
            assert_eq!(start.on(TunnelEvent::Error).unwrap(), TunnelState::Failed);
        }
    }

    #[test]
    fn invalid_transition_is_rejected() {
        // Un handshake « établi » n'a pas de sens hors montée.
        assert!(TunnelState::Down.on(TunnelEvent::HandshakeEstablished).is_err());
        // Une expiration n'a de sens que depuis Up.
        assert!(TunnelState::Down.on(TunnelEvent::HandshakeExpired).is_err());
    }
}
