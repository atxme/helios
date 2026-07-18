//! Rotation du PSK sans briquer le pair (ADR-001, « Rotation du PSK sans brique »).
//!
//! # Le piège
//!
//! WireGuard n'a **qu'un seul slot PSK par pair**. Impossible d'accepter
//! simultanément l'ancien et le nouveau : il n'y a pas de « make-before-break ».
//! Si les deux bouts se désynchronisent, le handshake échoue, le tunnel tombe —
//! et avec lui le canal de contrôle qui aurait permis de resynchroniser. Sur une
//! appliance distante, cela signifie une intervention physique.
//!
//! # La parade : revert local sur délai
//!
//! Changer le PSK d'un pair vivant **ne casse pas la session en cours** : les
//! clés de session sont déjà dérivées. Le nouveau PSK ne sert qu'au handshake
//! suivant, ≤ 2 min plus tard. Chaque bout applique alors, **sans avoir besoin
//! de communiquer** :
//!
//! > pas de handshake réussi [`REVERT_AFTER`] après l'installation de `PSK_new`
//! > → retour à `PSK_old`.
//!
//! Deux minuteurs locaux et déterministes convergent vers le même état. Le pire
//! cas est un déni de service temporaire, jamais une brique ni une fuite.
//!
//! Le temps est **injecté** (`now`) plutôt que lu de l'horloge : la logique est
//! ainsi entièrement déterministe et testable sans attendre trois minutes.

use std::time::Duration;

use aether::enroll::Psk;

/// Délai au-delà duquel un PSK non confirmé est abandonné.
///
/// 180 s = `REJECT_AFTER_TIME` de WireGuard : passé ce délai, si aucun handshake
/// n'a réussi, c'est que le nouveau PSK n'est pas partagé par le pair.
pub const REVERT_AFTER: Duration = Duration::from_secs(180);

/// État de la rotation pour un pair donné.
#[derive(Debug, Default)]
pub enum RotationState {
    /// Aucun PSK installé (tunnel classique seul, pas encore upgradé PQ).
    #[default]
    None,
    /// Un PSK confirmé par au moins un handshake réussi.
    Stable { psk: Psk },
    /// Un nouveau PSK installé, en attente de confirmation.
    Pending {
        new_psk: Psk,
        /// Conservé pour pouvoir revenir en arrière. `None` si on partait de rien.
        previous: Option<Psk>,
        /// Âge de l'installation, alimenté par l'appelant.
        installed_since: Duration,
    },
}

/// Ce que l'appelant doit appliquer au plan de données après une transition.
#[derive(Debug, PartialEq, Eq)]
pub enum RotationAction {
    /// Rien à faire.
    Nothing,
    /// Installer ce PSK sur le pair (base64), ou le retirer si `None`.
    InstallPsk(Option<String>),
}

impl RotationState {
    /// PSK actuellement en vigueur, s'il y en a un.
    pub fn active(&self) -> Option<&Psk> {
        match self {
            RotationState::None => None,
            RotationState::Stable { psk } => Some(psk),
            // En attente, c'est bien le nouveau qui est posé sur le pair.
            RotationState::Pending { new_psk, .. } => Some(new_psk),
        }
    }

    /// Une rotation est-elle en cours d'attente de confirmation ?
    pub fn is_pending(&self) -> bool {
        matches!(self, RotationState::Pending { .. })
    }

    /// Installe un nouveau PSK issu d'un provisioning.
    ///
    /// L'ancien est conservé : tant que le nouveau n'est pas confirmé par un
    /// handshake, on doit pouvoir y revenir.
    pub fn install(&mut self, new_psk: Psk) -> RotationAction {
        let previous = match std::mem::replace(self, RotationState::None) {
            RotationState::None => None,
            RotationState::Stable { psk } => Some(psk),
            // Rotation pendant une rotation : on garde l'ancien *confirmé*,
            // pas l'intermédiaire jamais validé — sinon un revert nous
            // ramènerait à un PSK dont on ne sait pas s'il fonctionne.
            RotationState::Pending { previous, .. } => previous,
        };

        let action = RotationAction::InstallPsk(Some(aether::enroll::psk_to_base64(&new_psk)));
        *self = RotationState::Pending {
            new_psk,
            previous,
            installed_since: Duration::ZERO,
        };
        action
    }

    /// Un handshake a réussi : le PSK en vigueur est confirmé.
    ///
    /// **Idempotent.** Le poller signale un handshake frais à chaque tour : cette
    /// méthode ne doit toucher à l'état que s'il y a effectivement une rotation
    /// à confirmer. Prendre l'état inconditionnellement (`mem::replace`) ferait
    /// perdre le PSK dès le deuxième appel.
    pub fn on_handshake_success(&mut self) -> RotationAction {
        if !self.is_pending() {
            return RotationAction::Nothing;
        }
        if let RotationState::Pending { new_psk, .. } = std::mem::replace(self, RotationState::None)
        {
            *self = RotationState::Stable { psk: new_psk };
        }
        RotationAction::Nothing
    }

    /// Fait avancer le temps. À appeler depuis la boucle de polling.
    ///
    /// Renvoie l'action à appliquer : un revert si le délai est dépassé.
    pub fn tick(&mut self, elapsed: Duration) -> RotationAction {
        let RotationState::Pending {
            previous,
            installed_since,
            ..
        } = self
        else {
            return RotationAction::Nothing;
        };

        *installed_since += elapsed;
        if *installed_since < REVERT_AFTER {
            return RotationAction::Nothing;
        }

        // Délai dépassé sans handshake : le pair n'a manifestement pas le même
        // PSK. On revient à l'état antérieur, qui lui fonctionnait.
        let previous = previous.take();
        let action =
            RotationAction::InstallPsk(previous.as_ref().map(aether::enroll::psk_to_base64));
        *self = match previous {
            Some(psk) => RotationState::Stable { psk },
            None => RotationState::None,
        };
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn psk(b: u8) -> Psk {
        Zeroizing::new([b; 32])
    }

    #[test]
    fn installation_puis_confirmation() {
        let mut st = RotationState::default();
        assert!(st.active().is_none());

        let action = st.install(psk(1));
        assert!(matches!(action, RotationAction::InstallPsk(Some(_))));
        assert!(st.is_pending());
        assert_eq!(**st.active().unwrap(), [1u8; 32]);

        st.on_handshake_success();
        assert!(!st.is_pending(), "un handshake réussi confirme le PSK");
        assert_eq!(**st.active().unwrap(), [1u8; 32]);
    }

    /// Le cœur de la parade anti-brique : sans confirmation, on revient seul à
    /// l'état antérieur, sans avoir eu besoin de parler au pair.
    #[test]
    fn revert_automatique_sans_handshake() {
        let mut st = RotationState::default();
        st.install(psk(1));
        st.on_handshake_success(); // PSK 1 confirmé

        st.install(psk(2)); // rotation vers PSK 2
        assert_eq!(**st.active().unwrap(), [2u8; 32]);

        // Avant le délai : on patiente, rien ne bouge.
        assert_eq!(st.tick(Duration::from_secs(179)), RotationAction::Nothing);
        assert!(st.is_pending());

        // Délai franchi sans handshake : retour au PSK qui fonctionnait.
        let action = st.tick(Duration::from_secs(2));
        assert!(matches!(action, RotationAction::InstallPsk(Some(_))));
        assert_eq!(**st.active().unwrap(), [1u8; 32], "retour au PSK confirmé");
        assert!(!st.is_pending());
    }

    #[test]
    fn confirmation_juste_avant_le_delai_annule_le_revert() {
        let mut st = RotationState::default();
        st.install(psk(1));
        st.on_handshake_success();
        st.install(psk(2));

        st.tick(Duration::from_secs(179));
        st.on_handshake_success(); // le pair a bien le PSK 2

        // Le temps continue de passer : plus aucun revert ne doit survenir.
        assert_eq!(st.tick(Duration::from_secs(600)), RotationAction::Nothing);
        assert_eq!(**st.active().unwrap(), [2u8; 32]);
    }

    /// Premier PSK jamais confirmé : le revert doit retirer le PSK et revenir
    /// au tunnel classique, pas installer un PSK inexistant.
    #[test]
    fn revert_depuis_rien_retire_le_psk() {
        let mut st = RotationState::default();
        st.install(psk(1));
        let action = st.tick(REVERT_AFTER);
        assert_eq!(
            action,
            RotationAction::InstallPsk(None),
            "sans PSK antérieur, on retire le PSK et le tunnel reste classique"
        );
        assert!(st.active().is_none());
    }

    /// Une rotation qui en écrase une autre ne doit pas prendre comme filet un
    /// PSK jamais validé : on garde le dernier PSK *confirmé*.
    #[test]
    fn rotation_pendant_rotation_garde_le_dernier_psk_confirme() {
        let mut st = RotationState::default();
        st.install(psk(1));
        st.on_handshake_success(); // 1 confirmé

        st.install(psk(2)); // jamais confirmé
        st.install(psk(3)); // écrase 2

        st.tick(REVERT_AFTER);
        assert_eq!(
            **st.active().unwrap(),
            [1u8; 32],
            "le revert doit ramener au dernier PSK réellement validé"
        );
    }

    /// Le poller signale un handshake frais à CHAQUE tour (toutes les 10 s) :
    /// confirmer un PSK déjà confirmé ne doit surtout pas le perdre.
    #[test]
    fn confirmations_repetees_sont_idempotentes() {
        let mut st = RotationState::default();
        st.install(psk(1));
        st.on_handshake_success();
        assert_eq!(**st.active().unwrap(), [1u8; 32]);

        for _ in 0..5 {
            st.on_handshake_success();
            assert_eq!(
                **st.active()
                    .expect("le PSK confirmé ne doit jamais disparaître"),
                [1u8; 32]
            );
        }
    }

    #[test]
    fn tick_sans_rotation_en_cours_ne_fait_rien() {
        let mut st = RotationState::default();
        assert_eq!(st.tick(Duration::from_secs(999)), RotationAction::Nothing);

        st.install(psk(1));
        st.on_handshake_success();
        assert_eq!(st.tick(Duration::from_secs(999)), RotationAction::Nothing);
    }
}
