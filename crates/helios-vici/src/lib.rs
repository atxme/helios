//! Client natif du protocole **VICI** de strongSwan (Versatile IKE Control
//! Interface), implémenté sans dépendance C.
//!
//! VICI est le canal par lequel le plan de contrôle pilote charon : charger des
//! connexions, lancer une négociation (`initiate`), s'abonner aux événements de
//! cycle de vie des SA. charon écoute sur un socket Unix ; chaque échange est un
//! paquet préfixé d'une longueur sur 4 octets (big-endian).
//!
//! Le module [`codec`] implémente la (dé)sérialisation des messages VICI et est
//! couvert par des tests de round-trip — il se valide donc entièrement sur WSL2,
//! sans charon en cours d'exécution.

pub mod client;
pub mod codec;
pub mod message;

pub use client::{PacketType, ViciClient};
pub use message::{Element, Message};
