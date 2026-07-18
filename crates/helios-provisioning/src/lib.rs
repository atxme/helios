//! Enrôlement des clients Orion côté gateway Helios (ADR-001, §4).
//!
//! WireGuard ne fournit ni authentification riche (X.509/EAP) ni adressage
//! dynamique (Config Payload) : ce crate reconstruit ce qu'IKEv2 donnait
//! gratuitement. Il tourne **sur la gateway** — son client est Orion, mais le
//! service est ici. Les primitives partagées par les deux bouts (l'échange
//! ML-KEM) vivent dans [`aether::pq`], pas ici, pour qu'`orion-core` n'ait
//! jamais à dépendre d'un crate `helios-*`.
//!
//! # Enrôlement = admission + provisioning
//!
//! Les deux ne s'automatisent pas de la même façon, et confondre les deux mène
//! à un design impossible :
//!
//! * **Admission** (premier contact) — un client dont la clé publique est
//!   inconnue ne peut pas monter le tunnel : WireGuard est fondé sur Noise_IK,
//!   le répondeur rejette un initiateur qu'il ne connaît pas. L'admission est
//!   donc **nécessairement hors bande** : un opérateur déclare la clé publique
//!   (aujourd'hui : `peers` dans `network.toml`). Sa VIP en est dérivée
//!   déterministement par [`ipam`], sans état sur disque.
//! * **Provisioning** ([`session`]) — une fois le tunnel classique monté, le
//!   canal de contrôle *dans* le tunnel automatise l'échange ML-KEM, la
//!   dérivation du PSK post-quantique et la confirmation de la VIP.
//!
//! Les messages du protocole et la dérivation du PSK vivent dans
//! [`aether::enroll`], puisque le client doit les partager.
//!
//! État : le cœur protocolaire est écrit et testé de bout en bout (avec la
//! vraie crypto ML-KEM). Le **transport** — TLS 1.3 ancré TPM — et le câblage
//! dans `heliosd` restent à faire.

pub mod ipam;
pub mod rotation;
pub mod session;

pub use ipam::{assign_vip, derive_cgnat_ip, IpamError, PeerTable, POOL_SIZE};
pub use rotation::{RotationAction, RotationState, REVERT_AFTER};
pub use session::{
    handle_request, AdmittedPeers, GatewayIdentity, Provisioned, DEFAULT_PSK_LIFETIME_SECS,
};
