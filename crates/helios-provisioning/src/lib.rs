//! Enrôlement des clients Orion côté gateway Helios (ADR-001, §4).
//!
//! WireGuard ne fournit ni authentification riche (X.509/EAP) ni adressage
//! dynamique intégré : ce crate fournit explicitement ce que WireGuard ne donne
//! pas gratuitement. Il tourne **sur la gateway** — son client est Orion, mais le
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
//!   dans `peers`, via [`admission`]. Sa VIP en est dérivée déterministement
//!   par [`ipam`], sans état sur disque.
//! * **Provisioning** ([`session`]) — une fois le tunnel classique monté, le
//!   canal de contrôle *dans* le tunnel automatise l'échange ML-KEM, la
//!   dérivation du PSK post-quantique et la confirmation de la VIP.
//!
//! Les messages du protocole et la dérivation du PSK vivent dans
//! [`aether::enroll`], puisque le client doit les partager.
//!
//! # Transport : pas de TLS, et c'est délibéré
//!
//! L'ADR-001 envisageait un canal TLS 1.3 dédié, ancré TPM. Il a été **écarté à
//! l'implémentation** : le canal vit de toute façon *à l'intérieur* du tunnel
//! WireGuard, qui fournit déjà la confidentialité et l'authentification
//! mutuelle. Le raisonnement complet est en tête de `helios-api::provision` et
//! de `orion_core::provisioning`. Le transport réel est donc `POST
//! /api/provision` sur le serveur HTTP existant, lui aussi derrière le tunnel.
//!
//! L'intention TPM reste valable mais vise un autre secret : `wg_private_key`,
//! l'identité réelle de la gateway, aujourd'hui en clair dans `network.toml`.
//!
//! # Pose du PSK : l'ordre est un invariant de sûreté
//!
//! Le PSK dérivé est installé sur le plan de données **avant** d'être annoncé
//! au client. WireGuard n'a qu'un seul slot PSK par pair : une valeur présente
//! d'un seul côté fait échouer *tous* les handshakes suivants, et le canal de
//! contrôle qui permettrait de se rattraper vit précisément dans le tunnel qui
//! vient de mourir.
//!
//! La chaîne est donc fail-closed de bout en bout : `helios-api::provision`
//! transmet le PSK à l'orchestrateur via [`aether::InstallPskRequest`] et
//! attend son acquittement ; l'orchestrateur ne l'acquitte qu'après un
//! `sync_peers` réussi, et annule sa modification en mémoire sinon. Un échec
//! quelconque se traduit par une requête refusée, laissant le tunnel classique
//! intact plutôt que de créer un PSK orphelin.
//!
//! Côté client, `orion_core::backend` n'installe le PSK qu'une fois cette
//! réponse reçue, par un `up()` idempotent qui ne démonte jamais l'adaptateur.
//!
//! # Limite connue : la VIP dérivée n'est pas réconciliée
//!
//! [`ipam::assign_vip`] dérive la VIP de la clé publique du pair et ne consulte
//! jamais l'adresse déclarée dans `network.toml`. Les deux peuvent diverger.
//! Aucun des deux bouts ne tranche : la gateway conserve l'adresse déclarée par
//! l'opérateur, le client conserve celle de son profil, et l'écart est
//! journalisé de part et d'autre. Réconcilier demande de décider qui fait
//! autorité — l'opérateur ou la dérivation — ce qui déborde du provisioning.
//!
//! [`admission::admit`] **réduit** cet écart sans le supprimer : elle déclare
//! précisément l'adresse que l'IPAM dérive, si bien qu'un pair admis par cette
//! voie ne diverge pas. Restent les entrées écrites à la main dans
//! `network.toml`, pour lesquelles la limite ci-dessus tient toujours.

pub mod admission;
pub mod ipam;
pub mod rotation;
pub mod session;

pub use admission::{admit, revoke, AdmissionError};
pub use ipam::{assign_vip, derive_cgnat_ip, IpamError, PeerTable, MAX_VIP_PROBES, POOL_SIZE};
pub use rotation::{RotationAction, RotationState, REVERT_AFTER};
pub use session::{
    handle_request, AdmittedPeers, GatewayIdentity, Provisioned, DEFAULT_PSK_LIFETIME_SECS,
};
