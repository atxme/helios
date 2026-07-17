//! Enrôlement des clients Orion côté gateway Helios (ADR-001, §4).
//!
//! WireGuard ne fournit ni authentification riche (X.509/EAP) ni adressage
//! dynamique (Config Payload) : ce crate reconstruit ce qu'IKEv2 donnait
//! gratuitement. Il tourne **sur la gateway** — son client est Orion, mais le
//! service est ici. Les primitives partagées par les deux bouts (l'échange
//! ML-KEM) vivent dans [`aether::pq`], pas ici, pour qu'`orion-core` n'ait
//! jamais à dépendre d'un crate `helios-*`.
//!
//! État d'avancement (A2) : l'IPAM CGNAT déterministe est en place et testé.
//! Le protocole d'enrôlement (canal TLS ancré TPM, échange des clés publiques,
//! rotation du PSK) sera ajouté quand son format sera figé — on ne code pas des
//! types de protocole avant qu'il soit conçu.

pub mod ipam;

pub use ipam::{assign_vip, derive_cgnat_ip, IpamError, PeerTable, POOL_SIZE};
