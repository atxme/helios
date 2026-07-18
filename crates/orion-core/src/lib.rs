//! Cœur logique du client VPN Helios.
//!
//! Ce crate ne dépend ni de Tauri ni de webkit : il compile et se teste partout,
//! y compris sur WSL2. Il porte trois choses :
//!
//! 1. [`config`] — le **profil VPN** éditable et persisté localement (endpoint de
//!    la gateway, identités, credentials, proposition IKE/ESP).
//! 2. [`backend`] — le `VpnBackend` qui **monte réellement le tunnel** via la pile
//!    IKEv2 native de l'OS. Seul `DryRunBackend` est compilé par défaut (testable
//!    WSL2) ; les backends réels sont derrière des features, comme `netlink`.
//! 3. [`telemetry`] — la consommation de l'API web de heliosd, qui n'est joignable
//!    qu'**après** montage du tunnel (le serveur web vit *derrière* l'IPsec).
//!
//! ## Invariant d'architecture (à ne jamais enfreindre)
//!
//! Un client IPsec se connecte à une gateway par son **endpoint IKE** (IP/FQDN),
//! pas par une URL HTTP. Le serveur web de heliosd n'est accessible qu'une fois le
//! tunnel établi — il ne sert donc **jamais** à faire monter la connexion, mais
//! uniquement à la télémétrie post-connexion. C'est pourquoi [`telemetry::run`]
//! n'est démarré que sur transition vers [`aether::TunnelState::Up`].

pub mod backend;
pub mod config;
pub mod events;
pub mod provisioning;
pub mod telemetry;

pub use backend::{default_backend, EventSink, VpnBackend, VpnController, HANDSHAKE_STALE_AFTER};
pub use config::{ClientConfig, ClientProfile, DEFAULT_ALLOWED_IPS, DEFAULT_KEEPALIVE_SECS};
pub use events::ClientEvent;
pub use provisioning::{provision, ProvisionError, ProvisionOutcome};
