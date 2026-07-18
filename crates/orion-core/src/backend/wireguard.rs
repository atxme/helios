//! Backend WireGuard réel, via `defguard_wireguard_rs`.
//!
//! Compilé derrière la feature `wireguard`. Il **compile** partout, mais ne peut
//! être *exercé* que sur une machine disposant du plan de données WireGuard —
//! même statut que la feature `netlink` côté heliosd. Sur WSL2, il compile et
//! échoue à l'exécution (pas de module `wireguard` dans le noyau).
//!
//! # Implémentation choisie par plateforme
//!
//! `defguard_wireguard_rs` expose deux implémentations, et **toutes les
//! plateformes n'ont pas le choix** :
//!
//! | Plateforme | Implémentation | Plan de données |
//! |---|---|---|
//! | Linux   | `WGApi<Kernel>`    | module noyau `wireguard` (netlink) |
//! | Windows | `WGApi<Kernel>`    | pilote noyau `wireguard-nt` |
//! | macOS   | `WGApi<Userspace>` | BoringTun embarqué (`defguard_boringtun`) |
//!
//! ⚠️ **Écart assumé avec l'ADR-001 §1**, qui prévoyait « BoringTun (userspace) +
//! Wintun » sur Windows : le module `wgapi_userspace` de defguard est
//! `#[cfg(unix)]`, donc **indisponible sur Windows**. Ce crate n'y propose que le
//! chemin noyau. Voir la note de vigilance de l'ADR : Wintun étant lui-même un
//! pilote NDIS noyau, l'objectif « 100 % user-space » n'était de toute façon pas
//! atteignable — on remplace un composant noyau par un autre.
//!
//! # L'invariante de cycle de vie
//!
//! Ce backend applique la règle de [`super`] : l'interface est créée **avant**
//! toute opération faillible, et **jamais retirée sur un chemin d'erreur**. Seul
//! [`WireGuardBackend::down`] la supprime. Retirer cette propriété rouvrirait la
//! fuite en clair décrite en ADR-001 §3 bis.

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aether::TunnelState;
use async_trait::async_trait;
use defguard_wireguard_rs::{
    key::Key, net::IpAddrMask, peer::Peer, InterfaceConfiguration, WGApi,
    WireguardInterfaceApi,
};

use crate::config::ClientProfile;
use crate::events::ClientEvent;

use super::{EventSink, VpnBackend};

/// Implémentation `defguard` retenue pour la plateforme courante (voir tableau
/// en tête de module).
#[cfg(any(target_os = "linux", target_os = "windows"))]
type WgApiImpl = WGApi<defguard_wireguard_rs::Kernel>;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
type WgApiImpl = WGApi<defguard_wireguard_rs::Userspace>;

/// Nom de l'interface WireGuard créée par Orion.
const DEFAULT_IFNAME: &str = "orion0";

/// Port d'écoute local. `0` = port éphémère choisi par l'OS, ce qui est le
/// comportement attendu d'un client road-warrior (il initie, il n'écoute pas).
const CLIENT_LISTEN_PORT: u16 = 0;

pub struct WireGuardBackend {
    ifname: String,
    /// L'API `defguard` est **synchrone** et `create_interface` exige `&mut`.
    /// D'où le `Mutex` : il fournit l'accès mutable derrière le `&self` du trait.
    /// Aucun `await` n'est tenu pendant que le verrou est pris.
    api: Mutex<WgApiImpl>,
    /// Reflète l'existence de l'interface. Sert à vérifier l'invariante.
    adapter_up: AtomicBool,
    /// Clé publique du pair, pour retrouver ses stats dans `read_interface_data`.
    peer_key: Mutex<Option<Key>>,
}

impl WireGuardBackend {
    /// Construit le backend pour l'interface `orion0`.
    pub fn new() -> anyhow::Result<Self> {
        Self::with_ifname(DEFAULT_IFNAME)
    }

    pub fn with_ifname(ifname: &str) -> anyhow::Result<Self> {
        let api = WgApiImpl::new(ifname.to_string())
            .map_err(|e| anyhow::anyhow!("initialisation de l'API WireGuard : {e}"))?;
        Ok(Self {
            ifname: ifname.to_string(),
            api: Mutex::new(api),
            adapter_up: AtomicBool::new(false),
            peer_key: Mutex::new(None),
        })
    }

    /// Traduit le profil en pair WireGuard `defguard`.
    fn build_peer(profile: &ClientProfile) -> anyhow::Result<Peer> {
        let public_key = Key::try_from(profile.peer_public_key.as_str())
            .map_err(|e| anyhow::anyhow!("clé publique du pair invalide : {e}"))?;

        let mut peer = Peer::new(public_key);

        peer.set_endpoint(&profile.endpoint)
            .map_err(|e| anyhow::anyhow!("endpoint `{}` invalide : {e}", profile.endpoint))?;

        let allowed = IpAddrMask::from_str(&profile.allowed_ips).map_err(|e| {
            anyhow::anyhow!("allowed_ips `{}` invalide : {e}", profile.allowed_ips)
        })?;
        peer.set_allowed_ips(vec![allowed]);

        peer.persistent_keepalive_interval = Some(profile.persistent_keepalive);

        // PSK post-quantique (ML-KEM). Absent = tunnel classique seul.
        if let Some(psk) = profile.preshared_key.as_deref().filter(|k| !k.trim().is_empty()) {
            let psk = Key::try_from(psk)
                .map_err(|e| anyhow::anyhow!("PSK post-quantique invalide : {e}"))?;
            peer.preshared_key = Some(psk);
        }

        Ok(peer)
    }
}

#[async_trait]
impl VpnBackend for WireGuardBackend {
    async fn up(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()> {
        // 1. Tout ce qui peut échouer sans effet de bord se fait AVANT de créer
        //    l'interface : profil, clés, endpoint, adresse.
        profile.validate()?;

        let address = profile
            .address
            .as_deref()
            .filter(|a| !a.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("adresse virtuelle absente du profil (enrôlement non effectué ?)")
            })?;
        let address = IpAddrMask::from_str(address)
            .map_err(|e| anyhow::anyhow!("adresse `{address}` invalide : {e}"))?;

        // Valide le format de la clé privée MAINTENANT. `defguard` l'attend
        // encodée dans `InterfaceConfiguration::prvkey` et ne la rejetterait
        // qu'après création de l'interface — trop tard pour échouer proprement.
        Key::try_from(profile.private_key.as_str())
            .map_err(|e| anyhow::anyhow!("clé privée du client invalide : {e}"))?;

        let peer = Self::build_peer(profile)?;
        *self.peer_key.lock().unwrap() = Some(peer.public_key.clone());

        let config = InterfaceConfiguration {
            name: self.ifname.clone(),
            prvkey: profile.private_key.clone(),
            addresses: vec![address],
            port: CLIENT_LISTEN_PORT as u32 as u16,
            peers: vec![peer.clone()],
            mtu: None,
            fwmark: None,
        };

        sink(ClientEvent::state(TunnelState::Connecting));

        let mut api = self.api.lock().unwrap();

        // 2. Création de l'interface. Dès qu'elle réussit, `AllowedIPs` capture
        //    le trafic : WireGuard le JETTE tant que la session n'est pas
        //    établie. À partir d'ici, aucun chemin d'erreur ne doit la retirer.
        api.create_interface()
            .map_err(|e| anyhow::anyhow!("création de l'interface {} : {e}", self.ifname))?;
        self.adapter_up.store(true, Ordering::SeqCst);
        sink(ClientEvent::log(
            "info",
            format!(
                "interface {} montée ({}) — le trafic hors tunnel est jeté",
                self.ifname, profile.allowed_ips
            ),
        ));

        // 3. Configuration. En cas d'échec on remonte l'erreur SANS démonter :
        //    une interface montée mais mal configurée ne laisse rien fuir, une
        //    interface absente si (ADR-001 §3 bis).
        api.configure_interface(&config)
            .map_err(|e| anyhow::anyhow!("configuration de l'interface : {e}"))?;
        api.configure_peer_routing(&config.peers)
            .map_err(|e| anyhow::anyhow!("routage du pair : {e}"))?;

        let pq = if profile.is_post_quantum() {
            "PSK post-quantique actif"
        } else {
            "tunnel classique (PSK PQ absent)"
        };
        sink(ClientEvent::log(
            "info",
            format!("pair configuré vers {} — {pq}", profile.endpoint),
        ));

        // On ne signale PAS `Up` ici : WireGuard est sans connexion, l'état se
        // déduit d'un handshake frais. C'est `VpnController::poll_handshake` qui
        // promeut `Connecting` → `Up` (ADR-001 §3).
        Ok(())
    }

    async fn down(&self, sink: &EventSink) -> anyhow::Result<()> {
        // Seul chemin autorisé à retirer l'interface.
        //
        // `mut` est requis sur Windows — `WireguardInterfaceApi::remove_interface`
        // y prend `&mut self`, contre `&self` ailleurs. Le garder inconditionnel
        // évite un `cfg` par plateforme ; d'où l'`allow` pour les cibles où il
        // est superflu.
        #[allow(unused_mut)]
        let mut api = self.api.lock().unwrap();
        let result = api.remove_interface();
        self.adapter_up.store(false, Ordering::SeqCst);
        *self.peer_key.lock().unwrap() = None;
        drop(api);

        sink(ClientEvent::log(
            "info",
            format!("interface {} démontée", self.ifname),
        ));
        sink(ClientEvent::state(TunnelState::Down));

        result.map_err(|e| anyhow::anyhow!("suppression de l'interface : {e}"))
    }

    async fn last_handshake_age(&self) -> Option<Duration> {
        let peer_key = self.peer_key.lock().unwrap().clone()?;
        let host = self.api.lock().unwrap().read_interface_data().ok()?;
        let last = host.peers.get(&peer_key)?.last_handshake?;

        // WireGuard rapporte l'epoch tant qu'aucun handshake n'a eu lieu :
        // le traiter comme « jamais » plutôt que comme « il y a 55 ans ».
        if last == UNIX_EPOCH {
            return None;
        }
        SystemTime::now().duration_since(last).ok()
    }

    fn adapter_is_up(&self) -> bool {
        self.adapter_up.load(Ordering::SeqCst)
    }

    fn kind(&self) -> &'static str {
        if cfg!(target_os = "windows") {
            "wireguard-nt"
        } else if cfg!(target_os = "linux") {
            "wireguard-kernel"
        } else {
            "wireguard-userspace"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ClientProfile {
        ClientProfile {
            name: "test".into(),
            endpoint: "203.0.113.10:51820".into(),
            // Clés Curve25519 valides en base64 (32 octets).
            private_key: "aAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAA=".into(),
            peer_public_key: "bBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBA=".into(),
            address: Some("100.64.1.2/32".into()),
            ..ClientProfile::default()
        }
    }

    /// La traduction profil → pair `defguard` doit être fidèle. Testable sans
    /// aucun plan de données : c'est de la conversion pure.
    #[test]
    fn construction_du_pair_depuis_le_profil() {
        let p = profile();
        let peer = WireGuardBackend::build_peer(&p).unwrap();

        assert_eq!(peer.allowed_ips.len(), 1);
        assert_eq!(peer.allowed_ips[0].to_string(), "0.0.0.0/0");
        assert_eq!(peer.persistent_keepalive_interval, Some(25));
        assert!(peer.endpoint.is_some());
        assert!(peer.preshared_key.is_none(), "pas de PSK dans ce profil");
    }

    #[test]
    fn le_psk_post_quantique_est_transmis_au_pair() {
        let mut p = profile();
        p.preshared_key = Some("cCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCA=".into());
        let peer = WireGuardBackend::build_peer(&p).unwrap();
        assert!(peer.preshared_key.is_some(), "le PSK ML-KEM doit atteindre WireGuard");
    }

    #[test]
    fn cle_de_pair_invalide_rejetee() {
        let mut p = profile();
        p.peer_public_key = "pas-du-base64-valide".into();
        assert!(WireGuardBackend::build_peer(&p).is_err());
    }

    #[test]
    fn endpoint_invalide_rejete() {
        let mut p = profile();
        p.endpoint = "je-ne-suis-pas-un-endpoint".into();
        assert!(WireGuardBackend::build_peer(&p).is_err());
    }
}
