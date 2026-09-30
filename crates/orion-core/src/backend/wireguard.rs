//! Real WireGuard backend, via `defguard_wireguard_rs`.
//!
//! Compiled behind the `wireguard` feature. It **compiles** everywhere, but can
//! only be *exercised* on a machine with a WireGuard data plane — same status
//! as the `netlink` feature on the heliosd side. On WSL2, it compiles and
//! fails at runtime (no `wireguard` kernel module).
//!
//! # Implementation chosen per platform
//!
//! `defguard_wireguard_rs` exposes two implementations, and **not all
//! platforms get to choose**:
//!
//! | Platform | Implementation | Data plane |
//! |---|---|---|
//! | Linux   | `WGApi<Kernel>`    | `wireguard` kernel module (netlink) |
//! | Windows | `WGApi<Kernel>`    | `wireguard-nt` kernel driver |
//! | macOS   | `WGApi<Userspace>` | embedded BoringTun (`defguard_boringtun`) |
//!
//! ⚠️ **Deliberate deviation from ADR-001 §1**, which planned "BoringTun
//! (userspace) + Wintun" on Windows: defguard's `wgapi_userspace` module is
//! `#[cfg(unix)]`, hence **unavailable on Windows**. This crate only offers
//! the kernel path there. See the ADR's caution note: since Wintun is itself
//! an NDIS kernel driver, the "100% user-space" goal wasn't achievable anyway
//! — we're replacing one kernel component with another.
//!
//! # The lifecycle invariant
//!
//! This backend applies the rule from [`super`]: the interface is created
//! **before** any fallible operation, and **never removed on an error path**.
//! Only [`WireGuardBackend::down`] removes it. Removing this property would
//! reopen the clear-text leak described in ADR-001 §3 bis.

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aether::TunnelState;
use async_trait::async_trait;
use defguard_wireguard_rs::{
    key::Key, net::IpAddrMask, peer::Peer, InterfaceConfiguration, WGApi, WireguardInterfaceApi,
};

use crate::config::ClientProfile;
use crate::events::ClientEvent;

use super::{EventSink, VpnBackend};

/// `defguard` implementation chosen for the current platform (see table
/// at the top of the module).
#[cfg(any(target_os = "linux", target_os = "windows"))]
type WgApiImpl = WGApi<defguard_wireguard_rs::Kernel>;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
type WgApiImpl = WGApi<defguard_wireguard_rs::Userspace>;

/// Name of the WireGuard interface created by Orion.
///
/// Defined in `net_pin` because the key-negotiation socket must name the
/// interface it has to avoid even on a build carrying no WireGuard backend —
/// the negotiation is not a compile-time feature.
use crate::net_pin::TUNNEL_IFNAME as DEFAULT_IFNAME;

/// Local listen port. `0` = ephemeral port chosen by the OS, which is the
/// expected behavior of a road-warrior client (it initiates, it doesn't listen).
const CLIENT_LISTEN_PORT: u16 = 0;

pub struct WireGuardBackend {
    ifname: String,
    /// The `defguard` API is **synchronous** and `create_interface` requires
    /// `&mut`. Hence the `Mutex`: it provides mutable access behind the
    /// trait's `&self`. No `await` is held while the lock is taken.
    api: Mutex<WgApiImpl>,
    /// Reflects whether the interface exists. Used to check the invariant.
    adapter_up: AtomicBool,
    /// Peer's public key, to find its stats in `read_interface_data`.
    peer_key: Mutex<Option<Key>>,
}

impl WireGuardBackend {
    /// Builds the backend for the `orion0` interface.
    pub fn new() -> anyhow::Result<Self> {
        Self::with_ifname(DEFAULT_IFNAME)
    }

    pub fn with_ifname(ifname: &str) -> anyhow::Result<Self> {
        let api = WgApiImpl::new(ifname.to_string())
            .map_err(|e| anyhow::anyhow!("WireGuard API initialization: {e}"))?;
        Ok(Self {
            ifname: ifname.to_string(),
            api: Mutex::new(api),
            adapter_up: AtomicBool::new(false),
            peer_key: Mutex::new(None),
        })
    }

    /// Access to the `defguard` API, poisoning included.
    ///
    /// A panic inside `wireguard-nt` — the crate asserts on some driver
    /// answers — poisons this mutex. `unwrap()` then turned that single
    /// failure into a client that panics on **every** subsequent call:
    /// impossible to disconnect, impossible to reconnect, and above all
    /// impossible to unmount the adapter. The lock protects a handle, not an
    /// invariant that a panic could have broken halfway; taking it back is
    /// strictly better than dying with it.
    fn api(&self) -> anyhow::Result<std::sync::MutexGuard<'_, WgApiImpl>> {
        Ok(self
            .api
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// Same reasoning for the peer key: an `Option<Key>`, nothing to corrupt.
    fn peer_key(&self) -> std::sync::MutexGuard<'_, Option<Key>> {
        self.peer_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Translates the profile into a `defguard` WireGuard peer.
    fn build_peer(profile: &ClientProfile) -> anyhow::Result<Peer> {
        let public_key = Key::try_from(profile.peer_public_key.as_str())
            .map_err(|e| anyhow::anyhow!("clé publique du pair invalide : {e}"))?;

        let mut peer = Peer::new(public_key);

        peer.set_endpoint(&profile.endpoint)
            .map_err(|e| anyhow::anyhow!("endpoint `{}` invalide : {e}", profile.endpoint))?;

        // Several prefixes, because `AllowedIPs` is the cryptographic routing
        // table and a split tunnel rarely reaches everything it needs through
        // one entry. Each is parsed on its own and named on failure: a list
        // refused as a whole says nothing about which entry to fix.
        let entries = crate::profile_import::split_cidr_list(&profile.allowed_ips);
        if entries.is_empty() {
            anyhow::bail!("allowed_ips est vide : aucun trafic ne serait capté par le tunnel");
        }
        let allowed = entries
            .iter()
            .map(|entry| {
                IpAddrMask::from_str(entry)
                    .map_err(|e| anyhow::anyhow!("allowed_ips : préfixe `{entry}` invalide : {e}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        peer.set_allowed_ips(allowed);

        peer.persistent_keepalive_interval = Some(profile.persistent_keepalive);

        // The `PresharedKey` slot, regardless of the secret's origin: static
        // on first mount, PQC on the remount performed by the ML-KEM upgrade.
        // Empty = Curve25519 only.
        if let Some(psk) = profile
            .preshared_key
            .as_deref()
            .filter(|k| !k.trim().is_empty())
        {
            let psk = Key::try_from(psk).map_err(|e| anyhow::anyhow!("PSK invalide : {e}"))?;
            peer.preshared_key = Some(psk);
        }

        Ok(peer)
    }
}

#[async_trait]
impl VpnBackend for WireGuardBackend {
    async fn up(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()> {
        // 1. Everything that can fail without a side effect is done BEFORE
        //    creating the interface: profile, keys, endpoint, address.
        //
        //    `validate_for_data_plane` and not `validate`: the second accepts
        //    an ML-KEM profile with an empty PSK slot, because that is its
        //    state at rest. Mounting in that state would establish the tunnel
        //    on the static key pair alone — WireGuard would handshake, the
        //    state would go `Up`, and the post-quantum protection the profile
        //    announces would simply not be there.
        profile.validate_for_data_plane()?;

        let address = profile
            .address
            .as_deref()
            .filter(|a| !a.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("adresse virtuelle absente du profil (enrôlement non effectué ?)")
            })?;
        let address = IpAddrMask::from_str(address)
            .map_err(|e| anyhow::anyhow!("adresse `{address}` invalide : {e}"))?;

        // Validates the private key format NOW. `defguard` expects it
        // encoded in `InterfaceConfiguration::prvkey` and would only reject
        // it after the interface is created — too late to fail cleanly.
        Key::try_from(profile.private_key.as_str())
            .map_err(|e| anyhow::anyhow!("clé privée du client invalide : {e}"))?;

        let peer = Self::build_peer(profile)?;
        *self.peer_key() = Some(peer.public_key.clone());

        let config = InterfaceConfiguration {
            name: self.ifname.clone(),
            prvkey: profile.private_key.clone(),
            addresses: vec![address],
            port: CLIENT_LISTEN_PORT as u32 as u16,
            peers: vec![peer.clone()],
            // WireGuard's default (1420) assumes a 1500 transport. Below
            // that threshold, encrypted packets exceed the link's MTU and
            // are silently dropped: the handshake and short requests get
            // through, only large ones disappear. A client interface only
            // carries one peer, so its MTU can hug the real path.
            mtu: crate::mtu::mtu_transport().map(aether::mtu::tunnel_mtu),
            fwmark: None,
        };

        sink(ClientEvent::state(TunnelState::Connecting));

        let mut api = self.api()?;

        // 2. Interface creation — **only if it does not exist yet**. `up()` is
        //    documented as idempotent, and the negotiation calls it again on
        //    each attempt: on Windows, recreating an adapter already opened by
        //    this process leaves `wireguard-nt` with a handle onto a device
        //    that no longer answers ("Failed to connect to adapter
        //    interface"), and its next configuration read panics inside the
        //    crate — taking the Tokio worker and our mutexes with it.
        //
        //    As soon as the interface exists, `AllowedIPs` captures traffic:
        //    WireGuard DROPS it as long as the session isn't established. From
        //    here on, no error path must remove it.
        if self.adapter_up.load(Ordering::SeqCst) {
            sink(ClientEvent::log(
                "info",
                format!("interface {} déjà montée — reconfiguration", self.ifname),
            ));
        } else {
            api.create_interface()
                .map_err(|e| anyhow::anyhow!("création de l'interface {} : {e}", self.ifname))?;
            self.adapter_up.store(true, Ordering::SeqCst);
            sink(ClientEvent::log(
                "info",
                format!(
                    "interface {} montée ({}) — les paquets hors tunnel sont bloqués",
                    self.ifname, profile.allowed_ips
                ),
            ));
        }

        // 3. Configuration. On failure we propagate the error WITHOUT
        //    unmounting: an interface that's mounted but misconfigured leaks
        //    nothing, an absent interface would (ADR-001 §3 bis).
        api.configure_interface(&config)
            .map_err(|e| anyhow::anyhow!("configuration de l'interface : {e}"))?;
        api.configure_peer_routing(&config.peers)
            .map_err(|e| anyhow::anyhow!("routage du pair : {e}"))?;

        // The backend sees a filled or empty slot, never where the secret
        // came from. It's `upgrade_to_post_quantum` that later names it
        // static PSK or PQC PSK; here, announcing "post-quantum" would be a
        // claim we have no way to back up.
        let pq = if profile.has_preshared_key() {
            "slot PresharedKey renseigné"
        } else {
            "slot PresharedKey vide (Curve25519 seul)"
        };
        sink(ClientEvent::log(
            "info",
            format!("pair configuré vers {} — {pq}", profile.endpoint),
        ));

        // We do NOT signal `Up` here: WireGuard is connectionless, state is
        // inferred from a recent handshake. It's `VpnController::poll_handshake`
        // that promotes `Connecting` → `Up` (ADR-001 §3).
        Ok(())
    }

    async fn down(&self, sink: &EventSink) -> anyhow::Result<()> {
        // Only path allowed to remove the interface.
        //
        // `mut` is required on Windows — `WireguardInterfaceApi::remove_interface`
        // takes `&mut self` there, versus `&self` elsewhere. Keeping it
        // unconditional avoids a per-platform `cfg`; hence the `allow` for
        // targets where it's superfluous.
        #[allow(unused_mut)]
        let mut api = self.api()?;
        let result = api.remove_interface();
        self.adapter_up.store(false, Ordering::SeqCst);
        *self.peer_key() = None;
        drop(api);

        sink(ClientEvent::log(
            "info",
            format!("interface {} démontée", self.ifname),
        ));
        sink(ClientEvent::state(TunnelState::Down));

        result.map_err(|e| anyhow::anyhow!("suppression de l'interface : {e}"))
    }

    async fn last_handshake_age(&self) -> Option<Duration> {
        let peer_key = self.peer_key().clone()?;
        let host = self.api().ok()?.read_interface_data().ok()?;
        let last = host.peers.get(&peer_key)?.last_handshake?;

        // WireGuard reports the epoch as long as no handshake has happened:
        // treat it as "never" rather than "55 years ago".
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
            // Valid Curve25519 keys in base64 (32 bytes).
            private_key: "aAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAA=".into(),
            peer_public_key: "bBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBA=".into(),
            address: Some("100.64.1.2/32".into()),
            ..ClientProfile::default()
        }
    }

    /// The profile → `defguard` peer translation must be faithful. Testable
    /// without any data plane: it's pure conversion.
    #[test]
    fn peer_construction_from_the_profile() {
        let p = profile();
        let peer = WireGuardBackend::build_peer(&p).unwrap();

        // Both families: `::/0` is what makes WireGuard drop IPv6 instead of
        // letting it leave through the physical interface.
        assert_eq!(peer.allowed_ips.len(), 2);
        assert_eq!(peer.allowed_ips[0].to_string(), "0.0.0.0/0");
        assert_eq!(peer.allowed_ips[1].to_string(), "::/0");
        assert_eq!(peer.persistent_keepalive_interval, Some(25));
        assert!(peer.endpoint.is_some());
        assert!(peer.preshared_key.is_none(), "no PSK in this profile");
    }

    #[test]
    fn the_post_quantum_psk_is_passed_to_the_peer() {
        let mut p = profile();
        p.preshared_key = Some("cCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCA=".into());
        let peer = WireGuardBackend::build_peer(&p).unwrap();
        assert!(
            peer.preshared_key.is_some(),
            "the ML-KEM PSK must reach WireGuard"
        );
    }

    #[test]
    fn invalid_peer_key_rejected() {
        let mut p = profile();
        p.peer_public_key = "not-valid-base64".into();
        assert!(WireGuardBackend::build_peer(&p).is_err());
    }

    #[test]
    fn invalid_endpoint_rejected() {
        let mut p = profile();
        p.endpoint = "not-an-endpoint".into();
        assert!(WireGuardBackend::build_peer(&p).is_err());
    }
}
