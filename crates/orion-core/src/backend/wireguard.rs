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
//!
//! # What was asked is not what was applied
//!
//! The invariant protects what the adapter captures, and nothing more. On
//! Windows, `defguard_wireguard_rs` 0.11 checks which address families the
//! adapter carries and, for a missing one, **silently** skips its routes and
//! addresses (`wgapi_windows.rs`, after `set_config`). A profile asking for
//! `::/0` on an adapter without IPv6 then mounts without error, and IPv6 keeps
//! leaving through the physical interface while the tunnel looks complete.
//!
//! Hence the read-back after every configuration ([`assess_capture`]): the
//! driver's peer table, and on Windows the routes the adapter really carries —
//! the stripping happens *after* the driver received the full list, so the
//! driver alone would read back a capture that does not exist. Any gap is
//! reported as a [`CaptureCheck`], never retried or repaired behind the
//! user's back.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
use crate::events::{CaptureCheck, ClientEvent};

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

    /// Reads back what the adapter captures for `peer_key`, from every place
    /// that can drop a prefix on this platform.
    ///
    /// A peer absent from the driver's table reads as an empty list: then
    /// nothing requested is carried, and every prefix is reported missing.
    fn observe_capture(&self, api: &WgApiImpl, peer_key: &Key) -> Vec<CaptureObservation> {
        let driver = api
            .read_interface_data()
            .map(|host| {
                host.peers
                    .get(peer_key)
                    .map(|peer| peer.allowed_ips.clone())
                    .unwrap_or_default()
            })
            .map_err(|e| e.to_string());
        #[allow(unused_mut)]
        let mut observations = vec![CaptureObservation {
            source: "configuration du pilote",
            applied: driver,
        }];
        // The routes only on Windows: that is where `defguard` strips them.
        // On Linux, a full tunnel is routed through a dedicated table and
        // policy rules, so the main table would report a gap that is not one.
        #[cfg(windows)]
        observations.push(CaptureObservation {
            source: "routes de l'adaptateur",
            applied: routed_prefixes(&self.ifname),
        });
        observations
    }
}

/// The prefixes the routing table sends through the adapter named `ifname`.
#[cfg(windows)]
fn routed_prefixes(ifname: &str) -> Result<Vec<IpAddrMask>, String> {
    use crate::net_pin::windows_impl;

    let index = windows_impl::interface_index(ifname)
        .ok_or_else(|| format!("adaptateur {ifname} introuvable"))?;
    windows_impl::prefixes_routed_through(index)
        .map(|prefixes| {
            prefixes
                .into_iter()
                .map(|(address, cidr)| IpAddrMask::new(address, cidr))
                .collect()
        })
        .map_err(|e| format!("{e:#}"))
}

/// One read-back of the capture, and where it was read.
struct CaptureObservation {
    /// Named in the message when the read fails.
    source: &'static str,
    /// The prefixes found there, or why they could not be read.
    applied: Result<Vec<IpAddrMask>, String>,
}

/// A prefix with its host bits cleared.
///
/// `10.1.2.3/8` and `10.0.0.0/8` capture the same traffic, and a driver may
/// hand back either form: comparing them as written would report a gap that
/// does not exist, or hide one behind a spelling.
fn canonical_prefix(prefix: &IpAddrMask) -> IpAddrMask {
    let network = match prefix.address {
        IpAddr::V4(address) => {
            let host_bits = 32 - u32::from(prefix.cidr.min(32));
            let mask = u32::MAX.checked_shl(host_bits).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        IpAddr::V6(address) => {
            let host_bits = 128 - u32::from(prefix.cidr.min(128));
            let mask = u128::MAX.checked_shl(host_bits).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
    };
    IpAddrMask::new(network, prefix.cidr)
}

/// Requested prefixes absent from `applied`, canonical, in the requested
/// order and without repetition.
///
/// Exact membership, not coverage: a broader applied prefix does not stand
/// for a narrower requested one. The driver strips whole entries, never
/// rewrites them, so an entry that is not there verbatim is an entry it
/// dropped. Extra applied prefixes are not a gap and are ignored.
fn missing_allowed_ips(requested: &[IpAddrMask], applied: &[IpAddrMask]) -> Vec<IpAddrMask> {
    let applied: HashSet<IpAddrMask> = applied.iter().map(canonical_prefix).collect();
    let mut missing: Vec<IpAddrMask> = Vec::new();
    for prefix in requested.iter().map(canonical_prefix) {
        if !applied.contains(&prefix) && !missing.contains(&prefix) {
            missing.push(prefix);
        }
    }
    missing
}

/// Verdict on the capture, from every read-back available.
///
/// A prefix missing from **any** source is missing: a driver that holds
/// `::/0` with no route to it captures nothing. A known gap outranks an
/// unreadable source, because it is the worse fact and it is certain; only
/// when nothing is known to be missing does a failed read make the verdict
/// `Unverified` — never `Complete`.
fn assess_capture(requested: &[IpAddrMask], observations: &[CaptureObservation]) -> CaptureCheck {
    let mut missing: HashSet<IpAddrMask> = HashSet::new();
    let mut unread: Vec<String> = Vec::new();
    for observation in observations {
        match &observation.applied {
            Ok(applied) => missing.extend(missing_allowed_ips(requested, applied)),
            Err(reason) => unread.push(format!("{} : {reason}", observation.source)),
        }
    }
    if !missing.is_empty() {
        // Back in the profile's order: the set only served the union.
        let ordered = missing_allowed_ips(requested, &[])
            .into_iter()
            .filter(|prefix| missing.contains(prefix))
            .map(|prefix| prefix.to_string())
            .collect();
        return CaptureCheck::Incomplete { missing: ordered };
    }
    if !unread.is_empty() {
        return CaptureCheck::Unverified {
            reason: unread.join(" ; "),
        };
    }
    CaptureCheck::Complete
}

/// What the user is told about a capture verdict.
///
/// The verdict itself goes first, for the posture panel. A gap is then an
/// `Error`: it is the one fact the screen cannot be allowed to bury in the
/// log, since everything else about the tunnel looks healthy. An unreadable
/// capture is a warning: nothing is known to leak, but nothing is proven.
fn capture_events(check: &CaptureCheck) -> Vec<ClientEvent> {
    let notice = match check {
        CaptureCheck::Complete => {
            ClientEvent::log("info", "AllowedIPs appliqués vérifiés sur l'adaptateur")
        }
        CaptureCheck::Incomplete { missing } => ClientEvent::Error {
            message: format!(
                "AllowedIPs non appliqués par le pilote : {} — ce trafic n'est pas capté \
                 par le tunnel et peut sortir en clair par l'interface physique",
                missing.join(", ")
            ),
        },
        CaptureCheck::Unverified { reason } => ClientEvent::log(
            "warn",
            format!(
                "capture du tunnel non vérifiée ({reason}) — les AllowedIPs réellement \
                 appliqués sont inconnus"
            ),
        ),
    };
    vec![ClientEvent::capture(check.clone()), notice]
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

        // 4. Read back what was really applied (see the module header).
        //
        //    A gap returns `Ok`, with the verdict on the event stream, and
        //    that is a choice, not leniency:
        //    - the adapter stays mounted whatever happens (ADR-001 §3 bis),
        //      so an `Err` would not remove the leak — it would only move the
        //      state to `Failed` and, on a negotiated profile, abort the
        //      confirmation and lose the IPv4 capture that *is* in place;
        //    - reconfiguring again would hit the same missing family, and a
        //      silent retry is precisely what must not hide the gap.
        //    So the tunnel keeps what it carries, and the gap is stated where
        //    the user looks: an error on screen and an amber posture row.
        let capture = assess_capture(
            &peer.allowed_ips,
            &self.observe_capture(&api, &peer.public_key),
        );
        drop(api);
        for event in capture_events(&capture) {
            sink(event);
        }

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

    fn prefixes(list: &str) -> Vec<IpAddrMask> {
        crate::profile_import::split_cidr_list(list)
            .into_iter()
            .map(|entry| IpAddrMask::from_str(entry).unwrap())
            .collect()
    }

    fn named(missing: Vec<IpAddrMask>) -> Vec<String> {
        missing.iter().map(ToString::to_string).collect()
    }

    fn read(source: &'static str, list: &str) -> CaptureObservation {
        CaptureObservation {
            source,
            applied: Ok(prefixes(list)),
        }
    }

    #[test]
    fn identical_sets_miss_nothing() {
        let requested = prefixes("0.0.0.0/0, ::/0");
        assert!(missing_allowed_ips(&requested, &prefixes("0.0.0.0/0, ::/0")).is_empty());
    }

    #[test]
    fn a_stripped_ipv6_default_is_named() {
        // The `defguard` Windows case: the adapter carries no IPv6, and the
        // whole family disappears from what was applied.
        let missing = missing_allowed_ips(&prefixes("0.0.0.0/0, ::/0"), &prefixes("0.0.0.0/0"));
        assert_eq!(named(missing), ["::/0"]);
    }

    #[test]
    fn a_stripped_ipv4_family_is_named() {
        let missing =
            missing_allowed_ips(&prefixes("0.0.0.0/0, 10.8.0.0/16, ::/0"), &prefixes("::/0"));
        assert_eq!(named(missing), ["0.0.0.0/0", "10.8.0.0/16"]);
    }

    #[test]
    fn an_extra_applied_prefix_is_not_a_gap() {
        // Windows adds on-link and multicast routes on the adapter on its own;
        // they capture more, never less.
        let missing = missing_allowed_ips(
            &prefixes("0.0.0.0/0, ::/0"),
            &prefixes("ff00::/8, 0.0.0.0/0, 100.64.1.2/32, ::/0"),
        );
        assert!(missing.is_empty());
    }

    #[test]
    fn order_and_spelling_do_not_count() {
        // Reversed order, an expanded IPv6 zero, host bits on both families,
        // a repeated entry: the same capture written differently.
        let missing = missing_allowed_ips(
            &prefixes("10.1.2.3/8, 0:0:0:0::/0, fd00::1/64, 10.0.0.0/8"),
            &prefixes("fd00::/64, ::/0, 10.0.0.0/8"),
        );
        assert!(missing.is_empty(), "{missing:?}");
    }

    #[test]
    fn a_missing_prefix_is_reported_canonical_and_once() {
        let missing = missing_allowed_ips(&prefixes("10.1.2.3/8, 10.0.0.0/8"), &[]);
        assert_eq!(named(missing), ["10.0.0.0/8"]);
    }

    #[test]
    fn a_broader_applied_prefix_does_not_stand_for_a_requested_one() {
        // Exact membership: the driver drops entries, it never merges them.
        let missing = missing_allowed_ips(&prefixes("10.8.0.0/16"), &prefixes("10.0.0.0/8"));
        assert_eq!(named(missing), ["10.8.0.0/16"]);
    }

    #[test]
    fn the_profile_capture_checked_against_a_stripped_adapter() {
        // From the profile to the verdict, as `up()` chains them: the default
        // full tunnel, the driver holding both families, and Windows routing
        // only IPv4 — what `defguard` 0.11 leaves after its family check.
        let peer = WireGuardBackend::build_peer(&profile()).unwrap();
        let check = assess_capture(
            &peer.allowed_ips,
            &[
                read("configuration du pilote", "0.0.0.0/0, ::/0"),
                read("routes de l'adaptateur", "0.0.0.0/0, 100.64.1.2/32"),
            ],
        );
        assert_eq!(
            check,
            CaptureCheck::Incomplete {
                missing: vec!["::/0".into()]
            }
        );
    }

    #[test]
    fn a_complete_read_back_is_complete() {
        let check = assess_capture(
            &prefixes("0.0.0.0/0, ::/0"),
            &[
                read("configuration du pilote", "::/0, 0.0.0.0/0"),
                read("routes de l'adaptateur", "0.0.0.0/0, ::/0, ff00::/8"),
            ],
        );
        assert_eq!(check, CaptureCheck::Complete);
    }

    #[test]
    fn missing_prefixes_from_several_sources_are_merged_in_profile_order() {
        let check = assess_capture(
            &prefixes("0.0.0.0/0, 10.8.0.0/16, ::/0"),
            &[
                read("configuration du pilote", "0.0.0.0/0, 10.8.0.0/16"),
                read("routes de l'adaptateur", "0.0.0.0/0, ::/0"),
            ],
        );
        assert_eq!(
            check,
            CaptureCheck::Incomplete {
                missing: vec!["10.8.0.0/16".into(), "::/0".into()]
            }
        );
    }

    #[test]
    fn an_absent_peer_misses_everything() {
        // `observe_capture` reads an absent peer as an empty list.
        let check = assess_capture(
            &prefixes("0.0.0.0/0, ::/0"),
            &[read("configuration du pilote", "")],
        );
        assert_eq!(
            check,
            CaptureCheck::Incomplete {
                missing: vec!["0.0.0.0/0".into(), "::/0".into()]
            }
        );
    }

    #[test]
    fn an_unreadable_configuration_is_unverified_not_complete() {
        let check = assess_capture(
            &prefixes("0.0.0.0/0, ::/0"),
            &[CaptureObservation {
                source: "configuration du pilote",
                applied: Err("adaptateur introuvable".into()),
            }],
        );
        assert_eq!(
            check,
            CaptureCheck::Unverified {
                reason: "configuration du pilote : adaptateur introuvable".into()
            }
        );
    }

    #[test]
    fn a_known_gap_outranks_an_unreadable_source() {
        let check = assess_capture(
            &prefixes("0.0.0.0/0, ::/0"),
            &[
                CaptureObservation {
                    source: "configuration du pilote",
                    applied: Err("lecture impossible".into()),
                },
                read("routes de l'adaptateur", "0.0.0.0/0"),
            ],
        );
        assert_eq!(
            check,
            CaptureCheck::Incomplete {
                missing: vec!["::/0".into()]
            }
        );
    }

    #[test]
    fn a_gap_reaches_the_screen_as_an_error_naming_the_prefix() {
        let events = capture_events(&CaptureCheck::Incomplete {
            missing: vec!["::/0".into()],
        });
        assert!(matches!(
            &events[0],
            ClientEvent::Capture { capture: CaptureCheck::Incomplete { missing } }
                if missing == &["::/0".to_string()]
        ));
        match &events[1] {
            ClientEvent::Error { message } => {
                assert!(
                    message.starts_with("AllowedIPs non appliqués par le pilote : ::/0 —"),
                    "{message}"
                );
            }
            other => panic!("a gap must be an error, got {other:?}"),
        }
    }

    #[test]
    fn an_unverified_capture_is_a_warning() {
        let events = capture_events(&CaptureCheck::Unverified {
            reason: "configuration du pilote : lecture impossible".into(),
        });
        assert!(matches!(
            &events[0],
            ClientEvent::Capture {
                capture: CaptureCheck::Unverified { .. }
            }
        ));
        match &events[1] {
            ClientEvent::Log { level, message } => {
                assert_eq!(level, "warn");
                assert!(message.contains("non vérifiée"), "{message}");
                assert!(message.contains("lecture impossible"), "{message}");
            }
            other => panic!("an unverified capture must be a warning, got {other:?}"),
        }
    }

    #[test]
    fn a_complete_capture_raises_no_error() {
        let events = capture_events(&CaptureCheck::Complete);
        assert!(matches!(
            &events[0],
            ClientEvent::Capture {
                capture: CaptureCheck::Complete
            }
        ));
        assert!(events
            .iter()
            .all(|event| !matches!(event, ClientEvent::Error { .. })));
    }
}
