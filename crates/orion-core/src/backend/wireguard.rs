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
//! On Windows, `defguard`'s `remove_peer` and `configure_peer` are empty: a
//! PSK renewal replaces the peer through `wireguard-nt` directly
//! (`replace_peer_on_adapter`).
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
//! Windows, `defguard_wireguard_rs` 0.12 checks which address families the
//! adapter carries and, for a missing one, **silently** skips its routes and
//! addresses (`wgapi_windows.rs`, after `set_config`). A profile asking for
//! `::/0` on an adapter without IPv6 then mounts without error, and IPv6 keeps
//! leaving through the physical interface while the tunnel looks complete.
//!
//! Hence the read-back after every configuration (`assess_capture`): the
//! driver's peer table, and on Windows the routes the adapter really carries —
//! the stripping happens *after* the driver received the full list, so the
//! driver alone would read back a capture that does not exist. Any gap is
//! reported as a [`CaptureCheck`], never retried or repaired behind the
//! user's back.
//!
//! The same family check skips the **addresses** of a missing family: a
//! profile carrying an IPv6 address (`address_v6`, `ADRESSAGE-IPV6.md` §7.3)
//! on an adapter without IPv6 mounts with its IPv4 address alone. On Windows
//! the read-back therefore also lists the unicast addresses the adapter
//! carries, and an address of the profile that is not among them is part of
//! the same verdict. On Linux and with the userspace backend, `defguard`
//! assigns each address through netlink or `ifconfig` and returns a refusal
//! as an error: `up()` then fails by name, adapter left mounted, so there is
//! nothing silent to read back.
//!
//! The **routes** are another matter on Linux: since `defguard` 0.12, a route
//! the kernel refuses for an `AllowedIPs` entry is a log line in
//! `add_peer_routing`, and `configure_peer_routing` still returns `Ok`. The
//! read-back there also lists the kernel routes through the adapter, and
//! `linux_expected_routes` says which of the requested prefixes must be
//! among them.

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

        // A literal, set as such: `Peer::set_endpoint` would run its own
        // `getaddrinfo` and keep the first answer, which may be the other
        // family than the address the controller chose (and, for a
        // negotiated profile, than the one that negotiated).
        let endpoint = crate::endpoint_resolution::literal_endpoint(&profile.endpoint)
            .map_err(|e| anyhow::anyhow!("endpoint `{}` invalide : {e}", profile.endpoint))?;
        peer.endpoint = Some(endpoint);

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
            .as_ref()
            .map(aether::SecretString::expose)
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
            observed: Observed::AllowedIps,
            applied: driver,
        }];
        // The routes on Windows, where `defguard` strips them, and on Linux,
        // where it only logs the ones the kernel refused. Linux compares a
        // narrower list ([`linux_expected_routes`]): a full tunnel is routed
        // through a dedicated table and policy rules, so the main table alone
        // would report a gap that is not one.
        #[cfg(target_os = "linux")]
        observations.push(CaptureObservation {
            source: "routes du noyau",
            observed: Observed::KernelRoutes,
            applied: kernel_routed_prefixes(&self.ifname),
        });
        #[cfg(windows)]
        observations.push(CaptureObservation {
            source: "routes de l'adaptateur",
            observed: Observed::AllowedIps,
            applied: routed_prefixes(&self.ifname),
        });
        // The addresses for the same reason: Windows is where they are
        // skipped without an error (see the module header).
        #[cfg(windows)]
        observations.push(CaptureObservation {
            source: "adresses de l'adaptateur",
            observed: Observed::Addresses,
            applied: carried_addresses(&self.ifname),
        });
        observations
    }
}

/// Replaces the adapter's only peer, through `wireguard-nt` itself.
///
/// `defguard`'s Windows `remove_peer` and `configure_peer` only log (0.12.2
/// and 0.12.3): a renewal went through them, announced the peer
/// re-registered, and left the previous PSK in the driver — the gateway
/// waited 45 s for a handshake that could not come, then rolled back.
/// `configure_interface` is no substitute either: it resets the MTU, and
/// restoring it takes the adapter down, which a renewal must never do.
///
/// `set_config` always replaces the peers: the peer is recreated, its
/// session dropped, and its keep-alive starts the proving handshake. No
/// private key or listen port is passed, so the driver keeps its own.
#[cfg(windows)]
fn replace_peer_on_adapter(ifname: &str, peer: &Peer) -> anyhow::Result<()> {
    use ipnet::{IpNet, Ipv4Net, Ipv6Net};

    // The DLL `defguard` loads, by the same relative path: the shell makes
    // the current directory the one holding it before any backend exists.
    #[cfg(target_arch = "x86_64")]
    const DLL: &str = "resources-windows/binaries/wireguard-amd64.dll";
    #[cfg(target_arch = "aarch64")]
    const DLL: &str = "resources-windows/binaries/wireguard-arm64.dll";

    let endpoint = peer
        .endpoint
        .ok_or_else(|| anyhow::anyhow!("réinscription du pair : endpoint absent"))?;
    let allowed_ips = peer
        .allowed_ips
        .iter()
        .map(|ip| match ip.address {
            IpAddr::V4(address) => Ipv4Net::new(address, ip.cidr).map(IpNet::V4),
            IpAddr::V6(address) => Ipv6Net::new(address, ip.cidr).map(IpNet::V6),
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("réinscription du pair : AllowedIPs invalides ({e})"))?;
    // SAFETY: the library `defguard` already loaded into this process for
    // the same adapter; loading it again only takes another reference.
    let wireguard = unsafe { wireguard_nt::load_from_path(DLL) }
        .map_err(|e| anyhow::anyhow!("chargement de WireGuardNT ({DLL}) : {e}"))?;
    // Opened, not created: closing this handle leaves the adapter in place.
    let adapter = wireguard_nt::Adapter::open(&wireguard, ifname)
        .map_err(|e| anyhow::anyhow!("ouverture de l'adaptateur {ifname} : {e}"))?;
    adapter
        .set_config(&wireguard_nt::SetInterface {
            listen_port: None,
            public_key: None,
            private_key: None,
            peers: vec![wireguard_nt::SetPeer {
                public_key: Some(peer.public_key.as_array()),
                preshared_key: peer.preshared_key.as_ref().map(Key::as_array),
                keep_alive: peer.persistent_keepalive_interval,
                endpoint,
                allowed_ips,
            }],
        })
        .map_err(|e| anyhow::anyhow!("réinscription du pair : {e}"))
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

/// The unicast addresses the adapter named `ifname` carries.
#[cfg(windows)]
fn carried_addresses(ifname: &str) -> Result<Vec<IpAddrMask>, String> {
    use crate::net_pin::windows_impl;

    let index = windows_impl::interface_index(ifname)
        .ok_or_else(|| format!("adaptateur {ifname} introuvable"))?;
    windows_impl::unicast_addresses_on(index)
        .map(|addresses| {
            addresses
                .into_iter()
                .map(|(address, cidr)| IpAddrMask::new(address, cidr))
                .collect()
        })
        .map_err(|e| format!("{e:#}"))
}

/// Whether `defguard` treats `prefix` as a family's default route: an
/// unspecified address with a zero length, checked as it does.
fn is_default_route(prefix: &IpAddrMask) -> bool {
    prefix.address.is_unspecified() && prefix.cidr == 0
}

/// The requested prefixes a Linux read-back of the kernel routes must find.
///
/// Per family, as `defguard`'s `add_peer_routing` routes it: with a default
/// route requested, the family goes through a dedicated fwmark table and no
/// other prefix of that family gets a route; without one, each prefix is a
/// main-table route on the adapter.
///
/// What the read can see sets the rest. `/proc/net/route` lists the main table
/// only, so an IPv4 default is not observable there — and needs not be: its
/// setup failing is an error `configure_peer_routing` returns. An IPv6 default
/// failing is only a log line in `defguard`, and `/proc/net/ipv6_route` lists
/// every table, so that one is expected. The read proves a route exists, not
/// the policy rules that steer traffic to its table.
fn linux_expected_routes(requested: &[IpAddrMask]) -> Vec<IpAddrMask> {
    let default_v4 = requested
        .iter()
        .any(|prefix| prefix.address.is_ipv4() && is_default_route(prefix));
    let default_v6 = requested
        .iter()
        .any(|prefix| prefix.address.is_ipv6() && is_default_route(prefix));
    requested
        .iter()
        .filter(|prefix| match prefix.address {
            IpAddr::V4(_) => !default_v4,
            IpAddr::V6(_) => !default_v6 || is_default_route(prefix),
        })
        .cloned()
        .collect()
}

/// The prefixes the Linux kernel routes through the adapter named `ifname`.
#[cfg(target_os = "linux")]
fn kernel_routed_prefixes(ifname: &str) -> Result<Vec<IpAddrMask>, String> {
    let read = |path: &str| std::fs::read_to_string(path).map_err(|e| format!("{path} : {e}"));
    let mut routed = parse_proc_net_route(&read("/proc/net/route")?, ifname)?;
    routed.extend(parse_proc_net_ipv6_route(
        &read("/proc/net/ipv6_route")?,
        ifname,
    )?);
    Ok(routed)
}

/// The IPv4 main-table routes on `ifname`, from `/proc/net/route`.
///
/// Destination and mask are the kernel's big-endian words printed as native
/// integers, hence `to_ne_bytes`. A line that does not parse makes the whole
/// read fail: a skipped line could be the very route being checked.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_net_route(text: &str, ifname: &str) -> Result<Vec<IpAddrMask>, String> {
    let word = |field: &str| {
        u32::from_str_radix(field, 16)
            .map(|value| Ipv4Addr::from(value.to_ne_bytes()))
            .map_err(|e| format!("/proc/net/route : `{field}` illisible : {e}"))
    };
    let mut routed = Vec::new();
    for line in text.lines().skip(1).filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            return Err(format!("/proc/net/route : ligne inattendue `{line}`"));
        }
        if fields[0] != ifname {
            continue;
        }
        let mask = u32::from(word(fields[7])?);
        if mask.leading_ones() != mask.count_ones() {
            return Err(format!("/proc/net/route : masque non contigu `{line}`"));
        }
        let cidr = u8::try_from(mask.count_ones()).unwrap_or(u8::MAX);
        routed.push(IpAddrMask::new(IpAddr::V4(word(fields[1])?), cidr));
    }
    Ok(routed)
}

/// The IPv6 routes on `ifname`, every table, from `/proc/net/ipv6_route`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_net_ipv6_route(text: &str, ifname: &str) -> Result<Vec<IpAddrMask>, String> {
    let mut routed = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            return Err(format!("/proc/net/ipv6_route : ligne inattendue `{line}`"));
        }
        if fields[9] != ifname {
            continue;
        }
        let destination = u128::from_str_radix(fields[0], 16)
            .map_err(|e| format!("/proc/net/ipv6_route : `{}` illisible : {e}", fields[0]))?;
        let cidr = u8::from_str_radix(fields[1], 16)
            .ok()
            .filter(|cidr| *cidr <= 128)
            .ok_or_else(|| format!("/proc/net/ipv6_route : longueur `{}` illisible", fields[1]))?;
        routed.push(IpAddrMask::new(
            IpAddr::V6(Ipv6Addr::from(destination)),
            cidr,
        ));
    }
    Ok(routed)
}

/// The peers handed to `configure_peer_routing`.
///
/// On Linux, `defguard` 0.12 also routes each peer's endpoint through the
/// physical default gateway — or blackholes it when there is none — in the
/// main table, and nothing ever removes that route: it outlives `down()`, and
/// blackholed it keeps the gateway unreachable on the next network. Linux does
/// not need it: the full tunnel's own packets carry the fwmark that keeps them
/// on the main table, as with `wg-quick`. Without an endpoint, a peer gets
/// exactly the routing it had before 0.12. Elsewhere that route is what keeps
/// a userspace full tunnel from routing its own packets into itself.
fn routing_peers(peers: &[Peer]) -> Vec<Peer> {
    peers
        .iter()
        .cloned()
        .map(|mut peer| {
            if cfg!(target_os = "linux") {
                peer.endpoint = None;
            }
            peer
        })
        .collect()
}

/// What a read-back is compared with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Observed {
    /// The prefixes the adapter captures: compared with `AllowedIPs`.
    AllowedIps,
    /// The addresses the adapter carries: compared with the profile's
    /// addresses, host for host.
    ///
    /// Only Windows reads it back (see the module header), so elsewhere the
    /// variant is built by the tests alone.
    #[cfg_attr(not(windows), allow(dead_code))]
    Addresses,
    /// The Linux kernel routes through the adapter: compared with the part of
    /// `AllowedIPs` that [`linux_expected_routes`] says must be routed there.
    ///
    /// Only Linux reads it back, so elsewhere the variant is built by the
    /// tests alone.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    KernelRoutes,
}

/// One read-back of the capture, and where it was read.
struct CaptureObservation {
    /// Named in the message when the read fails.
    source: &'static str,
    /// Which requested list this read-back answers.
    observed: Observed,
    /// The prefixes found there, or why they could not be read.
    applied: Result<Vec<IpAddrMask>, String>,
}

/// What `up()` asked the driver for: the peer's `AllowedIPs` and the
/// adapter's addresses.
struct RequestedCapture<'a> {
    allowed_ips: &'a [IpAddrMask],
    addresses: &'a [IpAddrMask],
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

/// Requested addresses the adapter does not carry, in the requested order.
///
/// Compared host for host: Windows reports an address with the on-link
/// prefix length it chose, which says nothing about whether the address is
/// there. An address read back in another spelling is the same address.
fn missing_addresses(requested: &[IpAddrMask], carried: &[IpAddrMask]) -> Vec<IpAddrMask> {
    let carried: HashSet<IpAddr> = carried.iter().map(|address| address.address).collect();
    let mut missing: Vec<IpAddrMask> = Vec::new();
    for address in requested {
        if !carried.contains(&address.address) && !missing.contains(address) {
            missing.push(address.clone());
        }
    }
    missing
}

/// The profile's addresses, as the adapter is given them: the virtual address,
/// then the IPv6 address when the profile has one (`ADRESSAGE-IPV6.md` §7.3).
///
/// Validated here, before the interface exists, like everything else that can
/// fail without a side effect. A profile without `address_v6` yields exactly
/// the one address it always did.
fn adapter_addresses(profile: &ClientProfile) -> anyhow::Result<Vec<IpAddrMask>> {
    let address = profile
        .address
        .as_deref()
        .filter(|a| !a.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("adresse virtuelle absente du profil (enrôlement non effectué ?)")
        })?;
    let address = IpAddrMask::from_str(address)
        .map_err(|e| anyhow::anyhow!("adresse `{address}` invalide : {e}"))?;
    let mut addresses = vec![address];
    if let Some(address_v6) = profile
        .address_v6
        .as_deref()
        .filter(|a| !a.trim().is_empty())
    {
        // The import rule, not a looser parse: a profile reaching the data
        // plane carries the `/128` host the gateway assigned, or nothing.
        crate::profile_import::validate_address_v6(address_v6)?;
        let host = aether::net::parse_vip_v6(address_v6.trim())
            .map_err(|e| anyhow::anyhow!("adresse IPv6 `{address_v6}` invalide : {e}"))?;
        addresses.push(IpAddrMask::new(IpAddr::V6(host), 128));
    }
    Ok(addresses)
}

/// Verdict on the capture, from every read-back available.
///
/// A prefix missing from **any** source is missing: a driver that holds
/// `::/0` with no route to it captures nothing. A known gap outranks an
/// unreadable source, because it is the worse fact and it is certain; only
/// when nothing is known to be missing does a failed read make the verdict
/// `Unverified` — never `Complete`.
///
/// An address the adapter does not carry is part of the same verdict: it is
/// as much a fact about what was applied as a stripped prefix, and as silent
/// on Windows.
fn assess_capture(
    requested: &RequestedCapture<'_>,
    observations: &[CaptureObservation],
) -> CaptureCheck {
    let mut missing: HashSet<IpAddrMask> = HashSet::new();
    let mut absent: HashSet<IpAddrMask> = HashSet::new();
    let mut unread: Vec<String> = Vec::new();
    for observation in observations {
        match (&observation.applied, observation.observed) {
            (Ok(applied), Observed::AllowedIps) => {
                missing.extend(missing_allowed_ips(requested.allowed_ips, applied));
            }
            (Ok(carried), Observed::Addresses) => {
                absent.extend(missing_addresses(requested.addresses, carried));
            }
            (Ok(routed), Observed::KernelRoutes) => {
                let expected = linux_expected_routes(requested.allowed_ips);
                missing.extend(missing_allowed_ips(&expected, routed));
            }
            (Err(reason), _) => unread.push(format!("{} : {reason}", observation.source)),
        }
    }
    if !missing.is_empty() || !absent.is_empty() {
        // Back in the profile's order: the sets only served the union.
        let missing = missing_allowed_ips(requested.allowed_ips, &[])
            .into_iter()
            .filter(|prefix| missing.contains(prefix))
            .map(|prefix| prefix.to_string())
            .collect();
        let missing_addresses = missing_addresses(requested.addresses, &[])
            .into_iter()
            .filter(|address| absent.contains(address))
            .map(|address| address.to_string())
            .collect();
        return CaptureCheck::Incomplete {
            missing,
            missing_addresses,
        };
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
///
/// A missing address is a warning, not an error: on its own it leaks nothing —
/// the adapter simply does not speak that family. When its family's prefixes
/// are missing too, which is the Windows case, the error already says what
/// leaks.
fn capture_events(check: &CaptureCheck) -> Vec<ClientEvent> {
    let mut events = vec![ClientEvent::capture(check.clone())];
    match check {
        CaptureCheck::Complete => events.push(ClientEvent::log(
            "info",
            "AllowedIPs et adresses appliqués vérifiés sur l'adaptateur",
        )),
        CaptureCheck::Incomplete {
            missing,
            missing_addresses,
        } => {
            if !missing.is_empty() {
                events.push(ClientEvent::Error {
                    message: format!(
                        "AllowedIPs non appliqués par le pilote : {} — ce trafic n'est pas \
                         capté par le tunnel et peut sortir en clair par l'interface physique",
                        missing.join(", ")
                    ),
                });
            }
            if !missing_addresses.is_empty() {
                events.push(ClientEvent::log(
                    "warn",
                    format!(
                        "adresse non posée par le pilote sur l'adaptateur : {} — le tunnel ne \
                         porte pas cette famille d'adresses",
                        missing_addresses.join(", ")
                    ),
                ));
            }
        }
        CaptureCheck::Unverified { reason } => events.push(ClientEvent::log(
            "warn",
            format!(
                "capture du tunnel non vérifiée ({reason}) — les AllowedIPs et adresses \
                 réellement appliqués sont inconnus"
            ),
        )),
    }
    events
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

        let addresses = adapter_addresses(profile)?;

        // Validates the private key format NOW. `defguard` expects it
        // encoded in `InterfaceConfiguration::prvkey` and would only reject
        // it after the interface is created — too late to fail cleanly.
        Key::try_from(profile.private_key.expose())
            .map_err(|e| anyhow::anyhow!("clé privée du client invalide : {e}"))?;

        let peer = Self::build_peer(profile)?;
        *self.peer_key() = Some(peer.public_key.clone());

        let config = InterfaceConfiguration {
            name: self.ifname.clone(),
            prvkey: profile.private_key.expose().to_owned(),
            addresses: addresses.clone(),
            port: CLIENT_LISTEN_PORT as u32 as u16,
            peers: vec![peer.clone()],
            // WireGuard's default (1420) assumes a 1500 transport. Below
            // that threshold, encrypted packets exceed the link's MTU and
            // are silently dropped: the handshake and short requests get
            // through, only large ones disappear. A client interface only
            // carries one peer, so its MTU can hug the real path.
            mtu: crate::mtu::mtu_transport(peer.endpoint.map(|e| e.ip()), &self.ifname)
                .map(aether::mtu::tunnel_mtu),
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
        api.configure_peer_routing(&routing_peers(&config.peers))
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
            &RequestedCapture {
                allowed_ips: &peer.allowed_ips,
                addresses: &addresses,
            },
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

    async fn rekey_peer(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()> {
        profile.validate_for_data_plane()?;
        let addresses = adapter_addresses(profile)?;
        let peer = Self::build_peer(profile)?;
        if !self.adapter_up.load(Ordering::SeqCst) {
            anyhow::bail!(
                "interface {} absente : aucun pair à réinscrire",
                self.ifname
            );
        }
        #[allow(unused_mut)]
        let mut api = self.api()?;
        // Updating the PSK in place would keep the current session, and no
        // handshake would come to prove the new PSK (spec §12.3). Removing
        // the peer drops its session keys; re-adding it makes the keep-alive
        // start a handshake at once. The adapter stays mounted throughout.
        //
        // The `defguard` lock is held across the Windows call too: the
        // driver configuration is written by one caller at a time.
        #[cfg(windows)]
        replace_peer_on_adapter(&self.ifname, &peer)?;
        #[cfg(not(windows))]
        {
            api.remove_peer(&peer.public_key)
                .map_err(|e| anyhow::anyhow!("retrait du pair : {e}"))?;
            api.configure_peer(&peer)
                .map_err(|e| anyhow::anyhow!("réinscription du pair : {e}"))?;
        }
        api.configure_peer_routing(&routing_peers(std::slice::from_ref(&peer)))
            .map_err(|e| anyhow::anyhow!("routage du pair : {e}"))?;
        let observed = self.observe_capture(&api, &peer.public_key);
        drop(api);
        *self.peer_key() = Some(peer.public_key.clone());
        let capture = assess_capture(
            &RequestedCapture {
                allowed_ips: &peer.allowed_ips,
                addresses: &addresses,
            },
            &observed,
        );
        for event in capture_events(&capture) {
            sink(event);
        }
        sink(ClientEvent::log(
            "info",
            "pair réinscrit — session WireGuard réinitialisée sur la nouvelle clé post-quantique"
                .to_string(),
        ));
        Ok(())
    }

    async fn transfer_bytes(&self) -> Option<u64> {
        let peer_key = self.peer_key().clone()?;
        let host = self.api().ok()?.read_interface_data().ok()?;
        let peer = host.peers.get(&peer_key)?;
        Some(peer.rx_bytes.saturating_add(peer.tx_bytes))
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

    /// The peer receives the literal as is, in either family: no resolver
    /// is involved, so nothing can swap the address for another one.
    #[test]
    fn a_literal_endpoint_reaches_the_peer_unchanged() {
        for literal in ["[2001:db8::1]:51820", "203.0.113.10:51820"] {
            let mut p = profile();
            p.endpoint = literal.into();
            let peer = WireGuardBackend::build_peer(&p).unwrap();
            assert_eq!(
                peer.endpoint,
                Some(literal.parse::<std::net::SocketAddr>().unwrap())
            );
        }
    }

    /// A name reaching the backend is a resolution the controller skipped.
    /// It is refused rather than resolved: a second `getaddrinfo` here is
    /// exactly what let the tunnel pick another family than the negotiation.
    #[test]
    fn a_hostname_endpoint_is_refused_not_resolved() {
        let mut p = profile();
        p.endpoint = "localhost:51820".into();
        let error = WireGuardBackend::build_peer(&p).unwrap_err().to_string();
        assert!(
            error.starts_with("endpoint `localhost:51820` invalide"),
            "{error}"
        );
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
            observed: Observed::AllowedIps,
            applied: Ok(prefixes(list)),
        }
    }

    fn read_addresses(list: &str) -> CaptureObservation {
        CaptureObservation {
            source: "adresses de l'adaptateur",
            observed: Observed::Addresses,
            applied: Ok(prefixes(list)),
        }
    }

    /// The verdict on `AllowedIPs` alone, the profile asking for no address
    /// the observations read back.
    fn assess(allowed_ips: &[IpAddrMask], observations: &[CaptureObservation]) -> CaptureCheck {
        assess_capture(
            &RequestedCapture {
                allowed_ips,
                addresses: &[],
            },
            observations,
        )
    }

    fn gap(missing: &[&str]) -> CaptureCheck {
        CaptureCheck::Incomplete {
            missing: missing.iter().map(ToString::to_string).collect(),
            missing_addresses: Vec::new(),
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
        // only IPv4 — what `defguard` 0.12 leaves after its family check.
        let peer = WireGuardBackend::build_peer(&profile()).unwrap();
        let check = assess(
            &peer.allowed_ips,
            &[
                read("configuration du pilote", "0.0.0.0/0, ::/0"),
                read("routes de l'adaptateur", "0.0.0.0/0, 100.64.1.2/32"),
            ],
        );
        assert_eq!(check, gap(&["::/0"]));
    }

    #[test]
    fn a_complete_read_back_is_complete() {
        let check = assess(
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
        let check = assess(
            &prefixes("0.0.0.0/0, 10.8.0.0/16, ::/0"),
            &[
                read("configuration du pilote", "0.0.0.0/0, 10.8.0.0/16"),
                read("routes de l'adaptateur", "0.0.0.0/0, ::/0"),
            ],
        );
        assert_eq!(check, gap(&["10.8.0.0/16", "::/0"]));
    }

    #[test]
    fn an_absent_peer_misses_everything() {
        // `observe_capture` reads an absent peer as an empty list.
        let check = assess(
            &prefixes("0.0.0.0/0, ::/0"),
            &[read("configuration du pilote", "")],
        );
        assert_eq!(check, gap(&["0.0.0.0/0", "::/0"]));
    }

    #[test]
    fn an_unreadable_configuration_is_unverified_not_complete() {
        let check = assess(
            &prefixes("0.0.0.0/0, ::/0"),
            &[CaptureObservation {
                source: "configuration du pilote",
                observed: Observed::AllowedIps,
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
        let check = assess(
            &prefixes("0.0.0.0/0, ::/0"),
            &[
                CaptureObservation {
                    source: "configuration du pilote",
                    observed: Observed::AllowedIps,
                    applied: Err("lecture impossible".into()),
                },
                read("routes de l'adaptateur", "0.0.0.0/0"),
            ],
        );
        assert_eq!(check, gap(&["::/0"]));
    }

    #[test]
    fn a_gap_reaches_the_screen_as_an_error_naming_the_prefix() {
        let events = capture_events(&gap(&["::/0"]));
        assert!(matches!(
            &events[0],
            ClientEvent::Capture { capture: CaptureCheck::Incomplete { missing, .. } }
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

    fn dual_stack() -> ClientProfile {
        ClientProfile {
            address_v6: Some("fd3c:91a2:7e04::2/128".into()),
            ..profile()
        }
    }

    /// A profile without `address_v6` gives the adapter the one address it
    /// always had (`ADRESSAGE-IPV6.md` §8).
    #[test]
    fn an_ipv4_profile_gives_the_adapter_one_address() {
        assert_eq!(
            named(adapter_addresses(&profile()).unwrap()),
            ["100.64.1.2/32"]
        );
    }

    /// Both addresses, IPv4 first, the IPv6 one as the `/128` host it is.
    /// `AllowedIPs` are not touched: the peer is the same with or without it.
    #[test]
    fn a_dual_stack_profile_gives_the_adapter_both_addresses() {
        assert_eq!(
            named(adapter_addresses(&dual_stack()).unwrap()),
            ["100.64.1.2/32", "fd3c:91a2:7e04::2/128"]
        );
        let ipv4 = WireGuardBackend::build_peer(&profile()).unwrap();
        let dual = WireGuardBackend::build_peer(&dual_stack()).unwrap();
        assert_eq!(ipv4.allowed_ips, dual.allowed_ips);
    }

    /// Refused before the interface exists, like everything that can fail
    /// without a side effect.
    #[test]
    fn a_malformed_ipv6_address_is_refused_before_mounting() {
        for value in ["fd3c:91a2:7e04::/64", "100.64.1.3/32", "fe80::2%eth0/128"] {
            let profile = ClientProfile {
                address_v6: Some(value.into()),
                ..profile()
            };
            let error = adapter_addresses(&profile).unwrap_err().to_string();
            assert!(
                error.starts_with("adresse IPv6 invalide"),
                "{value}: {error}"
            );
        }
        // A blank value is no value.
        let blank = ClientProfile {
            address_v6: Some("  ".into()),
            ..profile()
        };
        assert_eq!(named(adapter_addresses(&blank).unwrap()), ["100.64.1.2/32"]);
    }

    #[test]
    fn missing_addresses_are_compared_host_for_host() {
        // Windows reports the on-link length it chose: the host is what
        // counts, and an extra link-local address is not a gap.
        let requested = prefixes("100.64.1.2/32, fd3c:91a2:7e04::2/128");
        assert!(missing_addresses(
            &requested,
            &prefixes("fe80::5/64, 100.64.1.2/32, fd3c:91a2:7e04:0:0:0:0:2/64"),
        )
        .is_empty());
        assert_eq!(
            named(missing_addresses(&requested, &prefixes("100.64.1.2/32"))),
            ["fd3c:91a2:7e04::2/128"]
        );
    }

    /// The `defguard` Windows case on a dual-stack profile: no IPv6 on the
    /// adapter, so both `::/0` and the IPv6 address are skipped without an
    /// error. Both are part of the verdict.
    #[test]
    fn a_skipped_ipv6_address_is_part_of_the_verdict() {
        let profile = dual_stack();
        let peer = WireGuardBackend::build_peer(&profile).unwrap();
        let addresses = adapter_addresses(&profile).unwrap();
        let check = assess_capture(
            &RequestedCapture {
                allowed_ips: &peer.allowed_ips,
                addresses: &addresses,
            },
            &[
                read("configuration du pilote", "0.0.0.0/0, ::/0"),
                read("routes de l'adaptateur", "0.0.0.0/0, 100.64.1.2/32"),
                read_addresses("100.64.1.2/32"),
            ],
        );
        assert_eq!(
            check,
            CaptureCheck::Incomplete {
                missing: vec!["::/0".into()],
                missing_addresses: vec!["fd3c:91a2:7e04::2/128".into()],
            }
        );
    }

    /// An address missing on its own still makes the verdict incomplete: it
    /// is a fact about the adapter, not something to infer from the routes.
    #[test]
    fn a_missing_address_alone_is_incomplete() {
        let addresses = adapter_addresses(&dual_stack()).unwrap();
        let check = assess_capture(
            &RequestedCapture {
                allowed_ips: &prefixes("0.0.0.0/0, ::/0"),
                addresses: &addresses,
            },
            &[
                read("configuration du pilote", "0.0.0.0/0, ::/0"),
                read_addresses("fd3c:91a2:7e04::2/128"),
            ],
        );
        assert_eq!(
            check,
            CaptureCheck::Incomplete {
                missing: Vec::new(),
                missing_addresses: vec!["100.64.1.2/32".into()],
            }
        );
    }

    #[test]
    fn both_addresses_read_back_are_complete() {
        let addresses = adapter_addresses(&dual_stack()).unwrap();
        let check = assess_capture(
            &RequestedCapture {
                allowed_ips: &prefixes("0.0.0.0/0, ::/0"),
                addresses: &addresses,
            },
            &[
                read("configuration du pilote", "0.0.0.0/0, ::/0"),
                read_addresses("100.64.1.2/32, fe80::1/64, fd3c:91a2:7e04::2/128"),
            ],
        );
        assert_eq!(check, CaptureCheck::Complete);
    }

    #[test]
    fn an_unreadable_address_table_is_unverified() {
        let addresses = adapter_addresses(&dual_stack()).unwrap();
        let check = assess_capture(
            &RequestedCapture {
                allowed_ips: &prefixes("0.0.0.0/0, ::/0"),
                addresses: &addresses,
            },
            &[
                read("configuration du pilote", "0.0.0.0/0, ::/0"),
                CaptureObservation {
                    source: "adresses de l'adaptateur",
                    observed: Observed::Addresses,
                    applied: Err("adaptateur introuvable".into()),
                },
            ],
        );
        assert_eq!(
            check,
            CaptureCheck::Unverified {
                reason: "adresses de l'adaptateur : adaptateur introuvable".into()
            }
        );
    }

    /// A missing address is stated, as a warning naming it: on its own it
    /// leaks nothing, so it is not the error a stripped prefix is.
    #[test]
    fn a_missing_address_reaches_the_screen_as_a_warning_naming_it() {
        let events = capture_events(&CaptureCheck::Incomplete {
            missing: Vec::new(),
            missing_addresses: vec!["fd3c:91a2:7e04::2/128".into()],
        });
        assert!(matches!(
            &events[0],
            ClientEvent::Capture { capture: CaptureCheck::Incomplete { missing_addresses, .. } }
                if missing_addresses == &["fd3c:91a2:7e04::2/128".to_string()]
        ));
        assert!(events
            .iter()
            .all(|event| !matches!(event, ClientEvent::Error { .. })));
        match &events[1] {
            ClientEvent::Log { level, message } => {
                assert_eq!(level, "warn");
                assert!(
                    message.starts_with(
                        "adresse non posée par le pilote sur l'adaptateur : fd3c:91a2:7e04::2/128"
                    ),
                    "{message}"
                );
            }
            other => panic!("a missing address must be a warning, got {other:?}"),
        }
    }

    fn read_routes(list: &str) -> CaptureObservation {
        CaptureObservation {
            source: "routes du noyau",
            observed: Observed::KernelRoutes,
            applied: Ok(prefixes(list)),
        }
    }

    #[test]
    fn a_family_with_a_default_route_expects_no_other_route() {
        // `defguard` routes the family through its fwmark table and skips
        // the other prefixes; the IPv4 default lives outside the main table.
        let expected = linux_expected_routes(&prefixes("0.0.0.0/0, 10.8.0.0/16, ::/0, fd00::/8"));
        assert_eq!(named(expected), ["::/0"]);
    }

    #[test]
    fn a_split_tunnel_expects_every_prefix() {
        let expected = linux_expected_routes(&prefixes("10.8.0.0/16, 192.168.50.0/24, fd00::/8"));
        assert_eq!(
            named(expected),
            ["10.8.0.0/16", "192.168.50.0/24", "fd00::/8"]
        );
    }

    #[test]
    fn a_route_the_kernel_refused_is_a_gap() {
        // What `defguard` 0.12 only logs: the driver holds the prefix, the
        // kernel never routed it.
        let check = assess(
            &prefixes("10.8.0.0/16, 192.168.50.0/24"),
            &[
                read("configuration du pilote", "10.8.0.0/16, 192.168.50.0/24"),
                read_routes("10.8.0.0/16, 100.64.0.0/10"),
            ],
        );
        assert_eq!(check, gap(&["192.168.50.0/24"]));
    }

    #[test]
    fn the_default_full_tunnel_is_complete_with_the_ipv6_default_routed() {
        let peer = WireGuardBackend::build_peer(&profile()).unwrap();
        let check = assess(
            &peer.allowed_ips,
            &[
                read("configuration du pilote", "0.0.0.0/0, ::/0"),
                read_routes("::/0, fe80::/64"),
            ],
        );
        assert_eq!(check, CaptureCheck::Complete);
    }

    #[test]
    fn a_missing_ipv6_default_route_is_a_gap() {
        // `defguard` logs a failed IPv6 default and returns `Ok`.
        let peer = WireGuardBackend::build_peer(&profile()).unwrap();
        let check = assess(
            &peer.allowed_ips,
            &[
                read("configuration du pilote", "0.0.0.0/0, ::/0"),
                read_routes("fe80::/64"),
            ],
        );
        assert_eq!(check, gap(&["::/0"]));
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn proc_net_route_lists_the_adapter_routes_only() {
        let text =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            orion0\t0000080A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n\
            orion0\t00004064\t00000000\t0001\t0\t0\t0\t0000C0FF\t0\t0\t0\n";
        let routed = parse_proc_net_route(text, "orion0").unwrap();
        assert_eq!(named(routed), ["10.8.0.0/16", "100.64.0.0/10"]);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn a_malformed_proc_net_route_line_fails_the_read() {
        let text = "Iface\tDestination\n orion0\tzzzz\n";
        assert!(parse_proc_net_route(text, "orion0").is_err());
        let text = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
            orion0\t0000080A\t00000000\t0001\t0\t0\t0\t00FF00FF\n";
        let error = parse_proc_net_route(text, "orion0").unwrap_err();
        assert!(error.contains("masque non contigu"), "{error}");
    }

    #[test]
    fn proc_net_ipv6_route_lists_the_adapter_routes_from_every_table() {
        let zero = "00000000000000000000000000000000";
        let text = format!(
            "{zero} 00 {zero} 00 {zero} 00000400 00000001 00000000 00000001   orion0\n\
             fd3c91a27e0400000000000000000000 40 {zero} 00 {zero} 00000100 00000001 00000000 00000001   orion0\n\
             fe800000000000000000000000000000 40 {zero} 00 {zero} 00000100 00000001 00000000 00000001     eth0\n"
        );
        let routed = parse_proc_net_ipv6_route(&text, "orion0").unwrap();
        assert_eq!(named(routed), ["::/0", "fd3c:91a2:7e04::/64"]);
    }

    #[test]
    fn a_malformed_proc_net_ipv6_route_line_fails_the_read() {
        assert!(parse_proc_net_ipv6_route("short line   orion0\n", "orion0").is_err());
        let zero = "00000000000000000000000000000000";
        let text = format!("{zero} 99 {zero} 00 {zero} 0 0 0 0 orion0\n");
        assert!(parse_proc_net_ipv6_route(&text, "orion0").is_err());
    }

    #[test]
    fn the_endpoint_is_withheld_from_routing_on_linux_only() {
        let peer = WireGuardBackend::build_peer(&profile()).unwrap();
        let routed = routing_peers(std::slice::from_ref(&peer));
        assert_eq!(routed[0].allowed_ips, peer.allowed_ips);
        assert_eq!(routed[0].public_key, peer.public_key);
        if cfg!(target_os = "linux") {
            assert_eq!(routed[0].endpoint, None);
        } else {
            assert_eq!(routed[0].endpoint, peer.endpoint);
        }
        assert!(peer.endpoint.is_some(), "the interface keeps its endpoint");
    }
}
