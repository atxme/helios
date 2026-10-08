//! Rendering of a policy + a state into a **structured** ruleset.
//!
//! The ruleset is a data structure, not text: it is what the Netlink backend
//! translates into expressions, and from which [`crate::DryRunBackend`] and the
//! API derive human-readable nftables syntax via [`Display`](std::fmt::Display). The reverse —
//! producing text then re-parsing it — would be fragile and would silently
//! let the display diverge from what is actually applied.
//!
//! Each rule carries the **hooked chain** it belongs to: traffic destined for
//! the gateway itself (WireGuard listener, API, SSH) goes into `input`, LAN
//! traffic passing through it into `forward`, and traffic it emits into
//! `output`. Confusing them would let through — or block — the wrong traffic.
//!
//! # Internet egress for tunnel clients
//!
//! Two forms coexist, and they do not open the same paths:
//!
//! * **site-to-site**, always active: `forward` from `lan_ifaces` to
//!   `wan_iface`, for hosts located *behind* the gateway;
//! * **road-warrior**, behind `allow_client_internet`: `forward` from
//!   `wg_iface` to `wan_iface`, plus a masquerade in `postrouting`, for a
//!   client arriving *through* the tunnel. Both are IPv4-only
//!   (`meta nfproto ipv4`): the table is `inet`, and the gateway neither
//!   relays nor NATs IPv6, see [`MasqueradeRule`].
//!
//! A tunnel client's IPv6 bound for a WAN is not left to the `drop` policy
//! either: it is rejected with `icmpx admin-prohibited`, in every state, so
//! that the client falls back to IPv4 at once (module `client_ipv6_egress`).
//!
//! The second is closed by default. A gateway granting access to internal
//! resources has no reason to route Internet traffic, and opening it would
//! widen its surface with no benefit. Both only hold in a state where traffic
//! is allowed: NAT is applied and removed together with the tunnel, otherwise
//! the kill-switch would let out in the clear what it just cut off.
//!
//! # The gateway's own egress
//!
//! Neither of the two forms above covers the gateway's *own* traffic, and the
//! `output` chain is the one nobody reads: under the fail-closed policy it
//! accepts loopback, `established` flows, DHCP renewal and the site-to-site
//! WireGuard transport, then drops the rest. So a gateway resolves no name,
//! reaches no NTP server and fetches no package — including through
//! `helios update`, which runs `apt-get` on that very machine.
//!
//! `allow_gateway_egress` opens it, on the WAN interface and on those ports
//! only. It is separate from `allow_client_internet` because it answers a
//! different question — what the gateway emits, not what it relays — and it
//! does not follow the tunnel state, because an upgrade happens when the
//! tunnel is down.
//!
//! # Known limitation: DNS is not tunneled
//!
//! Even with `allow_client_internet` active, the client keeps its own
//! resolver: its DNS queries leave outside the tunnel and reveal the names it
//! looks up, while the rest of its traffic is protected. What would unblock
//! this: a resolver field in the `orion-profile` document — which
//! `orion-core` currently rejects, including the `DNS` key of a `wg-quick`
//! file — and the choice of a resolver reachable inside the tunnel. See
//! ADR-004 batch 5.

mod administration;
mod astra_channel;
mod client_ipv6_egress;
mod gateway_wan;
mod kill_switch;
mod link_ipv6;
mod meshnet;
mod nftables;
mod transport;
mod tunnel_interface;

pub use nftables::{
    Action, AddressFamily, ChainKind, ConnectionState, ConnectionStates, Counter, DefaultVerdict,
    Icmpv6Type, LogAction, MasqueradeRule, Match, RateLimit, RateLimitMode, RateUnit, Rule,
    Ruleset, Verdict, L4,
};

use aether::{FirewallPolicy, HeliosError, Result, TunnelState, SPEEDTEST_PORT};
use ipnetwork::IpNetwork;

/// Networks NordVPN classifies as local for Meshnet's separate local-network
/// permission.
const PRIVATE_IPV4_CIDRS: [&str; 4] = [
    "10.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
];

/// The IPv6 counterpart of [`PRIVATE_IPV4_CIDRS`]: unique local addresses
/// (RFC 4193) and link-local addresses (RFC 4291).
///
/// NordVPN hands out IPv4 Meshnet addresses only, so there is no NordVPN
/// IPv6 classification to mirror: these are the two scopes IPv6 reserves for
/// local use.
const PRIVATE_IPV6_CIDRS: [&str; 2] = ["fc00::/7", "fe80::/10"];

/// The local networks of one address family.
///
/// A drop pairing a source of one family with a destination of the other can
/// never match, so a peer's local-network denial must use its own family's
/// list: the IPv4 list alone would leave an IPv6 peer's local networks open.
fn local_networks(family: AddressFamily) -> &'static [&'static str] {
    match family {
        AddressFamily::Ipv4 => &PRIVATE_IPV4_CIDRS,
        AddressFamily::Ipv6 => &PRIVATE_IPV6_CIDRS,
    }
}

/// Builds the ruleset for `(policy, state)`.
///
/// Invariants, regardless of state:
/// * loopback and established/related traffic always accepted;
/// * the WireGuard listening port stays reachable, without which no client
///   could (re)establish the tunnel;
/// * IPv6 neighbor discovery and MLD on every WAN and LAN interface, router
///   discovery on the WANs only (module `link_ipv6`);
/// * LAN -> WAN forwarding is only open in the `Up` state;
/// * IPv6 from the tunnel interface to a WAN is rejected, last of `forward`
///   (module `client_ipv6_egress`).
pub fn render(policy: &FirewallPolicy, state: TunnelState) -> Result<Ruleset> {
    use ChainKind::{Forward, Input, Output};
    let mut rules = Vec::new();
    let wan_ifaces = policy.wan_ifaces.clone();

    // Invalid conntrack entries must never be rescued by a later, narrower
    // accept rule (the administration API is intentionally rendered before
    // the ordinary established/related opening). Keep this invariant at the
    // absolute head of every hooked chain.
    for chain in [Input, Forward, Output] {
        rules.push(
            Rule::new(
                chain,
                vec![Match::ConnectionState(ConnectionStates::INVALID)],
                Verdict::Drop,
            )
            .with_counter(Counter::Anonymous)
            .with_note("invalid conntrack state: dropped before every opening"),
        );
    }

    administration::admin_api(&mut rules, policy);

    // ── Always allowed ───────────────────────────────────────────────────────
    for chain in [Input, Forward, Output] {
        // Loopback is designated by the *ingress* interface in input and
        // forward, but by the *egress* interface in output: a locally
        // generated packet has no ingress interface. An `iifname "lo"` on the
        // output hook therefore never matches, and all local traffic falls
        // under the `drop` policy — including the gateway's API on
        // 127.0.0.1. Observed on target.
        let loopback = if chain == Output {
            Match::OutIface("lo".into())
        } else {
            Match::InIface("lo".into())
        };
        rules.push(Rule::new(chain, vec![loopback], Verdict::Accept));
        rules.push(Rule::new(
            chain,
            vec![Match::ConnectionState(
                ConnectionStates::ESTABLISHED_RELATED,
            )],
            Verdict::Accept,
        ));
    }

    astra_channel::lifecycle_and_public_origin(&mut rules)?;
    transport::wireguard_listener(&mut rules, policy, &wan_ifaces);
    transport::key_negotiation_listener(&mut rules, policy, &wan_ifaces);
    transport::site_to_site_peers(&mut rules, policy, &wan_ifaces)?;
    gateway_wan::dhcp_lease_renewal(&mut rules, policy, &wan_ifaces);
    gateway_wan::gateway_own_egress(&mut rules, policy, &wan_ifaces);
    link_ipv6::link_control(&mut rules, policy, &wan_ifaces);
    meshnet::nordvpn_meshnet(&mut rules, policy, &wan_ifaces)?;
    tunnel_interface::openings(&mut rules, policy);
    administration::ssh_sources(&mut rules, policy)?;
    administration::out_of_band_admin_ifaces(&mut rules, policy);
    kill_switch::state_gated_openings(&mut rules, policy, state, &wan_ifaces)?;
    // Last of `forward`, in every state: after every opening, before the
    // chain policy.
    client_ipv6_egress::reject(&mut rules, policy, &wan_ifaces);

    // In fail-open, the default policy becomes accept outside the tunnel (not recommended).
    let default_verdict = if policy.is_fail_closed() || state.traffic_allowed() {
        DefaultVerdict::Drop
    } else {
        DefaultVerdict::Accept
    };

    Ok(Ruleset {
        default_verdict,
        rules,
        mss_clamp: state
            .traffic_allowed()
            .then_some(policy.mss_clamp)
            .flatten(),
        // NAT follows the tunnel state exactly: applied with it, removed with
        // it. A masquerade that survived the tunnel going down would let out
        // in the clear what the kill-switch just cut off.
        // One masquerade per uplink, and they enter the **same** transaction as
        // the filtering: a masquerade that outlived the kill-switch would let
        // out in the clear what it had just cut. Several is not a widening —
        // each only ever matches packets that actually leave by its own
        // interface, which is what makes an uplink failover survive without a
        // reload.
        masquerade_out: if state.traffic_allowed()
            && policy.allow_client_internet
            && !policy.wg_iface.is_empty()
        {
            wan_ifaces.clone()
        } else {
            Vec::new()
        },
    })
}

/// Parses a policy address before it can enter the structured IR.
///
/// Public so that a caller accepting an address bound for the policy — the
/// API's split-tunnel route — refuses it with this exact rule, rather than
/// with a second parser that could accept what [`render`] then refuses.
pub fn parse_network(value: &str) -> Result<IpNetwork> {
    value.parse().map_err(|error| {
        HeliosError::Firewall(format!(
            "invalid IP network `{value}` in firewall policy: {error}"
        ))
    })
}

/// Every state a policy can be rendered for, in the order of
/// [`TunnelState`]'s declaration.
const TUNNEL_STATES: [TunnelState; 5] = [
    TunnelState::Down,
    TunnelState::Connecting,
    TunnelState::Up,
    TunnelState::Failed,
    TunnelState::CaptivePortal,
];

/// Compiles `policy` for every tunnel state, keeping none of the rulesets.
///
/// [`render`] only reads the fields the given state uses: the split-tunnel
/// CIDRs, for instance, only in `Up`. A policy accepted by an `apply` made
/// while the tunnel is down could therefore still be refused at the next
/// promotion, long after the operator who supplied the bad value was told it
/// was in force. Checking every state is what lets a caller refuse such a
/// policy before it becomes the running one.
pub fn check_policy(policy: &FirewallPolicy) -> Result<()> {
    for state in TUNNEL_STATES {
        render(policy, state)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
