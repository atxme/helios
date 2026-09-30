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
//!   client arriving *through* the tunnel.
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
//! `helios-ctl update`, which runs `apt-get` on that very machine.
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
mod gateway_wan;
mod kill_switch;
mod meshnet;
mod nftables;
mod transport;
mod tunnel_interface;

pub use nftables::{
    Action, AddressFamily, ChainKind, ConnectionState, ConnectionStates, Counter, LogAction, Match,
    RateLimit, RateLimitMode, RateUnit, Rule, Ruleset, Verdict, L4,
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

/// Builds the ruleset for `(policy, state)`.
///
/// Invariants, regardless of state:
/// * loopback and established/related traffic always accepted;
/// * the WireGuard listening port stays reachable, without which no client
///   could (re)establish the tunnel;
/// * LAN -> WAN forwarding is only open in the `Up` state.
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
    meshnet::nordvpn_meshnet(&mut rules, policy, &wan_ifaces)?;
    tunnel_interface::openings(&mut rules, policy);
    administration::ssh_sources(&mut rules, policy)?;
    administration::out_of_band_admin_ifaces(&mut rules, policy);
    kill_switch::state_gated_openings(&mut rules, policy, state, &wan_ifaces)?;

    // In fail-open, the default policy becomes accept outside the tunnel (not recommended).
    let default_verdict = if policy.is_fail_closed() || state.traffic_allowed() {
        Verdict::Drop
    } else {
        Verdict::Accept
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
pub(super) fn network(value: &str) -> Result<IpNetwork> {
    value.parse().map_err(|error| {
        HeliosError::Firewall(format!(
            "invalid IP network `{value}` in firewall policy: {error}"
        ))
    })
}

#[cfg(test)]
mod tests;
