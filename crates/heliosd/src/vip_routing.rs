//! Keeps admitted peers reachable when another VPN captures the CGNAT range.
//!
//! # The failure this exists for
//!
//! Helios derives every client VIP from `100.64.0.0/10` (RFC 6598), and it is
//! not alone: NordLynx, Tailscale and most consumer VPN clients draw from the
//! same shared range. That on its own would be survivable — two routes for the
//! same prefix in the main table still resolve. What is not survivable is that
//! those clients install **policy routing rules** which consult their own table
//! *before* the main one:
//!
//! ```text
//! 32765:  not from all fwmark 0xe1f1 lookup 205
//! 32766:  from all lookup main
//! ```
//!
//! with table 205 holding `100.64.0.0/10 dev nordlynx`. From that moment every
//! packet the gateway sends to one of **its own** clients leaves through the
//! other VPN, and the main table — where `helios0` lives — is never reached.
//! `ip route get 100.64.98.223` answers `dev nordlynx`, and the Helios data
//! plane is silently dead: nothing is dropped, nothing is logged, the packets
//! simply go somewhere else.
//!
//! # Why a rule, and why not a wider one
//!
//! Sending the whole `100.64.0.0/10` back to `helios0` would fix Helios by
//! breaking the other VPN — its own peers live in that range too. So the table
//! this module owns holds **one `/32` per admitted peer**, and nothing else. A
//! destination that is not one of ours finds no match, and the lookup falls
//! through to the next rule exactly as before. Coexistence is the whole point:
//! the operator asked for both, and neither is entitled to the range.
//!
//! Reusing `lookup main` instead of a private table would not work either. The
//! main table already carries *both* `100.64.0.0/10 dev nordlynx` and
//! `100.64.0.0/10 dev helios0`, same prefix length and same metric; which one
//! answers is an insertion-order accident, and it is not ours.
//!
//! # Why it is installed unconditionally
//!
//! Detecting the hijack first — resolving a VIP and only acting if it points
//! elsewhere — looks tidier and is wrong. The other VPN can connect at any
//! moment, long after `heliosd` started, and reinstalls its rules every time it
//! does. A check performed at startup would pass on a machine that breaks ten
//! minutes later. The rule is therefore always present, costs one lookup, and
//! is a no-op on a gateway that has the range to itself.
//!
//! # IPv6
//!
//! When the gateway installed its IPv6 tunnel prefix, the same plan is applied
//! in the IPv6 family (`ADRESSAGE-IPV6.md` §6.3): one `/128` per peer in the
//! same table, `src <prefix>::1`, and one `ip -6 rule` for `<prefix>::/64` at
//! the same priority. The families are separate in the kernel — `ip rule del`
//! and `route flush` only ever touch one — so each is flushed and withdrawn on
//! its own ([`PlanV6`]). The IPv6 routes are read from the very `AllowedIPs`
//! the gateway installed: a peer the data plane does not route in IPv6 gets no
//! IPv6 route either. A gateway without IPv6, or whose prefix could not be
//! installed, runs no `ip -6` command at all.
//!
//! Tailscale draws its IPv6 from `fd7a:115c:a1e0::/48`, and a random ULA `/64`
//! is unlikely to meet it; the pinning is kept anyway, for the same reason as
//! in IPv4 — the next VPN to connect is not one Helios can enumerate.
//!
//! # Limite connue
//!
//! Only single hosts are carried: IPv4 `/32` and IPv6 `/128` inside the tunnel
//! prefix. A peer whose `AllowedIPs` holds a wider network is left to the main
//! table, and will be captured by a foreign rule exactly as described above.
//! Helios's IPAM only ever assigns single hosts in both families
//! (`helios_provisioning::ipam`), so this covers what the gateway itself hands
//! out, not what an operator may have written by hand into `network.toml`.
//!
//! An IPv6 rule left by a crashed run, or by a run whose successor could not
//! install IPv6, stays until the next run that installs IPv6 flushes it. It is
//! inert meanwhile: the routes it points at named the interface, and went with
//! it.

use std::net::{Ipv4Addr, Ipv6Addr};

use aether::net::TunnelPrefixV6;
use helios_wireguard::PeerConfig;

/// Routing table Helios owns, and the only one it ever writes to.
///
/// Chosen to match the default WireGuard listening port for readability in
/// `ip route show table 51820`; it carries no other meaning, and nothing
/// derives one from it.
pub const VIP_TABLE: u32 = 51820;

/// Priority of the single rule pointing at [`VIP_TABLE`].
///
/// It has to beat the range-capturing rules other VPNs install just above the
/// main table — NordVPN sits at 32765, Tailscale's `suppress_prefixlength` at
/// 32764 — while staying *behind* their mark-based rules in the 5000s, which
/// are specific to their own marked packets and have no business being
/// overtaken.
pub const VIP_RULE_PRIORITY: u32 = 32000;

/// Lowest priority observed among the rules that capture the whole range:
/// Tailscale's `suppress_prefixlength` at 32764, NordVPN's `lookup 205` at
/// 32765. Being consulted after either of them is the same as not existing.
const FOREIGN_RANGE_RULE_PRIORITY: u32 = 32764;

/// Highest priority among the mark-based rules those same clients install.
/// Those match packets they marked themselves and are none of our business;
/// overtaking them would be a different bug, so the placement is asserted in
/// both directions rather than commented.
const FOREIGN_MARK_RULE_PRIORITY: u32 = 5270;

const _: () = assert!(VIP_RULE_PRIORITY < FOREIGN_RANGE_RULE_PRIORITY);
const _: () = assert!(VIP_RULE_PRIORITY > FOREIGN_MARK_RULE_PRIORITY);

/// How many stale rules at our priority are removed before giving up.
///
/// `ip rule del` removes one match per call, so flushing is a loop; the bound
/// exists so a kernel that kept answering success could not spin forever.
const MAX_STALE_RULES: usize = 16;

/// Why the policy routing could not be planned.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoutingError {
    /// The gateway's tunnel address is not a parsable IPv4 CIDR.
    #[error("the tunnel address {0} is not an IPv4 CIDR such as 100.64.0.1/10")]
    BadTunnelAddress(String),
    /// `ip` could not be executed at all.
    #[error("running `ip {0}`: {1}")]
    CommandFailed(String, String),
}

/// What must exist in the kernel for the admitted peers to stay ours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Interface the peer routes point at.
    pub iface: String,
    /// Source address stamped on those routes — the gateway's tunnel address.
    pub source: Ipv4Addr,
    /// Selector of the single rule: the tunnel network, e.g. `100.64.0.0/10`.
    pub selector: String,
    /// One `/32` per admitted peer, in the order they were declared.
    pub vips: Vec<String>,
}

impl Plan {
    /// Renders the plan as `ip` argument vectors, in the order to run them.
    ///
    /// Building the commands separately from running them is what makes this
    /// testable: the sequence is the part that can be wrong, and it is the
    /// part no test could observe through a live kernel.
    pub fn commands(&self) -> Vec<Vec<String>> {
        let mut out: Vec<Vec<String>> = Vec::new();
        // The table is rebuilt rather than diffed. A revoked peer must lose
        // its route in the same pass that a new one gains it, and a diff that
        // missed a removal would keep routing to a client that is no longer
        // admitted.
        out.push(table_flush(Family::V4));
        for vip in &self.vips {
            out.push(split(&format!(
                "route replace {vip} dev {} src {} table {VIP_TABLE}",
                self.iface, self.source
            )));
        }
        // Added last: a rule pointing at a table still being filled would send
        // packets to a lookup that has no answer yet, and `ip rule` offers no
        // way to install the two atomically.
        if !self.vips.is_empty() {
            out.push(split(&format!(
                "rule add to {} lookup {VIP_TABLE} priority {VIP_RULE_PRIORITY}",
                self.selector
            )));
        }
        out
    }
}

/// The IPv6 counterpart of [`Plan`]: same table, same priority, its own
/// family (`ADRESSAGE-IPV6.md` §6.3).
///
/// Built only for a gateway that installed its IPv6 tunnel prefix, from the
/// prefix itself rather than from text, so it cannot be malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanV6 {
    /// Interface the peer routes point at.
    pub iface: String,
    /// Source address stamped on those routes — the gateway's `<prefix>::1`.
    pub source: Ipv6Addr,
    /// Selector of the single rule: the tunnel prefix, e.g. `fd3c:91a2:7e04::/64`.
    pub selector: String,
    /// One `/128` per peer routed in IPv6, in the order they were declared.
    pub vips: Vec<String>,
}

impl PlanV6 {
    /// Renders the plan as `ip -6` argument vectors, in the order to run
    /// them: the same sequence as [`Plan::commands`], for the same reasons.
    pub fn commands(&self) -> Vec<Vec<String>> {
        let mut out: Vec<Vec<String>> = Vec::new();
        out.push(table_flush(Family::V6));
        for vip in &self.vips {
            out.push(Family::V6.ip(&format!(
                "route replace {vip} dev {} src {} table {VIP_TABLE}",
                self.iface, self.source
            )));
        }
        if !self.vips.is_empty() {
            out.push(Family::V6.ip(&format!(
                "rule add to {} lookup {VIP_TABLE} priority {VIP_RULE_PRIORITY}",
                self.selector
            )));
        }
        out
    }
}

/// Works out what the kernel should carry for `peers`.
pub fn plan(iface: &str, tunnel_address: &str, peers: &[PeerConfig]) -> Result<Plan, RoutingError> {
    let (source, prefix_len) = parse_cidr(tunnel_address)
        .ok_or_else(|| RoutingError::BadTunnelAddress(tunnel_address.to_string()))?;
    Ok(Plan {
        iface: iface.to_string(),
        source,
        selector: format!("{}/{prefix_len}", network_of(source, prefix_len)),
        vips: peers
            .iter()
            .flat_map(|p| p.allowed_ips.iter().filter_map(|a| host_route(a)))
            .collect(),
    })
}

/// Works out what the kernel should carry in IPv6 for `peers`, under the
/// installed tunnel `prefix`.
///
/// A peer's IPv6 route is taken from its `AllowedIPs`, read with the
/// canonical parser: what WireGuard does not route to a peer, this table does
/// not either. Only hosts inside the prefix are kept, like the IPv4 side keeps
/// only `/32`.
pub fn plan_v6(iface: &str, prefix: TunnelPrefixV6, peers: &[PeerConfig]) -> PlanV6 {
    PlanV6 {
        iface: iface.to_string(),
        source: prefix.gateway(),
        selector: format!("{}/{}", prefix.network(), TunnelPrefixV6::PREFIX_LEN),
        vips: peers
            .iter()
            .flat_map(|p| p.allowed_ips.iter())
            .filter_map(|allowed| aether::net::parse_vip_v6(allowed).ok())
            .filter(|vip| prefix.contains(*vip))
            .map(aether::net::format_vip_v6)
            .collect(),
    }
}

/// Installs the plan, replacing whatever a previous run had left behind.
pub async fn apply(plan: &Plan) -> Result<(), RoutingError> {
    install(Family::V4, &plan.commands()).await?;
    if !plan.vips.is_empty() {
        tracing::info!(
            iface = %plan.iface,
            selector = %plan.selector,
            peers = plan.vips.len(),
            table = VIP_TABLE,
            priority = VIP_RULE_PRIORITY,
            "peer VIPs pinned to the tunnel interface — another VPN sharing the CGNAT range \
             can no longer capture them"
        );
    }
    Ok(())
}

/// Installs the IPv6 plan, replacing what a previous run left in that family.
pub async fn apply_v6(plan: &PlanV6) -> Result<(), RoutingError> {
    install(Family::V6, &plan.commands()).await?;
    if !plan.vips.is_empty() {
        tracing::info!(
            iface = %plan.iface,
            selector = %plan.selector,
            peers = plan.vips.len(),
            table = VIP_TABLE,
            priority = VIP_RULE_PRIORITY,
            "peer IPv6 VIPs pinned to the tunnel interface"
        );
    }
    Ok(())
}

/// Removes everything [`apply`] installed. Called when the interface goes down.
pub async fn withdraw() -> Result<(), RoutingError> {
    remove(Family::V4).await
}

/// Removes everything [`apply_v6`] installed. Called when the interface goes
/// down on a gateway that had installed IPv6.
pub async fn withdraw_v6() -> Result<(), RoutingError> {
    remove(Family::V6).await
}

/// The kernel's two address families. Each has its own rules and its own
/// copy of the table: an `ip` command reaches one only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    /// `command` as `ip` arguments in this family. IPv4 keeps the bare form it
    /// always had; IPv6 is selected with `-6`.
    fn ip(self, command: &str) -> Vec<String> {
        let mut args = match self {
            Self::V4 => Vec::new(),
            Self::V6 => vec!["-6".to_string()],
        };
        args.extend(split(command));
        args
    }
}

fn table_flush(family: Family) -> Vec<String> {
    family.ip(&format!("route flush table {VIP_TABLE}"))
}

fn rule_delete(family: Family) -> Vec<String> {
    family.ip(&format!("rule del priority {VIP_RULE_PRIORITY}"))
}

/// Whether `args` clears the table — the one command whose failure says
/// nothing about the routes about to be added.
fn is_table_flush(args: &[String]) -> bool {
    args == table_flush(Family::V4).as_slice() || args == table_flush(Family::V6).as_slice()
}

/// Runs one family's commands after clearing that family's rules.
async fn install(family: Family, commands: &[Vec<String>]) -> Result<(), RoutingError> {
    flush_rules(family).await?;
    for args in commands {
        // `route flush` on a table that was never created is a success on some
        // kernels and an error on others, and neither says anything about the
        // routes we are about to add. Only the rule and the routes are
        // load-bearing.
        match run(args).await {
            Ok(()) => {}
            Err(error) if is_table_flush(args) => {
                tracing::debug!(%error, "clearing the VIP table found nothing to clear");
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn remove(family: Family) -> Result<(), RoutingError> {
    flush_rules(family).await?;
    // Left for last and unchecked: with the rule gone the table is
    // unreachable, so a route that survives is inert rather than harmful.
    if let Err(error) = run(&table_flush(family)).await {
        tracing::debug!(%error, "clearing the VIP table found nothing to clear");
    }
    Ok(())
}

/// Removes every rule sitting at our priority in `family`, ours or a previous
/// run's.
///
/// The priority is the ownership marker: nothing else in the system is
/// expected to claim it, and a crashed `heliosd` leaves its rule behind.
async fn flush_rules(family: Family) -> Result<(), RoutingError> {
    for _ in 0..MAX_STALE_RULES {
        if run(&rule_delete(family)).await.is_err() {
            return Ok(());
        }
    }
    Ok(())
}

async fn run(args: &[String]) -> Result<(), RoutingError> {
    let output = tokio::process::Command::new("ip")
        .args(args)
        .output()
        .await
        .map_err(|e| RoutingError::CommandFailed(args.join(" "), e.to_string()))?;
    if output.status.success() {
        return Ok(());
    }
    Err(RoutingError::CommandFailed(
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
    ))
}

fn split(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_string).collect()
}

/// Keeps only single IPv4 hosts: those are what the IPAM assigns.
fn host_route(allowed_ips: &str) -> Option<String> {
    let (address, prefix_len) = parse_cidr(allowed_ips)?;
    (prefix_len == 32).then(|| format!("{address}/32"))
}

fn parse_cidr(value: &str) -> Option<(Ipv4Addr, u8)> {
    let (address, prefix) = value.trim().split_once('/')?;
    let address: Ipv4Addr = address.parse().ok()?;
    let prefix_len: u8 = prefix.parse().ok()?;
    (prefix_len <= 32).then_some((address, prefix_len))
}

fn network_of(address: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let mask = u32::MAX << (32 - u32::from(prefix_len));
    Ipv4Addr::from(u32::from(address) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(allowed_ips: &str) -> PeerConfig {
        PeerConfig {
            public_key: "key".into(),
            allowed_ips: vec![allowed_ips.into()],
            preshared_key: None,
            persistent_keepalive_secs: 25,
        }
    }

    #[test]
    fn the_selector_is_the_tunnel_network_not_the_gateway_address() {
        let plan = plan("helios0", "100.64.0.1/10", &[]).unwrap();
        // 100.64.0.1/10 masked is 100.64.0.0/10 — writing the host address
        // into an `ip rule` selector would match a single address, and every
        // client would keep leaving through the other VPN.
        assert_eq!(plan.selector, "100.64.0.0/10");
    }

    #[test]
    fn a_gateway_address_without_a_prefix_is_refused_by_name() {
        assert_eq!(
            plan("helios0", "100.64.0.1", &[]),
            Err(RoutingError::BadTunnelAddress("100.64.0.1".into()))
        );
    }

    #[test]
    fn every_admitted_peer_gets_a_host_route_on_the_tunnel_interface() {
        let plan = plan(
            "helios0",
            "100.64.0.1/10",
            &[peer("100.64.98.223/32"), peer("100.65.3.7/32")],
        )
        .unwrap();
        let commands = plan.commands();
        assert!(commands.iter().any(|c| {
            c.join(" ") == "route replace 100.64.98.223/32 dev helios0 src 100.64.0.1 table 51820"
        }));
        assert!(commands.iter().any(|c| {
            c.join(" ") == "route replace 100.65.3.7/32 dev helios0 src 100.64.0.1 table 51820"
        }));
    }

    #[test]
    fn the_rule_comes_after_the_routes_it_points_at() {
        let plan = plan("helios0", "100.64.0.1/10", &[peer("100.64.98.223/32")]).unwrap();
        let commands = plan.commands();
        let rule = commands
            .iter()
            .position(|c| c.first().map(String::as_str) == Some("rule"))
            .expect("the plan installs a rule");
        let route = commands
            .iter()
            .position(|c| c.get(1).map(String::as_str) == Some("replace"))
            .expect("the plan installs a route");
        assert!(
            route < rule,
            "a rule pointing at a table still being filled sends packets to a lookup with no \
             answer: {commands:?}"
        );
    }

    #[test]
    fn the_table_is_cleared_before_it_is_refilled() {
        let plan = plan("helios0", "100.64.0.1/10", &[peer("100.64.98.223/32")]).unwrap();
        let commands = plan.commands();
        assert_eq!(
            commands.first().map(|c| c.join(" ")),
            Some("route flush table 51820".to_string()),
            "a revoked peer keeps its route otherwise, and the gateway keeps routing to a \
             client it no longer admits"
        );
    }

    #[test]
    fn no_peer_means_no_rule() {
        let plan = plan("helios0", "100.64.0.1/10", &[]).unwrap();
        assert!(
            !plan
                .commands()
                .iter()
                .any(|c| c.first().map(String::as_str) == Some("rule")),
            "an empty table behind a rule costs a lookup and pins nothing"
        );
    }

    #[test]
    fn wider_and_ipv6_peer_networks_are_left_alone() {
        // Neither is something the IPAM produces, and carrying a wider prefix
        // into our table would capture addresses that are not ours — exactly
        // the behaviour this module exists to stop another VPN from having.
        let plan = plan(
            "helios0",
            "100.64.0.1/10",
            &[
                peer("100.64.98.223/32"),
                peer("10.0.0.0/8"),
                peer("fd00::1/128"),
            ],
        )
        .unwrap();
        assert_eq!(plan.vips, vec!["100.64.98.223/32".to_string()]);
    }

    #[test]
    fn a_zero_length_prefix_does_not_shift_out_of_range() {
        // `u32::MAX << 32` is undefined in C and a panic in debug Rust; the
        // selector for a /0 has to be produced without shifting.
        assert_eq!(
            network_of(Ipv4Addr::new(10, 1, 2, 3), 0),
            Ipv4Addr::UNSPECIFIED
        );
    }

    fn rendered(commands: &[Vec<String>]) -> Vec<String> {
        commands.iter().map(|c| c.join(" ")).collect()
    }

    fn dual_stack_peer(v4: &str, v6: &str) -> PeerConfig {
        let mut peer = peer(v4);
        peer.allowed_ips.push(v6.into());
        peer
    }

    fn prefix() -> TunnelPrefixV6 {
        "fd3c:91a2:7e04::1/64".parse().unwrap()
    }

    /// Criterion 6: the IPv4 sequence is the one this module always ran,
    /// command for command, and a peer's IPv6 entry does not change it.
    #[test]
    fn the_ipv4_sequence_is_unchanged_by_ipv6_allowed_ips() {
        let expected = [
            "route flush table 51820",
            "route replace 100.64.98.223/32 dev helios0 src 100.64.0.1 table 51820",
            "route replace 100.65.3.7/32 dev helios0 src 100.64.0.1 table 51820",
            "rule add to 100.64.0.0/10 lookup 51820 priority 32000",
        ];
        let v4_only = plan(
            "helios0",
            "100.64.0.1/10",
            &[peer("100.64.98.223/32"), peer("100.65.3.7/32")],
        )
        .unwrap();
        let dual = plan(
            "helios0",
            "100.64.0.1/10",
            &[
                dual_stack_peer("100.64.98.223/32", "fd3c:91a2:7e04::2/128"),
                peer("100.65.3.7/32"),
            ],
        )
        .unwrap();
        assert_eq!(rendered(&v4_only.commands()), expected);
        assert_eq!(rendered(&dual.commands()), expected);
        assert_eq!(
            rendered(&[rule_delete(Family::V4)]),
            ["rule del priority 32000"]
        );
        assert_eq!(
            rendered(&[table_flush(Family::V4)]),
            ["route flush table 51820"]
        );
    }

    /// §6.3: one `/128` per peer, `src <prefix>::1`, then the rule for the
    /// `/64` — flush first, rule last, all in the IPv6 family.
    #[test]
    fn the_ipv6_sequence_mirrors_the_ipv4_one_in_its_own_family() {
        let plan = plan_v6(
            "helios0",
            prefix(),
            &[
                dual_stack_peer(
                    "100.64.98.223/32",
                    "fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517/128",
                ),
                peer("100.65.3.7/32"),
                dual_stack_peer("100.65.3.8/32", "fd3c:91a2:7e04::3/128"),
            ],
        );
        assert_eq!(
            rendered(&plan.commands()),
            [
                "-6 route flush table 51820",
                "-6 route replace fd3c:91a2:7e04:0:8a1f:3b2c:9d40:e517/128 dev helios0 \
                 src fd3c:91a2:7e04::1 table 51820",
                "-6 route replace fd3c:91a2:7e04::3/128 dev helios0 src fd3c:91a2:7e04::1 \
                 table 51820",
                "-6 rule add to fd3c:91a2:7e04::/64 lookup 51820 priority 32000",
            ]
        );
    }

    #[test]
    fn each_family_is_flushed_and_withdrawn_on_its_own() {
        assert_eq!(
            rendered(&[rule_delete(Family::V6), table_flush(Family::V6)]),
            ["-6 rule del priority 32000", "-6 route flush table 51820"]
        );
        // The flush tolerance recognises both families' table flush, and
        // nothing else: a failed route or rule is never forgiven.
        assert!(is_table_flush(&table_flush(Family::V4)));
        assert!(is_table_flush(&table_flush(Family::V6)));
        assert!(!is_table_flush(&rule_delete(Family::V6)));
        assert!(!is_table_flush(&Family::V6.ip(
            "route replace fd3c:91a2:7e04::3/128 dev helios0 src fd3c:91a2:7e04::1 table 51820"
        )));
    }

    #[test]
    fn no_ipv6_peer_means_no_ipv6_rule() {
        let plan = plan_v6("helios0", prefix(), &[peer("100.64.98.223/32")]);
        assert_eq!(
            rendered(&plan.commands()),
            ["-6 route flush table 51820"],
            "an empty table behind a rule costs a lookup and pins nothing"
        );
    }

    #[test]
    fn ipv6_routes_keep_only_hosts_of_the_tunnel_prefix() {
        let plan = plan_v6(
            "helios0",
            prefix(),
            &[
                dual_stack_peer("100.64.98.223/32", "fd3c:91a2:7e04::2/128"),
                dual_stack_peer("100.64.98.224/32", "fd00:1:2::5/128"),
                dual_stack_peer("100.64.98.225/32", "fd3c:91a2:7e04::/64"),
            ],
        );
        assert_eq!(plan.vips, ["fd3c:91a2:7e04::2/128"]);
        assert_eq!(plan.selector, "fd3c:91a2:7e04::/64");
        assert_eq!(plan.source.to_string(), "fd3c:91a2:7e04::1");
    }
}
