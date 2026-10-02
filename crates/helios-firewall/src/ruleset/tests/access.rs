//! Tests for the ruleset renderer, grouped by the behavior they protect.

use super::super::*;
use super::support::{policy, render, text};

#[test]
fn invalid_conntrack_is_dropped_before_every_opening() {
    let mut p = policy();
    p.admin_port = Some(8080);
    p.admin_iface = Some("helios0".into());
    p.allow_tunnel_icmp = true;

    let rs = render(&p, TunnelState::Up);
    for chain in [ChainKind::Input, ChainKind::Forward, ChainKind::Output] {
        let rules = rs.chain(chain).collect::<Vec<_>>();
        assert_eq!(
            rules.first().map(|rule| (&rule.matches, rule.verdict)),
            Some((
                &vec![Match::ConnectionState(ConnectionStates::INVALID)],
                Verdict::Drop,
            )),
            "{chain:?}: invalid traffic must be dropped before any accept rule"
        );
        assert_eq!(
            rules.first().map(|rule| rule.actions.as_slice()),
            Some([Action::Counter(Counter::Anonymous)].as_slice()),
            "{chain:?}: invalid drops must remain observable"
        );
    }

    let input = rs.chain(ChainKind::Input).collect::<Vec<_>>();
    let invalid = input
        .iter()
        .position(|rule| rule.matches == vec![Match::ConnectionState(ConnectionStates::INVALID)])
        .unwrap();
    let admin_accept = input
        .iter()
        .position(|rule| {
            rule.verdict == Verdict::Accept
                && rule.matches.contains(&Match::DestPort {
                    port: 8080,
                    proto: L4::Tcp,
                })
        })
        .unwrap();
    let established = input
        .iter()
        .position(|rule| {
            rule.matches
                == vec![Match::ConnectionState(
                    ConnectionStates::ESTABLISHED_RELATED,
                )]
        })
        .unwrap();

    assert!(invalid < admin_accept);
    assert!(admin_accept < established);
}

#[test]
fn invalid_networks_never_enter_the_structured_ir() {
    for invalid in ["not-an-address", "10.0.0.0/99", "2001:db8::/999"] {
        let mut p = policy();
        p.allow_ssh_from = vec![invalid.into()];
        assert!(
            super::super::render(&p, TunnelState::Down).is_err(),
            "invalid network {invalid} must stop ruleset compilation"
        );
    }
}

/// The split-tunnel CIDRs are only read in `Up`: rendering the down state
/// alone would let an invalid one through, to fail at the next promotion.
#[test]
fn a_policy_check_covers_the_states_that_do_not_read_a_field() {
    let mut p = policy();
    p.split_tunnel_cidrs = vec!["192.168.1.0/33".into()];
    assert!(super::super::render(&p, TunnelState::Down).is_ok());

    let error = check_policy(&p).expect_err("an invalid split-tunnel CIDR must be refused");
    assert!(error.to_string().contains("192.168.1.0/33"), "{error}");
}

/// Without a LAN interface no split-tunnel bypass is rendered, but the CIDRs
/// are still parsed: an invalid one is refused whatever the topology, so the
/// API and startup checks that rely on `check_policy` stay fail closed.
#[test]
fn a_policy_check_refuses_an_invalid_split_tunnel_cidr_without_a_lan() {
    let mut p = policy();
    p.lan_ifaces = Vec::new();
    p.split_tunnel_cidrs = vec!["192.168.1.0/24".into(), "fd00::/129".into()];

    let error = check_policy(&p).expect_err("an invalid split-tunnel CIDR must be refused");
    assert!(error.to_string().contains("fd00::/129"), "{error}");
    assert!(super::super::render(&p, TunnelState::Up).is_err());
}

#[test]
fn a_policy_check_accepts_valid_dual_stack_split_tunnel_cidrs() {
    let mut p = policy();
    p.split_tunnel_cidrs = vec!["192.168.1.0/24".into(), "fd00:1::/64".into()];
    check_policy(&p).expect("valid split-tunnel CIDRs");
}

/// `TUNNEL_STATES` cannot be derived from the enum. The match below has no
/// wildcard, so a new state stops this test from compiling until it is
/// listed here and in `TUNNEL_STATES`.
#[test]
fn a_policy_check_renders_every_tunnel_state() {
    use TunnelState::{CaptivePortal, Connecting, Down, Failed, Up};
    for state in [Down, Connecting, Up, Failed, CaptivePortal] {
        match state {
            Down | Connecting | Up | Failed | CaptivePortal => {
                assert!(TUNNEL_STATES.contains(&state), "{state:?} is not checked");
            }
        }
    }
}

#[test]
fn the_public_parser_names_the_refused_entry() {
    assert!(parse_network("10.0.0.0/8").is_ok());
    assert!(parse_network("2001:db8::/32").is_ok());
    let error = parse_network("2001:db8::/129").expect_err("prefix beyond 128");
    assert!(error.to_string().contains("`2001:db8::/129`"), "{error}");
}

/// The WireGuard listener is in `input` (traffic towards the gateway),
/// LAN forward in `forward`. Confusing them would block or open the
/// wrong traffic.
#[test]
fn loopback_is_accepted_according_to_chain_direction() {
    // Regression test: `iif "lo"` used to be applied on all three
    // chains. On the output hook, a locally generated packet has no
    // ingress interface: the rule never matched and all outbound
    // loopback traffic fell under `policy drop`. Symptom observed on
    // target — any connection to 127.0.0.1 stayed hung, without being
    // refused.
    let rs = render(&policy(), TunnelState::Down);

    assert!(
        rs.chain(ChainKind::Output).any(
            |r| r.matches == vec![Match::OutIface("lo".into())] && r.verdict == Verdict::Accept
        ),
        "the output chain must accept loopback via its egress interface"
    );

    for kind in [ChainKind::Input, ChainKind::Forward] {
        assert!(
            rs.chain(kind)
                .any(|r| r.matches == vec![Match::InIface("lo".into())]
                    && r.verdict == Verdict::Accept),
            "{kind:?} must accept loopback via its ingress interface"
        );
    }
}

/// Both tunnel openings exist only when asked, and only on the tunnel.
///
/// The interface scope is the whole security argument. A source-address
/// match — listing `100.64.0.0/10` in `allow_ssh_from`, the obvious
/// shortcut — would be satisfiable from the WAN by a packet forging that
/// source, because those rules carry no interface constraint. Only
/// WireGuard puts packets on `wg_iface`, and only for an authenticated
/// peer.
#[test]
fn tunnel_icmp_and_ssh_are_opt_in_and_scoped_to_the_tunnel_interface() {
    let closed = render(&policy(), TunnelState::Up);
    for forbidden in [
        "meta l4proto icmp",
        "meta l4proto ipv6-icmp",
        "tcp dport 22",
    ] {
        assert!(
            !text(&closed, ChainKind::Input)
                .iter()
                .any(|r| r.contains(forbidden)),
            "`{forbidden}` must not appear while the flag is off"
        );
    }

    let mut open = policy();
    open.allow_tunnel_icmp = true;
    open.allow_ssh_over_tunnel = true;
    let rs = render(&open, TunnelState::Up);
    let input = text(&rs, ChainKind::Input);
    assert!(input
        .iter()
        .any(|r| r == "iifname \"helios0\" meta l4proto icmp accept"));
    assert!(input
        .iter()
        .any(|r| r == "iifname \"helios0\" meta l4proto ipv6-icmp accept"));
    assert!(input
        .iter()
        .any(|r| r == "iifname \"helios0\" tcp dport 22 accept"));

    // Neither may ever be rendered without its interface match, whatever
    // the state: that rule alone is what keeps them off the WAN.
    for state in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
        for rule in render(&open, state).chain(ChainKind::Input) {
            let touches_tunnel_opening = rule
                .matches
                .iter()
                .any(|criterion| matches!(criterion, Match::Icmp(_)))
                || rule.matches.contains(&Match::DestPort {
                    port: 22,
                    proto: L4::Tcp,
                });
            if touches_tunnel_opening && rule.verdict == Verdict::Accept {
                assert!(
                    rule.matches.contains(&Match::InIface("helios0".into())),
                    "{state:?}: `{rule}` opens without being scoped to the tunnel"
                );
            }
        }
    }
}

/// The way back in when the tunnel is the thing that is broken.
///
/// The incident this encodes: a deployment ran *through* the Helios
/// tunnel, read its own source address — a peer VIP — and pinned SSH to
/// it via `allow_ssh_from`. Restarting `heliosd` dropped the tunnel, the
/// rule stopped matching, and the only permitted SSH source no longer
/// existed. `admin_ifaces` has to hold in exactly the states that
/// followed, which is why `Down` and `Connecting` are asserted here and
/// not just `Up`.
#[test]
fn admin_ifaces_open_ssh_in_every_state_scoped_to_their_interface() {
    let mut p = policy();
    p.admin_ifaces = vec!["tailscale0".into(), "nordlynx".into()];

    for state in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
        let input = text(&render(&p, state), ChainKind::Input);
        for iface in ["tailscale0", "nordlynx"] {
            assert!(
                input
                    .iter()
                    .any(|r| r == &format!("iifname \"{iface}\" tcp dport 22 accept")),
                "{state:?}: {iface} must keep administrative SSH open"
            );
        }
    }

    // Never by address: an overlay carries several, and they move. The
    // interface match is what covers v4 and v6 at once, today and after
    // the next reassignment.
    for rule in render(&p, TunnelState::Down).chain(ChainKind::Input) {
        if rule.verdict == Verdict::Accept
            && rule.matches.contains(&Match::DestPort {
                port: 22,
                proto: L4::Tcp,
            })
        {
            assert!(
                rule.matches
                    .iter()
                    .any(|m| matches!(m, Match::InIface(_) | Match::SourceNet(_))),
                "`{rule}` opens SSH with neither an interface nor a source scope"
            );
        }
    }
}

/// An empty list renders nothing at all — the default stays fail-closed.
#[test]
fn no_admin_iface_opens_no_ssh() {
    let input = text(&render(&policy(), TunnelState::Down), ChainKind::Input);
    assert!(
        !input.iter().any(|r| r.contains("tcp dport 22")),
        "SSH must stay closed when nothing declares an administration path"
    );
}

/// A gateway that cannot bring up its interface must open neither.
///
/// Same gate as the listener ports: a rule naming an interface that does
/// not exist is at best dead weight, and at worst a rule that starts
/// matching the day something else claims that name.
#[test]
fn the_tunnel_openings_need_a_wireguard_interface() {
    let mut p = policy();
    p.allow_tunnel_icmp = true;
    p.allow_ssh_over_tunnel = true;
    p.wg_iface = String::new();
    let rs = render(&p, TunnelState::Up);
    for forbidden in [
        "meta l4proto icmp",
        "meta l4proto ipv6-icmp",
        "tcp dport 22",
    ] {
        assert!(
            !text(&rs, ChainKind::Input)
                .iter()
                .any(|r| r.contains(forbidden)),
            "`{forbidden}` must not be rendered without a tunnel interface"
        );
    }
}

#[test]
fn rules_are_in_the_right_chain() {
    let rs = render(&policy(), TunnelState::Up);
    assert!(text(&rs, ChainKind::Input)
        .iter()
        .any(|r| r.contains("udp dport 51820")));
    assert!(text(&rs, ChainKind::Forward)
        .iter()
        .any(|r| r.contains("iifname \"eth1\" oifname \"eth0\"")));
    // Outbound transport to a static peer is in `output`.
    assert!(text(&rs, ChainKind::Output)
        .iter()
        .any(|r| r.contains("ip daddr 203.0.113.10")));
}

#[test]
fn up_allows_lan_forward() {
    let rs = render(&policy(), TunnelState::Up);
    assert!(text(&rs, ChainKind::Forward)
        .iter()
        .any(|r| r == "iifname \"eth1\" oifname \"eth0\" accept"));
}

#[test]
fn fail_closed_default_is_always_drop() {
    for st in [
        TunnelState::Down,
        TunnelState::Failed,
        TunnelState::Connecting,
    ] {
        assert_eq!(render(&policy(), st).default_verdict, DefaultVerdict::Drop);
    }
}

#[test]
fn admin_api_restricted_to_tunnel_interface() {
    let mut p = policy();
    p.admin_port = Some(8080);
    p.admin_iface = Some("helios0".into());
    let rs = render(&p, TunnelState::Up);
    let input = text(&rs, ChainKind::Input);

    // The scoped accept must precede the generic drop.
    let accept = input.iter().position(|r| r.contains("helios0")).unwrap();
    let drop = input
        .iter()
        .position(|r| r == "tcp dport 8080 drop")
        .unwrap();
    assert!(
        accept < drop,
        "the scoped accept must take precedence over the drop"
    );
}

/// The speedtest opening follows the tunnel interface, not the API's.
///
/// It used to be rendered inside the administration block, which is
/// skipped entirely when `admin_iface` is unset. On such a gateway nothing
/// opened the speedtest port, every probe was dropped in `input`, and the
/// client — with no answer and no refusal — reported a timeout against a
/// daemon that was listening.
#[test]
fn speedtest_stays_open_on_the_tunnel_without_an_administration_interface() {
    let mut p = policy();
    p.admin_port = None;
    p.admin_iface = None;
    let input = text(&render(&p, TunnelState::Up), ChainKind::Input);

    for proto in ["tcp", "udp"] {
        assert!(
            input
                .iter()
                .any(|r| r.contains(&format!("{proto} dport {SPEEDTEST_PORT}"))
                    && r.contains("iifname \"helios0\"")),
            "the speedtest must stay reachable through the tunnel ({proto})"
        );
    }
    // Never unscoped: only WireGuard puts packets on the tunnel interface.
    assert!(!input
        .iter()
        .any(|r| r == &format!("tcp dport {SPEEDTEST_PORT} accept")
            || r == &format!("udp dport {SPEEDTEST_PORT} accept")));
}

/// Nothing to scope the opening to means no opening at all.
#[test]
fn speedtest_is_closed_without_a_tunnel_interface() {
    let mut p = policy();
    p.wg_iface = String::new();
    let rs = render(&p, TunnelState::Up);
    for chain in [ChainKind::Input, ChainKind::Output] {
        assert!(
            !text(&rs, chain)
                .iter()
                .any(|r| r.contains(&SPEEDTEST_PORT.to_string())),
            "no speedtest opening without a tunnel interface"
        );
    }
}

/// Closed unless asked for: an always-open `iperf3` is always-open surface.
#[test]
fn iperf_is_closed_until_a_port_is_configured() {
    let rs = render(&policy(), TunnelState::Up);
    for chain in [ChainKind::Input, ChainKind::Output] {
        assert!(
            !text(&rs, chain).iter().any(|r| r.contains("5202")),
            "no iperf opening without a configured port"
        );
    }
}

/// The half that is easy to forget, and whose absence looks like the peer
/// being at fault: the gateway acting as `iperf3 -c` opens a **new**
/// outbound flow on the tunnel interface, which the drop policy takes
/// unless the `output` chain accepts it.
#[test]
fn iperf_opens_both_directions_on_the_tunnel_interface() {
    let mut p = policy();
    p.iperf_port = Some(5202);
    let rs = render(&p, TunnelState::Up);

    let input = text(&rs, ChainKind::Input);
    let output = text(&rs, ChainKind::Output);
    for proto in ["tcp", "udp"] {
        assert!(
            input
                .iter()
                .any(|r| r.contains(&format!("{proto} dport 5202"))
                    && r.contains("iifname \"helios0\"")),
            "server on the gateway: {proto} must be accepted inbound"
        );
        assert!(
            output
                .iter()
                .any(|r| r.contains(&format!("{proto} dport 5202"))
                    && r.contains("oifname \"helios0\"")),
            "client on the gateway: {proto} must be accepted outbound"
        );
    }

    // Interface-scoped, never a bare port accept: a match on the address
    // alone would be satisfiable from the WAN by forging a CGNAT source.
    for chain in [ChainKind::Input, ChainKind::Output] {
        assert!(
            !text(&rs, chain)
                .iter()
                .any(|r| r == "tcp dport 5202 accept" || r == "udp dport 5202 accept"),
            "no unscoped iperf accept"
        );
    }
}

#[test]
fn captive_portal_allows_http_to_gateway() {
    let mut p = policy();
    p.captive_portal_gateway = Some("192.168.1.1".into());
    let rs = render(&p, TunnelState::CaptivePortal);
    assert_eq!(
        captive_portal_openings(&rs, ChainKind::Output),
        ["oifname \"eth0\" ip daddr 192.168.1.1/32 tcp dport { 80, 443 } accept"]
    );
    assert_eq!(
        captive_portal_openings(&rs, ChainKind::Forward),
        ["iifname \"eth1\" oifname \"eth0\" ip daddr 192.168.1.1/32 tcp dport { 80, 443 } accept"]
    );
    // The captive portal replaces the LAN forward, it does not add to it.
    assert!(!text(&rs, ChainKind::Forward)
        .iter()
        .any(|r| r == "iifname \"eth1\" oifname \"eth0\" accept"));
    assert_eq!(rs.default_verdict, DefaultVerdict::Drop);
}

#[test]
fn captive_portal_without_gateway_allows_all_http() {
    let rs = render(&policy(), TunnelState::CaptivePortal);
    assert_eq!(
        captive_portal_openings(&rs, ChainKind::Output),
        ["oifname \"eth0\" tcp dport { 80, 443 } accept"]
    );
    assert_eq!(
        captive_portal_openings(&rs, ChainKind::Forward),
        ["iifname \"eth1\" oifname \"eth0\" tcp dport { 80, 443 } accept"]
    );
}

/// The captive-portal openings of one chain, as text.
fn captive_portal_openings(rs: &Ruleset, chain: ChainKind) -> Vec<String> {
    let ports = Match::DestPortSet {
        ports: vec![80, 443],
        proto: L4::Tcp,
    };
    rs.chain(chain)
        .filter(|rule| rule.matches.contains(&ports))
        .map(|rule| rule.to_string())
        .collect()
}

/// The relayed opening is for the LAN; without a LAN interface there is no
/// traffic it is for, and none is rendered — with or without a known
/// gateway, with or without a tunnel interface — rather than an opening
/// scoped by the WAN alone, which the tunnel clients would reach. The
/// gateway's own opening is unchanged.
#[test]
fn captive_portal_without_a_lan_interface_relays_nothing() {
    for gateway in [Some("192.0.2.1"), None] {
        for wg_iface in ["helios0", ""] {
            let mut p = policy();
            p.lan_ifaces = Vec::new();
            p.wg_iface = wg_iface.into();
            p.captive_portal_gateway = gateway.map(str::to_string);
            let rs = render(&p, TunnelState::CaptivePortal);
            assert!(
                captive_portal_openings(&rs, ChainKind::Forward).is_empty(),
                "gateway {gateway:?}, wg_iface {wg_iface:?}: {:?}",
                text(&rs, ChainKind::Forward)
            );
            let expected = match gateway {
                Some(gw) => {
                    format!("oifname \"eth0\" ip daddr {gw}/32 tcp dport {{ 80, 443 }} accept")
                }
                None => "oifname \"eth0\" tcp dport { 80, 443 } accept".to_string(),
            };
            assert_eq!(
                captive_portal_openings(&rs, ChainKind::Output),
                [expected],
                "gateway {gateway:?}, wg_iface {wg_iface:?}"
            );
        }
    }
}

/// One relayed opening per LAN interface and WAN: LAN interfaces in policy
/// order, and the WANs in policy order for each of them. The gateway's own
/// opening stays one per WAN.
#[test]
fn captive_portal_relays_one_opening_per_lan_and_wan() {
    let mut p = policy();
    p.wan_ifaces = vec!["enp3s0".into(), "wlo1".into()];
    p.lan_ifaces = vec!["eth1".into(), "br-lan".into()];
    p.captive_portal_gateway = Some("192.0.2.1".into());
    let rs = render(&p, TunnelState::CaptivePortal);
    assert_eq!(
        captive_portal_openings(&rs, ChainKind::Output),
        [
            "oifname \"enp3s0\" ip daddr 192.0.2.1/32 tcp dport { 80, 443 } accept",
            "oifname \"wlo1\" ip daddr 192.0.2.1/32 tcp dport { 80, 443 } accept",
        ]
    );
    assert_eq!(
        captive_portal_openings(&rs, ChainKind::Forward),
        [
            "iifname \"eth1\" oifname \"enp3s0\" ip daddr 192.0.2.1/32 tcp dport { 80, 443 } accept",
            "iifname \"eth1\" oifname \"wlo1\" ip daddr 192.0.2.1/32 tcp dport { 80, 443 } accept",
            "iifname \"br-lan\" oifname \"enp3s0\" ip daddr 192.0.2.1/32 tcp dport { 80, 443 } accept",
            "iifname \"br-lan\" oifname \"wlo1\" ip daddr 192.0.2.1/32 tcp dport { 80, 443 } accept",
        ]
    );
}

/// The gateway address is parsed whatever the topology: without a LAN
/// interface no relayed opening is rendered, but an invalid address still
/// fails the render, so that `check_policy` refuses it.
#[test]
fn an_invalid_captive_portal_gateway_is_refused_without_a_lan() {
    for lan_ifaces in [vec![], vec!["eth1".to_string()]] {
        let mut p = policy();
        p.lan_ifaces = lan_ifaces.clone();
        p.captive_portal_gateway = Some("192.0.2.1/33".into());
        let error = super::super::render(&p, TunnelState::CaptivePortal)
            .expect_err("an invalid captive-portal gateway must be refused");
        assert!(
            error.to_string().contains("192.0.2.1/33"),
            "lan {lan_ifaces:?}: {error}"
        );
        assert!(check_policy(&p).is_err(), "lan {lan_ifaces:?}");
    }
}

#[test]
fn split_tunnel_adds_bypass_rules() {
    let mut p = policy();
    p.split_tunnel_cidrs = vec![
        "192.168.1.0/24".into(),
        "10.0.0.0/8".into(),
        "fd00:1::/64".into(),
    ];
    let rs = render(&p, TunnelState::Up);
    let fwd = text(&rs, ChainKind::Forward);
    let bypasses: Vec<&String> = fwd.iter().filter(|r| r.contains("daddr")).collect();
    // The bypasses apply only to traffic entering by the LAN, in either
    // family.
    assert_eq!(
        bypasses,
        [
            "iifname \"eth1\" ip daddr 192.168.1.0/24 accept",
            "iifname \"eth1\" ip daddr 10.0.0.0/8 accept",
            "iifname \"eth1\" ip6 daddr fd00:1::/64 accept",
        ]
    );
    assert!(fwd.iter().any(|r| r.contains("oifname \"eth0\"")));
}

/// The bypass is scoped to the LAN; without a LAN interface there is no
/// traffic it is for, and none is rendered — with or without a tunnel
/// interface — rather than an unscoped acceptance.
#[test]
fn split_tunnel_without_a_lan_interface_renders_no_bypass() {
    for wg_iface in ["helios0", ""] {
        let mut p = policy();
        p.lan_ifaces = Vec::new();
        p.wg_iface = wg_iface.into();
        p.split_tunnel_cidrs = vec!["192.168.1.0/24".into(), "fd00:1::/64".into()];
        let rs = render(&p, TunnelState::Up);
        assert!(
            rs.chain(ChainKind::Forward)
                .all(|rule| !rule.matches.iter().any(|m| matches!(m, Match::DestNet(_)))),
            "wg_iface {wg_iface:?}: {:?}",
            text(&rs, ChainKind::Forward)
        );
    }
}

/// One bypass per LAN interface and CIDR: LAN interfaces in policy order,
/// and the CIDRs in policy order for each of them.
#[test]
fn split_tunnel_renders_one_bypass_per_lan_and_cidr() {
    let mut p = policy();
    p.lan_ifaces = vec!["eth1".into(), "br-lan".into()];
    p.split_tunnel_cidrs = vec!["192.168.1.0/24".into(), "fd00:1::/64".into()];
    let rs = render(&p, TunnelState::Up);
    let fwd = text(&rs, ChainKind::Forward);
    let bypasses: Vec<&String> = fwd.iter().filter(|r| r.contains("daddr")).collect();
    assert_eq!(
        bypasses,
        [
            "iifname \"eth1\" ip daddr 192.168.1.0/24 accept",
            "iifname \"eth1\" ip6 daddr fd00:1::/64 accept",
            "iifname \"br-lan\" ip daddr 192.168.1.0/24 accept",
            "iifname \"br-lan\" ip6 daddr fd00:1::/64 accept",
        ]
    );
}

/// No split-tunnel bypass can be reached by a packet entering by a WAN —
/// for a global IPv6 LAN prefix, that would be an inbound opening from the
/// Internet to the LAN — nor by one entering through the tunnel interface.
/// Every rule that names a split-tunnel destination requires a LAN input
/// interface.
#[test]
fn no_split_tunnel_bypass_matches_a_packet_entering_by_a_wan() {
    let mut p = policy();
    p.wan_ifaces = vec!["enp3s0".into(), "wlo1".into()];
    p.lan_ifaces = vec!["eth1".into(), "br-lan".into()];
    p.allow_client_internet = true;
    p.split_tunnel_cidrs = vec!["192.168.50.0/24".into(), "2001:db8:50::/48".into()];
    let destinations: Vec<Match> = p
        .split_tunnel_cidrs
        .iter()
        .map(|cidr| Match::DestNet(cidr.parse().expect("a valid CIDR")))
        .collect();
    let rs = render(&p, TunnelState::Up);
    let mut bypasses = 0;
    for rule in rs
        .chain(ChainKind::Forward)
        .filter(|rule| rule.matches.iter().any(|m| destinations.contains(m)))
    {
        bypasses += 1;
        let inputs: Vec<&String> = rule
            .matches
            .iter()
            .filter_map(|m| match m {
                Match::InIface(iface) => Some(iface),
                _ => None,
            })
            .collect();
        assert!(
            !inputs.is_empty() && inputs.iter().all(|iface| p.lan_ifaces.contains(iface)),
            "`{rule}` can be reached by a packet entering by a WAN or the tunnel"
        );
    }
    assert_eq!(bypasses, p.lan_ifaces.len() * destinations.len());
}

/// MSS clamping is a mangle action, not a verdict: it lives outside of
/// `rules` and is only retained while the tunnel is operational.
#[test]
fn mss_clamping_outside_rules_and_only_when_up() {
    let mut p = policy();
    p.mss_clamp = Some(1380);
    assert_eq!(render(&p, TunnelState::Up).mss_clamp, Some(1380));
    assert_eq!(render(&p, TunnelState::Down).mss_clamp, None);
}
