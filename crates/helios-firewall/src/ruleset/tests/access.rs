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
        assert_eq!(render(&policy(), st).default_verdict, Verdict::Drop);
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
    assert!(rs
        .rules
        .iter()
        .any(|r| r.to_string().contains("192.168.1.1") && r.to_string().contains("dport")));
    assert!(!text(&rs, ChainKind::Forward)
        .iter()
        .any(|r| r.contains("iifname \"eth1\" oifname")));
    assert_eq!(rs.default_verdict, Verdict::Drop);
}

#[test]
fn captive_portal_without_gateway_allows_all_http() {
    let rs = render(&policy(), TunnelState::CaptivePortal);
    assert!(rs
        .rules
        .iter()
        .any(|r| r.to_string().contains("tcp dport { 80, 443 } accept")));
}

#[test]
fn split_tunnel_adds_bypass_rules() {
    let mut p = policy();
    p.split_tunnel_cidrs = vec!["192.168.1.0/24".into(), "10.0.0.0/8".into()];
    let rs = render(&p, TunnelState::Up);
    let fwd = text(&rs, ChainKind::Forward);
    assert!(fwd.iter().any(|r| r == "ip daddr 192.168.1.0/24 accept"));
    assert!(fwd.iter().any(|r| r == "ip daddr 10.0.0.0/8 accept"));
    assert!(fwd.iter().any(|r| r.contains("iifname \"eth1\"")));
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
