//! Tests for the ruleset renderer, grouped by the behavior they protect.

use super::super::*;
use super::support::{every_state, policy, render, text};

/// The default stays closed: a gateway normally has a fixed address, and
/// opening DHCP without reason would widen fail-closed for nothing.
#[test]
fn dhcp_is_closed_by_default() {
    let rs = render(&policy(), TunnelState::Down);
    for kind in [ChainKind::Input, ChainKind::Output] {
        assert!(
            !text(&rs, kind)
                .iter()
                .any(|r| r.contains("dport 67") || r.contains("dport 68")),
            "DHCP open without the configuration requesting it"
        );
    }
}

/// Without these two rules, a gateway addressed by lease loses its
/// address on the first renewal — hence its tunnel and its
/// administration — several hours after a startup that seemed
/// successful.
#[test]
fn allowed_dhcp_stays_scoped_to_wan() {
    let mut p = policy();
    p.allow_dhcp_on_wan = true;

    for st in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
        let rs = render(&p, st);
        assert!(
            text(&rs, ChainKind::Output)
                .iter()
                .any(|r| r.starts_with("oifname \"eth0\" udp dport 67 accept")),
            "state {st:?}: the renewal request must be able to go out"
        );
        assert!(
            text(&rs, ChainKind::Input)
                .iter()
                .any(|r| r.starts_with("iifname \"eth0\" udp dport 68 accept")),
            "state {st:?}: the server's reply must be able to come in"
        );
        // The opening must only exist on the WAN: on the LAN it would let
        // a client speak DHCP through the gateway.
        assert!(
            !text(&rs, ChainKind::Forward)
                .iter()
                .any(|r| r.contains("dport 67") || r.contains("dport 68")),
            "state {st:?}: DHCP must not traverse the gateway"
        );
    }
}

/// The DHCPv6 client follows the same flag, closed by default.
#[test]
fn dhcpv6_is_closed_by_default() {
    for st in every_state() {
        let rs = render(&policy(), st);
        assert!(
            !rs.rules
                .iter()
                .any(|rule| rule.matches.iter().any(|m| matches!(
                    m,
                    Match::DestPort {
                        port: 546 | 547,
                        ..
                    }
                ))),
            "state {st:?}: DHCPv6 open without the configuration requesting it"
        );
    }
}

/// "The WAN address comes from a lease" holds for both families: the same
/// flag opens the DHCPv6 client, on the WAN, IPv6 only, in every state —
/// and never on the LAN nor through the gateway.
#[test]
fn allowed_dhcpv6_stays_scoped_to_wan_and_ipv6() {
    let mut p = policy();
    p.allow_dhcp_on_wan = true;

    for st in every_state() {
        let rs = render(&p, st);
        let dhcpv6: Vec<&Rule> = rs
            .rules
            .iter()
            .filter(|rule| {
                rule.matches.iter().any(|m| {
                    matches!(
                        m,
                        Match::DestPort {
                            port: 546 | 547,
                            ..
                        }
                    )
                })
            })
            .collect();
        assert_eq!(
            dhcpv6
                .iter()
                .map(|rule| (rule.chain, rule.matches.clone()))
                .collect::<Vec<_>>(),
            [
                (
                    ChainKind::Output,
                    vec![
                        Match::OutIface("eth0".into()),
                        Match::Family(AddressFamily::Ipv6),
                        Match::DestPort {
                            port: 547,
                            proto: L4::Udp
                        },
                    ]
                ),
                (
                    ChainKind::Input,
                    vec![
                        Match::InIface("eth0".into()),
                        Match::Family(AddressFamily::Ipv6),
                        Match::DestPort {
                            port: 546,
                            proto: L4::Udp
                        },
                    ]
                ),
            ],
            "state {st:?}"
        );
        assert!(dhcpv6.iter().all(|rule| rule.verdict == Verdict::Accept));
        assert_eq!(
            text(&rs, ChainKind::Output)
                .iter()
                .filter(|r| r.as_str() == "oifname \"eth0\" meta nfproto ipv6 udp dport 547 accept")
                .count(),
            1,
            "state {st:?}: the display must show the guard the backend applies"
        );
    }
}

/// Closed by default like everything else — but the failure it produces
/// is a name-resolution timeout, which points nowhere near the firewall.
#[test]
fn gateway_egress_is_closed_by_default() {
    let rs = render(&policy(), TunnelState::Up);
    for port in ["dport 53", "dport 123", "dport 443"] {
        assert!(
            !text(&rs, ChainKind::Output)
                .iter()
                .any(|r| r.contains(port)),
            "{port} open without the configuration requesting it"
        );
    }
}

/// The three openings the gateway needs for itself, and only in `output`:
/// this is what it emits, never what it relays.
#[test]
fn gateway_egress_opens_resolution_time_and_packages_on_the_wan() {
    let mut p = policy();
    p.allow_gateway_egress = true;
    let rs = render(&p, TunnelState::Up);
    let out = text(&rs, ChainKind::Output);

    for expected in [
        "oifname \"eth0\" udp dport 53 accept",
        "oifname \"eth0\" tcp dport { 53, 80, 443 } accept",
        "oifname \"eth0\" udp dport 123 accept",
    ] {
        assert!(
            out.iter().any(|r| r == expected),
            "missing rule: {expected}"
        );
    }

    for kind in [ChainKind::Input, ChainKind::Forward] {
        assert!(
            !text(&rs, kind)
                .iter()
                .any(|r| r.contains("dport 53") || r.contains("dport 123")),
            "the gateway's own egress must open nothing in {}",
            kind.as_str()
        );
    }
}

/// The moment an operator needs this opening is an upgrade, and that is
/// exactly a moment when the tunnel may be down. A flag that followed the
/// tunnel state would be closed precisely when it is needed —
/// `helios update` runs `apt-get` on the gateway itself.
#[test]
fn gateway_egress_does_not_follow_the_tunnel_state() {
    let mut p = policy();
    p.allow_gateway_egress = true;

    for st in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
        assert!(
            text(&render(&p, st), ChainKind::Output)
                .iter()
                .any(|r| r == "oifname \"eth0\" udp dport 53 accept"),
            "state {st:?}: the gateway must still be able to resolve"
        );
    }
}

#[test]
fn meshnet_is_scoped_to_its_mark_interface_peers_and_services() {
    let mut p = policy();
    p.allow_gateway_egress = true;
    p.nordvpn_meshnet = Some(aether::NordvpnMeshnetPolicy {
        iface: "nordlynx".into(),
        fwmark: 0xe1f1,
        peer_cidrs: vec!["100.70.36.212/32".into()],
        traffic_routing_peer_cidrs: Vec::new(),
        local_network_peer_cidrs: Vec::new(),
        inbound_tcp_ports: vec![22, 9100],
        inbound_udp_ports: vec![51830],
        allow_icmp: true,
    });

    for state in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
        let rs = render(&p, state);
        let output = text(&rs, ChainKind::Output);
        let input = text(&rs, ChainKind::Input);

        assert!(output
            .iter()
            .any(|rule| rule == "oifname \"eth0\" meta mark 0xe1f1 accept"));
        assert!(output
            .iter()
            .any(|rule| { rule == "oifname \"nordlynx\" ip daddr 100.70.36.212/32 accept" }));
        assert!(input.iter().any(|rule| {
            rule == "iifname \"nordlynx\" ip saddr 100.70.36.212/32 meta l4proto icmp accept"
        }));
        assert!(input.iter().any(|rule| {
            rule == "iifname \"nordlynx\" ip saddr 100.70.36.212/32 tcp dport { 22, 9100 } accept"
        }));
        assert!(input.iter().any(|rule| {
            rule == "iifname \"nordlynx\" ip saddr 100.70.36.212/32 udp dport { 51830 } accept"
        }));
        assert!(!text(&rs, ChainKind::Forward)
            .iter()
            .any(|rule| rule.contains("nordlynx") || rule.contains("0xe1f1")));
        assert!(!rs.rules.iter().any(|rule| {
            rule.matches
                .contains(&Match::SourceNet("100.70.36.213/32".parse().unwrap()))
        }));
    }
}

#[test]
fn meshnet_routing_mirrors_per_peer_routing_and_local_network_permissions() {
    let mut p = policy();
    p.wan_ifaces = vec!["eth0".into(), "wlan0".into()];
    p.lan_ifaces = vec!["lan0".into()];
    p.allow_gateway_egress = true;
    p.nordvpn_meshnet = Some(aether::NordvpnMeshnetPolicy {
        iface: "nordlynx".into(),
        fwmark: 0xe1f1,
        peer_cidrs: vec!["100.70.36.212/32".into(), "100.70.36.213/32".into()],
        traffic_routing_peer_cidrs: vec!["100.70.36.212/32".into(), "100.70.36.213/32".into()],
        local_network_peer_cidrs: vec!["100.70.36.213/32".into()],
        inbound_tcp_ports: vec![22, 49111],
        inbound_udp_ports: Vec::new(),
        allow_icmp: true,
    });

    for state in [TunnelState::Down, TunnelState::Connecting, TunnelState::Up] {
        let forward = text(&render(&p, state), ChainKind::Forward);

        for private_network in PRIVATE_IPV4_CIDRS {
            assert!(forward.iter().any(|rule| {
                rule
                    == &format!(
                        "iifname \"nordlynx\" ip saddr 100.70.36.212/32 ip daddr {private_network} drop"
                    )
            }));
            assert!(!forward.iter().any(|rule| {
                rule.contains("100.70.36.213/32") && rule.contains(private_network)
            }));
        }
        let private_drop = forward
            .iter()
            .position(|rule| {
                rule
                    == "iifname \"nordlynx\" ip saddr 100.70.36.212/32 ip daddr 192.168.0.0/16 drop"
            })
            .unwrap();
        let wan_accept = forward
            .iter()
            .position(|rule| {
                rule == "iifname \"nordlynx\" ip saddr 100.70.36.212/32 oifname \"eth0\" accept"
            })
            .unwrap();
        assert!(
            private_drop < wan_accept,
            "the broad WAN acceptance must not precede the private-network denial"
        );
        for wan in ["eth0", "wlan0"] {
            for peer in ["100.70.36.212/32", "100.70.36.213/32"] {
                assert!(forward.iter().any(|rule| {
                    rule == &format!(
                        "iifname \"nordlynx\" ip saddr {peer} oifname \"{wan}\" accept"
                    )
                }));
            }
        }
        assert!(forward.iter().any(|rule| {
            rule == "iifname \"nordlynx\" ip saddr 100.70.36.213/32 oifname \"lan0\" accept"
        }));
        assert!(!forward.iter().any(|rule| {
            rule.contains("100.70.36.212/32") && rule.contains("oifname \"lan0\"")
        }));
    }
}

/// The `forward` rules naming the tunnel interface, as displayed.
fn tunnel_forward(rs: &Ruleset) -> Vec<String> {
    text(rs, ChainKind::Forward)
        .into_iter()
        .filter(|r| r.contains("iifname \"helios0\""))
        .collect()
}

/// The IPv6 rejection of the single uplink: present in every state, it
/// refuses and opens nothing.
const IPV6_REJECTION: &str =
    "meta nfproto ipv6 iifname \"helios0\" oifname \"eth0\" reject with icmpx admin-prohibited";

/// Closed by default: a gateway granting access to internal resources has
/// no reason to route Internet traffic. The only `forward` rule naming the
/// tunnel interface is then the IPv6 rejection.
#[test]
fn client_internet_egress_is_closed_by_default() {
    let rs = render(&policy(), TunnelState::Up);
    assert!(
        rs.masquerade_out.is_empty(),
        "NAT applied without requesting it"
    );
    assert_eq!(tunnel_forward(&rs), [IPV6_REJECTION]);
}

/// NAT and forward must appear **and disappear** together with the
/// tunnel. A masquerade that survived the tunnel going down would let out
/// in the clear what the kill-switch just cut off.
#[test]
fn client_internet_egress_follows_tunnel_state_exactly() {
    let mut p = policy();
    p.allow_client_internet = true;

    let up = render(&p, TunnelState::Up);
    assert_eq!(up.masquerade_out, vec!["eth0".to_string()]);
    assert!(
        text(&up, ChainKind::Forward)
            .iter()
            .any(|r| r == "meta nfproto ipv4 iifname \"helios0\" oifname \"eth0\" accept"),
        "client forward rule missing in the Up state: {:?}",
        text(&up, ChainKind::Forward)
    );

    for st in [
        TunnelState::Down,
        TunnelState::Connecting,
        TunnelState::Failed,
    ] {
        let rs = render(&p, st);
        assert!(
            rs.masquerade_out.is_empty(),
            "state {st:?}: NAT must not exist outside the tunnel"
        );
        assert_eq!(
            tunnel_forward(&rs),
            [IPV6_REJECTION],
            "state {st:?}: client traffic must not traverse"
        );
    }
}

/// The opening is unidirectional: the client goes out, but nothing comes
/// in towards the gateway's LAN. The return path is covered by
/// `established`.
#[test]
fn client_internet_egress_does_not_open_lan_to_clients() {
    let mut p = policy();
    p.allow_client_internet = true;
    let rs = render(&p, TunnelState::Up);

    // Asserted on the structured matches rather than on a text prefix: the
    // egress rule now opens with its family guard, and a prefix check would
    // pass vacuously.
    assert!(
        !rs.chain(ChainKind::Forward).any(|rule| {
            rule.matches.contains(&Match::InIface("helios0".into()))
                && rule.matches.contains(&Match::OutIface("eth1".into()))
        }),
        "a client must not reach the gateway's LAN"
    );
}

#[test]
fn no_inbound_opening_without_server_role() {
    let mut p = policy();
    p.wg_listen_port = None;
    let rs = render(&p, TunnelState::Down);
    assert!(!text(&rs, ChainKind::Input)
        .iter()
        .any(|r| r.contains("udp dport 51820")));
    assert!(!text(&rs, ChainKind::Output)
        .iter()
        .any(|r| r.contains("udp sport 51820")));
}
