//! Which DNS servers a tunnel client applies, and why.
//!
//! [`decide`] is the one place where the resolvers of a tunnel are chosen.
//! Each backend applies its answer and reports it as [`crate::events::DnsCheck`];
//! no backend re-derives the choice on its own.

use std::net::Ipv4Addr;

use aether::client_dns::{ClientDnsProposal, DEFAULT_CLIENT_DNS};
use serde::{Deserialize, Serialize};

use crate::config::{ClientProfile, ProfileKind};
use crate::events::DnsCheck;
use crate::profile_import::{tunnel_capture, TunnelCapture};

/// Where the resolvers of an applied decision come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsOrigin {
    /// Proposed by the gateway to a Helios client.
    Gateway,
    /// Helios client whose gateway proposed nothing: the built-in default.
    Default,
    /// Chosen by the operator in a Helios profile.
    Custom,
    /// Written in a classic profile, which has no gateway to ask.
    Profile,
}

/// Why the system resolvers stay in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsLeaveReason {
    /// The profile does not capture all of IPv4: names resolved through the
    /// tunnel would be the only part of the traffic it protects.
    NotFullTunnel,
    /// The gateway proposed an empty list, and nothing else was chosen.
    GatewayDeclines,
    /// A classic profile without a `dns` line: there is no resolver to apply.
    NoResolver,
}

/// The resolvers to apply to the tunnel, or the reason to apply none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsDecision {
    Apply {
        servers: Vec<Ipv4Addr>,
        origin: DnsOrigin,
    },
    Leave {
        reason: DnsLeaveReason,
    },
}

impl DnsDecision {
    /// What the user is told once the decision is applied.
    pub fn check(&self) -> DnsCheck {
        match self {
            DnsDecision::Apply { servers, origin } => DnsCheck::Applied {
                servers: servers.clone(),
                origin: *origin,
            },
            DnsDecision::Leave { reason } => DnsCheck::Left { reason: *reason },
        }
    }
}

/// Chooses the resolvers of a tunnel, from the profile and the gateway's
/// proposal (`None` when none was received).
///
/// The rules apply in this order:
/// 1. the profile does not capture all of IPv4 → leave;
/// 2. a Helios profile whose gateway proposed an empty list → leave;
/// 3. the profile carries `dns` → apply it (`Custom` for Helios, `Profile`
///    for classic);
/// 4. a Helios profile with a non-empty proposal → apply it (`Gateway`);
/// 5. a Helios profile without proposal → apply the default (`Default`);
/// 6. a classic profile without `dns` → leave.
pub fn decide(profile: &ClientProfile, proposal: Option<&ClientDnsProposal>) -> DnsDecision {
    // Rule 1: names resolved outside the tunnel would be the traffic it
    // leaves unprotected, so only a full IPv4 capture takes a resolver.
    if !matches!(
        tunnel_capture(&profile.allowed_ips),
        TunnelCapture::Full | TunnelCapture::Ipv4Only
    ) {
        return DnsDecision::Leave {
            reason: DnsLeaveReason::NotFullTunnel,
        };
    }

    let helios = profile.kind() == ProfileKind::HeliosKeyNegotiation;
    let gateway = proposal.map(|proposal| proposal.servers.as_slice());

    // Rule 2: an empty proposal is the gateway declining, even over a custom
    // choice of the operator.
    if helios && matches!(gateway, Some(servers) if servers.is_empty()) {
        return DnsDecision::Leave {
            reason: DnsLeaveReason::GatewayDeclines,
        };
    }

    // Rule 3: a resolver written in the profile is the operator's choice.
    if let Some(servers) = &profile.dns {
        let origin = if helios {
            DnsOrigin::Custom
        } else {
            DnsOrigin::Profile
        };
        return DnsDecision::Apply {
            servers: servers.clone(),
            origin,
        };
    }

    if !helios {
        // Rule 6: a classic profile has no gateway to ask, and no default.
        return DnsDecision::Leave {
            reason: DnsLeaveReason::NoResolver,
        };
    }

    // Rules 4 and 5: the gateway's proposal, else the built-in default.
    match gateway {
        Some(servers) if !servers.is_empty() => DnsDecision::Apply {
            servers: servers.to_vec(),
            origin: DnsOrigin::Gateway,
        },
        _ => DnsDecision::Apply {
            servers: DEFAULT_CLIENT_DNS.to_vec(),
            origin: DnsOrigin::Default,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_ALLOWED_IPS;

    const FULL: &str = DEFAULT_ALLOWED_IPS;
    const IPV4_ONLY: &str = "0.0.0.0/0";
    const SPLIT: &str = "10.0.0.0/8";

    fn helios(allowed_ips: &str, dns: Option<Vec<Ipv4Addr>>) -> ClientProfile {
        ClientProfile {
            allowed_ips: allowed_ips.into(),
            dns,
            profile_type: Some(ProfileKind::HeliosKeyNegotiation),
            ..ClientProfile::default()
        }
    }

    fn classic(allowed_ips: &str, dns: Option<Vec<Ipv4Addr>>) -> ClientProfile {
        ClientProfile {
            allowed_ips: allowed_ips.into(),
            dns,
            profile_type: Some(ProfileKind::Classic),
            ..ClientProfile::default()
        }
    }

    fn proposal(servers: &[Ipv4Addr]) -> ClientDnsProposal {
        ClientDnsProposal {
            servers: servers.to_vec(),
        }
    }

    const CUSTOM: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(1, 0, 0, 1);

    #[test]
    fn a_split_tunnel_leaves_the_system_resolvers() {
        let profile = helios(SPLIT, None);
        assert_eq!(
            decide(&profile, Some(&proposal(&[GATEWAY]))),
            DnsDecision::Leave {
                reason: DnsLeaveReason::NotFullTunnel
            }
        );
    }

    #[test]
    fn a_split_tunnel_ignores_even_a_custom_choice() {
        let profile = helios(SPLIT, Some(vec![CUSTOM]));
        assert_eq!(
            decide(&profile, None),
            DnsDecision::Leave {
                reason: DnsLeaveReason::NotFullTunnel
            }
        );
    }

    #[test]
    fn an_ipv4_only_capture_still_gets_dns() {
        let profile = helios(IPV4_ONLY, None);
        assert_eq!(
            decide(&profile, None),
            DnsDecision::Apply {
                servers: DEFAULT_CLIENT_DNS.to_vec(),
                origin: DnsOrigin::Default,
            }
        );
    }

    #[test]
    fn an_empty_gateway_proposal_declines() {
        let profile = helios(FULL, None);
        assert_eq!(
            decide(&profile, Some(&proposal(&[]))),
            DnsDecision::Leave {
                reason: DnsLeaveReason::GatewayDeclines
            }
        );
    }

    #[test]
    fn an_empty_proposal_clears_even_a_custom_choice() {
        let profile = helios(FULL, Some(vec![CUSTOM]));
        assert_eq!(
            decide(&profile, Some(&proposal(&[]))),
            DnsDecision::Leave {
                reason: DnsLeaveReason::GatewayDeclines
            }
        );
    }

    #[test]
    fn a_profile_dns_is_custom_for_helios_and_profile_for_classic() {
        let servers = vec![CUSTOM];
        assert_eq!(
            decide(
                &helios(FULL, Some(servers.clone())),
                Some(&proposal(&[GATEWAY]))
            ),
            DnsDecision::Apply {
                servers: servers.clone(),
                origin: DnsOrigin::Custom,
            }
        );
        assert_eq!(
            decide(&classic(FULL, Some(servers.clone())), None),
            DnsDecision::Apply {
                servers,
                origin: DnsOrigin::Profile,
            }
        );
    }

    #[test]
    fn a_helios_profile_takes_the_gateway_proposal() {
        let profile = helios(FULL, None);
        assert_eq!(
            decide(&profile, Some(&proposal(&[GATEWAY]))),
            DnsDecision::Apply {
                servers: vec![GATEWAY],
                origin: DnsOrigin::Gateway,
            }
        );
    }

    #[test]
    fn a_helios_profile_without_proposal_gets_the_default() {
        let profile = helios(FULL, None);
        assert_eq!(
            decide(&profile, None),
            DnsDecision::Apply {
                servers: DEFAULT_CLIENT_DNS.to_vec(),
                origin: DnsOrigin::Default,
            }
        );
    }

    #[test]
    fn a_classic_profile_without_dns_has_no_resolver() {
        assert_eq!(
            decide(&classic(FULL, None), None),
            DnsDecision::Leave {
                reason: DnsLeaveReason::NoResolver
            }
        );
    }

    #[test]
    fn a_classic_profile_ignores_a_gateway_proposal() {
        assert_eq!(
            decide(&classic(FULL, None), Some(&proposal(&[GATEWAY]))),
            DnsDecision::Leave {
                reason: DnsLeaveReason::NoResolver
            }
        );
    }

    #[test]
    fn a_decision_reports_what_it_applied() {
        let applied = DnsDecision::Apply {
            servers: vec![GATEWAY],
            origin: DnsOrigin::Gateway,
        };
        assert_eq!(
            applied.check(),
            DnsCheck::Applied {
                servers: vec![GATEWAY],
                origin: DnsOrigin::Gateway,
            }
        );
        let left = DnsDecision::Leave {
            reason: DnsLeaveReason::NoResolver,
        };
        assert_eq!(
            left.check(),
            DnsCheck::Left {
                reason: DnsLeaveReason::NoResolver
            }
        );
    }
}
