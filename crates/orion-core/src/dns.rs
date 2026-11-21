//! Which DNS servers a tunnel client applies, and why.
//!
//! [`decide`] is the one place where the resolvers of a tunnel are chosen.
//! Each backend applies its answer and reports it as [`crate::events::DnsCheck`];
//! no backend re-derives the choice on its own.

use std::net::Ipv4Addr;
use std::time::Duration;

use aether::client_dns::{
    validate_resolvers, ClientDnsProposal, CLIENT_DNS_PATH, DEFAULT_CLIENT_DNS,
};
use serde::{Deserialize, Serialize};

use crate::backend::{EventSink, VpnController};
use crate::config::{ClientProfile, ProfileKind};
use crate::events::{ClientEvent, DnsCheck};
use crate::profile_import::{tunnel_capture, TunnelCapture};
use crate::telemetry::{error_chain, REQUEST_TIMEOUT};

/// Most attempts at reading the gateway's proposal while it is unreachable.
pub const PROPOSAL_ATTEMPTS: u32 = 5;

/// Pause between two attempts that found the gateway unreachable.
pub const PROPOSAL_RETRY_DELAY: Duration = Duration::from_secs(3);

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

/// Why the gateway's resolver proposal could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProposalError {
    /// The gateway answers, but has no route for the proposal: an older Helios.
    #[error("la passerelle ne propose pas de DNS (version antérieure)")]
    NotServed,
    /// No usable answer this time: connection, timeout, or an HTTP error.
    #[error("passerelle injoignable : {0}")]
    Unreachable(String),
    /// The gateway answered, but what it sent is not a valid proposal.
    #[error("proposition DNS refusée : {0}")]
    Invalid(String),
}

/// Reads the resolver proposal the gateway serves to this client, through the
/// tunnel at `heliosd_url`.
///
/// A 404 means the gateway predates the proposal. A proposal whose resolvers
/// are refused by [`validate_resolvers`] is an error, never corrected.
pub async fn fetch_proposal(heliosd_url: &str) -> Result<ClientDnsProposal, ProposalError> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        // Same reasoning as the telemetry probe: this URL is inside the
        // tunnel, and an inherited proxy cannot route it.
        .no_proxy()
        .build()
        .map_err(|error| ProposalError::Unreachable(error_chain(&error)))?;
    let url = format!("{}{CLIENT_DNS_PATH}", heliosd_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|error| ProposalError::Unreachable(error_chain(&error)))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(ProposalError::NotServed);
    }
    if !status.is_success() {
        return Err(ProposalError::Unreachable(format!("réponse HTTP {status}")));
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| ProposalError::Unreachable(error_chain(&error)))?;
    let proposal: ClientDnsProposal =
        serde_json::from_slice(&body).map_err(|error| ProposalError::Invalid(error.to_string()))?;
    validate_resolvers(&proposal.servers)
        .map_err(|error| ProposalError::Invalid(error.to_string()))?;
    Ok(proposal)
}

/// Reads the gateway's proposal once the tunnel is up, and hands it to the
/// backend.
///
/// An unreachable gateway is asked again, up to [`PROPOSAL_ATTEMPTS`] times,
/// `retry_delay` apart. A gateway without the route, or one whose proposal is
/// refused, is not asked again. A failure is reported once, as
/// [`DnsCheck::ProposalUnread`]; the resolvers mounted with the tunnel stay in
/// place, and nothing else changes.
pub async fn follow_gateway_proposal(
    controller: &VpnController,
    profile: &ClientProfile,
    heliosd_url: &str,
    retry_delay: Duration,
    sink: &EventSink,
) {
    let mut last_detail = String::new();
    for attempt in 1..=PROPOSAL_ATTEMPTS {
        if attempt > 1 {
            tokio::time::sleep(retry_delay).await;
        }
        match fetch_proposal(heliosd_url).await {
            Ok(proposal) => {
                if let Err(error) = controller.apply_gateway_dns(profile, proposal, sink).await {
                    sink(ClientEvent::dns(DnsCheck::Failed {
                        reason: format!("résolveurs DNS non appliqués : {error}"),
                    }));
                }
                return;
            }
            Err(ProposalError::Unreachable(detail)) => {
                tracing::debug!(
                    target: "orion_core::dns",
                    attempt,
                    detail = %detail,
                    "gateway DNS proposal not read yet"
                );
                last_detail = detail;
            }
            Err(error) => {
                sink(ClientEvent::dns(DnsCheck::ProposalUnread {
                    reason: error.to_string(),
                }));
                return;
            }
        }
    }
    sink(ClientEvent::dns(DnsCheck::ProposalUnread {
        reason: format!("passerelle injoignable après {PROPOSAL_ATTEMPTS} essais : {last_detail}"),
    }));
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

    fn response(status: &str, body: &str) -> Option<String> {
        Some(format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ))
    }

    /// Serves one request per entry, in order: a canned response, or `None`
    /// to close the connection without answering.
    async fn serve_each(responses: Vec<Option<String>>) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local listener");
        let address = listener.local_addr().expect("local address");
        tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.expect("request");
                let mut request = vec![0u8; 4096];
                let _ = stream.read(&mut request).await;
                if let Some(response) = response {
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .expect("response");
                }
            }
        });
        format!("http://{address}/")
    }

    #[tokio::test]
    async fn fetch_reads_the_proposal() {
        let url = serve_each(vec![response("200 OK", r#"{"servers":["1.0.0.1"]}"#)]).await;
        assert_eq!(
            fetch_proposal(&url).await,
            Ok(ClientDnsProposal {
                servers: vec![GATEWAY]
            })
        );
    }

    #[tokio::test]
    async fn fetch_maps_404_to_not_served() {
        let url = serve_each(vec![response("404 Not Found", "")]).await;
        assert_eq!(fetch_proposal(&url).await, Err(ProposalError::NotServed));
    }

    #[tokio::test]
    async fn fetch_refuses_a_private_resolver() {
        let url = serve_each(vec![response("200 OK", r#"{"servers":["10.0.0.1"]}"#)]).await;
        assert!(
            matches!(
                fetch_proposal(&url).await,
                Err(ProposalError::Invalid(detail)) if detail.contains("10.0.0.1")
            ),
            "a private resolver is refused, never corrected"
        );
    }

    #[tokio::test]
    async fn fetch_reports_a_closed_port_as_unreachable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("local listener");
        let url = format!("http://{}/", listener.local_addr().expect("address"));
        drop(listener);
        assert!(matches!(
            fetch_proposal(&url).await,
            Err(ProposalError::Unreachable(_))
        ));
    }

    #[cfg(feature = "certificate-signing")]
    fn collector() -> (
        EventSink,
        std::sync::Arc<std::sync::Mutex<Vec<ClientEvent>>>,
    ) {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = std::sync::Arc::clone(&log);
        let sink: EventSink = std::sync::Arc::new(move |event| {
            captured.lock().unwrap().push(event);
        });
        (sink, log)
    }

    #[cfg(feature = "certificate-signing")]
    fn dns_checks(log: &std::sync::Arc<std::sync::Mutex<Vec<ClientEvent>>>) -> Vec<DnsCheck> {
        log.lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                ClientEvent::Dns { dns } => Some(dns.clone()),
                _ => None,
            })
            .collect()
    }

    /// A Helios tunnel mounted on the dry-run backend, with the mount's DNS
    /// applied, and the controller that will receive the gateway's proposal.
    #[cfg(feature = "certificate-signing")]
    async fn mounted_helios() -> (
        std::sync::Arc<crate::backend::dryrun::DryRunBackend>,
        VpnController,
        ClientProfile,
        EventSink,
        std::sync::Arc<std::sync::Mutex<Vec<ClientEvent>>>,
    ) {
        use crate::backend::{dryrun::DryRunBackend, VpnBackend as _};

        let mut dryrun = DryRunBackend::default();
        dryrun.negotiate_delay = Duration::ZERO;
        let backend = std::sync::Arc::new(dryrun);
        let controller = VpnController::new(backend.clone());
        let (sink, log) = collector();
        let profile = crate::backend::dryrun::tests::helios();
        backend.up(&profile, &sink).await.expect("dry-run up");
        (backend, controller, profile, sink, log)
    }

    #[cfg(feature = "certificate-signing")]
    #[tokio::test]
    async fn an_old_gateway_keeps_the_mount_dns() {
        let url = serve_each(vec![response("404 Not Found", "")]).await;
        let (backend, controller, profile, sink, log) = mounted_helios().await;

        follow_gateway_proposal(&controller, &profile, &url, Duration::ZERO, &sink).await;

        let checks = dns_checks(&log);
        assert_eq!(
            checks.len(),
            2,
            "the mount's decision, then one unread proposal: {checks:?}"
        );
        assert!(matches!(
            checks.last(),
            Some(DnsCheck::ProposalUnread { .. })
        ));
        assert_eq!(
            backend.last_dns_decision(),
            Some(DnsDecision::Apply {
                servers: DEFAULT_CLIENT_DNS.to_vec(),
                origin: DnsOrigin::Default,
            }),
            "the mount's resolvers stay in place"
        );
    }

    #[cfg(feature = "certificate-signing")]
    #[tokio::test]
    async fn an_unreachable_gateway_is_asked_again_then_its_proposal_applies() {
        let url = serve_each(vec![None, response("200 OK", r#"{"servers":["1.0.0.1"]}"#)]).await;
        let (backend, controller, profile, sink, log) = mounted_helios().await;

        follow_gateway_proposal(&controller, &profile, &url, Duration::ZERO, &sink).await;

        assert_eq!(
            backend.last_dns_decision(),
            Some(DnsDecision::Apply {
                servers: vec![GATEWAY],
                origin: DnsOrigin::Gateway,
            })
        );
        assert!(
            !dns_checks(&log)
                .iter()
                .any(|check| matches!(check, DnsCheck::ProposalUnread { .. })),
            "a proposal read on a retry is not a failure"
        );
    }

    #[cfg(feature = "certificate-signing")]
    #[tokio::test]
    async fn an_unreachable_gateway_is_reported_once_after_every_attempt() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("local listener");
        let url = format!("http://{}/", listener.local_addr().expect("address"));
        drop(listener);
        let (backend, controller, profile, sink, log) = mounted_helios().await;

        follow_gateway_proposal(&controller, &profile, &url, Duration::ZERO, &sink).await;

        let checks = dns_checks(&log);
        let unread: Vec<&DnsCheck> = checks
            .iter()
            .filter(|check| matches!(check, DnsCheck::ProposalUnread { .. }))
            .collect();
        assert_eq!(unread.len(), 1, "{checks:?}");
        assert!(
            matches!(
                unread[0],
                DnsCheck::ProposalUnread { reason } if reason.contains("5 essais")
            ),
            "{checks:?}"
        );
        assert_eq!(
            backend.last_dns_decision(),
            Some(DnsDecision::Apply {
                servers: DEFAULT_CLIENT_DNS.to_vec(),
                origin: DnsOrigin::Default,
            })
        );
    }
}
