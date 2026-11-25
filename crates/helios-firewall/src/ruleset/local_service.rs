//! Operator services in containers on the gateway, reached by the gateway.
//!
//! One `output` rule per declared service, naming all four coordinates like
//! the Astra openings. The replies return under `ct state established`;
//! nothing lets the container open a connection, and `forward` stays closed.
//! Rendered in every state: this traffic never leaves the machine.

use std::net::IpAddr;

use aether::FirewallPolicy;

use super::ChainKind::Output;
use super::{Match, Rule, Verdict, L4};

pub(super) fn outbound(rules: &mut Vec<Rule>, policy: &FirewallPolicy) {
    for service in &policy.local_services {
        rules.push(
            Rule::new(
                Output,
                vec![
                    Match::OutIface(service.iface.clone()),
                    Match::SourceNet(IpAddr::from(service.host).into()),
                    Match::DestNet(IpAddr::from(service.peer).into()),
                    Match::DestPort {
                        port: service.port,
                        proto: L4::Tcp,
                    },
                ],
                Verdict::Accept,
            )
            .with_note(format!("gateway to the local service {}", service.name)),
        );
    }
}
