//! Resolvers pushed to tunnel clients, and the checks they must pass.
//!
//! The gateway tells each Helios client which DNS servers to use through the
//! tunnel. The list lives here, once, so the gateway (`helios-api`) and the
//! client (`orion-core`) cannot disagree about the default or about what a
//! valid resolver is.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Resolvers proposed to clients when the operator does not choose others:
/// DNS4EU, unfiltered.
pub const DEFAULT_CLIENT_DNS: [Ipv4Addr; 2] = [
    Ipv4Addr::new(86, 54, 11, 100),
    Ipv4Addr::new(86, 54, 11, 200),
];

/// Most resolvers a client accepts in one replacement.
pub const CLIENT_DNS_MAX: usize = 3;

/// API path on which a client fetches its resolver proposal.
pub const CLIENT_DNS_PATH: &str = "/api/client/dns";

/// Why a list of resolvers is refused. Refused, never corrected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClientDnsError {
    #[error("le résolveur {0} n'est pas une adresse publique unicast")]
    NotPublic(Ipv4Addr),
    #[error("le résolveur {0} est présent plusieurs fois")]
    Duplicate(Ipv4Addr),
    #[error("{0} résolveurs demandés, {CLIENT_DNS_MAX} au plus")]
    TooMany(usize),
}

/// The resolver proposal a client receives from the gateway.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClientDnsProposal {
    pub servers: Vec<Ipv4Addr>,
}

/// Checks a resolver list: at most [`CLIENT_DNS_MAX`] entries, each one a
/// public unicast IPv4 address, no duplicates. An empty list is valid and
/// means "propose nothing".
pub fn validate_resolvers(servers: &[Ipv4Addr]) -> Result<(), ClientDnsError> {
    if servers.len() > CLIENT_DNS_MAX {
        return Err(ClientDnsError::TooMany(servers.len()));
    }
    for (index, server) in servers.iter().enumerate() {
        if !is_public_unicast(*server) {
            return Err(ClientDnsError::NotPublic(*server));
        }
        if servers[..index].contains(server) {
            return Err(ClientDnsError::Duplicate(*server));
        }
    }
    Ok(())
}

/// `Ipv4Addr::is_global` is unstable, so the refused ranges are spelled out.
fn is_public_unicast(address: Ipv4Addr) -> bool {
    let [a, b, _, _] = address.octets();
    let private = a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b));
    let reserved = a == 0 || a == 127 || (a == 169 && b == 254) || a >= 224;
    !(private || reserved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn default_is_dns4eu_unfiltered() {
        assert_eq!(
            DEFAULT_CLIENT_DNS,
            [
                Ipv4Addr::new(86, 54, 11, 100),
                Ipv4Addr::new(86, 54, 11, 200)
            ]
        );
        assert!(validate_resolvers(&DEFAULT_CLIENT_DNS).is_ok());
    }

    #[test]
    fn validate_refuses_non_public_ranges() {
        let refused = [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ];
        for address in refused {
            let address: Ipv4Addr = address.parse().unwrap();
            assert_eq!(
                validate_resolvers(&[address]),
                Err(ClientDnsError::NotPublic(address)),
                "{address} must be refused"
            );
        }
    }

    #[test]
    fn validate_refuses_duplicates_and_more_than_three() {
        let public = Ipv4Addr::new(1, 1, 1, 1);
        assert_eq!(
            validate_resolvers(&[public, public]),
            Err(ClientDnsError::Duplicate(public))
        );
        let four = [
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::new(86, 54, 11, 100),
        ];
        assert_eq!(validate_resolvers(&four), Err(ClientDnsError::TooMany(4)));
        assert!(validate_resolvers(&[]).is_ok());
    }
}
