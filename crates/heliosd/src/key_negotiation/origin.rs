//! Where a negotiation comes from: the public port, or through the tunnel.
//!
//! A connection whose source is a peer's VIP arrived through WireGuard, which
//! only delivers it for a peer it has authenticated. Such a connection is an
//! in-tunnel PSK renewal and nothing else (design 2026-10-09 §4.3): it may not
//! post a first PSK, nor select another mode than `ml_kem`.

use std::net::IpAddr;

use aether::key_negotiation::ProtectionMode;

use super::SlotState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Origin {
    Public,
    Tunnel { peer_public_key: String },
}

/// Classifies a source against the peers currently admitted.
///
/// Read from the live configuration at each call, so a hot reload that moves
/// a VIP is honoured at the next connection.
pub(super) fn classify(network: &aether::NetworkConfig, source: IpAddr) -> Origin {
    let source = aether::net::canonical_source(source);
    network
        .peers
        .iter()
        .find(|peer| holds(peer, source))
        .map_or(Origin::Public, |peer| Origin::Tunnel {
            peer_public_key: peer.public_key.clone(),
        })
}

fn holds(peer: &aether::WgPeer, source: IpAddr) -> bool {
    match source {
        IpAddr::V4(source) => {
            peer.address
                .split('/')
                .next()
                .and_then(|host| host.trim().parse::<std::net::Ipv4Addr>().ok())
                == Some(source)
        }
        IpAddr::V6(source) => peer.address_v6 == Some(source),
    }
}

/// May a connection through the tunnel prepare in this mode, over this slot?
pub(super) fn tunnel_renewal_allowed(mode: ProtectionMode, slot: &SlotState) -> bool {
    mode == ProtectionMode::MlKem && matches!(slot, SlotState::Committed(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_negotiation::InstalledPsk;

    fn network() -> aether::NetworkConfig {
        let mut network = aether::NetworkConfig::default();
        network.peers.push(aether::WgPeer {
            name: "laptop".into(),
            public_key: "laptop-key".into(),
            address: "100.64.1.2/32".into(),
            address_v6: Some("fd00::2".parse().unwrap()),
            admin: false,
            preshared_key: None,
            key_negotiation_certificate_sha256: None,
            key_negotiation_pq_certificate_sha256: None,
            minimum_key_negotiation_mode: ProtectionMode::Classic,
            persistent_keepalive_secs: aether::config::DEFAULT_PERSISTENT_KEEPALIVE_SECS,
        });
        network
    }

    #[test]
    fn a_peer_vip_is_a_tunnel_source() {
        assert_eq!(
            classify(&network(), "100.64.1.2".parse().unwrap()),
            Origin::Tunnel {
                peer_public_key: "laptop-key".into()
            }
        );
        assert_eq!(
            classify(&network(), "fd00::2".parse().unwrap()),
            Origin::Tunnel {
                peer_public_key: "laptop-key".into()
            }
        );
    }

    #[test]
    fn classify_canonicalizes_a_mapped_source() {
        assert_eq!(
            classify(&network(), "::ffff:100.64.1.2".parse().unwrap()),
            Origin::Tunnel {
                peer_public_key: "laptop-key".into()
            }
        );
    }

    #[test]
    fn any_other_address_is_public() {
        assert_eq!(
            classify(&network(), "203.0.113.50".parse().unwrap()),
            Origin::Public
        );
        assert_eq!(
            classify(&network(), "100.64.1.3".parse().unwrap()),
            Origin::Public
        );
    }

    #[test]
    fn only_a_committed_ml_kem_slot_may_be_renewed_in_the_tunnel() {
        let committed = SlotState::Committed(InstalledPsk {
            transaction_id: [1; 16],
            public_key: "laptop-key".into(),
            address: "100.64.1.2/32".into(),
            installed_at: std::time::Instant::now(),
        });
        assert!(tunnel_renewal_allowed(ProtectionMode::MlKem, &committed));
        assert!(!tunnel_renewal_allowed(
            ProtectionMode::StaticPsk,
            &committed
        ));
        assert!(!tunnel_renewal_allowed(
            ProtectionMode::MlKem,
            &SlotState::Empty
        ));
        assert!(!tunnel_renewal_allowed(
            ProtectionMode::MlKem,
            &SlotState::ConfiguredStatic
        ));
    }
}
