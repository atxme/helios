//! The DNS resolvers a tunnel client is proposed.

use super::*;
use aether::client_dns::ClientDnsProposal;

/// Resolvers proposed to the admitted peer that calls, through the tunnel.
///
/// Behind `require_peer`: the source VIP names the peer, and the answer is
/// the same for every peer. The configuration is read at each call, so a
/// reload of `network.toml` applies without a restart.
pub async fn client_dns(State(s): State<AppState>) -> Json<ClientDnsProposal> {
    let network = s.network.read().await;
    Json(network.client_dns_proposal())
}
