//! Astra's client for the gateway's lifecycle routes.

use super::*;

/// Astra's typed client for the routes above.
///
/// It opens one connection per call and closes it. Not thrift: a rotation is a
/// handful of requests an hour, a pooled connection would have to be
/// revalidated against a certificate that may have been rotated meanwhile, and
/// a fresh handshake is the cheapest way to know the pin still holds.
pub struct GatewayLifecycleClient {
    http: PinnedHttpClient,
}

impl GatewayLifecycleClient {
    pub fn new(address: SocketAddr, tls: rustls::ClientConfig) -> Self {
        Self {
            http: PinnedHttpClient::new(address, tls, INTERNAL_SERVER_NAME),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.http.address
    }

    /// Hands a staging authorization to the gateway and returns its receipt.
    pub async fn stage(
        &self,
        authorization: &ClientCertificateStageAuthorization,
    ) -> Result<aether::certificates::client::GatewayCertificateStageReceipt, ChannelError> {
        let body = serde_json::to_vec(authorization)
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        let answer = self
            .http
            .request("POST", STAGE_PATH, Some(body), None)
            .await?;
        serde_json::from_slice(&answer).map_err(|error| ChannelError::Body(error.to_string()))
    }

    /// Relays a recovery commit for a client that has no tunnel (spec §7.3).
    pub async fn commit_recovery(&self, relayed: &RelayedStageCommit) -> Result<(), ChannelError> {
        let body =
            serde_json::to_vec(relayed).map_err(|error| ChannelError::Body(error.to_string()))?;
        self.http
            .request("POST", STAGE_COMMIT_PATH, Some(body), None)
            .await?;
        Ok(())
    }

    /// Applies a signed revocation.
    pub async fn revoke(
        &self,
        revocation: &EmergencyCertificateRevocation,
    ) -> Result<(), ChannelError> {
        let body = serde_json::to_vec(revocation)
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        self.http
            .request("POST", REVOKE_PATH, Some(body), None)
            .await?;
        Ok(())
    }

    /// Reads back one peer's bounded state.
    pub async fn peer_state(
        &self,
        identity: &WireGuardKey,
    ) -> Result<PeerCertificateStateView, ChannelError> {
        // A WireGuard key is base64 and therefore contains `/`, `+` and `=`: it
        // goes into the path percent-encoded, or it silently becomes several
        // path segments and the route stops matching.
        let path = format!(
            "{INTERNAL_PREFIX}state/{}",
            percent_encode_segment(&identity.to_base64())
        );
        let answer = self.http.request("GET", &path, None, None).await?;
        serde_json::from_slice(&answer).map_err(|error| ChannelError::Body(error.to_string()))
    }

    /// Lists every peer the gateway holds a certificate record for.
    pub async fn peer_keys(&self) -> Result<Vec<WireGuardKey>, ChannelError> {
        let answer = self.http.request("GET", PEERS_PATH, None, None).await?;
        let view: PeerKeysView = serde_json::from_slice(&answer)
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        Ok(view.peers)
    }

    /// Reads the leaf the gateway serves, so a receipt can be verified under
    /// the key that actually signed it.
    /// Leaves a signed transaction for the peer the manifest names (§8.1.1).
    ///
    /// The gateway queues it and hands the fragments to that peer as it polls.
    /// Nothing crosses back: there is no receipt to sign here, because the
    /// gateway attests nothing about a transaction it did not author.
    pub async fn distribute(&self, distribution: &TrustDistribution) -> Result<(), ChannelError> {
        let body = serde_json::to_vec(distribution)
            .map_err(|error| ChannelError::Body(error.to_string()))?;
        self.http
            .request("POST", DISTRIBUTION_PATH, Some(body), None)
            .await?;
        Ok(())
    }

    pub async fn gateway_identity(&self) -> Result<GatewayIdentityView, ChannelError> {
        let answer = self
            .http
            .request("GET", GATEWAY_IDENTITY_PATH, None, None)
            .await?;
        serde_json::from_slice(&answer).map_err(|error| ChannelError::Body(error.to_string()))
    }

    pub async fn gateway_transition_published(
        &self,
        published: &GatewayTransitionPublished,
    ) -> Result<(), ChannelError> {
        let body =
            serde_json::to_vec(published).map_err(|error| ChannelError::Body(error.to_string()))?;
        self.http
            .request("POST", GATEWAY_PUBLISHED_PATH, Some(body), None)
            .await?;
        Ok(())
    }
}
