//! The gateway's client for Astra's routes, and the operator bearer token
//! it relays.

use super::*;

/// The gateway's typed client for Astra's private routes.
///
/// One connection per call, like [`GatewayLifecycleClient`] and for the same
/// reason: a rotation is a handful of requests, and a fresh handshake is the
/// cheapest way to know the pin still holds.
pub struct AstraLifecycleClient {
    http: PinnedHttpClient,
}

impl AstraLifecycleClient {
    pub fn new(address: SocketAddr, tls: rustls::ClientConfig) -> Self {
        Self {
            http: PinnedHttpClient::new(address, tls, ASTRA_INTERNAL_SERVER_NAME),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.http.address
    }

    /// Relays one client's rotation request and returns the operation it
    /// opened — always `awaiting_operator`, never a certificate.
    pub async fn request_rotation(
        &self,
        relayed: &RelayedRotationRequest,
    ) -> Result<ClientRenewalOperationView, ChannelError> {
        self.post(ROTATION_REQUEST_PATH, relayed, None).await
    }

    /// Asks the authority to build the transaction this peer is missing.
    pub async fn prepare_trust_update(
        &self,
        relayed: &RelayedTrustUpdatePreparation,
    ) -> Result<PreparedTrustUpdate, ChannelError> {
        self.post(TRUST_UPDATE_PREPARE_PATH, relayed, None).await
    }

    /// Reads one operation on behalf of the peer that owns it.
    pub async fn operation(
        &self,
        operation: &Id16,
        query: &RelayedOperationQuery,
    ) -> Result<ClientRenewalOperationView, ChannelError> {
        self.post(&operation_path("operations", operation), query, None)
            .await
    }

    /// Fetches what the companion has to display and answer.
    pub async fn signer_request(
        &self,
        operation: &Id16,
        token: &str,
        query: &RelayedOperationQuery,
    ) -> Result<ClientRenewalSignerRequest, ChannelError> {
        self.post(
            &operation_path("signer-requests", operation),
            query,
            Some(token),
        )
        .await
    }

    /// Delivers the operator's assertion and returns the operation it produced.
    pub async fn signer_result(
        &self,
        operation: &Id16,
        token: &str,
        result: &ClientRenewalSignerResult,
    ) -> Result<ClientRenewalOperationView, ChannelError> {
        self.post(
            &operation_path("signer-results", operation),
            result,
            Some(token),
        )
        .await
    }

    // -- The operator ceremony, relayed from inside the tunnel (spec §8.5) --
    //
    // Four calls, one per surface the public origin exposes, and no fifth. The
    // administrator travels in the body on every one of them for the reason
    // the caller does on a renewal: on this link the authenticated party is
    // the gateway, and the authority has to be told who it resolved.

    /// Reads one campaign operation, on behalf of an administrator.
    pub async fn operator_operation(
        &self,
        operation: &Id16,
        relayed: &RelayedOperatorCampaign,
    ) -> Result<SigningOperationView, ChannelError> {
        self.post_bounded(
            &operator_path("operations", &operation.to_string()),
            relayed,
            None,
            MAX_OPERATOR_ANSWER_BYTES,
        )
        .await
    }

    /// Reads everything waiting for an operator. No capability token crosses.
    pub async fn operator_pending(
        &self,
        relayed: &RelayedOperatorCampaign,
    ) -> Result<OperatorPendingList, ChannelError> {
        self.post_bounded(
            OPERATOR_PENDING_ROUTE,
            relayed,
            None,
            MAX_OPERATOR_ANSWER_BYTES,
        )
        .await
    }

    /// Fetches what the companion has to display before it asks for a touch.
    pub async fn operator_signer_request(
        &self,
        operation: &Id16,
        token: &str,
        relayed: &RelayedOperatorCampaign,
    ) -> Result<OperatorSignerRequestResponse, ChannelError> {
        self.post_bounded(
            &operator_path("signer-requests", &operation.to_string()),
            relayed,
            Some(token),
            MAX_OPERATOR_ANSWER_BYTES,
        )
        .await
    }

    /// Downloads the encrypted vault this campaign names.
    ///
    /// Bytes rather than a decoded object: this process holds no key-slot
    /// secret, cannot read the file and has no business parsing it. The
    /// fingerprint is compared against the operation's **signed** request on
    /// the authority side, exactly as on the public origin.
    pub async fn operator_encrypted_vault(
        &self,
        fingerprint: &aether::certificates::encoding::Fingerprint,
        token: &str,
        relayed: &RelayedOperatorCampaign,
    ) -> Result<Vec<u8>, ChannelError> {
        let body =
            serde_json::to_vec(relayed).map_err(|error| ChannelError::Body(error.to_string()))?;
        let answer = self
            .http
            .request_bounded(
                "POST",
                &operator_path("vaults", &fingerprint.to_string()),
                Some(body),
                Some(token),
                MAX_OPERATOR_ANSWER_BYTES,
            )
            .await?;
        Ok(answer.to_vec())
    }

    /// Delivers the operator's assertion and returns the operation it produced.
    pub async fn operator_signer_result(
        &self,
        operation: &Id16,
        token: &str,
        relayed: &RelayedOperatorSignerResult,
    ) -> Result<SigningOperationView, ChannelError> {
        self.post_bounded(
            &operator_path("signer-results", &operation.to_string()),
            relayed,
            Some(token),
            MAX_OPERATOR_ANSWER_BYTES,
        )
        .await
    }

    /// Opens a campaign for a relayed administrator. No bearer token: opening
    /// carries no capability.
    pub async fn operator_open(
        &self,
        relayed: &RelayedOperatorOpen,
    ) -> Result<OperatorOpened, ChannelError> {
        self.post_bounded(
            OPERATOR_OPEN_ROUTE,
            relayed,
            None,
            MAX_OPERATOR_ANSWER_BYTES,
        )
        .await
    }

    async fn post<B: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
    ) -> Result<R, ChannelError> {
        let body =
            serde_json::to_vec(body).map_err(|error| ChannelError::Body(error.to_string()))?;
        let answer = self.http.request("POST", path, Some(body), bearer).await?;
        serde_json::from_slice(&answer).map_err(|error| ChannelError::Body(error.to_string()))
    }

    async fn post_bounded<B: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        bearer: Option<&str>,
        max_answer_bytes: usize,
    ) -> Result<R, ChannelError> {
        let body =
            serde_json::to_vec(body).map_err(|error| ChannelError::Body(error.to_string()))?;
        if body.len() > MAX_OPERATOR_RELAY_BODY_BYTES {
            return Err(ChannelError::Body(format!(
                "operator relay body is {} bytes, above the private route ceiling",
                body.len()
            )));
        }
        let answer = self
            .http
            .request_bounded("POST", path, Some(body), bearer, max_answer_bytes)
            .await?;
        serde_json::from_slice(&answer).map_err(|error| ChannelError::Body(error.to_string()))
    }
}

/// Builds one of Astra's operation paths.
///
/// The identifier is hexadecimal, so nothing in it can escape a path segment
/// today — and it goes through the same percent-encoder as a WireGuard key
/// anyway, because "this value happens to be safe" is how the next change of
/// encoding introduces a traversal.
/// Builds one of Astra's operator paths.
///
/// Its own builder rather than a parameter on [`operation_path`]: the two
/// prefixes address two stores, and a single function with a prefix argument
/// is one wrong argument away from relaying a campaign read onto a peer's
/// renewal. The identifier goes through the same percent-encoder.
pub(super) fn operator_path(collection: &str, identifier: &str) -> String {
    format!(
        "{ASTRA_OPERATOR_PREFIX}{collection}/{}",
        percent_encode_segment(identifier)
    )
}

pub(super) fn operation_path(collection: &str, operation: &Id16) -> String {
    format!(
        "{ASTRA_INTERNAL_PREFIX}{collection}/{}",
        percent_encode_segment(&operation.to_string())
    )
}

/// The `Authorization: Bearer` value of a capability token, or `None`.
///
/// One reader and one writer: the token never travels in a URL, a cookie or a
/// log (spec §8.2), and a second extraction site is how it ends up in one.
pub fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
