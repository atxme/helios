//! The other direction: what Astra serves the gateway — its paths, the
//! operator identity, the relayed documents and the trust-update preparer.

use super::*;

// ---------------------------------------------------------------------------
// The other direction: the gateway dials the authority (spec §8.1.2, §8.3).
// ---------------------------------------------------------------------------

/// Path prefix Astra's private listener serves. Everything outside it is
/// refused, exactly as on the gateway's own listener.
pub const ASTRA_INTERNAL_PREFIX: &str = "/internal/v1/client-rotation/";

pub const ROTATION_REQUEST_PATH: &str = "/internal/v1/client-rotation/request";
pub const ROTATION_OPERATION_ROUTE: &str = "/internal/v1/client-rotation/operations/{operation}";
pub const ROTATION_SIGNER_REQUEST_ROUTE: &str =
    "/internal/v1/client-rotation/signer-requests/{operation}";
pub const ROTATION_SIGNER_RESULT_ROUTE: &str =
    "/internal/v1/client-rotation/signer-results/{operation}";

/// The second prefix Astra's private listener serves (spec §0.6).
///
/// Its own prefix rather than a fifth route under the rotation one: a renewal
/// is about a peer asking to be re-certified, a preparation is about a peer
/// being behind on the domain's trust. They share a link, not a subject, and
/// naming them together would make the refusal log unable to say which surface
/// was probed.
pub const ASTRA_TRUST_UPDATE_PREFIX: &str = "/internal/v1/trust-update/";

pub const TRUST_UPDATE_PREPARE_PATH: &str = "/internal/v1/trust-update/prepare";

/// The third prefix Astra's private listener serves (spec §8.5).
///
/// Its own prefix, like the two above and for the same reason: a renewal
/// belongs to one peer, a preparation to one peer's backlog, and an operator
/// campaign to no peer at all. Sharing a prefix would leave a refusal log
/// unable to say which of the three surfaces was probed — and would make it
/// look as though a client identifier and a campaign identifier were
/// interchangeable, which is exactly the confusion §8.5 forbids.
pub const ASTRA_OPERATOR_PREFIX: &str = "/internal/v1/operator/";

pub const OPERATOR_OPERATION_ROUTE: &str = "/internal/v1/operator/operations/{operation}";
pub const OPERATOR_SIGNER_REQUEST_ROUTE: &str = "/internal/v1/operator/signer-requests/{operation}";
pub const OPERATOR_VAULT_ROUTE: &str = "/internal/v1/operator/vaults/{fingerprint}";
pub const OPERATOR_SIGNER_RESULT_ROUTE: &str = "/internal/v1/operator/signer-results/{operation}";
/// Everything waiting for an operator. Carries no capability token: see
/// [`aether::certificates::transport::OperatorPendingOperation`].
pub const OPERATOR_PENDING_ROUTE: &str = "/internal/v1/operator/pending";
/// What Astra reports of its authority state. A read: no capability token,
/// none minted.
pub const OPERATOR_STATUS_ROUTE: &str = "/internal/v1/operator/status";
/// Replaces the encrypted vault copy, and optionally the credential document,
/// for an administrator relayed from the tunnel (spec §5.9).
pub const OPERATOR_VAULT_COPY_ROUTE: &str = "/internal/v1/operator/vault-copy";
/// Opens a campaign for an administrator relayed from the tunnel. Carries no
/// capability token: opening grants nothing, the operator's credential does.
pub const OPERATOR_OPEN_ROUTE: &str = "/internal/v1/operator/campaigns";

/// Ceiling on every operator answer, including the encrypted vault.
///
/// 128 KiB, the §8.2 response ceiling — the public origin serves the same file
/// under the same bound, and Astra refuses to serve one that is larger. The
/// ordinary [`MAX_INTERNAL_BODY_BYTES`] stays what it is for every non-operator
/// call on this link.
pub const MAX_OPERATOR_ANSWER_BYTES: usize = 128 * 1024;

/// Largest canonical operator request accepted on either public surface.
///
/// Operator results may contain several ML-DSA-87-signed transition objects.
/// Their §8.5 ceiling is intentionally larger than the 32 KiB transaction
/// request used by the chunked trust-update protocol.
pub const MAX_OPERATOR_REQUEST_BYTES: usize = 64 * 1024;

/// Largest private body carrying an operator result.
///
/// The public route bounds the canonical result at 64 KiB. The private route
/// adds only the gateway-resolved, fixed-size operator identity and the JSON
/// field names around that result. Keeping a separate ceiling preserves the
/// public bound without making a valid boundary-sized result impossible to
/// relay.
pub const MAX_OPERATOR_RELAY_BODY_BYTES: usize = MAX_OPERATOR_REQUEST_BYTES + 256;

/// Largest vault copy accepted, in decoded bytes.
///
/// Twice the 128 KiB Astra serves a vault under ([`MAX_OPERATOR_ANSWER_BYTES`]):
/// a copy a companion could not then download would be a copy that breaks the
/// next ceremony, so nothing larger than what the download can carry is worth
/// accepting, and the margin is for the key-slots a vault may grow.
pub const MAX_OPERATOR_VAULT_COPY_BYTES: usize = 256 * 1024;

/// Room kept for the credential document that may travel with the vault.
const MAX_OPERATOR_VAULT_COPY_CREDENTIALS_BYTES: usize = 128 * 1024;

/// Largest body of the vault copy on the gateway's route and in the relay.
///
/// Its own bound, and not [`MAX_OPERATOR_RELAY_BODY_BYTES`]: the vault travels
/// in base64, a third larger than its bytes, and carries the credential
/// document beside it. The 1 KiB left over is the JSON envelope.
pub const MAX_OPERATOR_VAULT_COPY_BODY_BYTES: usize = MAX_OPERATOR_VAULT_COPY_BYTES.div_ceil(3) * 4
    + MAX_OPERATOR_VAULT_COPY_CREDENTIALS_BYTES
    + 1024;

/// Largest private body carrying a vault copy: the public one, plus the
/// gateway-resolved operator identity and the field name around it.
pub const MAX_OPERATOR_VAULT_COPY_RELAY_BODY_BYTES: usize =
    MAX_OPERATOR_VAULT_COPY_BODY_BYTES + 256;

/// Administrator identity established from the request's WireGuard source.
///
/// A peer name is a mutable UI label; the WireGuard public key is the unique
/// identity from the admitted peer table. Development loopback has no such
/// key and is represented explicitly so it can never be confused with a real
/// peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperatorIdentity {
    WireGuard { public_key: WireGuardKey },
    DevLoopback,
}

impl std::fmt::Display for OperatorIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WireGuard { public_key } => write!(formatter, "wireguard:{public_key}"),
            Self::DevLoopback => formatter.write_str("dev-loopback"),
        }
    }
}

/// What the gateway relays for an operator campaign (spec §8.5).
///
/// The administrator identity the gateway resolved from the source VIP, and
/// nothing else. It is **not** an authorization: a campaign is authorized by the
/// WebAuthn assertion and by the `CA-PQ` signatures the objects carry, never
/// by who relayed it. It travels so Astra's structured log can name the
/// admitted administrator the ceremony came through — the same reason the
/// client relay carries its caller. It does not advance the registry's
/// hash-chained mutation audit.
///
/// No path, no method, no header of the caller's: this is the whole of what
/// crosses, and the route is chosen by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedOperatorCampaign {
    pub operator: OperatorIdentity,
}

/// What the companion deposits, relayed with its administrator (spec §8.5).
///
/// Only the result. Astra holds the campaign it answers, and a result verified
/// against a campaign the same message supplied would verify nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedOperatorSignerResult {
    pub operator: OperatorIdentity,
    pub result: Box<aether::certificates::status::AstraSignerResult>,
}

/// What the gateway relays when an administrator opens a campaign.
///
/// The resolved administrator and the request, nothing of the caller's path,
/// method or headers. The identity is for the log, not an authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedOperatorOpen {
    pub operator: OperatorIdentity,
    pub request: OperatorOpenRequest,
}

/// What an administrator sends to replace Astra's vault copy (spec §5.9).
///
/// The vault stays encrypted: this carries bytes neither the gateway nor Astra
/// can open. The credential document, when present, is signed under `CA-PQ`
/// and Astra verifies it itself before taking it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorVaultCopy {
    pub vault_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Box<aether::certificates::approval::CredentialRegistry>>,
}

/// What Astra holds after a vault copy, for Orion to read back.
///
/// `credential_registry_epoch` has the meaning it has in
/// [`OperatorAuthorityStatus`]: `None` when no document is served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorVaultCopied {
    pub fingerprint: Fingerprint,
    pub credential_registry_epoch: Option<u64>,
}

/// What the gateway relays for a vault copy: the administrator it resolved,
/// for the structured log, and the copy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedOperatorVaultCopy {
    pub operator: OperatorIdentity,
    pub copy: OperatorVaultCopy,
}

/// The two operator shapes both ends parse, defined once in `aether`.
pub use aether::certificates::transport::{
    OperatorAuthorityStatus, OperatorIssuerStatus, OperatorOpenAction, OperatorOpenRequest,
    OperatorOpened, OperatorPendingList, OperatorPendingOperation, OperatorSignerRequestResponse,
    RevocationExpiries, SigningOperationState, SigningOperationView,
};

/// The name the gateway puts in SNI when it dials Astra.
///
/// A second constant rather than a reuse of [`INTERNAL_SERVER_NAME`]: the two
/// ends hold two different certificates, and one shared name would let a
/// mis-pinned pair look like a working one right up to the pin comparison.
pub const ASTRA_INTERNAL_SERVER_NAME: &str = "helios-authority.internal";

/// The three types both ends parse, defined once in `aether`.
///
/// Re-exported rather than moved out of sight: every gateway-side caller
/// already names them through this module, and the path is what says which
/// wire they belong to.
pub use aether::certificates::transport::{
    ClientRenewalOperationState, ClientRenewalOperationView, ClientRenewalSignerRequest,
};

/// What the gateway relays once it has resolved the caller from its VIP.
///
/// `caller_wg_public_key` is the gateway's own resolution, never a value the
/// client chose: Astra compares the request's copy against it and refuses a
/// mismatch. Relaying the request alone would make the authority trust a field
/// the client filled in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedRotationRequest {
    pub caller_wg_public_key: WireGuardKey,
    pub request: Box<aether::certificates::client::ClientCertificateRotationRequest>,
}

/// What the gateway relays when a peer is behind and its queue holds nothing
/// built for the state that peer signed (spec §0.6).
///
/// Three things, and deliberately not a fourth: the client's own authenticated
/// request, the gateway's resolution of who is asking, and the peer snapshot
/// the registry already holds. No method, no path, no header of the client's —
/// the gateway builds a canonical object and relays that, so a request the
/// authority acts on is never a request a client shaped.
///
/// The peer snapshot travels because the authority does not hold the gateway's
/// admission state: it is the same view `GET /internal/v1/certificates/state`
/// already publishes, and it is what lets the authority check the request's
/// signature against the generation the **domain** holds rather than one the
/// request supplied.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedTrustUpdatePreparation {
    pub caller_wg_public_key: WireGuardKey,
    pub request: Box<aether::certificates::transport::AuthenticatedTrustUpdateRequest>,
    pub peer: Box<PeerCertificateStateView>,
}

/// What the authority answers a preparation with.
///
/// `None` is a legitimate answer and not an error: the gateway's comparison
/// and the authority's registry can disagree about what «behind» means — the
/// gateway compares its own counters, the authority holds the objects — and a
/// disagreement resolves as «nothing to distribute», never as a fabricated
/// transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedTrustUpdate {
    pub transaction: Option<PreparedTrustUpdateTransaction>,
}

/// One manifest and every fragment of it, ready to be queued.
///
/// The whole set in one answer: the gateway's queue holds a complete
/// transaction or none, so streaming the fragments over several calls would
/// only create a half-queued state neither end could describe.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedTrustUpdateTransaction {
    pub manifest: aether::certificates::transport::TrustUpdateTransactionManifest,
    pub chunks: Vec<aether::certificates::transport::TrustUpdateChunk>,
}

/// A read of one operation, on behalf of one caller.
///
/// The caller travels with every read for the same reason it travels with the
/// request: on this link the authenticated party is the gateway, not the peer,
/// so the authority can only refuse a peer asking about somebody else's
/// operation if it is told which peer is asking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayedOperationQuery {
    pub caller_wg_public_key: WireGuardKey,
}

/// What the companion posts back.
///
/// Only the approval. Astra holds the request it answers, and an approval
/// verified against a request the same message supplied would verify nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientRenewalSignerResult {
    pub caller_wg_public_key: WireGuardKey,
    pub approval: Box<aether::certificates::approval::AstraRenewalApproval>,
}

/// The gateway's door to the authority's transaction producer (spec §0.6).
///
/// A trait rather than the concrete client, for the same reason
/// [`AstraChannelHandler`] is one: the certificate service owns a registry
/// lock and no transport, and giving it a `reqwest`-shaped dependency would
/// make every one of its tests need a listener. It is also what lets a gateway
/// deployed **without** an authority hold `None` and answer exactly as it does
/// today.
#[async_trait]
pub trait TrustUpdatePreparer: Send + Sync {
    /// Asks the authority for the transaction this peer is missing.
    async fn prepare(
        &self,
        relayed: &RelayedTrustUpdatePreparation,
    ) -> Result<PreparedTrustUpdate, TrustUpdateRefusal>;
}
