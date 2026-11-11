//! The companion's transport, when the client's tunnel is up (spec §8.1.2).
//!
//! # Why the companion talks to Helios and not to Astra
//!
//! The amendment of 15 August 2026 is explicit: a client whose WireGuard works
//! never contacts Astra directly, and neither does the companion the client
//! launches. Both go through the gateway's typed in-tunnel routes, where
//! `heliosd` authenticates the peer by its source VIP and relays a canonical
//! object it builds itself. Astra's public origin (§8.2) is reserved for a
//! client that cannot establish WireGuard at all.
//!
//! That is why this module needs no pin, no anchor and no TLS configuration:
//! it speaks plain HTTP to an address that only exists inside an encrypted,
//! mutually authenticated tunnel. Adding a second authentication here would
//! not add a second proof — it would add a second thing to get wrong.
//!
//! # Why the companion runs on the client's machine
//!
//! Because the routes are authenticated by the **peer's** VIP. §12.2 has the
//! Orion interface launch `astra-signer` with `heliosd_url` and
//! `operation_id`; the companion inherits the tunnel that is already up, and
//! nothing else about the client. An operator working from another machine
//! has no VIP the gateway would resolve, and belongs on the public channel
//! instead — which is still `501` (§12.3).
//!
//! # What the transport is not allowed to decide
//!
//! Nothing. The request that comes back is signed by Astra's service key and
//! verified against the domain hand-off the companion already holds — the same
//! verification as a request read from a file, because it is the object that
//! carries the signature and not the wire it arrived on. In particular
//! [`SignerRequest::authority_url`] and [`SignerRequest::webauthn_rp_id`] are
//! **reported, never adopted**: a gateway that named another RP ID would
//! otherwise have the operator's key answer a challenge for another domain.

use std::time::Duration;

use aether::certificates::approval::{
    AstraCredentialApprovalRequest, AstraRenewalApproval, CredentialRegistry,
};
use aether::certificates::authority::{CaTransition, ClientTlsCaTransition};
use aether::certificates::encoding::{DerCertificate, Fingerprint, Id16};
use aether::certificates::gateway::{
    GatewayCertificateRequest, GatewayIdentityTransition, GatewayTransitionAbort,
};
use aether::certificates::status::CertificateServiceRollbackAuthorization;
use aether::certificates::transport::{
    ClientRenewalOperationState, ClientRenewalOperationView, ClientRenewalSignerRequest,
    OperatorAuthorityStatus, OperatorChainStep, OperatorGatewayPublish, OperatorGatewayPublished,
    OperatorOpenRequest, OperatorOpened, OperatorVaultCopied, OperatorVaultCopy,
};
use anyhow::{bail, Context, Result};

use crate::rotation_journal::RotationKind;

/// Per-call timeout.
///
/// The gateway is one hop away over a tunnel that is already up. Anything
/// slower than this is a gateway that is not answering, and the operator is
/// standing at a prompt with a security key in hand — a long wait there is
/// worse than a clear refusal.
const CALL_TIMEOUT: Duration = Duration::from_secs(CALL_TIMEOUT_SECS);

/// How long one call through the tunnel may take, in seconds.
pub const CALL_TIMEOUT_SECS: u64 = 20;

/// Ceiling on any answer.
///
/// An approval request enumerates credential identifiers and carries one
/// ML-DSA-87 signature; an operation view may carry a whole grant. 256 KiB is
/// far above both, and the bound exists because the other end of the tunnel is
/// still a peer.
const MAX_ANSWER_BYTES: usize = 256 * 1024;

/// Ceiling on the domain view, the one answer that grows with the fleet.
///
/// A peer costs a few hundred bytes there, so the ceiling of the other answers
/// would make a rotation unresumable on a gateway with a thousand peers.
const MAX_DOMAIN_ANSWER_BYTES: usize = 8 * 1024 * 1024;

const NO_AUTHORITY: &str = "la gateway ne relaie aucune autorité (503) : Astra n'est pas déployé, \
                            ou son canal privé est tombé.";

/// The gateway answered with a status other than success.
///
/// Having an answer is all this type says, and a lost connection stays apart from
/// it. What the answer means is in [`status`](Self::status): a deposit's 403 or
/// 409 is the domain's word about a journal, while 429, 500 or 503 only say that
/// the gateway or the authority could not answer, and say nothing about it. So a
/// resume must not set `deposit_refused` from the type alone. Reached by
/// `downcast_ref` on the error any call on the operator routes returns.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct TunnelRefusal {
    pub status: u16,
    message: String,
}

/// Whether a call failed for want of an answer, rather than on what came back.
pub fn is_unreachable(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<reqwest::Error>())
}

/// Where a vault copy landed.
///
/// An enum rather than an error: [`VaultCopySent::HeldBack`] is an ordinary
/// answer the caller has to handle, not a failure of the rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultCopySent {
    /// Astra holds it, and this is what it reads back.
    Copied(OperatorVaultCopied),
    /// A live operation names the vault in place, or a rotation holds the
    /// document back. Nothing was written; the same copy can be sent again.
    HeldBack,
}

/// What the companion has to show, and what it must not believe.
///
/// `Debug` is derived and prints everything: nothing here is secret. The
/// capability token is the closest thing, and it is bound to one operation,
/// one manifest and five minutes — a value with no meaning outside the
/// exchange that is happening right now.
#[derive(Debug)]
pub struct SignerRequest {
    pub operation_id: Id16,
    /// Signed by Astra's service key. Verified by the gesture, not here.
    pub approval_request: Box<AstraCredentialApprovalRequest>,
    /// The `CA-PQ`-signed document the allow-list comes from.
    ///
    /// The companion holds its own copy beside the vault and uses that one:
    /// this is carried for the consumer that has none — Orion. Reported here
    /// so a caller can compare the two rather than choose between them.
    pub credential_registry: Box<CredentialRegistry>,
    /// What the gateway says the authority origin is. Displayed for the
    /// operator, and compared against the hand-off — never substituted for it.
    pub authority_url: String,
    /// Likewise: the RP ID the ceremony runs under comes from the vault.
    pub webauthn_rp_id: String,
    /// Capability token for the submission route, bound to this operation,
    /// this manifest and five minutes (spec §8.2).
    pub result_token: String,
}

/// One gateway, inside the tunnel.
pub struct Tunnel {
    base: String,
    http: reqwest::blocking::Client,
}

impl Tunnel {
    pub fn new(heliosd_url: &str) -> Result<Self> {
        let base = heliosd_url.trim_end_matches('/').to_string();
        if !base.starts_with("http://") && !base.starts_with("https://") {
            bail!("l'adresse de la gateway doit commencer par http:// ou https:// : {base}");
        }
        Ok(Self {
            base,
            http: reqwest::blocking::Client::builder()
                .timeout(CALL_TIMEOUT)
                // The companion talks to the Helios API through the tunnel;
                // an inherited proxy must not see capability tokens or route
                // the request away from the profile's gateway VIP.
                .no_proxy()
                // A renewal route never redirects. Following one would carry
                // the capability tokens, and later the operator's assertion,
                // to whatever host the answer named.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("client HTTP du tunnel")?,
        })
    }

    /// Fetches the operation, then the request it is waiting on.
    ///
    /// Two calls and not one: the tokens are minted per read and live five
    /// minutes, so the companion takes them as late as it can — the operator
    /// may be several minutes away from touching their key.
    pub fn fetch(&self, operation_id: &Id16) -> Result<SignerRequest> {
        let view: ClientRenewalOperationView = self
            .get(
                &format!(
                    "{}/api/key-negotiation/certificate-renewal/operations/{}",
                    self.base,
                    operation_id.to_hex()
                ),
                None,
            )
            .context("lecture de l'opération")?;

        if view.operation_id != *operation_id {
            bail!(
                "la gateway a répondu au sujet de l'opération {} et non de {}",
                view.operation_id.to_hex(),
                operation_id.to_hex()
            );
        }
        match view.state {
            ClientRenewalOperationState::AwaitingOperator => {}
            ClientRenewalOperationState::PendingGrant
            | ClientRenewalOperationState::PendingCommit => bail!(
                "cette opération n'attend plus d'opérateur : elle est déjà approuvée. Rien à \
                 signer, et une seconde assertion ne changerait ni génération ni clé candidate."
            ),
            ClientRenewalOperationState::Failed => bail!(
                "cette opération a échoué côté autorité. Aucune assertion n'y est plus acceptée : \
                 le client doit en ouvrir une nouvelle."
            ),
        }

        // Both tokens are refused as missing rather than as empty: an
        // operation that no longer mints them is one that no longer accepts a
        // result, and touching a security key for it would be wasted.
        let read_token = view.signer_request_token.ok_or_else(|| {
            anyhow::anyhow!(
                "l'opération ne délivre plus de jeton de lecture : sa fenêtre de cinq minutes est \
                 passée. Relancer depuis le client."
            )
        })?;
        let result_token = view.signer_result_token.ok_or_else(|| {
            anyhow::anyhow!(
                "l'opération ne délivre plus de jeton de dépôt : sa fenêtre de cinq minutes est \
                 passée. Relancer depuis le client."
            )
        })?;

        let request: ClientRenewalSignerRequest = self
            .get(
                &format!(
                    "{}/api/key-negotiation/certificate-renewal/signer-requests/{}",
                    self.base,
                    operation_id.to_hex()
                ),
                Some(&read_token),
            )
            .context("lecture de la demande d'approbation")?;

        if request.operation_id != *operation_id {
            bail!(
                "la demande porte l'opération {} et non {}",
                request.operation_id.to_hex(),
                operation_id.to_hex()
            );
        }
        if request.approval_request.operation_id != *operation_id {
            bail!(
                "la demande signée par Astra porte l'opération {} et non {}",
                request.approval_request.operation_id.to_hex(),
                operation_id.to_hex()
            );
        }
        // The manifest the tokens are bound to must be the object the operator
        // is about to be shown. Astra binds them to it; checking here is what
        // makes that binding mean something on this side too.
        if !view
            .operation_manifest_fingerprint
            .matches(&request.approval_request.fingerprint())
        {
            bail!(
                "la demande reçue n'est pas celle à laquelle l'opération est liée : le jeton de \
                 capacité vaut pour un manifeste, et ce n'est pas celui-là"
            );
        }

        Ok(SignerRequest {
            operation_id: *operation_id,
            approval_request: request.approval_request,
            credential_registry: request.credential_registry,
            authority_url: request.authority_url,
            webauthn_rp_id: request.webauthn_rp_id,
            result_token,
        })
    }

    /// Posts the assertion, and reports where the operation landed.
    ///
    /// The answer is the operation Astra reached with it: `pending_commit`
    /// when the whole chain succeeded, `failed` when it did not. Replaying the
    /// identical result under the same token is idempotent; a different body
    /// under the same operation is a conflict Astra decides.
    pub fn submit(
        &self,
        operation_id: &Id16,
        result_token: &str,
        approval: &AstraRenewalApproval,
    ) -> Result<ClientRenewalOperationState> {
        let body = serde_json::to_vec(approval).context("encodage de l'approbation")?;
        let response = self
            .http
            .post(format!(
                "{}/api/key-negotiation/certificate-renewal/signer-results/{}",
                self.base,
                operation_id.to_hex()
            ))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {result_token}"),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .context("dépôt de l'approbation")?;
        let view: ClientRenewalOperationView = Self::decode(response)?;
        Ok(view.state)
    }

    fn get<T: serde::de::DeserializeOwned>(&self, url: &str, token: Option<&str>) -> Result<T> {
        let mut request = self.http.get(url);
        if let Some(token) = token {
            request = request.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        Self::decode(request.send().context("appel de la gateway")?)
    }

    fn decode<T: serde::de::DeserializeOwned>(response: reqwest::blocking::Response) -> Result<T> {
        Self::decode_bounded(response, MAX_ANSWER_BYTES)
    }

    fn decode_bounded<T: serde::de::DeserializeOwned>(
        response: reqwest::blocking::Response,
        max_answer_bytes: usize,
    ) -> Result<T> {
        let status = response.status();
        if !status.is_success() {
            // The gateway keeps the reason in its own log by design (§8.1.2):
            // what a caller learns is that it was refused. Two statuses are
            // still worth naming, because they send the operator somewhere
            // different — and neither is their own mistake to fix.
            let code = status.as_u16();
            let message = match code {
                403 => "jeton de capacité refusé (403). Il vaut cinq minutes, pour une opération \
                        et un manifeste : relancer l'approbation depuis le client."
                    .to_string(),
                503 => NO_AUTHORITY.to_string(),
                code => format!(
                    "la gateway a refusé ({code}). Le motif détaillé reste dans son journal : le \
                     canal in-tunnel ne le renvoie jamais à l'appelant."
                ),
            };
            return Err(TunnelRefusal {
                status: code,
                message,
            }
            .into());
        }
        let bytes = response.bytes().context("lecture de la réponse")?;
        if bytes.len() > max_answer_bytes {
            bail!(
                "la gateway a répondu {} octets : au-delà de la borne de cette route",
                bytes.len()
            );
        }
        serde_json::from_slice(&bytes).context("réponse illisible")
    }
}

// ---------------------------------------------------------------------------
// The operator campaign, on the same tunnel (spec §8.5).
// ---------------------------------------------------------------------------

/// The four gateway routes an operator campaign travels on.
///
/// A different prefix from the renewal above, because they are different
/// surfaces: a renewal belongs to the peer whose VIP the gateway resolved, a
/// campaign belongs to no peer and sits behind the administration surface.
const OPERATOR_PREFIX: &str = "/api/certificates/operator";

impl Tunnel {
    fn get_campaign<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        token: Option<&str>,
    ) -> Result<T> {
        let mut request = self.http.get(url);
        if let Some(token) = token {
            request = request.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        Self::decode_bounded(
            request.send().context("appel de la gateway")?,
            crate::origin::MAX_ANSWER_BYTES,
        )
    }

    /// Reads the campaign operation, then the request it is waiting on.
    ///
    /// The verification is `crate::origin::Origin::accept` — the same
    /// function the public origin path uses, deliberately: the objects carry
    /// the signatures, so a campaign fetched through a tunnel is trusted
    /// exactly as much, and exactly as little, as one fetched from HTTPS.
    /// Sharing the check is what keeps the two transports from drifting into
    /// accepting different things.
    pub fn fetch_campaign(&self, operation_id: &Id16) -> Result<crate::origin::CampaignRequest> {
        let view: aether::certificates::transport::SigningOperationView = self
            .get_campaign(
                &format!(
                    "{}{OPERATOR_PREFIX}/operations/{}",
                    self.base,
                    operation_id.to_hex()
                ),
                None,
            )
            .context("lecture de l'opération de campagne")?;

        let answer: crate::origin::SignerRequestAnswer = {
            let read_token = crate::origin::Origin::read_token(operation_id, &view)?;
            self.get_campaign(
                &format!(
                    "{}{OPERATOR_PREFIX}/signer-requests/{}",
                    self.base,
                    operation_id.to_hex()
                ),
                Some(&read_token),
            )
            .context("lecture de la demande de signature")?
        };
        crate::origin::Origin::accept(operation_id, view, answer)
    }

    /// Downloads the encrypted vault this campaign names.
    ///
    /// Encrypted, and there is no other form: neither this companion's gateway
    /// nor the authority behind it holds a key-slot secret. The bytes are
    /// checked against the fingerprint the **signed** request names before
    /// they are handed back.
    pub fn campaign_vault(
        &self,
        request: &crate::origin::CampaignRequest,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let token = request.vault_token.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "cette campagne ne fait signer aucune ancre : l'autorité ne délivre pas de jeton \
                 de coffre, et il n'y a rien à ouvrir"
            )
        })?;
        let expected = request.signer_request.encrypted_vault_fingerprint;
        let response = self
            .http
            .get(format!(
                "{}{OPERATOR_PREFIX}/vaults/{}",
                self.base,
                expected.to_hex()
            ))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .context("téléchargement du coffre chiffré")?;
        let status = response.status();
        if !status.is_success() {
            bail!(crate::origin::Origin::refusal(status.as_u16()));
        }
        let bytes = response.bytes().context("lecture du coffre")?;
        if bytes.len() > crate::origin::MAX_ANSWER_BYTES {
            bail!(
                "la gateway a renvoyé {} octets : au-delà de la borne de cette route",
                bytes.len()
            );
        }
        crate::origin::Origin::accept_vault(request, bytes.to_vec())
    }

    /// Posts the operator's approval, and reports where the operation landed.
    pub fn submit_campaign(
        &self,
        operation_id: &Id16,
        result_token: &str,
        result: &aether::certificates::status::AstraSignerResult,
    ) -> Result<aether::certificates::transport::SigningOperationState> {
        let body = serde_json::to_vec(result).context("encodage du résultat de campagne")?;
        let response = self
            .http
            .post(format!(
                "{}{OPERATOR_PREFIX}/signer-results/{}",
                self.base,
                operation_id.to_hex()
            ))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {result_token}"),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .context("dépôt de l'approbation")?;
        let view: aether::certificates::transport::SigningOperationView =
            Self::decode_bounded(response, crate::origin::MAX_ANSWER_BYTES)?;
        Ok(view.state)
    }
}

// ---------------------------------------------------------------------------
// The administrator routes a rotation travels on (lot 5b).
// ---------------------------------------------------------------------------

/// The gateway's view of its domain, out of everything `GET /api/certificates`
/// says: the anchors, and the identity of the gateway itself (F14 lot 6b).
///
/// Its own subset rather than the gateway's type, which this crate does not
/// link, and which refuses a field it does not know: this read must outlive what
/// that view gains. Every field newer than the anchors is defaulted, so a
/// gateway older than it still reads. The names are those of Orion's
/// `GatewayDomainRead`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct GatewayIdentityRead {
    /// The gateway's clock when it answered. Absent on a gateway older than the field.
    #[serde(default)]
    pub now_unix: Option<u64>,
    pub ca_pq_fingerprint: Fingerprint,
    #[serde(default)]
    pub next_ca_fingerprint: Option<Fingerprint>,
    #[serde(default)]
    pub client_tls_ca_fingerprint: Option<Fingerprint>,
    #[serde(default)]
    pub next_client_tls_ca_fingerprint: Option<Fingerprint>,
    /// When the outgoing `CA-PQ` stops being accepted, while an overlap runs.
    #[serde(default)]
    pub ca_retire_active_at: Option<u64>,
    #[serde(default)]
    pub gateway_identity_epoch: u64,
    #[serde(default)]
    pub gateway_tls_fingerprint: String,
    #[serde(default)]
    pub gateway_pq_fingerprint: String,
    #[serde(default)]
    pub gateway_tls_not_after: Option<u64>,
    #[serde(default)]
    pub gateway_pq_not_after: Option<u64>,
    #[serde(default)]
    pub gateway_transition_pending: bool,
    #[serde(default)]
    pub gateway_transition_published: bool,
    #[serde(default)]
    pub gateway_activation_at: Option<u64>,
    #[serde(default)]
    pub gateway_retire_active_at: Option<u64>,
    #[serde(default)]
    pub gateway_rollback_expires_at: Option<u64>,
    #[serde(default)]
    pub gateway_restart_due: Option<String>,
}

/// What `POST /api/certificates/gateway-renewal` is asked (spec §5.2, step 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct RenewalAsk {
    /// Replace the self-signed TLS leaf too.
    pub rotate_tls: bool,
    /// Discard the sealed candidate and draw a fresh key.
    pub new_key: bool,
    /// Build the request without a continuity signature.
    pub key_recovery: bool,
}

/// The gateway's answer to a preparation, as far as the companion reads it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct GatewayRenewalRead {
    pub gateway_identity_epoch: u64,
    pub request_fingerprint: String,
    pub expires_at: u64,
    /// Fingerprint of the candidate TLS leaf, absent when TLS does not change.
    pub candidate_tls_fingerprint: Option<String>,
    /// `true` when a request already prepared for this epoch came back unchanged.
    pub reused: bool,
    pub key_recovery: bool,
}

/// The gateway's answer to a staged or cancelled decision.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct GatewayDecisionRead {
    pub gateway_identity_epoch: u64,
    pub fingerprint: String,
    /// `true` when this exact document was already applied.
    pub already_present: bool,
    /// Set for an installation: the instant the identity switches.
    pub activation_at: Option<u64>,
    /// Set for an installation: the instant the outgoing leaf retires.
    pub not_after: Option<u64>,
}

/// The gateway's answer to a service rollback: when the selection lapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub struct GatewayRollbackRead {
    pub expires_at: u64,
}

/// The sentence `GatewayActionRefusal` carries.
#[derive(serde::Deserialize)]
struct GatewayRefusalBody {
    message: String,
}

impl Tunnel {
    /// Opens a campaign through the door (lot 5a, §5.4).
    pub fn open_campaign(&self, request: &OperatorOpenRequest) -> Result<OperatorOpened> {
        let response = self
            .post_admin(&format!("{OPERATOR_PREFIX}/campaigns"), request)
            .context("ouverture de la campagne")?;
        Self::read_admin(response, crate::origin::MAX_ANSWER_BYTES)
            .context("ouverture de la campagne")
    }

    /// Publishes the signed gateway transition of `epoch` with this fingerprint (F14 lot 6b): Astra
    /// marks it published, then relays it to the gateway. Asking again retries
    /// a relay the gateway did not confirm; `relayed` says whether it did.
    pub fn publish_gateway_transition(
        &self,
        epoch: u64,
        transition_fingerprint: Fingerprint,
    ) -> Result<OperatorGatewayPublished> {
        let response = self
            .post_admin(
                &format!("{OPERATOR_PREFIX}/gateway-identity/publish"),
                &OperatorGatewayPublish {
                    epoch,
                    transition_fingerprint,
                },
            )
            .context("publication de la transition gateway")?;
        Self::read_admin(response, crate::origin::MAX_ANSWER_BYTES)
            .context("publication de la transition gateway")
    }

    /// Opens the next step of the certificate chain (F14 lot 6b), once the
    /// step in progress has taken effect. `Finished` when nothing remains. A
    /// step not yet in effect is refused with Astra's sentence in the error.
    pub fn chain_next(&self) -> Result<OperatorChainStep> {
        let response = self
            .http
            .post(format!("{}{OPERATOR_PREFIX}/chain/next", self.base))
            .send()
            .context("passage à l'étape suivante de la chaîne")?;
        if !response.status().is_success() {
            return Err(chain_next_refusal(response));
        }
        Self::read_admin(response, crate::origin::MAX_ANSWER_BYTES)
            .context("passage à l'étape suivante de la chaîne")
    }

    /// Drops the certificate chain's plan (F14 lot 6b). What was approved keeps
    /// its effect.
    pub fn chain_abandon(&self) -> Result<()> {
        let response = self
            .http
            .post(format!("{}{OPERATOR_PREFIX}/chain/abandon", self.base))
            .send()
            .context("abandon de la chaîne")?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(refused_installation(response, "abandon de la chaîne"))
    }

    /// Reads what Astra holds (§5.9). Fingerprints and epochs, no token.
    pub fn authority_status(&self) -> Result<OperatorAuthorityStatus> {
        let response = self
            .get_admin(&format!("{OPERATOR_PREFIX}/status"))
            .context("lecture de l'autorité")?;
        Self::read_admin(response, crate::origin::MAX_ANSWER_BYTES).context("lecture de l'autorité")
    }

    /// Replaces Astra's vault copy (§5.9).
    ///
    /// Unbounded here on purpose: the route has its own limit, far above the
    /// relay's 64 KiB, and answers `413` above it. A larger vault fails as a
    /// refusal that names its status, with nothing written.
    pub fn send_vault_copy(&self, copy: &OperatorVaultCopy) -> Result<VaultCopySent> {
        let response = self
            .post_admin(&format!("{OPERATOR_PREFIX}/vault-copy"), copy)
            .context("envoi de la copie du coffre")?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Ok(VaultCopySent::HeldBack);
        }
        Self::read_admin(response, crate::origin::MAX_ANSWER_BYTES)
            .map(VaultCopySent::Copied)
            .context("envoi de la copie du coffre")
    }

    /// Installs a `CA-PQ` transition on the gateway, which checks it itself and
    /// accepts a replay of the same one.
    pub fn install_ca_transition(&self, transition: &CaTransition) -> Result<()> {
        self.install_acknowledged(
            "/api/certificates/ca-transition",
            transition,
            "installation de la transition sur la gateway",
        )
    }

    /// Installs a client `CA-TLS` transition, on the same terms.
    pub fn install_client_tls_ca_transition(
        &self,
        transition: &ClientTlsCaTransition,
    ) -> Result<()> {
        self.install_acknowledged(
            "/api/certificates/client-tls-ca-transition",
            transition,
            "installation de la transition sur la gateway",
        )
    }

    /// Asks the gateway to prepare its next identity and export its request
    /// (spec §5.2, step 1). The answer is the request's fingerprint, not the
    /// request: [`Self::gateway_renewal_request`] reads that.
    pub fn prepare_gateway_renewal(&self, ask: &RenewalAsk) -> Result<GatewayRenewalRead> {
        self.install(
            "/api/certificates/gateway-renewal",
            ask,
            "préparation du renouvellement de la gateway",
        )
    }

    /// The public request the gateway prepared, for the ceremony.
    pub fn gateway_renewal_request(&self) -> Result<GatewayCertificateRequest> {
        let response = self
            .get_admin("/api/certificates/gateway-renewal")
            .context("lecture de la demande de la gateway")?;
        Self::read_admin(response, MAX_ANSWER_BYTES).context("lecture de la demande de la gateway")
    }

    /// The candidate TLS leaf sealed for that request, `None` when TLS does
    /// not change (spec §5.2, step 3).
    pub fn gateway_candidate_tls(&self) -> Result<Option<DerCertificate>> {
        let response = self
            .get_admin("/api/certificates/gateway-renewal/tls")
            .context("lecture de la feuille TLS candidate")?;
        Self::read_admin(response, MAX_ANSWER_BYTES).context("lecture de la feuille TLS candidate")
    }

    /// Installs a signed gateway transition (spec §5.2, step 6).
    pub fn install_gateway_transition(
        &self,
        transition: &GatewayIdentityTransition,
    ) -> Result<GatewayDecisionRead> {
        self.install(
            "/api/certificates/gateway-transition",
            transition,
            "installation de la transition sur la gateway",
        )
    }

    /// The transition the gateway holds staged, `None` outside an overlap
    /// (spec §5.4). A rollback and an abort are verified against it.
    pub fn staged_gateway_transition(&self) -> Result<Option<GatewayIdentityTransition>> {
        #[derive(serde::Deserialize)]
        struct Staged {
            transition: Option<GatewayIdentityTransition>,
        }
        let response = self
            .get_admin("/api/certificates/gateway-transition")
            .context("lecture de la transition en attente")?;
        Self::read_admin::<Staged>(response, MAX_ANSWER_BYTES)
            .map(|staged| staged.transition)
            .context("lecture de la transition en attente")
    }

    /// Cancels a staged, unpublished transition (spec §5.3).
    pub fn abort_gateway_transition(
        &self,
        abort: &GatewayTransitionAbort,
    ) -> Result<GatewayDecisionRead> {
        self.install(
            "/api/certificates/gateway-transition/abort",
            abort,
            "annulation de la transition sur la gateway",
        )
    }

    /// Selects the outgoing leaf for the rest of the overlap (spec §5.4).
    pub fn install_gateway_rollback(
        &self,
        authorization: &CertificateServiceRollbackAuthorization,
    ) -> Result<GatewayRollbackRead> {
        self.install(
            "/api/certificates/gateway-transition/rollback",
            authorization,
            "retour arrière de la gateway",
        )
    }

    /// The anchor the gateway is heading to: its next one, or its current one
    /// when no rotation of that kind is in flight.
    ///
    /// So a rotation already promoted still reads as installed. `None` is a
    /// gateway that names no such anchor; a failed read is an error, and not
    /// that.
    pub fn gateway_next_anchor(&self, kind: RotationKind) -> Result<Option<Fingerprint>> {
        let anchors = self.gateway_identity()?;
        Ok(match kind {
            RotationKind::CaPq => Some(
                anchors
                    .next_ca_fingerprint
                    .unwrap_or(anchors.ca_pq_fingerprint),
            ),
            RotationKind::CaTls => anchors
                .next_client_tls_ca_fingerprint
                .or(anchors.client_tls_ca_fingerprint),
        })
    }

    /// When the gateway retires the outgoing `CA-PQ`, while an overlap runs.
    ///
    /// Read from the same view as [`Self::gateway_next_anchor`]. `None` is a
    /// gateway with no overlap in flight.
    pub fn gateway_overlap_not_after(&self) -> Result<Option<u64>> {
        Ok(self.gateway_identity()?.ca_retire_active_at)
    }

    /// The gateway's domain, read once: the anchors and its own identity.
    pub fn gateway_identity(&self) -> Result<GatewayIdentityRead> {
        let response = self
            .get_admin("/api/certificates")
            .context("lecture du domaine de la gateway")?;
        Self::read_admin(response, MAX_DOMAIN_ANSWER_BYTES)
            .context("lecture du domaine de la gateway")
    }

    /// Posts a document to a gateway route and reads the decision it answers.
    ///
    /// `what` names the operation in the error chain: the refusal the gateway
    /// gives is the sentence the operator acts on, and it says what was refused.
    fn install<T, R>(&self, path: &str, body: &T, what: &str) -> Result<R>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let response = self
            .post_admin(path, body)
            .with_context(|| what.to_string())?;
        if !response.status().is_success() {
            return Err(refused_installation(response, what));
        }
        Self::read_admin(response, MAX_ANSWER_BYTES).with_context(|| what.to_string())
    }

    /// Like [`Self::install`], for a route whose success is only an
    /// acknowledgement: an empty or non-JSON `2xx` is accepted, as the
    /// gateway already accepted the document.
    fn install_acknowledged<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
        what: &str,
    ) -> Result<()> {
        let response = self
            .post_admin(path, body)
            .with_context(|| what.to_string())?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(refused_installation(response, what))
    }

    fn get_admin(&self, path: &str) -> Result<reqwest::blocking::Response> {
        self.http
            .get(format!("{}{path}", self.base))
            .send()
            .context("appel de la gateway")
    }

    fn post_admin<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<reqwest::blocking::Response> {
        let body = serde_json::to_vec(body).context("encodage de la requête")?;
        self.http
            .post(format!("{}{path}", self.base))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .context("appel de la gateway")
    }

    fn read_admin<T: serde::de::DeserializeOwned>(
        response: reqwest::blocking::Response,
        max_answer_bytes: usize,
    ) -> Result<T> {
        let status = response.status();
        if !status.is_success() {
            return Err(admin_refusal(status.as_u16(), None));
        }
        let bytes = response.bytes().context("lecture de la réponse")?;
        if bytes.len() > max_answer_bytes {
            bail!(
                "la gateway a répondu {} octets : au-delà de la borne de cette route",
                bytes.len()
            );
        }
        serde_json::from_slice(&bytes).context("réponse illisible")
    }
}

/// The refusal of `chain next`. A step not yet in effect carries Astra's own
/// sentence in the body, and that sentence is shown as it is: Astra produced
/// it, and the gateway only relayed it. Any other refusal is the class alone.
fn chain_next_refusal(response: reqwest::blocking::Response) -> anyhow::Error {
    let status = response.status();
    let sentence = response
        .bytes()
        .ok()
        .filter(|bytes| bytes.len() <= crate::origin::MAX_ANSWER_BYTES)
        .and_then(|bytes| serde_json::from_slice::<GatewayRefusalBody>(&bytes).ok())
        .map(|body| body.message);
    match sentence {
        Some(sentence) => anyhow::anyhow!("{sentence}"),
        None => {
            admin_refusal(status.as_u16(), None).context("passage à l'étape suivante de la chaîne")
        }
    }
}

/// The refusal of an installation route, with the gateway's sentence when it
/// names one: these routes say why, unlike the relayed ones.
fn refused_installation(response: reqwest::blocking::Response, what: &str) -> anyhow::Error {
    let status = response.status();
    // A body too large to read is no reason.
    let reason = response
        .bytes()
        .ok()
        .filter(|bytes| bytes.len() <= crate::origin::MAX_ANSWER_BYTES)
        .and_then(|bytes| serde_json::from_slice::<GatewayRefusalBody>(&bytes).ok())
        .map(|body| body.message);
    admin_refusal(status.as_u16(), reason).context(what.to_string())
}

/// A refusal on the administrator surface, where no capability token is at play.
pub fn admin_refusal(status: u16, reason: Option<String>) -> anyhow::Error {
    let message = match (status, reason) {
        (_, Some(reason)) => format!("la gateway a refusé ({status}) : {reason}"),
        (403, None) => {
            "refusé (403) : ce poste n'est pas administrateur de la gateway, ou l'autorité refuse \
             cette demande. Le motif reste dans le journal d'Astra."
                .to_string()
        }
        (413, None) => {
            "la gateway refuse cette taille (413) : au-delà de la borne de cette route.".to_string()
        }
        (429, None) => "trop d'opérations en attente (429).".to_string(),
        (503, None) => NO_AUTHORITY.to_string(),
        (status, None) => format!(
            "la gateway a refusé ({status}). Le motif détaillé reste dans son journal : le canal \
             in-tunnel ne le renvoie jamais à l'appelant."
        ),
    };
    TunnelRefusal { status, message }.into()
}
