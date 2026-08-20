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
use aether::certificates::encoding::Id16;
use aether::certificates::transport::{
    ClientRenewalOperationState, ClientRenewalOperationView, ClientRenewalSignerRequest,
};
use anyhow::{bail, Context, Result};

/// Per-call timeout.
///
/// The gateway is one hop away over a tunnel that is already up. Anything
/// slower than this is a gateway that is not answering, and the operator is
/// standing at a prompt with a security key in hand — a long wait there is
/// worse than a clear refusal.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Ceiling on any answer.
///
/// An approval request enumerates credential identifiers and carries one
/// ML-DSA-87 signature; an operation view may carry a whole grant. 256 KiB is
/// far above both, and the bound exists because the other end of the tunnel is
/// still a peer.
const MAX_ANSWER_BYTES: usize = 256 * 1024;

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
        let status = response.status();
        if !status.is_success() {
            // The gateway keeps the reason in its own log by design (§8.1.2):
            // what a caller learns is that it was refused. Two statuses are
            // still worth naming, because they send the operator somewhere
            // different — and neither is their own mistake to fix.
            match status.as_u16() {
                403 => bail!(
                    "jeton de capacité refusé (403). Il vaut cinq minutes, pour une opération et \
                     un manifeste : relancer l'approbation depuis le client."
                ),
                503 => bail!(
                    "la gateway ne relaie aucune autorité (503) : Astra n'est pas déployé, ou son \
                     canal privé est tombé."
                ),
                code => bail!(
                    "la gateway a refusé ({code}). Le motif détaillé reste dans son journal : le \
                     canal in-tunnel ne le renvoie jamais à l'appelant."
                ),
            }
        }
        let bytes = response.bytes().context("lecture de la réponse")?;
        if bytes.len() > MAX_ANSWER_BYTES {
            bail!(
                "la gateway a répondu {} octets : au-delà de la borne de cette route",
                bytes.len()
            );
        }
        serde_json::from_slice(&bytes).context("réponse illisible")
    }
}
