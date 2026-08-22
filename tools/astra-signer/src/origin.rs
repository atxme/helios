//! The companion's transport when there is no tunnel — spec §8.2.
//!
//! # When this channel, and when the other one
//!
//! [`crate::tunnel`] is the ordinary path: a client whose WireGuard works
//! never contacts Astra directly, and neither does the companion it launches.
//! This module is the case that channel cannot cover — an operator on their
//! own workstation, approving a manual campaign, with no VIP the gateway would
//! resolve. §8.2 reserves the public HTTPS origin for exactly that.
//!
//! # What authenticates what
//!
//! Nothing here is authenticated by the transport, and nothing needs to be.
//! The operation identifier is 128 bits from Astra's DRBG and is the only
//! thing that reaches the operation read; the three companion exchanges each
//! carry a capability token bound to one operation, one manifest, one scope
//! and five minutes. What the operator's key then answers is the **campaign
//! fingerprint**, recomputed here from the campaign itself — never a challenge
//! the answer supplied.
//!
//! # What the transport is not allowed to decide
//!
//! Nothing, exactly as in the tunnel. The signer request is signed by Astra's
//! service key and verified against the domain hand-off the companion already
//! holds; the campaign is verified by recomputing its fingerprint and
//! comparing it to the one that signed request names. The RP ID and the
//! authority URL an answer reports are **compared** to the vault's, never
//! adopted: a compromised origin naming another relying party would otherwise
//! have the operator's key answer a challenge for another domain.

use std::time::Duration;

use aether::certificates::encoding::{Fingerprint, Id16};
use aether::certificates::status::{AstraRotationCampaign, AstraSignerRequest, AstraSignerResult};
use anyhow::{bail, Context, Result};

/// Per-call timeout.
///
/// The operator is standing at a prompt with a security key in hand. A long
/// wait there is worse than a clear refusal, and the window they are inside is
/// five minutes wide.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Ceiling on any answer (spec §8.2).
const MAX_ANSWER_BYTES: usize = 128 * 1024;

/// What the companion fetched, and what it must not believe.
#[derive(Debug)]
pub struct CampaignRequest {
    pub operation_id: Id16,
    /// Signed by Astra's service key. Verified by the caller against the
    /// hand-off it already holds.
    pub signer_request: Box<AstraSignerRequest>,
    /// The text the operator reads. Its fingerprint is the challenge.
    pub campaign: Box<AstraRotationCampaign>,
    /// What the origin says its relying party is. Compared, never adopted.
    pub webauthn_rp_id: String,
    pub webauthn_origin: String,
    /// Capability token for the submission route.
    pub result_token: String,
    /// Capability token for the encrypted vault, when the scope needs one.
    pub vault_token: Option<String>,
}

/// One Astra public origin.
pub struct Origin {
    base: String,
    http: reqwest::blocking::Client,
}

impl Origin {
    pub fn new(authority_url: &str) -> Result<Self> {
        let base = authority_url.trim_end_matches('/').to_string();
        if !base.starts_with("https://") {
            bail!(
                "l'origine de l'autorité doit être en https:// : {base}. Ce canal sort du tunnel, \
                 et c'est TLS qui l'authentifie."
            );
        }
        Ok(Self {
            base,
            http: reqwest::blocking::Client::builder()
                .timeout(CALL_TIMEOUT)
                // A capability token travels in the header. An inherited proxy
                // would see every one of them.
                .no_proxy()
                // No route here redirects. Following one would carry the
                // tokens, and later the operator's assertion, to whatever host
                // the answer named.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("client HTTP de l'origine Astra")?,
        })
    }

    /// Reads the operation, then the campaign it is waiting on.
    ///
    /// Two calls and not one: the tokens are minted per read and live five
    /// minutes at most, so the companion takes them as late as it can — the
    /// operator may be several minutes from touching their key.
    pub fn fetch(&self, operation_id: &Id16) -> Result<CampaignRequest> {
        let view: astra::signing::SigningOperationView = self
            .get(
                &format!("{}/v1/operations/{}", self.base, operation_id.to_hex()),
                None,
            )
            .context("lecture de l'opération")?;

        if view.operation_id != *operation_id {
            bail!(
                "l'autorité a répondu au sujet de l'opération {} et non de {}",
                view.operation_id.to_hex(),
                operation_id.to_hex()
            );
        }
        if view.state != astra::signing::SigningOperationState::AwaitingOperator {
            bail!(
                "cette campagne est déjà approuvée : une seconde assertion ne changerait rien, et \
                 l'autorité la refuserait comme un conflit."
            );
        }
        let read_token = view.signer_request_token.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "l'opération ne délivre plus de jeton de lecture : sa fenêtre est passée. \
                 Rouvrir la campagne par `astra campaign open`."
            )
        })?;
        let result_token = view.signer_result_token.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "l'opération ne délivre plus de jeton de dépôt : sa fenêtre est passée. \
                 Rouvrir la campagne par `astra campaign open`."
            )
        })?;

        let answer: SignerRequestAnswer = self
            .get(
                &format!("{}/v1/signer-requests/{}", self.base, operation_id.to_hex()),
                Some(&read_token),
            )
            .context("lecture de la demande de signature")?;

        if answer.signer_request.operation_id != *operation_id {
            bail!(
                "la demande porte l'opération {} et non {}",
                answer.signer_request.operation_id.to_hex(),
                operation_id.to_hex()
            );
        }
        // The campaign is what the operator reads and what their key answers.
        // Binding it to the *signed* request here is what stops the origin
        // from displaying one text and having a token authorize another.
        answer
            .campaign
            .assert_unchanged(&answer.signer_request.campaign_fingerprint)
            .context("la campagne servie n'est pas celle que la demande signée nomme")?;
        if !view
            .campaign_fingerprint
            .matches(&answer.campaign.fingerprint())
        {
            bail!(
                "l'opération est liée à un manifeste différent de la campagne servie : le jeton \
                 de capacité vaut pour un manifeste, et ce n'est pas celui-là"
            );
        }

        Ok(CampaignRequest {
            operation_id: *operation_id,
            signer_request: answer.signer_request,
            campaign: answer.campaign,
            webauthn_rp_id: answer.webauthn_rp_id,
            webauthn_origin: answer.webauthn_origin,
            result_token,
            vault_token: view.vault_token,
        })
    }

    /// Downloads the encrypted vault this campaign names.
    ///
    /// Encrypted, and there is no other form: the origin holds no key-slot
    /// secret. The bytes are checked against the fingerprint the **signed**
    /// request names before they are handed to a caller, so a substituted file
    /// is refused here rather than at an unlock that fails obscurely.
    pub fn encrypted_vault(
        &self,
        request: &CampaignRequest,
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
            .get(format!("{}/v1/vaults/{}", self.base, expected.to_hex()))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .context("téléchargement du coffre chiffré")?;
        let status = response.status();
        if !status.is_success() {
            bail!(Self::refusal(status.as_u16()));
        }
        let bytes = response.bytes().context("lecture du coffre")?;
        if bytes.len() > MAX_ANSWER_BYTES {
            bail!(
                "l'autorité a renvoyé {} octets : au-delà de la borne de cette route",
                bytes.len()
            );
        }
        let bytes = zeroize::Zeroizing::new(bytes.to_vec());
        if !Fingerprint::of(&bytes).matches(&expected) {
            bail!(
                "le coffre reçu n'est pas celui que la demande signée nomme. Ne pas l'ouvrir : \
                 c'est un autre fichier."
            );
        }
        Ok(bytes)
    }

    /// Posts the operator's approval, and reports where the operation landed.
    ///
    /// Replaying the identical result is idempotent; different bytes under the
    /// same identifier are a conflict Astra decides.
    pub fn submit(
        &self,
        operation_id: &Id16,
        result_token: &str,
        result: &AstraSignerResult,
    ) -> Result<astra::signing::SigningOperationState> {
        let body = serde_json::to_vec(result).context("encodage du résultat de campagne")?;
        let response = self
            .http
            .post(format!(
                "{}/v1/signer-results/{}",
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
        let view: astra::signing::SigningOperationView = Self::decode(response)?;
        Ok(view.state)
    }

    fn get<T: serde::de::DeserializeOwned>(&self, url: &str, token: Option<&str>) -> Result<T> {
        let mut request = self.http.get(url);
        if let Some(token) = token {
            request = request.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        Self::decode(request.send().context("appel de l'autorité")?)
    }

    fn decode<T: serde::de::DeserializeOwned>(response: reqwest::blocking::Response) -> Result<T> {
        let status = response.status();
        if !status.is_success() {
            bail!(Self::refusal(status.as_u16()));
        }
        let bytes = response.bytes().context("lecture de la réponse")?;
        if bytes.len() > MAX_ANSWER_BYTES {
            bail!(
                "l'autorité a renvoyé {} octets : au-delà de la borne de cette route",
                bytes.len()
            );
        }
        serde_json::from_slice(&bytes).context("réponse illisible")
    }

    /// The public refusals of §8.2, which deliberately say very little.
    ///
    /// They do not distinguish an unknown operation from an expired one, nor a
    /// bad token from a wrong one — before a valid proof, the endpoint tells a
    /// caller nothing about what exists. What is worth naming is where the
    /// operator should go next, and that depends only on the class.
    fn refusal(code: u16) -> String {
        match code {
            400 => "l'autorité a refusé la requête (400) : identifiant ou jeton malformé.".into(),
            403 => {
                "refusé (403). Le jeton vaut cinq minutes, pour une opération et un manifeste — \
                    ou l'opération n'existe plus. Rouvrir la campagne par `astra campaign open`."
                    .into()
            }
            429 => "l'autorité limite cette source (429) : réessayer dans une minute.".into(),
            501 => "cette route n'est pas servie par cette version d'Astra (501).".into(),
            code => format!(
                "l'autorité a refusé ({code}). Le motif détaillé reste dans son journal protégé : \
                 le canal public ne le renvoie jamais à l'appelant."
            ),
        }
    }
}

/// The shape `GET /v1/signer-requests/<id>` answers with.
///
/// Declared here rather than imported from `astra` because it is what the
/// companion **reads**, and a decoder that shared the server's type would
/// silently accept whatever that type grew next.
#[derive(Debug, serde::Deserialize)]
struct SignerRequestAnswer {
    signer_request: Box<AstraSignerRequest>,
    campaign: Box<AstraRotationCampaign>,
    #[allow(dead_code)]
    credential_registry: Box<aether::certificates::approval::CredentialRegistry>,
    webauthn_rp_id: String,
    webauthn_origin: String,
}
