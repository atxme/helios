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
pub(crate) const MAX_ANSWER_BYTES: usize = 128 * 1024;

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
    /// The origin this client dials, normalized.
    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn fetch(&self, operation_id: &Id16) -> Result<CampaignRequest> {
        let view: aether::certificates::transport::SigningOperationView = self
            .get(
                &format!("{}/v1/operations/{}", self.base, operation_id.to_hex()),
                None,
            )
            .context("lecture de l'opération")?;

        let answer: SignerRequestAnswer = {
            let read_token = Self::read_token(operation_id, &view)?;
            self.get(
                &format!("{}/v1/signer-requests/{}", self.base, operation_id.to_hex()),
                Some(&read_token),
            )
            .context("lecture de la demande de signature")?
        };
        Self::accept(operation_id, view, answer)
    }

    /// The read token this operation still delivers, or the reason it does not.
    ///
    /// Separate from [`Self::accept`] because it is the one thing the caller
    /// needs *before* the second call, and the only reason `fetch` reads the
    /// view twice would otherwise be to hand it over.
    pub(crate) fn read_token(
        operation_id: &Id16,
        view: &aether::certificates::transport::SigningOperationView,
    ) -> Result<String> {
        Self::assert_view(operation_id, view)?;
        view.signer_request_token.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "l'opération ne délivre plus de jeton de lecture : sa fenêtre est passée. \
                 Rouvrir la campagne par `astra campaign open`."
            )
        })
    }

    /// What an operation read must say before anything else is asked of it.
    fn assert_view(
        operation_id: &Id16,
        view: &aether::certificates::transport::SigningOperationView,
    ) -> Result<()> {
        if view.operation_id != *operation_id {
            bail!(
                "l'autorité a répondu au sujet de l'opération {} et non de {}",
                view.operation_id.to_hex(),
                operation_id.to_hex()
            );
        }
        if view.state != aether::certificates::transport::SigningOperationState::AwaitingOperator {
            bail!(
                "cette campagne est déjà approuvée : une seconde assertion ne changerait rien, et \
                 l'autorité la refuserait comme un conflit."
            );
        }
        Ok(())
    }

    /// Everything the two answers must agree on before the operator is asked.
    ///
    /// Kept apart from the transport on purpose: nothing here is about HTTP,
    /// and all of it is about what the origin is not allowed to decide — which
    /// operation this is, whether it still awaits a touch, and that the text
    /// the operator will read is the one the *signed* request names.
    pub(crate) fn accept(
        operation_id: &Id16,
        view: aether::certificates::transport::SigningOperationView,
        answer: SignerRequestAnswer,
    ) -> Result<CampaignRequest> {
        Self::assert_view(operation_id, &view)?;
        let result_token = view.signer_result_token.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "l'opération ne délivre plus de jeton de dépôt : sa fenêtre est passée. \
                 Rouvrir la campagne par `astra campaign open`."
            )
        })?;

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
        Self::accept_vault(request, bytes.to_vec())
    }

    /// The vault bytes, or a refusal that says not to open them.
    ///
    /// The fingerprint compared is the one the **signed** request names, so a
    /// substituted file is refused here rather than at an unlock that fails
    /// obscurely — with an operator holding a security key and no idea which
    /// of the two halves is wrong.
    pub(crate) fn accept_vault(
        request: &CampaignRequest,
        bytes: Vec<u8>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let expected = request.signer_request.encrypted_vault_fingerprint;
        let bytes = zeroize::Zeroizing::new(bytes);
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
    ) -> Result<aether::certificates::transport::SigningOperationState> {
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
        let view: aether::certificates::transport::SigningOperationView = Self::decode(response)?;
        Ok(view.state)
    }

    /// Reads one §7.5 recovery.
    ///
    /// No token: everything it returns is public material — two expired
    /// leaves, a CSR, a public key, a receipt. The private halves are the
    /// client's and the anchor is in the vault; knowing the identifier confers
    /// nothing.
    pub fn recovery(
        &self,
        operation_id: &Id16,
    ) -> Result<aether::certificates::transport::ExpiredRecoveryOperationView> {
        let view: aether::certificates::transport::ExpiredRecoveryOperationView = self
            .get(
                &format!(
                    "{}/v1/client-rotation/recovery/{}",
                    self.base,
                    operation_id.to_hex()
                ),
                None,
            )
            .context("lecture de la récupération")?;
        if view.operation_id != *operation_id {
            bail!(
                "l'autorité a répondu au sujet de l'opération {} et non de {}",
                view.operation_id.to_hex(),
                operation_id.to_hex()
            );
        }
        Ok(view)
    }

    /// Deposits the approval and the `CA-PQ` staging one ceremony produced.
    pub fn deposit_recovery_authorization(
        &self,
        operation_id: &Id16,
        deposit: &aether::certificates::transport::ExpiredRecoveryAuthorizationDeposit,
    ) -> Result<aether::certificates::transport::ExpiredRecoveryOperationView> {
        self.post(
            &format!(
                "{}/v1/client-rotation/recovery/{}/authorization",
                self.base,
                operation_id.to_hex()
            ),
            deposit,
        )
    }

    /// Deposits the grant signed against the gateway's receipt.
    pub fn deposit_recovery_grant(
        &self,
        operation_id: &Id16,
        deposit: &aether::certificates::transport::ExpiredRecoveryGrantDeposit,
    ) -> Result<aether::certificates::transport::ExpiredRecoveryOperationView> {
        self.post(
            &format!(
                "{}/v1/client-rotation/recovery/{}/grant",
                self.base,
                operation_id.to_hex()
            ),
            deposit,
        )
    }

    fn post<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<T> {
        let encoded = serde_json::to_vec(body).context("encodage de la requête")?;
        let response = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(encoded)
            .send()
            .context("appel de l'autorité")?;
        Self::decode(response)
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
    pub(crate) fn refusal(code: u16) -> String {
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
pub(crate) struct SignerRequestAnswer {
    pub(crate) signer_request: Box<AstraSignerRequest>,
    pub(crate) campaign: Box<AstraRotationCampaign>,
    #[allow(dead_code)]
    pub(crate) credential_registry: Box<aether::certificates::approval::CredentialRegistry>,
    pub(crate) webauthn_rp_id: String,
    pub(crate) webauthn_origin: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::approval::CredentialRegistry;
    use aether::certificates::encoding::{MlDsa87Signature, TrustDomainId, WireGuardKey};
    use aether::certificates::status::{
        CampaignScope, CampaignTarget, CertificateKind, MAX_CAMPAIGN_TARGETS,
    };
    use aether::certificates::transport::{SigningOperationState, SigningOperationView};
    use aether::certificates::CERTIFICATE_FORMAT_VERSION;

    const NOW: u64 = 1_700_000_000;

    fn operation() -> Id16 {
        Id16::new([4; 16]).expect("id")
    }

    fn campaign() -> Box<AstraRotationCampaign> {
        let scope = CampaignScope::FleetLeafs;
        Box::new(AstraRotationCampaign {
            format_version: CERTIFICATE_FORMAT_VERSION,
            campaign_id: Id16::new([7; 16]).expect("id"),
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            server_name: "gateway.example".into(),
            created_at: NOW,
            expires_at: NOW + 300,
            scope,
            targets: vec![CampaignTarget {
                certificate_kind: CertificateKind::ClientPq,
                identity_key: WireGuardKey::from_bytes([3; 32]),
                epoch: 1,
                generation: 4,
                active_tls_certificate_fingerprint: Fingerprint::of(b"tls"),
                active_pq_certificate_fingerprint: Fingerprint::of(b"pq"),
            }],
            reason: "rotation trimestrielle".into(),
            requested_by: "operator".into(),
            policy_fingerprint: Fingerprint::of(b"policy"),
            required_credentials: scope.required_credentials(),
        })
    }

    fn signer_request(
        campaign: &AstraRotationCampaign,
        vault: Fingerprint,
    ) -> Box<AstraSignerRequest> {
        Box::new(AstraSignerRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: operation(),
            campaign_fingerprint: campaign.fingerprint(),
            authority_url: "https://astra.example".into(),
            encrypted_vault_fingerprint: vault,
            required_credentials: campaign.required_credentials,
            created_at: NOW,
            expires_at: NOW + 300,
            astra_service_key_epoch: 1,
            astra_signature: MlDsa87Signature::placeholder(),
        })
    }

    fn view(campaign: &AstraRotationCampaign) -> SigningOperationView {
        SigningOperationView {
            operation_id: operation(),
            state: SigningOperationState::AwaitingOperator,
            scope: campaign.scope,
            target_count: campaign.targets.len(),
            required_credentials: campaign.required_credentials,
            campaign_fingerprint: campaign.fingerprint(),
            created_at: NOW,
            expires_at: NOW + 300,
            signer_request_token: Some("read".into()),
            vault_token: None,
            signer_result_token: Some("submit".into()),
        }
    }

    fn answer(campaign: Box<AstraRotationCampaign>, vault: Fingerprint) -> SignerRequestAnswer {
        SignerRequestAnswer {
            signer_request: signer_request(&campaign, vault),
            campaign,
            credential_registry: Box::new(CredentialRegistry {
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                ca_epoch: 1,
                credential_registry_epoch: 1,
                bindings: Vec::new(),
            }),
            webauthn_rp_id: "astra.example".into(),
            webauthn_origin: "https://astra.example".into(),
        }
    }

    struct ObservedRequest {
        headers: String,
        body: Vec<u8>,
    }

    fn loopback_origin(
        responses: Vec<Vec<u8>>,
    ) -> (
        Origin,
        std::sync::mpsc::Receiver<ObservedRequest>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("listener address");
        listener.set_nonblocking(true).expect("bounded accept mode");
        let (sender, receiver) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = accept_with_timeout(&listener);
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("request timeout");
                let mut bytes = Vec::new();
                let header_end = loop {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).expect("request header");
                    bytes.push(byte[0]);
                    if bytes.ends_with(b"\r\n\r\n") {
                        break bytes.len();
                    }
                };
                let headers = String::from_utf8(bytes[..header_end].to_vec()).expect("headers");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("content length"))
                    })
                    .unwrap_or_default();
                let mut body = vec![0; content_length];
                stream.read_exact(&mut body).expect("request body");
                sender
                    .send(ObservedRequest { headers, body })
                    .expect("request observer");
                stream.write_all(&response).expect("write response");
            }
        });
        let base = format!("http://{address}");
        // The production constructor requires HTTPS. These loopback adapter
        // tests bypass TLS construction to exercise route and HTTP semantics
        // without creating a certificate authority or reaching the network.
        let origin = Origin {
            base,
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(2))
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("test HTTP client"),
        };
        (origin, receiver, server)
    }

    fn accept_with_timeout(
        listener: &std::net::TcpListener,
    ) -> (std::net::TcpStream, std::net::SocketAddr) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok(connection) => return connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("timed out waiting for loopback request: {error}"),
            }
        }
    }

    fn json_response<T: serde::Serialize>(status: &str, value: &T) -> Vec<u8> {
        let body = serde_json::to_vec(value).expect("JSON response");
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        response
    }

    fn signer_answer_json(answer: &SignerRequestAnswer) -> serde_json::Value {
        serde_json::json!({
            "signer_request": answer.signer_request,
            "campaign": answer.campaign,
            "credential_registry": answer.credential_registry,
            "webauthn_rp_id": answer.webauthn_rp_id,
            "webauthn_origin": answer.webauthn_origin,
        })
    }

    #[test]
    fn fetch_uses_the_read_capability_only_on_the_signer_request_route() {
        let campaign = campaign();
        let vault_fingerprint = Fingerprint::of(b"encrypted vault");
        let operation_id = operation();
        let operation_view = view(&campaign);
        let signer_answer = answer(campaign.clone(), vault_fingerprint);
        let responses = vec![
            json_response("200 OK", &operation_view),
            json_response("200 OK", &signer_answer_json(&signer_answer)),
        ];
        let (origin, observed, server) = loopback_origin(responses);

        let fetched = origin.fetch(&operation_id).expect("fetch campaign");
        assert_eq!(fetched.result_token, "submit");
        assert_eq!(fetched.campaign.fingerprint(), campaign.fingerprint());
        let first = observed
            .recv_timeout(Duration::from_secs(5))
            .expect("operation read");
        let second = observed
            .recv_timeout(Duration::from_secs(5))
            .expect("signer request read");
        assert!(first
            .headers
            .starts_with(&format!("GET /v1/operations/{} ", operation_id.to_hex())));
        assert!(!first
            .headers
            .to_ascii_lowercase()
            .contains("authorization:"));
        assert!(second.headers.starts_with(&format!(
            "GET /v1/signer-requests/{} ",
            operation_id.to_hex()
        )));
        assert!(second
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer read"));
        assert!(first.body.is_empty() && second.body.is_empty());
        server.join().expect("loopback server");
    }

    #[test]
    fn submit_posts_the_approval_with_the_result_capability() {
        use aether::certificates::status::CampaignApproval;

        let campaign = campaign();
        let operation_id = operation();
        let mut expected_view = view(&campaign);
        expected_view.state = SigningOperationState::Approved;
        let (origin, observed, server) =
            loopback_origin(vec![json_response("200 OK", &expected_view)]);
        let result = AstraSignerResult {
            format_version: CERTIFICATE_FORMAT_VERSION,
            approval: Box::new(CampaignApproval {
                campaign_id: campaign.campaign_id,
                campaign_fingerprint: campaign.fingerprint(),
                required_credentials: campaign.required_credentials,
                approved_at: NOW + 1,
                approvals: Vec::new(),
            }),
            objects: Vec::new(),
            credential_registry: None,
            issuer_authorization: None,
        };

        assert_eq!(
            origin
                .submit(&operation_id, "submit-secret", &result)
                .expect("approval submitted"),
            SigningOperationState::Approved
        );
        let request = observed
            .recv_timeout(Duration::from_secs(5))
            .expect("result POST");
        assert!(request.headers.starts_with(&format!(
            "POST /v1/signer-results/{} ",
            operation_id.to_hex()
        )));
        assert!(request
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer submit-secret"));
        assert!(request
            .headers
            .to_ascii_lowercase()
            .contains("content-type: application/json"));
        let decoded: AstraSignerResult =
            serde_json::from_slice(&request.body).expect("posted result JSON");
        assert_eq!(decoded, result);
        server.join().expect("loopback server");
    }

    #[test]
    fn encrypted_vault_fetch_is_fingerprint_bound_and_requires_its_capability() {
        let campaign = campaign();
        let operation_id = operation();
        let bytes = b"encrypted HVLT fixture".to_vec();
        let fingerprint = Fingerprint::of(&bytes);
        let mut operation_view = view(&campaign);
        operation_view.vault_token = Some("vault-secret".into());
        let request = Origin::accept(
            &operation_id,
            operation_view,
            answer(campaign.clone(), fingerprint),
        )
        .expect("accepted campaign answer");
        let response = {
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            )
            .into_bytes();
            response.extend_from_slice(&bytes);
            response
        };
        let (origin, observed, server) = loopback_origin(vec![response]);
        assert_eq!(
            origin
                .encrypted_vault(&request)
                .expect("download encrypted bytes")
                .as_slice(),
            bytes.as_slice()
        );
        let wire = observed
            .recv_timeout(Duration::from_secs(5))
            .expect("vault request");
        assert!(wire
            .headers
            .starts_with(&format!("GET /v1/vaults/{} ", fingerprint.to_hex())));
        assert!(wire
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer vault-secret"));
        server.join().expect("loopback server");

        let mut no_token_view = view(&campaign);
        no_token_view.vault_token = None;
        let no_token_request =
            Origin::accept(&operation_id, no_token_view, answer(campaign, fingerprint))
                .expect("campaign without vault capability");
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("token-check listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking token-check listener");
        let address = listener.local_addr().expect("listener address");
        let no_token_origin = Origin {
            base: format!("http://{address}"),
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_millis(250))
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("test HTTP client"),
        };
        let error = no_token_origin
            .encrypted_vault(&no_token_request)
            .expect_err("missing vault capability must fail before HTTP");
        assert!(error
            .to_string()
            .contains("ne délivre pas de jeton de coffre"));
        assert!(
            matches!(
                listener.accept(),
                Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock
            ),
            "a missing capability must produce no TCP connection"
        );
    }

    #[test]
    fn public_refusal_statuses_hide_the_authority_response_body() {
        let detail = b"private operator detail";
        for (status, expected_hint) in [
            (400, "400"),
            (403, "Rouvrir la campagne"),
            (429, "une minute"),
            (501, "version d'Astra"),
            (503, "503"),
        ] {
            let mut response = format!(
                "HTTP/1.1 {status} Refused\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                detail.len()
            )
            .into_bytes();
            response.extend_from_slice(detail);
            let (origin, observed, server) = loopback_origin(vec![response]);
            let error = origin.fetch(&operation()).expect_err("status refusal");
            let message = format!("{error:#}");
            assert!(message.contains(expected_hint), "{message}");
            assert!(
                !message.contains("private operator detail"),
                "the response body must not cross the public error boundary"
            );
            let request = observed
                .recv_timeout(Duration::from_secs(5))
                .expect("operation GET");
            assert!(request.headers.starts_with("GET /v1/operations/"));
            server.join().expect("loopback server");
        }
    }

    #[test]
    fn oversized_operation_answers_stop_before_the_signer_request_route() {
        let campaign = campaign();
        let valid_view = view(&campaign);
        let mut oversized = serde_json::to_vec(&valid_view).expect("valid operation JSON");
        assert!(oversized.len() < MAX_ANSWER_BYTES);
        oversized.resize(MAX_ANSWER_BYTES + 1, b' ');
        let _: SigningOperationView =
            serde_json::from_slice(&oversized).expect("oversized body remains valid JSON");
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            oversized.len()
        )
        .into_bytes();
        response.extend_from_slice(&oversized);
        let (origin, observed, server) = loopback_origin(vec![response]);
        let error = origin
            .fetch(&operation())
            .expect_err("answer ceiling enforced");
        assert!(
            format!("{error:#}").contains("au-delà de la borne"),
            "{error:#}"
        );
        let request = observed
            .recv_timeout(Duration::from_secs(5))
            .expect("operation GET");
        assert!(request.headers.starts_with("GET /v1/operations/"));
        assert!(
            observed.try_recv().is_err(),
            "no signer request after oversized view"
        );
        server.join().expect("loopback server");
    }

    /// This channel leaves the tunnel, so TLS is what authenticates it. A
    /// plain-text origin is refused before a single token could travel on it.
    #[test]
    fn an_origin_that_is_not_https_is_refused() {
        assert!(Origin::new("http://astra.example").is_err());
        assert!(Origin::new("astra.example").is_err());
        Origin::new("https://astra.example/").expect("an https origin");
    }

    /// The two answers must agree, and they must agree about *this* operation.
    #[test]
    fn the_campaign_served_must_be_the_one_the_signed_request_names() {
        let campaign = campaign();
        let vault = Fingerprint::of(b"vault");
        let request = Origin::accept(
            &operation(),
            view(&campaign),
            answer(campaign.clone(), vault),
        )
        .expect("both answers describe one campaign");
        assert_eq!(request.operation_id, operation());
        assert_eq!(request.result_token, "submit");
        // Compared, never adopted: the caller checks these against the vault.
        assert_eq!(request.webauthn_rp_id, "astra.example");

        // A campaign whose text moved after the request was signed. Its
        // fingerprint no longer matches, so the token would authorize a
        // decision the operator never read.
        let mut moved = campaign.clone();
        moved.reason = "autre chose".into();
        assert!(Origin::accept(&operation(), view(&campaign), answer(moved, vault),).is_err());
    }

    /// An origin answering about another operation is answering about another
    /// operator's touch.
    #[test]
    fn an_answer_about_another_operation_is_refused() {
        let campaign = campaign();
        let vault = Fingerprint::of(b"vault");

        let mut elsewhere = view(&campaign);
        elsewhere.operation_id = Id16::new([9; 16]).expect("id");
        assert!(Origin::accept(&operation(), elsewhere, answer(campaign.clone(), vault)).is_err());

        // And the reverse: the signed request naming another operation.
        let mut other_answer = answer(campaign.clone(), vault);
        other_answer.signer_request.operation_id = Id16::new([9; 16]).expect("id");
        assert!(Origin::accept(&operation(), view(&campaign), other_answer).is_err());
    }

    /// A campaign already approved does not take a second assertion: the
    /// authority would refuse it as a conflict, and asking for a touch that
    /// cannot land is the one thing a companion must not do.
    #[test]
    fn an_operation_already_approved_asks_for_no_second_touch() {
        let campaign = campaign();
        let vault = Fingerprint::of(b"vault");
        let mut spent = view(&campaign);
        spent.state = SigningOperationState::Approved;
        let refusal = Origin::accept(&operation(), spent, answer(campaign, vault))
            .expect_err("an approved campaign opens no second ceremony");
        assert!(refusal.to_string().contains("déjà approuvée"));
    }

    /// A window that has passed takes its tokens with it, and the refusal says
    /// which gesture reopens one rather than failing at the deposit.
    #[test]
    fn an_operation_without_its_tokens_is_refused_by_name() {
        let campaign = campaign();
        let vault = Fingerprint::of(b"vault");

        let mut no_read = view(&campaign);
        no_read.signer_request_token = None;
        let refusal = Origin::read_token(&operation(), &no_read).expect_err("no read token");
        assert!(refusal.to_string().contains("astra campaign open"));

        let mut no_submit = view(&campaign);
        no_submit.signer_result_token = None;
        assert!(Origin::accept(&operation(), no_submit, answer(campaign, vault)).is_err());
    }

    /// The vault is compared against the fingerprint the **signed** request
    /// names. A substituted file is refused here, not at an unlock that fails
    /// obscurely with a security key already in hand.
    #[test]
    fn a_vault_that_is_not_the_one_the_request_names_is_refused() {
        let campaign = campaign();
        let bytes = b"an encrypted vault".to_vec();
        let request = Origin::accept(
            &operation(),
            view(&campaign),
            answer(campaign, Fingerprint::of(&bytes)),
        )
        .expect("request");

        let opened = Origin::accept_vault(&request, bytes.clone()).expect("the named vault");
        assert_eq!(opened.as_slice(), bytes.as_slice());

        let refusal = Origin::accept_vault(&request, b"another file entirely".to_vec())
            .expect_err("a substituted vault");
        assert!(refusal.to_string().contains("Ne pas l'ouvrir"));
    }

    /// The ceiling of §8.2 is a real bound, and the campaign fixture stays
    /// under it — a test that resolved more targets than the format allows
    /// would be testing a document the authority never emits.
    #[test]
    fn the_fixture_campaign_is_one_an_authority_could_actually_emit() {
        let campaign = campaign();
        assert!(campaign.targets.len() <= MAX_CAMPAIGN_TARGETS);
        campaign
            .validate(NOW + 1)
            .expect("a campaign an operator may read");
    }
}
