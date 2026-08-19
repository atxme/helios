//! The client half of the relayed renewal — spec §8.1.2.
//!
//! # What this module is, and what it deliberately is not
//!
//! A client whose leaf reaches 80 % of its life has to obtain a new one before
//! the old one expires, and it has exactly one way to do that while WireGuard
//! works: the five typed routes the gateway serves **inside the tunnel**. It
//! never dials Astra. `heliosd` resolves the peer from its VIP, relays a
//! canonical object it builds itself, and hands back what the authority
//! answered.
//!
//! The eight steps of §8.1.2 collapse, from this side, into six — two of them
//! this client's, four of them somebody else's:
//!
//! 1. **here** — generate the candidate keys, sign
//!    [`ClientCertificateRotationRequest`], post it to `request`;
//! 2. Helios authenticates the peer and relays;
//! 3. Astra opens an `awaiting_operator` operation;
//! 4. the **companion** answers the WebAuthn challenge through the two
//!    `signer-*` routes;
//! 5. Astra issues, Helios persists the candidate and signs its receipt, and
//!    Astra releases the grant — three steps this client only observes;
//! 6. **here** — verify the grant against what this store already trusts,
//!    persist the candidate, sign [`ClientCertificateStageCommit`], post it to
//!    `stage-commit`, and commit locally.
//!
//! Step 4 is the operator's, not Orion's, and this module does not attempt it:
//! Orion's job is to expose the operation so that a surface can launch
//! `astra-signer` with `heliosd_url` and `operation_id`, then keep polling.
//!
//! # Why the private keys never leave this process
//!
//! Both halves of the candidate identity — the TLS key and the ML-DSA-87 key —
//! are generated here and stay here. What travels is a PKCS#10 request and a
//! public key, each covered by a signature made with the matching private
//! half. That is what makes the grant's binding check meaningful: the
//! authority certifies a key somebody proved they hold, and
//! [`ClientCertificateRotationGrant::verify`] then refuses a leaf that
//! certifies any other one.
//!
//! # Why nothing is written before the grant verifies
//!
//! The candidate keys live in [`RenewalSession`] and are written to the
//! protected store only at the commit, in the same step that installs the
//! candidate generation. An interrupted renewal therefore leaves **nothing**:
//! no half-sealed identity, no orphan key, no slot naming a certificate this
//! machine has no private key for. The cost is that a crash loses the keys and
//! the operation has to be reopened — which is the cheap failure, because the
//! active generation is untouched and still connects.
//!
//! # Limite connue : le compagnon ne se lance pas d'ici
//!
//! This module drives the operation and reports `awaiting_operator`; it does
//! not spawn `astra-signer`. The companion's own transport is still file-based
//! — the public routes of §8.2 answer `501` and the binary does not yet know
//! `heliosd_url` (spec §12.3, *non livré*). Until it does, a renewal reaches
//! `awaiting_operator` and stops there, which is why [`RenewalStep`] names
//! that state rather than treating it as an error.

use std::time::Duration;

use aether::certificates::client::{
    ClientCertificateRotationGrant, ClientCertificateRotationRequest, ClientCertificateStageCommit,
};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature,
};
use aether::certificates::transport::{ClientRenewalOperationState, ClientRenewalOperationView};
use aether::certificates::x509::{client_rotation_csr, ClientRotationCsr};
use aether::certificates::{
    CertificateError, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::certificates::TrustStore;
use crate::identity_store::ClientIdentityBundle;

/// How long a rotation request stays valid once signed.
///
/// One hour, well under the 24 h ceiling `MAX_REQUEST_LIFETIME_SECS` allows.
/// The request is answered in seconds when the operator is present; a long
/// window would only widen the interval during which a captured request could
/// be replayed into an operation the user has since abandoned.
pub const REQUEST_LIFETIME_SECS: u64 = 3_600;

/// Per-call timeout on the in-tunnel routes.
///
/// The tunnel is up — that is the precondition of this whole path — so a call
/// that takes longer than this is a gateway that is not answering, not a slow
/// link. Failing fast matters because the caller is a scheduler that will try
/// again, not a user waiting on a spinner.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Ceiling on any answer read from the gateway.
///
/// A grant carries two certificates and a receipt; 256 KiB is generous. The
/// bound exists because the peer on the other end of a tunnel is still a peer:
/// an unbounded read lets it choose this client's allocation.
const MAX_ANSWER_BYTES: u64 = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RenewalError {
    #[error("renewal refused: {0}")]
    Certificate(#[from] CertificateError),
    #[error("trust store: {0}")]
    Trust(#[from] crate::certificates::TrustError),
    #[error("protected identity store: {0}")]
    Identity(String),
    #[error("the gateway did not answer the renewal route: {0}")]
    Transport(String),
    #[error(
        "la gateway a refusé le renouvellement ({status}). Le motif détaillé reste dans son \
         journal : le canal in-tunnel ne le renvoie jamais au client."
    )]
    Refused { status: u16 },
    #[error(
        "cette gateway ne relaie aucune autorité de certification. Astra n'est pas déployé, ou \
         son canal privé est tombé — le renouvellement n'a pas d'autre chemin tant que le tunnel \
         fonctionne."
    )]
    AuthorityUnavailable,
    #[error("the gateway's answer is not a renewal operation: {0}")]
    Malformed(String),
    #[error(
        "l'opération de renouvellement a échoué côté autorité. Aucune assertion n'est plus \
         acceptée sous cet identifiant : en ouvrir une nouvelle."
    )]
    OperationFailed,
    #[error("the operation named {returned} instead of {expected}")]
    OperationMismatch { expected: String, returned: String },
    #[error(
        "l'autorité annonce un grant disponible et n'en joint aucun : l'opération est \
         inutilisable en l'état."
    )]
    GrantMissing,
    #[error("the local clock is before the Unix epoch")]
    Clock,
}

/// The five in-tunnel routes, resolved against one gateway.
///
/// The base is the same `heliosd_url` the rest of Orion already uses — the
/// gateway's VIP inside WireGuard. Nothing here ever falls back to Astra's
/// public origin: §8.1.2 reserves that channel for a client that cannot
/// establish WireGuard at all, and a silent fallback would turn a tunnel
/// failure into an unauthenticated request to a public endpoint.
#[derive(Debug, Clone)]
pub struct RenewalRoutes {
    base: String,
}

impl RenewalRoutes {
    pub fn new(heliosd_url: &str) -> Self {
        Self {
            base: heliosd_url.trim_end_matches('/').to_string(),
        }
    }

    fn request(&self) -> String {
        format!(
            "{}/api/key-negotiation/certificate-renewal/request",
            self.base
        )
    }

    fn operation(&self, operation_id: &Id16) -> String {
        format!(
            "{}/api/key-negotiation/certificate-renewal/operations/{}",
            self.base,
            operation_id.to_hex()
        )
    }

    fn stage_commit(&self) -> String {
        format!(
            "{}/api/key-negotiation/certificate-renewal/stage-commit",
            self.base
        )
    }
}

/// Where a renewal stands, as a surface states it.
///
/// `AwaitingOperator` is a step and not a failure: it is where every renewal
/// legitimately waits, sometimes for hours, while a human finds their key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalStep {
    /// The request is in; the authority is waiting for the operator's
    /// hardware credential. The surface launches the companion from here.
    AwaitingOperator { operation_id: Id16 },
    /// The approval landed and the authority is issuing. Nothing to do but
    /// poll.
    Issuing { operation_id: Id16 },
    /// Committed locally and at the gateway. The candidate is the `next`
    /// generation and will activate at its window.
    Committed { generation: u64 },
}

/// Candidate key material, alive only for the duration of one renewal.
///
/// Not `Clone`, not `Serialize`: there is exactly one holder, and the only
/// two things that ever happen to it are signing and — once the grant has
/// verified — being sealed into the protected store.
pub struct CandidateKeys {
    tls: ClientRotationCsr,
    pq_private_key: Zeroizing<Vec<u8>>,
    pq_public_key: MlDsa87PublicKey,
}

impl CandidateKeys {
    /// Generates both halves of a candidate identity.
    ///
    /// `subject` is the common name the client is admitted under, carried
    /// through unchanged — a renewal asks for a new certificate, never for a
    /// different identity.
    pub fn generate(subject: &str) -> Result<Self, RenewalError> {
        let tls = client_rotation_csr(subject)?;
        let (pq_private_key, pq_public_key) = generate_ml_dsa_87_keypair()?;
        Ok(Self {
            tls,
            pq_private_key,
            pq_public_key,
        })
    }
}

impl std::fmt::Debug for CandidateKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CandidateKeys")
            .field("csr_bytes", &self.tls.csr.as_bytes().len())
            .field("tls_private_key", &"***")
            .field("pq_private_key", &"***")
            .finish()
    }
}

/// What the active generation contributes: its two private keys.
///
/// Read from the protected store by the caller, because this module has no
/// business deciding which identity a profile refers to — the profile names
/// it, and [`crate::identity_store`] is what unseals it.
pub struct ActiveIdentity {
    /// Raw ML-DSA-87 private key of the active generation. **Secret.**
    pub pq_private_key: Zeroizing<Vec<u8>>,
    /// PKCS#8 TLS private key of the active generation. **Secret.**
    ///
    /// Not used to sign anything here: it is carried so that the bundle
    /// written at commit time can keep the active certificate usable until
    /// the candidate activates.
    pub tls_private_key_der: Zeroizing<Vec<u8>>,
}

/// One renewal, from the request to the commit.
///
/// Holds the candidate keys and the signed request, because both are needed
/// again at step 8: the grant is bound to the request's fingerprint, and the
/// commit is signed by the candidate's PQ key.
pub struct RenewalSession {
    routes: RenewalRoutes,
    http: reqwest::Client,
    keys: CandidateKeys,
    request: ClientCertificateRotationRequest,
    operation_id: Option<Id16>,
}

impl RenewalSession {
    /// Builds and signs the rotation request against the store's active state.
    ///
    /// Every field comes from the trust store or from the freshly generated
    /// keys. Nothing is passed in that the store already knows, which is what
    /// keeps a caller from asking for a generation, a domain or a gateway the
    /// local state does not agree with — the request would be signed and then
    /// refused by the gateway, and the refusal is deliberately uninformative.
    pub fn prepare(
        store: &TrustStore,
        identity_subject: &str,
        heliosd_url: &str,
        now_unix: u64,
    ) -> Result<Self, RenewalError> {
        let state = store.state();
        let active = &state.certificates.active;
        let keys = CandidateKeys::generate(identity_subject)?;

        let mut request_id = [0u8; 16];
        aether::random::fill_public(&mut request_id)
            .map_err(|_| RenewalError::Certificate(CertificateError::RandomnessUnavailable))?;

        let request = ClientCertificateRotationRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            request_id: Id16::new(request_id)?,
            trust_domain_id: state.trust_domain_id,
            gateway_wg_public_key: state.gateway.gateway_wg_public_key,
            server_name: state.gateway.server_name.clone(),
            client_wg_public_key: state.client_wg_public_key,
            active_generation: active.generation,
            requested_generation: active
                .generation
                .checked_add(1)
                .ok_or(CertificateError::ArithmeticOverflow)?,
            active_tls_certificate_fingerprint: active.tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: active.pq_certificate_fingerprint,
            tls_csr: keys.tls.csr.clone(),
            new_ml_dsa_87_public_key: keys.pq_public_key.clone(),
            created_at: now_unix,
            expires_at: now_unix
                .checked_add(REQUEST_LIFETIME_SECS)
                .ok_or(CertificateError::ArithmeticOverflow)?,
            active_pq_signature: MlDsa87Signature::placeholder(),
            new_pq_signature: MlDsa87Signature::placeholder(),
        };

        Ok(Self {
            routes: RenewalRoutes::new(heliosd_url),
            http: reqwest::Client::builder()
                .timeout(CALL_TIMEOUT)
                // A renewal route never redirects. Following one would send a
                // signed request, and the tokens in the answer, to whatever
                // host a compromised gateway named.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| RenewalError::Transport(error.to_string()))?,
            keys,
            request,
            operation_id: None,
        })
    }

    /// Signs the prepared request with both private keys (spec §7.1).
    ///
    /// Two proofs, two keys: continuity by the generation being replaced, and
    /// possession by the one asking to be certified. Neither is derivable from
    /// the other, which is the point — a stolen active key cannot name a
    /// candidate whose private half the thief does not hold, and a generated
    /// key pair cannot claim to succeed a generation it has no continuity
    /// with.
    pub fn sign(&mut self, active: &ActiveIdentity) -> Result<(), RenewalError> {
        let signed = self
            .request
            .clone()
            .sign(&active.pq_private_key, &self.keys.pq_private_key)?;
        self.request = signed;
        Ok(())
    }

    /// The request as it will travel. Public so a caller can log its
    /// fingerprint, which is the identifier every other end reports it by.
    pub fn request(&self) -> &ClientCertificateRotationRequest {
        &self.request
    }

    pub fn request_fingerprint(&self) -> Fingerprint {
        self.request.fingerprint()
    }

    /// The operation this session opened, once it has one.
    pub fn operation_id(&self) -> Option<Id16> {
        self.operation_id
    }

    /// Step 1: hands the signed request to the gateway.
    ///
    /// Idempotent by the request's own bytes: the authority keys an operation
    /// on the request fingerprint, so a retry after a lost answer resumes the
    /// same operation rather than opening a second one and burning a
    /// generation.
    pub async fn open(&mut self) -> Result<RenewalStep, RenewalError> {
        let body = serde_json::to_vec(&self.request)
            .map_err(|error| RenewalError::Malformed(error.to_string()))?;
        let view = self.post(&self.routes.request(), body).await?;
        self.adopt(view)
    }

    /// Reads the operation, and finishes it when the grant is there.
    ///
    /// One method rather than "poll, then a second call the caller must
    /// remember to make": the grant is released exactly once, and a caller
    /// that read it and then failed to commit would have to re-poll for
    /// something the authority already handed over.
    pub async fn advance(
        &mut self,
        store: &mut TrustStore,
        active: &ActiveIdentity,
        now_unix: u64,
    ) -> Result<RenewalStep, RenewalError> {
        let operation_id = self.operation_id.ok_or_else(|| {
            RenewalError::Malformed("advanced a session that has not opened an operation".into())
        })?;
        let view = self.get(&self.routes.operation(&operation_id)).await?;
        self.check_identity(&view)?;
        match view.state {
            ClientRenewalOperationState::AwaitingOperator => {
                Ok(RenewalStep::AwaitingOperator { operation_id })
            }
            ClientRenewalOperationState::PendingGrant => Ok(RenewalStep::Issuing { operation_id }),
            ClientRenewalOperationState::Failed => Err(RenewalError::OperationFailed),
            ClientRenewalOperationState::PendingCommit => {
                let grant = view.grant.ok_or(RenewalError::GrantMissing)?;
                self.commit(store, active, *grant, now_unix).await
            }
        }
    }

    /// Step 8: verifies the grant, persists the candidate, commits both ends.
    ///
    /// The order is the one the spec fixes and it is not interchangeable. The
    /// grant is verified **before** anything is written; the candidate is
    /// persisted **before** the commit travels; the local commit happens only
    /// once the gateway has confirmed. A client that committed locally first
    /// and then failed to reach the gateway would hold a `next` generation the
    /// gateway has never heard of, and would present it at activation to a
    /// peer that refuses it.
    async fn commit(
        &mut self,
        store: &mut TrustStore,
        active: &ActiveIdentity,
        grant: ClientCertificateRotationGrant,
        now_unix: u64,
    ) -> Result<RenewalStep, RenewalError> {
        let state = store.state();
        let gateway = &state.gateway;
        let tls_anchors = state.client_tls_ca.acceptable_anchors(now_unix);
        let gateway_pq_public_key =
            MlDsa87PublicKey::parse(&gateway.active_gateway_certificate.ml_dsa_87_public_key)?;
        let gateway_fingerprint = gateway.active_pq_fingerprint()?;

        grant.verify(
            &gateway.current_ca_public_key,
            &gateway_pq_public_key,
            &gateway_fingerprint,
            &state.trust_domain_id,
            gateway.ca_epoch,
            state.client_tls_ca.ca_tls_epoch,
            &gateway.gateway_wg_public_key,
            &gateway.server_name,
            &state.client_wg_public_key,
            &self.request,
            &tls_anchors,
            Some(&state.astra.astra_policy_fingerprint),
            now_unix,
        )?;

        // Persisted before the commit travels, in state `pending_commit`: an
        // interruption after this point resumes by replaying the same signed
        // commit, and the gateway recognises it by its fingerprint.
        store.stage_verified_grant(&grant, now_unix)?;

        let receipt = &grant.stage_receipt;
        let commit = ClientCertificateStageCommit {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: grant.trust_domain_id,
            stage_id: receipt.stage_id,
            grant_fingerprint: grant.fingerprint()?,
            stage_receipt_fingerprint: grant.stage_receipt_fingerprint,
            gateway_wg_public_key: grant.gateway_wg_public_key,
            client_wg_public_key: grant.client_wg_public_key,
            active_generation: grant.active_generation,
            staged_generation: grant.next_generation,
            staged_tls_certificate_fingerprint: grant.next_tls_certificate.fingerprint(),
            staged_pq_certificate_fingerprint: receipt.staged_pq_certificate_fingerprint,
            stage_expires_at: grant.stage_expires_at,
            committed_at: now_unix,
            active_pq_signature: MlDsa87Signature::placeholder(),
            staged_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&active.pq_private_key, &self.keys.pq_private_key)?;

        let body = serde_json::to_vec(&commit)
            .map_err(|error| RenewalError::Malformed(error.to_string()))?;
        self.post_ignoring_body(&self.routes.stage_commit(), body)
            .await?;

        store.commit_staged_candidate(&receipt.stage_id, &commit.fingerprint(), now_unix)?;
        Ok(RenewalStep::Committed {
            generation: grant.next_generation,
        })
    }

    /// The bundle the protected store must hold once the candidate activates.
    ///
    /// Produced from the grant rather than kept alongside it: the certificates
    /// that go in are the ones the authority issued and the local state now
    /// holds, never a copy assembled from what the client asked for.
    pub fn candidate_bundle(
        &self,
        identity: &str,
        grant: &ClientCertificateRotationGrant,
    ) -> Result<ClientIdentityBundle, RenewalError> {
        let encode = base64::engine::general_purpose::STANDARD;
        let bundle = ClientIdentityBundle {
            identity: identity.to_string(),
            certificate_chain: vec![encode.encode(grant.next_tls_certificate.as_bytes())],
            private_key: encode.encode(self.keys.tls.private_key_der.as_slice()),
            pq_certificate: encode.encode(
                serde_json::to_vec(&grant.next_pq_certificate)
                    .map_err(|error| RenewalError::Malformed(error.to_string()))?,
            ),
            pq_private_key: encode.encode(self.keys.pq_private_key.as_slice()),
        };
        bundle
            .validate()
            .map_err(|error| RenewalError::Identity(error.to_string()))?;
        Ok(bundle)
    }

    /// Records the operation the gateway named, refusing one that is not ours.
    fn adopt(&mut self, view: ClientRenewalOperationView) -> Result<RenewalStep, RenewalError> {
        self.check_identity(&view)?;
        let operation_id = view.operation_id;
        self.operation_id = Some(operation_id);
        match view.state {
            ClientRenewalOperationState::AwaitingOperator => {
                Ok(RenewalStep::AwaitingOperator { operation_id })
            }
            ClientRenewalOperationState::PendingGrant
            | ClientRenewalOperationState::PendingCommit => {
                Ok(RenewalStep::Issuing { operation_id })
            }
            ClientRenewalOperationState::Failed => Err(RenewalError::OperationFailed),
        }
    }

    /// The answer must be about **this** request and **this** client.
    ///
    /// Both comparisons matter and neither substitutes for the other: the
    /// request fingerprint says which renewal, the WireGuard key says whose.
    /// A gateway that returned somebody else's operation would otherwise have
    /// this client poll — and eventually commit — a candidate certifying a key
    /// it does not hold.
    fn check_identity(&self, view: &ClientRenewalOperationView) -> Result<(), RenewalError> {
        if !view
            .request_fingerprint
            .matches(&self.request.fingerprint())
        {
            return Err(RenewalError::OperationMismatch {
                expected: self.request.fingerprint().to_hex(),
                returned: view.request_fingerprint.to_hex(),
            });
        }
        if view.client_wg_public_key != self.request.client_wg_public_key {
            return Err(RenewalError::OperationMismatch {
                expected: self.request.client_wg_public_key.to_base64(),
                returned: view.client_wg_public_key.to_base64(),
            });
        }
        if let Some(known) = self.operation_id {
            if view.operation_id != known {
                return Err(RenewalError::OperationMismatch {
                    expected: known.to_hex(),
                    returned: view.operation_id.to_hex(),
                });
            }
        }
        Ok(())
    }

    async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> Result<ClientRenewalOperationView, RenewalError> {
        let response = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| RenewalError::Transport(error.to_string()))?;
        Self::decode(response).await
    }

    async fn post_ignoring_body(&self, url: &str, body: Vec<u8>) -> Result<(), RenewalError> {
        let response = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| RenewalError::Transport(error.to_string()))?;
        Self::refuse_status(&response)?;
        Ok(())
    }

    async fn get(&self, url: &str) -> Result<ClientRenewalOperationView, RenewalError> {
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| RenewalError::Transport(error.to_string()))?;
        Self::decode(response).await
    }

    async fn decode(
        response: reqwest::Response,
    ) -> Result<ClientRenewalOperationView, RenewalError> {
        Self::refuse_status(&response)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_ANSWER_BYTES)
        {
            return Err(RenewalError::Malformed("answer exceeds the ceiling".into()));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|error| RenewalError::Transport(error.to_string()))?;
        if bytes.len() as u64 > MAX_ANSWER_BYTES {
            return Err(RenewalError::Malformed("answer exceeds the ceiling".into()));
        }
        serde_json::from_slice(&bytes).map_err(|error| RenewalError::Malformed(error.to_string()))
    }

    /// Maps the gateway's coarse refusals, which is all it is allowed to send.
    ///
    /// §8.1.2 keeps the reason on the gateway and on Astra: a client learns
    /// that it was refused, never why. The one refusal worth telling apart is
    /// `503`, because it means the gateway has no authority to relay to — the
    /// user's next step is the operator's, not their own.
    fn refuse_status(response: &reqwest::Response) -> Result<(), RenewalError> {
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
            return Err(RenewalError::AuthorityUnavailable);
        }
        Err(RenewalError::Refused {
            status: status.as_u16(),
        })
    }
}

#[cfg(all(test, feature = "certificate-signing"))]
mod tests {
    use super::*;
    use aether::certificates::authority::RotationReason;
    use aether::certificates::client::ClientCertificateGeneration;
    use aether::certificates::client::{GatewayCertificateStageReceipt, IssuerKind};
    use aether::certificates::encoding::{
        derive_ml_dsa_87_public_key, generate_ml_dsa_87_keypair, DerCertificate, TrustDomainId,
        WireGuardKey,
    };
    use aether::certificates::state::{
        AstraProfile, ClientCertificateState, ClientTlsCaState, GatewayCertificateState,
        TrustLedger,
    };
    use aether::certificates::window::TransitionWindow;
    use aether::key_negotiation::{
        issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
    };
    use base64::engine::general_purpose::STANDARD;
    use rcgen::{
        CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    };

    const NOW: u64 = 1_700_000_000;
    const SERVER_NAME: &str = "gateway.example";
    const SUBJECT: &str = "poste-windows";

    /// Every private key the fixture has to hold, because every one of them
    /// signs something the client verifies.
    struct Domain {
        ca_pq_private: Zeroizing<Vec<u8>>,
        ca_pq_public: MlDsa87PublicKey,
        gateway_pq_private: Zeroizing<Vec<u8>>,
        gateway_leaf: PqCertificate,
        active_client_private: Zeroizing<Vec<u8>>,
        active_client_leaf: PqCertificate,
        tls_ca: rcgen::Certificate,
        tls_ca_key: KeyPair,
        tls_ca_der: DerCertificate,
        service_public: MlDsa87PublicKey,
    }

    fn client_key() -> WireGuardKey {
        WireGuardKey::from_bytes([2; 32])
    }

    fn gateway_key() -> WireGuardKey {
        WireGuardKey::from_bytes([9; 32])
    }

    fn domain_id() -> TrustDomainId {
        TrustDomainId::new([1; 16]).expect("domain")
    }

    fn name(common: &str) -> DistinguishedName {
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common);
        name
    }

    fn seconds_since_epoch(unix: u64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(unix as i64).expect("timestamp")
    }

    fn domain() -> Domain {
        let (ca_pq_private, ca_pq_public) = generate_ml_dsa_87_keypair().expect("CA-PQ");
        let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("service");
        drop(service_private);

        let (gateway_pq_private, gateway_pq_public) =
            generate_ml_dsa_87_keypair().expect("gateway leaf");
        let gateway_leaf = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [1; 16],
                subject: SERVER_NAME.into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Gateway,
                wireguard_public_key: gateway_key().to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(gateway_pq_public.as_bytes()),
                not_before_unix: NOW - 3_600,
                not_after_unix: NOW + 10 * 86_400,
                ml_dsa_87_signature: String::new(),
            },
            &ca_pq_private,
        )
        .expect("gateway leaf");

        let (active_client_private, active_client_public) =
            generate_ml_dsa_87_keypair().expect("active client");
        let active_client_leaf = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [2; 16],
                subject: SUBJECT.into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: client_key().to_base64(),
                ml_dsa_87_public_key: STANDARD.encode(active_client_public.as_bytes()),
                not_before_unix: NOW - 3_600,
                not_after_unix: NOW + 10 * 86_400,
                ml_dsa_87_signature: String::new(),
            },
            &ca_pq_private,
        )
        .expect("active client leaf");

        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name = name("CA-TLS cliente");
        params.not_before = seconds_since_epoch(NOW - 86_400);
        params.not_after = seconds_since_epoch(NOW + 365 * 86_400);
        let tls_ca_key = KeyPair::generate().expect("CA-TLS key");
        let tls_ca = params.self_signed(&tls_ca_key).expect("CA-TLS");
        let tls_ca_der = DerCertificate::new(tls_ca.der().to_vec()).expect("der");

        Domain {
            ca_pq_private,
            ca_pq_public,
            gateway_pq_private,
            gateway_leaf,
            active_client_private,
            active_client_leaf,
            tls_ca,
            tls_ca_key,
            tls_ca_der,
            service_public,
        }
    }

    fn active_generation(domain: &Domain) -> ClientCertificateGeneration {
        ClientCertificateGeneration {
            generation: 4,
            ca_tls_epoch: 1,
            tls_ca_certificate_fingerprint: domain.tls_ca_der.fingerprint(),
            tls_certificate_fingerprint: Fingerprint::of(b"active client tls"),
            pq_certificate_fingerprint: aether::certificates::gateway::pq_certificate_fingerprint(
                &domain.active_client_leaf,
            )
            .expect("active pq fingerprint"),
            not_before: NOW - 3_600,
            not_after: NOW + 10 * 86_400,
        }
    }

    fn store(directory: &std::path::Path, domain: &Domain) -> TrustStore {
        TrustStore::new(
            directory.join("trust.json"),
            crate::certificates::TrustState {
                trust_domain_id: domain_id(),
                client_wg_public_key: client_key(),
                gateway: GatewayCertificateState {
                    trust_domain_id: domain_id(),
                    gateway_wg_public_key: gateway_key(),
                    server_name: SERVER_NAME.into(),
                    ca_epoch: 1,
                    current_ca_public_key: domain.ca_pq_public.clone(),
                    next_ca_public_key: None,
                    next_ca_transition_fingerprint: None,
                    ca_activation_at: None,
                    ca_retire_active_at: None,
                    active_gateway_identity_epoch: 1,
                    gateway_decision_epoch: 1,
                    next_gateway_identity_epoch: None,
                    next_transition_fingerprint: None,
                    last_aborted_transition: None,
                    active_gateway_tls_certificate: DerCertificate::new(vec![1; 64]).expect("der"),
                    next_gateway_tls_certificate: None,
                    active_gateway_certificate: domain.gateway_leaf.clone(),
                    next_gateway_certificate: None,
                    activation_at: None,
                    retire_active_at: None,
                    published: false,
                    revoked: false,
                    revocation_epoch: 0,
                },
                client_tls_ca: ClientTlsCaState {
                    ca_tls_epoch: 1,
                    active_client_tls_ca_certificate: domain.tls_ca_der.clone(),
                    next_client_tls_ca_certificate: None,
                    next_transition_fingerprint: None,
                    activation_at: None,
                    retire_active_at: None,
                },
                astra: AstraProfile {
                    authority_url: "https://astra.example".into(),
                    webauthn_rp_id: "astra.example".into(),
                    astra_policy_fingerprint: aether::certificates::approval::AstraPolicyPin::new(
                        Fingerprint::of(b"policy"),
                    )
                    .expect("policy pin"),
                    credential_registry_epoch: 1,
                    credential_bindings: Default::default(),
                    active_astra_service_public_key: domain.service_public.clone(),
                    next_astra_service_public_key: None,
                    next_service_key_transition_fingerprint: None,
                    astra_service_key_epoch: 1,
                    service_key_activation_at: None,
                    service_key_retire_active_at: None,
                    service_key_revocation_epoch: 0,
                    last_emergency_replacement_fingerprint: None,
                },
                issuer_epoch: 1,
                issuer: None,
                certificates: ClientCertificateState::new(active_generation(domain)),
                staged_gateway_transition: None,
                ledger: TrustLedger::default(),
            },
        )
    }

    fn active_identity(domain: &Domain) -> ActiveIdentity {
        ActiveIdentity {
            pq_private_key: domain.active_client_private.clone(),
            tls_private_key_der: Zeroizing::new(vec![7; 64]),
        }
    }

    fn window() -> TransitionWindow {
        TransitionWindow {
            not_before: NOW - 60,
            activation_at: NOW + 3_600,
            not_after: NOW + 30 * 86_400,
        }
    }

    /// A grant as Astra would build it, signed by `CA-PQ` under
    /// [`IssuerKind::Master`] — the campaign path, which needs no delegation.
    fn grant(
        domain: &Domain,
        session: &RenewalSession,
        window: TransitionWindow,
    ) -> ClientCertificateRotationGrant {
        let request = session.request();

        // The leaf certifies the key the CSR proved possession of. Issuing
        // from a fresh key here would pass every signature check and fail the
        // one that matters.
        let csr =
            CertificateSigningRequestParams::from_der(&request.tls_csr.as_bytes().to_vec().into())
                .expect("csr");
        let mut params = csr.params.clone();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.not_before = seconds_since_epoch(window.not_before);
        params.not_after = seconds_since_epoch(window.not_after + 86_400);
        let leaf = CertificateSigningRequestParams {
            params,
            public_key: csr.public_key,
        }
        .signed_by(&domain.tls_ca, &domain.tls_ca_key)
        .expect("client leaf");
        let next_tls = DerCertificate::new(leaf.der().to_vec()).expect("der");

        let next_pq = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [3; 16],
                subject: SUBJECT.into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: client_key().to_base64(),
                ml_dsa_87_public_key: request.new_ml_dsa_87_public_key.to_base64(),
                not_before_unix: window.not_before,
                not_after_unix: window.not_after + 86_400,
                ml_dsa_87_signature: String::new(),
            },
            &domain.ca_pq_private,
        )
        .expect("candidate leaf");

        let approval = Fingerprint::of(b"operator approval");
        let staged_pq =
            aether::certificates::gateway::pq_certificate_fingerprint(&next_pq).expect("pq");
        let receipt = GatewayCertificateStageReceipt {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain_id(),
            stage_id: Id16::new([5; 16]).expect("stage id"),
            stage_authorization_fingerprint: Fingerprint::of(b"authorization"),
            request_fingerprint: request.fingerprint(),
            operator_approval_fingerprint: approval,
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            active_generation: request.active_generation,
            staged_generation: request.requested_generation,
            staged_tls_certificate_fingerprint: next_tls.fingerprint(),
            staged_pq_certificate_fingerprint: staged_pq,
            persisted_at: NOW,
            stage_expires_at: NOW + 900,
            active_gateway_identity_epoch: 1,
            gateway_decision_epoch: 1,
            gateway_certificate_fingerprint:
                aether::certificates::gateway::pq_certificate_fingerprint(&domain.gateway_leaf)
                    .expect("gateway fingerprint"),
            gateway_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&domain.gateway_pq_private)
        .expect("receipt");

        ClientCertificateRotationGrant {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: domain_id(),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            issuer_kind: IssuerKind::Master,
            issuer_epoch: 0,
            issuer_authorization_fingerprint: Fingerprint::from_bytes([0; 32]),
            issuer_authorization: None,
            request_fingerprint: request.fingerprint(),
            operator_approval_fingerprint: approval,
            renewal_approval: None,
            stage_receipt_fingerprint: receipt.fingerprint(),
            stage_receipt: receipt,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            client_wg_public_key: client_key(),
            active_generation: request.active_generation,
            next_generation: request.requested_generation,
            active_tls_certificate_fingerprint: request.active_tls_certificate_fingerprint,
            active_pq_certificate_fingerprint: request.active_pq_certificate_fingerprint,
            next_tls_ca_certificate_fingerprint: domain.tls_ca_der.fingerprint(),
            next_tls_certificate: next_tls,
            next_pq_certificate: next_pq,
            stage_expires_at: NOW + 900,
            window,
            reason: RotationReason::Scheduled,
            signature: MlDsa87Signature::placeholder(),
        }
        .sign(&domain.ca_pq_private)
        .expect("grant")
    }

    fn session(store: &TrustStore, domain: &Domain) -> RenewalSession {
        let mut session = RenewalSession::prepare(store, SUBJECT, "http://100.64.0.1:8080", NOW)
            .expect("prepare");
        session.sign(&active_identity(domain)).expect("sign");
        session
    }

    /// The request is built from the store and from nothing else, and both
    /// proofs are made — which is exactly what the gateway will check.
    #[test]
    fn a_prepared_request_verifies_against_the_active_generation() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let store = store(directory.path(), &domain);
        let session = session(&store, &domain);

        let active_public =
            MlDsa87PublicKey::parse(&domain.active_client_leaf.ml_dsa_87_public_key)
                .expect("active public key");
        session
            .request()
            .verify(
                &active_public,
                &domain_id(),
                &gateway_key(),
                SERVER_NAME,
                &active_generation(&domain),
                &client_key(),
                NOW,
            )
            .expect("the request the client signed is the one the gateway accepts");
        assert_eq!(session.request().requested_generation, 5);
    }

    /// Continuity is proved by the **active** key, not by the candidate's. A
    /// request signed twice with the new key would carry two valid signatures
    /// and still be a stranger's.
    #[test]
    fn a_request_signed_by_the_wrong_active_key_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let store = store(directory.path(), &domain);
        let mut session = RenewalSession::prepare(&store, SUBJECT, "http://100.64.0.1:8080", NOW)
            .expect("prepare");
        let (stranger, _) = generate_ml_dsa_87_keypair().expect("stranger");
        session
            .sign(&ActiveIdentity {
                pq_private_key: stranger,
                tls_private_key_der: Zeroizing::new(vec![0; 32]),
            })
            .expect("sign");

        let active_public =
            MlDsa87PublicKey::parse(&domain.active_client_leaf.ml_dsa_87_public_key)
                .expect("active public key");
        assert!(session
            .request()
            .verify(
                &active_public,
                &domain_id(),
                &gateway_key(),
                SERVER_NAME,
                &active_generation(&domain),
                &client_key(),
                NOW,
            )
            .is_err());
    }

    /// The whole point of the CSR: the grant's leaf certifies the key this
    /// machine generated, and the client refuses one that does not.
    #[test]
    fn a_verified_grant_stages_and_commits() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let mut store = store(directory.path(), &domain);
        let session = session(&store, &domain);
        let grant = grant(&domain, &session, window());

        let state = store.state();
        grant
            .verify(
                &domain.ca_pq_public,
                &MlDsa87PublicKey::parse(&domain.gateway_leaf.ml_dsa_87_public_key)
                    .expect("gateway key"),
                &aether::certificates::gateway::pq_certificate_fingerprint(&domain.gateway_leaf)
                    .expect("gateway fingerprint"),
                &state.trust_domain_id,
                1,
                1,
                &gateway_key(),
                SERVER_NAME,
                &client_key(),
                session.request(),
                &[&domain.tls_ca_der],
                Some(&state.astra.astra_policy_fingerprint),
                NOW,
            )
            .expect("the grant this client asked for");

        store
            .stage_verified_grant(&grant, NOW)
            .expect("candidate persisted");
        assert_eq!(
            store
                .state()
                .certificates
                .pending
                .as_ref()
                .expect("pending")
                .state,
            aether::certificates::state::PendingStageState::PendingCommit,
            "a client holds a candidate only once the grant exists"
        );

        store
            .commit_staged_candidate(
                &grant.stage_receipt.stage_id,
                &Fingerprint::of(b"commit"),
                NOW,
            )
            .expect("committed");
        let committed = store.state();
        assert!(committed.certificates.pending.is_none());
        assert_eq!(
            committed
                .certificates
                .next
                .as_ref()
                .expect("next")
                .generation,
            5
        );
        assert_eq!(
            committed.certificates.active.generation, 4,
            "still connects"
        );
    }

    /// A grant issued for somebody else's CSR is refused before anything is
    /// written — the failure a signature check alone would not catch.
    #[test]
    fn a_grant_certifying_another_key_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let store = store(directory.path(), &domain);
        let mine = session(&store, &domain);
        let theirs = session(&store, &domain);
        let stranger = grant(&domain, &theirs, window());

        let state = store.state();
        let refusal = stranger
            .verify(
                &domain.ca_pq_public,
                &MlDsa87PublicKey::parse(&domain.gateway_leaf.ml_dsa_87_public_key)
                    .expect("gateway key"),
                &aether::certificates::gateway::pq_certificate_fingerprint(&domain.gateway_leaf)
                    .expect("gateway fingerprint"),
                &state.trust_domain_id,
                1,
                1,
                &gateway_key(),
                SERVER_NAME,
                &client_key(),
                mine.request(),
                &[&domain.tls_ca_der],
                Some(&state.astra.astra_policy_fingerprint),
                NOW,
            )
            .expect_err("a grant for another CSR is not this client's");
        assert!(
            matches!(refusal, CertificateError::InvalidX509(_)),
            "expected the CSR binding to fail first, got {refusal:?}"
        );
    }

    /// The gateway names which operation it opened; a view about another
    /// renewal, or another peer, is refused rather than adopted.
    #[test]
    fn an_operation_about_another_renewal_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let store = store(directory.path(), &domain);
        let mut session = session(&store, &domain);

        let mut view = ClientRenewalOperationView {
            operation_id: Id16::new([6; 16]).expect("id"),
            state: ClientRenewalOperationState::AwaitingOperator,
            client_wg_public_key: client_key(),
            request_fingerprint: session.request_fingerprint(),
            operation_manifest_fingerprint: Fingerprint::of(b"manifest"),
            created_at: NOW,
            expires_at: NOW + 300,
            signer_request_token: None,
            signer_result_token: None,
            grant: None,
        };
        assert!(matches!(
            session.adopt(view.clone()).expect("ours"),
            RenewalStep::AwaitingOperator { .. }
        ));

        view.request_fingerprint = Fingerprint::of(b"somebody else's request");
        assert!(matches!(
            session.adopt(view.clone()),
            Err(RenewalError::OperationMismatch { .. })
        ));

        view.request_fingerprint = session.request_fingerprint();
        view.client_wg_public_key = WireGuardKey::from_bytes([3; 32]);
        assert!(matches!(
            session.adopt(view.clone()),
            Err(RenewalError::OperationMismatch { .. })
        ));

        view.client_wg_public_key = client_key();
        view.operation_id = Id16::new([7; 16]).expect("id");
        assert!(
            matches!(
                session.adopt(view),
                Err(RenewalError::OperationMismatch { .. })
            ),
            "an operation identifier does not change under a client's feet"
        );
    }

    /// A failed operation is terminal: the client opens a new one rather than
    /// polling an identifier the authority no longer accepts.
    #[test]
    fn a_failed_operation_is_reported_as_such() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let store = store(directory.path(), &domain);
        let mut session = session(&store, &domain);
        let view = ClientRenewalOperationView {
            operation_id: Id16::new([6; 16]).expect("id"),
            state: ClientRenewalOperationState::Failed,
            client_wg_public_key: client_key(),
            request_fingerprint: session.request_fingerprint(),
            operation_manifest_fingerprint: Fingerprint::of(b"manifest"),
            created_at: NOW,
            expires_at: NOW + 300,
            signer_request_token: None,
            signer_result_token: None,
            grant: None,
        };
        assert!(matches!(
            session.adopt(view),
            Err(RenewalError::OperationFailed)
        ));
    }

    /// The bundle written at commit time carries the candidate's own private
    /// keys — the ones this process generated and never sent anywhere.
    #[test]
    fn the_candidate_bundle_holds_the_keys_this_machine_generated() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let store = store(directory.path(), &domain);
        let session = session(&store, &domain);
        let grant = grant(&domain, &session, window());

        let bundle = session
            .candidate_bundle("poste-windows", &grant)
            .expect("bundle");
        assert_eq!(bundle.identity, "poste-windows");
        let certificate = STANDARD
            .decode(&bundle.certificate_chain[0])
            .expect("leaf der");
        assert_eq!(certificate, grant.next_tls_certificate.as_bytes());
        let pq_private = STANDARD.decode(&bundle.pq_private_key).expect("pq key");
        assert_eq!(
            derive_ml_dsa_87_public_key(&pq_private)
                .expect("derive public")
                .to_base64(),
            grant.next_pq_certificate.ml_dsa_87_public_key,
            "the sealed private key is the one the candidate leaf certifies"
        );
    }
}
