//! Recovery of an expired client identity, from the client — spec §7.5.
//!
//! # Why this cannot reuse the renewal path
//!
//! Every step of [`crate::certificate_renewal`] travels inside the tunnel,
//! and the tunnel is what has expired. An expired leaf is refused by mTLS, by
//! QUIC and by every ordinary validator; there is no route left to ask on. So
//! this module talks to Astra's **public origin** instead, and the proofs move
//! from the transport into the objects:
//!
//! - the expired private key signs the request, as a historical proof that
//!   `ExpiredCertificateRecoveryRequest::verify_historical` checks without ever
//!   accepting the certificate for anything else;
//! - an operator answers a challenge Astra issued, at a security key;
//! - `CA-PQ` — not the delegated issuer — signs the staging and the grant.
//!
//! # The commit goes back out the same way
//!
//! A client that has just installed its new generation still has no tunnel:
//! the gateway only starts accepting it once the commit has landed. So the
//! commit is posted to Astra, which relays it on the private channel. The
//! gateway refuses anything on that link whose pending stage was not opened by
//! the `CA-PQ` recovery authorization presented beside it, so relaying it
//! grants the authority nothing it did not already have.
//!
//! # Limite connue : la clé privée expirée doit exister encore
//!
//! §7.5 is explicit, and so is this module: if the old private key went with
//! the DPAPI or TPM store that held it, no historical proof can be produced
//! and this path does not apply. What is left is an operator re-admission
//! under two credentials — a different operation, which creates a new
//! continuity rather than extending one. [`RecoveryError::NoHistoricalProof`]
//! says exactly that rather than failing at a signature nobody can read.

use std::path::Path;
use std::time::Duration;

use aether::certificates::client::{
    ClientCertificateRotationGrant, ClientCertificateStageCommit, ExpiredCertificateRecoveryRequest,
};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey,
    MlDsa87Signature,
};
use aether::certificates::transport::{
    ExpiredRecoveryCommitDeposit, ExpiredRecoveryOperationView, ExpiredRecoveryState,
};
use aether::certificates::x509::{client_rotation_csr, ClientRotationCsr};
use aether::certificates::{CertificateError, CERTIFICATE_FORMAT_VERSION};
use aether::key_negotiation::PqCertificate;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::certificate_renewal::{candidate_identity_of, RenewalError};
use crate::certificates::TrustError;
use crate::identity_store::{ClientIdentityBundle, ProtectedIdentityStore};

/// How long one call to the public origin may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("recovery transport: {0}")]
    Transport(String),
    #[error("the authority answered {status}")]
    Status { status: u16 },
    #[error("the authority's answer could not be read: {0}")]
    Malformed(String),
    #[error(
        "the private key of the expired generation is gone, so no historical proof can be \
         produced; this identity is restored by an operator re-admission under two credentials, \
         not by a recovery"
    )]
    NoHistoricalProof,
    #[error("this profile carries no trust material, so there is no authority to ask")]
    TrustMaterialMissing,
    #[error("this identity has not expired; an ordinary renewal is the way")]
    NotExpired,
    #[error("the authority refused this recovery")]
    Refused,
    #[error("the recovery is still waiting for an operator")]
    AwaitingOperator,
    #[error("the authority reports a grant it did not send")]
    GrantMissing,
    #[error("identity store: {0}")]
    Identity(String),
    #[error("certificate: {0}")]
    Certificate(#[from] CertificateError),
    #[error("trust store: {0}")]
    Store(#[from] TrustError),
}

impl From<RenewalError> for RecoveryError {
    fn from(error: RenewalError) -> Self {
        Self::Identity(error.to_string())
    }
}

/// Where a recovery stands, as an interface shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryStep {
    /// The request is posted. The identifier is what the user reads out to
    /// whoever holds a security key — there is no other channel left.
    AwaitingOperator { operation_id: Id16 },
    /// The operator answered and the gateway staged the candidate.
    Issuing { operation_id: Id16 },
    /// Installed locally and committed at the gateway.
    Recovered { generation: u64 },
}

/// One recovery, from the signed request to the relayed commit.
pub struct RecoverySession {
    base: String,
    http: reqwest::Client,
    operation_id: Id16,
    request: Box<ExpiredCertificateRecoveryRequest>,
    keys: CandidateKeys,
}

struct CandidateKeys {
    tls: ClientRotationCsr,
    pq_private_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for RecoverySession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoverySession")
            .field("operation_id", &self.operation_id.to_hex())
            .field("candidate_keys", &"***")
            .finish()
    }
}

impl RecoverySession {
    pub fn operation_id(&self) -> Id16 {
        self.operation_id
    }

    /// The public origin this recovery is waiting on.
    ///
    /// Read by the interface to render the line the operator has to run: the
    /// identifier alone is not enough, because that operator is on another
    /// machine and has no way to know which authority opened the operation.
    pub fn authority_url(&self) -> &str {
        &self.base
    }
}

/// Assembles and double-signs the request, from the store and from nothing else.
///
/// Split out from [`begin`] so the decisions can be checked without a network
/// and without an OS identity store: whether this identity has actually
/// expired, which operator credential the request names, which generation it
/// asks for, and that both halves sign it. What remains in `begin` is the
/// transport and the sealed material it reads.
///
/// # Order
///
/// Expiry is confirmed **before** anything is generated. A client that ran
/// this on a live identity would burn a generation and ask an operator for a
/// touch that an ordinary renewal would have got without one.
fn build_request(
    state: &crate::certificates::TrustState,
    expired_pq: PqCertificate,
    expired_tls: DerCertificate,
    expired_pq_private_key: &Zeroizing<Vec<u8>>,
    astra_challenge: [u8; 32],
    now_unix: u64,
) -> Result<(ExpiredCertificateRecoveryRequest, CandidateKeys), RecoveryError> {
    if now_unix < expired_pq.not_after_unix {
        return Err(RecoveryError::NotExpired);
    }
    // The operator credential this request names. Any active row will do —
    // the operator picks the physical key — and naming one is what lets Astra
    // and the companion agree on which row an assertion must verify under.
    let credential_id = state
        .astra
        .credential_bindings
        .values()
        .find(|binding| binding.state == aether::certificates::approval::CredentialState::Active)
        .map(|binding| binding.credential_id.clone())
        .ok_or_else(|| {
            RecoveryError::Identity(
                "ce profil ne connaît aucun credential opérateur actif : sans lui personne ne \
                 peut approuver une récupération"
                    .into(),
            )
        })?;

    let tls = client_rotation_csr(&subject_of(&expired_pq))?;
    let (pq_private_key, pq_public_key) = generate_ml_dsa_87_keypair()?;

    let mut request_id = [0u8; 16];
    aether::random::fill_public(&mut request_id)
        .map_err(|_| CertificateError::RandomnessUnavailable)?;
    let request = ExpiredCertificateRecoveryRequest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
        trust_domain_id: state.trust_domain_id,
        astra_challenge,
        request_id: Id16::new(request_id)?,
        gateway_wg_public_key: state.gateway.gateway_wg_public_key,
        server_name: state.gateway.server_name.clone(),
        client_wg_public_key: state.client_wg_public_key,
        expired_generation: state.certificates.active.generation,
        requested_generation: state
            .certificates
            .active
            .generation
            .checked_add(1)
            .ok_or(CertificateError::ArithmeticOverflow)?,
        expired_tls_certificate: expired_tls,
        expired_pq_certificate: expired_pq,
        tls_csr: tls.csr.clone(),
        new_ml_dsa_87_public_key: pq_public_key,
        credential_id,
        created_at: now_unix,
        expires_at: now_unix
            .checked_add(aether::certificates::approval::MAX_APPROVAL_LIFETIME_SECS)
            .ok_or(CertificateError::ArithmeticOverflow)?,
        expired_pq_signature: MlDsa87Signature::placeholder(),
        new_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(expired_pq_private_key, &pq_private_key)?;

    Ok((
        request,
        CandidateKeys {
            tls,
            pq_private_key,
        },
    ))
}

/// Opens a recovery: draws the new keys, signs the request, posts it.
///
/// # Order
///
/// The identity is read and the expiry is **confirmed** before anything is
/// generated: a client that ran this on a live identity would burn a
/// generation and ask an operator for a touch that an ordinary renewal would
/// have got without one.
pub async fn begin(
    settings: &crate::KeyNegotiationSettings,
    now_unix: u64,
) -> Result<(RecoverySession, RecoveryStep), RecoveryError> {
    let identity = settings.identity.trim();
    if identity.is_empty() {
        return Err(RecoveryError::Identity(
            "ce profil ne nomme aucune identité protégée".into(),
        ));
    }
    let identities = ProtectedIdentityStore::for_current_user()
        .map_err(|error| RecoveryError::Identity(error.to_string()))?;
    let bundle = identities
        .load(identity)
        .map_err(|_| RecoveryError::NoHistoricalProof)?;

    let config = crate::config::ClientConfig::path()
        .map_err(|error| RecoveryError::Identity(error.to_string()))?;
    let store = crate::certificate_renewal::open_identity_store(
        config.parent().unwrap_or_else(|| Path::new(".")),
        settings,
        &bundle,
    )?;

    let expired_pq = crate::certificate_renewal::client_pq_leaf(&bundle)?;
    let expired_tls = leaf_of(&bundle)?;
    let expired_pq_private_key = decode_secret(&bundle.pq_private_key, "clé privée PQ expirée")?;

    let state = store.state();
    let authority = state.astra.authority_url.trim_end_matches('/').to_string();
    if authority.is_empty() {
        return Err(RecoveryError::TrustMaterialMissing);
    }

    let http = reqwest::Client::builder()
        .timeout(CALL_TIMEOUT)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| RecoveryError::Transport(error.to_string()))?;

    let challenge: ChallengeResponse = post_json(
        &http,
        &format!("{authority}/v1/client-rotation/challenge"),
        &serde_json::Value::Null,
    )
    .await?;

    let (request, keys) = build_request(
        state,
        expired_pq,
        expired_tls,
        &expired_pq_private_key,
        challenge.astra_challenge,
        now_unix,
    )?;

    let view: ExpiredRecoveryOperationView = post_json(
        &http,
        &format!("{authority}/v1/client-rotation/recovery"),
        &request,
    )
    .await?;
    let session = RecoverySession {
        base: authority,
        http,
        operation_id: view.operation_id,
        request: Box::new(request),
        keys,
    };
    let step = session.step_of(&view)?;
    Ok((session, step))
}

/// Takes one more step on a recovery already opened.
///
/// Idempotent while the operator is absent: it reports
/// [`RecoveryStep::AwaitingOperator`] again and changes nothing.
pub async fn resume(
    session: &RecoverySession,
    settings: &crate::KeyNegotiationSettings,
    now_unix: u64,
) -> Result<RecoveryStep, RecoveryError> {
    let view: ExpiredRecoveryOperationView = get_json(
        &session.http,
        &format!(
            "{}/v1/client-rotation/recovery/{}",
            session.base,
            session.operation_id.to_hex()
        ),
    )
    .await?;
    match session.step_of(&view)? {
        RecoveryStep::Recovered { .. } => unreachable!("step_of never concludes on its own"),
        step @ RecoveryStep::AwaitingOperator { .. } => Ok(step),
        RecoveryStep::Issuing { operation_id } => match view.grant {
            Some(grant) => install(session, settings, *grant, now_unix).await,
            None => Ok(RecoveryStep::Issuing { operation_id }),
        },
    }
}

impl RecoverySession {
    /// The answer must be about **this** request and **this** client.
    fn step_of(&self, view: &ExpiredRecoveryOperationView) -> Result<RecoveryStep, RecoveryError> {
        if !view
            .request_fingerprint
            .matches(&self.request.fingerprint())
            || view.client_wg_public_key != self.request.client_wg_public_key
        {
            return Err(RecoveryError::Refused);
        }
        Ok(match view.state {
            ExpiredRecoveryState::AwaitingOperator => RecoveryStep::AwaitingOperator {
                operation_id: self.operation_id,
            },
            ExpiredRecoveryState::Staged
            | ExpiredRecoveryState::Granted
            | ExpiredRecoveryState::Committed => RecoveryStep::Issuing {
                operation_id: self.operation_id,
            },
        })
    }
}

/// Verifies the grant, seals the candidate, commits at both ends.
///
/// The order is the renewal's and it is not interchangeable: verify before
/// writing, seal the private keys before the store names a certificate they
/// belong to, persist the candidate before the commit travels, and commit
/// locally only once the gateway has confirmed. A client that reversed the
/// last two would hold a generation the gateway never heard of, and would
/// present it at activation to a peer that refuses it — with no tunnel left to
/// say so on.
async fn install(
    session: &RecoverySession,
    settings: &crate::KeyNegotiationSettings,
    grant: ClientCertificateRotationGrant,
    now_unix: u64,
) -> Result<RecoveryStep, RecoveryError> {
    let identity = settings.identity.trim();
    let identities = ProtectedIdentityStore::for_current_user()
        .map_err(|error| RecoveryError::Identity(error.to_string()))?;
    let bundle = identities
        .load(identity)
        .map_err(|error| RecoveryError::Identity(error.to_string()))?;
    let config = crate::config::ClientConfig::path()
        .map_err(|error| RecoveryError::Identity(error.to_string()))?;
    let mut store = crate::certificate_renewal::open_identity_store(
        config.parent().unwrap_or_else(|| Path::new(".")),
        settings,
        &bundle,
    )?;

    {
        let state = store.state();
        let gateway = &state.gateway;
        let tls_anchors = state.client_tls_ca.acceptable_anchors(now_unix);
        let gateway_pq_public_key =
            MlDsa87PublicKey::parse(&gateway.active_gateway_certificate.ml_dsa_87_public_key)?;
        let gateway_fingerprint = gateway.active_pq_fingerprint()?;
        grant.verify_for_recovery(
            &gateway.current_ca_public_key,
            &gateway_pq_public_key,
            &gateway_fingerprint,
            &state.trust_domain_id,
            gateway.ca_epoch,
            state.client_tls_ca.ca_tls_epoch,
            &gateway.gateway_wg_public_key,
            &gateway.server_name,
            &state.client_wg_public_key,
            &session.request,
            &tls_anchors,
            Some(&state.astra.astra_policy_fingerprint),
            now_unix,
        )?;
    }

    let encode = base64::engine::general_purpose::STANDARD;
    let candidate = ClientIdentityBundle {
        identity: candidate_identity_of(identity),
        certificate_chain: vec![encode.encode(grant.next_tls_certificate.as_bytes())],
        private_key: encode.encode(session.keys.tls.private_key_der.as_slice()),
        pq_certificate: encode.encode(
            serde_json::to_vec(&grant.next_pq_certificate)
                .map_err(|error| RecoveryError::Malformed(error.to_string()))?,
        ),
        pq_private_key: encode.encode(session.keys.pq_private_key.as_slice()),
    };
    candidate
        .validate()
        .map_err(|error| RecoveryError::Identity(error.to_string()))?;
    identities
        .store(&candidate)
        .map_err(|error| RecoveryError::Identity(error.to_string()))?;

    store.stage_verified_grant(&grant, now_unix)?;

    let expired_pq_private_key = decode_secret(&bundle.pq_private_key, "clé privée PQ expirée")?;
    let receipt = &grant.stage_receipt;
    let commit = ClientCertificateStageCommit {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
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
    .sign(&expired_pq_private_key, &session.keys.pq_private_key)?;

    let _: ExpiredRecoveryOperationView = post_json(
        &session.http,
        &format!(
            "{}/v1/client-rotation/recovery/{}/commit",
            session.base,
            session.operation_id.to_hex()
        ),
        &ExpiredRecoveryCommitDeposit {
            commit: Box::new(commit.clone()),
        },
    )
    .await?;

    store.commit_staged_candidate(&receipt.stage_id, &commit.fingerprint(), now_unix)?;
    Ok(RecoveryStep::Recovered {
        generation: grant.next_generation,
    })
}

/// The nonce Astra issues for one recovery request.
#[derive(Debug, serde::Deserialize)]
struct ChallengeResponse {
    astra_challenge: [u8; 32],
}

/// The common name the recovered generation keeps.
///
/// Carried through unchanged: a recovery restores an identity, it never
/// renames one.
fn subject_of(expired: &PqCertificate) -> String {
    expired.subject.clone()
}

fn leaf_of(bundle: &ClientIdentityBundle) -> Result<DerCertificate, RecoveryError> {
    let encoded = bundle
        .certificate_chain
        .first()
        .ok_or(RecoveryError::NoHistoricalProof)?;
    let der = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| RecoveryError::NoHistoricalProof)?;
    DerCertificate::new(der).map_err(RecoveryError::Certificate)
}

fn decode_secret(value: &str, what: &str) -> Result<Zeroizing<Vec<u8>>, RecoveryError> {
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map(Zeroizing::new)
        .map_err(|_| RecoveryError::Identity(format!("{what} : base64 illisible")))
}

async fn post_json<B: serde::Serialize, T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    body: &B,
) -> Result<T, RecoveryError> {
    let encoded =
        serde_json::to_vec(body).map_err(|error| RecoveryError::Malformed(error.to_string()))?;
    let response = http
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(encoded)
        .send()
        .await
        .map_err(|error| RecoveryError::Transport(error.to_string()))?;
    decode_response(response).await
}

async fn get_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
) -> Result<T, RecoveryError> {
    let response = http
        .get(url)
        .send()
        .await
        .map_err(|error| RecoveryError::Transport(error.to_string()))?;
    decode_response(response).await
}

async fn decode_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, RecoveryError> {
    let status = response.status();
    if !status.is_success() {
        return Err(RecoveryError::Status {
            status: status.as_u16(),
        });
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| RecoveryError::Transport(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| RecoveryError::Malformed(error.to_string()))
}

/// The fingerprint the interface shows while a recovery waits.
pub fn request_fingerprint(session: &RecoverySession) -> Fingerprint {
    session.request.fingerprint()
}

#[cfg(all(test, feature = "certificate-signing"))]
mod tests {
    use super::*;
    use crate::test_domain::{domain, store, Domain, NOW, SERVER_NAME, SUBJECT};
    use aether::certificates::approval::{AstraCredentialBinding, CredentialState};
    use aether::certificates::client::ClientCertificateGeneration;
    use aether::certificates::encoding::WireGuardKey;
    use aether::certificates::transport::ExpiredRecoveryState;
    use aether::key_negotiation::{
        issue_pq_certificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
    };

    /// The instant the recovery is attempted: past the fixture's expiry.
    const LATER: u64 = NOW + 20 * 86_400;

    /// The client's own leaf, already expired. A recovery exists for exactly
    /// this document — no ordinary renewal accepts it.
    fn expired_leaf(domain: &Domain) -> (PqCertificate, Zeroizing<Vec<u8>>) {
        let (private, public) =
            aether::certificates::encoding::generate_ml_dsa_87_keypair().expect("client key");
        let leaf = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [8; 16],
                subject: SUBJECT.into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: crate::test_domain::client_key().to_base64(),
                ml_dsa_87_public_key:
                    <base64::engine::general_purpose::GeneralPurpose as base64::Engine>::encode(
                        &base64::engine::general_purpose::STANDARD,
                        public.as_bytes(),
                    ),
                not_before_unix: NOW - 86_400,
                not_after_unix: NOW + 10 * 86_400,
                ml_dsa_87_signature: String::new(),
            },
            &domain.ca_pq_private,
        )
        .expect("expired client leaf");
        (leaf, private)
    }

    fn binding(state: CredentialState) -> AstraCredentialBinding {
        AstraCredentialBinding {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            credential_id: vec![0xAB, 0xCD],
            credential_public_key: vec![1; 32],
            aaguid: [0; 16],
            trust_domain_id: crate::test_domain::domain_id(),
            gateway_wg_public_key: crate::test_domain::gateway_key(),
            state,
            credential_epoch: 1,
            credential_registry_epoch: 1,
            ca_epoch: 1,
            created_at: NOW,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
    }

    /// A store carrying the operator credentials this profile knows about,
    /// and an active generation that describes the very leaves handed to
    /// [`build_request`].
    ///
    /// Aligned rather than approximate: the historical validator compares the
    /// presented leaves against the generation Astra last recorded, so a
    /// fixture whose fingerprints only *look* right would pass a test that the
    /// real exchange fails.
    fn state_with(
        directory: &std::path::Path,
        domain: &Domain,
        credentials: Vec<AstraCredentialBinding>,
        expired: &PqCertificate,
    ) -> crate::certificates::TrustState {
        let mut state = store(directory, domain).state().clone();
        state.astra.credential_bindings = credentials
            .into_iter()
            .enumerate()
            .map(|(index, binding)| (format!("credential-{index}"), binding))
            .collect();
        state.certificates =
            aether::certificates::state::ClientCertificateState::new(ClientCertificateGeneration {
                generation: 4,
                ca_tls_epoch: 1,
                tls_ca_certificate_fingerprint: domain.tls_ca_der.fingerprint(),
                tls_certificate_fingerprint: domain.active_client_tls.fingerprint(),
                pq_certificate_fingerprint:
                    aether::certificates::gateway::pq_certificate_fingerprint(expired)
                        .expect("pq fingerprint"),
                not_before: NOW - 86_400,
                not_after: NOW + 10 * 86_400,
            });
        state
    }

    /// The order the module's own doc-comment claims: expiry is confirmed
    /// before a single key is drawn. Running this on a live identity would
    /// burn a generation and ask an operator for a touch that an ordinary
    /// renewal gets without one.
    #[test]
    fn a_live_identity_is_refused_before_any_key_is_generated() {
        let directory = tempfile::tempdir().expect("tempdir");
        let domain = domain();
        let (leaf, private) = expired_leaf(&domain);
        let state = state_with(
            directory.path(),
            &domain,
            vec![binding(CredentialState::Active)],
            &leaf,
        );

        assert!(matches!(
            build_request(
                &state,
                leaf,
                domain.active_client_tls.clone(),
                &private,
                [3; 32],
                NOW, // before not_after: the identity is still in service
            ),
            Err(RecoveryError::NotExpired)
        ));
    }

    /// A recovery names the credential an operator will answer under. Without
    /// one, nobody can approve it — and the profile says so instead of posting
    /// a request that Astra would open and no touch could ever close.
    #[test]
    fn a_profile_with_no_active_operator_credential_is_refused_by_name() {
        let directory = tempfile::tempdir().expect("tempdir");
        let domain = domain();
        let (leaf, private) = expired_leaf(&domain);

        for credentials in [vec![], vec![binding(CredentialState::Revoked)]] {
            let state = state_with(directory.path(), &domain, credentials, &leaf);
            let refusal = build_request(
                &state,
                leaf.clone(),
                domain.active_client_tls.clone(),
                &private,
                [3; 32],
                LATER,
            );
            assert!(matches!(refusal, Err(RecoveryError::Identity(_))));
        }
    }

    /// The whole point of the client half: what it assembles is what the
    /// authority's historical validator accepts. Both signatures, the
    /// challenge, the domain, the gateway, the generation.
    #[test]
    fn the_request_this_client_builds_is_the_one_the_validator_accepts() {
        let directory = tempfile::tempdir().expect("tempdir");
        let domain = domain();
        let (leaf, private) = expired_leaf(&domain);
        let state = state_with(
            directory.path(),
            &domain,
            vec![binding(CredentialState::Active)],
            &leaf,
        );
        let challenge = [7u8; 32];

        let (request, keys) = build_request(
            &state,
            leaf,
            domain.active_client_tls.clone(),
            &private,
            challenge,
            LATER,
        )
        .expect("the request is built");

        // A recovery restores an identity; it never renames one, and it never
        // skips a generation.
        assert_eq!(request.expired_pq_certificate.subject, SUBJECT);
        assert_eq!(
            request.requested_generation,
            state.certificates.active.generation + 1
        );
        assert_eq!(request.credential_id, vec![0xAB, 0xCD]);
        // The candidate keys stay here. What travels is a PKCS#10 and a public
        // key, each covered by a signature of its own private half.
        assert_eq!(request.tls_csr, keys.tls.csr);

        let issuer = &domain.ca_pq_public;
        request
            .verify_historical(
                &[issuer],
                &state.trust_domain_id,
                &state.gateway.gateway_wg_public_key,
                SERVER_NAME,
                &state.client_wg_public_key,
                &state.certificates.active,
                &challenge,
                LATER,
            )
            .expect("the authority accepts what this client signed");

        // The challenge is not decoration: another one breaks the request.
        assert!(request
            .verify_historical(
                &[issuer],
                &state.trust_domain_id,
                &state.gateway.gateway_wg_public_key,
                SERVER_NAME,
                &state.client_wg_public_key,
                &state.certificates.active,
                &[9; 32],
                LATER,
            )
            .is_err());
    }

    /// The answer must be about **this** request and **this** client. A view
    /// that names another recovery would advance a session towards installing
    /// a grant nobody asked for on this machine.
    #[test]
    fn an_answer_about_another_recovery_advances_nothing() {
        let directory = tempfile::tempdir().expect("tempdir");
        let domain = domain();
        let (leaf, private) = expired_leaf(&domain);
        let state = state_with(
            directory.path(),
            &domain,
            vec![binding(CredentialState::Active)],
            &leaf,
        );
        let (request, keys) = build_request(
            &state,
            leaf,
            domain.active_client_tls.clone(),
            &private,
            [7; 32],
            LATER,
        )
        .expect("request");

        let operation_id = Id16::new([4; 16]).expect("id");
        let session = RecoverySession {
            base: "https://astra.example".into(),
            http: reqwest::Client::new(),
            operation_id,
            request: Box::new(request),
            keys,
        };

        let view = |fingerprint: Fingerprint, client: WireGuardKey| ExpiredRecoveryOperationView {
            operation_id,
            state: ExpiredRecoveryState::AwaitingOperator,
            client_wg_public_key: client,
            request_fingerprint: fingerprint,
            created_at: LATER,
            expires_at: LATER + 300,
            request: None,
            receipt: None,
            gateway_pq_certificate: None,
            grant: None,
        };

        let mine = session.request.fingerprint();
        assert!(matches!(
            session
                .step_of(&view(mine, session.request.client_wg_public_key))
                .expect("this recovery"),
            RecoveryStep::AwaitingOperator { .. }
        ));
        assert!(matches!(
            session.step_of(&view(
                Fingerprint::of(b"another request"),
                session.request.client_wg_public_key
            )),
            Err(RecoveryError::Refused)
        ));
        assert!(matches!(
            session.step_of(&view(mine, WireGuardKey::from_bytes([0x5A; 32]))),
            Err(RecoveryError::Refused)
        ));
    }

    /// The known limit of §7.5, as an error rather than a panic: without the
    /// historical material there is no proof to produce, and the client says
    /// which door is left — an operator readmission.
    #[test]
    fn a_bundle_without_its_historical_leaf_names_the_missing_proof() {
        let bundle = ClientIdentityBundle {
            certificate_chain: Vec::new(),
            ..crate::test_domain::bundle(&domain())
        };
        assert!(matches!(
            leaf_of(&bundle),
            Err(RecoveryError::NoHistoricalProof)
        ));
    }
}
