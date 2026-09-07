//! Recovery of an identity whose leaf has already expired — spec §7.5.
//!
//! # Why this path exists at all
//!
//! Every ordinary renewal proves possession with a leaf that still verifies.
//! Once a leaf has expired, nothing the client holds is accepted by mTLS, by
//! QUIC or by any ordinary validator — including the tunnel it would normally
//! renew through. Without this path a machine that was switched off for too
//! long is re-admitted from scratch, which is a two-credential ceremony and a
//! new identity: the continuity of everything that named the old one is lost.
//!
//! # What replaces the tunnel as proof
//!
//! Three things at once, and one of them alone is never enough:
//!
//! - the **expired private key** signs the request. It is a historical proof,
//!   checked by [`ExpiredCertificateRecoveryRequest::verify_historical`], which
//!   ignores the validity period **and nothing else** — issuer, role, WireGuard
//!   binding, fingerprints and last recorded generation are all still checked;
//! - an **operator credential** answers a challenge this authority issued and
//!   consumes. One touch, and §7.5 says why one is enough: the touch is not the
//!   only proof, and a recovery can change neither the peer nor the domain;
//!   re-admission, which *can* create a new continuity, needs two;
//! - **`CA-PQ`** signs the staging and the grant. The delegated issuer is
//!   deliberately not allowed to: it may renew a live identity, never revive an
//!   expired one, and [`RotationReason::is_delegable`] refuses the reason.
//!
//! # Why the state is in memory
//!
//! The same reason the operator campaigns are. The challenge lives sixty
//! seconds and the whole exchange five minutes; persisting it would outlive
//! the window it exists to bound, and a restart would resurrect a request an
//! operator may have declined. A restart costs one retry of a ceremony that
//! has to be restarted anyway.
//!
//! # Limite connue : la clé privée expirée doit encore exister
//!
//! §7.5 is explicit — if the old private key went with the DPAPI or TPM store
//! that held it, no historical proof can be produced and this path does not
//! apply. What is left is an operator re-admission under two credentials, which
//! is a different operation with a different meaning: it creates a new
//! continuity rather than extending one.

use std::collections::BTreeMap;
use std::sync::Arc;

use aether::certificates::{
    approval::ExpiredRecoveryApprovalEvidence,
    client::{
        ClientCertificateRotationGrant, ClientCertificateStageAuthorization,
        ClientCertificateStageCommit, ExpiredCertificateRecoveryRequest,
        GatewayCertificateStageReceipt, IssuerKind,
    },
    encoding::{Fingerprint, Id16, WireGuardKey},
    transport::{ExpiredRecoveryOperationView, ExpiredRecoveryState},
    CertificateError,
};

use crate::service::AstraService;

/// How long one recovery may take, from the verified request to the commit.
///
/// Five minutes, the approval lifetime of §2.4. The operator's assertion is
/// bounded by it, and an operation that outlived its own approval would be an
/// operation waiting for a decision nobody may still act on.
pub const RECOVERY_LIFETIME_SECS: u64 = 300;

/// Recoveries alive at once.
///
/// A recovery is a rare, attended operation. More than a handful in flight
/// means something is looping, and growing memory on that is how a bound stops
/// being one.
pub const MAX_LIVE_RECOVERIES: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("no such recovery")]
    Unknown,
    #[error("this recovery has expired")]
    Expired,
    #[error("too many recoveries are already in flight")]
    Full,
    #[error("this recovery is not in a state that accepts this step")]
    WrongState,
    #[error("no admitted peer holds this identity")]
    UnknownPeer,
    #[error("this identity is revoked; no credential lifts that state")]
    Revoked,
    #[error("this authority has no private channel to the gateway")]
    NoGatewayChannel,
    #[error("the gateway refused: {0}")]
    Gateway(String),
    #[error("recovery refused: {0}")]
    Certificate(#[from] CertificateError),
    #[error("registry: {0}")]
    Registry(#[from] crate::registry::RegistryError),
    #[error("reconciliation intent: {0}")]
    Reconciliation(String),
}

/// One recovery, from the verified request to the relayed commit.
#[derive(Debug, Clone)]
pub struct RecoveryOperation {
    pub operation_id: Id16,
    pub request: Box<ExpiredCertificateRecoveryRequest>,
    pub request_fingerprint: Fingerprint,
    pub state: ExpiredRecoveryState,
    pub created_at: u64,
    pub expires_at: u64,
    authorization: Option<Box<ClientCertificateStageAuthorization>>,
    receipt: Option<Box<GatewayCertificateStageReceipt>>,
    gateway_pq_certificate: Option<Box<aether::key_negotiation::PqCertificate>>,
    grant: Option<Box<ClientCertificateRotationGrant>>,
}

impl RecoveryOperation {
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at
    }

    pub fn authorization(&self) -> Option<&ClientCertificateStageAuthorization> {
        self.authorization.as_deref()
    }

    pub fn receipt(&self) -> Option<&GatewayCertificateStageReceipt> {
        self.receipt.as_deref()
    }

    /// What a caller learns. The request travels for the companion, which has
    /// to display it; the receipt for the same reason; the grant for the
    /// client, which installs it.
    pub fn view(&self) -> ExpiredRecoveryOperationView {
        ExpiredRecoveryOperationView {
            operation_id: self.operation_id,
            state: self.state,
            client_wg_public_key: self.request.client_wg_public_key,
            request_fingerprint: self.request_fingerprint,
            created_at: self.created_at,
            expires_at: self.expires_at,
            request: Some(self.request.clone()),
            receipt: self.receipt.clone(),
            gateway_pq_certificate: self.gateway_pq_certificate.clone(),
            grant: self.grant.clone(),
        }
    }
}

/// Every recovery this process holds.
#[derive(Debug, Default)]
pub struct RecoveryStore {
    operations: BTreeMap<[u8; 16], RecoveryOperation>,
}

impl RecoveryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.operations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Opens a recovery, collecting the ones whose window has passed.
    ///
    /// The sweep happens on the way in rather than on a timer: a store that
    /// only grew would let a burst of abandoned ceremonies deny every honest
    /// one afterwards, and a timer is a second thing that has to be running.
    pub fn open(
        &mut self,
        operation: RecoveryOperation,
        now_unix: u64,
    ) -> Result<(), RecoveryError> {
        self.operations
            .retain(|_, existing| !existing.is_expired(now_unix));
        if self.operations.len() >= MAX_LIVE_RECOVERIES {
            return Err(RecoveryError::Full);
        }
        self.operations
            .insert(*operation.operation_id.as_bytes(), operation);
        Ok(())
    }

    pub fn get(
        &self,
        operation_id: &Id16,
        now_unix: u64,
    ) -> Result<&RecoveryOperation, RecoveryError> {
        let operation = self
            .operations
            .get(operation_id.as_bytes())
            .ok_or(RecoveryError::Unknown)?;
        if operation.is_expired(now_unix) {
            return Err(RecoveryError::Expired);
        }
        Ok(operation)
    }

    fn get_mut(
        &mut self,
        operation_id: &Id16,
        now_unix: u64,
    ) -> Result<&mut RecoveryOperation, RecoveryError> {
        let operation = self
            .operations
            .get_mut(operation_id.as_bytes())
            .ok_or(RecoveryError::Unknown)?;
        if operation.is_expired(now_unix) {
            return Err(RecoveryError::Expired);
        }
        Ok(operation)
    }
}

/// Step 1: the client's request, verified by the historical validator.
///
/// Nothing here trusts the caller. The peer is looked up by the key the
/// request names, but every proof is then checked against what **this
/// registry** holds — the issuers, the last recorded generation, the domain
/// and the challenge this authority issued. A request naming a peer that does
/// not exist, or an older generation, is refused before the signature work
/// that would confirm the peer exists at all.
pub async fn open(
    service: &Arc<AstraService>,
    request: Box<ExpiredCertificateRecoveryRequest>,
    now_unix: u64,
) -> Result<ExpiredRecoveryOperationView, RecoveryError> {
    let client = request.client_wg_public_key;
    // Le pair est transcrit depuis la gateway s'il ne l'est pas encore. Astra
    // n'admet personne — la gateway le fait, et c'est elle qui a remis les
    // feuilles à l'enrôlement — donc son registre se remplit en lisant le
    // canal privé, jamais par une seconde admission qu'un opérateur devrait
    // tenir à jour en double.
    //
    // Le renouvellement le faisait déjà ; la récupération, non. Elle refusait
    // donc « aucun pair admis ne détient cette identité » à un poste que la
    // gateway venait d'admettre, et cela pour toujours : la transcription
    // n'avait lieu qu'au premier renouvellement ordinaire, et un poste éteint
    // depuis son enrôlement n'en fait jamais. Le seul cas que §7.5 traite
    // était exactement celui qu'il ne pouvait pas atteindre.
    //
    // Aucune date n'entre dans la transcription : elle compare la clé
    // WireGuard et l'empreinte de la génération active, pas leur validité.
    // C'est ce qui la rend utilisable ici, sur une feuille déjà périmée.
    crate::renewal::transcribe_peer(service, &client, now_unix)
        .await
        .map_err(|error| match error {
            crate::renewal::RenewalError::UnknownPeer => RecoveryError::UnknownPeer,
            crate::renewal::RenewalError::Gateway(message) => RecoveryError::Gateway(message),
            other => RecoveryError::Gateway(other.to_string()),
        })?;

    let (issuers, trust_domain_id, gateway_key, server_name, last_known) = {
        let registry = service.registry.lock().await;
        let state = registry.state();
        let peer = registry.peer(&client).ok_or(RecoveryError::UnknownPeer)?;
        if peer.revoked {
            return Err(RecoveryError::Revoked);
        }
        // The anchor, and the delegated issuer when one exists: the expired
        // leaf may have been issued by either, and which one is not something
        // the request gets to assert.
        let mut issuers = vec![state.ca_public_key.clone()];
        if let Some(issuer) = &state.issuer {
            issuers.push(issuer.authorization.pq_issuer_public_key.clone());
        }
        // Et l'ancre d'admission, quand la gateway l'a nommée. Une feuille de
        // première génération est signée par elle et par rien que ce domaine
        // détienne : l'enrôlement se fait hors ligne, sans le coffre, donc
        // `CA-PQ` ne peut pas la signer. Ne fournir que les autorités du
        // domaine revenait à refuser toute identité jamais renouvelée — c'est
        // exactement la population que §7.5 sert.
        //
        // Elle n'affaiblit pas la vérification : la feuille présentée doit
        // déjà être, empreinte pour empreinte, celle que la gateway a
        // transcrite. La signature d'émetteur confirme cette liaison, elle ne
        // la remplace pas.
        if let Some(admission) = &peer.admission_pq_ca {
            issuers.push(admission.clone());
        }
        (
            issuers,
            state.trust_domain_id,
            state.gateway_wg_public_key,
            state.server_name.clone(),
            peer.active.clone(),
        )
    };

    // Consumed before anything is verified against it, and single-use: a
    // challenge that survived a refused request would be a nonce an attacker
    // could grind requests against.
    if !service
        .challenges
        .lock()
        .await
        .consume(&request.astra_challenge, now_unix)
    {
        return Err(RecoveryError::Certificate(
            CertificateError::InvalidChallenge,
        ));
    }

    let issuer_refs: Vec<_> = issuers.iter().collect();
    request.verify_historical(
        &issuer_refs,
        &trust_domain_id,
        &gateway_key,
        &server_name,
        &client,
        &last_known,
        &request.astra_challenge,
        now_unix,
    )?;

    let expires_at = now_unix
        .checked_add(RECOVERY_LIFETIME_SECS)
        .ok_or(CertificateError::ArithmeticOverflow)?
        // Never past the request's own deadline: the operator's assertion is
        // bounded by it, and an operation outliving it would wait for a
        // decision nobody may still act on.
        .min(request.expires_at);
    if expires_at <= now_unix {
        return Err(RecoveryError::Expired);
    }

    let operation = RecoveryOperation {
        operation_id: crate::renewal::fresh_id().map_err(RecoveryError::Certificate)?,
        request_fingerprint: request.fingerprint(),
        request,
        state: ExpiredRecoveryState::AwaitingOperator,
        created_at: now_unix,
        expires_at,
        authorization: None,
        receipt: None,
        gateway_pq_certificate: None,
        grant: None,
    };
    let view = operation.view();
    let operation_id = operation.operation_id;
    service.recoveries.lock().await.open(operation, now_unix)?;
    tracing::warn!(
        peer = %client,
        operation = %operation_id,
        expired_generation = view.request.as_ref().map_or(0, |r| r.expired_generation),
        "expired-identity recovery opened; it now needs an operator credential"
    );
    Ok(view)
}

/// Step 2: the companion's authorization, relayed to the gateway.
///
/// Both halves of the deposit are checked here, and the order matters: the
/// approval says an operator answered **this** request, and the authorization
/// says `CA-PQ` signed a staging for it. Either alone is a document that
/// authorizes nothing.
pub async fn authorize(
    service: &Arc<AstraService>,
    operation_id: &Id16,
    authorization: Box<ClientCertificateStageAuthorization>,
    evidence: Box<ExpiredRecoveryApprovalEvidence>,
    now_unix: u64,
) -> Result<ExpiredRecoveryOperationView, RecoveryError> {
    use aether::certificates::authority::RotationReason;

    let (request_fingerprint, challenge, client) = {
        let recoveries = service.recoveries.lock().await;
        let operation = recoveries.get(operation_id, now_unix)?;
        if operation.state != ExpiredRecoveryState::AwaitingOperator {
            // Idempotent replay of an identical deposit is handled by the
            // states below; anything else is a second decision on an
            // operation that already has one.
            return Err(RecoveryError::WrongState);
        }
        (
            operation.request_fingerprint,
            operation.request.astra_challenge,
            operation.request.client_wg_public_key,
        )
    };

    // A recovery is `CA-PQ`'s to authorize and no one else's. The delegated
    // issuer may renew a live identity; letting it revive an expired one would
    // make a bounded online key able to undo a validity period.
    if authorization.issuer_kind != IssuerKind::Master
        || authorization.reason != RotationReason::ExpiredRecovery
    {
        return Err(RecoveryError::Certificate(
            CertificateError::IssuerScopeViolation(
                "only CA-PQ authorizes the recovery of an expired identity",
            ),
        ));
    }
    if !authorization
        .request_fingerprint
        .matches(&request_fingerprint)
    {
        return Err(RecoveryError::Certificate(
            CertificateError::ApprovalMismatch("recovery request fingerprint"),
        ));
    }
    if !evidence
        .fingerprint()?
        .matches(&authorization.renewal_authorization_fingerprint)
    {
        return Err(RecoveryError::Certificate(
            CertificateError::ApprovalMismatch("recovery approval fingerprint"),
        ));
    }

    {
        let registry = service.registry.lock().await;
        let state = registry.state();
        evidence.verify(
            &state.ca_public_key,
            &state.trust_domain_id,
            &state.gateway_wg_public_key,
            &request_fingerprint,
            &challenge,
            &state.webauthn_rp_id,
            state.ca_epoch,
            state.credential_registry_epoch,
            now_unix,
        )?;
    }

    let gateway = service
        .gateway
        .as_ref()
        .ok_or(RecoveryError::NoGatewayChannel)?;
    let receipt = gateway
        .stage(&authorization)
        .await
        .map_err(|error| RecoveryError::Gateway(error.to_string()))?;

    // The leaf the daemon actually serves, read back on the same link. Not
    // Astra's copy: a gateway that rotated without restarting has a newer leaf
    // on disk that no client is offered, and a receipt is signed by what is
    // *served*. The companion cannot reach the gateway, so it is handed this
    // and compares the WireGuard key it names before trusting it.
    let served = gateway
        .gateway_identity()
        .await
        .map_err(|error| RecoveryError::Gateway(error.to_string()))?;
    // Recomputed rather than taken from the answer. The gateway sends its own
    // fingerprint; a disagreement here is a disagreement about identity, and
    // not a signature failure two steps later.
    if !aether::certificates::gateway::pq_certificate_fingerprint(&served.pq_certificate)?
        .matches(&served.pq_certificate_fingerprint)
    {
        return Err(RecoveryError::Gateway(
            "the gateway's leaf and the fingerprint it announced do not describe the same \
             identity"
                .into(),
        ));
    }
    let gateway_leaf = served.pq_certificate;

    let mut recoveries = service.recoveries.lock().await;
    let operation = recoveries.get_mut(operation_id, now_unix)?;
    operation.authorization = Some(authorization);
    operation.receipt = Some(Box::new(receipt));
    operation.gateway_pq_certificate = Some(Box::new(gateway_leaf));
    operation.state = ExpiredRecoveryState::Staged;
    tracing::warn!(
        peer = %client,
        operation = %operation_id,
        "recovery staged on the gateway; the companion may now sign the grant"
    );
    Ok(operation.view())
}

/// Step 3: the grant the companion signed against the gateway's receipt.
///
/// Verified against the authorization this authority relayed, not against the
/// one the deposit carries: a grant is only ever the answer to a staging that
/// actually happened.
pub async fn grant(
    service: &Arc<AstraService>,
    operation_id: &Id16,
    grant: Box<ClientCertificateRotationGrant>,
    now_unix: u64,
) -> Result<ExpiredRecoveryOperationView, RecoveryError> {
    let (ca_public_key, trust_domain_id, ca_epoch) = {
        let registry = service.registry.lock().await;
        let state = registry.state();
        (
            state.ca_public_key.clone(),
            state.trust_domain_id,
            state.ca_epoch,
        )
    };

    let mut recoveries = service.recoveries.lock().await;
    let operation = recoveries.get_mut(operation_id, now_unix)?;
    if operation.state != ExpiredRecoveryState::Staged {
        return Err(RecoveryError::WrongState);
    }
    let authorization = operation
        .authorization
        .as_deref()
        .ok_or(RecoveryError::WrongState)?;
    let receipt = operation
        .receipt
        .as_deref()
        .ok_or(RecoveryError::WrongState)?;

    // Everything the grant claims must already be true of the staging this
    // authority relayed. Anything the grant supplied on its own would be a
    // statement the client is asked to believe for being present.
    if grant.issuer_kind != IssuerKind::Master
        || grant.trust_domain_id != trust_domain_id
        || grant.ca_epoch != ca_epoch
        || !grant
            .request_fingerprint
            .matches(&authorization.request_fingerprint)
        || !grant
            .renewal_authorization_fingerprint
            .matches(&authorization.renewal_authorization_fingerprint)
        || !grant
            .stage_receipt_fingerprint
            .matches(&receipt.fingerprint())
        || grant.next_generation != authorization.next_generation
    {
        return Err(RecoveryError::Certificate(
            CertificateError::ApprovalMismatch("grant does not answer this staging"),
        ));
    }
    // Under `CA-PQ` itself: the signature is the whole point of relaying it.
    grant
        .verify_signed_by(&ca_public_key)
        .map_err(RecoveryError::Certificate)?;

    operation.grant = Some(grant);
    operation.state = ExpiredRecoveryState::Granted;
    tracing::warn!(
        peer = %operation.request.client_wg_public_key,
        operation = %operation_id,
        "recovery grant released; the client may install and commit"
    );
    let client = operation.request.client_wg_public_key;
    let generation = operation
        .authorization
        .as_deref()
        .map(|authorization| authorization.next_generation)
        .unwrap_or_default();
    let view = operation.view();
    // The recoveries lock is released before the registry is taken: `open`
    // holds them the other way round, and a lifecycle that can deadlock under
    // two simultaneous recoveries is not one an operator can be asked to
    // restart out of.
    drop(recoveries);

    // The one moment an operator credential resurrected a dead identity. It is
    // recorded here, at acceptance, and not at the commit: what was proved is
    // that the operator signed under `CA-PQ` against this staging. Whether the
    // client then managed to install it is a different fact, and it gets its
    // own record.
    let peer = {
        let registry = service.registry.lock().await;
        registry
            .peer(&client)
            .map(|peer| peer.name.clone())
            .unwrap_or_else(|| client.to_base64())
    };
    service
        .registry
        .lock()
        .await
        .record(
            crate::audit::AuditEvent::ExpiredRecoveryApproved { peer, generation },
            now_unix,
        )
        .map_err(RecoveryError::Registry)?;
    Ok(view)
}

/// Step 4: the client's commit, relayed to the gateway over the veth.
///
/// The client has no tunnel — that is the whole premise — so the authority
/// carries the commit. It carries it and decides nothing: the commit is signed
/// by both the expired key and the candidate's, and the gateway refuses
/// anything whose pending stage was not opened by the `CA-PQ` authorization
/// presented beside it.
pub async fn commit(
    service: &Arc<AstraService>,
    operation_id: &Id16,
    commit: Box<ClientCertificateStageCommit>,
    now_unix: u64,
) -> Result<ExpiredRecoveryOperationView, RecoveryError> {
    let (authorization, grant, client) = {
        let recoveries = service.recoveries.lock().await;
        let operation = recoveries.get(operation_id, now_unix)?;
        if operation.state != ExpiredRecoveryState::Granted {
            return Err(RecoveryError::WrongState);
        }
        (
            operation
                .authorization
                .clone()
                .ok_or(RecoveryError::WrongState)?,
            operation.grant.clone().ok_or(RecoveryError::WrongState)?,
            operation.request.client_wg_public_key,
        )
    };
    if commit.client_wg_public_key != client || commit.stage_id != authorization.stage_id {
        return Err(RecoveryError::Certificate(
            CertificateError::ClientIdentityMismatch,
        ));
    }

    let gateway = service
        .gateway
        .as_ref()
        .ok_or(RecoveryError::NoGatewayChannel)?;

    // Written **before** the gateway is asked, and not after: the failure this
    // guards against is a crash between the two writes, and an intent recorded
    // afterwards would not exist in exactly the window it is for. Recording it
    // for a commit the gateway then refuses costs one idempotent re-read at
    // the next start, which is the cheap side of the trade.
    let expected_generation = commit.staged_generation;
    crate::reconciliation::record(
        &service.state_dir,
        &crate::reconciliation::PendingReconciliation {
            peer: client,
            expected_generation,
            recorded_at: now_unix,
        },
    )
    .map_err(|error| RecoveryError::Reconciliation(error.to_string()))?;

    gateway
        .commit_recovery(&helios_api::internal::RelayedStageCommit {
            authorization,
            commit,
            grant,
        })
        .await
        .map_err(|error| RecoveryError::Gateway(error.to_string()))?;

    let mut recoveries = service.recoveries.lock().await;
    let operation = recoveries.get_mut(operation_id, now_unix)?;
    operation.state = ExpiredRecoveryState::Committed;
    tracing::warn!(
        peer = %client,
        operation = %operation_id,
        "expired identity recovered: the gateway holds the new generation"
    );
    let view = operation.view();
    drop(recoveries);

    // The gateway has not necessarily promoted yet: a recovered generation
    // activates at the end of its staging lease, which §7.2 puts after the
    // commit. So this is an attempt, not a guarantee, and the intent stays on
    // disk until it succeeds. Failing here must not fail the recovery — the
    // client's identity is installed at both ends by now, and refusing its
    // commit over a bookkeeping read would be refusing something that already
    // happened.
    match reconcile(service, &client, expected_generation, now_unix).await {
        Ok(true) => {}
        Ok(false) => tracing::info!(
            peer = %client,
            expected_generation,
            "the gateway has not promoted the recovered generation yet; the intent stays on \
             disk and the next contact adopts it"
        ),
        Err(error) => tracing::warn!(
            peer = %client,
            %error,
            "the recovered generation could not be adopted here; the intent stays on disk"
        ),
    }
    Ok(view)
}

/// Adopts what the gateway serves for one peer, and closes the intent when it
/// has caught up.
///
/// Returns whether the intent was closed. Idempotent: it reads the gateway and
/// reconciles forward-only, so replaying it after a crash — or at every start
/// — decides nothing it did not already decide.
pub async fn reconcile(
    service: &Arc<AstraService>,
    client: &WireGuardKey,
    expected_generation: u64,
    now_unix: u64,
) -> Result<bool, RecoveryError> {
    crate::renewal::transcribe_peer(service, client, now_unix)
        .await
        .map_err(|error| match error {
            crate::renewal::RenewalError::UnknownPeer => RecoveryError::UnknownPeer,
            other => RecoveryError::Gateway(other.to_string()),
        })?;
    let reached = service
        .registry
        .lock()
        .await
        .peer(client)
        .is_some_and(|peer| peer.active.generation >= expected_generation);
    if reached {
        crate::reconciliation::clear(&service.state_dir)
            .map_err(|error| RecoveryError::Reconciliation(error.to_string()))?;
    }
    Ok(reached)
}

/// The bounded class a public caller learns.
///
/// Four outcomes, and the reason never travels: this route is reachable
/// without a tunnel and without a credential, so a precise refusal would let
/// an unauthenticated caller enumerate which identities exist and which
/// generation they are on.
pub fn refusal(error: &RecoveryError) -> crate::service::ServiceError {
    use crate::service::ServiceError;
    match error {
        RecoveryError::Full => ServiceError::Throttled,
        RecoveryError::NoGatewayChannel | RecoveryError::Gateway(_) => ServiceError::Internal,
        _ => ServiceError::Refused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::encoding::{
        DerCertificate, MlDsa87PublicKey, MlDsa87Signature, TrustDomainId, WireGuardKey,
    };
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

    /// A request whose contents the store never reads.
    ///
    /// Everything that decides anything about a recovery is checked in
    /// [`open`], against the registry. What is asserted below is the store's
    /// own contract — its ceiling and its window — so a fixture with real
    /// signatures would only obscure which rule fired.
    fn request(seed: u8) -> Box<ExpiredCertificateRecoveryRequest> {
        Box::new(ExpiredCertificateRecoveryRequest {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            protocol_version: aether::certificates::CERTIFICATE_PROTOCOL_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            astra_challenge: [seed; 32],
            request_id: Id16::new([seed; 16]).expect("id"),
            gateway_wg_public_key: WireGuardKey::from_bytes([9; 32]),
            server_name: "gateway.example".into(),
            client_wg_public_key: WireGuardKey::from_bytes([seed; 32]),
            expired_generation: 4,
            requested_generation: 5,
            expired_tls_certificate: DerCertificate::new(vec![1; 64]).expect("der"),
            expired_pq_certificate: PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [seed; 16],
                subject: "workstation".into(),
                issuer: "CA-PQ".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: WireGuardKey::from_bytes([seed; 32]).to_base64(),
                ml_dsa_87_public_key: String::new(),
                not_before_unix: 0,
                not_after_unix: 100,
                ml_dsa_87_signature: String::new(),
            },
            tls_csr: DerCertificate::new(vec![2; 64]).expect("der"),
            new_ml_dsa_87_public_key: MlDsa87PublicKey::new(vec![0; 2592])
                .unwrap_or_else(|_| unreachable!("ML-DSA-87 public keys are 2592 bytes")),
            credential_id: b"credential-one".to_vec(),
            created_at: 1_000,
            expires_at: 1_300,
            expired_pq_signature: MlDsa87Signature::placeholder(),
            new_pq_signature: MlDsa87Signature::placeholder(),
        })
    }

    fn operation(seed: u8, now_unix: u64) -> RecoveryOperation {
        let request = request(seed);
        RecoveryOperation {
            operation_id: Id16::new([seed; 16]).expect("id"),
            request_fingerprint: request.fingerprint(),
            request,
            state: ExpiredRecoveryState::AwaitingOperator,
            created_at: now_unix,
            expires_at: now_unix + RECOVERY_LIFETIME_SECS,
            authorization: None,
            receipt: None,
            gateway_pq_certificate: None,
            grant: None,
        }
    }

    /// An unbounded store turns a public, unauthenticated route into a
    /// memory-exhaustion primitive: this one is reachable **without** a
    /// certificate by construction.
    #[test]
    fn the_store_refuses_rather_than_growing() {
        let mut store = RecoveryStore::new();
        for seed in 1..=MAX_LIVE_RECOVERIES {
            store
                .open(operation(seed as u8, 1_000), 1_000)
                .expect("opened");
        }
        assert!(matches!(
            store.open(operation(200, 1_000), 1_000),
            Err(RecoveryError::Full)
        ));
        assert_eq!(store.len(), MAX_LIVE_RECOVERIES);
    }

    /// The sweep happens on the way in. A burst of abandoned ceremonies must
    /// not deny every honest one that follows it.
    #[test]
    fn an_abandoned_recovery_frees_its_place() {
        let mut store = RecoveryStore::new();
        for seed in 1..=MAX_LIVE_RECOVERIES {
            store
                .open(operation(seed as u8, 1_000), 1_000)
                .expect("opened");
        }
        let later = 1_000 + RECOVERY_LIFETIME_SECS;
        store.open(operation(200, later), later).expect("opened");
        assert_eq!(store.len(), 1, "the window collected the previous ones");
    }

    /// Past its window an operation is gone, not merely stale: a caller that
    /// still held the identifier must not resume a ceremony whose approval
    /// nobody may act on any more.
    #[test]
    fn a_recovery_past_its_window_is_no_longer_readable() {
        let mut store = RecoveryStore::new();
        store.open(operation(1, 1_000), 1_000).expect("opened");
        let id = Id16::new([1; 16]).expect("id");
        assert!(store.get(&id, 1_100).is_ok());
        assert!(matches!(
            store.get(&id, 1_000 + RECOVERY_LIFETIME_SECS),
            Err(RecoveryError::Expired)
        ));
    }
}
