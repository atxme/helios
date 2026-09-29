//! The in-tunnel trust-update handler: the transitions a client fetches.

use super::*;

/// Refuses a candidate this gateway would not accept on the negotiation port.
///
/// # Why staging has to ask this at all
///
/// A staged generation becomes the client's only identity at the end of its
/// overlap. If the gateway cannot authenticate it then, the client is locked
/// out of the tunnel that was its only way to ask for help — and the operator
/// finds out days later, on a machine that no longer connects. So the question
/// is asked **before** the candidate is written, where the answer still costs
/// nothing.
///
/// # Why this asks the negotiation's own question
///
/// The negotiation now resolves callers from the registry and admits every
/// issuer the domain names — the anchor, its successor, the delegated issuer,
/// and the operator CA the first generation was signed by. This check builds
/// **the same set, the same way**. Two slightly different answers to "would
/// this leaf authenticate" is the failure that has no good outcome: the
/// narrower one refuses candidates that would have worked, and the wider one
/// stages a leaf whose owner is locked out at the end of the overlap, on a
/// machine whose only channel for saying so was the tunnel.
///
/// # Limite connue — the TLS root set is still read once, at startup
///
/// The QUIC endpoint loads the operator admission CA from
/// `/var/lib/helios/key-negotiation-client-ca.der`, then adds the domain
/// anchors the registry accepts at that instant. A delegated leaf therefore
/// validates when the client presents its intermediate. The set stays fixed
/// for the process lifetime: a `CA-TLS` transition installed before
/// `activation_at` still requires a restart during the overlap to offer its
/// successor, and another after retirement to stop offering the outgoing
/// root at the TLS layer. The paired TLS/PQ registry check remains
/// time-bounded on every request, so a root merely present in the endpoint is
/// never sufficient to admit a stale generation.
/// Every authority a client leaf may chain to, in the order the negotiation
/// port asks them.
///
/// Pure on purpose, like [`assert_candidate_is_presentable`](super::astra::assert_candidate_is_presentable): the key is read
/// from disk by the caller, so this can be exercised without a
/// `/var/lib/helios` on the machine running it.
pub(super) fn client_leaf_issuers<'a>(
    state: &'a helios_provisioning::certificates::RegistryState,
    operator_ca: &'a aether::certificates::encoding::MlDsa87PublicKey,
    now_unix: u64,
) -> Vec<&'a aether::certificates::encoding::MlDsa87PublicKey> {
    let mut issuers = vec![operator_ca];
    for key in state.client_leaf_issuers(now_unix) {
        if !issuers.contains(&key) {
            issuers.push(key);
        }
    }
    issuers
}

#[async_trait]
impl TrustUpdateHandler for CertificateService {
    /// The public trust material a profile must carry for one peer (spec §19).
    ///
    /// Every value is read from the registry in one lock, and that matters: an
    /// epoch taken from one moment beside an anchor from another would produce
    /// a profile that pins a pair which never existed together, and the
    /// mismatch would only surface at the first renewal — 80 % into a leaf's
    /// life, on a client with no fallback.
    async fn admit_peer(
        &self,
        name: &str,
        peer_wg_public_key: &str,
        tls_certificate: aether::certificates::encoding::DerCertificate,
        pq_certificate: Box<aether::key_negotiation::PqCertificate>,
    ) -> Result<(), TrustUpdateRefusal> {
        self.record_first_generation(name, peer_wg_public_key, tls_certificate, *pq_certificate)
            .await
    }

    async fn trust_enrolment(
        &self,
        peer_wg_public_key: &str,
    ) -> Result<helios_api::certificates::TrustEnrolmentView, TrustUpdateRefusal> {
        let peer_key =
            WireGuardKey::parse(peer_wg_public_key).map_err(|_| TrustUpdateRefusal::Rejected)?;
        let registry = self.registry.lock().await;
        let peer = registry
            .peer(&peer_key)
            .ok_or(TrustUpdateRefusal::Rejected)?;
        Ok(enrolment_view(registry.state(), peer))
    }

    async fn domain(
        &self,
    ) -> Result<helios_api::certificates::CertificateDomainView, TrustUpdateRefusal> {
        let now = now_unix();
        let registry = self.registry.lock().await;
        Ok(domain_view(registry.state(), now))
    }

    async fn trust_update(
        &self,
        caller_wg_public_key: &str,
        request: aether::certificates::transport::AuthenticatedTrustUpdateRequest,
    ) -> Result<TrustUpdateResponse, TrustUpdateRefusal> {
        let caller =
            WireGuardKey::parse(caller_wg_public_key).map_err(|_| TrustUpdateRefusal::Rejected)?;
        let now = now_unix();
        let registry = self.registry.lock().await;
        let state = registry.state();

        // Every authority that may have issued the caller's leaf, asked as
        // exactly the question the negotiation port answers: the operator CA
        // on disk, then the registry's anchors and the delegated issuer an
        // ordinary renewal chains to.
        //
        // The operator CA is not optional here. A client's *first* leaf is
        // issued under it at admission — only a renewal moves it to the
        // delegated issuer — so a set built from the registry alone refuses
        // every client that has never renewed, which on a fresh domain is all
        // of them. Both other sites that ask this question build it the same
        // way, and the three must not drift: this one did, and the symptom was
        // a `403` on every connection with nothing naming the cause.
        let operator_ca = std::fs::read(crate::key_negotiation::CLIENT_PQ_CA_PATH)
            .map_err(|error| {
                tracing::error!(
                    peer = %caller_wg_public_key,
                    %error,
                    "trust update refused: the client PQ CA the negotiation port authenticates \
                     under is unreadable"
                );
                TrustUpdateRefusal::Internal
            })
            .and_then(|bytes| {
                aether::certificates::encoding::MlDsa87PublicKey::new(bytes).map_err(|error| {
                    tracing::error!(
                        peer = %caller_wg_public_key,
                        %error,
                        "trust update refused: the client PQ CA on disk is not a readable \
                         ML-DSA-87 public key"
                    );
                    TrustUpdateRefusal::Internal
                })
            })?;
        let issuers = client_leaf_issuers(state, &operator_ca, now);

        request
            .verify(
                &issuers,
                &state.trust_domain_id,
                &state.gateway.gateway_wg_public_key,
                &caller,
                &registry.acceptable_pq_fingerprints(&caller, now),
                now,
            )
            .map_err(|error| {
                tracing::warn!(peer = %caller_wg_public_key, %error, "trust update refused");
                TrustUpdateRefusal::Rejected
            })?;

        let peer = registry.peer(&caller).ok_or(TrustUpdateRefusal::Rejected)?;
        let current = caller_is_current(state, peer, &request.request)
            .map_err(|_| TrustUpdateRefusal::Internal)?;

        if current {
            return Ok(TrustUpdateResponse {
                status: None,
                manifest: None,
                chunk: None,
            });
        }

        // Behind. Whether there is anything to hand over is a question about
        // the queue, not about the comparison — and the two are kept apart
        // because a client that is current must never pay for a queue read.
        let request_id = request.request.request_id;
        drop(registry);
        let mut registry = self.registry.lock().await;
        let served = registry
            .take_distribution_chunk(
                &caller,
                &request_id,
                &request.request.base_state_fingerprint,
                now,
            )
            .map_err(|error| {
                tracing::warn!(peer = %caller_wg_public_key, %error, "trust distribution unreadable");
                classify(error)
            })?;
        let served = match served {
            Some(served) => Some(served),
            // Nothing queued for this exact base state — either nothing was
            // ever queued, or what was queued described a state this client
            // has since left and the read above dropped it. Both mean the same
            // thing: ask the authority to build one for the state this request
            // signed (§0.6).
            None => {
                drop(registry);
                self.prepare_from_authority(&caller, &request, now).await?;
                let mut registry = self.registry.lock().await;
                registry
                    .take_distribution_chunk(
                        &caller,
                        &request_id,
                        &request.request.base_state_fingerprint,
                        now,
                    )
                    .map_err(|error| {
                        tracing::warn!(
                            peer = %caller_wg_public_key, %error,
                            "trust distribution unreadable after preparation"
                        );
                        classify(error)
                    })?
            }
        };
        match served {
            Some((manifest, chunk)) => Ok(TrustUpdateResponse {
                // Never a status: one is signed by Astra's service key, which
                // this gateway does not hold and must not hold. A client that
                // needs a signed freshness statement asks the authority for it
                // (§8.2); what it gets here is the transaction itself.
                status: None,
                manifest: Some(manifest),
                chunk: Some(chunk),
            }),
            None => {
                // Behind, and the authority has nothing for it. Saying so
                // beats claiming the client is up to date: an empty update is
                // the one answer a client does not recover from, because it
                // stops asking.
                tracing::warn!(
                    peer = %caller_wg_public_key,
                    "trust update: the caller is behind and the authority has nothing for it"
                );
                Err(TrustUpdateRefusal::Unavailable)
            }
        }
    }

    async fn stage_commit(
        &self,
        caller_wg_public_key: &str,
        request: Box<StageCommitRequest>,
    ) -> Result<(), TrustUpdateRefusal> {
        let caller =
            WireGuardKey::parse(caller_wg_public_key).map_err(|_| TrustUpdateRefusal::Rejected)?;
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        registry
            .commit(&caller, &request.commit, &request.grant, now)
            .map_err(|error| {
                tracing::warn!(peer = %caller_wg_public_key, %error, "commit refused");
                classify(error)
            })?;
        Ok(())
    }
}
