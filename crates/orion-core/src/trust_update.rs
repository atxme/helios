//! The client half of the in-tunnel trust update — spec §8.1.1 and §0.6.
//!
//! # What this asks, and what it never asks for
//!
//! One question: «here is every counter and fingerprint I hold, plus the hash
//! of my complete local state — is there anything for me?» The gateway answers
//! with nothing at all, or with one fragment of a signed transaction. There is
//! no way to ask for a *particular* object, and that is deliberate: a client
//! that could name what it wants could also decline to name a revocation.
//!
//! # The compare-and-swap token
//!
//! `base_state_fingerprint` is the hash of the **whole** local store, and it
//! travels inside the signed request (§0.6). Everything that comes back is
//! bound to it. So a transaction is only ever applied to the exact state it
//! was computed against: anything that moved the store in between — a
//! renewal committing, a revocation landing, a scheduled item coming due —
//! invalidates the transaction rather than applying a decision taken about a
//! state that no longer exists. The recomputation happens at
//! [`TrustStore::apply_transaction`], on the live store, not here.
//!
//! # Why a session and not a call
//!
//! A transaction is chunked, and one poll returns one fragment. The manifest
//! comes back with every fragment — so a manifest that changes mid-collection
//! is a conflict, not a resumption — and nothing is applied until the last
//! fragment lands. Holding that across polls is the session's whole job.

use std::time::Duration;

use aether::certificates::encoding::{Fingerprint, Id16};
use aether::certificates::transport::{
    AuthenticatedTrustUpdateRequest, PendingTrustTransaction, TrustUpdateRequest,
    MAX_TRUST_UPDATE_OBJECTS,
};
use aether::certificates::{CertificateError, CERTIFICATE_PROTOCOL_VERSION};
use aether::key_negotiation::PqCertificate;
use zeroize::Zeroizing;

use crate::certificates::{TrustError, TrustStore};

/// How long one poll may take.
///
/// The route is inside WireGuard and answers from a registry read; ten seconds
/// is generous. It exists so a gateway that accepts the connection and then
/// says nothing cannot pin the caller for good.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest number of polls one collection may spend.
///
/// A transaction is bounded at [`MAX_TRUST_UPDATE_OBJECTS`] objects and each
/// poll returns at least one fragment, so a well-behaved gateway finishes well
/// inside this. The bound is here so a gateway that returns the same fragment
/// forever ends the collection instead of spinning.
pub const MAX_POLLS: usize = MAX_TRUST_UPDATE_OBJECTS + 8;

#[derive(Debug, thiserror::Error)]
pub enum TrustUpdateError {
    #[error("trust update transport: {0}")]
    Transport(String),
    #[error("the gateway answered {status}")]
    Status { status: u16 },
    #[error("the gateway's answer could not be read: {0}")]
    Malformed(String),
    #[error(
        "the gateway sent a fragment without the manifest that owns it; a fragment alone \
         authorizes nothing"
    )]
    ManifestMissing,
    #[error(
        "the manifest changed while its fragments were being collected: a transaction is one \
         decision, and two of them cannot be assembled into it"
    )]
    ManifestChanged,
    #[error(
        "this transaction was built for a local state this client has already left; a new \
         request under the current state is the way forward"
    )]
    BaseStateMoved,
    #[error(
        "the gateway never finished this transaction within {MAX_POLLS} polls; nothing has been \
         applied"
    )]
    NeverCompleted,
    #[error("certificate: {0}")]
    Certificate(#[from] CertificateError),
    #[error("trust store: {0}")]
    Store(#[from] TrustError),
}

/// What one round of polling concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustUpdateOutcome {
    /// The gateway holds nothing this client lacks.
    UpToDate,
    /// A complete transaction was verified and applied, object by object.
    Applied { objects: usize },
}

/// One collection, from the first poll to the applied transaction.
pub struct TrustUpdateSession {
    url: String,
    http: reqwest::Client,
    request: AuthenticatedTrustUpdateRequest,
}

impl TrustUpdateSession {
    /// Builds and signs the request from the store's own state.
    ///
    /// Every field is read from the store, including the opaque token. Nothing
    /// is passed in that the store already knows: a caller that could supply a
    /// counter could ask about a state this client is not in, and the answer
    /// would be a transaction it then refuses at commit — a full fragment
    /// cycle spent on a mistake nobody can see from here.
    pub fn prepare(
        store: &TrustStore,
        heliosd_url: &str,
        certificate: PqCertificate,
        active_pq_private_key: &Zeroizing<Vec<u8>>,
    ) -> Result<Self, TrustUpdateError> {
        let state = store.state();
        let mut request_id = [0u8; 16];
        aether::random::fill_public(&mut request_id)
            .map_err(|_| CertificateError::RandomnessUnavailable)?;

        let presented = aether::certificates::gateway::pq_certificate_fingerprint(&certificate)?;
        let request = TrustUpdateRequest {
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            request_id: Id16::new(request_id)?,
            trust_domain_id: state.trust_domain_id,
            gateway_wg_public_key: state.gateway.gateway_wg_public_key,
            client_wg_public_key: state.client_wg_public_key,
            ca_epoch: state.gateway.ca_epoch,
            ca_tls_epoch: state.client_tls_ca.ca_tls_epoch,
            astra_service_key_epoch: state.astra.astra_service_key_epoch,
            issuer_epoch: state.issuer_epoch,
            active_gateway_identity_epoch: state.gateway.active_gateway_identity_epoch,
            gateway_decision_epoch: state.gateway.gateway_decision_epoch,
            client_identity_generation: state.certificates.active.generation,
            active_gateway_tls_certificate_fingerprint: state.gateway.active_tls_fingerprint(),
            active_gateway_certificate_fingerprint: state.gateway.active_pq_fingerprint()?,
            active_client_tls_certificate_fingerprint: state
                .certificates
                .active
                .tls_certificate_fingerprint,
            active_client_pq_certificate_fingerprint: state
                .certificates
                .active
                .pq_certificate_fingerprint,
            client_pq_certificate_fingerprint: presented,
            // The compare-and-swap token of §0.6, over the complete store.
            base_state_fingerprint: store.base_state_fingerprint()?,
        };

        Ok(Self {
            url: format!(
                "{}/api/key-negotiation/trust-update",
                heliosd_url.trim_end_matches('/')
            ),
            http: reqwest::Client::builder()
                .timeout(CALL_TIMEOUT)
                // The route is inside WireGuard. A system proxy would send a
                // signed request away from the gateway the profile names.
                .no_proxy()
                // And this route never redirects: following one would hand the
                // signed request to whatever host a compromised gateway chose.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| TrustUpdateError::Transport(error.to_string()))?,
            request: request.authenticate(certificate, active_pq_private_key)?,
        })
    }

    /// The token this collection is bound to, for logs.
    pub fn base_state_fingerprint(&self) -> Fingerprint {
        self.request.request.base_state_fingerprint
    }

    /// Polls until the transaction is whole, then applies it in one write.
    ///
    /// Nothing is written before the last fragment lands: `store.apply` is
    /// reached once, with the complete ordered object list, and it verifies
    /// each object under the anchors this client already holds — the manifest
    /// authorizes attribution and ordering, never a trust mutation.
    pub async fn run(
        &self,
        store: &mut TrustStore,
        now_unix: u64,
    ) -> Result<TrustUpdateOutcome, TrustUpdateError> {
        let mut collection = Collection::default();
        for _ in 0..MAX_POLLS {
            let answer = self.poll().await?;
            match collection.accept(answer, &store.base_state_fingerprint()?)? {
                Step::Poll => continue,
                Step::Done(outcome) => return Ok(outcome),
                Step::Apply { manifest, chunks } => {
                    let objects =
                        store.verify_and_apply_transaction(&manifest, &chunks, now_unix)?;
                    return Ok(TrustUpdateOutcome::Applied { objects });
                }
            }
        }
        Err(TrustUpdateError::NeverCompleted)
    }

    async fn poll(&self) -> Result<TrustUpdateAnswer, TrustUpdateError> {
        let body = serde_json::to_vec(&self.request)
            .map_err(|error| TrustUpdateError::Malformed(error.to_string()))?;
        let response = self
            .http
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| TrustUpdateError::Transport(error.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(TrustUpdateError::Status {
                status: status.as_u16(),
            });
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|error| TrustUpdateError::Transport(error.to_string()))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| TrustUpdateError::Malformed(error.to_string()))
    }
}

/// What one answer means for a collection in progress.
enum Step {
    /// Ask again: the transaction is real but not yet whole.
    Poll,
    /// Nothing more will come.
    Done(TrustUpdateOutcome),
    /// Every fragment is in. Apply, once, against the live store.
    ///
    /// Boxed: a manifest is the largest thing this enum carries by a wide
    /// margin, and every `Poll` in the collection loop would otherwise pay for
    /// it.
    Apply {
        manifest: Box<aether::certificates::transport::TrustUpdateTransactionManifest>,
        chunks: Vec<aether::certificates::transport::TrustUpdateChunk>,
    },
}

/// The collection state one session carries between polls.
///
/// Split out from the transport so what an answer *means* can be decided —
/// and tested — without a gateway on the other end. Every refusal below is a
/// property of the exchange, not of the network: a fragment without its
/// manifest, a manifest that changes mid-collection, a transaction computed
/// against a store this client has already left.
#[derive(Default)]
struct Collection {
    pending: Option<PendingTrustTransaction>,
    collected: Vec<aether::certificates::transport::TrustUpdateChunk>,
}

impl Collection {
    fn accept(
        &mut self,
        answer: TrustUpdateAnswer,
        base_state_fingerprint: &Fingerprint,
    ) -> Result<Step, TrustUpdateError> {
        let Some(chunk) = answer.chunk else {
            // No fragment. Either nothing is owed, or the gateway sent a
            // manifest alone — which authorizes nothing and is not a state
            // this collection can advance from.
            return match (answer.manifest, &self.pending) {
                (None, None) => Ok(Step::Done(TrustUpdateOutcome::UpToDate)),
                _ => Err(TrustUpdateError::ManifestMissing),
            };
        };
        let manifest = answer.manifest.ok_or(TrustUpdateError::ManifestMissing)?;

        let accumulator = match self.pending {
            None => {
                // One cheap check before spending a whole fragment cycle:
                // the token this transaction was built for against the one
                // this store is in. Everything else — the signature, the
                // authority, the window, the target — is checked by
                // `verify_and_apply_transaction`, at the only instant that
                // matters, and is deliberately not duplicated here.
                if !manifest
                    .base_state_fingerprint
                    .matches(base_state_fingerprint)
                {
                    return Err(TrustUpdateError::BaseStateMoved);
                }
                self.pending = Some(PendingTrustTransaction::new(manifest));
                self.pending.as_mut().expect("just set")
            }
            Some(ref mut accumulator) => {
                // A manifest comes back with every fragment. A different
                // one mid-collection is a second decision, and two of them
                // cannot be assembled into one.
                if !accumulator
                    .manifest_fingerprint()
                    .matches(&manifest.fingerprint())
                {
                    return Err(TrustUpdateError::ManifestChanged);
                }
                accumulator
            }
        };
        accumulator.accept(&chunk)?;
        self.collected.push(chunk);
        if accumulator.is_complete() {
            return Ok(Step::Apply {
                manifest: Box::new(accumulator.manifest().clone()),
                chunks: std::mem::take(&mut self.collected),
            });
        }
        Ok(Step::Poll)
    }
}

/// The gateway's answer, exactly as `helios-api` renders it.
///
/// Redeclared here rather than imported: `orion-core` does not depend on the
/// gateway's crate, and a client that could only be built against the server's
/// own types would be a client that cannot be tested without one.
#[derive(Debug, Clone, Default, serde::Deserialize)]
struct TrustUpdateAnswer {
    #[serde(default)]
    manifest: Option<aether::certificates::transport::TrustUpdateTransactionManifest>,
    #[serde(default)]
    chunk: Option<aether::certificates::transport::TrustUpdateChunk>,
}

/// Asks the gateway once whether this profile is behind, and catches it up.
///
/// # Why this opens the identity store itself
///
/// The request is signed by the **active** PQ leaf, and every counter in it is
/// read from the store. A caller that assembled those parts would be a second
/// place where «what this client currently holds» is decided, and the two
/// would drift silently — the symptom being a transaction refused at commit,
/// after a whole fragment cycle, for a state mismatch nobody can see from the
/// screen that triggered it.
///
/// Anything already due is promoted first, for the same reason
/// [`crate::certificate_renewal::begin`] does it: a request computed against a
/// state that has not caught up describes a generation this client is leaving.
///
/// It is safe to call on every connection. `UpToDate` is the ordinary answer
/// and costs one round trip inside the tunnel.
pub async fn refresh(
    settings: &crate::KeyNegotiationSettings,
    heliosd_url: &str,
    now_unix: u64,
) -> Result<TrustUpdateOutcome, TrustUpdateError> {
    use crate::certificate_renewal::{client_pq_leaf, open_identity_store, promote_due};
    use crate::identity_store::ProtectedIdentityStore;
    use std::path::Path;

    let identity = settings.identity.trim();
    if identity.is_empty() {
        return Err(TrustUpdateError::Transport(
            "ce profil ne nomme aucune identité protégée".into(),
        ));
    }
    let identities = ProtectedIdentityStore::for_current_user()
        .map_err(|error| TrustUpdateError::Transport(error.to_string()))?;
    let bundle = identities
        .load(identity)
        .map_err(|error| TrustUpdateError::Transport(error.to_string()))?;

    let config = crate::config::ClientConfig::path()
        .map_err(|error| TrustUpdateError::Transport(error.to_string()))?;
    let mut store = open_identity_store(
        config.parent().unwrap_or_else(|| Path::new(".")),
        settings,
        &bundle,
        now_unix,
    )
    .map_err(|error| TrustUpdateError::Transport(error.to_string()))?;
    promote_due(&mut store, &identities, identity, now_unix)
        .map_err(|error| TrustUpdateError::Transport(error.to_string()))?;

    let certificate =
        client_pq_leaf(&bundle).map_err(|error| TrustUpdateError::Transport(error.to_string()))?;
    let private_key = Zeroizing::new(
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            bundle.pq_private_key.trim(),
        )
        .map_err(|_| {
            TrustUpdateError::Transport("clé privée PQ cliente : base64 illisible".into())
        })?,
    );

    let session = TrustUpdateSession::prepare(&store, heliosd_url, certificate, &private_key)?;
    session.run(&mut store, now_unix).await
}

#[cfg(all(test, feature = "certificate-signing"))]
mod tests {
    use super::*;
    use aether::certificates::authority::CaTransition;
    use aether::certificates::encoding::{
        generate_ml_dsa_87_keypair, MlDsa87Signature, TrustDomainId, WireGuardKey,
    };
    use aether::certificates::transport::{
        ManifestAuthority, TrustUpdateChunk, TrustUpdateObject, TrustUpdateObjectRef,
        TrustUpdateTransactionManifest,
    };
    use aether::certificates::window::TransitionWindow;
    use aether::certificates::CERTIFICATE_FORMAT_VERSION;

    /// The token the fixture store is in. `Collection` compares against it and
    /// never computes it, which is what lets these tests run without a store.
    fn base() -> Fingerprint {
        Fingerprint::of(b"the state this client is in")
    }

    /// A cheap object to fill a transaction with. `Collection` verifies no
    /// signature — that is `verify_and_apply_transaction`, on the live store,
    /// at the only instant it means anything — so the halves here are
    /// placeholders on purpose.
    fn object(seed: u8) -> TrustUpdateObject {
        let (_, next) = generate_ml_dsa_87_keypair().expect("keygen");
        TrustUpdateObject::CaTransition(Box::new(CaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([5; 16]).expect("domain"),
            current_ca_epoch: u64::from(seed),
            next_ca_epoch: u64::from(seed) + 1,
            current_ca_fingerprint: Fingerprint::of(&[seed]),
            next_ca_fingerprint: next.authority_fingerprint(),
            next_ca_public_key: next,
            window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
        }))
    }

    fn manifest(
        objects: &[TrustUpdateObject],
        chunk_count: u16,
        base_state_fingerprint: Fingerprint,
    ) -> TrustUpdateTransactionManifest {
        TrustUpdateTransactionManifest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            protocol_version: CERTIFICATE_PROTOCOL_VERSION,
            transaction_id: Id16::new([6; 16]).expect("id"),
            trust_domain_id: TrustDomainId::new([5; 16]).expect("domain"),
            gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
            client_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            base_state_fingerprint,
            created_at: 1_000,
            expires_at: 5_000,
            minimum_activation_at: 9_000,
            chunk_count,
            objects: objects
                .iter()
                .map(|object| TrustUpdateObjectRef {
                    apply_order: object.apply_order(),
                    object_fingerprint: object.fingerprint().expect("fingerprint"),
                    prerequisite_bitmap: 0,
                })
                .collect(),
            manifest_authority_kind: ManifestAuthority::AstraServiceKey,
            manifest_authority_epoch: 1,
            signature: MlDsa87Signature::placeholder(),
        }
    }

    fn chunk(
        manifest: &TrustUpdateTransactionManifest,
        index: u16,
        first_object_index: u16,
        objects: Vec<TrustUpdateObject>,
    ) -> TrustUpdateChunk {
        TrustUpdateChunk {
            manifest_fingerprint: manifest.fingerprint(),
            chunk_index: index,
            chunk_count: manifest.chunk_count,
            first_object_index,
            objects,
        }
    }

    fn answer(
        manifest: Option<&TrustUpdateTransactionManifest>,
        chunk: Option<TrustUpdateChunk>,
    ) -> TrustUpdateAnswer {
        TrustUpdateAnswer {
            manifest: manifest.cloned(),
            chunk,
        }
    }

    /// The ordinary answer, and the one that must cost nothing: the gateway
    /// holds nothing this client lacks.
    #[test]
    fn an_empty_answer_is_up_to_date_and_writes_nothing() {
        let mut collection = Collection::default();
        assert!(matches!(
            collection
                .accept(TrustUpdateAnswer::default(), &base())
                .expect("an empty answer is legal"),
            Step::Done(TrustUpdateOutcome::UpToDate)
        ));
        assert!(collection.pending.is_none());
        assert!(collection.collected.is_empty());
    }

    /// A manifest alone authorizes nothing. Accepting it would leave the
    /// collection holding a decision it can neither complete nor discard, and
    /// the next fragment would look like the second of a transaction whose
    /// first was never sent.
    #[test]
    fn a_manifest_without_a_fragment_is_refused() {
        let objects = vec![object(1)];
        let manifest = manifest(&objects, 1, base());
        let mut collection = Collection::default();
        assert!(matches!(
            collection.accept(answer(Some(&manifest), None), &base()),
            Err(TrustUpdateError::ManifestMissing)
        ));
        assert!(collection.pending.is_none());
    }

    /// And a fragment without its manifest is refused for the mirror reason:
    /// nothing attributes it, orders it, or says how many more there are.
    #[test]
    fn a_fragment_without_its_manifest_is_refused() {
        let objects = vec![object(1)];
        let manifest = manifest(&objects, 1, base());
        let orphan = chunk(&manifest, 0, 0, objects);
        let mut collection = Collection::default();
        assert!(matches!(
            collection.accept(answer(None, Some(orphan)), &base()),
            Err(TrustUpdateError::ManifestMissing)
        ));
    }

    /// The compare-and-swap token of §0.6, checked before a fragment cycle is
    /// spent: a transaction computed against a state this client has already
    /// left describes a domain it is no longer in.
    #[test]
    fn a_transaction_built_for_another_local_state_is_refused_at_once() {
        let objects = vec![object(1)];
        let manifest = manifest(
            &objects,
            1,
            Fingerprint::of(b"a state this client has left"),
        );
        let fragment = chunk(&manifest, 0, 0, objects);
        let mut collection = Collection::default();
        assert!(matches!(
            collection.accept(answer(Some(&manifest), Some(fragment)), &base()),
            Err(TrustUpdateError::BaseStateMoved)
        ));
        assert!(collection.pending.is_none());
    }

    /// A transaction is one decision. A manifest that changes mid-collection
    /// is a second one, and two of them cannot be assembled into it.
    #[test]
    fn a_manifest_that_changes_mid_collection_is_a_conflict() {
        let objects = vec![object(1), object(2)];
        let first = manifest(&objects, 2, base());
        let mut collection = Collection::default();
        assert!(matches!(
            collection
                .accept(
                    answer(
                        Some(&first),
                        Some(chunk(&first, 0, 0, vec![objects[0].clone()]))
                    ),
                    &base(),
                )
                .expect("the first fragment lands"),
            Step::Poll
        ));

        // Same base state, same client, different transaction.
        let mut second = manifest(&objects, 2, base());
        second.transaction_id = Id16::new([7; 16]).expect("id");
        assert!(matches!(
            collection.accept(
                answer(
                    Some(&second),
                    Some(chunk(&second, 1, 1, vec![objects[1].clone()])),
                ),
                &base(),
            ),
            Err(TrustUpdateError::ManifestChanged)
        ));
    }

    /// Nothing is handed to the store until the last fragment lands, and what
    /// is handed over is the whole ordered list — never a partial one.
    #[test]
    fn nothing_is_applied_before_the_last_fragment() {
        let objects = vec![object(1), object(2)];
        let manifest = manifest(&objects, 2, base());
        let mut collection = Collection::default();

        assert!(matches!(
            collection
                .accept(
                    answer(
                        Some(&manifest),
                        Some(chunk(&manifest, 0, 0, vec![objects[0].clone()])),
                    ),
                    &base(),
                )
                .expect("first fragment"),
            Step::Poll
        ));

        let step = collection
            .accept(
                answer(
                    Some(&manifest),
                    Some(chunk(&manifest, 1, 1, vec![objects[1].clone()])),
                ),
                &base(),
            )
            .expect("second fragment");
        let Step::Apply {
            manifest: applied,
            chunks,
        } = step
        else {
            panic!("a complete transaction is applied");
        };
        assert!(applied.fingerprint().matches(&manifest.fingerprint()));
        assert_eq!(chunks.len(), 2);
        // Taken, not copied: a second completion cannot replay the same
        // fragments into a second write.
        assert!(collection.collected.is_empty());
    }

    /// A gateway that returns the same fragment forever ends the collection
    /// rather than spinning: `MAX_POLLS` bounds it, and an incomplete
    /// transaction applies nothing.
    #[test]
    fn a_repeated_fragment_never_completes_the_transaction() {
        let objects = vec![object(1), object(2)];
        let manifest = manifest(&objects, 2, base());
        let mut collection = Collection::default();
        for _ in 0..MAX_POLLS {
            let step = collection
                .accept(
                    answer(
                        Some(&manifest),
                        Some(chunk(&manifest, 0, 0, vec![objects[0].clone()])),
                    ),
                    &base(),
                )
                .expect("an identical fragment is idempotent, not a conflict");
            assert!(matches!(step, Step::Poll));
        }
        // The loop in `run` gives up here; nothing was ever handed to the store.
        assert!(collection
            .pending
            .as_ref()
            .is_some_and(|pending| !pending.is_complete()));
    }

    /// Every object slot filled is not the same as every fragment received:
    /// the chunk count is part of the signed manifest, so a transaction
    /// completed on one fragment is one the sender never emitted.
    #[test]
    fn one_fragment_covering_every_object_does_not_complete_a_two_chunk_transaction() {
        let objects = vec![object(1), object(2)];
        let manifest = manifest(&objects, 2, base());
        let mut collection = Collection::default();
        let step = collection
            .accept(
                answer(
                    Some(&manifest),
                    Some(chunk(&manifest, 0, 0, objects.clone())),
                ),
                &base(),
            )
            .expect("a wide fragment is legal");
        assert!(matches!(step, Step::Poll));
    }
}
