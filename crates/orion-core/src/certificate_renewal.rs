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
//! 3. Astra verifies the due window and its narrow issuer delegation;
//! 4. Astra issues, Helios persists the candidate and signs its receipt, and
//!    Astra releases the grant — three steps this client only observes;
//! 5. **here** — verify the grant against what this store already trusts,
//!    persist the candidate, sign [`ClientCertificateStageCommit`], post it to
//!    `stage-commit`, and commit locally.
//!
//! No operator credential participates in this ordinary path. Recovery and
//! manual authority campaigns use their separate companion-backed flows.
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
use std::path::{Path, PathBuf};
use std::time::Duration;

use aether::certificates::client::ClientCertificateGeneration;
use aether::certificates::client::{
    ClientCertificateRotationGrant, ClientCertificateRotationRequest, ClientCertificateStageCommit,
    StageCommitRequest,
};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, Id16, MlDsa87PublicKey,
    MlDsa87Signature, TrustDomainId, WireGuardKey,
};
use aether::certificates::gateway::pq_certificate_fingerprint;
use aether::certificates::state::{
    AstraProfile, ClientCertificateState, ClientTlsCaState, GatewayCertificateState, TrustLedger,
};
use aether::certificates::transport::{
    ClientRenewalOperationState, ClientRenewalOperationView, ClientRenewalSignerRequest,
};
use aether::certificates::x509::{client_rotation_csr, ClientRotationCsr};
use aether::certificates::{
    CertificateError, CERTIFICATE_FORMAT_VERSION, CERTIFICATE_PROTOCOL_VERSION,
};
use base64::Engine as _;
use zeroize::Zeroizing;

use aether::key_negotiation::PqCertificate;

use crate::certificates::{TrustState, TrustStore};
use crate::config::TrustMaterial;
use crate::identity_store::{ClientIdentityBundle, ProtectedIdentityStore};
use crate::KeyNegotiationSettings;

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
    #[error(
        "la génération {generation} est déjà engagée et s'active le {activation_at} : rien à \
         renouveler tant qu'elle n'a pas pris la place de l'active"
    )]
    AlreadyCommitted {
        generation: u64,
        /// Rendered as a date: this string reaches the operator's screen.
        activation_at: String,
    },
    #[error(
        "la génération récupérée {generation} est commitée mais ne sera admise qu'à partir du \
         {activation_at}; réessayer la connexion après cette heure"
    )]
    ActivationPending {
        generation: u64,
        /// Rendered as a date: this string reaches the operator's screen.
        activation_at: String,
    },
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
    #[error(
        "l'autorité demande encore une approbation YubiKey pour un renouvellement ordinaire. \
         Mettre Astra à jour : la politique courante autorise automatiquement une identité \
         active à partir de 80 % de sa validité."
    )]
    ObsoleteOperatorApproval,
    #[error("the operation named {returned} instead of {expected}")]
    OperationMismatch { expected: String, returned: String },
    #[error(
        "l'autorité annonce un grant disponible et n'en joint aucun : l'opération est \
         inutilisable en l'état."
    )]
    GrantMissing,
    #[error("the local clock is before the Unix epoch")]
    Clock,
    #[error("approbation : {0}")]
    Approval(#[from] crate::certificate_approval::ApprovalError),
    #[error(
        "la fenêtre de capacité de cette opération est passée : elle vaut cinq minutes. Relancer \
         le renouvellement."
    )]
    CapabilityWindowClosed,
    #[error(
        "ce profil ne porte pas le matériel de confiance qu'un renouvellement exige — domaine, \
         autorité Astra épinglée et CA TLS cliente. Demander à l'opérateur un document réémis."
    )]
    TrustMaterialMissing,
    #[error(
        "le magasin de confiance de ce poste ({path}) décrit « {held} » et non « {expected} ». \
         Il n'est ni adopté ni remplacé : il porte des décisions — générations préparées, \
         révocations — qu'un écrasement perdrait en silence."
    )]
    ForeignTrustStore {
        path: String,
        held: String,
        expected: String,
    },
    #[error(
        "le certificat client actif a expiré (échéance {not_after}). Il ne peut plus signer la \
         preuve de continuité qu'une rotation exige : c'est la récupération du §7.5 qu'il faut, \
         pas un renouvellement."
    )]
    ActiveExpired { not_after: u64 },
    #[error(
        "le retour à l'identité précédente n'est disponible que pendant le chevauchement actif"
    )]
    RollbackUnavailable,
}

/// Where one identity's trust store lives, beside the profile file.
///
/// The state is indexed by both the trust domain and the client's WireGuard
/// public key. The first keeps two authorities apart; the second keeps the
/// client generations, pending candidate and revocation ledger apart inside
/// one domain. Profile names are deliberately absent: they are presentation
/// labels and may change without changing the admitted identity.
///
/// The key is hashed before entering the filename. Besides avoiding base64
/// separators, this leaves a fixed lowercase alphabet that cannot escape the
/// configuration directory.
pub fn trust_store_path(
    trust_domain_id: &TrustDomainId,
    client_wg_public_key: &WireGuardKey,
) -> Result<PathBuf, RenewalError> {
    let config = crate::config::ClientConfig::path()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    Ok(identity_trust_store_path(
        config.parent().unwrap_or_else(|| Path::new(".")),
        trust_domain_id,
        client_wg_public_key,
    ))
}

fn identity_trust_store_path(
    directory: &Path,
    trust_domain_id: &TrustDomainId,
    client_wg_public_key: &WireGuardKey,
) -> PathBuf {
    let key_fingerprint = Fingerprint::of(client_wg_public_key.as_bytes()).to_hex();
    directory.join(format!(
        "trust-{}-{key_fingerprint}.json",
        trust_domain_id.to_hex()
    ))
}

/// Opens the identity-scoped store and imports the legacy machine-wide store
/// when — and only when — it describes this exact identity.
///
/// Import is a copy, not a move. `trust.json` stays as a recoverable snapshot;
/// it is never overwritten by a second profile. A legacy store belonging to a
/// different domain or WireGuard key is likewise left untouched and cannot
/// prevent this identity from obtaining its own store.
pub(crate) fn open_identity_store(
    directory: &Path,
    settings: &KeyNegotiationSettings,
    bundle: &ClientIdentityBundle,
) -> Result<TrustStore, RenewalError> {
    let trust = settings
        .trust
        .as_ref()
        .ok_or(RenewalError::TrustMaterialMissing)?;
    let trust_domain_id = trust
        .trust_domain()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let client_wg_public_key = client_key_of(bundle)?;
    let path = identity_trust_store_path(directory, &trust_domain_id, &client_wg_public_key);

    if TrustStore::load(&path)?.is_some() {
        return open_or_seed(&path, settings, bundle);
    }

    let legacy_path = directory.join("trust.json");
    if let Some(legacy) = TrustStore::load(&legacy_path)? {
        let state = legacy.state();
        if state.trust_domain_id == trust_domain_id
            && state.client_wg_public_key == client_wg_public_key
        {
            let migrated = TrustStore::new(path, state.clone());
            migrated.save()?;
            return Ok(migrated);
        }
    }

    open_or_seed(&path, settings, bundle)
}

/// Opens the trust store, or seeds it from the profile and the sealed identity.
///
/// # Why seeding is legitimate here
///
/// Every field of the initial state is already pinned somewhere the operator
/// signed for: the trust domain, the anchors and the Astra profile come from
/// the `.orion` document's trust block, and the active generation's own
/// fingerprints come from the certificates in the protected store. Nothing is
/// invented, and nothing is fetched — a store seeded from the network would be
/// a store an attacker chooses.
///
/// # Why the file wins once it exists
///
/// The store is the record. It may hold a staged `next` generation, a
/// revocation the profile never heard of, or a counter that has moved; the
/// profile is a static document an operator emitted months earlier. Re-seeding
/// over it would silently drop exactly the decisions that matter most.
///
/// What is checked instead is that the two describe the **same** identity: a
/// store belonging to another client, or another domain, is refused rather
/// than adopted or replaced.
/// The path is passed in rather than resolved here: one process-wide location
/// is a fine default and a poor test seam, and a store that only ever exists
/// at an environment variable's mercy is one an operator cannot inspect.
pub fn open_or_seed(
    path: &Path,
    settings: &KeyNegotiationSettings,
    bundle: &ClientIdentityBundle,
) -> Result<TrustStore, RenewalError> {
    let trust = settings
        .trust
        .as_ref()
        .ok_or(RenewalError::TrustMaterialMissing)?;

    let trust_domain_id = trust
        .trust_domain()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let client_wg_public_key = client_key_of(bundle)?;

    if let Some(existing) = TrustStore::load(path)? {
        let state = existing.state();
        if state.trust_domain_id != trust_domain_id {
            return Err(RenewalError::ForeignTrustStore {
                path: path.display().to_string(),
                held: state.trust_domain_id.to_hex(),
                expected: trust_domain_id.to_hex(),
            });
        }
        if state.client_wg_public_key != client_wg_public_key {
            return Err(RenewalError::ForeignTrustStore {
                path: path.display().to_string(),
                held: state.client_wg_public_key.to_base64(),
                expected: client_wg_public_key.to_base64(),
            });
        }
        return Ok(existing);
    }

    let seeded = seed(settings, trust, bundle, client_wg_public_key)?;
    let store = TrustStore::new(path.to_path_buf(), seeded);
    store.save()?;
    Ok(store)
}

/// The client's own WireGuard key, derived from its PQ leaf.
///
/// Read off the certificate rather than off the profile's private key: the
/// certificate is what the gateway admitted, and a mismatch between the two is
/// a profile that will not connect at all — a failure the renewal has no
/// business discovering, and none of masking.
fn client_key_of(bundle: &ClientIdentityBundle) -> Result<WireGuardKey, RenewalError> {
    let leaf = client_pq_leaf(bundle)?;
    WireGuardKey::parse(&leaf.wireguard_public_key).map_err(RenewalError::Certificate)
}

pub(crate) fn client_pq_leaf(bundle: &ClientIdentityBundle) -> Result<PqCertificate, RenewalError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(bundle.pq_certificate.trim())
        .map_err(|_| RenewalError::Identity("certificat PQ client : base64 illisible".into()))?;
    serde_json::from_slice(&raw)
        .map_err(|_| RenewalError::Identity("certificat PQ client : JSON illisible".into()))
}

fn client_tls_leaf(bundle: &ClientIdentityBundle) -> Result<DerCertificate, RenewalError> {
    let leaf = bundle
        .certificate_chain
        .first()
        .ok_or_else(|| RenewalError::Identity("chaîne de certificats cliente vide".into()))?;
    let der = base64::engine::general_purpose::STANDARD
        .decode(leaf.trim())
        .map_err(|_| RenewalError::Identity("certificat TLS client : base64 illisible".into()))?;
    DerCertificate::new(der).map_err(RenewalError::Certificate)
}

fn seed(
    settings: &KeyNegotiationSettings,
    trust: &TrustMaterial,
    bundle: &ClientIdentityBundle,
    client_wg_public_key: WireGuardKey,
) -> Result<TrustState, RenewalError> {
    let gateway_leaf = settings
        .gateway_pq_certificate()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let gateway_wg_public_key = WireGuardKey::parse(&gateway_leaf.wireguard_public_key)
        .map_err(RenewalError::Certificate)?;
    let gateway_tls = base64::engine::general_purpose::STANDARD
        .decode(settings.gateway_ca_der.trim())
        .map_err(|_| RenewalError::Identity("CA TLS gateway : base64 illisible".into()))
        .and_then(|der| DerCertificate::new(der).map_err(RenewalError::Certificate))?;
    let client_tls_ca = trust
        .client_tls_ca()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let client_pq = client_pq_leaf(bundle)?;
    let client_tls = client_tls_leaf(bundle)?;

    let active = ClientCertificateGeneration {
        generation: trust.client_generation,
        ca_tls_epoch: trust.ca_tls_epoch,
        tls_ca_certificate_fingerprint: client_tls_ca.fingerprint(),
        tls_certificate_fingerprint: client_tls.fingerprint(),
        pq_certificate_fingerprint: pq_certificate_fingerprint(&client_pq)?,
        not_before: client_pq.not_before_unix,
        not_after: client_pq.not_after_unix,
    };
    // Une feuille hors de sa validité est décrite, pas refusée. Le magasin est
    // le compte rendu de ce que ce poste détient, et un poste resté éteint trop
    // longtemps détient une feuille expirée — c'est même la seule situation que
    // la récupération du §7.5 traite. Refuser ici la rendait inatteignable :
    // un profil importé après l'échéance n'a pas encore de magasin, la
    // récupération en demande un, et le semis lui répondait d'aller renouveler.
    //
    // Ce qu'une feuille expirée ne peut pas faire, c'est signer la preuve de
    // continuité d'une rotation. C'est donc le renouvellement qui le vérifie,
    // là où il peut encore le dire utilement.

    let mut state = TrustState {
        trust_domain_id: trust
            .trust_domain()
            .map_err(|error| RenewalError::Identity(error.to_string()))?,
        client_wg_public_key,
        gateway: GatewayCertificateState {
            trust_domain_id: trust
                .trust_domain()
                .map_err(|error| RenewalError::Identity(error.to_string()))?,
            gateway_wg_public_key,
            server_name: settings.server_name.trim().to_string(),
            ca_epoch: trust.ca_epoch,
            current_ca_public_key: trust
                .ca_pq()
                .map_err(|error| RenewalError::Identity(error.to_string()))?,
            next_ca_public_key: None,
            next_ca_transition_fingerprint: None,
            ca_activation_at: None,
            ca_retire_active_at: None,
            active_gateway_identity_epoch: 0,
            gateway_decision_epoch: 0,
            next_gateway_identity_epoch: None,
            next_transition_fingerprint: None,
            last_aborted_transition: None,
            active_gateway_tls_certificate: gateway_tls,
            next_gateway_tls_certificate: None,
            active_gateway_certificate: gateway_leaf,
            next_gateway_certificate: None,
            activation_at: None,
            retire_active_at: None,
            published: false,
            revoked: false,
            revocation_epoch: 0,
            service_rollback: None,
            awaited_replacement: None,
        },
        client_tls_ca: ClientTlsCaState {
            ca_tls_epoch: trust.ca_tls_epoch,
            active_client_tls_ca_certificate: client_tls_ca,
            next_client_tls_ca_certificate: None,
            next_transition_fingerprint: None,
            activation_at: None,
            retire_active_at: None,
        },
        astra: AstraProfile {
            authority_url: trust.astra_authority_url.trim().to_string(),
            webauthn_rp_id: trust.webauthn_rp_id.trim().to_string(),
            astra_policy_fingerprint: trust
                .astra_policy_pin()
                .map_err(|error| RenewalError::Identity(error.to_string()))?,
            // Le compteur part à zéro et les liaisons le font monter. Il ne
            // peut pas partir du plancher que le profil épingle : une liaison
            // porte l'époque de la décision qui l'a créée, donc une clé
            // enrôlée tôt en a une plus basse que le registre courant, et
            // `accept_credential_binding` la refuserait comme un retour en
            // arrière. Le plancher est rétabli juste après l'adoption.
            credential_registry_epoch: 0,
            credential_bindings: Default::default(),
            active_astra_service_public_key: MlDsa87PublicKey::parse(
                trust.astra_service_public_key.trim(),
            )
            .map_err(RenewalError::Certificate)?,
            next_astra_service_public_key: None,
            next_service_key_transition_fingerprint: None,
            astra_service_key_epoch: trust.astra_service_key_epoch,
            service_key_activation_at: None,
            service_key_retire_active_at: None,
            service_key_revocation_epoch: 0,
            last_emergency_replacement_fingerprint: None,
        },
        issuer_epoch: 0,
        issuer: None,
        certificates: ClientCertificateState::new(active),
        staged_gateway_transition: None,
        ledger: TrustLedger::default(),
    };

    // Les credentials opérateur du domaine, vérifiés sous l'ancre de ce profil
    // et sous rien d'autre. Le document qui les a transportés — le bloc
    // d'enrôlement — ne prouve rien par lui-même, et c'est voulu : chaque
    // liaison porte sa propre signature `CA-PQ`.
    //
    // Ils voyagent avec l'enrôlement plutôt que par une route, parce que le
    // seul moment où ce poste en a besoin est celui où il n'a plus de tunnel :
    // la récupération d'une identité expirée (§7.5) nomme le credential qui
    // l'approuvera, et un client qui aurait appris cette liste par le tunnel
    // qu'il vient de perdre n'aurait pas de liste du tout.
    let ca_pq = trust
        .ca_pq()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    for binding in &trust.astra_credential_bindings {
        binding
            .verify(
                &ca_pq,
                &state.trust_domain_id,
                &state.gateway.gateway_wg_public_key,
                trust.ca_epoch,
                0,
            )
            .map_err(RenewalError::Certificate)?;
        state
            .astra
            .accept_credential_binding(binding)
            .map_err(RenewalError::Certificate)?;
    }
    // Le plancher anti-retour du profil, rétabli. Les liaisons ont pu porter
    // l'époque à leur propre valeur, jamais au-dessous de celle que
    // l'opérateur a inscrite dans le bloc d'enrôlement.
    state.astra.credential_registry_epoch = state
        .astra
        .credential_registry_epoch
        .max(trust.credential_registry_epoch);

    Ok(state)
}

/// Name the candidate identity is sealed under until it activates.
///
/// A second entry rather than a replacement, and that is the whole point: the
/// active generation keeps connecting for the length of the overlap, and its
/// private keys have to stay exactly where the tunnel expects them. Sealing
/// the candidate over the top would break every handshake between the commit
/// and the activation the window schedules — an outage the renewal is
/// precisely supposed to avoid.
///
/// The suffix survives [`ProtectedIdentityStore`]'s name sanitising, which
/// keeps `-` and drops separators: it can never designate a file elsewhere.
pub fn candidate_identity_of(identity: &str) -> String {
    format!("{}-next", identity.trim())
}

/// Promotes a candidate whose activation instant has come.
///
/// Two things move together, and the order is what matters: the sealed keys
/// go into place **before** the state says the candidate is active. A crash
/// between the two leaves the store still naming the old generation, which
/// still has its keys — the renewal is retried, not lost. The reverse order
/// leaves a state pointing at a certificate whose private half is under
/// another name, and the tunnel fails at the next handshake.
///
/// Returns whether anything moved. Called from the same place that refreshes
/// the store, so a client that was offline across its own activation instant
/// catches up at the next launch rather than at the next renewal.
pub fn promote_due(
    store: &mut TrustStore,
    identities: &ProtectedIdentityStore,
    identity: &str,
    now_unix: u64,
) -> Result<bool, RenewalError> {
    let due_window = store
        .state()
        .certificates
        .next
        .as_ref()
        .zip(store.state().certificates.activation_at)
        .zip(store.state().certificates.retire_active_at)
        .map(|((_, activation_at), retire_at)| (activation_at, retire_at))
        .filter(|(activation_at, _)| now_unix >= *activation_at);
    let Some((activation_at, retire_at)) = due_window else {
        // Everything else the store promotes on its own schedule — anchors,
        // gateway identity, service key — has no local key material to move.
        let refreshed = store.refresh(now_unix)?;
        let retired = identities
            .retire_previous(identity, now_unix)
            .map_err(|error| RenewalError::Identity(error.to_string()))?;
        return Ok(refreshed || retired);
    };

    let candidate_identity = candidate_identity_of(identity);
    let candidate = identities
        .load(&candidate_identity)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let promoted = ClientIdentityBundle {
        identity: identity.trim().to_string(),
        ..candidate
    };
    let installed = identities
        .promote_with_previous(identity, &promoted, activation_at, retire_at)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let refreshed = store.refresh(now_unix)?;
    let retired = identities
        .retire_previous(identity, now_unix)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    Ok(installed || refreshed || retired)
}

/// Catches the protected service identity up before pre-WireGuard negotiation.
///
/// Trust updates and renewals already call [`promote_due`], but both normally
/// run through the tunnel. An expired recovery has no tunnel yet: if its
/// committed candidate becomes active while Orion is disconnected, waiting
/// for an in-tunnel call to promote the sealed identity is a cycle that can
/// never complete. The connection path calls this before loading its TLS/PQ
/// pair, so the first negotiation at or after `activation_at` presents the
/// generation the gateway now admits.
pub fn promote_local_identity_if_due(
    settings: &KeyNegotiationSettings,
    identities: &ProtectedIdentityStore,
    now_unix: u64,
) -> Result<bool, RenewalError> {
    if settings.trust.is_none() {
        return Ok(false);
    }
    let identity = settings.identity.trim();
    if identity.is_empty() {
        return Err(RenewalError::Identity(
            "ce profil ne nomme aucune identité protégée".into(),
        ));
    }
    let bundle = identities
        .load(identity)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let config = crate::config::ClientConfig::path()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let mut store = open_identity_store(
        config.parent().unwrap_or_else(|| Path::new(".")),
        settings,
        &bundle,
    )?;
    promote_due(&mut store, identities, identity, now_unix)
}

/// Promotes what is due and refuses an expired outgoing identity while the
/// recovered successor is still waiting for its signed activation instant.
pub(crate) fn prepare_identity_for_connection(
    settings: &KeyNegotiationSettings,
    identities: &ProtectedIdentityStore,
    now_unix: u64,
) -> Result<bool, RenewalError> {
    let promoted = promote_local_identity_if_due(settings, identities, now_unix)?;
    if settings.trust.is_none() {
        return Ok(promoted);
    }

    let identity = settings.identity.trim();
    let bundle = identities
        .load(identity)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let config = crate::config::ClientConfig::path()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let store = open_identity_store(
        config.parent().unwrap_or_else(|| Path::new(".")),
        settings,
        &bundle,
    )?;
    if now_unix >= store.state().certificates.active.not_after {
        if let Some((generation, activation_at)) =
            committed_and_waiting(&store.state().certificates, now_unix)
        {
            return Err(RenewalError::ActivationPending {
                generation,
                activation_at: horodatage(activation_at),
            });
        }
    }
    Ok(promoted)
}

/// Result of selecting the outgoing identity for service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientServiceRollback {
    pub selected_generation: u64,
    pub available_until: u64,
}

fn bundle_matches_generation(
    bundle: &ClientIdentityBundle,
    generation: &ClientCertificateGeneration,
) -> Result<(), RenewalError> {
    let tls = client_tls_leaf(bundle)?;
    let pq = client_pq_leaf(bundle)?;
    if !generation
        .tls_certificate_fingerprint
        .matches(&tls.fingerprint())
    {
        return Err(RenewalError::Certificate(
            CertificateError::FingerprintMismatch("client TLS identity"),
        ));
    }
    if !generation
        .pq_certificate_fingerprint
        .matches(&pq_certificate_fingerprint(&pq)?)
    {
        return Err(RenewalError::Certificate(
            CertificateError::FingerprintMismatch("client PQ identity"),
        ));
    }
    Ok(())
}

fn rollback_window(
    state: &TrustState,
    now_unix: u64,
) -> Result<
    (
        ClientCertificateGeneration,
        ClientCertificateGeneration,
        u64,
    ),
    RenewalError,
> {
    let certificates = &state.certificates;
    let incoming = certificates
        .next
        .as_ref()
        .ok_or(RenewalError::RollbackUnavailable)?;
    let activation_at = certificates
        .activation_at
        .ok_or(RenewalError::RollbackUnavailable)?;
    let retire_at = certificates
        .retire_active_at
        .ok_or(RenewalError::RollbackUnavailable)?;
    if certificates.revoked || now_unix < activation_at || now_unix >= retire_at {
        return Err(RenewalError::RollbackUnavailable);
    }
    Ok((certificates.active.clone(), incoming.clone(), retire_at))
}

/// Selects the outgoing client identity during its overlap (§4.4).
///
/// This is deliberately a local service selection, not a signed trust-state
/// mutation. Both generations were already authorized by the operator-approved
/// grant and are accepted by the gateway during the overlap; a CA signature
/// cannot add authority to the client's possession of either private key. The
/// gateway case is different because a console user does not possess its
/// private keys, hence its separate `CA-PQ` rollback authorization.
///
/// The authoritative trust store is read and validated but never mutated. In
/// particular, no generation or revocation counter can move backwards, and a
/// restored protected file naming certificates outside active/next is refused
/// before the selector is written.
pub fn rollback_to_previous(
    settings: &KeyNegotiationSettings,
    now_unix: u64,
) -> Result<ClientServiceRollback, RenewalError> {
    let identity = settings.identity.trim();
    if identity.is_empty() {
        return Err(RenewalError::Identity(
            "ce profil ne nomme aucune identité protégée".into(),
        ));
    }
    let identities = ProtectedIdentityStore::for_current_user()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let snapshot = identities
        .snapshot_at(identity, now_unix)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let config = crate::config::ClientConfig::path()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let mut store = open_identity_store(
        config.parent().unwrap_or_else(|| Path::new(".")),
        settings,
        &snapshot.served,
    )?;
    promote_due(&mut store, &identities, identity, now_unix)?;

    let (outgoing, incoming, retire_at) = rollback_window(store.state(), now_unix)?;
    let selected_generation = outgoing.generation;

    identities
        .select_previous(identity, now_unix, |current, previous| {
            bundle_matches_generation(current, &incoming).map_err(anyhow::Error::from)?;
            bundle_matches_generation(previous, &outgoing).map_err(anyhow::Error::from)
        })
        .map_err(|error| RenewalError::Identity(error.to_string()))?;

    Ok(ClientServiceRollback {
        selected_generation,
        available_until: retire_at,
    })
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

    fn signer_request(&self, operation_id: &Id16) -> String {
        format!(
            "{}/api/key-negotiation/certificate-renewal/signer-requests/{}",
            self.base,
            operation_id.to_hex()
        )
    }

    fn signer_result(&self, operation_id: &Id16) -> String {
        format!(
            "{}/api/key-negotiation/certificate-renewal/signer-results/{}",
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
/// `AwaitingOperator` is retained only to decode the obsolete per-request
/// ceremony. Current Orion refuses that state and asks for an Astra upgrade;
/// scheduled renewal advances without a human or hardware credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalStep {
    /// An obsolete server is waiting for a per-request hardware credential.
    AwaitingOperator { operation_id: Id16 },
    /// The approval landed and the authority is issuing. Nothing to do but
    /// poll.
    Issuing { operation_id: Id16 },
    /// Committed locally and at the gateway. The candidate is the `next`
    /// generation and will activate at its window.
    Committed { generation: u64 },
}

/// The companion invocation this operation is waiting on (spec §12.2).
///
/// Built here rather than in the shell for one reason: the two arguments are
/// the *only* thing `astra-signer` needs, and both come from state this crate
/// owns. A screen that assembled the command itself would be a second place
/// where the route, the identifier and the gateway address have to agree.
///
/// Neither field is a secret. The operation identifier is public — it is what
/// the gateway prints in its own log — and the capability tokens the companion
/// will need are minted on the read it makes, never carried here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionInvocation {
    /// `astra-signer`, unqualified and fixed: installation chooses its location
    /// through `PATH`, while neither a profile field nor a network response can
    /// select another executable. A platform-specific absolute path would make
    /// development and packaged layouts disagree.
    pub program: &'static str,
    pub arguments: Vec<String>,
}

impl CompanionInvocation {
    /// One line, for a screen that shows a value the operator can copy.
    pub fn command_line(&self) -> String {
        std::iter::once(self.program.to_string())
            .chain(self.arguments.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ")
    }
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

impl ActiveIdentity {
    /// Reads both private halves out of a sealed bundle.
    ///
    /// Kept here rather than on the bundle: `identity_store` deals in base64
    /// documents, and turning one into signing material is a decision of the
    /// renewal — the same bundle is read elsewhere for entirely public facts.
    pub fn from_bundle(bundle: &ClientIdentityBundle) -> Result<Self, RenewalError> {
        let decode = |value: &str, label: &str| -> Result<Zeroizing<Vec<u8>>, RenewalError> {
            base64::engine::general_purpose::STANDARD
                .decode(value.trim())
                .map(Zeroizing::new)
                .map_err(|_| RenewalError::Identity(format!("{label} : base64 illisible")))
        };
        Ok(Self {
            pq_private_key: decode(&bundle.pq_private_key, "clé privée PQ cliente")?,
            tls_private_key_der: decode(&bundle.private_key, "clé privée TLS cliente")?,
        })
    }
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
    /// Capability tokens from the last read of the operation (spec §8.2).
    ///
    /// Minted per read and alive five minutes at most, so they are kept only
    /// until the ceremony that uses them. They confer nothing outside that
    /// operation, that manifest and that scope — which is why holding them in
    /// memory beside the session is exactly as much as they are worth.
    tokens: Option<CapabilityTokens>,
}

/// The two short-lived tokens one read of an operation hands over.
struct CapabilityTokens {
    read: String,
    submit: String,
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
                // Every renewal route is inside WireGuard. A system proxy
                // would send signed requests and capability tokens away from
                // the gateway named by the profile.
                .no_proxy()
                // A renewal route never redirects. Following one would send a
                // signed request, and the tokens in the answer, to whatever
                // host a compromised gateway named.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| RenewalError::Transport(error.to_string()))?,
            keys,
            request,
            operation_id: None,
            tokens: None,
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

    /// What to launch so an operator can approve this renewal.
    ///
    /// `None` until an operation exists: there is nothing to approve before
    /// the authority has opened one, and offering the command earlier would
    /// have the companion fail on an identifier that names nothing.
    ///
    /// The companion runs **on this machine**, because the routes it will call
    /// authenticate the peer by its WireGuard source address. That is also why
    /// it needs no credential of its own here — the tunnel is the credential.
    pub fn companion_invocation(&self) -> Option<CompanionInvocation> {
        let operation_id = self.operation_id?;
        Some(CompanionInvocation {
            program: "astra-signer",
            arguments: vec![
                "approve".into(),
                "--heliosd-url".into(),
                self.routes.base.clone(),
                "--operation-id".into(),
                operation_id.to_hex(),
            ],
        })
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

    /// Fetches the approval request this operation is waiting on (step 4a).
    ///
    /// Verified before it is returned, against what this profile pins: an
    /// operator must not be shown a generation or a peer that nothing vouches
    /// for, and a ceremony spent to reach a refusal is the one cost that
    /// cannot be retried casually.
    ///
    /// The tokens come from the last read of the operation, so the caller polls
    /// first. That is not an ordering quirk: they live five minutes, and taking
    /// them any earlier would spend the window on the user finding their key.
    pub async fn fetch_approval(
        &mut self,
        store: &TrustStore,
        now_unix: u64,
    ) -> Result<crate::certificate_approval::VerifiedApproval, RenewalError> {
        let operation_id = self
            .operation_id
            .ok_or_else(|| RenewalError::Malformed("no operation to approve".into()))?;
        let token = self
            .tokens
            .as_ref()
            .ok_or(RenewalError::CapabilityWindowClosed)?
            .read
            .clone();
        let served: ClientRenewalSignerRequest = self
            .get_with_token(&self.routes.signer_request(&operation_id), Some(&token))
            .await?;
        crate::certificate_approval::VerifiedApproval::verify(served, store.state(), now_unix)
            .map_err(RenewalError::Approval)
    }

    /// Posts the assertion the ceremony produced (step 4b).
    ///
    /// The answer is the operation Astra reached with it, so a caller that
    /// submits does not have to poll again to learn whether it landed.
    pub async fn submit_approval(
        &mut self,
        approval: &aether::certificates::approval::AstraRenewalApproval,
    ) -> Result<RenewalStep, RenewalError> {
        let operation_id = self
            .operation_id
            .ok_or_else(|| RenewalError::Malformed("no operation to approve".into()))?;
        let token = self
            .tokens
            .as_ref()
            .ok_or(RenewalError::CapabilityWindowClosed)?
            .submit
            .clone();
        let body = serde_json::to_vec(approval)
            .map_err(|error| RenewalError::Malformed(error.to_string()))?;
        let view = self
            .post_with_token(&self.routes.signer_result(&operation_id), body, &token)
            .await?;
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
        identities: &ProtectedIdentityStore,
        identity: &str,
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
                Err(RenewalError::ObsoleteOperatorApproval)
            }
            ClientRenewalOperationState::PendingGrant => Ok(RenewalStep::Issuing { operation_id }),
            ClientRenewalOperationState::Failed => Err(RenewalError::OperationFailed),
            ClientRenewalOperationState::PendingCommit => {
                let grant = view.grant.ok_or(RenewalError::GrantMissing)?;
                self.commit(store, identities, identity, active, *grant, now_unix)
                    .await
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
    #[allow(clippy::too_many_arguments)]
    async fn commit(
        &mut self,
        store: &mut TrustStore,
        identities: &ProtectedIdentityStore,
        identity: &str,
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

        // The private keys are sealed **first**, under the candidate's own
        // name. They exist only in this process's memory until now, and the
        // slot is about to name a certificate they belong to: committing
        // before sealing would leave a `next` generation whose private half a
        // crash had just lost, with no way to notice until activation.
        let candidate_identity = candidate_identity_of(identity);
        let bundle = self.candidate_bundle(&candidate_identity, &grant)?;
        identities
            .store(&bundle)
            .map_err(|error| RenewalError::Identity(error.to_string()))?;

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

        // The grant travels with the commit. The gateway needs both — the
        // signatures say who is committing, the grant says the authority
        // released anything at all — and it refuses a bare commit outright.
        let body = serde_json::to_vec(&StageCommitRequest {
            commit: commit.clone(),
            grant: grant.clone(),
        })
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
    ///
    /// # Why the chain can be two certificates
    ///
    /// A delegated renewal signs the leaf with the delegation's TLS
    /// intermediate, and the gateway's QUIC listener holds only the anchor:
    /// it builds the path from what the client presents. A chain of one would
    /// therefore be a leaf the gateway cannot attach to anything it trusts —
    /// and the handshake fails at the end of the overlap, on a machine whose
    /// only channel for saying so was the tunnel it can no longer open.
    ///
    /// The intermediate goes in when it is the one that **signed this leaf**,
    /// not merely when the grant carries a delegation. The grant's own
    /// verification has already checked the whole path
    /// (`ClientCertificateRotationGrant::verify`), so this is the same fact
    /// asked once more where the file is written, rather than a second
    /// opinion.
    pub fn candidate_bundle(
        &self,
        identity: &str,
        grant: &ClientCertificateRotationGrant,
    ) -> Result<ClientIdentityBundle, RenewalError> {
        let encode = base64::engine::general_purpose::STANDARD;
        let mut certificate_chain = vec![encode.encode(grant.next_tls_certificate.as_bytes())];
        if let Some(intermediate) = grant
            .issuer_authorization
            .as_ref()
            .map(|delegation| &delegation.tls_intermediate_certificate)
        {
            if aether::certificates::x509::assert_issued_by(
                &grant.next_tls_certificate,
                intermediate,
            )
            .is_ok()
            {
                certificate_chain.push(encode.encode(intermediate.as_bytes()));
            }
        }
        let bundle = ClientIdentityBundle {
            identity: identity.to_string(),
            certificate_chain,
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
        // Kept only while both are there: an operation that has stopped
        // minting one of them no longer accepts a result, and a half-set would
        // let a ceremony run for an assertion nowhere to put.
        self.tokens = match (view.signer_request_token, view.signer_result_token) {
            (Some(read), Some(submit)) => Some(CapabilityTokens { read, submit }),
            _ => None,
        };
        match view.state {
            ClientRenewalOperationState::AwaitingOperator => {
                Err(RenewalError::ObsoleteOperatorApproval)
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

    /// A read that carries a capability token, for a typed answer.
    async fn get_with_token<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        token: Option<&str>,
    ) -> Result<T, RenewalError> {
        let mut request = self.http.get(url);
        if let Some(token) = token {
            request = request.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = request
            .send()
            .await
            .map_err(|error| RenewalError::Transport(error.to_string()))?;
        Self::decode_typed(response).await
    }

    async fn post_with_token(
        &self,
        url: &str,
        body: Vec<u8>,
        token: &str,
    ) -> Result<ClientRenewalOperationView, RenewalError> {
        let response = self
            .http
            .post(url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| RenewalError::Transport(error.to_string()))?;
        Self::decode_typed(response).await
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
        Self::decode_typed(response).await
    }

    async fn decode_typed<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, RenewalError> {
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

/// One renewal, driven from a profile through the automatic ordinary path.
///
/// # Why the session is returned even on the first step
///
/// It holds the candidate private keys. Dropping it is what makes an
/// abandoned renewal leave nothing behind — and it is also why a caller that
/// wants to finish one has to keep it.
/// The generation this client has already committed and is waiting to activate.
///
/// `None` once the instant has passed: `promote_due` will have taken it, and a
/// renewal is legitimate again.
fn committed_and_waiting(
    certificates: &aether::certificates::state::ClientCertificateState,
    now_unix: u64,
) -> Option<(u64, u64)> {
    let next = certificates.next.as_ref()?;
    let activation_at = certificates.activation_at?;
    (now_unix < activation_at).then_some((next.generation, activation_at))
}

/// A Unix instant, as a date an operator can act on.
///
/// The raw seconds stay out of operator-facing text: an activation is
/// something someone compares to a calendar, and «1796659573» is not.
fn horodatage(seconds: u64) -> String {
    aether::display_time::format_paris_timestamp(seconds)
}

pub async fn begin(
    settings: &KeyNegotiationSettings,
    heliosd_url: &str,
    now_unix: u64,
) -> Result<(RenewalSession, TrustStore, RenewalStep), RenewalError> {
    let identity = settings.identity.trim();
    if identity.is_empty() {
        return Err(RenewalError::Identity(
            "ce profil ne nomme aucune identité protégée".into(),
        ));
    }
    let identities = ProtectedIdentityStore::for_current_user()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let bundle = identities
        .load(identity)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;

    let config = crate::config::ClientConfig::path()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let mut store = open_identity_store(
        config.parent().unwrap_or_else(|| Path::new(".")),
        settings,
        &bundle,
    )?;
    // Anything already due is applied before a new generation is asked for: a
    // renewal computed against a state that has not caught up would name the
    // generation it is replacing.
    promote_due(&mut store, &identities, identity, now_unix)?;

    // A candidate already committed is not a reason to ask again. The
    // authority would refuse — this peer already holds the generation it would
    // be asking for — and that refusal, surfaced to the operator ten seconds
    // after the success it followed, says the opposite of what happened.
    // Refusing here keeps the answer truthful and spends no network call.
    if let Some((generation, activation_at)) =
        committed_and_waiting(&store.state().certificates, now_unix)
    {
        return Err(RenewalError::AlreadyCommitted {
            generation,
            activation_at: horodatage(activation_at),
        });
    }

    assert_active_can_prove_continuity(store.state(), now_unix)?;

    let active = ActiveIdentity::from_bundle(&bundle)?;
    let mut session = RenewalSession::prepare(&store, identity, heliosd_url, now_unix)?;
    session.sign(&active)?;
    let mut step = session.open().await?;
    if matches!(step, RenewalStep::Issuing { .. }) {
        step = session
            .advance(&mut store, &identities, identity, &active, now_unix)
            .await?;
    }
    Ok((session, store, step))
}

/// Refuses a rotation whose active leaf can no longer prove continuity.
///
/// Called after `promote_due`, and that order is the point: a client holding a
/// staged generation whose activation has passed is not expired at all, and
/// checking before the promotion would refuse it for the state it just left.
///
/// The refusal names the recovery. Letting the authority answer instead would
/// produce a refusal that says nothing about which side is wrong — the local
/// clock, or the certificate.
fn assert_active_can_prove_continuity(
    state: &TrustState,
    now_unix: u64,
) -> Result<(), RenewalError> {
    let not_after = state.certificates.active.not_after;
    if now_unix >= not_after {
        return Err(RenewalError::ActiveExpired { not_after });
    }
    Ok(())
}

/// Takes one more step on a renewal already opened.
///
/// Idempotent by the operation: called while the operator is still absent it
/// reports [`RenewalStep::AwaitingOperator`] again and changes nothing.
pub async fn resume(
    session: &mut RenewalSession,
    store: &mut TrustStore,
    settings: &KeyNegotiationSettings,
    now_unix: u64,
) -> Result<RenewalStep, RenewalError> {
    let identity = settings.identity.trim();
    let identities = ProtectedIdentityStore::for_current_user()
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let bundle = identities
        .load(identity)
        .map_err(|error| RenewalError::Identity(error.to_string()))?;
    let active = ActiveIdentity::from_bundle(&bundle)?;
    session
        .advance(store, &identities, identity, &active, now_unix)
        .await
}

#[cfg(all(test, feature = "certificate-signing"))]
mod tests {
    use super::*;
    use crate::test_domain::*;

    /// The contradiction this guard exists to remove.
    ///
    /// A renewal committed at 18:26 was followed ten seconds later by two
    /// fresh requests, refused by the authority — which was right: the peer
    /// already held the generation it was asking for. The refusal then
    /// overwrote the success on the operator's screen, so a rotation that had
    /// worked read as one that had failed.
    #[test]
    fn a_committed_candidate_stops_a_second_renewal_until_it_activates() {
        fn generation(number: u64) -> aether::certificates::client::ClientCertificateGeneration {
            aether::certificates::client::ClientCertificateGeneration {
                generation: number,
                ca_tls_epoch: 1,
                tls_ca_certificate_fingerprint: Fingerprint::of(b"ca"),
                tls_certificate_fingerprint: Fingerprint::of(b"tls"),
                pq_certificate_fingerprint: Fingerprint::of(b"pq"),
                not_before: 0,
                not_after: 10_000,
            }
        }

        let mut certificates =
            aether::certificates::state::ClientCertificateState::new(generation(1));
        // Nothing committed: a renewal is the operator's to ask for.
        assert_eq!(committed_and_waiting(&certificates, 1_000), None);

        certificates.next = Some(generation(2));
        certificates.activation_at = Some(2_000);
        assert_eq!(
            committed_and_waiting(&certificates, 1_000),
            Some((2, 2_000))
        );

        // Once the instant passes, `promote_due` takes it and asking again is
        // legitimate. The guard must not outlive the wait it describes.
        assert_eq!(committed_and_waiting(&certificates, 2_000), None);

        certificates.active.not_after = 900;
        let (generation, activation_at) =
            committed_and_waiting(&certificates, 1_000).expect("recovery still waits");
        let refusal = RenewalError::ActivationPending {
            generation,
            activation_at: horodatage(activation_at),
        };
        assert!(refusal.to_string().contains("réessayer la connexion"));
    }
    use aether::certificates::authority::RotationReason;
    use aether::certificates::client::{GatewayCertificateStageReceipt, IssuerKind};
    use aether::certificates::encoding::{
        derive_ml_dsa_87_public_key, generate_ml_dsa_87_keypair, DerCertificate, WireGuardKey,
    };
    use aether::certificates::window::TransitionWindow;
    use aether::key_negotiation::{
        issue_pq_certificate, PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION,
    };
    use base64::engine::general_purpose::STANDARD;
    use rcgen::{
        CertificateParams, CertificateSigningRequestParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };

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
            renewal_authorization_fingerprint: approval,
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
            renewal_authorization_fingerprint: approval,
            renewal_approval: None,
            campaign_approval: None,
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
            // `AwaitingOperator` is no longer a state a scheduled renewal
            // reaches; the authority issues as soon as the request is due.
            state: ClientRenewalOperationState::PendingGrant,
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
            RenewalStep::Issuing { .. }
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

    /// A profile plus a sealed identity is enough to seed the bounded state.
    ///
    /// Nothing is fetched and nothing is invented: the anchors come from the
    /// document the operator signed for, and the active generation's own
    /// fingerprints come from the certificates in the protected store.
    #[test]
    fn a_profile_and_its_identity_seed_the_trust_store() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let settings = settings(&domain);
        let bundle = bundle(&domain);
        let path = directory.path().join("trust.json");

        let store = open_or_seed(&path, &settings, &bundle).expect("seeded");
        let state = store.state();
        assert_eq!(state.trust_domain_id, domain_id());
        assert_eq!(state.client_wg_public_key, client_key());
        assert_eq!(state.gateway.gateway_wg_public_key, gateway_key());
        assert_eq!(state.gateway.server_name, SERVER_NAME);
        assert_eq!(state.certificates.active.generation, 4);
        assert_eq!(
            state.certificates.active.pq_certificate_fingerprint,
            aether::certificates::gateway::pq_certificate_fingerprint(&domain.active_client_leaf)
                .expect("fingerprint"),
            "the active generation is the certificate the store actually holds"
        );
        assert_eq!(
            state.client_tls_ca.active_client_tls_ca_certificate,
            domain.tls_ca_der
        );
        assert!(path.exists(), "seeding writes, so a restart resumes");
    }

    /// Once the file exists it is the record: it may hold a staged generation
    /// or a revocation the static profile never heard of.
    #[test]
    fn an_existing_store_is_not_reseeded_from_the_profile() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let mut settings = settings(&domain);
        let bundle = bundle(&domain);
        let path = directory.path().join("trust.json");
        open_or_seed(&path, &settings, &bundle).expect("seeded");

        // The operator re-emits a document claiming a generation that has
        // already been superseded locally.
        settings.trust.as_mut().expect("trust").client_generation = 1;
        let store = open_or_seed(&path, &settings, &bundle).expect("reopened");
        assert_eq!(
            store.state().certificates.active.generation,
            4,
            "the store is the record, not the document"
        );
    }

    /// A machine can hold several Orion identities, including several peers
    /// admitted in the same trust domain. Their pending generations and
    /// revocation ledgers must never share a file.
    #[test]
    fn trust_store_paths_are_scoped_by_domain_and_client_key() {
        let directory = tempfile::tempdir().expect("temp dir");
        let first = identity_trust_store_path(directory.path(), &domain_id(), &client_key());
        let second = identity_trust_store_path(
            directory.path(),
            &domain_id(),
            &WireGuardKey::from_bytes([3; 32]),
        );

        assert_ne!(first, second);
        let filename = first
            .file_name()
            .and_then(|name| name.to_str())
            .expect("UTF-8 filename");
        assert!(filename.starts_with(&format!("trust-{}-", domain_id().to_hex())));
        assert!(filename.ends_with(".json"));
        assert!(filename
            .trim_end_matches(".json")
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'));
    }

    /// Upgrade keeps every decision already recorded in the machine-wide
    /// store. It copies that state under the identity-scoped name and retains
    /// the old file as a recoverable snapshot.
    #[test]
    fn a_matching_legacy_store_is_copied_without_being_deleted() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let settings = settings(&domain);
        let bundle = bundle(&domain);
        let legacy_path = directory.path().join("trust.json");
        let legacy = store(directory.path(), &domain);
        legacy.save().expect("legacy saved");

        let migrated =
            open_identity_store(directory.path(), &settings, &bundle).expect("legacy imported");
        let scoped_path = identity_trust_store_path(directory.path(), &domain_id(), &client_key());

        assert!(
            legacy_path.exists(),
            "migration retains the legacy snapshot"
        );
        assert!(scoped_path.exists(), "migration writes the scoped store");
        assert_eq!(migrated.state(), legacy.state());
    }

    /// A legacy store for another peer is not an error and is not overwritten:
    /// the newly loaded profile receives an independent state file.
    #[test]
    fn another_clients_legacy_store_does_not_block_a_new_profile() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let settings = settings(&domain);
        let legacy = store(directory.path(), &domain);
        legacy.save().expect("legacy saved");
        let other_key = WireGuardKey::from_bytes([3; 32]);
        let other_bundle = bundle_for_client_key(&domain, other_key);

        let opened = open_identity_store(directory.path(), &settings, &other_bundle)
            .expect("independent store seeded");
        let scoped_path = identity_trust_store_path(directory.path(), &domain_id(), &other_key);

        assert_eq!(opened.state().client_wg_public_key, other_key);
        assert!(scoped_path.exists());
        let preserved = TrustStore::load(&directory.path().join("trust.json"))
            .expect("legacy readable")
            .expect("legacy retained");
        assert_eq!(preserved.state().client_wg_public_key, client_key());
    }

    /// A store belonging to another domain is refused, never replaced: it
    /// carries decisions an overwrite would drop in silence.
    #[test]
    fn a_store_describing_another_domain_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let settings = settings(&domain);
        let bundle = bundle(&domain);
        let path = directory.path().join("trust.json");
        open_or_seed(&path, &settings, &bundle).expect("seeded");

        let mut stranger = settings.clone();
        stranger.trust.as_mut().expect("trust").trust_domain_id = "ab".repeat(16);
        assert!(matches!(
            open_or_seed(&path, &stranger, &bundle),
            Err(RenewalError::ForeignTrustStore { .. })
        ));
    }

    /// A store belonging to another admitted peer of the **same** domain is
    /// refused too. The domain check alone would let one machine's second
    /// profile adopt the first one's generations, and the renewal would then
    /// prove continuity for an identity it does not hold the key of.
    #[test]
    fn a_store_describing_another_client_key_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let settings = settings(&domain);
        let path = directory.path().join("trust.json");
        open_or_seed(&path, &settings, &bundle(&domain)).expect("seeded");

        let stranger = bundle_for_client_key(&domain, WireGuardKey::from_bytes([3; 32]));
        assert!(matches!(
            open_or_seed(&path, &settings, &stranger),
            Err(RenewalError::ForeignTrustStore { .. })
        ));
    }

    /// Conversion into a numbered generation is a triple correspondence
    /// (spec §14.1): the chain, the fingerprints and the local keys. Each of
    /// the three is read from the material the machine already holds — the
    /// sealed bundle and the operator's trust block — and never from the
    /// document alone, which is why they are asserted together here.
    #[test]
    fn the_seeded_generation_matches_the_chain_the_fingerprints_and_the_local_key() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let settings = settings(&domain);
        let bundle = bundle(&domain);
        let path = directory.path().join("trust.json");

        let store = open_or_seed(&path, &settings, &bundle).expect("seeded");
        let state = store.state();
        let active = &state.certificates.active;
        let trust = settings.trust.as_ref().expect("trust");

        // The chain: the leaf the bundle carries, not a fingerprint the
        // profile asserts about it.
        let chain_leaf = DerCertificate::new(
            STANDARD
                .decode(bundle.certificate_chain.first().expect("chain").trim())
                .expect("chain leaf base64"),
        )
        .expect("chain leaf der");
        assert_eq!(active.tls_certificate_fingerprint, chain_leaf.fingerprint());

        // The fingerprints: the anchor the operator pinned, and the PQ leaf
        // the protected store holds.
        assert_eq!(
            active.tls_ca_certificate_fingerprint,
            domain.tls_ca_der.fingerprint()
        );
        assert_eq!(
            active.pq_certificate_fingerprint,
            aether::certificates::gateway::pq_certificate_fingerprint(&domain.active_client_leaf)
                .expect("pq fingerprint")
        );
        assert_eq!(active.generation, trust.client_generation);
        assert_eq!(active.ca_tls_epoch, trust.ca_tls_epoch);
        assert_eq!(active.not_before, domain.active_client_leaf.not_before_unix);
        assert_eq!(active.not_after, domain.active_client_leaf.not_after_unix);

        // The local key: read off the certificate the gateway admitted, so a
        // profile naming another key cannot seed a state around it.
        assert_eq!(
            state.client_wg_public_key,
            WireGuardKey::parse(&domain.active_client_leaf.wireguard_public_key).expect("key")
        );
    }

    /// A COSE ES256 public key, as an authenticator publishes one.
    ///
    /// Built here rather than faked: the binding's own verification parses
    /// this field, so a placeholder would make the test pass on a shape the
    /// real exchange refuses.
    fn cose_es256_key() -> Vec<u8> {
        let mut key = vec![
            0xA5, // map(5)
            0x01, 0x02, // 1 (kty)  : 2   — EC2
            0x03, 0x26, // 3 (alg)  : -7  — ES256
            0x20, 0x01, // -1 (crv) : 1   — P-256
            0x21, 0x58, 0x20, // -2 (x) : bstr(32)
        ];
        key.extend_from_slice(&[3u8; 32]);
        key.extend_from_slice(&[0x22, 0x58, 0x20]); // -3 (y) : bstr(32)
        key.extend_from_slice(&[5u8; 32]);
        key
    }

    /// A binding the domain's `CA-PQ` signed, carried by the enrolment.
    fn signed_binding(
        domain: &Domain,
        credential_id: Vec<u8>,
    ) -> aether::certificates::approval::AstraCredentialBinding {
        aether::certificates::approval::AstraCredentialBinding {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            credential_id,
            credential_public_key: cose_es256_key(),
            aaguid: [0; 16],
            trust_domain_id: crate::test_domain::domain_id(),
            gateway_wg_public_key: crate::test_domain::gateway_key(),
            state: aether::certificates::approval::CredentialState::Active,
            credential_epoch: 1,
            credential_registry_epoch: 1,
            ca_epoch: 1,
            created_at: NOW,
            ca_pq_signature: aether::certificates::encoding::MlDsa87Signature::placeholder(),
        }
        .sign(&domain.ca_pq_private)
        .expect("signed under CA-PQ")
    }

    /// Recovering an expired identity begins by naming the credential that
    /// will approve it, and a client with no tunnel cannot go and ask. The
    /// enrolment therefore carries the list, and the seed adopts it.
    #[test]
    fn the_operator_credentials_travel_with_the_enrolment() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let mut settings = settings(&domain);
        settings
            .trust
            .as_mut()
            .expect("trust")
            .astra_credential_bindings = vec![signed_binding(&domain, vec![0xAB, 0xCD])];
        let bundle = bundle(&domain);
        let path = directory.path().join("trust.json");
        let store = open_or_seed(&path, &settings, &bundle).expect("seeded");
        let bindings = &store.state().astra.credential_bindings;
        assert_eq!(bindings.len(), 1, "the credential the enrolment carried");
        assert!(
            bindings
                .values()
                .any(|binding| binding.state
                    == aether::certificates::approval::CredentialState::Active),
            "an active row is what a recovery may name"
        );
    }

    /// The document that carried the bindings proves nothing by itself: each
    /// one is verified under the anchor of this profile, and a row signed by
    /// another authority is refused rather than adopted.
    #[test]
    fn a_credential_binding_signed_by_another_anchor_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let stranger = crate::test_domain::domain();
        let mut settings = settings(&domain);
        settings
            .trust
            .as_mut()
            .expect("trust")
            .astra_credential_bindings = vec![signed_binding(&stranger, vec![0xAB, 0xCD])];
        let bundle = bundle(&domain);
        let path = directory.path().join("trust.json");
        assert!(
            open_or_seed(&path, &settings, &bundle).is_err(),
            "a row the domain never signed is not adopted"
        );
        assert!(!path.exists(), "a refused seed writes nothing");
    }

    /// A machine left off past its own expiry is exactly what §7.5 recovers,
    /// and it reaches that path through a store it does not have yet. Seeding
    /// therefore describes the expired leaf instead of refusing it — the
    /// refusal that used to live here made the recovery unreachable.
    #[test]
    fn an_expired_active_leaf_is_seeded_so_the_recovery_can_read_it() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let settings = settings(&domain);
        let bundle = bundle(&domain);
        let path = directory.path().join("trust.json");
        let expired_at = NOW + 20 * 86_400;
        let store = open_or_seed(&path, &settings, &bundle).expect("seeded");
        assert!(
            path.exists(),
            "the store the recovery opens must be written"
        );
        assert!(
            store.state().certificates.active.not_after <= expired_at,
            "the seeded state describes the expired leaf rather than hiding it"
        );
    }

    /// An expired leaf cannot sign the continuity proof a rotation needs, so
    /// the refusal names the recovery rather than letting the authority refuse
    /// without saying which side is wrong.
    #[test]
    fn an_expired_active_leaf_cannot_prove_continuity() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let settings = settings(&domain);
        let bundle = bundle(&domain);
        let path = directory.path().join("trust.json");
        let expired_at = NOW + 20 * 86_400;
        let store = open_or_seed(&path, &settings, &bundle).expect("seeded");
        assert!(matches!(
            assert_active_can_prove_continuity(store.state(), expired_at),
            Err(RenewalError::ActiveExpired { .. })
        ));
        assert!(
            assert_active_can_prove_continuity(store.state(), NOW).is_ok(),
            "a leaf still inside its validity proves continuity"
        );
    }

    /// A profile enrolled before §19 carries no trust block, and the refusal
    /// is that — not a store that could not be written.
    #[test]
    fn a_profile_without_trust_material_is_named() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let mut settings = settings(&domain);
        settings.trust = None;
        assert!(matches!(
            open_or_seed(
                &directory.path().join("trust.json"),
                &settings,
                &bundle(&domain)
            ),
            Err(RenewalError::TrustMaterialMissing)
        ));
    }

    /// The candidate is sealed beside the active identity, never over it: the
    /// active generation keeps connecting for the length of the overlap.
    #[test]
    fn the_candidate_is_sealed_under_a_name_of_its_own() {
        assert_eq!(candidate_identity_of("poste-windows"), "poste-windows-next");
        assert_ne!(candidate_identity_of("poste"), "poste");
    }

    #[test]
    fn service_rollback_reads_the_overlap_without_lowering_any_counter() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let mut state = store(directory.path(), &domain).state().clone();
        let mut incoming = state.certificates.active.clone();
        incoming.generation += 1;
        incoming.tls_certificate_fingerprint = Fingerprint::of(b"incoming TLS");
        incoming.pq_certificate_fingerprint = Fingerprint::of(b"incoming PQ");
        state.certificates.next = Some(incoming.clone());
        state.certificates.activation_at = Some(NOW + 100);
        state.certificates.retire_active_at = Some(NOW + 200);
        state.certificates.revocation_epoch = 7;
        let before = state.clone();

        let (outgoing, selected_incoming, retire_at) =
            rollback_window(&state, NOW + 150).expect("inside overlap");
        assert_eq!(outgoing.generation, 4);
        assert_eq!(selected_incoming, incoming);
        assert_eq!(retire_at, NOW + 200);
        assert_eq!(
            state, before,
            "service selection must not mutate trust state"
        );
        assert_eq!(state.certificates.revocation_epoch, 7);
        assert!(rollback_window(&state, NOW + 99).is_err());
        assert!(rollback_window(&state, NOW + 200).is_err());
    }

    /// An authority still asking for a credential is named as obsolete.
    ///
    /// The amendment of 6 September 2026 removed the per-request approval from
    /// the scheduled path, so `AwaitingOperator` can only come from an Astra
    /// that has not been migrated. The client says which of the two ends is
    /// behind rather than launching a companion for a ceremony that no longer
    /// exists — and the companion is never offered for it.
    #[test]
    fn an_authority_still_awaiting_an_operator_is_reported_as_obsolete() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let store = store(directory.path(), &domain);
        let mut session = session(&store, &domain);
        assert!(
            session.companion_invocation().is_none(),
            "nothing to approve before an operation exists"
        );

        let operation_id = Id16::new([6; 16]).expect("id");
        let adopted = session.adopt(ClientRenewalOperationView {
            operation_id,
            state: ClientRenewalOperationState::AwaitingOperator,
            client_wg_public_key: client_key(),
            request_fingerprint: session.request_fingerprint(),
            operation_manifest_fingerprint: Fingerprint::of(b"manifest"),
            created_at: NOW,
            expires_at: NOW + 300,
            signer_request_token: None,
            signer_result_token: None,
            grant: None,
        });

        assert!(matches!(
            adopted,
            Err(RenewalError::ObsoleteOperatorApproval)
        ));
        // Limite connue : `companion_invocation` reste offert dès qu'une
        // opération existe, alors que la cérémonie qu'il lancerait n'a plus de
        // rôle dans le chemin planifié. Le remède que nomme l'erreur est de
        // migrer l'autorité, pas d'approuver une demande à la main.
        assert!(session.companion_invocation().is_some());
    }

    /// The same grant, but issued by a delegation: an intermediate signed by
    /// `CA-TLS`, and a leaf signed by that intermediate.
    fn delegated_grant(
        domain: &Domain,
        session: &RenewalSession,
        window: TransitionWindow,
    ) -> (ClientCertificateRotationGrant, DerCertificate) {
        use aether::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};

        let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).expect("params");
        intermediate_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        intermediate_params.distinguished_name = name("astra delegated issuer 1");
        intermediate_params.not_before = seconds_since_epoch(window.not_before);
        intermediate_params.not_after = seconds_since_epoch(window.not_after + 172_800);
        let intermediate_key = KeyPair::generate().expect("intermediate key");
        let intermediate = intermediate_params
            .signed_by(&intermediate_key, &domain.tls_ca, &domain.tls_ca_key)
            .expect("intermediate");
        let intermediate_der = DerCertificate::new(intermediate.der().to_vec()).expect("der");

        let request = session.request();
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
        .signed_by(&intermediate, &intermediate_key)
        .expect("delegated leaf");

        let (_, issuer_public) = generate_ml_dsa_87_keypair().expect("issuer key");
        let mut grant = grant(domain, session, window);
        grant.issuer_kind = IssuerKind::Astra;
        grant.issuer_epoch = 1;
        grant.next_tls_certificate = DerCertificate::new(leaf.der().to_vec()).expect("der");
        grant.issuer_authorization = Some(AstraIssuerAuthorization {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain_id(),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            gateway_wg_public_key: gateway_key(),
            server_name: SERVER_NAME.into(),
            issuer_epoch: 1,
            pq_issuer_public_key: issuer_public,
            tls_intermediate_certificate: intermediate_der.clone(),
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 90 * 86_400,
            policy_fingerprint: Fingerprint::of(b"policy"),
            not_before: window.not_before,
            not_after: window.not_after + 172_800,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        });
        (grant, intermediate_der)
    }

    /// A delegated leaf is signed by the delegation's intermediate, and the
    /// gateway's listener holds only the anchor: it builds the path from what
    /// the client presents. A chain of one would be a leaf attached to nothing
    /// the gateway trusts — and the handshake fails at the end of the overlap,
    /// on the machine whose only channel for saying so was that tunnel.
    #[test]
    fn a_delegated_candidate_carries_the_intermediate_that_signed_it() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let store = store(directory.path(), &domain);
        let session = session(&store, &domain);
        let (grant, intermediate) = delegated_grant(&domain, &session, window());

        let bundle = session
            .candidate_bundle("poste-windows", &grant)
            .expect("bundle");

        assert_eq!(
            bundle.certificate_chain.len(),
            2,
            "the delegated chain is leaf then intermediate"
        );
        assert_eq!(
            STANDARD
                .decode(&bundle.certificate_chain[0])
                .expect("leaf der"),
            grant.next_tls_certificate.as_bytes(),
            "the leaf stays first: every reader takes index 0 as the identity"
        );
        assert_eq!(
            STANDARD
                .decode(&bundle.certificate_chain[1])
                .expect("intermediate der"),
            intermediate.as_bytes()
        );
    }

    /// Carrying a delegation is not the same as having been signed by it. A
    /// master-issued leaf chains to the anchor directly, and appending an
    /// intermediate that signed nothing would make the gateway reject a path
    /// it would otherwise have built.
    #[test]
    fn a_master_issued_candidate_carries_the_leaf_alone() {
        let directory = tempfile::tempdir().expect("temp dir");
        let domain = domain();
        let store = store(directory.path(), &domain);
        let session = session(&store, &domain);
        let (delegated, _) = delegated_grant(&domain, &session, window());
        let mut grant = grant(&domain, &session, window());
        // The delegation object, beside a leaf the master signed.
        grant.issuer_authorization = delegated.issuer_authorization;

        let bundle = session
            .candidate_bundle("poste-windows", &grant)
            .expect("bundle");

        assert_eq!(bundle.certificate_chain.len(), 1);
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
