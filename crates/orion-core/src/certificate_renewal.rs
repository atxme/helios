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
mod tests;
