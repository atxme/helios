//! Where this machine's trust store lives, and how it comes into being.
//!
//! Opening one, migrating the legacy machine-wide file into it, and seeding
//! an absent one from the profile's trust block and the sealed identity.

use std::path::{Path, PathBuf};

use aether::certificates::client::ClientCertificateGeneration;
use aether::certificates::encoding::{
    DerCertificate, Fingerprint, MlDsa87PublicKey, TrustDomainId, WireGuardKey,
};
use aether::certificates::gateway::pq_certificate_fingerprint;
use aether::certificates::state::{
    AstraProfile, ClientCertificateState, ClientTlsCaState, GatewayCertificateState, TrustLedger,
};
use base64::Engine as _;

use aether::key_negotiation::PqCertificate;

use crate::certificates::{TrustState, TrustStore};
use crate::config::TrustMaterial;
use crate::identity_store::ClientIdentityBundle;
use crate::KeyNegotiationSettings;

use super::RenewalError;

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

pub(super) fn identity_trust_store_path(
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

pub(super) fn client_tls_leaf(
    bundle: &ClientIdentityBundle,
) -> Result<DerCertificate, RenewalError> {
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
