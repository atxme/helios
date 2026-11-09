//! What a profile pins and what this machine holds, as facts a screen renders.
//!
//! # Why this is not the trust store
//!
//! [`crate::certificates::TrustStore`] is the *decision* half of the
//! certificate lifecycle: bounded slots, generations, transitions applied in
//! one write. It is populated from the profile's trust material and advanced
//! by the renewal driver; exposing that state directly would couple a display
//! to the transaction store and its private candidate lifecycle.
//!
//! This module is the *observation* half. Four
//! certificates already exist on any enrolled machine — the two the profile
//! pins for the gateway, and the two the protected store holds for this
//! client — and they answer what is pinned, until when, and when the renewal
//! window opens. Those answers are computed with the lifecycle's own
//! arithmetic (`ValidityPeriod` at 80 / 90 / 95 %), so the panel and the
//! protocol agree by construction rather than by resemblance.
//!
//! # Operator credentials
//!
//! The trust store retains the verified registry seeded from enrolment.
//! Inventory rechecks its signatures, domain and epoch against the local
//! anchors before projecting public fingerprints and credential states.
//! Profiles and older stores without a complete snapshot report the epoch
//! alone. No rendering operation fetches an authority or changes trust.
//!
//! # What a fault is, and what an absence is
//!
//! An empty slot is not an error: a profile with no negotiation block pins
//! nothing, and a machine with no protected store holds nothing. A slot that
//! is *present but unreadable* is a fault, and it is named — a certificate
//! that fails to parse is exactly the case where a silent dash would send the
//! user looking at the network.

use aether::certificates::window::ValidityPeriod;
use aether::certificates::{encoding::DerCertificate, x509};
use aether::key_negotiation::PqCertificate;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::identity_store::{PreviousIdentityStatus, ProtectedIdentityStore};
use crate::KeyNegotiationSettings;

/// Where a certificate stands on the renewal ladder of spec §4.3.
///
/// The ladder itself lives in [`aether::certificates::window`], with the
/// protocol's own thresholds. Orion keeps the name it has always exported —
/// the wire form is unchanged — but no longer keeps a second copy of the
/// comparisons: the Helios console reports the same rungs, and two surfaces
/// computing them apart is how one of them ends up a threshold behind.
pub use aether::certificates::window::ValidityPhase as CertificatePhase;

/// One certificate, as an interface needs to state it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateFacts {
    pub subject: String,
    pub issuer: String,
    /// SHA-256, lowercase hex. The value a user reads out to compare.
    pub fingerprint: String,
    pub not_before: u64,
    pub not_after: u64,
    /// Instant the renewal window opens — 80 % of the lifetime.
    pub renewal_at: u64,
    pub phase: CertificatePhase,
}

/// What this profile locally knows about the domain's operator credentials.
///
/// `EpochOnly` is a positive statement, not an empty list: the profile has
/// accepted a registry generation, but this client has never retained its
/// verified rows. Keeping that distinction in the value prevents a surface
/// from rendering “zero registered keys”, which would be false.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCredentialInventory {
    pub registry_epoch: u64,
    pub detail: OperatorCredentialDetail,
    #[serde(default)]
    pub credentials: Vec<OperatorCredentialFacts>,
}

/// Public facts only; credential IDs, COSE keys and assertions stay internal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCredentialFacts {
    pub fingerprint: String,
    pub state: aether::certificates::approval::CredentialState,
    pub credential_epoch: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorCredentialDetail {
    EpochOnly,
    Verified,
}

fn epoch_inventory(epoch: u64) -> OperatorCredentialInventory {
    OperatorCredentialInventory {
        registry_epoch: epoch,
        detail: OperatorCredentialDetail::EpochOnly,
        credentials: Vec::new(),
    }
}

fn verified_registry_inventory(
    registry: &aether::certificates::approval::CredentialRegistry,
) -> OperatorCredentialInventory {
    let mut credentials: Vec<_> = registry
        .bindings
        .iter()
        .map(|binding| OperatorCredentialFacts {
            fingerprint: aether::certificates::encoding::Fingerprint::of(&binding.credential_id)
                .to_hex(),
            state: binding.state,
            credential_epoch: binding.credential_epoch,
            created_at: binding.created_at,
        })
        .collect();
    credentials.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    OperatorCredentialInventory {
        registry_epoch: registry.credential_registry_epoch,
        detail: OperatorCredentialDetail::Verified,
        credentials,
    }
}

/// Reads the durable snapshot without trusting the clear registry header.
pub fn operator_inventory(
    state: &crate::certificates::TrustState,
) -> Result<OperatorCredentialInventory, aether::certificates::CertificateError> {
    let Some(registry) = &state.credential_registry else {
        return Ok(epoch_inventory(state.astra.credential_registry_epoch));
    };
    registry.verify(
        &state.gateway.current_ca_public_key,
        &state.trust_domain_id,
        &state.gateway.gateway_wg_public_key,
        state.gateway.ca_epoch,
        state.astra.credential_registry_epoch,
    )?;
    if registry.credential_registry_epoch != state.astra.credential_registry_epoch {
        return Err(
            aether::certificates::CertificateError::InvalidCredentialBinding(
                "registry epoch differs from retained state",
            ),
        );
    }
    if registry.bindings.len() != state.astra.credential_bindings.len() {
        return Err(
            aether::certificates::CertificateError::InvalidCredentialBinding(
                "registry omits retained decisions",
            ),
        );
    }
    for binding in &registry.bindings {
        let key = aether::certificates::encoding::Fingerprint::of(&binding.credential_id).to_hex();
        if state.astra.credential_bindings.get(&key) != Some(binding) {
            return Err(
                aether::certificates::CertificateError::InvalidCredentialBinding(
                    "registry differs from retained decisions",
                ),
            );
        }
    }
    Ok(verified_registry_inventory(registry))
}

impl CertificateFacts {
    fn new(
        subject: String,
        issuer: String,
        fingerprint: String,
        not_before: u64,
        not_after: u64,
        now_unix: u64,
    ) -> Result<Self, String> {
        let period = ValidityPeriod::new(not_before, not_after)
            .map_err(|_| "période de validité incohérente".to_string())?;
        let renewal_at = period
            .renewal_at()
            .map_err(|_| "période de validité incohérente".to_string())?;
        let phase = period.phase(now_unix);
        Ok(Self {
            subject,
            issuer,
            fingerprint,
            not_before,
            not_after,
            renewal_at,
            phase,
        })
    }
}

/// The four certificates a connection depends on, plus what could not be read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateInventory {
    /// The gateway's ML-DSA-87 leaf, pinned by the profile.
    pub gateway_pq: Option<CertificateFacts>,
    /// The gateway's TLS anchor, pinned by the profile.
    pub gateway_ca_tls: Option<CertificateFacts>,
    /// This machine's mTLS leaf, from the protected store.
    pub client_tls: Option<CertificateFacts>,
    /// This machine's ML-DSA-87 leaf, from the protected store.
    pub client_pq: Option<CertificateFacts>,
    /// Slots that exist but could not be read, each named.
    pub faults: Vec<String>,
    /// The protected identity named by the profile is on this machine.
    pub identity_sealed: bool,
    /// Outgoing identity retained for a bounded service rollback.
    pub previous_identity: Option<PreviousIdentityStatus>,
    /// Highest authenticated credential-registry epoch carried by the profile.
    pub operator_credentials: Option<OperatorCredentialInventory>,
}

/// Reads a PQ certificate as the negotiation format carries it.
fn pq_facts(certificate: &PqCertificate, now_unix: u64) -> Result<CertificateFacts, String> {
    let fingerprint = certificate
        .fingerprint()
        .map_err(|_| "empreinte illisible".to_string())?;
    CertificateFacts::new(
        certificate.subject.clone(),
        certificate.issuer.clone(),
        fingerprint,
        certificate.not_before_unix,
        certificate.not_after_unix,
        now_unix,
    )
}

/// Reads an X.509 certificate through the lifecycle's own validator.
fn x509_facts(der: Vec<u8>, now_unix: u64) -> Result<CertificateFacts, String> {
    let certificate = DerCertificate::new(der).map_err(|error| error.to_string())?;
    let inspected = x509::inspect(&certificate).map_err(|error| error.to_string())?;
    let (subject, issuer) =
        x509::subject_and_issuer(&certificate).map_err(|error| error.to_string())?;
    CertificateFacts::new(
        subject,
        issuer,
        certificate.fingerprint().to_hex(),
        inspected.not_before,
        inspected.not_after,
        now_unix,
    )
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|_| "base64 illisible".to_string())
}

/// Everything the gateway half of a profile pins.
///
/// Split from the client half because the two fail independently: a profile
/// can pin a perfectly readable gateway while this machine holds no identity
/// at all, and reporting one failure for both would hide which.
pub fn gateway_inventory(
    settings: &KeyNegotiationSettings,
    now_unix: u64,
    inventory: &mut CertificateInventory,
) {
    match settings.gateway_pq_certificate() {
        Ok(certificate) => match pq_facts(&certificate, now_unix) {
            Ok(facts) => inventory.gateway_pq = Some(facts),
            Err(error) => inventory
                .faults
                .push(format!("certificat PQ de la gateway : {error}")),
        },
        Err(error) => inventory
            .faults
            .push(format!("certificat PQ de la gateway : {error}")),
    }

    match decode(&settings.gateway_ca_der).and_then(|der| x509_facts(der, now_unix)) {
        Ok(facts) => inventory.gateway_ca_tls = Some(facts),
        Err(error) => inventory
            .faults
            .push(format!("CA TLS de la gateway : {error}")),
    }
}

/// Everything this machine holds for the identity a profile names.
///
/// Reading it unseals the bundle, which is what the connection would do
/// anyway. The two private halves are never touched: the bundle is dropped at
/// the end of this function and only dates and fingerprints leave it.
pub fn client_inventory(
    settings: &KeyNegotiationSettings,
    now_unix: u64,
    inventory: &mut CertificateInventory,
) {
    let identity = settings.identity.trim();
    if identity.is_empty() {
        return;
    }
    let Ok(store) = ProtectedIdentityStore::for_current_user() else {
        // Not a fault of this profile: the machine has no protected store at
        // all, which the interface states once rather than per certificate.
        return;
    };
    inventory.identity_sealed = store.contains(identity);
    if !inventory.identity_sealed {
        return;
    }
    let snapshot = match store.snapshot_at(identity, now_unix) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            inventory
                .faults
                .push(format!("identité protégée « {identity} » : {error}"));
            return;
        }
    };
    if snapshot
        .previous
        .is_some_and(|previous| previous.phase == crate::PreviousIdentityPhase::Expired)
    {
        if let Err(error) = store.retire_previous(identity, now_unix) {
            inventory.faults.push(format!(
                "purge de l'identité cliente précédente impossible : {error}"
            ));
        }
    }
    inventory.previous_identity = snapshot.previous;
    let bundle = snapshot.served;

    if let Err(error) = retained_operator_inventory(settings, &bundle, inventory) {
        inventory
            .faults
            .push(format!("registre opérateur : {error}"));
    }

    match bundle
        .certificate_chain
        .first()
        .ok_or_else(|| "chaîne de certificats vide".to_string())
        .and_then(|leaf| decode(leaf))
        .and_then(|der| x509_facts(der, now_unix))
    {
        Ok(facts) => inventory.client_tls = Some(facts),
        Err(error) => inventory.faults.push(format!("certificat TLS : {error}")),
    }

    match decode(&bundle.pq_certificate)
        .and_then(|raw| {
            serde_json::from_slice::<PqCertificate>(&raw).map_err(|_| "JSON illisible".to_string())
        })
        .and_then(|certificate| pq_facts(&certificate, now_unix))
    {
        Ok(facts) => inventory.client_pq = Some(facts),
        Err(error) => inventory.faults.push(format!("certificat PQ : {error}")),
    }
}

/// The whole inventory for one profile.
pub fn inventory(settings: Option<&KeyNegotiationSettings>, now_unix: u64) -> CertificateInventory {
    let mut inventory = CertificateInventory::default();
    let Some(settings) = settings else {
        return inventory;
    };
    inventory.operator_credentials = settings
        .trust
        .as_ref()
        .map(|trust| epoch_inventory(trust.credential_registry_epoch));
    gateway_inventory(settings, now_unix, &mut inventory);
    client_inventory(settings, now_unix, &mut inventory);
    inventory
}

fn retained_operator_inventory(
    settings: &KeyNegotiationSettings,
    bundle: &crate::identity_store::ClientIdentityBundle,
    inventory: &mut CertificateInventory,
) -> anyhow::Result<()> {
    let Some(trust) = &settings.trust else {
        return Ok(());
    };
    let domain = trust.trust_domain()?;
    let leaf = crate::certificate_renewal::client_pq_leaf(bundle)?;
    let client = aether::certificates::encoding::WireGuardKey::parse(&leaf.wireguard_public_key)?;
    let path = crate::certificate_renewal::trust_store_path(&domain, &client)?;
    let Some(store) = crate::certificates::TrustStore::load(&path)? else {
        return Ok(());
    };
    let state = store.state();
    let gateway = settings.gateway_pq_certificate()?;
    let gateway_key =
        aether::certificates::encoding::WireGuardKey::parse(&gateway.wireguard_public_key)?;
    if state.trust_domain_id != domain
        || state.client_wg_public_key != client
        || state.gateway.gateway_wg_public_key != gateway_key
    {
        anyhow::bail!("le magasin de confiance appartient à une autre identité");
    }
    // The persisted epoch is authoritative, while an imported profile may
    // still carry a newer floor. Neither can make the other move backwards.
    let epoch = state
        .astra
        .credential_registry_epoch
        .max(trust.credential_registry_epoch);
    inventory.operator_credentials = Some(epoch_inventory(epoch));
    if state.astra.credential_registry_epoch < epoch {
        anyhow::bail!("le registre conservé est antérieur au profil");
    }
    inventory.operator_credentials = Some(operator_inventory(state)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_domain::{domain, settings, NOW};
    use base64::engine::general_purpose::STANDARD;

    fn period(not_before: u64, not_after: u64, now: u64) -> CertificatePhase {
        CertificateFacts::new(
            "sujet".into(),
            "émetteur".into(),
            "ff".into(),
            not_before,
            not_after,
            now,
        )
        .expect("facts")
        .phase
    }

    /// The ladder is the protocol's, read through `ValidityPeriod`: a panel
    /// with thresholds of its own would eventually contradict the planner that
    /// actually decides when to renew.
    #[test]
    fn the_phase_follows_the_eighty_ninety_ninety_five_ladder() {
        // A 100-second life starting at zero puts the thresholds on round
        // numbers, which is the whole reason for these values.
        assert_eq!(period(0, 100, 0), CertificatePhase::Valid);
        assert_eq!(period(0, 100, 79), CertificatePhase::Valid);
        assert_eq!(period(0, 100, 80), CertificatePhase::RenewalDue);
        assert_eq!(period(0, 100, 89), CertificatePhase::RenewalDue);
        assert_eq!(period(0, 100, 90), CertificatePhase::Warning);
        assert_eq!(period(0, 100, 94), CertificatePhase::Warning);
        assert_eq!(period(0, 100, 95), CertificatePhase::Critical);
        assert_eq!(period(0, 100, 99), CertificatePhase::Critical);
        assert_eq!(period(0, 100, 100), CertificatePhase::Expired);
    }

    /// A certificate prepared for later is not expired and not due: it is a
    /// staged one, and calling it anything else would report a rotation in
    /// progress as a failure.
    #[test]
    fn a_certificate_prepared_for_later_reads_as_not_yet_valid() {
        assert_eq!(period(1_000, 2_000, 999), CertificatePhase::NotYetValid);
        assert_eq!(period(1_000, 2_000, 1_000), CertificatePhase::Valid);
    }

    /// An inconsistent period is refused rather than shown with an invented
    /// renewal instant.
    #[test]
    fn an_inconsistent_period_is_a_fault_and_not_a_zero() {
        assert!(CertificateFacts::new(
            "sujet".into(),
            "émetteur".into(),
            "ff".into(),
            2_000,
            1_000,
            1_500
        )
        .is_err());
    }

    /// No negotiation block pins nothing, and that is an empty inventory —
    /// not a fault. The screen shows an absence, not an error.
    #[test]
    fn a_profile_without_negotiation_has_an_empty_inventory() {
        let found = inventory(None, 1_000);
        assert_eq!(found, CertificateInventory::default());
        assert!(found.faults.is_empty());
    }

    /// Orion must not turn a pinned epoch into an invented list. Until it
    /// persists a CA-PQ-verified registry, the inventory says exactly what the
    /// profile holds and distinguishes that from an empty registry.
    #[test]
    fn a_trust_profile_reports_the_registry_epoch_without_inventing_rows() {
        let mut settings = KeyNegotiationSettings {
            mode: aether::key_negotiation::ProtectionMode::MlKem,
            minimum_mode: aether::key_negotiation::ProtectionMode::MlKem,
            endpoint: "gateway:51821".into(),
            server_name: "gateway.example".into(),
            gateway_ca_der: "pas du base64 !".into(),
            gateway_pq_certificate: "pas du base64 !".into(),
            identity: String::new(),
            trust: None,
        };
        settings.trust = Some(crate::config::TrustMaterial {
            trust_domain_id: "01".repeat(16),
            ca_epoch: 3,
            ca_pq_public_key: String::new(),
            ca_tls_epoch: 4,
            client_tls_ca_der: String::new(),
            client_generation: 7,
            astra_authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: "11".repeat(32),
            credential_registry_epoch: 12,
            astra_credential_bindings: Vec::new(),
            astra_service_key_epoch: 2,
            astra_service_public_key: String::new(),
            active_gateway_identity_epoch: 1,
            gateway_decision_epoch: 1,
        });

        let found = inventory(Some(&settings), 1_000);
        assert_eq!(
            found.operator_credentials,
            Some(OperatorCredentialInventory {
                registry_epoch: 12,
                detail: OperatorCredentialDetail::EpochOnly,
                credentials: Vec::new(),
            })
        );
    }

    /// A block whose pinned material is unreadable names which half failed.
    /// A dash on both would send the user looking at the network.
    #[test]
    fn unreadable_pinned_material_is_reported_per_certificate() {
        let settings = KeyNegotiationSettings {
            mode: aether::key_negotiation::ProtectionMode::MlKem,
            minimum_mode: aether::key_negotiation::ProtectionMode::MlKem,
            endpoint: "gateway:51821".into(),
            server_name: "gateway.example".into(),
            gateway_ca_der: "pas du base64 !".into(),
            gateway_pq_certificate: "pas du base64 !".into(),
            identity: String::new(),
            trust: None,
        };
        let found = inventory(Some(&settings), 1_000);
        assert!(found.gateway_pq.is_none());
        assert!(found.gateway_ca_tls.is_none());
        assert_eq!(found.faults.len(), 2);
        assert!(found.faults.iter().any(|fault| fault.contains("PQ")));
        assert!(found.faults.iter().any(|fault| fault.contains("CA TLS")));
    }

    /// A real X.509 certificate is read through the lifecycle's own validator,
    /// so the panel and the chain checks agree on the dates.
    #[test]
    fn a_genuine_x509_certificate_yields_its_names_and_dates() {
        let material = aether::certificates::test_x509::client_material("workstation");
        let facts =
            x509_facts(material.leaf.as_bytes().to_vec(), 1_000).expect("a genuine leaf reads");
        assert!(facts.subject.contains("workstation"));
        assert!(facts.issuer.contains("CA-TLS"));
        assert_eq!(facts.fingerprint, material.leaf.fingerprint().to_hex());
        assert!(facts.not_after > facts.renewal_at);
        assert!(facts.renewal_at > facts.not_before);
    }

    #[test]
    fn gateway_inventory_projects_both_valid_pins_without_client_state() {
        let domain = domain();
        let mut settings = settings(&domain);
        settings.gateway_pq_certificate = STANDARD.encode(
            serde_json::to_vec(&domain.gateway_leaf).expect("encode gateway PQ certificate"),
        );
        settings.gateway_ca_der = STANDARD.encode(domain.tls_ca_der.as_bytes());
        let mut inventory = CertificateInventory::default();

        gateway_inventory(&settings, NOW, &mut inventory);

        let pq = inventory.gateway_pq.expect("gateway PQ facts");
        assert_eq!(pq.subject, domain.gateway_leaf.subject);
        assert_eq!(pq.issuer, domain.gateway_leaf.issuer);
        assert_eq!(
            pq.fingerprint,
            domain.gateway_leaf.fingerprint().expect("PQ fingerprint")
        );
        assert_eq!(pq.not_before, domain.gateway_leaf.not_before_unix);
        assert_eq!(pq.not_after, domain.gateway_leaf.not_after_unix);
        assert_eq!(pq.phase, CertificatePhase::Valid);

        let ca = inventory.gateway_ca_tls.expect("gateway CA-TLS facts");
        assert_eq!(ca.fingerprint, domain.tls_ca_der.fingerprint().to_hex());
        assert_eq!(ca.phase, CertificatePhase::Valid);
        assert!(inventory.client_tls.is_none());
        assert!(inventory.client_pq.is_none());
        assert!(inventory.faults.is_empty());
    }

    #[test]
    fn an_unreadable_gateway_pq_pin_does_not_hide_the_valid_tls_anchor() {
        let domain = domain();
        let mut settings = settings(&domain);
        settings.gateway_pq_certificate = STANDARD.encode(br#"{"wrong":"shape"}"#);
        settings.gateway_ca_der = STANDARD.encode(domain.tls_ca_der.as_bytes());
        let mut inventory = CertificateInventory::default();

        gateway_inventory(&settings, NOW, &mut inventory);

        assert!(inventory.gateway_pq.is_none());
        assert!(inventory.gateway_ca_tls.is_some());
        assert_eq!(inventory.faults.len(), 1);
        assert!(inventory.faults[0].contains("PQ de la gateway"));
    }

    #[test]
    fn an_incoherent_gateway_pq_period_is_named_as_a_fault() {
        let domain = domain();
        let mut invalid = domain.gateway_leaf.clone();
        invalid.not_after_unix = invalid.not_before_unix;
        let mut settings = settings(&domain);
        settings.gateway_pq_certificate =
            STANDARD.encode(serde_json::to_vec(&invalid).expect("encode malformed period"));
        settings.gateway_ca_der = STANDARD.encode(domain.tls_ca_der.as_bytes());
        let mut inventory = CertificateInventory::default();

        gateway_inventory(&settings, NOW, &mut inventory);

        assert!(inventory.gateway_pq.is_none());
        assert!(inventory.gateway_ca_tls.is_some());
        assert_eq!(inventory.faults.len(), 1);
        assert!(inventory.faults[0].contains("période de validité incohérente"));
    }

    #[test]
    fn an_unreadable_gateway_tls_anchor_does_not_hide_the_valid_pq_pin() {
        let domain = domain();
        let malformed_der = STANDARD.encode(b"not DER");
        for invalid_anchor in ["not base64 !", malformed_der.as_str()] {
            let mut settings = settings(&domain);
            settings.gateway_pq_certificate = STANDARD.encode(
                serde_json::to_vec(&domain.gateway_leaf).expect("encode gateway PQ certificate"),
            );
            settings.gateway_ca_der = invalid_anchor.to_string();
            let mut inventory = CertificateInventory::default();

            gateway_inventory(&settings, NOW, &mut inventory);

            assert!(inventory.gateway_pq.is_some());
            assert!(inventory.gateway_ca_tls.is_none());
            assert_eq!(inventory.faults.len(), 1);
            assert!(inventory.faults[0].contains("CA TLS de la gateway"));
        }
    }
}
