//! Turning the file on disk into a verified state, whatever version wrote it.
//!
//! Loading is the one place a registry may be refused outright — a chain that
//! forks away from the head an operator recorded — and the one place a file
//! written by an older Astra is completed rather than refused. Both repairs
//! are **derived**: the policy pin is recomputed from the identity already in
//! the file, and an accepted rotation window is restored from the signed
//! transition the same file holds. Nothing here decides anything, which is why
//! none of it appends to the audit chain.

use std::path::Path;

use super::{
    AstraIssuancePolicy, AstraRegistry, AstraState, CaPqRotation, ClientTlsCaRotation, Fingerprint,
    RegistryError, TrustDomainId, WireGuardKey,
};

impl AstraRegistry {
    /// Loads the registry, refusing a chain that forks away from `expected_head`.
    ///
    /// A registry written before [`AstraState::astra_policy_fingerprint`] and
    /// `credential_registry_epoch` existed is **migrated** rather than
    /// refused — see `Self::migrate`. Refusing it would leave an operator
    /// with an authority that has a history, a service key and a domain, and
    /// no way to read any of them.
    pub fn load(path: &Path, expected_head: Option<&Fingerprint>) -> Result<Self, RegistryError> {
        Self::load_with(path, expected_head, false)
    }

    /// Loads a registry for a daemon restart, accepting the unattended
    /// per-peer lifecycle appended since the operator recorded the witness.
    ///
    /// See [`crate::audit::AuditChain::verify_from_witness`] for where the line
    /// is drawn. What grew is logged rather than swallowed.
    pub fn load_allowing_unattended_tail(
        path: &Path,
        expected_head: Option<&Fingerprint>,
    ) -> Result<Self, RegistryError> {
        Self::load_with(path, expected_head, true)
    }

    fn load_with(
        path: &Path,
        expected_head: Option<&Fingerprint>,
        allow_unattended_tail: bool,
    ) -> Result<Self, RegistryError> {
        let raw = std::fs::read(path)?;
        let mut document: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
        let mut migrated = Self::migrate(&mut document)?;
        let mut state: AstraState = serde_json::from_value(document)
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
        migrated |= Self::recover_ca_pq_rotation(&mut state)?;
        migrated |= Self::recover_client_tls_ca_rotation(&mut state)?;
        match expected_head {
            Some(expected) if allow_unattended_tail => {
                let growth = state.audit.verify_from_witness(expected)?;
                if growth.appended > 0 {
                    tracing::info!(
                        witnessed_sequence = growth.witnessed_sequence,
                        appended = growth.appended,
                        "the audit chain grew past the recorded witness; every record after it \
                         is per-peer lifecycle, which widens nothing this authority may do"
                    );
                }
            }
            _ => state.audit.verify(expected_head)?,
        }
        let registry = Self {
            path: path.to_path_buf(),
            state,
        };
        if migrated {
            // Written back so this happens once. The audit chain is untouched:
            // nothing was decided here, and appending an event for a field
            // that was always implied would fork the head an operator holds.
            registry.save()?;
            tracing::info!(
                path = %path.display(),
                "registry migrated: derived state was restored from the identity and signed \
                 transitions already recorded"
            );
        }
        Ok(registry)
    }

    /// Fills the two fields a registry written before them does not carry.
    ///
    /// Both are **derived**, which is the only reason this is a migration and
    /// not a decision:
    ///
    /// - the issuance policy pin is `AstraIssuancePolicy::standard` over the
    ///   trust domain, the gateway key and the server name — the three values
    ///   already in the file. Astra and Helios each compute it independently
    ///   at bootstrap and compare the result out of band, so recomputing it
    ///   here reproduces exactly what bootstrap would have written. It is not
    ///   read from anywhere, and a file that supplied its own would be
    ///   supplying a pin, which is the one thing a pin may never be;
    /// - the credential registry epoch starts at zero rather than at one.
    ///   Every consumer keeps the highest it has seen, so the lowest possible
    ///   value is the only safe one: starting higher would refuse the first
    ///   genuine credential document as a rollback.
    ///
    /// Returns whether anything was filled, so a file already current is not
    /// rewritten.
    fn migrate(document: &mut serde_json::Value) -> Result<bool, RegistryError> {
        let Some(object) = document.as_object_mut() else {
            return Err(RegistryError::Corrupt(
                "the registry is not a JSON object".into(),
            ));
        };
        let mut migrated = false;
        if !object.contains_key("credential_registry_epoch") {
            object.insert("credential_registry_epoch".into(), serde_json::json!(0));
            migrated = true;
        }
        if !object.contains_key("astra_policy_fingerprint") {
            let identity = |field: &str| -> Result<String, RegistryError> {
                object
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| {
                        RegistryError::Corrupt(format!(
                            "the registry carries no policy pin and no `{field}` to recompute it \
                             from"
                        ))
                    })
            };
            let trust_domain_id = TrustDomainId::parse_hex(&identity("trust_domain_id")?)
                .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
            let gateway_wg_public_key = WireGuardKey::parse(&identity("gateway_wg_public_key")?)
                .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
            let pin = AstraIssuancePolicy::standard(
                trust_domain_id,
                gateway_wg_public_key,
                identity("server_name")?,
            )
            .pin()
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
            object.insert(
                "astra_policy_fingerprint".into(),
                serde_json::to_value(pin)
                    .map_err(|error| RegistryError::Corrupt(error.to_string()))?,
            );
            migrated = true;
        }
        Ok(migrated)
    }

    /// Restores the `CA-TLS` window accepted by a registry written before the
    /// window itself was persisted.
    ///
    /// The transition is verified again against the active pin. Two different
    /// successors for the same epoch are refused as corruption rather than
    /// choosing one based on storage order.
    fn recover_client_tls_ca_rotation(state: &mut AstraState) -> Result<bool, RegistryError> {
        use aether::certificates::transport::TrustUpdateObject;

        if state.ca_tls_rotation.is_some() {
            return Ok(false);
        }
        let Some(active) = state.ca_tls_fingerprint else {
            return Ok(false);
        };
        let mut recovered = None;
        for transition in state
            .transitions
            .iter()
            .filter_map(|stored| match &stored.object {
                TrustUpdateObject::ClientTlsCaTransition(transition)
                    if transition.current_ca_tls_epoch == state.ca_tls_epoch
                        && transition.active_client_tls_ca_fingerprint.matches(&active) =>
                {
                    Some(transition.as_ref())
                }
                _ => None,
            })
        {
            transition.verify(
                &state.ca_public_key,
                &state.trust_domain_id,
                state.ca_epoch,
                state.ca_tls_epoch,
                &active,
            )?;
            if recovered.is_some() {
                return Err(RegistryError::Corrupt(
                    "multiple client CA-TLS rotations target the active epoch".into(),
                ));
            }
            recovered = Some(ClientTlsCaRotation::from_transition(transition));
        }
        let restored = recovered.is_some();
        state.ca_tls_rotation = recovered;
        Ok(restored)
    }

    /// Restores a `CA-PQ` window accepted before Astra persisted its own
    /// active/next anchor state.
    ///
    /// Recovery still verifies both signatures under the anchor already
    /// pinned in the registry. Ambiguous successors are corruption, never a
    /// storage-order choice.
    fn recover_ca_pq_rotation(state: &mut AstraState) -> Result<bool, RegistryError> {
        use aether::certificates::transport::TrustUpdateObject;

        if state.ca_rotation.is_some() {
            return Ok(false);
        }
        let active = state.ca_public_key.authority_fingerprint();
        let mut recovered = None;
        for transition in state
            .transitions
            .iter()
            .filter_map(|stored| match &stored.object {
                TrustUpdateObject::CaTransition(transition)
                    if transition.current_ca_epoch == state.ca_epoch
                        && transition.current_ca_fingerprint.matches(&active) =>
                {
                    Some(transition.as_ref())
                }
                _ => None,
            })
        {
            transition.verify(&state.ca_public_key, &state.trust_domain_id, state.ca_epoch)?;
            if recovered.is_some() {
                return Err(RegistryError::Corrupt(
                    "multiple CA-PQ rotations target the active epoch".into(),
                ));
            }
            recovered = Some(CaPqRotation::from_transition(transition));
        }
        let restored = recovered.is_some();
        state.ca_rotation = recovered;
        Ok(restored)
    }
}
