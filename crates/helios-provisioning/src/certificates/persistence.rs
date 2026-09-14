//! The registry's file: where it lives, how it is opened and how it is written.
//!
//! Every mutation in the other blocks ends here, in [`CertificateRegistry::persist`],
//! and the order that method follows — write, `fsync`, then adopt — is the
//! invariant the whole module is built on.

use super::{
    AstraIssuancePolicy, CertificateRegistry, Path, PathBuf, RegistryError, RegistryState,
    TrustDomainId, Value, WireGuardKey, CERTIFICATE_REGISTRY_PATH,
};

impl CertificateRegistry {
    /// Path of the registry. `HELIOS_CERTIFICATE_REGISTRY` isolates a test run
    /// exactly as `HELIOS_NETWORK_CONFIG` does for the network configuration.
    pub fn path() -> PathBuf {
        std::env::var_os("HELIOS_CERTIFICATE_REGISTRY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(CERTIFICATE_REGISTRY_PATH))
    }

    pub fn new(path: PathBuf, state: RegistryState) -> Self {
        Self { path, state }
    }

    /// Creates the registry of a trust domain, once and only once.
    ///
    /// The counterpart of `astra bootstrap` on this side of the wire, and it
    /// refuses an existing file for the same reason: a domain has one history,
    /// and a second one starting at epoch 1 would be refused by every client
    /// already holding a higher one — while looking, locally, like a clean
    /// install.
    ///
    /// Nothing here is secret. Every value is either public by construction
    /// (the leaves this gateway already serves, the anchors it is told to
    /// trust) or an identifier. The command that calls this therefore needs
    /// no TPM: it opens no vault and unseals nothing.
    pub fn bootstrap(path: PathBuf, state: RegistryState) -> Result<Self, RegistryError> {
        if path.exists() {
            return Err(RegistryError::AlreadyBootstrapped(path));
        }
        if let Some(parent) = path.parent() {
            aether::private_file::create_private_dir(parent)?;
        }
        let mut registry = Self::new(path, state.clone());
        registry.persist(state)?;
        Ok(registry)
    }

    /// Loads the registry, or reports that the domain is not bootstrapped.
    ///
    /// A missing file is **not** an empty registry: a gateway with no trust
    /// domain has no `CA-PQ` to verify anything against, and inventing an
    /// empty one would silently accept the first object that arrived.
    pub fn load(path: &Path) -> Result<Option<Self>, RegistryError> {
        match std::fs::read(path) {
            Ok(raw) => {
                let mut document: Value = serde_json::from_slice(&raw)
                    .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
                let migrated = migrate_legacy_registry(&mut document)?;
                let state: RegistryState = serde_json::from_value(document)
                    .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
                let mut registry = Self {
                    path: path.to_path_buf(),
                    state,
                };
                if migrated {
                    // The migration is part of loading, but it still follows
                    // the registry's normal written-first rule. A daemon
                    // restart therefore cannot leave a legacy document on
                    // disk after it has served the current state in memory.
                    let state = registry.state.clone();
                    registry.persist(state)?;
                    tracing::info!(
                        path = %path.display(),
                        "migrated the certificate registry to the current Astra trust schema"
                    );
                }
                Ok(Some(registry))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(RegistryError::Io(error)),
        }
    }

    pub fn state(&self) -> &RegistryState {
        &self.state
    }

    /// Writes a candidate state atomically, `fsync`s, then adopts it.
    ///
    /// The order is the invariant: on a failed write the live state is the one
    /// that is still on disk, so a retry sees exactly what a restart would.
    /// Adopting first and reporting the error afterwards would leave the
    /// running registry describing a transaction the disk never received.
    pub(super) fn persist(&mut self, candidate: RegistryState) -> Result<(), RegistryError> {
        let encoded = serde_json::to_vec_pretty(&candidate)
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
        aether::private_file::write_private_atomic(&self.path, &encoded)?;
        self.state = candidate;
        Ok(())
    }
}

/// Adds fields introduced after the first trust-domain registry format.
///
/// The gateway registry is deliberately not bootstrapped again when a file is
/// already present: doing so would erase its certificate generations and
/// ledger. Newer binaries therefore migrate the small, deterministic Astra
/// profile extension in place. The policy pin is recomputed from the same
/// three public inputs used by `heliosd init-trust-domain`; it is never copied
/// from an operator-signed object or accepted from an untrusted default.
fn migrate_legacy_registry(document: &mut Value) -> Result<bool, RegistryError> {
    let root = document
        .as_object_mut()
        .ok_or_else(|| RegistryError::Corrupt("registry root is not an object".into()))?;

    let trust_domain_id: TrustDomainId = serde_json::from_value(
        root.get("trust_domain_id")
            .cloned()
            .ok_or_else(|| RegistryError::Corrupt("missing field `trust_domain_id`".into()))?,
    )
    .map_err(|error| RegistryError::Corrupt(format!("invalid `trust_domain_id`: {error}")))?;

    let gateway = root
        .get("gateway")
        .and_then(Value::as_object)
        .ok_or_else(|| RegistryError::Corrupt("missing field `gateway`".into()))?;
    let gateway_wg_public_key: WireGuardKey = serde_json::from_value(
        gateway
            .get("gateway_wg_public_key")
            .cloned()
            .ok_or_else(|| {
                RegistryError::Corrupt("missing field `gateway.gateway_wg_public_key`".into())
            })?,
    )
    .map_err(|error| {
        RegistryError::Corrupt(format!("invalid `gateway.gateway_wg_public_key`: {error}"))
    })?;
    let server_name = gateway
        .get("server_name")
        .and_then(Value::as_str)
        .ok_or_else(|| RegistryError::Corrupt("missing field `gateway.server_name`".into()))?
        .to_owned();

    let astra = root
        .get_mut("astra")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| RegistryError::Corrupt("missing field `astra`".into()))?;

    let mut migrated = false;
    if !astra.contains_key("astra_policy_fingerprint") {
        let pin =
            AstraIssuancePolicy::standard(trust_domain_id, gateway_wg_public_key, server_name)
                .pin()
                .map_err(|error| {
                    RegistryError::Corrupt(format!("building the Astra policy pin: {error}"))
                })?;
        let encoded = serde_json::to_value(pin.fingerprint())
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
        astra.insert("astra_policy_fingerprint".into(), encoded);
        migrated = true;
    }
    if !astra.contains_key("credential_registry_epoch") {
        astra.insert("credential_registry_epoch".into(), Value::from(1_u64));
        migrated = true;
    }
    if !astra.contains_key("credential_bindings") {
        astra.insert(
            "credential_bindings".into(),
            Value::Object(Default::default()),
        );
        migrated = true;
    }

    Ok(migrated)
}
