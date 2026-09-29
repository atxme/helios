//! The identity the endpoint serves: bootstrap, sealed storage and the
//! selection of what a restart loads.

use super::*;

pub struct InitializedIdentity {
    pub certificate_path: std::path::PathBuf,
    pub certificate_sha256: String,
    pub bootstrap_request_path: std::path::PathBuf,
    pub bootstrap_request_fingerprint: String,
}

/// The public identity material a trust-domain bootstrap needs.
///
/// Three files, all public by construction: the TLS leaf this gateway serves,
/// its PQ leaf, and the client TLS anchor it was told to trust. Reading them
/// opens no vault — which is why `init-trust-domain` needs no TPM, and can be
/// run on a gateway whose boot chain has moved.
///
/// The PQ leaf is where the server name and the WireGuard identity come from,
/// rather than from arguments an operator retypes: the registry must describe
/// the identity actually being served, and two fields that must agree are two
/// fields that can disagree.
pub struct ServedIdentity {
    pub tls_certificate: aether::certificates::encoding::DerCertificate,
    pub pq_certificate: PqCertificate,
    pub client_tls_ca: aether::certificates::encoding::DerCertificate,
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayBootstrapCertificateError {
    #[error("a self-signed gateway PQ leaf cannot become the active trust-domain identity")]
    SelfSignedGatewayCertificate,
    #[error("the gateway PQ leaf does not match its sealed bootstrap request")]
    IdentityMismatch,
    #[error("invalid gateway bootstrap request: {0}")]
    InvalidRequest(#[source] aether::certificates::CertificateError),
    #[error("invalid CA-PQ-issued gateway certificate: {0}")]
    InvalidCertificate(#[source] aether::key_negotiation::KeyNegotiationError),
}

/// Reads the proof exported by `init-key-negotiation`, if that gesture ran.
pub fn gateway_bootstrap_request(
) -> Result<Option<aether::certificates::gateway::GatewayBootstrapRequest>> {
    let encoded = match std::fs::read(GATEWAY_BOOTSTRAP_REQUEST_PATH) {
        Ok(encoded) => encoded,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {GATEWAY_BOOTSTRAP_REQUEST_PATH}"))
        }
    };
    serde_json::from_slice(&encoded)
        .with_context(|| format!("reading {GATEWAY_BOOTSTRAP_REQUEST_PATH}"))
        .map(Some)
}

/// Checks that epoch 1 is a `CA-PQ` issuance for the locally sealed key.
pub fn verify_gateway_bootstrap_certificate(
    request: &aether::certificates::gateway::GatewayBootstrapRequest,
    certificate: &PqCertificate,
    ca_public_key: &aether::certificates::encoding::MlDsa87PublicKey,
    now_unix: u64,
) -> std::result::Result<(), GatewayBootstrapCertificateError> {
    request
        .verify()
        .map_err(GatewayBootstrapCertificateError::InvalidRequest)?;

    // Test the signature at the leaf's own lower bound so an expired legacy
    // self-signed leaf is still identified by the named refusal, rather than
    // falling through to a generic CA signature error.
    if certificate
        .verify_self_signed(
            PqCertificateRole::Gateway,
            Some(&request.server_name),
            &request.gateway_wg_public_key.to_base64(),
            certificate.not_before_unix,
        )
        .is_ok()
    {
        return Err(GatewayBootstrapCertificateError::SelfSignedGatewayCertificate);
    }

    certificate
        .verify(
            ca_public_key.as_bytes(),
            PqCertificateRole::Gateway,
            Some(&request.server_name),
            &request.gateway_wg_public_key.to_base64(),
            now_unix,
        )
        .map_err(GatewayBootstrapCertificateError::InvalidCertificate)?;
    let certificate_key =
        aether::certificates::encoding::MlDsa87PublicKey::parse(&certificate.ml_dsa_87_public_key)
            .map_err(GatewayBootstrapCertificateError::InvalidRequest)?;
    if certificate_key != request.ml_dsa_87_public_key {
        return Err(GatewayBootstrapCertificateError::IdentityMismatch);
    }
    Ok(())
}

/// Installs only the public leaf returned by the offline CA-PQ ceremony.
pub fn install_gateway_bootstrap_certificate(
    source: &Path,
    ca_public_key: &aether::certificates::encoding::MlDsa87PublicKey,
    now_unix: u64,
) -> Result<PqCertificate> {
    let request = gateway_bootstrap_request()?.context(
        "the gateway has no bootstrap request: run `heliosd init-key-negotiation` first",
    )?;
    let encoded = std::fs::read(source)
        .with_context(|| format!("reading gateway certificate {}", source.display()))?;
    let certificate: PqCertificate = serde_json::from_slice(&encoded)
        .with_context(|| format!("reading gateway certificate {}", source.display()))?;
    verify_gateway_bootstrap_certificate(&request, &certificate, ca_public_key, now_unix)
        .context("verifying the initial gateway certificate under CA-PQ")?;
    write_public_atomic(
        Path::new(PQ_CERTIFICATE_PATH),
        &serde_json::to_vec_pretty(&certificate).context("encoding the gateway PQ certificate")?,
    )
    .context("installing the CA-PQ-issued gateway certificate")?;
    Ok(certificate)
}

pub fn served_identity() -> Result<Option<ServedIdentity>> {
    use aether::certificates::encoding::DerCertificate;

    let (Ok(tls_der), Ok(pq_json), Ok(client_ca_der)) = (
        std::fs::read(CERTIFICATE_PATH),
        std::fs::read(PQ_CERTIFICATE_PATH),
        std::fs::read(CLIENT_CA_PATH),
    ) else {
        return Ok(None);
    };
    let pq_certificate: PqCertificate = serde_json::from_slice(&pq_json)
        .with_context(|| format!("reading {PQ_CERTIFICATE_PATH}"))?;
    Ok(Some(ServedIdentity {
        tls_certificate: DerCertificate::new(tls_der)
            .with_context(|| format!("reading {CERTIFICATE_PATH}"))?,
        pq_certificate,
        client_tls_ca: DerCertificate::new(client_ca_der)
            .with_context(|| format!("reading {CLIENT_CA_PATH}"))?,
    }))
}

/// Reads the public certificates the API republishes to the operator tooling.
///
/// Deliberately independent from [`start`]: it opens neither the TPM nor the
/// sealed keystore, and only touches files that are public by construction.
/// A gateway whose identity has not been created yet simply has nothing to
/// publish — that is `None`, not an error, because it is the ordinary state
/// before `heliosd init-key-negotiation`.
pub fn public_material() -> Result<Option<helios_api::KeyNegotiationMaterial>> {
    let (Ok(certificate_der), Ok(pq_certificate_json)) = (
        std::fs::read(CERTIFICATE_PATH),
        std::fs::read(PQ_CERTIFICATE_PATH),
    ) else {
        return Ok(None);
    };
    Ok(Some(helios_api::KeyNegotiationMaterial {
        certificate_der,
        pq_certificate_json,
    }))
}

#[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredPrivateIdentity {
    pub(super) tls_private_key: String,
    pub(super) pq_private_key: String,
}

pub(super) struct LoadedIdentity {
    pub(super) tls: TlsIdentity,
    pub(super) pq_certificate: PqCertificate,
    pub(super) pq_private_key: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ServedIdentitySlot {
    Active,
    Candidate { epoch: u64 },
}

/// The slot this process selected at start-up.
///
/// Set once, when the negotiation listener is built, and read by the lifecycle
/// sweep to answer one question the daemon could not answer before: has the
/// registry moved past what this process is serving? See [`restart_due`].
pub(super) static SERVED_SLOT: std::sync::OnceLock<ServedIdentitySlot> = std::sync::OnceLock::new();

/// Why a restart is due, or `None` while the served leaf is still the right one.
///
/// # Why a signal and not a hot swap
///
/// The served identity is unsealed once and held for the life of the process,
/// deliberately: reloading it would rebuild the QUIC endpoint while
/// negotiations own PSK slots on it. Every scheduled switch is therefore a
/// restart — `activation_at`, `not_after`, and the expiry of a bounded service
/// rollback alike.
///
/// What was missing is not the swap, it is the **notice**. A rollback expires
/// by the clock (§4.4) and nothing restarts the daemon when it does, so the
/// gateway went on presenting the outgoing leaf with no trace of why. This
/// compares, on every sweep, the slot this process chose against the one a
/// fresh start would choose, and says so in the log and on the console.
pub fn restart_due(
    gateway: Option<&aether::certificates::state::GatewayCertificateState>,
    now_unix: u64,
) -> Option<String> {
    let selected = SERVED_SLOT.get()?;
    restart_reason(*selected, served_identity_slot(gateway, now_unix))
}

/// The comparison [`restart_due`] makes, without the process-wide selection.
pub(super) fn restart_reason(
    selected: ServedIdentitySlot,
    fresh: Result<ServedIdentitySlot>,
) -> Option<String> {
    match fresh {
        Ok(fresh) if fresh == selected => None,
        Ok(ServedIdentitySlot::Active) => Some(
            "a service rollback is in force and this process is serving the staged \
             identity; restart to present the outgoing leaf"
                .to_string(),
        ),
        Ok(ServedIdentitySlot::Candidate { epoch }) => Some(format!(
            "gateway identity epoch {epoch} is due and this process is serving the \
             outgoing leaf; restart to present it"
        )),
        // A fresh start would refuse outright — the identity is revoked, or an
        // overlap ran past `not_after` unpromoted. Restarting is exactly what
        // must not be done blind, so the reason travels rather than the verdict.
        Err(error) => Some(format!(
            "a restart would refuse to serve this identity: {error}"
        )),
    }
}

/// Selects the private slot a fresh daemon may serve.
///
/// A staged leaf is never selected merely because the wall clock moved: Astra
/// must first have persisted `published`. At `not_after` the overlap is over,
/// so startup refuses an unpromoted state rather than reviving either side of
/// a decision whose finalization should already be durable.
///
/// A service rollback in force turns the overlap back to the outgoing leaf
/// (spec §4.4). It is read **here**, at startup, because the identity served
/// is unsealed once and held for the life of the process: installing a
/// rollback does not swap the leaf under a running daemon, it decides what the
/// next start serves.
pub(super) fn served_identity_slot(
    gateway: Option<&aether::certificates::state::GatewayCertificateState>,
    now_unix: u64,
) -> Result<ServedIdentitySlot> {
    let Some(gateway) = gateway else {
        return Ok(ServedIdentitySlot::Active);
    };
    select_served_identity_slot(
        gateway.revoked,
        gateway.next_gateway_identity_epoch,
        gateway.activation_at,
        gateway.retire_active_at,
        gateway.published,
        gateway.active_service_rollback(now_unix).is_some(),
        now_unix,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn select_served_identity_slot(
    revoked: bool,
    next_epoch: Option<u64>,
    activation_at: Option<u64>,
    retire_active_at: Option<u64>,
    published: bool,
    rolled_back: bool,
    now_unix: u64,
) -> Result<ServedIdentitySlot> {
    anyhow::ensure!(
        !revoked,
        "the gateway certificate identity is revoked; the negotiation listener stays closed"
    );
    let Some(epoch) = next_epoch else {
        return Ok(ServedIdentitySlot::Active);
    };
    let activation_at = activation_at.context("a staged gateway identity has no activation_at")?;
    let retire_active_at =
        retire_active_at.context("a staged gateway identity has no retire_active_at")?;
    anyhow::ensure!(
        now_unix < retire_active_at,
        "gateway identity epoch {epoch} reached not_after without being promoted"
    );
    if now_unix < activation_at {
        return Ok(ServedIdentitySlot::Active);
    }
    anyhow::ensure!(
        published,
        "gateway identity epoch {epoch} reached activation_at before publication"
    );
    // The selection is bounded and the promotion is not: at `not_after` the
    // ensure above still fires, so a rollback can postpone which leaf is
    // served but never the end of the decision it lives in.
    if rolled_back {
        return Ok(ServedIdentitySlot::Active);
    }
    Ok(ServedIdentitySlot::Candidate { epoch })
}

/// The gateway signs staging receipts with the leaf it already serves.
///
/// Not a second copy of the sealed key: the certificate lifecycle asks the
/// negotiation handler, which unsealed it once at startup and is the only
/// holder for the life of the process.
impl crate::certificates::StageReceiptSigner for GatewayHandler {
    fn sign_stage_receipt(
        &self,
        receipt: aether::certificates::client::GatewayCertificateStageReceipt,
    ) -> Result<
        aether::certificates::client::GatewayCertificateStageReceipt,
        aether::certificates::CertificateError,
    > {
        receipt.sign(&self.gateway_pq_private_key)
    }

    fn served_pq_certificate(&self) -> PqCertificate {
        self.gateway_pq_certificate.clone()
    }
}

/// Object context of the negotiation identity: the gateway WireGuard public
/// key it serves.
///
/// **Limite connue** : ADR-006 §2 demande d'y joindre l'époque du certificat.
/// Aucune époque n'est modelée aujourd'hui — l'ajouter suppose de versionner le
/// certificat de négociation, ce qui relève du lot gateway. La liaison au pair
/// est en place ; la fraîcheur du certificat ne l'est pas encore.
pub(super) fn negotiation_identity_context(gateway_wg_public_key: &str) -> helios_tpm::Context {
    helios_tpm::Context::new().field("gateway_wg_public_key", gateway_wg_public_key.as_bytes())
}

pub(super) fn load_served_identity(
    secret: Option<&SecretKey>,
    dry_run: bool,
    gateway_wg_public_key: &str,
    gateway: Option<&aether::certificates::state::GatewayCertificateState>,
    now_unix: u64,
) -> Result<LoadedIdentity> {
    match served_identity_slot(gateway, now_unix)? {
        ServedIdentitySlot::Active => {
            load_active_identity(secret, dry_run, gateway_wg_public_key, gateway)
        }
        ServedIdentitySlot::Candidate { epoch } => {
            let gateway = gateway.context("candidate selection requires a certificate registry")?;
            let active = load_active_private_identity(secret, dry_run, gateway_wg_public_key)?;
            let candidate = load_candidate_private_identity(
                secret.context(
                    "TPM secret unavailable: the scheduled gateway identity stays sealed",
                )?,
                gateway_wg_public_key,
                epoch,
            )?;
            let stored = compose_private_identity(
                active,
                candidate,
                gateway.next_gateway_tls_certificate.is_some(),
                gateway.next_gateway_certificate.is_some(),
            )?;
            let tls_certificate = gateway
                .next_gateway_tls_certificate
                .as_ref()
                .unwrap_or(&gateway.active_gateway_tls_certificate)
                .as_bytes()
                .to_vec();
            let pq_certificate = gateway
                .next_gateway_certificate
                .as_ref()
                .unwrap_or(&gateway.active_gateway_certificate)
                .clone();
            decode_loaded_identity(stored, tls_certificate, pq_certificate, false)
        }
    }
}

fn load_active_identity(
    secret: Option<&SecretKey>,
    dry_run: bool,
    gateway_wg_public_key: &str,
    gateway: Option<&aether::certificates::state::GatewayCertificateState>,
) -> Result<LoadedIdentity> {
    let stored = load_active_private_identity(secret, dry_run, gateway_wg_public_key)?;
    let (tls_certificate, pq_certificate, verify_self_signed) = match gateway {
        Some(gateway) => (
            gateway.active_gateway_tls_certificate.as_bytes().to_vec(),
            gateway.active_gateway_certificate.clone(),
            false,
        ),
        None => (
            std::fs::read(CERTIFICATE_PATH).context("reading key-negotiation certificate")?,
            serde_json::from_slice(
                &std::fs::read(PQ_CERTIFICATE_PATH)
                    .context("reading key-negotiation PQ certificate")?,
            )
            .context("decoding the key-negotiation PQ certificate")?,
            true,
        ),
    };
    decode_loaded_identity(stored, tls_certificate, pq_certificate, verify_self_signed)
}

pub(super) fn load_active_private_identity(
    secret: Option<&SecretKey>,
    dry_run: bool,
    gateway_wg_public_key: &str,
) -> Result<StoredPrivateIdentity> {
    let encoded = match secret {
        Some(secret) => {
            return load_active_private_identity_with_secret(secret, gateway_wg_public_key)
        }
        None if dry_run => {
            let path = std::env::var("HELIOS_KEY_NEGO_DEV_KEY_DER")
                .context("HELIOS_KEY_NEGO_DEV_KEY_DER is required in dev mode")?;
            check_private_permissions(Path::new(&path))?;
            std::fs::read(path).context("reading development key-negotiation private key")?
        }
        None => anyhow::bail!("TPM secret unavailable: key-negotiation identity stays sealed"),
    };
    serde_json::from_slice(&encoded).context("decoding the sealed key-negotiation identity")
}

pub(super) fn load_active_private_identity_with_secret(
    secret: &SecretKey,
    gateway_wg_public_key: &str,
) -> Result<StoredPrivateIdentity> {
    let encoded = SealedKeystore::new(
        PRIVATE_KEYSTORE_PATH,
        helios_tpm::DOMAIN_KEY_NEGOTIATION_IDENTITY,
    )
    .load(secret, &negotiation_identity_context(gateway_wg_public_key))
    .context("unsealing key-negotiation private key")?;
    serde_json::from_slice(&encoded).context("decoding the sealed key-negotiation identity")
}

pub(super) fn load_candidate_private_identity(
    secret: &SecretKey,
    gateway_wg_public_key: &str,
    gateway_identity_epoch: u64,
) -> Result<StoredCandidateIdentity> {
    let encoded = SealedKeystore::new(
        next_private_keystore_path(),
        helios_tpm::DOMAIN_KEY_NEGOTIATION_IDENTITY,
    )
    .load(
        secret,
        &candidate_identity_context(gateway_wg_public_key, gateway_identity_epoch),
    )
    .context("unsealing the candidate gateway identity")?;
    serde_json::from_slice(&encoded).context("decoding the candidate gateway identity")
}

pub(super) fn compose_private_identity(
    active: StoredPrivateIdentity,
    candidate: StoredCandidateIdentity,
    rotate_tls: bool,
    rotate_pq: bool,
) -> Result<StoredPrivateIdentity> {
    let tls_private_key = if rotate_tls {
        candidate.tls_private_key.as_ref().cloned().context(
            "the transition rotates TLS, but the sealed candidate has no TLS private key",
        )?
    } else {
        active.tls_private_key.clone()
    };
    let pq_private_key = if rotate_pq {
        candidate.pq_private_key.clone()
    } else {
        active.pq_private_key.clone()
    };
    Ok(StoredPrivateIdentity {
        tls_private_key,
        pq_private_key,
    })
}

fn decode_loaded_identity(
    private_identity: StoredPrivateIdentity,
    tls_certificate: Vec<u8>,
    pq_certificate: PqCertificate,
    verify_self_signed: bool,
) -> Result<LoadedIdentity> {
    let tls_private_key = base64::engine::general_purpose::STANDARD
        .decode(&private_identity.tls_private_key)
        .context("decoding the sealed TLS private key")?;
    let pq_private_key = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(&private_identity.pq_private_key)
            .context("decoding the sealed PQ private key")?,
    );
    if verify_self_signed {
        pq_certificate
            .verify_self_signed(
                PqCertificateRole::Gateway,
                None,
                &pq_certificate.wireguard_public_key,
                unix_time_now()?,
            )
            .context("verifying the gateway PQ certificate")?;
    }
    Ok(LoadedIdentity {
        tls: TlsIdentity {
            certificate_chain: vec![tls_certificate],
            private_key: tls_private_key,
        },
        pq_certificate,
        pq_private_key,
    })
}

#[cfg(unix)]
fn check_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    anyhow::ensure!(
        mode & 0o077 == 0,
        "development private key permissions are {mode:o}; expected 0600 or stricter"
    );
    Ok(())
}

#[cfg(not(unix))]
fn check_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Creates the gateway TLS key locally, seals it, and installs public trust
/// material. The private key never exists as a plaintext filesystem object.
pub fn initialize(
    server_name: &str,
    gateway_wg_public_key: &str,
    client_ca_path: &Path,
    client_pq_ca_path: &Path,
    boot: &BootDecision,
    rotate: bool,
) -> Result<InitializedIdentity> {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};

    let certificate_path = std::path::PathBuf::from(CERTIFICATE_PATH);
    let client_ca_destination = std::path::PathBuf::from(CLIENT_CA_PATH);
    let bootstrap_request_path = std::path::PathBuf::from(GATEWAY_BOOTSTRAP_REQUEST_PATH);
    let client_pq_ca_destination = std::path::PathBuf::from(CLIENT_PQ_CA_PATH);
    let keystore = SealedKeystore::new(
        PRIVATE_KEYSTORE_PATH,
        helios_tpm::DOMAIN_KEY_NEGOTIATION_IDENTITY,
    );
    let already_initialized = keystore.exists()
        || certificate_path.exists()
        || client_ca_destination.exists()
        || std::path::Path::new(PQ_CERTIFICATE_PATH).exists()
        || bootstrap_request_path.exists()
        || client_pq_ca_destination.exists();
    anyhow::ensure!(
        rotate || !already_initialized,
        "a key-negotiation identity already exists; use --rotate to replace it explicitly"
    );
    let secret = boot
        .secret()
        .context("TPM secret unavailable: cannot seal the key-negotiation identity")?;
    let client_ca = std::fs::read(client_ca_path)
        .with_context(|| format!("reading client CA {}", client_ca_path.display()))?;
    let client_pq_ca = std::fs::read(client_pq_ca_path)
        .with_context(|| format!("reading client PQ CA {}", client_pq_ca_path.display()))?;
    anyhow::ensure!(
        client_pq_ca.len() == aether::key_negotiation::ML_DSA_87_PUBLIC_KEY_LEN,
        "client PQ CA public key is {} bytes; an ML-DSA-87 public key is {}",
        client_pq_ca.len(),
        aether::key_negotiation::ML_DSA_87_PUBLIC_KEY_LEN
    );
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(client_ca.clone()))
        .context("client CA is not a valid DER certificate")?;

    let mut params = CertificateParams::new(vec![server_name.trim().to_string()])
        .context("server name is not valid for an X.509 certificate")?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(825);
    let key_pair = KeyPair::generate().context("generating the gateway TLS key")?;
    let certificate = params
        .self_signed(&key_pair)
        .context("creating the gateway TLS certificate")?;
    let tls_private_key = Zeroizing::new(key_pair.serialize_der());
    let (pq_private_key, pq_public_key) =
        generate_ml_dsa_87_keypair().context("generating the gateway PQ identity")?;
    aether::wg::validate_key(gateway_wg_public_key)
        .context("gateway WireGuard identity is unavailable")?;
    let bootstrap_request = aether::certificates::gateway::GatewayBootstrapRequest {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        gateway_wg_public_key: aether::certificates::encoding::WireGuardKey::parse(
            gateway_wg_public_key,
        )
        .context("reading the gateway WireGuard identity")?,
        server_name: server_name.trim().to_string(),
        ml_dsa_87_public_key: aether::certificates::encoding::MlDsa87PublicKey::parse(
            &base64::engine::general_purpose::STANDARD.encode(pq_public_key),
        )
        .context("reading the generated gateway PQ public key")?,
        key_possession_proof: aether::certificates::encoding::MlDsa87Signature::placeholder(),
    }
    .sign(pq_private_key.as_slice())
    .context("signing the gateway bootstrap request")?;
    let private_identity = Zeroizing::new(
        serde_json::to_vec(&StoredPrivateIdentity {
            tls_private_key: base64::engine::general_purpose::STANDARD
                .encode(tls_private_key.as_slice()),
            pq_private_key: base64::engine::general_purpose::STANDARD
                .encode(pq_private_key.as_slice()),
        })
        .context("encoding the private key-negotiation identity")?,
    );
    keystore
        .store(
            secret,
            &negotiation_identity_context(gateway_wg_public_key),
            private_identity.as_slice(),
        )
        .context("sealing the gateway TLS and PQ keys")?;

    write_public_atomic(&certificate_path, certificate.der().as_ref())
        .context("installing the gateway TLS certificate")?;
    write_public_atomic(&client_ca_destination, &client_ca)
        .context("installing the Orion client CA")?;
    write_public_atomic(
        &bootstrap_request_path,
        &serde_json::to_vec_pretty(&bootstrap_request)
            .context("encoding the gateway bootstrap request")?,
    )
    .context("installing the gateway bootstrap request")?;
    // A replacement must not leave the previous self-signed leaf looking like
    // the answer to this new request. Without a registry the loader still
    // requires self-signature, so absence fails closed until CA-PQ answers;
    // with a registry, the persisted active leaf remains authoritative.
    remove_if_present(Path::new(PQ_CERTIFICATE_PATH))
        .context("retiring the previous gateway PQ certificate")?;
    write_public_atomic(&client_pq_ca_destination, &client_pq_ca)
        .context("installing the Orion client PQ CA")?;

    if rotate {
        tracing::warn!(
            "key-negotiation identity replaced; a CA-PQ bootstrap leaf must be issued before restart"
        );
    }
    Ok(InitializedIdentity {
        certificate_sha256: aether_key_negotiation::certificate_fingerprint_der(
            certificate.der().as_ref(),
        ),
        certificate_path,
        bootstrap_request_fingerprint: bootstrap_request.fingerprint().to_hex(),
        bootstrap_request_path,
    })
}
