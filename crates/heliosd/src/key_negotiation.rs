//! Gateway integration of the public key-negotiation service.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
};

use aether::{
    key_negotiation::{
        authenticate_commit, authenticate_response, generate_ml_dsa_65_keypair,
        issue_pq_certificate, AuthenticatedKeyNegotiationCommit,
        AuthenticatedKeyNegotiationConfirmation, AuthenticatedKeyNegotiationRequest, PqCertificate,
        PqCertificateRole, ProtectionMode, PQ_CERTIFICATE_VERSION,
    },
    InstallPskRequest, NetworkConfig, SecretString,
};
use anyhow::{Context, Result};
use base64::Engine as _;
use helio_tpm::{BootDecision, SealedKeystore};
use helios_key_negotiation::{
    prepare_key_material, server_endpoint, NegotiationHandler, PreparedNegotiation, PublicError,
    TlsIdentity, DEFAULT_CONFIRMATION_TIMEOUT,
};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use zeroize::Zeroizing;

const CERTIFICATE_PATH: &str = "/var/lib/helios/key-negotiation-cert.der";
const CLIENT_CA_PATH: &str = "/var/lib/helios/key-negotiation-client-ca.der";
const PQ_CERTIFICATE_PATH: &str = "/var/lib/helios/key-negotiation-pq-cert.json";
const CLIENT_PQ_CA_PATH: &str = "/var/lib/helios/key-negotiation-client-pq-ca-public.bin";
const PRIVATE_KEYSTORE_PATH: &str = "/var/lib/helios/key-negotiation-key.sealed";
const MAX_REPLAY_IDENTIFIERS: usize = 4096;

pub struct InitializedIdentity {
    pub certificate_path: std::path::PathBuf,
    pub certificate_sha256: String,
    pub pq_certificate_path: std::path::PathBuf,
    pub pq_certificate_sha256: String,
}

struct Transaction {
    public_key: String,
    address: String,
    previous_psk: Option<String>,
    client_pq_public_key: String,
    mode: ProtectionMode,
}

#[derive(Default)]
struct TransactionState {
    active: HashMap<[u8; 16], Transaction>,
    /// Tunnels whose transaction committed and whose link is still open.
    ///
    /// Kept so the slot can be released the moment the client hangs up:
    /// `active` is emptied at commit, and without this the gateway would have
    /// nothing left to tie a closing link to.
    committed: HashMap<[u8; 16], (String, String)>,
    peers: HashSet<String>,
    replay_order: VecDeque<[u8; 16]>,
    replay_set: HashSet<[u8; 16]>,
}

struct GatewayHandler {
    network: Arc<RwLock<NetworkConfig>>,
    psk_tx: mpsc::Sender<InstallPskRequest>,
    gateway_public_key: String,
    client_pq_ca_public_key: Vec<u8>,
    gateway_pq_certificate: PqCertificate,
    gateway_pq_private_key: Zeroizing<Vec<u8>>,
    dry_run: bool,
    static_psks: RwLock<HashMap<String, String>>,
    transactions: Mutex<TransactionState>,
}

fn elevate_security_floor(
    network: &mut NetworkConfig,
    public_key: &str,
    mode: ProtectionMode,
) -> Result<Option<ProtectionMode>, PublicError> {
    let peer = network
        .peers
        .iter_mut()
        .find(|peer| peer.public_key == public_key)
        .ok_or(PublicError::Rejected)?;
    if mode == peer.minimum_key_negotiation_mode
        || !mode.satisfies(peer.minimum_key_negotiation_mode)
    {
        return Ok(None);
    }
    let previous = peer.minimum_key_negotiation_mode;
    peer.minimum_key_negotiation_mode = mode;
    Ok(Some(previous))
}

impl GatewayHandler {
    async fn install(
        &self,
        public_key: String,
        address: String,
        psk: Option<SecretString>,
    ) -> Result<(), PublicError> {
        let (reply, response) = oneshot::channel();
        self.psk_tx
            .send(InstallPskRequest {
                public_key,
                address,
                psk,
                reply,
            })
            .await
            .map_err(|_| PublicError::DataPlane)?;
        response
            .await
            .map_err(|_| PublicError::DataPlane)?
            .map_err(|_| PublicError::DataPlane)
    }

    async fn release_peer(&self, transaction_id: [u8; 16]) -> Option<Transaction> {
        let mut state = self.transactions.lock().await;
        let transaction = state.active.remove(&transaction_id)?;
        state.peers.remove(&transaction.public_key);
        Some(transaction)
    }

    async fn raise_security_floor(
        &self,
        public_key: &str,
        mode: ProtectionMode,
    ) -> Result<(), PublicError> {
        let mut network = self.network.write().await;
        let Some(previous) = elevate_security_floor(&mut network, public_key, mode)? else {
            return Ok(());
        };

        let mut on_disk = network.clone();
        if !self.dry_run {
            on_disk.wg_private_key.clear();
        }
        for peer in &mut on_disk.peers {
            peer.preshared_key = None;
        }
        if on_disk.save().is_err() {
            if let Some(peer) = network
                .peers
                .iter_mut()
                .find(|peer| peer.public_key == public_key)
            {
                peer.minimum_key_negotiation_mode = previous;
            }
            return Err(PublicError::DataPlane);
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl NegotiationHandler for GatewayHandler {
    async fn prepare(
        &self,
        certificate_sha256: String,
        authenticated: AuthenticatedKeyNegotiationRequest,
    ) -> Result<PreparedNegotiation, PublicError> {
        let request = &authenticated.request;
        request.validate().map_err(|_| PublicError::Protocol)?;
        let (address, previous_psk, pq_fingerprint, minimum_mode) = {
            let network = self.network.read().await;
            let peer = network
                .peers
                .iter()
                .find(|peer| peer.public_key == request.client_wg_public_key)
                .ok_or(PublicError::Rejected)?;
            if peer.key_negotiation_certificate_sha256.as_deref()
                != Some(certificate_sha256.as_str())
            {
                return Err(PublicError::IdentityMismatch);
            }
            (
                peer.address.clone(),
                peer.preshared_key.clone(),
                peer.key_negotiation_pq_certificate_sha256
                    .clone()
                    .ok_or(PublicError::IdentityMismatch)?,
                peer.minimum_key_negotiation_mode,
            )
        };
        if !request.mode.satisfies(minimum_mode) {
            return Err(PublicError::Downgrade);
        }
        authenticated
            .verify(
                &self.client_pq_ca_public_key,
                &pq_fingerprint,
                unix_time_now().map_err(|_| PublicError::Protocol)?,
            )
            .map_err(|_| PublicError::IdentityMismatch)?;
        let baseline_static_psk = self
            .static_psks
            .read()
            .await
            .get(&request.client_wg_public_key)
            .cloned();
        let current_matches_static_request = request
            .static_psk_fingerprint
            .as_deref()
            .zip(previous_psk.as_deref())
            .is_some_and(|(requested, current)| {
                aether::key_negotiation::static_psk_fingerprint(current)
                    .is_ok_and(|actual| actual == requested)
            });
        let configured_static_psk = if current_matches_static_request {
            previous_psk.as_deref()
        } else {
            baseline_static_psk.as_deref()
        };

        {
            let mut state = self.transactions.lock().await;
            if state.replay_set.contains(&request.transaction_id) {
                return Err(PublicError::Rejected);
            }
            if !state.peers.insert(request.client_wg_public_key.clone()) {
                return Err(PublicError::Busy);
            }
            state.replay_set.insert(request.transaction_id);
            state.replay_order.push_back(request.transaction_id);
            while state.replay_order.len() > MAX_REPLAY_IDENTIFIERS {
                if let Some(expired) = state.replay_order.pop_front() {
                    state.replay_set.remove(&expired);
                }
            }
        }

        let gateway_nonce = random_nonce().map_err(|_| PublicError::Protocol)?;
        let material = match prepare_key_material(
            request,
            &self.gateway_public_key,
            gateway_nonce,
            configured_static_psk,
            DEFAULT_CONFIRMATION_TIMEOUT,
        ) {
            Ok(material) => material,
            Err(error) => {
                let mut state = self.transactions.lock().await;
                state.peers.remove(&request.client_wg_public_key);
                return Err(error);
            }
        };

        if let Err(error) = self
            .install(
                request.client_wg_public_key.clone(),
                address.clone(),
                material.psk,
            )
            .await
        {
            let mut state = self.transactions.lock().await;
            state.peers.remove(&request.client_wg_public_key);
            return Err(error);
        }
        if request.mode == ProtectionMode::StaticPsk && current_matches_static_request {
            if let Some(static_psk) = previous_psk.clone() {
                self.static_psks
                    .write()
                    .await
                    .insert(request.client_wg_public_key.clone(), static_psk);
            }
        }

        self.transactions.lock().await.active.insert(
            request.transaction_id,
            Transaction {
                public_key: request.client_wg_public_key.clone(),
                address,
                previous_psk,
                client_pq_public_key: authenticated.certificate.ml_dsa_65_public_key.clone(),
                mode: request.mode,
            },
        );
        let response = authenticate_response(
            material.response,
            self.gateway_pq_certificate.clone(),
            self.gateway_pq_private_key.as_slice(),
        )
        .map_err(|_| PublicError::Protocol)?;
        Ok(PreparedNegotiation {
            response,
            confirmation_timeout: DEFAULT_CONFIRMATION_TIMEOUT,
        })
    }

    async fn confirm(
        &self,
        confirmation: AuthenticatedKeyNegotiationConfirmation,
    ) -> Result<AuthenticatedKeyNegotiationCommit, PublicError> {
        let transaction_id = confirmation.confirmation.transaction_id;
        let (client_pq_public_key, public_key, mode) = self
            .transactions
            .lock()
            .await
            .active
            .get(&transaction_id)
            .map(|transaction| {
                (
                    transaction.client_pq_public_key.clone(),
                    transaction.public_key.clone(),
                    transaction.mode,
                )
            })
            .ok_or(PublicError::Rejected)?;
        confirmation
            .verify(&client_pq_public_key)
            .map_err(|_| PublicError::IdentityMismatch)?;
        self.raise_security_floor(&public_key, mode).await?;
        let transaction = self
            .release_peer(transaction_id)
            .await
            .ok_or(PublicError::Rejected)?;
        self.transactions.lock().await.committed.insert(
            transaction_id,
            (transaction.public_key.clone(), transaction.address.clone()),
        );
        authenticate_commit(transaction_id, self.gateway_pq_private_key.as_slice())
            .map_err(|_| PublicError::Protocol)
    }

    /// Releases the slot as soon as the client hangs up.
    ///
    /// The alternative is waiting for WireGuard handshakes to go stale — up to
    /// 150 s during which the gateway holds a post-quantum secret for a peer
    /// that is gone. The link closing is a far better signal than silence, and
    /// it also covers a client that crashed rather than disconnected cleanly.
    ///
    /// Clearing the slot is safe because it cannot strand anybody: the peer's
    /// floor is at `ml_kem`, so its next tunnel has to negotiate a fresh PSK
    /// anyway. A link that dropped on its own leads the client to renegotiate,
    /// and both ends converge on a new secret.
    async fn disconnected(&self, transaction_id: [u8; 16]) {
        let Some((public_key, address)) = self
            .transactions
            .lock()
            .await
            .committed
            .remove(&transaction_id)
        else {
            return;
        };
        tracing::info!(
            peer = %public_key,
            "key-negotiation link closed: releasing the PSK slot without waiting for handshakes"
        );
        if self.install(public_key, address, None).await.is_err() {
            tracing::warn!("could not release the PSK slot after the client disconnected");
        }
    }

    async fn rollback(&self, transaction_id: [u8; 16]) {
        let Some(transaction) = self.release_peer(transaction_id).await else {
            return;
        };
        let psk = transaction.previous_psk.map(SecretString::new);
        if self
            .install(transaction.public_key, transaction.address, psk)
            .await
            .is_err()
        {
            tracing::error!(
                "key-negotiation rollback failed; peer remains fail-closed until operator action"
            );
        }
    }
}

pub async fn start(
    network: Arc<RwLock<NetworkConfig>>,
    psk_tx: mpsc::Sender<InstallPskRequest>,
    boot: &BootDecision,
    dry_run: bool,
) -> Result<()> {
    let (port, gateway_private_key, static_psks) = {
        let network = network.read().await;
        // No port declared, no service. This used to be an error, back when
        // the negotiation was a build flag: a binary carrying the feature and
        // a configuration ignoring it looked like a contradiction worth
        // refusing to start over. Every binary carries it now, so the absence
        // of a port is simply the ordinary state of a gateway that has not
        // opened it — and refusing to start would take down every gateway
        // that upgrades.
        let Some(port) = network.key_negotiation_port else {
            tracing::info!(
                "key_negotiation_port absent: the pre-WireGuard negotiation stays closed"
            );
            return Ok(());
        };
        let static_psks = network
            .peers
            .iter()
            .filter_map(|peer| {
                peer.preshared_key
                    .clone()
                    .map(|psk| (peer.public_key.clone(), psk))
            })
            .collect();
        (port, network.wg_private_key.clone(), static_psks)
    };
    let gateway_public_key = aether::wg::public_from_private(&gateway_private_key)
        .context("gateway WireGuard identity is unavailable for key negotiation")?;
    let identity = load_identity(boot, dry_run)?;
    let client_ca =
        std::fs::read(CLIENT_CA_PATH).context("reading key-negotiation client CA certificate")?;
    let endpoint = server_endpoint(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
        &identity.tls,
        client_ca,
    )
    .context("binding the key-negotiation QUIC listener")?;
    let handler = Arc::new(GatewayHandler {
        network,
        psk_tx,
        gateway_public_key,
        client_pq_ca_public_key: std::fs::read(CLIENT_PQ_CA_PATH)
            .context("reading key-negotiation client PQ CA public key")?,
        gateway_pq_certificate: identity.pq_certificate,
        gateway_pq_private_key: identity.pq_private_key,
        dry_run,
        static_psks: RwLock::new(static_psks),
        transactions: Mutex::new(TransactionState::default()),
    });
    tracing::info!("key-negotiation listening on UDP {port}");
    tokio::spawn(helios_key_negotiation::serve(endpoint, handler));
    Ok(())
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

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPrivateIdentity {
    tls_private_key: String,
    pq_private_key: String,
}

struct LoadedIdentity {
    tls: TlsIdentity,
    pq_certificate: PqCertificate,
    pq_private_key: Zeroizing<Vec<u8>>,
}

fn load_identity(boot: &BootDecision, dry_run: bool) -> Result<LoadedIdentity> {
    let certificate =
        std::fs::read(CERTIFICATE_PATH).context("reading key-negotiation certificate")?;
    let private_identity = match boot.secret() {
        Some(secret) => SealedKeystore::new(PRIVATE_KEYSTORE_PATH)
            .load(secret)
            .context("unsealing key-negotiation private key")?
            .to_vec(),
        None if dry_run => {
            let path = std::env::var("HELIOS_KEY_NEGO_DEV_KEY_DER")
                .context("HELIOS_KEY_NEGO_DEV_KEY_DER is required in dev mode")?;
            check_private_permissions(Path::new(&path))?;
            std::fs::read(path).context("reading development key-negotiation private key")?
        }
        None => anyhow::bail!("TPM secret unavailable: key-negotiation identity stays sealed"),
    };
    let private_identity: StoredPrivateIdentity = serde_json::from_slice(&private_identity)
        .context("decoding the sealed key-negotiation identity")?;
    let tls_private_key = base64::engine::general_purpose::STANDARD
        .decode(private_identity.tls_private_key)
        .context("decoding the sealed TLS private key")?;
    let pq_private_key = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(private_identity.pq_private_key)
            .context("decoding the sealed PQ private key")?,
    );
    let pq_certificate: PqCertificate = serde_json::from_slice(
        &std::fs::read(PQ_CERTIFICATE_PATH).context("reading key-negotiation PQ certificate")?,
    )
    .context("decoding the key-negotiation PQ certificate")?;
    pq_certificate
        .verify_self_signed(
            PqCertificateRole::Gateway,
            None,
            &pq_certificate.wireguard_public_key,
            unix_time_now()?,
        )
        .context("verifying the gateway PQ certificate")?;
    Ok(LoadedIdentity {
        tls: TlsIdentity {
            certificate_chain: vec![certificate],
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

fn random_nonce() -> Result<[u8; 16]> {
    use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
    let mut nonce = [0u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| anyhow::anyhow!("system CSPRNG unavailable"))?;
    Ok(nonce)
}

fn unix_time_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock predates the Unix epoch")?
        .as_secs())
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
    let pq_certificate_path = std::path::PathBuf::from(PQ_CERTIFICATE_PATH);
    let client_pq_ca_destination = std::path::PathBuf::from(CLIENT_PQ_CA_PATH);
    let keystore = SealedKeystore::new(PRIVATE_KEYSTORE_PATH);
    let already_initialized = keystore.exists()
        || certificate_path.exists()
        || client_ca_destination.exists()
        || pq_certificate_path.exists()
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
        client_pq_ca.len() == aether::sig::ML_DSA_65_PUBLIC_KEY_LEN,
        "client PQ CA public key has an invalid ML-DSA-65 length"
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
        generate_ml_dsa_65_keypair().context("generating the gateway PQ identity")?;
    let now = unix_time_now()?;
    aether::wg::validate_key(gateway_wg_public_key)
        .context("gateway WireGuard identity is unavailable")?;
    let pq_certificate = issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: random_nonce()?,
            subject: server_name.trim().to_string(),
            issuer: server_name.trim().to_string(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: gateway_wg_public_key.to_string(),
            ml_dsa_65_public_key: base64::engine::general_purpose::STANDARD.encode(pq_public_key),
            not_before_unix: now.saturating_sub(300),
            not_after_unix: now + 825 * 24 * 60 * 60,
            ml_dsa_65_signature: String::new(),
        },
        pq_private_key.as_slice(),
    )
    .context("creating the gateway PQ certificate")?;
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
        .store(secret, private_identity.as_slice())
        .context("sealing the gateway TLS and PQ keys")?;

    write_public_atomic(&certificate_path, certificate.der().as_ref())
        .context("installing the gateway TLS certificate")?;
    write_public_atomic(&client_ca_destination, &client_ca)
        .context("installing the Orion client CA")?;
    write_public_atomic(
        &pq_certificate_path,
        &serde_json::to_vec_pretty(&pq_certificate)
            .context("encoding the gateway PQ certificate")?,
    )
    .context("installing the gateway PQ certificate")?;
    write_public_atomic(&client_pq_ca_destination, &client_pq_ca)
        .context("installing the Orion client PQ CA")?;

    if rotate {
        tracing::warn!(
            "key-negotiation identity rotated; Orion profiles must trust the new certificate"
        );
    }
    Ok(InitializedIdentity {
        certificate_sha256: helios_key_negotiation::certificate_fingerprint_der(
            certificate.der().as_ref(),
        ),
        certificate_path,
        pq_certificate_sha256: pq_certificate.fingerprint()?,
        pq_certificate_path,
    })
}

fn write_public_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, contents)
        .with_context(|| format!("writing {}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("atomically replacing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Horloge des tests : les requêtes doivent être fraîches pour passer la
    /// fenêtre anti-rejeu.
    fn test_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    use aether::key_negotiation::{
        authenticate_request, generate_ml_dsa_65_keypair, issue_pq_certificate,
        AuthenticatedKeyNegotiationRequest, KeyNegotiationRequest, PqCertificate,
        PqCertificateRole, ProtectionMode, KEY_NEGOTIATION_VERSION, PQ_CERTIFICATE_VERSION,
    };
    const CLIENT_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const GATEWAY_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const CERTIFICATE_FINGERPRINT: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct PqFixture {
        client_ca_public_key: Vec<u8>,
        client_certificate: PqCertificate,
        client_private_key: Vec<u8>,
        gateway_certificate: PqCertificate,
        gateway_private_key: Vec<u8>,
    }

    fn certificate(
        subject: &str,
        role: PqCertificateRole,
        wireguard_key: &str,
        public_key: &[u8],
        issuer_private_key: &[u8],
    ) -> PqCertificate {
        issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [8; 16],
                subject: subject.into(),
                issuer: "test-ca".into(),
                role,
                wireguard_public_key: wireguard_key.into(),
                ml_dsa_65_public_key: base64::engine::general_purpose::STANDARD.encode(public_key),
                not_before_unix: 1,
                not_after_unix: u64::MAX,
                ml_dsa_65_signature: String::new(),
            },
            issuer_private_key,
        )
        .unwrap()
    }

    fn pq_fixture() -> PqFixture {
        let (ca_private, ca_public) = generate_ml_dsa_65_keypair().unwrap();
        let (client_private, client_public) = generate_ml_dsa_65_keypair().unwrap();
        let client_certificate = certificate(
            "orion",
            PqCertificateRole::Client,
            CLIENT_KEY,
            &client_public,
            ca_private.as_slice(),
        );
        let (gateway_private, gateway_public) = generate_ml_dsa_65_keypair().unwrap();
        let gateway_certificate = certificate(
            "gateway",
            PqCertificateRole::Gateway,
            GATEWAY_KEY,
            &gateway_public,
            gateway_private.as_slice(),
        );
        PqFixture {
            client_ca_public_key: ca_public,
            client_certificate,
            client_private_key: client_private.to_vec(),
            gateway_certificate,
            gateway_private_key: gateway_private.to_vec(),
        }
    }

    fn request(
        transaction_id: [u8; 16],
        fixture: &PqFixture,
    ) -> AuthenticatedKeyNegotiationRequest {
        let request = KeyNegotiationRequest {
            protocol_version: KEY_NEGOTIATION_VERSION,
            transaction_id,
            mode: ProtectionMode::Classic,
            client_wg_public_key: CLIENT_KEY.to_string(),
            client_nonce: [2; 16],
            timestamp_unix: test_now(),
            kem_public_key: None,
            static_psk_fingerprint: None,
        };
        authenticate_request(
            request,
            fixture.client_certificate.clone(),
            &fixture.client_private_key,
        )
        .unwrap()
    }

    fn network(previous_psk: &str, pq_fingerprint: &str) -> NetworkConfig {
        let mut network = NetworkConfig::default();
        network.peers.push(aether::WgPeer {
            name: "orion".into(),
            public_key: CLIENT_KEY.into(),
            address: "100.64.1.2/32".into(),
            admin: false,
            preshared_key: Some(previous_psk.into()),
            key_negotiation_certificate_sha256: Some(CERTIFICATE_FINGERPRINT.into()),
            key_negotiation_pq_certificate_sha256: Some(pq_fingerprint.into()),
            minimum_key_negotiation_mode: ProtectionMode::Classic,
        });
        network
    }

    #[tokio::test]
    async fn unconfirmed_transaction_restores_the_previous_slot() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let shared = Arc::new(RwLock::new(network(
            &previous_psk,
            &fixture.client_certificate.fingerprint().unwrap(),
        )));
        let (tx, mut rx) = mpsc::channel::<InstallPskRequest>(4);
        let applied = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
        let observed = Arc::clone(&applied);
        tokio::spawn(async move {
            while let Some(request) = rx.recv().await {
                observed
                    .lock()
                    .await
                    .push(request.psk.map(|secret| secret.expose().to_string()));
                let _ = request.reply.send(Ok(()));
            }
        });
        let handler = GatewayHandler {
            network: shared,
            psk_tx: tx,
            gateway_public_key: GATEWAY_KEY.into(),
            client_pq_ca_public_key: fixture.client_ca_public_key.clone(),
            gateway_pq_certificate: fixture.gateway_certificate.clone(),
            gateway_pq_private_key: Zeroizing::new(fixture.gateway_private_key.clone()),
            dry_run: true,
            static_psks: RwLock::new(HashMap::from([(CLIENT_KEY.into(), previous_psk.clone())])),
            transactions: Mutex::new(TransactionState::default()),
        };

        handler
            .prepare(CERTIFICATE_FINGERPRINT.into(), request([1; 16], &fixture))
            .await
            .unwrap();
        handler.rollback([1; 16]).await;

        assert_eq!(
            *applied.lock().await,
            vec![None, Some(previous_psk)],
            "classic preparation must clear the slot and rollback must restore it"
        );
    }

    #[tokio::test]
    async fn certificate_mismatch_never_reaches_the_data_plane() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let shared = Arc::new(RwLock::new(network(
            &previous_psk,
            &fixture.client_certificate.fingerprint().unwrap(),
        )));
        let (tx, mut rx) = mpsc::channel::<InstallPskRequest>(1);
        let handler = GatewayHandler {
            network: shared,
            psk_tx: tx,
            gateway_public_key: GATEWAY_KEY.into(),
            client_pq_ca_public_key: fixture.client_ca_public_key.clone(),
            gateway_pq_certificate: fixture.gateway_certificate.clone(),
            gateway_pq_private_key: Zeroizing::new(fixture.gateway_private_key.clone()),
            dry_run: true,
            static_psks: RwLock::new(HashMap::new()),
            transactions: Mutex::new(TransactionState::default()),
        };

        assert!(matches!(
            handler
                .prepare("b".repeat(64), request([3; 16], &fixture))
                .await,
            Err(PublicError::IdentityMismatch)
        ));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn pq_security_floor_rejects_a_classic_renegotiation() {
        let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let fixture = pq_fixture();
        let mut configured = network(
            &previous_psk,
            &fixture.client_certificate.fingerprint().unwrap(),
        );
        configured.peers[0].minimum_key_negotiation_mode = ProtectionMode::MlKem;
        let shared = Arc::new(RwLock::new(configured));
        let (tx, mut rx) = mpsc::channel::<InstallPskRequest>(1);
        let handler = GatewayHandler {
            network: shared,
            psk_tx: tx,
            gateway_public_key: GATEWAY_KEY.into(),
            client_pq_ca_public_key: fixture.client_ca_public_key.clone(),
            gateway_pq_certificate: fixture.gateway_certificate.clone(),
            gateway_pq_private_key: Zeroizing::new(fixture.gateway_private_key.clone()),
            dry_run: true,
            static_psks: RwLock::new(HashMap::new()),
            transactions: Mutex::new(TransactionState::default()),
        };

        assert!(matches!(
            handler
                .prepare(CERTIFICATE_FINGERPRINT.into(), request([4; 16], &fixture))
                .await,
            Err(PublicError::Downgrade)
        ));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn committed_modes_only_raise_the_persistent_floor() {
        let mut configured = network("static", &"a".repeat(64));
        assert_eq!(
            elevate_security_floor(&mut configured, CLIENT_KEY, ProtectionMode::StaticPsk).unwrap(),
            Some(ProtectionMode::Classic)
        );
        assert_eq!(
            configured.peers[0].minimum_key_negotiation_mode,
            ProtectionMode::StaticPsk
        );
        assert_eq!(
            elevate_security_floor(&mut configured, CLIENT_KEY, ProtectionMode::Classic).unwrap(),
            None
        );
        assert_eq!(
            configured.peers[0].minimum_key_negotiation_mode,
            ProtectionMode::StaticPsk
        );
        assert_eq!(
            elevate_security_floor(&mut configured, CLIENT_KEY, ProtectionMode::MlKem).unwrap(),
            Some(ProtectionMode::StaticPsk)
        );
        assert_eq!(
            configured.peers[0].minimum_key_negotiation_mode,
            ProtectionMode::MlKem
        );
    }

    /// TLS material for the interoperability test.
    ///
    /// One CA signs both leaves, exactly as the operator's does: the gateway
    /// authenticates the client against it, and Orion pins the server
    /// certificate as its trust anchor.
    struct TestTls {
        ca_der: Vec<u8>,
        server: helios_key_negotiation::TlsIdentity,
        client_certificate: Vec<u8>,
        client_key: Vec<u8>,
    }

    fn test_tls() -> TestTls {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            KeyUsagePurpose,
        };

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().unwrap();
        let server_certificate = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();

        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client_certificate = client_params.signed_by(&client_key, &ca, &ca_key).unwrap();

        TestTls {
            ca_der: ca.der().to_vec(),
            server: helios_key_negotiation::TlsIdentity {
                certificate_chain: vec![server_certificate.der().to_vec(), ca.der().to_vec()],
                private_key: server_key.serialize_der(),
            },
            client_certificate: client_certificate.der().to_vec(),
            client_key: client_key.serialize_der(),
        }
    }

    /// Provides the client identity from memory, as the Windows store would.
    struct TestIdentities(orion_core::key_negotiation::ClientIdentity);

    #[async_trait::async_trait]
    impl orion_core::key_negotiation::IdentityProvider for TestIdentities {
        async fn load(
            &self,
            _identity: &str,
        ) -> anyhow::Result<orion_core::key_negotiation::ClientIdentity> {
            Ok(orion_core::key_negotiation::ClientIdentity {
                certificate_chain: self.0.certificate_chain.clone(),
                private_key: self.0.private_key.clone(),
                pq_certificate: self.0.pq_certificate.clone(),
                pq_private_key: self.0.pq_private_key.clone(),
            })
        }
    }

    /// **The interoperability test**: the real gateway handler against the
    /// real Orion client, over a real QUIC socket.
    ///
    /// Unit tests on either side cannot show what matters here. The gateway
    /// derives the PSK from the shared secret it encapsulated; Orion derives
    /// it from the secret it decapsulated. Both call `derive_negotiated_psk`
    /// with what they believe the transcript to be — and if those two beliefs
    /// diverge by one field, both sides still succeed, install *different*
    /// PSKs, and every WireGuard handshake fails afterwards with no error
    /// pointing at the cause. Comparing the two values is the only way to
    /// know they agree.
    #[tokio::test]
    async fn the_gateway_and_orion_derive_the_same_psk() {
        use aether::key_negotiation::PqCertificateRole;

        let gateway_wg = aether::wg::generate_keypair().unwrap();
        let client_wg = aether::wg::generate_keypair().unwrap();

        // PQ identities bound to those WireGuard keys, as the operator CA
        // issues them.
        let (ca_private, ca_public) = generate_ml_dsa_65_keypair().unwrap();
        let (client_pq_private, client_pq_public) = generate_ml_dsa_65_keypair().unwrap();
        let client_pq_certificate = certificate(
            "orion",
            PqCertificateRole::Client,
            &client_wg.public_key,
            &client_pq_public,
            ca_private.as_slice(),
        );
        let (gateway_pq_private, gateway_pq_public) = generate_ml_dsa_65_keypair().unwrap();
        let gateway_pq_certificate = certificate(
            "localhost",
            PqCertificateRole::Gateway,
            &gateway_wg.public_key,
            &gateway_pq_public,
            gateway_pq_private.as_slice(),
        );

        let tls = test_tls();
        let mut network = NetworkConfig::default();
        network.peers.push(aether::WgPeer {
            name: "orion".into(),
            public_key: client_wg.public_key.clone(),
            address: "100.64.1.2/32".into(),
            admin: false,
            preshared_key: None,
            key_negotiation_certificate_sha256: Some(
                helios_key_negotiation::certificate_fingerprint_der(&tls.client_certificate),
            ),
            key_negotiation_pq_certificate_sha256: Some(
                client_pq_certificate.fingerprint().unwrap(),
            ),
            minimum_key_negotiation_mode: ProtectionMode::MlKem,
        });

        // Captures what the gateway actually installs on its data plane.
        let (psk_tx, mut psk_rx) = mpsc::channel::<InstallPskRequest>(4);
        let installed = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
        let observed = Arc::clone(&installed);
        tokio::spawn(async move {
            while let Some(request) = psk_rx.recv().await {
                observed
                    .lock()
                    .await
                    .push(request.psk.map(|secret| secret.expose().to_string()));
                let _ = request.reply.send(Ok(()));
            }
        });

        let handler = Arc::new(GatewayHandler {
            network: Arc::new(RwLock::new(network)),
            psk_tx,
            gateway_public_key: gateway_wg.public_key.clone(),
            client_pq_ca_public_key: ca_public,
            gateway_pq_certificate: gateway_pq_certificate.clone(),
            gateway_pq_private_key: Zeroizing::new(gateway_pq_private.to_vec()),
            dry_run: true,
            static_psks: RwLock::new(HashMap::new()),
            transactions: Mutex::new(TransactionState::default()),
        });

        let server = helios_key_negotiation::server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &tls.server,
            tls.ca_der.clone(),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let served = tokio::spawn(helios_key_negotiation::serve(server, handler));

        // From here on, everything runs through the client Orion actually
        // ships — same module, same code path as a real connection.
        let identities = TestIdentities(orion_core::key_negotiation::ClientIdentity {
            certificate_chain: vec![tls.client_certificate.clone()],
            private_key: tls.client_key.clone(),
            pq_certificate: serde_json::to_vec(&client_pq_certificate).unwrap(),
            pq_private_key: client_pq_private.to_vec(),
        });
        let profile = orion_core::ClientProfile {
            name: "orion".into(),
            endpoint: format!("127.0.0.1:{}", address.port()),
            private_key: client_wg.private_key.expose().to_string(),
            peer_public_key: gateway_wg.public_key.clone(),
            address: Some("100.64.1.2/32".into()),
            key_negotiation: Some(orion_core::KeyNegotiationSettings {
                mode: ProtectionMode::MlKem,
                minimum_mode: ProtectionMode::MlKem,
                endpoint: format!("127.0.0.1:{}", address.port()),
                server_name: "localhost".into(),
                gateway_ca_der: base64::engine::general_purpose::STANDARD.encode(&tls.ca_der),
                gateway_pq_certificate: base64::engine::general_purpose::STANDARD
                    .encode(serde_json::to_vec(&gateway_pq_certificate).unwrap()),
                identity: "orion".into(),
            }),
            ..orion_core::ClientProfile::default()
        };

        let negotiated = orion_core::key_negotiation::prepare_for_profile(&profile, &identities)
            .await
            .expect("Orion negotiates with the real gateway handler");

        let client_psk = negotiated
            .psk
            .as_ref()
            .map(|secret| secret.expose().to_string())
            .expect("ML-KEM yields a PSK");

        // The gateway installs before answering: its value is already here.
        let gateway_psk = installed
            .lock()
            .await
            .last()
            .cloned()
            .flatten()
            .expect("the gateway installed a PSK before replying");

        assert_eq!(
            client_psk, gateway_psk,
            "both ends must derive the same PSK — differing values would fail every \
             WireGuard handshake with nothing to point at the cause"
        );
        // A 32-byte secret, base64: anything shorter would mean a truncated
        // derivation that still compares equal on both sides.
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&client_psk)
                .unwrap()
                .len(),
            32
        );

        negotiated
            .confirm()
            .await
            .expect("the gateway commits the transaction Orion confirms");
        served.abort();
    }
}
