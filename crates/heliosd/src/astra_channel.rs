//! The gateway's end of the private Astra ↔ Helios veth channel (spec §8.3).
//!
//! [`helios_api::internal`] holds the protocol — the four routes, the two TLS
//! configurations, the pinned verifier. This module holds the deployment: where
//! the transport identity lives on this machine, how it is created, and how the
//! listener is started beside the administration API without ever becoming part
//! of it.
//!
//! # One file, and why it is not sealed
//!
//! Everything the channel needs is in a single `0600` document beside
//! `network.toml`: the address to bind, this gateway's certificate and private
//! key, and the exact DER of Astra's certificate. One file because these four
//! values are meaningless apart — a pin without the key it is served beside
//! authenticates nothing — and because a deployment that has to keep four paths
//! in step is a deployment that will not.
//!
//! It is deliberately **not** sealed to the TPM. The key authenticates a
//! process on a link whose two ends the host kernel already owns, so sealing
//! buys nothing against the attacker who matters, while making the lifecycle
//! listener refuse to start on a gateway whose TPM is unavailable — exactly the
//! state `heliosd init-trust-domain` was built to survive. The authorization on
//! this channel is the ML-DSA-87 signature carried by every object, never this
//! key.
//!
//! # Absent means closed, and closed is not broken
//!
//! No file, no listener, and no error: the same rule `key_negotiation_port`
//! follows. A gateway with no authority is a gateway that works — it serves
//! traffic, negotiates PSKs and admits peers — so the absence is reported as
//! one `info` line naming the consequence, not as a startup failure. A file
//! that exists and is unusable **is** reported loudly, because that is an
//! operator error rather than a deployment choice.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aether::certificates::encoding::DerCertificate;
use anyhow::{Context, Result};
use base64::Engine as _;
use helios_api::internal::{AstraChannelHandler, ChannelIdentity};
use serde::{Deserialize, Serialize};

/// Where the channel's configuration and key live.
const ASTRA_CHANNEL_PATH: &str = "/var/lib/helios/astra-channel.json";

/// How long a freshly created transport identity is valid.
///
/// Two years, like the negotiation leaf. It is a service identity (spec §8.3):
/// rotating it re-runs the two `init` commands and touches neither `CA-PQ` nor
/// any client, so a long life costs nothing and a short one would turn a
/// forgotten rotation into a dead authority.
const IDENTITY_VALIDITY_DAYS: i64 = 730;

/// The document `heliosd init-astra-channel` writes.
///
/// `deny_unknown_fields` for the same reason the registry has it: a document
/// this process cannot fully read is a document written by another version, and
/// half-reading it would start a listener whose bounds are not the ones on
/// disk.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredChannel {
    /// Address of the veth end this gateway listens on.
    ///
    /// Never `0.0.0.0`: the point of the channel is that it exists on one
    /// interface with no default route, and a wildcard bind would publish the
    /// lifecycle API on the WAN and on the tunnel as well.
    bind: SocketAddr,
    /// This gateway's transport certificate, DER, base64. Astra pins it.
    certificate: String,
    /// Its PKCS#8 private key, DER, base64. The reason this file is `0600`.
    private_key: String,
    /// Astra's transport certificate, DER, base64. The only client identity
    /// this listener accepts, byte for byte.
    astra_certificate: String,
}

/// A loaded, checked channel: ready to serve.
pub struct AstraChannel {
    pub bind: SocketAddr,
    identity: ChannelIdentity,
    astra_certificate: DerCertificate,
}

fn path() -> PathBuf {
    // Same override as the network configuration and the registry, so a test
    // run never reads or writes the system file.
    std::env::var_os("HELIOS_ASTRA_CHANNEL")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(ASTRA_CHANNEL_PATH))
}

fn decode(field: &str, value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .with_context(|| format!("decoding {field} of the Astra channel document"))
}

impl AstraChannel {
    /// Reads the channel, or reports that this gateway has none.
    ///
    /// `Ok(None)` is a deployment without an authority, which is a supported
    /// state. Every other failure is an error: a document that exists and does
    /// not load means the operator meant to have a channel and does not.
    pub fn load() -> Result<Option<Self>> {
        Self::load_from(&path())
    }

    fn load_from(path: &Path) -> Result<Option<Self>> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        let stored: StoredChannel = serde_json::from_slice(&bytes)
            .with_context(|| format!("decoding {}", path.display()))?;
        anyhow::ensure!(
            !stored.bind.ip().is_unspecified(),
            "the Astra channel is configured to bind {}, which publishes the lifecycle API on \
             every interface including the WAN and the tunnel; name the gateway's veth address",
            stored.bind
        );
        let astra_certificate =
            DerCertificate::new(decode("the Astra certificate", &stored.astra_certificate)?)
                .map_err(|error| anyhow::anyhow!("pinned Astra certificate: {error}"))?;
        Ok(Some(Self {
            bind: stored.bind,
            identity: ChannelIdentity {
                certificate_der: decode("the gateway certificate", &stored.certificate)?,
                private_key_der: decode("the gateway private key", &stored.private_key)?,
            },
            astra_certificate,
        }))
    }

    /// Builds the TLS configuration, refusing a pin that cannot serve.
    fn server_config(&self) -> Result<rustls::ServerConfig> {
        helios_api::internal::server_config(&self.identity, &self.astra_certificate)
            .map_err(|error| anyhow::anyhow!("{error}"))
    }
}

/// Starts the private listener, when this gateway has a channel.
///
/// The listener runs in its own task and its failure is never fatal: the
/// gateway keeps serving traffic, and the certificate lifecycle simply stays on
/// the in-tunnel routes. What is fatal is silence, so both the absence and the
/// failure name their consequence.
pub fn spawn(handler: Arc<dyn AstraChannelHandler>) {
    let channel = match AstraChannel::load() {
        Ok(Some(channel)) => channel,
        Ok(None) => {
            tracing::info!(
                "no Astra channel document: the private lifecycle API stays closed, and the \
                 gateway distributes no pre-signed object"
            );
            return;
        }
        Err(error) => {
            tracing::error!(
                %error,
                "the Astra channel document is unusable — the private lifecycle API stays closed"
            );
            return;
        }
    };
    let config = match channel.server_config() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(
                %error,
                "the Astra channel identity is unusable — the private lifecycle API stays closed"
            );
            return;
        }
    };
    let bind = channel.bind;
    let router = helios_api::internal::router(handler);
    tokio::spawn(async move {
        // The address belongs to the veth, whose host end is created by the
        // container engine — which may well start after `heliosd`. The first
        // binds therefore fail with "Cannot assign requested address", exactly
        // as the administration API's do on the WireGuard address, and for the
        // same reason they are retried rather than treated as final. The bound
        // keeps a genuine misconfiguration visible instead of retrying for
        // ever.
        for attempt in 1..=BIND_ATTEMPTS {
            match helios_api::internal::serve(bind, config.clone(), router.clone()).await {
                Ok(()) => return,
                Err(error) if attempt < BIND_ATTEMPTS => {
                    tracing::warn!(
                        %bind, %error, attempt,
                        "private Astra listener unavailable; retrying"
                    );
                    tokio::time::sleep(BIND_DELAY).await;
                }
                Err(error) => tracing::error!(
                    %bind, %error,
                    "the private Astra listener never came up; the certificate lifecycle keeps \
                     only its in-tunnel routes"
                ),
            }
        }
    });
}

/// Listen attempts before the private channel is given up on.
///
/// Sixty over half a minute: long enough for a container engine to create the
/// bridge after `heliosd` started, short enough that a wrong address is
/// reported while the operator is still watching the journal.
const BIND_ATTEMPTS: u32 = 60;
const BIND_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

/// Creates the gateway's transport identity and pins Astra's, or reads back
/// the pairing already on disk.
///
/// Idempotent when nothing changed, and only then: an identical `bind` and an
/// identical pin return the certificate already served, so a deployment resumed
/// after an interruption finishes what the first one started. A **different**
/// bind or a **different** pin is refused without `--rotate`, because replacing
/// the served bytes without re-pinning them on the other side stops the two
/// from talking, silently, until the next rotation fails.
///
/// The certificate is printed rather than kept: `deploy.sh` reads it off this
/// output and hands it to the container, which is what keeps an operator from
/// copying base64 between two shells.
pub fn initialize(
    bind: SocketAddr,
    astra_certificate_path: &Path,
    rotate: bool,
) -> Result<DerCertificate> {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};

    let path = path();
    if !rotate {
        if let Some(existing) = AstraChannel::load_from(&path)? {
            let wanted = std::fs::read(astra_certificate_path).with_context(|| {
                format!(
                    "reading Astra's transport certificate {}",
                    astra_certificate_path.display()
                )
            })?;
            anyhow::ensure!(
                existing.bind == bind && existing.astra_certificate.as_bytes() == wanted,
                "an Astra channel identity already exists at {} and it pins something else; use \
                 --rotate to replace it explicitly — the gateway's certificate changes with it, \
                 and Astra must be re-pinned in the same breath",
                path.display()
            );
            return DerCertificate::new(existing.identity.certificate_der)
                .map_err(|error| anyhow::anyhow!("the served channel certificate: {error}"));
        }
    }
    anyhow::ensure!(
        !bind.ip().is_unspecified(),
        "refusing to bind {bind}: the private lifecycle API belongs on the gateway's veth \
         address, not on every interface"
    );
    let astra_certificate =
        DerCertificate::new(std::fs::read(astra_certificate_path).with_context(|| {
            format!(
                "reading Astra's transport certificate {}",
                astra_certificate_path.display()
            )
        })?)
        .map_err(|error| anyhow::anyhow!("Astra's transport certificate: {error}"))?;

    let mut params =
        CertificateParams::new(vec![helios_api::internal::INTERNAL_SERVER_NAME.to_string()])
            .context("building the channel certificate parameters")?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after =
        time::OffsetDateTime::now_utc() + time::Duration::days(IDENTITY_VALIDITY_DAYS);
    let key_pair = KeyPair::generate().context("generating the Astra channel key")?;
    let certificate = params
        .self_signed(&key_pair)
        .context("creating the Astra channel certificate")?;
    let certificate_der = DerCertificate::new(certificate.der().to_vec())
        .map_err(|error| anyhow::anyhow!("generated channel certificate: {error}"))?;

    let stored = StoredChannel {
        bind,
        certificate: certificate_der.to_base64(),
        private_key: base64::engine::general_purpose::STANDARD.encode(key_pair.serialize_der()),
        astra_certificate: astra_certificate.to_base64(),
    };
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    aether::private_file::write_private_atomic(
        &path,
        &serde_json::to_vec_pretty(&stored).context("encoding the Astra channel document")?,
    )
    .with_context(|| format!("writing {}", path.display()))?;

    // Built once here so an unusable pairing fails now, at the operator's
    // console, rather than at the first rotation.
    let channel = AstraChannel::load_from(&path)?
        .context("the Astra channel document was written and cannot be read back")?;
    channel.server_config()?;
    Ok(certificate_der)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn astra_certificate(directory: &Path) -> PathBuf {
        use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
        std::fs::create_dir_all(directory).unwrap();
        let mut params = CertificateParams::new(vec!["astra.internal".to_string()]).unwrap();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let key_pair = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();
        let path = directory.join("astra.der");
        std::fs::write(&path, certificate.der().as_ref()).unwrap();
        path
    }

    /// `HELIOS_ASTRA_CHANNEL` is process-wide, exactly like
    /// `HELIOS_NETWORK_CONFIG`: without a lock two parallel tests read each
    /// other's file.
    fn isolated(directory: &Path) -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        std::env::set_var("HELIOS_ASTRA_CHANNEL", directory.join("astra-channel.json"));
        guard
    }

    /// A gateway with no channel document is a gateway without an authority,
    /// which is a supported state — not an error.
    #[test]
    fn an_absent_document_is_not_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let _guard = isolated(directory.path());
        assert!(AstraChannel::load().unwrap().is_none());
    }

    /// The round trip: create, read back, and build a server configuration
    /// that pins exactly the certificate that was handed in.
    #[test]
    fn an_initialized_channel_loads_and_pins_astra() {
        let directory = tempfile::tempdir().unwrap();
        let _guard = isolated(directory.path());
        let astra = astra_certificate(directory.path());

        let served = initialize("10.88.0.1:8444".parse().unwrap(), &astra, false).unwrap();
        let channel = AstraChannel::load().unwrap().expect("channel");
        assert_eq!(channel.bind, "10.88.0.1:8444".parse().unwrap());
        assert_eq!(channel.identity.certificate_der, served.as_bytes());
        assert_eq!(
            channel.astra_certificate.as_bytes(),
            std::fs::read(&astra).unwrap()
        );
        channel.server_config().expect("server configuration");

        // Run again with the same pairing: the same certificate comes back, so
        // a resumed deployment finishes what an interrupted one started.
        let again = initialize("10.88.0.1:8444".parse().unwrap(), &astra, false).unwrap();
        assert_eq!(again.as_bytes(), served.as_bytes());

        // A different pin, on the other hand, is a replacement — and a
        // replacement the other end has not been told about breaks the link.
        let other = astra_certificate(&directory.path().join("other"));
        assert!(
            initialize("10.88.0.1:8444".parse().unwrap(), &other, false).is_err(),
            "a changed pin was adopted without --rotate"
        );
        // So is a different address: the pairing includes where it is served.
        assert!(initialize("10.88.0.1:9999".parse().unwrap(), &astra, false).is_err());

        let rotated = initialize("10.88.0.1:8444".parse().unwrap(), &other, true).unwrap();
        assert_ne!(rotated.as_bytes(), served.as_bytes());
    }

    /// A wildcard bind publishes the lifecycle API on the WAN and inside the
    /// tunnel. It is refused when the document is written and again when it is
    /// read, because a document may arrive from somewhere other than `init`.
    #[test]
    fn a_wildcard_bind_is_refused_at_both_ends() {
        let directory = tempfile::tempdir().unwrap();
        let _guard = isolated(directory.path());
        let astra = astra_certificate(directory.path());

        assert!(initialize("0.0.0.0:8444".parse().unwrap(), &astra, false).is_err());

        initialize("10.88.0.1:8444".parse().unwrap(), &astra, true).unwrap();
        let path = path();
        let mut stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        stored["bind"] = serde_json::json!("0.0.0.0:8444");
        std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert!(
            AstraChannel::load().is_err(),
            "a hand-edited wildcard bind was accepted"
        );
    }

    /// A pin that cannot authenticate a client is refused when the identity is
    /// created, at the operator's console — not at the first rotation.
    #[test]
    fn a_pin_that_cannot_authenticate_a_client_is_refused_at_init() {
        use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
        let directory = tempfile::tempdir().unwrap();
        let _guard = isolated(directory.path());

        let mut params = CertificateParams::new(vec!["astra.internal".to_string()]).unwrap();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key_pair = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();
        let wrong = directory.path().join("wrong.der");
        std::fs::write(&wrong, certificate.der().as_ref()).unwrap();

        assert!(initialize("10.88.0.1:8444".parse().unwrap(), &wrong, false).is_err());
    }
}
