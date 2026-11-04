//! The gateway's end of the private Astra ↔ Helios veth channel (spec §8.3).
//!
//! [`astra-channel`](::astra_channel) holds the protocol — the four routes, the two TLS
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
//! The record's private fields are [`SecretString`], never generic serialized
//! values. Its explicit JSON encoder writes canonical base64 into a zeroizing
//! buffer bounded at 256 KiB; reading enforces the same document size limit.
//!
//! # Absent means closed, and closed is not broken
//!
//! No file, no listener, and no error: the same rule `key_negotiation_port`
//! follows. A gateway with no authority is a gateway that works — it serves
//! traffic, negotiates PSKs and admits peers — so the absence is reported as
//! one `info` line naming the consequence, not as a startup failure. A file
//! that exists and is unusable **is** reported loudly, because that is an
//! operator error rather than a deployment choice.

use std::io::Read as _;
use std::mem;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ::astra_channel::{AstraChannelHandler, ChannelIdentity};
use aether::certificates::encoding::DerCertificate;
use aether::{secret::json::SecretJson, SecretString};
use anyhow::{Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Where the channel's configuration and key live.
const ASTRA_CHANNEL_PATH: &str = "/var/lib/helios/astra-channel.json";

/// Bounds both parsing and the fixed-capacity secret encoding buffer.
const MAX_CHANNEL_DOCUMENT_BYTES: usize = 256 * 1024;

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
#[derive(Debug, Deserialize)]
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
    private_key: SecretString,
    /// Astra's transport certificate, DER, base64. The only client identity
    /// this listener accepts, byte for byte.
    astra_certificate: String,
    /// Address of Astra's own private listener, on the same veth.
    ///
    /// The direction this gateway **dials**, to relay a client renewal
    /// (spec §8.1.2). Optional because a deployment may have the staging half
    /// and not the renewal half — that is what an older document is — and the
    /// renewal routes then answer `503` rather than the daemon refusing to
    /// start.
    #[serde(default)]
    authority: Option<SocketAddr>,
    /// This gateway's **client** certificate, DER, base64. Astra pins it.
    ///
    /// A second identity from the one served above, because the two are pinned
    /// by different peers under different names and different extended key
    /// usages. One certificate carrying both roles would let either end be
    /// replayed into the other's.
    #[serde(default)]
    client_certificate: Option<String>,
    /// Its PKCS#8 private key, DER, base64.
    #[serde(default)]
    client_private_key: Option<SecretString>,
    /// Astra's **server** certificate, DER, base64. The only authority this
    /// gateway will dial, byte for byte.
    #[serde(default)]
    astra_authority_certificate: Option<String>,
}

impl StoredChannel {
    /// Encodes the deployment record without making the secret type serializable.
    /// Secrets are appended directly to a bounded buffer allocated at its final
    /// capacity, so growth cannot leave an unwiped copy behind.
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        #[derive(Serialize)]
        struct PublicFields<'a> {
            bind: SocketAddr,
            certificate: &'a str,
            astra_certificate: &'a str,
            authority: Option<SocketAddr>,
            client_certificate: Option<&'a str>,
            astra_authority_certificate: Option<&'a str>,
        }

        let public = serde_json::to_vec(&PublicFields {
            bind: self.bind,
            certificate: &self.certificate,
            astra_certificate: &self.astra_certificate,
            authority: self.authority,
            client_certificate: self.client_certificate.as_deref(),
            astra_authority_certificate: self.astra_authority_certificate.as_deref(),
        })
        .context("encoding the public Astra channel fields")?;
        anyhow::ensure!(
            public.len() <= MAX_CHANNEL_DOCUMENT_BYTES
                && self.private_key.expose().len() <= MAX_CHANNEL_DOCUMENT_BYTES
                && self
                    .client_private_key
                    .as_ref()
                    .is_none_or(|key| key.expose().len() <= MAX_CHANNEL_DOCUMENT_BYTES),
            "the Astra channel document is too large"
        );
        for key in std::iter::once(&self.private_key).chain(self.client_private_key.as_ref()) {
            let decoded = Zeroizing::new(decode("the channel private key", key.expose())?);
            anyhow::ensure!(!decoded.is_empty(), "the channel private key is empty");
        }
        let mut encoded = SecretJson::new(MAX_CHANNEL_DOCUMENT_BYTES);
        encoded.append(&public[..public.len() - 1])?;
        encoded.append(b",\"private_key\":")?;
        encoded.secret(&self.private_key)?;
        encoded.append(b",\"client_private_key\":")?;
        match &self.client_private_key {
            Some(key) => encoded.secret(key)?,
            None => encoded.append(b"null")?,
        }
        encoded.append(b"}")?;
        Ok(encoded.finish())
    }
}

/// A loaded, checked channel: ready to serve.
pub struct AstraChannel {
    pub bind: SocketAddr,
    identity: ChannelIdentity,
    astra_certificate: DerCertificate,
    /// The dialling half, present only when the document carries all three of
    /// its values. Two of three is refused at load: half a pairing is an
    /// operator error, and it would surface as a renewal that never works.
    authority: Option<AuthorityEndpoint>,
}

/// Everything needed to dial Astra's private listener.
struct AuthorityEndpoint {
    address: SocketAddr,
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
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_CHANNEL_DOCUMENT_BYTES + 1));
        file.take((MAX_CHANNEL_DOCUMENT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading {}", path.display()))?;
        anyhow::ensure!(
            bytes.len() <= MAX_CHANNEL_DOCUMENT_BYTES,
            "the Astra channel document is too large"
        );
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
        let authority = match (
            stored.authority.as_ref(),
            &stored.client_certificate,
            &stored.client_private_key,
            &stored.astra_authority_certificate,
        ) {
            (Some(address), Some(certificate), Some(key), Some(astra)) => Some(AuthorityEndpoint {
                address: *address,
                identity: ChannelIdentity {
                    certificate_der: decode("the gateway client certificate", certificate)?,
                    private_key_der: decode("the gateway client private key", key.expose())?,
                },
                astra_certificate: DerCertificate::new(decode(
                    "the Astra authority certificate",
                    astra,
                )?)
                .map_err(|error| anyhow::anyhow!("pinned Astra authority certificate: {error}"))?,
            }),
            (None, None, None, None) => None,
            _ => anyhow::bail!(
                "the Astra channel document carries only part of the dialling half: it needs the \
                 authority address, this gateway's client certificate and key, and Astra's \
                 authority certificate — re-run `heliosd init-astra-channel` with --authority \
                 and --astra-authority-certificate"
            ),
        };
        Ok(Some(Self {
            bind: stored.bind,
            identity: ChannelIdentity {
                certificate_der: decode("the gateway certificate", &stored.certificate)?,
                private_key_der: decode("the gateway private key", stored.private_key.expose())?,
            },
            astra_certificate,
            authority,
        }))
    }

    /// The typed client for Astra's private routes, when this gateway has one.
    ///
    /// Built here rather than by the caller so the pin is checked at start-up:
    /// an unusable pairing found at deployment costs a command, and the same
    /// pairing found at 80 % of a leaf's life costs a night.
    pub fn authority_client(&self) -> Result<Option<::astra_channel::AstraLifecycleClient>> {
        let Some(authority) = &self.authority else {
            return Ok(None);
        };
        let tls = ::astra_channel::client_config(&authority.identity, &authority.astra_certificate)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok(Some(::astra_channel::AstraLifecycleClient::new(
            authority.address,
            tls,
        )))
    }

    /// Builds the TLS configuration, refusing a pin that cannot serve.
    fn server_config(&self) -> Result<rustls::ServerConfig> {
        ::astra_channel::server_config(&self.identity, &self.astra_certificate)
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
    let router = ::astra_channel::router(handler);
    tokio::spawn(async move {
        // The address belongs to the veth, whose host end is created by the
        // container engine — which may well start after `heliosd`. The first
        // binds therefore fail with "Cannot assign requested address", exactly
        // as the administration API's do on the WireGuard address, and for the
        // same reason they are retried rather than treated as final. The bound
        // keeps a genuine misconfiguration visible instead of retrying for
        // ever.
        for attempt in 1..=BIND_ATTEMPTS {
            match ::astra_channel::serve(
                bind,
                config.clone(),
                router.clone(),
                ::astra_channel::INTERNAL_PREFIX,
            )
            .await
            {
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
    authority: Option<SocketAddr>,
    astra_authority_certificate_path: Option<&Path>,
    rotate: bool,
) -> Result<TransportIdentities> {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};

    anyhow::ensure!(
        authority.is_some() == astra_authority_certificate_path.is_some(),
        "the dialling half needs both --authority and --astra-authority-certificate; only one \
         was given, and half a pairing is a renewal that never works"
    );
    let path = path();
    if !rotate {
        if let Some(existing) = AstraChannel::load_from(&path)? {
            let wanted = std::fs::read(astra_certificate_path).with_context(|| {
                format!(
                    "reading Astra's transport certificate {}",
                    astra_certificate_path.display()
                )
            })?;
            // The dialling half is compared too: a second run that named a
            // different authority, or none where one was recorded, would
            // otherwise return the certificate already served and leave the
            // document describing the previous deployment.
            let same_authority = match (&existing.authority, authority) {
                (Some(existing), Some(wanted)) => existing.address == wanted,
                (None, None) => true,
                _ => false,
            };
            anyhow::ensure!(
                existing.bind == bind
                    && existing.astra_certificate.as_bytes() == wanted
                    && same_authority,
                "an Astra channel identity already exists at {} and it pins something else; use \
                 --rotate to replace it explicitly — the gateway's certificate changes with it, \
                 and Astra must be re-pinned in the same breath",
                path.display()
            );
            let client = existing
                .authority
                .as_ref()
                .map(|authority| DerCertificate::new(authority.identity.certificate_der.clone()))
                .transpose()
                .map_err(|error| anyhow::anyhow!("the client channel certificate: {error}"))?;
            return Ok(TransportIdentities {
                served: DerCertificate::new(existing.identity.certificate_der)
                    .map_err(|error| anyhow::anyhow!("the served channel certificate: {error}"))?,
                client,
            });
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
        CertificateParams::new(vec![::astra_channel::INTERNAL_SERVER_NAME.to_string()])
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

    // The dialling half, when this deployment has one. A `clientAuth`
    // certificate under a different name: the two ends pin each other in two
    // roles, and one certificate holding both would let each be replayed into
    // the other's.
    let dialling = match astra_authority_certificate_path {
        Some(astra_authority_path) => {
            let astra_authority =
                DerCertificate::new(std::fs::read(astra_authority_path).with_context(|| {
                    format!(
                        "reading Astra's authority certificate {}",
                        astra_authority_path.display()
                    )
                })?)
                .map_err(|error| anyhow::anyhow!("Astra's authority certificate: {error}"))?;
            let mut params = CertificateParams::new(vec![CLIENT_IDENTITY_NAME.to_string()])
                .context("building the client channel certificate parameters")?;
            params.is_ca = IsCa::NoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
            params.not_after =
                time::OffsetDateTime::now_utc() + time::Duration::days(IDENTITY_VALIDITY_DAYS);
            let key_pair = KeyPair::generate().context("generating the client channel key")?;
            let certificate = params
                .self_signed(&key_pair)
                .context("creating the client channel certificate")?;
            let der = DerCertificate::new(certificate.der().to_vec())
                .map_err(|error| anyhow::anyhow!("generated client certificate: {error}"))?;
            Some((
                der,
                Zeroizing::new(key_pair.serialize_der()),
                astra_authority,
            ))
        }
        None => None,
    };

    let served_private_key_der = Zeroizing::new(key_pair.serialize_der());
    let private_key = base64::engine::general_purpose::STANDARD.encode(&served_private_key_der);
    let stored = StoredChannel {
        bind,
        certificate: certificate_der.to_base64(),
        private_key: SecretString::new(private_key),
        astra_certificate: astra_certificate.to_base64(),
        authority,
        client_certificate: dialling
            .as_ref()
            .map(|(certificate, _, _)| certificate.to_base64()),
        client_private_key: dialling.as_ref().map(|(_, key, _)| {
            SecretString::new(base64::engine::general_purpose::STANDARD.encode(key.as_slice()))
        }),
        astra_authority_certificate: dialling.as_ref().map(|(_, _, astra)| astra.to_base64()),
    };
    if let Some(parent) = path.parent() {
        aether::private_file::create_private_dir(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let encoded = stored.encode()?;
    aether::private_file::write_private_atomic(&path, encoded.as_ref())
        .with_context(|| format!("writing {}", path.display()))?;

    // Built once here so an unusable pairing fails now, at the operator's
    // console, rather than at the first rotation.
    let channel = AstraChannel::load_from(&path)?
        .context("the Astra channel document was written and cannot be read back")?;
    channel.server_config()?;
    channel.authority_client()?;
    mem::drop(served_private_key_der);
    Ok(TransportIdentities {
        served: certificate_der,
        client: dialling.map(|(certificate, _, _)| certificate),
    })
}

/// The name the gateway's client certificate carries.
///
/// Distinct from [`::astra_channel::INTERNAL_SERVER_NAME`], which the
/// served certificate carries: two identities, two names, so a mis-pinned pair
/// cannot look like a working one right up to the pin comparison.
const CLIENT_IDENTITY_NAME: &str = "helios-gateway-client.internal";

/// What `heliosd init-astra-channel` produced, in both directions.
pub struct TransportIdentities {
    /// `serverAuth`. Astra pins it to dial this gateway.
    pub served: DerCertificate,
    /// `clientAuth`, absent when this deployment has no dialling half. Astra
    /// pins it to accept this gateway on its own listener.
    pub client: Option<DerCertificate>,
}

/// The gateway's half of the relayed client renewal (spec §8.1.2).
///
/// # Why this is not a proxy
///
/// Each method takes an identity the API layer **resolved from a source VIP**
/// and an object it deserialized into a named type. Nothing the client chose —
/// method, path, header, redirect — travels: the request that reaches Astra is
/// built here, and `caller_wg_public_key` is this gateway's own resolution
/// rather than a field the peer filled in. Astra compares the object's copy
/// against it and refuses a mismatch, so neither end has to trust the other's
/// word about who is asking.
///
/// # What it does not decide
///
/// Nothing. It holds no registry lock and takes no view on whether a renewal
/// is due, approved or refused: that is the authority's, and the gateway's own
/// registry only learns about it later, when Astra stages the candidate on the
/// other direction of this same veth. Every refusal is relayed as its coarse
/// class, because a finer one on the in-tunnel route would be an oracle about
/// other peers.
pub struct AstraRenewalRelay {
    client: ::astra_channel::AstraLifecycleClient,
}

impl AstraRenewalRelay {
    pub fn new(client: ::astra_channel::AstraLifecycleClient) -> Self {
        Self { client }
    }

    /// The caller, parsed once, before anything is relayed.
    fn caller(
        raw: &str,
    ) -> Result<
        aether::certificates::encoding::WireGuardKey,
        helios_api::certificates::TrustUpdateRefusal,
    > {
        aether::certificates::encoding::WireGuardKey::parse(raw).map_err(|error| {
            tracing::error!(%error, "the resolved caller is not a WireGuard key");
            helios_api::certificates::TrustUpdateRefusal::Internal
        })
    }

    /// One channel failure, logged with its reason and answered with a class.
    fn refuse(
        route: &str,
        error: ::astra_channel::ChannelError,
    ) -> helios_api::certificates::TrustUpdateRefusal {
        use ::astra_channel::ChannelError;
        use helios_api::certificates::TrustUpdateRefusal;
        match error {
            // A status the authority chose is relayed as what it means, not as
            // a gateway failure: `403` is a refusal the peer earned, and
            // reporting it as `500` would send an Orion into retrying
            // something that will never succeed.
            ChannelError::Status(status) => {
                tracing::warn!(route, %status, "the authority refused a relayed renewal");
                match status.as_u16() {
                    400 => TrustUpdateRefusal::Protocol,
                    403 => TrustUpdateRefusal::Rejected,
                    501 | 503 => TrustUpdateRefusal::Unavailable,
                    _ => TrustUpdateRefusal::Internal,
                }
            }
            error => {
                // The authority is unreachable, or answered something this
                // client cannot read. Either way the peer is not at fault and
                // retrying later is the right advice.
                tracing::error!(route, %error, "the authority could not be reached");
                TrustUpdateRefusal::Unavailable
            }
        }
    }
}

#[async_trait::async_trait]
impl ::astra_channel::TrustUpdatePreparer for AstraRenewalRelay {
    /// Relays one preparation and hands back whatever the authority built.
    ///
    /// The same coarse-class mapping as every other relayed call: this end
    /// decides nothing, and a finer reason on a route a peer can reach would
    /// be an oracle about the domain's state.
    async fn prepare(
        &self,
        relayed: &::astra_channel::RelayedTrustUpdatePreparation,
    ) -> Result<::astra_channel::PreparedTrustUpdate, helios_api::certificates::TrustUpdateRefusal>
    {
        self.client
            .prepare_trust_update(relayed)
            .await
            .map_err(|error| Self::refuse(::astra_channel::TRUST_UPDATE_PREPARE_PATH, error))
    }
}

#[async_trait::async_trait]
impl helios_api::certificates::OperatorCampaignRelay for AstraRenewalRelay {
    /// Reads one campaign operation on behalf of an administrator.
    ///
    /// No caller key is resolved here, and that is the difference from the
    /// renewal relay above: a campaign belongs to no peer. What bounds who may
    /// make one circulate is `require_admin` on the route; what authorizes it
    /// is the assertion and the `CA-PQ` signatures its objects carry. The
    /// administrator's stable WireGuard identity travels for Astra's
    /// structured service log only.
    async fn pending(
        &self,
        operator: &::astra_channel::OperatorIdentity,
    ) -> Result<::astra_channel::OperatorPendingList, helios_api::certificates::TrustUpdateRefusal>
    {
        self.client
            .operator_pending(&::astra_channel::RelayedOperatorCampaign {
                operator: operator.clone(),
            })
            .await
            .map_err(|error| Self::refuse("operator-pending", error))
    }

    async fn operation(
        &self,
        operator: &::astra_channel::OperatorIdentity,
        operation: &aether::certificates::encoding::Id16,
    ) -> Result<::astra_channel::SigningOperationView, helios_api::certificates::TrustUpdateRefusal>
    {
        self.client
            .operator_operation(
                operation,
                &::astra_channel::RelayedOperatorCampaign {
                    operator: operator.clone(),
                },
            )
            .await
            .map_err(|error| Self::refuse("operator-operation", error))
    }

    async fn signer_request(
        &self,
        operator: &::astra_channel::OperatorIdentity,
        operation: &aether::certificates::encoding::Id16,
        capability_token: &str,
    ) -> Result<
        ::astra_channel::OperatorSignerRequestResponse,
        helios_api::certificates::TrustUpdateRefusal,
    > {
        self.client
            .operator_signer_request(
                operation,
                capability_token,
                &::astra_channel::RelayedOperatorCampaign {
                    operator: operator.clone(),
                },
            )
            .await
            .map_err(|error| Self::refuse("operator-signer-request", error))
    }

    async fn encrypted_vault(
        &self,
        operator: &::astra_channel::OperatorIdentity,
        fingerprint: &aether::certificates::encoding::Fingerprint,
        capability_token: &str,
    ) -> Result<Vec<u8>, helios_api::certificates::TrustUpdateRefusal> {
        self.client
            .operator_encrypted_vault(
                fingerprint,
                capability_token,
                &::astra_channel::RelayedOperatorCampaign {
                    operator: operator.clone(),
                },
            )
            .await
            .map_err(|error| Self::refuse("operator-vault", error))
    }

    async fn signer_result(
        &self,
        operator: &::astra_channel::OperatorIdentity,
        operation: &aether::certificates::encoding::Id16,
        capability_token: &str,
        result: Box<aether::certificates::status::AstraSignerResult>,
    ) -> Result<::astra_channel::SigningOperationView, helios_api::certificates::TrustUpdateRefusal>
    {
        self.client
            .operator_signer_result(
                operation,
                capability_token,
                &::astra_channel::RelayedOperatorSignerResult {
                    operator: operator.clone(),
                    result,
                },
            )
            .await
            .map_err(|error| Self::refuse("operator-signer-result", error))
    }

    /// Relays an opening to Astra's door, with the administrator it came
    /// through. The door decides what the tunnel may open; this end only
    /// carries the request and maps the answer onto its coarse class.
    async fn open(
        &self,
        operator: &::astra_channel::OperatorIdentity,
        request: ::astra_channel::OperatorOpenRequest,
    ) -> Result<::astra_channel::OperatorOpened, helios_api::certificates::TrustUpdateRefusal> {
        self.client
            .operator_open(&::astra_channel::RelayedOperatorOpen {
                operator: operator.clone(),
                request,
            })
            .await
            .map_err(|error| Self::refuse("operator-open", error))
    }
}

#[async_trait::async_trait]
impl helios_api::certificates::ClientRenewalRelay for AstraRenewalRelay {
    async fn open(
        &self,
        caller_wg_public_key: &str,
        request: Box<aether::certificates::client::ClientCertificateRotationRequest>,
    ) -> Result<
        ::astra_channel::ClientRenewalOperationView,
        helios_api::certificates::TrustUpdateRefusal,
    > {
        let caller = Self::caller(caller_wg_public_key)?;
        self.client
            .request_rotation(&::astra_channel::RelayedRotationRequest {
                caller_wg_public_key: caller,
                request,
            })
            .await
            .map_err(|error| Self::refuse("request", error))
    }

    async fn operation(
        &self,
        caller_wg_public_key: &str,
        operation: &aether::certificates::encoding::Id16,
    ) -> Result<
        ::astra_channel::ClientRenewalOperationView,
        helios_api::certificates::TrustUpdateRefusal,
    > {
        let caller = Self::caller(caller_wg_public_key)?;
        self.client
            .operation(
                operation,
                &::astra_channel::RelayedOperationQuery {
                    caller_wg_public_key: caller,
                },
            )
            .await
            .map_err(|error| Self::refuse("operation", error))
    }

    async fn signer_request(
        &self,
        caller_wg_public_key: &str,
        operation: &aether::certificates::encoding::Id16,
        capability_token: &str,
    ) -> Result<
        ::astra_channel::ClientRenewalSignerRequest,
        helios_api::certificates::TrustUpdateRefusal,
    > {
        let caller = Self::caller(caller_wg_public_key)?;
        self.client
            .signer_request(
                operation,
                capability_token,
                &::astra_channel::RelayedOperationQuery {
                    caller_wg_public_key: caller,
                },
            )
            .await
            .map_err(|error| Self::refuse("signer-request", error))
    }

    async fn signer_result(
        &self,
        caller_wg_public_key: &str,
        operation: &aether::certificates::encoding::Id16,
        capability_token: &str,
        approval: Box<aether::certificates::approval::AstraRenewalApproval>,
    ) -> Result<
        ::astra_channel::ClientRenewalOperationView,
        helios_api::certificates::TrustUpdateRefusal,
    > {
        let caller = Self::caller(caller_wg_public_key)?;
        self.client
            .signer_result(
                operation,
                capability_token,
                &::astra_channel::ClientRenewalSignerResult {
                    caller_wg_public_key: caller,
                    approval,
                },
            )
            .await
            .map_err(|error| Self::refuse("signer-result", error))
    }
}

/// The relay, when this gateway has a dialling half.
///
/// `Ok(None)` is a deployment whose authority only receives — a supported
/// state, and the one every deployment starts in. The renewal routes then
/// answer `503`: the route exists and the client is right to use it; what is
/// missing is the authority behind it.
pub fn relay() -> Option<AstraRenewalRelay> {
    let channel = match AstraChannel::load() {
        Ok(Some(channel)) => channel,
        Ok(None) => return None,
        Err(error) => {
            tracing::error!(%error, "the Astra channel document is unusable — no renewal relay");
            return None;
        }
    };
    match channel.authority_client() {
        Ok(Some(client)) => {
            tracing::info!(
                authority = %client.address(),
                "client renewal relay ready; renewals are relayed on the private veth"
            );
            Some(AstraRenewalRelay::new(client))
        }
        Ok(None) => {
            tracing::info!(
                "no authority address in the Astra channel document: the four renewal routes \
                 answer 503 until `heliosd init-astra-channel --authority` is run"
            );
            None
        }
        Err(error) => {
            tracing::error!(%error, "the renewal relay identity is unusable — the routes stay 503");
            None
        }
    }
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

    #[test]
    fn stored_channel_debug_redacts_private_keys_without_changing_json() {
        let stored = StoredChannel {
            bind: "10.88.0.1:8444".parse().unwrap(),
            certificate: "served-certificate".into(),
            private_key: SecretString::new(
                base64::engine::general_purpose::STANDARD.encode(b"served-private-key"),
            ),
            astra_certificate: "astra-certificate".into(),
            authority: Some("10.88.0.2:8444".parse().unwrap()),
            client_certificate: Some("client-certificate".into()),
            client_private_key: Some(SecretString::new(
                base64::engine::general_purpose::STANDARD.encode(b"client-private-key"),
            )),
            astra_authority_certificate: Some("astra-authority-certificate".into()),
        };

        let debug = format!("{stored:?}");
        assert!(debug.contains("served-certificate"));
        assert!(debug.contains("client-certificate"));
        assert!(debug.contains("SecretString(***)"));
        assert!(!debug.contains(stored.private_key.expose()));
        assert!(!debug.contains(stored.client_private_key.as_ref().unwrap().expose()));

        let encoded = stored.encode().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(json["private_key"], stored.private_key.expose());
        assert_eq!(
            json["client_private_key"],
            stored.client_private_key.as_ref().unwrap().expose()
        );
        let decoded: StoredChannel = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.bind, stored.bind);
        assert_eq!(decoded.certificate, stored.certificate);
        assert_eq!(decoded.astra_certificate, stored.astra_certificate);
        assert_eq!(decoded.authority, stored.authority);
        assert_eq!(decoded.client_certificate, stored.client_certificate);
        assert_eq!(
            decoded.astra_authority_certificate,
            stored.astra_authority_certificate
        );
        assert_eq!(decoded.private_key, stored.private_key);
        assert_eq!(decoded.client_private_key, stored.client_private_key);

        let mut invalid = decoded;
        invalid.private_key = SecretString::new("not-base64\"}");
        assert!(invalid.encode().is_err());
        invalid.private_key = SecretString::default();
        assert!(invalid.encode().is_err());
        invalid.private_key = stored.private_key.duplicate();
        invalid.client_private_key = None;
        let encoded = invalid.encode().unwrap();
        let decoded: StoredChannel = serde_json::from_slice(&encoded).unwrap();
        assert!(decoded.client_private_key.is_none());
        invalid.certificate = "a".repeat(MAX_CHANNEL_DOCUMENT_BYTES);
        assert!(invalid
            .encode()
            .unwrap_err()
            .to_string()
            .contains("too large"));
    }

    #[test]
    fn an_oversized_channel_document_is_refused_before_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("astra-channel.json");
        std::fs::write(&path, vec![b' '; MAX_CHANNEL_DOCUMENT_BYTES + 1]).unwrap();
        assert!(AstraChannel::load_from(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("too large"));
    }

    /// The round trip: create, read back, and build a server configuration
    /// that pins exactly the certificate that was handed in.
    #[test]
    fn an_initialized_channel_loads_and_pins_astra() {
        let directory = tempfile::tempdir().unwrap();
        let _guard = isolated(directory.path());
        let astra = astra_certificate(directory.path());

        let served =
            initialize("10.88.0.1:8444".parse().unwrap(), &astra, None, None, false).unwrap();
        let channel = AstraChannel::load().unwrap().expect("channel");
        assert_eq!(channel.bind, "10.88.0.1:8444".parse().unwrap());
        assert_eq!(channel.identity.certificate_der, served.served.as_bytes());
        assert_eq!(
            channel.astra_certificate.as_bytes(),
            std::fs::read(&astra).unwrap()
        );
        channel.server_config().expect("server configuration");

        // Run again with the same pairing: the same certificate comes back, so
        // a resumed deployment finishes what an interrupted one started.
        let again =
            initialize("10.88.0.1:8444".parse().unwrap(), &astra, None, None, false).unwrap();
        assert_eq!(again.served.as_bytes(), served.served.as_bytes());

        // A different pin, on the other hand, is a replacement — and a
        // replacement the other end has not been told about breaks the link.
        let other = astra_certificate(&directory.path().join("other"));
        assert!(
            initialize("10.88.0.1:8444".parse().unwrap(), &other, None, None, false).is_err(),
            "a changed pin was adopted without --rotate"
        );
        // So is a different address: the pairing includes where it is served.
        assert!(initialize("10.88.0.1:9999".parse().unwrap(), &astra, None, None, false).is_err());

        let rotated =
            initialize("10.88.0.1:8444".parse().unwrap(), &other, None, None, true).unwrap();
        assert_ne!(rotated.served.as_bytes(), served.served.as_bytes());
    }

    /// A wildcard bind publishes the lifecycle API on the WAN and inside the
    /// tunnel. It is refused when the document is written and again when it is
    /// read, because a document may arrive from somewhere other than `init`.
    #[test]
    fn a_wildcard_bind_is_refused_at_both_ends() {
        let directory = tempfile::tempdir().unwrap();
        let _guard = isolated(directory.path());
        let astra = astra_certificate(directory.path());

        assert!(initialize("0.0.0.0:8444".parse().unwrap(), &astra, None, None, false).is_err());

        initialize("10.88.0.1:8444".parse().unwrap(), &astra, None, None, true).unwrap();
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

        assert!(initialize("10.88.0.1:8444".parse().unwrap(), &wrong, None, None, false).is_err());
    }
}
