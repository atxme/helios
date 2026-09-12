//! Astra's end of the private veth channel to `heliosd` (spec §8.3).
//!
//! The protocol — the four routes, the TLS bounds, the pinned verifier — lives
//! in [`helios_api::internal`], and both ends are built from it on purpose: a
//! bound that only one side declares bounds only that side. This module holds
//! what belongs to Astra alone: where its transport identity lives inside the
//! container, how it is created, and the pin it puts on the gateway.
//!
//! # Why the authority depends on the gateway's API crate
//!
//! It reads backwards, and it is deliberate. The alternative is a second copy
//! of the pinned verifier, the ALPN, the version floor and the route paths — and
//! a second copy is exactly how "resumption is refused" becomes true on one end
//! and false on the other, silently, six months later. One definition, two
//! callers, and the tests check the pair.
//!
//! # What crosses, and what never does
//!
//! Objects already signed by `CA-PQ` or by the delegated issuer, and the
//! receipt the gateway signs with its served leaf. Never a private key, a PSK,
//! a TPM secret or an unredacted view of `network.toml`. The transport
//! authenticates the process; the ML-DSA-87 signature on every object
//! authorizes the mutation, and the gateway verifies it after the handshake has
//! already been passed.
//!
//! The ordinary relayed renewal calls [`GatewayChannel::stage`] after Astra
//! has verified and durably consumed the operator approval. The public
//! companion routes of §8.2 are a separate transport and are not a fallback
//! for an Orion whose tunnel works: they carry the offline ceremony, never a
//! relayed renewal. See
//! [`docs/testing/TESTING.md`](../../../docs/testing/TESTING.md) for what a
//! WSL2 build does and does not prove about the veth itself.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aether::certificates::client::{
    ClientCertificateStageAuthorization, GatewayCertificateStageReceipt,
};
use aether::certificates::encoding::{DerCertificate, WireGuardKey};
use aether::certificates::revocation::EmergencyCertificateRevocation;
use helios_api::internal::{
    ChannelError, ChannelIdentity, GatewayIdentityView, GatewayLifecycleClient,
    PeerCertificateStateView,
};

/// Astra's transport certificate inside its state volume.
///
/// The **client** half: Astra dials the gateway with it, and the gateway pins
/// these exact bytes.
pub const CHANNEL_CERTIFICATE_FILE: &str = "channel-cert.der";
/// Its PKCS#8 private key. `0600`, in the same volume, and nothing else.
pub const CHANNEL_KEY_FILE: &str = "channel-key.der";
/// Astra's **server** certificate, for the direction the gateway dials.
///
/// A second identity rather than the same one in both roles. The two are
/// pinned by different peers under different names and different extended key
/// usages, and a single certificate carrying `clientAuth` and `serverAuth`
/// would let either end be replayed into the other's role by whoever holds it.
pub const AUTHORITY_CERTIFICATE_FILE: &str = "authority-cert.der";
/// Its PKCS#8 private key.
pub const AUTHORITY_KEY_FILE: &str = "authority-key.der";

/// How long a freshly created transport identity is valid.
///
/// Two years. It is a service identity: rotating it re-runs two commands and
/// touches neither `CA-PQ` nor any client, so a long life costs nothing while a
/// short one turns a forgotten rotation into a dead authority.
const IDENTITY_VALIDITY_DAYS: i64 = 730;

/// Astra's client for the gateway's private lifecycle API.
pub struct GatewayChannel {
    client: GatewayLifecycleClient,
}

impl GatewayChannel {
    /// Opens the channel: reads the local identity, pins the gateway's.
    ///
    /// It performs no I/O on the network — the pin is checked, the
    /// configuration is built, and the first connection happens on the first
    /// call. A gateway that is down must not stop the authority from starting:
    /// they are two processes with two lifetimes, and the veth may come up
    /// after either of them.
    pub fn open(
        state_dir: &Path,
        address: SocketAddr,
        pinned_gateway_certificate: &DerCertificate,
    ) -> Result<Self, ChannelError> {
        let identity = ChannelIdentity {
            certificate_der: std::fs::read(state_dir.join(CHANNEL_CERTIFICATE_FILE))?,
            private_key_der: std::fs::read(state_dir.join(CHANNEL_KEY_FILE))?,
        };
        let tls = helios_api::internal::client_config(&identity, pinned_gateway_certificate)?;
        Ok(Self {
            client: GatewayLifecycleClient::new(address, tls),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.client.address()
    }

    /// Hands a staging authorization over and returns the gateway's receipt.
    ///
    /// The receipt comes back on this same link (§8.3, amendment of 16 August
    /// 2026): Orion carries neither the authorization nor the receipt, so
    /// nothing between the two authorities is relayed by a party either of
    /// them would have to trust for it.
    pub async fn stage(
        &self,
        authorization: &ClientCertificateStageAuthorization,
    ) -> Result<GatewayCertificateStageReceipt, ChannelError> {
        self.client.stage(authorization).await
    }

    /// Relays a recovery commit for a client that has no tunnel (§7.3, §7.5).
    ///
    /// Only a recovery reaches this route, and the gateway is what decides
    /// that: it refuses anything whose pending stage was not opened by the
    /// `CA-PQ` authorization presented alongside. This end never claims it.
    pub async fn commit_recovery(
        &self,
        relayed: &helios_api::internal::RelayedStageCommit,
    ) -> Result<(), ChannelError> {
        self.client.commit_recovery(relayed).await
    }

    /// Applies a signed revocation on the gateway.
    pub async fn revoke(
        &self,
        revocation: &EmergencyCertificateRevocation,
    ) -> Result<(), ChannelError> {
        self.client.revoke(revocation).await
    }

    /// Reads back what the gateway persists about one peer.
    pub async fn peer_state(
        &self,
        identity: &WireGuardKey,
    ) -> Result<PeerCertificateStateView, ChannelError> {
        self.client.peer_state(identity).await
    }

    /// Reads back the leaf the gateway **serves**.
    ///
    /// Not the one Astra recorded: a receipt is signed by what the daemon
    /// actually presents, and a rotation it has not restarted for leaves the
    /// two different. Verifying against Astra's copy would be verifying
    /// against a key that signed nothing.
    pub async fn gateway_identity(&self) -> Result<GatewayIdentityView, ChannelError> {
        self.client.gateway_identity().await
    }

    /// Tells the gateway a staged transition has left the authority (§6.3).
    pub async fn gateway_transition_published(
        &self,
        published: &helios_api::internal::GatewayTransitionPublished,
    ) -> Result<(), ChannelError> {
        self.client.gateway_transition_published(published).await
    }
}

/// Creates Astra's transport identity in its state volume, or reads back the
/// one already there.
///
/// Idempotent on purpose. `deploy.sh` runs it on every deployment and has to
/// learn the certificate each time — the gateway pins these exact bytes — so a
/// second run that refused would make a resumed deployment unable to finish
/// what an interrupted one started. Replacing the identity stays explicit:
/// that is what `--rotate` is, and it breaks the pairing until the gateway is
/// told.
pub fn initialize(state_dir: &Path, rotate: bool) -> Result<DerCertificate, ChannelInitError> {
    initialize_pair(state_dir, rotate).map(|pair| pair.client)
}

/// Both of Astra's transport identities: the one it dials with, and the one it
/// answers on.
pub struct TransportIdentities {
    /// `clientAuth`, named `astra.internal`. The gateway pins it.
    pub client: DerCertificate,
    /// `serverAuth`, named [`helios_api::internal::ASTRA_INTERNAL_SERVER_NAME`].
    /// The gateway pins it too, for the direction it dials.
    pub authority: DerCertificate,
}

/// Creates — or reads back — both identities in one call.
///
/// One call because a deployment that had to run two commands would eventually
/// run one of them, and half a pairing is a channel that handshakes in one
/// direction and refuses in the other, at the first renewal rather than at
/// deployment.
pub fn initialize_pair(
    state_dir: &Path,
    rotate: bool,
) -> Result<TransportIdentities, ChannelInitError> {
    Ok(TransportIdentities {
        client: identity(
            state_dir,
            rotate,
            CHANNEL_CERTIFICATE_FILE,
            CHANNEL_KEY_FILE,
            "astra.internal",
            Role::Client,
        )?,
        authority: identity(
            state_dir,
            rotate,
            AUTHORITY_CERTIFICATE_FILE,
            AUTHORITY_KEY_FILE,
            helios_api::internal::ASTRA_INTERNAL_SERVER_NAME,
            Role::Server,
        )?,
    })
}

/// Which direction one identity serves. Never both.
#[derive(Clone, Copy)]
enum Role {
    Client,
    Server,
}

/// Reads one transport identity back, or creates it.
fn identity(
    state_dir: &Path,
    rotate: bool,
    certificate_file: &str,
    key_file: &str,
    name: &str,
    role: Role,
) -> Result<DerCertificate, ChannelInitError> {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};

    let certificate_path = state_dir.join(certificate_file);
    let key_path = state_dir.join(key_file);
    if !rotate && certificate_path.exists() {
        // Both halves, or neither: a certificate whose key never landed would
        // look like a usable identity and fail at the first handshake.
        if !key_path.exists() {
            return Err(ChannelInitError::HalfInitialized(key_path));
        }
        return DerCertificate::new(std::fs::read(&certificate_path)?)
            .map_err(|error| ChannelInitError::Certificate(error.to_string()));
    }
    aether::private_file::create_private_dir(state_dir)?;

    let mut params = CertificateParams::new(vec![name.to_string()])
        .map_err(|error| ChannelInitError::Certificate(error.to_string()))?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    // One usage, never two: the pinned verifier on the far end refuses a
    // certificate that cannot hold the role it was pinned for, and a
    // certificate holding both roles would let each end be replayed into the
    // other's.
    params.extended_key_usages = vec![match role {
        Role::Client => ExtendedKeyUsagePurpose::ClientAuth,
        Role::Server => ExtendedKeyUsagePurpose::ServerAuth,
    }];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after =
        time::OffsetDateTime::now_utc() + time::Duration::days(IDENTITY_VALIDITY_DAYS);
    let key_pair =
        KeyPair::generate().map_err(|error| ChannelInitError::Certificate(error.to_string()))?;
    let certificate = params
        .self_signed(&key_pair)
        .map_err(|error| ChannelInitError::Certificate(error.to_string()))?;

    // The private key first and privately; the certificate afterwards. A
    // certificate on disk whose key never landed would look like a usable
    // identity to the next `run`.
    aether::private_file::write_private_atomic(&key_path, &key_pair.serialize_der())?;
    std::fs::write(&certificate_path, certificate.der().as_ref())?;
    DerCertificate::new(certificate.der().to_vec())
        .map_err(|error| ChannelInitError::Certificate(error.to_string()))
}

/// The identity Astra answers on, ready to serve.
pub fn authority_identity(state_dir: &Path) -> Result<ChannelIdentity, ChannelInitError> {
    Ok(ChannelIdentity {
        certificate_der: std::fs::read(state_dir.join(AUTHORITY_CERTIFICATE_FILE))?,
        private_key_der: std::fs::read(state_dir.join(AUTHORITY_KEY_FILE))?,
    })
}

/// Why a transport identity could not be created.
#[derive(Debug, thiserror::Error)]
pub enum ChannelInitError {
    #[error(
        "a transport certificate exists but its private key {0} does not: this identity cannot \
         authenticate anything, and creating a second one would break the gateway's pin — remove \
         the certificate, or pass --rotate to replace the pair and re-pin the gateway"
    )]
    HalfInitialized(PathBuf),
    #[error("transport identity input/output: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport identity: {0}")]
    Certificate(String),
}
