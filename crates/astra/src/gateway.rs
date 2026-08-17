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
//! # Limite connue
//!
//! Nothing in this build calls [`GatewayChannel::stage`] on its own: issuing a
//! staging authorization needs the operator approval of the 15 August 2026
//! amendment, whose routes answer `501`. The channel is opened at startup
//! anyway — and its pin checked there — because an unusable pairing found at
//! deployment costs a command, and the same pairing found at the first rotation
//! costs a night. See [`docs/testing/TESTING.md`](../../../docs/testing/TESTING.md)
//! for what a WSL2 build does and does not prove about the veth itself.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aether::certificates::client::{
    ClientCertificateStageAuthorization, GatewayCertificateStageReceipt,
};
use aether::certificates::encoding::{DerCertificate, WireGuardKey};
use aether::certificates::revocation::EmergencyCertificateRevocation;
use helios_api::internal::{
    ChannelError, ChannelIdentity, GatewayLifecycleClient, PeerCertificateStateView,
};

/// Astra's transport certificate inside its state volume.
pub const CHANNEL_CERTIFICATE_FILE: &str = "channel-cert.der";
/// Its PKCS#8 private key. `0600`, in the same volume, and nothing else.
pub const CHANNEL_KEY_FILE: &str = "channel-key.der";

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
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};

    let certificate_path = state_dir.join(CHANNEL_CERTIFICATE_FILE);
    let key_path = state_dir.join(CHANNEL_KEY_FILE);
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

    let mut params = CertificateParams::new(vec!["astra.internal".to_string()])
        .map_err(|error| ChannelInitError::Certificate(error.to_string()))?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    // `clientAuth` and nothing else: Astra dials, it never answers on this
    // link, and the gateway's verifier refuses a pin that cannot be a client.
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
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
