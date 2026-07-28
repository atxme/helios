//! Orion client for authenticated pre-WireGuard key negotiation.
//!
//! The certificate and CA are public profile material. The PKCS#8 private key
//! is supplied at connection time by the shell's protected identity store and
//! is never serialized by this module.

use std::{net::SocketAddr, time::Duration};

use aether::{
    key_negotiation::{
        authenticate_confirmation, authenticate_request, derive_negotiated_psk,
        static_psk_fingerprint, KeyNegotiationRequest, PqCertificate, ProtectionMode,
        KEY_NEGOTIATION_NONCE_LEN, KEY_NEGOTIATION_VERSION,
    },
    pq::{Kem, MlKem1024Kem},
    SecretString,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::Engine as _;
use helios_key_negotiation::{
    client_endpoint_on_socket, negotiate, ClientSession, SessionLink, TlsIdentity,
};
use zeroize::Zeroizing;

use crate::ClientProfile;

/// Certificate chain and PKCS#8 key returned by a protected OS identity store.
pub struct ClientIdentity {
    pub certificate_chain: Vec<Vec<u8>>,
    pub private_key: Vec<u8>,
    /// JSON application certificate signed with ML-DSA-65.
    pub pq_certificate: Vec<u8>,
    /// Raw ML-DSA-65 key loaded from the protected store.
    pub pq_private_key: Vec<u8>,
}

/// Boundary implemented by the Orion shell for Windows Credential Manager,
/// DPAPI or an equivalent protected platform store.
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    async fn load(&self, identity: &str) -> Result<ClientIdentity>;
}

/// Reads the identity from the machine's protected store.
///
/// The decoding lives here rather than in the store because it is the
/// protocol side that knows what shape each half must take: the store only
/// guarantees the bytes came back exactly as they were sealed.
#[async_trait]
impl IdentityProvider for crate::identity_store::ProtectedIdentityStore {
    async fn load(&self, identity: &str) -> Result<ClientIdentity> {
        let bundle = self.load(identity)?;
        let decoder = base64::engine::general_purpose::STANDARD;
        Ok(ClientIdentity {
            certificate_chain: bundle
                .certificate_chain
                .iter()
                .map(|certificate| {
                    decoder
                        .decode(certificate.trim())
                        .context("decoding a client certificate of the protected identity")
                })
                .collect::<Result<Vec<_>>>()?,
            private_key: decoder
                .decode(bundle.private_key.trim())
                .context("decoding the client private key of the protected identity")?,
            pq_certificate: decoder
                .decode(bundle.pq_certificate.trim())
                .context("decoding the client PQ certificate of the protected identity")?,
            pq_private_key: decoder
                .decode(bundle.pq_private_key.trim())
                .context("decoding the client PQ private key of the protected identity")?,
        })
    }
}

/// Public connection settings and protected client identity material.
pub struct KeyNegotiationClient {
    /// Public UDP endpoint of the gateway key-negotiation service.
    pub remote: String,
    /// DNS identity authenticated by the gateway certificate.
    pub server_name: String,
    /// Client leaf certificate followed by any intermediate certificates.
    pub client_certificate_chain: Vec<Vec<u8>>,
    /// Client PKCS#8 key loaded from an OS-protected store.
    pub client_private_key: Vec<u8>,
    /// JSON ML-DSA-65 client certificate.
    pub client_pq_certificate: Vec<u8>,
    /// Raw ML-DSA-65 client private key.
    pub client_pq_private_key: Vec<u8>,
    /// CA certificate that authenticates the gateway certificate.
    pub gateway_ca: Vec<u8>,
    /// Pinned self-signed ML-DSA-65 gateway certificate.
    pub gateway_pq_certificate: PqCertificate,
    /// Orion refuses any locally selected mode below this floor.
    pub minimum_mode: ProtectionMode,
}

impl std::fmt::Debug for KeyNegotiationClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyNegotiationClient")
            .field("remote", &self.remote)
            .field("server_name", &self.server_name)
            .field(
                "client_certificate_chain",
                &self.client_certificate_chain.len(),
            )
            .field("client_private_key", &"***")
            .field("client_pq_certificate", &self.client_pq_certificate.len())
            .field("client_pq_private_key", &"***")
            .field("gateway_ca", &self.gateway_ca.len())
            .field("gateway_pq_certificate", &"pinned")
            .field("minimum_mode", &self.minimum_mode)
            .finish()
    }
}

/// Prepared WireGuard slot and an uncommitted server transaction.
///
/// Dropping this value without calling [`Self::confirm`] closes the QUIC
/// stream. Helios then restores the peer's previous PSK slot.
pub struct NegotiatedKey {
    pub mode: ProtectionMode,
    pub psk: Option<SecretString>,
    pub confirmation_timeout: Duration,
    session: ClientSession,
    transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
    client_pq_private_key: Zeroizing<Vec<u8>>,
    gateway_pq_public_key: String,
}

impl NegotiatedKey {
    /// Commits only after the caller has seen a WireGuard handshake succeed
    /// with the PSK this negotiation just installed.
    ///
    /// Returns the live link: as long as it is held, the gateway considers
    /// this tunnel alive. Closing it — or dropping it, or crashing — tells the
    /// gateway to release the slot at once instead of waiting for handshakes
    /// to go stale.
    pub async fn confirm(self) -> Result<SessionLink> {
        let transaction = hex_prefix(&self.transaction_id);
        let confirmation =
            authenticate_confirmation(self.transaction_id, self.client_pq_private_key.as_slice())
                .context("signing the key-negotiation confirmation with ML-DSA-65")?;
        tracing::info!(
            %transaction,
            "key negotiation: sending the confirmation over the QUIC session"
        );
        let started = std::time::Instant::now();
        let (commit, link) = self.session.confirm(confirmation).await.with_context(|| {
            // This is where a session that was fine at negotiation time dies:
            // the WireGuard interface has come up in between, and the route to
            // the gateway is no longer the one this connection was opened on.
            // Saying how long we waited separates a refusal from a silence.
            format!(
                "confirming the key-negotiation transaction {transaction} \
                 (no answer after {} ms — the QUIC session opened before the \
                 tunnel came up may no longer be routable)",
                started.elapsed().as_millis()
            )
        })?;
        commit
            .verify(&self.gateway_pq_public_key)
            .context("verifying the gateway PQ commit acknowledgment")?;
        tracing::info!(
            %transaction,
            elapsed_ms = started.elapsed().as_millis(),
            "key negotiation: gateway committed the slot"
        );
        Ok(link)
    }
}

/// Negotiates exactly the mode selected by Orion.
///
/// The response is bound to the transaction, both nonces and both WireGuard
/// identities. A server response selecting a different mode is rejected.
pub async fn prepare(
    client: KeyNegotiationClient,
    mode: ProtectionMode,
    client_wg_public_key: &str,
    expected_gateway_wg_public_key: &str,
    static_psk: Option<&str>,
) -> Result<NegotiatedKey> {
    if !mode.satisfies(client.minimum_mode) {
        anyhow::bail!("selected mode is below the profile security floor");
    }
    let identity = TlsIdentity {
        certificate_chain: client.client_certificate_chain,
        private_key: client.client_private_key,
    };
    aether::wg::validate_key(client_wg_public_key)
        .context("invalid client WireGuard public key")?;
    aether::wg::validate_key(expected_gateway_wg_public_key)
        .context("invalid gateway WireGuard public key")?;

    let transaction_id = random_identifier()?;
    let client_nonce = random_identifier()?;
    let mut kem_secret = None;
    let (kem_public_key, static_psk_fingerprint) = match mode {
        ProtectionMode::Classic => (None, None),
        ProtectionMode::StaticPsk => {
            let psk = static_psk.context("static mode requires a profile PSK")?;
            (None, Some(static_psk_fingerprint(psk)?))
        }
        ProtectionMode::MlKem => {
            let (secret, public) =
                MlKem1024Kem::generate().context("generating an ML-KEM-1024 keypair")?;
            kem_secret = Some(secret);
            (Some(public), None)
        }
    };
    let request = KeyNegotiationRequest {
        protocol_version: KEY_NEGOTIATION_VERSION,
        transaction_id,
        mode,
        client_wg_public_key: client_wg_public_key.to_string(),
        client_nonce,
        // Signed and bound into the derivation: the gateway refuses a request
        // whose clock drifts too far, which bounds replay in time rather than
        // in cache size. A machine with a wrong clock is refused with a
        // message naming the clock.
        timestamp_unix: unix_time_now()?,
        kem_public_key,
        static_psk_fingerprint,
    };
    let client_pq_certificate: PqCertificate =
        serde_json::from_slice(&client.client_pq_certificate)
            .context("decoding the client PQ certificate")?;
    let authenticated_request = authenticate_request(
        request,
        client_pq_certificate,
        &client.client_pq_private_key,
    )
    .context("signing the key-negotiation request with ML-DSA-65")?;

    let remote = resolve_remote(&client.remote).await?;
    // Pinned off the tunnel before anything is sent. This session opens
    // before the WireGuard interface exists and has to outlive it coming up;
    // a socket left on the wildcard address changes egress interface at that
    // moment, and the gateway sees a QUIC migration mid-transaction. See
    // `crate::net_pin`.
    let socket = crate::net_pin::negotiation_socket(remote, crate::net_pin::TUNNEL_IFNAME)
        .context("opening the key-negotiation socket")?;
    let endpoint = client_endpoint_on_socket(socket, &identity, client.gateway_ca)
        .context("building the authenticated key-negotiation client")?;
    // Everything needed to tell a routing problem from a refusal: where we
    // dial, under which name the certificate is checked, and what the request
    // weighs — the PQ material is what makes these datagrams large.
    tracing::info!(
        endpoint = %client.remote,
        resolved = %remote,
        server_name = %client.server_name,
        ?mode,
        floor = ?client.minimum_mode,
        transaction = %hex_prefix(&transaction_id),
        request_bytes = serde_json::to_vec(&authenticated_request)
            .map(|raw| raw.len())
            .unwrap_or_default(),
        "key negotiation: dialing the gateway"
    );
    let started = std::time::Instant::now();
    let (authenticated_response, session) = negotiate(
        &endpoint,
        remote,
        &client.server_name,
        &authenticated_request,
    )
    .await
    .with_context(|| {
        format!(
            "performing key negotiation with {remote} (server name {}, after {} ms)",
            client.server_name,
            started.elapsed().as_millis()
        )
    })?;
    tracing::info!(
        elapsed_ms = started.elapsed().as_millis(),
        selected_mode = ?authenticated_response.response.selected_mode,
        confirmation_timeout_s = authenticated_response.response.confirmation_timeout_secs,
        "key negotiation: gateway answered"
    );
    authenticated_response
        .verify(
            &authenticated_request.request,
            &client.gateway_pq_certificate,
            &client.server_name,
            expected_gateway_wg_public_key,
            unix_time_now()?,
        )
        .context("rejecting an invalid PQ-authenticated key-negotiation response")?;
    let request = authenticated_request.request;
    let response = authenticated_response.response;

    let psk = match mode {
        ProtectionMode::Classic => None,
        ProtectionMode::StaticPsk => Some(SecretString::new(
            static_psk
                .context("static PSK disappeared during negotiation")?
                .to_string(),
        )),
        ProtectionMode::MlKem => {
            let secret_key = kem_secret.context("ML-KEM secret key is unavailable")?;
            let ciphertext = response
                .kem_ciphertext
                .as_deref()
                .context("ML-KEM response has no ciphertext")?;
            let shared_secret = MlKem1024Kem::decapsulate(&secret_key, ciphertext)
                .context("decapsulating the ML-KEM-1024 ciphertext")?;
            let derived = derive_negotiated_psk(&shared_secret, &request, &response)
                .context("deriving the WireGuard PSK")?;
            Some(SecretString::new(
                base64::engine::general_purpose::STANDARD.encode(derived.as_slice()),
            ))
        }
    };

    Ok(NegotiatedKey {
        mode,
        psk,
        confirmation_timeout: Duration::from_secs(response.confirmation_timeout_secs.into()),
        session,
        transaction_id,
        client_pq_private_key: Zeroizing::new(client.client_pq_private_key),
        gateway_pq_public_key: client.gateway_pq_certificate.ml_dsa_65_public_key.clone(),
    })
}

/// Loads the protected identity and prepares the profile's selected mode.
pub async fn prepare_for_profile(
    profile: &ClientProfile,
    identities: &dyn IdentityProvider,
) -> Result<NegotiatedKey> {
    let settings = profile
        .key_negotiation
        .as_ref()
        .context("profile has no key-negotiation settings")?;
    let gateway_ca = base64::engine::general_purpose::STANDARD
        .decode(settings.gateway_ca_der.trim())
        .context("decoding the gateway CA certificate")?;
    let gateway_pq_certificate: PqCertificate = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(settings.gateway_pq_certificate.trim())
            .context("decoding the gateway PQ certificate")?,
    )
    .context("parsing the gateway PQ certificate")?;
    let client_wg_public_key = profile
        .public_key()
        .context("deriving the client WireGuard public key")?;
    tracing::info!(
        identity = %settings.identity,
        endpoint = %settings.endpoint,
        mode = ?settings.mode,
        floor = ?settings.minimum_mode,
        "key negotiation: loading the protected identity"
    );
    let identity = identities.load(&settings.identity).await.with_context(|| {
        format!(
            "loading key-negotiation identity {} from the machine's protected store",
            settings.identity
        )
    })?;
    prepare(
        KeyNegotiationClient {
            remote: settings.endpoint.clone(),
            server_name: settings.server_name.clone(),
            client_certificate_chain: identity.certificate_chain,
            client_private_key: identity.private_key,
            client_pq_certificate: identity.pq_certificate,
            client_pq_private_key: identity.pq_private_key,
            gateway_ca,
            gateway_pq_certificate,
            minimum_mode: settings.minimum_mode,
        },
        settings.mode,
        &client_wg_public_key,
        &profile.peer_public_key,
        profile.preshared_key.as_deref(),
    )
    .await
}

/// First bytes of an identifier, for correlating with the gateway's logs.
///
/// A prefix rather than the whole value: it is long enough to pair two lines
/// in the same session, and short enough to be read out loud.
fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unix_time_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock predates the Unix epoch")?
        .as_secs())
}

async fn resolve_remote(value: &str) -> Result<SocketAddr> {
    let mut addresses = tokio::net::lookup_host(value)
        .await
        .with_context(|| format!("resolving key-negotiation endpoint {value}"))?;
    addresses
        .find(|address| address.port() != 0)
        .context("key-negotiation endpoint resolved to no usable address")
}

fn random_identifier() -> Result<[u8; KEY_NEGOTIATION_NONCE_LEN]> {
    use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};

    let mut value = [0u8; KEY_NEGOTIATION_NONCE_LEN];
    SystemRandom::new()
        .fill(&mut value)
        .map_err(|_| anyhow::anyhow!("system CSPRNG unavailable"))?;
    if value.iter().all(|byte| *byte == 0) {
        return Err(anyhow::anyhow!(
            "system CSPRNG returned an invalid identifier"
        ));
    }
    Ok(value)
}
