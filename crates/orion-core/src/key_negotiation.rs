//! Orion client for authenticated pre-WireGuard key negotiation.
//!
//! The certificate and CA are public profile material. The PKCS#8 private key
//! is supplied at connection time by the shell's protected identity store and
//! is never serialized by this module.

use std::{net::SocketAddr, time::Duration};

use aether::{
    key_negotiation::{
        authenticate_confirmation, authenticate_request, derive_negotiated_psk,
        static_psk_commitment, KeyNegotiationRequest, PqCertificate, ProtectionMode,
        KEY_NEGOTIATION_NONCE_LEN, KEY_NEGOTIATION_VERSION, SERVER_CHALLENGE_LEN,
    },
    pq::{Kem, MlKem1024Kem},
    SecretString,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::Engine as _;
use helios_key_negotiation::{
    client_endpoint_on_socket, negotiate, request_challenge, ClientSession, TlsIdentity,
};
use zeroize::Zeroizing;

use crate::ClientProfile;

/// Certificate chain and PKCS#8 key returned by a protected OS identity store.
pub struct ClientIdentity {
    pub certificate_chain: Vec<Vec<u8>>,
    pub private_key: Vec<u8>,
    /// JSON application certificate signed with ML-DSA-87.
    pub pq_certificate: Vec<u8>,
    /// Raw ML-DSA-87 key loaded from the protected store.
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
    /// JSON ML-DSA-87 client certificate.
    pub client_pq_certificate: Vec<u8>,
    /// Raw ML-DSA-87 client private key.
    pub client_pq_private_key: Vec<u8>,
    /// CA certificate that authenticates the gateway certificate.
    pub gateway_ca: Vec<u8>,
    /// Pinned self-signed ML-DSA-87 gateway certificate.
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
    server_challenge: [u8; SERVER_CHALLENGE_LEN],
    client_pq_private_key: Zeroizing<Vec<u8>>,
    gateway_pq_public_key: String,
}

impl NegotiatedKey {
    /// Identifier the gateway records as this slot's owner.
    ///
    /// Needed later to release it: the gateway only accepts a release naming
    /// the transaction that currently owns the slot, so a delayed one cannot
    /// dismantle a tunnel a newer negotiation just built.
    pub fn transaction_id(&self) -> [u8; KEY_NEGOTIATION_NONCE_LEN] {
        self.transaction_id
    }

    /// Commits only after the caller has seen a WireGuard handshake succeed
    /// with the PSK this negotiation just installed.
    ///
    /// The connection is closed on the way out. v4 handed back a liveness
    /// link whose closure released the PSK; that tied a tunnel's life to a
    /// control connection on a WAN path, so any blip over 35 seconds killed a
    /// healthy tunnel. Liveness is now read from the data plane, and the PSK
    /// is removed only by an explicit release, a replacement, a revocation or
    /// a deadline.
    pub async fn confirm(self) -> Result<()> {
        let transaction = hex_prefix(&self.transaction_id);
        let confirmation = authenticate_confirmation(
            self.server_challenge,
            self.transaction_id,
            self.client_pq_private_key.as_slice(),
        )
        .context("signing the key-negotiation confirmation with ML-DSA-87")?;
        tracing::info!(
            %transaction,
            "key negotiation: sending the confirmation over the QUIC session"
        );
        let started = std::time::Instant::now();
        let commit = self.session.confirm(confirmation).await.with_context(|| {
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
        Ok(())
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

    // The challenge comes first, and the request cannot exist without it: it
    // is signed into the transcript and mixed into the HKDF salt. Asking for
    // it also checks, for free and before any ML-DSA-87 work, that the
    // gateway answering is the one this profile pins.
    let pending = request_challenge(
        &endpoint,
        remote,
        &client.server_name,
        expected_gateway_wg_public_key,
    )
    .await
    .with_context(|| {
        format!(
            "obtaining a key-negotiation challenge from {remote} \
             (server name {})",
            client.server_name
        )
    })?;
    let server_challenge = pending.server_challenge();

    let transaction_id = random_identifier()?;
    let client_nonce = random_identifier()?;
    let mut kem_secret = None;
    let (kem_public_key, commitment) = match mode {
        ProtectionMode::Classic => (None, None),
        ProtectionMode::StaticPsk => {
            let psk = static_psk.context("static mode requires a profile PSK")?;
            // Bound to this transaction, so two sessions with the same PSK
            // present two different values and an observer of the public port
            // has nothing to correlate.
            (
                None,
                Some(static_psk_commitment(
                    psk,
                    &transaction_id,
                    &client_nonce,
                    &server_challenge,
                    client_wg_public_key,
                    expected_gateway_wg_public_key,
                )?),
            )
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
        server_challenge,
        transaction_id,
        mode,
        client_wg_public_key: client_wg_public_key.to_string(),
        // Names the gateway this request is for. Signed, and checked there
        // before any slot moves: without it an authentic request could be
        // replayed against another gateway sharing the operator CA.
        gateway_wg_public_key: expected_gateway_wg_public_key.to_string(),
        server_name: client.server_name.clone(),
        gateway_certificate_fingerprint: client
            .gateway_pq_certificate
            .fingerprint()
            .context("computing the pinned gateway certificate fingerprint")?,
        client_nonce,
        // A secondary control since v5: it discards a delayed request before
        // any cryptography and names a drifting clock. The challenge above is
        // what makes replay impossible.
        timestamp_unix: unix_time_now()?,
        kem_public_key,
        static_psk_commitment: commitment,
    };
    let client_pq_certificate: PqCertificate =
        serde_json::from_slice(&client.client_pq_certificate)
            .context("decoding the client PQ certificate")?;
    let authenticated_request = authenticate_request(
        request,
        client_pq_certificate,
        &client.client_pq_private_key,
    )
    .context("signing the key-negotiation request with ML-DSA-87")?;
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
    let (authenticated_response, session) = negotiate(&endpoint, pending, &authenticated_request)
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
        server_challenge,
        mode,
        psk,
        confirmation_timeout: Duration::from_secs(response.confirmation_timeout_secs.into()),
        session,
        transaction_id,
        client_pq_private_key: Zeroizing::new(client.client_pq_private_key),
        gateway_pq_public_key: client.gateway_pq_certificate.ml_dsa_87_public_key.clone(),
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
    let mut value = [0u8; KEY_NEGOTIATION_NONCE_LEN];
    aether::random::fill_public(&mut value)
        .map_err(|error| anyhow::anyhow!("the approved DRBG refused: {error}"))?;
    // A shape check, not a generator check: the DRBG above is what makes the
    // value unpredictable, and an all-zero identifier is refused on receipt.
    if value.iter().all(|byte| *byte == 0) {
        return Err(anyhow::anyhow!("the DRBG returned an invalid identifier"));
    }
    Ok(value)
}

/// Longest Orion waits for the gateway to answer a release.
///
/// Two seconds, and the disconnection continues regardless. The request is a
/// courtesy: it lets the gateway zeroise the secret now instead of at the
/// 300-second reclamation, and refusing to disconnect because a courtesy did
/// not land would be worse than the courtesy. It also cannot be waited on
/// honestly — clearing the PSK can make the response untransportable on the
/// very WireGuard session that carried the request.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(2);

/// Tells the gateway to drop the PSK a committed negotiation installed.
///
/// Sent **inside the tunnel**, on the internal API, before the adapter comes
/// down. The public negotiation port exists because a key has to be agreed
/// before WireGuard is up; a disconnection is the opposite case, and reopening
/// that port to announce one re-authenticated by mTLS, challenge and ML-DSA a
/// machine already holding an encrypted, mutually authenticated channel to the
/// gateway (spec §7.5).
///
/// There is no fallback: if `heliosd_url` is absent, does not name an address
/// the tunnel routes, or the request fails, Orion unmounts and lets the
/// gateway's data-plane reclamation do the rest. Falling back to the public
/// port would reintroduce exactly the second listener this removed.
pub async fn release_for_profile(
    profile: &ClientProfile,
    identities: &dyn IdentityProvider,
    installed_transaction_id: [u8; KEY_NEGOTIATION_NONCE_LEN],
) -> Result<()> {
    let settings = profile
        .key_negotiation
        .as_ref()
        .context("profile has no key-negotiation settings")?;
    let url = profile
        .heliosd_url
        .as_deref()
        .context("profile carries no internal Helios URL to send the release to")?;
    // Resolved before anything is signed: the address must be a literal the
    // tunnel routes. A hostname would mean a DNS lookup, and Orion's DNS is
    // not tunnelled — the query would leave in clear, and the answer could
    // point the release anywhere.
    let target = tunnel_routed_address(url, &profile.allowed_ips)?;
    let client_wg_public_key = profile
        .public_key()
        .context("deriving the client WireGuard public key")?;
    let identity = identities.load(&settings.identity).await.with_context(|| {
        format!(
            "loading key-negotiation identity {} to release the PSK",
            settings.identity
        )
    })?;
    let client_pq_certificate: PqCertificate = serde_json::from_slice(&identity.pq_certificate)
        .context("decoding the client PQ certificate")?;

    let release = aether::key_negotiation::authenticate_release(
        aether::key_negotiation::PskRelease {
            protocol_version: KEY_NEGOTIATION_VERSION,
            installed_transaction_id,
            client_wg_public_key,
            gateway_wg_public_key: profile.peer_public_key.clone(),
        },
        client_pq_certificate,
        &identity.pq_private_key,
    )
    .context("signing the PSK release")?;

    post_release(target, &release).await?;
    tracing::info!(
        transaction = %hex_prefix(&installed_transaction_id),
        "key negotiation: the gateway acknowledged the release request"
    );
    Ok(())
}

/// Posts the signed release to an address [`tunnel_routed_address`] approved.
///
/// Separate from the signing above so the transport can be exercised on its
/// own: what this function refuses is not visible in the URL, and each refusal
/// answers a way the request could still leave the tunnel or come back wrong.
async fn post_release(
    target: reqwest::Url,
    release: &aether::key_negotiation::AuthenticatedPskRelease,
) -> Result<()> {
    let http = reqwest::Client::builder()
        .timeout(RELEASE_TIMEOUT)
        // Two defaults that would undo the address check that just ran. An
        // environment proxy sends the request to a host the profile never
        // named, in clear on the physical interface; a redirect lets whoever
        // answered choose the next hop, which turns a validated destination
        // into a suggestion. Neither has any use here — the target is one
        // fixed address inside the tunnel.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building the release HTTP client")?;
    let response = http
        .post(target)
        .json(release)
        .send()
        .await
        .context("sending the signed PSK release inside the tunnel")?;
    // Exactly `204`, not any 2xx. The endpoint has one success shape, and the
    // gateway also serves an embedded single-page app from the same origin: a
    // request that missed the handler falls through to that static handler,
    // which answers `200` with HTML. Treating it as success would report a
    // release the state machine never saw — and a redirect refused above
    // surfaces here as its own `3xx` rather than as a followed hop.
    if response.status() != reqwest::StatusCode::NO_CONTENT {
        anyhow::bail!(
            "the gateway did not accept the PSK release (HTTP {})",
            response.status().as_u16()
        );
    }
    Ok(())
}

/// Builds the release URL, refusing anything the tunnel would not carry.
///
/// Parsed by the **same** URL implementation the HTTP client uses, and that is
/// the point. Hand-splitting the string validated a destination the client
/// never contacted: `http://100.64.0.1:8080@evil.example` reads as an address
/// followed by a port to a naive parser, while every RFC 3986 parser reads
/// `100.64.0.1:8080` as userinfo and `evil.example` as the host. Any check
/// that does not run on the parse the request is built from is decoration.
///
/// Four conditions, all before a signature is produced:
///
/// - no userinfo, no path, no query, no fragment — a release goes to one fixed
///   endpoint, so every one of these is either an attempt to move the target
///   or a profile that is not describing this API;
/// - the host is an **IP literal**, never a name: Orion's DNS is not
///   tunnelled, so resolving one would leak the query in clear and let the
///   answer point the release anywhere;
/// - that address falls inside the profile's `AllowedIPs`, which is
///   WireGuard's cryptographic routing table. Outside it, the request leaves
///   through the physical interface, in clear, to whoever holds the address;
/// - `http` or `https`, nothing else.
fn tunnel_routed_address(heliosd_url: &str, allowed_ips: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(heliosd_url).context("internal Helios URL is unreadable")?;
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("internal Helios URL must use http:// or https://");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!(
            "internal Helios URL must not carry userinfo — the host it names is not \
             the host that would be contacted"
        );
    }
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("internal Helios URL must be a bare origin: no path, query or fragment");
    }
    let address = match url.host() {
        Some(url::Host::Ipv4(address)) => std::net::IpAddr::V4(address),
        Some(url::Host::Ipv6(address)) => std::net::IpAddr::V6(address),
        _ => {
            anyhow::bail!("the release is only sent to a literal gateway address, never to a name")
        }
    };
    if !allowed_ips
        .split(',')
        .filter_map(|entry| parse_prefix(entry.trim()))
        .any(|(network, prefix)| prefix_contains(network, prefix, address))
    {
        anyhow::bail!(
            "the internal Helios address {address} is outside the tunnel's AllowedIPs — \
             the release would leave in clear"
        );
    }
    url.set_path("/api/key-negotiation/release");
    Ok(url)
}

fn parse_prefix(entry: &str) -> Option<(std::net::IpAddr, u32)> {
    let (address, prefix) = entry.split_once('/')?;
    let address: std::net::IpAddr = address.trim().parse().ok()?;
    let prefix: u32 = prefix.trim().parse().ok()?;
    let width = if address.is_ipv4() { 32 } else { 128 };
    (prefix <= width).then_some((address, prefix))
}

fn prefix_contains(network: std::net::IpAddr, prefix: u32, address: std::net::IpAddr) -> bool {
    match (network, address) {
        (std::net::IpAddr::V4(network), std::net::IpAddr::V4(address)) => {
            let mask = shift_mask::<u32>(prefix);
            u32::from(network) & mask == u32::from(address) & mask
        }
        (std::net::IpAddr::V6(network), std::net::IpAddr::V6(address)) => {
            let mask = shift_mask::<u128>(prefix);
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

/// `!0 << (width - prefix)`, with `/0` handled rather than shifted.
///
/// Shifting an integer by its own width is undefined in C and a panic in
/// debug Rust; `0.0.0.0/0` is a perfectly ordinary `AllowedIPs` entry.
fn shift_mask<T: PrimitiveMask>(prefix: u32) -> T {
    if prefix == 0 {
        T::ZERO
    } else {
        T::MAX << (T::WIDTH - prefix)
    }
}

trait PrimitiveMask: Copy + std::ops::Shl<u32, Output = Self> {
    const ZERO: Self;
    const MAX: Self;
    const WIDTH: u32;
}

impl PrimitiveMask for u32 {
    const ZERO: Self = 0;
    const MAX: Self = u32::MAX;
    const WIDTH: u32 = 32;
}

impl PrimitiveMask for u128 {
    const ZERO: Self = 0;
    const MAX: Self = u128::MAX;
    const WIDTH: u32 = 128;
}

#[cfg(test)]
mod tests {
    use super::tunnel_routed_address;
    use aether::key_negotiation::{KEY_NEGOTIATION_NONCE_LEN, KEY_NEGOTIATION_VERSION};

    const TUNNEL: &str = "100.64.0.0/10, 192.168.1.0/24";

    fn target(url: &str) -> String {
        tunnel_routed_address(url, TUNNEL).unwrap().to_string()
    }

    /// The release only ever goes to a literal address the tunnel routes.
    #[test]
    fn a_release_target_must_be_a_literal_inside_the_tunnel() {
        assert_eq!(
            target("http://100.64.0.1:8080"),
            "http://100.64.0.1:8080/api/key-negotiation/release"
        );
        // A trailing slash is the same origin, not a second one.
        assert_eq!(
            target("http://100.64.0.1:8080/"),
            "http://100.64.0.1:8080/api/key-negotiation/release"
        );
    }

    /// The check has to run on the parse the request is built from.
    ///
    /// `http://100.64.0.1:8080@evil.example` reads as an address and a port to
    /// a hand-written splitter, and as userinfo followed by the host
    /// `evil.example` to every RFC 3986 parser — which is the one the HTTP
    /// client uses. Validating the first and contacting the second is the
    /// whole bug.
    #[test]
    fn a_url_carrying_userinfo_is_refused() {
        for url in [
            "http://100.64.0.1:8080@evil.example",
            "http://100.64.0.1:8080@evil.example/",
            "http://user@100.64.0.1:8080",
            "http://100.64.0.1@100.64.0.1:8080",
        ] {
            let outcome = tunnel_routed_address(url, TUNNEL);
            assert!(outcome.is_err(), "{url} must be refused: {outcome:?}");
        }
    }

    /// A path, a query or a fragment either aims at something other than this
    /// endpoint, or would push the request onto the SPA fallback — which
    /// answers `200` with HTML and no handler behind it.
    #[test]
    fn a_url_that_is_not_a_bare_origin_is_refused() {
        for url in [
            "http://100.64.0.1:8080/ui",
            "http://100.64.0.1:8080/?a=b",
            "http://100.64.0.1:8080/#fragment",
        ] {
            let outcome = tunnel_routed_address(url, TUNNEL);
            assert!(outcome.is_err(), "{url} must be refused: {outcome:?}");
        }
    }

    /// A name would mean a DNS lookup, and Orion's DNS is not tunnelled: the
    /// query would leave in clear and the answer could point the release
    /// anywhere.
    #[test]
    fn a_hostname_is_refused_before_anything_is_signed() {
        assert!(tunnel_routed_address("http://gateway.example:8080", TUNNEL).is_err());
        // Including one that merely looks like an address.
        assert!(tunnel_routed_address("http://100.64.0.1.example:8080", TUNNEL).is_err());
    }

    /// Anything but `http`/`https` never reaches a client that speaks neither.
    #[test]
    fn a_foreign_scheme_is_refused() {
        assert!(tunnel_routed_address("file:///etc/passwd", TUNNEL).is_err());
        assert!(tunnel_routed_address("ftp://100.64.0.1:8080", TUNNEL).is_err());
    }

    /// Outside `AllowedIPs` the request leaves through the physical
    /// interface, in clear, to whoever holds that address.
    #[test]
    fn an_address_outside_the_allowed_ips_is_refused() {
        assert!(tunnel_routed_address("http://203.0.113.9:8080", TUNNEL).is_err());
        assert!(tunnel_routed_address("http://192.168.1.44:8080", TUNNEL).is_ok());
    }

    // --- Transport ---
    //
    // What follows is not about the URL any more: the address is already
    // approved, and these are the ways the request could still leave the
    // tunnel or come back meaning something else.

    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A one-shot HTTP server. Returns its origin and what it was asked for.
    async fn release_server(response: String) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local listener");
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = vec![0u8; 8192];
                let read = stream.read(&mut request).await.unwrap_or(0);
                recorded.lock().unwrap().push(
                    String::from_utf8_lossy(&request[..read])
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .to_string(),
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        (origin, seen)
    }

    /// A syntactically complete release. Nothing here verifies its signature:
    /// these tests are about where the bytes go and what an answer means.
    fn signed_release() -> aether::key_negotiation::AuthenticatedPskRelease {
        use aether::key_negotiation::{
            AuthenticatedPskRelease, PqCertificate, PqCertificateRole, PskRelease,
        };

        AuthenticatedPskRelease {
            release: PskRelease {
                protocol_version: KEY_NEGOTIATION_VERSION,
                installed_transaction_id: [9; KEY_NEGOTIATION_NONCE_LEN],
                client_wg_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                gateway_wg_public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            },
            certificate: PqCertificate {
                version: aether::key_negotiation::PQ_CERTIFICATE_VERSION,
                serial: [3; KEY_NEGOTIATION_NONCE_LEN],
                subject: "orion".into(),
                issuer: "operator".into(),
                role: PqCertificateRole::Client,
                wireguard_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                ml_dsa_87_public_key: String::new(),
                not_before_unix: 0,
                not_after_unix: u64::MAX,
                ml_dsa_87_signature: String::new(),
            },
            ml_dsa_87_signature: String::new(),
        }
    }

    fn loopback_target(origin: &str) -> reqwest::Url {
        tunnel_routed_address(origin, "127.0.0.0/8").expect("loopback stands in for the tunnel")
    }

    /// `204` and only `204` is a release the gateway actually applied.
    #[tokio::test]
    async fn a_two_hundred_from_the_spa_fallback_is_not_a_release() {
        let body = "<!doctype html><title>Orion</title>";
        let (origin, seen) = release_server(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        ))
        .await;

        let outcome = super::post_release(loopback_target(&origin), &signed_release()).await;

        assert!(
            outcome.is_err(),
            "the static handler answers 200 without the state machine ever seeing the release"
        );
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_two_hundred_and_four_is_accepted() {
        let (origin, seen) = release_server(
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;

        super::post_release(loopback_target(&origin), &signed_release())
            .await
            .expect("204 is the one success shape");

        assert_eq!(
            seen.lock().unwrap().first().map(String::as_str),
            Some("POST /api/key-negotiation/release HTTP/1.1")
        );
    }

    /// A redirect lets whoever answered choose the next hop, which would undo
    /// the address check: the second hop is never validated against
    /// `AllowedIPs` and can sit outside the tunnel entirely.
    #[tokio::test]
    async fn a_redirect_is_never_followed() {
        let (elsewhere, followed) = release_server(
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        let (origin, seen) = release_server(format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {elsewhere}/api/key-negotiation/release\
             \r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ))
        .await;

        let outcome = super::post_release(loopback_target(&origin), &signed_release()).await;

        assert!(outcome.is_err(), "a 3xx is not a release");
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(
            followed.lock().unwrap().is_empty(),
            "the redirect target must never be contacted"
        );
    }

    /// An environment proxy would send the release to a host the profile
    /// never named, in clear on the physical interface.
    ///
    /// The variables are set for the duration of this test only. It is the
    /// single test in this crate that touches them, and no other test here
    /// builds an HTTP client, so nothing else can observe them.
    #[tokio::test]
    async fn an_environment_proxy_is_ignored() {
        let (proxy, proxied) = release_server(
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        let (origin, seen) = release_server(
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        std::env::set_var("HTTP_PROXY", &proxy);
        std::env::set_var("http_proxy", &proxy);

        let outcome = super::post_release(loopback_target(&origin), &signed_release()).await;

        std::env::remove_var("HTTP_PROXY");
        std::env::remove_var("http_proxy");

        outcome.expect("the request must reach the gateway directly");
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(
            proxied.lock().unwrap().is_empty(),
            "the release must not be handed to a proxy the profile never named"
        );
    }

    /// `0.0.0.0/0` is an ordinary full-tunnel entry, and its mask is the one
    /// case a naive shift gets wrong.
    #[test]
    fn a_default_route_carries_every_address() {
        assert!(tunnel_routed_address("http://203.0.113.9:8080", "0.0.0.0/0").is_ok());
        assert!(tunnel_routed_address("http://[fd00::1]:8080", "0.0.0.0/0").is_err());
        assert_eq!(
            tunnel_routed_address("http://[fd00::1]:8080", "fd00::/8")
                .unwrap()
                .to_string(),
            "http://[fd00::1]:8080/api/key-negotiation/release"
        );
    }
}
