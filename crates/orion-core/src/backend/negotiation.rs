//! Connecting through the pre-WireGuard key negotiation: bounded attempts,
//! the WireGuard endpoint they settle on, and the commit after a fresh
//! handshake.

use super::*;

/// Handshake polling period while a negotiation waits to be confirmed.
///
/// Four times a second rather than once: here the poll is on the critical
/// path of the connection — the confirmation cannot be sent before a fresh
/// handshake is seen, so every tick spent waiting is a tick the user spends
/// looking at «connexion…». The read is a local query on the interface, and
/// the wait it shortens lasts a second or two.
const NEGOTIATION_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Renegotiations a stale handshake may trigger before the tunnel gives up.
///
/// Three, and the bound matters as much as the repair: a gateway that is
/// durably absent must not be met with a permanent negotiation loop. Each
/// attempt is itself the bounded loop of [`KEY_NEGOTIATION_ATTEMPTS`], so the
/// spacing the specification asks for is already there — and wider than the
/// two seconds it names, because §4.5 arms ten seconds of rest after a
/// rollback and a retry inside that window is rejected by construction.
pub(super) const STALE_RENEGOTIATIONS_ALLOWED: u32 = 3;

/// Negotiations attempted before giving up.
///
/// Three, because the failure this exists for is a **lost message**, and a
/// lost message is not repeated by a fourth try if the first two retries did
/// not carry it.
const KEY_NEGOTIATION_ATTEMPTS: u32 = 3;

/// Pause between two negotiations.
///
/// The gateway arms ten seconds of rest after rolling back a candidate that
/// reached the data plane (v5, sections 4.5 and 11.3). Retrying sooner cannot
/// succeed: it is deliberately rejected, and used to consume Orion's two
/// remaining attempts in four seconds. One extra second keeps the client past
/// the boundary despite scheduling and transport jitter.
pub(super) const KEY_NEGOTIATION_RETRY_DELAY: Duration = Duration::from_secs(11);

/// Errors that cannot be repaired by opening the same authenticated session
/// again.  In particular, a `BadSignature` means that the certificate the
/// gateway serves does not match the one pinned by the profile; retrying it
/// only keeps the UI in `Connexion…` while no state can change.
///
/// Transport timeouts, refused UDP packets and lost responses remain
/// retryable: those are the desynchronisation and transient-network cases the
/// bounded retry loop exists to recover from.
pub(super) fn is_terminal_negotiation_error(error: &anyhow::Error) -> bool {
    if error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<crate::certificate_renewal::RenewalError>(),
            Some(crate::certificate_renewal::RenewalError::ActivationPending { .. })
        )
    }) {
        return true;
    }
    let rendered = format!("{error:#}");
    rendered.contains("invalid peer certificate")
        || rendered.contains("BadSignature")
        || rendered.contains("invalid certificate")
        || rendered.contains("TLS configuration failed")
        || rendered.contains("invalid PKCS#8 private key")
        || rendered.contains("peer did not present a certificate")
}

/// Negotiates, mounts, and recovers from a desynchronised slot.
///
/// # The failure this guards against
///
/// The transaction is only committed once Helios receives the signed
/// confirmation. If that message — or the commit answering it — is lost, the
/// two ends disagree in the worst possible way: Helios restores the previous
/// slot while Orion keeps the PSK it just installed. Every WireGuard handshake
/// then fails, and nothing in either log says why, because **both sides did
/// exactly what they were supposed to do**.
///
/// Retrying resolves it, because a fresh negotiation installs a new PSK on
/// both ends at once. Without this loop the tunnel stayed dead until the user
/// happened to disconnect and reconnect by hand.
///
/// Preparation failures with a deterministic local or certificate cause are
/// not retried: nothing has been installed yet, so there is nothing to
/// resynchronise, and repeating a missing identity three times would only
/// delay an error the user needs now. Network and response failures still use
/// the bounded retry loop below.
///
/// If every attempt fails, the adapter deliberately stays mounted with its
/// desynchronised PSK: WireGuard drops the packets, which is the anti-leak
/// invariant of this module. A dead tunnel is the correct outcome — a leaking
/// one would not be.
pub(super) async fn connect_with_key_negotiation(
    backend: &Arc<dyn VpnBackend>,
    profile: &ClientProfile,
    sink: &EventSink,
    identities: Option<&dyn crate::key_negotiation::IdentityProvider>,
    installed: &Mutex<Option<InstalledNegotiation>>,
    link_lost: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let identities = identities
        .context("the Orion shell did not provide a protected key-negotiation identity store")?;

    let endpoint = profile
        .key_negotiation
        .as_ref()
        .map(|settings| settings.endpoint.clone())
        .unwrap_or_default();

    let mut last_error = None;
    for attempt in 1..=KEY_NEGOTIATION_ATTEMPTS {
        sink(ClientEvent::log(
            "info",
            format!("négociation {attempt}/{KEY_NEGOTIATION_ATTEMPTS} : ouverture vers {endpoint}"),
        ));
        // A failed preparation installed nothing — but it is retried all the
        // same. It used to abort the loop outright, so a transient failure on
        // the second attempt discarded the third: the log showed one warning
        // then a final error, and the retry the user was promised never
        // happened.
        let (negotiated, wireguard_endpoint) = match prepare_attempt(profile, identities).await {
            Ok(prepared) => prepared,
            Err(error) => {
                // Also to `tracing`, and not only to the UI: the event sink
                // feeds a window the user has usually already closed, while
                // the file is what gets pasted into a bug report. Without
                // this line `orion.log` showed three dial attempts two
                // seconds apart and not one word about why any of them
                // failed — the retry looked like the whole story.
                tracing::warn!(
                    attempt,
                    attempts = KEY_NEGOTIATION_ATTEMPTS,
                    %endpoint,
                    error = format!("{error:#}"),
                    "key negotiation: attempt failed, nothing installed on the data plane"
                );
                sink(ClientEvent::log(
                    "warn",
                    format!(
                        "négociation {attempt}/{KEY_NEGOTIATION_ATTEMPTS} : échec — \
                         {error:#}. Aucun PSK installé sur le plan de données."
                    ),
                ));
                let terminal = is_terminal_negotiation_error(&error);
                if terminal {
                    sink(ClientEvent::log(
                        "error",
                        "échec cryptographique définitif : aucune nouvelle tentative de \
                         négociation ne peut réparer l’identité présentée."
                            .to_string(),
                    ));
                    return Err(error);
                }
                last_error = Some(error);
                if attempt < KEY_NEGOTIATION_ATTEMPTS {
                    tokio::time::sleep(KEY_NEGOTIATION_RETRY_DELAY).await;
                }
                continue;
            }
        };
        let mode = negotiated.mode;
        // Which address answered, in which family, and what was passed over
        // on the way: a broken IPv6 path that IPv4 replaced is said here, as
        // a warning, never absorbed in silence.
        let (level, route) = negotiated.selection().describe();
        sink(ClientEvent::log(
            level,
            format!("négociation {attempt}/{KEY_NEGOTIATION_ATTEMPTS} : {route}"),
        ));
        sink(ClientEvent::log(
            "info",
            format!(
                "négociation {attempt}/{KEY_NEGOTIATION_ATTEMPTS} : {}",
                wireguard_endpoint.describe(&profile.endpoint)
            ),
        ));
        sink(ClientEvent::log(
            "info",
            format!(
                "négociation {attempt}/{KEY_NEGOTIATION_ATTEMPTS} : PSK négocié ({mode:?}) — \
                 installation puis attente d'un handshake WireGuard réussi avec ce PSK \
                 ({} s au plus)",
                negotiated.confirmation_timeout.as_secs()
            ),
        ));
        let confirmation_timeout = negotiated.confirmation_timeout;
        let prepared_at = tokio::time::Instant::now();
        let negotiated_profile = ClientProfile {
            // The literal chosen above, never the name: the data plane must
            // not resolve it a second time. Only this ephemeral copy carries
            // it; the receipt below keeps the profile as stored, so a
            // renegotiation resolves the name afresh.
            endpoint: wireguard_endpoint.address.to_string(),
            preshared_key: negotiated.psk.as_ref().map(aether::SecretString::duplicate),
            // Says where that PSK comes from. Without it, the copy
            // contradicted its own settings — a PSK plus a non-static mode —
            // and the `validate()` inside every `up()` refused the tunnel the
            // negotiation had just succeeded in preparing.
            preshared_key_is_negotiated: negotiated.psk.is_some(),
            ..profile.duplicate()
        };

        match commit_negotiated_slot(
            backend,
            &negotiated_profile,
            sink,
            negotiated,
            prepared_at,
            confirmation_timeout,
        )
        .await
        {
            Ok(transaction_id) => {
                // The receipt the gateway will require to accept a release.
                // It replaces any previous one: the slot has a single owner,
                // and a renegotiation is precisely a change of owner.
                //
                // Only `ml_kem` produces one. A `static_psk` negotiation
                // proves possession of a value both peers were configured
                // with; it leaves the gateway's slot in `configured_static`,
                // owned by nobody. Sending a release for it would ask the
                // gateway to delete an operator's configuration — which it
                // refuses — so recording a receipt here would only schedule a
                // round trip that announces the disconnection and changes
                // nothing (spec §12.2).
                let bytes = backend.transfer_bytes().await;
                *installed.lock().await = (mode == aether::key_negotiation::ProtectionMode::MlKem)
                    .then(|| {
                        InstalledNegotiation::new(
                            transaction_id,
                            profile.duplicate(),
                            negotiated_profile.duplicate(),
                            bytes,
                        )
                    });
                link_lost.store(false, Ordering::SeqCst);
                let protection = match mode {
                    aether::key_negotiation::ProtectionMode::Classic => PskKind::None,
                    aether::key_negotiation::ProtectionMode::StaticPsk => PskKind::Static,
                    aether::key_negotiation::ProtectionMode::MlKem => PskKind::MlKem,
                };
                sink(ClientEvent::protection(protection));
                sink(ClientEvent::log(
                    "info",
                    format!(
                        "négociation confirmée ({mode:?}) — un handshake WireGuard a réussi \
                         avec le PSK négocié, tunnel établi"
                    ),
                ));
                // The commit's precondition was a handshake that succeeded
                // with this PSK, a second ago: the tunnel is up, and saying
                // so now spares the
                // user the ten seconds the state poller would have taken to
                // reach the same conclusion.
                sink(ClientEvent::state(TunnelState::Up));
                return Ok(());
            }
            Err(error) => {
                // `{error:#}` and not `{error}`: anyhow only prints the outermost
                // context by default, so the message read «confirming the
                // key-negotiation transaction» and dropped the cause — the one
                // thing worth reading.
                sink(ClientEvent::log(
                    "warn",
                    format!(
                        "négociation {attempt}/{KEY_NEGOTIATION_ATTEMPTS} : non confirmée — \
                         {error:#}. La gateway a restauré son slot précédent."
                    ),
                ));
                last_error = Some(error);
                if attempt < KEY_NEGOTIATION_ATTEMPTS {
                    tokio::time::sleep(KEY_NEGOTIATION_RETRY_DELAY).await;
                }
            }
        }
    }

    let error = last_error
        .unwrap_or_else(|| anyhow::anyhow!("key negotiation failed without a reported cause"));
    // What the user is left with, said plainly: the client holds a PSK the
    // gateway does not. WireGuard will drop everything — which is the
    // anti-leak invariant working as intended, not a bug to hunt.
    sink(ClientEvent::log(
        "error",
        format!(
            "négociation abandonnée après {KEY_NEGOTIATION_ATTEMPTS} tentatives : {error:#}. \
             Le slot PSK reste posé côté client alors que la gateway a restauré le sien : \
             aucun handshake n'aboutira tant qu'une négociation n'a pas abouti. Se déconnecter \
             puis se reconnecter en repart proprement."
        ),
    ));
    Err(error)
}

/// The literal address the tunnel's peer is given, and how it was chosen.
///
/// `defguard_wireguard_rs` resolves a name on its own, synchronously, and
/// keeps the first answer: a second `getaddrinfo`, free to return the other
/// family than the one the negotiation just reached. Handing it a literal is
/// what makes the negotiation and the tunnel agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WireGuardEndpoint {
    pub(super) address: SocketAddr,
    pub(super) origin: EndpointOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EndpointOrigin {
    /// The WireGuard endpoint names the negotiation's host: the address that
    /// negotiated, on the WireGuard port.
    Negotiated,
    /// No negotiation on that host — a classic profile, or a negotiation
    /// endpoint naming another host: the first candidate of the WireGuard
    /// host's own single resolution. WireGuard offers one peer endpoint, so
    /// there is nothing to race there.
    FirstCandidate,
}

impl WireGuardEndpoint {
    /// The log line naming the address and family, for the user.
    pub(super) fn describe(&self, endpoint: &str) -> String {
        let origin = match self.origin {
            EndpointOrigin::Negotiated => "l'adresse qui a négocié",
            EndpointOrigin::FirstCandidate => "premier candidat de sa résolution",
        };
        format!(
            "endpoint WireGuard {endpoint} : {} {} ({origin})",
            crate::endpoint_resolution::family(&self.address),
            self.address
        )
    }
}

/// The copy of `profile` the data plane receives: identical, but for an
/// endpoint that is now the literal `address`.
///
/// A copy, never an edit: the stored profile keeps the name the operator
/// wrote, so the next connection resolves it again — the gateway may have
/// moved, or the network may have gained or lost a family.
pub(super) fn with_wireguard_endpoint(
    profile: &ClientProfile,
    address: SocketAddr,
) -> ClientProfile {
    ClientProfile {
        endpoint: address.to_string(),
        ..profile.duplicate()
    }
}

/// Resolves the WireGuard endpoint once and keeps its first RFC 8305
/// candidate.
///
/// The error keeps the wording the backend used when it resolved the name
/// itself, so a profile pointing nowhere reads as it always did.
async fn resolve_wireguard_endpoint(endpoint: &str) -> anyhow::Result<SocketAddr> {
    let candidates = crate::endpoint_resolution::resolve_candidates(endpoint)
        .await
        .map_err(|e| anyhow::anyhow!("endpoint `{endpoint}` invalide : {e:#}"))?;
    candidates.first().copied().ok_or_else(|| {
        anyhow::anyhow!("endpoint `{endpoint}` invalide : aucune adresse utilisable")
    })
}

/// A classic connection's data-plane copy: validated, then resolved once.
///
/// The validation is the one `up()` starts with, made **before** the
/// resolver is asked, so an incomplete profile is still refused before any
/// network activity. `up()` runs it again on the copy, unchanged.
pub(super) async fn classic_data_plane_profile(
    profile: &ClientProfile,
    sink: &EventSink,
) -> anyhow::Result<ClientProfile> {
    profile.validate_for_data_plane()?;
    let target = WireGuardEndpoint {
        address: resolve_wireguard_endpoint(&profile.endpoint).await?,
        origin: EndpointOrigin::FirstCandidate,
    };
    sink(ClientEvent::log("info", target.describe(&profile.endpoint)));
    Ok(with_wireguard_endpoint(profile, target.address))
}

/// One negotiation attempt's preparation: each host resolved once, then the
/// negotiation, then the WireGuard endpoint that follows from both.
///
/// The WireGuard host is resolved **before** negotiating when it differs
/// from the negotiation host. A name that does not resolve is then refused
/// with nothing prepared on the gateway; resolving it afterwards would drop
/// a prepared transaction, and the gateway arms ten seconds of rest after
/// every such rollback.
async fn prepare_attempt(
    profile: &ClientProfile,
    identities: &dyn crate::key_negotiation::IdentityProvider,
) -> anyhow::Result<(crate::key_negotiation::NegotiatedKey, WireGuardEndpoint)> {
    enum Plan {
        FromNegotiation(u16),
        Resolved(SocketAddr),
    }
    let plan = match profile.key_negotiation.as_ref() {
        // Refused by the negotiation below with its own message, before
        // anything is resolved.
        None => None,
        Some(settings)
            if crate::endpoint_resolution::same_host(&profile.endpoint, &settings.endpoint) =>
        {
            let port = crate::endpoint_resolution::port_of(&profile.endpoint).ok_or_else(|| {
                anyhow::anyhow!(
                    "endpoint `{}` invalide : port UDP absent ou nul",
                    profile.endpoint
                )
            })?;
            Some(Plan::FromNegotiation(port))
        }
        // Two names are two hosts: each is resolved once, never merged.
        Some(_) => Some(Plan::Resolved(
            resolve_wireguard_endpoint(&profile.endpoint).await?,
        )),
    };
    let negotiated = crate::key_negotiation::prepare_for_profile(profile, identities).await?;
    let wireguard = match plan {
        Some(Plan::FromNegotiation(port)) => {
            // `set_port` rather than a new address: an IPv6 candidate keeps
            // its scope identifier.
            let mut address = negotiated.remote();
            address.set_port(port);
            WireGuardEndpoint {
                address,
                origin: EndpointOrigin::Negotiated,
            }
        }
        Some(Plan::Resolved(address)) => WireGuardEndpoint {
            address,
            origin: EndpointOrigin::FirstCandidate,
        },
        None => anyhow::bail!("profile has no key-negotiation settings"),
    };
    Ok((negotiated, wireguard))
}

/// Installs the negotiated slot and commits it, or reports why it could not.
///
/// Split out so the caller can tell a failure that left the slot
/// desynchronised — everything below — from one that touched nothing.
async fn commit_negotiated_slot(
    backend: &Arc<dyn VpnBackend>,
    negotiated_profile: &ClientProfile,
    sink: &EventSink,
    negotiated: crate::key_negotiation::NegotiatedKey,
    prepared_at: tokio::time::Instant,
    confirmation_timeout: Duration,
) -> anyhow::Result<[u8; 16]> {
    backend
        .up(negotiated_profile, sink)
        .await
        .context("installing the negotiated PSK on the data plane")?;
    if !wait_for_new_handshake(backend, prepared_at, confirmation_timeout).await {
        anyhow::bail!(
            "no WireGuard handshake succeeded with the negotiated PSK within {} s: the gateway \
             either did not receive the client's handshakes, or answered with a PSK that does \
             not match — check UDP {} reaches the gateway",
            confirmation_timeout.as_secs(),
            negotiated_profile
                .endpoint
                .rsplit_once(':')
                .map(|(_, port)| port)
                .unwrap_or("51820")
        );
    }
    sink(ClientEvent::log(
        "info",
        format!(
            "handshake WireGuard obtenu en {} s — envoi de la confirmation",
            prepared_at.elapsed().as_secs()
        ),
    ));
    let transaction_id = negotiated.transaction_id();
    negotiated.confirm().await?;
    Ok(transaction_id)
}

pub(super) async fn wait_for_new_handshake(
    backend: &Arc<dyn VpnBackend>,
    prepared_at: tokio::time::Instant,
    confirmation_timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + confirmation_timeout;
    while tokio::time::Instant::now() < deadline {
        if matches!(
            backend.last_handshake_age().await,
            Some(age) if age <= prepared_at.elapsed()
        ) {
            return true;
        }
        tokio::time::sleep(NEGOTIATION_POLL_INTERVAL).await;
    }
    false
}
