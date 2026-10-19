//! Starting the negotiation endpoint, and the reclaimer that retires PSKs
//! past their lifetime.

use super::*;

/// Starts the negotiation service, and hands back what the internal API needs.
///
/// The returned handler is the **same** object the QUIC listener serves, not a
/// copy: the in-tunnel `release` and the negotiation itself must contend for
/// one per-peer serializer, or two writers would race on the same slot.
/// `None` means no `key_negotiation_port`, so no service and nothing to
/// release.
pub async fn start(
    network: Arc<RwLock<NetworkConfig>>,
    psk_tx: mpsc::Sender<InstallPskRequest>,
    handshake_tx: mpsc::Sender<aether::ObserveHandshakeRequest>,
    peer_runtime: Arc<RwLock<Vec<helios_wireguard::PeerStatus>>>,
    // The certificate registry, already opened, or `None` on a gateway with no
    // trust domain. Opened by the caller and shared rather than loaded here,
    // because the lifecycle service that *writes* it is built from this
    // handler — it signs its receipts through the served leaf — and a second
    // `CertificateRegistry` over the same path would be a second writer.
    registry: Option<crate::certificates::SharedRegistry>,
    boot: &BootDecision,
    dry_run: bool,
) -> Result<Option<Arc<GatewayHandler>>> {
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
            return Ok(None);
        };
        let static_psks = network
            .peers
            .iter()
            .filter_map(|peer| {
                peer.preshared_key
                    .as_ref()
                    .map(|psk| (peer.public_key.clone(), psk.duplicate()))
            })
            .collect();
        (
            port,
            network.wg_private_key.expose().to_owned(),
            static_psks,
        )
    };
    let gateway_public_key = aether::wg::public_from_private(&gateway_private_key)
        .context("gateway WireGuard identity is unavailable for key negotiation")?;
    let gateway_certificates = match &registry {
        Some(registry) => Some(registry.lock().await.state().gateway.clone()),
        None => None,
    };
    let now_unix = unix_time_now()?;
    let slot = served_identity_slot(gateway_certificates.as_ref(), now_unix)?;
    let identity = load_served_identity(
        boot.secret(),
        dry_run,
        &gateway_public_key,
        gateway_certificates.as_ref(),
        now_unix,
    )?;
    let operator_client_ca =
        std::fs::read(CLIENT_CA_PATH).context("reading key-negotiation client CA certificate")?;
    // The TLS half of the admission question, asked as the PQ half already
    // asks it (`client_leaf_issuers`): the operator CA that admits a
    // first-generation leaf, plus the domain anchors the registry names —
    // active, and its successor once a §9.4 window has opened. A renewed leaf
    // chains to Astra's delegated intermediate, which is signed by the domain
    // anchor and by nothing on this disk, so a verifier holding the operator
    // CA alone locks every renewed client out of the port it just renewed for.
    let mut client_cas = vec![operator_client_ca];
    if let Some(registry) = &registry {
        for anchor in registry.lock().await.state().client_tls_anchors(now_unix) {
            let bytes = anchor.as_bytes().to_vec();
            if !client_cas.contains(&bytes) {
                client_cas.push(bytes);
            }
        }
    }
    // The identity is read **once**, here, and served for the lifetime of the
    // process — unlike `network.toml`, which is watched and re-read.
    //
    // Reloading an identity under a live data plane would rebuild the QUIC
    // endpoint while negotiations own PSK slots on it. The scheduled switch
    // therefore remains a restart: this selection is stable for the process,
    // and a restart inside the overlap selects the published candidate. The
    // accepted client anchors are fixed here for exactly the same reason; a
    // client renewal never moves them, and a §9.4 overlap lasts a month.
    tracing::info!(
        certificate_sha256 = %aether_key_negotiation::certificate_fingerprint_der(
            identity.tls.certificate_chain.first().map_or(&[], Vec::as_slice)
        ),
        client_ca_sha256 = %client_cas
            .iter()
            .map(|client_ca| {
                aether_key_negotiation::certificate_fingerprint_der(client_ca).to_string()
            })
            .collect::<Vec<_>>()
            .join(" "),
        gateway_identity_slot = ?slot,
        "key-negotiation identity selected at startup and served until this daemon restarts"
    );
    // Recorded so the lifecycle sweep can tell when the registry has moved
    // past it. Set once: a second listener in one process would be two
    // identities, which nothing here builds.
    let _ = SERVED_SLOT.set(slot);
    // One dual-stack `[::]` socket: an Orion whose only uplink is IPv6, or
    // whose profile names a `[v6]:port` endpoint, must reach the same port as
    // an IPv4 one. A host without IPv6 keeps serving IPv4 and says so below;
    // any other bind failure still refuses to start, as it always has.
    let (endpoint, families) = dual_stack_server_endpoint(port, &identity.tls, &client_cas)
        .context("binding the key-negotiation QUIC listener")?;
    let handler = Arc::new(GatewayHandler {
        network,
        psk_tx,
        handshake_tx,
        gateway_public_key,
        client_pq_ca_public_key: std::fs::read(CLIENT_PQ_CA_PATH)
            .context("reading key-negotiation client PQ CA public key")?,
        registry,
        served_certificate_fingerprint: identity
            .pq_certificate
            .fingerprint()
            .context("computing the fingerprint of the served PQ certificate")?,
        gateway_pq_certificate: identity.pq_certificate,
        gateway_pq_private_key: identity.pq_private_key,
        dry_run,
        static_psks: RwLock::new(static_psks),
        transactions: Mutex::new(TransactionState::default()),
    });
    match &families {
        ListenFamilies::DualStack => {
            tracing::info!(%families, "key-negotiation listening on UDP [::]:{port}");
        }
        ListenFamilies::Ipv4Only { reason } => {
            tracing::warn!(
                %reason,
                "key-negotiation listening on UDP 0.0.0.0:{port} only: IPv6 clients cannot negotiate with this gateway"
            );
        }
    }
    spawn_psk_reclaimer(Arc::clone(&handler), peer_runtime);
    tokio::spawn(aether_key_negotiation::serve(
        endpoint,
        Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
    ));
    Ok(Some(handler))
}

/// How often the reclaimer looks at the data plane.
///
/// Matches the orchestrator's own poll: it reads that poll's snapshot, so a
/// shorter period would only re-examine unchanged data.
const RECLAIM_POLL: std::time::Duration = std::time::Duration::from_secs(10);

/// Reclaims PSKs whose peer has gone quiet, and PSKs that have aged out.
///
/// This is what replaces v4's closing QUIC link, and it reads the only source
/// that actually knows whether a peer is there: the data plane. A peer whose
/// last handshake is older than
/// [`PSK_RECLAIM_AFTER_STALE_SECS`](helios_wireguard::PSK_RECLAIM_AFTER_STALE_SECS)
/// has already been abandoned by WireGuard itself — that threshold sits above
/// the 180 s after which a session is dead — so clearing its slot destroys
/// nothing that still worked.
///
/// Three questions. Handshake age answers «is this peer still there»;
/// [`MAX_PSK_LIFETIME`] answers «has this secret protected traffic for long
/// enough»; the byte ceiling
/// ([`NEGOTIATED_PSK_BYTE_LIMIT`](aether::key_negotiation::NEGOTIATED_PSK_BYTE_LIMIT))
/// answers «has it carried enough». The last two fire even on a perfectly
/// healthy tunnel. Orion is expected to renegotiate well before, so reaching
/// either means the renewal did not happen and the journal says so.
///
/// The whole loop depends on gateway-sent keep-alives, which
/// `NetworkConfig::validate` makes mandatory for every negotiated peer: an
/// idle tunnel without them produces no handshake, and a peer that is fine
/// would look long gone.
fn spawn_psk_reclaimer(
    handler: Arc<GatewayHandler>,
    peer_runtime: Arc<RwLock<Vec<helios_wireguard::PeerStatus>>>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RECLAIM_POLL);
        loop {
            ticker.tick().await;
            handler.revoke_unadmitted().await;
            let observed = peer_runtime.read().await.clone();
            for (public_key, generation, reason) in handler.reclaimable(&observed).await {
                tracing::warn!(
                    peer = %public_key,
                    %reason,
                    "reclaiming a negotiated PSK"
                );
                // The snapshot this decision came from is up to ten seconds
                // old, so a negotiation may have committed in between. The
                // generation is what makes that harmless: a slot that moved
                // on is left alone rather than cleared under a client that
                // has just finished handshaking.
                if handler.clear_slot(&public_key, generation).await.is_err() {
                    tracing::error!("could not clear a reclaimed PSK slot");
                }
            }
        }
    });
}
