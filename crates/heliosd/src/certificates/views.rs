//! The API projections of the registry, without a secret.

/// The §19 trust block for one peer, from one reading of the registry.
///
/// A free function over the persisted state, like [`caller_is_current`](super::caller_is_current) and
/// for the same reason: it can then be exercised without a runtime, a lock or
/// a signer — and the values it copies are exactly the ones a profile pins for
/// years.
pub fn enrolment_view(
    state: &helios_provisioning::certificates::RegistryState,
    peer: &helios_provisioning::certificates::PeerCertificates,
) -> helios_api::certificates::TrustEnrolmentView {
    use base64::Engine as _;

    let encoder = base64::engine::general_purpose::STANDARD;
    helios_api::certificates::TrustEnrolmentView {
        trust_domain_id: state.trust_domain_id.to_hex(),
        ca_epoch: state.gateway.ca_epoch,
        ca_pq_public_key: state.gateway.current_ca_public_key.to_base64(),
        ca_tls_epoch: state.client_tls_ca.ca_tls_epoch,
        client_tls_ca_der: encoder.encode(
            state
                .client_tls_ca
                .active_client_tls_ca_certificate
                .as_bytes(),
        ),
        client_generation: peer.state.active.generation,
        active_gateway_identity_epoch: state.gateway.active_gateway_identity_epoch,
        gateway_decision_epoch: state.gateway.gateway_decision_epoch,
        astra_authority_url: state.astra.authority_url.clone(),
        webauthn_rp_id: state.astra.webauthn_rp_id.clone(),
        astra_policy_fingerprint: state.astra.astra_policy_fingerprint.fingerprint().to_hex(),
        credential_registry_epoch: state.astra.credential_registry_epoch,
        astra_credential_bindings: state.astra.credential_bindings.values().cloned().collect(),
        astra_service_key_epoch: state.astra.astra_service_key_epoch,
        astra_service_public_key: state.astra.active_astra_service_public_key.to_base64(),
    }
}

/// The whole domain, from one reading of the registry (spec §12.1).
///
/// A free function over the persisted state, like [`enrolment_view`]: the
/// console's numbers are then exercised without a runtime, a lock or a signer,
/// and the arithmetic that decides a renewal is due is the protocol's own
/// rather than a second copy of it.
///
/// Nothing secret crosses: anchors, epochs, fingerprints, dates and counts.
/// The certificate bodies stay here — an operator acts on an expiry, never on
/// a DER blob — and so does every private key, which this process holds none
/// of anyway.
pub fn domain_view(
    state: &helios_provisioning::certificates::RegistryState,
    now_unix: u64,
) -> helios_api::certificates::CertificateDomainView {
    use aether::certificates::window::{ValidityPeriod, ValidityPhase};
    use helios_api::certificates::{IssuerView, PeerCertificateView, PendingStageView};

    let peers = state
        .peers
        .iter()
        .map(|(key, peer)| {
            let active = &peer.state.active;
            // A period the issuer wrote inconsistently cannot be placed on the
            // ladder. It is reported as expired rather than hidden: the leaf
            // is unusable either way, and a peer missing from the list is a
            // peer nobody investigates.
            let phase = ValidityPeriod::new(active.not_before, active.not_after)
                .map(|period| period.phase(now_unix))
                .unwrap_or(ValidityPhase::Expired);
            PeerCertificateView {
                name: peer.name.clone(),
                wg_public_key: key.clone(),
                generation: active.generation,
                not_before: active.not_before,
                not_after: active.not_after,
                phase,
                revoked: peer.state.revoked,
                pending: peer.state.pending.as_ref().map(|pending| PendingStageView {
                    generation: pending.candidate.generation,
                    state: pending.state,
                    stage_expires_at: pending.stage_expires_at,
                }),
                next_generation: peer.state.next.as_ref().map(|next| next.generation),
                activation_at: peer.state.activation_at,
                distribution_chunks_pending: peer
                    .distribution
                    .as_ref()
                    .map(|distribution| {
                        let served = usize::from(distribution.cursor);
                        u16::try_from(distribution.chunks.len().saturating_sub(served))
                            .unwrap_or(u16::MAX)
                    })
                    .unwrap_or(0),
            }
        })
        .collect();

    helios_api::certificates::CertificateDomainView {
        trust_domain_id: state.trust_domain_id.to_hex(),
        server_name: state.gateway.server_name.clone(),
        now_unix,
        ca_epoch: state.gateway.ca_epoch,
        ca_pq_fingerprint: state
            .gateway
            .current_ca_public_key
            .authority_fingerprint()
            .to_hex(),
        ca_transition_pending: state.gateway.next_ca_public_key.is_some(),
        ca_activation_at: state.gateway.ca_activation_at,
        ca_retire_active_at: state.gateway.ca_retire_active_at,
        next_ca_fingerprint: state
            .gateway
            .next_ca_public_key
            .as_ref()
            .map(|key| key.authority_fingerprint().to_hex()),
        client_tls_ca_epoch: state.client_tls_ca.ca_tls_epoch,
        client_tls_ca_transition_pending: state
            .client_tls_ca
            .next_client_tls_ca_certificate
            .is_some(),
        gateway_identity_epoch: state.gateway.active_gateway_identity_epoch,
        gateway_tls_fingerprint: state.gateway.active_tls_fingerprint().to_hex(),
        // An unreadable active leaf is the gateway's own identity failing to
        // parse. Empty rather than a panic: this is a read, and the console
        // showing a blank fingerprint beside populated epochs is a louder
        // symptom than a `500` an operator reads as "the console is broken".
        gateway_pq_fingerprint: state
            .gateway
            .active_pq_fingerprint()
            .map(|fingerprint| fingerprint.to_hex())
            .unwrap_or_default(),
        gateway_transition_pending: state.gateway.next_gateway_certificate.is_some(),
        gateway_activation_at: state.gateway.activation_at,
        gateway_retire_active_at: state.gateway.retire_active_at,
        gateway_transition_published: state.gateway.published,
        gateway_rollback_expires_at: state
            .gateway
            .active_service_rollback(now_unix)
            .map(|rollback| rollback.expires_at),
        gateway_restart_due: crate::key_negotiation::restart_due(Some(&state.gateway), now_unix),
        astra_authority_url: state.astra.authority_url.clone(),
        astra_service_key_epoch: state.astra.astra_service_key_epoch,
        astra_policy_fingerprint: state.astra.astra_policy_fingerprint.fingerprint().to_hex(),
        webauthn_rp_id: state.astra.webauthn_rp_id.clone(),
        credential_registry_epoch: state.astra.credential_registry_epoch,
        credential_bindings: state.astra.credential_bindings.len(),
        issuer: state.issuer.as_ref().map(|issuer| IssuerView {
            issuer_epoch: issuer.issuer_epoch,
            lifecycle: issuer.state,
            not_before: issuer.authorization.not_before,
            not_after: issuer.authorization.not_after,
            usable: issuer.is_usable(now_unix),
        }),
        peers,
    }
}
