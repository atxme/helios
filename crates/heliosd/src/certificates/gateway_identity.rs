//! The in-tunnel gateway-identity handler: what the administration API asks
//! of the gateway's own leaves.

use super::*;

#[async_trait]
impl helios_api::certificates::GatewayIdentityHandler for CertificateService {
    /// §11.1 steps 1 and 2, driven from the console instead of a terminal.
    ///
    /// The registry is the daemon's own, held under the same lock as every
    /// other mutation. The offline command loads a second copy from disk,
    /// which is only safe while this process is stopped — one file with two
    /// writers is the failure the whole module is built to avoid.
    async fn prepare_renewal(
        &self,
        request: helios_api::certificates::GatewayRenewalRequest,
    ) -> Result<helios_api::certificates::GatewayRenewalView, GatewayActionRefusal> {
        let now = now_unix();
        let registry = self.registry.lock().await;
        let prepared = crate::gateway_rotation::prepare_request(
            &registry,
            self.gateway_identity_secret.as_ref(),
            // Never the development key on this route: a console that sealed
            // a candidate under a file key would hand an operator a request
            // for an identity no TPM can ever serve.
            false,
            request.rotate_tls,
            request.new_key,
            request.key_recovery,
            now,
        )
        .map_err(|error| {
            tracing::warn!(%error, "gateway renewal refused");
            GatewayActionRefusal::new(format!("{error:#}"))
        })?;

        Ok(helios_api::certificates::GatewayRenewalView {
            gateway_identity_epoch: prepared.request.gateway_identity_epoch,
            request_id: prepared.request.request_id.to_hex(),
            request_fingerprint: prepared.request.fingerprint().to_hex(),
            expires_at: prepared.request.expires_at,
            candidate_tls_fingerprint: prepared
                .tls_certificate
                .as_ref()
                .map(|certificate| certificate.fingerprint().to_hex()),
            reused: prepared.reused,
            key_recovery: request.key_recovery,
        })
    }

    async fn install_transition(
        &self,
        transition: Box<aether::certificates::gateway::GatewayIdentityTransition>,
    ) -> Result<helios_api::certificates::GatewayDecisionView, GatewayActionRefusal> {
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let staged = crate::gateway_rotation::install_transition(&mut registry, *transition, now)
            .map_err(|error| {
            tracing::warn!(%error, "gateway transition refused");
            GatewayActionRefusal::new(format!("{error:#}"))
        })?;
        let fingerprint = staged.transition.fingerprint().map_err(|error| {
            GatewayActionRefusal::new(format!("fingerprinting the staged transition: {error}"))
        })?;
        tracing::warn!(
            epoch = staged.transition.gateway_identity_epoch,
            "gateway transition staged from the console; the identity in service is unchanged"
        );
        Ok(helios_api::certificates::GatewayDecisionView {
            gateway_identity_epoch: staged.transition.gateway_identity_epoch,
            fingerprint: fingerprint.to_hex(),
            already_present: staged.already_present,
            activation_at: Some(staged.transition.window.activation_at),
            not_after: Some(staged.transition.window.not_after),
        })
    }

    async fn abort_transition(
        &self,
        abort: Box<aether::certificates::gateway::GatewayTransitionAbort>,
    ) -> Result<helios_api::certificates::GatewayDecisionView, GatewayActionRefusal> {
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let aborted = crate::gateway_rotation::abort_transition(&mut registry, *abort, now)
            .map_err(|error| {
                tracing::warn!(%error, "gateway transition abort refused");
                GatewayActionRefusal::new(format!("{error:#}"))
            })?;
        tracing::warn!(
            epoch = aborted.abort.gateway_identity_epoch,
            "gateway transition cancelled from the console; the epoch stays consumed"
        );
        Ok(helios_api::certificates::GatewayDecisionView {
            gateway_identity_epoch: aborted.abort.gateway_identity_epoch,
            fingerprint: aborted.abort.fingerprint().to_hex(),
            already_present: aborted.already_present,
            activation_at: None,
            not_after: None,
        })
    }

    /// §11.1 step 8, driven from the console.
    ///
    /// Records the selection; it takes effect at the next start, because the
    /// leaf in service was unsealed once and is held for the life of this
    /// process. Nothing else moves: the candidate stays sealed and its
    /// promotion still happens at `not_after`.
    async fn install_rollback(
        &self,
        authorization: Box<aether::certificates::status::CertificateServiceRollbackAuthorization>,
    ) -> Result<helios_api::certificates::GatewayRollbackView, GatewayActionRefusal> {
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let installed =
            crate::gateway_rotation::install_rollback(&mut registry, *authorization, now).map_err(
                |error| {
                    tracing::warn!(%error, "gateway service rollback refused");
                    GatewayActionRefusal::new(format!("{error:#}"))
                },
            )?;
        tracing::warn!(
            epoch = installed.gateway_identity_epoch,
            expires_at = installed.expires_at,
            "gateway service rollback selected from the console; it applies at the next restart"
        );
        Ok(helios_api::certificates::GatewayRollbackView {
            gateway_identity_epoch: installed.gateway_identity_epoch,
            selected_certificate_fingerprint: installed.selected_certificate_fingerprint.to_hex(),
            expires_at: installed.expires_at,
            already_present: installed.already_present,
        })
    }

    /// §9.1, applied to the anchor this gateway pins.
    ///
    /// The registry is the daemon's own, under the same lock as every other
    /// mutation. The anchor does not move here: both verify from
    /// `activation_at`, and the outgoing one is retired by the maintenance
    /// pass at `not_after` — the same pass that promotes the client
    /// generations, and in the same write.
    async fn install_ca_transition(
        &self,
        transition: Box<aether::certificates::authority::CaTransition>,
    ) -> Result<helios_api::certificates::AnchorDecisionView, GatewayActionRefusal> {
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let outcome = registry
            .install_ca_transition(&transition, now)
            .map_err(|error| {
                tracing::warn!(%error, "CA-PQ rotation refused");
                GatewayActionRefusal::new(format!("{error:#}"))
            })?;
        tracing::warn!(
            next_ca_epoch = transition.next_ca_epoch,
            "CA-PQ rotation staged from the console; both anchors verify from activation_at"
        );
        Ok(helios_api::certificates::AnchorDecisionView {
            ca_epoch: transition.current_ca_epoch,
            next_ca_epoch: transition.next_ca_epoch,
            next_ca_fingerprint: transition.next_ca_fingerprint.to_hex(),
            activation_at: transition.window.activation_at,
            not_after: transition.window.not_after,
            already_present: matches!(
                outcome,
                aether::certificates::state::InstallOutcome::AlreadyPresent
            ),
        })
    }

    /// §9.4, applied to the client `CA-TLS` this gateway accepts.
    ///
    /// The gateway verifies the `CA-PQ` signature itself, as the offline
    /// command does: Orion's word that it signed the object proves nothing.
    /// Both chains are accepted from `activation_at`; the outgoing anchor is
    /// retired by the maintenance pass at `not_after`.
    async fn install_client_tls_ca_transition(
        &self,
        transition: Box<aether::certificates::authority::ClientTlsCaTransition>,
    ) -> Result<helios_api::certificates::ClientTlsCaDecisionView, GatewayActionRefusal> {
        let now = now_unix();
        let mut registry = self.registry.lock().await;
        let outcome = registry
            .install_client_tls_ca_transition(&transition, now)
            .map_err(|error| {
                tracing::warn!(%error, "client TLS CA rotation refused");
                GatewayActionRefusal::new(format!("{error:#}"))
            })?;
        tracing::warn!(
            next_ca_tls_epoch = transition.next_ca_tls_epoch,
            "client TLS CA rotation staged from the console; both chains are accepted from activation_at"
        );
        Ok(helios_api::certificates::ClientTlsCaDecisionView {
            ca_tls_epoch: transition.current_ca_tls_epoch,
            next_ca_tls_epoch: transition.next_ca_tls_epoch,
            next_ca_tls_fingerprint: transition
                .next_client_tls_ca_certificate
                .fingerprint()
                .to_hex(),
            activation_at: transition.window.activation_at,
            not_after: transition.window.not_after,
            already_present: matches!(
                outcome,
                aether::certificates::state::InstallOutcome::AlreadyPresent
            ),
        })
    }
}
