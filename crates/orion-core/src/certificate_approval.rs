//! The operator ceremony, run by Orion itself — spec §8.1.2 step 4, §14.1.
//!
//! # Why this lives in Orion at all
//!
//! ADR-008 §4 keeps `astra-signer` away from every other program because it is
//! the one that holds `CA-PQ` in the clear. The **ordinary approval** holds
//! nothing: §14.1 requires it to obtain no PRF output and open no key-slot, and
//! [`aether_fido::approve_renewal`] enforces that by taking no vault and
//! passing no salt. The gesture is therefore separable from the program, and
//! separating it is what removes the second binary.
//!
//! What Orion may do with a security key is exactly this: one `GetAssertion`
//! over one challenge, for one operation. Registering a credential, deriving a
//! slot secret and everything else that touches `hmac-secret` stays in the
//! companion — Orion links `aether-fido`, never `astra`, so the vault format
//! is not reachable from this process at all.
//!
//! # What Orion checks before touching the key
//!
//! Everything the companion checks, against material it already pins rather
//! than material the answer supplied:
//!
//! - the **approval request** verifies under the Astra service key the profile
//!   pinned, for this domain, this gateway and this peer;
//! - the **credential registry** verifies under the profile's own `CA-PQ`. It
//!   travels with the request because Orion has no copy beside a vault — and
//!   an allow-list taken on the authority's word would let a compromised Astra
//!   name a credential nobody enrolled;
//! - the **RP ID** is the one the trust block carries, compared with what the
//!   gateway announced and never replaced by it: an assertion produced under
//!   another RP ID would be valid for another domain.
//!
//! Only then is the user asked to touch anything. A ceremony spent to reach a
//! refusal is the one cost that cannot be retried casually — the person is
//! standing there with a key in their hand.
//!
//! # Limite connue : le matériel ne s'exerce pas en WSL2
//!
//! No USB passthrough, and the platform transport is Windows-only. What is
//! exercised here is everything above the key: the verification order, the
//! refusals, and the fact that no path reaches the vault. See
//! [`docs/testing/TESTING.md`].
//!
//! [`docs/testing/TESTING.md`]: ../../../docs/testing/TESTING.md

use aether::certificates::approval::{AstraCredentialApprovalRequest, AstraRenewalApproval};
use aether::certificates::encoding::MlDsa87PublicKey;
use aether::certificates::transport::ClientRenewalSignerRequest;
use aether_fido::authenticator::Transport;
use aether_fido::DomainIdentity;

use crate::certificates::TrustState;

/// Which transport Orion speaks to a security key over.
///
/// **Platform under Windows**, and that is not a preference: Orion runs under
/// the user's own account, and raw HID needs an elevated process there. The
/// platform API also collects the PIN itself, so it never enters this process —
/// which for an application that also holds a VPN profile is the difference
/// that matters. Elsewhere there is no platform API and HID is the only one.
pub const fn transport() -> Transport {
    if cfg!(windows) {
        Transport::Platform
    } else {
        Transport::Hid
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("approbation refusée : {0}")]
    Ceremony(#[from] aether_fido::ApprovalError),
    #[error("objet refusé : {0}")]
    Certificate(#[from] aether::certificates::CertificateError),
    #[error(
        "la gateway annonce le RP ID « {announced} » alors que ce profil épingle « {pinned} ». \
         Rien n'est signé : une assertion produite sous un autre RP ID vaudrait pour un autre \
         domaine."
    )]
    ForeignRelyingParty { announced: String, pinned: String },
    #[error(
        "la demande d'approbation ne concerne pas l'opération demandée : l'autorité a répondu au \
         sujet de {returned} et non de {expected}."
    )]
    OperationMismatch { expected: String, returned: String },
    #[error(
        "aucune clé de sécurité n'a répondu. Brancher la clé d'approbation de ce domaine, puis \
         recommencer."
    )]
    NoAuthenticator,
}

/// What the screen shows before anyone is asked to touch a key.
///
/// Every field comes from the **verified** request, never from the envelope:
/// showing an operator a generation or a peer that nothing vouches for is how
/// a ceremony gets spent on a lie.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApprovalManifest {
    pub operation_id: String,
    pub client_wg_public_key: String,
    pub active_generation: u64,
    pub requested_generation: u64,
    /// SHA-256 of the rotation request this approval is bound to.
    pub request_fingerprint: String,
    pub expires_at: u64,
    /// How many of the domain's credentials may answer this request.
    pub eligible_credentials: usize,
}

/// A request that has been verified, and is ready for the key.
///
/// Not `Clone`: there is one ceremony per verification, and a second run
/// against a stale copy would ask for a touch the authority no longer accepts.
pub struct VerifiedApproval {
    request: Box<AstraCredentialApprovalRequest>,
    registry: Box<aether::certificates::approval::CredentialRegistry>,
    identity: DomainIdentity,
    service_key: MlDsa87PublicKey,
    service_key_epoch: u64,
    ca_pq: MlDsa87PublicKey,
    rp_id: String,
    active_generation: u64,
}

impl VerifiedApproval {
    /// Verifies what the gateway served, against what this profile pins.
    ///
    /// The order is deliberate and is the whole value of this function: the
    /// service signature first, so no field is displayed that nothing vouches
    /// for; then the registry under `CA-PQ`, so the allow-list is the domain's
    /// and not the authority's claim; then the RP ID, which is compared and
    /// never adopted.
    pub fn verify(
        served: ClientRenewalSignerRequest,
        state: &TrustState,
        now_unix: u64,
    ) -> Result<Self, ApprovalError> {
        let announced = served.webauthn_rp_id.trim();
        let pinned = state.astra.webauthn_rp_id.trim();
        if announced != pinned {
            return Err(ApprovalError::ForeignRelyingParty {
                announced: announced.to_string(),
                pinned: pinned.to_string(),
            });
        }
        if served.approval_request.operation_id != served.operation_id {
            return Err(ApprovalError::OperationMismatch {
                expected: served.operation_id.to_hex(),
                returned: served.approval_request.operation_id.to_hex(),
            });
        }

        let identity = DomainIdentity {
            trust_domain_id: state.trust_domain_id,
            gateway_wg_public_key: state.gateway.gateway_wg_public_key,
            server_name: state.gateway.server_name.clone(),
            ca_epoch: state.gateway.ca_epoch,
            ca_tls_epoch: state.client_tls_ca.ca_tls_epoch,
        };
        // The service key **this profile pins**, at the epoch it pins — never
        // the one the answer names. An authority that could pick its own
        // verification key would be verifying nothing.
        let service_key = state
            .astra
            .service_key_for(state.astra.astra_service_key_epoch, now_unix)
            .ok_or(aether::certificates::CertificateError::UnauthorizedIssuer)?
            .clone();

        served.approval_request.verify(
            &service_key,
            state.astra.astra_service_key_epoch,
            &identity.trust_domain_id,
            &identity.gateway_wg_public_key,
            &state.client_wg_public_key,
            pinned,
            state.certificates.active.generation,
            now_unix,
        )?;
        served.credential_registry.verify(
            &state.gateway.current_ca_public_key,
            &identity.trust_domain_id,
            &identity.gateway_wg_public_key,
            state.gateway.ca_epoch,
            state.astra.credential_registry_epoch,
        )?;

        Ok(Self {
            request: served.approval_request,
            registry: served.credential_registry,
            identity,
            service_key,
            service_key_epoch: state.astra.astra_service_key_epoch,
            ca_pq: state.gateway.current_ca_public_key.clone(),
            rp_id: pinned.to_string(),
            active_generation: state.certificates.active.generation,
        })
    }

    /// What to show before asking for a touch (spec §12.2).
    pub fn manifest(&self) -> ApprovalManifest {
        let eligible = self
            .registry
            .approvable()
            .into_iter()
            .filter(|binding| {
                self.request
                    .allowed_credential_ids
                    .contains(&binding.credential_id)
            })
            .count();
        ApprovalManifest {
            operation_id: self.request.operation_id.to_hex(),
            client_wg_public_key: self.request.client_wg_public_key.to_base64(),
            active_generation: self.request.active_generation,
            requested_generation: self.request.requested_generation,
            request_fingerprint: self.request.request_fingerprint.to_hex(),
            expires_at: self.request.expires_at,
            eligible_credentials: eligible,
        }
    }

    /// Runs the ceremony: one assertion, over this operation's challenge.
    ///
    /// Blocking, because talking to a security key is: the platform API puts a
    /// modal on screen and waits for a human. The caller runs it off the UI
    /// thread.
    ///
    /// `pin` is only ever consulted on the HID transport. Under Windows the
    /// system collects it in its own dialog and it never enters this process,
    /// which is why [`needs_pin`](aether_fido::authenticator::Authenticator::needs_pin)
    /// is asked rather than assumed.
    pub fn run(&self, pin: &str, now_unix: u64) -> Result<AstraRenewalApproval, ApprovalError> {
        let key = aether_fido::authenticator::connect(transport())
            .map_err(|_| ApprovalError::NoAuthenticator)?;
        Ok(aether_fido::approve_renewal(
            key.as_ref(),
            &self.request,
            &self.service_key,
            self.service_key_epoch,
            &self.identity,
            &self.ca_pq,
            &self.registry,
            &self.rp_id,
            Some(self.active_generation),
            pin,
            now_unix,
        )?)
    }

    /// Whether the caller has to collect a PIN at all.
    pub fn needs_pin(&self) -> Result<bool, ApprovalError> {
        let key = aether_fido::authenticator::connect(transport())
            .map_err(|_| ApprovalError::NoAuthenticator)?;
        Ok(key.needs_pin())
    }
}

#[cfg(all(test, feature = "certificate-signing"))]
mod tests;
