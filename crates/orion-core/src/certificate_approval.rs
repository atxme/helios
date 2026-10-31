//! The operator ceremony, verified here and performed by the interface process
//! — spec §8.1.2 step 4, §6.1, §14.1.
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
//! The engine stops there: [`VerifiedApproval::material`] hands out what the
//! assertion needs, and the process that owns the window performs it with
//! [`ApprovalMaterial::approve`]. That function re-verifies everything before
//! the key, but against anchors carried in the same material: the material is
//! trusted for where it comes from. It must come from the engine and never from
//! the WebView, which only relays it.
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

use aether::certificates::approval::{
    AstraCredentialApprovalRequest, AstraRenewalApproval, CredentialRegistry,
};
use aether::certificates::encoding::{MlDsa87PublicKey, TrustDomainId, WireGuardKey};
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
    #[error("l'approbation reçue ne répond pas à la demande vérifiée : rien n'est déposé.")]
    ApprovalMismatch,
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

/// Everything the assertion needs, and nothing else.
///
/// Public objects only: a signed request, the `CA-PQ`-signed registry, the
/// domain's identity and the keys this profile pins. No PIN, no vault, no
/// secret — which is what lets it cross to the process that owns the window.
/// [`approve`](Self::approve) re-verifies all of it before the key is asked
/// for anything, but against the anchors this same material carries (service
/// key, `CA-PQ`, RP ID). That catches corruption and tampering of the signed
/// objects, not a substituted set of anchors: the material is trusted for where
/// it comes from, the engine, never the WebView.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalMaterial {
    pub request: Box<AstraCredentialApprovalRequest>,
    pub registry: Box<CredentialRegistry>,
    #[serde(with = "identity_shape")]
    pub identity: DomainIdentity,
    pub service_key: MlDsa87PublicKey,
    pub service_key_epoch: u64,
    pub ca_pq: MlDsa87PublicKey,
    pub rp_id: String,
    pub active_generation: u64,
}

/// `DomainIdentity` carries no serde of its own, and `aether-fido` is a
/// hardware boundary that has no reason to learn a wire format. Its five
/// fields are public values; this is their shape on the way across.
mod identity_shape {
    use super::{DomainIdentity, TrustDomainId, WireGuardKey};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Shape {
        trust_domain_id: TrustDomainId,
        gateway_wg_public_key: WireGuardKey,
        server_name: String,
        ca_epoch: u64,
        ca_tls_epoch: u64,
    }

    pub fn serialize<S: Serializer>(
        identity: &DomainIdentity,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        Shape {
            trust_domain_id: identity.trust_domain_id,
            gateway_wg_public_key: identity.gateway_wg_public_key,
            server_name: identity.server_name.clone(),
            ca_epoch: identity.ca_epoch,
            ca_tls_epoch: identity.ca_tls_epoch,
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DomainIdentity, D::Error> {
        let shape = Shape::deserialize(deserializer)?;
        Ok(DomainIdentity {
            trust_domain_id: shape.trust_domain_id,
            gateway_wg_public_key: shape.gateway_wg_public_key,
            server_name: shape.server_name,
            ca_epoch: shape.ca_epoch,
            ca_tls_epoch: shape.ca_tls_epoch,
        })
    }
}

impl ApprovalMaterial {
    /// One assertion over this operation's challenge.
    ///
    /// Blocking, because talking to a security key is: the platform API puts a
    /// modal on screen and waits for a human. `pin` is only consulted on the
    /// HID transport. The request, the registry and the RP ID are checked
    /// again here, before `key` is asked for anything.
    pub fn approve(
        &self,
        key: &dyn aether_fido::authenticator::Authenticator,
        pin: &str,
        now_unix: u64,
    ) -> Result<AstraRenewalApproval, ApprovalError> {
        Ok(aether_fido::approve_renewal(
            key,
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
}

/// A request that has been verified, and is ready for the key.
///
/// Not `Clone`: it is the engine's own proof that verification happened. What
/// leaves it is the [`ApprovalMaterial`], which re-verifies its signed objects
/// on use but vouches for nothing about its own origin.
pub struct VerifiedApproval {
    material: ApprovalMaterial,
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
            material: ApprovalMaterial {
                request: served.approval_request,
                registry: served.credential_registry,
                identity,
                service_key,
                service_key_epoch: state.astra.astra_service_key_epoch,
                ca_pq: state.gateway.current_ca_public_key.clone(),
                rp_id: pinned.to_string(),
                active_generation: state.certificates.active.generation,
            },
        })
    }

    /// What to show before asking for a touch (spec §12.2).
    pub fn manifest(&self) -> ApprovalManifest {
        let request = &self.material.request;
        let eligible = self
            .material
            .registry
            .approvable()
            .into_iter()
            .filter(|binding| {
                request
                    .allowed_credential_ids
                    .contains(&binding.credential_id)
            })
            .count();
        ApprovalManifest {
            operation_id: request.operation_id.to_hex(),
            client_wg_public_key: request.client_wg_public_key.to_base64(),
            active_generation: request.active_generation,
            requested_generation: request.requested_generation,
            request_fingerprint: request.request_fingerprint.to_hex(),
            expires_at: request.expires_at,
            eligible_credentials: eligible,
        }
    }

    /// What the interface process needs to perform the assertion.
    pub fn material(&self) -> ApprovalMaterial {
        self.material.clone()
    }

    /// Whether `approval` answers exactly the request this engine verified.
    ///
    /// Checked on the engine side before anything is posted: an assertion
    /// coming back from the interface process is input like any other, and
    /// one that answers another operation, another rotation request or
    /// another signed approval request must deposit nothing.
    pub fn accepts(&self, approval: &AstraRenewalApproval) -> Result<(), ApprovalError> {
        let request = &self.material.request;
        if approval.operation_id != request.operation_id
            || approval.request_fingerprint != request.request_fingerprint
            || approval.approval_request_fingerprint != request.fingerprint()
        {
            return Err(ApprovalError::ApprovalMismatch);
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "certificate-signing"))]
mod tests {
    use super::*;
    use crate::test_domain::{
        client_key, domain, domain_id, gateway_key, store, Domain, NOW, SERVER_NAME,
    };
    use aether::certificates::approval::{
        AstraCredentialBinding, CredentialState, PER_REQUEST_APPROVAL_CREDENTIALS,
    };
    use aether::certificates::encoding::{
        generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87Signature,
    };
    use aether::certificates::webauthn::WebAuthnAssertion;
    use aether::certificates::CERTIFICATE_FORMAT_VERSION;
    use aether_fido::authenticator::{
        Approval, ApprovedOpening, CredentialSubject, Opened, Registration, SALT_LEN,
    };

    const RP_ID: &str = "astra.example";
    const CREDENTIAL_ID: &[u8] = b"credential-one";

    /// A key that fails the test the moment it is asked to do anything: the
    /// refusal being tested must come before the first touch.
    struct KeyThatMustNotBeAsked;

    impl aether_fido::authenticator::Authenticator for KeyThatMustNotBeAsked {
        fn register(
            &self,
            _: &str,
            _: &CredentialSubject,
            _: &[Vec<u8>],
            _: &str,
        ) -> aether_fido::authenticator::Result<Registration> {
            panic!("the key was asked to register");
        }

        fn derive(
            &self,
            _: &str,
            _: &[Vec<u8>],
            _: &[u8; SALT_LEN],
            _: &str,
        ) -> aether_fido::authenticator::Result<Opened> {
            panic!("the key was asked to derive");
        }

        fn approve(
            &self,
            _: &str,
            _: &[Vec<u8>],
            _: &[u8],
            _: &str,
        ) -> aether_fido::authenticator::Result<Approval> {
            panic!("the key was asked for an assertion");
        }

        fn approve_and_derive(
            &self,
            _: &str,
            _: &[Vec<u8>],
            _: &[u8],
            _: &[u8; SALT_LEN],
            _: &str,
        ) -> aether_fido::authenticator::Result<ApprovedOpening> {
            panic!("the key was asked for an assertion and a derivation");
        }
    }

    struct Setup {
        domain: Domain,
        verified: VerifiedApproval,
        binding: AstraCredentialBinding,
        persisted_generation: u64,
    }

    /// A COSE ES256 key shape the verifier accepts. The point is not checked
    /// until an assertion is: nothing here gets that far.
    fn cose_key() -> Vec<u8> {
        let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        key.extend_from_slice(&[7; 32]);
        key.extend_from_slice(&[0x22, 0x58, 0x20]);
        key.extend_from_slice(&[8; 32]);
        key
    }

    fn setup() -> Setup {
        let mut domain = domain();
        let (service_private, service_public) = generate_ml_dsa_87_keypair().expect("service");
        domain.service_public = service_public;

        let directory = tempfile::tempdir().expect("temp dir");
        let state = store(directory.path(), &domain).state().clone();
        let mut state = state;
        state.astra.active_astra_service_public_key = domain.service_public.clone();
        state.astra.webauthn_rp_id = RP_ID.into();
        // Distinct values, so a round trip that swapped the two would show.
        state.client_tls_ca.ca_tls_epoch = 2;

        let binding = AstraCredentialBinding {
            format_version: CERTIFICATE_FORMAT_VERSION,
            credential_id: CREDENTIAL_ID.to_vec(),
            credential_public_key: cose_key(),
            aaguid: [0; 16],
            trust_domain_id: domain_id(),
            gateway_wg_public_key: gateway_key(),
            state: CredentialState::Active,
            credential_epoch: 1,
            credential_registry_epoch: 1,
            ca_epoch: 1,
            created_at: NOW - 1_000,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&domain.ca_pq_private)
        .expect("binding");
        let registry = CredentialRegistry {
            trust_domain_id: domain_id(),
            gateway_wg_public_key: gateway_key(),
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings: vec![binding.clone()],
        };
        let request = AstraCredentialApprovalRequest {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: Id16::new([5; 16]).expect("operation"),
            request_fingerprint: Fingerprint::of(b"rotation request"),
            trust_domain_id: domain_id(),
            gateway_wg_public_key: gateway_key(),
            client_wg_public_key: client_key(),
            active_generation: state.certificates.active.generation,
            requested_generation: state.certificates.active.generation + 1,
            credential_registry_epoch: 1,
            webauthn_rp_id: RP_ID.into(),
            webauthn_origin: format!("https://{RP_ID}"),
            allowed_credential_ids: vec![CREDENTIAL_ID.to_vec()],
            required_credentials: PER_REQUEST_APPROVAL_CREDENTIALS,
            created_at: NOW - 10,
            expires_at: NOW + 230,
            astra_service_key_epoch: state.astra.astra_service_key_epoch,
            astra_signature: MlDsa87Signature::placeholder(),
        }
        .sign(&service_private)
        .expect("request");

        let verified = VerifiedApproval::verify(
            ClientRenewalSignerRequest {
                operation_id: request.operation_id,
                approval_request: Box::new(request),
                credential_registry: Box::new(registry),
                authority_url: "https://astra.example".into(),
                webauthn_rp_id: RP_ID.into(),
            },
            &state,
            NOW,
        )
        .expect("the test request verifies");
        Setup {
            domain,
            verified,
            binding,
            persisted_generation: state.certificates.active.generation,
        }
    }

    /// The approval the interface process would hand back, with the fields
    /// `accepts` compares set from the verified request.
    fn answer(setup: &Setup) -> AstraRenewalApproval {
        let request = &setup.verified.material.request;
        let assertion = WebAuthnAssertion {
            authenticator_data: vec![1],
            client_data_json: vec![2],
            signature: vec![3],
        };
        AstraRenewalApproval {
            format_version: CERTIFICATE_FORMAT_VERSION,
            operation_id: request.operation_id,
            request_fingerprint: request.request_fingerprint,
            approval_request_fingerprint: request.fingerprint(),
            credential_binding: setup.binding.clone(),
            credential_fingerprint: setup.binding.fingerprint(),
            assertion_fingerprint: assertion.fingerprint(),
            webauthn_assertion: assertion,
            approved_at: NOW,
            expires_at: NOW + 60,
            astra_service_key_epoch: request.astra_service_key_epoch,
            astra_signature: MlDsa87Signature::placeholder(),
        }
    }

    /// Windows is where Orion actually runs, and there raw HID needs an
    /// elevated process. A VPN client asking for administrator to renew a
    /// certificate is the privilege nobody should grant.
    #[test]
    fn windows_speaks_to_the_key_through_the_platform() {
        if cfg!(windows) {
            assert_eq!(transport(), Transport::Platform);
        } else {
            assert_eq!(transport(), Transport::Hid);
        }
    }

    #[test]
    fn the_material_carries_what_was_verified() {
        let setup = setup();
        let material = setup.verified.material();

        assert_eq!(
            material.request.operation_id.to_hex(),
            setup.verified.manifest().operation_id
        );
        assert_eq!(material.rp_id, RP_ID);
        assert_eq!(material.active_generation, setup.persisted_generation);
        assert_eq!(material.identity.server_name, SERVER_NAME);
        assert_eq!(material.identity.trust_domain_id, domain_id());
        assert_eq!(material.ca_pq, setup.domain.ca_pq_public);
        assert_eq!(material.service_key, setup.domain.service_public);

        let json = serde_json::to_string(&material).expect("serialize");
        let back: ApprovalMaterial = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(serde_json::to_string(&back).expect("serialize again"), json);
        assert_eq!(back.request, material.request);
        assert_eq!(back.registry, material.registry);
        assert_eq!(back.identity, material.identity);
        assert_eq!(back.identity.ca_epoch, 1);
        assert_eq!(back.identity.ca_tls_epoch, 2);
        assert_eq!(back.service_key, material.service_key);
        assert_eq!(back.ca_pq, material.ca_pq);
        assert_eq!(back.rp_id, material.rp_id);
        assert_eq!(back.active_generation, material.active_generation);
    }

    #[test]
    fn an_approval_for_the_verified_request_is_accepted() {
        let setup = setup();
        setup
            .verified
            .accepts(&answer(&setup))
            .expect("the approval answers the verified request");
    }

    #[test]
    fn an_approval_for_another_operation_is_not_accepted() {
        let setup = setup();
        let mut approval = answer(&setup);
        approval.operation_id = Id16::new([6; 16]).expect("operation");
        assert!(matches!(
            setup.verified.accepts(&approval),
            Err(ApprovalError::ApprovalMismatch)
        ));
    }

    #[test]
    fn an_approval_for_another_request_is_not_accepted() {
        let setup = setup();

        let mut other_rotation = answer(&setup);
        other_rotation.request_fingerprint = Fingerprint::of(b"another rotation request");
        assert!(matches!(
            setup.verified.accepts(&other_rotation),
            Err(ApprovalError::ApprovalMismatch)
        ));

        let mut other_signed_request = answer(&setup);
        other_signed_request.approval_request_fingerprint =
            Fingerprint::of(b"another signed approval request");
        assert!(matches!(
            setup.verified.accepts(&other_signed_request),
            Err(ApprovalError::ApprovalMismatch)
        ));
    }

    #[test]
    fn the_material_refuses_a_tampered_request_before_the_key() {
        let setup = setup();
        let mut material = setup.verified.material();
        material.request.expires_at += 1;

        // `KeyThatMustNotBeAsked` panics on any call: reaching it fails the
        // test, so an `Err` here is an `Err` raised before the touch.
        let outcome = material.approve(&KeyThatMustNotBeAsked, "0000", NOW);
        assert!(matches!(outcome, Err(ApprovalError::Ceremony(_))));
    }

    /// Positive control: with nothing tampered the same call reaches the key,
    /// which proves the refusal above is not a vacuous pass.
    #[test]
    #[should_panic(expected = "the key was asked for an assertion")]
    fn an_untampered_material_reaches_the_key() {
        let setup = setup();
        let _ = setup
            .verified
            .material()
            .approve(&KeyThatMustNotBeAsked, "0000", NOW);
    }

    #[test]
    fn material_with_an_unknown_field_is_refused() {
        let setup = setup();
        let mut value = serde_json::to_value(setup.verified.material()).expect("value");
        value["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ApprovalMaterial>(value).is_err());
    }
}
