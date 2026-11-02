//! The delegated issuer's request, drawn inside the service.
//!
//! The private halves are born here and never travel; what leaves is the
//! public request. Two entry points and not one, because the signature
//! happens on another machine at a security key: [`AstraService::issuer_request_only`]
//! prepares the material and opens nothing, and
//! [`AstraService::open_issuer_delegation`] also opens the campaign the
//! operator reads before touching.
//!
//! The caller holds [`super::chain::VOLUME_WRITES`]: the key files are named by
//! epoch, so two requests for the same epoch would overwrite each other's keys,
//! and an install at the door, which reads them, holds it too.

use aether::certificates::encoding::{generate_ml_dsa_87_keypair, Fingerprint};
use aether::certificates::status::{CampaignScope, CampaignTarget, CertificateKind};
use aether::certificates::transport::OperatorOpened;
use base64::Engine as _;

use super::open::{self, Resolved};
use super::{DoorConnector, DoorRefusal, OpeningText};
use crate::service::AstraService;

/// A request whose keys are on disk, and the target that pins its material.
struct Material {
    /// The public request, pretty JSON: what `issuer request` prints.
    request: String,
    target: CampaignTarget,
}

/// Refuses a delegation campaign for an epoch the registry has moved past.
///
/// The epoch is read under one registry lock and the campaign opened under
/// another, with the key generation in between. A delegation installed in
/// that gap would leave this campaign pinning an epoch that is no longer the
/// next one: an operator would sign a delegation the registry then refuses as
/// not advancing.
pub(super) fn still_next_epoch(
    state: &crate::registry::AstraState,
    epoch: u64,
) -> Result<(), DoorRefusal> {
    let installed = state
        .issuer
        .as_ref()
        .map(|installed| installed.issuer_epoch)
        .unwrap_or(0);
    if installed.checked_add(1) == Some(epoch) {
        Ok(())
    } else {
        Err(DoorRefusal::IssuerEpochMoved { epoch })
    }
}

impl AstraService {
    /// Draws the next delegation's private keys and returns its public request.
    ///
    /// Nothing is installed and nothing is announced: the registry is only
    /// read, for the epoch to advance from. Until an authorization comes
    /// back, the two key files are a pair no signed object names — which is
    /// exactly the state an interrupted ceremony should leave behind.
    ///
    /// Refused while a delegation campaign is waiting for its operator: that
    /// campaign pins the public keys of the files on disk, and a second draw
    /// for the same epoch would overwrite them under it.
    pub(super) async fn issuer_request_only(&self, now_unix: u64) -> Result<String, DoorRefusal> {
        self.refuse_live_delegation(now_unix).await?;
        Ok(self.prepare_issuer_material().await?.request)
    }

    /// Prepares the material, then opens the campaign that pins it.
    ///
    /// The campaign pins the **exact material** that will be certified: the
    /// epoch, the ML-DSA-87 public key, and the `SubjectPublicKeyInfo` the
    /// PKCS#10 request proved possession of. That is what the operator reads
    /// before the touch, and what refuses a substituted request afterwards —
    /// the request itself carries no signature, so nothing else could.
    pub(super) async fn open_issuer_delegation(
        &self,
        connector: &DoorConnector,
        text: OpeningText,
        now_unix: u64,
    ) -> Result<(String, OperatorOpened), DoorRefusal> {
        // Before any key is drawn: a refused opening must not overwrite the
        // keys a live one pins.
        open::check_text(&text)?;
        self.refuse_live_delegation(now_unix).await?;
        let Material { request, target } = self.prepare_issuer_material().await?;
        let opened = open::open_campaign(
            self,
            connector,
            CampaignScope::IssuerDelegation,
            text,
            |state| {
                still_next_epoch(state, target.epoch)?;
                Ok(Resolved::targets(vec![target]))
            },
            now_unix,
        )
        .await?;
        Ok((request, opened))
    }

    async fn refuse_live_delegation(&self, now_unix: u64) -> Result<(), DoorRefusal> {
        let store = self.signing.lock().await;
        match store.live_conflict(CampaignScope::IssuerDelegation, &[], now_unix) {
            Some(operation_id) => Err(DoorRefusal::AlreadyOpen { operation_id }),
            None => Ok(()),
        }
    }

    async fn prepare_issuer_material(&self) -> Result<Material, DoorRefusal> {
        let (trust_domain_id, gateway_wg_public_key, issuer_epoch) = {
            let registry = self.registry.lock().await;
            let state = registry.state();
            let epoch = state
                .issuer
                .as_ref()
                .map(|installed| installed.issuer_epoch)
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| {
                    tracing::error!("the door cannot advance the issuer epoch: it would overflow");
                    DoorRefusal::Internal
                })?;
            (state.trust_domain_id, state.gateway_wg_public_key, epoch)
        };
        let state_dir = self.state_dir.clone();
        // Key generation and the sealed writes are blocking work, done with
        // neither lock held.
        tokio::task::spawn_blocking(move || -> Result<Material, DoorRefusal> {
            let internal = |what: &'static str| {
                move |error: &dyn std::fmt::Display| {
                    tracing::error!(%error, "the door could not {what}");
                    DoorRefusal::Internal
                }
            };
            let (pq_private_key, pq_public_key) = generate_ml_dsa_87_keypair()
                .map_err(|error| internal("generate the delegated issuer ML-DSA-87 key")(&error))?;
            let tls_key = rcgen::KeyPair::generate()
                .map_err(|error| internal("generate the delegated issuer TLS key")(&error))?;

            // Subject only. Validity, `basicConstraints` and key usage are the
            // issuer's decision and are set by the companion when it signs — a
            // PKCS#10 request that carried them would be asking for what it is
            // not entitled to choose.
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
                .map_err(|error| internal("build the intermediate request")(&error))?;
            let mut name = rcgen::DistinguishedName::new();
            name.push(
                rcgen::DnType::CommonName,
                format!("astra delegated issuer {issuer_epoch}"),
            );
            params.distinguished_name = name;
            let csr = params
                .serialize_request(&tls_key)
                .map_err(|error| internal("serialize the intermediate request")(&error))?;

            // The private halves first: a request whose keys were not written
            // would name a public key nobody can ever sign with, and the
            // operator would only discover it after a security-key ceremony.
            aether::private_file::write_private_atomic(
                &crate::issuer::pq_key_path(&state_dir, issuer_epoch),
                &pq_private_key,
            )
            .map_err(|error| internal("seal the delegated issuer ML-DSA-87 key")(&error))?;
            aether::private_file::write_private_atomic(
                &crate::issuer::tls_key_path(&state_dir, issuer_epoch),
                &tls_key.serialize_der(),
            )
            .map_err(|error| internal("seal the delegated issuer TLS key")(&error))?;

            let public_key_info =
                aether::certificates::x509::certification_request_public_key_info(
                    &aether::certificates::encoding::DerCertificate::new(csr.der().to_vec())
                        .map_err(|error| internal("read the intermediate request")(&error))?,
                )
                .map_err(|error| internal("read the request's public key")(&error))?;
            let request = crate::issuer::IssuerDelegationRequest {
                trust_domain_id: trust_domain_id.to_hex(),
                issuer_epoch,
                pq_issuer_public_key: pq_public_key.to_base64(),
                tls_intermediate_csr: base64::engine::general_purpose::STANDARD.encode(csr.der()),
            };
            let encoded = serde_json::to_vec_pretty(&request)
                .map_err(|error| internal("encode the delegation request")(&error))?;
            Ok(Material {
                request: String::from_utf8_lossy(&encoded).into_owned(),
                target: CampaignTarget {
                    certificate_kind: CertificateKind::AstraIssuer,
                    identity_key: gateway_wg_public_key,
                    epoch: issuer_epoch,
                    generation: issuer_epoch,
                    active_tls_certificate_fingerprint: Fingerprint::of(&public_key_info),
                    active_pq_certificate_fingerprint: Fingerprint::of(pq_public_key.as_bytes()),
                },
            })
        })
        .await
        .map_err(|error| {
            tracing::error!(%error, "the issuer material task did not complete");
            DoorRefusal::Internal
        })?
    }
}
