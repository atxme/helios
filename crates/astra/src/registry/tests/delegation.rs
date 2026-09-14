//! Installation and epoch ownership of Astra's delegated issuer.

use aether::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, DerCertificate, Fingerprint, MlDsa87Signature, TrustDomainId,
    WireGuardKey,
};
use aether::certificates::state::{AstraIssuerState, IssuerLifecycle};

use super::{registry, RegistryError};

/// A delegation is installed by epoch, and the epoch only ever rises.
/// Reinstalling one already used would let a withdrawn intermediate come
/// back under a signature that is still perfectly valid.
#[test]
fn a_delegation_may_not_walk_its_epoch_backwards() {
    let (mut registry, _dir) = registry();
    let (_, issuer_key) = generate_ml_dsa_87_keypair().expect("keygen");
    let delegation = |epoch: u64| AstraIssuerState {
        issuer_epoch: epoch,
        authorization: AstraIssuerAuthorization {
            format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
            ca_epoch: 1,
            ca_tls_epoch: 1,
            gateway_wg_public_key: WireGuardKey::from_bytes([1; 32]),
            server_name: "gateway.example".into(),
            issuer_epoch: epoch,
            pq_issuer_public_key: issuer_key.clone(),
            tls_intermediate_certificate: DerCertificate::new(vec![9; 64]).expect("der"),
            allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
            maximum_leaf_lifetime_secs: 100,
            policy_fingerprint: Fingerprint::of(b"policy"),
            not_before: 0,
            not_after: 100_000,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        },
        state: IssuerLifecycle::Active,
    };

    registry
        .install_issuer(delegation(1), 1_000)
        .expect("first");
    // The same delegation again is a replay of §8.2, not a walk-back: a
    // companion whose response was lost redeposits the same bytes.
    registry
        .install_issuer(delegation(1), 1_100)
        .expect("an identical delegation is a no-op");
    // A *different* delegation at a spent epoch is the substitution this
    // refuses — it would bring back an intermediate that was withdrawn,
    // under a signature that still verifies.
    let mut substituted = delegation(1);
    substituted.authorization.tls_intermediate_certificate =
        DerCertificate::new(vec![7; 64]).expect("der");
    assert!(matches!(
        registry.install_issuer(substituted, 1_150),
        Err(RegistryError::IssuerEpochNotAdvancing {
            installed: 1,
            offered: 1
        })
    ));
    registry
        .install_issuer(delegation(2), 1_200)
        .expect("second");
    assert_eq!(
        registry
            .state()
            .issuer
            .as_ref()
            .expect("issuer")
            .issuer_epoch,
        2
    );
}
