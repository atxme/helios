use super::*;

/// Every state the specification names, so a new one cannot be added to
/// the enum and quietly left out of the family table.
const EVERY_STATUS: [CertificateStatus; 12] = [
    CertificateStatus::Active,
    CertificateStatus::RenewalDue,
    CertificateStatus::AwaitingOperator,
    CertificateStatus::PendingGrant,
    CertificateStatus::PendingCommit,
    CertificateStatus::Staged,
    CertificateStatus::Published,
    CertificateStatus::Aborted,
    CertificateStatus::Overlap,
    CertificateStatus::Promoted,
    CertificateStatus::Expired,
    CertificateStatus::Revoked,
];

fn domain() -> TrustDomainId {
    TrustDomainId::new([1; 16]).expect("domain")
}

fn target(seed: u8) -> CampaignTarget {
    CampaignTarget {
        certificate_kind: CertificateKind::ClientPq,
        identity_key: WireGuardKey::from_bytes([seed; 32]),
        epoch: 1,
        generation: 3,
        active_tls_certificate_fingerprint: Fingerprint::of(&[seed, 1]),
        active_pq_certificate_fingerprint: Fingerprint::of(&[seed, 2]),
    }
}

fn campaign(scope: CampaignScope, targets: Vec<CampaignTarget>) -> AstraRotationCampaign {
    AstraRotationCampaign {
        format_version: CERTIFICATE_FORMAT_VERSION,
        campaign_id: Id16::new([7; 16]).expect("id"),
        trust_domain_id: domain(),
        gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        server_name: "gateway.example".into(),
        created_at: 1_000,
        expires_at: 1_300,
        scope,
        targets,
        reason: "rotation trimestrielle".into(),
        requested_by: "operator".into(),
        policy_fingerprint: Fingerprint::of(b"policy"),
        required_credentials: scope.required_credentials(),
    }
}

/// The chain is a plan of campaigns, and never one campaign (§7.6).
#[test]
fn the_full_certificate_chain_is_not_a_campaign() {
    let chain = campaign(CampaignScope::FullCertificateChain, vec![target(3)]);
    assert!(matches!(
        chain.validate(1_100),
        Err(CertificateError::IssuerScopeViolation(_))
    ));
    // Its three siblings under the same family still resolve: the refusal
    // is about this scope, not about client leaves.
    for scope in [
        CampaignScope::FleetLeafs,
        CampaignScope::OrionDevice,
        CampaignScope::OrionProfile,
    ] {
        campaign(scope, vec![target(3)])
            .validate(1_100)
            .expect("an ordinary client-leaf campaign");
    }
}

/// The §0.6 half: what a campaign that touches an anchor may produce.
///
/// Gated on the signing feature only because a valid ML-DSA-87 public key
/// has to be generated to build a transition at all; everything asserted
/// below is pure decision logic that a verifier-only build also runs.
#[cfg(feature = "key-negotiation-signing")]
mod authority_objects {
    use super::*;
    use crate::certificates::encoding::generate_ml_dsa_87_keypair;

    /// The anchor as a campaign names it: the gateway key, the outgoing epoch
    /// and the outgoing fingerprint, exactly as `astra campaign open` resolves
    /// them.
    fn anchor_target(kind: CertificateKind, epoch: u64, current: Fingerprint) -> CampaignTarget {
        CampaignTarget {
            certificate_kind: kind,
            identity_key: WireGuardKey::from_bytes([2; 32]),
            epoch,
            generation: epoch,
            active_tls_certificate_fingerprint: current,
            active_pq_certificate_fingerprint: current,
        }
    }

    fn ca_transition(
        current_epoch: u64,
        current: Fingerprint,
    ) -> crate::certificates::transport::TrustUpdateObject {
        use crate::certificates::authority::CaTransition;
        use crate::certificates::window::TransitionWindow;

        crate::certificates::transport::TrustUpdateObject::CaTransition(Box::new(CaTransition {
            format_version: CERTIFICATE_FORMAT_VERSION,
            trust_domain_id: domain(),
            current_ca_epoch: current_epoch,
            next_ca_epoch: current_epoch + 1,
            current_ca_fingerprint: current,
            next_ca_public_key: generate_ml_dsa_87_keypair().expect("keygen").1,
            next_ca_fingerprint: Fingerprint::of(b"next anchor"),
            window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
            current_ca_signature: MlDsa87Signature::placeholder(),
            next_ca_signature: MlDsa87Signature::placeholder(),
        }))
    }

    fn registry() -> Box<crate::certificates::approval::CredentialRegistry> {
        Box::new(crate::certificates::approval::CredentialRegistry {
            trust_domain_id: domain(),
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            ca_epoch: 2,
            credential_registry_epoch: 2,
            bindings: Vec::new(),
        })
    }

    fn signer_result(
        campaign: &AstraRotationCampaign,
        objects: Vec<crate::certificates::transport::TrustUpdateObject>,
        credential_registry: Option<Box<crate::certificates::approval::CredentialRegistry>>,
    ) -> AstraSignerResult {
        AstraSignerResult {
            format_version: CERTIFICATE_FORMAT_VERSION,
            approval: Box::new(CampaignApproval {
                campaign_id: campaign.campaign_id,
                campaign_fingerprint: campaign.fingerprint(),
                required_credentials: campaign.required_credentials,
                approved_at: 1_100,
                approvals: Vec::new(),
            }),
            objects,
            credential_registry,
            issuer_authorization: None,
        }
    }

    /// A delegation, and the exact material it will certify (spec §9.5).
    mod issuer_delegation {
        use super::*;
        use crate::certificates::authority::{AllowedUsage, AstraIssuerAuthorization};
        use crate::certificates::encoding::{DerCertificate, MlDsa87Signature};

        /// A self-signed certificate, standing in for the intermediate the
        /// companion issues. What matters below is its public key: it is
        /// the value the campaign pinned before the touch.
        fn intermediate() -> DerCertificate {
            let key = rcgen::KeyPair::generate().expect("key");
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
            DerCertificate::new(
                params
                    .self_signed(&key)
                    .expect("intermediate")
                    .der()
                    .to_vec(),
            )
            .expect("der")
        }

        fn pq_key() -> crate::certificates::encoding::MlDsa87PublicKey {
            let (_, public_key) = crate::ml_dsa::generate_keypair().expect("keypair");
            crate::certificates::encoding::MlDsa87PublicKey::new(public_key).expect("key")
        }

        fn authorization(
            issuer_epoch: u64,
            pq_issuer_public_key: crate::certificates::encoding::MlDsa87PublicKey,
            tls_intermediate_certificate: DerCertificate,
        ) -> Box<AstraIssuerAuthorization> {
            Box::new(AstraIssuerAuthorization {
                format_version: CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: domain(),
                ca_epoch: 1,
                ca_tls_epoch: 1,
                gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                server_name: "gateway.example".into(),
                issuer_epoch,
                pq_issuer_public_key,
                tls_intermediate_certificate,
                allowed_usage: AllowedUsage::AdmittedClientLeafRenewal,
                maximum_leaf_lifetime_secs: 90 * 86_400,
                policy_fingerprint: Fingerprint::of(b"policy"),
                not_before: 1_000,
                not_after: 2_000,
                ca_pq_signature: MlDsa87Signature::placeholder(),
            })
        }

        fn issuer_campaign(
            issuer_epoch: u64,
            pq: &crate::certificates::encoding::MlDsa87PublicKey,
            intermediate: &DerCertificate,
        ) -> AstraRotationCampaign {
            super::super::campaign(
                CampaignScope::IssuerDelegation,
                vec![CampaignTarget {
                    certificate_kind: CertificateKind::AstraIssuer,
                    identity_key: WireGuardKey::from_bytes([2; 32]),
                    epoch: issuer_epoch,
                    generation: 0,
                    active_tls_certificate_fingerprint: Fingerprint::of(
                        &crate::certificates::x509::subject_public_key_info(intermediate)
                            .expect("spki"),
                    ),
                    active_pq_certificate_fingerprint: Fingerprint::of(pq.as_bytes()),
                }],
            )
        }

        fn result(
            campaign: &AstraRotationCampaign,
            authorization: Option<Box<AstraIssuerAuthorization>>,
        ) -> AstraSignerResult {
            let mut result = signer_result(campaign, Vec::new(), None);
            result.issuer_authorization = authorization;
            result
        }

        /// The delegation request carries no signature of its own, so the
        /// campaign is what binds it. Either half substituted, and the
        /// approval no longer covers what would be certified.
        #[test]
        fn a_delegation_is_covered_by_the_exact_material_the_operator_read() {
            let pq = pq_key();
            let tls = intermediate();
            let campaign = issuer_campaign(2, &pq, &tls);

            result(&campaign, Some(authorization(2, pq.clone(), tls.clone())))
                .validate(&campaign)
                .expect("the delegation the campaign named");

            // Another PQ issuer key, under the same touch.
            assert!(matches!(
                result(&campaign, Some(authorization(2, pq_key(), tls.clone())))
                    .validate(&campaign),
                Err(CertificateError::CampaignMismatch)
            ));
            // Another intermediate, therefore another certified key.
            assert!(matches!(
                result(
                    &campaign,
                    Some(authorization(2, pq.clone(), intermediate()))
                )
                .validate(&campaign),
                Err(CertificateError::CampaignMismatch)
            ));
            // A spent epoch: the walk-back `install_issuer` refuses, caught
            // before a signature is ever produced for it.
            assert!(matches!(
                result(&campaign, Some(authorization(1, pq, tls))).validate(&campaign),
                Err(CertificateError::CampaignMismatch)
            ));
        }

        /// Total in both directions, like every other family.
        #[test]
        fn a_delegation_belongs_to_its_family_and_to_no_other() {
            let pq = pq_key();
            let tls = intermediate();
            let campaign = issuer_campaign(2, &pq, &tls);

            // An issuer campaign with nothing to install is not a
            // ceremony that succeeded quietly.
            assert!(matches!(
                result(&campaign, None).validate(&campaign),
                Err(CertificateError::EmptyTransition)
            ));

            // No other family delivers one.
            let fleet = super::super::campaign(CampaignScope::FleetLeafs, vec![target(3)]);
            assert!(matches!(
                result(&fleet, Some(authorization(2, pq.clone(), tls.clone()))).validate(&fleet),
                Err(CertificateError::IssuerScopeViolation(_))
            ));

            // And an issuer campaign delivers nothing else: no trust
            // update, and no re-signed credential registry.
            let mut smuggled = result(&campaign, Some(authorization(2, pq, tls)));
            smuggled.credential_registry = Some(registry());
            assert!(matches!(
                smuggled.validate(&campaign),
                Err(CertificateError::IssuerScopeViolation(_))
            ));
        }

        /// One credential, and the vault opens: the companion issues the
        /// intermediate under `CA-TLS` and signs under `CA-PQ`. It rotates
        /// no anchor, so it is not the two-credential decision of §0.2.
        #[test]
        fn an_issuer_campaign_is_a_one_credential_vault_ceremony() {
            let scope = CampaignScope::IssuerDelegation;
            assert_eq!(scope.required_credentials(), 1);
            assert!(scope.opens_vault());
            assert!(!scope.rotates_authority());
            assert!(!scope.authorizes_client_rotation());
            assert!(!scope.revokes());
        }
    }

    /// The whole point of §0.6: an object the operator's campaign named, and
    /// nothing else, is what the companion may deposit.
    #[test]
    fn an_authority_campaign_covers_the_anchor_state_its_operator_read() {
        let current = Fingerprint::of(b"anchor of epoch 1");
        let campaign = campaign(
            CampaignScope::TrustAuthorities,
            vec![anchor_target(CertificateKind::CaPq, 1, current)],
        );
        assert!(campaign
            .covers_authority_object(&ca_transition(1, current))
            .is_ok());

        // A transition that leaves another epoch verifies under its own
        // anchor and still walks the domain somewhere nobody approved.
        assert!(matches!(
            campaign.covers_authority_object(&ca_transition(2, current)),
            Err(CertificateError::CampaignMismatch)
        ));
        // Same epoch, another outgoing anchor: not the object that was read.
        assert!(matches!(
            campaign.covers_authority_object(&ca_transition(1, Fingerprint::of(b"elsewhere"))),
            Err(CertificateError::CampaignMismatch)
        ));
    }

    /// A one-credential campaign must never be a delivery vehicle for an
    /// anchor transition — that is the whole difference between the two
    /// families of §7.2.
    #[test]
    fn a_fleet_campaign_produces_no_transition_object() {
        let campaign = campaign(CampaignScope::FleetLeafs, vec![target(3)]);
        assert!(matches!(
            campaign.covers_authority_object(&ca_transition(1, Fingerprint::of(b"anchor"))),
            Err(CertificateError::IssuerScopeViolation(_))
        ));

        let result = signer_result(&campaign, Vec::new(), None);
        assert!(result.validate(&campaign).is_ok());

        let smuggled = signer_result(
            &campaign,
            vec![ca_transition(1, Fingerprint::of(b"anchor"))],
            None,
        );
        assert!(matches!(
            smuggled.validate(&campaign),
            Err(CertificateError::IssuerScopeViolation(_))
        ));
    }

    /// A successor anchor and a credential registry only the anchor it
    /// replaces can verify would leave the domain unable to approve anything
    /// again — on the one path that repairs a domain.
    #[test]
    fn a_ca_pq_transition_carries_the_registry_that_survives_it() {
        let current = Fingerprint::of(b"anchor of epoch 1");
        let campaign = campaign(
            CampaignScope::TrustAuthorities,
            vec![anchor_target(CertificateKind::CaPq, 1, current)],
        );

        let complete = signer_result(&campaign, vec![ca_transition(1, current)], Some(registry()));
        assert!(complete.validate(&campaign).is_ok());

        let orphaned = signer_result(&campaign, vec![ca_transition(1, current)], None);
        assert!(matches!(
            orphaned.validate(&campaign),
            Err(CertificateError::InvalidCredentialBinding(_))
        ));
    }

    /// An empty authority result is not «nothing to do»: the operator touched
    /// their key for a text that named an anchor, and no object came back.
    #[test]
    fn an_authority_campaign_with_no_object_is_refused() {
        let current = Fingerprint::of(b"anchor of epoch 1");
        let campaign = campaign(
            CampaignScope::TrustAuthorities,
            vec![anchor_target(CertificateKind::CaPq, 1, current)],
        );
        assert!(matches!(
            signer_result(&campaign, Vec::new(), None).validate(&campaign),
            Err(CertificateError::EmptyTransition)
        ));
    }

    /// Two rows naming one object would make «what did the operator approve»
    /// a question of iteration order, and the ceiling stops a result from
    /// being a bulk channel.
    #[test]
    fn a_result_names_each_object_once_and_stays_under_the_ceiling() {
        let current = Fingerprint::of(b"anchor of epoch 1");
        let campaign = campaign(
            CampaignScope::TrustAuthorities,
            vec![anchor_target(CertificateKind::CaPq, 1, current)],
        );
        // The same object twice, not two objects that merely look alike:
        // each call draws a fresh successor key, and two successors are
        // two decisions rather than one repeated.
        let object = ca_transition(1, current);
        let twice = signer_result(
            &campaign,
            vec![object.clone(), object.clone()],
            Some(registry()),
        );
        assert!(matches!(
            twice.validate(&campaign),
            Err(CertificateError::DuplicateFingerprint)
        ));

        let flood = signer_result(
            &campaign,
            (0..=MAX_CAMPAIGN_OBJECTS).map(|_| object.clone()).collect(),
            Some(registry()),
        );
        assert!(matches!(
            flood.validate(&campaign),
            Err(CertificateError::CampaignMismatch)
        ));
    }

    /// The result answers the campaign it was fetched for, and Astra compares
    /// that before reading a single object.
    #[test]
    fn a_result_answering_another_campaign_is_refused() {
        let current = Fingerprint::of(b"anchor of epoch 1");
        let campaign = campaign(
            CampaignScope::TrustAuthorities,
            vec![anchor_target(CertificateKind::CaPq, 1, current)],
        );
        let mut elsewhere = campaign.clone();
        elsewhere.reason = "un autre texte".into();
        let result = signer_result(
            &elsewhere,
            vec![ca_transition(1, current)],
            Some(registry()),
        );
        assert!(matches!(
            result.validate(&campaign),
            Err(CertificateError::CampaignMismatch)
        ));
    }

    fn gateway_target(epoch: u64, tls: Fingerprint, pq: Fingerprint) -> CampaignTarget {
        CampaignTarget {
            certificate_kind: CertificateKind::GatewayPq,
            identity_key: WireGuardKey::from_bytes([2; 32]),
            epoch,
            generation: epoch,
            active_tls_certificate_fingerprint: tls,
            active_pq_certificate_fingerprint: pq,
        }
    }

    fn gateway_transition(
        epoch: u64,
        tls: Fingerprint,
        pq: Fingerprint,
    ) -> crate::certificates::transport::TrustUpdateObject {
        use crate::certificates::authority::RotationReason;
        use crate::certificates::gateway::GatewayIdentityTransition;
        use crate::certificates::window::TransitionWindow;

        crate::certificates::transport::TrustUpdateObject::GatewayIdentityTransition(Box::new(
            GatewayIdentityTransition {
                format_version: CERTIFICATE_FORMAT_VERSION,
                protocol_version: crate::certificates::CERTIFICATE_PROTOCOL_VERSION,
                trust_domain_id: domain(),
                ca_epoch: 1,
                gateway_identity_epoch: epoch,
                gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                server_name: "gateway.example".into(),
                active_gateway_tls_certificate_fingerprint: tls,
                next_gateway_tls_certificate: None,
                active_gateway_certificate_fingerprint: pq,
                next_gateway_certificate: None,
                window: TransitionWindow::new(1_000, 2_000, 3_000).expect("window"),
                reason: RotationReason::Scheduled,
                ca_signature: MlDsa87Signature::placeholder(),
            },
        ))
    }

    fn gateway_abort(epoch: u64) -> crate::certificates::transport::TrustUpdateObject {
        use crate::certificates::gateway::{AbortReason, GatewayTransitionAbort};

        crate::certificates::transport::TrustUpdateObject::GatewayTransitionAbort(Box::new(
            GatewayTransitionAbort {
                format_version: CERTIFICATE_FORMAT_VERSION,
                protocol_version: crate::certificates::CERTIFICATE_PROTOCOL_VERSION,
                trust_domain_id: domain(),
                ca_epoch: 1,
                gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                server_name: "gateway.example".into(),
                gateway_identity_epoch: epoch,
                gateway_transition_fingerprint: Fingerprint::of(b"the staged transition"),
                aborted_at: 1_500,
                reason: AbortReason::OperatorCancelled,
                campaign_fingerprint: Fingerprint::of(b"campaign"),
                ca_signature: MlDsa87Signature::placeholder(),
            },
        ))
    }

    /// §11.1 step 3: the campaign freezes the identity in service, and the
    /// transition it authorizes is the next decision on that exact state.
    #[test]
    fn a_gateway_campaign_covers_the_identity_state_its_operator_read() {
        let tls = Fingerprint::of(b"gateway tls in service");
        let pq = Fingerprint::of(b"gateway pq in service");
        let campaign = campaign(
            CampaignScope::GatewayIdentity,
            vec![gateway_target(4, tls, pq)],
        );

        let result = signer_result(&campaign, vec![gateway_transition(5, tls, pq)], None);
        result.validate(&campaign).expect("the approved decision");

        // Two decisions forward: an epoch nobody was shown.
        let skipped = signer_result(&campaign, vec![gateway_transition(6, tls, pq)], None);
        assert!(matches!(
            skipped.validate(&campaign),
            Err(CertificateError::CampaignMismatch)
        ));
        // The same epoch over another leaf in service: a decision taken
        // against a state the operator never read.
        let elsewhere = signer_result(
            &campaign,
            vec![gateway_transition(5, tls, Fingerprint::of(b"another leaf"))],
            None,
        );
        assert!(matches!(
            elsewhere.validate(&campaign),
            Err(CertificateError::CampaignMismatch)
        ));
    }

    /// The asymmetry that would silently refuse every abort: a transition
    /// is one decision forward, an abort is *at* the decision it cancels.
    #[test]
    fn an_abort_is_covered_at_the_epoch_it_cancels() {
        let tls = Fingerprint::of(b"gateway tls in service");
        let pq = Fingerprint::of(b"gateway pq in service");
        let campaign = campaign(
            CampaignScope::GatewayIdentity,
            vec![gateway_target(5, tls, pq)],
        );

        let result = signer_result(&campaign, vec![gateway_abort(5)], None);
        result.validate(&campaign).expect("the staged epoch");

        let forward = signer_result(&campaign, vec![gateway_abort(6)], None);
        assert!(matches!(
            forward.validate(&campaign),
            Err(CertificateError::CampaignMismatch)
        ));
    }

    /// Four families, and each refuses the other three.
    #[test]
    fn a_gateway_decision_belongs_to_no_other_family() {
        let tls = Fingerprint::of(b"gateway tls in service");
        let pq = Fingerprint::of(b"gateway pq in service");
        let transition = gateway_transition(5, tls, pq);

        for scope in [
            CampaignScope::TrustAuthorities,
            CampaignScope::EmergencyRevocation,
            CampaignScope::FleetLeafs,
        ] {
            let campaign = campaign(scope, vec![gateway_target(4, tls, pq)]);
            let smuggled = signer_result(&campaign, vec![transition.clone()], None);
            assert!(
                matches!(
                    smuggled.validate(&campaign),
                    Err(CertificateError::IssuerScopeViolation(_))
                ),
                "{scope:?} accepted a gateway transition"
            );
        }

        // And the reverse: a gateway campaign is not a delivery vehicle
        // for an anchor rotation.
        let campaign = campaign(
            CampaignScope::GatewayIdentity,
            vec![gateway_target(4, tls, pq)],
        );
        let anchor = signer_result(&campaign, vec![ca_transition(1, tls)], Some(registry()));
        assert!(matches!(
            anchor.validate(&campaign),
            Err(CertificateError::IssuerScopeViolation(_))
        ));
    }

    /// One touch, one decision about the identity every client pins.
    #[test]
    fn a_gateway_campaign_carries_exactly_one_decision() {
        let tls = Fingerprint::of(b"gateway tls in service");
        let pq = Fingerprint::of(b"gateway pq in service");
        let campaign = campaign(
            CampaignScope::GatewayIdentity,
            vec![gateway_target(4, tls, pq)],
        );

        let twice = signer_result(
            &campaign,
            vec![
                gateway_transition(5, tls, pq),
                gateway_transition(5, tls, pq),
            ],
            None,
        );
        assert!(matches!(
            twice.validate(&campaign),
            Err(CertificateError::CampaignMismatch)
        ));

        let empty = signer_result(&campaign, Vec::new(), None);
        assert!(matches!(
            empty.validate(&campaign),
            Err(CertificateError::CampaignMismatch)
        ));
    }

    /// A gateway renewal is signed by `CA-PQ` without replacing it, so it
    /// opens the vault while rotating no authority at all.
    #[test]
    fn a_gateway_campaign_opens_the_vault_without_rotating_an_anchor() {
        assert!(CampaignScope::GatewayIdentity.opens_vault());
        assert!(!CampaignScope::GatewayIdentity.rotates_authority());
        assert!(!CampaignScope::GatewayIdentity.revokes());
        assert!(!CampaignScope::GatewayIdentity.authorizes_client_rotation());
        assert_eq!(CampaignScope::GatewayIdentity.required_credentials(), 1);
    }
}

fn revocation(
    identity_key: WireGuardKey,
    tls: Option<Fingerprint>,
    pq: Option<Fingerprint>,
) -> super::super::revocation::EmergencyCertificateRevocation {
    use super::super::revocation::{
        EmergencyCertificateRevocation, RevocationReason, RevocationScope,
    };

    EmergencyCertificateRevocation {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        ca_epoch: 1,
        scope: RevocationScope::Client,
        identity_key,
        server_name: None,
        revocation_epoch: 2,
        revoked_tls_fingerprint: tls,
        revoked_tls_not_after: tls.map(|_| 9_000),
        revoked_pq_fingerprint: pq,
        revoked_pq_not_after: pq.map(|_| 9_000),
        effective_at: 1_100,
        reason: RevocationReason::KeyCompromise,
        replacement_transition_fingerprint: None,
        ca_signature: MlDsa87Signature::placeholder(),
    }
}

#[test]
fn a_revocation_campaign_covers_only_the_identity_state_shown_to_the_operator() {
    let target = target(1);
    let campaign = campaign(CampaignScope::EmergencyRevocation, vec![target.clone()]);
    let decision = revocation(
        target.identity_key,
        Some(target.active_tls_certificate_fingerprint),
        Some(target.active_pq_certificate_fingerprint),
    );
    campaign
        .covers_revocation(&decision)
        .expect("the exact frozen identity");

    let substituted = revocation(
        target.identity_key,
        None,
        Some(Fingerprint::of(b"a leaf the operator was not shown")),
    );
    assert!(matches!(
        campaign.covers_revocation(&substituted),
        Err(CertificateError::CampaignMismatch)
    ));
}

#[test]
fn a_revocation_campaign_neither_renews_a_client_nor_carries_an_anchor() {
    let target = target(1);
    let campaign = campaign(CampaignScope::EmergencyRevocation, vec![target.clone()]);
    assert!(campaign
        .covers_client(
            &target.identity_key,
            target.generation,
            &target.active_tls_certificate_fingerprint,
            &target.active_pq_certificate_fingerprint,
        )
        .is_err());
    assert!(campaign
        .covers_authority_object(
            &crate::certificates::transport::TrustUpdateObject::CertificateRevocation(Box::new(
                revocation(
                    target.identity_key,
                    None,
                    Some(target.active_pq_certificate_fingerprint),
                )
            ),)
        )
        .is_err());
}

#[test]
fn a_revocation_result_carries_exactly_one_revocation_and_no_registry() {
    let target = target(1);
    let campaign = campaign(CampaignScope::EmergencyRevocation, vec![target.clone()]);
    let object = crate::certificates::transport::TrustUpdateObject::CertificateRevocation(
        Box::new(revocation(
            target.identity_key,
            Some(target.active_tls_certificate_fingerprint),
            Some(target.active_pq_certificate_fingerprint),
        )),
    );
    let result = AstraSignerResult {
        format_version: CERTIFICATE_FORMAT_VERSION,
        approval: Box::new(CampaignApproval {
            campaign_id: campaign.campaign_id,
            campaign_fingerprint: campaign.fingerprint(),
            required_credentials: 1,
            approved_at: 1_100,
            approvals: Vec::new(),
        }),
        objects: vec![object.clone()],
        credential_registry: None,
        issuer_authorization: None,
    };
    result.validate(&campaign).expect("one signed decision");

    let mut twice = result.clone();
    twice.objects.push(object);
    assert!(twice.validate(&campaign).is_err());
    let mut with_registry = result;
    with_registry.credential_registry = Some(Box::new(
        crate::certificates::approval::CredentialRegistry {
            trust_domain_id: domain(),
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            ca_epoch: 1,
            credential_registry_epoch: 1,
            bindings: Vec::new(),
        },
    ));
    assert!(with_registry.validate(&campaign).is_err());
}

/// Anchor rotation and continuity-free bootstrap need two credentials;
/// every decision that starts from an authenticated identity needs one.
#[test]
fn authority_and_bootstrap_scopes_require_two_credentials() {
    assert_eq!(CampaignScope::FleetLeafs.required_credentials(), 1);
    assert_eq!(
        CampaignScope::FullCertificateChain.required_credentials(),
        1
    );
    assert_eq!(CampaignScope::TrustAuthorities.required_credentials(), 2);
    assert_eq!(CampaignScope::GatewayBootstrap.required_credentials(), 2);
    assert!(CampaignScope::TrustAuthorities.rotates_authority());
    assert!(!CampaignScope::FullCertificateChain.rotates_authority());
}

#[test]
fn bootstrap_scope_never_becomes_an_online_astra_campaign() {
    let campaign = campaign(CampaignScope::GatewayBootstrap, vec![target(1)]);
    assert!(matches!(
        campaign.validate(1_100),
        Err(CertificateError::IssuerScopeViolation(_))
    ));
}

#[test]
fn a_campaign_asking_for_fewer_credentials_than_its_scope_is_refused() {
    let mut campaign = campaign(CampaignScope::TrustAuthorities, vec![target(1)]);
    campaign.required_credentials = 1;
    assert!(matches!(
        campaign.validate(1_100),
        Err(CertificateError::InsufficientApprovals {
            required: 2,
            provided: 1
        })
    ));
}

/// Two rows for the same object make «what was approved» an iteration
/// order, and `covers_client` would answer with whichever it met first.
#[test]
fn a_campaign_naming_the_same_object_twice_is_refused() {
    let twice = campaign(CampaignScope::FleetLeafs, vec![target(1), target(1)]);
    assert!(matches!(
        twice.validate(1_100),
        Err(CertificateError::DuplicateFingerprint)
    ));

    // Same identity, other family: two different objects, both allowed.
    let mut tls = target(1);
    tls.certificate_kind = CertificateKind::ClientTls;
    let pair = campaign(CampaignScope::FleetLeafs, vec![target(1), tls]);
    pair.validate(1_100).expect("two families of one identity");
}

/// The row authorizes the rotation it described, and no later one.
#[test]
fn a_campaign_covers_the_state_its_operator_read_and_no_other() {
    let campaign = campaign(CampaignScope::FleetLeafs, vec![target(1), target(2)]);
    let key = WireGuardKey::from_bytes([1; 32]);
    let tls = Fingerprint::of(&[1, 1]);
    let pq = Fingerprint::of(&[1, 2]);
    campaign
        .covers_client(&key, 3, &tls, &pq)
        .expect("the approved target");

    // The same identity, one generation on: a different rotation, and the
    // touch that approved the first must not authorize it. Without this a
    // single approval renews a peer for as long as nobody looks.
    assert!(matches!(
        campaign.covers_client(&key, 4, &tls, &pq),
        Err(CertificateError::CampaignMismatch)
    ));
    // A leaf that moved under the operator between reading and approving.
    assert!(matches!(
        campaign.covers_client(&key, 3, &Fingerprint::of(b"other"), &pq),
        Err(CertificateError::CampaignMismatch)
    ));
    assert!(matches!(
        campaign.covers_client(&key, 3, &tls, &Fingerprint::of(b"other")),
        Err(CertificateError::CampaignMismatch)
    ));
    // An identity the campaign never named.
    assert!(matches!(
        campaign.covers_client(&WireGuardKey::from_bytes([9; 32]), 3, &tls, &pq),
        Err(CertificateError::CampaignMismatch)
    ));
}

/// A generation is a TLS leaf and a PQ leaf together, so either row names
/// it — both pin both fingerprints.
#[test]
fn either_client_family_names_the_generation() {
    let mut tls = target(1);
    tls.certificate_kind = CertificateKind::ClientTls;
    let campaign = campaign(CampaignScope::FleetLeafs, vec![tls]);
    campaign
        .covers_client(
            &WireGuardKey::from_bytes([1; 32]),
            3,
            &Fingerprint::of(&[1, 1]),
            &Fingerprint::of(&[1, 2]),
        )
        .expect("a TLS row names the same generation");
}

/// A gateway row is not a client row, whatever its fingerprints say.
#[test]
fn a_gateway_target_does_not_authorize_a_client_rotation() {
    let mut gateway = target(1);
    gateway.certificate_kind = CertificateKind::GatewayPq;
    let campaign = campaign(CampaignScope::FleetLeafs, vec![gateway]);
    assert!(matches!(
        campaign.covers_client(
            &WireGuardKey::from_bytes([1; 32]),
            3,
            &Fingerprint::of(&[1, 1]),
            &Fingerprint::of(&[1, 2]),
        ),
        Err(CertificateError::CampaignMismatch)
    ));
}

/// Two credentials approved a decision about `CA-PQ`. Spending it on a
/// client leaf would apply a text the operator was never shown.
#[test]
fn an_authority_campaign_never_authorizes_a_client_rotation() {
    let campaign = campaign(CampaignScope::TrustAuthorities, vec![target(1)]);
    assert!(matches!(
        campaign.covers_client(
            &WireGuardKey::from_bytes([1; 32]),
            3,
            &Fingerprint::of(&[1, 1]),
            &Fingerprint::of(&[1, 2]),
        ),
        Err(CertificateError::IssuerScopeViolation(_))
    ));
}

/// Adding, removing or reordering a target after approval must be visible.
#[test]
fn any_change_to_the_target_list_invalidates_the_approval() {
    let campaign = campaign(CampaignScope::FleetLeafs, vec![target(1), target(2)]);
    campaign.validate(1_100).expect("valid campaign");
    let approved = campaign.fingerprint();
    assert!(campaign.assert_unchanged(&approved).is_ok());

    let added = super::AstraRotationCampaign {
        targets: vec![target(1), target(2), target(3)],
        ..campaign.clone()
    };
    assert!(matches!(
        added.assert_unchanged(&approved),
        Err(CertificateError::CampaignMismatch)
    ));

    let reordered = super::AstraRotationCampaign {
        targets: vec![target(2), target(1)],
        ..campaign.clone()
    };
    assert!(matches!(
        reordered.assert_unchanged(&approved),
        Err(CertificateError::CampaignMismatch)
    ));

    let mut modified = campaign.clone();
    modified.targets[0].generation = 4;
    assert!(matches!(
        modified.assert_unchanged(&approved),
        Err(CertificateError::CampaignMismatch)
    ));
}

#[test]
fn an_empty_or_oversized_campaign_is_refused() {
    let empty = campaign(CampaignScope::FleetLeafs, Vec::new());
    assert!(matches!(
        empty.validate(1_100),
        Err(CertificateError::EmptyTransition)
    ));

    let targets = (0..=MAX_CAMPAIGN_TARGETS)
        .map(|index| target((index % 251) as u8))
        .collect();
    let oversized = campaign(CampaignScope::FleetLeafs, targets);
    assert!(matches!(
        oversized.validate(1_100),
        Err(CertificateError::TooManyObjects)
    ));
}

/// The service key epoch is compared first, so a compromised key cannot
/// freeze its target by publishing `status_epoch = u64::MAX`.
#[test]
fn a_maximal_status_epoch_under_the_old_key_loses_to_the_next_key() {
    let frozen = (3u64, u64::MAX);
    let successor = (4u64, 1u64);
    assert!(successor > frozen);
}

#[test]
fn a_status_window_can_be_brought_forward_but_never_pushed_back() {
    let status = AstraCertificateStatus {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        certificate_fingerprint: Fingerprint::of(b"leaf"),
        certificate_kind: CertificateKind::ClientPq,
        generation: 3,
        status: CertificateStatus::RenewalDue,
        suggested_window_start: 9_000,
        suggested_window_end: 20_000,
        produced_at: 1_000,
        next_update: 2_000,
        status_epoch: 5,
        astra_service_key_epoch: 1,
        astra_signature: MlDsa87Signature::new(vec![0; 4627]).unwrap(),
    };
    // Local calculation says renewal opens at 8 000 and the leaf dies at
    // 10 000: Astra cannot delay either bound.
    assert_eq!(status.clamped_window(8_000, 10_000), (8_000, 10_000));
    // Bringing the window forward for an incident is allowed.
    let earlier = AstraCertificateStatus {
        suggested_window_start: 5_000,
        ..status
    };
    assert_eq!(earlier.clamped_window(8_000, 10_000), (5_000, 10_000));
}

#[test]
fn revoked_is_the_only_terminal_status() {
    assert!(CertificateStatus::Revoked.is_terminal());
    for status in [
        CertificateStatus::Active,
        CertificateStatus::Overlap,
        CertificateStatus::Expired,
        CertificateStatus::Aborted,
    ] {
        assert!(!status.is_terminal(), "{status:?}");
    }
}

/// The refusal happens in the **verifier**, not only in a display.
///
/// And before the signature: the family check is a match, the signature is
/// an ML-DSA-87 verification, and a combination the table does not hold is
/// meaningless whoever signed it.
#[test]
fn a_status_outside_its_family_is_refused_before_its_signature() {
    let (_, service_key) =
        crate::certificates::encoding::generate_ml_dsa_87_keypair().expect("keygen");
    let fingerprint = Fingerprint::of(b"delegation");
    let status = AstraCertificateStatus {
        format_version: CERTIFICATE_FORMAT_VERSION,
        trust_domain_id: domain(),
        certificate_fingerprint: fingerprint,
        // A delegated issuer is replaced, never staged through a client
        // renewal: this pair is not in the table.
        certificate_kind: CertificateKind::AstraIssuer,
        generation: 3,
        status: CertificateStatus::PendingCommit,
        suggested_window_start: 9_000,
        suggested_window_end: 20_000,
        produced_at: 1_000,
        next_update: 2_000,
        status_epoch: 5,
        astra_service_key_epoch: 1,
        astra_signature: MlDsa87Signature::placeholder(),
    };

    assert!(matches!(
        status.verify(&service_key, 1, &domain(), &fingerprint, None),
        Err(CertificateError::UnsupportedStatus {
            kind: CertificateKind::AstraIssuer,
            status: CertificateStatus::PendingCommit,
        })
    ));

    // The same object in a state its family does hold gets as far as the
    // signature — which a placeholder fails. That is what says the refusal
    // above was about the family and not about the signature.
    let allowed = AstraCertificateStatus {
        status: CertificateStatus::RenewalDue,
        ..status
    };
    assert!(!matches!(
        allowed.verify(&service_key, 1, &domain(), &fingerprint, None),
        Err(CertificateError::UnsupportedStatus { .. })
    ));
}

/// §8.2 selects the state type by family, and the decoder **must** refuse a
/// combination absent from its table.
///
/// A flat enum lets a signed status say `astra_issuer: pending_commit` — a
/// sentence with no meaning that every consumer would then have to
/// interpret, and interpreting it is how two interfaces end up disagreeing
/// about what the authority said.
#[test]
fn each_family_admits_only_the_states_the_table_gives_it() {
    use CertificateKind::*;
    use CertificateStatus::*;

    // The table of §8.2, transcribed. Anything outside a row is refused.
    let client: &[CertificateStatus] = &[
        Active,
        RenewalDue,
        AwaitingOperator,
        PendingGrant,
        PendingCommit,
        Overlap,
        Promoted,
        Expired,
        Revoked,
    ];
    let gateway: &[CertificateStatus] = &[
        Active, RenewalDue, Staged, Published, Aborted, Overlap, Promoted, Expired, Revoked,
    ];
    let anchors: &[CertificateStatus] = &[
        Active, RenewalDue, Staged, Overlap, Promoted, Expired, Revoked,
    ];
    let issuer: &[CertificateStatus] = &[Active, RenewalDue, Expired, Revoked];
    let table: [(CertificateKind, &[CertificateStatus]); 8] = [
        (ClientTls, client),
        (ClientPq, client),
        (GatewayTls, gateway),
        (GatewayPq, gateway),
        (CaPq, anchors),
        (CaTls, anchors),
        (AstraServiceKey, anchors),
        (AstraIssuer, issuer),
    ];

    for (kind, admitted) in table {
        for status in EVERY_STATUS {
            assert_eq!(
                status.permitted_for(kind),
                admitted.contains(&status),
                "{kind:?} / {status:?}"
            );
        }
    }
}

/// A state no family may hold is a state nothing can express.
#[test]
fn no_state_is_orphaned_by_the_table() {
    use CertificateKind::*;

    let families = [
        GatewayTls,
        GatewayPq,
        ClientTls,
        ClientPq,
        CaPq,
        CaTls,
        AstraIssuer,
        AstraServiceKey,
    ];
    for status in EVERY_STATUS {
        assert!(
            families.iter().any(|kind| status.permitted_for(*kind)),
            "{status:?} belongs to no family"
        );
    }
}

/// Two states cannot share a transcript byte: that byte is what the
/// signature covers, so a collision makes two statements identical.
#[test]
fn every_state_has_its_own_transcript_byte() {
    let mut bytes: Vec<u8> = EVERY_STATUS
        .into_iter()
        .map(CertificateStatus::domain_byte)
        .collect();
    let total = bytes.len();
    bytes.sort_unstable();
    bytes.dedup();
    assert_eq!(bytes.len(), total, "two states share a byte");
    // The ten original states keep the numbers they were signed under:
    // renumbering one would silently change what every signed status said.
    assert_eq!(CertificateStatus::Active.domain_byte(), 0);
    assert_eq!(CertificateStatus::Revoked.domain_byte(), 9);
}

mod campaign_approval {
    use super::*;
    use crate::certificates::approval::{
        AstraCredentialBinding, CredentialRegistry, CredentialState,
    };
    use crate::certificates::encoding::generate_ml_dsa_87_keypair;
    use crate::certificates::webauthn::test_credentials::Credential;
    use crate::certificates::webauthn::WebAuthnAssertion;
    use aws_lc_rs::digest;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    const RELYING_PARTY: &str = "astra.example";
    const ORIGIN: &str = "https://astra.example";

    fn binding(ca_private: &[u8], credential: &Credential, id: &[u8]) -> AstraCredentialBinding {
        AstraCredentialBinding {
            format_version: CERTIFICATE_FORMAT_VERSION,
            credential_id: id.to_vec(),
            credential_public_key: credential.cose_public_key(),
            aaguid: [0; 16],
            trust_domain_id: domain(),
            gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
            state: CredentialState::Active,
            credential_epoch: 1,
            credential_registry_epoch: 4,
            ca_epoch: 1,
            created_at: 500,
            ca_pq_signature: MlDsa87Signature::placeholder(),
        }
        .sign(ca_private)
        .expect("sign")
    }

    fn assertion(credential: &Credential, challenge: &Fingerprint) -> WebAuthnAssertion {
        let mut authenticator_data = Fingerprint::of(RELYING_PARTY.as_bytes())
            .as_bytes()
            .to_vec();
        // User presence and user verification.
        authenticator_data.push(0x05);
        authenticator_data.extend_from_slice(&11u32.to_be_bytes());
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}"}}"#,
            URL_SAFE_NO_PAD.encode(challenge.as_bytes())
        )
        .into_bytes();
        let mut message = authenticator_data.clone();
        message.extend_from_slice(digest::digest(&digest::SHA256, &client_data_json).as_ref());
        WebAuthnAssertion {
            authenticator_data,
            client_data_json,
            signature: credential.sign(&message),
        }
    }

    fn answer(
        credential: &Credential,
        binding: &AstraCredentialBinding,
        challenge: &Fingerprint,
    ) -> CredentialAssertion {
        let assertion = assertion(credential, challenge);
        CredentialAssertion {
            credential_id: binding.credential_id.clone(),
            credential_fingerprint: binding.fingerprint(),
            assertion_fingerprint: assertion.fingerprint(),
            assertion,
        }
    }

    struct Domain {
        ca_public: MlDsa87PublicKey,
        registry: CredentialRegistry,
        first: Credential,
        second: Credential,
        first_binding: AstraCredentialBinding,
        second_binding: AstraCredentialBinding,
    }

    fn domain_with_two_credentials() -> Domain {
        let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("keygen");
        let first = Credential::generate();
        let second = Credential::generate();
        let first_binding = binding(&ca_private, &first, b"credential-one");
        let second_binding = binding(&ca_private, &second, b"credential-two");
        Domain {
            ca_public,
            registry: CredentialRegistry {
                trust_domain_id: domain(),
                gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
                ca_epoch: 1,
                credential_registry_epoch: 4,
                bindings: vec![first_binding.clone(), second_binding.clone()],
            },
            first,
            second,
            first_binding,
            second_binding,
        }
    }

    fn approval(
        campaign: &AstraRotationCampaign,
        answers: Vec<CredentialAssertion>,
    ) -> CampaignApproval {
        CampaignApproval {
            campaign_id: campaign.campaign_id,
            campaign_fingerprint: campaign.fingerprint(),
            required_credentials: campaign.required_credentials,
            approved_at: 1_100,
            approvals: answers,
        }
    }

    /// The evidence a delegated `manual_global` staging carries (§7.2).
    mod evidence {
        use super::*;
        use crate::certificates::approval::AstraCampaignApprovalEvidence;

        const POLICY: &[u8] = b"policy";

        fn client_key() -> WireGuardKey {
            WireGuardKey::from_bytes([1; 32])
        }

        fn evidence(
            domain: &Domain,
            campaign: AstraRotationCampaign,
        ) -> AstraCampaignApprovalEvidence {
            let challenge = campaign.fingerprint();
            let approval = approval(
                &campaign,
                vec![answer(&domain.first, &domain.first_binding, &challenge)],
            );
            AstraCampaignApprovalEvidence {
                campaign,
                approval,
                credential_registry: domain.registry.clone(),
                webauthn_origin: ORIGIN.into(),
            }
        }

        fn check(
            domain: &Domain,
            evidence: &AstraCampaignApprovalEvidence,
            policy: &Fingerprint,
        ) -> Result<(), CertificateError> {
            evidence.verify(
                &domain.ca_public,
                &super::super::domain(),
                &WireGuardKey::from_bytes([2; 32]),
                &client_key(),
                3,
                &Fingerprint::of(&[1, 1]),
                &Fingerprint::of(&[1, 2]),
                RELYING_PARTY,
                policy,
                1,
                4,
                1_100,
            )
        }

        #[test]
        fn a_campaign_approval_authorizes_the_target_it_named() {
            let domain = domain_with_two_credentials();
            let evidence = evidence(
                &domain,
                campaign(CampaignScope::FleetLeafs, vec![target(1), target(2)]),
            );
            check(&domain, &evidence, &Fingerprint::of(POLICY)).expect("covered target");
        }

        /// The fingerprint is what the staging authorization signs. An
        /// evidence blob that did not hash to it would be a second
        /// document beside the one the signature commits to.
        #[test]
        fn the_carried_fingerprint_is_the_approval_itself() {
            let domain = domain_with_two_credentials();
            let evidence = evidence(
                &domain,
                campaign(CampaignScope::FleetLeafs, vec![target(1)]),
            );
            assert!(evidence
                .fingerprint()
                .expect("fingerprint")
                .matches(&evidence.approval.fingerprint().expect("approval")));
        }

        /// §2.4: the policy pin is confirmed out of band, and a campaign
        /// resolved under another set of rules is not this domain's.
        #[test]
        fn a_campaign_naming_another_policy_is_refused() {
            let domain = domain_with_two_credentials();
            let evidence = evidence(
                &domain,
                campaign(CampaignScope::FleetLeafs, vec![target(1)]),
            );
            assert!(matches!(
                check(&domain, &evidence, &Fingerprint::of(b"another policy")),
                Err(CertificateError::PolicyNotPinned)
            ));
        }

        /// The origin is supplied, so it is checked against the relying
        /// party the consumer pins — otherwise supplying it would be
        /// supplying the answer.
        #[test]
        fn an_origin_outside_the_pinned_relying_party_is_refused() {
            let domain = domain_with_two_credentials();
            let mut evidence = evidence(
                &domain,
                campaign(CampaignScope::FleetLeafs, vec![target(1)]),
            );
            evidence.webauthn_origin = "https://attacker.example".into();
            assert!(check(&domain, &evidence, &Fingerprint::of(POLICY)).is_err());
        }

        /// The registry travels along and is verified under the `CA-PQ`
        /// the consumer already holds, never believed for being present.
        #[test]
        fn a_registry_no_ca_pq_of_this_domain_signed_is_refused() {
            let domain = domain_with_two_credentials();
            let stranger = domain_with_two_credentials();
            let mut evidence = evidence(
                &domain,
                campaign(CampaignScope::FleetLeafs, vec![target(1)]),
            );
            evidence.credential_registry = stranger.registry.clone();
            assert!(check(&domain, &evidence, &Fingerprint::of(POLICY)).is_err());
        }

        /// A campaign for another gateway resolves credentials that verify
        /// nowhere; it is refused before any of them is looked at.
        #[test]
        fn a_campaign_for_another_gateway_is_refused() {
            let domain = domain_with_two_credentials();
            let mut wrong = campaign(CampaignScope::FleetLeafs, vec![target(1)]);
            wrong.gateway_wg_public_key = WireGuardKey::from_bytes([9; 32]);
            let evidence = evidence(&domain, wrong);
            assert!(matches!(
                check(&domain, &evidence, &Fingerprint::of(POLICY)),
                Err(CertificateError::GatewayIdentityMismatch)
            ));
        }

        /// The whole point of the family: a perfectly approved campaign
        /// that does not name this peer authorizes nothing for it.
        #[test]
        fn a_valid_approval_for_other_targets_authorizes_nothing_here() {
            let domain = domain_with_two_credentials();
            let evidence = evidence(
                &domain,
                campaign(CampaignScope::FleetLeafs, vec![target(2), target(3)]),
            );
            assert!(matches!(
                check(&domain, &evidence, &Fingerprint::of(POLICY)),
                Err(CertificateError::CampaignMismatch)
            ));
        }
    }

    #[test]
    fn one_credential_approves_an_ordinary_campaign() {
        let domain = domain_with_two_credentials();
        let campaign = campaign(CampaignScope::FleetLeafs, vec![target(3)]);
        let challenge = campaign.fingerprint();
        let approval = approval(
            &campaign,
            vec![answer(&domain.first, &domain.first_binding, &challenge)],
        );

        approval
            .verify(&campaign, &domain.registry, RELYING_PARTY, ORIGIN, 1_100)
            .expect("one active credential is what this scope demands");
    }

    /// Two touches of one token read as two people and are one.
    ///
    /// The whole value of a two-credential scope is that two objects were
    /// present; accepting the same identifier twice would make the count a
    /// formality.
    #[test]
    fn the_same_credential_cannot_answer_twice() {
        let domain = domain_with_two_credentials();
        let campaign = campaign(CampaignScope::TrustAuthorities, vec![target(3)]);
        let challenge = campaign.fingerprint();
        let once = answer(&domain.first, &domain.first_binding, &challenge);
        let twice = approval(&campaign, vec![once.clone(), once]);

        assert!(matches!(
            twice.verify(&campaign, &domain.registry, RELYING_PARTY, ORIGIN, 1_100),
            Err(CertificateError::DuplicateApproval)
        ));

        // Two distinct ones pass, so the refusal above is about identity
        // and not about the count.
        let distinct = approval(
            &campaign,
            vec![
                answer(&domain.first, &domain.first_binding, &challenge),
                answer(&domain.second, &domain.second_binding, &challenge),
            ],
        );
        distinct
            .verify(&campaign, &domain.registry, RELYING_PARTY, ORIGIN, 1_100)
            .expect("two distinct credentials");
    }

    /// A target that moved after the touch invalidates the approval.
    ///
    /// The operator approved *that* list. Recomputing the campaign around
    /// a new target and reusing the assertion would apply a decision
    /// nobody made.
    #[test]
    fn a_campaign_whose_targets_moved_is_refused() {
        let domain = domain_with_two_credentials();
        let approved = campaign(CampaignScope::FleetLeafs, vec![target(3)]);
        let challenge = approved.fingerprint();
        let approval = approval(
            &approved,
            vec![answer(&domain.first, &domain.first_binding, &challenge)],
        );

        let widened = campaign(CampaignScope::FleetLeafs, vec![target(3), target(4)]);
        assert!(matches!(
            approval.verify(&widened, &domain.registry, RELYING_PARTY, ORIGIN, 1_100),
            Err(CertificateError::CampaignMismatch)
        ));
    }

    /// The count comes from the campaign, never from the approval.
    ///
    /// A document that carried its own threshold would set it.
    #[test]
    fn an_approval_cannot_lower_the_count_its_campaign_demands() {
        let domain = domain_with_two_credentials();
        let campaign = campaign(CampaignScope::TrustAuthorities, vec![target(3)]);
        let challenge = campaign.fingerprint();
        let mut approval = approval(
            &campaign,
            vec![answer(&domain.first, &domain.first_binding, &challenge)],
        );
        approval.required_credentials = 1;

        assert!(matches!(
            approval.verify(&campaign, &domain.registry, RELYING_PARTY, ORIGIN, 1_100),
            Err(CertificateError::InsufficientApprovals { .. })
        ));
    }

    /// An assertion produced for another relying party is valid for
    /// another domain, and must not verify here.
    #[test]
    fn an_assertion_for_another_relying_party_is_refused() {
        let domain = domain_with_two_credentials();
        let campaign = campaign(CampaignScope::FleetLeafs, vec![target(3)]);
        let challenge = campaign.fingerprint();
        let approval = approval(
            &campaign,
            vec![answer(&domain.first, &domain.first_binding, &challenge)],
        );

        assert!(approval
            .verify(
                &campaign,
                &domain.registry,
                "other.example",
                "https://other.example",
                1_100
            )
            .is_err());
    }

    /// A credential the registry does not carry approves nothing, however
    /// well-formed its assertion is.
    #[test]
    fn a_credential_outside_the_registry_is_refused() {
        let domain = domain_with_two_credentials();
        let campaign = campaign(CampaignScope::FleetLeafs, vec![target(3)]);
        let challenge = campaign.fingerprint();
        let stranger = Credential::generate();
        let mut answer = answer(&domain.first, &domain.first_binding, &challenge);
        answer.credential_id = b"credential-unknown".to_vec();
        let _ = stranger;
        let approval = approval(&campaign, vec![answer]);

        assert!(matches!(
            approval.verify(&campaign, &domain.registry, RELYING_PARTY, ORIGIN, 1_100),
            Err(CertificateError::UnknownCredential)
        ));
    }
}
