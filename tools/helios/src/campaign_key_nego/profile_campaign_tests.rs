//! Profile and public negotiation diagnostics using a controlled loopback gateway.

use super::*;
use aether::key_negotiation::{
    authenticate_response, AuthenticatedKeyNegotiationCommit,
    AuthenticatedKeyNegotiationConfirmation, AuthenticatedKeyNegotiationRequest,
};
use aether_key_negotiation::{
    prepare_key_material, server_endpoint, GatewayIdentity, NegotiationHandler,
    PreparedNegotiation, PublicError, TlsIdentity,
};
use orion_core::config::KeyNegotiationSettings;
use orion_core::key_negotiation::ClientIdentity;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};

struct Identity {
    tls: TlsIdentity,
    pq: PqCertificate,
    pq_key: zeroize::Zeroizing<Vec<u8>>,
}

impl Identity {
    fn new(
        name: &str,
        role: PqCertificateRole,
        wg_public_key: &str,
        ca: &Issuer<'_, KeyPair>,
    ) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![match role {
            PqCertificateRole::Gateway => ExtendedKeyUsagePurpose::ServerAuth,
            PqCertificateRole::Client => ExtendedKeyUsagePurpose::ClientAuth,
        }];
        let certificate = params.signed_by(&key, ca).unwrap();
        let (pq_key, pq_public) = generate_ml_dsa_87_keypair().unwrap();
        let pq = issue_pq_certificate(
            PqCertificate {
                version: PQ_CERTIFICATE_VERSION,
                serial: [1; 16],
                subject: name.to_owned(),
                issuer: name.to_owned(),
                role,
                wireguard_public_key: wg_public_key.to_owned(),
                ml_dsa_87_public_key: b64().encode(&pq_public),
                not_before_unix: 1,
                not_after_unix: u64::MAX,
                ml_dsa_87_signature: String::new(),
            },
            &pq_key,
        )
        .unwrap();
        Self {
            tls: TlsIdentity {
                certificate_chain: vec![certificate.der().to_vec()],
                private_key: key.serialize_der(),
            },
            pq,
            pq_key,
        }
    }
}

#[async_trait::async_trait]
impl IdentityProvider for Identity {
    async fn load(&self, identity: &str) -> Result<ClientIdentity> {
        anyhow::ensure!(identity == "test-profile", "identity unavailable");
        Ok(ClientIdentity {
            certificate_chain: self.tls.certificate_chain.clone(),
            private_key: self.tls.private_key.clone(),
            pq_certificate: serde_json::to_vec(&self.pq)?,
            pq_private_key: self.pq_key.to_vec(),
        })
    }
}

struct MockGateway {
    identity: Identity,
    client_tls: String,
    client_key: String,
}

#[async_trait::async_trait]
impl NegotiationHandler for MockGateway {
    fn announced_identity(&self) -> GatewayIdentity {
        GatewayIdentity {
            wg_public_key: self.identity.pq.wireguard_public_key.clone(),
            server_name: self.identity.pq.subject.clone(),
        }
    }

    async fn resolve_admitted_peer(
        &self,
        fingerprint: &str,
        _: std::net::IpAddr,
    ) -> Option<String> {
        (fingerprint == self.client_tls).then(|| self.client_key.clone())
    }

    async fn prepare(
        &self,
        fingerprint: String,
        _: std::net::IpAddr,
        request: AuthenticatedKeyNegotiationRequest,
    ) -> Result<PreparedNegotiation, PublicError> {
        assert_eq!(fingerprint, self.client_tls);
        assert_eq!(request.request.client_wg_public_key, self.client_key);
        let confirmation_timeout = Duration::from_secs(5);
        let material = prepare_key_material(
            &request.request,
            &self.identity.pq.wireguard_public_key,
            [7; 16],
            None,
            confirmation_timeout,
        )?;
        let response = authenticate_response(
            material.response,
            self.identity.pq.clone(),
            &self.identity.pq_key,
        )
        .map_err(|_| PublicError::Internal)?;
        Ok(PreparedNegotiation {
            response,
            confirmation_timeout,
        })
    }

    async fn confirm(
        &self,
        _: AuthenticatedKeyNegotiationConfirmation,
    ) -> Result<AuthenticatedKeyNegotiationCommit, PublicError> {
        Err(PublicError::Internal)
    }

    async fn rollback(&self, _: [u8; 16], _: &str) {}
}

#[tokio::test]
async fn profile_and_gateway_campaigns_check_local_policy_and_fresh_loopback_sessions() {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_ca_cert_der(ca_cert.der(), ca_key).unwrap();
    let client = aether::wg::generate_keypair().unwrap();
    let client_identity = Identity::new(
        "orion",
        PqCertificateRole::Client,
        &client.public_key,
        &issuer,
    );
    let gateway_key = aether::wg::generate_keypair().unwrap().public_key;
    let gateway = Identity::new(
        "localhost",
        PqCertificateRole::Gateway,
        &gateway_key,
        &issuer,
    );
    let gateway_leaf = b64().encode(serde_json::to_vec(&gateway.pq).unwrap());
    let endpoint = server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &gateway.tls,
        &[ca_cert.der().to_vec()],
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap();
    let gateway_server = tokio::spawn(aether_key_negotiation::serve(
        endpoint,
        Arc::new(MockGateway {
            identity: gateway,
            client_tls: aether_key_negotiation::certificate_fingerprint_der(
                &client_identity.tls.certificate_chain[0],
            ),
            client_key: client.public_key,
        }),
    ));
    let mut enrolled = Enrolled {
        profile: ClientProfile {
            private_key: client.private_key,
            peer_public_key: gateway_key,
            key_negotiation: Some(KeyNegotiationSettings {
                mode: ProtectionMode::MlKem,
                minimum_mode: ProtectionMode::MlKem,
                endpoint: address.to_string(),
                server_name: "localhost".into(),
                gateway_ca_der: b64().encode(ca_cert.der()),
                gateway_pq_certificate: gateway_leaf,
                identity: "test-profile".into(),
                trust: None,
            }),
            ..ClientProfile::default()
        },
        identities: Arc::new(client_identity),
    };

    for (name, outcome) in profile_scenarios(&enrolled).await {
        assert!(matches!(outcome, Outcome::Pass(_)), "{name}: {outcome:?}");
    }
    let cases = gateway_scenarios(&enrolled, false).await;
    let [nominal, freshness, rollback, soak] = cases.as_slice() else {
        panic!("expected the four gateway scenarios");
    };
    for (name, outcome) in [nominal, freshness, rollback] {
        assert!(matches!(outcome, Outcome::Pass(_)), "{name}: {outcome:?}");
    }
    assert!(matches!(soak.1, Outcome::Skip(_)));
    gateway_server.abort();

    enrolled.profile.private_key = aether::wg::generate_keypair().unwrap().private_key;
    assert!(matches!(
        scenario_identity_matches(&enrolled).await,
        Outcome::Fail(_)
    ));
    let settings = enrolled.profile.key_negotiation.as_mut().unwrap();
    settings.identity = "unknown".into();
    assert!(matches!(
        scenario_identity_matches(&enrolled).await,
        Outcome::Fail(_)
    ));

    for (name, outcome) in gateway_scenarios(&enrolled, false)
        .await
        .into_iter()
        .take(3)
    {
        assert!(matches!(outcome, Outcome::Fail(_)), "{name}: {outcome:?}");
    }
    enrolled
        .profile
        .key_negotiation
        .as_mut()
        .unwrap()
        .minimum_mode = ProtectionMode::StaticPsk;
    assert!(matches!(
        scenario_local_downgrade(&enrolled).await,
        Outcome::Skip(_)
    ));

    enrolled.profile.peer_public_key = some_wg_key(3);
    assert!(matches!(
        scenario_profile_block(&enrolled.profile),
        Outcome::Fail(_)
    ));
    enrolled.profile.key_negotiation = None;
    for (name, outcome) in profile_scenarios(&enrolled).await {
        assert!(matches!(outcome, Outcome::Skip(_)), "{name}: {outcome:?}");
    }
}
