use super::*;
use crate::commands::test_support::{answer_gateway, gateway_test_profile, scripted_engine};
use aether::certificates::encoding::{
    generate_ml_dsa_87_keypair, Fingerprint, Id16, MlDsa87Signature, WireGuardKey,
};
use aether::key_negotiation::{
    EnrollmentInvitation, ProtectionMode, ENROLLMENT_FORMAT_VERSION, ENROLLMENT_PROTOCOL_VERSION,
};
use astra_operator::{
    enrollment::{InvitationRegistry, InvitationState},
    operations::fixtures::{domain, gateway_key},
};
use std::time::Duration;
use tokio::net::TcpListener;

fn invitation(seed: u8) -> EnrollmentInvitation {
    let (private, public) = generate_ml_dsa_87_keypair().unwrap();
    let now = crate::operator::now_unix();
    EnrollmentInvitation {
        format_version: ENROLLMENT_FORMAT_VERSION,
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: Id16::new([seed; 16]).unwrap(),
        gateway_wg_public_key: gateway_key(),
        gateway_certificate_fingerprint: Fingerprint::of(b"gateway fixture leaf"),
        server_name: "gateway.example".into(),
        operator_ca_public_key: public,
        wireguard_proof_public_key: WireGuardKey::from_bytes([0x41; 32]),
        not_before_unix: now - 60,
        not_after_unix: now + 3600,
        minimum_mode: ProtectionMode::MlKem,
        allow_readmission: false,
        operator_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&private)
    .expect("sign a fixture invitation")
}

fn write_consumed(registry: &InvitationRegistry, seed: u8) -> (Id16, WireGuardKey) {
    let invitation = invitation(seed);
    let id = invitation.invitation_id;
    let peer = WireGuardKey::from_bytes([seed; 32]);
    let state = InvitationState::Consumed {
        request_id: Id16::new([0x42; 16]).unwrap(),
        request_fingerprint: Fingerprint::of(b"fixture request"),
        client_wg_public_key: peer,
        consumed_at_unix: invitation.not_before_unix + 30,
        issued: None,
    };
    std::fs::create_dir_all(registry.directory()).unwrap();
    let record = serde_json::json!({ "invitation": invitation, "state": state });
    std::fs::write(
        registry.directory().join(format!("{}.json", id.to_hex())),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    (id, peer)
}

async fn connected_engine(
    url: &str,
    state: &'static str,
) -> (EngineClient, tokio::task::JoinHandle<()>) {
    let (client, mut engine) = scripted_engine().await;
    let profile = gateway_test_profile(url, gateway_key().to_base64());
    let server = tokio::spawn(async move {
        engine
            .reply(|command| {
                assert!(matches!(command, EngineCommand::GetState));
                Ok(EngineReply::State(state.into()))
            })
            .await;
        engine
            .reply(|command| {
                assert!(matches!(command, EngineCommand::GetConfig));
                Ok(EngineReply::Config(ConfigView {
                    profiles: vec![profile.clone()],
                    selected: Some(profile.name.clone()),
                    locked: Vec::new(),
                    vault_error: None,
                }))
            })
            .await;
    });
    (client, server)
}

#[tokio::test]
async fn invitation_listing_matches_admission_for_each_consumed_device() {
    let domain = domain();
    let registry = InvitationRegistry::at(domain.path.with_file_name("invitations"));
    let (admitted, admitted_key) = write_consumed(&registry, 0x17);
    let (withdrawn, _) = write_consumed(&registry, 0x18);
    let gateway = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", gateway.local_addr().unwrap());
    let (engine, engine_task) = connected_engine(&url, "up").await;
    let server = tokio::spawn(async move {
        let response = serde_json::json!({
            "wg_public_key": gateway_key().to_base64(),
            "wg_address": "100.64.0.1/10",
            "peers": [{
                "name": "admitted",
                "public_key": admitted_key.to_base64(),
                "address": "100.64.0.2/32",
            }],
        })
        .to_string();
        let request = tokio::time::timeout(
            Duration::from_secs(5),
            answer_gateway(&gateway, "GET /api/network ", "200 OK", &response),
        )
        .await
        .expect("gateway admission read");
        assert!(request.is_empty());
    });

    let list = operator_invitations_from(&engine, &registry).await.unwrap();
    let states: std::collections::BTreeMap<_, _> = list
        .into_iter()
        .map(|invitation| (invitation.invitation_id, invitation.peer_admitted))
        .collect();
    assert_eq!(
        states,
        [
            (admitted.to_hex(), Some(true)),
            (withdrawn.to_hex(), Some(false))
        ]
        .into()
    );
    engine_task.await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn invitation_listing_keeps_the_consumed_state_when_gateway_admission_is_unknown() {
    let domain = domain();
    let registry = InvitationRegistry::at(domain.path.with_file_name("invitations"));
    let (id, _) = write_consumed(&registry, 0x23);
    let gateway = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", gateway.local_addr().unwrap());
    let (engine, engine_task) = connected_engine(&url, "down").await;
    let list = operator_invitations_from(&engine, &registry).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].invitation_id, id.to_hex());
    assert_eq!(list[0].state, "consommée");
    assert_eq!(list[0].peer_admitted, None);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), gateway.accept())
            .await
            .is_err()
    );
    engine_task.await.unwrap();
}

#[test]
fn revocation_trims_the_id_and_erases_the_stored_proof_key() {
    let domain = domain();
    let path = domain.path.with_file_name("invitations");
    let registry = InvitationRegistry::at(path.clone());
    let invitation = invitation(0x34);
    registry
        .issue(&invitation, zeroize::Zeroizing::new([0x39; 32]))
        .unwrap();
    let id = invitation.invitation_id;
    let arg = format!("  {}\n", id.to_hex());

    revoke_invitation_with_registry(&arg, || Ok(InvitationRegistry::at(path.clone()))).unwrap();
    assert!(matches!(
        registry.load(&id).unwrap().state,
        InvitationState::Revoked { .. }
    ));
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join(format!("{}.json", id.to_hex()))).unwrap())
            .unwrap();
    assert!(record.get("proof_private_key").is_none());
    let error = revoke_invitation_with_registry(&arg, || Ok(registry)).unwrap_err();
    assert!(error.contains("révoquée"));
}

#[tokio::test]
async fn revocation_refuses_an_invalid_id_before_resolving_the_registry() {
    let error = revoke_invitation("invalid-invitation-id".into())
        .await
        .unwrap_err();
    assert_eq!(
        error,
        Id16::parse_hex("invalid-invitation-id")
            .unwrap_err()
            .to_string()
    );
    assert!(
        revoke_invitation_with_registry("invalid", || panic!("registry must stay unopened"))
            .is_err()
    );
}
