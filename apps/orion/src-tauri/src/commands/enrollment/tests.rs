use super::*;
use crate::commands::test_support::scripted_engine;
use aether::certificates::encoding::Id16;

const INVITATION: &str = "fixture invitation\n";
const TOKEN: &str = "normalized invitation token";
const FINGERPRINT: &str = "7ab5 dfc1";
const REQUEST: &str = "public enrollment request\n";
const PROFILE: &str = "  workstation  ";
const REQUEST_ID: &str = " abababababababababababababababab ";

#[tokio::test]
async fn preview_forwards_the_invitation_text_and_returns_the_confirmation_fields() {
    let (client, mut engine) = scripted_engine().await;
    let (preview, ()) = tokio::join!(
        preview_enrollment_invitation_from(&client, INVITATION.into()),
        engine.reply(|command| {
            assert!(matches!(
                command,
                EngineCommand::PreviewEnrollmentInvitation { contents } if contents == INVITATION
            ));
            Ok(EngineReply::InvitationPreview(InvitationPreviewView {
                server_name: "vpn.example.net".into(),
                ca_fingerprint: FINGERPRINT.into(),
                expires_at_unix: 1_800_000_000,
                invitation_token: TOKEN.into(),
            }))
        }),
    );
    let preview = preview.expect("preview");
    assert_eq!(preview.server_name, "vpn.example.net");
    assert_eq!(preview.ca_fingerprint, FINGERPRINT);
    assert_eq!(preview.expires_at_unix, 1_800_000_000);
    assert_eq!(preview.invitation_token, TOKEN);
}

#[tokio::test]
async fn begin_forwards_the_confirmation_and_returns_the_public_request() {
    let (client, mut engine) = scripted_engine().await;
    let (request, ()) = tokio::join!(
        begin_enrollment_from(&client, TOKEN.into(), FINGERPRINT.into(), PROFILE.into()),
        engine.reply(|command| {
            assert!(matches!(
                command,
                EngineCommand::BeginEnrollment {
                    invitation,
                    confirmed_ca_fingerprint,
                    requested_name,
                } if invitation == TOKEN
                    && confirmed_ca_fingerprint == FINGERPRINT
                    && requested_name == PROFILE
            ));
            Ok(EngineReply::EnrollmentStarted(REQUEST.into()))
        }),
    );
    assert_eq!(request.as_deref(), Ok(REQUEST));
}

fn pending(request_byte: u8, label: &str, created_at_unix: u64) -> PendingEnrollment {
    PendingEnrollment {
        invitation_id: Id16::new([0x37; 16]).expect("nonzero invitation ID"),
        request_id: Id16::new([request_byte; 16]).expect("nonzero request ID"),
        requested_name: label.into(),
        server_name: "vpn.example.net".into(),
        created_at_unix,
        invitation_expires_at_unix: 1_800_000_000,
    }
}

#[tokio::test]
async fn pending_list_preserves_request_identity_and_display_order() {
    let (client, mut engine) = scripted_engine().await;
    let expected = vec![
        pending(0xcd, "second alphabetically", 1_799_999_800),
        pending(0xab, "first alphabetically", 1_799_999_900),
    ];
    let (listed, ()) = tokio::join!(
        list_pending_enrollments_from(&client),
        engine.reply(|command| {
            assert!(matches!(command, EngineCommand::ListPendingEnrollments));
            Ok(EngineReply::PendingEnrollments(expected.clone()))
        }),
    );
    assert_eq!(listed, Ok(expected));
}

#[tokio::test]
async fn export_and_discard_forward_the_selected_request_id() {
    let (client, mut engine) = scripted_engine().await;
    let (exported, ()) = tokio::join!(
        export_pending_request_from(&client, REQUEST_ID.into()),
        engine.reply(|command| {
            assert!(matches!(
                command,
                EngineCommand::ExportPendingRequest { request_id } if request_id == REQUEST_ID
            ));
            Ok(EngineReply::RequestFile(REQUEST.into()))
        }),
    );
    assert_eq!(exported.as_deref(), Ok(REQUEST));

    let (discarded, ()) = tokio::join!(
        discard_pending_enrollment_from(&client, REQUEST_ID.into()),
        engine.reply(|command| {
            assert!(matches!(
                command,
                EngineCommand::DiscardPendingEnrollment { request_id } if request_id == REQUEST_ID
            ));
            Ok(EngineReply::Unit)
        }),
    );
    assert_eq!(discarded, Ok(()));
}

#[tokio::test]
async fn enrollment_commands_propagate_engine_refusals_and_reject_mismatched_replies() {
    let (client, mut engine) = scripted_engine().await;
    const REFUSAL: &str = "fixture: the engine refused this request";
    let unexpected = unexpected_engine_reply();

    macro_rules! assert_refusals {
        ($call:expr, $wrong:expr) => {{
            let (result, ()) = tokio::join!($call, engine.reply(|_| Err(REFUSAL.into())));
            assert_eq!(result.err().as_deref(), Some(REFUSAL));
            let (result, ()) = tokio::join!($call, engine.reply(|_| Ok($wrong)));
            assert_eq!(result.err().as_deref(), Some(unexpected.as_str()));
        }};
    }

    assert_refusals!(
        preview_enrollment_invitation_from(&client, INVITATION.into()),
        EngineReply::Unit
    );
    assert_refusals!(
        begin_enrollment_from(&client, TOKEN.into(), FINGERPRINT.into(), PROFILE.into()),
        EngineReply::RequestFile(REQUEST.into())
    );
    assert_refusals!(list_pending_enrollments_from(&client), EngineReply::Unit);
    assert_refusals!(
        export_pending_request_from(&client, REQUEST_ID.into()),
        EngineReply::EnrollmentStarted(REQUEST.into())
    );
    assert_refusals!(
        discard_pending_enrollment_from(&client, REQUEST_ID.into()),
        EngineReply::RequestFile(REQUEST.into())
    );
}
