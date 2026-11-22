use super::{tests::Scratch, *};
use crate::commands::test_support::scripted_engine;
use orion_engine::ProfileView;
use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::Mutex;

#[cfg(not(windows))]
fn command_app(client: orion_engine::client::EngineClient) -> tauri::App<tauri::test::MockRuntime> {
    use crate::{operator::location::VaultLocation, AppState};
    use std::sync::Arc;
    use tauri::Manager;

    let app = tauri::test::mock_app();
    assert!(app.manage(AppState {
        client,
        pending_profile_paths: Mutex::new(VecDeque::new()),
        operator: Default::default(),
        vault_location: VaultLocation::at(std::env::temp_dir().join(format!(
            "orion-profile-command-settings-{}",
            std::process::id()
        ))),
        chain_opened: Arc::default(),
        quitting: Default::default(),
        tunnel_taken_down: Default::default(),
        engine_lost: Default::default(),
    }));
    app
}

fn profile_draft() -> ProfileDraft {
    ProfileDraft {
        name: "gateway".into(),
        endpoint: "vpn.example:51820".into(),
        peer_public_key: String::new(),
        address: Some("100.64.0.2/32".into()),
        address_v6: Some("fd00::2/128".into()),
        allowed_ips: "0.0.0.0/0, ::/0".into(),
        persistent_keepalive: 25,
        heliosd_url: None,
        ssh_target: None,
        dns: None,
        key_negotiation: None,
        use_staged_key: true,
        clear_preshared_key: false,
        use_staged_psk: true,
        nomad: false,
    }
}

fn imported_reply(name: &str) -> EngineReply {
    let profile = orion_core::ClientProfile {
        name: name.into(),
        ..Default::default()
    };
    EngineReply::Imported(ImportOutcome {
        profile: ProfileView::from(&profile),
        identity_sealed: false,
        private_key_missing: Some("local key required".into()),
        incomplete: None,
        notices: vec!["DNS ignored".into()],
    })
}

fn assert_import_command(command: EngineCommand, expected_name: &str, expected_contents: &str) {
    let EngineCommand::ImportProfile {
        contents,
        file_name,
    } = command
    else {
        panic!("expected a profile import");
    };
    assert_eq!(file_name, expected_name);
    assert_eq!(contents.expose(), expected_contents);
    assert!(!format!("{contents:?}").contains(expected_contents));
}

#[tokio::test]
async fn file_association_decodes_document_in_the_shell_and_forwards_only_text_and_basename() {
    let scratch = Scratch::new();
    let path = scratch.0.join("gateway.ORION");
    let document = "profil associé";
    let mut encoded = vec![0xff, 0xfe];
    encoded.extend(document.encode_utf16().flat_map(u16::to_le_bytes));
    std::fs::write(&path, encoded).expect("write UTF-16LE profile");

    let bad = scratch.0.join("unsupported.conf");
    let pending = Mutex::new(VecDeque::from([path]));
    let (client, mut engine) = scripted_engine().await;
    let (outcome, ()) = tokio::join!(
        async {
            let err = import_associated_profile(&client, &pending, Some(bad.display().to_string()))
                .await
                .expect_err("do not forward a non-associated file");
            assert!(err.contains("fichiers .orion"));

            let imported = import_associated_profile(&client, &pending, None)
                .await
                .expect("import via association")
                .expect("queued document consumed");
            assert!(import_associated_profile(&client, &pending, None)
                .await
                .expect("empty queue does not ask engine")
                .is_none());
            imported
        },
        async move {
            engine
                .reply(|command| {
                    assert_import_command(command, "gateway.ORION", document);
                    Ok(imported_reply("gateway"))
                })
                .await;
        }
    );

    assert_eq!(outcome.profile.name, "gateway");
    assert!(!outcome.identity_sealed);
    assert_eq!(
        outcome.private_key_missing.as_deref(),
        Some("local key required")
    );
    assert_eq!(outcome.notices, ["DNS ignored"]);
}

#[tokio::test]
async fn picker_import_preserves_filename_and_reports_engine_refusal() {
    let (client, mut engine) = scripted_engine().await;
    let (error, ()) = tokio::join!(
        import_profile_document(&client, "picker document".into(), "wg-home.conf".into()),
        async move {
            engine
                .reply(|command| {
                    assert_import_command(command, "wg-home.conf", "picker document");
                    Err("profile requires encrypted volume".into())
                })
                .await;
        }
    );
    assert_eq!(
        error.expect_err("preserve the engine's refusal"),
        "profile requires encrypted volume"
    );
}

#[tokio::test]
async fn picker_import_rejects_reply_from_another_command() {
    let (client, mut engine) = scripted_engine().await;
    let (error, ()) = tokio::join!(
        import_profile_document(&client, "picker document".into(), "gateway.orion".into()),
        async move {
            engine
                .reply(|command| {
                    assert_import_command(command, "gateway.orion", "picker document");
                    Ok(EngineReply::Unit)
                })
                .await;
        }
    );
    assert_eq!(
        error.expect_err("reject invalid import reply"),
        unexpected_engine_reply()
    );
}

#[tokio::test]
async fn ssh_launcher_receives_only_the_validated_destination_for_the_named_profile() {
    let (client, mut engine) = scripted_engine().await;
    let launched = Cell::new(false);
    let (result, ()) = tokio::join!(
        open_ssh_with(&client, Some("secondary".into()), |destination| {
            assert_eq!(destination, "operator@gateway.example:2222");
            launched.set(true);
            Err("terminal unavailable".into())
        }),
        async move {
            engine
                .reply(|command| {
                    let EngineCommand::SshCommand { name } = command else {
                        panic!("expected a request for SSH");
                    };
                    assert_eq!(name.as_deref(), Some("secondary"));
                    Ok(EngineReply::SshCommand(
                        "ssh operator@gateway.example:2222".into(),
                    ))
                })
                .await;
        }
    );

    assert_eq!(result, Err("terminal unavailable".into()));
    assert!(launched.get());
}

#[tokio::test]
async fn failed_or_invalid_ssh_lookup_never_launches_a_terminal() {
    let invalid = "ssh gateway.example extra".to_string();
    let expected = validated_ssh_target(&invalid).expect_err("invalid target");
    for (reply, expected) in [
        (Ok(EngineReply::SshCommand(invalid)), expected),
        (Ok(EngineReply::Unit), unexpected_engine_reply()),
        (
            Err("profile has no SSH destination".into()),
            "profile has no SSH destination".into(),
        ),
    ] {
        let (client, mut engine) = scripted_engine().await;
        let (result, ()) = tokio::join!(
            open_ssh_with(&client, None, |_| panic!("must not open a terminal")),
            async move {
                engine
                    .reply(|command| {
                        assert!(matches!(command, EngineCommand::SshCommand { name: None }));
                        reply
                    })
                    .await;
            }
        );
        assert_eq!(result, Err(expected));
    }
}

#[tokio::test]
async fn validation_sends_the_draft_and_preserves_its_field_diagnostics() {
    let mut draft = profile_draft();
    draft.address_v6 = Some("100.64.0.3/32".into());
    draft.persistent_keepalive = 0;
    let issues = ProfileIssues {
        address_v6: Some("IPv6 required".into()),
        persistent_keepalive: Some("keepalive must be positive".into()),
        ..Default::default()
    };
    let reply = EngineReply::Issues(issues.clone());
    let (client, mut engine) = scripted_engine().await;
    let (result, ()) = tokio::join!(profile_issues(&client, draft), async move {
        engine
            .reply(|command| {
                let EngineCommand::ValidateProfile { draft } = command else {
                    panic!("expected validation without saving");
                };
                assert_eq!(draft.name, "gateway");
                assert_eq!(draft.address_v6.as_deref(), Some("100.64.0.3/32"));
                assert_eq!(draft.persistent_keepalive, 0);
                assert!(draft.use_staged_key);
                assert!(draft.use_staged_psk);
                Ok(reply)
            })
            .await;
    });

    assert_eq!(result, Ok(issues));
}

#[tokio::test]
async fn saving_with_staged_secrets_refreshes_the_tray_after_the_engine_returns_a_view() {
    let (client, mut engine) = scripted_engine().await;
    let engine_answered = Cell::new(false);
    let refreshed = Cell::new(false);
    let (result, ()) = tokio::join!(
        change_profile(
            &client,
            EngineCommand::SaveProfile {
                draft: profile_draft()
            },
            || {
                assert!(engine_answered.get());
                refreshed.set(true);
            }
        ),
        async {
            engine
                .reply(|command| {
                    let EngineCommand::SaveProfile { draft } = command else {
                        panic!("expected saving the edited profile");
                    };
                    assert_eq!(draft.name, "gateway");
                    assert!(draft.use_staged_key);
                    assert!(draft.use_staged_psk);
                    assert!(!draft.clear_preshared_key);
                    engine_answered.set(true);
                    Ok(EngineReply::Config(ConfigView {
                        profiles: vec![],
                        selected: Some("gateway".into()),
                        vault_error: None,
                        locked: Vec::new(),
                    }))
                })
                .await;
            drop(engine);
        }
    );

    assert!(refreshed.get());
    assert_eq!(
        result.expect("configuration view").selected.as_deref(),
        Some("gateway")
    );
}

#[tokio::test]
async fn profile_change_refused_by_the_engine_leaves_the_tray_untouched() {
    for (reply, expected) in [
        (Ok(EngineReply::Unit), unexpected_engine_reply()),
        (
            Err("profile no longer exists".into()),
            "profile no longer exists".into(),
        ),
    ] {
        let (client, mut engine) = scripted_engine().await;
        let (result, ()) = tokio::join!(
            change_profile(
                &client,
                EngineCommand::DeleteProfile {
                    name: "gateway".into()
                },
                || panic!("refresh only follows a successful mutation")
            ),
            async move {
                engine
                    .reply(|command| {
                        let EngineCommand::DeleteProfile { name } = command else {
                            panic!("expected deletion");
                        };
                        assert_eq!(name, "gateway");
                        reply
                    })
                    .await;
            }
        );
        assert_eq!(result.expect_err("refuse profile change"), expected);
    }
}

fn config_reply() -> EngineReply {
    EngineReply::Config(ConfigView {
        profiles: vec![],
        selected: Some("gateway".into()),
        vault_error: None,
        locked: Vec::new(),
    })
}

fn assert_nomad_command(command: EngineCommand, expected: &str) {
    let actual = match command {
        EngineCommand::MakeNomad { name } => ("make_nomad", name),
        EngineCommand::ChangePassphrase { name } => ("change_passphrase", name),
        EngineCommand::MakeService { name } => ("make_service", name),
        _ => panic!("expected a nomad profile gesture"),
    };
    assert_eq!(actual, (expected, "gateway".into()));
}

#[tokio::test]
async fn nomad_profile_gestures_forward_names_and_refresh_after_success() {
    for (command, expected) in [
        (
            EngineCommand::MakeNomad {
                name: "gateway".into(),
            },
            "make_nomad",
        ),
        (
            EngineCommand::ChangePassphrase {
                name: "gateway".into(),
            },
            "change_passphrase",
        ),
        (
            EngineCommand::MakeService {
                name: "gateway".into(),
            },
            "make_service",
        ),
    ] {
        let (client, mut engine) = scripted_engine().await;
        let refreshed = Cell::new(false);
        let (result, ()) = tokio::join!(
            change_nomad_profile(&client, command, || refreshed.set(true)),
            async move {
                engine
                    .reply(|command| {
                        assert_nomad_command(command, expected);
                        Ok(config_reply())
                    })
                    .await;
            }
        );

        assert_eq!(
            result.expect("configuration view").selected.as_deref(),
            Some("gateway")
        );
        assert!(refreshed.get());
    }
}

#[tokio::test]
async fn refused_or_mismatched_nomad_gesture_does_not_refresh_tray() {
    for reply in [
        Ok::<_, String>(EngineReply::Unit),
        Err("passphrase dialog cancelled".into()),
    ] {
        let expected = match &reply {
            Ok(_) => unexpected_engine_reply(),
            Err(error) => error.clone(),
        };
        let (client, mut engine) = scripted_engine().await;
        let refreshed = Cell::new(false);
        let (result, ()) = tokio::join!(
            change_nomad_profile(
                &client,
                EngineCommand::MakeService {
                    name: "gateway".into()
                },
                || refreshed.set(true),
            ),
            async move {
                engine
                    .reply(|command| {
                        assert_nomad_command(command, "make_service");
                        reply
                    })
                    .await;
            }
        );

        assert_eq!(result.err().as_deref(), Some(expected.as_str()));
        assert!(!refreshed.get());
    }
}

fn posture(protected: bool, waived: bool) -> EngineReply {
    EngineReply::VaultPosture(VaultPosture {
        hardware_backed: true,
        software_keystore: false,
        volume: if protected {
            "BitLocker"
        } else {
            "non chiffré"
        }
        .into(),
        volume_protected: protected,
        unencrypted_volume_waived: waived,
        memory_locked: true,
        lock_watch_active: false,
        nomad_available: false,
        memory: "pages verrouillées".into(),
        dumps_excluded: true,
        dumps: "exclus".into(),
        rotation_required: vec![],
        legacy_present: false,
    })
}

#[tokio::test]
async fn vault_posture_tracks_the_volume_and_explicit_consent_separately() {
    let (client, mut engine) = scripted_engine().await;
    tokio::join!(
        async {
            let initial = vault_posture_reply(&client, EngineCommand::VaultPosture)
                .await
                .expect("get initial posture");
            assert!(initial.volume_protected);
            assert!(!initial.unencrypted_volume_waived);

            let suspended = vault_posture_reply(&client, EngineCommand::VaultPosture)
                .await
                .expect("reread suspended volume");
            assert!(!suspended.volume_protected);
            assert!(!suspended.unencrypted_volume_waived);

            let accepted = vault_posture_reply(&client, EngineCommand::AllowUnencryptedVolume)
                .await
                .expect("acknowledge the explicit waiver");
            assert!(!accepted.volume_protected);
            assert!(accepted.unencrypted_volume_waived);
        },
        async move {
            for protected in [true, false] {
                engine
                    .reply(|command| {
                        assert!(matches!(command, EngineCommand::VaultPosture));
                        Ok(posture(protected, false))
                    })
                    .await;
            }
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::AllowUnencryptedVolume));
                    Ok(posture(false, true))
                })
                .await;
        }
    );
}

#[tokio::test]
async fn vault_posture_and_waiver_surface_failures() {
    let (client, mut engine) = scripted_engine().await;
    tokio::join!(
        async {
            assert_eq!(
                vault_posture_reply(&client, EngineCommand::VaultPosture)
                    .await
                    .expect_err("only a posture reply can attest the volume"),
                unexpected_engine_reply()
            );
            assert_eq!(
                vault_posture_reply(&client, EngineCommand::AllowUnencryptedVolume)
                    .await
                    .expect_err("show failure to save the waiver"),
                "unable to save volume settings"
            );
        },
        async move {
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::VaultPosture));
                    Ok(EngineReply::Unit)
                })
                .await;
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::AllowUnencryptedVolume));
                    Err("unable to save volume settings".into())
                })
                .await;
        }
    );
}

#[tokio::test]
async fn staged_private_key_commands_return_public_keys_and_discard_by_acknowledgement() {
    let (client, mut engine) = scripted_engine().await;
    let private = "fixture private key";
    tokio::join!(
        async {
            let generated = public_key_reply(&client, EngineCommand::GeneratePrivateKey)
                .await
                .expect("generate a new staged key");
            assert_eq!(generated, "generated public key");

            let adopted = public_key_reply(
                &client,
                EngineCommand::AdoptPrivateKey {
                    private_key: SecretInput::from(private.to_string()),
                },
            )
            .await
            .expect("stage a supplied key");
            assert_eq!(adopted, "adopted public key");

            staging_reply(&client, EngineCommand::DiscardStagedKey)
                .await
                .expect("discard the staged private key");
        },
        async move {
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::GeneratePrivateKey));
                    Ok(EngineReply::PublicKey("generated public key".into()))
                })
                .await;
            engine
                .reply(|command| {
                    let EngineCommand::AdoptPrivateKey { private_key } = command else {
                        panic!("expected the private-key staging command");
                    };
                    assert_eq!(private_key.expose(), private);
                    assert!(!format!("{private_key:?}").contains(private));
                    Ok(EngineReply::PublicKey("adopted public key".into()))
                })
                .await;
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::DiscardStagedKey));
                    Ok(EngineReply::Unit)
                })
                .await;
        }
    );
}

#[tokio::test]
async fn staged_psk_commands_acknowledge_secret_entry_and_discard_without_returning_a_key() {
    let (client, mut engine) = scripted_engine().await;
    let psk = "fixture preshared key";
    tokio::join!(
        async {
            staging_reply(
                &client,
                EngineCommand::AdoptPresharedKey {
                    preshared_key: SecretInput::from(psk.to_string()),
                },
            )
            .await
            .expect("stage the static PSK");
            staging_reply(&client, EngineCommand::DiscardStagedPsk)
                .await
                .expect("discard the staged PSK");
        },
        async move {
            engine
                .reply(|command| {
                    let EngineCommand::AdoptPresharedKey { preshared_key } = command else {
                        panic!("expected the PSK staging command");
                    };
                    assert_eq!(preshared_key.expose(), psk);
                    assert!(!format!("{preshared_key:?}").contains(psk));
                    Ok(EngineReply::Unit)
                })
                .await;
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::DiscardStagedPsk));
                    Ok(EngineReply::Unit)
                })
                .await;
        }
    );
}

#[tokio::test]
async fn staging_refuses_mismatched_replies_and_preserves_validation_errors() {
    let (client, mut engine) = scripted_engine().await;
    tokio::join!(
        async {
            assert_eq!(
                public_key_reply(&client, EngineCommand::GeneratePrivateKey).await,
                Err(unexpected_engine_reply())
            );
            assert_eq!(
                staging_reply(&client, EngineCommand::DiscardStagedPsk).await,
                Err(unexpected_engine_reply())
            );
            assert_eq!(
                staging_reply(
                    &client,
                    EngineCommand::AdoptPresharedKey {
                        preshared_key: SecretInput::from("invalid fixture PSK".to_string()),
                    },
                )
                .await,
                Err("invalid WireGuard PSK".into())
            );
        },
        async move {
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::GeneratePrivateKey));
                    Ok(EngineReply::Unit)
                })
                .await;
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::DiscardStagedPsk));
                    Ok(EngineReply::PublicKey("unrelated public key".into()))
                })
                .await;
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::AdoptPresharedKey { .. }));
                    Err("invalid WireGuard PSK".into())
                })
                .await;
        }
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn get_config_command_forwards_the_engine_view_and_rejects_other_replies() {
    let (client, mut engine) = scripted_engine().await;
    let app = command_app(client);
    let state = app.state::<crate::AppState>();
    let expected = ConfigView {
        profiles: vec![],
        selected: Some("picked".into()),
        locked: vec![orion_engine::LockedProfileView {
            name: "sealed".into(),
            client_public_key: "client public".into(),
            peer_public_key: "gateway public".into(),
        }],
        vault_error: None,
    };
    let (result, ()) = tokio::join!(get_config(state), async move {
        engine
            .reply(|command| {
                assert!(matches!(command, EngineCommand::GetConfig));
                Ok(EngineReply::Config(expected.clone()))
            })
            .await;
    });
    let view = result.expect("configuration view");
    assert_eq!(view.selected.as_deref(), Some("picked"));
    assert_eq!(view.locked[0].name, "sealed");
    drop(app);

    let (client, mut engine) = scripted_engine().await;
    let app = command_app(client);
    let (result, ()) = tokio::join!(get_config(app.state()), async move {
        engine
            .reply(|command| {
                assert!(matches!(command, EngineCommand::GetConfig));
                Ok(EngineReply::Unit)
            })
            .await;
    });
    assert_eq!(
        result.expect_err("reject a mismatched reply"),
        unexpected_engine_reply()
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn import_profile_command_preserves_document_name_and_engine_outcome() {
    let (client, mut engine) = scripted_engine().await;
    let app = command_app(client);
    let outcome = imported_reply("from-file");
    let EngineReply::Imported(expected) = outcome.clone() else {
        unreachable!()
    };
    let (result, ()) = tokio::join!(
        import_profile(app.state(), "opaque document".into(), "chosen.conf".into()),
        async move {
            engine
                .reply(|command| {
                    assert_import_command(command, "chosen.conf", "opaque document");
                    Ok(outcome)
                })
                .await;
        }
    );
    let imported = result.expect("import outcome");
    assert_eq!(imported.profile.name, expected.profile.name);
    assert_eq!(imported.notices, expected.notices);
}

#[cfg(not(windows))]
#[tokio::test]
async fn import_profile_path_command_consumes_queued_path_and_forwards_only_file_data() {
    let scratch = Scratch::new();
    let path = scratch.0.join("queued.orion");
    std::fs::write(&path, "queued contents").expect("write associated profile");
    let (client, mut engine) = scripted_engine().await;
    let app = command_app(client);
    app.state::<crate::AppState>()
        .pending_profile_paths
        .lock()
        .expect("pending paths")
        .push_back(path);
    let outcome = imported_reply("queued");
    let (result, ()) = tokio::join!(import_profile_path(app.state(), None), async move {
        engine
            .reply(|command| {
                assert_import_command(command, "queued.orion", "queued contents");
                Ok(outcome)
            })
            .await;
    });
    assert_eq!(
        result
            .expect("queued import")
            .expect("path was queued")
            .profile
            .name,
        "queued"
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn import_profile_path_command_returns_none_without_contacting_the_engine() {
    let (client, _engine) = scripted_engine().await;
    let app = command_app(client);
    assert!(import_profile_path(app.state(), None)
        .await
        .expect("empty queue is not an error")
        .is_none());
}

#[cfg(not(windows))]
#[tokio::test]
async fn vault_posture_commands_keep_read_and_explicit_waiver_distinct() {
    let (client, mut engine) = scripted_engine().await;
    let app = command_app(client);
    tokio::join!(
        async {
            let current = vault_posture(app.state()).await.expect("current posture");
            assert!(current.volume_protected);
            assert!(!current.unencrypted_volume_waived);
            let waived = allow_unencrypted_volume(app.state())
                .await
                .expect("explicit volume waiver");
            assert!(!waived.volume_protected);
            assert!(waived.unencrypted_volume_waived);
        },
        async move {
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::VaultPosture));
                    Ok(posture(true, false))
                })
                .await;
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::AllowUnencryptedVolume));
                    Ok(posture(false, true))
                })
                .await;
        }
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn key_commands_route_user_input_and_only_return_public_material() {
    let (client, mut engine) = scripted_engine().await;
    let app = command_app(client);
    let private = "private fixture";
    let psk = "PSK fixture";
    tokio::join!(
        async {
            assert_eq!(
                generate_private_key(app.state()).await,
                Ok("generated public".into())
            );
            assert_eq!(
                adopt_private_key(app.state(), private.into()).await,
                Ok("adopted public".into())
            );
            adopt_preshared_key(app.state(), psk.into())
                .await
                .expect("adopt PSK");
            discard_staged_key(app.state()).await.expect("discard key");
            discard_staged_psk(app.state()).await.expect("discard PSK");
        },
        async move {
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::GeneratePrivateKey));
                    Ok(EngineReply::PublicKey("generated public".into()))
                })
                .await;
            engine
                .reply(|command| {
                    let EngineCommand::AdoptPrivateKey { private_key } = command else {
                        panic!("adopt key")
                    };
                    assert_eq!(private_key.expose(), private);
                    Ok(EngineReply::PublicKey("adopted public".into()))
                })
                .await;
            engine
                .reply(|command| {
                    let EngineCommand::AdoptPresharedKey { preshared_key } = command else {
                        panic!("adopt PSK")
                    };
                    assert_eq!(preshared_key.expose(), psk);
                    Ok(EngineReply::Unit)
                })
                .await;
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::DiscardStagedKey));
                    Ok(EngineReply::Unit)
                })
                .await;
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::DiscardStagedPsk));
                    Ok(EngineReply::Unit)
                })
                .await;
        }
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn ssh_command_wrapper_preserves_optional_profile_selection_and_engine_error() {
    let (client, mut engine) = scripted_engine().await;
    let app = command_app(client);
    tokio::join!(
        async {
            let command = ssh_command(app.state(), Some("secondary".into())).await;
            assert_eq!(command.as_deref(), Ok("ssh operator@gateway.example"));
            assert_eq!(
                ssh_command(app.state(), None).await,
                Err("profile has no SSH destination".into())
            );
        },
        async move {
            engine
                .reply(|command| {
                    let EngineCommand::SshCommand { name: Some(name) } = command else {
                        panic!("expected SSH lookup for a named profile");
                    };
                    assert_eq!(name, "secondary");
                    Ok(EngineReply::SshCommand(
                        "ssh operator@gateway.example".into(),
                    ))
                })
                .await;
            engine
                .reply(|command| {
                    assert!(matches!(command, EngineCommand::SshCommand { name: None }));
                    Err("profile has no SSH destination".into())
                })
                .await;
        }
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn validate_profile_command_forwards_the_draft_and_field_issues() {
    let (client, mut engine) = scripted_engine().await;
    let app = command_app(client);
    let mut draft = profile_draft();
    draft.name = "edited-name".into();
    let expected = ProfileIssues {
        name: Some("already exists".into()),
        ..Default::default()
    };
    let reply = expected.clone();
    let (result, ()) = tokio::join!(validate_profile(app.state(), draft), async move {
        engine
            .reply(|command| {
                let EngineCommand::ValidateProfile { draft } = command else {
                    panic!("validate profile")
                };
                assert_eq!(draft.name, "edited-name");
                Ok(EngineReply::Issues(reply))
            })
            .await;
    });
    assert_eq!(result, Ok(expected));
}
