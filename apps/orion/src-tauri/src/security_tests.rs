use super::{
    associated_profile_paths, sanitize_stem, window_size_for, Path, PathBuf,
    LEGACY_PROFILE_EXTENSION, PROFILE_EXTENSION,
};
use orion_core::ClientProfile;
use orion_engine::{ConfigView, ProfileDraft, ProfileView};

fn profile(name: &str) -> ClientProfile {
    let pair = aether::wg::generate_keypair().expect("keypair");
    let gateway = aether::wg::generate_keypair().expect("keypair");
    ClientProfile {
        name: name.into(),
        endpoint: "203.0.113.10:51820".into(),
        private_key: pair.private_key.duplicate(),
        peer_public_key: gateway.public_key,
        preshared_key: Some("cHNrLXN0YXRpcXVlLWhvcnMtYmFuZGU=".into()),
        address: Some("100.64.1.2/32".into()),
        ..ClientProfile::default()
    }
}

/// The payload the screen actually sends must deserialise.
///
/// This is the test whose absence let `missing field peerPublicKey` reach a
/// user. The TypeScript suite mocks `invoke`, so it never encodes anything;
/// the Rust suite builds `ProfileDraft` directly, so it never decodes
/// anything. The names only have to agree at the boundary, and nothing was
/// standing there.
///
/// The JSON below is written by hand, in the shape `api.ts` produces —
/// snake_case for everything the profile carries, camelCase for the two
/// intents. Deriving it from the struct would test serde against itself
/// and prove nothing.
#[test]
fn the_frontend_payload_deserialises() {
    let payload = serde_json::json!({
        "name": "poste-windows",
        "endpoint": "86.229.12.86:51820",
        "peer_public_key": "6Y8gpK+aOPbZvSnQnIbdQGTBoe5trFFWksGJVKlH3wk=",
        "address": "100.109.177.86/32",
        "address_v6": "fd3c:91a2:7e04::2/128",
        "allowed_ips": "0.0.0.0/0",
        "persistent_keepalive": 25,
        "heliosd_url": null,
        "key_negotiation": null,
        "useStagedKey": true,
        "clearPresharedKey": false,
    });

    let draft: ProfileDraft = serde_json::from_value(payload).expect(
        "le brouillon envoyé par l'écran doit se décoder : c'est ici que les noms \
             doivent concorder",
    );
    assert_eq!(draft.name, "poste-windows");
    assert_eq!(
        draft.peer_public_key,
        "6Y8gpK+aOPbZvSnQnIbdQGTBoe5trFFWksGJVKlH3wk="
    );
    assert_eq!(draft.address.as_deref(), Some("100.109.177.86/32"));
    assert_eq!(draft.address_v6.as_deref(), Some("fd3c:91a2:7e04::2/128"));
    assert_eq!(draft.persistent_keepalive, 25);
    assert!(draft.use_staged_key);
    assert!(!draft.clear_preshared_key);
}

/// The two optional intents may be absent entirely.
#[test]
fn a_payload_without_intents_defaults_to_touching_no_secret() {
    let payload = serde_json::json!({
        "name": "poste",
        "endpoint": "203.0.113.10:51820",
        "peer_public_key": "cHVibGlj",
        "address": null,
        "allowed_ips": "0.0.0.0/0",
        "persistent_keepalive": 25,
        "heliosd_url": null,
        "key_negotiation": null,
    });
    let draft: ProfileDraft = serde_json::from_value(payload).expect("decode");
    assert_eq!(draft.address_v6, None, "a payload without it means no IPv6");
    assert!(!draft.use_staged_key, "aucune clé adoptée sans demande");
    assert!(!draft.clear_preshared_key, "aucun PSK retiré sans demande");
}

/// **The** property of this lot: no secret crosses the Tauri IPC.
///
/// The check is on the serialised bytes rather than on a list of fields we
/// remembered to omit. A field added later that happens to carry a secret
/// fails here, not in a WebView memory dump.
#[test]
fn no_secret_is_ever_serialised_towards_the_interface() {
    let profile = profile("poste");
    let private_key = profile.private_key.duplicate();
    let psk = profile
        .preshared_key
        .as_ref()
        .map(aether::SecretString::duplicate)
        .expect("psk");

    let config = orion_core::ClientConfig {
        profiles: vec![profile],
        selected: Some("poste".into()),
    };
    let json = serde_json::to_string(&ConfigView::from(&config)).expect("serialise");

    assert!(
        !json.contains(private_key.expose()),
        "la clé privée traverse l'IPC :\n{json}"
    );
    assert!(
        !json.contains(psk.expose()),
        "le PSK statique traverse l'IPC"
    );
    // What the screen legitimately needs is still there.
    assert!(json.contains("publicKey") || json.contains("public_key"));
    assert!(json.contains("203.0.113.10:51820"));
}

/// The view states the *presence* of a secret, never its value.
#[test]
fn the_view_reports_presence_and_the_public_half() {
    let profile = profile("poste");
    let expected = profile.public_key().expect("public key");
    let view = ProfileView::from(&profile);

    assert!(view.has_private_key);
    assert!(view.has_static_psk);
    assert_eq!(view.public_key.as_deref(), Some(expected.as_str()));

    let bare = ClientProfile {
        name: "vide".into(),
        ..ClientProfile::default()
    };
    let view = ProfileView::from(&bare);
    assert!(!view.has_private_key);
    assert!(!view.has_static_psk);
    assert_eq!(view.public_key, None);
}

/// Each view has its size, and an unexpected label must not produce a
/// degenerate window: it falls back to the startup view.
#[test]
fn each_view_has_its_size_and_unknown_falls_back_to_connect() {
    let connect = window_size_for("connect");
    assert_eq!(window_size_for("unknown"), connect);
    assert_ne!(window_size_for("profiles"), connect);
    assert_ne!(window_size_for("logs"), connect);
    // The profile form is the most demanding view of the three.
    for view in ["connect", "logs"] {
        assert!(window_size_for("profiles").0 >= window_size_for(view).0);
    }
    // No size drops below the minimum declared in tauri.conf.json.
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    let window = &config["app"]["windows"][0];
    let (min_w, min_h) = (
        window["minWidth"].as_f64().expect("minWidth"),
        window["minHeight"].as_f64().expect("minHeight"),
    );
    for view in ["connect", "profiles", "certificates", "speedtest", "logs"] {
        let (w, h) = window_size_for(view);
        assert!(w >= min_w, "{view} : {w} < {min_w}");
        assert!(h >= min_h, "{view} : {h} < {min_h}");
    }
}

/// The frontend names the export, it doesn't place it. Anything that
/// could designate another directory must disappear from the label.
#[test]
fn the_export_name_cannot_designate_another_path() {
    assert_eq!(
        sanitize_stem("orion-journal-2026-07-23"),
        "orion-journal-2026-07-23"
    );
    assert_eq!(sanitize_stem("../../etc/passwd"), "etcpasswd");
    assert_eq!(
        sanitize_stem("C:\\Windows\\System32\\x"),
        "CWindowsSystem32x"
    );
    assert_eq!(sanitize_stem("journal.log.exe"), "journallogexe");
    // An empty or entirely filtered label falls back to a default name
    // rather than producing a hidden ".log" file.
    assert_eq!(sanitize_stem(""), "orion-journal");
    assert_eq!(sanitize_stem("../.."), "orion-journal");
    assert_eq!(sanitize_stem(&"a".repeat(200)).len(), 64);
}

#[test]
fn cargo_run_server_aligns_with_the_tauri_dev_url() {
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    let expected = format!("http://localhost:{}", super::FRONTEND_DEV_PORT);

    assert_eq!(config["build"]["devUrl"].as_str(), Some(expected.as_str()));
}

#[test]
fn tauri_configuration_enforces_a_csp_and_freezes_prototypes() {
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    let security = &config["app"]["security"];
    let csp = security["csp"].as_str().expect("Tauri CSP required");

    assert_eq!(security["freezePrototype"], true);
    assert!(csp.contains("default-src 'self'"));
    assert!(csp.contains("script-src 'self'"));
    assert!(!csp.contains("unsafe-eval"));
    assert!(!csp.contains("script-src *"));
    assert!(!csp.contains("connect-src *"));
}

#[test]
fn bundle_declares_association_and_linux_capability() {
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    let association = &config["bundle"]["fileAssociations"][0];
    assert_eq!(
        association["ext"],
        serde_json::json!([PROFILE_EXTENSION]),
        "the registered extension is the one the tooling writes"
    );
    assert_eq!(
        config["bundle"]["linux"]["deb"]["postInstallScript"],
        "linux/postinst"
    );
    assert!(config["bundle"]["linux"]["deb"]["depends"]
        .as_array()
        .unwrap()
        .iter()
        .any(|dependency| dependency == "libcap2-bin"));
    let postinst = include_str!("../linux/postinst");
    assert!(postinst.contains("setcap cap_net_admin=ep"));
}

#[test]
fn windows_bundle_ships_wireguard_and_requires_timestamped_signtool() {
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.windows.conf.json")).unwrap();
    assert_eq!(
        config["bundle"]["resources"]["../../../resources-windows/"],
        "resources-windows/"
    );
    assert!(
        config["bundle"].get("externalBin").is_none(),
        "Orion ships no sidecar: ceremonies run in the UI"
    );
    let args = config["bundle"]["windows"]["signCommand"]["args"]
        .as_array()
        .unwrap();
    assert!(args.iter().any(|arg| arg == "windows/sign-orion.ps1"));
    let signer = include_str!("../windows/sign-orion.ps1");
    for required in ["ORION_TIMESTAMP_URL", "/tr", "/td", "SHA256", "/tw"] {
        assert!(signer.contains(required), "missing element: {required}");
    }
}

/// A profile must not wear the icon of the application that opens it.
///
/// The chain is long enough to break silently: the registry key the
/// fragment writes is built from `productName` and the declared extension,
/// the icon it points at is installed by a resource entry, and the
/// component that carries the whole thing only reaches the package because
/// it is listed in `componentRefs`. Any one of the four moving alone
/// produces an installer that builds, installs, and shows the wrong icon.
#[test]
fn windows_bundle_gives_orion_profiles_their_own_icon() {
    let base: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    let windows: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.windows.conf.json")).unwrap();
    let fragment = include_str!("../windows/orion-profile-icon.wxs");

    let product = base["productName"].as_str().expect("product name");
    let progid = format!("{product}.{PROFILE_EXTENSION}");
    assert!(
        fragment.contains(&format!(r"Software\Classes\{progid}")),
        "the fragment must write under the ProgID the WiX template creates ({progid})"
    );
    assert!(fragment.contains(r#"Id="OrionProfileIcon""#));
    assert!(fragment.contains("[INSTALLDIR]orion-profile.ico"));

    let wix = &windows["bundle"]["windows"]["wix"];
    assert!(wix["fragmentPaths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|path| path == "windows/orion-profile-icon.wxs"));
    assert!(wix["componentRefs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|component| component == "OrionProfileIcon"));
    assert_eq!(
        windows["bundle"]["resources"]["icons/orion-profile.ico"], "orion-profile.ico",
        "the icon must be installed beside the executable the key points next to"
    );

    // An `.ico` is a set of images, and the small sizes are drawn
    // separately: a single frame scaled by the shell is what the file
    // exists to avoid.
    let icon = include_bytes!("../icons/orion-profile.ico");
    assert_eq!(
        &icon[0..4],
        &[0x00, 0x00, 0x01, 0x00],
        "ICO header expected"
    );
    assert!(
        u16::from_le_bytes([icon[4], icon[5]]) >= 5,
        "the icon must carry the small sizes drawn for them"
    );
}

/// The WiX fragment must stay well-formed XML, comments included.
///
/// `--` inside a comment body is illegal XML, and a command line quoted in
/// prose is the natural way to write one by accident. candle refuses the
/// file before reading an element, but the bundler logs its output at debug
/// level: the build then fails with `failed to run candle.exe` and no line
/// number, minutes into a release job that only runs on Windows.
#[test]
fn windows_wix_fragment_comments_are_well_formed() {
    let mut rest = include_str!("../windows/orion-profile-icon.wxs");
    while let Some(start) = rest.find("<!--") {
        let body = &rest[start + "<!--".len()..];
        let end = body.find("-->").expect("unterminated XML comment");
        assert!(
            !body[..end].contains("--"),
            "an XML comment must not contain `--`: {}",
            &body[..end]
        );
        rest = &body[end + "-->".len()..];
    }
}

#[test]
fn tauri_capabilities_stay_minimal() {
    let capabilities: serde_json::Value =
        serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
    assert_eq!(capabilities["windows"], serde_json::json!(["main"]));
    assert_eq!(
        capabilities["permissions"],
        serde_json::json!([
            "core:default",
            "companion:allow-launch-certificate-companion"
        ])
    );
}

#[test]
fn association_only_forwards_orion_profiles() {
    let args = vec![
        "orion.exe".to_string(),
        format!("invitation.{PROFILE_EXTENSION}"),
        "--unexpected".to_string(),
        "other.json".to_string(),
    ];
    assert_eq!(
        associated_profile_paths(&args, Path::new("/profils")),
        vec![PathBuf::from(format!(
            "/profils/invitation.{PROFILE_EXTENSION}"
        ))]
    );
}

/// The extension changed; the documents already written did not.
///
/// A profile sitting on an operator's disk outlives the client that reads
/// it. Dropping the old suffix would turn a valid document into «format
/// inconnu» — and send the user back through an enrolment they have no
/// reason to redo.
#[test]
fn the_previous_extension_is_still_read() {
    let args = vec![
        "orion.exe".to_string(),
        format!("invitation.{LEGACY_PROFILE_EXTENSION}"),
    ];
    assert_eq!(
        associated_profile_paths(&args, Path::new("/profils")),
        vec![PathBuf::from(format!(
            "/profils/invitation.{LEGACY_PROFILE_EXTENSION}"
        ))]
    );
}

/// Windows matches an extension without regard to case, and so must the
/// filter: a document named `.Orion` is the same document.
#[test]
fn the_extension_is_matched_without_regard_to_case() {
    let args = vec!["orion.exe".to_string(), "Poste.Orion".to_string()];
    assert_eq!(
        associated_profile_paths(&args, Path::new("/profils")),
        vec![PathBuf::from("/profils/Poste.Orion")]
    );
}

#[test]
fn windows_manifest_requires_administrator_privileges() {
    let manifest = include_str!("../windows/orion-manifest.xml");
    assert!(manifest.contains("requireAdministrator"));
    assert!(manifest.contains("Microsoft.Windows.Common-Controls"));
}

/// The shipped client spawns nothing with its **own** token.
///
/// # The escalation this forbids
///
/// Orion runs elevated — the test above is what guarantees it, because
/// WireGuard-NT cannot be loaded otherwise. A child process inherits its
/// parent's token, so any `std::process::Command` in a release build is
/// an Administrator process. A terminal launched that way would hand out
/// an admin shell for one click, with no UAC prompt of its own, to anyone
/// who can reach this window — or anything that can reach the command,
/// the webview included. It was written that way once.
///
/// Spawning is allowed again, but only through [`crate::deelevate`],
/// which builds the child from the standard-user token and refuses until
/// Windows confirms it is not elevated. This test keeps the shortcut from
/// coming back: the only `Command::new` left in this file is the dev-only
/// Vite server, behind `debug_assertions`.
#[test]
fn the_shipped_client_spawns_nothing_with_its_own_token() {
    let source = include_str!("main.rs");
    // Split so this test's own scan does not match itself.
    let needle = concat!("Command", "::new");
    let mut spawns = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        if code.contains(needle) {
            spawns.push((index + 1, code.trim().to_string()));
        }
    }
    assert_eq!(
        spawns.len(),
        1,
        "a release build must spawn nothing with Orion's own token — it is an \
             Administrator token. Use `deelevate`. Found: {spawns:?}"
    );
    let (line, _) = spawns[0];
    let before = source.lines().take(line - 1).collect::<Vec<_>>().join("\n");
    let guard = before
        .rfind("#[cfg(debug_assertions)]")
        .expect("the only spawn must sit behind #[cfg(debug_assertions)]");
    assert!(
        !before[guard..].contains("\n#[cfg("),
        "the spawn at line {line} is no longer the one guarded by debug_assertions"
    );
}

/// The de-elevating launcher keeps its post-condition, and its shape.
///
/// Asserted on the source text, which is crude and is the only mechanism
/// available: the module is Windows-only, so nothing here compiles or runs
/// it. What it protects is the one line that makes the module safe — the
/// refusal when Windows still reports the token as elevated. Someone
/// tidying this file could drop that check and every other test would stay
/// green, on every platform, forever.
#[test]
fn the_deelevating_launcher_checks_before_it_launches() {
    let source = include_str!("deelevate.rs");
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        !code.contains(concat!("Command", "::new")),
        "the launcher must not fall back to std::process — that inherits the \
             elevated token, which is the whole thing it exists to avoid"
    );

    let refusal = code
        .find("if is_elevated(&token)?")
        .expect("the elevation post-condition must be present");
    let launch = code
        .find("CreateProcessWithTokenW(")
        .expect("the launcher must go through CreateProcessWithTokenW");
    assert!(
        refusal < launch,
        "the token must be checked **before** anything is launched"
    );
}

/// What the enrollment screen receives carries the public half only.
///
/// The pending record holds three private keys; the views built from it, and
/// the invitation preview, are what crosses the IPC. Checked on the JSON the
/// WebView actually decodes.
#[test]
fn enrollment_commands_never_return_private_material() {
    use aether::certificates::encoding::{Fingerprint, Id16, MlDsa87Signature, WireGuardKey};
    use aether::key_negotiation::{
        encode_invitation_file, generate_ml_dsa_87_keypair, EnrollmentInvitation, ProtectionMode,
        ENROLLMENT_FORMAT_VERSION, ENROLLMENT_PROTOCOL_VERSION,
    };

    let (ca_private, ca_public) = generate_ml_dsa_87_keypair().expect("ca");
    let now = orion_engine::service::certificates::now_unix();
    let invitation = EnrollmentInvitation {
        format_version: ENROLLMENT_FORMAT_VERSION,
        protocol_version: ENROLLMENT_PROTOCOL_VERSION,
        invitation_id: Id16::new([1; 16]).expect("id"),
        gateway_wg_public_key: WireGuardKey::from_bytes([2; 32]),
        gateway_certificate_fingerprint: Fingerprint::from_bytes([4; 32]),
        server_name: "vpn.example.net".into(),
        operator_ca_public_key: aether::certificates::encoding::MlDsa87PublicKey::new(ca_public)
            .expect("ca key"),
        wireguard_proof_public_key: WireGuardKey::from_bytes([5; 32]),
        not_before_unix: now - 60,
        not_after_unix: now + 3_600,
        minimum_mode: ProtectionMode::MlKem,
        allow_readmission: false,
        operator_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&ca_private)
    .expect("signed");
    let token = encode_invitation_file(&invitation);
    let preview = orion_engine::service::enrollment::invitation_preview_view(token.as_bytes(), now)
        .expect("preview");
    assert_eq!(preview.invitation_token, token);

    let pending = orion_core::enrollment::PendingEnrollment {
        invitation_id: invitation.invitation_id,
        request_id: Id16::new([6; 16]).expect("id"),
        requested_name: "poste-windows".into(),
        server_name: invitation.server_name.clone(),
        created_at_unix: now,
        invitation_expires_at_unix: invitation.not_after_unix,
    };
    for json in [
        serde_json::to_value(&preview).expect("preview json"),
        serde_json::to_value(vec![pending]).expect("pending json"),
    ] {
        let text = json.to_string().to_ascii_lowercase();
        for forbidden in ["private", "secret"] {
            assert!(!text.contains(forbidden), "{forbidden} in {text}");
        }
    }
}
