//! The operator ceremony, run in a thread of this process.
//!
//! # Why it runs here
//!
//! The WebAuthn API answers only inside the interactive user's session, and
//! the platform dialog belongs to a window of the process that asks for it.
//! Orion is that process: its window is the one the operator is looking at,
//! and the press that opens a key dialog comes from it. The ceremony therefore
//! needs no second process, no socket and no foreground grant.
//!
//! # What crosses
//!
//! Presses come in over a channel, one [`Press`] per button. Statuses go out
//! through `publish`. Neither carries a PIN, an assertion or a vault byte: the
//! vault is opened and the key is asked for in this function, and nothing it
//! holds is handed to the caller.

use std::path::Path;
use std::sync::mpsc::Receiver;

use aether::certificates::encoding::{Id16, MlDsa87PublicKey, WireGuardKey};
use aether::certificates::operator_session::{
    AstraManifest, GestureState, InvitationManifest, KeyCheckManifest, KeyPurpose, KeySlotLabel,
    OperationKind, OperationLocator, OperatorAction, OperatorStatus, Refusal, RemoteState,
};
use aether::key_negotiation::{encode_invitation_file, PqCertificate, PqCertificateRole};
use aether_fido::authenticator::{Authenticator, DialogOwner};
use astra_operator::enrollment::InvitationRegistry;
use astra_operator::vault::AuthorityVault;

use super::{EnrollmentGesture, OperatorArtifact};

/// One button pressed in the window: what it asks, the status it answers, and
/// the window the press came from.
///
/// `owner` is the platform handle of that window, or `0` where there is none.
/// It is read on the press that opens a key dialog and is the window the
/// dialog belongs to, so it is carried per press rather than fixed at launch.
#[derive(Debug, Clone, Copy)]
pub struct Press {
    pub action: OperatorAction,
    pub revision: u64,
    pub owner: isize,
}

/// Runs one ceremony to its end, publishing every state it reaches.
///
/// Returns when the ceremony is over, whatever the reason. A `Err` has
/// already been published as a refusal before it is returned, except when the
/// ceremony could not start at all.
pub fn run(
    session_id: Id16,
    locator: OperationLocator,
    presses: Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
) -> Result<(), String> {
    let vault_path = astra_operator::store::default_path().map_err(|error| format!("{error:#}"))?;
    run_with_vault(session_id, locator, presses, publish, &vault_path)
}

/// [`run`], with the vault named instead of looked up, so a test can point it
/// at a path of its own.
fn run_with_vault(
    session_id: Id16,
    locator: OperationLocator,
    presses: Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    vault_path: &Path,
) -> Result<(), String> {
    let mut ceremony = Ceremony::new(session_id, locator);
    publish(ceremony.status());

    match ceremony.operation {
        OperationKind::RecoverIdentity => recover(&mut ceremony, &presses, publish, vault_path),
        OperationKind::ApproveCampaign => {
            approve_campaign(&mut ceremony, &presses, publish, vault_path)
        }
        OperationKind::VerifyKey => verify_key(&mut ceremony, &presses, publish, vault_path),
        // Named rather than swallowed: an operator whose tab offered a
        // ceremony this build cannot run must be told that, and not left
        // watching a status that never moves.
        other => {
            ceremony.refuse(Refusal::Internal);
            publish(ceremony.status());
            Err(format!(
                "la cérémonie « {other:?} » n'est pas encore portée dans ce processus"
            ))
        }
    }
}

/// Runs one enrollment gesture to its end, publishing every state it reaches
/// and handing each file it produces to `deposit`.
///
/// Called from the ceremony's own thread, which is what lets the gateway be
/// read from it with a blocking wait: that thread is not a runtime worker.
pub fn run_enrollment(
    session_id: Id16,
    gesture: EnrollmentGesture,
    gateway: Option<String>,
    presses: Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    deposit: &mut dyn FnMut(OperatorArtifact),
) -> Result<(), String> {
    let resolved = astra_operator::store::default_path()
        .and_then(|path| InvitationRegistry::default_location().map(|registry| (path, registry)));
    let (vault_path, registry) = match resolved {
        Ok(resolved) => resolved,
        Err(error) => {
            let mut ceremony = Ceremony::new(session_id, enrollment_locator(&gesture));
            publish(ceremony.status());
            ceremony.refuse(Refusal::VaultUnavailable);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };
    run_enrollment_with(
        session_id,
        gesture,
        gateway,
        presses,
        publish,
        deposit,
        &vault_path,
        &registry,
    )
}

fn enrollment_locator(gesture: &EnrollmentGesture) -> OperationLocator {
    OperationLocator {
        kind: gesture.operation(),
        operation_id: None,
    }
}

/// [`run_enrollment`], with the vault and the registry named, so a test can
/// point it at a directory of its own.
#[allow(clippy::too_many_arguments)]
fn run_enrollment_with(
    session_id: Id16,
    gesture: EnrollmentGesture,
    gateway: Option<String>,
    presses: Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    deposit: &mut dyn FnMut(OperatorArtifact),
    vault_path: &Path,
    registry: &InvitationRegistry,
) -> Result<(), String> {
    let mut ceremony = Ceremony::new(session_id, enrollment_locator(&gesture));
    publish(ceremony.status());

    match gesture {
        EnrollmentGesture::Invite {
            valid_for_hours,
            allow_readmission,
            name,
            gateway_pq_certificate,
        } => invite(
            &mut ceremony,
            &presses,
            publish,
            deposit,
            vault_path,
            registry,
            Invite {
                valid_for_hours,
                allow_readmission,
                name: &name,
                gateway: gateway.as_deref(),
                sheet: gateway_pq_certificate.as_deref(),
            },
        ),
        // Named rather than swallowed, as for the other ceremonies: a gesture
        // this build does not carry yet is said so, not left silent.
        EnrollmentGesture::Accept { .. } | EnrollmentGesture::Resume { .. } => {
            ceremony.refuse(Refusal::Internal);
            publish(ceremony.status());
            Err("ce geste d'enrôlement n'est pas encore porté dans ce processus".to_string())
        }
    }
}

/// What the operator decided about one invitation, already range-checked.
struct Invite<'a> {
    valid_for_hours: u8,
    allow_readmission: bool,
    name: &'a str,
    /// The connected gateway's control-plane address, when a tunnel is up.
    gateway: Option<&'a str>,
    /// The contents of a leaf file the operator chose.
    sheet: Option<&'a str>,
}

/// The purpose of the `index`-th key (from 1) of an invitation: the first
/// opens the vault, the following approve beside it.
fn invitation_key_purpose(index: u8) -> KeyPurpose {
    if index <= 1 {
        KeyPurpose::OpenVault
    } else {
        KeyPurpose::SecondApproval
    }
}

/// §15.2, the invitation: checked in full, shown, then signed under the
/// operator's key or keys.
///
/// The order is the safety: the window and the gateway's identity are checked,
/// and the manifest is shown, before a key is asked for anything; and the
/// registry is written by the signing and by nothing earlier, so a ceremony
/// abandoned or refused before it leaves no record behind.
fn invite(
    ceremony: &mut Ceremony,
    presses: &Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    deposit: &mut dyn FnMut(OperatorArtifact),
    vault_path: &Path,
    registry: &InvitationRegistry,
    invite: Invite<'_>,
) -> Result<(), String> {
    let now = now_unix();
    let not_after = now + u64::from(invite.valid_for_hours) * 3_600;

    let prepared = match prepare_invitation(vault_path, &invite, now) {
        Ok(prepared) => prepared,
        Err((refusal, message)) => {
            ceremony.refuse(refusal);
            publish(ceremony.status());
            return Err(message);
        }
    };
    let Prepared {
        vault,
        certificate,
        gateway_wg_public_key,
        server_name,
        ca_pq_public_key,
    } = prepared;
    let required = u8::try_from(astra_operator::signing::enrollment_credentials(
        invite.allow_readmission,
    ))
    .unwrap_or(2);

    // Shown before any key is asked for anything, and it states what the
    // signed invitation will say.
    ceremony.remote = RemoteState::AwaitingOperator;
    ceremony.manifest = Some(AstraManifest::Invitation(InvitationManifest {
        server_name: server_name.clone(),
        gateway_wg_public_key,
        not_after_unix: not_after,
        allow_readmission: invite.allow_readmission,
        ca_pq_fingerprint: ca_pq_public_key.authority_fingerprint(),
    }));

    let mut openings = Vec::with_capacity(usize::from(required));
    for index in 1..=required {
        ceremony.gesture = GestureState::AwaitingKey {
            index,
            of: required,
            purpose: invitation_key_purpose(index),
        };
        let offered = ceremony.status();
        publish(offered.clone());

        let Some(key) = open_key(ceremony, presses, publish, &offered)? else {
            return Ok(());
        };
        let opened =
            match astra_operator::gestures::open_with_authorized_key(key.as_ref(), &vault, "") {
                Ok(opened) => opened,
                Err(error) => {
                    ceremony.refuse(Refusal::KeyNotEnrolled);
                    publish(ceremony.status());
                    return Err(format!("{error:#}"));
                }
            };
        // Said at this key rather than after the last: the operator can still
        // swap the token, and nothing has been signed.
        if openings
            .iter()
            .any(|earlier: &astra_operator::authenticator::Opened| {
                earlier.credential_id == opened.credential_id
            })
        {
            ceremony.refuse(Refusal::KeyRepeated);
            publish(ceremony.status());
            return Err(
                "le même credential a été présenté deux fois : une réadmission en exige deux \
                 distincts"
                    .to_string(),
            );
        }
        if let Ok(slot) = vault.slot_for_credential(&opened.credential_id) {
            ceremony.keys.push(KeySlotLabel {
                slot: index.to_string(),
                label: slot.label.clone(),
            });
        }
        openings.push(opened);
    }

    ceremony.gesture = GestureState::Signing;
    publish(ceremony.status());

    let references: Vec<&astra_operator::authenticator::Opened> = openings.iter().collect();
    let signed = astra_operator::signing::sign_invitation(
        &vault,
        &references,
        &astra_operator::signing::InvitationDraft {
            gateway_certificate: &certificate,
            gateway_wg_public_key,
            server_name: &server_name,
            not_before_unix: now,
            not_after_unix: not_after,
            allow_readmission: invite.allow_readmission,
        },
        registry,
        now,
    );
    match signed {
        Ok(invitation) => {
            deposit(OperatorArtifact {
                file_name: format!("{}.helios-invite", invite.name),
                contents: encode_invitation_file(&invitation),
            });
            ceremony.gesture = GestureState::Done;
            publish(ceremony.status());
            Ok(())
        }
        Err(error) => {
            ceremony.refuse(Refusal::Internal);
            publish(ceremony.status());
            Err(format!("{error:#}"))
        }
    }
}

/// What an invitation is made of, once everything that needs no key has been
/// verified.
struct Prepared {
    vault: AuthorityVault,
    certificate: PqCertificate,
    gateway_wg_public_key: WireGuardKey,
    server_name: String,
    ca_pq_public_key: MlDsa87PublicKey,
}

/// Reads the vault and the relay beside it, finds the gateway's leaf and
/// verifies it under `CA-PQ` for the gateway the relay names — all without a
/// key. Anything doubtful is a refusal.
fn prepare_invitation(
    vault_path: &Path,
    invite: &Invite<'_>,
    now: u64,
) -> Result<Prepared, (Refusal, String)> {
    let mismatch = |message: String| (Refusal::HandoffMismatch, message);
    let vault = astra_operator::store::load(vault_path)
        .map_err(|error| (Refusal::VaultUnavailable, format!("{error:#}")))?;
    let relay = astra_operator::handoff::DomainHandoff::beside(vault_path, &vault)
        .map_err(|error| mismatch(format!("{error:#}")))?;
    let (Some(gateway_key), Some(server_name)) = (
        relay.gateway_wg_public_key.as_deref(),
        relay.server_name.as_deref(),
    ) else {
        return Err(mismatch(
            "le relais de domaine ne nomme encore aucune gateway : l'amorçage de la gateway \
             doit précéder les invitations"
                .to_string(),
        ));
    };
    let gateway_wg_public_key =
        WireGuardKey::parse(gateway_key).map_err(|error| mismatch(error.to_string()))?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(&relay.ca_pq_public_key)
        .map_err(|error| mismatch(error.to_string()))?;

    let certificate = gateway_leaf(invite, server_name, &gateway_wg_public_key)?;
    certificate
        .verify(
            ca_pq_public_key.as_bytes(),
            PqCertificateRole::Gateway,
            Some(server_name),
            &gateway_wg_public_key.to_base64(),
            now,
        )
        .map_err(|error| {
            mismatch(format!(
                "la feuille PQ de la gateway ne vérifie pas sous CA-PQ pour la gateway de ce \
                 domaine : {error}"
            ))
        })?;

    Ok(Prepared {
        vault,
        certificate,
        gateway_wg_public_key,
        server_name: server_name.to_string(),
        ca_pq_public_key,
    })
}

/// The gateway's leaf: read from the connected gateway, else taken from the
/// sheet the operator chose.
///
/// A gateway that answers for another identity than the relay names is a
/// refusal, not a reason to look elsewhere. One that does not answer falls back
/// to the sheet when there is one. Either way the leaf is verified afterwards.
fn gateway_leaf(
    invite: &Invite<'_>,
    server_name: &str,
    gateway_key: &WireGuardKey,
) -> Result<PqCertificate, (Refusal, String)> {
    use orion_core::gateway_admin as admin;

    let read = invite.gateway.map(|base| {
        admin::orion_client()
            .and_then(|client| {
                tauri::async_runtime::block_on(admin::gateway_negotiation(&client, base))
            })
            .map_err(|error| error.to_string())
    });
    leaf_from(invite.sheet, read, server_name, gateway_key)
}

/// The decision of [`gateway_leaf`], on what the connected gateway answered
/// (`None` when no gateway is connected).
fn leaf_from(
    sheet: Option<&str>,
    read: Option<Result<orion_core::enrollment_draft::GatewayMaterial, String>>,
    server_name: &str,
    gateway_key: &WireGuardKey,
) -> Result<PqCertificate, (Refusal, String)> {
    use orion_core::gateway_admin as admin;

    let mut unreadable = None;
    match read {
        Some(Ok(material)) => {
            let same_key = WireGuardKey::parse(material.wireguard_public_key.trim())
                .map(|key| key == *gateway_key)
                .unwrap_or(false);
            if material.server_name.trim() != server_name || !same_key {
                return Err((
                    Refusal::HandoffMismatch,
                    "la gateway connectée n'est pas celle que le domaine nomme".to_string(),
                ));
            }
            return admin::decode_pq_certificate(&material.gateway_pq_certificate)
                .map_err(|error| (Refusal::HandoffMismatch, error.to_string()));
        }
        Some(Err(message)) => unreadable = Some(message),
        None => {}
    }
    match (sheet, unreadable) {
        (Some(sheet), _) => admin::decode_pq_certificate(sheet)
            .map_err(|error| (Refusal::HandoffMismatch, error.to_string())),
        (None, Some(message)) => Err((Refusal::GatewayUnavailable, message)),
        (None, None) => Err((
            Refusal::HandoffMismatch,
            "aucune gateway connectée et aucune feuille PQ fournie : l'invitation n'a rien à \
             épingler"
                .to_string(),
        )),
    }
}

/// §7.5, driven from a screen instead of a terminal.
///
/// The shape is the protocol's: verify, show, wait for the operator, act. The
/// waiting is a press naming the revision it answers, not a blocking read on a
/// console this process does not have.
fn recover(
    ceremony: &mut Ceremony,
    presses: &Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    vault_path: &Path,
) -> Result<(), String> {
    let operation = ceremony.operation_id.ok_or_else(|| {
        "une récupération est désignée par l'identifiant qu'Orion détient".to_string()
    })?;
    let verified = match astra_operator::operations::recovery::begin(
        vault_path,
        operation,
        None,
        None,
        now_unix(),
    ) {
        Ok(verified) => verified,
        Err(error) => {
            ceremony.refuse(Refusal::HandoffMismatch);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };

    // Shown before a key is asked for anything, and it is this object that is
    // signed — §12.2 is the reason the two are the same value rather than two
    // descriptions of one intention.
    ceremony.remote = RemoteState::AwaitingOperator;
    ceremony.gesture = GestureState::AwaitingKey {
        index: 1,
        of: 1,
        purpose: KeyPurpose::OpenVault,
    };
    ceremony.manifest = Some(AstraManifest::Recovery(verified.manifest().clone()));
    let offered = ceremony.status();
    publish(offered.clone());

    let Some(key) = open_key(ceremony, presses, publish, &offered)? else {
        return Ok(());
    };

    ceremony.gesture = GestureState::Signing;
    publish(ceremony.status());

    let mut reached = Vec::new();
    let outcome = verified.approve(key.as_ref(), "", &mut |state| reached.push(state));
    // Emitted after the fact rather than from inside the callback: the
    // publisher is borrowed by this frame, and a status lost to a closure's
    // borrow would be a step the operator never saw.
    for state in reached {
        ceremony.remote = state;
        publish(ceremony.status());
    }
    match outcome {
        Ok(()) => {
            ceremony.gesture = GestureState::Done;
            publish(ceremony.status());
            Ok(())
        }
        Err(error) => {
            ceremony.refuse(Refusal::AuthorityRefused { status: 0 });
            publish(ceremony.status());
            Err(format!("{error:#}"))
        }
    }
}

/// §8.5, with its keys asked for one at a time.
///
/// The campaign says how many distinct credentials must approve it, and each
/// one is a separate wait: an operator about to touch the same token twice
/// finds that out at the *second* prompt rather than after both, which is the
/// only moment where the answer is still theirs to change.
fn approve_campaign(
    ceremony: &mut Ceremony,
    presses: &Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    vault_path: &Path,
) -> Result<(), String> {
    let operation = ceremony.operation_id.ok_or_else(|| {
        "une campagne est désignée par l'opération que l'autorité a ouverte".to_string()
    })?;
    let verified = match astra_operator::operations::campaign::begin(
        vault_path,
        operation,
        None,
        None,
        now_unix(),
    ) {
        Ok(verified) => verified,
        Err(error) => {
            ceremony.refuse(Refusal::HandoffMismatch);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };

    ceremony.remote = RemoteState::AwaitingOperator;
    ceremony.manifest = Some(AstraManifest::Campaign(verified.manifest().clone()));
    let mut approval = match verified.start_approval(now_unix()) {
        Ok(approval) => approval,
        Err(error) => {
            ceremony.refuse(Refusal::ManifestMismatch);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };
    let required = approval.required_credentials();

    for index in 1..=required {
        ceremony.gesture = GestureState::AwaitingKey {
            index,
            of: required,
            purpose: KeyPurpose::ApproveCampaign,
        };
        let offered = ceremony.status();
        publish(offered.clone());

        let Some(key) = open_key(ceremony, presses, publish, &offered)? else {
            return Ok(());
        };
        match approval.approve_key(key.as_ref(), "", now_unix()) {
            Ok(label) => ceremony.keys.push(KeySlotLabel {
                slot: index.to_string(),
                label,
            }),
            Err(error) => {
                ceremony.refuse(Refusal::KeyDeclined);
                publish(ceremony.status());
                return Err(format!("{error:#}"));
            }
        }
    }

    ceremony.gesture = GestureState::Signing;
    publish(ceremony.status());

    let mut reached = Vec::new();
    let outcome = approval.finish(now_unix(), &mut |state| reached.push(state));
    for state in reached {
        ceremony.remote = state;
        publish(ceremony.status());
    }
    match outcome {
        Ok(_) => {
            ceremony.gesture = GestureState::Done;
            publish(ceremony.status());
            Ok(())
        }
        Err(error) => {
            ceremony.refuse(Refusal::AuthorityRefused { status: 0 });
            publish(ceremony.status());
            Err(format!("{error:#}"))
        }
    }
}

/// The key check: the vault opens under a touch, and nothing is written.
///
/// It proves that the token in hand still opens this vault and names the
/// key-slot that answered. The manifest carries the vault's fingerprint and
/// nothing a key signs, because nothing is signed.
fn verify_key(
    ceremony: &mut Ceremony,
    presses: &Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    vault_path: &Path,
) -> Result<(), String> {
    let (vault, fingerprint) = match load_with_fingerprint(vault_path) {
        Ok(loaded) => loaded,
        Err(error) => {
            ceremony.refuse(Refusal::HandoffMismatch);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };

    ceremony.remote = RemoteState::AwaitingOperator;
    ceremony.gesture = GestureState::AwaitingKey {
        index: 1,
        of: 1,
        purpose: KeyPurpose::OpenVault,
    };
    ceremony.manifest = Some(AstraManifest::KeyCheck(KeyCheckManifest {
        vault_fingerprint: fingerprint,
    }));
    let offered = ceremony.status();
    publish(offered.clone());

    let Some(key) = open_key(ceremony, presses, publish, &offered)? else {
        return Ok(());
    };

    // The PIN is empty for the reason `open_key` refused a transport that
    // wants one: the platform collects it in its own dialog.
    let checked = prove_key_opens(key.as_ref(), &vault);
    match checked {
        Ok(label) => {
            ceremony.keys.push(KeySlotLabel {
                slot: "1".to_string(),
                label,
            });
            ceremony.gesture = GestureState::Done;
            publish(ceremony.status());
            Ok(())
        }
        Err(error) => {
            ceremony.refuse(Refusal::KeyDeclined);
            publish(ceremony.status());
            Err(format!("{error:#}"))
        }
    }
}

fn load_with_fingerprint(
    vault_path: &Path,
) -> anyhow::Result<(AuthorityVault, aether::certificates::encoding::Fingerprint)> {
    let vault = astra_operator::store::load(vault_path)?;
    let fingerprint = vault.fingerprint()?;
    Ok((vault, fingerprint))
}

/// Opens the vault under `key`, proves the anchors are readable, and returns
/// the label of the key-slot that answered — never any secret.
fn prove_key_opens(key: &dyn Authenticator, vault: &AuthorityVault) -> anyhow::Result<String> {
    let opened = astra_operator::gestures::open_with_authorized_key(key, vault, "")?;
    astra_operator::gestures::prove_anchors_open(vault, &opened)?;
    Ok(vault
        .slot_for_credential(&opened.credential_id)?
        .label
        .clone())
}

/// Waits for the operator's Continue, then connects the key it asks for.
///
/// The one copy of the sequence every key-asking ceremony shares: wait for the
/// press answering `offered`, attach the dialog to the window it came from,
/// connect the key, and refuse a transport that wants a PIN this process has
/// no way to ask for. `None` is an abandonment, already published as such.
/// An `Err` has been published as a refusal.
///
/// The position of the key (`index` of `of`) is read from the gesture the
/// ceremony is waiting in, so the caller sets it before offering.
fn open_key(
    ceremony: &mut Ceremony,
    presses: &Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    offered: &OperatorStatus,
) -> Result<Option<Box<dyn Authenticator>>, String> {
    let GestureState::AwaitingKey { index, of, .. } = ceremony.gesture else {
        ceremony.refuse(Refusal::Internal);
        publish(ceremony.status());
        return Err("aucune clé n'est attendue à cette étape de la cérémonie".to_string());
    };
    let press = match awaited_action(presses, offered) {
        Some(press) if press.action == OperatorAction::Continue => press,
        _ => {
            ceremony.cancel();
            publish(ceremony.status());
            return Ok(None);
        }
    };

    ceremony.gesture = GestureState::ProcessingKey { index, of };
    publish(ceremony.status());
    let owner = match dialog_owner(press.owner) {
        Ok(owner) => owner,
        Err(error) => {
            ceremony.refuse(Refusal::ForegroundUnavailable);
            publish(ceremony.status());
            return Err(error);
        }
    };
    let key = match aether_fido::authenticator::connect_owned(
        aether_fido::authenticator::Transport::default(),
        owner,
    ) {
        Ok(key) => key,
        Err(error) => {
            ceremony.refuse(Refusal::KeyDeclined);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };
    // The platform collects the PIN in its own dialog, so it never enters this
    // process. A transport that needs one has no way to ask from here — there
    // is no console — and saying so is better than an empty string that fails
    // three steps later as «clé refusée».
    if key.needs_pin() {
        ceremony.refuse(Refusal::ProtocolViolation);
        publish(ceremony.status());
        return Err(
            "ce transport demande que le PIN soit saisi par le programme, et ce processus n'a \
             aucune interface pour le demander"
                .to_string(),
        );
    }
    Ok(Some(key))
}

/// Waits for the operator's answer to one rendered status.
///
/// A press naming another revision is ignored rather than obeyed: it answers a
/// screen this session has already left, and acting on it would apply a press
/// to whatever replaced it. `None` means every sender is gone — the window that
/// held the ceremony was closed, which is an abandonment and not a failure.
fn awaited_action(presses: &Receiver<Press>, offered: &OperatorStatus) -> Option<Press> {
    loop {
        let press = presses.recv().ok()?;
        if offered.accepts(press.action, press.revision) {
            return Some(press);
        }
    }
}

/// The window the platform dialog belongs to, from the press that opened it.
///
/// Orion's own window: the press came from it, and it is the window the
/// operator is looking at. A press that carries no handle is refused rather
/// than opened unowned — an unowned dialog may appear behind the window the
/// operator is reading, with nothing to say why the key never answers.
#[cfg(windows)]
fn dialog_owner(owner: isize) -> Result<DialogOwner, String> {
    if owner == 0 {
        return Err(
            "la fenêtre d'Orion est introuvable : la boîte de la clé n'aurait pas de propriétaire"
                .to_string(),
        );
    }
    Ok(DialogOwner::Window(owner))
}

/// Off Windows the only transport is raw CTAP, whose gesture is on the token
/// and shows no dialog: the console is the honest owner, and nothing is
/// claimed.
#[cfg(not(windows))]
fn dialog_owner(owner: isize) -> Result<DialogOwner, String> {
    let _ = owner;
    Ok(DialogOwner::Console)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// One ceremony, and the revision counter that orders what it says.
struct Ceremony {
    session_id: Id16,
    operation: OperationKind,
    operation_id: Option<Id16>,
    revision: u64,
    remote: RemoteState,
    gesture: GestureState,
    manifest: Option<AstraManifest>,
    refusal: Option<Refusal>,
    keys: Vec<KeySlotLabel>,
}

impl Ceremony {
    fn new(session_id: Id16, locator: OperationLocator) -> Self {
        Self {
            session_id,
            operation: locator.kind,
            operation_id: locator.operation_id,
            revision: 0,
            remote: RemoteState::Local,
            gesture: GestureState::Verifying,
            manifest: None,
            refusal: None,
            keys: Vec::new(),
        }
    }

    /// Renders the current state, advancing the revision.
    ///
    /// Every status a ceremony emits goes through here, so the counter can only
    /// move forward and two statuses can never share a revision — which is what
    /// makes a press naming one of them unambiguous.
    fn status(&mut self) -> OperatorStatus {
        self.revision += 1;
        let mut status = OperatorStatus::new(
            self.session_id,
            self.revision,
            self.operation,
            self.remote,
            self.gesture,
        );
        status.operation_id = self.operation_id;
        status.manifest = self.manifest.clone();
        status.refusal = self.refusal;
        status.keys = self.keys.clone();
        status
    }

    fn refuse(&mut self, refusal: Refusal) {
        self.gesture = GestureState::Failed;
        self.refusal = Some(refusal);
    }

    /// Abandoned by the operator, before anything left this machine.
    ///
    /// A distinct state from a refusal: nothing failed, and an interface that
    /// showed «échec» for a decision would be telling the operator their own
    /// choice went wrong.
    fn cancel(&mut self) {
        self.gesture = GestureState::Cancelled;
        self.refusal = Some(Refusal::Cancelled);
    }
}

#[cfg(test)]
mod tests;
