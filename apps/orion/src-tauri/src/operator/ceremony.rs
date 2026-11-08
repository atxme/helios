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

use aether::certificates::encoding::{DerCertificate, Id16, MlDsa87PublicKey, WireGuardKey};
use aether::certificates::operator_session::{
    AcceptanceManifest, AstraManifest, GestureState, InvitationManifest, KeyCheckManifest,
    KeyPurpose, KeySlotLabel, OperationKind, OperationLocator, OperatorAction, OperatorStatus,
    Refusal, RemoteState,
};
use aether::key_negotiation::{
    decode_request_file, encode_invitation_file, EnrollmentRequest, PqCertificate,
    PqCertificateRole, ProtectionMode,
};
use aether_fido::authenticator::Authenticator;
use astra_operator::enrollment::{AcceptedEnrollment, InvitationRegistry};
use astra_operator::operations::rotation::RotationTerms;
use astra_operator::vault::AuthorityVault;

use super::{dialog_owner, now_unix, ArtifactEncoding, EnrollmentGesture, OperatorArtifact};

mod issuer;
mod rotation;
mod vault;
pub use issuer::run_issuer;
pub use rotation::run_rotation;
pub use vault::run_vault;

/// One button pressed in the window: what it asks, the status it answers, and
/// the window the press came from.
///
/// `owner` is the platform handle of that window, or `0` where there is none.
/// It is read on the press that opens a key dialog and is the window the
/// dialog belongs to, so it is carried per press rather than fixed at launch.
///
/// `terms` come with the one press that opens a rotation's campaign: what the
/// operator chose on the approval screen. Public, as the manifest they lead to is.
#[derive(Debug, Clone)]
pub struct Press {
    pub action: OperatorAction,
    pub revision: u64,
    pub owner: isize,
    pub terms: Option<RotationTerms>,
}

/// Runs one ceremony to its end against the vault at `vault_path`, publishing
/// every state it reaches.
///
/// Returns when the ceremony is over, whatever the reason. A `Err` has
/// already been published as a refusal before it is returned, except when the
/// ceremony could not start at all.
pub fn run(
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
        // Opened by their gesture, which carries what they fix, and never by
        // a locator, which carries nothing.
        OperationKind::CreateDomain
        | OperationKind::AddKey
        | OperationKind::RemoveKey
        | OperationKind::MarkKey
        | OperationKind::FinalizeDomain
        | OperationKind::IssueGatewayBootstrap
        | OperationKind::AuthorizeIssuer
        | OperationKind::RotateAnchor
        | OperationKind::RotateClientTlsCa => {
            ceremony.refuse(Refusal::Internal);
            publish(ceremony.status());
            Err(format!(
                "la cérémonie « {:?} » s'ouvre par son geste, pas par un localisateur",
                ceremony.operation
            ))
        }
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

/// Runs one enrollment gesture to its end against the vault at `vault_path`,
/// publishing every state it reaches and handing each file it produces to
/// `deposit`.
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
    vault_path: &Path,
) -> Result<(), String> {
    let registry = match InvitationRegistry::default_location() {
        Ok(registry) => registry,
        Err(error) => {
            let mut ceremony = Ceremony::new(session_id, enrollment_locator(&gesture));
            publish(ceremony.status());
            ceremony.refuse(Refusal::VaultUnavailable);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };
    run_enrollment_with(
        session_id, gesture, gateway, presses, publish, deposit, vault_path, &registry,
    )
}

fn enrollment_locator(gesture: &EnrollmentGesture) -> OperationLocator {
    OperationLocator {
        kind: gesture.operation(),
        operation_id: None,
    }
}

/// [`run_enrollment`], with the registry named, so a test can point it at a
/// directory of its own.
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
        EnrollmentGesture::Accept {
            request,
            validity_days,
            endpoint,
            allowed_ips,
            ssh_target,
        } => accept(
            &mut ceremony,
            &presses,
            publish,
            deposit,
            vault_path,
            registry,
            Accept {
                request: &request,
                validity_days,
                endpoint: &endpoint,
                allowed_ips: allowed_ips.as_deref(),
                ssh_target: ssh_target.as_deref(),
                gateway: gateway.as_deref(),
            },
        ),
        EnrollmentGesture::Resume {
            invitation_id,
            endpoint,
            allowed_ips,
            ssh_target,
        } => resume(
            &mut ceremony,
            &presses,
            publish,
            deposit,
            vault_path,
            registry,
            Resume {
                invitation_id,
                delivery: Delivery {
                    endpoint: &endpoint,
                    allowed_ips: allowed_ips.as_deref(),
                    ssh_target: ssh_target.as_deref(),
                    gateway: gateway.as_deref(),
                },
            },
            &read_negotiation,
            &read_admitted_keys,
        ),
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
                encoding: ArtifactEncoding::Text,
                fingerprint: None,
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

/// What the operator decided about one acceptance.
struct Accept<'a> {
    /// The contents of the `.helios-request` file the operator chose.
    request: &'a str,
    validity_days: u16,
    /// The gateway's public WireGuard endpoint, as the document will carry it.
    endpoint: &'a str,
    allowed_ips: Option<&'a str>,
    ssh_target: Option<&'a str>,
    /// The connected gateway's control-plane address, when a tunnel is up.
    gateway: Option<&'a str>,
}

impl Accept<'_> {
    fn delivery(&self) -> Delivery<'_> {
        Delivery {
            endpoint: self.endpoint,
            allowed_ips: self.allowed_ips,
            ssh_target: self.ssh_target,
            gateway: self.gateway,
        }
    }
}

/// What the document of an accepted device is built from, beyond the leaves:
/// the part an acceptance and its resumption have in common.
struct Delivery<'a> {
    /// The gateway's public WireGuard endpoint, as the document will carry it.
    endpoint: &'a str,
    allowed_ips: Option<&'a str>,
    ssh_target: Option<&'a str>,
    /// The connected gateway's control-plane address, when a tunnel is up.
    gateway: Option<&'a str>,
}

/// What the operator decided about the resumption of one acceptance.
struct Resume<'a> {
    invitation_id: Id16,
    delivery: Delivery<'a>,
}

const DAY_SECS: u64 = 86_400;

/// How far back the leaves start, so a device whose clock runs a little slow
/// does not find them "not yet valid".
const LEAF_BACKDATE_SECS: u64 = 300;

/// What an acceptance is made of, once everything that needs no key has been
/// verified.
struct Accepting {
    vault: AuthorityVault,
    ca_tls_certificate: DerCertificate,
    request: EnrollmentRequest,
    leaf_validity: (u64, u64),
    pin: GatewayPin,
}

/// The gateway an invitation was issued for: what a connected gateway must
/// answer to before anything is consumed on its account or admitted to it.
struct GatewayPin {
    wg_public_key: WireGuardKey,
    server_name: String,
}

impl GatewayPin {
    fn of(invitation: &aether::key_negotiation::EnrollmentInvitation) -> Self {
        Self {
            wg_public_key: invitation.gateway_wg_public_key,
            server_name: invitation.server_name.clone(),
        }
    }

    /// Whether `material` is the pinned gateway. An unreadable key is a
    /// mismatch, never a pass.
    fn matches(&self, material: &orion_core::enrollment_draft::GatewayMaterial) -> bool {
        let same_key = WireGuardKey::parse(material.wireguard_public_key.trim())
            .map(|key| key == self.wg_public_key)
            .unwrap_or(false);
        same_key && material.server_name.trim() == self.server_name
    }

    fn check(
        &self,
        material: &orion_core::enrollment_draft::GatewayMaterial,
    ) -> Result<(), (Refusal, String)> {
        if self.matches(material) {
            Ok(())
        } else {
            Err((
                Refusal::HandoffMismatch,
                "la gateway connectée n'est pas celle que l'invitation épingle".to_string(),
            ))
        }
    }
}

type GatewayReader<'a> = &'a dyn Fn(
    &str,
) -> Result<
    orion_core::enrollment_draft::GatewayMaterial,
    orion_core::gateway_admin::GatewayAdminError,
>;

/// Reads the gateway's negotiation material with the Orion client.
fn read_negotiation(
    base: &str,
) -> Result<
    orion_core::enrollment_draft::GatewayMaterial,
    orion_core::gateway_admin::GatewayAdminError,
> {
    use orion_core::gateway_admin as admin;
    let client = admin::orion_client()?;
    tauri::async_runtime::block_on(admin::gateway_negotiation(&client, base))
}

/// The typed refusal of a gateway error. The French sentence is the window's.
fn gateway_refusal(error: &orion_core::gateway_admin::GatewayAdminError) -> Refusal {
    use orion_core::gateway_admin::GatewayAdminError as E;
    match error {
        E::Forbidden => Refusal::GatewayForbidden,
        E::Refused { status, .. } => Refusal::GatewayRefused { status: *status },
        E::Unreachable | E::Invalid(_) => Refusal::GatewayUnavailable,
    }
}

/// §15.2, the acceptance: verify the request, consume its invitation and issue
/// the two leaves under one key opening, keep them, admit the peer, then sign
/// the device's document under the same opening.
///
/// Everything before the key is a refusal that leaves the registry untouched.
/// From the consumption on, the invitation stays consumed whatever happens: a
/// failure is published, the leaves are kept for the resumption, and no leaf
/// is ever issued twice.
fn accept(
    ceremony: &mut Ceremony,
    presses: &Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    deposit: &mut dyn FnMut(OperatorArtifact),
    vault_path: &Path,
    registry: &InvitationRegistry,
    accept: Accept<'_>,
) -> Result<(), String> {
    let now = now_unix();
    let accepting = match prepare_acceptance(vault_path, registry, &accept, now, &read_negotiation)
    {
        Ok(accepting) => accepting,
        Err((refusal, message)) => {
            ceremony.refuse(refusal);
            publish(ceremony.status());
            return Err(message);
        }
    };
    let Accepting {
        vault,
        ca_tls_certificate,
        request,
        leaf_validity,
        pin,
    } = accepting;

    let manifest = AcceptanceManifest {
        invitation_id: request.invitation_id,
        request_fingerprint: request.fingerprint(),
        requested_name: request.requested_name.clone(),
        client_wg_public_key: request.client_wg_public_key,
        leaves_not_after_unix: leaf_validity.1,
        endpoint: accept.endpoint.trim().to_string(),
        allowed_ips: accept.allowed_ips.map(str::to_string),
        ssh_target: accept.ssh_target.map(str::to_string),
    };
    let Some(opened) = open_for_delivery(ceremony, presses, publish, &vault, manifest)? else {
        return Ok(());
    };

    // One opening for the issuance and for the document: the operator touches
    // the key once for the whole gesture.
    let leaves = match astra_operator::signing::accept_request(
        &vault,
        &opened,
        registry,
        &ca_tls_certificate,
        &request,
        leaf_validity,
        now,
    ) {
        Ok(leaves) => leaves,
        Err(error) => {
            ceremony.refuse(Refusal::Internal);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };
    let accepted = AcceptedEnrollment {
        request,
        tls_certificate: leaves.tls_certificate,
        pq_certificate: leaves.pq_certificate,
    };

    keep_leaves(ceremony, publish, deposit, registry, &accepted)?;
    deliver(
        ceremony,
        publish,
        deposit,
        Delivering {
            registry,
            vault: &vault,
            opened: &opened,
            accepted: &accepted,
            delivery: &accept.delivery(),
            pin: &pin,
            admit: true,
        },
    )
}

/// Shows what is about to be signed, asks for one key and opens the vault with
/// it. `None` is an abandonment at the prompt, already published; an `Err` has
/// been published as a refusal.
///
/// Shared by the acceptance and its resumption, so the manifest is shown and
/// the key checked the same way before anything is signed.
fn open_for_delivery(
    ceremony: &mut Ceremony,
    presses: &Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    vault: &AuthorityVault,
    manifest: AcceptanceManifest,
) -> Result<Option<astra_operator::authenticator::Opened>, String> {
    // Shown before any key is asked for anything, and it states what the
    // consumption and the leaves will be.
    ceremony.remote = RemoteState::AwaitingOperator;
    ceremony.manifest = Some(AstraManifest::EnrollmentAcceptance(manifest));
    ceremony.gesture = GestureState::AwaitingKey {
        index: 1,
        of: 1,
        purpose: KeyPurpose::OpenVault,
    };
    let offered = ceremony.status();
    publish(offered.clone());

    let Some(key) = open_key(ceremony, presses, publish, &offered)? else {
        return Ok(None);
    };
    let opened = match astra_operator::gestures::open_with_authorized_key(key.as_ref(), vault, "") {
        Ok(opened) => opened,
        Err(error) => {
            ceremony.refuse(Refusal::KeyNotEnrolled);
            publish(ceremony.status());
            return Err(format!("{error:#}"));
        }
    };
    if let Ok(slot) = vault.slot_for_credential(&opened.credential_id) {
        ceremony.keys.push(KeySlotLabel {
            slot: "1".to_string(),
            label: slot.label.clone(),
        });
    }
    ceremony.gesture = GestureState::Signing;
    publish(ceremony.status());
    Ok(Some(opened))
}

/// What steps 4 to 6 work from: the leaves of an accepted request, the opening
/// that may sign, and the gateway they are delivered to.
struct Delivering<'a> {
    registry: &'a InvitationRegistry,
    vault: &'a AuthorityVault,
    opened: &'a astra_operator::authenticator::Opened,
    accepted: &'a AcceptedEnrollment,
    delivery: &'a Delivery<'a>,
    pin: &'a GatewayPin,
    /// False when the gateway already lists the peer.
    admit: bool,
}

/// Steps 4 to 6, from leaves that exist: check them, admit the peer unless it
/// is admitted, sign the document and hand it over.
///
/// The one place both the acceptance and its resumption deliver from, and
/// nothing here issues a leaf: the leaves are an argument.
fn deliver(
    ceremony: &mut Ceremony,
    publish: &mut dyn FnMut(OperatorStatus),
    deposit: &mut dyn FnMut(OperatorArtifact),
    delivering: Delivering<'_>,
) -> Result<(), String> {
    let Delivering {
        registry,
        vault,
        opened,
        accepted,
        delivery,
        pin,
        admit,
    } = delivering;
    if let Err(error) = orion_core::enrollment_draft::check_leaves(
        &accepted.request,
        &accepted.tls_certificate,
        &accepted.pq_certificate,
    ) {
        ceremony.refuse(Refusal::ManifestMismatch);
        publish(ceremony.status());
        return Err(format!("{error:#}"));
    }
    if admit {
        admit_or_stop(
            ceremony,
            publish,
            deposit,
            accepted,
            delivery.gateway,
            pin,
            &read_negotiation,
        )?;
    }

    match sign_delivery(registry, vault, opened, accepted, delivery, pin) {
        Ok(artifact) => {
            deposit(artifact);
            ceremony.gesture = GestureState::Done;
            publish(ceremony.status());
            Ok(())
        }
        Err((refusal, message)) => {
            ceremony.refuse(refusal);
            publish(ceremony.status());
            Err(message)
        }
    }
}

type AdmittedReader<'a> =
    &'a dyn Fn(&str) -> Result<Vec<String>, orion_core::gateway_admin::GatewayAdminError>;

/// Reads the keys of the peers the gateway has admitted, with the Orion client.
fn read_admitted_keys(
    base: &str,
) -> Result<Vec<String>, orion_core::gateway_admin::GatewayAdminError> {
    use orion_core::gateway_admin as admin;
    let client = admin::orion_client()?;
    tauri::async_runtime::block_on(admin::admitted_keys(&client, base))
}

/// What a resumption is made of, once everything that needs no key has been
/// verified.
struct Resuming {
    vault: AuthorityVault,
    accepted: AcceptedEnrollment,
    pin: GatewayPin,
    /// The gateway lists the device's key already: admission is skipped.
    admitted: bool,
    /// Why no gateway can be used: none is connected, or it did not answer.
    /// The resumption then stops before any key.
    gateway_error: Option<(Refusal, String)>,
}

/// Step 5 and 6 again, §15.2: finishes an acceptance whose invitation is
/// consumed and whose leaves are kept, without issuing anything.
///
/// Everything before the key is a refusal that changes nothing. Without a
/// reachable gateway it stops before any key, handing over the leaves kept and
/// the line that admits the peer by hand: the same files the acceptance would
/// have handed over. Otherwise one key signs the document, and the peer is
/// admitted first only when the gateway does not list it.
#[allow(clippy::too_many_arguments)]
fn resume(
    ceremony: &mut Ceremony,
    presses: &Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    deposit: &mut dyn FnMut(OperatorArtifact),
    vault_path: &Path,
    registry: &InvitationRegistry,
    resume: Resume<'_>,
    read: GatewayReader<'_>,
    admitted: AdmittedReader<'_>,
) -> Result<(), String> {
    let resuming = match prepare_resumption(vault_path, registry, &resume, read, admitted) {
        Ok(resuming) => resuming,
        Err((refusal, message)) => {
            ceremony.refuse(refusal);
            publish(ceremony.status());
            return Err(message);
        }
    };
    let Resuming {
        vault,
        accepted,
        pin,
        admitted,
        gateway_error,
    } = resuming;

    if let Some((refusal, message)) = gateway_error {
        return stop_with_leaves(ceremony, publish, deposit, &accepted, refusal, message);
    }

    let request = &accepted.request;
    let manifest = AcceptanceManifest {
        invitation_id: request.invitation_id,
        request_fingerprint: request.fingerprint(),
        requested_name: request.requested_name.clone(),
        client_wg_public_key: request.client_wg_public_key,
        leaves_not_after_unix: accepted.pq_certificate.not_after_unix,
        endpoint: resume.delivery.endpoint.trim().to_string(),
        allowed_ips: resume.delivery.allowed_ips.map(str::to_string),
        ssh_target: resume.delivery.ssh_target.map(str::to_string),
    };
    let Some(opened) = open_for_delivery(ceremony, presses, publish, &vault, manifest)? else {
        return Ok(());
    };
    deliver(
        ceremony,
        publish,
        deposit,
        Delivering {
            registry,
            vault: &vault,
            opened: &opened,
            accepted: &accepted,
            delivery: &resume.delivery,
            pin: &pin,
            admit: !admitted,
        },
    )
}

/// Everything a resumption needs before a key: the kept acceptance, the vault,
/// and what the gateway says. Anything doubtful is a refusal, and the registry
/// has not been written.
fn prepare_resumption(
    vault_path: &Path,
    registry: &InvitationRegistry,
    resume: &Resume<'_>,
    read: GatewayReader<'_>,
    admitted: AdmittedReader<'_>,
) -> Result<Resuming, (Refusal, String)> {
    use astra_operator::enrollment::InvitationState;

    let mismatch = |message: String| (Refusal::HandoffMismatch, message);
    if resume.delivery.endpoint.trim().is_empty() {
        return Err((
            Refusal::ManifestMismatch,
            "l'adresse publique de la gateway est vide".to_string(),
        ));
    }
    let record = registry.load(&resume.invitation_id).map_err(|error| {
        (
            Refusal::InvitationUnknown,
            format!("cette invitation est inconnue de ce poste : {error:#}"),
        )
    })?;
    match &record.state {
        InvitationState::Consumed { .. } => {}
        InvitationState::Issued => {
            return Err((
                Refusal::Internal,
                "cette invitation n'a pas encore été acceptée : il n'y a rien à reprendre"
                    .to_string(),
            ))
        }
        other => {
            return Err((
                Refusal::InvitationExpired,
                format!(
                    "cette invitation est {} : elle n'admet plus aucune reprise",
                    other.label()
                ),
            ))
        }
    }
    let accepted = match registry.accepted(&resume.invitation_id) {
        Ok(Some(accepted)) => accepted,
        Ok(None) => {
            return Err((
                Refusal::AcceptedElsewhere,
                "cette invitation a été acceptée hors d'Orion : ses feuilles ne sont pas ici"
                    .to_string(),
            ))
        }
        Err(error) => return Err((Refusal::Internal, format!("{error:#}"))),
    };
    let vault = astra_operator::store::load(vault_path)
        .map_err(|error| (Refusal::VaultUnavailable, format!("{error:#}")))?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())
        .map_err(|error| mismatch(error.to_string()))?;
    if record.invitation.operator_ca_public_key != ca_pq_public_key {
        return Err(mismatch(
            "cette invitation n'a pas été signée par le CA-PQ de ce coffre".to_string(),
        ));
    }
    // The same pin as the acceptance, checked before a key is touched.
    let pin = GatewayPin::of(&record.invitation);
    let mut peer_admitted = false;
    let gateway_error = match resume.delivery.gateway {
        None => Some((
            Refusal::GatewayUnavailable,
            NO_GATEWAY_CONNECTED.to_string(),
        )),
        Some(base) => match read(base) {
            Ok(material) => {
                pin.check(&material)?;
                // A list that cannot be read is not a reason to skip the
                // admission: the gateway refuses a peer it already holds.
                if let Ok(keys) = admitted(base) {
                    let device = accepted.request.client_wg_public_key.to_base64();
                    peer_admitted = keys.iter().any(|held| held.trim() == device);
                }
                None
            }
            Err(error) => Some((gateway_refusal(&error), error.to_string())),
        },
    };
    Ok(Resuming {
        vault,
        accepted,
        pin,
        admitted: peer_admitted,
        gateway_error,
    })
}

/// Hands over the kept leaves and the line that admits the peer by hand, then
/// stops with the typed refusal.
fn stop_with_leaves(
    ceremony: &mut Ceremony,
    publish: &mut dyn FnMut(OperatorStatus),
    deposit: &mut dyn FnMut(OperatorArtifact),
    accepted: &AcceptedEnrollment,
    refusal: Refusal,
    message: String,
) -> Result<(), String> {
    let handed = hand_over_leaves(deposit, accepted);
    ceremony.refuse(refusal);
    publish(ceremony.status());
    Err(match handed {
        Ok(()) => message,
        Err(second) => format!("{message} ; {second}"),
    })
}

/// Everything that needs no key: the vault and its relay, the request, the
/// invitation it answers. Anything doubtful is a refusal, and the registry has
/// not been written.
fn prepare_acceptance(
    vault_path: &Path,
    registry: &InvitationRegistry,
    accept: &Accept<'_>,
    now: u64,
    read: GatewayReader<'_>,
) -> Result<Accepting, (Refusal, String)> {
    use astra_operator::enrollment::InvitationState;

    let mismatch = |message: String| (Refusal::HandoffMismatch, message);
    let vault = astra_operator::store::load(vault_path)
        .map_err(|error| (Refusal::VaultUnavailable, format!("{error:#}")))?;
    let relay = astra_operator::handoff::DomainHandoff::beside(vault_path, &vault)
        .map_err(|error| mismatch(format!("{error:#}")))?;
    let ca_tls_certificate = relay
        .ca_tls_certificate
        .as_deref()
        .ok_or_else(|| {
            (
                Refusal::CaTlsMissing,
                "le relais de domaine ne porte aucun CA-TLS : l'émission de CA-TLS doit précéder \
                 l'acceptation des demandes"
                    .to_string(),
            )
        })
        .and_then(|encoded| {
            DerCertificate::parse(encoded).map_err(|error| mismatch(error.to_string()))
        })?;

    if accept.endpoint.trim().is_empty() {
        return Err((
            Refusal::ManifestMismatch,
            "l'adresse publique de la gateway est vide".to_string(),
        ));
    }
    let request = decode_request_file(accept.request).map_err(|error| {
        mismatch(format!(
            "ce fichier n'est pas une demande d'enrôlement : {error}"
        ))
    })?;
    let not_after = u64::from(accept.validity_days)
        .checked_mul(DAY_SECS)
        .and_then(|seconds| now.checked_add(seconds))
        .ok_or_else(|| mismatch("durée de validité hors bornes".to_string()))?;

    let record = registry.load(&request.invitation_id).map_err(|error| {
        (
            Refusal::InvitationUnknown,
            format!("cette invitation est inconnue de ce poste : {error:#}"),
        )
    })?;
    let ca_pq_public_key = MlDsa87PublicKey::parse(vault.ca_pq_public_key.trim())
        .map_err(|error| mismatch(error.to_string()))?;
    if record.invitation.operator_ca_public_key != ca_pq_public_key {
        return Err(mismatch(
            "cette invitation n'a pas été signée par le CA-PQ de ce coffre".to_string(),
        ));
    }
    match &record.state {
        InvitationState::Issued => {}
        InvitationState::Consumed { .. } => {
            // Only an acceptance kept here can be resumed: one made outside
            // Orion has no « Reprendre » to point to.
            if !matches!(registry.accepted(&request.invitation_id), Ok(Some(_))) {
                return Err((
                    Refusal::AcceptedElsewhere,
                    "cette invitation a été acceptée hors d'Orion : ses feuilles ne sont pas ici"
                        .to_string(),
                ));
            }
            return Err((
                Refusal::InvitationConsumed,
                "Cette invitation est déjà consommée : la reprendre depuis la liste des \
                 invitations."
                    .to_string(),
            ));
        }
        other => {
            return Err((
                Refusal::InvitationExpired,
                format!(
                    "cette invitation est {} : elle n'admet plus aucune demande",
                    other.label()
                ),
            ))
        }
    }
    if !record.invitation.is_open_at(now) {
        return Err((
            Refusal::InvitationExpired,
            "cette invitation a expiré : en émettre une nouvelle".to_string(),
        ));
    }
    request.verify(&record.invitation).map_err(|error| {
        mismatch(format!(
            "la demande ne correspond pas à cette invitation : {error}"
        ))
    })?;

    // A connected gateway must be the one the invitation names, before a key
    // is touched. One that does not answer is not a reason to refuse: the
    // acceptance then stops after the leaves.
    let pin = GatewayPin::of(&record.invitation);
    if let Some(Ok(material)) = accept.gateway.map(read) {
        pin.check(&material)?;
    }

    Ok(Accepting {
        vault,
        ca_tls_certificate,
        request,
        leaf_validity: (now.saturating_sub(LEAF_BACKDATE_SECS), not_after),
        pin,
    })
}

/// Keeps the accepted request and its leaves beside the invitation, so a
/// gesture interrupted from here on resumes without issuing again.
///
/// A leaf that cannot be kept is still handed over: the operator holds the only
/// copy of public material that cost a consumed invitation.
fn keep_leaves(
    ceremony: &mut Ceremony,
    publish: &mut dyn FnMut(OperatorStatus),
    deposit: &mut dyn FnMut(OperatorArtifact),
    registry: &InvitationRegistry,
    accepted: &AcceptedEnrollment,
) -> Result<(), String> {
    match registry.store_accepted(&accepted.request.invitation_id, accepted) {
        Ok(()) => Ok(()),
        Err(error) => {
            let handed = hand_over_leaves(deposit, accepted);
            ceremony.refuse(Refusal::AcceptanceNotKept);
            publish(ceremony.status());
            Err(match handed {
                Ok(()) => format!(
                    "les feuilles sont émises mais n'ont pas pu être conservées pour la \
                     reprise : {error:#}"
                ),
                Err(second) => format!("{error:#} ; {second}"),
            })
        }
    }
}

const NO_GATEWAY_CONNECTED: &str = "aucune gateway n'est connectée : admettre le pair avec la \
                                    ligne fournie, puis reprendre depuis la liste des invitations";

/// Steps 4 and 5: admits the peer on the connected gateway, or stops after the
/// leaves with the line that admits it by hand.
///
/// `Err` is a stop, already published as a typed refusal (the gateway's, or a
/// pin mismatch), with the reason as the message for the log.
fn admit_or_stop(
    ceremony: &mut Ceremony,
    publish: &mut dyn FnMut(OperatorStatus),
    deposit: &mut dyn FnMut(OperatorArtifact),
    accepted: &AcceptedEnrollment,
    gateway: Option<&str>,
    pin: &GatewayPin,
    read: GatewayReader<'_>,
) -> Result<(), String> {
    use orion_core::gateway_admin as admin;

    let admitted: Result<(), (Refusal, String)> = match gateway {
        None => Err((
            Refusal::GatewayUnavailable,
            NO_GATEWAY_CONNECTED.to_string(),
        )),
        Some(base) => read(base)
            .map_err(|error| (gateway_refusal(&error), error.to_string()))
            .and_then(|material| pin.check(&material))
            .and_then(|()| admission_of(accepted).map_err(|message| (Refusal::Internal, message)))
            .and_then(|admission| {
                admin::orion_client()
                    .and_then(|client| {
                        tauri::async_runtime::block_on(admin::admit_peer(&client, base, &admission))
                    })
                    .map_err(|error| (gateway_refusal(&error), error.to_string()))
            }),
    };
    let Err((refusal, message)) = admitted else {
        return Ok(());
    };
    stop_with_leaves(ceremony, publish, deposit, accepted, refusal, message)
}

/// The admission of the device: a plain peer, never an administrator, held to
/// ML-KEM at least.
fn admission_of(
    accepted: &AcceptedEnrollment,
) -> Result<orion_core::gateway_admin::PeerAdmission, String> {
    let pq = astra_operator::signing::encode_pq_certificate(&accepted.pq_certificate)
        .map_err(|error| format!("{error:#}"))?;
    Ok(orion_core::gateway_admin::PeerAdmission {
        name: accepted.request.requested_name.clone(),
        public_key: accepted.request.client_wg_public_key.to_base64(),
        admin: false,
        minimum_key_negotiation_mode: ProtectionMode::MlKem,
        key_negotiation_certificate: accepted.tls_certificate.to_base64(),
        key_negotiation_pq_certificate: pq,
    })
}

/// Deposits the two leaves and the line that admits the peer by hand. The line
/// names the files deposited, under the names they are saved by.
fn hand_over_leaves(
    deposit: &mut dyn FnMut(OperatorArtifact),
    accepted: &AcceptedEnrollment,
) -> Result<(), String> {
    let stem = accepted.request.request_id.to_hex();
    let tls_name = format!("{stem}-client-cert.der");
    let pq_name = format!("{stem}-client-pq-cert.json");
    let pq = serde_json::to_string_pretty(&accepted.pq_certificate)
        .map_err(|_| "encodage de la feuille PQ".to_string())?;
    let line = astra_operator::admission::admission_command_line(
        &accepted.request.requested_name,
        &accepted.request.client_wg_public_key.to_base64(),
        &tls_name,
        &pq_name,
    );
    deposit(OperatorArtifact {
        file_name: tls_name,
        contents: accepted.tls_certificate.to_base64(),
        encoding: ArtifactEncoding::Base64,
        fingerprint: None,
    });
    deposit(OperatorArtifact {
        file_name: pq_name,
        contents: pq,
        encoding: ArtifactEncoding::Text,
        fingerprint: None,
    });
    deposit(OperatorArtifact {
        file_name: "admission.txt".to_string(),
        contents: format!("{line}\n"),
        encoding: ArtifactEncoding::Text,
        fingerprint: None,
    });
    Ok(())
}

/// Step 6: reads the gateway, builds the device's document and signs it under
/// the opening that issued the leaves. Every failure is a published refusal,
/// and every one is `DocumentNotSigned`: the peer is admitted by now, so the
/// operator resumes rather than admitting again.
fn sign_delivery(
    registry: &InvitationRegistry,
    vault: &AuthorityVault,
    opened: &astra_operator::authenticator::Opened,
    accepted: &AcceptedEnrollment,
    delivery: &Delivery<'_>,
    pin: &GatewayPin,
) -> Result<OperatorArtifact, (Refusal, String)> {
    let not_signed = |error: String| (Refusal::DocumentNotSigned, error);
    let draft = draft_delivery(accepted, delivery, pin)?;
    let request = &accepted.request;
    let signed = astra_operator::signing::sign_document(vault, opened, registry, draft)
        .map_err(|error| not_signed(format!("{error:#}")))?;
    let contents = signed
        .to_json()
        .map_err(|error| not_signed(format!("encodage du document : {error}")))?;
    Ok(OperatorArtifact {
        file_name: document_file_name(&request.requested_name, &request.request_id),
        contents,
        encoding: ArtifactEncoding::Text,
        fingerprint: None,
    })
}

/// The part of step 6 that needs no key: reads the gateway and builds the
/// document Orion will be asked to import. Every failure is `DocumentNotSigned`.
fn draft_delivery(
    accepted: &AcceptedEnrollment,
    delivery: &Delivery<'_>,
    pin: &GatewayPin,
) -> Result<aether::key_negotiation::EnrollmentDocument, (Refusal, String)> {
    use orion_core::enrollment_draft::{build_draft, resolve_negotiation_endpoint, DraftInput};
    use orion_core::gateway_admin as admin;

    let not_signed = |error: String| (Refusal::DocumentNotSigned, error);
    let base = delivery.gateway.ok_or_else(|| {
        not_signed("aucune gateway n'est connectée pour lire sa matière".to_string())
    })?;
    let request = &accepted.request;
    let client = admin::orion_client().map_err(|error| not_signed(error.to_string()))?;
    let (material, admission) = tauri::async_runtime::block_on(admin::gateway_material(
        &client,
        base,
        &request.client_wg_public_key.to_base64(),
    ))
    .map_err(|error| not_signed(error.to_string()))?;
    pin.check(&material)
        .map_err(|(_, message)| not_signed(message))?;
    let negotiation_endpoint =
        resolve_negotiation_endpoint(delivery.endpoint.trim(), None, material.negotiation_port)
            .map_err(|error| not_signed(format!("{error:#}")))?;
    let draft = build_draft(DraftInput {
        request,
        tls_certificate: accepted.tls_certificate.clone(),
        pq_certificate: &accepted.pq_certificate,
        material: &material,
        admission,
        endpoint: delivery.endpoint.trim(),
        negotiation_endpoint,
        allowed_ips: delivery.allowed_ips,
        ssh_target: delivery.ssh_target,
        now_unix: now_unix(),
    })
    .map_err(|error| not_signed(format!("{error:#}")))?;
    // Read as Orion will read it before anyone signs it: a document Orion
    // would refuse must not cost a signature.
    let json = draft
        .to_json()
        .map_err(|error| not_signed(format!("encodage du brouillon : {error}")))?;
    orion_core::parse_profile_import(&json, "draft.orion").map_err(|error| {
        not_signed(format!(
            "le brouillon n'est pas lisible par Orion : {error:#}"
        ))
    })?;
    Ok(draft)
}

/// `<requested_name>.orion` when the name is one a file can safely carry, else
/// `<request_id>.orion`: the name is the device's choice, and the file name is
/// not.
fn document_file_name(requested_name: &str, request_id: &Id16) -> String {
    if super::valid_invitation_name(requested_name) {
        format!("{requested_name}.orion")
    } else {
        format!("{}.orion", request_id.to_hex())
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
        (None, Some(message)) => Err((Refusal::GatewayLeafUnavailable, message)),
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
    match connect_key(press.owner) {
        Ok(key) => Ok(Some(key)),
        Err((refusal, message)) => {
            ceremony.refuse(refusal);
            publish(ceremony.status());
            Err(message)
        }
    }
}

/// Attaches the dialog to the window the press came from, connects the key, and
/// refuses a transport that wants a PIN this process has no way to ask for.
fn connect_key(owner: isize) -> Result<Box<dyn Authenticator>, (Refusal, String)> {
    let owner = dialog_owner(owner).map_err(|error| (Refusal::ForegroundUnavailable, error))?;
    let key = aether_fido::authenticator::connect_owned(
        aether_fido::authenticator::Transport::default(),
        owner,
    )
    .map_err(|error| (Refusal::KeyDeclined, format!("{error:#}")))?;
    // The platform collects the PIN in its own dialog, so it never enters this
    // process. A transport that needs one has no way to ask from here — there
    // is no console — and saying so is better than an empty string that fails
    // three steps later as «clé refusée».
    if key.needs_pin() {
        return Err((
            Refusal::ProtocolViolation,
            "ce transport demande que le PIN soit saisi par le programme, et ce processus n'a \
             aucune interface pour le demander"
                .to_string(),
        ));
    }
    Ok(key)
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
    /// Why the last key was turned down, while another is still being asked for.
    key_retry: Option<Refusal>,
    /// The keys that approved, by the label they validated under.
    approved: Vec<KeySlotLabel>,
    /// When the wait now offered ends by itself.
    idle_until: Option<u64>,
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
            key_retry: None,
            approved: Vec::new(),
            idle_until: None,
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
        status.key_retry = self.key_retry;
        status.approved = self.approved.clone();
        status.idle_until = self.idle_until;
        status
    }

    fn refuse(&mut self, refusal: Refusal) {
        self.gesture = GestureState::Failed;
        self.refusal = Some(refusal);
        self.key_retry = None;
        self.approved.clear();
        self.idle_until = None;
    }

    /// Abandoned by the operator, before anything left this machine.
    ///
    /// A distinct state from a refusal: nothing failed, and an interface that
    /// showed «échec» for a decision would be telling the operator their own
    /// choice went wrong.
    fn cancel(&mut self) {
        self.gesture = GestureState::Cancelled;
        self.refusal = Some(Refusal::Cancelled);
        self.key_retry = None;
        self.approved.clear();
        self.idle_until = None;
    }
}

#[cfg(test)]
mod tests;
