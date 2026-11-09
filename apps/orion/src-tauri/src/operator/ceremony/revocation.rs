//! The revocation of one workstation (F14 lot 5c), run as an operator ceremony.
//!
//! The sequences are [`astra_operator::operations::revocation`]'s; this module puts the
//! cut before them, the touches and the publications between them, and words what they
//! refuse as a [`Refusal`]. The waits are [`super::wait`]'s, shared with the rotations.
//!
//! # Why the cut comes first
//!
//! The gateway's admission is the immediate revocation of reference (spec §5.3): the
//! signed object never delays it. So `Revoke` checks the name and the key against the
//! gateway, then withdraws the admission, and only then calls Astra, the vault or a key.
//! From the cut on, every failure leaves the workstation cut and says so.
//!
//! # What stays here
//!
//! The campaign opened by [`revocation::open`] is held for the length of the approval,
//! and nothing else. It is erased on every exit of the ceremony, like the rotation's
//! openings: [`RevocationRun::run`] clears it whatever the step ended with.

use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::mpsc::Receiver;

use aether::certificates::encoding::{Id16, WireGuardKey};
use aether::certificates::operator_session::{
    AstraManifest, GestureState, KeyPurpose, KeySlotLabel, OperationLocator, OperatorStatus,
    Refusal, RemoteState,
};
use aether_fido::authenticator::Authenticator;
use astra_operator::operations::revocation::{
    self, OpenedRevocation, RevocationDeposit, RevocationReasonChoice, RevocationRefusal,
    RevocationRemote, SignedRevocation,
};
use astra_operator::operations::rotation::KeyStep;
use astra_operator::tunnel::{self, Tunnel, TunnelRefusal};
use orion_core::gateway_admin::{self as admin, AdmittedPeer, GatewayAdminError};

use super::wait::{Ended, Step, Waiting};
use super::{connect_key, gateway_refusal, now_unix, Ceremony, Press};
use crate::operator::{relay_names_peer, GatewayTarget, RevocationGesture};

/// Said when the tunnel leads to a gateway the domain's relay does not name.
const WRONG_GATEWAY: &str = "la gateway jointe n'est pas celle que le relais du domaine désigne";

/// Said when no tunnel is up to the gateway.
const NO_TUNNEL: &str = "aucun tunnel n'est monté vers la gateway";

/// Said when the gateway binds the name to another key, or admits no such name.
const NAME_NOT_THIS_KEY: &str = "la gateway ne lie pas ce nom à cette clé : rien n'a été coupé";

/// What a revocation reaches outside this process, and the time it reads.
struct Reach<'a> {
    remote: &'a dyn RevocationRemote,
    /// The peers the gateway admits, by name and key.
    admitted: &'a dyn Fn(&str) -> Result<Vec<AdmittedPeer>, GatewayAdminError>,
    /// Withdraws the admission of a name: the cut.
    withdraw: &'a dyn Fn(&str, &str) -> Result<(), GatewayAdminError>,
    connect: &'a dyn Fn(isize) -> Result<Box<dyn Authenticator>, (Refusal, String)>,
    now: &'a dyn Fn() -> u64,
}

/// Runs one revocation gesture to its end against the vault at `vault_path`,
/// publishing every state it reaches.
///
/// Called from the ceremony's own thread, which is what lets the tunnel be used with a
/// blocking wait: that thread is not a runtime worker.
pub fn run_revocation(
    session_id: Id16,
    gesture: RevocationGesture,
    gateway: Option<GatewayTarget>,
    presses: Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    vault_path: &Path,
) -> Result<(), String> {
    let tunnel = gateway
        .as_ref()
        .ok_or_else(|| NO_TUNNEL.to_string())
        .and_then(|target| Tunnel::new(&target.address).map_err(|error| format!("{error:#}")));
    let tunnel = match tunnel {
        Ok(tunnel) => tunnel,
        Err(message) => {
            let mut ceremony = Ceremony::new(session_id, locator_of(&gesture));
            publish(ceremony.status());
            ceremony.refuse(Refusal::GatewayUnavailable);
            publish(ceremony.status());
            return Err(message);
        }
    };
    let Some(target) = gateway else {
        return Err(NO_TUNNEL.to_string());
    };
    let reach = Reach {
        remote: &tunnel,
        admitted: &read_admitted,
        withdraw: &withdraw,
        connect: &connect_key,
        now: &now_unix,
    };
    run_with(
        session_id, gesture, &target, presses, publish, vault_path, &reach,
    )
}

fn locator_of(gesture: &RevocationGesture) -> OperationLocator {
    OperationLocator {
        kind: gesture.operation(),
        operation_id: None,
    }
}

/// [`run_revocation`] with what it reaches named, so a test can stand in for the gateway
/// and for Astra.
fn run_with(
    session_id: Id16,
    gesture: RevocationGesture,
    target: &GatewayTarget,
    presses: Receiver<Press>,
    publish: &mut dyn FnMut(OperatorStatus),
    vault_path: &Path,
    reach: &Reach<'_>,
) -> Result<(), String> {
    let mut ceremony = Ceremony::new(session_id, locator_of(&gesture));
    publish(ceremony.status());

    // Before anything is cut, and before any call: the tunnel leads to the domain's
    // gateway, and the workstation named is not this one.
    let mut refuse_first = |ceremony: &mut Ceremony, refusal: Refusal, message: &str| {
        ceremony.refuse(refusal);
        publish(ceremony.status());
        Err(message.to_string())
    };
    let peer = match WireGuardKey::parse(gesture.peer().trim()) {
        Ok(peer) => peer,
        Err(error) => return refuse_first(&mut ceremony, Refusal::Internal, &error.to_string()),
    };
    if !relay_names_peer(vault_path, &target.peer_key).unwrap_or(false) {
        return refuse_first(&mut ceremony, Refusal::HandoffMismatch, WRONG_GATEWAY);
    }
    let own = target
        .own_key
        .as_deref()
        .and_then(|key| WireGuardKey::parse(key.trim()).ok());
    if own == Some(peer) {
        return refuse_first(
            &mut ceremony,
            Refusal::SelfRevocation,
            "ce poste ne peut pas se révoquer lui-même : utiliser `helios peer revoke <nom>` \
             sur la gateway",
        );
    }

    RevocationRun::new(
        &mut ceremony,
        &presses,
        publish,
        vault_path,
        &target.address,
        peer,
        reach,
    )
    .run(&gesture)
}

/// Whether the admission of `name` is the key `peer`, as the gateway binds it.
fn bound_to(admitted: &[AdmittedPeer], name: &str, peer: &WireGuardKey) -> bool {
    admitted.iter().any(|held| {
        held.name == name.trim()
            && WireGuardKey::parse(held.wg_public_key.trim()).ok().as_ref() == Some(peer)
    })
}

/// The reach of a revocation through the ceremony's thread: the waits, the openings it
/// holds, and the calls it makes.
struct RevocationRun<'a> {
    wait: Waiting<'a>,
    vault_path: &'a Path,
    base: &'a str,
    peer: WireGuardKey,
    reach: &'a Reach<'a>,
    /// The campaign under approval, from its opening until its signature.
    held: Option<Box<OpenedRevocation>>,
}

impl<'a> Deref for RevocationRun<'a> {
    type Target = Waiting<'a>;

    fn deref(&self) -> &Waiting<'a> {
        &self.wait
    }
}

impl DerefMut for RevocationRun<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wait
    }
}

impl<'a> RevocationRun<'a> {
    fn new(
        ceremony: &'a mut Ceremony,
        presses: &'a Receiver<Press>,
        publish: &'a mut dyn FnMut(OperatorStatus),
        vault_path: &'a Path,
        base: &'a str,
        peer: WireGuardKey,
        reach: &'a Reach<'a>,
    ) -> Self {
        Self {
            wait: Waiting::new(ceremony, presses, publish, reach.connect, reach.now),
            vault_path,
            base,
            peer,
            reach,
            held: None,
        }
    }

    fn run(&mut self, gesture: &RevocationGesture) -> Result<(), String> {
        let stepped = match gesture {
            RevocationGesture::Revoke { name, reason, .. } => self.revoke(name, *reason),
            RevocationGesture::Resume { reason, .. } => self.resume(*reason),
        };
        // Every exit of the ceremony erases what it held, whatever the step ended with.
        self.held = None;
        match stepped {
            Ok(()) => Ok(()),
            Err(Ended(end)) => end,
        }
    }

    /// The cut, then the campaign, its approval, its signature and its deposit.
    fn revoke(&mut self, name: &str, reason: RevocationReasonChoice) -> Step<()> {
        self.cut(name)?;
        self.sign_and_deposit(reason)
    }

    /// Withdraws the admission of `name`, once the gateway has been asked whose key it is.
    /// Nothing is withdrawn on a name bound to another key.
    fn cut(&mut self, name: &str) -> Step<()> {
        let admitted = (self.reach.admitted)(self.base)
            .map_err(|error| self.refuse(gateway_refusal(&error), error.to_string()))?;
        if !bound_to(&admitted, name, &self.peer) {
            return Err(self.refuse(Refusal::PeerNameMismatch, NAME_NOT_THIS_KEY.to_string()));
        }
        (self.reach.withdraw)(self.base, name.trim()).map_err(|error| {
            let refusal = match error {
                GatewayAdminError::UnknownPeer => Refusal::PeerNameMismatch,
                ref other => gateway_refusal(other),
            };
            self.refuse(refusal, error.to_string())
        })?;
        // The cut stands from here: nothing after it may undo it, and every failure says so.
        self.ceremony.peer_cut = true;
        self.ceremony.gesture = GestureState::Idle;
        self.show();
        Ok(())
    }

    /// Resumes a revocation whose cut is done. A decision on record for this workstation
    /// is deposited again, with no key; another workstation's record stands in the way.
    fn resume(&mut self, reason: RevocationReasonChoice) -> Step<()> {
        let now = self.now();
        let recorded = revocation::pending(self.vault_path, now)
            .map_err(|error| self.refuse(Refusal::Internal, format!("{error:#}")))?;
        match recorded {
            Some(signed) if signed.peer().ok() == Some(self.peer) => self.deposit(&signed),
            Some(_) => Err(self.refuse(
                Refusal::RevocationAwaitsDeposit,
                "une autre révocation attend son dépôt".to_string(),
            )),
            None => self.sign_and_deposit(reason),
        }
    }

    /// Opens the campaign, approves it under the keys it asks for, signs the decision and
    /// deposits it.
    fn sign_and_deposit(&mut self, reason: RevocationReasonChoice) -> Step<()> {
        self.open(reason)?;
        self.approve()?;
        let signed = self.sign()?;
        self.deposit(&signed)
    }

    fn open(&mut self, reason: RevocationReasonChoice) -> Step<()> {
        let now = self.now();
        let opened = revocation::open(self.reach.remote, self.vault_path, &self.peer, reason, now)
            .map_err(|error| self.refuse(refusal_of_open(&error), error.to_string()))?;
        // Shown before the first key: the operator reads what the campaign names.
        self.ceremony.remote = RemoteState::AwaitingOperator;
        self.ceremony.manifest = Some(AstraManifest::Revocation(opened.manifest(now)));
        self.held = Some(Box::new(opened));
        self.show();
        Ok(())
    }

    fn approve(&mut self) -> Step<()> {
        let required = match self.held.as_ref() {
            Some(opened) => opened.required_credentials(),
            None => return Err(self.nothing_held()),
        };
        for index in 1..=required {
            loop {
                let key = self.ask_key(index, required, KeyPurpose::ApproveCampaign)?;
                // Read after the key is reached: the campaign may have died meanwhile.
                let now = self.now();
                let Some(opened) = self.held.as_mut() else {
                    return Err(self.nothing_held());
                };
                match opened.approve(key.as_ref(), now) {
                    Ok(label) => {
                        self.ceremony.approved.push(KeySlotLabel {
                            slot: index.to_string(),
                            label,
                        });
                        self.ceremony.key_retry = None;
                        self.operator_seen();
                        break;
                    }
                    Err(step) => self.turned_down(step)?,
                }
            }
        }
        Ok(())
    }

    fn sign(&mut self) -> Step<SignedRevocation> {
        // The last moment: signing offers no way back.
        self.honour_cancel()?;
        self.ceremony.gesture = GestureState::Signing;
        self.ceremony.idle_until = None;
        self.show();
        let Some(opened) = self.held.take() else {
            return Err(self.nothing_held());
        };
        let now = self.now();
        (*opened)
            .sign_and_record(self.vault_path, now)
            .map_err(|error| {
                let refusal = match error.downcast_ref::<KeyStep>() {
                    Some(KeyStep::Expired) => Refusal::WindowExpired,
                    _ => Refusal::Internal,
                };
                self.refuse(refusal, format!("{error:#}"))
            })
    }

    /// Deposits the decision. Astra may already hold it: that is the same outcome.
    fn deposit(&mut self, signed: &SignedRevocation) -> Step<()> {
        self.ceremony.remote = RemoteState::Prepared;
        self.show();
        match revocation::deposit(self.reach.remote, self.vault_path, signed) {
            Ok(RevocationDeposit::Accepted | RevocationDeposit::AlreadyRevoked) => {
                self.ceremony.remote = RemoteState::Deposited;
                self.done();
                Ok(())
            }
            Err(error) => Err(self.refuse(refusal_of_deposit(&error), format!("{error:#}"))),
        }
    }
}

/// Reads the peers the gateway admits, with the Orion client.
fn read_admitted(base: &str) -> Result<Vec<AdmittedPeer>, GatewayAdminError> {
    let client = admin::orion_client()?;
    tauri::async_runtime::block_on(admin::admitted_peers(&client, base))
}

/// Withdraws the admission of `name`, with the Orion client.
fn withdraw(base: &str, name: &str) -> Result<(), GatewayAdminError> {
    let client = admin::orion_client()?;
    tauri::async_runtime::block_on(admin::revoke_peer(&client, base, name))
}

/// Why Astra did not open the campaign. Each word is one the operator can act on.
fn refusal_of_open(error: &RevocationRefusal) -> Refusal {
    match error {
        RevocationRefusal::AlreadyRevoked => Refusal::PeerAlreadyRevoked,
        RevocationRefusal::AlreadyPending => Refusal::RevocationAwaitsDeposit,
        RevocationRefusal::PeerUnknown | RevocationRefusal::Internal(_) => Refusal::Internal,
        RevocationRefusal::NotBefore(until) => Refusal::RevocationNotBefore { until: *until },
        RevocationRefusal::UnknownAnchor => Refusal::RevocationAnchorUnknown,
        RevocationRefusal::CredentialsUnverified => Refusal::CredentialsUnverified,
        RevocationRefusal::CampaignMismatch => Refusal::CampaignMismatch,
        RevocationRefusal::Unreachable => Refusal::AuthorityUnreachable,
    }
}

/// Whose word a failed deposit is follows from what answered: nothing answered or a 503
/// is Astra unreachable; another refusal is Astra's, carried by its status alone, since
/// a refusal carries no text; anything else is this code's own.
fn refusal_of_deposit(error: &anyhow::Error) -> Refusal {
    if tunnel::is_unreachable(error) {
        return Refusal::AuthorityUnreachable;
    }
    match error.downcast_ref::<TunnelRefusal>() {
        Some(refused) if refused.status == 503 => Refusal::AuthorityUnreachable,
        Some(refused) => Refusal::AuthorityRefused {
            status: refused.status,
        },
        None => Refusal::Internal,
    }
}

#[cfg(test)]
mod tests;
