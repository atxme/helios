//! Orion's side of an operator ceremony (ADR-008 §9.4, §8.5, §7.5).
//!
//! # What runs here, and what does not cross a boundary
//!
//! The ceremony runs in a thread of this process, see [`ceremony`]. The
//! authority vault, the key gesture and every signature are reached from that
//! thread and nowhere else in the WebView's reach. F11 de-elevates this
//! process, and the ceremony does not depend on its token: the vault and the
//! key are opened by the same code whatever level the process holds.
//!
//! # What crosses
//!
//! Only [`OperatorStatus`] outward, through a `watch` channel, and a [`Press`]
//! inward, through a `mpsc` channel. A status carries two states, a typed
//! manifest, the labels of the key-slots that answered. A press carries an
//! action, the revision it answers and the window it came from. No PIN, no
//! assertion, no vault byte crosses either way. The WebView therefore renders
//! progress it cannot influence, and the refusals stay where the secrets are.
//!
//! # Files
//!
//! A ceremony that produces a file — an invitation — deposits it in its
//! session, and the window fetches it once with [`OperatorCeremony::artifacts`]
//! and saves it. It never rides the status.
//!
//! # Why the WebView names so little
//!
//! An [`OperationLocator`] — a kind, and at most an operation identifier Orion
//! itself opened. The authority origin, the RP ID, the domain and the service
//! key come from the hand-off pinned beside the vault. A WebView that sends a
//! press therefore buys the ability to answer a ceremony the operator started;
//! it does not buy the ability to choose one.

mod ceremony;

use std::time::Duration;

use aether::certificates::encoding::Id16;
use aether::certificates::operator_session::{
    GestureState, OperationKind, OperationLocator, OperatorAction, OperatorStatus, Refusal,
    RemoteState,
};
use ceremony::Press;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::{watch, Mutex};

/// How long a step may take before Orion stops waiting for the next state.
///
/// The steps that hold on a human — finding a key, touching it — are not
/// bounded here: the ceremony publishes a state of its own the moment it starts
/// working on them. This bounds the fetching and the signing between two such
/// states.
const STEP_TIMEOUT: Duration = Duration::from_secs(90);

/// Said when the ceremony stopped answering within [`STEP_TIMEOUT`].
const NOT_ANSWERING: &str = "la cérémonie opérateur ne répond plus";
/// Said when the ceremony's thread ended before the step it was asked for.
const STOPPED: &str = "la cérémonie opérateur s'est arrêtée";

/// Longest name an invitation file may carry.
const MAX_INVITATION_NAME: usize = 64;

/// A gesture of the enrollment ceremonies (§15.2), as the WebView names it.
///
/// Typed and closed: the page chooses among these three and fills their
/// parameters, and every value is validated here before a ceremony opens. A
/// file the operator picked travels by its public content only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "gesture", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollmentGesture {
    /// Signs an invitation aimed at the connected gateway.
    Invite {
        /// 1 to 24: an invitation is a short window, not a standing right.
        #[serde(deserialize_with = "invitation_hours")]
        valid_for_hours: u8,
        allow_readmission: bool,
        /// Becomes `<name>.helios-invite`; see [`valid_invitation_name`].
        name: String,
        /// The contents of the gateway's leaf, read from a file the operator
        /// chose, when no gateway is connected to read it from.
        #[serde(default)]
        gateway_pq_certificate: Option<String>,
    },
    /// Verifies a request, consumes its invitation, then issues the leaves.
    Accept {
        request: String,
        /// 1 to 1825 days; a year when absent.
        #[serde(default = "default_validity_days", deserialize_with = "validity_days")]
        validity_days: u16,
        endpoint: String,
        #[serde(default)]
        allowed_ips: Option<String>,
        #[serde(default)]
        ssh_target: Option<String>,
    },
    /// Finishes an acceptance whose leaves were issued but not delivered.
    Resume {
        invitation_id: Id16,
        endpoint: String,
        #[serde(default)]
        allowed_ips: Option<String>,
        #[serde(default)]
        ssh_target: Option<String>,
    },
}

fn default_validity_days() -> u16 {
    365
}

fn invitation_hours<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
    let hours = u8::deserialize(deserializer)?;
    if (1..=24).contains(&hours) {
        Ok(hours)
    } else {
        Err(serde::de::Error::custom(
            "une invitation dure entre 1 et 24 heures",
        ))
    }
}

fn validity_days<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
    let days = u16::deserialize(deserializer)?;
    if (1..=1825).contains(&days) {
        Ok(days)
    } else {
        Err(serde::de::Error::custom(
            "la validité des feuilles est de 1 à 1825 jours",
        ))
    }
}

/// `[A-Za-z0-9._-]{1,64}`: the name ends up in a file name the WebView will
/// save, so nothing that could walk out of a folder or hide is accepted.
fn valid_invitation_name(name: &str) -> bool {
    (1..=MAX_INVITATION_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

impl EnrollmentGesture {
    /// Refuses what no ceremony should be opened for.
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Invite { name, .. } if !valid_invitation_name(name) => Err(
                "le nom de l'invitation tient en 1 à 64 caractères parmi lettres, chiffres, \
                 « . », « _ » et « - »"
                    .to_string(),
            ),
            _ => Ok(()),
        }
    }

    fn operation(&self) -> aether::certificates::operator_session::OperationKind {
        use aether::certificates::operator_session::OperationKind;
        match self {
            Self::Invite { .. } => OperationKind::InviteEnrollment,
            Self::Accept { .. } | Self::Resume { .. } => OperationKind::AcceptEnrollment,
        }
    }
}

/// A file the ceremony produced, for the WebView to save.
///
/// Public content only (an invitation, an issued leaf). It is kept out of the
/// status, which every poll carries, and fetched once by the screen that saves
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperatorArtifact {
    pub file_name: String,
    pub contents: String,
}

/// The files of one session, written by its ceremony and read by the window.
type Artifacts = std::sync::Arc<std::sync::Mutex<Vec<OperatorArtifact>>>;

/// Keeps a produced file for the window.
///
/// A poisoned lock is recovered, not skipped: the list holds plain values, and
/// dropping here would lose an invitation already signed and recorded.
fn deposit(artifacts: &Artifacts, artifact: OperatorArtifact) {
    artifacts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(artifact);
}

/// The live ceremony, for as long as one is open.
struct Session {
    presses: std::sync::mpsc::Sender<Press>,
    status: watch::Receiver<OperatorStatus>,
    artifacts: Artifacts,
}

/// The one ceremony Orion hosts at a time.
///
/// A second concurrent ceremony is refused rather than queued. Two of them
/// would open the vault twice against one domain, and — for the two that
/// consume an operation — each would spend an approval the other is still
/// counting on.
#[derive(Default)]
pub struct OperatorCeremony(Mutex<Option<Session>>);

impl OperatorCeremony {
    /// The last state the ceremony published, or `None` when none ran.
    ///
    /// `None` rather than a synthetic «idle» status: there is no session, so
    /// there is no revision, and inventing one would give the WebView a number
    /// it could send back.
    pub async fn status(&self) -> Option<OperatorStatus> {
        self.0
            .lock()
            .await
            .as_mut()
            .map(|session| session.status.borrow_and_update().clone())
    }

    /// Starts the ceremony in its own thread and returns the first state it
    /// publishes.
    pub async fn begin(&self, locator: OperationLocator) -> Result<OperatorStatus, String> {
        self.open(
            locator.kind,
            move |session_id, presses, publish, _artifacts| {
                ceremony::run(session_id, locator, presses, publish)
            },
        )
        .await
    }

    /// Starts an enrollment gesture the same way, under the same rule of one
    /// ceremony at a time.
    ///
    /// `gateway` is the control-plane address of the connected profile, read by
    /// the caller from the engine, or `None` when no tunnel is up.
    pub async fn begin_enrollment(
        &self,
        gesture: EnrollmentGesture,
        gateway: Option<String>,
    ) -> Result<OperatorStatus, String> {
        gesture.validate()?;
        let kind = gesture.operation();
        self.open(kind, move |session_id, presses, publish, artifacts| {
            ceremony::run_enrollment(
                session_id,
                gesture,
                gateway,
                presses,
                publish,
                &mut |artifact| deposit(artifacts, artifact),
            )
        })
        .await
    }

    /// The files the current session produced, or none.
    pub async fn artifacts(&self) -> Vec<OperatorArtifact> {
        match self.0.lock().await.as_ref() {
            Some(session) => session
                .artifacts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            None => Vec::new(),
        }
    }

    async fn open<F>(&self, kind: OperationKind, run: F) -> Result<OperatorStatus, String>
    where
        F: FnOnce(
                Id16,
                std::sync::mpsc::Receiver<Press>,
                &mut dyn FnMut(OperatorStatus),
                &Artifacts,
            ) -> Result<(), String>
            + Send
            + 'static,
    {
        let mut held = self.0.lock().await;
        if let Some(session) = held.as_mut() {
            let current = session.status.borrow_and_update().clone();
            if !current.gesture.is_terminal() {
                return Err(
                    "une cérémonie opérateur est déjà ouverte : la mener à son terme ou \
                     l'annuler avant d'en ouvrir une autre"
                        .to_string(),
                );
            }
        }
        *held = None;

        let session_id = Id16::new(
            *aether::random::secret_bytes::<16>()
                .map_err(|error| format!("tirage de l'identifiant de session : {error}"))?,
        )
        .map_err(|error| format!("identifiant de session : {error}"))?;
        let (publisher, status) = watch::channel(OperatorStatus::new(
            session_id,
            0,
            kind,
            RemoteState::Local,
            GestureState::Verifying,
        ));
        let (presses, received) = std::sync::mpsc::channel();
        let artifacts = Artifacts::default();
        let produced = artifacts.clone();

        // Its own thread, with the stack the vault and the signatures need: the
        // default stack of a runtime worker does not hold their post-quantum
        // computations.
        std::thread::Builder::new()
            .name("orion-operator-ceremony".into())
            .stack_size(astra_operator::WORK_STACK_BYTES)
            .spawn(move || {
                let final_status = FinalStatus::new(publisher);
                let outcome = run(
                    session_id,
                    received,
                    &mut |state| final_status.publish(state),
                    &produced,
                );
                if let Err(message) = &outcome {
                    tracing::warn!(error = %message, "cérémonie opérateur interrompue");
                }
                outcome
            })
            .map_err(|error| format!("démarrage de la cérémonie opérateur : {error}"))?;

        // Held before its first state is awaited: a ceremony that is slow to
        // speak is still running, and a second `begin` must find it here and
        // refuse rather than open the vault a second time beside it.
        let session = held.insert(Session {
            presses,
            status,
            artifacts,
        });
        awaited(&mut session.status).await
    }

    /// Takes the next step of the open ceremony.
    ///
    /// `revision` names the status the operator was looking at. Both ends
    /// check it: this one because it is the surface that offered the button,
    /// the ceremony because it is the one that would act on it. `owner` is the
    /// window the press came from, and the dialog of a key belongs to it.
    pub async fn advance(
        &self,
        action: OperatorAction,
        revision: u64,
        owner: isize,
    ) -> Result<OperatorStatus, String> {
        let mut held = self.0.lock().await;
        let session = held
            .as_mut()
            .ok_or_else(|| "aucune cérémonie opérateur n'est ouverte".to_string())?;

        let current = session.status.borrow_and_update().clone();
        if !current.accepts(action, revision) {
            return Err(
                "cette étape n'accepte pas cette action : l'écran a changé depuis la pression"
                    .to_string(),
            );
        }

        session
            .presses
            .send(Press {
                action,
                revision,
                owner,
            })
            .map_err(|_| STOPPED.to_string())?;
        awaited(&mut session.status).await
    }

    /// Forgets a completed session after its final state has been shown.
    /// A live session cannot be dismissed: dropping its press channel would
    /// look like cancellation even after the ceremony crossed the point where
    /// cancellation is honest.
    pub async fn dismiss(&self) -> Result<(), String> {
        let mut held = self.0.lock().await;
        if let Some(session) = held.as_mut() {
            let current = session.status.borrow_and_update().clone();
            if !current.gesture.is_terminal() {
                return Err("la cérémonie opérateur est encore en cours".to_string());
            }
        }
        *held = None;
        Ok(())
    }
}

/// Publishes the end of a ceremony that stopped without one.
///
/// Owned by the ceremony's thread, so whatever ends that thread — a return, a
/// refusal, a panic — runs this destructor. A ceremony that stops short of a
/// terminal state would otherwise leave the operator on its last hopeful
/// screen, waiting on a «signature en cours» nothing is performing.
struct FinalStatus {
    publisher: watch::Sender<OperatorStatus>,
}

impl FinalStatus {
    fn new(publisher: watch::Sender<OperatorStatus>) -> Self {
        Self { publisher }
    }

    fn publish(&self, status: OperatorStatus) {
        self.publisher.send_replace(status);
    }
}

impl Drop for FinalStatus {
    fn drop(&mut self) {
        let last = self.publisher.borrow().clone();
        if last.gesture.is_terminal() {
            return;
        }
        let mut failed = OperatorStatus::new(
            last.session_id,
            last.revision + 1,
            last.operation,
            last.remote,
            GestureState::Failed,
        );
        failed.operation_id = last.operation_id;
        failed.refusal = Some(Refusal::Internal);
        self.publisher.send_replace(failed);
    }
}

/// Waits for the next state the ceremony publishes.
async fn awaited(status: &mut watch::Receiver<OperatorStatus>) -> Result<OperatorStatus, String> {
    tokio::time::timeout(STEP_TIMEOUT, status.changed())
        .await
        .map_err(|_| NOT_ANSWERING.to_string())?
        .map_err(|_| STOPPED.to_string())?;
    Ok(status.borrow_and_update().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::operator_session::{KeyPurpose, OperationKind};

    fn session() -> Id16 {
        Id16::new([4; 16]).expect("id")
    }

    /// The button is offered and refused from the same value, so a WebView
    /// that invented one gains nothing.
    #[tokio::test]
    async fn a_ceremony_that_never_started_accepts_nothing() {
        let ceremony = OperatorCeremony::default();
        assert!(ceremony.status().await.is_none());
        assert!(ceremony
            .advance(OperatorAction::Continue, 1, 0)
            .await
            .is_err());
    }

    /// A press on a screen the ceremony has already left must not be applied to
    /// whatever replaced it, and Orion refuses it before it reaches the wire.
    #[test]
    fn a_stale_revision_is_not_accepted() {
        let status = OperatorStatus::new(
            session(),
            9,
            OperationKind::RecoverIdentity,
            RemoteState::AwaitingOperator,
            GestureState::AwaitingKey {
                index: 1,
                of: 1,
                purpose: KeyPurpose::OpenVault,
            },
        );
        assert!(status.accepts(OperatorAction::Continue, 9));
        assert!(!status.accepts(OperatorAction::Continue, 8));
    }

    /// Once the signed objects have left, «Annuler» would promise something
    /// this side cannot deliver — and the surface must not offer it either.
    #[test]
    fn nothing_is_cancellable_past_the_deposit() {
        let status = OperatorStatus::new(
            session(),
            2,
            OperationKind::RecoverIdentity,
            RemoteState::Staged,
            GestureState::Idle,
        );
        assert!(!status.accepts(OperatorAction::Cancel, 2));
    }

    /// A ceremony that stops short of a terminal state must not leave the
    /// operator on its last hopeful screen: the guard says it failed, one
    /// revision on.
    #[test]
    fn a_ceremony_that_stops_short_is_reported_failed() {
        let (publisher, observed) = watch::channel(OperatorStatus::new(
            session(),
            3,
            OperationKind::RecoverIdentity,
            RemoteState::AwaitingOperator,
            GestureState::AwaitingKey {
                index: 1,
                of: 1,
                purpose: KeyPurpose::OpenVault,
            },
        ));
        drop(FinalStatus::new(publisher));
        let last = observed.borrow().clone();
        assert_eq!(last.gesture, GestureState::Failed);
        assert_eq!(last.refusal, Some(Refusal::Internal));
        assert_eq!(last.revision, 4);
    }

    /// A ceremony that ended on its own terms is left as it ended.
    #[test]
    fn a_finished_ceremony_is_left_as_it_ended() {
        let (publisher, observed) = watch::channel(OperatorStatus::new(
            session(),
            5,
            OperationKind::RecoverIdentity,
            RemoteState::Staged,
            GestureState::Done,
        ));
        drop(FinalStatus::new(publisher));
        let last = observed.borrow().clone();
        assert_eq!(last.gesture, GestureState::Done);
        assert_eq!(last.refusal, None);
        assert_eq!(last.revision, 5);
    }

    fn gesture(json: &str) -> Result<EnrollmentGesture, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// The window is a day at most, and it is refused on arrival: a value out
    /// of range never reaches the ceremony.
    #[test]
    fn an_invitation_lasts_at_most_a_day() {
        let invite = |hours: u32| {
            gesture(&format!(
                r#"{{"gesture":"invite","valid_for_hours":{hours},"allow_readmission":false,"name":"laptop"}}"#
            ))
        };
        assert!(invite(24).is_ok());
        assert!(invite(1).is_ok());
        assert!(invite(25).is_err());
        assert!(invite(0).is_err());
        assert!(gesture(
            r#"{"gesture":"invite","valid_for_hours":2,"allow_readmission":false,"name":"a","extra":1}"#
        )
        .is_err());
    }

    /// The acceptance window is bounded the same way, with a year by default.
    #[test]
    fn an_acceptance_lasts_at_most_five_years() {
        let accept = |extra: &str| {
            gesture(&format!(
                r#"{{"gesture":"accept","request":"r","endpoint":"gw:51820"{extra}}}"#
            ))
        };
        match accept("") {
            Ok(EnrollmentGesture::Accept { validity_days, .. }) => assert_eq!(validity_days, 365),
            other => panic!("{other:?}"),
        }
        assert!(accept(r#","validity_days":1825"#).is_ok());
        assert!(accept(r#","validity_days":1826"#).is_err());
        assert!(accept(r#","validity_days":0"#).is_err());
    }

    /// The name becomes a file name: only the documented alphabet and length.
    #[tokio::test]
    async fn a_bad_invitation_name_is_refused() {
        let ceremony = OperatorCeremony::default();
        let too_long = "a".repeat(65);
        for name in ["", "a/b", "a b", "..\\x", "é", "a\n", too_long.as_str()] {
            let refused = ceremony
                .begin_enrollment(
                    EnrollmentGesture::Invite {
                        valid_for_hours: 2,
                        allow_readmission: false,
                        name: name.to_string(),
                        gateway_pq_certificate: None,
                    },
                    None,
                )
                .await;
            assert!(refused.is_err(), "{name:?}");
        }
        assert!(ceremony.status().await.is_none());
        for name in ["laptop", "a.b_c-D9", &"a".repeat(64)] {
            assert!(valid_invitation_name(name), "{name:?}");
        }
    }

    /// An artifact belongs to a session: without one there is nothing to hand.
    #[tokio::test]
    async fn artifacts_are_empty_without_a_session() {
        assert!(OperatorCeremony::default().artifacts().await.is_empty());
    }

    /// A thread that panicked holding the list must not cost the operator an
    /// invitation that is already signed and recorded.
    #[test]
    fn a_poisoned_artifact_list_still_keeps_the_invitation() {
        let artifacts = Artifacts::default();
        let poisoner = artifacts.clone();
        let _ = std::thread::spawn(move || {
            let _held = poisoner.lock().expect("lock");
            panic!("poisoning on purpose");
        })
        .join();
        assert!(artifacts.is_poisoned());
        deposit(
            &artifacts,
            OperatorArtifact {
                file_name: "a.helios-invite".into(),
                contents: "x".into(),
            },
        );
        let held = artifacts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(held.len(), 1);
    }
}
