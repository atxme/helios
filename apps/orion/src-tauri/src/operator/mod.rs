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
    GestureState, OperationLocator, OperatorAction, OperatorStatus, Refusal, RemoteState,
};
use ceremony::Press;
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

/// The live ceremony, for as long as one is open.
struct Session {
    presses: std::sync::mpsc::Sender<Press>,
    status: watch::Receiver<OperatorStatus>,
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

        let kind = locator.kind;
        let session_id = Id16::new(
            *aether::random::secret_bytes::<16>()
                .map_err(|error| format!("tirage de l'identifiant de session : {error}"))?,
        )
        .map_err(|error| format!("identifiant de session : {error}"))?;
        let (publisher, mut status) = watch::channel(OperatorStatus::new(
            session_id,
            0,
            kind,
            RemoteState::Local,
            GestureState::Verifying,
        ));
        let (presses, received) = std::sync::mpsc::channel();

        // Its own thread, with the stack the vault and the signatures need: the
        // default stack of a runtime worker does not hold their post-quantum
        // computations.
        std::thread::Builder::new()
            .name("orion-operator-ceremony".into())
            .stack_size(astra_operator::WORK_STACK_BYTES)
            .spawn(move || {
                let final_status = FinalStatus::new(publisher);
                let outcome = ceremony::run(session_id, locator, received, &mut |state| {
                    final_status.publish(state)
                });
                if let Err(message) = &outcome {
                    tracing::warn!(error = %message, "cérémonie opérateur interrompue");
                }
                outcome
            })
            .map_err(|error| format!("démarrage de la cérémonie opérateur : {error}"))?;

        let first = awaited(&mut status).await?;
        *held = Some(Session { presses, status });
        Ok(first)
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
}
