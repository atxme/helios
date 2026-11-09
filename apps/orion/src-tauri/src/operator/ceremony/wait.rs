//! The waits of an operator ceremony (F14 lot 5b, reused by lot 5c): the keys it asks
//! for, the presses it reads, and the clocks that bound both.
//!
//! # What stays out of here
//!
//! A [`Waiting`] holds no opening. The ceremony that owns the openings erases them on
//! every exit, whatever the wait ended with, so the waits never decide that.

use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::{Duration, Instant};

use aether::certificates::operator_session::{
    GestureState, KeyPurpose, OperatorAction, OperatorStatus, Refusal,
};
use aether_fido::authenticator::Authenticator;
use astra_operator::operations::rotation::KeyStep;

use super::{Ceremony, Press};

/// How long an opening is kept for an operator who answers nothing.
pub const VALIDATION_IDLE_SECS: u64 = 300;

/// How often a wait looks at the clock: nothing else would end it, with no press.
pub(super) const WAIT_TICK: Duration = Duration::from_secs(1);

/// How long one wait for the operator may last.
///
/// Both clocks count: the wall clock goes on through a machine asleep, and the
/// monotonic one is not fooled by a wall clock set back.
pub(super) struct Patience {
    pub(super) since: u64,
    pub(super) started: Instant,
    /// The end of the campaign being approved, when one is open.
    pub(super) until: Option<u64>,
}

impl Patience {
    /// When the wait ends if nobody answers: the idle bound, or the campaign's end.
    pub(super) fn ends_at(&self) -> u64 {
        let idle = self.since.saturating_add(VALIDATION_IDLE_SECS);
        self.until.map_or(idle, |until| idle.min(until))
    }

    pub(super) fn is_over(&self, now: u64) -> bool {
        now.saturating_sub(self.since) >= VALIDATION_IDLE_SECS
            || self.started.elapsed() >= Duration::from_secs(VALIDATION_IDLE_SECS)
            || self.until.is_some_and(|until| now >= until)
    }
}

/// A ceremony over before the end of its steps, already published as such.
pub(super) struct Ended(pub(super) Result<(), String>);

pub(super) type Step<T> = Result<T, Ended>;

pub(super) fn answers_the_screen(status: &OperatorStatus, press: &Press) -> bool {
    status.accepts(press.action, press.revision)
}

/// The approval screen offers only Cancel in `allowed`: the terms have a command of
/// their own, which is the one way a press there carries them.
pub(super) fn answers_the_terms(status: &OperatorStatus, press: &Press) -> bool {
    press.revision == status.revision
        && (press.action == OperatorAction::Cancel
            || (press.action == OperatorAction::Continue && press.terms.is_some()))
}

/// What a ceremony waits on the operator for, and when that wait gives up.
pub(super) struct Waiting<'a> {
    pub(super) ceremony: &'a mut Ceremony,
    pub(super) presses: &'a Receiver<Press>,
    pub(super) publish: &'a mut dyn FnMut(OperatorStatus),
    /// Connects the key a press names.
    pub(super) connect: &'a dyn Fn(isize) -> Result<Box<dyn Authenticator>, (Refusal, String)>,
    /// The wall clock, read for every bound.
    pub(super) clock: &'a dyn Fn() -> u64,
    /// The end of the campaign being approved, when one is open.
    pub(super) until: Option<u64>,
    /// When the operator was last shown to be there, on both clocks.
    pub(super) last_seen: Option<(u64, Instant)>,
}

impl<'a> Waiting<'a> {
    pub(super) fn new(
        ceremony: &'a mut Ceremony,
        presses: &'a Receiver<Press>,
        publish: &'a mut dyn FnMut(OperatorStatus),
        connect: &'a dyn Fn(isize) -> Result<Box<dyn Authenticator>, (Refusal, String)>,
        clock: &'a dyn Fn() -> u64,
    ) -> Self {
        Self {
            ceremony,
            presses,
            publish,
            connect,
            clock,
            until: None,
            last_seen: None,
        }
    }
}

impl Waiting<'_> {
    /// Offers a key and connects it once the operator presses. A key out of reach
    /// costs nothing that was already validated, so it asks again rather than ending.
    pub(super) fn ask_key(
        &mut self,
        index: u8,
        of: u8,
        purpose: KeyPurpose,
    ) -> Step<Box<dyn Authenticator>> {
        loop {
            self.honour_cancel()?;
            self.ceremony.gesture = GestureState::AwaitingKey { index, of, purpose };
            let patience = self.patience();
            self.ceremony.idle_until = Some(patience.ends_at());
            let offered = self.show();
            let press = self.await_press(&offered, &patience, answers_the_screen)?;

            self.ceremony.key_retry = None;
            self.ceremony.gesture = GestureState::ProcessingKey { index, of };
            self.show();
            match (self.connect)(press.owner) {
                Ok(key) => return Ok(key),
                Err((
                    refusal @ (Refusal::KeyDeclined | Refusal::ForegroundUnavailable),
                    message,
                )) => {
                    tracing::warn!(error = %message, "clé de sécurité injoignable");
                    self.ceremony.key_retry = Some(refusal);
                }
                Err((refusal, message)) => return Err(self.refuse(refusal, message)),
            }
        }
    }

    /// A key that answered and cannot be used is asked for again, except once the
    /// campaign is dead, which no key changes.
    pub(super) fn turned_down(&mut self, step: KeyStep) -> Step<()> {
        let retry = match step {
            KeyStep::NotEnrolled => Refusal::KeyNotEnrolled,
            KeyStep::NotApprovable => Refusal::SignerRevoked,
            KeyStep::Repeated => Refusal::KeyRepeated,
            KeyStep::NotValidated => Refusal::KeyNotValidated,
            KeyStep::Declined => Refusal::KeyDeclined,
            KeyStep::Expired => {
                return Err(self.refuse(Refusal::WindowExpired, step.to_string()));
            }
        };
        self.ceremony.key_retry = Some(retry);
        Ok(())
    }

    /// Reads what came in while this thread was busy, before the screen it was busy on
    /// is left. That screen offered Cancel, and the next one has a revision of its own
    /// that would lose it. Run before anything is published: the revision is that
    /// screen's. Anything else in the queue answers a screen already gone.
    pub(super) fn honour_cancel(&mut self) -> Step<()> {
        let left = self.ceremony.revision;
        loop {
            match self.presses.try_recv() {
                Ok(press) if press.action == OperatorAction::Cancel && press.revision == left => {
                    return Err(self.cancel());
                }
                Ok(_) => {}
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => return Err(self.cancel()),
            }
        }
    }

    /// Waits for the operator's answer to one status, for as long as `patience` allows.
    ///
    /// A press `takes` does not want answers a screen already left, and is ignored.
    /// Every sender gone means the window holding the ceremony was closed.
    pub(super) fn await_press(
        &mut self,
        offered: &OperatorStatus,
        patience: &Patience,
        takes: fn(&OperatorStatus, &Press) -> bool,
    ) -> Step<Press> {
        loop {
            if patience.is_over(self.now()) {
                return Err(self.expired());
            }
            match self.presses.recv_timeout(WAIT_TICK) {
                Ok(press) if takes(offered, &press) => {
                    if press.action == OperatorAction::Cancel {
                        return Err(self.cancel());
                    }
                    // Past the bound, a press in the queue opens nothing.
                    if patience.is_over(self.now()) {
                        return Err(self.expired());
                    }
                    self.operator_seen();
                    return Ok(press);
                }
                Ok(_) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(self.cancel()),
            }
        }
    }

    /// A press, or a touch that went through. Not a dialog that timed out nor a key
    /// turned down, which show nobody.
    pub(super) fn operator_seen(&mut self) {
        self.last_seen = Some((self.now(), Instant::now()));
    }

    /// Counted from when the operator was last seen rather than from this offer, so a
    /// dialog that timed out with nobody there buys no more time. Taken before the
    /// status it bounds is published, for the first wait, which begins as it is offered.
    pub(super) fn patience(&self) -> Patience {
        let (since, started) = self
            .last_seen
            .unwrap_or_else(|| (self.now(), Instant::now()));
        Patience {
            since,
            started,
            until: self.until,
        }
    }

    pub(super) fn now(&self) -> u64 {
        (self.clock)()
    }

    pub(super) fn show(&mut self) -> OperatorStatus {
        let status = self.ceremony.status();
        (self.publish)(status.clone());
        status
    }

    pub(super) fn expired(&mut self) -> Ended {
        self.refuse(
            Refusal::WindowExpired,
            "aucune réponse dans le délai : les ouvertures sont effacées".to_string(),
        )
    }

    /// An opening a step needed was gone: this code's own contradiction.
    pub(super) fn nothing_held(&mut self) -> Ended {
        self.refuse(
            Refusal::Internal,
            "aucune ouverture n'est détenue à cette étape de la cérémonie".to_string(),
        )
    }

    pub(super) fn refuse(&mut self, refusal: Refusal, message: String) -> Ended {
        self.ceremony.keys.clear();
        self.ceremony.refuse(refusal);
        self.show();
        Ended(Err(message))
    }

    pub(super) fn cancel(&mut self) -> Ended {
        self.ceremony.keys.clear();
        self.ceremony.cancel();
        self.show();
        Ended(Ok(()))
    }

    pub(super) fn done(&mut self) {
        self.ceremony.gesture = GestureState::Done;
        self.ceremony.idle_until = None;
        self.show();
    }
}
