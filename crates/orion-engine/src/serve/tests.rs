use super::*;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aether::TunnelState;
use orion_core::events::ClientEvent;
use tokio::io::{AsyncWriteExt, BufReader, DuplexStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::command::EngineCommand;
use crate::events::EVENT_QUEUE;
use crate::session::SessionRefusal;
use crate::wire::{read_frame, write_frame, Hello, PROTOCOL_VERSION};

/// Pipe that never fills in these tests: the client reads everything.
const PIPE: usize = 64 * 1024;
/// Pipe that fills after a few events, for a client that stops reading.
const SMALL_PIPE: usize = 4 * 1024;
const WAIT: Duration = Duration::from_secs(10);

/// Engine double. Each command does the one thing a test needs; teardowns are counted.
#[derive(Default)]
struct Fake {
    teardowns: AtomicUsize,
    release: Notify,
    flood_done: Notify,
    flood_took: Mutex<Duration>,
    overflow_seen: AtomicBool,
    in_flight: AtomicUsize,
    in_flight_at_teardown: AtomicUsize,
    entered: Notify,
    gate: Notify,
    late: AtomicBool,
}

/// Counts a command as running from its first poll until it is dropped, so an
/// aborted command counts as stopped only once its future is really gone.
struct Running<'a>(&'a Fake);

impl<'a> Running<'a> {
    fn enter(fake: &'a Fake) -> Self {
        fake.in_flight.fetch_add(1, Ordering::SeqCst);
        fake.entered.notify_one();
        Self(fake)
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

fn telemetry() -> ClientEvent {
    ClientEvent::Telemetry {
        iface: "wg0".into(),
        rx_bps: 1,
        tx_bps: 2,
        rx_pps: 3,
        tx_pps: 4,
    }
}

#[async_trait::async_trait]
impl Engine for Fake {
    async fn handle(
        &self,
        command: EngineCommand,
        events: &EventQueue,
    ) -> Result<EngineReply, String> {
        match command {
            EngineCommand::GetState => Ok(EngineReply::State("idle".into())),
            EngineCommand::RunSpeedTest { mode } if mode == "slow" => {
                self.release.notified().await;
                Ok(EngineReply::Unit)
            }
            EngineCommand::RunSpeedTest { mode } if mode == "block" => {
                let _running = Running::enter(self);
                self.gate.notified().await;
                self.late.store(true, Ordering::SeqCst);
                Ok(EngineReply::Unit)
            }
            EngineCommand::Connect { .. } => {
                let sink = events.sink();
                sink(ClientEvent::state(TunnelState::Connecting));
                Ok(EngineReply::Unit)
            }
            EngineCommand::GetConfig => {
                let sink = events.sink();
                let started = Instant::now();
                for _ in 0..10_000 {
                    sink(telemetry());
                }
                *self.flood_took.lock().expect("the test lock") = started.elapsed();
                self.flood_done.notify_one();
                Ok(EngineReply::Unit)
            }
            EngineCommand::RenewPsk => {
                let sink = events.sink();
                for _ in 0..EVENT_QUEUE + 100 {
                    sink(ClientEvent::log("info", "line"));
                }
                sink(ClientEvent::state(TunnelState::Up));
                self.overflow_seen
                    .store(events.overflowed(), Ordering::SeqCst);
                self.flood_done.notify_one();
                Ok(EngineReply::Unit)
            }
            _ => Ok(EngineReply::Unit),
        }
    }

    async fn teardown(&self) {
        self.in_flight_at_teardown
            .store(self.in_flight.load(Ordering::SeqCst), Ordering::SeqCst);
        self.teardowns.fetch_add(1, Ordering::SeqCst);
    }
}

/// The UI's side of one session: its end of the pipe, the token it holds,
/// and the task running the engine's side.
struct Session {
    ui: BufReader<DuplexStream>,
    token: Arc<SessionToken>,
    engine: JoinHandle<ServeOutcome>,
}

fn start(fake: Arc<Fake>, capacity: usize) -> Session {
    let token = Arc::new(SessionToken::generate().expect("a session token"));
    let (ui, engine_end) = tokio::io::duplex(capacity);
    let served = token.clone();
    let engine = tokio::spawn(async move { serve(engine_end, &served, fake).await });
    Session {
        ui: BufReader::new(ui),
        token,
        engine,
    }
}

impl Session {
    async fn send(&mut self, frame: &ClientFrame) {
        write_frame(self.ui.get_mut(), frame, limits::REQUEST_BYTES)
            .await
            .expect("the frame reaches the engine");
    }

    async fn hello(&mut self) {
        let token = self.token.as_str().to_owned();
        self.send(&ClientFrame::Hello(Hello {
            protocol_version: PROTOCOL_VERSION,
            token,
        }))
        .await;
    }

    async fn request(&mut self, id: u64, command: EngineCommand) {
        self.send(&ClientFrame::Request {
            id,
            command: Box::new(command),
        })
        .await;
    }

    async fn next(&mut self) -> Option<EngineFrame> {
        read_frame::<_, EngineFrame>(&mut self.ui, limits::REPLY_BYTES)
            .await
            .expect("a readable frame")
    }

    /// The next reply, skipping any event before it.
    async fn reply(&mut self) -> (u64, Result<EngineReply, String>) {
        loop {
            match self.next().await {
                Some(EngineFrame::Reply { id, result }) => {
                    return (id, result.map(|reply| *reply));
                }
                Some(EngineFrame::Event(_)) => continue,
                None => panic!("the session ended before its reply"),
            }
        }
    }
}

async fn ended(session: Session) -> ServeOutcome {
    timeout_wait(session.engine).await
}

async fn timeout_wait<T>(handle: JoinHandle<T>) -> T {
    tokio::time::timeout(WAIT, handle)
        .await
        .expect("the session ends")
        .expect("the session task does not panic")
}

#[tokio::test]
async fn a_request_gets_the_reply_of_its_id() {
    let mut session = start(Arc::new(Fake::default()), PIPE);
    session.hello().await;
    session.request(7, EngineCommand::GetState).await;

    let (id, result) = session.reply().await;
    assert_eq!(id, 7);
    assert!(matches!(result, Ok(EngineReply::State(ref state)) if state == "idle"));
}

#[tokio::test]
async fn events_reach_the_client_between_replies() {
    let mut session = start(Arc::new(Fake::default()), PIPE);
    session.hello().await;
    session
        .request(1, EngineCommand::Connect { name: None })
        .await;
    session.request(2, EngineCommand::GetState).await;

    // Replies and events may interleave in either order: read until both
    // replies and the event have arrived.
    let mut replies = Vec::new();
    let mut events = 0;
    while replies.len() < 2 || events < 1 {
        match session.next().await {
            Some(EngineFrame::Event(ClientEvent::StateChanged { .. })) => events += 1,
            Some(EngineFrame::Reply { id, .. }) => replies.push(id),
            _ => panic!("an unexpected frame or the end of the stream"),
        }
    }
    replies.sort_unstable();
    assert_eq!(replies, vec![1, 2]);
    assert_eq!(events, 1);
}

#[tokio::test]
async fn shutdown_ends_the_session_with_shutdown_requested() {
    let mut session = start(Arc::new(Fake::default()), PIPE);
    session.hello().await;
    session.request(3, EngineCommand::Shutdown).await;

    let (id, result) = session.reply().await;
    assert_eq!(id, 3);
    assert!(matches!(result, Ok(EngineReply::Unit)));
    assert!(matches!(
        ended(session).await,
        ServeOutcome::ShutdownRequested
    ));
}

#[tokio::test]
async fn a_client_that_leaves_ends_the_session() {
    let mut session = start(Arc::new(Fake::default()), PIPE);
    session.hello().await;
    drop(session.ui);

    assert!(matches!(
        timeout_wait(session.engine).await,
        ServeOutcome::ClientLeft
    ));
}

#[tokio::test]
async fn a_stalled_client_never_blocks_the_controller() {
    let fake = Arc::new(Fake::default());
    let mut session = start(fake.clone(), SMALL_PIPE);
    session.hello().await;
    session.request(1, EngineCommand::GetConfig).await;

    // The UI never reads. The engine must still push all its telemetry,
    // and the 10 000 pushes must return at once.
    tokio::time::timeout(WAIT, fake.flood_done.notified())
        .await
        .expect("the flood finishes");
    let took = *fake.flood_took.lock().expect("the test lock");
    assert!(
        took < Duration::from_millis(250),
        "10 000 sink calls took {took:?}"
    );

    drop(session.ui);
    assert!(matches!(
        timeout_wait(session.engine).await,
        ServeOutcome::ClientLeft
    ));
}

#[tokio::test]
async fn critical_events_are_never_dropped() {
    // Depends on the current-thread runtime: the command never awaits, so the
    // queue fills before the loop gets a turn to drain it.
    let fake = Arc::new(Fake::default());
    let mut session = start(fake.clone(), SMALL_PIPE);
    session.hello().await;
    // Logs fill the queue; the state change that follows finds no room.
    session.request(1, EngineCommand::RenewPsk).await;
    tokio::time::timeout(WAIT, fake.flood_done.notified())
        .await
        .expect("the flood finishes");

    assert!(fake.overflow_seen.load(Ordering::SeqCst));
    assert!(matches!(
        ended(session).await,
        ServeOutcome::EventsOverflowed
    ));
}

#[tokio::test]
async fn teardown_runs_at_every_outcome_after_hello() {
    // The client leaves.
    let fake = Arc::new(Fake::default());
    let mut session = start(fake.clone(), PIPE);
    session.hello().await;
    drop(session.ui);
    assert!(matches!(
        timeout_wait(session.engine).await,
        ServeOutcome::ClientLeft
    ));
    assert_eq!(fake.teardowns.load(Ordering::SeqCst), 1);

    // The UI asks for a shutdown.
    let fake = Arc::new(Fake::default());
    let mut session = start(fake.clone(), PIPE);
    session.hello().await;
    session.request(1, EngineCommand::Shutdown).await;
    assert!(matches!(
        ended(session).await,
        ServeOutcome::ShutdownRequested
    ));
    assert_eq!(fake.teardowns.load(Ordering::SeqCst), 1);

    // The UI sends a frame that is not a frame.
    let fake = Arc::new(Fake::default());
    let mut session = start(fake.clone(), PIPE);
    session.hello().await;
    session
        .ui
        .get_mut()
        .write_all(b"not a frame\n")
        .await
        .expect("the pipe takes the line");
    assert!(matches!(
        ended(session).await,
        ServeOutcome::Broken(WireError::Malformed)
    ));
    assert_eq!(fake.teardowns.load(Ordering::SeqCst), 1);

    // The engine overflows against a UI that stopped reading.
    let fake = Arc::new(Fake::default());
    let mut session = start(fake.clone(), SMALL_PIPE);
    session.hello().await;
    session.request(1, EngineCommand::RenewPsk).await;
    tokio::time::timeout(WAIT, fake.flood_done.notified())
        .await
        .expect("the flood finishes");
    assert!(matches!(
        ended(session).await,
        ServeOutcome::EventsOverflowed
    ));
    assert_eq!(fake.teardowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_refused_hello_does_not_tear_down() {
    let fake = Arc::new(Fake::default());
    let mut session = start(fake.clone(), PIPE);
    session
        .send(&ClientFrame::Hello(Hello {
            protocol_version: PROTOCOL_VERSION,
            token: "not the session's token".into(),
        }))
        .await;

    assert!(matches!(
        ended(session).await,
        ServeOutcome::Refused(SessionRefusal::WrongToken)
    ));
    assert_eq!(fake.teardowns.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_second_hello_breaks_the_session() {
    let fake = Arc::new(Fake::default());
    let mut session = start(fake.clone(), PIPE);
    session.hello().await;
    session.hello().await;

    assert!(matches!(
        ended(session).await,
        ServeOutcome::Broken(WireError::Malformed)
    ));
    assert_eq!(fake.teardowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_slow_command_does_not_hold_back_another() {
    let fake = Arc::new(Fake::default());
    let mut session = start(fake.clone(), PIPE);
    session.hello().await;
    session
        .request(
            1,
            EngineCommand::RunSpeedTest {
                mode: "slow".into(),
            },
        )
        .await;
    session.request(2, EngineCommand::GetState).await;

    let (first, _) = session.reply().await;
    assert_eq!(first, 2);
    fake.release.notify_one();
    let (second, _) = session.reply().await;
    assert_eq!(second, 1);
}

#[tokio::test]
async fn teardown_waits_for_running_commands() {
    let fake = Arc::new(Fake::default());
    let mut session = start(fake.clone(), PIPE);
    session.hello().await;
    session
        .request(
            1,
            EngineCommand::RunSpeedTest {
                mode: "block".into(),
            },
        )
        .await;
    tokio::time::timeout(WAIT, fake.entered.notified())
        .await
        .expect("the command started");

    drop(session.ui);
    assert!(matches!(
        timeout_wait(session.engine).await,
        ServeOutcome::ClientLeft
    ));
    assert_eq!(fake.in_flight_at_teardown.load(Ordering::SeqCst), 0);
    assert_eq!(fake.teardowns.load(Ordering::SeqCst), 1);

    // Opening the gate now must not resume the aborted command.
    fake.gate.notify_one();
    tokio::task::yield_now().await;
    assert!(!fake.late.load(Ordering::SeqCst));
}
