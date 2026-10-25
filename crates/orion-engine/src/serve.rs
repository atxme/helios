//! One authenticated UI session, served over any byte stream.
//!
//! The engine serves exactly one client. [`serve`] authenticates it, then runs
//! its requests and the events pushed to it on the same stream. Replies and
//! events are written by one loop only. Once the UI is authenticated, every
//! exit runs [`Engine::teardown`], whatever ended the session.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use orion_core::events::ClientEvent;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::command::{EngineCommand, EngineReply};
use crate::events::{is_droppable, EventQueue};
use crate::session::{accept_hello, SessionRefusal, SessionToken};
use crate::wire::{limits, read_frame, write_frame, ClientFrame, EngineFrame, WireError};

/// Frames the reader may buffer ahead of the loop.
const INCOMING_FRAMES: usize = 16;

/// Answer to a reply too large for the channel. Short and in French, for the UI.
const OVERSIZED_REPLY: &str = "Réponse trop volumineuse pour être transmise à l'interface.";

/// What the engine does with the UI's commands.
#[async_trait::async_trait]
pub trait Engine: Send + Sync + 'static {
    /// Runs one command. Events it pushes go through `events`.
    async fn handle(
        &self,
        command: EngineCommand,
        events: &EventQueue,
    ) -> Result<EngineReply, String>;

    /// Disconnects, releases the negotiated PSK, takes the adapter down. Idempotent.
    async fn teardown(&self);
}

/// How a session ended.
#[derive(Debug)]
pub enum ServeOutcome {
    /// The UI closed the channel, or its side of it failed.
    ClientLeft,
    /// The UI asked the engine to stop.
    ShutdownRequested,
    /// The first frame did not authenticate the UI. Nothing was torn down.
    Refused(SessionRefusal),
    /// The caller asked the session to end — its UI is gone.
    Stopped,
    /// A critical event found no room: the UI has stopped reading.
    EventsOverflowed,
    /// The channel carried something it must not: an unreadable or oversized
    /// frame, or a second hello. Fail-closed: the session ends.
    Broken(WireError),
}

/// Serves one UI session on `stream` until it ends.
///
/// A refused hello returns at once and never reaches the engine. Once the UI
/// is authenticated, every exit runs [`Engine::teardown`], and only after
/// every running command has stopped. Dropping this future skips teardown:
/// callers drive it to completion.
pub async fn serve<S, E>(stream: S, token: &SessionToken, engine: Arc<E>) -> ServeOutcome
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    E: Engine,
{
    serve_until(stream, token, engine, std::future::pending()).await
}

/// [`serve`], which also ends when `stop` completes.
///
/// A stop during the hello returns [`ServeOutcome::Stopped`] without teardown:
/// nothing has started. A stop once authenticated takes the same ordered path
/// as any other exit: running commands are cancelled and awaited, then the
/// engine is torn down.
pub async fn serve_until<S, E, F>(
    stream: S,
    token: &SessionToken,
    engine: Arc<E>,
    stop: F,
) -> ServeOutcome
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    E: Engine,
    F: Future<Output = ()> + Send,
{
    tokio::pin!(stop);
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let accepted = tokio::select! {
        accepted = accept_hello(&mut reader, token) => accepted,
        () = &mut stop => return ServeOutcome::Stopped,
    };
    if let Err(refusal) = accepted {
        return ServeOutcome::Refused(refusal);
    }

    let (frames_tx, mut frames) = mpsc::channel(INCOMING_FRAMES);
    let (queue, mut events) = EventQueue::new();
    let reading = tokio::spawn(read_requests(reader, frames_tx));

    let outcome = run(
        &mut write_half,
        &mut frames,
        &mut events,
        &queue,
        &engine,
        &mut stop,
    )
    .await;

    reading.abort();
    engine.teardown().await;
    outcome
}

/// Forwards the UI's frames to the loop, and ends after the first failure.
async fn read_requests<R>(mut reader: R, frames: mpsc::Sender<Result<ClientFrame, WireError>>)
where
    R: AsyncBufRead + Unpin,
{
    loop {
        match read_frame::<_, ClientFrame>(&mut reader, limits::REQUEST_BYTES).await {
            Ok(Some(frame)) => {
                if frames.send(Ok(frame)).await.is_err() {
                    return;
                }
            }
            // Clean end of stream: dropping the sender tells the loop.
            Ok(None) => return,
            Err(error) => {
                let _ = frames.send(Err(error)).await;
                return;
            }
        }
    }
}

/// The session loop. Each request runs in its own task, so a slow command
/// holds back neither the other requests nor the events.
async fn run<W, E, F>(
    writer: &mut W,
    frames: &mut mpsc::Receiver<Result<ClientFrame, WireError>>,
    events: &mut mpsc::Receiver<ClientEvent>,
    queue: &EventQueue,
    engine: &Arc<E>,
    stop: &mut Pin<&mut F>,
) -> ServeOutcome
where
    W: AsyncWrite + Unpin,
    E: Engine,
    F: Future<Output = ()>,
{
    let mut tasks: JoinSet<(u64, Result<EngineReply, String>)> = JoinSet::new();
    let outcome = loop {
        tokio::select! {
            incoming = frames.recv() => match incoming {
                None => break ServeOutcome::ClientLeft,
                Some(Err(error)) => break ServeOutcome::Broken(error),
                Some(Ok(ClientFrame::Hello(_))) => break ServeOutcome::Broken(WireError::Malformed),
                Some(Ok(ClientFrame::Request { id, command })) => match *command {
                    EngineCommand::Shutdown => {
                        break match reply(writer, queue, id, Ok(EngineReply::Unit)).await {
                            Ok(()) => ServeOutcome::ShutdownRequested,
                            Err(outcome) => outcome,
                        };
                    }
                    command => {
                        let engine = engine.clone();
                        let queue = queue.clone();
                        tasks.spawn(async move { (id, engine.handle(command, &queue).await) });
                    }
                },
            },
            Some(joined) = tasks.join_next(), if !tasks.is_empty() => match joined {
                Ok((id, result)) => {
                    if let Err(outcome) = reply(writer, queue, id, result).await {
                        break outcome;
                    }
                }
                // A panicked command leaves no id to answer: the session ends.
                Err(_) => break ServeOutcome::Broken(WireError::Io(io::ErrorKind::Other)),
            },
            Some(event) = events.recv() => {
                if let Err(outcome) = forward(writer, queue, event).await {
                    break outcome;
                }
            }
            () = queue.overflow() => break ServeOutcome::EventsOverflowed,
            () = &mut *stop => break ServeOutcome::Stopped,
        }
    };
    // Abort only asks: a command stops when its future is dropped, and
    // teardown must not run beside one still in flight.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    outcome
}

/// Writes one frame. A write that cannot complete ends the session, and so
/// does an overflow raised meanwhile: a UI that stops reading must not keep
/// the engine waiting on it.
async fn emit<W>(
    writer: &mut W,
    frame: &EngineFrame,
    limit: usize,
    queue: &EventQueue,
) -> Result<(), ServeOutcome>
where
    W: AsyncWrite + Unpin,
{
    tokio::select! {
        written = write_frame(writer, frame, limit) => written.map_err(|error| match error {
            WireError::Io(_) => ServeOutcome::ClientLeft,
            other => ServeOutcome::Broken(other),
        }),
        () = queue.overflow() => Err(ServeOutcome::EventsOverflowed),
    }
}

/// Writes the reply to request `id`. A reply over the limit becomes a short
/// error for the same id, so the session survives it.
async fn reply<W>(
    writer: &mut W,
    queue: &EventQueue,
    id: u64,
    result: Result<EngineReply, String>,
) -> Result<(), ServeOutcome>
where
    W: AsyncWrite + Unpin,
{
    let frame = EngineFrame::Reply {
        id,
        result: result.map(Box::new),
    };
    match emit(writer, &frame, limits::REPLY_BYTES, queue).await {
        Err(ServeOutcome::Broken(WireError::TooLarge { .. })) => {
            let refusal = EngineFrame::Reply {
                id,
                result: Err(OVERSIZED_REPLY.to_owned()),
            };
            emit(writer, &refusal, limits::REPLY_BYTES, queue).await
        }
        other => other,
    }
}

/// Writes one event. An oversized telemetry or log line is skipped; any other
/// oversized event ends the session rather than vanish.
async fn forward<W>(
    writer: &mut W,
    queue: &EventQueue,
    event: ClientEvent,
) -> Result<(), ServeOutcome>
where
    W: AsyncWrite + Unpin,
{
    let droppable = is_droppable(&event);
    match emit(
        writer,
        &EngineFrame::Event(event),
        limits::EVENT_BYTES,
        queue,
    )
    .await
    {
        Err(ServeOutcome::Broken(WireError::TooLarge { .. })) if droppable => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests;
