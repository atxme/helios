//! The UI's end of a session: calls to the engine, and the events it pushes.
//!
//! One connection, one reader task. The reader hands each reply to the call
//! waiting for its id, and each event to the receiver the UI drains. When the
//! engine goes away, every call still waiting fails, and later calls fail at
//! once.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use orion_core::events::ClientEvent;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex};

use crate::command::{EngineCommand, EngineReply};
use crate::events::EVENT_QUEUE;
use crate::serve::{serve, Engine};
use crate::session::SessionToken;
use crate::wire::{
    limits, read_frame, write_frame, ClientFrame, EngineFrame, Hello, WireError, PROTOCOL_VERSION,
};

/// Message of every call made once the engine is gone.
const GONE: &str = "Le moteur d'Orion ne répond plus.";
/// Pipe between the in-process UI and engine. Frames are small: a few
/// kilobytes, never a whole configuration.
const IN_PROCESS_PIPE: usize = 64 * 1024;

type Answer = oneshot::Sender<Result<EngineReply, String>>;

/// State shared by the calls and the reader task.
#[derive(Default)]
struct Pending {
    /// Set once the reader has ended: no call may wait any longer.
    closed: bool,
    /// Calls in flight, by request id.
    waiting: HashMap<u64, Answer>,
}

/// The UI's handle on the engine. Calls may run concurrently.
pub struct EngineClient {
    writer: AsyncMutex<Box<dyn AsyncWrite + Send + Unpin>>,
    next_id: AtomicU64,
    pending: Arc<Mutex<Pending>>,
    closed: watch::Receiver<bool>,
}

impl EngineClient {
    /// Sends one command and waits for its reply.
    pub async fn call(&self, command: EngineCommand) -> Result<EngineReply, String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (answer, reply) = oneshot::channel();
        {
            let mut pending = lock(&self.pending);
            if pending.closed {
                return Err(GONE.into());
            }
            pending.waiting.insert(id, answer);
        }

        let frame = ClientFrame::Request {
            id,
            command: Box::new(command),
        };
        let written = {
            let mut writer = self.writer.lock().await;
            write_frame(&mut *writer, &frame, limits::REQUEST_BYTES).await
        };
        if let Err(error) = written {
            lock(&self.pending).waiting.remove(&id);
            return Err(match error {
                WireError::TooLarge { .. } => {
                    "Commande trop volumineuse pour être envoyée au moteur.".into()
                }
                WireError::Malformed => "Commande impossible à transmettre au moteur.".into(),
                WireError::Io(_) => GONE.into(),
            });
        }

        // A dropped answer means the reader ended before the reply arrived.
        reply.await.unwrap_or_else(|_| Err(GONE.into()))
    }

    /// Completes once the engine has ended the session, or the reader has.
    pub async fn closed(&self) {
        let mut closed = self.closed.clone();
        // A dropped sender means the reader has ended too.
        let _ = closed.wait_for(|gone| *gone).await;
    }
}

/// Opens the session on `stream`: presents the token, then starts the reader.
///
/// The engine answers nothing to a hello. A refused hello shows up as the
/// stream ending, so the first call fails.
pub async fn connect<S>(
    stream: S,
    token: &SessionToken,
) -> Result<(EngineClient, mpsc::Receiver<ClientEvent>), String>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let hello = ClientFrame::Hello(Hello {
        protocol_version: PROTOCOL_VERSION,
        token: token.as_str().to_owned(),
    });
    write_frame(&mut write_half, &hello, limits::HELLO_BYTES)
        .await
        .map_err(|_| "Connexion au moteur impossible.".to_owned())?;

    let pending = Arc::new(Mutex::new(Pending::default()));
    let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
    let (closed_tx, closed_rx) = watch::channel(false);
    tokio::spawn(read_frames(
        BufReader::new(read_half),
        pending.clone(),
        events_tx,
        closed_tx,
    ));

    let client = EngineClient {
        writer: AsyncMutex::new(Box::new(write_half)),
        next_id: AtomicU64::new(0),
        pending,
        closed: closed_rx,
    };
    Ok((client, events_rx))
}

/// Runs the engine in this process, over an in-memory pipe, with the same
/// session as a separate process.
pub async fn in_process<E: Engine>(
    engine: Arc<E>,
) -> Result<(EngineClient, mpsc::Receiver<ClientEvent>), String> {
    let token = Arc::new(SessionToken::generate()?);
    let (ui_end, engine_end) = tokio::io::duplex(IN_PROCESS_PIPE);
    let served = token.clone();
    tokio::spawn(async move { serve(engine_end, &served, engine).await });
    connect(ui_end, &token).await
}

/// Dispatches replies to their calls and events to the receiver, until the
/// stream ends or breaks.
async fn read_frames<R>(
    mut reader: R,
    pending: Arc<Mutex<Pending>>,
    events: mpsc::Sender<ClientEvent>,
    closed: watch::Sender<bool>,
) where
    R: AsyncBufRead + Unpin,
{
    loop {
        match read_frame::<_, EngineFrame>(&mut reader, limits::REPLY_BYTES).await {
            Ok(Some(EngineFrame::Reply { id, result })) => {
                let answer = lock(&pending).waiting.remove(&id);
                if let Some(answer) = answer {
                    let _ = answer.send(result.map(|reply| *reply));
                }
            }
            // A UI that stopped draining holds the reader here, and the engine
            // then overflows. A receiver that is gone takes its events with it.
            Ok(Some(EngineFrame::Event(event))) => {
                let _ = events.send(event).await;
            }
            Ok(None) | Err(_) => break,
        }
    }
    {
        let mut state = lock(&pending);
        state.closed = true;
        state.waiting.clear();
    }
    closed.send_replace(true);
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
