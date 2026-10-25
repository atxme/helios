use super::*;

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use aether::TunnelState;
use orion_core::events::ClientEvent;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::Notify;

use crate::events::EventQueue;
use crate::serve::ServeOutcome;

/// Engine double: answers a state query, announces a connection, and blocks
/// on the `block` command until the session is torn down.
#[derive(Default)]
struct Echo {
    teardowns: AtomicUsize,
    entered: Notify,
    gate: Notify,
}

#[async_trait::async_trait]
impl Engine for Echo {
    async fn handle(
        &self,
        command: EngineCommand,
        events: &EventQueue,
    ) -> Result<EngineReply, String> {
        match command {
            EngineCommand::GetState => Ok(EngineReply::State("idle".into())),
            EngineCommand::Connect { .. } => {
                let sink = events.sink();
                sink(ClientEvent::state(TunnelState::Connecting));
                Ok(EngineReply::Unit)
            }
            EngineCommand::RunSpeedTest { mode } if mode == "block" => {
                self.entered.notify_one();
                self.gate.notified().await;
                Ok(EngineReply::Unit)
            }
            _ => Err("commande non gérée par le faux moteur".into()),
        }
    }

    async fn teardown(&self) {
        self.teardowns.fetch_add(1, Ordering::SeqCst);
    }
}

/// A stream whose read side always fails, as a reader that breaks looks to `connect`.
struct Unreadable(DuplexStream);

impl AsyncRead for Unreadable {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unreadable",
        )))
    }
}

impl AsyncWrite for Unreadable {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn a_call_gets_its_reply_in_process() {
    let (client, _events) = in_process(Arc::new(Echo::default()))
        .await
        .expect("an in-process engine");

    let reply = client.call(EngineCommand::GetState).await.expect("a reply");
    assert!(matches!(reply, EngineReply::State(ref state) if state == "idle"));
}

#[tokio::test]
async fn an_event_reaches_the_receiver() {
    let (client, mut events) = in_process(Arc::new(Echo::default()))
        .await
        .expect("an in-process engine");

    client
        .call(EngineCommand::Connect { name: None })
        .await
        .expect("a reply");

    let event = events.recv().await.expect("the event the engine pushed");
    assert!(matches!(event, ClientEvent::StateChanged { .. }));
}

#[tokio::test]
async fn calls_fail_once_the_engine_is_gone() {
    let (client, _events) = in_process(Arc::new(Echo::default()))
        .await
        .expect("an in-process engine");
    client
        .call(EngineCommand::Shutdown)
        .await
        .expect("the shutdown is answered");
    client.closed().await;

    let error = client
        .call(EngineCommand::GetState)
        .await
        .expect_err("the engine is gone");
    assert_eq!(error, GONE);
}

#[tokio::test]
async fn closed_resolves_when_the_engine_ends() {
    let (client, _events) = in_process(Arc::new(Echo::default()))
        .await
        .expect("an in-process engine");
    client
        .call(EngineCommand::Shutdown)
        .await
        .expect("the shutdown is answered");

    tokio::time::timeout(Duration::from_secs(5), client.closed())
        .await
        .expect("closed resolves once the engine has ended");
}

#[tokio::test]
async fn an_in_flight_call_fails_when_the_engine_ends() {
    let engine = Arc::new(Echo::default());
    let (client, _events) = in_process(engine.clone())
        .await
        .expect("an in-process engine");
    let client = Arc::new(client);
    let waiting = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .call(EngineCommand::RunSpeedTest {
                    mode: "block".into(),
                })
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), engine.entered.notified())
        .await
        .expect("the blocked command started");

    client
        .call(EngineCommand::Shutdown)
        .await
        .expect("the shutdown is answered");
    let answer = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("the in-flight call does not block")
        .expect("the calling task does not panic");
    assert_eq!(answer.expect_err("the engine is gone"), GONE);
}

#[tokio::test]
async fn a_client_whose_reader_breaks_releases_the_engine() {
    let engine = Arc::new(Echo::default());
    let token = Arc::new(SessionToken::generate().expect("a session token"));
    let (ui_end, engine_end) = tokio::io::duplex(64 * 1024);
    let served = token.clone();
    let session = tokio::spawn({
        let engine = engine.clone();
        async move { serve(engine_end, &served, engine).await }
    });

    let (client, _events) = connect(Unreadable(ui_end), &token)
        .await
        .expect("the hello is written");

    let outcome = tokio::time::timeout(Duration::from_secs(5), session)
        .await
        .expect("the engine notices the client left")
        .expect("the session task does not panic");
    assert!(matches!(outcome, ServeOutcome::ClientLeft));
    assert_eq!(engine.teardowns.load(Ordering::SeqCst), 1);
    drop(client);
}
