use super::*;

use std::time::Duration;

use crate::events::EventQueue;
use aether::TunnelState;
use orion_core::events::ClientEvent;

/// Engine double: answers a state query and announces a connection.
struct Echo;

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
            _ => Err("commande non gérée par le faux moteur".into()),
        }
    }

    async fn teardown(&self) {}
}

#[tokio::test]
async fn a_call_gets_its_reply_in_process() {
    let (client, _events) = in_process(Arc::new(Echo))
        .await
        .expect("an in-process engine");

    let reply = client.call(EngineCommand::GetState).await.expect("a reply");
    assert!(matches!(reply, EngineReply::State(ref state) if state == "idle"));
}

#[tokio::test]
async fn an_event_reaches_the_receiver() {
    let (client, mut events) = in_process(Arc::new(Echo))
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
    let (client, _events) = in_process(Arc::new(Echo))
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
    let (client, _events) = in_process(Arc::new(Echo))
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
