use super::*;
use crate::command::EngineCommand;
use crate::wire::{write_frame, Hello};
use tokio::io::{BufReader, DuplexStream};

/// Client end of a duplex pipe, and the engine's end, buffered as the engine
/// buffers it.
fn pipe() -> (DuplexStream, BufReader<DuplexStream>) {
    let (client, engine) = tokio::io::duplex(64 * 1024);
    (client, BufReader::new(engine))
}

async fn send(client: &mut DuplexStream, frame: &ClientFrame) {
    write_frame(client, frame, limits::REQUEST_BYTES)
        .await
        .expect("the frame fits in the pipe");
}

fn hello(version: u16, token: &str) -> ClientFrame {
    ClientFrame::Hello(Hello {
        protocol_version: version,
        token: token.to_owned(),
    })
}

fn token() -> SessionToken {
    SessionToken::generate().expect("session token")
}

#[tokio::test]
async fn the_right_hello_opens_the_session() {
    let token = token();
    let (mut client, mut engine) = pipe();
    send(&mut client, &hello(PROTOCOL_VERSION, token.as_str())).await;

    assert!(accept_hello(&mut engine, &token).await.is_ok());
}

#[tokio::test]
async fn a_wrong_token_is_refused() {
    let token = token();
    let (mut client, mut engine) = pipe();
    let mut forged = token.as_str().to_owned();
    let first = if &forged[..1] == "0" { "1" } else { "0" };
    forged.replace_range(..1, first);
    send(&mut client, &hello(PROTOCOL_VERSION, &forged)).await;

    let refusal = accept_hello(&mut engine, &token).await.unwrap_err();
    assert!(matches!(refusal, SessionRefusal::WrongToken));
}

#[tokio::test]
async fn a_token_of_another_length_is_refused() {
    let token = token();
    let (mut client, mut engine) = pipe();
    let shorter = &token.as_str()[..token.as_str().len() - 2];
    send(&mut client, &hello(PROTOCOL_VERSION, shorter)).await;

    let refusal = accept_hello(&mut engine, &token).await.unwrap_err();
    assert!(matches!(refusal, SessionRefusal::WrongToken));
}

#[tokio::test]
async fn another_protocol_version_is_refused() {
    let token = token();
    let (mut client, mut engine) = pipe();
    send(&mut client, &hello(PROTOCOL_VERSION + 1, token.as_str())).await;

    let refusal = accept_hello(&mut engine, &token).await.unwrap_err();
    assert!(matches!(refusal, SessionRefusal::WrongVersion));
}

#[tokio::test]
async fn a_request_before_the_hello_is_refused() {
    let token = token();
    let (mut client, mut engine) = pipe();
    send(
        &mut client,
        &ClientFrame::Request {
            id: 1,
            command: EngineCommand::Shutdown,
        },
    )
    .await;

    let refusal = accept_hello(&mut engine, &token).await.unwrap_err();
    assert!(matches!(refusal, SessionRefusal::NotAHello));
}

#[tokio::test]
async fn a_connection_closed_before_the_hello_is_refused() {
    let token = token();
    let (client, mut engine) = pipe();
    drop(client);

    let refusal = accept_hello(&mut engine, &token).await.unwrap_err();
    assert!(matches!(refusal, SessionRefusal::Closed));
}

#[tokio::test]
async fn an_oversized_hello_is_refused_as_a_wire_error() {
    let token = token();
    let (mut client, mut engine) = pipe();
    let padding = "x".repeat(limits::HELLO_BYTES);
    send(&mut client, &hello(PROTOCOL_VERSION, &padding)).await;

    let refusal = accept_hello(&mut engine, &token).await.unwrap_err();
    assert!(matches!(
        refusal,
        SessionRefusal::Wire(WireError::TooLarge { .. })
    ));
}

#[tokio::test(start_paused = true)]
async fn silence_past_the_hello_timeout_is_refused() {
    let token = token();
    // The client stays open and silent: only the timeout can end the wait.
    let (_client, mut engine) = pipe();

    let refusal = accept_hello(&mut engine, &token).await.unwrap_err();
    assert!(matches!(refusal, SessionRefusal::Timeout));
}

#[tokio::test]
async fn the_token_never_appears_in_debug_output() {
    let token = token();
    let secret = token.as_str().to_owned();
    let debug = format!("{token:?}");
    assert!(!debug.contains(&secret));

    let refusals = [
        SessionRefusal::Timeout,
        SessionRefusal::WrongVersion,
        SessionRefusal::WrongToken,
        SessionRefusal::NotAHello,
        SessionRefusal::Wire(WireError::Malformed),
        SessionRefusal::Wire(WireError::TooLarge {
            limit: limits::HELLO_BYTES,
        }),
        SessionRefusal::Closed,
    ];
    for refusal in &refusals {
        for rendered in [format!("{refusal:?}"), format!("{refusal}")] {
            assert!(
                !rendered.contains(&secret),
                "refusal leaks the token: {rendered}"
            );
        }
    }
}

#[test]
fn a_wrong_secret_is_refused_whatever_its_shape() {
    assert!(same_secret("abcd", "abcd"));
    assert!(!same_secret("abcd", "abce"));
    assert!(!same_secret("abcd", "abcde"));
    assert!(!same_secret("", "a"));
}
