use super::*;
use aether::TunnelState;
use orion_core::events::ClientEvent;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

/// Counts the bytes a reader hands out, to prove the wire stops reading.
struct CountingReader<R> {
    inner: R,
    consumed: Arc<AtomicUsize>,
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = poll {
            self.consumed
                .fetch_add(buf.filled().len() - before, Ordering::Relaxed);
        }
        poll
    }
}

#[tokio::test]
async fn a_frame_round_trips() {
    let frame = ClientFrame::Hello(Hello {
        protocol_version: PROTOCOL_VERSION,
        token: "jeton".into(),
    });
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &frame, limits::HELLO_BYTES)
        .await
        .unwrap();

    let mut reader = tokio::io::BufReader::new(bytes.as_slice());
    match read_frame::<_, ClientFrame>(&mut reader, limits::HELLO_BYTES)
        .await
        .unwrap()
    {
        Some(ClientFrame::Hello(hello)) => {
            assert_eq!(hello.protocol_version, PROTOCOL_VERSION);
            assert_eq!(hello.token, "jeton");
        }
        _ => panic!("the Hello frame must come back unchanged"),
    }
}

#[tokio::test]
async fn a_line_over_its_limit_is_refused_without_reading_it_all() {
    let limit = 64;
    let mut line = vec![b'a'; limit + 1];
    line.extend_from_slice(b"\n{}\n");
    let consumed = Arc::new(AtomicUsize::new(0));
    let source = CountingReader {
        inner: line.as_slice(),
        consumed: consumed.clone(),
    };
    let mut reader = tokio::io::BufReader::with_capacity(limit + 1, source);

    let result = read_frame::<_, ClientFrame>(&mut reader, limit).await;

    assert!(matches!(result, Err(WireError::TooLarge { limit: 64 })));
    assert!(consumed.load(Ordering::Relaxed) <= limit + 1);
}

#[tokio::test]
async fn a_malformed_line_is_refused() {
    let mut reader = tokio::io::BufReader::new(&b"pas du json\n"[..]);
    let result = read_frame::<_, ClientFrame>(&mut reader, limits::HELLO_BYTES).await;
    assert!(matches!(result, Err(WireError::Malformed)));

    let mut reader = tokio::io::BufReader::new(&b"{\"frame\":\"hello\""[..]);
    let result = read_frame::<_, ClientFrame>(&mut reader, limits::HELLO_BYTES).await;
    assert!(matches!(result, Err(WireError::Malformed)));
}

#[tokio::test]
async fn end_of_stream_is_none() {
    let mut reader = tokio::io::BufReader::new(&b""[..]);
    let result = read_frame::<_, ClientFrame>(&mut reader, limits::HELLO_BYTES).await;
    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn a_writer_refuses_a_frame_over_its_limit() {
    let frame = EngineFrame::Reply {
        id: 1,
        result: Ok(Box::new(EngineReply::Unit)),
    };
    let mut bytes = Vec::new();
    let result = write_frame(&mut bytes, &frame, 8).await;

    assert!(matches!(result, Err(WireError::TooLarge { limit: 8 })));
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn an_event_frame_round_trips() {
    let events = [
        EngineFrame::Event(ClientEvent::state(TunnelState::Up)),
        EngineFrame::Event(ClientEvent::log("info", "tunnel up")),
    ];
    let mut bytes = Vec::new();
    for frame in &events {
        write_frame(&mut bytes, frame, limits::EVENT_BYTES)
            .await
            .unwrap();
    }

    let mut reader = tokio::io::BufReader::new(bytes.as_slice());
    match read_frame::<_, EngineFrame>(&mut reader, limits::EVENT_BYTES)
        .await
        .unwrap()
    {
        Some(EngineFrame::Event(ClientEvent::StateChanged { state })) => {
            assert_eq!(state, TunnelState::Up);
        }
        _ => panic!("the state event must come back unchanged"),
    }
    match read_frame::<_, EngineFrame>(&mut reader, limits::EVENT_BYTES)
        .await
        .unwrap()
    {
        Some(EngineFrame::Event(ClientEvent::Log { level, message })) => {
            assert_eq!(level, "info");
            assert_eq!(message, "tunnel up");
        }
        _ => panic!("the log event must come back unchanged"),
    }
    assert!(matches!(
        read_frame::<_, EngineFrame>(&mut reader, limits::EVENT_BYTES).await,
        Ok(None)
    ));
}

#[tokio::test]
async fn a_reply_frame_round_trips() {
    let replies = [
        EngineFrame::Reply {
            id: 7,
            result: Ok(Box::new(EngineReply::Unit)),
        },
        EngineFrame::Reply {
            id: 8,
            result: Err("refus".into()),
        },
    ];
    let mut bytes = Vec::new();
    for frame in &replies {
        write_frame(&mut bytes, frame, limits::REPLY_BYTES)
            .await
            .unwrap();
    }

    let mut reader = tokio::io::BufReader::new(bytes.as_slice());
    match read_frame::<_, EngineFrame>(&mut reader, limits::REPLY_BYTES)
        .await
        .unwrap()
    {
        Some(EngineFrame::Reply { id, result }) => {
            assert_eq!(id, 7);
            assert!(matches!(result.as_deref(), Ok(EngineReply::Unit)));
        }
        _ => panic!("the unit reply must come back unchanged"),
    }
    match read_frame::<_, EngineFrame>(&mut reader, limits::REPLY_BYTES)
        .await
        .unwrap()
    {
        Some(EngineFrame::Reply { id, result }) => {
            assert_eq!(id, 8);
            assert!(matches!(result, Err(message) if message == "refus"));
        }
        _ => panic!("the error reply must come back unchanged"),
    }
}
