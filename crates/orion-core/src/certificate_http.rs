//! Bounded response bodies for the three certificate lifecycle exchanges.

#[derive(Debug)]
pub(crate) enum BodyError {
    TooLarge,
    Transport(reqwest::Error),
}

/// Checks both advertised and actual bytes before retaining a body fragment.
///
/// Content-Length is only an early refusal: chunked and close-delimited bodies
/// have the same bound. The caller's request timeout still covers the read.
pub(crate) async fn read_bounded(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, BodyError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(BodyError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(BodyError::Transport)? {
        if chunk.len() > limit - body.len() {
            return Err(BodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A raw peer makes framing and deliberately incomplete bodies explicit.
    pub(crate) async fn response(
        wire: Vec<u8>,
        hold_open: bool,
    ) -> (reqwest::Response, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("connection");
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.expect("request");
                assert_ne!(read, 0, "request headers complete");
                request.extend_from_slice(&buffer[..read]);
            }
            // Oversize refusal may close the connection before all bytes land.
            let _ = stream.write_all(&wire).await;
            if hold_open {
                std::future::pending::<()>().await;
            }
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .expect("client")
            .get(format!("http://{address}"))
            .send()
            .await
            .expect("response headers");
        (response, server)
    }

    pub(crate) fn chunked(body: &[u8]) -> Vec<u8> {
        let mut wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for part in body.chunks(11) {
            wire.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            wire.extend_from_slice(part);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        wire
    }

    #[tokio::test]
    async fn every_framing_accepts_the_exact_limit_and_refuses_the_next_byte() {
        const LIMIT: usize = 32;
        for length in [LIMIT - 1, LIMIT, LIMIT + 1] {
            let body = vec![b'x'; length];
            for framing in 0..3 {
                let wire = match framing {
                    0 => {
                        let mut wire =
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n")
                                .into_bytes();
                        wire.extend_from_slice(&body);
                        wire
                    }
                    1 => chunked(&body),
                    _ => {
                        let mut wire = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
                        wire.extend_from_slice(&body);
                        wire
                    }
                };
                let (response, server) = response(wire, false).await;
                let result = read_bounded(response, LIMIT).await;
                server.abort();
                if length <= LIMIT {
                    assert_eq!(result.expect("bounded body"), body);
                } else {
                    assert!(matches!(result, Err(BodyError::TooLarge)), "{result:?}");
                }
            }
        }
    }

    #[tokio::test]
    async fn advertised_oversize_is_refused_without_waiting_for_any_body() {
        let (response, server) = response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 33\r\n\r\n".to_vec(),
            true,
        )
        .await;
        let result = tokio::time::timeout(Duration::from_secs(1), read_bounded(response, 32)).await;
        server.abort();
        assert!(matches!(result, Ok(Err(BodyError::TooLarge))));
    }

    #[tokio::test]
    async fn chunked_oversize_is_refused_without_waiting_for_the_stream_to_end() {
        let mut wire = chunked(&[b'x'; 33]);
        wire.truncate(wire.len() - 5);
        let (response, server) = response(wire, true).await;
        let result = tokio::time::timeout(Duration::from_secs(1), read_bounded(response, 32)).await;
        server.abort();
        assert!(matches!(result, Ok(Err(BodyError::TooLarge))));
    }

    #[tokio::test]
    async fn truncated_content_length_is_a_transport_error() {
        let (response, server) = response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nx".to_vec(),
            false,
        )
        .await;
        assert!(matches!(
            read_bounded(response, 32).await,
            Err(BodyError::Transport(_))
        ));
        server.abort();
    }

    #[tokio::test]
    async fn unfinished_chunked_body_is_a_transport_error() {
        let (response, server) = response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nx".to_vec(),
            false,
        )
        .await;
        assert!(matches!(
            read_bounded(response, 32).await,
            Err(BodyError::Transport(_))
        ));
        server.abort();
    }

    #[tokio::test]
    async fn zero_limit_accepts_only_an_empty_body() {
        for body in [b"".as_slice(), b"x".as_slice()] {
            let (response, server) = response(chunked(body), false).await;
            let result = read_bounded(response, 0).await;
            server.abort();
            if body.is_empty() {
                assert!(result.expect("empty body").is_empty());
            } else {
                assert!(matches!(result, Err(BodyError::TooLarge)));
            }
        }
    }
}
