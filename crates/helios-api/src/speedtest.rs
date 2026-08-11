//! Bounded in-tunnel transfers used by Orion's performance screen.
//!
//! These routes are behind [`crate::auth::require_peer`]. The source VIP is
//! therefore the authentication; no profile name, public key or additional
//! token is accepted from the client. Bodies are streamed in both directions:
//! allocating an entire test payload on every request would benchmark the
//! gateway allocator as much as the WireGuard path.

use std::{convert::Infallible, sync::LazyLock};

use axum::{
    body::{Body, Bytes},
    extract::{Query, Request},
    http::{header, HeaderValue, StatusCode},
    response::Response,
};
use futures_util::{stream, StreamExt as _};
use serde::Deserialize;

/// Maximum payload accepted in either direction of one request.
pub const MAX_TRANSFER_BYTES: usize = 64 * 1024 * 1024;
/// Safe default for a manual probe. Orion always sends its calibrated size.
pub const DEFAULT_TRANSFER_BYTES: usize = 8 * 1024 * 1024;
// Large frames keep userspace polling and reference-count churn negligible on
// multi-gigabit links; socket backpressure still slices them for the network.
const STREAM_CHUNK_BYTES: usize = 1024 * 1024;

/// One deterministic non-repeating chunk, generated once for the process.
/// WireGuard itself does not compress, but a realistic payload also prevents a
/// future HTTP middleware from making the benchmark accidentally optimistic.
static DOWNLOAD_CHUNK: LazyLock<Bytes> = LazyLock::new(|| {
    let mut data = vec![0u8; STREAM_CHUNK_BYTES];
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for block in data.chunks_exact_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        block.copy_from_slice(&state.to_le_bytes());
    }
    Bytes::from(data)
});

#[derive(Debug, Deserialize)]
pub struct TransferQuery {
    bytes: Option<usize>,
}

impl TransferQuery {
    fn requested_bytes(&self) -> Result<usize, (StatusCode, String)> {
        let bytes = self.bytes.unwrap_or(DEFAULT_TRANSFER_BYTES);
        if bytes == 0 || bytes > MAX_TRANSFER_BYTES {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "la taille du speedtest doit être comprise entre 1 et {MAX_TRANSFER_BYTES} octets"
                ),
            ));
        }
        Ok(bytes)
    }
}

/// A cheap authenticated round-trip probe.
pub async fn ping() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Streams a bounded payload to the client without a per-request large buffer.
pub async fn download(
    Query(query): Query<TransferQuery>,
) -> Result<Response, (StatusCode, String)> {
    let bytes = query.requested_bytes()?;
    let stream = stream::unfold(
        (bytes, DOWNLOAD_CHUNK.clone()),
        |(remaining, chunk)| async move {
            if remaining == 0 {
                return None;
            }
            let emitted = remaining.min(chunk.len());
            Some((
                Ok::<Bytes, Infallible>(chunk.slice(..emitted)),
                (remaining - emitted, chunk),
            ))
        },
    );
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.to_string()).expect("decimal content length is valid"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-transform"),
    );
    Ok(response)
}

/// Streams and discards a bounded upload, acknowledging only after every byte
/// reached the application. The response therefore cannot race ahead of data
/// still buffered in the server's socket.
pub async fn upload(
    Query(query): Query<TransferQuery>,
    request: Request,
) -> Result<StatusCode, (StatusCode, String)> {
    let expected = query.requested_bytes()?;
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| {
            (
                StatusCode::LENGTH_REQUIRED,
                "le speedtest exige une taille de corps explicite".to_string(),
            )
        })?;
    if declared != expected {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("le speedtest annonce {declared} octets, {expected} étaient attendus"),
        ));
    }

    let mut received = 0usize;
    let mut body = request.into_body().into_data_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|error| {
            (
                StatusCode::BAD_REQUEST,
                format!("corps du speedtest interrompu : {error}"),
            )
        })?;
        received = received.checked_add(chunk.len()).ok_or_else(|| {
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                "taille du speedtest débordée".to_string(),
            )
        })?;
        if received > expected {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "le corps du speedtest dépasse la taille annoncée".to_string(),
            ));
        }
    }
    if received != expected {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("le speedtest a reçu {received} octets, {expected} étaient attendus"),
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_sizes_are_bounded_before_stream_creation() {
        assert!(TransferQuery { bytes: Some(0) }.requested_bytes().is_err());
        assert!(TransferQuery {
            bytes: Some(MAX_TRANSFER_BYTES + 1)
        }
        .requested_bytes()
        .is_err());
        assert_eq!(
            TransferQuery { bytes: None }
                .requested_bytes()
                .expect("default size"),
            DEFAULT_TRANSFER_BYTES
        );
    }

    #[test]
    fn download_chunk_is_not_a_repeated_byte_pattern() {
        assert_eq!(DOWNLOAD_CHUNK.len(), STREAM_CHUNK_BYTES);
        assert!(DOWNLOAD_CHUNK.windows(2).any(|pair| pair[0] != pair[1]));
    }
}
