//! Serves the React app's static files.
//!
//! With the `embed-ui` feature: the files under `web/dist/` are embedded into
//! the binary at compile time (via `rust-embed`). Any unknown route falls back
//! to `index.html` (SPA fallback).
//!
//! Without the feature: returns 503 with a helpful message — convenient in dev
//! where Vite runs separately and proxies to heliosd.

use axum::{
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};

#[cfg(feature = "embed-ui")]
#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/dist/"]
struct Assets;

pub async fn static_handler(uri: Uri) -> Response {
    #[cfg(feature = "embed-ui")]
    return serve_embedded(uri).await;

    #[cfg(not(feature = "embed-ui"))]
    {
        let _ = uri;
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "UI not embedded. In dev: run `npm run dev` in web/. \
             In prod: run `npm run build` then recompile with --features embed-ui.",
        )
            .into_response()
    }
}

#[cfg(feature = "embed-ui")]
async fn serve_embedded(uri: Uri) -> Response {
    use axum::http::header;
    use axum::response::Html;

    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
        }
        None => match Assets::get("index.html") {
            Some(content) => {
                Html(String::from_utf8_lossy(&content.data).into_owned()).into_response()
            }
            None => StatusCode::NOT_FOUND.into_response(),
        },
    }
}

#[cfg(all(test, feature = "embed-ui"))]
mod tests {
    use super::*;
    use axum::http::header;

    #[tokio::test]
    async fn serves_the_embedded_index_at_the_root() {
        let response = static_handler(Uri::from_static("/")).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html");
    }

    #[tokio::test]
    async fn unknown_routes_fall_back_to_the_spa_index() {
        let response = static_handler(Uri::from_static("/profiles/portable")).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
    }
}
