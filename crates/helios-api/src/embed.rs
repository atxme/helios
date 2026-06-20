//! Sert les fichiers statiques de l'app React.
//!
//! Avec la feature `embed-ui` : les fichiers de `web/dist/` sont embarqués dans
//! le binaire à la compilation (via `rust-embed`). Toute route inconnue renvoie
//! `index.html` (SPA fallback).
//!
//! Sans la feature : renvoie 503 avec un message d'aide — pratique en dev où
//! Vite tourne séparément et proxy vers heliosd.

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
            "UI non intégrée. En dev : lancez `npm run dev` dans web/. \
             En prod : exécutez `npm run build` puis recompilez avec --features embed-ui.",
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
            Some(content) => Html(String::from_utf8_lossy(&content.data).into_owned()).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
    }
}
