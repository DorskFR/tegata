use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rust_embed::Embed;
use sha2::{Digest, Sha256};

#[derive(Embed)]
#[folder = "ui/build"]
#[allow_missing = true]
struct Assets;

/// CSP allowing exactly the inline scripts of the built index page.
pub fn content_security_policy() -> String {
    let inline = Assets::get("index.html")
        .map(|f| inline_script_hashes(&String::from_utf8_lossy(&f.data)))
        .unwrap_or_default();
    format!(
        "default-src 'self'; script-src 'self'{inline}; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; \
         form-action 'self'"
    )
}

fn inline_script_hashes(html: &str) -> String {
    let mut out = String::new();
    let mut rest = html;
    while let Some(open) = rest.find("<script") {
        let after = &rest[open..];
        let Some(tag_end) = after.find('>') else { break };
        let tag = &after[..tag_end];
        let body_start = &after[tag_end + 1..];
        let Some(close) = body_start.find("</script>") else { break };
        if !tag.contains("src=") {
            let digest = STANDARD.encode(Sha256::digest(&body_start.as_bytes()[..close]));
            out.push_str(" 'sha256-");
            out.push_str(&digest);
            out.push('\'');
        }
        rest = &body_start[close..];
    }
    out
}

pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(file) = (!path.is_empty()).then(|| Assets::get(path)).flatten() {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        let cache = if path.starts_with("_app/immutable/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return Response::builder()
            .header(header::CONTENT_TYPE, mime.as_ref())
            .header(header::CACHE_CONTROL, cache)
            .body(Body::from(file.data.into_owned()))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    match Assets::get("index.html") {
        Some(index) => {
            let mut resp = Body::from(index.data.into_owned()).into_response();
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
            resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            resp
        }
        None => (StatusCode::NOT_FOUND, "UI not built").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_only_inline_scripts() {
        let html = r#"<script src="/a.js"></script><script>x()</script><script type="module">y()</script>"#;
        let hashes = inline_script_hashes(html);
        assert_eq!(hashes.matches("'sha256-").count(), 2);
        assert!(hashes.contains(&STANDARD.encode(Sha256::digest(b"x()"))));
    }
}
