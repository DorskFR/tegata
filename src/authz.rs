use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::app::{AppState, AuthzDecision, DenyReason};

/// The `Hash` (SHA-256 of the DER certificate) from the last element of an
/// `x-forwarded-client-cert` header.
pub fn xfcc_hash(header: &str) -> Option<String> {
    let element = split_outside_quotes(header, ',').into_iter().last()?;
    split_outside_quotes(element, ';').into_iter().find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim().eq_ignore_ascii_case("hash").then(|| value.trim().trim_matches('"').to_owned())
    })
}

fn split_outside_quotes(s: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in s.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => quoted = !quoted,
            c if c == sep && !quoted => {
                parts.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

fn client_ip(headers: &HeaderMap) -> Option<String> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    header("x-envoy-external-address").map(str::to_owned).or_else(|| {
        header("x-forwarded-for").and_then(|v| v.split(',').next()).map(|v| v.trim().to_owned())
    })
}

pub async fn check(State(app): State<AppState>, headers: HeaderMap) -> Response {
    let hash =
        headers.get("x-forwarded-client-cert").and_then(|v| v.to_str().ok()).and_then(xfcc_hash);
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|ua| ua.chars().take(256).collect());
    let host = ["x-forwarded-host", "host"]
        .iter()
        .find_map(|name| headers.get(*name).and_then(|v| v.to_str().ok()));
    match app.authorize(hash.as_deref(), host, client_ip(&headers), user_agent).await {
        AuthzDecision::Allow { device } => {
            let mut resp = StatusCode::OK.into_response();
            if let Ok(value) = HeaderValue::from_str(&device)
                && !device.is_empty()
            {
                resp.headers_mut().insert("x-tegata-device", value);
            }
            resp
        }
        AuthzDecision::Deny(reason) => denied_page(&reason),
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Envoy relays this to the browser as is, so a refusal reads as one.
fn denied_page(reason: &DenyReason) -> Response {
    let (title, detail) = match reason {
        DenyReason::NotAllowed { device, host } => (
            "This device is not allowed here".to_owned(),
            format!(
                "<strong>{}</strong> is not in a group allowed on <strong>{}</strong>. \
                 Ask whoever runs the gateway to change the device's groups or the app's access.",
                html_escape(device),
                html_escape(host)
            ),
        ),
        DenyReason::NoLongerValid { device } => (
            "This certificate no longer works".to_owned(),
            format!(
                "The certificate for <strong>{}</strong> was revoked, replaced or has expired. \
                 Remove it from this device and install its current one.",
                html_escape(device)
            ),
        ),
        DenyReason::Unknown => (
            "Unknown certificate".to_owned(),
            "This certificate was not issued for any registered device.".to_owned(),
        ),
        DenyReason::NoCertificate => (
            "Client certificate required".to_owned(),
            "This site needs a client certificate installed on the device.".to_owned(),
        ),
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>403 · {title}</title><style>\
         body{{font:16px/1.5 system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;\
         background:#f4f5f7;color:#1c2330}}main{{max-width:32rem;margin:1.5rem;padding:2rem;background:#fff;\
         border:1px solid #dde1e7;border-radius:12px}}h1{{font-size:1.25rem;margin:.25rem 0 .75rem}}\
         p{{margin:0;color:#4a5363}}small{{color:#8a93a3;letter-spacing:.08em;text-transform:uppercase}}\
         @media(prefers-color-scheme:dark){{body{{background:#14171c;color:#e6e9ee}}\
         main{{background:#1c2027;border-color:#2c323c}}p{{color:#b3bac6}}}}</style></head>\
         <body><main><small>403 · tegata</small><h1>{title}</h1><p>{detail}</p></main></body></html>"
    );
    let mut resp = (StatusCode::FORBIDDEN, body).into_response();
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xfcc() {
        assert_eq!(
            xfcc_hash(r#"Hash=AbC123;Subject="CN=a,O=b;c";URI=spiffe://x"#).as_deref(),
            Some("AbC123")
        );
        assert_eq!(
            xfcc_hash(r#"By=x;Hash=first,By=y;Hash=second;Subject="CN=q""#).as_deref(),
            Some("second")
        );
        assert_eq!(xfcc_hash(r#"Subject="CN=no hash""#), None);
        assert_eq!(xfcc_hash(""), None);
    }

    #[tokio::test]
    async fn refusals_explain_themselves() {
        use http_body_util::BodyExt;
        let resp = denied_page(&DenyReason::NotAllowed {
            device: "<tablet>".into(),
            host: "nas.example.com".into(),
        });
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("&lt;tablet&gt;") && !body.contains("<tablet>"));
        assert!(body.contains("nas.example.com"));
    }
}
