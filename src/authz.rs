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
    let fact = |k: &str, v: &str| format!("<dt>{k}</dt><dd>{}</dd>", html_escape(v));
    let (title, detail, facts, hint) = match reason {
        DenyReason::NotAllowed { device, host } => (
            "This device is not allowed on this app",
            "The app is restricted to some device groups, and this device is in none of them.",
            fact("Device", device) + &fact("App", host),
            "<strong>Need access?</strong> Add the device to one of the app's groups, or open \
             the app to every device, from tegata's Apps page.",
        ),
        DenyReason::NoLongerValid { device } => (
            "This certificate no longer works",
            "It was revoked, replaced by a newer one, or has expired.",
            fact("Device", device),
            "<strong>Fix it:</strong> remove this certificate from the device and install the \
             device's current one (Rotate in tegata gives a fresh install link).",
        ),
        DenyReason::Unknown => (
            "Unknown certificate",
            "The certificate this device presented was not issued for any registered device.",
            String::new(),
            "<strong>Fix it:</strong> enroll the device in tegata and install its own certificate.",
        ),
        DenyReason::NoCertificate => (
            "Client certificate required",
            "This site only answers devices that present a client certificate.",
            String::new(),
            "<strong>Fix it:</strong> enroll the device in tegata and install its certificate.",
        ),
    };
    let body = include_str!("denied.html")
        .replace("{{TITLE}}", title)
        .replace("{{DETAIL}}", detail)
        .replace("{{FACTS}}", &facts)
        .replace("{{HINT}}", hint);
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
        assert!(!body.contains("{{"), "every placeholder is filled");
    }
}
