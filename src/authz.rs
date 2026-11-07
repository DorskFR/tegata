use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::app::{AppState, AuthzDecision};

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
        AuthzDecision::Deny => StatusCode::FORBIDDEN.into_response(),
    }
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
}
