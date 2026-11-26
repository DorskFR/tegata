use std::fmt::Write;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

use crate::app::{AppState, AuthzDecision, DenyReason};

/// The `Hash` (SHA-256 of the DER certificate) from the last element of an
/// `x-forwarded-client-cert` header.
pub fn xfcc_hash(header: &str) -> Option<String> {
    xfcc_field(header, "hash")
}

/// The subject CN from the last element of an `x-forwarded-client-cert` header.
pub fn xfcc_cn(header: &str) -> Option<String> {
    let subject = xfcc_field(header, "subject")?;
    subject.split(',').find_map(|rdn| {
        let (key, value) = rdn.split_once('=')?;
        key.trim().eq_ignore_ascii_case("cn").then(|| value.trim().to_owned())
    })
}

fn xfcc_field(header: &str, name: &str) -> Option<String> {
    let element = split_outside_quotes(header, ',').into_iter().last()?;
    split_outside_quotes(element, ';').into_iter().find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim().trim_matches('"').to_owned())
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

/// Envoy appends the peer it saw to `X-Forwarded-For`; anything before it is whatever the
/// client sent, so the address is counted from the end.
fn client_ip(headers: &HeaderMap, trusted_hops: usize) -> Option<String> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    header("x-envoy-external-address").map(str::to_owned).or_else(|| {
        let entries: Vec<&str> = header("x-forwarded-for")?.split(',').map(str::trim).collect();
        let at = entries.len().checked_sub(1 + trusted_hops)?;
        Some(entries[at].to_owned()).filter(|ip| !ip.is_empty())
    })
}

pub async fn check(State(app): State<AppState>, uri: Uri, headers: HeaderMap) -> Response {
    if !app.state_is_fresh() {
        tracing::error!(age = ?app.db.state_age(), "refusing checks: the state could not be reloaded");
        return (StatusCode::SERVICE_UNAVAILABLE, "tegata state is stale").into_response();
    }
    let xfcc = headers.get("x-forwarded-client-cert").and_then(|v| v.to_str().ok());
    let hash = xfcc.and_then(xfcc_hash);
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|ua| ua.chars().take(256).collect());
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str));
    let ip = client_ip(&headers, app.settings.trusted_hops);
    match app.authorize(hash.as_deref(), host, ip.clone(), user_agent.clone()).await {
        AuthzDecision::AllowUnknown => {
            tracing::info!(
                fingerprint = hash.as_deref().unwrap_or_default(),
                cn = ?xfcc.and_then(xfcc_cn),
                ?host,
                ?ip,
                ?user_agent,
                "allowed an unknown certificate"
            );
            StatusCode::OK.into_response()
        }
        AuthzDecision::Allow { device } => {
            let mut resp = StatusCode::OK.into_response();
            if !device.is_empty() {
                match HeaderValue::from_str(&header_safe(&device)) {
                    Ok(value) => {
                        resp.headers_mut().insert("x-tegata-device", value);
                    }
                    Err(err) => tracing::warn!(%device, %err, "x-tegata-device left out"),
                }
            }
            resp
        }
        AuthzDecision::Deny(reason) => denied_page(&reason),
    }
}

/// Percent-encodes `%` and every byte outside printable ASCII, so any name fits a header.
fn header_safe(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for byte in name.bytes() {
        if (0x20..0x7f).contains(&byte) && byte != b'%' {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
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

    #[test]
    fn parses_xfcc_cn() {
        assert_eq!(
            xfcc_cn(r#"Hash=ab;Subject="O=dorsk.dev,CN=artifact-uploader""#).as_deref(),
            Some("artifact-uploader")
        );
        assert_eq!(
            xfcc_cn(r#"By=x;Subject="CN=first",Hash=ab;Subject="C=JP,O=cyberia,CN=cyberia.dorsk.dev,emailAddress=a@b""#)
                .as_deref(),
            Some("cyberia.dorsk.dev")
        );
        assert_eq!(xfcc_cn("Hash=ab"), None);
        assert_eq!(xfcc_cn(r#"Hash=ab;Subject="O=no cn""#), None);
    }

    #[test]
    fn client_ip_is_counted_from_the_end() {
        let xff = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-for", HeaderValue::from_str(v).unwrap());
            h
        };
        let spoofed = xff("198.51.100.1, 203.0.113.7");
        assert_eq!(client_ip(&spoofed, 0).as_deref(), Some("203.0.113.7"));
        assert_eq!(client_ip(&spoofed, 1).as_deref(), Some("198.51.100.1"));
        assert_eq!(client_ip(&spoofed, 2), None);
        assert_eq!(client_ip(&xff("203.0.113.7"), 0).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn device_names_always_fit_a_header() {
        assert_eq!(header_safe("Zoe's phone"), "Zoe's phone");
        assert_eq!(header_safe("iPhone de Zoé"), "iPhone de Zo%C3%A9");
        assert_eq!(header_safe("100%"), "100%25");
        assert_eq!(header_safe("太郎"), "%E5%A4%AA%E9%83%8E");
        for name in ["iPhone de Zoé", "太郎のPixel", "tab\tname"] {
            assert!(HeaderValue::from_str(&header_safe(name)).is_ok(), "{name}");
        }
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
