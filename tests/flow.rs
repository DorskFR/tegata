use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tegata::app::{App, AppState};
use tegata::config::Cli;
use tower::ServiceExt;

const ORIGIN: &str = "https://tegata.test";

struct Harness {
    app: AppState,
    dir: std::path::PathBuf,
    cookie: String,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn harness() -> Harness {
    let dir = std::env::temp_dir().join(format!("tegata-flow-{}", uuid::Uuid::new_v4()));
    let cli = <Cli as clap::Parser>::parse_from([
        "tegata",
        "--public-url",
        ORIGIN,
        "--backend",
        "memory",
        "--data-dir",
        dir.to_str().unwrap(),
        "--setup-token",
        "setup",
    ]);
    let app: Arc<App> = Arc::new(cli.build().await.unwrap());
    let session = app.auth.open_session(1).await;
    Harness { app, dir, cookie: format!("tegata_session={session}") }
}

impl Harness {
    async fn call(
        &self,
        method: &str,
        uri: &str,
        body: Option<Value>,
        auth: bool,
    ) -> (StatusCode, Vec<u8>, header::HeaderMap) {
        let mut req = Request::builder().method(method).uri(uri).header(header::ORIGIN, ORIGIN);
        if auth {
            req = req.header(header::COOKIE, &self.cookie);
        }
        let req = match body {
            Some(b) => {
                req.header(header::CONTENT_TYPE, "application/json").body(Body::from(b.to_string()))
            }
            None => req.body(Body::empty()),
        }
        .unwrap();
        let resp = tegata::router(self.app.clone()).oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, bytes, headers)
    }

    async fn json(&self, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let (status, bytes, _) = self.call(method, uri, body, true).await;
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn authz(&self, fingerprint: &str) -> StatusCode {
        self.authz_at("/authz/some/path", fingerprint).await
    }

    async fn authz_at(&self, uri: &str, fingerprint: &str) -> StatusCode {
        self.authz_full(uri, fingerprint, None).await
    }

    async fn authz_host(&self, host: &str, fingerprint: &str) -> StatusCode {
        self.authz_full("/authz/", fingerprint, Some(host)).await
    }

    async fn authz_full(&self, uri: &str, fingerprint: &str, host: Option<&str>) -> StatusCode {
        let mut req = Request::builder().uri(uri);
        if let Some(host) = host {
            req = req.header(header::HOST, host);
        }
        let req = req
            .header("x-forwarded-client-cert", format!("Hash={fingerprint};Subject=\"CN=x\""))
            .header("x-forwarded-for", "203.0.113.7")
            .body(Body::empty())
            .unwrap();
        tegata::authz_router(self.app.clone()).oneshot(req).await.unwrap().status()
    }
}

fn token_of(created: &Value) -> String {
    created["enrollment"]["url"].as_str().unwrap().rsplit('/').next().unwrap().to_owned()
}

fn crl_serials(pem: &str) -> Vec<String> {
    let block = pem::parse(pem).unwrap();
    let (_, crl) = x509_parser::parse_x509_crl(block.contents()).unwrap();
    crl.iter_revoked_certificates().map(|r| tegata::util::format_serial(r.raw_serial())).collect()
}

#[tokio::test]
async fn guards() {
    let h = harness().await;
    let (status, _, _) = h.call("GET", "/api/devices", None, false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = h.call("GET", "/authz", None, false).await;
    assert_ne!(status, StatusCode::FORBIDDEN, "authz is not served on the public router");

    let req = Request::builder()
        .method("POST")
        .uri("/api/devices")
        .header(header::COOKIE, &h.cookie)
        .header(header::ORIGIN, "https://evil.test")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"name":"x"}"#))
        .unwrap();
    let resp = tegata::router(h.app.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let (status, body, headers) = h.call("GET", "/api/session", None, false).await;
    assert_eq!(status, StatusCode::OK);
    let session: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(session["setup_required"], true);
    assert_eq!(session["authenticated"], false);
    assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
    assert!(
        headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );

    let (status, _) = h
        .json("POST", "/api/auth/register/start", Some(json!({"name": "k", "setup_token": "nope"})))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, options) = h
        .json(
            "POST",
            "/api/auth/register/start",
            Some(json!({"name": "k", "setup_token": "setup"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(options["publicKey"]["challenge"].is_string());
    assert_eq!(options["publicKey"]["rp"]["id"], "tegata.test");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn device_lifecycle() {
    let h = harness().await;

    let (status, created) = h
        .json(
            "POST",
            "/api/devices",
            Some(json!({"name": "phone", "owner": "me", "validity_days": 30})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["device"]["status"], "pending");
    let password = created["enrollment"]["password"].as_str().unwrap().to_owned();
    let first_fp = created["device"]["cert"]["fingerprint_sha256"].as_str().unwrap().to_owned();
    let first_serial = created["device"]["cert"]["serial"].as_str().unwrap().to_owned();
    let token = token_of(&created);

    let (status, _) = h.json("POST", "/api/devices", Some(json!({"name": "PHONE"}))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) =
        h.json("POST", "/api/devices", Some(json!({"name": "x", "validity_days": 9999}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h.json("POST", "/api/devices", Some(json!({"name": "a/b"}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    assert_eq!(h.authz(&first_fp).await, StatusCode::FORBIDDEN, "pending certs are not usable yet");

    let (status, info) = h.json("GET", &format!("/api/enroll/{token}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["device_name"], "phone");

    let (status, p12, headers) =
        h.call("GET", &format!("/enroll/{token}/device.p12"), None, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/x-pkcs12");
    assert_eq!(headers[header::CONTENT_DISPOSITION], "attachment; filename=\"phone.p12\"");
    let store = p12_keystore::KeyStore::from_pkcs12(
        &p12,
        &password,
        p12_keystore::Pkcs12ImportPolicy::default(),
    )
    .unwrap();
    let (_, chain) = store.private_key_chain().unwrap();
    assert_eq!(tegata::util::sha256_hex(chain.certs()[0].as_der()), first_fp);

    let (status, _, _) = h.call("GET", &format!("/enroll/{token}/device.p12"), None, false).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "links work once");
    let (status, _, _) =
        h.call("GET", &format!("/enroll/{token}/profile.mobileconfig"), None, false).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    assert_eq!(h.authz(&first_fp).await, StatusCode::OK);
    for uri in ["/authz", "/authz/", "/authz?q=1", "/elsewhere"] {
        assert_eq!(h.authz_at(uri, &first_fp).await, StatusCode::OK, "{uri}");
    }
    assert_eq!(h.authz(&first_fp.to_uppercase()).await, StatusCode::OK);
    assert_eq!(h.authz("00ff").await, StatusCode::FORBIDDEN);
    h.app.flush_seen().await.unwrap();

    let (_, devices) = h.json("GET", "/api/devices", None).await;
    let device = &devices[0];
    assert_eq!(device["status"], "active");
    assert_eq!(device["last_seen"]["ip"], "203.0.113.7");
    let id = device["id"].as_str().unwrap().to_owned();

    let (status, rotated) =
        h.json("POST", &format!("/api/devices/{id}/rotate"), Some(json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    assert_eq!(rotated["device"]["status"], "active");
    assert_eq!(rotated["device"]["rotation"]["state"], "pending");
    assert_eq!(
        h.authz(&first_fp).await,
        StatusCode::OK,
        "old cert works until the new one is installed"
    );

    let (status, relinked) = h.json("POST", &format!("/api/devices/{id}/enrollment"), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) =
        h.call("GET", &format!("/enroll/{}/device.p12", token_of(&rotated)), None, false).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a new link voids the previous one");

    let (status, profile, headers) = h
        .call("GET", &format!("/enroll/{}/profile.mobileconfig", token_of(&relinked)), None, false)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/x-apple-aspen-config");
    assert!(String::from_utf8(profile).unwrap().contains(&format!("tegata.{id}")));

    let second_fp =
        relinked["device"]["rotation"]["fingerprint_sha256"].as_str().unwrap().to_owned();
    assert_eq!(
        h.authz(&first_fp).await,
        StatusCode::FORBIDDEN,
        "installing the rotation retires the old cert"
    );
    assert_eq!(h.authz(&second_fp).await, StatusCode::OK);
    let crl = h.app.ca.crl_pem().await.unwrap();
    assert!(crl_serials(&crl).contains(&first_serial));

    let (_, devices) = h.json("GET", "/api/devices", None).await;
    let history: Vec<&str> = devices[0]["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["state"].as_str().unwrap())
        .collect();
    assert_eq!(history, ["revoked", "superseded"]);

    let (status, _) = h.json("DELETE", &format!("/api/devices/{id}"), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, revoked) = h.json("POST", &format!("/api/devices/{id}/revoke"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(revoked["status"], "revoked");
    assert_eq!(h.authz(&second_fp).await, StatusCode::FORBIDDEN);
    let second_serial = revoked["cert"]["serial"].as_str().unwrap().to_owned();
    assert!(crl_serials(&h.app.ca.crl_pem().await.unwrap()).contains(&second_serial));

    let (status, _) = h.json("DELETE", &format!("/api/devices/{id}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn sweeper_revokes_lost_enrollments() {
    let h = harness().await;
    let (_, created) = h.json("POST", "/api/devices", Some(json!({"name": "laptop"}))).await;
    let serial = created["device"]["cert"]["serial"].as_str().unwrap().to_owned();
    h.app.enrollments.take(&token_of(&created), tegata::util::now()).await.unwrap();
    h.app.sweep().await.unwrap();
    let (_, devices) = h.json("GET", "/api/devices", None).await;
    assert_eq!(devices[0]["status"], "revoked");
    assert!(crl_serials(&h.app.ca.crl_pem().await.unwrap()).contains(&serial));
}

#[tokio::test]
async fn validity_reaches_the_ca_lifetime() {
    let h = harness().await;
    let (status, config) = h.json("GET", "/api/config", None).await;
    assert_eq!(status, StatusCode::OK);
    let max = config["validity_days"]["max"].as_u64().unwrap();
    let presets: Vec<u64> = config["validity_days"]["presets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    assert!(max > 3000, "the local CA lasts ten years, got {max}");
    assert_eq!(presets.last(), Some(&max));
    assert!(presets.contains(&1825));
    assert_eq!(config["validity_days"]["default"], 365);

    let ca_not_after = time::OffsetDateTime::parse(
        config["ca_not_after"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let (status, created) = h
        .json("POST", "/api/devices", Some(json!({"name": "forever", "validity_days": max})))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let not_after = time::OffsetDateTime::parse(
        created["device"]["cert"]["not_after"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert!(not_after <= ca_not_after);
    assert!(ca_not_after - not_after < time::Duration::days(2));

    let (status, _) = h
        .json("POST", "/api/devices", Some(json!({"name": "too-long", "validity_days": max + 1})))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

async fn installed(h: &Harness, name: &str, groups: &[&str]) -> String {
    let (status, created) =
        h.json("POST", "/api/devices", Some(json!({"name": name, "groups": groups}))).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let (status, _, _) =
        h.call("GET", &format!("/enroll/{}/device.p12", token_of(&created)), None, false).await;
    assert_eq!(status, StatusCode::OK);
    created["device"]["cert"]["fingerprint_sha256"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn app_rules() {
    let h = harness().await;
    let admin = installed(&h, "laptop", &["Admin", "family"]).await;
    let kid = installed(&h, "tablet", &["family"]).await;

    assert_eq!(h.authz_host("Media.Example.com:443", &kid).await, StatusCode::OK);
    assert_eq!(h.authz_host("nas.example.com", &admin).await, StatusCode::OK);
    h.app.flush_seen().await.unwrap();
    let (_, apps) = h.json("GET", "/api/apps", None).await;
    let hosts: Vec<&str> =
        apps.as_array().unwrap().iter().map(|a| a["host"].as_str().unwrap()).collect();
    assert_eq!(hosts, ["media.example.com", "nas.example.com"], "apps are learned from traffic");
    assert_eq!(apps[0]["restricted"], false);
    assert!(apps[0]["first_seen"].is_string());

    let (status, _) =
        h.json("PUT", "/api/apps/nas.example.com", Some(json!({"restricted": true}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "restricting needs a group");
    let (status, rule) = h
        .json(
            "PUT",
            "/api/apps/nas.example.com",
            Some(json!({"restricted": true, "groups": ["ADMIN"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{rule}");
    assert_eq!(rule["groups"], json!(["admin"]));

    assert_eq!(h.authz_host("nas.example.com", &admin).await, StatusCode::OK);
    assert_eq!(h.authz_host("nas.example.com", &kid).await, StatusCode::FORBIDDEN);
    assert_eq!(
        h.authz_host("media.example.com", &kid).await,
        StatusCode::OK,
        "open apps stay open"
    );

    let (_, devices) = h.json("GET", "/api/devices", None).await;
    let tablet = devices.as_array().unwrap().iter().find(|d| d["name"] == "tablet").unwrap();
    assert_eq!(tablet["groups"], json!(["family"]));
    let id = tablet["id"].as_str().unwrap();
    let (status, patched) = h
        .json("PATCH", &format!("/api/devices/{id}"), Some(json!({"groups": ["family", "admin"]})))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(patched["groups"], json!(["admin", "family"]));
    assert_eq!(h.authz_host("nas.example.com", &kid).await, StatusCode::OK);

    let (_, groups) = h.json("GET", "/api/groups", None).await;
    assert_eq!(groups, json!(["admin", "family"]));

    let (status, _) = h.json("POST", "/api/apps", Some(json!({"host": "new.example.com"}))).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = h.json("POST", "/api/apps", Some(json!({"host": "NEW.example.com"}))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = h.json("POST", "/api/apps", Some(json!({"host": "not a host"}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h.json("DELETE", "/api/apps/new.example.com", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) =
        h.json("PATCH", &format!("/api/devices/{id}"), Some(json!({"groups": ["a b"]}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_certificates_only_reach_open_apps() {
    let dir = std::env::temp_dir().join(format!("tegata-unknown-{}", uuid::Uuid::new_v4()));
    let cli = <Cli as clap::Parser>::parse_from([
        "tegata",
        "--public-url",
        ORIGIN,
        "--backend",
        "memory",
        "--data-dir",
        dir.to_str().unwrap(),
        "--authz-allow-unknown",
    ]);
    let app: Arc<App> = Arc::new(cli.build().await.unwrap());
    let session = app.auth.open_session(1).await;
    let h = Harness { app, dir, cookie: format!("tegata_session={session}") };
    assert_eq!(h.authz_host("open.example.com", "00aa").await, StatusCode::OK);
    h.app.flush_seen().await.unwrap();
    h.json("POST", "/api/apps", Some(json!({"host": "locked.example.com"}))).await;
    h.json(
        "PUT",
        "/api/apps/locked.example.com",
        Some(json!({"restricted": true, "groups": ["admin"]})),
    )
    .await;
    assert_eq!(h.authz_host("locked.example.com", "00aa").await, StatusCode::FORBIDDEN);
    assert_eq!(h.authz_host("open.example.com", "00aa").await, StatusCode::OK);
}
