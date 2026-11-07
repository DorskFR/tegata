pub mod api;
pub mod app;
pub mod auth;
pub mod authz;
pub mod bundle;
pub mod ca;
pub mod config;
pub mod db;
pub mod enroll;
pub mod error;
pub mod kube;
pub mod model;
pub mod openbao;
pub mod rules;
pub mod store;
pub mod util;
pub mod web;

use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post, put};

pub use crate::app::{App, AppState};
use crate::error::ApiError;

pub fn router(app: AppState) -> Router {
    let csp = HeaderValue::from_str(&web::content_security_policy())
        .unwrap_or_else(|_| HeaderValue::from_static("default-src 'self'"));
    let api = Router::new()
        .route("/session", get(api::session))
        .route("/config", get(api::config))
        .route("/auth/register/start", post(api::register_start))
        .route("/auth/register/finish", post(api::register_finish))
        .route("/auth/login/start", post(api::login_start))
        .route("/auth/login/finish", post(api::login_finish))
        .route("/auth/logout", post(api::logout))
        .route("/passkeys", get(api::passkeys))
        .route("/passkeys/{id}", delete(api::delete_passkey))
        .route("/devices", get(api::devices).post(api::create_device))
        .route("/devices/{id}", delete(api::delete_device).patch(api::patch_device))
        .route("/groups", get(api::groups))
        .route("/apps", get(api::apps).post(api::add_app).put(api::set_app_rules))
        .route("/apps/{host}", put(api::set_app_rule).delete(api::remove_app))
        .route("/devices/{id}/rotate", post(api::rotate))
        .route("/devices/{id}/enrollment", post(api::new_enrollment))
        .route("/devices/{id}/revoke", post(api::revoke))
        .route("/enroll/{token}", get(api::enrollment))
        .route_layer(middleware::from_fn_with_state(app.clone(), same_origin));
    Router::new()
        .nest("/api", api)
        .route("/enroll/{token}/profile.mobileconfig", get(api::download_profile))
        .route("/enroll/{token}/device.p12", get(api::download_p12))
        .route("/ca.crt", get(api::ca_pem))
        .route("/crl.pem", get(api::crl_pem))
        .route("/healthz", get(|| async { "ok" }))
        .fallback(web::serve)
        .layer(middleware::from_fn(move |req, next| security_headers(csp.clone(), req, next)))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(app)
}

/// The Envoy ext_authz endpoint, served on its own port so it is never exposed publicly.
pub fn authz_router(app: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .fallback(any(authz::check))
        .with_state(app)
}

/// Rejects state-changing API calls that do not come from the app's own origin.
async fn same_origin(State(app): State<AppState>, req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }
    let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if origin != Some(app.settings.origin().as_str()) {
        return ApiError::Forbidden("cross-origin request refused".into()).into_response();
    }
    next.run(req).await
}

async fn security_headers(csp: HeaderValue, req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, csp);
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    resp
}

/// Sweeps stale enrollments every minute, refreshes the published CRL periodically and
/// picks up other replicas' writes every couple of seconds.
pub fn spawn_background(app: AppState, crl_every: Duration) {
    let refresher = app.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            tick.tick().await;
            if let Err(err) = refresher.db.refresh().await {
                tracing::warn!(error = ?err, "refreshing state failed");
            }
        }
    });
    let sweeper = app.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if let Err(err) = sweeper.sweep().await {
                tracing::error!(error = ?err, "sweep failed");
            }
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(crl_every);
        loop {
            tick.tick().await;
            if let Err(err) = app.refresh_crl().await {
                tracing::error!(error = ?err, "refreshing the CRL failed");
            }
        }
    });
}
