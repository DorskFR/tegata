use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::app::{AppState, Download};
use crate::auth::{Admin, SESSION_COOKIE, is_signed_in};
use crate::error::{ApiError, ApiResult};

pub async fn session(State(app): State<AppState>, jar: CookieJar) -> Json<Value> {
    let setup_required = app.db.read().await.passkeys.is_empty();
    Json(json!({
        "authenticated": is_signed_in(&app, &jar).await,
        "setup_required": setup_required,
        "rp_name": app.settings.rp_name,
    }))
}

pub async fn config(State(app): State<AppState>, _: Admin) -> Json<Value> {
    let s = &app.settings;
    Json(json!({
        "validity_days": {
            "default": s.default_validity_days,
            "max": s.max_validity_days,
            "presets": s.validity_presets,
        },
        "expiring_days": s.expiring_days,
        "enrollment_minutes": s.enrollment_minutes,
        "ca_subject": app.ca.subject(),
        "ca_not_after": app.ca.not_after().format(&time::format_description::well_known::Rfc3339).ok(),
    }))
}

#[derive(Deserialize)]
pub struct RegisterStart {
    name: String,
    setup_token: Option<String>,
}

pub async fn register_start(
    State(app): State<AppState>,
    jar: CookieJar,
    Json(body): Json<RegisterStart>,
) -> ApiResult<impl IntoResponse> {
    let (jar, challenge) =
        app.start_registration(jar, &body.name, body.setup_token.as_deref()).await?;
    Ok((jar, Json(challenge)))
}

pub async fn register_finish(
    State(app): State<AppState>,
    jar: CookieJar,
    Json(credential): Json<RegisterPublicKeyCredential>,
) -> ApiResult<impl IntoResponse> {
    Ok((app.finish_registration(jar, &credential).await?, StatusCode::NO_CONTENT))
}

pub async fn login_start(
    State(app): State<AppState>,
    jar: CookieJar,
) -> ApiResult<impl IntoResponse> {
    let (jar, challenge) = app.start_login(jar).await?;
    Ok((jar, Json(challenge)))
}

pub async fn login_finish(
    State(app): State<AppState>,
    jar: CookieJar,
    Json(credential): Json<PublicKeyCredential>,
) -> ApiResult<impl IntoResponse> {
    Ok((app.finish_login(jar, &credential).await?, StatusCode::NO_CONTENT))
}

pub async fn logout(State(app): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    if let Some(c) = jar.get(SESSION_COOKIE) {
        app.auth.end_session(c.value()).await;
    }
    (
        jar.remove(axum_extra::extract::cookie::Cookie::build(SESSION_COOKIE).path("/")),
        StatusCode::NO_CONTENT,
    )
}

pub async fn passkeys(State(app): State<AppState>, _: Admin) -> Json<Value> {
    let list: Vec<Value> = app
        .db
        .read()
        .await
        .passkeys
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
                "name": p.name,
                "created_at": p.created_at.format(&time::format_description::well_known::Rfc3339).ok(),
                "last_used_at": p.last_used_at.and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok()),
            })
        })
        .collect();
    Json(Value::Array(list))
}

pub async fn delete_passkey(
    State(app): State<AppState>,
    _: Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    app.delete_passkey(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn devices(State(app): State<AppState>, _: Admin) -> impl IntoResponse {
    Json(app.devices().await)
}

#[derive(Deserialize)]
pub struct NewDevice {
    name: String,
    #[serde(default)]
    owner: String,
    validity_days: Option<u32>,
}

pub async fn create_device(
    State(app): State<AppState>,
    _: Admin,
    Json(body): Json<NewDevice>,
) -> ApiResult<impl IntoResponse> {
    let created = app.create_device(&body.name, &body.owner, body.validity_days).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

#[derive(Deserialize, Default)]
pub struct Rotate {
    validity_days: Option<u32>,
}

pub async fn rotate(
    State(app): State<AppState>,
    _: Admin,
    Path(id): Path<Uuid>,
    body: Option<Json<Rotate>>,
) -> ApiResult<impl IntoResponse> {
    let body = body.map(|b| b.0).unwrap_or_default();
    Ok(Json(app.rotate(id, body.validity_days).await?))
}

pub async fn new_enrollment(
    State(app): State<AppState>,
    _: Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(app.new_enrollment(id).await?))
}

pub async fn revoke(
    State(app): State<AppState>,
    _: Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    Ok(Json(app.revoke_device(id).await?))
}

pub async fn delete_device(
    State(app): State<AppState>,
    _: Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    app.delete_device(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn enrollment(
    State(app): State<AppState>,
    Path(token): Path<String>,
) -> ApiResult<Json<Value>> {
    let (device_name, expires_at) = app.enrollment_info(&token).await.ok_or(ApiError::NotFound)?;
    Ok(Json(json!({
        "device_name": device_name,
        "expires_at": expires_at.format(&time::format_description::well_known::Rfc3339).map_err(|e| ApiError::Internal(e.into()))?,
    })))
}

fn attachment(bytes: Vec<u8>, content_type: &'static str, name: &str, extension: &str) -> Response {
    let stem: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    let safe = format!("{stem}.{extension}");
    let mut resp = bytes.into_response();
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{safe}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    resp
}

pub async fn download_profile(
    State(app): State<AppState>,
    Path(token): Path<String>,
) -> ApiResult<Response> {
    let (bytes, name) = app.download(&token, &Download::Profile).await?;
    Ok(attachment(bytes, "application/x-apple-aspen-config", &name, "mobileconfig"))
}

pub async fn download_p12(
    State(app): State<AppState>,
    Path(token): Path<String>,
) -> ApiResult<Response> {
    let (bytes, name) = app.download(&token, &Download::Pkcs12).await?;
    Ok(attachment(bytes, "application/x-pkcs12", &name, "p12"))
}

pub async fn ca_pem(State(app): State<AppState>) -> Response {
    let mut resp = app.ca.ca_pem().to_owned().into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/x-pem-file"));
    resp
}

pub async fn crl_pem(State(app): State<AppState>) -> ApiResult<Response> {
    let mut resp = app.ca.crl_pem().await?.into_response();
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/x-pem-file"));
    Ok(resp)
}
