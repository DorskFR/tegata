use std::collections::HashMap;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn, WebauthnBuilder,
};

use crate::app::{App, AppState};
use crate::error::{ApiError, ApiResult};
use crate::model::PasskeyRecord;
use crate::util::{now, random_token, sha256_hex};

pub const SESSION_COOKIE: &str = "tegata_session";
const CHALLENGE_COOKIE: &str = "tegata_challenge";
const CHALLENGE_TTL: Duration = Duration::minutes(5);

struct Registration {
    state: PasskeyRegistration,
    name: String,
    first: bool,
    expires_at: OffsetDateTime,
}

struct Login {
    state: PasskeyAuthentication,
    expires_at: OffsetDateTime,
}

pub struct Auth {
    webauthn: Webauthn,
    user_id: Uuid,
    sessions: Mutex<HashMap<String, OffsetDateTime>>,
    registrations: Mutex<HashMap<String, Registration>>,
    logins: Mutex<HashMap<String, Login>>,
}

impl Auth {
    pub fn new(public_url: &Url, rp_name: &str) -> anyhow::Result<Self> {
        let rp_id =
            public_url.host_str().ok_or_else(|| anyhow::anyhow!("public URL has no host"))?;
        let webauthn = WebauthnBuilder::new(rp_id, public_url)?.rp_name(rp_name).build()?;
        Ok(Self {
            webauthn,
            user_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, public_url.as_str().as_bytes()),
            sessions: Mutex::new(HashMap::new()),
            registrations: Mutex::new(HashMap::new()),
            logins: Mutex::new(HashMap::new()),
        })
    }

    pub async fn is_valid(&self, token: &str) -> bool {
        let t = now();
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, exp| *exp > t);
        sessions.contains_key(&sha256_hex(token.as_bytes()))
    }

    pub async fn end_session(&self, token: &str) {
        self.sessions.lock().await.remove(&sha256_hex(token.as_bytes()));
    }

    /// Opens a session without a passkey ceremony; for tests and tooling, never routed.
    #[doc(hidden)]
    pub async fn open_session(&self, hours: u32) -> String {
        self.new_session(hours).await
    }

    async fn new_session(&self, hours: u32) -> String {
        let token = random_token();
        self.sessions
            .lock()
            .await
            .insert(sha256_hex(token.as_bytes()), now() + Duration::hours(i64::from(hours)));
        token
    }
}

fn cookie(name: &'static str, value: String, max_age: Duration, secure: bool) -> Cookie<'static> {
    Cookie::build((name, value))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(max_age)
        .build()
}

fn challenge_id(jar: &CookieJar) -> ApiResult<String> {
    jar.get(CHALLENGE_COOKIE)
        .map(|c| c.value().to_owned())
        .ok_or_else(|| ApiError::bad_request("no passkey ceremony in progress"))
}

fn webauthn_error(err: impl std::fmt::Display) -> ApiError {
    tracing::warn!(error = %err, "passkey ceremony rejected");
    ApiError::Forbidden("passkey was not accepted".into())
}

pub async fn is_signed_in(app: &App, jar: &CookieJar) -> bool {
    match jar.get(SESSION_COOKIE) {
        Some(c) => app.auth.is_valid(c.value()).await,
        None => false,
    }
}

impl App {
    pub async fn start_registration(
        &self,
        jar: CookieJar,
        name: &str,
        setup_token: Option<&str>,
    ) -> ApiResult<(CookieJar, CreationChallengeResponse)> {
        let state = self.db.read().await;
        let first = state.passkeys.is_empty();
        if first {
            let given = setup_token.unwrap_or_default().trim();
            if sha256_hex(given.as_bytes()) != sha256_hex(self.settings.setup_token.as_bytes()) {
                return Err(ApiError::Forbidden("setup token does not match".into()));
            }
        } else if !is_signed_in(self, &jar).await {
            return Err(ApiError::Unauthorized);
        }
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(ApiError::bad_request("give the passkey a name of up to 64 characters"));
        }
        let exclude = state.passkeys.iter().map(|p| p.passkey.cred_id().clone()).collect();
        let (challenge, reg) = self
            .auth
            .webauthn
            .start_passkey_registration(
                self.auth.user_id,
                "admin",
                &self.settings.rp_name,
                Some(exclude),
            )
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?;
        let id = random_token();
        let mut regs = self.auth.registrations.lock().await;
        let t = now();
        regs.retain(|_, r| r.expires_at > t);
        regs.insert(
            id.clone(),
            Registration {
                state: reg,
                name: name.to_owned(),
                first,
                expires_at: t + CHALLENGE_TTL,
            },
        );
        let jar =
            jar.add(cookie(CHALLENGE_COOKIE, id, CHALLENGE_TTL, self.settings.secure_cookies()));
        Ok((jar, challenge))
    }

    pub async fn finish_registration(
        &self,
        jar: CookieJar,
        credential: &RegisterPublicKeyCredential,
    ) -> ApiResult<CookieJar> {
        let id = challenge_id(&jar)?;
        let reg = self
            .auth
            .registrations
            .lock()
            .await
            .remove(&id)
            .filter(|r| r.expires_at > now())
            .ok_or_else(|| ApiError::bad_request("passkey ceremony expired, try again"))?;
        if !reg.first && !is_signed_in(self, &jar).await {
            return Err(ApiError::Unauthorized);
        }
        let passkey = self
            .auth
            .webauthn
            .finish_passkey_registration(credential, &reg.state)
            .map_err(webauthn_error)?;
        self.db
            .update(|s| {
                if reg.first && !s.passkeys.is_empty() {
                    return Err(ApiError::Conflict("setup was already completed".into()));
                }
                s.passkeys.push(PasskeyRecord {
                    id: Uuid::new_v4(),
                    name: reg.name.clone(),
                    created_at: now(),
                    last_used_at: None,
                    passkey: passkey.clone(),
                });
                Ok(())
            })
            .await?;
        tracing::info!(name = %reg.name, "passkey registered");
        let jar = jar.remove(Cookie::build(CHALLENGE_COOKIE).path("/"));
        if reg.first {
            let token = self.auth.new_session(self.settings.session_hours).await;
            return Ok(jar.add(self.session_cookie(token)));
        }
        Ok(jar)
    }

    fn session_cookie(&self, token: String) -> Cookie<'static> {
        cookie(
            SESSION_COOKIE,
            token,
            Duration::hours(i64::from(self.settings.session_hours)),
            self.settings.secure_cookies(),
        )
    }

    pub async fn start_login(
        &self,
        jar: CookieJar,
    ) -> ApiResult<(CookieJar, RequestChallengeResponse)> {
        let passkeys: Vec<_> =
            self.db.read().await.passkeys.into_iter().map(|p| p.passkey).collect();
        if passkeys.is_empty() {
            return Err(ApiError::Conflict("no passkey is registered yet".into()));
        }
        let (challenge, state) = self
            .auth
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?;
        let id = random_token();
        let mut logins = self.auth.logins.lock().await;
        let t = now();
        logins.retain(|_, l| l.expires_at > t);
        logins.insert(id.clone(), Login { state, expires_at: t + CHALLENGE_TTL });
        let jar =
            jar.add(cookie(CHALLENGE_COOKIE, id, CHALLENGE_TTL, self.settings.secure_cookies()));
        Ok((jar, challenge))
    }

    pub async fn finish_login(
        &self,
        jar: CookieJar,
        credential: &PublicKeyCredential,
    ) -> ApiResult<CookieJar> {
        let id = challenge_id(&jar)?;
        let login = self
            .auth
            .logins
            .lock()
            .await
            .remove(&id)
            .filter(|l| l.expires_at > now())
            .ok_or_else(|| ApiError::bad_request("passkey ceremony expired, try again"))?;
        let result = self
            .auth
            .webauthn
            .finish_passkey_authentication(credential, &login.state)
            .map_err(webauthn_error)?;
        let name = self
            .db
            .update(|s| {
                let record = s
                    .passkeys
                    .iter_mut()
                    .find(|p| p.passkey.cred_id() == result.cred_id())
                    .ok_or_else(|| ApiError::Forbidden("passkey is not registered".into()))?;
                record.passkey.update_credential(&result);
                record.last_used_at = Some(now());
                Ok::<_, ApiError>(record.name.clone())
            })
            .await?;
        tracing::info!(passkey = %name, "signed in");
        let token = self.auth.new_session(self.settings.session_hours).await;
        Ok(jar.remove(Cookie::build(CHALLENGE_COOKIE).path("/")).add(self.session_cookie(token)))
    }

    pub async fn delete_passkey(&self, id: Uuid) -> ApiResult<()> {
        self.db
            .update(|s| {
                if !s.passkeys.iter().any(|p| p.id == id) {
                    return Err(ApiError::NotFound);
                }
                if s.passkeys.len() == 1 {
                    return Err(ApiError::Conflict("the last passkey cannot be removed".into()));
                }
                s.passkeys.retain(|p| p.id != id);
                Ok(())
            })
            .await
    }
}

/// Extractor guarding the admin API.
pub struct Admin;

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        app: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        if is_signed_in(app, &jar).await { Ok(Self) } else { Err(ApiError::Unauthorized) }
    }
}
