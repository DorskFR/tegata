use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn, WebauthnBuilder,
};

use crate::app::{App, AppState};
use crate::error::{ApiError, ApiResult};
use crate::model::{CeremonyRecord, PasskeyRecord, RegistrationIntent, SessionRecord, State};
use crate::util::{now, random_token, sha256_hex};

pub const SESSION_COOKIE: &str = "tegata_session";
const CHALLENGE_COOKIE: &str = "tegata_challenge";
const CHALLENGE_TTL: Duration = Duration::minutes(5);

pub struct Auth {
    webauthn: Webauthn,
    user_id: Uuid,
}

impl Auth {
    pub fn new(public_url: &Url, rp_name: &str) -> anyhow::Result<Self> {
        let rp_id =
            public_url.host_str().ok_or_else(|| anyhow::anyhow!("public URL has no host"))?;
        let webauthn = WebauthnBuilder::new(rp_id, public_url)?.rp_name(rp_name).build()?;
        Ok(Self {
            webauthn,
            user_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, public_url.as_str().as_bytes()),
        })
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
        Some(c) => app.session_valid(c.value()).await,
        None => false,
    }
}

fn internal(err: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(anyhow::anyhow!("{err}"))
}

impl App {
    /// Checks the cached state, then the store, since another replica may have opened it.
    pub async fn session_valid(&self, token: &str) -> bool {
        let hash = sha256_hex(token.as_bytes());
        let found = |s: &State| {
            let t = now();
            s.sessions.iter().any(|x| x.token_hash == hash && x.expires_at > t)
        };
        if found(&self.db.read().await) {
            return true;
        }
        if let Err(err) = self.db.refresh().await {
            tracing::warn!(error = ?err, "refreshing state failed");
        }
        found(&self.db.read().await)
    }

    pub async fn end_session(&self, token: &str) -> ApiResult<()> {
        let hash = sha256_hex(token.as_bytes());
        self.db
            .update(|s| {
                s.prune(now());
                s.sessions.retain(|x| x.token_hash != hash);
                Ok::<_, ApiError>(())
            })
            .await
    }

    /// Opens a session without a passkey ceremony; for tests and tooling, never routed.
    #[doc(hidden)]
    pub async fn open_session(&self, hours: u32) -> ApiResult<String> {
        self.new_session(hours).await
    }

    async fn new_session(&self, hours: u32) -> ApiResult<String> {
        let token = random_token();
        let record = SessionRecord {
            token_hash: sha256_hex(token.as_bytes()),
            expires_at: now() + Duration::hours(i64::from(hours)),
        };
        self.db
            .update(|s| {
                s.prune(now());
                s.sessions.push(record.clone());
                Ok::<_, ApiError>(())
            })
            .await?;
        Ok(token)
    }

    async fn store_ceremony(
        &self,
        registration: Option<RegistrationIntent>,
        state: serde_json::Value,
    ) -> ApiResult<String> {
        let id = random_token();
        let record = CeremonyRecord {
            id_hash: sha256_hex(id.as_bytes()),
            registration,
            state,
            expires_at: now() + CHALLENGE_TTL,
        };
        self.db
            .update(|s| {
                s.prune(now());
                s.ceremonies.push(record.clone());
                Ok::<_, ApiError>(())
            })
            .await?;
        Ok(id)
    }

    /// Removes and returns the ceremony; one check-and-set write, so it is used once.
    async fn take_ceremony(&self, jar: &CookieJar) -> ApiResult<CeremonyRecord> {
        let id = challenge_id(jar)?;
        let hash = sha256_hex(id.as_bytes());
        if let Err(err) = self.db.refresh().await {
            tracing::warn!(error = ?err, "refreshing state failed");
        }
        self.db
            .update(|s| {
                s.prune(now());
                let at =
                    s.ceremonies.iter().position(|c| c.id_hash == hash).ok_or_else(|| {
                        ApiError::bad_request("passkey ceremony expired, try again")
                    })?;
                Ok(s.ceremonies.remove(at))
            })
            .await
    }

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
            .map_err(internal)?;
        let intent = RegistrationIntent { name: name.to_owned(), first };
        let id = self
            .store_ceremony(Some(intent), serde_json::to_value(&reg).map_err(internal)?)
            .await?;
        let jar =
            jar.add(cookie(CHALLENGE_COOKIE, id, CHALLENGE_TTL, self.settings.secure_cookies()));
        Ok((jar, challenge))
    }

    pub async fn finish_registration(
        &self,
        jar: CookieJar,
        credential: &RegisterPublicKeyCredential,
    ) -> ApiResult<CookieJar> {
        let ceremony = self.take_ceremony(&jar).await?;
        let reg = ceremony
            .registration
            .ok_or_else(|| ApiError::bad_request("passkey ceremony expired, try again"))?;
        let state: PasskeyRegistration =
            serde_json::from_value(ceremony.state).map_err(internal)?;
        if !reg.first && !is_signed_in(self, &jar).await {
            return Err(ApiError::Unauthorized);
        }
        let passkey = self
            .auth
            .webauthn
            .finish_passkey_registration(credential, &state)
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
            let token = self.new_session(self.settings.session_hours).await?;
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
        let (challenge, state) =
            self.auth.webauthn.start_passkey_authentication(&passkeys).map_err(internal)?;
        let id = self.store_ceremony(None, serde_json::to_value(&state).map_err(internal)?).await?;
        let jar =
            jar.add(cookie(CHALLENGE_COOKIE, id, CHALLENGE_TTL, self.settings.secure_cookies()));
        Ok((jar, challenge))
    }

    pub async fn finish_login(
        &self,
        jar: CookieJar,
        credential: &PublicKeyCredential,
    ) -> ApiResult<CookieJar> {
        let ceremony = self.take_ceremony(&jar).await?;
        if ceremony.registration.is_some() {
            return Err(ApiError::bad_request("passkey ceremony expired, try again"));
        }
        let state: PasskeyAuthentication =
            serde_json::from_value(ceremony.state).map_err(internal)?;
        let result = self
            .auth
            .webauthn
            .finish_passkey_authentication(credential, &state)
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
        let token = self.new_session(self.settings.session_hours).await?;
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
