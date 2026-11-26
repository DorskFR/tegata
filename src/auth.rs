use std::future::{Future, ready};
use std::net::IpAddr;
use std::time::SystemTime;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use kagi::{
    Account, CreationChallengeResponse, CredentialStore, Kagi, MemoryCeremonies, Passkey,
    PasskeyRole, Proof, PublicKeyCredential, RegisterPublicKeyCredential, Removal,
    RequestChallengeResponse, Settings, Stored, StoredPasskey,
};
use time::Duration;
use url::Url;
use uuid::Uuid;

use crate::app::{App, AppState};
use crate::error::{ApiError, ApiResult};
use crate::model::{PasskeyRecord, SessionRecord};
use crate::util::{Failures, now, random_token, sha256_hex};

pub const SESSION_COOKIE: &str = "tegata_session";
const CHALLENGE_COOKIE: &str = "tegata_challenge";
const CHALLENGE_TTL: Duration = Duration::minutes(5);
/// Adding or removing a passkey needs a sign-in this recent, so a session cookie alone is not
/// enough.
pub const STEP_UP: std::time::Duration = std::time::Duration::from_mins(5);
const ADMIN: &str = "admin";
const SETUP: &str = "setup";

pub struct Auth {
    kagi: Kagi<()>,
    user_id: Uuid,
    pub(crate) failures: Failures,
}

impl Auth {
    pub fn new(public_url: &Url, rp_name: &str) -> anyhow::Result<Self> {
        let decoy_key: [u8; 32] = rand::random();
        let settings =
            Settings { step_up: STEP_UP, ..Settings::new(public_url, rp_name, &decoy_key) };
        Ok(Self {
            kagi: Kagi::new(settings, MemoryCeremonies::default())?,
            user_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, public_url.as_str().as_bytes()),
            failures: Failures::default(),
        })
    }
}

/// The admin's passkeys in the shared state, as kagi sees them.
struct Passkeys<'a> {
    app: &'a App,
    added_by: Option<Uuid>,
}

fn stored(record: &PasskeyRecord) -> Stored<Passkeys<'_>> {
    StoredPasskey { id: record.id, user: (), passkey: record.passkey.clone() }
}

impl CredentialStore for Passkeys<'_> {
    type User = ();
    type PasskeyId = Uuid;
    type Error = ApiError;

    fn user_handle(&self, (): &()) -> Uuid {
        self.app.auth.user_id
    }

    fn passkeys(&self, (): &()) -> impl Future<Output = ApiResult<Vec<Stored<Self>>>> + Send {
        ready(Ok(self.app.db.read().passkeys.iter().map(stored).collect()))
    }

    fn find(
        &self,
        credential_id: &[u8],
    ) -> impl Future<Output = ApiResult<Option<Stored<Self>>>> + Send {
        let state = self.app.db.read();
        let found = state.passkeys.iter().find(|p| p.passkey.cred_id().as_slice() == credential_id);
        ready(Ok(found.map(stored)))
    }

    async fn add(&self, (): &(), passkey: &Passkey, label: &str) -> ApiResult<Uuid> {
        let id = Uuid::new_v4();
        let record = PasskeyRecord {
            id,
            name: label.to_owned(),
            created_at: now(),
            last_used_at: None,
            added_by: self.added_by,
            passkey: passkey.clone(),
        };
        self.app
            .db
            .update(|s| {
                s.passkeys.push(record.clone());
                Ok::<_, ApiError>(())
            })
            .await?;
        Ok(id)
    }

    async fn update(&self, id: &Uuid, passkey: &Passkey) -> ApiResult<()> {
        self.app
            .db
            .update(|s| {
                if let Some(record) = s.passkeys.iter_mut().find(|p| p.id == *id) {
                    record.passkey = passkey.clone();
                }
                Ok(())
            })
            .await
    }

    async fn remove(&self, (): &(), id: &Uuid, keep_last: bool) -> ApiResult<Removal> {
        self.app
            .db
            .update(|s| {
                if !s.passkeys.iter().any(|p| p.id == *id) {
                    return Ok(Removal::NotFound);
                }
                if keep_last && s.passkeys.len() == 1 {
                    return Ok(Removal::Last);
                }
                s.passkeys.retain(|p| p.id != *id);
                s.sessions.retain(|x| x.passkey_id != Some(*id));
                Ok(Removal::Removed { remaining: s.passkeys.len() })
            })
            .await
    }
}

/// The client address the gateway saw, if tegata sits behind one.
pub struct ClientAddress(pub Option<IpAddr>);

impl FromRequestParts<AppState> for ClientAddress {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        app: &AppState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let ip = crate::authz::client_ip(&parts.headers, app.settings.trusted_hops);
        ready(Ok(Self(ip.and_then(|ip| ip.parse().ok()))))
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

fn passkey_name(name: &str) -> ApiResult<&str> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ApiError::bad_request("give the passkey a name of up to 64 characters"));
    }
    Ok(name)
}

fn step_up_refused() -> ApiError {
    ApiError::Forbidden("sign out and sign in again with a passkey first".into())
}

fn refused(err: kagi::Error) -> ApiError {
    use kagi::Error;
    match err {
        Error::TooMany { retry_after } => ApiError::TooManyRequests(format!(
            "too many sign-in attempts, try again in {}s",
            retry_after.as_secs()
        )),
        Error::Busy => ApiError::TooManyRequests("too many sign-in attempts, try again".into()),
        Error::Ceremony | Error::Purpose | Error::Binding => {
            ApiError::bad_request("passkey ceremony expired, try again")
        }
        Error::Rejected { .. } => ApiError::Forbidden("passkey was not accepted".into()),
        Error::StepUp => step_up_refused(),
        Error::Duplicate => ApiError::Conflict("this passkey is already registered".into()),
        Error::LastCredential => ApiError::Conflict("the last passkey cannot be removed".into()),
        Error::NotFound => ApiError::NotFound,
        Error::Store(err) => match err.downcast::<ApiError>() {
            Ok(err) => *err,
            Err(err) => ApiError::Internal(anyhow::anyhow!("{err}")),
        },
        other => ApiError::Internal(anyhow::anyhow!("{other}")),
    }
}

pub async fn is_signed_in(app: &App, jar: &CookieJar) -> bool {
    match jar.get(SESSION_COOKIE) {
        Some(c) => app.session_valid(c.value()).await,
        None => false,
    }
}

impl App {
    const fn passkeys(&self, added_by: Option<Uuid>) -> Passkeys<'_> {
        Passkeys { app: self, added_by }
    }

    fn throttle(&self, address: Option<IpAddr>) -> ApiResult<()> {
        if self.auth.failures.blocked(address) {
            return Err(ApiError::TooManyRequests(
                "too many failed attempts, try again later".into(),
            ));
        }
        Ok(())
    }

    fn count_failure(&self, address: Option<IpAddr>, err: &kagi::Error) {
        if matches!(err, kagi::Error::Rejected { .. }) {
            tracing::warn!(?address, "passkey ceremony rejected");
            self.auth.failures.record(address);
        }
    }

    async fn signed_in(&self, jar: &CookieJar) -> ApiResult<SessionRecord> {
        let token = jar.get(SESSION_COOKIE).ok_or(ApiError::Unauthorized)?.value().to_owned();
        if !self.session_valid(&token).await {
            return Err(ApiError::Unauthorized);
        }
        let hash = sha256_hex(token.as_bytes());
        let session = self.db.read().sessions.iter().find(|s| s.token_hash == hash).cloned();
        session.ok_or(ApiError::Unauthorized)
    }

    fn sign_in_proof(session: &SessionRecord) -> Proof {
        let at = session.authenticated_at.map_or(SystemTime::UNIX_EPOCH, SystemTime::from);
        Proof::RecentSignIn { at, human: true }
    }

    /// Checks the cached state, then the store, since another replica may have opened it.
    pub async fn session_valid(&self, token: &str) -> bool {
        let hash = sha256_hex(token.as_bytes());
        let found = |s: &crate::model::State| {
            let t = now();
            s.sessions.iter().any(|x| x.token_hash == hash && x.expires_at > t)
        };
        if found(self.db.read().as_ref()) {
            return true;
        }
        if let Err(err) = self.db.refresh_on_miss().await {
            tracing::warn!(error = ?err, "refreshing state failed");
        }
        found(self.db.read().as_ref())
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
        self.new_session(hours, None).await
    }

    async fn new_session(&self, hours: u32, passkey_id: Option<Uuid>) -> ApiResult<String> {
        let token = random_token();
        let record = SessionRecord {
            token_hash: sha256_hex(token.as_bytes()),
            expires_at: now() + Duration::hours(i64::from(hours)),
            passkey_id,
            authenticated_at: Some(now()),
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

    fn challenge_cookie(&self, jar: CookieJar, ceremony: String) -> CookieJar {
        jar.add(cookie(CHALLENGE_COOKIE, ceremony, CHALLENGE_TTL, self.settings.secure_cookies()))
    }

    pub async fn start_registration(
        &self,
        jar: CookieJar,
        address: Option<IpAddr>,
        name: &str,
        setup_token: Option<&str>,
    ) -> ApiResult<(CookieJar, CreationChallengeResponse)> {
        self.throttle(address)?;
        let (proof, binding) = if self.db.read().passkeys.is_empty() {
            let given = setup_token.map(str::trim).filter(|t| !t.is_empty());
            let expected = sha256_hex(self.settings.setup_token.as_bytes());
            if given.is_none_or(|t| sha256_hex(t.as_bytes()) != expected) {
                self.auth.failures.record(address);
                return Err(ApiError::Forbidden("setup token does not match".into()));
            }
            (Proof::Grant { grant: SETUP.into() }, SETUP.to_owned())
        } else {
            let session = self.signed_in(&jar).await?;
            (Self::sign_in_proof(&session), session.token_hash)
        };
        passkey_name(name)?;
        let account = Account { user: (), name: ADMIN, display_name: &self.settings.rp_name };
        let challenge = self
            .auth
            .kagi
            .start_registration(&self.passkeys(None), account, proof, &binding, address)
            .await
            .map_err(refused)?;
        Ok((self.challenge_cookie(jar, challenge.ceremony), challenge.options))
    }

    pub async fn finish_registration(
        &self,
        jar: CookieJar,
        address: Option<IpAddr>,
        name: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> ApiResult<CookieJar> {
        let ceremony = challenge_id(&jar)?;
        let name = passkey_name(name)?;
        let jar = jar.remove(Cookie::build(CHALLENGE_COOKIE).path("/"));
        if self.db.read().passkeys.is_empty() {
            return self.finish_setup(jar, address, &ceremony, name, credential).await;
        }
        let session = self.signed_in(&jar).await?;
        let store = self.passkeys(session.passkey_id);
        self.auth
            .kagi
            .finish_registration(&store, &ceremony, &session.token_hash, credential, name)
            .await
            .inspect_err(|err| self.count_failure(address, err))
            .map_err(refused)?;
        tracing::warn!(%name, added_by = ?session.passkey_id, "passkey added");
        Ok(jar)
    }

    async fn finish_setup(
        &self,
        jar: CookieJar,
        address: Option<IpAddr>,
        ceremony: &str,
        name: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> ApiResult<CookieJar> {
        let enrolment = self
            .auth
            .kagi
            .finish_enrolment(&self.passkeys(None), ceremony, SETUP, credential)
            .await
            .inspect_err(|err| self.count_failure(address, err))
            .map_err(refused)?;
        let id = Uuid::new_v4();
        let record = PasskeyRecord {
            id,
            name: name.to_owned(),
            created_at: now(),
            last_used_at: None,
            added_by: None,
            passkey: enrolment.passkey,
        };
        self.db
            .update(|s| {
                if !s.passkeys.is_empty() {
                    return Err(ApiError::Conflict("setup was already completed".into()));
                }
                s.passkeys.push(record.clone());
                Ok(())
            })
            .await?;
        tracing::info!(%name, "first passkey registered");
        let token = self.new_session(self.settings.session_hours, Some(id)).await?;
        Ok(jar.add(self.session_cookie(token)))
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
        address: Option<IpAddr>,
    ) -> ApiResult<(CookieJar, RequestChallengeResponse)> {
        self.throttle(address)?;
        if self.db.read().passkeys.is_empty() {
            return Err(ApiError::Conflict("no passkey is registered yet".into()));
        }
        let challenge = self
            .auth
            .kagi
            .start_sign_in(&self.passkeys(None), ADMIN, Some(&()), address)
            .await
            .map_err(refused)?;
        Ok((self.challenge_cookie(jar, challenge.ceremony), challenge.options))
    }

    pub async fn finish_login(
        &self,
        jar: CookieJar,
        address: Option<IpAddr>,
        credential: &PublicKeyCredential,
    ) -> ApiResult<CookieJar> {
        let ceremony = challenge_id(&jar)?;
        let signed_in = self
            .auth
            .kagi
            .finish_sign_in(&self.passkeys(None), &ceremony, credential)
            .await
            .inspect_err(|err| self.count_failure(address, err))
            .map_err(refused)?;
        let id = signed_in.passkey;
        let name =
            self.db
                .update(|s| {
                    let record =
                        s.passkeys.iter_mut().find(|p| p.id == id).ok_or_else(|| {
                            ApiError::Forbidden("passkey is not registered".into())
                        })?;
                    record.last_used_at = Some(now());
                    Ok::<_, ApiError>(record.name.clone())
                })
                .await?;
        tracing::info!(passkey = %name, "signed in");
        let token = self.new_session(self.settings.session_hours, Some(id)).await?;
        Ok(jar.remove(Cookie::build(CHALLENGE_COOKIE).path("/")).add(self.session_cookie(token)))
    }

    /// Needs the same recent sign-in as adding one, then ends the sessions it opened.
    pub async fn delete_passkey(&self, jar: &CookieJar, id: Uuid) -> ApiResult<()> {
        let session = self.signed_in(jar).await?;
        let recent =
            session.authenticated_at.is_some_and(|at| (now() - at).unsigned_abs() <= STEP_UP);
        if !recent {
            return Err(step_up_refused());
        }
        let removed = self
            .auth
            .kagi
            .remove(&self.passkeys(None), &(), &id, PasskeyRole::Only, false)
            .await
            .map_err(refused)?;
        tracing::warn!(passkey = %removed.passkey, by = ?session.passkey_id, "passkey removed");
        Ok(())
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
