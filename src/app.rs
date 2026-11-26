use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use serde::Serialize;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

use crate::auth::Auth;
use crate::bundle;
use crate::ca::Ca;
use crate::db::Db;
use crate::enroll::{encode_p12, p12_bytes, token_hash};
use crate::error::{ApiError, ApiResult};
use crate::identities::Identities;
use crate::kube::ConfigMapWriter;
use crate::model::{
    AppRule, CertRecord, CertState, Device, DeviceView, EnrollmentRecord, RetiredCert, Seen, State,
};
use crate::rules::{clean_groups, normalize_host};
use crate::util::{RateLimit, now, password, random_token};

pub struct Settings {
    pub public_url: Url,
    pub rp_name: String,
    pub default_validity_days: u32,
    pub max_validity_days: u32,
    pub validity_presets: Vec<u32>,
    pub expiring_days: u32,
    pub stale_days: u32,
    pub enrollment_minutes: u32,
    pub session_hours: u32,
    pub authz_allow_unknown: bool,
    pub extra_ca_pem: Vec<String>,
    pub extra_crl_pem: Vec<String>,
    pub setup_token: String,
    /// Oldest state `/authz` and readiness accept before refusing.
    pub max_state_age: std::time::Duration,
    /// Proxies in front of Envoy that append to `X-Forwarded-For`.
    pub trusted_hops: usize,
}

impl Settings {
    pub fn origin(&self) -> String {
        self.public_url.origin().ascii_serialization()
    }

    pub fn secure_cookies(&self) -> bool {
        self.public_url.scheme() == "https"
    }
}

pub struct App {
    pub settings: Settings,
    pub db: Db,
    pub ca: Arc<dyn Ca>,
    pub auth: Auth,
    pub trust: Option<ConfigMapWriter>,
    pub identities: Identities,
    seen: Mutex<HashMap<String, Seen>>,
    hosts_seen: Mutex<HashMap<String, OffsetDateTime>>,
    publish_lock: Mutex<()>,
    pub(crate) login_starts: RateLimit,
}

const MAX_TRACKED_HOSTS: usize = 1000;
/// Sign-in attempts one replica starts per second; anyone can call it.
const LOGIN_STARTS_PER_SECOND: u32 = 5;

pub type AppState = Arc<App>;

#[derive(Serialize)]
pub struct Enrollment {
    pub url: String,
    pub password: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[derive(Serialize)]
pub struct Created {
    pub device: DeviceView,
    pub enrollment: Enrollment,
}

pub enum Download {
    Profile,
    Pkcs12,
}

pub enum AuthzDecision {
    Allow { device: String },
    AllowUnknown,
    Deny(DenyReason),
}

pub enum DenyReason {
    NoCertificate,
    NotAllowed { device: String, host: String },
    NoLongerValid { device: String },
    Unknown,
}

fn clean_label(raw: &str, what: &str, required: bool) -> ApiResult<String> {
    let value = raw.trim();
    if required && value.is_empty() {
        return Err(ApiError::bad_request(format!("{what} is required")));
    }
    if value.chars().count() > 64 {
        return Err(ApiError::bad_request(format!("{what} is longer than 64 characters")));
    }
    if value.chars().any(|c| c.is_control() || r#"/\,=+"<>;#"#.contains(c)) {
        return Err(ApiError::bad_request(format!(
            "{what} contains a character that is not allowed"
        )));
    }
    Ok(value.to_owned())
}

impl App {
    pub fn new(
        settings: Settings,
        db: Db,
        ca: Arc<dyn Ca>,
        auth: Auth,
        trust: Option<ConfigMapWriter>,
        identities: Identities,
    ) -> Self {
        Self {
            settings,
            db,
            ca,
            auth,
            trust,
            identities,
            seen: Mutex::new(HashMap::new()),
            hosts_seen: Mutex::new(HashMap::new()),
            publish_lock: Mutex::new(()),
            login_starts: RateLimit::new(
                LOGIN_STARTS_PER_SECOND,
                std::time::Duration::from_secs(1),
            ),
        }
    }

    pub fn expiring(&self) -> Duration {
        Duration::days(i64::from(self.settings.expiring_days))
    }

    pub fn view(&self, device: &Device) -> DeviceView {
        let t = now();
        let view = DeviceView::new(device, t, self.expiring());
        match self.settings.stale_days {
            0 => view,
            days => view.with_staleness(device, t, Duration::days(i64::from(days))),
        }
    }

    pub fn devices(&self) -> Vec<DeviceView> {
        let mut devices: Vec<_> = self.db.read().devices.iter().map(|d| self.view(d)).collect();
        devices.sort_by_key(|d| d.name.to_lowercase());
        devices
    }

    fn validity(&self, days: Option<u32>) -> ApiResult<Duration> {
        let days = days.unwrap_or(self.settings.default_validity_days);
        if days == 0 || days > self.settings.max_validity_days {
            return Err(ApiError::bad_request(format!(
                "validity must be between 1 and {} days",
                self.settings.max_validity_days
            )));
        }
        Ok(Duration::days(i64::from(days)))
    }

    async fn issue_pending(
        &self,
        device_id: Uuid,
        name: &str,
        validity: Duration,
    ) -> ApiResult<(CertRecord, EnrollmentRecord, Enrollment)> {
        let latest = self.ca.not_after() - Duration::minutes(5) - now();
        let issued = self.ca.issue(name, validity.min(latest)).await?;
        let password = password();
        let p12 = bundle::pkcs12(&issued, name, &password)?;
        let mobileconfig = bundle::mobileconfig(device_id, name, &p12);
        let expires_at = now() + Duration::minutes(i64::from(self.settings.enrollment_minutes));
        let token = random_token();
        let record = CertRecord {
            serial: issued.serial.clone(),
            fingerprint_sha256: issued.fingerprint(),
            not_before: issued.not_before,
            not_after: issued.not_after,
            enrollment_expires_at: Some(expires_at),
            enrolled_at: None,
            revoked_at: None,
            ca_revoked_at: None,
            superseded: false,
        };
        let link = EnrollmentRecord {
            token_hash: token_hash(&token),
            device_id,
            device_name: name.to_owned(),
            serial: issued.serial,
            p12_base64: encode_p12(&p12),
            mobileconfig,
            expires_at,
        };
        let url = self
            .settings
            .public_url
            .join(&format!("enroll/{token}"))
            .map_err(|e| ApiError::Internal(e.into()))?;
        Ok((record, link, Enrollment { url: url.to_string(), password, expires_at }))
    }

    pub async fn create_device(
        &self,
        name: &str,
        owner: &str,
        groups: &[String],
        validity_days: Option<u32>,
    ) -> ApiResult<Created> {
        let name = clean_label(name, "name", true)?;
        let owner = clean_label(owner, "owner", false)?;
        let groups = clean_groups(groups)?;
        let validity = self.validity(validity_days)?;
        let taken = |s: &State| s.devices.iter().any(|d| d.name.eq_ignore_ascii_case(&name));
        if taken(self.db.read().as_ref()) {
            return Err(ApiError::Conflict(format!("a device named {name} already exists")));
        }
        let id = Uuid::new_v4();
        let (record, link, enrollment) = self.issue_pending(id, &name, validity).await?;
        let serial = record.serial.clone();
        let result = self
            .db
            .update(|s| {
                s.prune(now());
                if taken(s) {
                    return Err(ApiError::Conflict(format!(
                        "a device named {name} already exists"
                    )));
                }
                let device = Device {
                    id,
                    name: name.clone(),
                    owner: owner.clone(),
                    groups: groups.clone(),
                    created_at: now(),
                    certs: vec![record.clone()],
                    last_seen: None,
                };
                let view = self.view(&device);
                s.devices.push(device);
                s.enrollments.push(link.clone());
                Ok(view)
            })
            .await;
        match result {
            Ok(device) => {
                tracing::info!(device = %name, serial = %serial, "device created");
                Ok(Created { device, enrollment })
            }
            Err(err) => {
                self.ca.revoke(&serial).await?;
                Err(err)
            }
        }
    }

    fn find(&self, id: Uuid) -> ApiResult<Device> {
        self.db.read().devices.iter().find(|d| d.id == id).cloned().ok_or(ApiError::NotFound)
    }

    /// Issues a replacement; the current cert stays valid until the new one is downloaded.
    pub async fn rotate(&self, id: Uuid, validity_days: Option<u32>) -> ApiResult<Created> {
        let validity = self.validity(validity_days)?;
        let device = self.find(id)?;
        self.replace_pending(&device, validity).await
    }

    /// A fresh link for a device whose install has not happened yet.
    pub async fn new_enrollment(&self, id: Uuid) -> ApiResult<Created> {
        let device = self.find(id)?;
        let pending = device
            .pending_cert(now())
            .ok_or_else(|| ApiError::Conflict("nothing is waiting to be installed".into()))?;
        let validity = pending.not_after - pending.not_before;
        self.replace_pending(&device, validity).await
    }

    async fn replace_pending(&self, device: &Device, validity: Duration) -> ApiResult<Created> {
        let (record, link, enrollment) =
            self.issue_pending(device.id, &device.name, validity).await?;
        let mut stale = Vec::new();
        let view = self
            .db
            .update(|s| {
                stale.clear();
                s.prune(now());
                s.enrollments.retain(|e| e.device_id != device.id);
                s.enrollments.push(link.clone());
                let d =
                    s.devices.iter_mut().find(|d| d.id == device.id).ok_or(ApiError::NotFound)?;
                let t = now();
                for cert in d.certs.iter_mut().filter(|c| c.state(t) == CertState::Pending) {
                    cert.revoked_at = Some(t);
                    stale.push(cert.serial.clone());
                }
                d.certs.push(record.clone());
                Ok::<_, ApiError>(self.view(d))
            })
            .await?;
        self.revoke_serials(&stale).await;
        Ok(Created { device: view, enrollment })
    }

    pub async fn revoke_device(&self, id: Uuid) -> ApiResult<DeviceView> {
        let mut serials = Vec::new();
        let view = self
            .db
            .update(|s| {
                serials.clear();
                s.enrollments.retain(|e| e.device_id != id);
                let d = s.devices.iter_mut().find(|d| d.id == id).ok_or(ApiError::NotFound)?;
                let t = now();
                for cert in d.certs.iter_mut().filter(|c| c.is_live(t)) {
                    cert.revoked_at = Some(t);
                    serials.push(cert.serial.clone());
                }
                Ok::<_, ApiError>(self.view(d))
            })
            .await?;
        tracing::info!(device = %view.name, ?serials, "device revoked");
        self.revoke_serials(&serials).await;
        Ok(view)
    }

    pub async fn delete_device(&self, id: Uuid) -> ApiResult<()> {
        self.db
            .update(|s| {
                let d = s.devices.iter().find(|d| d.id == id).ok_or(ApiError::NotFound)?;
                let t = now();
                if d.has_live_cert(t) {
                    return Err(ApiError::Conflict("revoke the device before deleting it".into()));
                }
                let retired: Vec<RetiredCert> = d
                    .certs
                    .iter()
                    .filter(|c| c.not_after > t)
                    .map(|c| RetiredCert {
                        fingerprint_sha256: c.fingerprint_sha256.clone(),
                        serial: c.serial.clone(),
                        device_name: d.name.clone(),
                        not_after: c.not_after,
                    })
                    .collect();
                s.retired.extend(retired);
                s.devices.retain(|d| d.id != id);
                Ok(())
            })
            .await
    }

    /// Revokes each serial at the CA and records which ones it confirmed; the sweep
    /// retries the rest, so callers never fail on it.
    async fn revoke_serials(&self, serials: &[String]) {
        let mut confirmed = Vec::new();
        for serial in serials {
            match self.ca.revoke(serial).await {
                Ok(()) => confirmed.push(serial.clone()),
                Err(err) => {
                    tracing::error!(%serial, error = ?err, "revoking at the CA failed, the sweep retries it");
                }
            }
        }
        if confirmed.is_empty() {
            return;
        }
        let t = now();
        let recorded = self
            .db
            .update(|s| {
                for cert in s.devices.iter_mut().flat_map(|d| d.certs.iter_mut()) {
                    if confirmed.contains(&cert.serial) {
                        cert.ca_revoked_at.get_or_insert(t);
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
            .await;
        if let Err(err) = recorded {
            tracing::error!(error = ?err, "recording CA revocations failed, the sweep retries them");
        }
        if let Err(err) = self.publish_trust().await {
            tracing::error!(error = ?err, "publishing the CRL after a revocation failed");
        }
    }

    /// Hands out the bundle once, marks the cert installed and retires the one it replaces.
    /// Taking the link is one check-and-set write, so only one replica can serve it.
    pub async fn download(&self, token: &str, kind: &Download) -> ApiResult<(Vec<u8>, String)> {
        let hash = token_hash(token);
        let mut superseded = Vec::new();
        let mut take = |s: &mut State| {
            superseded.clear();
            let t = now();
            s.prune(t);
            let at = s
                .enrollments
                .iter()
                .position(|e| e.token_hash == hash)
                .ok_or(ApiError::NotFound)?;
            let link = s.enrollments.remove(at);
            let d =
                s.devices.iter_mut().find(|d| d.id == link.device_id).ok_or(ApiError::NotFound)?;
            let cert = d.cert_mut(&link.serial).ok_or(ApiError::NotFound)?;
            if cert.state(t) != CertState::Pending {
                return Err(ApiError::NotFound);
            }
            cert.enrolled_at = Some(t);
            for old in d.certs.iter_mut().filter(|c| c.serial != link.serial) {
                if old.state(t) == CertState::Active {
                    old.revoked_at = Some(t);
                    old.superseded = true;
                    superseded.push(old.serial.clone());
                }
            }
            Ok::<_, ApiError>(link)
        };
        let link = match self.db.update(&mut take).await {
            Err(ApiError::NotFound) => {
                if let Err(err) = self.db.refresh_on_miss().await {
                    tracing::warn!(error = ?err, "refreshing state failed");
                }
                self.db.update(&mut take).await
            }
            other => other,
        }?;
        tracing::info!(device = %link.device_name, serial = %link.serial, "certificate downloaded");
        let bundle = match kind {
            Download::Profile => link.mobileconfig.into_bytes(),
            Download::Pkcs12 => p12_bytes(&link)?,
        };
        self.revoke_serials(&superseded).await;
        Ok((bundle, link.device_name))
    }

    /// Revokes certs whose install link expired or was lost in a restart, and retries
    /// revocations the CA has not confirmed.
    pub async fn sweep(&self) -> anyhow::Result<()> {
        let t = now();
        let mut orphans = Vec::new();
        let mut unconfirmed = Vec::new();
        self.db
            .update(|s| {
                orphans.clear();
                unconfirmed.clear();
                s.prune(t);
                let live: Vec<String> = s.enrollments.iter().map(|e| e.serial.clone()).collect();
                for cert in s.devices.iter_mut().flat_map(|d| d.certs.iter_mut()) {
                    if cert.state(t) == CertState::Pending && !live.contains(&cert.serial) {
                        cert.revoked_at = Some(t);
                        orphans.push(cert.serial.clone());
                    } else if cert.awaits_ca_revoke(t) {
                        unconfirmed.push(cert.serial.clone());
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
            .await?;
        if !orphans.is_empty() {
            tracing::info!(?orphans, "revoked certificates that were never installed");
        }
        if !unconfirmed.is_empty() {
            tracing::warn!(?unconfirmed, "retrying revocations the CA has not confirmed");
        }
        orphans.append(&mut unconfirmed);
        self.revoke_serials(&orphans).await;
        self.flush_seen().await
    }

    pub async fn trust_bundle(&self) -> anyhow::Result<BTreeMap<String, String>> {
        let mut ca = self.ca.ca_pem().trim().to_owned();
        for extra in &self.settings.extra_ca_pem {
            ca.push('\n');
            ca.push_str(extra.trim());
        }
        let mut crl = self.ca.crl_pem().await?.trim().to_owned();
        for extra in &self.settings.extra_crl_pem {
            crl.push('\n');
            crl.push_str(extra.trim());
        }
        ca.push('\n');
        crl.push('\n');
        Ok(BTreeMap::from([("ca.crt".to_owned(), ca), ("ca.crl".to_owned(), crl)]))
    }

    pub async fn publish_trust(&self) -> anyhow::Result<()> {
        let Some(writer) = &self.trust else { return Ok(()) };
        let _guard = self.publish_lock.lock().await;
        let bundle = self.trust_bundle().await?;
        if let Some(published) = writer.current("ca.crl").await?
            && bundle.get("ca.crl").is_some_and(|crl| crate::kube::older_crl(crl, &published))
        {
            tracing::info!("kept the published CRL, it is newer than the one fetched");
            return Ok(());
        }
        writer.apply(&bundle).await
    }

    pub async fn refresh_crl(&self) -> anyhow::Result<()> {
        self.ca.refresh_crl().await?;
        self.publish_trust().await
    }

    /// Whether the state is recent enough to decide on; past `max_state_age` revocations
    /// made on other replicas may be missing.
    pub fn state_is_fresh(&self) -> bool {
        self.db.state_age() <= self.settings.max_state_age
    }

    pub async fn authorize(
        &self,
        fingerprint: Option<&str>,
        host: Option<&str>,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> AuthzDecision {
        let Some(fingerprint) = fingerprint.map(str::to_ascii_lowercase) else {
            return AuthzDecision::Deny(DenyReason::NoCertificate);
        };
        let t = now();
        let host = host.and_then(normalize_host);
        if let Some(host) = &host {
            let mut hosts = self.hosts_seen.lock().await;
            if hosts.len() < MAX_TRACKED_HOSTS || hosts.contains_key(host) {
                hosts.insert(host.clone(), t);
            }
        }
        let state = self.db.read();
        let rule = host.as_ref().and_then(|h| state.apps.iter().find(|a| &a.host == h));
        let found = state.devices.iter().find_map(|d| {
            d.certs.iter().find(|c| c.fingerprint_sha256 == fingerprint).map(|c| (d, c))
        });
        match found {
            Some((device, cert)) if cert.state(t) == CertState::Active => {
                self.seen
                    .lock()
                    .await
                    .insert(fingerprint, Seen { at: t, ip: ip.clone(), user_agent });
                if host.is_none() && state.apps.iter().any(|a| a.restricted) {
                    tracing::warn!(device = %device.name, ?ip, "refused a check without a usable host while some apps are restricted");
                    return AuthzDecision::Deny(DenyReason::NotAllowed {
                        device: device.name.clone(),
                        host: "(unknown host)".into(),
                    });
                }
                if rule.is_some_and(|r| !r.admits(&device.groups)) {
                    tracing::info!(device = %device.name, ?host, ?ip, "device is not allowed on this app");
                    return AuthzDecision::Deny(DenyReason::NotAllowed {
                        device: device.name.clone(),
                        host: host.unwrap_or_default(),
                    });
                }
                AuthzDecision::Allow { device: device.name.clone() }
            }
            Some((device, cert)) => {
                tracing::warn!(device = %device.name, serial = %cert.serial, ?ip, state = ?cert.state(t), "rejected a certificate that is no longer valid");
                AuthzDecision::Deny(DenyReason::NoLongerValid { device: device.name.clone() })
            }
            None => {
                if let Some(retired) =
                    state.retired.iter().find(|r| r.fingerprint_sha256 == fingerprint)
                {
                    tracing::warn!(device = %retired.device_name, serial = %retired.serial, ?ip, "rejected a certificate of a deleted device");
                    return AuthzDecision::Deny(DenyReason::NoLongerValid {
                        device: retired.device_name.clone(),
                    });
                }
                if let Some(identity) = self.identities.find(&fingerprint) {
                    if identity.admits(host.as_deref(), rule.is_some_and(|r| r.restricted)) {
                        tracing::debug!(identity = %identity.name, ?host, ?ip, "allowed a service identity");
                        return AuthzDecision::Allow { device: identity.name };
                    }
                    tracing::info!(identity = %identity.name, ?host, ?ip, "service identity is not allowed on this app");
                    return AuthzDecision::Deny(DenyReason::NotAllowed {
                        device: identity.name,
                        host: host.unwrap_or_default(),
                    });
                }
                if self.settings.authz_allow_unknown && rule.is_none_or(|r| !r.restricted) {
                    return AuthzDecision::AllowUnknown;
                }
                tracing::warn!(%fingerprint, ?ip, "rejected an unknown certificate");
                AuthzDecision::Deny(DenyReason::Unknown)
            }
        }
    }

    pub async fn flush_seen(&self) -> anyhow::Result<()> {
        let seen = std::mem::take(&mut *self.seen.lock().await);
        let hosts = std::mem::take(&mut *self.hosts_seen.lock().await);
        if seen.is_empty() && hosts.is_empty() {
            return Ok(());
        }
        self.db
            .update(|s| {
                for (host, at) in &hosts {
                    match s.apps.iter_mut().find(|a| &a.host == host) {
                        Some(app) => {
                            if app.last_seen.is_none_or(|old| old < *at) {
                                app.last_seen = Some(*at);
                            }
                            app.first_seen.get_or_insert(*at);
                        }
                        None => s.apps.push(AppRule {
                            host: host.clone(),
                            restricted: false,
                            groups: Vec::new(),
                            first_seen: Some(*at),
                            last_seen: Some(*at),
                        }),
                    }
                }
                for d in &mut s.devices {
                    let latest = d
                        .certs
                        .iter()
                        .filter_map(|c| seen.get(&c.fingerprint_sha256))
                        .max_by_key(|s| s.at);
                    if let Some(latest) = latest
                        && d.last_seen.as_ref().is_none_or(|old| old.at < latest.at)
                    {
                        d.last_seen = Some(latest.clone());
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
    }
}
