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
use crate::enroll::{Enrollments, Pending};
use crate::error::{ApiError, ApiResult};
use crate::kube::ConfigMapWriter;
use crate::model::{CertRecord, CertState, Device, DeviceView, Seen, State};
use crate::util::{now, password, random_token};

pub struct Settings {
    pub public_url: Url,
    pub rp_name: String,
    pub default_validity_days: u32,
    pub max_validity_days: u32,
    pub validity_presets: Vec<u32>,
    pub expiring_days: u32,
    pub enrollment_minutes: u32,
    pub session_hours: u32,
    pub authz_allow_unknown: bool,
    pub extra_ca_pem: Vec<String>,
    pub extra_crl_pem: Vec<String>,
    pub setup_token: String,
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
    pub enrollments: Enrollments,
    pub auth: Auth,
    pub trust: Option<ConfigMapWriter>,
    seen: Mutex<HashMap<String, Seen>>,
    publish_lock: Mutex<()>,
}

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
    Deny,
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
    ) -> Self {
        Self {
            settings,
            db,
            ca,
            enrollments: Enrollments::default(),
            auth,
            trust,
            seen: Mutex::new(HashMap::new()),
            publish_lock: Mutex::new(()),
        }
    }

    pub fn expiring(&self) -> Duration {
        Duration::days(i64::from(self.settings.expiring_days))
    }

    pub fn view(&self, device: &Device) -> DeviceView {
        DeviceView::new(device, now(), self.expiring())
    }

    pub async fn devices(&self) -> Vec<DeviceView> {
        let mut devices: Vec<_> =
            self.db.read().await.devices.iter().map(|d| self.view(d)).collect();
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
    ) -> ApiResult<(CertRecord, Enrollment)> {
        let issued = self.ca.issue(name, validity).await?;
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
            superseded: false,
        };
        self.enrollments
            .insert(
                &token,
                Pending {
                    device_id,
                    device_name: name.to_owned(),
                    serial: issued.serial,
                    p12,
                    mobileconfig,
                    expires_at,
                },
            )
            .await;
        let url = self
            .settings
            .public_url
            .join(&format!("enroll/{token}"))
            .map_err(|e| ApiError::Internal(e.into()))?;
        Ok((record, Enrollment { url: url.to_string(), password, expires_at }))
    }

    pub async fn create_device(
        &self,
        name: &str,
        owner: &str,
        validity_days: Option<u32>,
    ) -> ApiResult<Created> {
        let name = clean_label(name, "name", true)?;
        let owner = clean_label(owner, "owner", false)?;
        let validity = self.validity(validity_days)?;
        let taken = |s: &State| s.devices.iter().any(|d| d.name.eq_ignore_ascii_case(&name));
        if taken(&self.db.read().await) {
            return Err(ApiError::Conflict(format!("a device named {name} already exists")));
        }
        let id = Uuid::new_v4();
        let (record, enrollment) = self.issue_pending(id, &name, validity).await?;
        let serial = record.serial.clone();
        let result = self
            .db
            .update(|s| {
                if taken(s) {
                    return Err(ApiError::Conflict(format!(
                        "a device named {name} already exists"
                    )));
                }
                let device = Device {
                    id,
                    name: name.clone(),
                    owner: owner.clone(),
                    created_at: now(),
                    certs: vec![record.clone()],
                    last_seen: None,
                };
                let view = self.view(&device);
                s.devices.push(device);
                Ok(view)
            })
            .await;
        match result {
            Ok(device) => {
                tracing::info!(device = %name, serial = %serial, "device created");
                Ok(Created { device, enrollment })
            }
            Err(err) => {
                self.enrollments.forget_device(id).await;
                self.ca.revoke(&serial).await?;
                Err(err)
            }
        }
    }

    async fn find(&self, id: Uuid) -> ApiResult<Device> {
        self.db.read().await.devices.into_iter().find(|d| d.id == id).ok_or(ApiError::NotFound)
    }

    /// Issues a replacement; the current cert stays valid until the new one is downloaded.
    pub async fn rotate(&self, id: Uuid, validity_days: Option<u32>) -> ApiResult<Created> {
        let validity = self.validity(validity_days)?;
        let device = self.find(id).await?;
        self.replace_pending(&device, validity).await
    }

    /// A fresh link for a device whose install has not happened yet.
    pub async fn new_enrollment(&self, id: Uuid) -> ApiResult<Created> {
        let device = self.find(id).await?;
        let pending = device
            .pending_cert(now())
            .ok_or_else(|| ApiError::Conflict("nothing is waiting to be installed".into()))?;
        let validity = pending.not_after - pending.not_before;
        self.replace_pending(&device, validity).await
    }

    async fn replace_pending(&self, device: &Device, validity: Duration) -> ApiResult<Created> {
        let (record, enrollment) = self.issue_pending(device.id, &device.name, validity).await?;
        self.enrollments.forget_device_except(device.id, &record.serial).await;
        let mut stale = Vec::new();
        let view = self
            .db
            .update(|s| {
                stale.clear();
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
        self.revoke_serials(&stale).await?;
        Ok(Created { device: view, enrollment })
    }

    pub async fn revoke_device(&self, id: Uuid) -> ApiResult<DeviceView> {
        self.enrollments.forget_device(id).await;
        let mut serials = Vec::new();
        let view = self
            .db
            .update(|s| {
                serials.clear();
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
        self.revoke_serials(&serials).await?;
        Ok(view)
    }

    pub async fn delete_device(&self, id: Uuid) -> ApiResult<()> {
        self.db
            .update(|s| {
                let d = s.devices.iter().find(|d| d.id == id).ok_or(ApiError::NotFound)?;
                if d.has_live_cert(now()) {
                    return Err(ApiError::Conflict("revoke the device before deleting it".into()));
                }
                s.devices.retain(|d| d.id != id);
                Ok(())
            })
            .await
    }

    async fn revoke_serials(&self, serials: &[String]) -> ApiResult<()> {
        if serials.is_empty() {
            return Ok(());
        }
        for serial in serials {
            self.ca.revoke(serial).await?;
        }
        if let Err(err) = self.publish_trust().await {
            tracing::error!(error = ?err, "publishing the CRL after a revocation failed");
        }
        Ok(())
    }

    pub async fn enrollment_info(&self, token: &str) -> Option<(String, OffsetDateTime)> {
        self.enrollments.peek(token, now()).await
    }

    /// Hands out the bundle once, marks the cert installed and retires the one it replaces.
    pub async fn download(&self, token: &str, kind: &Download) -> ApiResult<(Vec<u8>, String)> {
        let pending = self.enrollments.take(token, now()).await.ok_or(ApiError::NotFound)?;
        let mut superseded = Vec::new();
        self.db
            .update(|s| {
                superseded.clear();
                let d = s
                    .devices
                    .iter_mut()
                    .find(|d| d.id == pending.device_id)
                    .ok_or(ApiError::NotFound)?;
                let t = now();
                let cert = d.cert_mut(&pending.serial).ok_or(ApiError::NotFound)?;
                if cert.state(t) != CertState::Pending {
                    return Err(ApiError::NotFound);
                }
                cert.enrolled_at = Some(t);
                for old in d.certs.iter_mut().filter(|c| c.serial != pending.serial) {
                    if old.state(t) == CertState::Active {
                        old.revoked_at = Some(t);
                        old.superseded = true;
                        superseded.push(old.serial.clone());
                    }
                }
                Ok::<_, ApiError>(())
            })
            .await?;
        tracing::info!(device = %pending.device_name, serial = %pending.serial, "certificate downloaded");
        self.revoke_serials(&superseded).await?;
        Ok(match kind {
            Download::Profile => (pending.mobileconfig.into_bytes(), pending.device_name),
            Download::Pkcs12 => (pending.p12, pending.device_name),
        })
    }

    /// Revokes certs whose install link expired or was lost in a restart.
    pub async fn sweep(&self) -> anyhow::Result<()> {
        let t = now();
        self.enrollments.drop_expired(t).await;
        let live: Vec<String> = self.enrollments.serials().await;
        let mut orphans = Vec::new();
        self.db
            .update(|s| {
                orphans.clear();
                for cert in s.devices.iter_mut().flat_map(|d| d.certs.iter_mut()) {
                    if cert.state(t) == CertState::Pending && !live.contains(&cert.serial) {
                        cert.revoked_at = Some(t);
                        orphans.push(cert.serial.clone());
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
            .await?;
        if !orphans.is_empty() {
            tracing::info!(?orphans, "revoked certificates that were never installed");
            self.revoke_serials(&orphans).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        }
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
        writer.apply(&self.trust_bundle().await?).await
    }

    pub async fn refresh_crl(&self) -> anyhow::Result<()> {
        self.ca.refresh_crl().await?;
        self.publish_trust().await
    }

    pub async fn authorize(
        &self,
        fingerprint: Option<&str>,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> AuthzDecision {
        let Some(fingerprint) = fingerprint.map(str::to_ascii_lowercase) else {
            return AuthzDecision::Deny;
        };
        let t = now();
        let state = self.db.read().await;
        let found = state.devices.iter().find_map(|d| {
            d.certs.iter().find(|c| c.fingerprint_sha256 == fingerprint).map(|c| (d, c))
        });
        match found {
            Some((device, cert)) if cert.state(t) == CertState::Active => {
                self.seen.lock().await.insert(fingerprint, Seen { at: t, ip, user_agent });
                AuthzDecision::Allow { device: device.name.clone() }
            }
            Some((device, cert)) => {
                tracing::warn!(device = %device.name, serial = %cert.serial, ?ip, state = ?cert.state(t), "rejected a certificate that is no longer valid");
                AuthzDecision::Deny
            }
            None if self.settings.authz_allow_unknown => {
                AuthzDecision::Allow { device: String::new() }
            }
            None => {
                tracing::warn!(%fingerprint, ?ip, "rejected an unknown certificate");
                AuthzDecision::Deny
            }
        }
    }

    pub async fn flush_seen(&self) -> anyhow::Result<()> {
        let seen = std::mem::take(&mut *self.seen.lock().await);
        if seen.is_empty() {
            return Ok(());
        }
        self.db
            .update(|s| {
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
