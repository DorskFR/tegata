use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub devices: Vec<Device>,
    #[serde(default)]
    pub passkeys: Vec<PasskeyRecord>,
    #[serde(default)]
    pub apps: Vec<AppRule>,
    #[serde(default)]
    pub sessions: Vec<SessionRecord>,
    #[serde(default)]
    pub ceremonies: Vec<CeremonyRecord>,
    #[serde(default)]
    pub enrollments: Vec<EnrollmentRecord>,
}

impl State {
    pub fn prune(&mut self, now: OffsetDateTime) {
        self.sessions.retain(|s| s.expires_at > now);
        self.ceremonies.retain(|c| c.expires_at > now);
        self.enrollments.retain(|e| e.expires_at > now);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRecord {
    pub token_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// A passkey ceremony between its start and finish requests, which may reach different
/// replicas. The state never leaves the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CeremonyRecord {
    pub id_hash: String,
    pub registration: Option<RegistrationIntent>,
    pub state: serde_json::Value,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationIntent {
    pub name: String,
    pub first: bool,
}

/// A one-shot install link. The bundles are encrypted with a password that is not stored.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    pub token_hash: String,
    pub device_id: Uuid,
    pub device_name: String,
    pub serial: String,
    pub p12_base64: String,
    pub mobileconfig: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// A hostname behind the gateway. Open to every valid device unless `restricted`, in
/// which case only devices sharing one of `groups` pass.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppRule {
    pub host: String,
    #[serde(default)]
    pub restricted: bool,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub first_seen: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub last_seen: Option<OffsetDateTime>,
}

impl AppRule {
    pub fn admits(&self, groups: &[String]) -> bool {
        !self.restricted || groups.iter().any(|g| self.groups.contains(g))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub name: String,
    pub owner: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Oldest first.
    pub certs: Vec<CertRecord>,
    pub last_seen: Option<Seen>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertRecord {
    pub serial: String,
    pub fingerprint_sha256: String,
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub enrollment_expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub enrolled_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub revoked_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub superseded: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Seen {
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyRecord {
    pub id: Uuid,
    pub name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub last_used_at: Option<OffsetDateTime>,
    pub passkey: Passkey,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CertState {
    Pending,
    Active,
    Superseded,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus {
    Pending,
    Active,
    Expiring,
    Expired,
    Revoked,
}

impl CertRecord {
    pub fn state(&self, now: OffsetDateTime) -> CertState {
        if self.revoked_at.is_some() {
            if self.superseded { CertState::Superseded } else { CertState::Revoked }
        } else if self.not_after <= now {
            CertState::Expired
        } else if self.enrolled_at.is_none() {
            CertState::Pending
        } else {
            CertState::Active
        }
    }

    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        matches!(self.state(now), CertState::Pending | CertState::Active)
    }
}

impl Device {
    pub fn active_cert(&self, now: OffsetDateTime) -> Option<&CertRecord> {
        self.certs.iter().rev().find(|c| c.state(now) == CertState::Active)
    }

    pub fn pending_cert(&self, now: OffsetDateTime) -> Option<&CertRecord> {
        self.certs.iter().rev().find(|c| c.state(now) == CertState::Pending)
    }

    pub fn has_live_cert(&self, now: OffsetDateTime) -> bool {
        self.certs.iter().any(|c| c.is_live(now))
    }

    pub fn cert_mut(&mut self, serial: &str) -> Option<&mut CertRecord> {
        self.certs.iter_mut().find(|c| c.serial == serial)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CertView {
    pub serial: String,
    pub fingerprint_sha256: String,
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    pub state: CertState,
    #[serde(with = "time::serde::rfc3339::option")]
    pub enrolled_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub enrollment_expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceView {
    pub id: Uuid,
    pub name: String,
    pub owner: String,
    pub groups: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub status: DeviceStatus,
    pub cert: Option<CertView>,
    pub rotation: Option<CertView>,
    pub history: Vec<CertView>,
    pub last_seen: Option<Seen>,
    /// In use but not seen for the configured number of days.
    pub stale: bool,
}

impl CertView {
    fn new(cert: &CertRecord, now: OffsetDateTime) -> Self {
        let state = cert.state(now);
        Self {
            serial: cert.serial.clone(),
            fingerprint_sha256: cert.fingerprint_sha256.clone(),
            not_before: cert.not_before,
            not_after: cert.not_after,
            state,
            enrolled_at: cert.enrolled_at,
            revoked_at: cert.revoked_at,
            enrollment_expires_at: if state == CertState::Pending {
                cert.enrollment_expires_at
            } else {
                None
            },
        }
    }
}

impl DeviceView {
    pub fn new(device: &Device, now: OffsetDateTime, expiring: Duration) -> Self {
        let active = device.active_cert(now);
        let pending = device.pending_cert(now);
        let (status, current, rotation) = match (active, pending) {
            (Some(a), p) => {
                let status = if a.not_after - now < expiring {
                    DeviceStatus::Expiring
                } else {
                    DeviceStatus::Active
                };
                (status, Some(a), p)
            }
            (None, Some(p)) => (DeviceStatus::Pending, Some(p), None),
            (None, None) => {
                let last = device.certs.last();
                let status = match last.map(|c| c.state(now)) {
                    Some(CertState::Expired) => DeviceStatus::Expired,
                    _ => DeviceStatus::Revoked,
                };
                (status, last, None)
            }
        };
        let shown = |c: &&CertRecord| {
            Some(c.serial.as_str()) != current.map(|x| x.serial.as_str())
                && Some(c.serial.as_str()) != rotation.map(|x| x.serial.as_str())
        };
        Self {
            id: device.id,
            name: device.name.clone(),
            owner: device.owner.clone(),
            groups: device.groups.clone(),
            created_at: device.created_at,
            status,
            cert: current.map(|c| CertView::new(c, now)),
            rotation: rotation.map(|c| CertView::new(c, now)),
            history: device
                .certs
                .iter()
                .rev()
                .filter(shown)
                .map(|c| CertView::new(c, now))
                .collect(),
            last_seen: device.last_seen.clone(),
            stale: false,
        }
    }

    /// Marks a device in use whose latest sign of life (last seen, else install) is
    /// older than `stale_after`.
    #[must_use]
    pub fn with_staleness(
        mut self,
        device: &Device,
        now: OffsetDateTime,
        stale_after: Duration,
    ) -> Self {
        let in_use = matches!(self.status, DeviceStatus::Active | DeviceStatus::Expiring);
        let installed = device.active_cert(now).and_then(|c| c.enrolled_at);
        let last = device.last_seen.as_ref().map(|s| s.at).or(installed);
        self.stale = in_use && last.is_some_and(|t| now - t > stale_after);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn cert(serial: &str, days: i64) -> CertRecord {
        let issued = datetime!(2030-01-01 0:00 UTC);
        CertRecord {
            serial: serial.into(),
            fingerprint_sha256: format!("fp-{serial}"),
            not_before: issued,
            not_after: issued + Duration::days(days),
            enrollment_expires_at: Some(issued + Duration::minutes(30)),
            enrolled_at: None,
            revoked_at: None,
            superseded: false,
        }
    }

    fn device(certs: Vec<CertRecord>) -> Device {
        Device {
            id: Uuid::new_v4(),
            name: "phone".into(),
            owner: "me".into(),
            groups: Vec::new(),
            created_at: datetime!(2030-01-01 0:00 UTC),
            certs,
            last_seen: None,
        }
    }

    #[test]
    fn staleness() {
        let now = datetime!(2030-03-01 0:00 UTC);
        let after = Duration::days(30);
        let mut c = cert("01", 365);
        c.enrolled_at = Some(datetime!(2030-01-01 0:00 UTC));
        let mut d = device(vec![c]);
        let view =
            |d: &Device| DeviceView::new(d, now, Duration::days(14)).with_staleness(d, now, after);
        assert!(view(&d).stale, "installed two months ago and never seen");
        d.last_seen = Some(Seen { at: now - Duration::days(3), ip: None, user_agent: None });
        assert!(!view(&d).stale);
        d.last_seen = Some(Seen { at: now - Duration::days(31), ip: None, user_agent: None });
        assert!(view(&d).stale);
        d.certs[0].revoked_at = Some(now);
        assert!(!view(&d).stale, "revoked devices are not stale, they are gone");
        let fresh = device(vec![cert("02", 365)]);
        assert!(!view(&fresh).stale, "pending devices are not stale");
    }

    #[test]
    fn statuses() {
        let now = datetime!(2030-01-02 0:00 UTC);
        let expiring = Duration::days(14);

        let pending = device(vec![cert("01", 90)]);
        let view = DeviceView::new(&pending, now, expiring);
        assert_eq!(view.status, DeviceStatus::Pending);
        assert!(view.cert.unwrap().enrollment_expires_at.is_some());

        let mut active = cert("01", 90);
        active.enrolled_at = Some(now);
        let view = DeviceView::new(&device(vec![active.clone(), cert("02", 90)]), now, expiring);
        assert_eq!(view.status, DeviceStatus::Active);
        assert_eq!(view.cert.unwrap().serial, "01");
        assert_eq!(view.rotation.unwrap().serial, "02");
        assert!(view.history.is_empty());

        let mut short = cert("03", 10);
        short.enrolled_at = Some(now);
        assert_eq!(
            DeviceView::new(&device(vec![short]), now, expiring).status,
            DeviceStatus::Expiring
        );

        let mut old = active.clone();
        old.revoked_at = Some(now);
        old.superseded = true;
        let mut new = cert("02", 90);
        new.enrolled_at = Some(now);
        let view = DeviceView::new(&device(vec![old, new]), now, expiring);
        assert_eq!(view.status, DeviceStatus::Active);
        assert_eq!(view.history.len(), 1);
        assert_eq!(view.history[0].state, CertState::Superseded);

        let mut revoked = active;
        revoked.revoked_at = Some(now);
        assert_eq!(
            DeviceView::new(&device(vec![revoked]), now, expiring).status,
            DeviceStatus::Revoked
        );

        let mut expired = cert("04", 1);
        expired.enrolled_at = Some(now);
        let later = now + Duration::days(5);
        assert_eq!(
            DeviceView::new(&device(vec![expired]), later, expiring).status,
            DeviceStatus::Expired
        );
    }
}
