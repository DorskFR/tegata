use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use uuid::Uuid;

use crate::app::App;
use crate::authz::xfcc_hash;
use crate::error::{ApiError, ApiResult};
use crate::model::{AppRule, CertState, DeviceView, State};
use crate::util::now;

/// Fingerprint of the client certificate behind an admin request, from the gateway's
/// `x-forwarded-client-cert`. `None` when tegata is reached without a gateway.
pub struct Caller(pub Option<String>);

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self(
            parts
                .headers
                .get("x-forwarded-client-cert")
                .and_then(|v| v.to_str().ok())
                .and_then(xfcc_hash)
                .map(|h| h.to_ascii_lowercase()),
        )))
    }
}

/// What the caller's certificate is to tegata.
pub enum CallerDevice<'a> {
    Unidentified,
    Foreign,
    Device { name: &'a str, groups: &'a [String] },
}

pub fn caller_device<'a>(state: &'a State, caller: &Caller) -> CallerDevice<'a> {
    let Some(fingerprint) = &caller.0 else { return CallerDevice::Unidentified };
    let t = now();
    state
        .devices
        .iter()
        .find(|d| {
            d.certs
                .iter()
                .any(|c| &c.fingerprint_sha256 == fingerprint && c.state(t) == CertState::Active)
        })
        .map_or(CallerDevice::Foreign, |d| CallerDevice::Device {
            name: &d.name,
            groups: &d.groups,
        })
}

/// Lowercase host without port or trailing dot, or `None` when it is not a hostname.
pub fn normalize_host(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let host = if raw.starts_with('[') {
        return None;
    } else {
        raw.rsplit_once(':')
            .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
            .map_or(raw, |(h, _)| h)
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    valid.then_some(host)
}

/// Lowercase, deduplicated, sorted group names of letters, digits, `-` and `_`.
pub fn clean_groups(raw: &[String]) -> ApiResult<Vec<String>> {
    let mut groups = Vec::new();
    for g in raw {
        let g = g.trim().to_lowercase();
        if g.is_empty() {
            continue;
        }
        if g.len() > 32 || !g.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(ApiError::bad_request(format!(
                "group {g:?} must be up to 32 letters, digits, - or _"
            )));
        }
        if !groups.contains(&g) {
            groups.push(g);
        }
    }
    groups.sort();
    Ok(groups)
}

impl App {
    pub fn own_host(&self) -> Option<String> {
        self.settings.public_url.host_str().and_then(normalize_host)
    }

    /// Why the caller's certificate cannot reach tegata under `state`, if it cannot.
    fn caller_shut_out(&self, state: &State, caller: &Caller) -> Option<String> {
        let own = self.own_host()?;
        let rule = state.apps.iter().find(|a| a.host == own).filter(|r| r.restricted)?;
        let allowed = rule.groups.join(", ");
        match caller_device(state, caller) {
            CallerDevice::Unidentified => None,
            CallerDevice::Device { groups, .. } if rule.admits(groups) => None,
            CallerDevice::Device { name, .. } => Some(format!(
                "{own} would only admit {allowed}, and {name}, the device you are using, is in \
                 none of them."
            )),
            CallerDevice::Foreign => Some(format!(
                "This browser presents a certificate tegata did not issue, and those never \
                 pass a restricted app like {own}."
            )),
        }
    }

    /// Applies `change`, refusing unless `confirmed` when it shuts the caller out of tegata.
    fn guarded<T>(
        &self,
        s: &mut State,
        caller: &Caller,
        confirmed: bool,
        change: impl FnOnce(&mut State) -> ApiResult<T>,
    ) -> ApiResult<T> {
        let was_in = self.caller_shut_out(s, caller).is_none();
        let out = change(s)?;
        if let Some(reason) = self.caller_shut_out(s, caller).filter(|_| was_in) {
            if !confirmed {
                return Err(ApiError::LockOut(format!(
                    "This would lock you out of tegata. {reason}"
                )));
            }
            tracing::warn!(%reason, "applied a change that locks the caller out of tegata");
        }
        Ok(out)
    }

    pub async fn apps(&self) -> Vec<AppRule> {
        let mut apps = self.db.read().await.apps;
        apps.sort_by(|a, b| a.host.cmp(&b.host));
        apps
    }

    pub async fn groups(&self) -> Vec<String> {
        let state = self.db.read().await;
        let mut all: Vec<String> = state
            .devices
            .iter()
            .flat_map(|d| d.groups.iter())
            .chain(state.apps.iter().flat_map(|a| a.groups.iter()))
            .cloned()
            .collect();
        all.sort();
        all.dedup();
        all
    }

    pub async fn add_app(&self, host: &str) -> ApiResult<AppRule> {
        let host =
            normalize_host(host).ok_or_else(|| ApiError::bad_request("not a valid hostname"))?;
        self.db
            .update(|s| {
                if s.apps.iter().any(|a| a.host == host) {
                    return Err(ApiError::Conflict(format!("{host} is already listed")));
                }
                let rule = AppRule {
                    host: host.clone(),
                    restricted: false,
                    groups: Vec::new(),
                    first_seen: None,
                    last_seen: None,
                };
                s.apps.push(rule.clone());
                Ok(rule)
            })
            .await
    }

    pub async fn set_app_rule(
        &self,
        caller: &Caller,
        confirmed: bool,
        host: &str,
        restricted: bool,
        groups: &[String],
    ) -> ApiResult<AppRule> {
        let mut rules =
            self.set_app_rules(caller, confirmed, &[host.to_owned()], restricted, groups).await?;
        Ok(rules.remove(0))
    }

    /// Gives every host in `hosts` the same rule, in one write.
    pub async fn set_app_rules(
        &self,
        caller: &Caller,
        confirmed: bool,
        hosts: &[String],
        restricted: bool,
        groups: &[String],
    ) -> ApiResult<Vec<AppRule>> {
        let mut wanted = Vec::new();
        for raw in hosts {
            let host = normalize_host(raw).ok_or(ApiError::NotFound)?;
            if !wanted.contains(&host) {
                wanted.push(host);
            }
        }
        if wanted.is_empty() {
            return Err(ApiError::bad_request("pick at least one app"));
        }
        let groups = clean_groups(groups)?;
        if restricted && groups.is_empty() {
            return Err(ApiError::bad_request("a restricted app needs at least one group"));
        }
        let rules = self
            .db
            .update(|s| {
                self.guarded(s, caller, confirmed, |s| {
                    let mut changed = Vec::new();
                    for host in &wanted {
                        let app = s
                            .apps
                            .iter_mut()
                            .find(|a| &a.host == host)
                            .ok_or(ApiError::NotFound)?;
                        app.restricted = restricted;
                        app.groups.clone_from(&groups);
                        changed.push(app.clone());
                    }
                    Ok(changed)
                })
            })
            .await?;
        for rule in &rules {
            tracing::info!(host = %rule.host, restricted, groups = ?rule.groups, "app rule changed");
        }
        Ok(rules)
    }

    pub async fn remove_app(&self, host: &str) -> ApiResult<()> {
        let host = normalize_host(host).ok_or(ApiError::NotFound)?;
        self.db
            .update(|s| {
                let before = s.apps.len();
                s.apps.retain(|a| a.host != host);
                if s.apps.len() == before { Err(ApiError::NotFound) } else { Ok(()) }
            })
            .await
    }

    pub async fn set_device_groups(
        &self,
        caller: &Caller,
        confirmed: bool,
        id: Uuid,
        groups: &[String],
    ) -> ApiResult<DeviceView> {
        let groups = clean_groups(groups)?;
        self.db
            .update(|s| {
                self.guarded(s, caller, confirmed, |s| {
                    let d = s.devices.iter_mut().find(|d| d.id == id).ok_or(ApiError::NotFound)?;
                    d.groups.clone_from(&groups);
                    Ok(self.view(d))
                })
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(normalize_host("App.Example.com:443").as_deref(), Some("app.example.com"));
        assert_eq!(normalize_host("app.example.com.").as_deref(), Some("app.example.com"));
        assert_eq!(normalize_host("localhost").as_deref(), Some("localhost"));
        assert_eq!(normalize_host("[::1]:80"), None);
        assert_eq!(normalize_host("bad_host"), None);
        assert_eq!(normalize_host("-x.example.com"), None);
        assert_eq!(normalize_host(""), None);
    }

    #[test]
    fn groups() {
        let raw = ["Family".to_owned(), " admin ".to_owned(), "family".to_owned(), String::new()];
        assert_eq!(clean_groups(&raw).unwrap(), ["admin", "family"]);
        assert!(clean_groups(&["a b".to_owned()]).is_err());
    }
}
