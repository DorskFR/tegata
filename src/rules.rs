use uuid::Uuid;

use crate::app::App;
use crate::error::{ApiError, ApiResult};
use crate::model::{AppRule, DeviceView};

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
        host: &str,
        restricted: bool,
        groups: &[String],
    ) -> ApiResult<AppRule> {
        let host = normalize_host(host).ok_or(ApiError::NotFound)?;
        let groups = clean_groups(groups)?;
        if restricted && groups.is_empty() {
            return Err(ApiError::bad_request("a restricted app needs at least one group"));
        }
        let rule = self
            .db
            .update(|s| {
                let app = s.apps.iter_mut().find(|a| a.host == host).ok_or(ApiError::NotFound)?;
                app.restricted = restricted;
                app.groups.clone_from(&groups);
                Ok::<_, ApiError>(app.clone())
            })
            .await?;
        tracing::info!(host = %rule.host, restricted, groups = ?rule.groups, "app rule changed");
        Ok(rule)
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

    pub async fn set_device_groups(&self, id: Uuid, groups: &[String]) -> ApiResult<DeviceView> {
        let groups = clean_groups(groups)?;
        self.db
            .update(|s| {
                let d = s.devices.iter_mut().find(|d| d.id == id).ok_or(ApiError::NotFound)?;
                d.groups.clone_from(&groups);
                Ok::<_, ApiError>(self.view(d))
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
