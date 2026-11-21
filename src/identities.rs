use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::rules::normalize_host;

/// Where a service identity may go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hosts {
    /// Every app that is not restricted to device groups.
    Unrestricted,
    /// Only these hosts, restricted or not.
    Only(Vec<String>),
}

/// A certificate tegata did not issue, declared by the operator and authorised like a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceIdentity {
    pub name: String,
    pub fingerprint_sha256: String,
    pub hosts: Hosts,
}

impl ServiceIdentity {
    pub fn admits(&self, host: Option<&str>, restricted: bool) -> bool {
        match &self.hosts {
            Hosts::Unrestricted => !restricted,
            Hosts::Only(list) => host.is_some_and(|h| list.iter().any(|l| l == h)),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawHosts {
    Keyword(String),
    List(Vec<String>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    name: String,
    fingerprint_sha256: String,
    hosts: RawHosts,
}

/// Parses a JSON list of `{"name", "fingerprint_sha256", "hosts"}`, where `hosts` is
/// `"unrestricted"` or a list of hostnames.
pub fn parse(json: &str) -> anyhow::Result<Vec<ServiceIdentity>> {
    let raw: Vec<RawIdentity> =
        serde_json::from_str(json).context("not a JSON list of identities")?;
    let mut out: Vec<ServiceIdentity> = Vec::with_capacity(raw.len());
    for r in raw {
        let name = r.name.trim().to_owned();
        if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            bail!("identity name {name:?} must be 1 to 64 printable characters");
        }
        let fingerprint = r.fingerprint_sha256.trim().replace(':', "").to_ascii_lowercase();
        if fingerprint.len() != 64 || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("{name}: fingerprint_sha256 must be 64 hex digits");
        }
        let hosts = match r.hosts {
            RawHosts::Keyword(k) if k == "unrestricted" => Hosts::Unrestricted,
            RawHosts::Keyword(k) => {
                bail!("{name}: hosts is {k:?}, expected \"unrestricted\" or a list")
            }
            RawHosts::List(list) if list.is_empty() => bail!("{name}: hosts is an empty list"),
            RawHosts::List(list) => Hosts::Only(
                list.iter()
                    .map(|h| normalize_host(h).with_context(|| format!("{name}: bad host {h:?}")))
                    .collect::<anyhow::Result<_>>()?,
            ),
        };
        if out.iter().any(|o| o.name.eq_ignore_ascii_case(&name)) {
            bail!("identity {name} is declared twice");
        }
        if out.iter().any(|o| o.fingerprint_sha256 == fingerprint) {
            bail!("{name}: fingerprint already belongs to another identity");
        }
        out.push(ServiceIdentity { name, fingerprint_sha256: fingerprint, hosts });
    }
    Ok(out)
}

/// The declared identities, re-read from their file by [`Identities::reload`].
#[derive(Default)]
pub struct Identities {
    path: Option<PathBuf>,
    current: RwLock<(String, Arc<Vec<ServiceIdentity>>)>,
}

impl Identities {
    pub fn open(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let this = Self { path, current: RwLock::default() };
        this.reload()?;
        Ok(this)
    }

    pub fn all(&self) -> Arc<Vec<ServiceIdentity>> {
        self.current.read().unwrap_or_else(std::sync::PoisonError::into_inner).1.clone()
    }

    pub fn find(&self, fingerprint: &str) -> Option<ServiceIdentity> {
        self.all().iter().find(|i| i.fingerprint_sha256 == fingerprint).cloned()
    }

    /// Re-reads the file; `true` when the list changed. A file that fails to parse leaves
    /// the previous list in place.
    pub fn reload(&self) -> anyhow::Result<bool> {
        let Some(path) = &self.path else { return Ok(false) };
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if self.current.read().unwrap_or_else(std::sync::PoisonError::into_inner).0 == text {
            return Ok(false);
        }
        let list = parse(&text).with_context(|| format!("parsing {}", path.display()))?;
        let names: Vec<&str> = list.iter().map(|i| i.name.as_str()).collect();
        tracing::info!(?names, "service identities loaded");
        *self.current.write().unwrap_or_else(std::sync::PoisonError::into_inner) =
            (text, Arc::new(list));
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_identities() {
        let fp = format!("1B:97:{}", "0e".repeat(30));
        let list = parse(&format!(
            r#"[{{"name":"qa-bot","fingerprint_sha256":"{fp}","hosts":"unrestricted"}},
               {{"name":"uploader","fingerprint_sha256":"{}","hosts":["Artifact.Example.com"]}}]"#,
            "ab".repeat(32)
        ))
        .unwrap();
        assert_eq!(list[0].fingerprint_sha256, fp.replace(':', "").to_ascii_lowercase());
        assert_eq!(list[0].hosts, Hosts::Unrestricted);
        assert_eq!(list[1].hosts, Hosts::Only(vec!["artifact.example.com".into()]));
    }

    #[test]
    fn rejects_bad_identities() {
        let one = |fp: &str, hosts: &str| {
            parse(&format!(r#"[{{"name":"a","fingerprint_sha256":"{fp}","hosts":{hosts}}}]"#))
        };
        let fp = "ab".repeat(32);
        assert!(one("abc", r#""unrestricted""#).is_err());
        assert!(one(&fp, r#""everywhere""#).is_err());
        assert!(one(&fp, "[]").is_err());
        assert!(one(&fp, r#"["bad_host"]"#).is_err());
        assert!(one(&fp, r#""unrestricted""#).is_ok());
        let twice = format!(
            r#"[{{"name":"a","fingerprint_sha256":"{fp}","hosts":"unrestricted"}},
               {{"name":"b","fingerprint_sha256":"{fp}","hosts":"unrestricted"}}]"#
        );
        assert!(parse(&twice).is_err());
        assert!(
            parse(r#"[{"name":"a","fingerprint_sha256":"x","hosts":"unrestricted","groups":[]}]"#)
                .is_err()
        );
    }

    #[test]
    fn admits() {
        let open = ServiceIdentity {
            name: "a".into(),
            fingerprint_sha256: String::new(),
            hosts: Hosts::Unrestricted,
        };
        assert!(open.admits(Some("x.example.com"), false));
        assert!(open.admits(None, false));
        assert!(!open.admits(Some("x.example.com"), true));
        let only = ServiceIdentity { hosts: Hosts::Only(vec!["x.example.com".into()]), ..open };
        assert!(only.admits(Some("x.example.com"), true));
        assert!(!only.admits(Some("y.example.com"), false));
        assert!(!only.admits(None, false));
    }
}
