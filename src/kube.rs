use std::collections::BTreeMap;

use anyhow::{Context, bail};
use reqwest::{Certificate, Client};
use serde_json::json;

const SA_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

/// Whether the CRL first in `candidate` has a lower CRL number than the one first in
/// `published`, i.e. another replica already published a newer one.
pub fn older_crl(candidate: &str, published: &str) -> bool {
    let (Ok(candidate), Ok(published)) = (::pem::parse(candidate), ::pem::parse(published)) else {
        return false;
    };
    let parsed = (
        x509_parser::parse_x509_crl(candidate.contents()),
        x509_parser::parse_x509_crl(published.contents()),
    );
    let (Ok((_, candidate)), Ok((_, published))) = parsed else { return false };
    matches!((candidate.crl_number(), published.crl_number()), (Some(c), Some(p)) if c < p)
}

/// Just enough of the Kubernetes API to server-side apply one ConfigMap.
pub struct ConfigMapWriter {
    http: Client,
    base: String,
    namespace: String,
    name: String,
}

impl ConfigMapWriter {
    pub fn in_cluster(namespace: String, name: String) -> anyhow::Result<Self> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").context("not running in a cluster")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        let ca = std::fs::read(format!("{SA_DIR}/ca.crt")).context("reading cluster CA")?;
        let http = Client::builder()
            .tls_certs_only(Certificate::from_pem_bundle(&ca)?)
            .timeout(std::time::Duration::from_secs(20))
            .build()?;
        let host = if host.contains(':') { format!("[{host}]") } else { host };
        Ok(Self { http, base: format!("https://{host}:{port}"), namespace, name })
    }

    /// One key of the ConfigMap as published, `None` when it does not exist yet.
    pub async fn current(&self, key: &str) -> anyhow::Result<Option<String>> {
        let token = tokio::fs::read_to_string(format!("{SA_DIR}/token")).await?;
        let url =
            format!("{}/api/v1/namespaces/{}/configmaps/{}", self.base, self.namespace, self.name);
        let resp = self.http.get(url).bearer_auth(token.trim()).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            bail!("reading ConfigMap failed: {} {}", resp.status(), resp.text().await?);
        }
        let body: serde_json::Value = resp.json().await?;
        Ok(body["data"][key].as_str().map(str::to_owned))
    }

    pub async fn apply(&self, data: &BTreeMap<String, String>) -> anyhow::Result<()> {
        let token = tokio::fs::read_to_string(format!("{SA_DIR}/token")).await?;
        let body = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": self.name,
                "namespace": self.namespace,
                "labels": { "app.kubernetes.io/managed-by": "tegata" },
            },
            "data": data,
        });
        let url = format!(
            "{}/api/v1/namespaces/{}/configmaps/{}?fieldManager=tegata&force=true",
            self.base, self.namespace, self.name
        );
        let resp = self
            .http
            .patch(url)
            .bearer_auth(token.trim())
            .header("Content-Type", "application/apply-patch+yaml")
            .body(body.to_string())
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("applying ConfigMap failed: {} {}", resp.status(), resp.text().await?);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::{Ca, LocalCa};

    #[tokio::test]
    async fn a_crl_fetched_earlier_never_replaces_a_newer_one() {
        let dir = std::env::temp_dir().join(format!("tegata-crl-{}", uuid::Uuid::new_v4()));
        let ca = LocalCa::open(dir.clone(), "test CA").await.unwrap();
        let before = ca.crl_pem().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        ca.revoke("01:02").await.unwrap();
        let after = ca.crl_pem().await.unwrap();
        assert!(older_crl(&before, &after));
        assert!(!older_crl(&after, &before));
        assert!(!older_crl(&after, &after), "the same CRL is published again");
        assert!(!older_crl(&after, "not a CRL"), "an unreadable published CRL is replaced");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
