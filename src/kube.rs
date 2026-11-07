use std::collections::BTreeMap;

use anyhow::{Context, bail};
use reqwest::{Certificate, Client};
use serde_json::json;

const SA_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

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
