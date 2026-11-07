use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use reqwest::Method;
use serde_json::json;
use time::{Duration, OffsetDateTime};

use super::{Ca, Issued, pem_not_after, subject_of, validity_of};
use crate::openbao::OpenBao;
use crate::util::normalize_serial;

/// Issues from an OpenBao PKI role; OpenBao generates the key pair.
pub struct OpenBaoCa {
    bao: Arc<OpenBao>,
    mount: String,
    role: String,
    ca_pem: String,
    subject: String,
    not_after: OffsetDateTime,
}

impl OpenBaoCa {
    /// Retries for a minute: a fresh pod may not reach OpenBao until its network policy lands.
    pub async fn new(bao: Arc<OpenBao>, mount: String, role: String) -> anyhow::Result<Self> {
        let path = format!("{mount}/ca/pem");
        let mut attempt = 0;
        let ca_pem = loop {
            match bao.get_text(&path).await {
                Ok(pem) => break pem,
                Err(err) if attempt < 60 => {
                    attempt += 1;
                    tracing::warn!(error = %err, attempt, "OpenBao not reachable yet");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(err) => return Err(err.into()),
            }
        };
        let subject = subject_of(&ca_pem)?;
        let not_after = pem_not_after(&ca_pem)?;
        Ok(Self { bao, mount, role, ca_pem, subject, not_after })
    }
}

fn der_of(pem: &str) -> anyhow::Result<Vec<u8>> {
    Ok(::pem::parse(pem)?.into_contents())
}

#[async_trait]
impl Ca for OpenBaoCa {
    async fn issue(&self, common_name: &str, validity: Duration) -> anyhow::Result<Issued> {
        let body = json!({
            "common_name": common_name,
            "ttl": format!("{}s", validity.whole_seconds()),
            "private_key_format": "pkcs8",
            "exclude_cn_from_sans": true,
        });
        let resp = self
            .bao
            .request(Method::POST, &format!("{}/issue/{}", self.mount, self.role), Some(&body))
            .await?;
        let data = &resp["data"];
        let field = |name: &str| data[name].as_str().with_context(|| format!("{name} missing"));
        let cert_der = der_of(field("certificate")?)?;
        let (not_before, not_after) = validity_of(&cert_der)?;
        let chain_der = match data["ca_chain"].as_array() {
            Some(chain) if !chain.is_empty() => chain
                .iter()
                .filter_map(|c| c.as_str())
                .map(der_of)
                .collect::<anyhow::Result<_>>()?,
            _ => vec![der_of(field("issuing_ca")?)?],
        };
        Ok(Issued {
            cert_der,
            key_pkcs8_der: der_of(field("private_key")?)?,
            chain_der,
            serial: normalize_serial(field("serial_number")?),
            not_before,
            not_after,
        })
    }

    async fn revoke(&self, serial: &str) -> anyhow::Result<()> {
        let body = json!({ "serial_number": serial });
        self.bao.request(Method::POST, &format!("{}/revoke", self.mount), Some(&body)).await?;
        Ok(())
    }

    async fn refresh_crl(&self) -> anyhow::Result<()> {
        self.bao.request(Method::GET, &format!("{}/crl/rotate", self.mount), None).await?;
        Ok(())
    }

    async fn crl_pem(&self) -> anyhow::Result<String> {
        Ok(self.bao.get_text(&format!("{}/crl/pem", self.mount)).await?)
    }

    fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    fn subject(&self) -> &str {
        &self.subject
    }

    fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }
}
