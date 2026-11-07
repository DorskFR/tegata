mod local;
mod openbao;

use async_trait::async_trait;
pub use local::LocalCa;
pub use openbao::OpenBaoCa;
use time::{Duration, OffsetDateTime};

use crate::util::sha256_hex;

pub struct Issued {
    pub cert_der: Vec<u8>,
    pub key_pkcs8_der: Vec<u8>,
    pub chain_der: Vec<Vec<u8>>,
    pub serial: String,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl Issued {
    pub fn fingerprint(&self) -> String {
        sha256_hex(&self.cert_der)
    }
}

#[async_trait]
pub trait Ca: Send + Sync {
    async fn issue(&self, common_name: &str, validity: Duration) -> anyhow::Result<Issued>;
    async fn revoke(&self, serial: &str) -> anyhow::Result<()>;
    /// Builds a fresh CRL so its next-update keeps moving forward.
    async fn refresh_crl(&self) -> anyhow::Result<()>;
    async fn crl_pem(&self) -> anyhow::Result<String>;
    fn ca_pem(&self) -> &str;
    fn subject(&self) -> &str;
}

pub fn subject_of(pem: &str) -> anyhow::Result<String> {
    let block = ::pem::parse(pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(block.contents())
        .map_err(|e| anyhow::anyhow!("parsing CA certificate: {e}"))?;
    Ok(cert.subject().to_string())
}

pub fn validity_of(der: &[u8]) -> anyhow::Result<(OffsetDateTime, OffsetDateTime)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| anyhow::anyhow!("parsing issued certificate: {e}"))?;
    let v = cert.validity();
    Ok((v.not_before.to_datetime(), v.not_after.to_datetime()))
}
