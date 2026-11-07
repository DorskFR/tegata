use std::path::{Path, PathBuf};

use anyhow::Context;
use async_trait::async_trait;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
    RevocationReason, RevokedCertParams, SerialNumber,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

use super::{Ca, Issued, pem_not_after, subject_of};
use crate::util::{format_serial, normalize_serial, now};

#[derive(Default, Serialize, Deserialize)]
struct Revoked {
    #[serde(default)]
    serials: Vec<(String, i64)>,
}

/// A CA kept in a directory: `ca.crt`, `ca.key`, `revoked.json`. Created on first use.
pub struct LocalCa {
    dir: PathBuf,
    cert_pem: String,
    key: KeyPair,
    subject: String,
    not_after: OffsetDateTime,
    revoked: Mutex<Revoked>,
}

impl LocalCa {
    pub async fn open(dir: impl AsRef<Path>, common_name: &str) -> anyhow::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&dir).await.context("creating CA dir")?;
        let (cert_path, key_path) = (dir.join("ca.crt"), dir.join("ca.key"));
        let (cert_pem, key) = if tokio::fs::try_exists(&key_path).await? {
            let key = KeyPair::from_pem(&tokio::fs::read_to_string(&key_path).await?)?;
            (tokio::fs::read_to_string(&cert_path).await?, key)
        } else {
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::default();
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, common_name);
            params.distinguished_name = dn;
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.not_before = now() - Duration::minutes(5);
            params.not_after = now() + Duration::days(3650);
            let cert = params.self_signed(&key)?;
            write_private(&key_path, key.serialize_pem().as_bytes()).await?;
            tokio::fs::write(&cert_path, cert.pem()).await?;
            (cert.pem(), key)
        };
        let revoked = match tokio::fs::read(dir.join("revoked.json")).await {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Revoked::default(),
            Err(e) => return Err(e.into()),
        };
        let subject = subject_of(&cert_pem)?;
        let not_after = pem_not_after(&cert_pem)?;
        Ok(Self { dir, cert_pem, key, subject, not_after, revoked: Mutex::new(revoked) })
    }

    fn issuer(&self) -> anyhow::Result<Issuer<'_, &KeyPair>> {
        Ok(Issuer::from_ca_cert_pem(&self.cert_pem, &self.key)?)
    }
}

async fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    tokio::fs::write(path, bytes).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    Ok(())
}

#[async_trait]
impl Ca for LocalCa {
    async fn issue(&self, common_name: &str, validity: Duration) -> anyhow::Result<Issued> {
        let key = KeyPair::generate()?;
        let serial: [u8; 16] = rand::random();
        let mut serial = serial.to_vec();
        serial[0] &= 0x7f;
        serial[0] |= 0x01;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now() - Duration::minutes(5);
        params.not_after = now() + validity;
        let cert = params.signed_by(&key, &self.issuer()?)?;
        let ca_der = ::pem::parse(&self.cert_pem)?.into_contents();
        Ok(Issued {
            cert_der: cert.der().to_vec(),
            key_pkcs8_der: key.serialize_der(),
            chain_der: vec![ca_der],
            serial: format_serial(&serial),
            not_before: params.not_before,
            not_after: params.not_after,
        })
    }

    async fn revoke(&self, serial: &str) -> anyhow::Result<()> {
        let serial = normalize_serial(serial);
        let mut revoked = self.revoked.lock().await;
        if !revoked.serials.iter().any(|(s, _)| *s == serial) {
            revoked.serials.push((serial, now().unix_timestamp()));
            tokio::fs::write(self.dir.join("revoked.json"), serde_json::to_vec(&*revoked)?).await?;
        }
        Ok(())
    }

    async fn refresh_crl(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn crl_pem(&self) -> anyhow::Result<String> {
        let revoked = self.revoked.lock().await;
        let revoked_certs = revoked
            .serials
            .iter()
            .map(|(serial, at)| {
                Ok(RevokedCertParams {
                    serial_number: SerialNumber::from_slice(&hex::decode(serial.replace(':', ""))?),
                    revocation_time: OffsetDateTime::from_unix_timestamp(*at)?,
                    reason_code: Some(RevocationReason::Unspecified),
                    invalidity_date: None,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let this_update = now();
        let crl_number = this_update.unix_timestamp().to_be_bytes();
        let params = CertificateRevocationListParams {
            this_update,
            next_update: this_update + Duration::days(7),
            crl_number: SerialNumber::from_slice(&crl_number),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };
        Ok(params.signed_by(&self.issuer()?)?.pem()?)
    }

    fn ca_pem(&self) -> &str {
        &self.cert_pem
    }

    fn subject(&self) -> &str {
        &self.subject
    }

    fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }
}
