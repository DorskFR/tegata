use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, ValueEnum};
use url::Url;

use crate::app::{App, Settings};
use crate::auth::Auth;
use crate::ca::{Ca, LocalCa, OpenBaoCa};
use crate::db::Db;
use crate::identities::Identities;
use crate::kube::ConfigMapWriter;
use crate::openbao::{self, OpenBao};
use crate::store::{FileStore, MemoryStore, OpenBaoStore, Store};
use crate::util::{now, random_token, write_atomic};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Backend {
    /// Everything on local disk under `--data-dir`.
    Local,
    /// OpenBao PKI for certificates and KV v2 for state.
    Openbao,
    /// Local CA, state kept in memory only. For trying things out.
    Memory,
}

#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    #[arg(long, env = "TEGATA_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,
    /// Where Envoy's ext_authz reaches `/authz`. Keep it off the public route.
    #[arg(long, env = "TEGATA_AUTHZ_LISTEN", default_value = "0.0.0.0:8081")]
    pub authz_listen: SocketAddr,
    /// The URL browsers use, e.g. https://tegata.example.com. Passkeys are bound to its host.
    #[arg(long, env = "TEGATA_PUBLIC_URL")]
    pub public_url: Url,
    #[arg(long, env = "TEGATA_RP_NAME", default_value = "tegata")]
    pub rp_name: String,
    #[arg(long, env = "TEGATA_BACKEND", value_enum, default_value = "local")]
    pub backend: Backend,
    #[arg(long, env = "TEGATA_DATA_DIR", default_value = "data")]
    pub data_dir: PathBuf,
    #[arg(long, env = "TEGATA_CA_NAME", default_value = "tegata device CA")]
    pub ca_name: String,
    /// Needed to register the first passkey. When unset, a random one is written to
    /// `setup-token` in the data dir.
    #[arg(long, env = "TEGATA_SETUP_TOKEN", hide_env_values = true)]
    pub setup_token: Option<String>,

    #[arg(long, env = "TEGATA_OPENBAO_ADDR")]
    pub openbao_addr: Option<String>,
    #[arg(long, env = "TEGATA_OPENBAO_TOKEN", hide_env_values = true)]
    pub openbao_token: Option<String>,
    #[arg(long, env = "TEGATA_OPENBAO_K8S_MOUNT", default_value = "kubernetes")]
    pub openbao_k8s_mount: String,
    #[arg(long, env = "TEGATA_OPENBAO_K8S_ROLE")]
    pub openbao_k8s_role: Option<String>,
    #[arg(long, env = "TEGATA_OPENBAO_CA_CERT")]
    pub openbao_ca_cert: Option<PathBuf>,
    /// Refuse a plain http:// OpenBao address that is not loopback, instead of warning.
    #[arg(long, env = "TEGATA_OPENBAO_REQUIRE_TLS", default_value_t = false)]
    pub openbao_require_tls: bool,
    #[arg(long, env = "TEGATA_OPENBAO_PKI_MOUNT", default_value = "pki")]
    pub openbao_pki_mount: String,
    #[arg(long, env = "TEGATA_OPENBAO_PKI_ROLE", default_value = "device")]
    pub openbao_pki_role: String,
    #[arg(long, env = "TEGATA_OPENBAO_KV_MOUNT", default_value = "secret")]
    pub openbao_kv_mount: String,
    #[arg(long, env = "TEGATA_OPENBAO_KV_PATH", default_value = "tegata/state")]
    pub openbao_kv_path: String,

    #[arg(long, env = "TEGATA_DEFAULT_VALIDITY_DAYS", default_value_t = 365)]
    pub default_validity_days: u32,
    /// Longest validity offered. Defaults to whatever the CA itself has left.
    #[arg(long, env = "TEGATA_MAX_VALIDITY_DAYS")]
    pub max_validity_days: Option<u32>,
    #[arg(long, env = "TEGATA_EXPIRING_DAYS", default_value_t = 14)]
    pub expiring_days: u32,
    /// Flag devices in use but not seen for this many days; 0 turns it off.
    #[arg(long, env = "TEGATA_STALE_DAYS", default_value_t = 30)]
    pub stale_days: u32,
    #[arg(long, env = "TEGATA_ENROLLMENT_MINUTES", default_value_t = 30)]
    pub enrollment_minutes: u32,
    #[arg(long, env = "TEGATA_SESSION_HOURS", default_value_t = 12)]
    pub session_hours: u32,
    /// Let `/authz` accept certificates tegata did not issue, e.g. while migrating.
    #[arg(long, env = "TEGATA_AUTHZ_ALLOW_UNKNOWN", default_value_t = false)]
    pub authz_allow_unknown: bool,
    /// JSON file of service identities: certificates tegata did not issue, authorised like
    /// devices. Re-read when it changes.
    #[arg(long, env = "TEGATA_SERVICE_IDENTITIES")]
    pub service_identities: Option<PathBuf>,

    /// `namespace/name` of a ConfigMap to keep filled with `ca.crt` and `ca.crl`.
    #[arg(long, env = "TEGATA_TRUST_CONFIGMAP")]
    pub trust_configmap: Option<String>,
    /// More CA certificates (PEM files) to publish alongside tegata's own.
    #[arg(long, env = "TEGATA_EXTRA_CA_FILES", value_delimiter = ',')]
    pub extra_ca_files: Vec<PathBuf>,
    /// More CRLs (PEM files) to publish, one per extra CA.
    #[arg(long, env = "TEGATA_EXTRA_CRL_FILES", value_delimiter = ',')]
    pub extra_crl_files: Vec<PathBuf>,
    #[arg(long, env = "TEGATA_CRL_REFRESH_MINUTES", default_value_t = 60)]
    pub crl_refresh_minutes: u64,
    /// `/authz` answers 503 and readiness fails when the state could not be reloaded for
    /// this long.
    #[arg(long, env = "TEGATA_MAX_STATE_AGE_SECONDS", default_value_t = 30)]
    pub max_state_age_seconds: u64,
    /// Proxies in front of the gateway that append to `X-Forwarded-For`; the client IP is
    /// the entry this many places from the end.
    #[arg(long, env = "TEGATA_TRUSTED_HOPS", default_value_t = 0)]
    pub trusted_hops: usize,
}

/// Whether `addr` is http:// to anything but a loopback host.
fn plaintext_remote(addr: &str) -> anyhow::Result<bool> {
    let url =
        Url::parse(addr).with_context(|| format!("TEGATA_OPENBAO_ADDR {addr} is not a URL"))?;
    if url.scheme() != "http" {
        return Ok(false);
    }
    let loopback = match url.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    Ok(!loopback)
}

impl Cli {
    /// Writes a generated setup token where only this user can read it, never to the logs.
    async fn hand_out_setup_token(&self, token: &str) {
        let path = self.data_dir.join("setup-token");
        let written = async {
            tokio::fs::create_dir_all(&self.data_dir).await?;
            write_atomic(&path, format!("{token}\n").as_bytes(), 0o600).await
        };
        match written.await {
            Ok(()) => {
                tracing::warn!(path = %path.display(), "no passkey registered yet: open the app and use the setup token in this file")
            }
            Err(err) => {
                tracing::warn!(path = %path.display(), %err, "no passkey registered yet, and the setup token could not be written: set TEGATA_SETUP_TOKEN")
            }
        }
        if std::io::stderr().is_terminal() {
            eprintln!("setup token: {token}");
        }
    }

    fn openbao(&self) -> anyhow::Result<Arc<OpenBao>> {
        let addr = self.openbao_addr.as_deref().context("TEGATA_OPENBAO_ADDR is required")?;
        if plaintext_remote(addr)? {
            if self.openbao_require_tls {
                bail!(
                    "TEGATA_OPENBAO_ADDR {addr} is plain http; use https (TEGATA_OPENBAO_CA_CERT \
                     for a private CA) or unset TEGATA_OPENBAO_REQUIRE_TLS"
                );
            }
            tracing::warn!(
                %addr,
                "OpenBao is reached over plain http: device private keys, the OpenBao token and \
                 the published CA and CRL cross the network unencrypted and unauthenticated; \
                 use https, and set TEGATA_OPENBAO_REQUIRE_TLS=true to refuse this"
            );
        }
        let auth = match (&self.openbao_token, &self.openbao_k8s_role) {
            (Some(token), _) => openbao::Auth::Token(token.clone()),
            (None, Some(role)) => OpenBao::kubernetes(self.openbao_k8s_mount.clone(), role.clone()),
            (None, None) => bail!("set TEGATA_OPENBAO_TOKEN or TEGATA_OPENBAO_K8S_ROLE"),
        };
        let ca = self.openbao_ca_cert.as_ref().map(std::fs::read).transpose()?;
        Ok(Arc::new(OpenBao::new(addr, auth, ca.as_deref())?))
    }

    pub async fn build(self) -> anyhow::Result<App> {
        self.build_with_store(None).await
    }

    /// `shared` replaces the backend's own state store; replicas in tests share one.
    pub async fn build_with_store(self, shared: Option<Arc<dyn Store>>) -> anyhow::Result<App> {
        let (store, ca): (Arc<dyn Store>, Arc<dyn Ca>) = match self.backend {
            Backend::Local => (
                Arc::new(FileStore::new(self.data_dir.join("state.json"))),
                Arc::new(LocalCa::open(self.data_dir.join("ca"), &self.ca_name).await?),
            ),
            Backend::Memory => (
                Arc::new(MemoryStore::default()),
                Arc::new(LocalCa::open(self.data_dir.join("ca"), &self.ca_name).await?),
            ),
            Backend::Openbao => {
                let bao = self.openbao()?;
                (
                    Arc::new(OpenBaoStore::new(
                        bao.clone(),
                        self.openbao_kv_mount.clone(),
                        self.openbao_kv_path.clone(),
                    )),
                    Arc::new(
                        OpenBaoCa::new(
                            bao,
                            self.openbao_pki_mount.clone(),
                            self.openbao_pki_role.clone(),
                        )
                        .await?,
                    ),
                )
            }
        };
        let store = shared.unwrap_or(store);
        let trust = self
            .trust_configmap
            .as_deref()
            .map(|target| {
                let (ns, name) = target
                    .split_once('/')
                    .context("TEGATA_TRUST_CONFIGMAP must be namespace/name")?;
                ConfigMapWriter::in_cluster(ns.to_owned(), name.to_owned())
            })
            .transpose()?;
        let read_all = |files: &[PathBuf]| -> anyhow::Result<Vec<String>> {
            files
                .iter()
                .map(|f| {
                    std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))
                })
                .collect()
        };
        let configured_token = match self.setup_token.as_deref().map(str::trim) {
            Some("") => bail!("TEGATA_SETUP_TOKEN is set but empty; unset it or give it a value"),
            other => other.map(str::to_owned),
        };
        let setup_token = configured_token.clone().unwrap_or_else(random_token);
        let ca_days = u32::try_from((ca.not_after() - now()).whole_days()).unwrap_or(0);
        if ca_days == 0 {
            bail!("the CA expires within a day; renew it before issuing certificates");
        }
        let max_validity_days = self.max_validity_days.map_or(ca_days, |m| m.clamp(1, ca_days));
        let default_validity_days = self.default_validity_days.clamp(1, max_validity_days);
        let mut presets: Vec<u32> =
            [30, 90, 365, 730, 1825].into_iter().filter(|d| *d < max_validity_days).collect();
        presets.push(max_validity_days);
        if !presets.contains(&default_validity_days) {
            presets.push(default_validity_days);
            presets.sort_unstable();
        }
        let settings = Settings {
            public_url: self.public_url.clone(),
            rp_name: self.rp_name.clone(),
            default_validity_days,
            max_validity_days,
            validity_presets: presets,
            expiring_days: self.expiring_days,
            stale_days: self.stale_days,
            enrollment_minutes: self.enrollment_minutes,
            session_hours: self.session_hours,
            authz_allow_unknown: self.authz_allow_unknown,
            extra_ca_pem: read_all(&self.extra_ca_files)?,
            extra_crl_pem: read_all(&self.extra_crl_files)?,
            setup_token,
            max_state_age: std::time::Duration::from_secs(self.max_state_age_seconds.max(1)),
            trusted_hops: self.trusted_hops,
        };
        let identities = Identities::open(self.service_identities.clone())?;
        let auth = Auth::new(&settings.public_url, &settings.rp_name)?;
        let db = Db::open(store).await?;
        if db.read().passkeys.is_empty() && configured_token.is_none() {
            self.hand_out_setup_token(&settings.setup_token).await;
        }
        Ok(App::new(settings, db, ca, auth, trust, identities))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_is_flagged_unless_loopback() {
        for addr in ["http://openbao.security.svc.cluster.local:8200", "http://10.0.0.5:8200"] {
            assert!(plaintext_remote(addr).unwrap(), "{addr}");
        }
        for addr in [
            "https://openbao.security.svc.cluster.local:8200",
            "http://127.0.0.1:8200",
            "http://localhost:8200",
            "http://[::1]:8200",
        ] {
            assert!(!plaintext_remote(addr).unwrap(), "{addr}");
        }
        assert!(plaintext_remote("not a url").is_err());
    }

    #[tokio::test]
    async fn require_tls_refuses_plain_http() {
        let cli = Cli::parse_from([
            "tegata",
            "--public-url",
            "https://tegata.test",
            "--backend",
            "openbao",
            "--openbao-addr",
            "http://openbao.example:8200",
            "--openbao-token",
            "t",
            "--openbao-require-tls",
        ]);
        let err = cli.build().await.err().expect("refused");
        assert!(err.to_string().contains("plain http"), "{err}");
    }
}
