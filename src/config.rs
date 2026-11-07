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
use crate::kube::ConfigMapWriter;
use crate::openbao::{self, OpenBao};
use crate::store::{FileStore, MemoryStore, OpenBaoStore, Store};
use crate::util::{now, random_token};

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
    /// Needed to register the first passkey. Generated and logged when unset.
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
}

impl Cli {
    fn openbao(&self) -> anyhow::Result<Arc<OpenBao>> {
        let addr = self.openbao_addr.as_deref().context("TEGATA_OPENBAO_ADDR is required")?;
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
        let setup_token = self.setup_token.clone().unwrap_or_else(random_token);
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
        };
        let auth = Auth::new(&settings.public_url, &settings.rp_name)?;
        let db = Db::open(store).await?;
        if db.read().await.passkeys.is_empty() && self.setup_token.is_none() {
            tracing::warn!(setup_token = %settings.setup_token, "no passkey registered yet: open the app and use this setup token");
        }
        Ok(App::new(settings, db, ca, auth, trust))
    }
}
