use std::path::PathBuf;

use anyhow::Context;
use reqwest::{Certificate, Client, Method, StatusCode};
use serde_json::{Value, json};
use tokio::sync::RwLock;

const SA_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

#[derive(Clone, Debug)]
pub enum Auth {
    Token(String),
    Kubernetes { mount: String, role: String, jwt_path: PathBuf },
}

#[derive(Debug, thiserror::Error)]
pub enum BaoError {
    #[error("openbao returned {0}: {1}")]
    Status(u16, String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub struct OpenBao {
    http: Client,
    addr: String,
    auth: Auth,
    token: RwLock<Option<String>>,
}

impl OpenBao {
    pub fn new(addr: &str, auth: Auth, ca_pem: Option<&[u8]>) -> anyhow::Result<Self> {
        let mut builder = Client::builder().timeout(std::time::Duration::from_secs(20));
        if let Some(pem) = ca_pem {
            builder = builder.tls_certs_merge(
                Certificate::from_pem_bundle(pem).context("parsing OpenBao CA bundle")?,
            );
        }
        Ok(Self {
            http: builder.build()?,
            addr: addr.trim_end_matches('/').to_owned(),
            token: RwLock::new(match &auth {
                Auth::Token(t) => Some(t.clone()),
                Auth::Kubernetes { .. } => None,
            }),
            auth,
        })
    }

    pub fn kubernetes(mount: String, role: String) -> Auth {
        Auth::Kubernetes { mount, role, jwt_path: SA_TOKEN.into() }
    }

    async fn login(&self) -> Result<String, BaoError> {
        let Auth::Kubernetes { mount, role, jwt_path } = &self.auth else {
            return Err(BaoError::Status(403, "token rejected".into()));
        };
        let jwt = tokio::fs::read_to_string(jwt_path)
            .await
            .with_context(|| format!("reading {}", jwt_path.display()))?;
        let body = json!({ "role": role, "jwt": jwt.trim() });
        let resp =
            self.send(Method::POST, &format!("auth/{mount}/login"), Some(&body), None).await?;
        let token =
            resp["auth"]["client_token"].as_str().context("login returned no token")?.to_owned();
        *self.token.write().await = Some(token.clone());
        Ok(token)
    }

    async fn current_token(&self) -> Result<String, BaoError> {
        let cached = self.token.read().await.clone();
        match cached {
            Some(token) => Ok(token),
            None => self.login().await,
        }
    }

    /// Calls `/v1/{path}`; logs in again once when the token was rejected.
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, BaoError> {
        let token = self.current_token().await?;
        match self.send(method.clone(), path, body, Some(&token)).await {
            Err(BaoError::Status(403, _)) if matches!(self.auth, Auth::Kubernetes { .. }) => {
                let token = self.login().await?;
                self.send(method, path, body, Some(&token)).await
            }
            other => other,
        }
    }

    pub async fn get_text(&self, path: &str) -> Result<String, BaoError> {
        let resp = self
            .http
            .get(format!("{}/v1/{path}", self.addr))
            .send()
            .await
            .context("calling OpenBao")?;
        let status = resp.status();
        let text = resp.text().await.context("reading OpenBao response")?;
        if status.is_success() { Ok(text) } else { Err(BaoError::Status(status.as_u16(), text)) }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        token: Option<&str>,
    ) -> Result<Value, BaoError> {
        let mut req = self.http.request(method, format!("{}/v1/{path}", self.addr));
        if let Some(token) = token {
            req = req.header("X-Vault-Token", token);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        let resp = req.send().await.context("calling OpenBao")?;
        let status = resp.status();
        let text = resp.text().await.context("reading OpenBao response")?;
        if status == StatusCode::NO_CONTENT || (status.is_success() && text.is_empty()) {
            return Ok(Value::Null);
        }
        if !status.is_success() {
            return Err(BaoError::Status(status.as_u16(), text));
        }
        serde_json::from_str(&text).context("parsing OpenBao response").map_err(Into::into)
    }
}
