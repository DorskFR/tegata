use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use reqwest::Method;
use serde_json::json;

use super::{SaveError, Store};
use crate::model::State;
use crate::openbao::{BaoError, OpenBao};

/// State kept as a single KV v2 secret, written with check-and-set.
pub struct OpenBaoStore {
    bao: Arc<OpenBao>,
    mount: String,
    path: String,
}

impl OpenBaoStore {
    pub fn new(bao: Arc<OpenBao>, mount: impl Into<String>, path: impl Into<String>) -> Self {
        Self { bao, mount: mount.into(), path: path.into() }
    }

    fn url(&self) -> String {
        format!("{}/data/{}", self.mount, self.path)
    }
}

#[async_trait]
impl Store for OpenBaoStore {
    async fn load(&self) -> anyhow::Result<(State, Option<u64>)> {
        match self.bao.request(Method::GET, &self.url(), None).await {
            Ok(body) => {
                let doc = body["data"]["data"]["state"].as_str().context("state field missing")?;
                let version = body["data"]["metadata"]["version"].as_u64();
                Ok((serde_json::from_str(doc).context("parsing stored state")?, version))
            }
            Err(BaoError::Status(404, _)) => Ok((State::default(), Some(0))),
            Err(err) => Err(err.into()),
        }
    }

    async fn save(&self, state: &State, version: Option<u64>) -> Result<u64, SaveError> {
        let doc = serde_json::to_string(state).context("serializing state")?;
        let mut body = json!({ "data": { "state": doc } });
        if let Some(version) = version {
            body["options"] = json!({ "cas": version });
        }
        match self.bao.request(Method::POST, &self.url(), Some(&body)).await {
            Ok(resp) => Ok(resp["data"]["version"].as_u64().unwrap_or_default()),
            Err(BaoError::Status(400, msg)) if msg.contains("check-and-set") => {
                Err(SaveError::Conflict)
            }
            Err(err) => Err(SaveError::Other(err.into())),
        }
    }
}
