use std::path::PathBuf;

use anyhow::Context;
use async_trait::async_trait;

use super::{SaveError, Store};
use crate::model::State;

pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl Store for FileStore {
    async fn load(&self) -> anyhow::Result<(State, Option<u64>)> {
        match tokio::fs::read(&self.path).await {
            Ok(bytes) => {
                let state = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing {}", self.path.display()))?;
                Ok((state, None))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok((State::default(), None)),
            Err(err) => Err(err).with_context(|| format!("reading {}", self.path.display())),
        }
    }

    async fn save(&self, state: &State, _version: Option<u64>) -> Result<u64, SaveError> {
        let bytes = serde_json::to_vec_pretty(state).context("serializing state")?;
        if let Some(dir) = self.path.parent() {
            tokio::fs::create_dir_all(dir).await.context("creating state dir")?;
        }
        let tmp = self.path.with_extension("tmp");
        tokio::fs::write(&tmp, bytes).await.context("writing state")?;
        tokio::fs::rename(&tmp, &self.path).await.context("replacing state")?;
        Ok(0)
    }
}
