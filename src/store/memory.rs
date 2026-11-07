use async_trait::async_trait;
use tokio::sync::Mutex;

use super::{SaveError, Store};
use crate::model::State;

#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<(State, u64)>,
}

#[async_trait]
impl Store for MemoryStore {
    async fn load(&self) -> anyhow::Result<(State, Option<u64>)> {
        let guard = self.inner.lock().await;
        Ok((guard.0.clone(), Some(guard.1)))
    }

    async fn save(&self, state: &State, version: Option<u64>) -> Result<u64, SaveError> {
        let mut guard = self.inner.lock().await;
        if version != Some(guard.1) {
            return Err(SaveError::Conflict);
        }
        guard.0 = state.clone();
        guard.1 += 1;
        Ok(guard.1)
    }
}
