mod file;
mod memory;
mod openbao;

use async_trait::async_trait;
pub use file::FileStore;
pub use memory::MemoryStore;
pub use openbao::OpenBaoStore;

use crate::model::State;

/// Persists the whole state as one document; `version` enables compare-and-set.
#[async_trait]
pub trait Store: Send + Sync {
    async fn load(&self) -> anyhow::Result<(State, Option<u64>)>;
    async fn save(&self, state: &State, version: Option<u64>) -> Result<u64, SaveError>;
}

#[derive(Debug, thiserror::Error)]
pub enum SaveError {
    #[error("state changed underneath")]
    Conflict,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
