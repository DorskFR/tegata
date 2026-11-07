use std::sync::Arc;

use anyhow::anyhow;
use tokio::sync::Mutex;

use crate::model::State;
use crate::store::{SaveError, Store};

/// Cached state with serialized, compare-and-set writes.
pub struct Db {
    store: Arc<dyn Store>,
    cache: Mutex<(State, Option<u64>)>,
}

impl Db {
    pub async fn open(store: Arc<dyn Store>) -> anyhow::Result<Self> {
        let loaded = store.load().await?;
        Ok(Self { store, cache: Mutex::new(loaded) })
    }

    pub async fn read(&self) -> State {
        self.cache.lock().await.0.clone()
    }

    /// Applies `f` to a copy of the state and persists it. `f` may run again after a
    /// concurrent write elsewhere, so it must only depend on the state it is given.
    pub async fn update<T, E>(&self, mut f: impl FnMut(&mut State) -> Result<T, E>) -> Result<T, E>
    where
        E: From<anyhow::Error>,
    {
        let mut cache = self.cache.lock().await;
        for _ in 0..3 {
            let mut next = cache.0.clone();
            let out = f(&mut next)?;
            match self.store.save(&next, cache.1).await {
                Ok(version) => {
                    *cache = (next, cache.1.map(|_| version));
                    return Ok(out);
                }
                Err(SaveError::Conflict) => *cache = self.store.load().await?,
                Err(SaveError::Other(err)) => return Err(err.into()),
            }
        }
        Err(anyhow!("state kept changing during update").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    #[tokio::test]
    async fn update_persists_and_retries_on_conflict() {
        let store = Arc::new(MemoryStore::default());
        let db = Db::open(store.clone()).await.unwrap();
        store.save(&State::default(), Some(0)).await.unwrap();

        let calls = std::sync::atomic::AtomicU32::new(0);
        db.update(|s| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            s.devices.clear();
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(store.load().await.unwrap().1, Some(2));
    }
}
