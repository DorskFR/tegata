use std::sync::Arc;

use anyhow::anyhow;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

use crate::model::State;
use crate::store::{SaveError, Store};

/// Lower bound between two store loads triggered by cache misses.
pub const MISS_RELOAD_INTERVAL: Duration = Duration::from_secs(1);

/// Cached state with serialized, compare-and-set writes.
pub struct Db {
    store: Arc<dyn Store>,
    cache: Mutex<(State, Option<u64>)>,
    /// When the last completed load started; held across a load, so loads never overlap.
    loaded_at: Mutex<Instant>,
}

impl Db {
    pub async fn open(store: Arc<dyn Store>) -> anyhow::Result<Self> {
        let started = Instant::now();
        let loaded = store.load().await?;
        Ok(Self { store, cache: Mutex::new(loaded), loaded_at: Mutex::new(started) })
    }

    pub async fn read(&self) -> State {
        self.cache.lock().await.0.clone()
    }

    /// Picks up writes made by other replicas. Never moves the cache backwards.
    pub async fn refresh(&self) -> anyhow::Result<()> {
        let mut loaded_at = self.loaded_at.lock().await;
        let started = Instant::now();
        self.load_newer().await?;
        *loaded_at = started;
        Ok(())
    }

    /// Like `refresh`, for lookups that missed the cache: returns once a load that started
    /// after the call has finished, but loads at most once per `MISS_RELOAD_INTERVAL`
    /// however many callers miss, since the misses can come from anyone.
    pub async fn refresh_on_miss(&self) -> anyhow::Result<()> {
        let asked = Instant::now();
        let mut loaded_at = self.loaded_at.lock().await;
        if *loaded_at >= asked {
            return Ok(());
        }
        tokio::time::sleep_until(*loaded_at + MISS_RELOAD_INTERVAL).await;
        let started = Instant::now();
        self.load_newer().await?;
        *loaded_at = started;
        Ok(())
    }

    async fn load_newer(&self) -> anyhow::Result<()> {
        let loaded = self.store.load().await?;
        let mut cache = self.cache.lock().await;
        let newer = match (loaded.1, cache.1) {
            (Some(new), Some(old)) => new > old,
            _ => true,
        };
        if newer {
            *cache = loaded;
        }
        Ok(())
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
    use std::sync::atomic::{AtomicU32, Ordering};

    use async_trait::async_trait;

    use super::*;
    use crate::store::MemoryStore;

    #[derive(Default)]
    struct CountingStore {
        inner: MemoryStore,
        loads: AtomicU32,
    }

    #[async_trait]
    impl Store for CountingStore {
        async fn load(&self) -> anyhow::Result<(State, Option<u64>)> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            self.inner.load().await
        }

        async fn save(&self, state: &State, version: Option<u64>) -> Result<u64, SaveError> {
            self.inner.save(state, version).await
        }
    }

    #[tokio::test]
    async fn misses_share_rate_limited_loads_that_still_see_new_writes() {
        let store = Arc::new(CountingStore::default());
        let db = Arc::new(Db::open(store.clone()).await.unwrap());
        let mut state = State::default();
        state.sessions.push(crate::model::SessionRecord {
            token_hash: "x".into(),
            expires_at: crate::util::now(),
        });
        store.save(&state, Some(0)).await.unwrap();

        let misses: Vec<_> = (0..50)
            .map(|_| {
                let db = db.clone();
                tokio::spawn(async move { db.refresh_on_miss().await.unwrap() })
            })
            .collect();
        for miss in misses {
            miss.await.unwrap();
        }
        assert_eq!(store.loads.load(Ordering::SeqCst), 2, "50 misses cost one load");
        assert_eq!(db.read().await.sessions.len(), 1, "a write made before the miss is seen");

        let before = Instant::now();
        db.refresh_on_miss().await.unwrap();
        assert!(before.elapsed() >= MISS_RELOAD_INTERVAL / 2, "back-to-back misses are spaced");
        assert_eq!(store.loads.load(Ordering::SeqCst), 3);
    }

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
