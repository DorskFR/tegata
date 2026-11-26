use std::sync::{Arc, RwLock};

use anyhow::anyhow;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

use crate::model::State;
use crate::store::{SaveError, Store};

/// Lower bound between two store loads triggered by cache misses.
pub const MISS_RELOAD_INTERVAL: Duration = Duration::from_secs(1);

type Snapshot = (Arc<State>, Option<u64>);

/// Cached state with serialized, compare-and-set writes. Readers get the last committed
/// snapshot and never wait on the store.
pub struct Db {
    store: Arc<dyn Store>,
    snapshot: RwLock<Snapshot>,
    /// Held across every store load and save, so a load never lands over a newer write.
    writer: Mutex<()>,
    /// When the last completed load started.
    loaded_at: Mutex<Instant>,
}

impl Db {
    pub async fn open(store: Arc<dyn Store>) -> anyhow::Result<Self> {
        let started = Instant::now();
        let (state, version) = store.load().await?;
        Ok(Self {
            store,
            snapshot: RwLock::new((Arc::new(state), version)),
            writer: Mutex::new(()),
            loaded_at: Mutex::new(started),
        })
    }

    pub fn read(&self) -> Arc<State> {
        self.current().0
    }

    fn current(&self) -> Snapshot {
        self.snapshot.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }

    fn commit(&self, next: Snapshot) {
        *self.snapshot.write().unwrap_or_else(std::sync::PoisonError::into_inner) = next;
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
        let _writer = self.writer.lock().await;
        let (state, version) = self.store.load().await?;
        let newer = match (version, self.current().1) {
            (Some(new), Some(old)) => new > old,
            _ => true,
        };
        if newer {
            self.commit((Arc::new(state), version));
        }
        Ok(())
    }

    /// Applies `f` to a copy of the state and persists it. `f` may run again after a
    /// concurrent write elsewhere, so it must only depend on the state it is given.
    pub async fn update<T, E>(&self, mut f: impl FnMut(&mut State) -> Result<T, E>) -> Result<T, E>
    where
        E: From<anyhow::Error>,
    {
        let _writer = self.writer.lock().await;
        let (mut base, mut version) = self.current();
        for _ in 0..3 {
            let mut next = State::clone(&*base);
            let out = f(&mut next)?;
            match self.store.save(&next, version).await {
                Ok(saved) => {
                    self.commit((Arc::new(next), version.map(|_| saved)));
                    return Ok(out);
                }
                Err(SaveError::Conflict) => {
                    let (state, loaded) = self.store.load().await?;
                    (base, version) = (Arc::new(state), loaded);
                    self.commit((base.clone(), version));
                }
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
            passkey_id: None,
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
        assert_eq!(db.read().sessions.len(), 1, "a write made before the miss is seen");

        let before = Instant::now();
        db.refresh_on_miss().await.unwrap();
        assert!(before.elapsed() >= MISS_RELOAD_INTERVAL / 2, "back-to-back misses are spaced");
        assert_eq!(store.loads.load(Ordering::SeqCst), 3);
    }

    /// Versionless like `FileStore`; loads and saves can be held open by the test.
    struct SlowStore {
        inner: MemoryStore,
        load_delay: std::sync::Mutex<Duration>,
        save_gate: tokio::sync::Semaphore,
    }

    impl Default for SlowStore {
        fn default() -> Self {
            Self {
                inner: MemoryStore::default(),
                load_delay: std::sync::Mutex::new(Duration::ZERO),
                save_gate: tokio::sync::Semaphore::new(0),
            }
        }
    }

    #[async_trait]
    impl Store for SlowStore {
        async fn load(&self) -> anyhow::Result<(State, Option<u64>)> {
            let (state, _) = self.inner.load().await?;
            let delay = *self.load_delay.lock().unwrap();
            tokio::time::sleep(delay).await;
            Ok((state, None))
        }

        async fn save(&self, state: &State, _: Option<u64>) -> Result<u64, SaveError> {
            drop(self.save_gate.acquire().await.unwrap());
            let version = self.inner.load().await?.1;
            self.inner.save(state, version).await
        }
    }

    fn session(hash: &str) -> crate::model::SessionRecord {
        crate::model::SessionRecord {
            token_hash: hash.into(),
            expires_at: crate::util::now() + time::Duration::hours(1),
            passkey_id: None,
        }
    }

    #[tokio::test]
    async fn reads_do_not_wait_for_a_slow_save() {
        let store = Arc::new(SlowStore::default());
        let db = Arc::new(Db::open(store.clone()).await.unwrap());
        let writer = db.clone();
        let write = tokio::spawn(async move {
            writer
                .update(|s| {
                    s.sessions.push(session("a"));
                    Ok::<_, anyhow::Error>(())
                })
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let read = tokio::time::timeout(Duration::from_millis(100), async { db.read() }).await;
        assert!(read.unwrap().sessions.is_empty(), "the read returns the committed state");
        store.save_gate.add_permits(1);
        write.await.unwrap().unwrap();
        assert_eq!(db.read().sessions.len(), 1);
    }

    #[tokio::test]
    async fn a_refresh_never_rolls_back_a_write_that_finished_during_its_load() {
        let store = Arc::new(SlowStore::default());
        store.save_gate.add_permits(100);
        let db = Arc::new(Db::open(store.clone()).await.unwrap());
        *store.load_delay.lock().unwrap() = Duration::from_millis(200);
        let refresher = db.clone();
        let refresh = tokio::spawn(async move { refresher.refresh().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        db.update(|s| {
            s.sessions.push(session("logged-in"));
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
        refresh.await.unwrap().unwrap();
        db.update(|s| {
            s.sessions.push(session("later"));
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
        let hashes: Vec<_> = store
            .inner
            .load()
            .await
            .unwrap()
            .0
            .sessions
            .into_iter()
            .map(|s| s.token_hash)
            .collect();
        assert_eq!(hashes, ["logged-in", "later"]);
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
