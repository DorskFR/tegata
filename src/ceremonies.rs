use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use kagi::{Ceremony, CeremonyStore, Error, Limits};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::db::Db;
use crate::util::now;

/// Kept in the shared state, so the whole document is bounded by `global`.
pub const LIMITS: Limits = Limits { ttl: Duration::from_mins(5), per_address: 20, global: 256 };

/// A ceremony between start and finish, keyed by the hashed id so the state never holds one.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CeremonyRecord {
    pub key: String,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(default)]
    pub network: Option<IpAddr>,
    pub ceremony: serde_json::Value,
}

/// Ceremonies in the state every replica shares; check-and-set makes `take` single-use and
/// the caps exact.
pub struct SharedCeremonies {
    db: Arc<Db>,
    limits: Limits,
}

impl SharedCeremonies {
    pub const fn new(db: Arc<Db>, limits: Limits) -> Self {
        Self { db, limits }
    }

    /// A refusal may come from a stale cache, so callers check it again after a refresh.
    async fn insert(&self, record: &CeremonyRecord) -> Result<(), Outcome> {
        let Limits { ttl, per_address, global } = self.limits;
        self.db
            .update(|s| {
                let at = now();
                s.ceremonies.retain(|c| age(at, c.started_at) < ttl);
                let held = s.ceremonies.iter().filter(|c| c.network == record.network);
                if let Some(oldest) = held.clone().map(|c| c.started_at).min()
                    && held.count() >= per_address
                {
                    let left = ttl.saturating_sub(age(at, oldest));
                    return Err(Outcome::Full(Error::TooMany {
                        retry_after: left.max(Duration::from_secs(1)),
                    }));
                }
                if s.ceremonies.len() >= global {
                    return Err(Outcome::Full(Error::Busy));
                }
                s.ceremonies.push(record.clone());
                Ok(())
            })
            .await
    }

    async fn remove(&self, key: &str) -> Result<CeremonyRecord, Outcome> {
        self.db
            .update(|s| {
                let at = s.ceremonies.iter().position(|c| c.key == key).ok_or(Outcome::Missing)?;
                Ok(s.ceremonies.remove(at))
            })
            .await
    }
}

#[derive(Debug)]
enum Outcome {
    Missing,
    Full(Error),
    Failed(Error),
}

impl From<anyhow::Error> for Outcome {
    fn from(err: anyhow::Error) -> Self {
        Self::Failed(Error::Store(err.into()))
    }
}

fn store_error(err: impl Into<kagi::StoreError>) -> Error {
    Error::Store(err.into())
}

fn age(at: OffsetDateTime, since: OffsetDateTime) -> Duration {
    (at - since).try_into().unwrap_or_default()
}

impl<U> CeremonyStore<U> for SharedCeremonies
where
    U: Serialize + DeserializeOwned + Send,
{
    async fn begin(&self, address: Option<IpAddr>, ceremony: Ceremony<U>) -> Result<String, Error> {
        let id = kagi::ceremony_id()?;
        let record = CeremonyRecord {
            key: hex::encode(kagi::ceremony_key(&id)),
            started_at: now(),
            network: address.map(kagi::network),
            ceremony: serde_json::to_value(&ceremony).map_err(store_error)?,
        };
        let begun = match self.insert(&record).await {
            Err(Outcome::Full(_)) => {
                self.db.refresh_on_miss().await.map_err(store_error)?;
                self.insert(&record).await
            }
            other => other,
        };
        match begun {
            Ok(()) => Ok(id),
            Err(Outcome::Full(err) | Outcome::Failed(err)) => Err(err),
            Err(Outcome::Missing) => Err(Error::Ceremony),
        }
    }

    async fn take(&self, id: &str) -> Result<Option<Ceremony<U>>, Error> {
        let key = hex::encode(kagi::ceremony_key(id));
        let taken = match self.remove(&key).await {
            Err(Outcome::Missing) => {
                self.db.refresh_on_miss().await.map_err(store_error)?;
                self.remove(&key).await
            }
            other => other,
        };
        let record = match taken {
            Ok(record) => record,
            Err(Outcome::Missing) => return Ok(None),
            Err(Outcome::Full(err) | Outcome::Failed(err)) => return Err(err),
        };
        if age(now(), record.started_at) >= self.limits.ttl {
            return Ok(None);
        }
        serde_json::from_value(record.ceremony).map(Some).map_err(store_error)
    }
}

#[cfg(test)]
mod tests {
    use std::future::ready;

    use kagi::{
        Kagi, Passkey, PublicKeyCredential, RegisterPublicKeyCredential, Removal, Settings, Stored,
        Url, Uuid,
    };

    use super::*;
    use crate::store::{MemoryStore, Store};

    struct NoPasskeys;

    impl kagi::CredentialStore for NoPasskeys {
        type User = ();
        type PasskeyId = Uuid;
        type Error = std::io::Error;

        fn user_handle(&self, (): &()) -> Uuid {
            Uuid::nil()
        }

        fn passkeys(
            &self,
            (): &(),
        ) -> impl Future<Output = Result<Vec<Stored<Self>>, Self::Error>> + Send {
            ready(Ok(Vec::new()))
        }

        fn find(
            &self,
            _: &[u8],
        ) -> impl Future<Output = Result<Option<Stored<Self>>, Self::Error>> + Send {
            ready(Ok(None))
        }

        fn add(
            &self,
            (): &(),
            _: &Passkey,
            _: &str,
        ) -> impl Future<Output = Result<Uuid, Self::Error>> + Send {
            ready(Ok(Uuid::new_v4()))
        }

        fn update(
            &self,
            _: &Uuid,
            _: &Passkey,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            ready(Ok(()))
        }

        fn remove(
            &self,
            (): &(),
            _: &Uuid,
            _: bool,
        ) -> impl Future<Output = Result<Removal, Self::Error>> + Send {
            ready(Ok(Removal::NotFound))
        }
    }

    struct Replica {
        db: Arc<Db>,
        kagi: Kagi<(), SharedCeremonies>,
    }

    async fn replica(store: &Arc<MemoryStore>, limits: Limits) -> Replica {
        let db = Arc::new(Db::open(store.clone()).await.unwrap());
        let url = Url::parse("https://tegata.test").unwrap();
        let settings = Settings::new(&url, "tegata", &[7; 32]);
        let kagi = Kagi::new(settings, SharedCeremonies::new(db.clone(), limits)).unwrap();
        Replica { db, kagi }
    }

    fn address(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    async fn start(replica: &Replica, address: Option<IpAddr>) -> Result<String, Error> {
        replica.kagi.start_discoverable(address, false).await.map(|c| c.ceremony)
    }

    fn assertion() -> PublicKeyCredential {
        serde_json::from_value(serde_json::json!({
            "id": "AAAA",
            "rawId": "AAAA",
            "response": { "authenticatorData": "AAAA", "clientDataJSON": "AAAA", "signature": "AAAA" },
            "type": "public-key",
            "extensions": {}
        }))
        .unwrap()
    }

    fn attestation() -> RegisterPublicKeyCredential {
        serde_json::from_value(serde_json::json!({
            "id": "AAAA",
            "rawId": "AAAA",
            "response": { "attestationObject": "AAAA", "clientDataJSON": "AAAA" },
            "type": "public-key",
            "extensions": {}
        }))
        .unwrap()
    }

    async fn sign_in(replica: &Replica, id: &str) -> Error {
        replica.kagi.finish_sign_in(&NoPasskeys, id, &assertion()).await.unwrap_err()
    }

    #[tokio::test]
    async fn a_ceremony_started_on_one_replica_finishes_once_on_another() {
        let store = Arc::new(MemoryStore::default());
        let (a, b) = (replica(&store, LIMITS).await, replica(&store, LIMITS).await);
        let id = start(&a, Some(address(1))).await.unwrap();

        let state = store.load().await.unwrap().0;
        assert_eq!(state.ceremonies.len(), 1);
        assert_eq!(state.ceremonies[0].key, hex::encode(kagi::ceremony_key(&id)));
        assert!(!serde_json::to_string(&state).unwrap().contains(&id), "only the hash is kept");

        let err = sign_in(&b, &id).await;
        assert!(!matches!(err, Error::Ceremony), "the other replica found it: {err:?}");
        assert!(matches!(sign_in(&a, &id).await, Error::Ceremony), "and it was used up");
        assert!(matches!(sign_in(&b, &id).await, Error::Ceremony));
        assert!(store.load().await.unwrap().0.ceremonies.is_empty());
        assert!(a.db.read().ceremonies.is_empty());
    }

    #[tokio::test]
    async fn a_ceremony_finished_for_the_wrong_purpose_is_refused_and_used_up() {
        let store = Arc::new(MemoryStore::default());
        let a = replica(&store, LIMITS).await;
        let id = start(&a, None).await.unwrap();
        let err = a.kagi.finish_carried_registration(&NoPasskeys, &id, "x", &attestation()).await;
        assert!(matches!(err, Err(Error::Purpose)), "{err:?}");
        assert!(matches!(sign_in(&a, &id).await, Error::Ceremony));
    }

    #[tokio::test]
    async fn an_expired_ceremony_is_refused_and_removed() {
        let store = Arc::new(MemoryStore::default());
        let a = replica(&store, Limits { ttl: Duration::ZERO, ..LIMITS }).await;
        let id = start(&a, None).await.unwrap();
        assert_eq!(store.load().await.unwrap().0.ceremonies.len(), 1);
        assert!(matches!(sign_in(&a, &id).await, Error::Ceremony));
        assert!(store.load().await.unwrap().0.ceremonies.is_empty(), "taking removed it");
    }

    #[tokio::test]
    async fn caps_refuse_new_ceremonies_without_evicting_live_ones() {
        let store = Arc::new(MemoryStore::default());
        let limits = Limits { per_address: 2, global: 3, ..LIMITS };
        let (a, b) = (replica(&store, limits).await, replica(&store, limits).await);
        let first = start(&a, Some(address(1))).await.unwrap();
        let second = start(&b, Some(address(1))).await.unwrap();

        let refused = start(&a, Some(address(1))).await;
        assert!(
            matches!(refused, Err(Error::TooMany { retry_after }) if retry_after > Duration::ZERO),
            "the per-network cap holds across replicas: {refused:?}"
        );
        let v6 = |last| Some(IpAddr::from([0x2001, 0xdb8, 0, 1, 0, 0, 0, last]));
        let third = start(&b, v6(1)).await.unwrap();
        assert!(
            matches!(start(&a, v6(2)).await, Err(Error::Busy)),
            "the global cap refuses instead of evicting"
        );
        assert!(matches!(start(&a, v6(2)).await, Err(Error::Busy)));

        for id in [&first, &second, &third] {
            assert!(!matches!(sign_in(&b, id).await, Error::Ceremony), "{id} stayed live");
        }
        start(&a, v6(2)).await.unwrap();
    }
}
