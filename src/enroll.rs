use std::collections::HashMap;

use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::util::sha256_hex;

pub struct Pending {
    pub device_id: Uuid,
    pub device_name: String,
    pub serial: String,
    pub p12: Vec<u8>,
    pub mobileconfig: String,
    pub expires_at: OffsetDateTime,
}

/// One-shot download links, kept in memory only: a restart voids them and the sweeper
/// revokes their certificates.
#[derive(Default)]
pub struct Enrollments {
    by_token: Mutex<HashMap<String, Pending>>,
}

impl Enrollments {
    pub async fn insert(&self, token: &str, pending: Pending) {
        self.by_token.lock().await.insert(sha256_hex(token.as_bytes()), pending);
    }

    pub async fn peek(&self, token: &str, now: OffsetDateTime) -> Option<(String, OffsetDateTime)> {
        let map = self.by_token.lock().await;
        map.get(&sha256_hex(token.as_bytes()))
            .filter(|p| p.expires_at > now)
            .map(|p| (p.device_name.clone(), p.expires_at))
    }

    pub async fn take(&self, token: &str, now: OffsetDateTime) -> Option<Pending> {
        let mut map = self.by_token.lock().await;
        map.remove(&sha256_hex(token.as_bytes())).filter(|p| p.expires_at > now)
    }

    pub async fn forget_device(&self, device_id: Uuid) {
        self.by_token.lock().await.retain(|_, p| p.device_id != device_id);
    }

    pub async fn forget_device_except(&self, device_id: Uuid, serial: &str) {
        self.by_token.lock().await.retain(|_, p| p.device_id != device_id || p.serial == serial);
    }

    pub async fn drop_expired(&self, now: OffsetDateTime) {
        self.by_token.lock().await.retain(|_, p| p.expires_at > now);
    }

    pub async fn serials(&self) -> Vec<String> {
        self.by_token.lock().await.values().map(|p| p.serial.clone()).collect()
    }
}
