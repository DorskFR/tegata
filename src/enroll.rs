use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use time::OffsetDateTime;

use crate::app::App;
use crate::model::EnrollmentRecord;
use crate::util::{now, sha256_hex};

pub fn token_hash(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

pub fn p12_bytes(record: &EnrollmentRecord) -> anyhow::Result<Vec<u8>> {
    Ok(STANDARD.decode(&record.p12_base64)?)
}

pub fn encode_p12(p12: &[u8]) -> String {
    STANDARD.encode(p12)
}

impl App {
    /// Device name and expiry of a still usable link; checks the store again on a miss
    /// in case another replica created it.
    pub async fn enrollment_info(&self, token: &str) -> Option<(String, OffsetDateTime)> {
        let hash = token_hash(token);
        let find = |state: &crate::model::State| {
            let t = now();
            state
                .enrollments
                .iter()
                .find(|e| e.token_hash == hash && e.expires_at > t)
                .map(|e| (e.device_name.clone(), e.expires_at))
        };
        if let Some(found) = find(&self.db.read().await) {
            return Some(found);
        }
        if let Err(err) = self.db.refresh().await {
            tracing::warn!(error = ?err, "refreshing state failed");
        }
        find(&self.db.read().await)
    }
}
