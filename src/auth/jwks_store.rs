use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::Jwk;
use parking_lot::RwLock;
use thiserror::Error;

use crate::auth::JwksClient;
use crate::config::{DEFAULT_MAX_COOLDOWN_SECS, DEFAULT_MIN_COOLDOWN_SECS};

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Key not found: {0}")]
    NotFound(String),

    #[error("Fetch error: {0}")]
    FetchError(String),

    #[error("Cooldown is active, cannot fetch JWKS")]
    CooldownActive,
}

#[derive(Clone)]
pub struct JwksStore {
    local_cache: Arc<RwLock<HashMap<String, Jwk>>>,
    jwks_client: JwksClient,
    cooldown_until: Arc<RwLock<Option<Instant>>>,
}

impl JwksStore {
    pub async fn new(jwks_client: JwksClient) -> Self {
        let store = Self::new_in_memory(jwks_client);

        if let Err(e) = store.refill_jwks().await {
            eprintln!("[cache] warning: startup JWKS load failed (will lazy-load on demand): {e}");
        }

        store
    }

    pub fn new_in_memory(jwks_client: JwksClient) -> Self {
        JwksStore {
            local_cache: Arc::new(RwLock::new(HashMap::new())),
            jwks_client,
            cooldown_until: Arc::new(RwLock::new(None)),
        }
    }

    pub fn calculate_jitter_cooldown() -> Duration {
        let secs = fastrand::u64(DEFAULT_MIN_COOLDOWN_SECS..=DEFAULT_MAX_COOLDOWN_SECS);
        Duration::from_secs(secs)
    }

    pub fn is_cooldown_active(&self) -> bool {
        self.cooldown_until
            .read()
            .is_some_and(|until| Instant::now() < until)
    }

    pub fn set_cooldown(&self, duration: Duration) {
        let mut guard = self.cooldown_until.write();
        *guard = Some(Instant::now() + duration);
    }

    pub fn clear_cooldown(&self) {
        let mut guard = self.cooldown_until.write();
        *guard = None;
    }

    pub fn get_local_jwk(&self, kid: &str) -> Option<Jwk> {
        let guard = self.local_cache.read();
        guard.get(kid).cloned()
    }

    pub fn replace_local_jwks(&self, jwks: Vec<(String, Jwk)>) {
        let mut guard = self.local_cache.write();
        guard.clear();
        for (kid, jwk) in jwks {
            guard.insert(kid, jwk);
        }
    }

    pub async fn refill_jwks(&self) -> Result<bool, CacheError> {
        let set = self
            .jwks_client
            .fetch_jwks_from_endpoint()
            .await
            .map_err(|e| CacheError::FetchError(e.to_string()))?;

        let pairs: Vec<(String, Jwk)> = set
            .keys
            .into_iter()
            .filter_map(|jwk| jwk.common.key_id.clone().map(|kid| (kid, jwk)))
            .collect();

        self.replace_local_jwks(pairs);

        Ok(true)
    }

    pub async fn get_or_fetch_jwk(&self, kid: &str) -> Result<Jwk, CacheError> {
        if let Some(jwk) = self.get_local_jwk(kid) {
            return Ok(jwk);
        }

        {
            let mut guard = self.cooldown_until.write();
            if let Some(until) = *guard
                && Instant::now() < until
            {
                return Err(CacheError::CooldownActive);
            }
            let cooldown = Self::calculate_jitter_cooldown();
            *guard = Some(Instant::now() + cooldown);
        }

        self.refill_jwks().await?;

        if let Some(jwk) = self.get_local_jwk(kid) {
            self.clear_cooldown();
            Ok(jwk)
        } else {
            Err(CacheError::NotFound(kid.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_in_memory_local_jwk_storage() {
        let jwks_client = JwksClient::new("http://localhost/jwks".to_string()).unwrap();
        let cache = JwksStore::new_in_memory(jwks_client);

        assert!(cache.get_local_jwk("kid-1").is_none());
        assert!(!cache.is_cooldown_active());

        cache.set_cooldown(Duration::from_secs(10));
        assert!(cache.is_cooldown_active());

        cache.clear_cooldown();
        assert!(!cache.is_cooldown_active());
    }
}
