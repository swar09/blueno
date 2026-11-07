use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest;

use crate::auth::Claims;

#[derive(Clone)]
pub struct ClaimsCache {
    cache: moka::sync::Cache<TokenKey, Claims>,
    enabled: bool,
}

impl ClaimsCache {
    pub fn new(default_ttl: Duration, max_capacity: u64) -> Arc<Self> {
        Self::with_options(default_ttl, max_capacity, true)
    }

    pub fn with_options(default_ttl: Duration, max_capacity: u64, enabled: bool) -> Arc<Self> {
        let cache = moka::sync::Cache::builder()
            .max_capacity(max_capacity.max(1024))
            .time_to_live(default_ttl)
            .build();

        Arc::new(Self { cache, enabled })
    }

    pub fn from_config(config: &crate::config::JwtCacheConfig) -> Arc<Self> {
        let max_capacity = (config.max_entries_per_shard.saturating_mul(64)) as u64;
        Self::with_options(
            Duration::from_secs(config.ttl_secs),
            max_capacity,
            config.enabled,
        )
    }

    pub fn get(&self, token_bytes: &[u8]) -> Option<Claims> {
        if !self.enabled {
            return None;
        }
        let key = token_key(token_bytes);
        let claims = self.cache.get(&key)?;
        if claims.exp <= unix_now_secs() {
            self.cache.invalidate(&key);
            return None;
        }
        Some(claims)
    }

    pub fn insert(&self, token_bytes: &[u8], claims: Claims) {
        if !self.enabled {
            return;
        }
        self.cache.insert(token_key(token_bytes), claims);
    }

    pub fn evict(&self, token_bytes: &[u8]) {
        self.cache.invalidate(&token_key(token_bytes));
    }

    pub fn clear(&self) {
        self.cache.invalidate_all();
    }

    pub fn len(&self) -> usize {
        self.cache.entry_count() as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

type TokenKey = [u8; 32];

fn token_key(token_bytes: &[u8]) -> TokenKey {
    let digest = digest::digest(&digest::SHA256, token_bytes);
    let mut key: TokenKey = [0; 32];
    key.copy_from_slice(digest.as_ref());
    key
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl Default for ClaimsCache {
    fn default() -> Self {
        let config = crate::config::JwtCacheConfig::default();
        let max_capacity = (config.max_entries_per_shard.saturating_mul(64)) as u64;
        let cache = moka::sync::Cache::builder()
            .max_capacity(max_capacity.max(1024))
            .time_to_live(Duration::from_secs(config.ttl_secs))
            .build();
        Self {
            cache,
            enabled: config.enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::auth::{Audience, UserRole};

    #[test]
    fn test_local_jwt_cache_operations() {
        let cache = ClaimsCache::new(Duration::from_secs(60), 100);
        let token = b"test-bearer-token";
        let claims = Claims {
            iss: "issuer".to_string(),
            sub: Uuid::new_v4(),
            iat: 100,
            nbf: 100,
            exp: 9999999999,
            aud: Audience("test-aud".to_string()),
            role: UserRole("admin".to_string()),
            jti: Uuid::new_v4(),
        };

        assert!(cache.get(token).is_none());
        assert_eq!(cache.len(), 0);

        cache.insert(token, claims.clone());
        let retrieved = cache.get(token);
        assert_eq!(retrieved, Some(claims));

        cache.evict(token);
        assert!(cache.get(token).is_none());
    }

    #[test]
    fn test_local_jwt_cache_rejects_expired_claims() {
        let cache = ClaimsCache::new(Duration::from_secs(60), 100);
        let token = b"expired-bearer-token";
        let claims = Claims {
            iss: "issuer".to_string(),
            sub: Uuid::new_v4(),
            iat: 100,
            nbf: 100,
            exp: 1000,
            aud: Audience("test-aud".to_string()),
            role: UserRole("admin".to_string()),
            jti: Uuid::new_v4(),
        };

        cache.insert(token, claims);
        assert!(
            cache.get(token).is_none(),
            "expired claims must not be served from cache"
        );
    }

    #[test]
    fn test_local_jwt_cache_distinguishes_tokens() {
        let cache = ClaimsCache::new(Duration::from_secs(60), 100);
        let claims = Claims {
            iss: "issuer".to_string(),
            sub: Uuid::new_v4(),
            iat: 100,
            nbf: 100,
            exp: 9999999999,
            aud: Audience("test-aud".to_string()),
            role: UserRole("admin".to_string()),
            jti: Uuid::new_v4(),
        };

        cache.insert(b"token-a", claims);
        assert!(
            cache.get(b"token-b").is_none(),
            "a different token must miss the cache"
        );
    }
}
