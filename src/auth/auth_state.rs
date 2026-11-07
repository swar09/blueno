use std::sync::Arc;

use crate::auth::{
    Authenticator, ClaimsCache, JwksAuthenticator, JwksStore, RevocationCheck, RevocationList,
    SecretAuthenticator,
};

#[derive(Clone)]
pub struct AuthState {
    pub authenticator: Arc<dyn Authenticator>,
    pub jwt_cache: Arc<ClaimsCache>,
    pub logout_path: String,
    pub revocations: Arc<dyn RevocationCheck>,
}

impl AuthState {
    pub fn new(cache: JwksStore) -> Self {
        Self::new_with_jwks(cache)
    }

    pub fn new_with_jwks(cache: JwksStore) -> Self {
        let config = crate::config::JwtCacheConfig::default();
        Self {
            authenticator: Arc::new(JwksAuthenticator::new(cache)),
            jwt_cache: ClaimsCache::from_config(&config),
            logout_path: crate::config::DEFAULT_LOGOUT_PATH.to_string(),
            revocations: Arc::new(RevocationList::disabled()),
        }
    }

    pub fn new_with_secret(secret: impl Into<Vec<u8>>) -> Self {
        let config = crate::config::JwtCacheConfig::default();
        Self {
            authenticator: Arc::new(SecretAuthenticator::new(secret)),
            jwt_cache: ClaimsCache::from_config(&config),
            logout_path: crate::config::DEFAULT_LOGOUT_PATH.to_string(),
            revocations: Arc::new(RevocationList::disabled()),
        }
    }

    pub fn from_config(cache: JwksStore, config: &crate::config::JwtCacheConfig) -> Self {
        Self {
            authenticator: Arc::new(JwksAuthenticator::new(cache)),
            jwt_cache: ClaimsCache::from_config(config),
            logout_path: crate::config::DEFAULT_LOGOUT_PATH.to_string(),
            revocations: Arc::new(RevocationList::disabled()),
        }
    }

    pub fn with_jwt_cache(cache: JwksStore, jwt_cache: Arc<ClaimsCache>) -> Self {
        Self {
            authenticator: Arc::new(JwksAuthenticator::new(cache)),
            jwt_cache,
            logout_path: crate::config::DEFAULT_LOGOUT_PATH.to_string(),
            revocations: Arc::new(RevocationList::disabled()),
        }
    }

    pub fn with_authenticator(
        authenticator: Arc<dyn Authenticator>,
        jwt_cache: Arc<ClaimsCache>,
    ) -> Self {
        Self {
            authenticator,
            jwt_cache,
            logout_path: crate::config::DEFAULT_LOGOUT_PATH.to_string(),
            revocations: Arc::new(RevocationList::disabled()),
        }
    }

    pub fn with_logout_path(mut self, path: impl Into<String>) -> Self {
        self.logout_path = path.into();
        self
    }

    pub fn with_revocations(mut self, revocations: Arc<dyn RevocationCheck>) -> Self {
        self.revocations = revocations;
        self
    }
}
