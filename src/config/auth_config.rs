use serde::{Deserialize, Serialize};

pub const DEFAULT_JWKS_ENDPOINT: &str = "https://auth.internal/.well_known/jwks.json";
pub const DEFAULT_AUTH_ENABLED: bool = true;
pub const DEFAULT_JWT_CACHE_ENABLED: bool = true;
pub const DEFAULT_JWT_CACHE_TTL_SECS: u64 = 15;
pub const DEFAULT_JWT_CACHE_MAX_ENTRIES_PER_SHARD: usize = 5000;
pub const DEFAULT_JWT_CACHE_SWEEP_INTERVAL_MS: u64 = 200;
pub const DEFAULT_LOGOUT_PATH: &str = "/api/v1/auth/logout";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    Jwks,
    Secret,
    None,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AuthConfig {
    #[serde(default = "default_auth_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub mode: AuthMode,
    #[serde(default = "default_jwks_endpoint")]
    pub jwks_endpoint: String,
    #[serde(default = "default_logout_path")]
    pub logout_path: String,
    #[serde(default)]
    pub jwt_cache: Option<JwtCacheConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: default_auth_enabled(),
            mode: AuthMode::default(),
            jwks_endpoint: default_jwks_endpoint(),
            logout_path: default_logout_path(),
            jwt_cache: None,
        }
    }
}

fn default_logout_path() -> String {
    DEFAULT_LOGOUT_PATH.to_string()
}

fn default_auth_enabled() -> bool {
    DEFAULT_AUTH_ENABLED
}

fn default_jwks_endpoint() -> String {
    DEFAULT_JWKS_ENDPOINT.to_string()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct JwtCacheConfig {
    #[serde(default = "default_jwt_cache_enabled")]
    pub enabled: bool,
    #[serde(default = "default_jwt_cache_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default = "default_jwt_cache_max_entries_per_shard")]
    pub max_entries_per_shard: usize,
    #[serde(default = "default_jwt_cache_sweep_interval_ms")]
    pub sweep_interval_ms: u64,
}

impl Default for JwtCacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_jwt_cache_enabled(),
            ttl_secs: default_jwt_cache_ttl_secs(),
            max_entries_per_shard: default_jwt_cache_max_entries_per_shard(),
            sweep_interval_ms: default_jwt_cache_sweep_interval_ms(),
        }
    }
}

fn default_jwt_cache_enabled() -> bool {
    DEFAULT_JWT_CACHE_ENABLED
}

fn default_jwt_cache_ttl_secs() -> u64 {
    DEFAULT_JWT_CACHE_TTL_SECS
}

fn default_jwt_cache_max_entries_per_shard() -> usize {
    DEFAULT_JWT_CACHE_MAX_ENTRIES_PER_SHARD
}

fn default_jwt_cache_sweep_interval_ms() -> u64 {
    DEFAULT_JWT_CACHE_SWEEP_INTERVAL_MS
}
