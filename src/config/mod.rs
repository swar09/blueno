mod auth_config;
mod config_error;
mod env_file;
mod forwarding_config;
mod gateway_config;
mod header_rule_config;
mod headers_config;
mod limits_config;
mod rate_limiter_config;
mod redis_config;
mod request_body_limit;
mod request_body_limit_error;
mod secret_error;
mod secret_source;
mod serde_defaults;
mod server_config;
mod services_config;
mod x_forwarded_for_mode;

pub use auth_config::{
    AuthConfig, AuthMode, DEFAULT_AUTH_ENABLED, DEFAULT_JWKS_ENDPOINT, DEFAULT_JWT_CACHE_ENABLED,
    DEFAULT_JWT_CACHE_MAX_ENTRIES_PER_SHARD, DEFAULT_JWT_CACHE_SWEEP_INTERVAL_MS,
    DEFAULT_JWT_CACHE_TTL_SECS, DEFAULT_LOGOUT_PATH, JwtCacheConfig,
};
pub use config_error::ConfigError;
pub use env_file::load_env_file;
pub use forwarding_config::ForwardingConfig;
pub use gateway_config::{ApiGatewayConfig, CONFIG_PATH_ENV, DEFAULT_CONFIG_PATH, GatewayConfig};
pub use header_rule_config::HeaderRuleConfig;
pub use headers_config::{
    DEFAULT_ALLOWED_HEADERS, HeaderFilter, HeaderSafetyConfig, HeadersConfig,
};
pub use limits_config::{
    DEFAULT_MAX_COOLDOWN_SECS, DEFAULT_MIN_COOLDOWN_SECS, DEFAULT_TIMEOUT_SECS, LimitsConfig,
};
pub use rate_limiter_config::{
    DEFAULT_RATE_LIMIT_BATCH_WINDOW_MICROS, DEFAULT_RATE_LIMIT_ENABLED,
    DEFAULT_RATE_LIMIT_KEY_PREFIX, DEFAULT_RATE_LIMIT_LEASE_DURATION_SECS,
    DEFAULT_RATE_LIMIT_REDIS_URL, RateLimiterConfig, Tier, TierLimitConfig, TiersConfig,
};
pub use redis_config::{DEFAULT_REDIS_URL, RedisConfig};
pub use request_body_limit::{DEFAULT_MAX_REQUEST_BODY_BYTES, RequestBodyLimit};
pub use request_body_limit_error::RequestBodyLimitError;
pub use secret_error::SecretError;
pub use secret_source::{read_secret, read_secret_with};
pub use server_config::{DEFAULT_HOST, DEFAULT_PORT, ServerConfig};
pub use services_config::{RouteRuleConfig, ServicesConfig};
pub use x_forwarded_for_mode::XForwardedForMode;
