use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;

use crate::config::{
    AuthConfig, AuthMode, ConfigError, HeadersConfig, JwtCacheConfig, LimitsConfig,
    RateLimiterConfig, RedisConfig, RequestBodyLimit, RouteRuleConfig, ServerConfig,
    ServicesConfig, secret_source,
};

pub const DEFAULT_CONFIG_PATH: &str = "conf/blueno.toml";
pub const CONFIG_PATH_ENV: &str = "BLUENO_CONFIG";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct ApiGatewayConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub services: ServicesConfig,
    #[serde(default)]
    pub routes: Vec<RouteRuleConfig>,
    #[serde(default)]
    pub rate_limiter: RateLimiterConfig,
    #[serde(default)]
    pub jwt_cache: JwtCacheConfig,
    #[serde(default)]
    pub headers: HeadersConfig,
}

pub type GatewayConfig = ApiGatewayConfig;

impl GatewayConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        let path_str = path_ref.to_string_lossy().to_string();
        let content = fs::read_to_string(path_ref).map_err(|e| ConfigError::Io {
            path: path_str.clone(),
            source: e,
        })?;
        Self::from_toml_str(&content, &path_str)
    }

    fn from_toml_str(content: &str, path: &str) -> Result<Self, ConfigError> {
        let parse_error = |source| ConfigError::Parse {
            path: path.to_string(),
            source,
        };
        let value: toml::Value = toml::from_str(content).map_err(parse_error)?;
        let has_secret = value
            .get("auth")
            .and_then(|auth| auth.get("secret"))
            .is_some();
        if has_secret {
            return Err(ConfigError::SecretInConfigFile {
                path: path.to_string(),
            });
        }
        let mut config: GatewayConfig = value.try_into().map_err(parse_error)?;
        if let Some(sub_jwt_cache) = config.auth.jwt_cache.take() {
            config.jwt_cache = sub_jwt_cache;
        }
        if config.services.routes.is_empty() && !config.routes.is_empty() {
            config.services.routes = config.routes.clone();
        } else if config.routes.is_empty() && !config.services.routes.is_empty() {
            config.routes = config.services.routes.clone();
        }
        Ok(config)
    }

    pub fn resolve_path(
        cli_path: Option<&str>,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> PathBuf {
        cli_path
            .map(PathBuf::from)
            .or_else(|| {
                lookup(CONFIG_PATH_ENV)
                    .filter(|path| !path.is_empty())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let mut config = Self::from_file(path)?;
        config.apply_env_overrides()?;
        Ok(config)
    }

    pub fn apply_env_overrides(&mut self) -> Result<(), ConfigError> {
        fn env_parsed<T: std::str::FromStr>(key: &str) -> Option<T> {
            std::env::var(key).ok().and_then(|v| v.parse().ok())
        }

        if let Ok(mode) = std::env::var("AUTH_MODE") {
            match mode.to_lowercase().as_str() {
                "secret" => self.auth.mode = AuthMode::Secret,
                "jwks" => self.auth.mode = AuthMode::Jwks,
                "none" => {
                    self.auth.mode = AuthMode::None;
                    self.auth.enabled = false;
                }
                _ => {}
            }
        }
        if let Ok(host) = std::env::var("SERVER_HOST") {
            self.server.host = host;
        }
        if let Some(port) = env_parsed("SERVER_PORT") {
            self.server.port = port;
        }
        if let Some(enabled) = env_parsed("AUTH_ENABLED") {
            self.auth.enabled = enabled;
        }
        if let Ok(jwks) =
            std::env::var("GLOBAL_JWKS_ENDPOINT").or_else(|_| std::env::var("JWKS_ENDPOINT"))
        {
            self.auth.jwks_endpoint = jwks;
        }
        if let Some(redis) = secret_source::read_secret("REDIS_URL")? {
            self.redis.url = redis;
        }
        if let Some(timeout) = env_parsed("REQUEST_TIMEOUT_SECS") {
            self.limits.request_timeout_secs = timeout;
        }
        let body_limit_env = ["MAX_REQUEST_BODY_BYTES", "MAX_CONTENT_LENGTH_BYTES"]
            .into_iter()
            .find_map(|key| std::env::var(key).ok().map(|value| (key, value)));
        if let Some((key, value)) = body_limit_env {
            self.limits.max_request_body_bytes =
                RequestBodyLimit::from_str(&value).map_err(|source| {
                    ConfigError::InvalidEnvValue {
                        key: key.to_string(),
                        source,
                    }
                })?;
        }
        if let Some(enabled) = env_parsed("RATE_LIMIT_ENABLED") {
            self.rate_limiter.enabled = enabled;
        }
        if let Some(redis_url) = secret_source::read_secret("RATE_LIMIT_REDIS_URL")? {
            self.rate_limiter.redis_url = redis_url;
        }
        if let Some(batch_window) = env_parsed("RATE_LIMIT_BATCH_WINDOW_MICROS") {
            self.rate_limiter.batch_window_micros = batch_window;
        }
        if let Some(lease_duration) = env_parsed("RATE_LIMIT_LEASE_DURATION_SECS") {
            self.rate_limiter.lease_duration_secs = lease_duration;
        }
        if let Ok(script_path) = std::env::var("RATE_LIMIT_SCRIPT_PATH") {
            self.rate_limiter.script_path = Some(script_path.into());
        }
        if let Some(enabled) = env_parsed("JWT_CACHE_ENABLED") {
            self.jwt_cache.enabled = enabled;
        }
        if let Some(ttl) = env_parsed("JWT_CACHE_TTL_SECS") {
            self.jwt_cache.ttl_secs = ttl;
        }
        if let Some(max_entries) = env_parsed("JWT_CACHE_MAX_ENTRIES_PER_SHARD") {
            self.jwt_cache.max_entries_per_shard = max_entries;
        }
        if let Some(sweep_ms) = env_parsed("JWT_CACHE_SWEEP_INTERVAL_MS") {
            self.jwt_cache.sweep_interval_ms = sweep_ms;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_auth_secret_in_toml() {
        let toml = "[auth]\nmode = \"secret\"\nsecret = \"x\"\n";
        let error = GatewayConfig::from_toml_str(toml, "test.toml").expect_err("secret rejected");
        assert!(matches!(error, ConfigError::SecretInConfigFile { .. }));
        let message = error.to_string();
        assert!(message.contains("JWT_SECRET"));
        assert!(message.contains("JWT_SECRET_FILE"));
    }

    #[test]
    fn parses_auth_without_secret() {
        let toml = "[auth]\nmode = \"secret\"\n";
        let config = GatewayConfig::from_toml_str(toml, "test.toml").expect("parse");
        assert_eq!(config.auth.mode, AuthMode::Secret);
    }

    #[test]
    fn invalid_toml_is_a_parse_error() {
        let error = GatewayConfig::from_toml_str("[auth", "test.toml").expect_err("invalid");
        assert!(matches!(error, ConfigError::Parse { .. }));
    }

    #[test]
    fn resolve_path_prefers_cli_argument() {
        let path = GatewayConfig::resolve_path(Some("cli.toml"), |_| Some("env.toml".to_string()));
        assert_eq!(path, PathBuf::from("cli.toml"));
    }

    #[test]
    fn resolve_path_uses_env_without_cli_argument() {
        let path = GatewayConfig::resolve_path(None, |key| {
            (key == CONFIG_PATH_ENV).then(|| "env.toml".to_string())
        });
        assert_eq!(path, PathBuf::from("env.toml"));
    }

    #[test]
    fn resolve_path_falls_back_to_default() {
        let path = GatewayConfig::resolve_path(None, |_| None);
        assert_eq!(path, PathBuf::from(DEFAULT_CONFIG_PATH));
    }

    #[test]
    fn resolve_path_ignores_empty_env_value() {
        let path = GatewayConfig::resolve_path(None, |_| Some(String::new()));
        assert_eq!(path, PathBuf::from(DEFAULT_CONFIG_PATH));
    }

    #[test]
    fn load_fails_when_file_is_missing() {
        let error =
            GatewayConfig::load(Path::new("does/not/exist.toml")).expect_err("missing file");
        assert!(matches!(error, ConfigError::Io { .. }));
    }
}
