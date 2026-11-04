use serde::Deserialize;

pub const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1:6379";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RedisConfig {
    #[serde(default = "default_redis_url")]
    pub url: String,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: default_redis_url(),
        }
    }
}

fn default_redis_url() -> String {
    DEFAULT_REDIS_URL.to_string()
}
