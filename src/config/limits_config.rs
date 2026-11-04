use serde::Deserialize;

use crate::config::RequestBodyLimit;
use crate::config::serde_defaults::default_true;

pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_MIN_COOLDOWN_SECS: u64 = 60;
pub const DEFAULT_MAX_COOLDOWN_SECS: u64 = 240;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LimitsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, alias = "max_content_length_bytes")]
    pub max_request_body_bytes: RequestBodyLimit,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_min_cooldown_secs")]
    pub min_cooldown_secs: u64,
    #[serde(default = "default_max_cooldown_secs")]
    pub max_cooldown_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_request_body_bytes: RequestBodyLimit::default(),
            request_timeout_secs: default_request_timeout_secs(),
            min_cooldown_secs: default_min_cooldown_secs(),
            max_cooldown_secs: default_max_cooldown_secs(),
        }
    }
}

fn default_request_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

fn default_min_cooldown_secs() -> u64 {
    DEFAULT_MIN_COOLDOWN_SECS
}

fn default_max_cooldown_secs() -> u64 {
    DEFAULT_MAX_COOLDOWN_SECS
}
