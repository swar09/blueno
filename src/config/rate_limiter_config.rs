use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const DEFAULT_RATE_LIMIT_ENABLED: bool = false;
pub const DEFAULT_RATE_LIMIT_REDIS_URL: &str = "redis://127.0.0.1:16379";
pub const DEFAULT_RATE_LIMIT_KEY_PREFIX: &str = "rl";
pub const DEFAULT_RATE_LIMIT_LEASE_DURATION_SECS: u64 = 5;
pub const DEFAULT_RATE_LIMIT_BATCH_WINDOW_MICROS: u64 = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Tier1,
    Tier2,
    Tier3,
    #[default]
    Tier4,
}

impl Tier {
    #[inline]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tier1 => "tier1",
            Self::Tier2 => "tier2",
            Self::Tier3 => "tier3",
            Self::Tier4 => "tier4",
        }
    }
}

impl std::str::FromStr for Tier {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tier1" => Ok(Self::Tier1),
            "tier2" => Ok(Self::Tier2),
            "tier3" => Ok(Self::Tier3),
            _ => Ok(Self::Tier4),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TierLimitConfig {
    pub initial_tokens: u64,
    pub fill_rate: u64,
    pub burst_interval_secs: u64,
    pub max_tokens: u64,
    pub lease_batch_size: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TiersConfig {
    #[serde(default = "default_tier1_config")]
    pub tier1: TierLimitConfig,
    #[serde(default = "default_tier2_config")]
    pub tier2: TierLimitConfig,
    #[serde(default = "default_tier3_config")]
    pub tier3: TierLimitConfig,
    #[serde(default = "default_tier4_config")]
    pub tier4: TierLimitConfig,
}

impl Default for TiersConfig {
    fn default() -> Self {
        Self {
            tier1: default_tier1_config(),
            tier2: default_tier2_config(),
            tier3: default_tier3_config(),
            tier4: default_tier4_config(),
        }
    }
}

impl TiersConfig {
    #[inline]
    pub fn get(&self, tier: Tier) -> &TierLimitConfig {
        match tier {
            Tier::Tier1 => &self.tier1,
            Tier::Tier2 => &self.tier2,
            Tier::Tier3 => &self.tier3,
            Tier::Tier4 => &self.tier4,
        }
    }
}

fn default_tier1_config() -> TierLimitConfig {
    TierLimitConfig {
        initial_tokens: 1000,
        fill_rate: 1000,
        burst_interval_secs: 60,
        max_tokens: 5000,
        lease_batch_size: 500,
    }
}

fn default_tier2_config() -> TierLimitConfig {
    TierLimitConfig {
        initial_tokens: 200,
        fill_rate: 200,
        burst_interval_secs: 60,
        max_tokens: 1000,
        lease_batch_size: 100,
    }
}

fn default_tier3_config() -> TierLimitConfig {
    TierLimitConfig {
        initial_tokens: 50,
        fill_rate: 50,
        burst_interval_secs: 60,
        max_tokens: 250,
        lease_batch_size: 50,
    }
}

fn default_tier4_config() -> TierLimitConfig {
    TierLimitConfig {
        initial_tokens: 10,
        fill_rate: 10,
        burst_interval_secs: 60,
        max_tokens: 50,
        lease_batch_size: 10,
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RateLimiterConfig {
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_rate_limit_redis_url")]
    pub redis_url: String,
    #[serde(default = "default_rate_limit_key_prefix")]
    pub key_prefix: String,
    #[serde(default = "default_rate_limit_lease_duration_secs")]
    pub lease_duration_secs: u64,
    #[serde(default = "default_rate_limit_batch_window_micros")]
    pub batch_window_micros: u64,
    #[serde(default)]
    pub script_path: Option<PathBuf>,
    #[serde(default)]
    pub default_tier: Tier,
    #[serde(default)]
    pub tiers: TiersConfig,
    #[serde(default = "default_role_mapping")]
    pub role_mapping: HashMap<String, Tier>,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            redis_url: default_rate_limit_redis_url(),
            key_prefix: default_rate_limit_key_prefix(),
            lease_duration_secs: default_rate_limit_lease_duration_secs(),
            batch_window_micros: default_rate_limit_batch_window_micros(),
            script_path: None,
            default_tier: Tier::Tier4,
            tiers: TiersConfig::default(),
            role_mapping: default_role_mapping(),
        }
    }
}

fn default_rate_limit_enabled() -> bool {
    DEFAULT_RATE_LIMIT_ENABLED
}

fn default_rate_limit_redis_url() -> String {
    DEFAULT_RATE_LIMIT_REDIS_URL.to_string()
}

fn default_rate_limit_key_prefix() -> String {
    DEFAULT_RATE_LIMIT_KEY_PREFIX.to_string()
}

fn default_rate_limit_lease_duration_secs() -> u64 {
    DEFAULT_RATE_LIMIT_LEASE_DURATION_SECS
}

fn default_rate_limit_batch_window_micros() -> u64 {
    DEFAULT_RATE_LIMIT_BATCH_WINDOW_MICROS
}

fn default_role_mapping() -> HashMap<String, Tier> {
    HashMap::new()
}
