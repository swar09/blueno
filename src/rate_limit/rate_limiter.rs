use std::sync::Arc;

use uuid::Uuid;

use crate::config::{RateLimiterConfig, Tier, TierLimitConfig};
use crate::rate_limit::{AutonomousLimiter, Decision, DistributedLimiter, RateLimitError};

pub struct RateLimiter {
    pub config: Arc<RateLimiterConfig>,
    pub engine: RateLimiterEngine,
}

impl RateLimiter {
    pub fn new(config: Arc<RateLimiterConfig>, engine: RateLimiterEngine) -> Self {
        Self { config, engine }
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    #[inline]
    pub fn resolve_role(&self, role: Option<&str>) -> Tier {
        role.and_then(|r| self.config.role_mapping.get(r).copied())
            .unwrap_or(self.config.default_tier)
    }

    #[inline]
    pub fn tier_config(&self, tier: Tier) -> &TierLimitConfig {
        self.config.tiers.get(tier)
    }

    pub async fn check(&self, user_id: &Uuid, tier: Tier) -> Result<Decision, RateLimitError> {
        if !self.config.enabled {
            return Ok(Decision::Allowed {
                remaining: u64::MAX,
                limit: u64::MAX,
            });
        }

        let tier_config = self.config.tiers.get(tier);
        self.engine.check(user_id, tier, tier_config).await
    }

    pub fn clear(&self) {
        self.engine.clear();
    }
}

#[derive(Clone)]
pub enum RateLimiterEngine {
    Distributed(DistributedLimiter),
    Autonomous(AutonomousLimiter),
    PassThrough,
}

impl RateLimiterEngine {
    pub async fn check(
        &self,
        user_id: &Uuid,
        tier: Tier,
        config: &TierLimitConfig,
    ) -> Result<Decision, RateLimitError> {
        match self {
            Self::Distributed(limiter) => limiter.acquire(user_id, tier, config).await,
            Self::Autonomous(limiter) => Ok(limiter.check(user_id, tier, config)),
            Self::PassThrough => Ok(Decision::Allowed {
                remaining: u64::MAX,
                limit: u64::MAX,
            }),
        }
    }

    pub fn clear(&self) {
        match self {
            Self::Distributed(limiter) => limiter.clear(),
            Self::Autonomous(limiter) => limiter.clear(),
            Self::PassThrough => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tier_config(initial: u64, max: u64) -> TierLimitConfig {
        TierLimitConfig {
            initial_tokens: initial,
            fill_rate: 0,
            burst_interval_secs: 60,
            max_tokens: max,
            lease_batch_size: 10,
        }
    }

    #[test]
    fn test_rate_limiter_engine_passthrough() {
        let engine = RateLimiterEngine::PassThrough;
        let user_id = Uuid::new_v4();
        let config = test_tier_config(1, 1);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let decision = rt
            .block_on(engine.check(&user_id, Tier::Tier1, &config))
            .unwrap();
        assert_eq!(
            decision,
            Decision::Allowed {
                remaining: u64::MAX,
                limit: u64::MAX,
            }
        );
    }
}
